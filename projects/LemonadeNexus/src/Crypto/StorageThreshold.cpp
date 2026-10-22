#include <LemonadeNexus/Crypto/StorageThreshold.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <sodium.h>
#include <storage_threshold.h>

#include <cstring>
#include <exception>
#include <string_view>
#include <utility>

namespace nexus::crypto {

namespace {

constexpr std::string_view kWrapLabel = "data-key-wrap";

StorageStatus status_from(int32_t code) {
    switch (code) {
        case STORAGE_OK:
            return StorageStatus::Ok;
        case STORAGE_ERR_INVALID_ARGUMENT:
            return StorageStatus::InvalidArgument;
        case STORAGE_ERR_CRYPTO:
            return StorageStatus::CryptoFailure;
        case STORAGE_ERR_SERIALIZATION:
            return StorageStatus::Serialization;
        case STORAGE_ERR_BELOW_THRESHOLD:
            return StorageStatus::BelowThreshold;
        case STORAGE_ERR_THRESHOLD_CHANGE:
            return StorageStatus::ThresholdChange;
        case STORAGE_ERR_HOLDER_COUNT:
            return StorageStatus::HolderCount;
        case STORAGE_ERR_PROOF:
            return StorageStatus::InvalidProof;
        case STORAGE_ERR_SHARE_MISMATCH:
            return StorageStatus::ShareMismatch;
        default:
            return StorageStatus::Internal;
    }
}

template <typename T>
StorageResult<T> failure(StorageStatus status) {
    StorageResult<T> result;
    result.status = status;
    return result;
}

template <typename T>
StorageResult<T> success(T value) {
    StorageResult<T> result;
    result.status = StorageStatus::Ok;
    result.value.emplace(std::move(value));
    return result;
}

// Copies a Rust buffer out and releases it; the Rust side wipes on free.
StorageBytes take_buffer(StorageBuffer& buffer) {
    StorageBytes bytes(buffer.data, buffer.data + buffer.len);
    storage_buffer_free(&buffer);
    return bytes;
}

StoragePeerBytesMap take_peer_buffers(StoragePeerBuffer* buffers, size_t count) {
    StoragePeerBytesMap out;
    for (size_t i = 0; i < count; ++i) {
        const auto& entry = buffers[i];
        out[entry.identifier] = StorageBytes(entry.buffer.data, entry.buffer.data + entry.buffer.len);
    }
    storage_peer_buffers_free(buffers, count);
    return out;
}

std::vector<StoragePeerBytes> to_peer_bytes(const StoragePeerBytesMap& map) {
    std::vector<StoragePeerBytes> out;
    out.reserve(map.size());
    for (const auto& [identifier, bytes] : map) {
        out.push_back(StoragePeerBytes{identifier, bytes.data(), bytes.size()});
    }
    return out;
}

::StorageUnlockContext to_c(const StorageUnlockContext& context) {
    ::StorageUnlockContext out{};
    std::memcpy(out.network_id, context.network_id.data(), sizeof(out.network_id));
    out.epoch = context.epoch;
    std::memcpy(out.plan_digest, context.plan_digest.data(), sizeof(out.plan_digest));
    std::memcpy(out.request_nonce, context.request_nonce.data(), sizeof(out.request_nonce));
    return out;
}

std::span<const uint8_t> as_bytes(std::string_view text) {
    return {reinterpret_cast<const uint8_t*>(text.data()), text.size()};
}

/// u32 little-endian length followed by the bytes, as in aead_aad.
void put_length_prefixed(std::vector<uint8_t>& out, std::span<const uint8_t> bytes) {
    const auto n = static_cast<uint32_t>(bytes.size());
    for (int shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<uint8_t>((n >> shift) & 0xFF));
    }
    out.insert(out.end(), bytes.begin(), bytes.end());
}

/// Wipes a stack secret when the scope ends, on every path.
class WipeOnExit {
public:
    WipeOnExit(void* data, std::size_t size) : data_(data), size_(size) {}
    WipeOnExit(const WipeOnExit&) = delete;
    WipeOnExit& operator=(const WipeOnExit&) = delete;
    ~WipeOnExit() { sodium_memzero(data_, size_); }

private:
    void* data_;
    std::size_t size_;
};

/// HKDF-SHA256 over the shared point r*S = s*R. The info binds the domain
/// tag, the construction label, S, R, and the server, so a wrap key is
/// specific to one wrapped object.
void derive_wrap_key(SodiumCryptoService& crypto, std::span<const uint8_t> shared_point,
                     const StoragePoint& storage_public_key, const StoragePoint& ephemeral_point,
                     std::span<const uint8_t> server_id, AeadKey& out) {
    std::vector<uint8_t> info;
    put_length_prefixed(info, as_bytes(STORAGE_DOMAIN));
    put_length_prefixed(info, as_bytes(kWrapLabel));
    put_length_prefixed(info, storage_public_key);
    put_length_prefixed(info, ephemeral_point);
    put_length_prefixed(info, server_id);
    auto okm = crypto.hkdf_sha256(shared_point, {}, info, out.size());
    std::memcpy(out.data(), okm.data(), out.size());
    sodium_memzero(okm.data(), okm.size());
}

std::vector<uint8_t> wrap_aad(const StoragePoint& storage_public_key,
                              const StoragePoint& ephemeral_point,
                              std::span<const uint8_t> server_id) {
    return aead_aad(aead_purpose::kStorageDataKey,
                    {storage_public_key, ephemeral_point, server_id});
}

struct ShareInfo {
    StorageHolderId holder = 0;
    uint16_t threshold = 0;
    StoragePoint storage_public_key{};
};

std::optional<ShareInfo> share_info(const ::StorageShare* handle) {
    ShareInfo info;
    if (handle == nullptr ||
        storage_share_info(handle, &info.holder, &info.threshold,
                           info.storage_public_key.data()) != STORAGE_OK) {
        return std::nullopt;
    }
    return info;
}

}  // namespace

// --- StorageKeyShare --------------------------------------------------------

StorageKeyShare::StorageKeyShare(StorageKeyShare&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)) {}

StorageKeyShare& StorageKeyShare::operator=(StorageKeyShare&& other) noexcept {
    if (this != &other) {
        storage_share_free(handle_);
        handle_ = std::exchange(other.handle_, nullptr);
    }
    return *this;
}

StorageKeyShare::~StorageKeyShare() { storage_share_free(handle_); }

std::optional<StorageHolderId> StorageKeyShare::holder() const {
    const auto info = share_info(handle_);
    return info ? std::optional<StorageHolderId>(info->holder) : std::nullopt;
}

std::optional<uint16_t> StorageKeyShare::threshold() const {
    const auto info = share_info(handle_);
    return info ? std::optional<uint16_t>(info->threshold) : std::nullopt;
}

std::optional<StoragePoint> StorageKeyShare::storage_public_key() const {
    const auto info = share_info(handle_);
    return info ? std::optional<StoragePoint>(info->storage_public_key) : std::nullopt;
}

// --- StorageDkgRound1 -------------------------------------------------------

StorageDkgRound1::StorageDkgRound1(StorageDkgRound1&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)), package_(std::move(other.package_)) {}

StorageDkgRound1& StorageDkgRound1::operator=(StorageDkgRound1&& other) noexcept {
    if (this != &other) {
        storage_dkg_round1_state_free(handle_);
        handle_ = std::exchange(other.handle_, nullptr);
        package_ = std::move(other.package_);
    }
    return *this;
}

StorageDkgRound1::~StorageDkgRound1() { storage_dkg_round1_state_free(handle_); }

::StorageDkgRound1State* StorageDkgRound1::release() { return std::exchange(handle_, nullptr); }

// --- StorageDkgRound2 -------------------------------------------------------

StorageDkgRound2::StorageDkgRound2(StorageDkgRound2&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)), packages_(std::move(other.packages_)) {}

StorageDkgRound2& StorageDkgRound2::operator=(StorageDkgRound2&& other) noexcept {
    if (this != &other) {
        storage_dkg_round2_state_free(handle_);
        handle_ = std::exchange(other.handle_, nullptr);
        packages_ = std::move(other.packages_);
    }
    return *this;
}

StorageDkgRound2::~StorageDkgRound2() { storage_dkg_round2_state_free(handle_); }

::StorageDkgRound2State* StorageDkgRound2::release() { return std::exchange(handle_, nullptr); }

// --- StorageRefreshRound1 ---------------------------------------------------

StorageRefreshRound1::StorageRefreshRound1(StorageRefreshRound1&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)), package_(std::move(other.package_)) {}

StorageRefreshRound1& StorageRefreshRound1::operator=(StorageRefreshRound1&& other) noexcept {
    if (this != &other) {
        storage_refresh_round1_state_free(handle_);
        handle_ = std::exchange(other.handle_, nullptr);
        package_ = std::move(other.package_);
    }
    return *this;
}

StorageRefreshRound1::~StorageRefreshRound1() { storage_refresh_round1_state_free(handle_); }

::StorageRefreshRound1State* StorageRefreshRound1::release() { return std::exchange(handle_, nullptr); }

// --- StorageRefreshRound2 ---------------------------------------------------

StorageRefreshRound2::StorageRefreshRound2(StorageRefreshRound2&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)), packages_(std::move(other.packages_)) {}

StorageRefreshRound2& StorageRefreshRound2::operator=(StorageRefreshRound2&& other) noexcept {
    if (this != &other) {
        storage_refresh_round2_state_free(handle_);
        handle_ = std::exchange(other.handle_, nullptr);
        packages_ = std::move(other.packages_);
    }
    return *this;
}

StorageRefreshRound2::~StorageRefreshRound2() { storage_refresh_round2_state_free(handle_); }

::StorageRefreshRound2State* StorageRefreshRound2::release() { return std::exchange(handle_, nullptr); }

// --- StorageThreshold -------------------------------------------------------

std::optional<uint16_t> StorageThreshold::threshold_for(uint16_t holder_count) {
    uint16_t threshold = 0;
    if (storage_threshold_for(holder_count, &threshold) != STORAGE_OK) {
        return std::nullopt;
    }
    return threshold;
}

StorageResult<StorageDkgRound1> StorageThreshold::dkg_part1(StorageHolderId holder,
                                                            uint16_t holder_count) {
    ::StorageDkgRound1State* state = nullptr;
    StorageBuffer package{};
    const int32_t code = storage_dkg_part1(holder, holder_count, &state, &package);
    if (code != STORAGE_OK) {
        return failure<StorageDkgRound1>(status_from(code));
    }
    return success(StorageDkgRound1(state, take_buffer(package)));
}

StorageResult<StorageDkgRound1> StorageThreshold::dkg_rotation_part1(StorageHolderId holder,
                                                                     uint16_t holder_count) {
    ::StorageDkgRound1State* state = nullptr;
    StorageBuffer package{};
    const int32_t code = storage_dkg_rotation_part1(holder, holder_count, &state, &package);
    if (code != STORAGE_OK) {
        return failure<StorageDkgRound1>(status_from(code));
    }
    return success(StorageDkgRound1(state, take_buffer(package)));
}

StorageResult<StorageDkgRound2> StorageThreshold::dkg_part2(
    StorageDkgRound1&& round1, const StoragePeerBytesMap& round1_packages) {
    ::StorageDkgRound1State* state = round1.release();
    if (state == nullptr) {
        return failure<StorageDkgRound2>(StorageStatus::InvalidArgument);
    }
    const auto inputs = to_peer_bytes(round1_packages);
    ::StorageDkgRound2State* next = nullptr;
    StoragePeerBuffer* outputs = nullptr;
    size_t output_count = 0;
    // The C call consumes `state` on every return path.
    const int32_t code =
        storage_dkg_part2(state, inputs.data(), inputs.size(), &next, &outputs, &output_count);
    if (code != STORAGE_OK) {
        return failure<StorageDkgRound2>(status_from(code));
    }
    return success(StorageDkgRound2(next, take_peer_buffers(outputs, output_count)));
}

StorageResult<StorageKeyOutcome> StorageThreshold::dkg_part3(
    StorageDkgRound2&& round2, const StoragePeerBytesMap& round1_packages,
    const StoragePeerBytesMap& round2_packages) {
    ::StorageDkgRound2State* state = round2.release();
    if (state == nullptr) {
        return failure<StorageKeyOutcome>(StorageStatus::InvalidArgument);
    }
    const auto r1 = to_peer_bytes(round1_packages);
    const auto r2 = to_peer_bytes(round2_packages);
    ::StorageShare* share = nullptr;
    StorageKeyOutcome outcome;
    StorageBuffer plan{};
    const int32_t code = storage_dkg_part3(state, r1.data(), r1.size(), r2.data(), r2.size(),
                                           &share, outcome.storage_public_key.data(), &plan);
    if (code != STORAGE_OK) {
        return failure<StorageKeyOutcome>(status_from(code));
    }
    outcome.share = StorageKeyShare(share);
    outcome.plan = take_buffer(plan);
    return success(std::move(outcome));
}

StorageResult<StorageRefreshRound1> StorageThreshold::refresh_part1(const StorageKeyShare& current,
                                                                    uint16_t new_holder_count) {
    if (!current.valid()) {
        return failure<StorageRefreshRound1>(StorageStatus::InvalidArgument);
    }
    ::StorageRefreshRound1State* state = nullptr;
    StorageBuffer package{};
    const int32_t code = storage_refresh_part1(current.raw(), new_holder_count, &state, &package);
    if (code != STORAGE_OK) {
        return failure<StorageRefreshRound1>(status_from(code));
    }
    return success(StorageRefreshRound1(state, take_buffer(package)));
}

StorageResult<StorageRefreshRound2> StorageThreshold::refresh_part2(
    StorageRefreshRound1&& round1, const StoragePeerBytesMap& round1_packages) {
    ::StorageRefreshRound1State* state = round1.release();
    if (state == nullptr) {
        return failure<StorageRefreshRound2>(StorageStatus::InvalidArgument);
    }
    const auto inputs = to_peer_bytes(round1_packages);
    ::StorageRefreshRound2State* next = nullptr;
    StoragePeerBuffer* outputs = nullptr;
    size_t output_count = 0;
    // The C call consumes `state` on every return path.
    const int32_t code = storage_refresh_part2(state, inputs.data(), inputs.size(), &next,
                                               &outputs, &output_count);
    if (code != STORAGE_OK) {
        return failure<StorageRefreshRound2>(status_from(code));
    }
    return success(StorageRefreshRound2(next, take_peer_buffers(outputs, output_count)));
}

StorageResult<StorageKeyOutcome> StorageThreshold::refresh_part3(
    StorageRefreshRound2&& round2, const StoragePeerBytesMap& round1_packages,
    const StoragePeerBytesMap& round2_packages, const StorageKeyShare& current,
    std::span<const uint8_t> old_plan) {
    ::StorageRefreshRound2State* state = round2.release();
    if (state == nullptr || !current.valid()) {
        storage_refresh_round2_state_free(state);
        return failure<StorageKeyOutcome>(StorageStatus::InvalidArgument);
    }
    const auto r1 = to_peer_bytes(round1_packages);
    const auto r2 = to_peer_bytes(round2_packages);
    ::StorageShare* share = nullptr;
    StorageBuffer plan{};
    // The C call consumes `state` on every return path.
    const int32_t code =
        storage_refresh_part3(state, r1.data(), r1.size(), r2.data(), r2.size(), current.raw(),
                              old_plan.data(), old_plan.size(), &share, &plan);
    if (code != STORAGE_OK) {
        return failure<StorageKeyOutcome>(status_from(code));
    }
    StorageKeyOutcome outcome;
    outcome.share = StorageKeyShare(share);
    outcome.plan = take_buffer(plan);
    auto key = outcome.share.storage_public_key();
    if (!key) {
        return failure<StorageKeyOutcome>(StorageStatus::Internal);
    }
    outcome.storage_public_key = *key;
    return success(std::move(outcome));
}

StorageResult<StoragePeerBytesMap> StorageThreshold::repair_part1(
    const StorageKeyShare& helper, std::span<const uint8_t> plan,
    std::span<const StorageHolderId> helpers, StorageHolderId new_holder) {
    if (!helper.valid()) {
        return failure<StoragePeerBytesMap>(StorageStatus::InvalidArgument);
    }
    StoragePeerBuffer* outputs = nullptr;
    size_t output_count = 0;
    const int32_t code =
        storage_repair_part1(helper.raw(), plan.data(), plan.size(), helpers.data(),
                             helpers.size(), new_holder, &outputs, &output_count);
    if (code != STORAGE_OK) {
        return failure<StoragePeerBytesMap>(status_from(code));
    }
    return success(take_peer_buffers(outputs, output_count));
}

StorageResult<StorageBytes> StorageThreshold::repair_part2(const StorageKeyShare& helper,
                                                           const StoragePeerBytesMap& deltas) {
    if (!helper.valid()) {
        return failure<StorageBytes>(StorageStatus::InvalidArgument);
    }
    const auto inputs = to_peer_bytes(deltas);
    StorageBytes sigma(32);
    const int32_t code =
        storage_repair_part2(helper.raw(), inputs.data(), inputs.size(), sigma.data());
    if (code != STORAGE_OK) {
        return failure<StorageBytes>(status_from(code));
    }
    return success(std::move(sigma));
}

StorageResult<StorageKeyShare> StorageThreshold::repair_part3(std::span<const uint8_t> plan,
                                                              StorageHolderId new_holder,
                                                              const StoragePeerBytesMap& sigmas) {
    const auto inputs = to_peer_bytes(sigmas);
    ::StorageShare* share = nullptr;
    const int32_t code = storage_repair_part3(plan.data(), plan.size(), new_holder,
                                              inputs.data(), inputs.size(), &share);
    if (code != STORAGE_OK) {
        return failure<StorageKeyShare>(status_from(code));
    }
    return success(StorageKeyShare(share));
}

StorageResult<StoragePartial> StorageThreshold::create_partial(const StorageKeyShare& share,
                                                               std::span<const uint8_t> plan,
                                                               const StorageUnlockContext& context,
                                                               const StoragePoint& ephemeral_point) {
    if (!share.valid()) {
        return failure<StoragePartial>(StorageStatus::InvalidArgument);
    }
    const auto c_context = to_c(context);
    StoragePartial partial{};
    const int32_t code = storage_partial_create(share.raw(), plan.data(), plan.size(), &c_context,
                                                ephemeral_point.data(), partial.data());
    if (code != STORAGE_OK) {
        return failure<StoragePartial>(status_from(code));
    }
    return success(partial);
}

StorageStatus StorageThreshold::verify_partial(std::span<const uint8_t> plan,
                                               const StorageUnlockContext& context,
                                               const StoragePoint& ephemeral_point,
                                               StorageHolderId holder,
                                               std::span<const uint8_t> partial) {
    const auto c_context = to_c(context);
    return status_from(storage_partial_verify(plan.data(), plan.size(), &c_context,
                                              ephemeral_point.data(), holder, partial.data(),
                                              partial.size()));
}

StorageResult<StorageWrappedDataKey> StorageThreshold::wrap_data_key(
    SodiumCryptoService& crypto, const StoragePoint& storage_public_key,
    std::span<const uint8_t> data_key, std::span<const uint8_t> server_id) {
    if (data_key.empty() || data_key.size() > kMaxDataKeySize || server_id.empty() ||
        server_id.size() > kMaxServerIdSize) {
        return failure<StorageWrappedDataKey>(StorageStatus::InvalidArgument);
    }
    try {
        SecureBuffer shared(STORAGE_POINT_LEN);
        StorageWrappedDataKey wrapped;
        wrapped.storage_public_key = storage_public_key;
        const int32_t code = storage_encapsulate(storage_public_key.data(),
                                                 wrapped.ephemeral_point.data(), shared.data());
        if (code != STORAGE_OK) {
            return failure<StorageWrappedDataKey>(status_from(code));
        }
        AeadKey key{};
        WipeOnExit wipe_key(key.data(), key.size());
        derive_wrap_key(crypto, shared.span(), storage_public_key, wrapped.ephemeral_point,
                        server_id, key);
        shared.clear();
        wrapped.ciphertext = crypto.aead_encrypt(
            key, data_key, wrap_aad(storage_public_key, wrapped.ephemeral_point, server_id));
        return success(std::move(wrapped));
    } catch (const std::exception&) {
        return failure<StorageWrappedDataKey>(StorageStatus::Internal);
    }
}

StorageResult<SecureBuffer> StorageThreshold::unwrap_data_key(
    SodiumCryptoService& crypto, const StorageWrappedDataKey& wrapped,
    std::span<const uint8_t> plan, const StorageUnlockContext& context,
    const StoragePeerBytesMap& partials, std::span<const uint8_t> server_id) {
    if (server_id.empty() || server_id.size() > kMaxServerIdSize) {
        return failure<SecureBuffer>(StorageStatus::InvalidArgument);
    }
    auto info = validate_plan(plan);
    if (!info.ok()) {
        return failure<SecureBuffer>(info.status);
    }
    if (info.value->storage_public_key != wrapped.storage_public_key) {
        return failure<SecureBuffer>(StorageStatus::InvalidArgument);
    }
    try {
        const auto inputs = to_peer_bytes(partials);
        const auto c_context = to_c(context);
        SecureBuffer shared(STORAGE_POINT_LEN);
        const int32_t code =
            storage_combine(plan.data(), plan.size(), &c_context, wrapped.ephemeral_point.data(),
                            inputs.data(), inputs.size(), shared.data());
        if (code != STORAGE_OK) {
            return failure<SecureBuffer>(status_from(code));
        }
        AeadKey key{};
        WipeOnExit wipe_key(key.data(), key.size());
        derive_wrap_key(crypto, shared.span(), wrapped.storage_public_key,
                        wrapped.ephemeral_point, server_id, key);
        shared.clear();
        auto plaintext = crypto.aead_decrypt(
            key, wrapped.ciphertext,
            wrap_aad(wrapped.storage_public_key, wrapped.ephemeral_point, server_id));
        if (!plaintext) {
            return failure<SecureBuffer>(StorageStatus::CryptoFailure);
        }
        SecureBuffer data_key(*plaintext);
        sodium_memzero(plaintext->data(), plaintext->size());
        return success(std::move(data_key));
    } catch (const std::exception&) {
        return failure<SecureBuffer>(StorageStatus::Internal);
    }
}

StorageResult<StoragePlanInfo> StorageThreshold::validate_plan(std::span<const uint8_t> plan) {
    StoragePlanInfo info;
    int32_t code = storage_plan_validate(plan.data(), plan.size(), &info.holder_count,
                                         &info.threshold, info.storage_public_key.data());
    if (code != STORAGE_OK) {
        return failure<StoragePlanInfo>(status_from(code));
    }
    info.holders.resize(kMaxHolders);
    size_t count = 0;
    code = storage_plan_holders(plan.data(), plan.size(), info.holders.data(), info.holders.size(),
                                &count);
    if (code != STORAGE_OK) {
        return failure<StoragePlanInfo>(status_from(code));
    }
    info.holders.resize(count);
    return success(std::move(info));
}

StorageResult<StoragePoint> StorageThreshold::plan_commitment(std::span<const uint8_t> plan,
                                                              StorageHolderId holder) {
    StoragePoint commitment{};
    const int32_t code =
        storage_plan_commitment(plan.data(), plan.size(), holder, commitment.data());
    if (code != STORAGE_OK) {
        return failure<StoragePoint>(status_from(code));
    }
    return success(commitment);
}

StorageResult<SecureBuffer> StorageThreshold::serialize_share(const StorageKeyShare& share) {
    if (!share.valid()) {
        return failure<SecureBuffer>(StorageStatus::InvalidArgument);
    }
    StorageBuffer buffer{};
    const int32_t code = storage_share_serialize(share.raw(), &buffer);
    if (code != STORAGE_OK) {
        return failure<SecureBuffer>(status_from(code));
    }
    try {
        SecureBuffer secure(std::span<const uint8_t>(buffer.data, buffer.len));
        storage_buffer_free(&buffer);
        return success(std::move(secure));
    } catch (const std::exception&) {
        storage_buffer_free(&buffer);
        return failure<SecureBuffer>(StorageStatus::Internal);
    }
}

StorageResult<StorageKeyShare> StorageThreshold::deserialize_share(std::span<const uint8_t> bytes) {
    ::StorageShare* share = nullptr;
    const int32_t code = storage_share_deserialize(bytes.data(), bytes.size(), &share);
    if (code != STORAGE_OK) {
        return failure<StorageKeyShare>(status_from(code));
    }
    return success(StorageKeyShare(share));
}

}  // namespace nexus::crypto
