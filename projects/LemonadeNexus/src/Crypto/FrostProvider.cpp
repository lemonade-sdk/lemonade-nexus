#include <LemonadeNexus/Crypto/FrostProvider.hpp>

#include <frost_ffi.h>

#include <algorithm>
#include <utility>

namespace nexus::crypto {

namespace {

FrostStatus status_from(int32_t code) {
    switch (code) {
        case FROST_OK:
            return FrostStatus::Ok;
        case FROST_ERR_INVALID_ARGUMENT:
            return FrostStatus::InvalidArgument;
        case FROST_ERR_CRYPTO:
            return FrostStatus::CryptoFailure;
        case FROST_ERR_SERIALIZATION:
            return FrostStatus::Serialization;
        default:
            return FrostStatus::Internal;
    }
}

template <typename T>
FrostResult<T> failure(FrostStatus status) {
    FrostResult<T> result;
    result.status = status;
    return result;
}

// Copies a Rust buffer out and releases it; the Rust side wipes on free.
FrostBytes take_buffer(FrostBuffer& buffer) {
    FrostBytes bytes(buffer.data, buffer.data + buffer.len);
    frost_buffer_free(&buffer);
    return bytes;
}

std::vector<FrostPeerBytes> to_peer_bytes(const FrostPeerBytesMap& map) {
    std::vector<FrostPeerBytes> out;
    out.reserve(map.size());
    for (const auto& [identifier, bytes] : map) {
        out.push_back(FrostPeerBytes{identifier, bytes.data(), bytes.size()});
    }
    return out;
}

}  // namespace

// --- FrostKeyShare ----------------------------------------------------------

FrostKeyShare::FrostKeyShare(FrostKeyShare&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)) {}

FrostKeyShare& FrostKeyShare::operator=(FrostKeyShare&& other) noexcept {
    if (this != &other) {
        frost_key_package_free(handle_);
        handle_ = std::exchange(other.handle_, nullptr);
    }
    return *this;
}

FrostKeyShare::~FrostKeyShare() { frost_key_package_free(handle_); }

std::optional<ParticipantIndex> FrostKeyShare::identifier() const {
    if (handle_ == nullptr) {
        return std::nullopt;
    }
    uint16_t identifier = 0;
    if (frost_key_package_identifier(handle_, &identifier) != FROST_OK) {
        return std::nullopt;
    }
    return identifier;
}

// --- FrostNonces ------------------------------------------------------------

FrostNonces::FrostNonces(FrostNonces&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)) {}

FrostNonces& FrostNonces::operator=(FrostNonces&& other) noexcept {
    if (this != &other) {
        frost_signing_nonces_free(handle_);
        handle_ = std::exchange(other.handle_, nullptr);
    }
    return *this;
}

FrostNonces::~FrostNonces() { frost_signing_nonces_free(handle_); }

::FrostSigningNonces* FrostNonces::release() { return std::exchange(handle_, nullptr); }

// --- FrostDkgRound1 ---------------------------------------------------------

FrostDkgRound1::FrostDkgRound1(FrostDkgRound1&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)), package_(std::move(other.package_)) {}

FrostDkgRound1& FrostDkgRound1::operator=(FrostDkgRound1&& other) noexcept {
    if (this != &other) {
        frost_dkg_round1_state_free(handle_);
        handle_ = std::exchange(other.handle_, nullptr);
        package_ = std::move(other.package_);
    }
    return *this;
}

FrostDkgRound1::~FrostDkgRound1() { frost_dkg_round1_state_free(handle_); }

::FrostDkgRound1State* FrostDkgRound1::release() { return std::exchange(handle_, nullptr); }

// --- FrostDkgRound2 ---------------------------------------------------------

FrostDkgRound2::FrostDkgRound2(FrostDkgRound2&& other) noexcept
    : handle_(std::exchange(other.handle_, nullptr)), packages_(std::move(other.packages_)) {}

FrostDkgRound2& FrostDkgRound2::operator=(FrostDkgRound2&& other) noexcept {
    if (this != &other) {
        frost_dkg_round2_state_free(handle_);
        handle_ = std::exchange(other.handle_, nullptr);
        packages_ = std::move(other.packages_);
    }
    return *this;
}

FrostDkgRound2::~FrostDkgRound2() { frost_dkg_round2_state_free(handle_); }

::FrostDkgRound2State* FrostDkgRound2::release() { return std::exchange(handle_, nullptr); }

// --- FrostProvider ----------------------------------------------------------

FrostResult<FrostDkgRound1> FrostProvider::dkg_part1(ParticipantIndex identifier,
                                                     uint16_t max_signers,
                                                     uint16_t min_signers) {
    ::FrostDkgRound1State* state = nullptr;
    FrostBuffer package{};
    const int32_t code = frost_dkg_part1(identifier, max_signers, min_signers, &state, &package);
    if (code != FROST_OK) {
        return failure<FrostDkgRound1>(status_from(code));
    }
    FrostResult<FrostDkgRound1> result;
    result.status = FrostStatus::Ok;
    result.value.emplace(state, take_buffer(package));
    return result;
}

FrostResult<FrostDkgRound2> FrostProvider::dkg_part2(FrostDkgRound1&& round1,
                                                     const FrostPeerBytesMap& round1_packages) {
    ::FrostDkgRound1State* state = round1.release();
    if (state == nullptr) {
        return failure<FrostDkgRound2>(FrostStatus::InvalidArgument);
    }
    const auto inputs = to_peer_bytes(round1_packages);

    ::FrostDkgRound2State* next = nullptr;
    FrostPeerBuffer* outputs = nullptr;
    size_t output_count = 0;
    // The C call consumes `state` on every return path.
    const int32_t code = frost_dkg_part2(state, inputs.data(), inputs.size(), &next, &outputs,
                                         &output_count);
    if (code != FROST_OK) {
        return failure<FrostDkgRound2>(status_from(code));
    }

    FrostPeerBytesMap packages;
    for (size_t i = 0; i < output_count; ++i) {
        packages[outputs[i].identifier] =
            FrostBytes(outputs[i].buffer.data, outputs[i].buffer.data + outputs[i].buffer.len);
    }
    frost_peer_buffers_free(outputs, output_count);

    FrostResult<FrostDkgRound2> result;
    result.status = FrostStatus::Ok;
    result.value.emplace(next, std::move(packages));
    return result;
}

FrostResult<FrostDkgOutcome> FrostProvider::dkg_part3(FrostDkgRound2&& round2,
                                                      const FrostPeerBytesMap& round1_packages,
                                                      const FrostPeerBytesMap& round2_packages) {
    ::FrostDkgRound2State* state = round2.release();
    if (state == nullptr) {
        return failure<FrostDkgOutcome>(FrostStatus::InvalidArgument);
    }
    const auto round1 = to_peer_bytes(round1_packages);
    const auto round2_inputs = to_peer_bytes(round2_packages);

    ::FrostKeyPackage* key_package = nullptr;
    Ed25519PublicKey group_key{};
    FrostBuffer public_key_package{};
    const int32_t code = frost_dkg_part3(state, round1.data(), round1.size(), round2_inputs.data(),
                                         round2_inputs.size(), &key_package, group_key.data(),
                                         &public_key_package);
    if (code != FROST_OK) {
        return failure<FrostDkgOutcome>(status_from(code));
    }

    FrostResult<FrostDkgOutcome> result;
    result.status = FrostStatus::Ok;
    result.value.emplace();
    result.value->key_share = FrostKeyShare(key_package);
    result.value->group_public_key = group_key;
    result.value->public_key_package = take_buffer(public_key_package);
    return result;
}

FrostResult<FrostCommitment> FrostProvider::signing_commit(const FrostKeyShare& share) {
    if (!share.valid()) {
        return failure<FrostCommitment>(FrostStatus::InvalidArgument);
    }
    ::FrostSigningNonces* nonces = nullptr;
    FrostBuffer commitments{};
    const int32_t code = frost_signing_commit(share.raw(), &nonces, &commitments);
    if (code != FROST_OK) {
        return failure<FrostCommitment>(status_from(code));
    }
    FrostResult<FrostCommitment> result;
    result.status = FrostStatus::Ok;
    result.value.emplace();
    result.value->nonces = FrostNonces(nonces);
    result.value->commitments = take_buffer(commitments);
    return result;
}

FrostResult<FrostBytes> FrostProvider::sign(const FrostKeyShare& share, FrostNonces&& nonces,
                                            std::span<const uint8_t> message,
                                            const FrostPeerBytesMap& commitments) {
    ::FrostSigningNonces* raw_nonces = nonces.release();
    if (!share.valid() || raw_nonces == nullptr) {
        frost_signing_nonces_free(raw_nonces);
        return failure<FrostBytes>(FrostStatus::InvalidArgument);
    }
    const auto inputs = to_peer_bytes(commitments);

    FrostBuffer signature_share{};
    // The C call consumes `raw_nonces` on every return path.
    const int32_t code = frost_sign(share.raw(), raw_nonces, message.data(), message.size(),
                                    inputs.data(), inputs.size(), &signature_share);
    if (code != FROST_OK) {
        return failure<FrostBytes>(status_from(code));
    }
    FrostResult<FrostBytes> result;
    result.status = FrostStatus::Ok;
    result.value = take_buffer(signature_share);
    return result;
}

FrostResult<Ed25519Signature> FrostProvider::aggregate(std::span<const uint8_t> message,
                                                       const FrostPeerBytesMap& commitments,
                                                       const FrostPeerBytesMap& signature_shares,
                                                       std::span<const uint8_t> public_key_package) {
    const auto commitment_inputs = to_peer_bytes(commitments);
    const auto share_inputs = to_peer_bytes(signature_shares);

    Ed25519Signature signature{};
    const int32_t code = frost_aggregate(message.data(), message.size(), commitment_inputs.data(),
                                         commitment_inputs.size(), share_inputs.data(),
                                         share_inputs.size(), public_key_package.data(),
                                         public_key_package.size(), signature.data());
    if (code != FROST_OK) {
        return failure<Ed25519Signature>(status_from(code));
    }
    FrostResult<Ed25519Signature> result;
    result.status = FrostStatus::Ok;
    result.value = signature;
    return result;
}

bool FrostProvider::verify(const Ed25519PublicKey& group_public_key,
                           std::span<const uint8_t> message,
                           const Ed25519Signature& signature) {
    return frost_verify(group_public_key.data(), message.data(), message.size(),
                        signature.data()) == FROST_OK;
}

}  // namespace nexus::crypto
