#include <LemonadeNexus/Security/Storage/DataKeyService.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/DurableWrite.hpp>
#include <LemonadeNexus/Security/Storage/StorageKeyService.hpp>
#include <LemonadeNexus/Security/Transport/PairwiseSeal.hpp>

#include <nlohmann/json.hpp>
#include <sodium.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <sstream>

namespace nexus::security {

namespace {

using json = nlohmann::json;

constexpr int kFileFormat = 1;
constexpr std::size_t kDataKeyBytes = 32;
// Liveness pacing of unlock attempts. Never part of any validity rule.
constexpr uint64_t kAttemptTimeoutMs = 15'000;
constexpr uint64_t kFirstBackoffMs = 5'000;
constexpr uint64_t kMaxBackoffMs = 60'000;
constexpr uint64_t kClaimResendMs = 5'000;

StorageWrapRef wrap_ref(const crypto::StorageWrappedDataKey& wrapped) {
    return StorageWrapRef{wrapped.storage_public_key, wrapped.ephemeral_point};
}

std::string short_hex(std::span<const uint8_t> bytes) {
    return crypto::to_hex(bytes.first(std::min<std::size_t>(bytes.size(), 6)));
}

}  // namespace

DataKeyService::DataKeyService(StorageKeyService& service)
    : service_(service),
      path_(service.config().directory / "data-key.json"),
      next_path_(service.config().directory / "data-key.next.json") {}

DataKeyState DataKeyService::state() const {
    std::lock_guard lock(mutex_);
    return state_;
}

std::optional<crypto::SecureBuffer> DataKeyService::data_key() const {
    std::lock_guard lock(mutex_);
    if (state_ != DataKeyState::Unlocked || !dek_.has_value()) {
        return std::nullopt;
    }
    return crypto::SecureBuffer(dek_->span());
}

bool DataKeyService::unlock_verified() const {
    std::lock_guard lock(mutex_);
    return verified_;
}

std::optional<StoragePointBytes> DataKeyService::wrapped_to() const {
    std::lock_guard lock(mutex_);
    if (!wrapped_.has_value()) {
        return std::nullopt;
    }
    return wrapped_->storage_public_key;
}

std::optional<StoragePointBytes> DataKeyService::staged_to() const {
    std::lock_guard lock(mutex_);
    if (!next_wrapped_.has_value()) {
        return std::nullopt;
    }
    return next_wrapped_->storage_public_key;
}

bool DataKeyService::claimed(const crypto::StorageWrappedDataKey& wrapped) const {
    return storage_wrap_claimed(service_.chain(), service_.config().self, wrap_ref(wrapped));
}

void DataKeyService::maintain_claim(uint64_t now_ms) {
    std::vector<StorageWrapRef> wraps;
    {
        std::lock_guard lock(mutex_);
        if (wrapped_.has_value()) {
            wraps.push_back(wrap_ref(*wrapped_));
        }
        if (next_wrapped_.has_value()) {
            wraps.push_back(wrap_ref(*next_wrapped_));
        }
    }
    // Only wraps on a live S can be claimed. A committed wrap whose S already
    // ended opens nothing, so a staged rewrap is claimed without it.
    const auto& chain = service_.chain();
    std::erase_if(wraps, [&](const StorageWrapRef& wrap) {
        const bool current = chain.current.has_value() &&
                             wrap.storage_public_key == chain.current->storage_public_key;
        const bool retiring = chain.retiring.has_value() && service_.retiring_live() &&
                              wrap.storage_public_key == chain.retiring->storage_public_key;
        return !current && !retiring;
    });
    if (wraps.empty()) {
        return;
    }
    const auto finalized = chain.wrap_claims.find(service_.config().self);
    if (finalized != chain.wrap_claims.end() && finalized->second.wraps == wraps) {
        claim_.reset();
        return;
    }
    if (!claim_.has_value() || claim_->wraps != wraps) {
        StorageWrapClaim claim;
        claim.node = service_.config().self;
        claim.wraps = std::move(wraps);
        // Strictly above every claim this server made before: the counter of
        // its finalized claim, the claim it last signed, and the wall clock.
        uint64_t counter = service_.config().wall_clock_ms ? service_.config().wall_clock_ms() : 0;
        if (finalized != chain.wrap_claims.end()) {
            counter = std::max(counter, finalized->second.counter + 1);
        }
        if (claim_.has_value()) {
            counter = std::max(counter, claim_->counter + 1);
        }
        claim.counter = counter;
        sign_storage_wrap_claim(service_.config().network_id, claim,
                                service_.config().identity.private_key);
        claim_ = std::move(claim);
        claim_sent_ms_ = 0;
    }
    if (claim_sent_ms_ == 0 || now_ms - claim_sent_ms_ >= kClaimResendMs) {
        service_.submit_wrap_claim(*claim_);
        claim_sent_ms_ = std::max<uint64_t>(now_ms, 1);
    }
}

void DataKeyService::set_state_callback(std::function<void(DataKeyState)> callback) {
    on_state_ = std::move(callback);
}

std::optional<Digest> DataKeyService::live_request() const {
    if (!attempt_.has_value()) {
        return std::nullopt;
    }
    return attempt_->request_digest;
}

void DataKeyService::set_state(DataKeyState next) {
    {
        std::lock_guard lock(mutex_);
        if (state_ == next) {
            return;
        }
        state_ = next;
    }
    if (on_state_) {
        on_state_(next);
    }
}

std::vector<uint8_t> DataKeyService::server_id() const {
    const auto& self = service_.config().self.bytes;
    return {self.begin(), self.end()};
}

std::string DataKeyService::encode_wrapped(const crypto::StorageWrappedDataKey& wrapped) {
    json j;
    j["format"] = kFileFormat;
    j["storage_public_key"] = crypto::to_base64(wrapped.storage_public_key);
    j["ephemeral_point"] = crypto::to_base64(wrapped.ephemeral_point);
    j["version"] = static_cast<unsigned>(wrapped.ciphertext.version);
    j["nonce"] = crypto::to_base64(wrapped.ciphertext.nonce);
    j["ciphertext"] = crypto::to_base64(wrapped.ciphertext.ciphertext);
    return j.dump();
}

std::optional<crypto::StorageWrappedDataKey> DataKeyService::decode_wrapped(
        const std::string& text) {
    const json j = json::parse(text, nullptr, false);
    if (!j.is_object() || !j.contains("format") || j["format"] != kFileFormat) {
        return std::nullopt;
    }
    for (const char* field : {"storage_public_key", "ephemeral_point", "nonce", "ciphertext"}) {
        if (!j.contains(field) || !j[field].is_string()) {
            return std::nullopt;
        }
    }
    if (!j.contains("version") || j["version"] != crypto::kEncryptedBlobVersion) {
        return std::nullopt;
    }
    crypto::StorageWrappedDataKey wrapped;
    const auto key = crypto::from_base64(j["storage_public_key"].get<std::string>());
    const auto point = crypto::from_base64(j["ephemeral_point"].get<std::string>());
    if (key.size() != wrapped.storage_public_key.size() ||
        point.size() != wrapped.ephemeral_point.size()) {
        return std::nullopt;
    }
    std::copy(key.begin(), key.end(), wrapped.storage_public_key.begin());
    std::copy(point.begin(), point.end(), wrapped.ephemeral_point.begin());
    wrapped.ciphertext.version = crypto::kEncryptedBlobVersion;
    wrapped.ciphertext.nonce = crypto::from_base64(j["nonce"].get<std::string>());
    wrapped.ciphertext.ciphertext = crypto::from_base64(j["ciphertext"].get<std::string>());
    if (wrapped.ciphertext.nonce.size() != crypto::kAeadNonceSize ||
        wrapped.ciphertext.ciphertext.empty()) {
        return std::nullopt;
    }
    return wrapped;
}

bool DataKeyService::store(const crypto::StorageWrappedDataKey& wrapped) {
    std::error_code ec;
    std::filesystem::create_directories(path_.parent_path(), ec);
    if (!write_durable(path_, encode_wrapped(wrapped))) {
        return false;
    }
    std::lock_guard lock(mutex_);
    wrapped_ = wrapped;
    return true;
}

bool DataKeyService::load() {
    std::error_code ec;
    if (std::filesystem::exists(next_path_, ec)) {
        // A replacement or a rewrap that was never committed. The current
        // wrapped key and the files under it still stand.
        spdlog::info("[storage] discarding an uncommitted staged data key");
        std::filesystem::remove(next_path_, ec);
    }
    std::ifstream in(path_, std::ios::binary);
    if (!in) {
        return true;  // none stored yet
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    auto wrapped = decode_wrapped(buffer.str());
    if (!wrapped.has_value()) {
        return false;
    }
    std::lock_guard lock(mutex_);
    wrapped_ = std::move(*wrapped);
    return true;
}

void DataKeyService::request_verification() {
    {
        std::lock_guard lock(mutex_);
        verified_ = false;
    }
    // A round trip already in flight started before this request; it does not
    // count.
    if (attempt_.has_value() && attempt_->target == Target::Current && attempt_->verify_only) {
        attempt_.reset();
    }
    next_attempt_ms_ = now_ms_;
}

bool DataKeyService::begin_replacement() {
    const auto& chain = service_.chain();
    if (!chain.current.has_value() || !service_.current_verified()) {
        return false;
    }
    {
        std::lock_guard lock(mutex_);
        // A replacement starts only under the current S, never beside a
        // staged rewrap.
        if (!dek_.has_value() || next_dek_.has_value() || !wrapped_.has_value() ||
            wrapped_->storage_public_key != chain.current->storage_public_key) {
            return false;
        }
    }
    crypto::SecureBuffer dek(kDataKeyBytes);
    randombytes_buf(dek.data(), dek.size());
    auto wrapped = crypto::StorageThreshold::wrap_data_key(
        service_.crypto(), chain.current->storage_public_key, dek.span(), server_id());
    std::error_code ec;
    std::filesystem::create_directories(next_path_.parent_path(), ec);
    if (!wrapped.ok() || !write_durable(next_path_, encode_wrapped(*wrapped.value))) {
        spdlog::warn("[storage] the replacement data key could not be wrapped and stored");
        return false;
    }
    {
        std::lock_guard lock(mutex_);
        next_dek_ = std::move(dek);
        next_wrapped_ = *wrapped.value;
        next_verified_ = false;
        next_rewrap_ = false;
    }
    next_attempt_ms_ = now_ms_;
    spdlog::info("[storage] replacement data key created and wrapped to S {}",
                 short_hex(chain.current->storage_public_key));
    return true;
}

std::optional<crypto::SecureBuffer> DataKeyService::replacement_key() const {
    std::lock_guard lock(mutex_);
    if (!next_dek_.has_value() || next_rewrap_) {
        return std::nullopt;
    }
    return crypto::SecureBuffer(next_dek_->span());
}

bool DataKeyService::replacement_verified() const {
    std::lock_guard lock(mutex_);
    return next_dek_.has_value() && !next_rewrap_ && next_verified_;
}

bool DataKeyService::commit_replacement() {
    {
        std::lock_guard lock(mutex_);
        if (next_rewrap_) {
            return false;
        }
    }
    if (!commit_staged()) {
        return false;
    }
    spdlog::info("[storage] replacement data key committed");
    return true;
}

bool DataKeyService::commit_staged() {
    std::optional<crypto::StorageWrappedDataKey> next;
    {
        std::lock_guard lock(mutex_);
        if (!next_dek_.has_value() || !next_wrapped_.has_value() || !next_verified_) {
            return false;
        }
        next = next_wrapped_;
    }
    // The durable replacement of data-key.json is the switch point. A crash
    // after it leaves data-key.next.json with the same key; load() removes it.
    if (!write_durable(path_, encode_wrapped(*next))) {
        return false;
    }
    std::error_code ec;
    std::filesystem::remove(next_path_, ec);
    {
        std::lock_guard lock(mutex_);
        dek_ = std::move(next_dek_);
        wrapped_ = std::move(next_wrapped_);
        verified_ = true;
        next_dek_.reset();
        next_wrapped_.reset();
        next_verified_ = false;
        next_rewrap_ = false;
    }
    if (attempt_.has_value() && attempt_->target == Target::Replacement) {
        attempt_.reset();
    }
    return true;
}

void DataKeyService::abort_replacement() {
    {
        std::lock_guard lock(mutex_);
        if (next_rewrap_) {
            return;  // a staged rewrap is not the vault's replacement
        }
    }
    discard_staged();
}

void DataKeyService::discard_staged() {
    std::error_code ec;
    std::filesystem::remove(next_path_, ec);
    {
        std::lock_guard lock(mutex_);
        next_dek_.reset();
        next_wrapped_.reset();
        next_verified_ = false;
        next_rewrap_ = false;
    }
    if (attempt_.has_value() && attempt_->target == Target::Replacement) {
        attempt_.reset();
    }
}

void DataKeyService::on_chain_changed() {
    // The live attempt may name a plan that is no longer live; the next tick
    // decides with the new chain.
    if (attempt_.has_value()) {
        const auto& chain = service_.chain();
        const bool still_live =
            attempt_->plan_digest == chain.current_digest ||
            (service_.retiring_live() && attempt_->plan_digest == chain.retiring_digest);
        if (!still_live) {
            attempt_.reset();
            next_attempt_ms_ = now_ms_;
        }
    }
}

void DataKeyService::tick(uint64_t now_ms) {
    now_ms_ = now_ms;
    if (!loaded_) {
        if (!load()) {
            // A damaged wrapped key is not replaced with a new DEK: that would
            // orphan whatever Phase 7 encrypted. It stays locked.
            spdlog::error("[storage] the wrapped data key does not load; the data key stays "
                          "locked");
            loaded_ = true;
            set_state(DataKeyState::Locked);
            return;
        }
        loaded_ = true;
    }
    const auto& chain = service_.chain();
    if (!chain.current.has_value()) {
        set_state(DataKeyState::NoStorageKey);
        return;
    }
    std::optional<crypto::StorageWrappedDataKey> wrapped;
    bool in_memory = false;
    {
        std::lock_guard lock(mutex_);
        wrapped = wrapped_;
        in_memory = dek_.has_value();
    }
    if (!wrapped.has_value()) {
        if (service_.files_encrypted()) {
            // The files are encrypted under a DEK that only the lost wrapped
            // key opens. A new DEK would orphan them; StorageKeyService::start
            // already refuses this state, so this is the last guard.
            if (!create_refused_) {
                spdlog::error("[storage] data-key.json is missing and the files are encrypted; "
                              "no new data key is created");
                create_refused_ = true;
            }
            set_state(DataKeyState::Locked);
            return;
        }
        if (service_.current_verified()) {
            create(now_ms);
        } else {
            set_state(DataKeyState::NoStorageKey);
        }
        return;
    }

    if (attempt_.has_value() && now_ms - attempt_->started_ms >= kAttemptTimeoutMs) {
        fail_attempt();
    }

    if (in_memory) {
        set_state(DataKeyState::Unlocked);
        const bool rotated = wrapped->storage_public_key != chain.current->storage_public_key;
        if (rotated && service_.current_verified()) {
            // A rotation this server has not rewrapped for yet: stage the DEK
            // from memory under the new S. data-key.json changes only after
            // the staged wrap verifies.
            const auto staged = staged_to();
            if (!staged.has_value() || *staged != chain.current->storage_public_key) {
                if (staged.has_value()) {
                    discard_staged();
                }
                (void)rewrap();
            }
        }
        maintain_claim(now_ms);
        std::optional<crypto::StorageWrappedDataKey> next;
        bool next_verified = false;
        bool next_rewrap = false;
        {
            std::lock_guard lock(mutex_);
            next = next_wrapped_;
            next_verified = next_verified_;
            next_rewrap = next_rewrap_;
        }
        if (next.has_value()) {
            if (next->storage_public_key != chain.current->storage_public_key) {
                // S rotated under the staged wrap; a replacement restarts in
                // the vault, a rewrap restages on the next tick.
                discard_staged();
            } else if (!next_verified && (next_rewrap || unlock_verified()) &&
                       !attempt_.has_value() && now_ms >= next_attempt_ms_ && claimed(*next)) {
                start_attempt(*chain.current, chain.current_digest, true, now_ms,
                              Target::Replacement);
            }
            return;
        }
        if (!rotated && !unlock_verified() && !attempt_.has_value() &&
            now_ms >= next_attempt_ms_ && claimed(*wrapped)) {
            start_attempt(*chain.current, chain.current_digest, true, now_ms);
        }
        return;
    }

    // Locked: unlock under the plan whose S the wrapped key names, once this
    // server's claim of that wrap is finalized.
    const StorageFinalPlan* plan = nullptr;
    Digest plan_digest{};
    if (wrapped->storage_public_key == chain.current->storage_public_key) {
        plan = &*chain.current;
        plan_digest = chain.current_digest;
    } else if (chain.retiring.has_value() &&
               wrapped->storage_public_key == chain.retiring->storage_public_key) {
        if (service_.retiring_live()) {
            plan = &*chain.retiring;
            plan_digest = chain.retiring_digest;
        } else {
            set_state(DataKeyState::Retired);
            return;
        }
    }
    if (plan == nullptr) {
        // No live plan holds this S. Fail closed; a later record may still
        // name it while the chain catches up.
        set_state(DataKeyState::Locked);
        return;
    }
    set_state(DataKeyState::Locked);
    maintain_claim(now_ms);
    if (!attempt_.has_value() && now_ms >= next_attempt_ms_ && claimed(*wrapped)) {
        start_attempt(*plan, plan_digest, false, now_ms);
    }
}

void DataKeyService::create(uint64_t now_ms) {
    const auto& chain = service_.chain();
    crypto::SecureBuffer dek(kDataKeyBytes);
    randombytes_buf(dek.data(), dek.size());
    auto wrapped = crypto::StorageThreshold::wrap_data_key(
        service_.crypto(), chain.current->storage_public_key, dek.span(), server_id());
    if (!wrapped.ok() || !store(*wrapped.value)) {
        spdlog::warn("[storage] the data key could not be wrapped and stored; retrying");
        return;
    }
    {
        std::lock_guard lock(mutex_);
        dek_ = std::move(dek);
        verified_ = false;
    }
    spdlog::info("[storage] data key created and wrapped to S {}",
                 short_hex(chain.current->storage_public_key));
    set_state(DataKeyState::Unlocked);
    next_attempt_ms_ = now_ms;
}

bool DataKeyService::rewrap() {
    const auto& chain = service_.chain();
    if (!chain.current.has_value() || !service_.current_verified()) {
        return false;
    }
    std::optional<crypto::SecureBuffer> dek;
    {
        std::lock_guard lock(mutex_);
        if (!dek_.has_value() || next_dek_.has_value() || !wrapped_.has_value() ||
            wrapped_->storage_public_key == chain.current->storage_public_key) {
            return false;
        }
        dek = crypto::SecureBuffer(dek_->span());
    }
    auto wrapped = crypto::StorageThreshold::wrap_data_key(
        service_.crypto(), chain.current->storage_public_key, dek->span(), server_id());
    std::error_code ec;
    std::filesystem::create_directories(next_path_.parent_path(), ec);
    // Staged beside the stored key, as for a replacement: data-key.json keeps
    // the old wrap until the new one verifies through the holders.
    if (!wrapped.ok() || !write_durable(next_path_, encode_wrapped(*wrapped.value))) {
        spdlog::warn("[storage] the data key could not be rewrapped");
        return false;
    }
    {
        std::lock_guard lock(mutex_);
        next_dek_ = std::move(dek);
        next_wrapped_ = *wrapped.value;
        next_verified_ = false;
        next_rewrap_ = true;
    }
    if (attempt_.has_value() && attempt_->target == Target::Current) {
        attempt_.reset();
    }
    next_attempt_ms_ = now_ms_;
    spdlog::info("[storage] data key staged under S {} (epoch {}); it replaces the stored key "
                 "once the holders reproduce it",
                 short_hex(chain.current->storage_public_key),
                 service_.current_epoch().underlying());
    return true;
}

void DataKeyService::start_attempt(const StorageFinalPlan& plan, const Digest& plan_digest,
                                   bool verify_only, uint64_t now_ms, Target target) {
    const EpochId epoch = service_.current_epoch();
    if (epoch == EpochId{}) {
        return;
    }
    std::optional<crypto::StorageWrappedDataKey> wrapped;
    {
        std::lock_guard lock(mutex_);
        wrapped = target == Target::Replacement ? next_wrapped_ : wrapped_;
    }
    if (!wrapped.has_value()) {
        return;
    }
    Attempt attempt;
    attempt.target = target;
    attempt.wrapped = *wrapped;
    attempt.plan_digest = plan_digest;
    attempt.plan = plan;
    attempt.verify_only = verify_only;
    attempt.started_ms = now_ms;
    attempt.request.requester = service_.config().self;
    attempt.request.epoch = epoch;
    attempt.request.plan_digest = plan_digest;
    attempt.request.ephemeral_point = wrapped->ephemeral_point;
    randombytes_buf(attempt.request.nonce.data(), attempt.request.nonce.size());
    attempt.request_digest =
        storage_unlock_request_digest(service_.config().network_id, attempt.request);
    attempt.context = storage_unlock_attestation_context(service_.config().network_id, epoch,
                                                         plan_digest, attempt.request_digest);
    for (const auto& holder : plan.holders) {
        if (holder.node == service_.config().self) {
            // This server holds a share of the plan it unlocks under: its own
            // partial needs no attestation of itself.
            if (const auto own = service_.own_partial(plan, plan_digest, attempt.request)) {
                attempt.partials.emplace(holder.holder_id,
                                         crypto::StorageBytes(own->begin(), own->end()));
            }
            continue;
        }
        attempt.asked.insert(holder.node);
    }
    ++attempts_;
    attempt_ = std::move(attempt);
    for (const auto& node : attempt_->asked) {
        service_.send_unlock_request(node, attempt_->request);
    }
    finish_attempt();
}

void DataKeyService::on_partial(const StorageUnlockPartialMsg& partial) {
    if (!attempt_.has_value() || partial.request_digest != attempt_->request_digest ||
        !attempt_->asked.contains(partial.holder)) {
        return;
    }
    const auto holder = std::find_if(
        attempt_->plan.holders.begin(), attempt_->plan.holders.end(),
        [&](const StorageHolder& h) { return h.node == partial.holder; });
    if (holder == attempt_->plan.holders.end() || holder->holder_id != partial.holder_id ||
        attempt_->partials.contains(partial.holder_id)) {
        return;
    }
    auto opened =
        service_.sealer().unseal_bound(attempt_->request_digest, partial.sealed_partial);
    if (!opened.has_value() || opened->size() != crypto::kStoragePartialSize) {
        return;
    }
    const auto& wrapped = attempt_->wrapped;
    // Each partial is checked as it arrives: a bad DLEQ proof, a partial for
    // another R, or one from a share outside this plan never counts.
    const auto context =
        StorageKeyService::unlock_context(service_.config().network_id, attempt_->request);
    if (crypto::StorageThreshold::verify_partial(attempt_->plan.key_plan, context,
                                                 wrapped.ephemeral_point, partial.holder_id,
                                                 *opened) != crypto::StorageStatus::Ok) {
        spdlog::debug("[storage] a partial from holder {} failed verification",
                      partial.holder_id);
        return;
    }
    attempt_->partials.emplace(partial.holder_id, std::move(*opened));
    finish_attempt();
}

void DataKeyService::finish_attempt() {
    if (!attempt_.has_value() || attempt_->partials.size() < attempt_->plan.threshold) {
        return;
    }
    const auto context =
        StorageKeyService::unlock_context(service_.config().network_id, attempt_->request);
    auto unwrapped = crypto::StorageThreshold::unwrap_data_key(
        service_.crypto(), attempt_->wrapped, attempt_->plan.key_plan, context,
        attempt_->partials, server_id());
    const bool verify_only = attempt_->verify_only;
    const Target target = attempt_->target;
    const StoragePointBytes attempt_wrapped_key = attempt_->wrapped.storage_public_key;
    attempt_.reset();
    if (!unwrapped.ok()) {
        spdlog::warn("[storage] unwrapping the data key failed (status {})",
                     static_cast<int>(unwrapped.status));
        if (target == Target::Replacement) {
            discard_staged();
        }
        fail_attempt();
        return;
    }
    backoff_ms_ = 0;
    bool matches = true;
    bool commit_rewrap = false;
    {
        std::lock_guard lock(mutex_);
        if (target == Target::Replacement) {
            matches = next_dek_.has_value() && next_dek_->size() == unwrapped.value->size() &&
                      sodium_memcmp(next_dek_->data(), unwrapped.value->data(),
                                    next_dek_->size()) == 0;
            next_verified_ = matches;
            commit_rewrap = matches && next_rewrap_;
        } else if (verify_only && dek_.has_value()) {
            matches = dek_->size() == unwrapped.value->size() &&
                      sodium_memcmp(dek_->data(), unwrapped.value->data(), dek_->size()) == 0;
            verified_ = matches;
        } else if (!verify_only) {
            dek_ = std::move(*unwrapped.value);
            verified_ = true;
        }
    }
    if (!matches) {
        spdlog::error("[storage] the stored wrapped data key does not open to the data key in "
                      "memory");
        if (target == Target::Replacement) {
            // A staged wrap that does not reproduce the DEK is discarded; the
            // stored key and the files under it still stand.
            discard_staged();
        }
        fail_attempt();
        return;
    }
    if (commit_rewrap) {
        if (commit_staged()) {
            spdlog::info("[storage] data key rewrapped to S {}; the holders reproduced it",
                         short_hex(attempt_wrapped_key));
        } else {
            spdlog::warn("[storage] the verified rewrap could not replace data-key.json; "
                         "retrying");
            {
                std::lock_guard lock(mutex_);
                next_verified_ = false;
            }
            fail_attempt();
        }
        return;
    }
    if (!verify_only) {
        spdlog::info("[storage] data key unlocked through the holders");
        set_state(DataKeyState::Unlocked);
    }
}

void DataKeyService::fail_attempt() {
    attempt_.reset();
    backoff_ms_ = backoff_ms_ == 0 ? kFirstBackoffMs : std::min(backoff_ms_ * 2, kMaxBackoffMs);
    next_attempt_ms_ = now_ms_ + backoff_ms_;
}

bool DataKeyService::expects_challenge(const NodeId& holder, const Digest& context) const {
    if (!attempt_.has_value() || !attempt_->asked.contains(holder)) {
        return false;
    }
    return context == Digest{} || context == attempt_->context;
}

}  // namespace nexus::security
