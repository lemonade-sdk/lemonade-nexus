#include <LemonadeNexus/Security/Storage/StorageRecords.hpp>

#include <LemonadeNexus/Crypto/StorageThreshold.hpp>
#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <map>

namespace nexus::security {

namespace {

constexpr std::string_view kRecordDomain = "lemonade-nexus/storage-record:v1";
constexpr std::string_view kConfirmationDomain = "lemonade-nexus/storage-confirmation:v1";
constexpr std::string_view kPairwiseDomain = "lemonade-nexus/storage-pairwise:v1";
constexpr std::string_view kUnlockRequestDomain = "lemonade-nexus/storage-unlock-request:v1";
constexpr std::string_view kRankDomain = "lemonade-nexus/storage-holder-rank:v1";
constexpr std::string_view kWrapClaimDomain = "lemonade-nexus/storage-wrap-claim:v1";

/// Reads the field stream CanonicalEncoder writes: each field a u32 length
/// and its bytes. Every read checks its exact or maximum length.
class FieldReader {
public:
    explicit FieldReader(std::span<const uint8_t> bytes) : bytes_(bytes) {}

    [[nodiscard]] bool field(std::span<const uint8_t>& out, std::size_t max) {
        if (bytes_.size() - offset_ < 4) {
            return false;
        }
        uint32_t length = 0;
        for (int i = 0; i < 4; ++i) {
            length |= static_cast<uint32_t>(bytes_[offset_ + i]) << (8 * i);
        }
        offset_ += 4;
        if (length > max || bytes_.size() - offset_ < length) {
            return false;
        }
        out = bytes_.subspan(offset_, length);
        offset_ += length;
        return true;
    }

    template <std::size_t N>
    [[nodiscard]] bool fixed(std::array<uint8_t, N>& out) {
        std::span<const uint8_t> view;
        if (!field(view, N) || view.size() != N) {
            return false;
        }
        std::memcpy(out.data(), view.data(), N);
        return true;
    }

    [[nodiscard]] bool bytes(std::vector<uint8_t>& out, std::size_t max) {
        std::span<const uint8_t> view;
        if (!field(view, max)) {
            return false;
        }
        out.assign(view.begin(), view.end());
        return true;
    }

    template <typename T>
    [[nodiscard]] bool integer(T& out) {
        std::span<const uint8_t> view;
        if (!field(view, sizeof(T)) || view.size() != sizeof(T)) {
            return false;
        }
        uint64_t value = 0;
        for (std::size_t i = 0; i < sizeof(T); ++i) {
            value |= static_cast<uint64_t>(view[i]) << (8 * i);
        }
        out = static_cast<T>(value);
        return true;
    }

    [[nodiscard]] bool epoch(EpochId& out) {
        uint64_t raw = 0;
        if (!integer(raw)) {
            return false;
        }
        out = raw;
        return true;
    }

    [[nodiscard]] bool text(std::string_view expected) {
        std::span<const uint8_t> view;
        return field(view, expected.size()) && view.size() == expected.size() &&
               std::memcmp(view.data(), expected.data(), expected.size()) == 0;
    }

    [[nodiscard]] bool done() const { return offset_ == bytes_.size(); }

private:
    std::span<const uint8_t> bytes_;
    std::size_t offset_ = 0;
};

bool valid_operation(uint16_t raw) {
    return raw >= static_cast<uint16_t>(StorageOperation::Create) &&
           raw <= static_cast<uint16_t>(StorageOperation::Rotate);
}

void add_holders(CanonicalEncoder& encoder, const std::vector<StorageHolder>& holders) {
    encoder.add_u32(static_cast<uint32_t>(holders.size()));
    for (const auto& holder : holders) {
        encoder.add_bytes(holder.node.bytes);
        encoder.add_u16(holder.holder_id);
    }
}

bool read_holders(FieldReader& reader, std::vector<StorageHolder>& holders) {
    uint32_t count = 0;
    if (!reader.integer(count) || count == 0 || count > constants::kStorageMaxHolders) {
        return false;
    }
    holders.resize(count);
    for (auto& holder : holders) {
        if (!reader.fixed(holder.node.bytes) || !reader.integer(holder.holder_id)) {
            return false;
        }
    }
    return true;
}

/// Holders sorted by identifier, identifiers nonzero and unique, nodes unique.
bool well_formed_holders(const std::vector<StorageHolder>& holders) {
    if (holders.empty() || holders.size() > constants::kStorageMaxHolders) {
        return false;
    }
    std::set<NodeId> nodes;
    for (std::size_t i = 0; i < holders.size(); ++i) {
        if (holders[i].holder_id == 0 || !nodes.insert(holders[i].node).second) {
            return false;
        }
        if (i > 0 && holders[i - 1].holder_id >= holders[i].holder_id) {
            return false;
        }
    }
    return true;
}

CanonicalEncoder encode_selection(const StorageSelection& s) {
    CanonicalEncoder encoder(kRecordDomain);
    encoder.add_u16(static_cast<uint16_t>(StorageRecordStage::Selection));
    encoder.add_bytes(s.network_id);
    encoder.add_u64(s.sequence);
    encoder.add_bytes(s.previous_record);
    encoder.add_u64(s.target_epoch.underlying());
    encoder.add_u16(static_cast<uint16_t>(s.operation));
    encoder.add_u32(s.attempt);
    encoder.add_bytes(s.eligibility_commitment);
    encoder.add_bytes(s.checkpoint_seed);
    encoder.add_u16(s.threshold);
    encoder.add_bytes(s.base_plan);
    encoder.add_u64(s.block_time_ms);
    add_holders(encoder, s.holders);
    return encoder;
}

CanonicalEncoder encode_final(const StorageFinalPlan& f) {
    CanonicalEncoder encoder(kRecordDomain);
    encoder.add_u16(static_cast<uint16_t>(StorageRecordStage::Final));
    encoder.add_bytes(f.network_id);
    encoder.add_u64(f.sequence);
    encoder.add_bytes(f.previous_record);
    encoder.add_bytes(f.selection);
    encoder.add_u16(static_cast<uint16_t>(f.operation));
    encoder.add_u64(f.effective_epoch.underlying());
    encoder.add_u16(f.threshold);
    encoder.add_bytes(f.storage_public_key);
    encoder.add_bytes(f.key_plan);
    add_holders(encoder, f.holders);
    encoder.add_u32(static_cast<uint32_t>(f.confirmations.size()));
    for (const auto& signature : f.confirmations) {
        encoder.add_bytes(signature);
    }
    encoder.add_bytes(f.retiring_plan);
    encoder.add_u64(f.retiring_until_ms);
    encoder.add_u64(f.block_time_ms);
    encoder.add_u64(f.key_created_ms);
    return encoder;
}

void add_claim(CanonicalEncoder& encoder, const StorageWrapClaim& claim) {
    encoder.add_bytes(claim.node.bytes);
    encoder.add_u64(claim.counter);
    encoder.add_u32(static_cast<uint32_t>(claim.wraps.size()));
    for (const auto& wrap : claim.wraps) {
        encoder.add_bytes(wrap.storage_public_key);
        encoder.add_bytes(wrap.ephemeral_point);
    }
}

bool well_formed_claim(const StorageWrapClaim& claim) {
    if (claim.wraps.empty() || claim.wraps.size() > constants::kStorageMaxWrapsPerClaim) {
        return false;
    }
    for (std::size_t i = 0; i < claim.wraps.size(); ++i) {
        for (std::size_t j = i + 1; j < claim.wraps.size(); ++j) {
            if (claim.wraps[i] == claim.wraps[j]) {
                return false;
            }
        }
    }
    return true;
}

/// Claims ascending by node, one per node, each well formed.
bool well_formed_claims(const std::vector<StorageWrapClaim>& claims) {
    if (claims.empty() || claims.size() > constants::kStorageMaxClaimsPerBatch) {
        return false;
    }
    for (std::size_t i = 0; i < claims.size(); ++i) {
        if (!well_formed_claim(claims[i]) || (i > 0 && !(claims[i - 1].node < claims[i].node))) {
            return false;
        }
    }
    return true;
}

CanonicalEncoder encode_wraps(const StorageWrapBatch& b) {
    CanonicalEncoder encoder(kRecordDomain);
    encoder.add_u16(static_cast<uint16_t>(StorageRecordStage::Wraps));
    encoder.add_bytes(b.network_id);
    encoder.add_u64(b.sequence);
    encoder.add_bytes(b.previous_record);
    encoder.add_u64(b.block_time_ms);
    encoder.add_u32(static_cast<uint32_t>(b.claims.size()));
    for (const auto& claim : b.claims) {
        add_claim(encoder, claim);
        encoder.add_bytes(claim.signature);
    }
    return encoder;
}

std::optional<StorageRecord> decode_fields(std::span<const uint8_t> bytes) {
    FieldReader reader(bytes);
    uint16_t stage = 0;
    if (!reader.text(kRecordDomain) || !reader.integer(stage)) {
        return std::nullopt;
    }
    uint16_t operation = 0;
    if (stage == static_cast<uint16_t>(StorageRecordStage::Selection)) {
        StorageSelection s;
        if (!(reader.fixed(s.network_id) && reader.integer(s.sequence) &&
              reader.fixed(s.previous_record) && reader.epoch(s.target_epoch) &&
              reader.integer(operation) && reader.integer(s.attempt) &&
              reader.fixed(s.eligibility_commitment) && reader.fixed(s.checkpoint_seed) &&
              reader.integer(s.threshold) && reader.fixed(s.base_plan) &&
              reader.integer(s.block_time_ms) && read_holders(reader, s.holders) &&
              reader.done() && valid_operation(operation))) {
            return std::nullopt;
        }
        s.operation = static_cast<StorageOperation>(operation);
        if (!well_formed_holders(s.holders)) {
            return std::nullopt;
        }
        return StorageRecord{std::move(s)};
    }
    if (stage == static_cast<uint16_t>(StorageRecordStage::Final)) {
        StorageFinalPlan f;
        uint32_t signatures = 0;
        if (!(reader.fixed(f.network_id) && reader.integer(f.sequence) &&
              reader.fixed(f.previous_record) && reader.fixed(f.selection) &&
              reader.integer(operation) && reader.epoch(f.effective_epoch) &&
              reader.integer(f.threshold) && reader.fixed(f.storage_public_key) &&
              reader.bytes(f.key_plan, constants::kMaxStoragePlanBytes) &&
              read_holders(reader, f.holders) && reader.integer(signatures) &&
              valid_operation(operation))) {
            return std::nullopt;
        }
        if (signatures != f.holders.size()) {
            return std::nullopt;
        }
        f.confirmations.resize(signatures);
        for (auto& signature : f.confirmations) {
            if (!reader.fixed(signature)) {
                return std::nullopt;
            }
        }
        if (!(reader.fixed(f.retiring_plan) && reader.integer(f.retiring_until_ms) &&
              reader.integer(f.block_time_ms) && reader.integer(f.key_created_ms) &&
              reader.done())) {
            return std::nullopt;
        }
        f.operation = static_cast<StorageOperation>(operation);
        if (!well_formed_holders(f.holders) || f.key_plan.empty()) {
            return std::nullopt;
        }
        return StorageRecord{std::move(f)};
    }
    if (stage == static_cast<uint16_t>(StorageRecordStage::Wraps)) {
        StorageWrapBatch b;
        uint32_t count = 0;
        if (!(reader.fixed(b.network_id) && reader.integer(b.sequence) &&
              reader.fixed(b.previous_record) && reader.integer(b.block_time_ms) &&
              reader.integer(count)) ||
            count == 0 || count > constants::kStorageMaxClaimsPerBatch) {
            return std::nullopt;
        }
        b.claims.resize(count);
        for (auto& claim : b.claims) {
            uint32_t wraps = 0;
            if (!(reader.fixed(claim.node.bytes) && reader.integer(claim.counter) &&
                  reader.integer(wraps)) ||
                wraps == 0 || wraps > constants::kStorageMaxWrapsPerClaim) {
                return std::nullopt;
            }
            claim.wraps.resize(wraps);
            for (auto& wrap : claim.wraps) {
                if (!(reader.fixed(wrap.storage_public_key) && reader.fixed(wrap.ephemeral_point))) {
                    return std::nullopt;
                }
            }
            if (!reader.fixed(claim.signature)) {
                return std::nullopt;
            }
        }
        if (!reader.done() || !well_formed_claims(b.claims)) {
            return std::nullopt;
        }
        return StorageRecord{std::move(b)};
    }
    return std::nullopt;
}

std::vector<StorageHolder> numbered(const std::vector<NodeId>& nodes) {
    std::vector<StorageHolder> holders;
    holders.reserve(nodes.size());
    for (std::size_t i = 0; i < nodes.size(); ++i) {
        holders.push_back({nodes[i], static_cast<uint16_t>(i + 1)});
    }
    return holders;
}

std::vector<NodeId> nodes_of(const std::vector<StorageHolder>& holders) {
    std::vector<NodeId> nodes;
    nodes.reserve(holders.size());
    for (const auto& holder : holders) {
        nodes.push_back(holder.node);
    }
    return nodes;
}

/// The current plan's identifiers for `nodes`, sorted by identifier, or
/// nullopt when a node is not a current holder.
std::optional<std::vector<StorageHolder>> keep_identifiers(const StorageFinalPlan& current,
                                                           const std::vector<NodeId>& nodes) {
    std::vector<StorageHolder> holders;
    for (const auto& node : nodes) {
        const auto it = std::find_if(current.holders.begin(), current.holders.end(),
                                     [&](const StorageHolder& h) { return h.node == node; });
        if (it == current.holders.end()) {
            return std::nullopt;
        }
        holders.push_back(*it);
    }
    std::sort(holders.begin(), holders.end(),
              [](const StorageHolder& a, const StorageHolder& b) {
                  return a.holder_id < b.holder_id;
              });
    return holders;
}

StorageSelection base_selection(const NetworkId& network_id, const StorageChainState& state,
                                uint64_t block_time_ms) {
    StorageSelection s;
    s.network_id = network_id;
    s.sequence = state.sequence + 1;
    s.previous_record = state.head;
    s.block_time_ms = block_time_ms;
    return s;
}

/// Refresh when allowed, else Rotate when allowed, for a holder set drawn
/// from `nodes` in order. nullopt below the re-share minimum or when neither
/// is allowed.
std::optional<StorageSelection> reshare(StorageSelection s, const StorageChainState& state,
                                        const std::vector<NodeId>& nodes, bool refresh_allowed,
                                        bool rotation_allowed) {
    if (nodes.size() < constants::kStorageMinReshareHolders || !state.current.has_value()) {
        return std::nullopt;
    }
    const auto t = storage_threshold_for(nodes.size());
    if (!t.has_value()) {
        return std::nullopt;
    }
    s.threshold = *t;
    if (refresh_allowed && *t == state.current->threshold) {
        if (auto kept = keep_identifiers(*state.current, nodes)) {
            s.operation = StorageOperation::Refresh;
            s.holders = std::move(*kept);
            s.base_plan = state.current_digest;
            return s;
        }
    }
    if (!rotation_allowed) {
        return std::nullopt;
    }
    s.operation = StorageOperation::Rotate;
    s.holders = numbered(nodes);
    s.base_plan = Digest{};
    return s;
}

bool rotation_due(const StorageChainState& state, uint64_t block_time_ms) {
    return state.current.has_value() &&
           block_time_ms >= state.current->key_created_ms + constants::kStorageRotationIntervalMs;
}

std::optional<StorageSelection> boundary_selection(const NetworkId& network_id,
                                                   const StorageChainState& state,
                                                   const StorageEligibleSnapshot& snapshot,
                                                   uint64_t block_time_ms) {
    const auto nodes = rank_storage_holders(snapshot.checkpoint_seed, snapshot.pool);
    StorageSelection s = base_selection(network_id, state, block_time_ms);
    s.target_epoch = snapshot.target_epoch;
    s.eligibility_commitment = snapshot.eligibility_commitment;
    s.checkpoint_seed = snapshot.checkpoint_seed;
    if (!state.current.has_value()) {
        if (nodes.size() < constants::kStorageMinCreateHolders) {
            return std::nullopt;
        }
        s.operation = StorageOperation::Create;
        s.threshold = *storage_threshold_for(nodes.size());
        s.holders = numbered(nodes);
        return s;
    }
    // A due rotation waits while the retiring plan is live; the boundary
    // refreshes instead when it can.
    const bool retiring = storage_retiring_live(state, block_time_ms);
    const bool rotate_now = rotation_due(state, block_time_ms) && !retiring;
    return reshare(std::move(s), state, nodes, !rotate_now, !retiring);
}

std::optional<StorageSelection> retry_selection(const NetworkId& network_id,
                                                const StorageChainState& state,
                                                const std::set<NodeId>& silent,
                                                uint64_t block_time_ms) {
    const StorageSelection& failed = *state.pending;
    std::vector<NodeId> remaining;
    for (const auto& holder : failed.holders) {
        if (!silent.contains(holder.node)) {
            remaining.push_back(holder.node);
        }
    }
    StorageSelection s = base_selection(network_id, state, block_time_ms);
    s.target_epoch = failed.target_epoch;
    s.attempt = failed.attempt + 1;
    s.eligibility_commitment = failed.eligibility_commitment;
    s.checkpoint_seed = failed.checkpoint_seed;
    if (failed.operation == StorageOperation::Create) {
        if (remaining.size() < constants::kStorageMinCreateHolders) {
            return std::nullopt;
        }
        s.operation = StorageOperation::Create;
        s.threshold = *storage_threshold_for(remaining.size());
        s.holders = numbered(remaining);
        return s;
    }
    // A retry of a rotation stays a rotation. A refresh whose retry would
    // change t becomes a new rotation, which waits for the retiring plan.
    return reshare(std::move(s), state, remaining,
                   failed.operation == StorageOperation::Refresh,
                   failed.operation == StorageOperation::Rotate ||
                       !storage_retiring_live(state, block_time_ms));
}

/// Applies a finalized batch's claims: a claim replaces the node's claim only
/// when its counter is higher, and each wrap keeps its first owner.
bool apply_claims(StorageChainState& state, const StorageWrapBatch& batch) {
    bool changed = false;
    for (const auto& claim : batch.claims) {
        const auto it = state.wrap_claims.find(claim.node);
        if (it != state.wrap_claims.end() && it->second.counter >= claim.counter) {
            continue;
        }
        state.wrap_claims.insert_or_assign(claim.node, claim);
        for (const auto& wrap : claim.wraps) {
            state.wrap_owners.emplace(wrap, claim.node);
        }
        changed = true;
    }
    return changed;
}

/// Drops the wrap owners of every S that neither the current nor the retiring
/// plan holds, and the claims that name no other S: no holder serves a
/// partial for that S any more, and a claim for it can no longer finalize.
void prune_wrap_owners(StorageChainState& state) {
    const auto live = [&state](const StoragePointBytes& key) {
        return (state.current.has_value() && state.current->storage_public_key == key) ||
               (state.retiring.has_value() && state.retiring->storage_public_key == key);
    };
    std::erase_if(state.wrap_owners,
                  [&live](const auto& entry) { return !live(entry.first.storage_public_key); });
    std::erase_if(state.wrap_claims, [&live](const auto& entry) {
        return std::none_of(entry.second.wraps.begin(), entry.second.wraps.end(),
                            [&live](const auto& wrap) { return live(wrap.storage_public_key); });
    });
}

bool verify_confirmation(const NetworkId& network_id, const Digest& selection,
                         std::span<const uint8_t> key_plan, const StorageHolder& holder,
                         const crypto::Ed25519Signature& signature) {
    const Digest digest = storage_confirmation_digest(network_id, selection, key_plan, holder);
    return crypto_sign_verify_detached(signature.data(), digest.data(), digest.size(),
                                       holder.node.bytes.data()) == 0;
}

}  // namespace

std::string_view storage_operation_name(StorageOperation operation) {
    switch (operation) {
        case StorageOperation::Create:
            return "create";
        case StorageOperation::Refresh:
            return "refresh";
        case StorageOperation::Rotate:
            return "rotate";
    }
    return "unknown";
}

std::vector<uint8_t> encode_storage_record(const StorageRecord& record) {
    return std::visit(
        [](const auto& value) -> std::vector<uint8_t> {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, StorageSelection>) {
                if (!well_formed_holders(value.holders)) {
                    return {};
                }
                return encode_selection(value).bytes();
            } else if constexpr (std::is_same_v<T, StorageWrapBatch>) {
                if (!well_formed_claims(value.claims)) {
                    return {};
                }
                return encode_wraps(value).bytes();
            } else {
                if (!well_formed_holders(value.holders) ||
                    value.confirmations.size() != value.holders.size() ||
                    value.key_plan.empty() ||
                    value.key_plan.size() > constants::kMaxStoragePlanBytes) {
                    return {};
                }
                return encode_final(value).bytes();
            }
        },
        record);
}

std::optional<StorageRecord> decode_storage_record(std::span<const uint8_t> bytes) {
    if (bytes.empty() || bytes.size() > constants::kMaxBlockPayloadBytes) {
        return std::nullopt;
    }
    auto record = decode_fields(bytes);
    if (!record.has_value()) {
        return std::nullopt;
    }
    // Canonical only: the bytes must be exactly what the encoder produces.
    const auto again = encode_storage_record(*record);
    if (again.size() != bytes.size() || !std::equal(again.begin(), again.end(), bytes.begin())) {
        return std::nullopt;
    }
    return record;
}

Digest storage_record_digest(const StorageRecord& record) {
    const auto bytes = encode_storage_record(record);
    Digest digest{};
    crypto_hash_sha256(digest.data(), bytes.data(), bytes.size());
    return digest;
}

BlockPayloadKind storage_record_kind(const StorageRecord& record) {
    const bool rotation = std::visit(
        [](const auto& value) {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, StorageWrapBatch>) {
                return false;
            } else {
                return value.operation == StorageOperation::Rotate;
            }
        },
        record);
    return rotation ? BlockPayloadKind::StorageKeyRotation : BlockPayloadKind::StorageHolderPlan;
}

BlockPayload storage_record_payload(const StorageRecord& record) {
    return BlockPayload{storage_record_kind(record), encode_storage_record(record)};
}

std::optional<StorageRecord> storage_record_from_payload(const BlockPayload& payload) {
    if (payload.kind != BlockPayloadKind::StorageHolderPlan &&
        payload.kind != BlockPayloadKind::StorageKeyRotation) {
        return std::nullopt;
    }
    auto record = decode_storage_record(payload.body);
    if (!record.has_value() || storage_record_kind(*record) != payload.kind) {
        return std::nullopt;
    }
    return record;
}

uint64_t storage_record_sequence(const StorageRecord& record) {
    return std::visit([](const auto& value) { return value.sequence; }, record);
}

uint64_t storage_record_block_time(const StorageRecord& record) {
    return std::visit([](const auto& value) { return value.block_time_ms; }, record);
}

std::optional<uint16_t> storage_threshold_for(std::size_t holder_count) {
    if (holder_count == 0 || holder_count > constants::kStorageMaxHolders) {
        return std::nullopt;
    }
    return crypto::StorageThreshold::threshold_for(static_cast<uint16_t>(holder_count));
}

Digest storage_confirmation_digest(const NetworkId& network_id, const Digest& selection_digest,
                                   std::span<const uint8_t> key_plan,
                                   const StorageHolder& holder) {
    Digest plan_digest{};
    crypto_hash_sha256(plan_digest.data(), key_plan.data(), key_plan.size());
    CanonicalEncoder encoder(kConfirmationDomain);
    encoder.add_string(constants::kStorageKeyDomain);
    encoder.add_bytes(network_id);
    encoder.add_bytes(selection_digest);
    encoder.add_bytes(plan_digest);
    encoder.add_bytes(holder.node.bytes);
    encoder.add_u16(holder.holder_id);
    return encoder.digest();
}

Digest storage_pairwise_binding(const NetworkId& network_id, const Digest& session,
                                uint16_t sender_id, uint16_t recipient_id) {
    CanonicalEncoder encoder(kPairwiseDomain);
    encoder.add_string(constants::kStorageKeyDomain);
    encoder.add_bytes(network_id);
    encoder.add_bytes(session);
    encoder.add_u16(sender_id);
    encoder.add_u16(recipient_id);
    return encoder.digest();
}

Digest storage_unlock_request_digest(const NetworkId& network_id,
                                     const StorageUnlockRequestMsg& request) {
    CanonicalEncoder encoder(kUnlockRequestDomain);
    encoder.add_string(constants::kStorageKeyDomain);
    encoder.add_bytes(network_id);
    encoder.add_bytes(request.requester.bytes);
    encoder.add_u64(request.epoch.underlying());
    encoder.add_bytes(request.plan_digest);
    encoder.add_bytes(request.ephemeral_point);
    encoder.add_bytes(request.nonce);
    return encoder.digest();
}

Digest storage_holder_rank(const Digest& checkpoint_seed, const NodeId& node) {
    CanonicalEncoder encoder(kRankDomain);
    encoder.add_string(constants::kStorageKeyDomain);
    encoder.add_bytes(checkpoint_seed);
    encoder.add_bytes(node.bytes);
    return encoder.digest();
}

std::vector<NodeId> rank_storage_holders(const Digest& checkpoint_seed,
                                         std::vector<NodeId> pool) {
    std::sort(pool.begin(), pool.end());
    pool.erase(std::unique(pool.begin(), pool.end()), pool.end());
    std::vector<std::pair<Digest, NodeId>> ranked;
    ranked.reserve(pool.size());
    for (const auto& node : pool) {
        ranked.emplace_back(storage_holder_rank(checkpoint_seed, node), node);
    }
    std::sort(ranked.begin(), ranked.end());
    std::vector<NodeId> out;
    for (std::size_t i = 0; i < ranked.size() && i < constants::kStorageMaxHolders; ++i) {
        out.push_back(ranked[i].second);
    }
    return out;
}

bool apply_storage_record(StorageChainState& state, const StorageRecord& record) {
    const Digest digest = storage_record_digest(record);
    const uint64_t sequence = storage_record_sequence(record);
    if (const auto* batch = std::get_if<StorageWrapBatch>(&record)) {
        // An older batch still carries claims a lagging server lacks; the
        // counter rule makes the order of application irrelevant.
        bool changed = apply_claims(state, *batch);
        if (sequence > state.sequence) {
            state.sequence = sequence;
            state.head = digest;
            state.last_block_time_ms = batch->block_time_ms;
            changed = true;
        }
        prune_wrap_owners(state);
        return changed;
    }
    if (sequence <= state.sequence) {
        // Catch-up of the grace plan: an older final plan is kept only when
        // the current plan names it as retiring.
        const auto* plan = std::get_if<StorageFinalPlan>(&record);
        if (plan != nullptr && state.current.has_value() && !state.retiring.has_value() &&
            state.current->retiring_plan == digest) {
            state.retiring = *plan;
            state.retiring_digest = digest;
            return true;
        }
        return false;
    }
    state.sequence = sequence;
    state.head = digest;
    state.last_block_time_ms = storage_record_block_time(record);
    if (const auto* selection = std::get_if<StorageSelection>(&record)) {
        state.pending = *selection;
        state.pending_digest = digest;
        if (selection->eligibility_commitment != Digest{}) {
            state.last_boundary_epoch = std::max(state.last_boundary_epoch,
                                                 selection->target_epoch);
        }
        return true;
    }
    const auto& plan = std::get<StorageFinalPlan>(record);
    std::optional<StorageFinalPlan> retiring;
    Digest retiring_digest{};
    if (plan.retiring_plan != Digest{}) {
        if (state.current.has_value() && state.current_digest == plan.retiring_plan) {
            retiring = state.current;
            retiring_digest = state.current_digest;
        } else if (state.retiring.has_value() && state.retiring_digest == plan.retiring_plan) {
            retiring = state.retiring;
            retiring_digest = state.retiring_digest;
        }
    }
    state.retiring = std::move(retiring);
    state.retiring_digest = retiring_digest;
    state.current = plan;
    state.current_digest = digest;
    state.pending.reset();
    state.pending_digest = Digest{};
    prune_wrap_owners(state);
    return true;
}

bool storage_wrap_claimed(const StorageChainState& state, const NodeId& node,
                          const StorageWrapRef& wrap) {
    const auto it = state.wrap_claims.find(node);
    return it != state.wrap_claims.end() &&
           std::find(it->second.wraps.begin(), it->second.wraps.end(), wrap) !=
               it->second.wraps.end();
}

bool storage_retiring_live(const StorageChainState& state, uint64_t block_time_ms) {
    if (!state.current.has_value() || !state.retiring.has_value() ||
        state.current->retiring_plan == Digest{} ||
        state.retiring_digest != state.current->retiring_plan ||
        block_time_ms >= state.current->retiring_until_ms) {
        return false;
    }
    const auto& retiring_key = state.retiring->storage_public_key;
    for (const auto& [node, claim] : state.wrap_claims) {
        for (const auto& wrap : claim.wraps) {
            if (wrap.storage_public_key == retiring_key) {
                return true;
            }
        }
    }
    return false;
}

std::optional<StorageSelection> derive_storage_selection(
    const NetworkId& network_id, const StorageChainState& state,
    const StorageEligibleSnapshot* snapshot, const std::set<NodeId>& silent,
    uint64_t block_time_ms) {
    const bool fresh_boundary =
        snapshot != nullptr && snapshot->target_epoch > state.last_boundary_epoch;
    if (state.pending.has_value()) {
        if (block_time_ms < state.pending->block_time_ms + constants::kStorageSessionTimeoutMs) {
            return std::nullopt;
        }
        if (fresh_boundary) {
            return boundary_selection(network_id, state, *snapshot, block_time_ms);
        }
        if (state.pending->attempt + 1 < constants::kStorageMaxSessionAttempts) {
            if (auto retry = retry_selection(network_id, state, silent, block_time_ms)) {
                return retry;
            }
        }
    }
    if (fresh_boundary) {
        return boundary_selection(network_id, state, *snapshot, block_time_ms);
    }
    if (rotation_due(state, block_time_ms) && !storage_retiring_live(state, block_time_ms)) {
        StorageSelection s = base_selection(network_id, state, block_time_ms);
        s.target_epoch = state.last_boundary_epoch;
        return reshare(std::move(s), state, nodes_of(state.current->holders), false, true);
    }
    return std::nullopt;
}

std::optional<StorageFinalPlan> make_storage_final(
    const StorageChainState& state, std::span<const uint8_t> key_plan,
    const std::map<NodeId, crypto::Ed25519Signature>& confirmations, EpochId effective_epoch,
    uint64_t block_time_ms) {
    if (!state.pending.has_value() || key_plan.empty() ||
        key_plan.size() > constants::kMaxStoragePlanBytes) {
        return std::nullopt;
    }
    const StorageSelection& selection = *state.pending;
    const auto info = crypto::StorageThreshold::validate_plan(key_plan);
    if (!info.ok()) {
        return std::nullopt;
    }
    StorageFinalPlan plan;
    plan.network_id = selection.network_id;
    plan.sequence = state.sequence + 1;
    plan.previous_record = state.head;
    plan.selection = state.pending_digest;
    plan.operation = selection.operation;
    plan.effective_epoch = effective_epoch;
    plan.threshold = selection.threshold;
    plan.storage_public_key = info.value->storage_public_key;
    plan.key_plan.assign(key_plan.begin(), key_plan.end());
    plan.holders = selection.holders;
    for (const auto& holder : selection.holders) {
        const auto it = confirmations.find(holder.node);
        if (it == confirmations.end()) {
            return std::nullopt;
        }
        plan.confirmations.push_back(it->second);
    }
    plan.block_time_ms = block_time_ms;
    switch (selection.operation) {
        case StorageOperation::Create:
            plan.key_created_ms = block_time_ms;
            break;
        case StorageOperation::Rotate:
            plan.key_created_ms = block_time_ms;
            if (state.current.has_value()) {
                plan.retiring_plan = state.current_digest;
                plan.retiring_until_ms = block_time_ms + constants::kStorageRetiringCapMs;
            }
            break;
        case StorageOperation::Refresh:
            if (!state.current.has_value()) {
                return std::nullopt;
            }
            plan.key_created_ms = state.current->key_created_ms;
            plan.retiring_plan = state.current->retiring_plan;
            plan.retiring_until_ms = state.current->retiring_until_ms;
            break;
    }
    if (check_storage_final(state, plan, effective_epoch) != StorageFinalFailure::None) {
        return std::nullopt;
    }
    return plan;
}

StorageFinalFailure check_storage_final(const StorageChainState& state,
                                        const StorageFinalPlan& plan, EpochId effective_epoch) {
    if (!state.pending.has_value()) {
        return StorageFinalFailure::NoPendingSelection;
    }
    const StorageSelection& selection = *state.pending;
    if (plan.selection != state.pending_digest || plan.operation != selection.operation ||
        plan.holders != selection.holders || plan.threshold != selection.threshold ||
        plan.network_id != selection.network_id) {
        return StorageFinalFailure::SelectionMismatch;
    }
    if (plan.sequence != state.sequence + 1 || plan.previous_record != state.head ||
        plan.block_time_ms <= state.last_block_time_ms) {
        return StorageFinalFailure::ChainMismatch;
    }
    if (selection.operation == StorageOperation::Refresh &&
        (!state.current.has_value() || selection.base_plan != state.current_digest)) {
        return StorageFinalFailure::ChainMismatch;
    }
    if (selection.operation != StorageOperation::Create && !state.current.has_value()) {
        return StorageFinalFailure::ChainMismatch;
    }

    // The plan must validate with exactly the selected identifiers and t.
    const auto info = crypto::StorageThreshold::validate_plan(plan.key_plan);
    if (!info.ok() || info.value->threshold != selection.threshold ||
        info.value->holder_count != selection.holders.size()) {
        return StorageFinalFailure::PlanInvalid;
    }
    std::vector<uint16_t> ids;
    for (const auto& holder : selection.holders) {
        ids.push_back(holder.holder_id);
    }
    if (info.value->holders != ids) {
        return StorageFinalFailure::PlanInvalid;
    }
    if (info.value->storage_public_key != plan.storage_public_key) {
        return StorageFinalFailure::KeyMismatch;
    }
    if (selection.operation == StorageOperation::Refresh &&
        plan.storage_public_key != state.current->storage_public_key) {
        return StorageFinalFailure::KeyMismatch;
    }
    if (selection.operation != StorageOperation::Refresh && state.current.has_value() &&
        plan.storage_public_key == state.current->storage_public_key) {
        // A rotation that reproduces the old S is not a rotation.
        return StorageFinalFailure::KeyMismatch;
    }

    // Every selected holder signed these exact plan bytes.
    if (plan.confirmations.size() != selection.holders.size()) {
        return StorageFinalFailure::ConfirmationInvalid;
    }
    for (std::size_t i = 0; i < selection.holders.size(); ++i) {
        if (!verify_confirmation(selection.network_id, state.pending_digest, plan.key_plan,
                                 selection.holders[i], plan.confirmations[i])) {
            return StorageFinalFailure::ConfirmationInvalid;
        }
    }

    // Derived fields.
    if (plan.effective_epoch != effective_epoch) {
        return StorageFinalFailure::FieldMismatch;
    }
    Digest retiring{};
    uint64_t retiring_until_ms = 0;
    uint64_t key_created = plan.block_time_ms;
    if (selection.operation == StorageOperation::Rotate) {
        retiring = state.current_digest;
        retiring_until_ms = plan.block_time_ms + constants::kStorageRetiringCapMs;
    } else if (selection.operation == StorageOperation::Refresh) {
        retiring = state.current->retiring_plan;
        retiring_until_ms = state.current->retiring_until_ms;
        key_created = state.current->key_created_ms;
    }
    if (plan.retiring_plan != retiring || plan.retiring_until_ms != retiring_until_ms ||
        plan.key_created_ms != key_created) {
        return StorageFinalFailure::FieldMismatch;
    }
    return StorageFinalFailure::None;
}

Digest storage_wrap_claim_digest(const NetworkId& network_id, const StorageWrapClaim& claim) {
    CanonicalEncoder encoder(kWrapClaimDomain);
    encoder.add_string(constants::kStorageKeyDomain);
    encoder.add_bytes(network_id);
    add_claim(encoder, claim);
    return encoder.digest();
}

void sign_storage_wrap_claim(const NetworkId& network_id, StorageWrapClaim& claim,
                             const crypto::Ed25519PrivateKey& identity) {
    const Digest digest = storage_wrap_claim_digest(network_id, claim);
    crypto_sign_detached(claim.signature.data(), nullptr, digest.data(), digest.size(),
                         identity.data());
}

bool check_storage_wrap_claim(const StorageChainState& state, const NetworkId& network_id,
                              const StorageWrapClaim& claim, uint64_t block_time_ms) {
    if (!well_formed_claim(claim) || !state.current.has_value()) {
        return false;
    }
    const auto existing = state.wrap_claims.find(claim.node);
    if (existing != state.wrap_claims.end()
            ? claim.counter <= existing->second.counter
            : state.wrap_claims.size() >= constants::kStorageMaxWrapOwners) {
        return false;
    }
    const bool retiring = storage_retiring_live(state, block_time_ms);
    for (const auto& wrap : claim.wraps) {
        const bool live_key =
            wrap.storage_public_key == state.current->storage_public_key ||
            (retiring && wrap.storage_public_key == state.retiring->storage_public_key);
        if (!live_key) {
            return false;
        }
        // An R belongs to the first server that claimed it while its S is live.
        const auto owner = state.wrap_owners.find(wrap);
        if (owner != state.wrap_owners.end() && owner->second != claim.node) {
            return false;
        }
    }
    const Digest digest = storage_wrap_claim_digest(network_id, claim);
    return crypto_sign_verify_detached(claim.signature.data(), digest.data(), digest.size(),
                                       claim.node.bytes.data()) == 0;
}

std::optional<StorageWrapBatch> make_storage_wrap_batch(
    const NetworkId& network_id, const StorageChainState& state,
    const std::map<NodeId, StorageWrapClaim>& pool, uint64_t block_time_ms) {
    StorageWrapBatch batch;
    batch.network_id = network_id;
    batch.sequence = state.sequence + 1;
    batch.previous_record = state.head;
    batch.block_time_ms = block_time_ms;
    std::set<StorageWrapRef> named;
    for (const auto& [node, claim] : pool) {
        if (batch.claims.size() >= constants::kStorageMaxClaimsPerBatch) {
            break;
        }
        if (claim.node != node ||
            !check_storage_wrap_claim(state, network_id, claim, block_time_ms)) {
            continue;
        }
        const bool conflict = std::any_of(claim.wraps.begin(), claim.wraps.end(),
                                          [&named](const auto& w) { return named.contains(w); });
        if (conflict) {
            continue;
        }
        named.insert(claim.wraps.begin(), claim.wraps.end());
        batch.claims.push_back(claim);
    }
    if (batch.claims.empty()) {
        return std::nullopt;
    }
    return batch;
}

StorageWrapFailure check_storage_wrap_batch(const StorageChainState& state,
                                            const StorageWrapBatch& batch) {
    if (batch.sequence != state.sequence + 1 || batch.previous_record != state.head ||
        batch.block_time_ms <= state.last_block_time_ms) {
        return StorageWrapFailure::ChainMismatch;
    }
    if (batch.claims.empty()) {
        return StorageWrapFailure::Empty;
    }
    if (!well_formed_claims(batch.claims)) {
        return StorageWrapFailure::Order;
    }
    std::set<StorageWrapRef> named;
    for (const auto& claim : batch.claims) {
        if (!check_storage_wrap_claim(state, batch.network_id, claim, batch.block_time_ms)) {
            return StorageWrapFailure::ClaimInvalid;
        }
        for (const auto& wrap : claim.wraps) {
            if (!named.insert(wrap).second) {
                return StorageWrapFailure::ClaimInvalid;
            }
        }
    }
    return StorageWrapFailure::None;
}

}  // namespace nexus::security
