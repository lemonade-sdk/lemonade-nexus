#include <LemonadeNexus/Security/Upgrade/UpgradeProgress.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Eligibility/EligibilityLedger.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstring>

namespace nexus::security {

namespace {

constexpr std::string_view kStatusDomain = "lemonade-nexus/upgrade-status:v1";
constexpr std::string_view kObservationDomain = "lemonade-nexus/upgrade-observation:v1";
constexpr std::string_view kRecordDomain = "lemonade-nexus/upgrade-record:v1";
constexpr std::string_view kOrderDomain = "LEMONADE-NEXUS-UPGRADE-ORDER-V1";

// A witness set never exceeds the largest Tier 1 population.
constexpr std::size_t kMaxObservations = constants::kMaxActiveTier1;

class Writer {
public:
    void u8(uint8_t v) { out_.push_back(v); }
    void u16(uint16_t v) {
        for (int shift = 8; shift >= 0; shift -= 8) {
            out_.push_back(static_cast<uint8_t>(v >> shift));
        }
    }
    void u64(uint64_t v) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            out_.push_back(static_cast<uint8_t>(v >> shift));
        }
    }
    void fixed(std::span<const uint8_t> bytes) {
        out_.insert(out_.end(), bytes.begin(), bytes.end());
    }
    std::vector<uint8_t> take() { return std::move(out_); }

private:
    std::vector<uint8_t> out_;
};

class Reader {
public:
    explicit Reader(std::span<const uint8_t> bytes) : bytes_(bytes) {}
    bool u8(uint8_t& v) {
        if (pos_ + 1 > bytes_.size()) return false;
        v = bytes_[pos_++];
        return true;
    }
    bool u16(uint16_t& v) {
        if (pos_ + 2 > bytes_.size()) return false;
        v = static_cast<uint16_t>((bytes_[pos_] << 8) | bytes_[pos_ + 1]);
        pos_ += 2;
        return true;
    }
    bool u64(uint64_t& v) {
        if (pos_ + 8 > bytes_.size()) return false;
        v = 0;
        for (int i = 0; i < 8; ++i) v = (v << 8) | bytes_[pos_ + i];
        pos_ += 8;
        return true;
    }
    template <std::size_t N>
    bool fixed(std::array<uint8_t, N>& out) {
        if (pos_ + N > bytes_.size()) return false;
        std::memcpy(out.data(), bytes_.data() + pos_, N);
        pos_ += N;
        return true;
    }
    [[nodiscard]] bool done() const { return pos_ == bytes_.size(); }

private:
    std::span<const uint8_t> bytes_;
    std::size_t pos_ = 0;
};

void put_status(Writer& w, const UpgradeStatus& s) {
    w.fixed(s.network_id);
    w.fixed(s.node.bytes);
    w.u64(s.running_release);
    w.u64(s.staged_release);
    w.u64(s.accepted_release);
    w.u8(s.flags);
    w.u64(s.timestamp_ms);
    w.fixed(s.signature);
}

bool get_status(Reader& r, UpgradeStatus& s) {
    return r.fixed(s.network_id) && r.fixed(s.node.bytes) && r.u64(s.running_release) &&
           r.u64(s.staged_release) && r.u64(s.accepted_release) && r.u8(s.flags) &&
           r.u64(s.timestamp_ms) &&
           r.fixed(s.signature);
}

void put_observation(Writer& w, const UpgradeObservation& o) {
    w.fixed(o.network_id);
    w.u64(o.release_number);
    w.fixed(o.subject.bytes);
    w.fixed(o.chain_head);
    w.fixed(o.witness.bytes);
    w.fixed(o.evidence_digest);
    w.fixed(o.signature);
}

bool get_observation(Reader& r, UpgradeObservation& o) {
    return r.fixed(o.network_id) && r.u64(o.release_number) && r.fixed(o.subject.bytes) &&
           r.fixed(o.chain_head) && r.fixed(o.witness.bytes) && r.fixed(o.evidence_digest) &&
           r.fixed(o.signature);
}

bool verify_signature(const crypto::Ed25519Signature& signature, const Digest& digest,
                      const NodeId& signer) {
    return crypto_sign_verify_detached(signature.data(), digest.data(), digest.size(),
                                       signer.bytes.data()) == 0;
}

Digest order_rank(uint64_t release_number, const NodeId& node) {
    CanonicalEncoder encoder(kOrderDomain);
    encoder.add_u64(release_number);
    encoder.add_bytes(node.bytes);
    return encoder.digest();
}

}  // namespace

// --- Signed statements --------------------------------------------------------

std::vector<uint8_t> encode_upgrade_status(const UpgradeStatus& status) {
    Writer w;
    put_status(w, status);
    return w.take();
}

std::optional<UpgradeStatus> decode_upgrade_status(std::span<const uint8_t> bytes) {
    Reader r(bytes);
    UpgradeStatus status;
    if (!get_status(r, status) || !r.done()) return std::nullopt;
    return status;
}

std::vector<uint8_t> encode_upgrade_observation(const UpgradeObservation& observation) {
    Writer w;
    put_observation(w, observation);
    return w.take();
}

std::optional<UpgradeObservation> decode_upgrade_observation(std::span<const uint8_t> bytes) {
    Reader r(bytes);
    UpgradeObservation observation;
    if (!get_observation(r, observation) || !r.done()) return std::nullopt;
    return observation;
}

Digest upgrade_status_digest(const UpgradeStatus& status) {
    CanonicalEncoder encoder(kStatusDomain);
    encoder.add_bytes(status.network_id);
    encoder.add_bytes(status.node.bytes);
    encoder.add_u64(status.running_release);
    encoder.add_u64(status.staged_release);
    encoder.add_u64(status.accepted_release);
    encoder.add_u16(status.flags);
    encoder.add_u64(status.timestamp_ms);
    return encoder.digest();
}

void sign_upgrade_status(UpgradeStatus& status, const crypto::Ed25519PrivateKey& key) {
    const Digest digest = upgrade_status_digest(status);
    crypto_sign_detached(status.signature.data(), nullptr, digest.data(), digest.size(),
                         key.data());
}

bool verify_upgrade_status(const UpgradeStatus& status) {
    return verify_signature(status.signature, upgrade_status_digest(status), status.node);
}

Digest upgrade_observation_digest(const UpgradeObservation& observation) {
    CanonicalEncoder encoder(kObservationDomain);
    encoder.add_bytes(observation.network_id);
    encoder.add_u64(observation.release_number);
    encoder.add_bytes(observation.subject.bytes);
    encoder.add_bytes(observation.chain_head);
    encoder.add_bytes(observation.witness.bytes);
    encoder.add_bytes(observation.evidence_digest);
    return encoder.digest();
}

void sign_upgrade_observation(UpgradeObservation& observation,
                              const crypto::Ed25519PrivateKey& key) {
    const Digest digest = upgrade_observation_digest(observation);
    crypto_sign_detached(observation.signature.data(), nullptr, digest.data(), digest.size(),
                         key.data());
}

bool verify_upgrade_observation(const UpgradeObservation& observation) {
    return observation.evidence_digest != Digest{} &&
           verify_signature(observation.signature, upgrade_observation_digest(observation),
                            observation.witness);
}

// --- Records ------------------------------------------------------------------

std::vector<uint8_t> encode_upgrade_record(const UpgradeRecord& record) {
    if (record.order.size() > constants::kMaxUpgradeParticipants ||
        record.observations.size() > kMaxObservations) {
        return {};
    }
    Writer w;
    w.u8(record.version);
    w.fixed(record.network_id);
    w.u64(record.sequence);
    w.fixed(record.previous);
    w.u8(static_cast<uint8_t>(record.event));
    w.u64(record.release_number);
    w.fixed(record.approval_digest);
    w.u16(static_cast<uint16_t>(record.order.size()));
    for (const auto& participant : record.order) {
        w.fixed(participant.node.bytes);
        w.u8(participant.tier1 ? 1 : 0);
    }
    w.fixed(record.subject.bytes);
    w.u8(record.status.has_value() ? 1 : 0);
    if (record.status) put_status(w, *record.status);
    w.u16(static_cast<uint16_t>(record.observations.size()));
    for (const auto& observation : record.observations) put_observation(w, observation);
    auto bytes = w.take();
    if (bytes.size() > constants::kMaxBlockPayloadBytes) return {};
    return bytes;
}

std::optional<UpgradeRecord> decode_upgrade_record(std::span<const uint8_t> bytes) {
    if (bytes.size() > constants::kMaxBlockPayloadBytes) return std::nullopt;
    Reader r(bytes);
    UpgradeRecord record;
    uint8_t event = 0;
    uint16_t count = 0;
    if (!(r.u8(record.version) && record.version == kUpgradeRecordVersion &&
          r.fixed(record.network_id) && r.u64(record.sequence) && r.fixed(record.previous) &&
          r.u8(event) && r.u64(record.release_number) && r.fixed(record.approval_digest) &&
          r.u16(count))) {
        return std::nullopt;
    }
    if (event < static_cast<uint8_t>(UpgradeEvent::Start) ||
        event > static_cast<uint8_t>(UpgradeEvent::Halt) ||
        count > constants::kMaxUpgradeParticipants) {
        return std::nullopt;
    }
    record.event = static_cast<UpgradeEvent>(event);
    record.order.resize(count);
    for (auto& participant : record.order) {
        uint8_t tier1 = 0;
        if (!r.fixed(participant.node.bytes) || !r.u8(tier1) || tier1 > 1) return std::nullopt;
        participant.tier1 = tier1 == 1;
    }
    uint8_t has_status = 0;
    if (!r.fixed(record.subject.bytes) || !r.u8(has_status) || has_status > 1) {
        return std::nullopt;
    }
    if (has_status == 1) {
        UpgradeStatus status;
        if (!get_status(r, status)) return std::nullopt;
        record.status = status;
    }
    if (!r.u16(count) || count > kMaxObservations) return std::nullopt;
    record.observations.resize(count);
    for (auto& observation : record.observations) {
        if (!get_observation(r, observation)) return std::nullopt;
    }
    if (!r.done()) return std::nullopt;
    return record;
}

Digest upgrade_record_digest(const UpgradeRecord& record) {
    CanonicalEncoder encoder(kRecordDomain);
    encoder.add_bytes(encode_upgrade_record(record));
    return encoder.digest();
}

BlockPayload upgrade_record_payload(const UpgradeRecord& record) {
    return BlockPayload{BlockPayloadKind::UpgradeProgress, encode_upgrade_record(record)};
}

std::optional<UpgradeRecord> upgrade_record_from_payload(const BlockPayload& payload) {
    if (payload.kind != BlockPayloadKind::UpgradeProgress) return std::nullopt;
    return decode_upgrade_record(payload.body);
}

// --- Order and state ----------------------------------------------------------

std::vector<UpgradeParticipant> derive_upgrade_order(uint64_t release_number,
                                                     const std::vector<NodeId>& tier1,
                                                     const std::vector<NodeId>& others) {
    const std::set<NodeId> tier1_set(tier1.begin(), tier1.end());
    std::set<NodeId> tier2_set;
    for (const auto& node : others) {
        if (!tier1_set.contains(node)) tier2_set.insert(node);
    }
    const auto ranked = [release_number](const std::set<NodeId>& nodes, bool is_tier1) {
        std::vector<std::pair<Digest, NodeId>> keyed;
        keyed.reserve(nodes.size());
        for (const auto& node : nodes) keyed.emplace_back(order_rank(release_number, node), node);
        std::sort(keyed.begin(), keyed.end());
        std::vector<UpgradeParticipant> out;
        out.reserve(keyed.size());
        for (const auto& entry : keyed) out.push_back({entry.second, is_tier1});
        return out;
    };
    auto order = ranked(tier2_set, false);
    const auto tier1_order = ranked(tier1_set, true);
    order.insert(order.end(), tier1_order.begin(), tier1_order.end());
    return order;
}

bool UpgradeChainState::participant(const NodeId& node) const {
    return std::any_of(order.begin(), order.end(),
                       [&node](const UpgradeParticipant& entry) { return entry.node == node; });
}

bool UpgradeChainState::complete() const {
    return active() && std::all_of(order.begin(), order.end(),
                                   [this](const UpgradeParticipant& entry) {
                                       return upgraded.contains(entry.node);
                                   });
}

std::optional<NodeId> UpgradeChainState::next_subject() const {
    for (const auto& entry : order) {
        if (!upgraded.contains(entry.node)) return entry.node;
    }
    return std::nullopt;
}

std::string_view upgrade_record_failure_name(UpgradeRecordFailure failure) {
    switch (failure) {
        case UpgradeRecordFailure::None: return "none";
        case UpgradeRecordFailure::Malformed: return "malformed";
        case UpgradeRecordFailure::WrongNetwork: return "wrong_network";
        case UpgradeRecordFailure::NotChained: return "not_chained";
        case UpgradeRecordFailure::StaleRelease: return "stale_release";
        case UpgradeRecordFailure::TurnOpen: return "turn_open";
        case UpgradeRecordFailure::BadOrder: return "bad_order";
        case UpgradeRecordFailure::RolloutClosed: return "rollout_closed";
        case UpgradeRecordFailure::NotNext: return "not_next";
        case UpgradeRecordFailure::NotInTurn: return "not_in_turn";
        case UpgradeRecordFailure::BadStatus: return "bad_status";
        case UpgradeRecordFailure::BadObservation: return "bad_observation";
        case UpgradeRecordFailure::TooFewWitnesses: return "too_few_witnesses";
    }
    return "unknown";
}

UpgradeRecordFailure check_upgrade_record(const UpgradeChainState& state,
                                          const UpgradeRecord& record,
                                          const UpgradeWitnessSet* witnesses, bool as_base) {
    if (record.version != kUpgradeRecordVersion || record.release_number == 0) {
        return UpgradeRecordFailure::Malformed;
    }
    const bool rebase = as_base && record.event == UpgradeEvent::Start &&
                        record.sequence > state.sequence + 1;
    if (!rebase && (record.sequence != state.sequence + 1 || record.previous != state.head)) {
        return UpgradeRecordFailure::NotChained;
    }

    if (record.event == UpgradeEvent::Start) {
        if (record.release_number <= state.release_number) {
            return UpgradeRecordFailure::StaleRelease;
        }
        if (!rebase && state.in_turn.has_value()) {
            return UpgradeRecordFailure::TurnOpen;
        }
        if (record.approval_digest == Digest{} || record.order.empty() ||
            record.order.size() > constants::kMaxUpgradeParticipants || record.status ||
            !record.observations.empty() || record.subject != NodeId{}) {
            return UpgradeRecordFailure::BadOrder;
        }
        // The order must be the canonical one for its own member sets, so no
        // proposer can choose who goes first.
        std::vector<NodeId> tier1;
        std::vector<NodeId> others;
        for (const auto& entry : record.order) {
            (entry.tier1 ? tier1 : others).push_back(entry.node);
        }
        if (derive_upgrade_order(record.release_number, tier1, others) != record.order) {
            return UpgradeRecordFailure::BadOrder;
        }
        return UpgradeRecordFailure::None;
    }

    if (!state.active() || state.halted || record.release_number != state.release_number ||
        !record.order.empty() || record.approval_digest != Digest{}) {
        return UpgradeRecordFailure::RolloutClosed;
    }
    switch (record.event) {
        case UpgradeEvent::Turn: {
            if (state.in_turn.has_value() || state.next_subject() != record.subject) {
                return UpgradeRecordFailure::NotNext;
            }
            const auto& status = record.status;
            if (!status || !record.observations.empty() || status->node != record.subject ||
                status->network_id != record.network_id ||
                status->staged_release != record.release_number ||
                (status->flags & kUpgradeStatusReady) == 0 ||
                (status->flags & kUpgradeStatusFailed) != 0 || !verify_upgrade_status(*status)) {
                return UpgradeRecordFailure::BadStatus;
            }
            return UpgradeRecordFailure::None;
        }
        case UpgradeEvent::Upgraded: {
            const bool in_turn = state.in_turn == record.subject;
            const bool next_without_turn =
                !state.in_turn.has_value() && state.next_subject() == record.subject;
            if (!in_turn && !next_without_turn) {
                return UpgradeRecordFailure::NotInTurn;
            }
            if (record.status || witnesses == nullptr ||
                witnesses->network_id != record.network_id) {
                return UpgradeRecordFailure::BadObservation;
            }
            std::set<NodeId> seen;
            for (const auto& observation : record.observations) {
                const bool member =
                    std::find(witnesses->members.begin(), witnesses->members.end(),
                              observation.witness) != witnesses->members.end();
                if (!member || observation.witness == record.subject ||
                    observation.network_id != record.network_id ||
                    observation.release_number != record.release_number ||
                    observation.subject != record.subject || observation.chain_head != state.head ||
                    !seen.insert(observation.witness).second ||
                    !verify_upgrade_observation(observation)) {
                    return UpgradeRecordFailure::BadObservation;
                }
            }
            const auto context = established_fact_context(witnesses->network_id,
                                                          witnesses->epoch, witnesses->members);
            if (seen.size() < witness_threshold(context, record.subject) || seen.empty()) {
                return UpgradeRecordFailure::TooFewWitnesses;
            }
            return UpgradeRecordFailure::None;
        }
        case UpgradeEvent::Halt: {
            if (state.in_turn != record.subject) {
                return UpgradeRecordFailure::NotInTurn;
            }
            const auto& status = record.status;
            if (!status || !record.observations.empty() || status->node != record.subject ||
                status->network_id != record.network_id ||
                status->staged_release != record.release_number ||
                (status->flags & kUpgradeStatusFailed) == 0 || !verify_upgrade_status(*status)) {
                return UpgradeRecordFailure::BadStatus;
            }
            return UpgradeRecordFailure::None;
        }
        case UpgradeEvent::Start:
            break;
    }
    return UpgradeRecordFailure::Malformed;
}

void apply_upgrade_record(UpgradeChainState& state, const UpgradeRecord& record) {
    switch (record.event) {
        case UpgradeEvent::Start:
            state.release_number = record.release_number;
            state.approval_digest = record.approval_digest;
            state.order = record.order;
            state.upgraded.clear();
            state.in_turn.reset();
            state.halted = false;
            break;
        case UpgradeEvent::Turn:
            state.in_turn = record.subject;
            break;
        case UpgradeEvent::Upgraded:
            state.upgraded.insert(record.subject);
            state.in_turn.reset();
            break;
        case UpgradeEvent::Halt:
            state.halted = true;
            state.in_turn.reset();
            break;
    }
    state.sequence = record.sequence;
    state.head = upgrade_record_digest(record);
}

std::string_view upgrade_gate_name(UpgradeGate gate) {
    switch (gate) {
        case UpgradeGate::Go: return "go";
        case UpgradeGate::Wait: return "wait";
        case UpgradeGate::Halted: return "halted";
        case UpgradeGate::Done: return "done";
        case UpgradeGate::NotStarted: return "not_started";
    }
    return "unknown";
}

UpgradeGate evaluate_upgrade_gate(const UpgradeChainState& state, const NodeId& self,
                                  uint64_t release_number) {
    if (!state.active() || state.release_number != release_number) {
        return UpgradeGate::NotStarted;
    }
    if (state.halted) return UpgradeGate::Halted;
    if (state.upgraded.contains(self)) return UpgradeGate::Done;
    if (state.in_turn == self) return UpgradeGate::Go;
    if (!state.participant(self)) {
        // A server outside the order holds no epoch role and no storage share
        // in this rollout; it restarts once every participant is Upgraded.
        return state.complete() ? UpgradeGate::Go : UpgradeGate::Wait;
    }
    return UpgradeGate::Wait;
}

}  // namespace nexus::security
