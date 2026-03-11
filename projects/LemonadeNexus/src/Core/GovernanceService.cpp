#include <LemonadeNexus/Core/GovernanceService.hpp>

#include <spdlog/spdlog.h>
#include <sodium.h>

#include <chrono>
#include <cstring>

namespace nexus::core {

using json = nlohmann::json;
namespace chrono = std::chrono;

// ---------------------------------------------------------------------------
// Canonical JSON helpers (deterministic field ordering for signing)
// ---------------------------------------------------------------------------

std::string GovernanceService::canonical_proposal_json(
    const gossip::GovernanceProposalData& p) {
    json j = {
        {"created_at",       p.created_at},
        {"expires_at",       p.expires_at},
        {"new_value",        p.new_value},
        {"old_value",        p.old_value},
        {"parameter",        static_cast<uint8_t>(p.parameter)},
        {"proposal_id",      p.proposal_id},
        {"proposer_pubkey",  p.proposer_pubkey},
        {"rationale",        p.rationale},
    };
    return j.dump(); // nlohmann sorts keys alphabetically
}

std::string GovernanceService::canonical_vote_json(
    const gossip::GovernanceVoteData& v) {
    json j = {
        {"approve",       v.approve},
        {"proposal_id",   v.proposal_id},
        {"reason",        v.reason},
        {"timestamp",     v.timestamp},
        {"voter_pubkey",  v.voter_pubkey},
    };
    return j.dump();
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

GovernanceService::GovernanceService(crypto::SodiumCryptoService& crypto,
                                       storage::FileStorageService& storage,
                                       RootKeyChainService& root_key_chain)
    : crypto_(crypto), storage_(storage), root_key_chain_(root_key_chain) {}

void GovernanceService::set_broadcast_fn(BroadcastFn fn) {
    broadcast_fn_ = std::move(fn);
}

void GovernanceService::set_keypair(const crypto::Ed25519Keypair& kp) {
    keypair_ = kp;
}

void GovernanceService::set_tier1_peer_count(uint32_t count) {
    tier1_peer_count_ = count;
}

// ---------------------------------------------------------------------------
// IService lifecycle
// ---------------------------------------------------------------------------

void GovernanceService::on_start() {
    load_state();
    if (!proposals_.empty()) {
        uint32_t active = 0;
        for (const auto& [id, ballot] : proposals_) {
            if (ballot.state == gossip::GovernanceBallot::State::Collecting) ++active;
        }
        spdlog::info("[{}] loaded {} proposals ({} active)", name(), proposals_.size(), active);
    }
}

void GovernanceService::on_stop() {
    save_state();
}

// ---------------------------------------------------------------------------
// Proposal creation
// ---------------------------------------------------------------------------

std::string GovernanceService::create_proposal(gossip::GovernableParam parameter,
                                                 const std::string& new_value,
                                                 const std::string& rationale) {
    // Validate parameter value
    if (!validate_param_value(parameter, new_value)) {
        spdlog::warn("[{}] invalid parameter value for proposal", name());
        return {};
    }

    auto now = static_cast<uint64_t>(
        chrono::duration_cast<chrono::seconds>(
            chrono::system_clock::now().time_since_epoch()).count());

    // Generate proposal ID: hex of random 16 bytes
    std::array<uint8_t, 16> id_bytes{};
    randombytes_buf(id_bytes.data(), id_bytes.size());
    std::string proposal_id = crypto::to_hex(
        std::vector<uint8_t>(id_bytes.begin(), id_bytes.end()));

    gossip::GovernanceProposalData proposal;
    proposal.proposal_id     = proposal_id;
    proposal.proposer_pubkey = crypto::to_hex(
        std::vector<uint8_t>(keypair_.public_key.begin(), keypair_.public_key.end()));
    proposal.parameter       = parameter;
    proposal.new_value       = new_value;
    proposal.old_value       = current_param_value(parameter);
    proposal.rationale       = rationale;
    proposal.created_at      = now;
    proposal.expires_at      = now + kProposalTimeoutSec;

    // Sign the proposal
    auto canonical = canonical_proposal_json(proposal);
    auto sig = crypto_.ed25519_sign(
        keypair_.private_key,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(canonical.data()),
                                  canonical.size()));
    proposal.signature = crypto::to_base64(
        std::vector<uint8_t>(sig.begin(), sig.end()));

    // Store locally
    {
        std::lock_guard lock(mutex_);
        gossip::GovernanceBallot ballot;
        ballot.proposal = proposal;
        ballot.state    = gossip::GovernanceBallot::State::Collecting;
        proposals_[proposal_id] = std::move(ballot);
    }

    // Broadcast to all peers
    if (broadcast_fn_) {
        json msg = {
            {"proposal_id",      proposal.proposal_id},
            {"proposer_pubkey",  proposal.proposer_pubkey},
            {"parameter",        static_cast<uint8_t>(proposal.parameter)},
            {"new_value",        proposal.new_value},
            {"old_value",        proposal.old_value},
            {"rationale",        proposal.rationale},
            {"created_at",       proposal.created_at},
            {"expires_at",       proposal.expires_at},
            {"signature",        proposal.signature},
        };
        auto payload = json::to_msgpack(msg);
        broadcast_fn_(gossip::GossipMsgType::GovernanceProposal, payload);
    }

    // Auto-vote approve (proposer votes yes)
    gossip::GovernanceVoteData self_vote;
    self_vote.proposal_id  = proposal_id;
    self_vote.voter_pubkey = proposal.proposer_pubkey;
    self_vote.approve      = true;
    self_vote.reason       = "proposer";
    self_vote.timestamp    = now;

    auto vote_canonical = canonical_vote_json(self_vote);
    auto vote_sig = crypto_.ed25519_sign(
        keypair_.private_key,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(vote_canonical.data()),
                                  vote_canonical.size()));
    self_vote.signature = crypto::to_base64(
        std::vector<uint8_t>(vote_sig.begin(), vote_sig.end()));

    handle_vote(self_vote);

    save_state();

    spdlog::info("[{}] created proposal {} for parameter {} -> {}",
                  name(), proposal_id.substr(0, 12), static_cast<int>(parameter), new_value);

    return proposal_id;
}

// ---------------------------------------------------------------------------
// Incoming gossip handlers
// ---------------------------------------------------------------------------

bool GovernanceService::handle_proposal(const gossip::GovernanceProposalData& proposal) {
    // Verify signature
    if (!verify_proposal_signature(proposal)) {
        spdlog::warn("[{}] rejected proposal {} — invalid signature", name(), proposal.proposal_id.substr(0, 12));
        return false;
    }

    // Validate parameter value
    if (!validate_param_value(proposal.parameter, proposal.new_value)) {
        spdlog::warn("[{}] rejected proposal {} — invalid param value", name(), proposal.proposal_id.substr(0, 12));
        return false;
    }

    auto now = static_cast<uint64_t>(
        chrono::duration_cast<chrono::seconds>(
            chrono::system_clock::now().time_since_epoch()).count());

    // Check if expired
    if (proposal.expires_at > 0 && proposal.expires_at < now) {
        spdlog::debug("[{}] ignoring expired proposal {}", name(), proposal.proposal_id.substr(0, 12));
        return false;
    }

    // Check old_value matches current (safety against stale proposals)
    auto current = current_param_value(proposal.parameter);
    if (proposal.old_value != current) {
        spdlog::warn("[{}] rejected proposal {} — old_value mismatch (expected '{}', got '{}')",
                      name(), proposal.proposal_id.substr(0, 12), current, proposal.old_value);
        return false;
    }

    {
        std::lock_guard lock(mutex_);
        // Deduplicate
        if (proposals_.contains(proposal.proposal_id)) {
            return false;
        }

        gossip::GovernanceBallot ballot;
        ballot.proposal = proposal;
        ballot.state    = gossip::GovernanceBallot::State::Collecting;
        proposals_[proposal.proposal_id] = std::move(ballot);
    }

    spdlog::info("[{}] accepted proposal {} from {} — param {} -> {}",
                  name(), proposal.proposal_id.substr(0, 12),
                  proposal.proposer_pubkey.substr(0, 12),
                  static_cast<int>(proposal.parameter), proposal.new_value);

    save_state();
    return true;
}

bool GovernanceService::handle_vote(const gossip::GovernanceVoteData& vote) {
    // Verify signature
    if (!verify_vote_signature(vote)) {
        spdlog::warn("[{}] rejected vote for {} — invalid signature", name(), vote.proposal_id.substr(0, 12));
        return false;
    }

    {
        std::lock_guard lock(mutex_);
        auto it = proposals_.find(vote.proposal_id);
        if (it == proposals_.end()) {
            spdlog::debug("[{}] ignoring vote for unknown proposal {}", name(), vote.proposal_id.substr(0, 12));
            return false;
        }

        auto& ballot = it->second;
        if (ballot.state != gossip::GovernanceBallot::State::Collecting) {
            return false; // already decided
        }

        // Deduplicate votes from the same voter
        for (const auto& existing : ballot.votes) {
            if (existing.voter_pubkey == vote.voter_pubkey) {
                return false;
            }
        }

        ballot.votes.push_back(vote);
        spdlog::info("[{}] received {} vote from {} for proposal {}",
                      name(), vote.approve ? "APPROVE" : "REJECT",
                      vote.voter_pubkey.substr(0, 12), vote.proposal_id.substr(0, 12));
    }

    // Check if quorum reached
    check_governance_quorum(vote.proposal_id);

    // Broadcast vote to peers
    if (broadcast_fn_) {
        json msg = {
            {"proposal_id",  vote.proposal_id},
            {"voter_pubkey", vote.voter_pubkey},
            {"approve",      vote.approve},
            {"reason",       vote.reason},
            {"timestamp",    vote.timestamp},
            {"signature",    vote.signature},
        };
        auto payload = json::to_msgpack(msg);
        broadcast_fn_(gossip::GossipMsgType::GovernanceVote, payload);
    }

    save_state();
    return true;
}

void GovernanceService::expire_proposals() {
    auto now = static_cast<uint64_t>(
        chrono::duration_cast<chrono::seconds>(
            chrono::system_clock::now().time_since_epoch()).count());

    std::lock_guard lock(mutex_);
    for (auto& [id, ballot] : proposals_) {
        if (ballot.state == gossip::GovernanceBallot::State::Collecting &&
            ballot.proposal.expires_at > 0 && ballot.proposal.expires_at < now) {
            ballot.state = gossip::GovernanceBallot::State::TimedOut;
            spdlog::info("[{}] proposal {} timed out ({} votes received)",
                          name(), id.substr(0, 12), ballot.votes.size());
        }
    }
}

// ---------------------------------------------------------------------------
// Quorum check and application
// ---------------------------------------------------------------------------

void GovernanceService::check_governance_quorum(const std::string& proposal_id) {
    std::lock_guard lock(mutex_);
    auto it = proposals_.find(proposal_id);
    if (it == proposals_.end()) return;

    auto& ballot = it->second;
    if (ballot.state != gossip::GovernanceBallot::State::Collecting) return;

    // Count votes
    uint32_t approve_count = 0;
    uint32_t reject_count  = 0;
    for (const auto& v : ballot.votes) {
        if (v.approve) ++approve_count;
        else           ++reject_count;
    }

    // Quorum: >50% of known Tier1 peers must approve
    // Include ourselves in the count (we're a Tier1 peer participating in governance)
    uint32_t total_tier1 = tier1_peer_count_ + 1; // +1 for ourselves
    if (total_tier1 < 1) total_tier1 = 1;

    auto quorum_needed = static_cast<uint32_t>(
        std::ceil(static_cast<float>(total_tier1) * kGovernanceQuorum));
    if (quorum_needed < 1) quorum_needed = 1;

    if (approve_count >= quorum_needed) {
        ballot.state = gossip::GovernanceBallot::State::Approved;
        spdlog::info("[{}] proposal {} APPROVED ({}/{} votes, quorum={})",
                      name(), proposal_id.substr(0, 12),
                      approve_count, ballot.votes.size(), quorum_needed);
        apply_proposal(ballot.proposal);
    } else if (reject_count > total_tier1 - quorum_needed) {
        // Enough rejections that approval is impossible
        ballot.state = gossip::GovernanceBallot::State::Rejected;
        spdlog::info("[{}] proposal {} REJECTED ({} rejections, approval impossible)",
                      name(), proposal_id.substr(0, 12), reject_count);
    }
}

void GovernanceService::apply_proposal(const gossip::GovernanceProposalData& proposal) {
    // Read current values
    auto rotation = root_key_chain_.rotation_interval_sec();
    auto quorum   = root_key_chain_.quorum_ratio();
    auto uptime   = root_key_chain_.min_uptime();

    switch (proposal.parameter) {
        case gossip::GovernableParam::RotationIntervalSec:
            rotation = static_cast<uint32_t>(std::stoul(proposal.new_value));
            break;
        case gossip::GovernableParam::ShamirQuorumRatio:
            quorum = std::stof(proposal.new_value);
            break;
        case gossip::GovernableParam::MinTier1Uptime:
            uptime = std::stof(proposal.new_value);
            break;
    }

    root_key_chain_.apply_governance_params(rotation, quorum, uptime);

    spdlog::info("[{}] applied governance change: param {} = {}",
                  name(), static_cast<int>(proposal.parameter), proposal.new_value);
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

std::vector<gossip::GovernanceBallot> GovernanceService::active_proposals() const {
    std::lock_guard lock(mutex_);
    std::vector<gossip::GovernanceBallot> result;
    for (const auto& [id, ballot] : proposals_) {
        if (ballot.state == gossip::GovernanceBallot::State::Collecting) {
            result.push_back(ballot);
        }
    }
    return result;
}

std::vector<gossip::GovernanceBallot> GovernanceService::all_proposals() const {
    std::lock_guard lock(mutex_);
    std::vector<gossip::GovernanceBallot> result;
    result.reserve(proposals_.size());
    for (const auto& [id, ballot] : proposals_) {
        result.push_back(ballot);
    }
    return result;
}

nlohmann::json GovernanceService::current_params() const {
    return json{
        {"rotation_interval_sec", root_key_chain_.rotation_interval_sec()},
        {"shamir_quorum_ratio",   root_key_chain_.quorum_ratio()},
        {"min_tier1_uptime",      root_key_chain_.min_uptime()},
    };
}

// ---------------------------------------------------------------------------
// Parameter validation
// ---------------------------------------------------------------------------

bool GovernanceService::validate_param_value(gossip::GovernableParam param,
                                               const std::string& value) const {
    try {
        switch (param) {
            case gossip::GovernableParam::RotationIntervalSec: {
                auto v = std::stoul(value);
                // Minimum 1 day, maximum 90 days
                return v >= 86400 && v <= 7776000;
            }
            case gossip::GovernableParam::ShamirQuorumRatio: {
                auto v = std::stof(value);
                // Minimum 51% (safety), maximum 100%
                return v >= 0.51f && v <= 1.0f;
            }
            case gossip::GovernableParam::MinTier1Uptime: {
                auto v = std::stof(value);
                // Minimum 50%, maximum 99.9%
                return v >= 0.50f && v <= 0.999f;
            }
        }
    } catch (...) {
        return false;
    }
    return false;
}

std::string GovernanceService::current_param_value(gossip::GovernableParam param) const {
    switch (param) {
        case gossip::GovernableParam::RotationIntervalSec:
            return std::to_string(root_key_chain_.rotation_interval_sec());
        case gossip::GovernableParam::ShamirQuorumRatio:
            return std::to_string(root_key_chain_.quorum_ratio());
        case gossip::GovernableParam::MinTier1Uptime:
            return std::to_string(root_key_chain_.min_uptime());
    }
    return {};
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

bool GovernanceService::verify_proposal_signature(
    const gossip::GovernanceProposalData& p) const {
    if (p.signature.empty() || p.proposer_pubkey.empty()) return false;

    auto pubkey_bytes = crypto::from_hex(p.proposer_pubkey);
    if (pubkey_bytes.size() != crypto::kEd25519PublicKeySize) return false;

    crypto::Ed25519PublicKey pk{};
    std::memcpy(pk.data(), pubkey_bytes.data(), pk.size());

    auto sig_bytes = crypto::from_base64(p.signature);
    if (sig_bytes.size() != crypto::kEd25519SignatureSize) return false;

    crypto::Ed25519Signature sig{};
    std::memcpy(sig.data(), sig_bytes.data(), sig.size());

    auto canonical = canonical_proposal_json(p);
    return crypto_.ed25519_verify(
        pk,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(canonical.data()),
                                  canonical.size()),
        sig);
}

bool GovernanceService::verify_vote_signature(
    const gossip::GovernanceVoteData& v) const {
    if (v.signature.empty() || v.voter_pubkey.empty()) return false;

    auto pubkey_bytes = crypto::from_hex(v.voter_pubkey);
    if (pubkey_bytes.size() != crypto::kEd25519PublicKeySize) return false;

    crypto::Ed25519PublicKey pk{};
    std::memcpy(pk.data(), pubkey_bytes.data(), pk.size());

    auto sig_bytes = crypto::from_base64(v.signature);
    if (sig_bytes.size() != crypto::kEd25519SignatureSize) return false;

    crypto::Ed25519Signature sig{};
    std::memcpy(sig.data(), sig_bytes.data(), sig.size());

    auto canonical = canonical_vote_json(v);
    return crypto_.ed25519_verify(
        pk,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(canonical.data()),
                                  canonical.size()),
        sig);
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

void GovernanceService::load_state() {
    auto env = storage_.read_file("governance", "proposals.json");
    if (!env) return;

    try {
        auto j = json::parse(env->data);
        if (!j.is_array()) return;

        for (const auto& entry : j) {
            gossip::GovernanceBallot ballot;
            ballot.state = static_cast<gossip::GovernanceBallot::State>(
                entry.value("state", 0));

            auto& p = ballot.proposal;
            const auto& pj = entry.at("proposal");
            p.proposal_id     = pj.value("proposal_id", "");
            p.proposer_pubkey = pj.value("proposer_pubkey", "");
            p.parameter       = static_cast<gossip::GovernableParam>(pj.value("parameter", 0));
            p.new_value       = pj.value("new_value", "");
            p.old_value       = pj.value("old_value", "");
            p.rationale       = pj.value("rationale", "");
            p.created_at      = pj.value("created_at", uint64_t{0});
            p.expires_at      = pj.value("expires_at", uint64_t{0});
            p.signature       = pj.value("signature", "");

            if (entry.contains("votes") && entry["votes"].is_array()) {
                for (const auto& vj : entry["votes"]) {
                    gossip::GovernanceVoteData vote;
                    vote.proposal_id  = vj.value("proposal_id", "");
                    vote.voter_pubkey = vj.value("voter_pubkey", "");
                    vote.approve      = vj.value("approve", false);
                    vote.reason       = vj.value("reason", "");
                    vote.timestamp    = vj.value("timestamp", uint64_t{0});
                    vote.signature    = vj.value("signature", "");
                    ballot.votes.push_back(std::move(vote));
                }
            }

            if (!p.proposal_id.empty()) {
                proposals_[p.proposal_id] = std::move(ballot);
            }
        }
    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to load governance state: {}", name(), e.what());
    }
}

void GovernanceService::save_state() {
    std::lock_guard lock(mutex_);

    json arr = json::array();
    for (const auto& [id, ballot] : proposals_) {
        json entry;
        entry["state"] = static_cast<uint8_t>(ballot.state);

        const auto& p = ballot.proposal;
        entry["proposal"] = {
            {"proposal_id",      p.proposal_id},
            {"proposer_pubkey",  p.proposer_pubkey},
            {"parameter",        static_cast<uint8_t>(p.parameter)},
            {"new_value",        p.new_value},
            {"old_value",        p.old_value},
            {"rationale",        p.rationale},
            {"created_at",       p.created_at},
            {"expires_at",       p.expires_at},
            {"signature",        p.signature},
        };

        json votes_arr = json::array();
        for (const auto& v : ballot.votes) {
            votes_arr.push_back({
                {"proposal_id",  v.proposal_id},
                {"voter_pubkey", v.voter_pubkey},
                {"approve",      v.approve},
                {"reason",       v.reason},
                {"timestamp",    v.timestamp},
                {"signature",    v.signature},
            });
        }
        entry["votes"] = votes_arr;

        arr.push_back(std::move(entry));
    }

    storage::SignedEnvelope env;
    env.type = "governance_proposals";
    env.data = arr.dump(2);
    env.timestamp = static_cast<uint64_t>(
        chrono::duration_cast<chrono::seconds>(
            chrono::system_clock::now().time_since_epoch()).count());
    (void)storage_.write_file("governance", "proposals.json", env);
}

} // namespace nexus::core
