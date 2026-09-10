#pragma once

// Shared deterministic harness for the HotStuff service tests.
//
// Fixed network and genesis digests, byte-pattern node identities, real
// per-epoch vote keys, a chain builder whose QCs every member signs, and a
// recording store that can refuse to persist.

#include <LemonadeNexus/Security/Consensus/ConsensusStore.hpp>
#include <LemonadeNexus/Security/Consensus/ConsensusTypes.hpp>
#include <LemonadeNexus/Security/Consensus/HotStuffService.hpp>
#include <LemonadeNexus/Security/Consensus/HotStuffState.hpp>
#include <LemonadeNexus/Security/Consensus/QuorumValidation.hpp>
#include <LemonadeNexus/Security/Consensus/VoteKey.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <utility>
#include <variant>
#include <vector>

namespace hotstuff_test {

namespace constants = nexus::security::constants;
using nexus::security::ConsensusCommit;
using nexus::security::ConsensusFailure;
using nexus::security::Digest;
using nexus::security::EpochId;
using nexus::security::EpochVoteKey;
using nexus::security::Height;
using nexus::security::HotStuffConfig;
using nexus::security::HotStuffService;
using nexus::security::HotStuffState;
using nexus::security::IConsensusStore;
using nexus::security::NetworkId;
using nexus::security::NodeId;
using nexus::security::Proposal;
using nexus::security::ProposalResult;
using nexus::security::QcSigner;
using nexus::security::QcValidationContext;
using nexus::security::QuorumCertificate;
using nexus::security::TimeoutCertificate;
using nexus::security::TimeoutVote;
using nexus::security::View;
using nexus::security::Vote;

inline constexpr EpochId kEpoch = 7;

[[nodiscard]] inline Digest filled_digest(uint8_t value) {
    Digest digest{};
    digest.fill(value);
    return digest;
}

[[nodiscard]] inline NodeId filled_node(uint8_t value) {
    NodeId node{};
    node.bytes.fill(value);
    return node;
}

[[nodiscard]] inline NetworkId test_network() { return filled_digest(0xAA); }
[[nodiscard]] inline Digest test_genesis() { return filled_digest(0x11); }

// EpochVoteKey is move-only; the service needs its own copy of a member key.
[[nodiscard]] inline EpochVoteKey clone_key(const EpochVoteKey& key) {
    EpochVoteKey copy{};
    copy.epoch = key.epoch;
    copy.node_id = key.node_id;
    copy.public_key = key.public_key;
    copy.private_key = nexus::crypto::SecureBuffer(key.private_key.span());
    return copy;
}

struct Block {
    Proposal proposal;
    // The QC the proposal ships with; it certifies the parent.
    QuorumCertificate justify;
    Digest digest;
};

class Harness {
public:
    explicit Harness(std::size_t member_count = 4) {
        for (std::size_t i = 0; i < member_count; ++i) {
            const NodeId node = filled_node(static_cast<uint8_t>(i + 1));
            members.push_back(node);
            keys.push_back(nexus::security::make_epoch_vote_key(kEpoch, node));
            vote_keys[node] = keys.back().public_key;
        }
        quorum = constants::consensus_quorum(member_count);
    }

    // leader_order is the member order: view v is led by members[v % n].
    [[nodiscard]] HotStuffConfig config_for(std::size_t self_index) const {
        HotStuffConfig config{};
        config.security_ruleset = constants::kSecurityRulesetVersion;
        config.consensus_ruleset = constants::kConsensusRulesetVersion;
        config.network_id = test_network();
        config.epoch = kEpoch;
        config.genesis_digest = test_genesis();
        config.leader_order = members;
        config.vote_keys = vote_keys;
        config.quorum = quorum;
        config.self = members[self_index];
        // These replicas model nodes that already arrived at whatever
        // transition a proposal carries, so the safety rules under test are
        // the only thing that can reject one. The refusal rule itself is
        // covered by TransitionUnknown tests in hotstuff_safety.cpp, and
        // production installs the driver's real pending handoff.
        config.transition_validator = [](const Digest&) { return true; };
        return config;
    }

    [[nodiscard]] QcValidationContext validation_context() const {
        return QcValidationContext{constants::kConsensusRulesetVersion, test_network(), kEpoch,
                                   quorum};
    }

    [[nodiscard]] QuorumCertificate genesis_qc() const {
        QuorumCertificate certificate{};
        certificate.qc_format_version = constants::kQcFormatVersion;
        certificate.consensus_ruleset = constants::kConsensusRulesetVersion;
        certificate.network_id = test_network();
        certificate.epoch = kEpoch;
        certificate.height = 0;
        certificate.view = 0;
        certificate.proposal_digest = test_genesis();
        return certificate;
    }

    // A QC over the proposal signed by every member.
    [[nodiscard]] QuorumCertificate qc_for(const Proposal& proposal) const {
        QuorumCertificate certificate{};
        certificate.qc_format_version = constants::kQcFormatVersion;
        certificate.consensus_ruleset = constants::kConsensusRulesetVersion;
        certificate.network_id = test_network();
        certificate.epoch = kEpoch;
        certificate.height = proposal.height;
        certificate.view = proposal.view;
        certificate.proposal_digest = nexus::security::proposal_digest(proposal);
        for (const auto& key : keys) {
            QcSigner signer{};
            signer.node_id = key.node_id;
            signer.signature = nexus::security::sign_digest(
                key, nexus::security::vote_signing_digest(
                         constants::kConsensusRulesetVersion, test_network(), kEpoch,
                         proposal.height, proposal.view, certificate.proposal_digest,
                         key.node_id));
            certificate.signers.push_back(signer);
        }
        return certificate;
    }

    // A proposal on top of parent_digest, justified by the given QC. The
    // leader is the correct one for the view.
    [[nodiscard]] Block make_block(Height height,
                                   View view,
                                   const Digest& parent_digest,
                                   const QuorumCertificate& justify,
                                   uint8_t payload_seed) const {
        Proposal proposal{};
        proposal.security_ruleset = constants::kSecurityRulesetVersion;
        proposal.consensus_ruleset = constants::kConsensusRulesetVersion;
        proposal.network_id = test_network();
        proposal.epoch = kEpoch;
        proposal.height = height;
        proposal.view = view;
        proposal.leader = members[view % members.size()];
        proposal.parent_digest = parent_digest;
        proposal.justify_qc_digest = nexus::security::qc_digest(justify);
        proposal.previous_state_root = filled_digest(payload_seed);
        proposal.proposed_state_root = filled_digest(static_cast<uint8_t>(payload_seed + 1));
        proposal.transitions_digest = filled_digest(static_cast<uint8_t>(payload_seed + 2));
        proposal.timestamp_hint = 0;
        return Block{proposal, justify, nexus::security::proposal_digest(proposal)};
    }

    // b1..bk: height i at view i, each justified by a full QC over its parent.
    [[nodiscard]] std::vector<Block> build_chain(std::size_t length) const {
        std::vector<Block> chain;
        QuorumCertificate justify = genesis_qc();
        Digest parent = test_genesis();
        for (std::size_t i = 1; i <= length; ++i) {
            Block block = make_block(i, i, parent, justify, static_cast<uint8_t>(0x20 + i * 4));
            parent = block.digest;
            justify = qc_for(block.proposal);
            chain.push_back(std::move(block));
        }
        return chain;
    }

    [[nodiscard]] Vote make_vote(std::size_t member_index,
                                 View view,
                                 Height height,
                                 const Digest& digest) const {
        Vote vote{};
        vote.consensus_ruleset = constants::kConsensusRulesetVersion;
        vote.network_id = test_network();
        vote.epoch = kEpoch;
        vote.height = height;
        vote.view = view;
        vote.proposal_digest = digest;
        vote.voter = members[member_index];
        vote.signature = nexus::security::sign_digest(
            keys[member_index], nexus::security::vote_signing_digest(vote));
        return vote;
    }

    [[nodiscard]] TimeoutVote make_timeout(std::size_t member_index,
                                           View view,
                                           const Digest& high_qc_digest) const {
        TimeoutVote vote{};
        vote.consensus_ruleset = constants::kConsensusRulesetVersion;
        vote.network_id = test_network();
        vote.epoch = kEpoch;
        vote.view = view;
        vote.high_qc_digest = high_qc_digest;
        vote.voter = members[member_index];
        vote.signature = nexus::security::sign_digest(
            keys[member_index], nexus::security::timeout_vote_signing_digest(vote));
        return vote;
    }

    std::vector<NodeId> members;
    std::vector<EpochVoteKey> keys;
    std::map<NodeId, nexus::crypto::Ed25519PublicKey> vote_keys;
    std::size_t quorum = 0;
};

// Logs every call. store_before_vote can be told to refuse.
class RecordingStore final : public IConsensusStore {
public:
    struct StoreCall {
        HotStuffState state;
        bool accepted;
    };

    [[nodiscard]] bool store_before_vote(const HotStuffState& state) override {
        const bool accepted = !fail_store_before_vote;
        calls.push_back({state, accepted});
        return accepted;
    }

    [[nodiscard]] std::variant<HotStuffState, LoadResult> load(EpochId) const override {
        if (seed_corrupt) return LoadResult::Corrupt;
        if (seed_state) return *seed_state;
        return LoadResult::Absent;
    }

    bool store_commit(const ConsensusCommit& commit) override {
        commits.push_back(commit);
        return true;
    }

    [[nodiscard]] std::optional<ConsensusCommit> latest_commit(EpochId) const override {
        if (commits.empty()) return std::nullopt;
        return commits.back();
    }

    bool fail_store_before_vote = false;
    bool seed_corrupt = false;
    std::optional<HotStuffState> seed_state;
    std::vector<StoreCall> calls;
    std::vector<ConsensusCommit> commits;
};

}  // namespace hotstuff_test
