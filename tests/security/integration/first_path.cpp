// The first integrated security path (class structure 47):
//
//   verdicts -> Tier1EligibilityPolicy -> Genesis founding set -> Epoch 1 DKG
//   -> bootstrap certificate -> Epoch 1 activates -> HotStuff commits
//   -> FROST authority signature -> Epoch 2 handoff.
//
// Five in-process runtimes exchange every message directly. The attestation
// verifier's positive path needs a real confidential VM, so the verdicts here
// are constructed; everything after them — eligibility, selection, DKG,
// certificates, consensus, and signing — runs the real code and real crypto.

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Consensus/LeaderSelection.hpp>
#include <LemonadeNexus/Security/Consensus/VoteKey.hpp>
#include <LemonadeNexus/Security/Genesis/GenesisService.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Policy/Tier1Eligibility.hpp>
#include <LemonadeNexus/Security/SecurityRuntime.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <unistd.h>
#include <vector>

using namespace nexus::security;
namespace constants = nexus::security::constants;
namespace fs = std::filesystem;

namespace {

constexpr std::size_t kFounders = 5;

struct Node {
    nexus::crypto::Ed25519PublicKey identity_pub{};
    nexus::crypto::Ed25519PrivateKey identity_priv{};
    NodeId id;
    fs::path dir;
    std::unique_ptr<SecurityRuntime> runtime;
};

AttestationVerdict passing_verdict(const NodeId& id, EpochId epoch) {
    AttestationVerdict verdict;
    verdict.node_id = id;
    verdict.epoch = epoch;
    verdict.incarnation = 1;
    verdict.passed = true;
    verdict.evidence_digest.fill(id.bytes[0]);
    return verdict;
}

Tier1EvidenceState all_prerequisites_pass() {
    Tier1EvidenceState state;
    state.node_identity_valid = state.certificate_valid = true;
    state.snp_valid = state.vtpm_valid = state.quote_fresh = true;
    state.boot_state_valid = state.binary_valid = state.ima_valid = true;
    state.runtime_profile_valid = state.uptime_valid = state.mesh_health_valid = true;
    state.incarnation_current = state.epoch_current = true;
    return state;
}

Digest attestation_root(const std::vector<AttestationVerdict>& verdicts) {
    CanonicalEncoder encoder("lemonade-nexus/attestation-root:v1");
    encoder.add_u64(verdicts.size());
    for (const auto& verdict : verdicts) {
        encoder.add_bytes(verdict.node_id.bytes);
        encoder.add_bytes(verdict.evidence_digest);
    }
    return encoder.digest();
}

struct DkgRun {
    std::vector<DkgResult> results;
    Digest transcript{};
};

DkgTranscriptAttest signed_transcript_attest(const Node& node, const Tier1Set& founders,
                                             const Digest& transcript,
                                             const nexus::crypto::Ed25519PublicKey& group) {
    DkgTranscriptAttest attest;
    attest.epoch = 1;
    attest.participant_set_digest = founders.digest();
    attest.transcript_digest = transcript;
    attest.group_public_key = group;
    attest.node = node.id;
    const Digest digest = dkg_transcript_attest_digest(attest);
    crypto_sign_detached(attest.identity_signature.data(), nullptr, digest.data(), digest.size(),
                         node.identity_priv.data());
    return attest;
}

// Runs one dealerless DKG across the runtimes of the given participants.
DkgRun run_dkg(std::vector<Node*> participants, const NetworkId& network, EpochId target) {
    std::vector<NodeId> ids;
    std::map<NodeId, IncarnationId> incarnations;
    for (const Node* node : participants) {
        ids.push_back(node->id);
        incarnations[node->id] = 1;
    }
    const Tier1Set set = *Tier1Set::from_nodes(ids);

    std::vector<DkgMessage> broadcasts;
    for (Node* node : participants) {
        DkgConfiguration config;
        config.network_id = network;
        config.target_epoch = target;
        config.participants = set;
        config.incarnations = incarnations;
        config.threshold = constants::authority_threshold(set.size());
        config.self = node->id;
        auto message = node->runtime->authority().start_dkg(config);
        EXPECT_TRUE(message.has_value());
        broadcasts.push_back(*message);
    }
    for (Node* node : participants) {
        for (const auto& broadcast : broadcasts) {
            (void)node->runtime->authority().dkg()->receive_broadcast(broadcast);
        }
    }
    std::vector<DkgMessage> pairwise;
    for (Node* node : participants) {
        auto messages = node->runtime->authority().dkg()->round2_messages();
        pairwise.insert(pairwise.end(), messages.begin(), messages.end());
    }
    for (const auto& message : pairwise) {
        for (Node* node : participants) {
            if (node->id == message.recipient) {
                EXPECT_EQ(node->runtime->authority().dkg()->receive_pairwise(message),
                          DkgFailure::None);
            }
        }
    }
    DkgRun run;
    for (Node* node : participants) {
        EXPECT_TRUE(node->runtime->authority().dkg()->finish());
        run.transcript = *node->runtime->authority().dkg()->transcript_digest();
        auto result = node->runtime->authority().take_dkg_result();
        EXPECT_TRUE(result.has_value());
        run.results.push_back(std::move(*result));
    }
    return run;
}

QuorumCertificate genesis_qc(const NetworkId& network, EpochId epoch, const Digest& anchor) {
    QuorumCertificate certificate{};
    certificate.qc_format_version = constants::kQcFormatVersion;
    certificate.consensus_ruleset = constants::kConsensusRulesetVersion;
    certificate.network_id = network;
    certificate.epoch = epoch;
    certificate.height = 0;
    certificate.view = 0;
    certificate.proposal_digest = anchor;
    return certificate;
}

struct Round {
    Proposal proposal;
    QuorumCertificate certificate;
    std::vector<ConsensusCommit> commits;
};

// One HotStuff round: the leader proposes on top of `justify`, every member
// votes, the leader forms the certificate.
void run_round(std::vector<Node*>& members, const std::vector<NodeId>& order,
               const QuorumCertificate& justify, uint8_t state_byte, Round& round) {
    // The justify proves the network reached its view; the round is the next
    // one. Votes go to the leader of the view after that, who forms the
    // certificate and proposes on it (chained HotStuff).
    const View view = justify.view + 1;
    Node* leader = nullptr;
    Node* next_leader = nullptr;
    for (Node* node : members) {
        if (node->id == order[view % order.size()]) leader = node;
        if (node->id == order[(view + 1) % order.size()]) next_leader = node;
    }
    ASSERT_NE(leader, nullptr);
    ASSERT_NE(next_leader, nullptr);

    Digest previous;
    previous.fill(static_cast<uint8_t>(state_byte - 1));
    Digest proposed;
    proposed.fill(state_byte);
    Digest transitions;
    transitions.fill(0xF0);
    auto made = leader->runtime->consensus()->make_proposal(previous, proposed, transitions);
    if (!std::holds_alternative<Proposal>(made)) {
        ADD_FAILURE() << "make_proposal failed with code "
                      << static_cast<int>(std::get<ConsensusFailure>(made)) << " at view " << view
                      << " leader current_view " << leader->runtime->consensus()->current_view();
        return;
    }
    round.proposal = std::get<Proposal>(made);

    std::vector<Vote> votes;
    for (Node* node : members) {
        auto result = node->runtime->consensus()->receive_proposal(round.proposal, justify);
        EXPECT_FALSE(result.rejected.has_value());
        EXPECT_TRUE(result.vote.has_value());
        if (result.vote.has_value()) votes.push_back(*result.vote);
        if (!result.commits.empty()) round.commits = result.commits;
    }
    for (const auto& vote : votes) {
        auto outcome = next_leader->runtime->consensus()->receive_vote(vote);
        if (std::holds_alternative<QuorumCertificate>(outcome)) {
            round.certificate = std::get<QuorumCertificate>(outcome);
        }
    }
    EXPECT_EQ(round.certificate.proposal_digest, proposal_digest(round.proposal));
}

Round run_round(std::vector<Node*>& members, const std::vector<NodeId>& order,
                const QuorumCertificate& justify, uint8_t state_byte) {
    Round round;
    run_round(members, order, justify, state_byte, round);
    return round;
}

struct FirstPath : ::testing::Test {
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        crypto_sign_keypair(genesis_pub.data(), genesis_priv.data());
        network = derive_network_id(genesis_pub, constants::kSecurityRulesetVersion,
                                    constants::kConsensusRulesetVersion);
        root = fs::temp_directory_path() / ("nexus_first_path_" + std::to_string(::getpid()));
        fs::create_directories(root);

        for (std::size_t i = 0; i < kFounders + 1; ++i) {
            auto node = std::make_unique<Node>();
            crypto_sign_keypair(node->identity_pub.data(), node->identity_priv.data());
            node->id.bytes = node->identity_pub;
            node->dir = root / ("node" + std::to_string(i));
            SecurityRuntimeConfig config;
            config.self = node->id;
            config.consensus_directory = node->dir;
            // This test drives the runtime directly, with no driver to hold a
            // pending handoff. Every replica here has agreed to the transition
            // the test proposes; the refusal rule itself lives in
            // tests/security/consensus/hotstuff_safety.cpp.
            config.transition_validator = [](const Digest&) { return true; };
            node->runtime = std::make_unique<SecurityRuntime>(config);
            nodes.push_back(std::move(node));
        }
        for (std::size_t i = 0; i < kFounders; ++i) founders.push_back(nodes[i].get());
        outsider = nodes[kFounders].get();
    }

    void TearDown() override { fs::remove_all(root); }

    nexus::crypto::Ed25519PublicKey genesis_pub{};
    nexus::crypto::Ed25519PrivateKey genesis_priv{};
    NetworkId network{};
    fs::path root;
    std::vector<std::unique_ptr<Node>> nodes;
    std::vector<Node*> founders;
    Node* outsider = nullptr;
};

TEST_F(FirstPath, GenesisToEpochTwo) {
    // --- Eligibility: policy decides, from verdicts, never from a vote. ---
    EXPECT_EQ(Tier1EligibilityPolicy::evaluate(all_prerequisites_pass()),
              Tier1Eligibility::Eligible);

    GenesisService genesis(network);
    std::vector<AttestationVerdict> verdicts;
    for (Node* node : founders) {
        ASSERT_TRUE(genesis.admit_candidate(node->id));
        verdicts.push_back(passing_verdict(node->id, 0));
        ASSERT_TRUE(genesis.record_verdict(verdicts.back()));
    }
    // A candidate that fails a prerequisite is introduced but never founds.
    ASSERT_TRUE(genesis.admit_candidate(outsider->id));
    auto failed = passing_verdict(outsider->id, 0);
    failed.passed = false;
    ASSERT_TRUE(genesis.record_verdict(failed));

    ASSERT_TRUE(genesis.quorum_ready());
    const Tier1Set founding_set = *genesis.founding_set();
    ASSERT_EQ(founding_set.size(), kFounders);
    EXPECT_FALSE(founding_set.contains(outsider->id));

    // --- Epoch 1 vote keys and fresh dealerless DKG. ---
    std::map<NodeId, nexus::crypto::Ed25519PublicKey> vote_keys_1;
    std::vector<EpochVoteKey> own_keys_1;
    for (Node* node : founders) {
        own_keys_1.push_back(make_epoch_vote_key(1, node->id));
        vote_keys_1[node->id] = own_keys_1.back().public_key;
    }
    DkgRun dkg_1 = run_dkg(founders, network, 1);
    ASSERT_EQ(dkg_1.results.size(), kFounders);
    for (const auto& result : dkg_1.results) {
        EXPECT_EQ(result.group_public_key, dkg_1.results[0].group_public_key);
    }

    // --- Genesis signs the one bootstrap certificate; its authority ends. ---
    std::sort(verdicts.begin(), verdicts.end(),
              [](const auto& a, const auto& b) { return a.node_id < b.node_id; });
    for (Node* node : founders) {
        ASSERT_TRUE(genesis.record_transcript_attest(signed_transcript_attest(
            *node, founding_set, dkg_1.transcript, dkg_1.results[0].group_public_key)));
    }
    ASSERT_TRUE(genesis.transcript_agreed());
    const auto certificate = genesis.finalize_epoch_one(
        dkg_1.results[0].group_public_key, dkg_1.transcript, attestation_root(verdicts),
        genesis_priv);
    ASSERT_TRUE(certificate.has_value());
    ASSERT_TRUE(verify_bootstrap_certificate(*certificate, genesis_pub));
    EXPECT_TRUE(genesis.finalized());

    // --- Every founder adopts Epoch 1; a tampered certificate is refused. ---
    auto tampered = *certificate;
    tampered.authority_threshold -= 1;
    EXPECT_FALSE(outsider->runtime->adopt_epoch_one(tampered, genesis_pub, founding_set,
                                                    vote_keys_1, std::nullopt, std::nullopt));
    EXPECT_TRUE(outsider->runtime->adopt_epoch_one(*certificate, genesis_pub, founding_set,
                                                   vote_keys_1, std::nullopt, std::nullopt));
    EXPECT_EQ(outsider->runtime->consensus(), nullptr);
    EXPECT_FALSE(outsider->runtime->authority().has_key_share());

    for (std::size_t i = 0; i < kFounders; ++i) {
        ASSERT_TRUE(founders[i]->runtime->adopt_epoch_one(
            *certificate, genesis_pub, founding_set, vote_keys_1, std::move(dkg_1.results[i]),
            std::move(own_keys_1[i])));
        ASSERT_NE(founders[i]->runtime->consensus(), nullptr);
        EXPECT_TRUE(founders[i]->runtime->consensus()->usable());
        EXPECT_EQ(founders[i]->runtime->epochs()->current().id, 1u);
        EXPECT_EQ(*founders[i]->runtime->authority().key_epoch(), 1u);
        EXPECT_EQ(*founders[i]->runtime->authority().group_public_key(),
                  certificate->authority_public_key);
    }

    // --- Chained HotStuff: three-chain commits b1. ---
    const Digest anchor = bootstrap_certificate_signing_digest(*certificate);
    const auto order = LeaderSelection::order(founding_set.members(), anchor, 1);
    QuorumCertificate justify = genesis_qc(network, 1, anchor);

    Round b1 = run_round(founders, order, justify, 0x10);
    Round b2 = run_round(founders, order, b1.certificate, 0x11);
    Round b3 = run_round(founders, order, b2.certificate, 0x12);
    EXPECT_TRUE(b3.commits.empty());
    Round b4 = run_round(founders, order, b3.certificate, 0x13);
    ASSERT_EQ(b4.commits.size(), 1u);
    EXPECT_EQ(b4.commits[0].height, 1u);
    EXPECT_EQ(b4.commits[0].proposal_digest, proposal_digest(b1.proposal));
    EXPECT_EQ(b4.commits[0].qc_digest, qc_digest(b1.certificate));

    // --- FROST signs the finalized object, and only that object. ---
    Digest previous_state;
    previous_state.fill(0x0F);
    const AuthorityObject object = make_authority_object(
        b4.commits[0], network, AuthorityOperation::EpochTransition, 1, previous_state);
    std::vector<NodeId> signer_set = founding_set.members();

    auto start = founders[0]->runtime->authority().start_signing(object, b1.certificate,
                                                                 signer_set);
    ASSERT_EQ(start.failure, SigningFailure::None);
    std::vector<FrostCommitmentMessage> commitments{*start.commitment};
    for (std::size_t i = 1; i < kFounders; ++i) {
        auto join = founders[i]->runtime->authority().join_signing(*start.session_id, object,
                                                                   b1.certificate, signer_set);
        ASSERT_EQ(join.failure, SigningFailure::None);
        commitments.push_back(*join.commitment);
    }
    std::vector<FrostShareMessage> shares;
    for (Node* node : founders) {
        for (const auto& commitment : commitments) {
            auto outcome = node->runtime->authority().receive_commitment(commitment);
            if (std::holds_alternative<FrostShareMessage>(outcome)) {
                shares.push_back(std::get<FrostShareMessage>(outcome));
            }
        }
    }
    ASSERT_EQ(shares.size(), kFounders);
    std::optional<AuthoritySignature> signature;
    for (Node* node : founders) {
        for (const auto& share : shares) {
            auto outcome = node->runtime->authority().receive_signature_share(share);
            if (std::holds_alternative<AuthoritySignature>(outcome)) {
                signature = std::get<AuthoritySignature>(outcome);
            }
        }
    }
    ASSERT_TRUE(signature.has_value());
    EXPECT_TRUE(nexus::crypto::FrostProvider::verify(certificate->authority_public_key,
                                                     authority_object_digest(object),
                                                     signature->signature));

    // --- Epoch 2 handoff: select, attest, vote keys, DKG, authorize, activate. ---
    std::map<NodeId, nexus::crypto::Ed25519PublicKey> vote_keys_2;
    std::vector<EpochVoteKey> own_keys_2;
    for (Node* node : founders) {
        own_keys_2.push_back(make_epoch_vote_key(2, node->id));
        vote_keys_2[node->id] = own_keys_2.back().public_key;
    }
    DkgRun dkg_2 = run_dkg(founders, network, 2);
    EXPECT_NE(dkg_2.results[0].group_public_key, certificate->authority_public_key);

    for (Node* node : founders) {
        EpochManager* epochs = node->runtime->epochs();
        ASSERT_TRUE(epochs->prepare_next_epoch(founding_set, kFounders));
        for (Node* member : founders) {
            ASSERT_TRUE(epochs->record_final_attestation(passing_verdict(member->id, 2)));
            ASSERT_TRUE(epochs->record_vote_key(member->id, vote_keys_2.at(member->id)));
        }
        ASSERT_TRUE(epochs->record_dkg_result(dkg_2.results[0].group_public_key, dkg_2.transcript));
        ASSERT_EQ(epochs->transition()->phase, EpochTransitionPhase::Ready);
        ASSERT_TRUE(epochs->record_handoff_authorization(qc_digest(b1.certificate)));
    }
    const Digest checkpoint_2 = qc_digest(b1.certificate);
    for (std::size_t i = 0; i < kFounders; ++i) {
        ASSERT_TRUE(founders[i]->runtime->activate_next_epoch(
            std::move(dkg_2.results[i]), std::move(own_keys_2[i]), checkpoint_2));
        EXPECT_EQ(founders[i]->runtime->epochs()->current().id, 2u);
        EXPECT_EQ(*founders[i]->runtime->authority().key_epoch(), 2u);
        EXPECT_NE(*founders[i]->runtime->authority().group_public_key(),
                  certificate->authority_public_key);
        ASSERT_NE(founders[i]->runtime->consensus(), nullptr);
        EXPECT_TRUE(founders[i]->runtime->consensus()->usable());
    }

    // The old epoch's authority is historical: its object cannot be signed
    // again, and an epoch-1 vote key cannot vote in epoch 2.
    EXPECT_EQ(founders[0]->runtime->authority().start_signing(object, b1.certificate, signer_set)
                  .failure,
              SigningFailure::WrongEpoch);

    Vote stale{};
    stale.consensus_ruleset = constants::kConsensusRulesetVersion;
    stale.network_id = network;
    stale.epoch = 2;
    stale.height = 1;
    stale.view = founders[0]->runtime->consensus()->current_view();
    stale.proposal_digest.fill(0x99);
    stale.voter = founders[1]->id;
    const EpochVoteKey old_key = make_epoch_vote_key(1, founders[1]->id);
    stale.signature = sign_digest(old_key, vote_signing_digest(stale));
    auto refused = founders[0]->runtime->consensus()->receive_vote(stale);
    ASSERT_TRUE(std::holds_alternative<ConsensusFailure>(refused));
    EXPECT_EQ(std::get<ConsensusFailure>(refused), ConsensusFailure::InvalidSignature);

    // Epoch 2 makes progress under the new keys.
    const auto order_2 = LeaderSelection::order(founding_set.members(), checkpoint_2, 2);
    Round c1 = run_round(founders, order_2, genesis_qc(network, 2, checkpoint_2), 0x20);
    EXPECT_EQ(c1.certificate.epoch, 2u);
    EXPECT_EQ(c1.certificate.signers.size(), constants::consensus_quorum(kFounders));
}

}  // namespace
