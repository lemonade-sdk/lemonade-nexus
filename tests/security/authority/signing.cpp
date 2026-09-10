#include <LemonadeNexus/Crypto/FrostProvider.hpp>
#include <LemonadeNexus/Security/Authority/AuthorityService.hpp>
#include <LemonadeNexus/Security/Consensus/VoteKey.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>

#include <memory>
#include <vector>

using namespace nexus::security;
namespace constants = nexus::security::constants;

namespace {

NodeId node(uint8_t byte) {
    NodeId id;
    id.bytes.fill(byte);
    return id;
}

constexpr std::size_t kNodes = 5;
constexpr EpochId kEpoch = 2;

struct Mesh {
    // install == false keeps the DKG results for a test to install itself.
    explicit Mesh(EpochId target = kEpoch, bool install = true) : epoch(target) {
        network.fill(0x0F);
        for (std::size_t i = 1; i <= kNodes; ++i) {
            nodes.push_back(node(static_cast<uint8_t>(i)));
        }
        members = *Tier1Set::from_nodes(nodes);
        for (const auto& member : nodes) {
            vote_keys.push_back(make_epoch_vote_key(epoch, member));
            vote_pubkeys[member] = vote_keys.back().public_key;
        }
        run_dkg();
        build_certificate();

        ConsensusCommit commit;
        commit.epoch = epoch;
        commit.height = 3;
        commit.view = 3;
        commit.proposal_digest = certificate.proposal_digest;
        commit.proposed_state_root.fill(0x42);
        commit.qc_digest = qc_digest(certificate);
        Digest previous;
        previous.fill(0x41);
        object = make_authority_object(commit, network, AuthorityOperation::EpochTransition, 1,
                                       previous);

        for (std::size_t i = 0; i < kNodes; ++i) {
            stores.push_back(std::make_unique<NonceCommitmentStore>());
            services.push_back(std::make_unique<AuthorityService>(nodes[i], *stores.back()));
            if (install) {
                EXPECT_TRUE(services.back()->install_epoch(context(), std::move(dkg_results[i])));
            }
        }
    }

    AuthorityEpochContext context() const {
        AuthorityEpochContext ctx;
        ctx.network_id = network;
        ctx.epoch = epoch;
        ctx.consensus_quorum = constants::consensus_quorum(kNodes);
        ctx.authority_threshold = constants::authority_threshold(kNodes);
        ctx.members = members;
        ctx.vote_keys = vote_pubkeys;
        return ctx;
    }

    void run_dkg() {
        std::vector<std::unique_ptr<DkgSession>> sessions;
        std::map<NodeId, IncarnationId> incarnations;
        for (const auto& member : nodes) {
            incarnations[member] = 7;
        }
        for (const auto& member : nodes) {
            DkgConfiguration config;
            config.network_id = network;
            config.target_epoch = epoch;
            config.participants = members;
            config.incarnations = incarnations;
            config.threshold = constants::authority_threshold(kNodes);
            config.self = member;
            sessions.push_back(std::make_unique<DkgSession>(config));
        }
        std::vector<DkgMessage> broadcasts;
        for (auto& session : sessions) {
            broadcasts.push_back(*session->start());
        }
        for (auto& session : sessions) {
            for (const auto& broadcast : broadcasts) {
                (void)session->receive_broadcast(broadcast);
            }
        }
        std::vector<DkgMessage> pairwise;
        for (auto& session : sessions) {
            auto messages = session->round2_messages();
            pairwise.insert(pairwise.end(), messages.begin(), messages.end());
        }
        for (const auto& message : pairwise) {
            (void)sessions[message.recipient.bytes[0] - 1]->receive_pairwise(message);
        }
        for (auto& session : sessions) {
            EXPECT_TRUE(session->finish());
            dkg_results.push_back(*session->take_result());
        }
        group_key = dkg_results[0].group_public_key;
    }

    void build_certificate() {
        certificate.qc_format_version = constants::kQcFormatVersion;
        certificate.consensus_ruleset = constants::kConsensusRulesetVersion;
        certificate.network_id = network;
        certificate.epoch = epoch;
        certificate.height = 3;
        certificate.view = 3;
        certificate.proposal_digest.fill(0x31);
        for (const auto& key : vote_keys) {
            const Digest digest = vote_signing_digest(
                certificate.consensus_ruleset, certificate.network_id, certificate.epoch,
                certificate.height, certificate.view, certificate.proposal_digest, key.node_id);
            certificate.signers.push_back(QcSigner{key.node_id, sign_digest(key, digest)});
        }
    }

    // Runs one complete signing session across every service and returns the
    // signature each service produced.
    std::vector<AuthoritySignature> sign_everywhere(
        SigningSessionId* out_id = nullptr,
        std::vector<FrostCommitmentMessage>* out_commitments = nullptr) {
        std::vector<FrostCommitmentMessage> commitments;
        auto start = services[0]->start_signing(object, certificate, nodes);
        EXPECT_EQ(start.failure, SigningFailure::None);
        EXPECT_TRUE(start.session_id.has_value());
        const SigningSessionId id = *start.session_id;
        if (out_id != nullptr) {
            *out_id = id;
        }
        commitments.push_back(*start.commitment);
        for (std::size_t i = 1; i < kNodes; ++i) {
            auto join = services[i]->join_signing(id, object, certificate, nodes);
            EXPECT_EQ(join.failure, SigningFailure::None);
            commitments.push_back(*join.commitment);
        }

        std::vector<FrostShareMessage> shares;
        for (auto& service : services) {
            for (const auto& commitment : commitments) {
                auto outcome = service->receive_commitment(commitment);
                if (std::holds_alternative<FrostShareMessage>(outcome)) {
                    shares.push_back(std::get<FrostShareMessage>(outcome));
                }
            }
        }
        EXPECT_EQ(shares.size(), kNodes);
        if (out_commitments != nullptr) {
            *out_commitments = commitments;
        }

        std::vector<AuthoritySignature> signatures;
        for (auto& service : services) {
            for (const auto& share : shares) {
                auto outcome = service->receive_signature_share(share);
                if (std::holds_alternative<AuthoritySignature>(outcome)) {
                    signatures.push_back(std::get<AuthoritySignature>(outcome));
                }
            }
        }
        return signatures;
    }

    EpochId epoch = kEpoch;
    NetworkId network{};
    std::vector<NodeId> nodes;
    Tier1Set members{*Tier1Set::from_nodes({})};
    std::vector<EpochVoteKey> vote_keys;
    std::map<NodeId, nexus::crypto::Ed25519PublicKey> vote_pubkeys;
    std::vector<DkgResult> dkg_results;
    nexus::crypto::Ed25519PublicKey group_key{};
    QuorumCertificate certificate;
    AuthorityObject object;
    std::vector<std::unique_ptr<NonceCommitmentStore>> stores;
    std::vector<std::unique_ptr<AuthorityService>> services;
};

TEST(AuthoritySigning, ThresholdSetSignsFinalizedObject) {
    Mesh mesh;
    SigningSessionId id = 0;
    const auto signatures = mesh.sign_everywhere(&id);
    ASSERT_EQ(signatures.size(), kNodes);

    const Digest object_digest = authority_object_digest(mesh.object);
    for (const auto& signature : signatures) {
        EXPECT_EQ(signature.epoch, kEpoch);
        EXPECT_EQ(signature.key_generation, kEpoch);
        EXPECT_EQ(signature.object_digest, object_digest);
        EXPECT_EQ(signature.signature, signatures[0].signature);
        EXPECT_TRUE(nexus::crypto::FrostProvider::verify(mesh.group_key, object_digest,
                                                         signature.signature));
    }
    ASSERT_TRUE(mesh.services[0]->result(id).has_value());
    EXPECT_EQ(mesh.services[0]->session(id)->phase, SigningPhase::Complete);
}

TEST(AuthoritySigning, NothingSignsWithoutAKeyShare) {
    Mesh mesh;
    NonceCommitmentStore store;
    AuthorityService fresh(mesh.nodes[0], store);
    const auto start = fresh.start_signing(mesh.object, mesh.certificate, mesh.nodes);
    EXPECT_EQ(start.failure, SigningFailure::NoKeyShare);
}

TEST(AuthoritySigning, ObjectMustBindThisEpochAndNetwork) {
    Mesh mesh;
    auto object = mesh.object;
    object.epoch = kEpoch + 1;
    EXPECT_EQ(mesh.services[0]->start_signing(object, mesh.certificate, mesh.nodes).failure,
              SigningFailure::WrongEpoch);

    object = mesh.object;
    object.key_generation = kEpoch + 1;
    EXPECT_EQ(mesh.services[0]->start_signing(object, mesh.certificate, mesh.nodes).failure,
              SigningFailure::WrongKeyGeneration);

    object = mesh.object;
    object.network_id.fill(0xEE);
    EXPECT_EQ(mesh.services[0]->start_signing(object, mesh.certificate, mesh.nodes).failure,
              SigningFailure::WrongNetwork);
}

TEST(AuthoritySigning, SignerExaminesTheConsensusCertificate) {
    Mesh mesh;
    auto object = mesh.object;
    object.consensus_certificate_digest.fill(0xEE);
    EXPECT_EQ(mesh.services[0]->start_signing(object, mesh.certificate, mesh.nodes).failure,
              SigningFailure::CertificateMismatch);

    // A certificate whose digest matches but whose signatures do not verify
    // is not finalized state; the object built from it is refused.
    auto forged = mesh.certificate;
    forged.signers[0].signature[0] ^= 0x01;
    auto forged_object = mesh.object;
    forged_object.consensus_certificate_digest = qc_digest(forged);
    EXPECT_EQ(mesh.services[0]->start_signing(forged_object, forged, mesh.nodes).failure,
              SigningFailure::CertificateInvalid);

    // Too few signers: the certificate digest matches, the quorum does not.
    auto thin = mesh.certificate;
    thin.signers.resize(constants::consensus_quorum(kNodes) - 1);
    auto thin_object = mesh.object;
    thin_object.consensus_certificate_digest = qc_digest(thin);
    EXPECT_EQ(mesh.services[0]->start_signing(thin_object, thin, mesh.nodes).failure,
              SigningFailure::CertificateInvalid);
}

TEST(AuthoritySigning, SignerSetRules) {
    Mesh mesh;
    std::vector<NodeId> below(mesh.nodes.begin(), mesh.nodes.begin() + 4);
    EXPECT_EQ(mesh.services[0]->start_signing(mesh.object, mesh.certificate, below).failure,
              SigningFailure::SignerSetInvalid);

    std::vector<NodeId> without_self(mesh.nodes.begin() + 1, mesh.nodes.end());
    without_self.push_back(node(0x99));
    EXPECT_EQ(
        mesh.services[0]->start_signing(mesh.object, mesh.certificate, without_self).failure,
        SigningFailure::SignerSetInvalid);

    auto duplicated = mesh.nodes;
    duplicated[4] = duplicated[0];
    EXPECT_EQ(mesh.services[0]->start_signing(mesh.object, mesh.certificate, duplicated).failure,
              SigningFailure::SignerSetInvalid);
}

TEST(AuthoritySigning, RepeatedSessionIdIsRefused) {
    Mesh mesh;
    const auto first = mesh.services[1]->join_signing(77, mesh.object, mesh.certificate, mesh.nodes);
    ASSERT_EQ(first.failure, SigningFailure::None);
    const auto again = mesh.services[1]->join_signing(77, mesh.object, mesh.certificate, mesh.nodes);
    EXPECT_EQ(again.failure, SigningFailure::SessionRepeated);
}

TEST(AuthoritySigning, ReplayedCommitmentIsRefused) {
    Mesh mesh;
    SigningSessionId first_id = 0;
    std::vector<FrostCommitmentMessage> first_commitments;
    ASSERT_EQ(mesh.sign_everywhere(&first_id, &first_commitments).size(), kNodes);

    // A restored signer replays a commitment from the completed session into
    // a new one. Every other node's mesh record already holds those bytes.
    auto start = mesh.services[0]->start_signing(mesh.object, mesh.certificate, mesh.nodes);
    ASSERT_EQ(start.failure, SigningFailure::None);
    auto join = mesh.services[1]->join_signing(*start.session_id, mesh.object, mesh.certificate,
                                               mesh.nodes);
    ASSERT_EQ(join.failure, SigningFailure::None);

    FrostCommitmentMessage replay = first_commitments[2];
    replay.header.session_id = *start.session_id;
    auto outcome = mesh.services[1]->receive_commitment(replay);
    ASSERT_TRUE(std::holds_alternative<SigningFailure>(outcome));
    EXPECT_EQ(std::get<SigningFailure>(outcome), SigningFailure::CommitmentReplayed);
}

TEST(AuthoritySigning, MessageValidationOrder) {
    Mesh mesh;
    auto start = mesh.services[0]->start_signing(mesh.object, mesh.certificate, mesh.nodes);
    ASSERT_EQ(start.failure, SigningFailure::None);
    const auto id = *start.session_id;
    auto join = mesh.services[1]->join_signing(id, mesh.object, mesh.certificate, mesh.nodes);
    ASSERT_EQ(join.failure, SigningFailure::None);

    FrostCommitmentMessage message = *join.commitment;
    message.header.session_id = id + 1;
    EXPECT_EQ(std::get<SigningFailure>(mesh.services[0]->receive_commitment(message)),
              SigningFailure::UnknownSession);

    message = *join.commitment;
    message.header.object_digest.fill(0xEE);
    EXPECT_EQ(std::get<SigningFailure>(mesh.services[0]->receive_commitment(message)),
              SigningFailure::ObjectMismatch);

    message = *join.commitment;
    message.header.sender = node(0x99);
    EXPECT_EQ(std::get<SigningFailure>(mesh.services[0]->receive_commitment(message)),
              SigningFailure::UnknownSigner);

    // Own commitment fed back is already recorded.
    EXPECT_EQ(std::get<SigningFailure>(mesh.services[0]->receive_commitment(*start.commitment)),
              SigningFailure::DuplicateCommitment);

    // A share cannot arrive before the commitments are complete.
    FrostShareMessage early;
    early.header = join.commitment->header;
    early.share = {1, 2, 3};
    EXPECT_EQ(std::get<SigningFailure>(mesh.services[0]->receive_signature_share(early)),
              SigningFailure::WrongPhase);

    // A valid commitment is accepted once.
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        mesh.services[0]->receive_commitment(*join.commitment)));
    EXPECT_EQ(std::get<SigningFailure>(mesh.services[0]->receive_commitment(*join.commitment)),
              SigningFailure::DuplicateCommitment);
}

TEST(AuthoritySigning, TamperedShareAbortsSessionAndRetryUsesFreshSession) {
    Mesh mesh;
    auto start = mesh.services[0]->start_signing(mesh.object, mesh.certificate, mesh.nodes);
    ASSERT_EQ(start.failure, SigningFailure::None);
    const auto id = *start.session_id;

    std::vector<FrostCommitmentMessage> commitments{*start.commitment};
    for (std::size_t i = 1; i < kNodes; ++i) {
        auto join = mesh.services[i]->join_signing(id, mesh.object, mesh.certificate, mesh.nodes);
        ASSERT_EQ(join.failure, SigningFailure::None);
        commitments.push_back(*join.commitment);
    }
    std::vector<FrostShareMessage> shares;
    for (auto& service : mesh.services) {
        for (const auto& commitment : commitments) {
            auto outcome = service->receive_commitment(commitment);
            if (std::holds_alternative<FrostShareMessage>(outcome)) {
                shares.push_back(std::get<FrostShareMessage>(outcome));
            }
        }
    }
    ASSERT_EQ(shares.size(), kNodes);
    shares[2].share[0] ^= 0x01;

    std::optional<SigningFailure> failure;
    for (const auto& share : shares) {
        auto outcome = mesh.services[0]->receive_signature_share(share);
        if (std::holds_alternative<SigningFailure>(outcome)) {
            failure = std::get<SigningFailure>(outcome);
        }
    }
    ASSERT_TRUE(failure.has_value());
    EXPECT_EQ(*failure, SigningFailure::CryptoFailure);
    EXPECT_EQ(mesh.services[0]->session(id)->phase, SigningPhase::Aborted);
    EXPECT_FALSE(mesh.services[0]->result(id).has_value());

    // The retry is a new session with new nonces and it completes.
    EXPECT_EQ(mesh.sign_everywhere().size(), kNodes);
}

TEST(AuthoritySigning, AbortDestroysTheSession) {
    Mesh mesh;
    auto start = mesh.services[0]->start_signing(mesh.object, mesh.certificate, mesh.nodes);
    ASSERT_EQ(start.failure, SigningFailure::None);
    mesh.services[0]->abort_signing(*start.session_id);
    EXPECT_EQ(mesh.services[0]->session(*start.session_id)->phase, SigningPhase::Aborted);

    auto join = mesh.services[1]->join_signing(*start.session_id, mesh.object, mesh.certificate,
                                               mesh.nodes);
    EXPECT_EQ(std::get<SigningFailure>(mesh.services[0]->receive_commitment(*join.commitment)),
              SigningFailure::WrongPhase);
}

TEST(AuthoritySigning, NewEpochDropsOldShareAndSessions) {
    Mesh mesh;
    auto start = mesh.services[0]->start_signing(mesh.object, mesh.certificate, mesh.nodes);
    ASSERT_EQ(start.failure, SigningFailure::None);
    const auto old_id = *start.session_id;
    const auto old_key = *mesh.services[0]->group_public_key();

    // A DKG result for another epoch never installs; the old share stays.
    Mesh wrong_epoch(kEpoch + 2, false);
    EXPECT_FALSE(mesh.services[0]->install_epoch(mesh.context(), std::move(wrong_epoch.dkg_results[0])));
    EXPECT_EQ(*mesh.services[0]->group_public_key(), old_key);
    EXPECT_NE(mesh.services[0]->session(old_id), nullptr);

    Mesh next(kEpoch + 1, false);
    EXPECT_TRUE(mesh.services[0]->install_epoch(next.context(), std::move(next.dkg_results[0])));

    EXPECT_EQ(mesh.services[0]->session(old_id), nullptr);
    EXPECT_NE(*mesh.services[0]->group_public_key(), old_key);
    EXPECT_EQ(*mesh.services[0]->key_epoch(), kEpoch + 1);
    EXPECT_EQ(mesh.services[0]->start_signing(mesh.object, mesh.certificate, mesh.nodes).failure,
              SigningFailure::WrongEpoch);
}

}  // namespace
