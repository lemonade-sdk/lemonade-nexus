#include <LemonadeNexus/Crypto/FrostProvider.hpp>
#include <LemonadeNexus/Security/Authority/DkgSession.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>

#include <memory>
#include <vector>

using nexus::security::Digest;
using nexus::security::DkgConfiguration;
using nexus::security::DkgFailure;
using nexus::security::DkgMessage;
using nexus::security::DkgPhase;
using nexus::security::DkgResult;
using nexus::security::DkgRound;
using nexus::security::DkgSession;
using nexus::security::NetworkId;
using nexus::security::NodeId;
using nexus::security::Tier1Set;

namespace constants = nexus::security::constants;

namespace {

NodeId node(uint8_t byte) {
    NodeId id;
    id.bytes.fill(byte);
    return id;
}

struct Mesh {
    explicit Mesh(std::size_t count, std::size_t threshold_override = 0) {
        network.fill(0x0F);
        std::vector<NodeId> nodes;
        for (std::size_t i = 1; i <= count; ++i) {
            nodes.push_back(node(static_cast<uint8_t>(i)));
        }
        participants = *Tier1Set::from_nodes(nodes);
        for (const auto& member : nodes) {
            incarnations[member] = 100 + member.bytes[0];
        }
        threshold = threshold_override == 0 ? constants::authority_threshold(count)
                                            : threshold_override;
        for (const auto& member : nodes) {
            sessions.push_back(std::make_unique<DkgSession>(config_for(member)));
        }
    }

    DkgConfiguration config_for(const NodeId& self) const {
        DkgConfiguration config;
        config.network_id = network;
        config.target_epoch = 2;
        config.participants = participants;
        config.incarnations = incarnations;
        config.threshold = threshold;
        config.self = self;
        return config;
    }

    // Runs round 1 for everyone and delivers every broadcast to every session.
    std::vector<DkgMessage> run_round1() {
        std::vector<DkgMessage> broadcasts;
        for (auto& session : sessions) {
            auto message = session->start();
            EXPECT_TRUE(message.has_value());
            broadcasts.push_back(*message);
        }
        for (auto& session : sessions) {
            for (const auto& broadcast : broadcasts) {
                (void)session->receive_broadcast(broadcast);
            }
        }
        return broadcasts;
    }

    NetworkId network{};
    Tier1Set participants{*Tier1Set::from_nodes({})};
    std::map<NodeId, nexus::security::IncarnationId> incarnations;
    std::size_t threshold = 0;
    std::vector<std::unique_ptr<DkgSession>> sessions;
};

// The mesh delivers pairwise packages by recipient; sessions are stored in
// participant order, so index i belongs to node i + 1.
void deliver_round2(Mesh& mesh) {
    std::vector<DkgMessage> pairwise;
    for (auto& session : mesh.sessions) {
        auto messages = session->round2_messages();
        ASSERT_EQ(messages.size(), mesh.sessions.size() - 1);
        pairwise.insert(pairwise.end(), messages.begin(), messages.end());
    }
    for (const auto& message : pairwise) {
        auto& recipient = mesh.sessions[message.recipient.bytes[0] - 1];
        ASSERT_EQ(recipient->receive_pairwise(message), DkgFailure::None);
    }
}

TEST(DkgSession, FiveParticipantsAgreeOnOneGroupKeyAndTranscript) {
    Mesh mesh(5);
    mesh.run_round1();
    for (auto& session : mesh.sessions) {
        ASSERT_TRUE(session->round1_complete());
    }
    const Digest transcript = *mesh.sessions[0]->transcript_digest();
    for (auto& session : mesh.sessions) {
        EXPECT_EQ(*session->transcript_digest(), transcript);
    }

    deliver_round2(mesh);
    std::vector<DkgResult> results;
    for (auto& session : mesh.sessions) {
        ASSERT_TRUE(session->finish());
        ASSERT_TRUE(session->complete());
        auto result = session->take_result();
        ASSERT_TRUE(result.has_value());
        EXPECT_FALSE(session->take_result().has_value());
        results.push_back(std::move(*result));
    }
    for (const auto& result : results) {
        EXPECT_EQ(result.group_public_key, results[0].group_public_key);
        EXPECT_EQ(result.transcript_digest, transcript);
        EXPECT_EQ(result.participant_set_digest, mesh.participants.digest());
        EXPECT_EQ(result.index_of, results[0].index_of);
        EXPECT_TRUE(result.key_share.valid());
    }

    // The shares sign together under the agreed group key.
    const std::vector<uint8_t> message{'o', 'b', 'j', 'e', 'c', 't'};
    nexus::crypto::FrostPeerBytesMap commitments;
    std::vector<nexus::crypto::FrostNonces> nonces(results.size() + 1);
    for (auto& result : results) {
        auto commit = nexus::crypto::FrostProvider::signing_commit(result.key_share);
        ASSERT_TRUE(commit.ok());
        commitments[result.own_index] = commit.value->commitments;
        nonces[result.own_index] = std::move(commit.value->nonces);
    }
    nexus::crypto::FrostPeerBytesMap shares;
    for (auto& result : results) {
        auto share = nexus::crypto::FrostProvider::sign(
            result.key_share, std::move(nonces[result.own_index]), message, commitments);
        ASSERT_TRUE(share.ok());
        shares[result.own_index] = *share.value;
    }
    auto signature = nexus::crypto::FrostProvider::aggregate(message, commitments, shares,
                                                             results[0].public_key_package);
    ASSERT_TRUE(signature.ok());
    EXPECT_TRUE(nexus::crypto::FrostProvider::verify(results[0].group_public_key, message,
                                                     *signature.value));
}

TEST(DkgSession, CompiledThresholdCannotBeLowered) {
    Mesh mesh(5, 4);
    EXPECT_FALSE(mesh.sessions[0]->start().has_value());
    EXPECT_EQ(mesh.sessions[0]->failure(), DkgFailure::ThresholdInvalid);
    EXPECT_EQ(mesh.sessions[0]->phase(), DkgPhase::Failed);
}

TEST(DkgSession, PopulationBelowMinimumRefused) {
    Mesh mesh(4);
    EXPECT_FALSE(mesh.sessions[0]->start().has_value());
    EXPECT_EQ(mesh.sessions[0]->failure(), DkgFailure::ParticipantSetInvalid);
}

TEST(DkgSession, SelfOutsideParticipantSetRefused) {
    Mesh mesh(5);
    DkgSession outsider(mesh.config_for(node(0x99)));
    EXPECT_FALSE(outsider.start().has_value());
    EXPECT_EQ(outsider.failure(), DkgFailure::ParticipantSetInvalid);
}

TEST(DkgSession, BroadcastBindingIsEnforcedBeforeAnyFrostWork) {
    Mesh mesh(5);
    auto& receiver = *mesh.sessions[0];
    ASSERT_TRUE(receiver.start().has_value());
    auto valid = *mesh.sessions[1]->start();

    auto broken = valid;
    broken.network_id.fill(0xEE);
    EXPECT_EQ(receiver.receive_broadcast(broken), DkgFailure::WrongNetwork);

    broken = valid;
    broken.target_epoch = 3;
    EXPECT_EQ(receiver.receive_broadcast(broken), DkgFailure::WrongEpoch);

    broken = valid;
    broken.participant_set_digest.fill(0xEE);
    EXPECT_EQ(receiver.receive_broadcast(broken), DkgFailure::WrongParticipantSet);

    broken = valid;
    broken.sender = node(0x99);
    EXPECT_EQ(receiver.receive_broadcast(broken), DkgFailure::UnknownSender);

    broken = valid;
    broken.sender_incarnation += 1;
    EXPECT_EQ(receiver.receive_broadcast(broken), DkgFailure::IncarnationMismatch);

    broken = valid;
    broken.round = DkgRound::Round2Pairwise;
    EXPECT_EQ(receiver.receive_broadcast(broken), DkgFailure::WrongRound);

    broken = valid;
    broken.recipient = node(0x01);
    EXPECT_EQ(receiver.receive_broadcast(broken), DkgFailure::WrongRecipient);

    broken = valid;
    broken.payload.clear();
    EXPECT_EQ(receiver.receive_broadcast(broken), DkgFailure::InvalidPackage);

    // None of the rejections changed the session.
    EXPECT_EQ(receiver.phase(), DkgPhase::Round1);
    EXPECT_EQ(receiver.receive_broadcast(valid), DkgFailure::None);
    EXPECT_EQ(receiver.receive_broadcast(valid), DkgFailure::DuplicateMessage);
}

TEST(DkgSession, EquivocatingBroadcastFailsSessionAndNamesCulprit) {
    Mesh mesh(5);
    auto& receiver = *mesh.sessions[0];
    ASSERT_TRUE(receiver.start().has_value());
    auto first = *mesh.sessions[1]->start();
    ASSERT_EQ(receiver.receive_broadcast(first), DkgFailure::None);

    auto second = first;
    second.payload[0] ^= 0x01;
    EXPECT_EQ(receiver.receive_broadcast(second), DkgFailure::Equivocation);
    EXPECT_EQ(receiver.phase(), DkgPhase::Failed);
    ASSERT_TRUE(receiver.culprit().has_value());
    EXPECT_EQ(*receiver.culprit(), first.sender);
    EXPECT_TRUE(receiver.round2_messages().empty());
}

TEST(DkgSession, TamperedRound1PackageFailsRound2) {
    Mesh mesh(5);
    std::vector<DkgMessage> broadcasts;
    for (auto& session : mesh.sessions) {
        broadcasts.push_back(*session->start());
    }
    // Corrupt participant 3's package as seen by participant 1 only.
    auto corrupted = broadcasts[2];
    corrupted.payload.back() ^= 0xFF;
    for (std::size_t i = 0; i < broadcasts.size(); ++i) {
        const auto& message = (i == 2) ? corrupted : broadcasts[i];
        (void)mesh.sessions[0]->receive_broadcast(message);
    }
    ASSERT_TRUE(mesh.sessions[0]->round1_complete());
    EXPECT_TRUE(mesh.sessions[0]->round2_messages().empty());
    EXPECT_EQ(mesh.sessions[0]->phase(), DkgPhase::Failed);
    EXPECT_NE(mesh.sessions[0]->failure(), DkgFailure::None);
}

TEST(DkgSession, PairwiseRulesHold) {
    Mesh mesh(5);
    mesh.run_round1();

    // Before round 2 starts, no pairwise message is accepted.
    DkgMessage early;
    EXPECT_EQ(mesh.sessions[0]->receive_pairwise(early), DkgFailure::WrongPhase);

    std::vector<DkgMessage> pairwise;
    for (auto& session : mesh.sessions) {
        auto messages = session->round2_messages();
        pairwise.insert(pairwise.end(), messages.begin(), messages.end());
    }

    // A package addressed to someone else is refused by everyone else.
    for (const auto& message : pairwise) {
        for (std::size_t i = 0; i < mesh.sessions.size(); ++i) {
            if (message.recipient != node(static_cast<uint8_t>(i + 1))) {
                EXPECT_EQ(mesh.sessions[i]->receive_pairwise(message), DkgFailure::WrongRecipient);
            }
        }
    }

    // finish() refuses until every package for this participant is present.
    EXPECT_FALSE(mesh.sessions[0]->finish());
    for (const auto& message : pairwise) {
        auto& recipient = mesh.sessions[message.recipient.bytes[0] - 1];
        ASSERT_EQ(recipient->receive_pairwise(message), DkgFailure::None);
        EXPECT_EQ(recipient->receive_pairwise(message), DkgFailure::DuplicateMessage);
    }
    for (auto& session : mesh.sessions) {
        EXPECT_TRUE(session->finish());
    }
}

TEST(DkgSession, FreshSessionGivesFreshKey) {
    Mesh first(5);
    first.run_round1();
    deliver_round2(first);
    Mesh second(5);
    second.run_round1();
    deliver_round2(second);
    ASSERT_TRUE(first.sessions[0]->finish());
    ASSERT_TRUE(second.sessions[0]->finish());
    EXPECT_NE(first.sessions[0]->take_result()->group_public_key,
              second.sessions[0]->take_result()->group_public_key);
}

}  // namespace
