#include <LemonadeNexus/Security/Consensus/ConsensusTypes.hpp>
#include <LemonadeNexus/Security/Consensus/QuorumValidation.hpp>
#include <LemonadeNexus/Security/Consensus/VoteKey.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <map>
#include <vector>

namespace constants = nexus::security::constants;
using nexus::security::ConsensusFailure;
using nexus::security::Digest;
using nexus::security::EpochVoteKey;
using nexus::security::NodeId;
using nexus::security::QcSigner;
using nexus::security::QcValidationContext;
using nexus::security::QuorumCertificate;
using nexus::security::TimeoutCertificate;
using nexus::security::TimeoutSigner;

namespace {

[[nodiscard]] Digest filled_digest(uint8_t value) {
    Digest digest{};
    digest.fill(value);
    return digest;
}

[[nodiscard]] NodeId filled_node(uint8_t value) {
    NodeId node{};
    node.bytes.fill(value);
    return node;
}

constexpr nexus::security::EpochId kEpoch = 7;
constexpr nexus::security::Height kHeight = 100;
constexpr nexus::security::View kView = 12;
constexpr std::size_t kNodes = 5;
constexpr std::size_t kQuorum = 4;  // ConsensusQuorum(5)

class QuorumCertificateValidation : public ::testing::Test {
protected:
    void SetUp() override {
        network_id_ = filled_digest(0xAA);
        proposal_digest_ = filled_digest(0x33);
        for (uint8_t i = 0; i < kNodes; ++i) {
            const NodeId node = filled_node(static_cast<uint8_t>(i + 1));
            keys_.push_back(nexus::security::make_epoch_vote_key(kEpoch, node));
            vote_keys_[node] = keys_.back().public_key;
        }
        context_ = QcValidationContext{constants::kConsensusRulesetVersion, network_id_,
                                       kEpoch, kQuorum};
    }

    [[nodiscard]] QcSigner signed_entry(const EpochVoteKey& key) const {
        QcSigner signer{};
        signer.node_id = key.node_id;
        signer.signature = nexus::security::sign_digest(
            key, nexus::security::vote_signing_digest(
                     constants::kConsensusRulesetVersion, network_id_, kEpoch, kHeight,
                     kView, proposal_digest_, key.node_id));
        return signer;
    }

    [[nodiscard]] QuorumCertificate make_qc(std::size_t signer_count) const {
        QuorumCertificate certificate{};
        certificate.qc_format_version = constants::kQcFormatVersion;
        certificate.consensus_ruleset = constants::kConsensusRulesetVersion;
        certificate.network_id = network_id_;
        certificate.epoch = kEpoch;
        certificate.height = kHeight;
        certificate.view = kView;
        certificate.proposal_digest = proposal_digest_;
        for (std::size_t i = 0; i < signer_count; ++i) {
            certificate.signers.push_back(signed_entry(keys_[i]));
        }
        return certificate;
    }

    [[nodiscard]] TimeoutSigner timeout_entry(const EpochVoteKey& key,
                                              const Digest& high_qc_digest) const {
        TimeoutSigner signer{};
        signer.node_id = key.node_id;
        signer.high_qc_digest = high_qc_digest;
        signer.signature = nexus::security::sign_digest(
            key, nexus::security::timeout_vote_signing_digest(
                     constants::kConsensusRulesetVersion, network_id_, kEpoch, kView,
                     high_qc_digest, key.node_id));
        return signer;
    }

    [[nodiscard]] TimeoutCertificate make_tc(std::size_t signer_count) const {
        TimeoutCertificate certificate{};
        certificate.consensus_ruleset = constants::kConsensusRulesetVersion;
        certificate.network_id = network_id_;
        certificate.epoch = kEpoch;
        certificate.view = kView;
        for (std::size_t i = 0; i < signer_count; ++i) {
            // Each signer attests to its own highest known QC.
            certificate.signers.push_back(
                timeout_entry(keys_[i], filled_digest(static_cast<uint8_t>(0x40 + i))));
        }
        return certificate;
    }

    Digest network_id_{};
    Digest proposal_digest_{};
    std::vector<EpochVoteKey> keys_;
    std::map<NodeId, nexus::crypto::Ed25519PublicKey> vote_keys_;
    QcValidationContext context_{};
};

TEST_F(QuorumCertificateValidation, AcceptsFiveValidSigners) {
    EXPECT_EQ(nexus::security::validate_quorum_certificate(make_qc(5), context_, vote_keys_),
              std::nullopt);
}

TEST_F(QuorumCertificateValidation, AcceptsExactQuorumBoundary) {
    EXPECT_EQ(nexus::security::validate_quorum_certificate(make_qc(4), context_, vote_keys_),
              std::nullopt);
}

TEST_F(QuorumCertificateValidation, RejectsBelowQuorum) {
    EXPECT_EQ(nexus::security::validate_quorum_certificate(make_qc(3), context_, vote_keys_),
              ConsensusFailure::InsufficientQuorum);
}

TEST_F(QuorumCertificateValidation, DuplicateSignersCountOnce) {
    // Five entries, two duplicates: three distinct identities. A cloned VM
    // identity gains no voting weight.
    auto certificate = make_qc(3);
    certificate.signers.push_back(certificate.signers[0]);
    certificate.signers.push_back(certificate.signers[1]);
    ASSERT_EQ(certificate.signers.size(), 5u);
    EXPECT_EQ(nexus::security::validate_quorum_certificate(certificate, context_, vote_keys_),
              ConsensusFailure::InsufficientQuorum);
}

TEST_F(QuorumCertificateValidation, TamperedSignatureRejectsWholeCertificate) {
    auto certificate = make_qc(5);
    certificate.signers[2].signature[0] ^= 0xFF;
    EXPECT_EQ(nexus::security::validate_quorum_certificate(certificate, context_, vote_keys_),
              ConsensusFailure::InvalidSignature);
}

TEST_F(QuorumCertificateValidation, TamperedViewInvalidatesSignatures) {
    // The view is inside every vote signing digest.
    auto certificate = make_qc(5);
    certificate.view += 1;
    EXPECT_EQ(nexus::security::validate_quorum_certificate(certificate, context_, vote_keys_),
              ConsensusFailure::InvalidSignature);
}

TEST_F(QuorumCertificateValidation, UnknownSignerRejects) {
    auto certificate = make_qc(5);
    certificate.signers[4].node_id = filled_node(0xEE);
    EXPECT_EQ(nexus::security::validate_quorum_certificate(certificate, context_, vote_keys_),
              ConsensusFailure::UnknownSigner);
}

TEST_F(QuorumCertificateValidation, WrongFormatVersionRejects) {
    auto certificate = make_qc(5);
    certificate.qc_format_version += 1;
    EXPECT_EQ(nexus::security::validate_quorum_certificate(certificate, context_, vote_keys_),
              ConsensusFailure::FormatVersion);
}

TEST_F(QuorumCertificateValidation, WrongRulesetRejects) {
    auto certificate = make_qc(5);
    certificate.consensus_ruleset += 1;
    EXPECT_EQ(nexus::security::validate_quorum_certificate(certificate, context_, vote_keys_),
              ConsensusFailure::RulesetMismatch);
}

TEST_F(QuorumCertificateValidation, WrongNetworkRejects) {
    auto certificate = make_qc(5);
    certificate.network_id[0] ^= 0xFF;
    EXPECT_EQ(nexus::security::validate_quorum_certificate(certificate, context_, vote_keys_),
              ConsensusFailure::NetworkMismatch);
}

TEST_F(QuorumCertificateValidation, WrongEpochRejects) {
    auto certificate = make_qc(5);
    certificate.epoch += 1;
    EXPECT_EQ(nexus::security::validate_quorum_certificate(certificate, context_, vote_keys_),
              ConsensusFailure::EpochMismatch);
}

TEST_F(QuorumCertificateValidation, TooManySignaturesRejectsBeforeAnyVerification) {
    // Unknown identities and garbage signatures: only the count check can
    // produce TooManySignatures, so this proves the bound applies first.
    auto certificate = make_qc(0);
    for (std::size_t i = 0; i < constants::kMaxQcSignatures + 1; ++i) {
        QcSigner signer{};
        signer.node_id = filled_node(static_cast<uint8_t>(0x80 + i));
        certificate.signers.push_back(signer);
    }
    EXPECT_EQ(nexus::security::validate_quorum_certificate(certificate, context_, vote_keys_),
              ConsensusFailure::TooManySignatures);
}

TEST_F(QuorumCertificateValidation, TimeoutCertificateAcceptsOwnHighQcPerSigner) {
    EXPECT_EQ(nexus::security::validate_timeout_certificate(make_tc(5), context_, vote_keys_),
              std::nullopt);
}

TEST_F(QuorumCertificateValidation, TimeoutSignerMustSignItsOwnHighQc) {
    // The listed high_qc_digest differs from the signed one.
    auto certificate = make_tc(5);
    certificate.signers[0].high_qc_digest[0] ^= 0xFF;
    EXPECT_EQ(nexus::security::validate_timeout_certificate(certificate, context_, vote_keys_),
              ConsensusFailure::InvalidSignature);
}

TEST_F(QuorumCertificateValidation, TimeoutDuplicateSignersCountOnce) {
    auto certificate = make_tc(3);
    certificate.signers.push_back(certificate.signers[0]);
    certificate.signers.push_back(certificate.signers[1]);
    EXPECT_EQ(nexus::security::validate_timeout_certificate(certificate, context_, vote_keys_),
              ConsensusFailure::InsufficientQuorum);
}

TEST_F(QuorumCertificateValidation, TimeoutUnknownSignerRejects) {
    auto certificate = make_tc(5);
    certificate.signers[1].node_id = filled_node(0xEE);
    EXPECT_EQ(nexus::security::validate_timeout_certificate(certificate, context_, vote_keys_),
              ConsensusFailure::UnknownSigner);
}

TEST_F(QuorumCertificateValidation, TimeoutWrongEpochRejects) {
    auto certificate = make_tc(5);
    certificate.epoch += 1;
    EXPECT_EQ(nexus::security::validate_timeout_certificate(certificate, context_, vote_keys_),
              ConsensusFailure::EpochMismatch);
}

TEST_F(QuorumCertificateValidation, TimeoutTooManySignaturesRejects) {
    auto certificate = make_tc(0);
    for (std::size_t i = 0; i < constants::kMaxQcSignatures + 1; ++i) {
        TimeoutSigner signer{};
        signer.node_id = filled_node(static_cast<uint8_t>(0x80 + i));
        certificate.signers.push_back(signer);
    }
    EXPECT_EQ(nexus::security::validate_timeout_certificate(certificate, context_, vote_keys_),
              ConsensusFailure::TooManySignatures);
}

TEST_F(QuorumCertificateValidation, VoteKeyRoundTrip) {
    const auto digest = filled_digest(0x11);
    const auto signature = nexus::security::sign_digest(keys_[0], digest);
    EXPECT_TRUE(nexus::security::verify_digest(keys_[0].public_key, digest, signature));

    // A different digest or a different key must not verify.
    EXPECT_FALSE(
        nexus::security::verify_digest(keys_[0].public_key, filled_digest(0x12), signature));
    EXPECT_FALSE(nexus::security::verify_digest(keys_[1].public_key, digest, signature));
}

}  // namespace
