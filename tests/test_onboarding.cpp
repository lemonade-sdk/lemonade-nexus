#include <LemonadeNexus/Core/ServerAdmissionService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>

#include <gtest/gtest.h>

#include <span>

using namespace nexus;

namespace {

crypto::Ed25519Keypair make_key(crypto::SodiumCryptoService& c) {
    return c.ed25519_keygen();
}

std::string b64(const std::vector<uint8_t>& v) {
    return crypto::to_base64(std::span<const uint8_t>(v.data(), v.size()));
}

} // namespace

// ===========================================================================
// valid_server_id_label
// ===========================================================================

TEST(Onboarding, ServerIdLabelRules) {
    EXPECT_TRUE(gossip::valid_server_id_label("aws-use1-a"));
    EXPECT_TRUE(gossip::valid_server_id_label("s"));
    EXPECT_TRUE(gossip::valid_server_id_label("server-1a93e411838e0b34"));

    EXPECT_FALSE(gossip::valid_server_id_label(""));           // empty
    EXPECT_FALSE(gossip::valid_server_id_label("-lead"));      // leading hyphen
    EXPECT_FALSE(gossip::valid_server_id_label("trail-"));     // trailing hyphen
    EXPECT_FALSE(gossip::valid_server_id_label("Upper"));      // uppercase
    EXPECT_FALSE(gossip::valid_server_id_label("under_score")); // underscore
    EXPECT_FALSE(gossip::valid_server_id_label("has space"));  // space
    EXPECT_FALSE(gossip::valid_server_id_label(std::string(64, 'a'))); // too long
    EXPECT_TRUE(gossip::valid_server_id_label(std::string(63, 'a')));  // max length
}

// ===========================================================================
// issue_server_certificate — round-trip verify against the root pubkey
// ===========================================================================

TEST(Onboarding, CertificateIssueAndVerify) {
    crypto::SodiumCryptoService c;
    c.start();
    auto root = make_key(c);
    auto cand = make_key(c);

    gossip::CertIssueParams p;
    p.server_pubkey_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    p.server_id = "berlin-2";

    auto cert = gossip::issue_server_certificate(p, c, root.private_key, root.public_key);

    // Bound to the candidate, issued by the root.
    EXPECT_EQ(cert.server_pubkey, p.server_pubkey_b64);
    EXPECT_EQ(cert.server_id, "berlin-2");
    EXPECT_EQ(cert.issuer_pubkey,
              crypto::to_base64(std::span<const uint8_t>(root.public_key.data(),
                                                         root.public_key.size())));
    EXPECT_EQ(cert.expires_at, 0u);

    // Signature verifies against the root pubkey over the canonical form.
    auto canonical = gossip::canonical_cert_json(cert);
    std::vector<uint8_t> msg(canonical.begin(), canonical.end());
    auto sig = crypto::from_base64(cert.signature);
    ASSERT_EQ(sig.size(), crypto::kEd25519SignatureSize);
    crypto::Ed25519Signature s{};
    std::memcpy(s.data(), sig.data(), s.size());
    EXPECT_TRUE(c.ed25519_verify(root.public_key, std::span<const uint8_t>(msg), s));

    // A different key must NOT verify it (issuer binding is real).
    auto other = make_key(c);
    EXPECT_FALSE(c.ed25519_verify(other.public_key, std::span<const uint8_t>(msg), s));
    c.stop();
}

TEST(Onboarding, CertificateTierCapability) {
    crypto::SodiumCryptoService c;
    c.start();
    auto root = make_key(c);
    auto cand = make_key(c);
    gossip::CertIssueParams p;
    p.server_pubkey_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    p.server_id = "tpm-node";
    p.tpm_ak_pubkey = "QUstUElOTkVE";  // non-empty → Tier1-capable

    auto cert = gossip::issue_server_certificate(p, c, root.private_key, root.public_key);
    EXPECT_EQ(cert.tpm_ak_pubkey, "QUstUElOTkVE");
    // The pinned AK is inside the signed canonical form.
    EXPECT_NE(gossip::canonical_cert_json(cert).find("QUstUElOTkVE"), std::string::npos);
    c.stop();
}

// ===========================================================================
// Candidate proof-of-possession signing (the /api/onboard/request path)
// ===========================================================================

TEST(Onboarding, RequestSignatureRoundTrip) {
    crypto::SodiumCryptoService c;
    c.start();
    auto cand = make_key(c);

    core::ServerAdmissionService::RequestInput in;
    in.candidate_pubkey = b64({cand.public_key.begin(), cand.public_key.end()});
    in.server_id = "berlin-2";
    in.region = "eu-west";
    in.nonce = "bm9uY2U=";
    in.timestamp = 1751328000;

    auto msg = core::ServerAdmissionService::canonical_request(in);
    auto sig = c.ed25519_sign(cand.private_key, std::span<const uint8_t>(msg));
    EXPECT_TRUE(c.ed25519_verify(cand.public_key, std::span<const uint8_t>(msg), sig));

    // Tampering with any signed field breaks verification.
    auto tampered = in;
    tampered.server_id = "berlin-3";
    auto msg2 = core::ServerAdmissionService::canonical_request(tampered);
    EXPECT_FALSE(c.ed25519_verify(cand.public_key, std::span<const uint8_t>(msg2), sig));
    c.stop();
}

TEST(Onboarding, PollSignatureIsDomainSeparated) {
    // poll and ack share a shape but must not be cross-usable (distinct tags).
    auto poll = core::ServerAdmissionService::canonical_poll("ln-onboard-poll:v1", "rid", 42);
    auto ack  = core::ServerAdmissionService::canonical_poll("ln-onboard-ack:v1", "rid", 42);
    EXPECT_NE(poll, ack);
}
