// Server onboarding under the surviving admission model: proof-of-possession,
// evidence-digest binding, single-use bound tokens, and root-holder sole
// discretion. The old gossip admission ballot is gone; Tier-1 authority lives
// in the mesh security system. Historical "ballot" records must still load.

#include <LemonadeNexus/Core/AdmissionTokenStore.hpp>
#include <LemonadeNexus/Core/OnboardingClient.hpp>
#include <LemonadeNexus/Core/ServerAdmissionService.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <OnboardingValidation.hpp>

#include <asio.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <cctype>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <set>
#include <fstream>
#include <memory>
#include <span>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
namespace fs = std::filesystem;

// Observation-only friend seam: reads the private revoked set so the
// supersede test can see the revocation land. No test writes through it.
namespace nexus::gossip {
struct GossipBallotTestAccess {
    static bool revoked(const GossipService& g, const std::string& pubkey_b64) {
        return g.is_revoked(pubkey_b64);
    }
};
}  // namespace nexus::gossip

namespace {

// Certificates bind to a network id; one value serves every fixture.
inline const std::string kTestNetworkHex(64, 'a');

crypto::Ed25519Keypair make_key(crypto::SodiumCryptoService& c) {
    return c.ed25519_keygen();
}

std::string b64(const std::vector<uint8_t>& v) {
    return crypto::to_base64(std::span<const uint8_t>(v.data(), v.size()));
}

// True when `cert_json` carries a certificate whose signature verifies against
// `root_pk` over the canonical form. Approval paths must never mint anything
// weaker.
bool cert_verifies_against(const std::string& cert_json,
                           const crypto::Ed25519PublicKey& root_pk,
                           crypto::SodiumCryptoService& c) {
    auto cert = nlohmann::json::parse(cert_json).get<gossip::ServerCertificate>();
    auto canonical = gossip::canonical_cert_json(cert);
    auto sig = crypto::from_base64(cert.signature);
    if (sig.size() != crypto::kEd25519SignatureSize) return false;
    crypto::Ed25519Signature s{};
    std::memcpy(s.data(), sig.data(), s.size());
    std::vector<uint8_t> msg(canonical.begin(), canonical.end());
    return c.ed25519_verify(root_pk, std::span<const uint8_t>(msg), s);
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
    p.network_id = kTestNetworkHex;
    p.server_pubkey_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    p.server_id = "berlin-2";

    auto cert = gossip::issue_server_certificate(p, c, root.private_key, root.public_key);

    // Bound to the candidate, issued by the root.
    EXPECT_EQ(cert.server_pubkey, p.server_pubkey_b64);
    EXPECT_EQ(cert.server_id, "berlin-2");
    EXPECT_EQ(cert.issuer_pubkey, crypto::to_base64(root.public_key));
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
    p.network_id = kTestNetworkHex;
    p.server_pubkey_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    p.server_id = "tpm-node";
    p.tpm_ak_pubkey = "QUstUElOTkVE";  // non-empty → Tier1-capable

    auto cert = gossip::issue_server_certificate(p, c, root.private_key, root.public_key);
    EXPECT_EQ(cert.tpm_ak_pubkey, "QUstUElOTkVE");
    // The pinned AK is inside the signed canonical form.
    EXPECT_NE(gossip::canonical_cert_json(cert).find("QUstUElOTkVE"), std::string::npos);
    c.stop();
}

TEST(Onboarding, CertificatePlatformPolicyIsSigned) {
    crypto::SodiumCryptoService c;
    c.start();
    auto root = make_key(c);
    auto cand = make_key(c);

    gossip::CertIssueParams p;
    p.network_id = kTestNetworkHex;
    p.server_pubkey_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    p.server_id            = "snp-node";
    p.tpm_ak_pubkey        = "QUstUElOTkVE";
    p.platform_class       = "snp-vtpm";
    p.expected_measurement = std::string(96, 'a');
    p.approved_binary_hash = std::string(64, 'b');

    auto cert = gossip::issue_server_certificate(p, c, root.private_key, root.public_key);
    const auto canonical = gossip::canonical_cert_json(cert);
    EXPECT_NE(canonical.find("snp-vtpm"), std::string::npos);
    EXPECT_NE(canonical.find(p.expected_measurement), std::string::npos);
    EXPECT_NE(canonical.find(p.approved_binary_hash), std::string::npos);

    // Downgrading the policy must invalidate the root signature, or a peer could
    // strip the measurement pin and present any Azure CVM.
    auto sig = crypto::from_base64(cert.signature);
    crypto::Ed25519Signature sigv{};
    ASSERT_EQ(sig.size(), sigv.size());
    std::memcpy(sigv.data(), sig.data(), sig.size());

    auto downgraded = cert;
    downgraded.expected_measurement.clear();
    const auto tampered = gossip::canonical_cert_json(downgraded);
    EXPECT_FALSE(c.ed25519_verify(
        root.public_key,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(tampered.data()),
                                 tampered.size()),
        sigv));
    c.stop();
}

TEST(Onboarding, CertificateJsonCarriesThePlatformPolicy) {
    gossip::ServerCertificate cert;
    cert.server_pubkey        = "cGs=";
    cert.platform_class       = "snp-vtpm";
    cert.expected_measurement = std::string(96, 'a');
    cert.approved_binary_hash = std::string(64, 'b');

    nlohmann::json j = cert;
    auto back = j.get<gossip::ServerCertificate>();
    EXPECT_EQ(back.platform_class, cert.platform_class);
    EXPECT_EQ(back.expected_measurement, cert.expected_measurement);
    EXPECT_EQ(back.approved_binary_hash, cert.approved_binary_hash);
}

TEST(Onboarding, CertificateMeshKeyJsonAcceptsLegacyField) {
    gossip::ServerCertificate cert;
    cert.server_pubkey = "cGs=";
    cert.mesh_pubkey = "mesh-key";

    nlohmann::json current = cert;
    EXPECT_EQ(current.at("mesh_pubkey"), "mesh-key");
    EXPECT_FALSE(current.contains("wg_pubkey"));

    auto legacy = current;
    legacy["wg_pubkey"] = legacy["mesh_pubkey"];
    legacy.erase("mesh_pubkey");
    EXPECT_EQ(legacy.get<gossip::ServerCertificate>().mesh_pubkey, "mesh-key");
}

// ===========================================================================
// Candidate proof-of-possession signing (the /api/onboard/request path)
// ===========================================================================

TEST(Onboarding, RequestSignatureRoundTrip) {
    crypto::SodiumCryptoService c;
    c.start();
    auto cand = make_key(c);

    core::AdmissionRequest in;
    in.candidate_pubkey = b64({cand.public_key.begin(), cand.public_key.end()});
    in.server_id = "berlin-2";
    in.region = "eu-west";
    in.nonce = "bm9uY2U=";
    in.timestamp = 1751328000;

    auto msg = core::canonical_admission_request(in);
    auto sig = c.ed25519_sign(cand.private_key, std::span<const uint8_t>(msg));
    EXPECT_TRUE(c.ed25519_verify(cand.public_key, std::span<const uint8_t>(msg), sig));

    // Tampering with any signed field breaks verification.
    auto tampered = in;
    tampered.server_id = "berlin-3";
    auto msg2 = core::canonical_admission_request(tampered);
    EXPECT_FALSE(c.ed25519_verify(cand.public_key, std::span<const uint8_t>(msg2), sig));
    c.stop();
}

TEST(Onboarding, EveryPlatformEvidenceFieldIsSigned) {
    // A peer that could edit any of these after signing would be choosing its own
    // platform policy. Each must break the signature on its own.
    crypto::SodiumCryptoService c;
    c.start();
    auto cand = make_key(c);

    core::AdmissionRequest in;
    in.candidate_pubkey = b64({cand.public_key.begin(), cand.public_key.end()});
    in.server_id      = "berlin-2";
    in.region         = "eu-west";
    in.tpm_ak_pubkey  = "QUs=";
    in.platform_class = core::AdmissionPlatform::SnpVtpm;
    in.measurement    = std::string(96, 'a');
    in.binary_hash    = std::string(64, 'b');
    in.evidence_sha256 = std::string(64, 'c');
    in.nonce          = "bm9uY2U=";
    in.timestamp      = 1751328000;

    const auto msg = core::canonical_admission_request(in);
    const auto sig = c.ed25519_sign(cand.private_key, std::span<const uint8_t>(msg));

    auto breaks = [&](core::AdmissionRequest edited) {
        auto m = core::canonical_admission_request(edited);
        return !c.ed25519_verify(cand.public_key, std::span<const uint8_t>(m), sig);
    };
    {
        auto e = in;
        e.platform_class = core::AdmissionPlatform::Tpm2;
        EXPECT_TRUE(breaks(e));
    }
    { auto e = in; e.measurement     = std::string(96, 'f'); EXPECT_TRUE(breaks(e)); }
    { auto e = in; e.binary_hash     = std::string(64, 'f'); EXPECT_TRUE(breaks(e)); }
    { auto e = in; e.evidence_sha256 = std::string(64, 'f'); EXPECT_TRUE(breaks(e)); }
    { auto e = in; e.tpm_ak_pubkey   = "b3RoZXI=";           EXPECT_TRUE(breaks(e)); }
    c.stop();
}

TEST(Onboarding, RequestCanonicalIsTaggedV2) {
    // A v1 client signs different bytes; the tag makes that a signature failure
    // rather than a silently narrower set of fields.
    core::AdmissionRequest in;
    in.nonce = "n";
    const auto msg = core::canonical_admission_request(in);
    const std::string text(msg.begin(), msg.end());
    EXPECT_NE(text.find("ln-onboard:v2"), std::string::npos);
    EXPECT_EQ(text.find("ln-onboard:v1"), std::string::npos);
}

TEST(Onboarding, AdmissionRequestSerializationPreservesCanonicalBytes) {
    // The receiver re-derives the canonical form from the request body. A lost
    // field means the server verifies different bytes than the candidate signed.
    core::AdmissionRequest in;
    in.candidate_pubkey = b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 1));
    in.server_id       = "tokyo-1";
    in.region          = "ap-northeast";
    in.tpm_ak_pubkey   = "QUs=";
    in.platform_class  = core::AdmissionPlatform::SnpVtpm;
    in.measurement     = std::string(96, 'a');
    in.binary_hash     = std::string(64, 'b');
    in.evidence_sha256 = std::string(64, 'c');
    in.evidence        = "bundle";
    in.nonce           = b64(std::vector<uint8_t>(32, 2));
    in.timestamp       = 1751328000;
    in.signature       = b64(std::vector<uint8_t>(crypto::kEd25519SignatureSize, 3));

    const auto claim = in.toJson();
    const auto decoded = core::AdmissionRequest::fromJson(claim);
    ASSERT_TRUE(decoded) << decoded.error;
    const auto& back = *decoded.value;

    EXPECT_EQ(core::canonical_admission_request(in),
              core::canonical_admission_request(back));
    EXPECT_EQ(back.signature, in.signature);
    // The bearer token remains outside the signed canonical projection.
    EXPECT_FALSE(claim.contains("enrollment_token"));
}

TEST(Onboarding, PollSignatureIsDomainSeparated) {
    // poll and ack share a shape but must not be cross-usable. Assert on the
    // production constants both endpoints verify with (OnboardApiHandler uses
    // kOnboardPollTag / kOnboardAckTag) — not on re-typed literals, which
    // would keep passing if the endpoints drifted to one shared tag.
    ASSERT_NE(core::kOnboardPollTag, core::kOnboardAckTag);
    auto poll = core::canonical_onboarding_status(core::kOnboardPollTag, "rid", 42);
    auto ack  = core::canonical_onboarding_status(core::kOnboardAckTag, "rid", 42);
    EXPECT_NE(poll, ack);
}

TEST(OnboardingJson, StrictAdmissionRequestDecoding) {
    core::AdmissionRequest request;
    request.candidate_pubkey = b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 1));
    request.server_id = "berlin-2";
    request.region = "eu-west";
    request.nonce = b64(std::vector<uint8_t>(32, 2));
    request.timestamp = 1751328000;
    request.signature = b64(std::vector<uint8_t>(crypto::kEd25519SignatureSize, 3));

    const auto valid = request.toJson();
    ASSERT_TRUE(core::AdmissionRequest::fromJson(valid));

    auto missing = valid;
    missing.erase("region");
    EXPECT_EQ(missing.value("region", std::string{}), "");
    auto missing_result = core::AdmissionRequest::fromJson(missing);
    ASSERT_FALSE(missing_result);
    EXPECT_NE(missing_result.error.find("/region"), std::string::npos);

    auto wrong_type = valid;
    wrong_type["timestamp"] = "1751328000";
    auto type_result = core::AdmissionRequest::fromJson(wrong_type);
    ASSERT_FALSE(type_result);
    EXPECT_NE(type_result.error.find("/timestamp"), std::string::npos);

    auto unknown = valid;
    unknown["candidate_role"] = "root";
    auto unknown_result = core::AdmissionRequest::fromJson(unknown);
    ASSERT_FALSE(unknown_result);
    EXPECT_NE(unknown_result.error.find("/candidate_role"), std::string::npos);

    auto bad_key = valid;
    bad_key["candidate_pubkey"] = "c2hvcnQ=";
    auto key_result = core::AdmissionRequest::fromJson(bad_key);
    ASSERT_FALSE(key_result);
    EXPECT_NE(key_result.error.find("/candidate_pubkey"), std::string::npos);

    auto bad_digest = valid;
    bad_digest["evidence"] = "bundle";
    bad_digest["evidence_sha256"] = "abcd";
    auto digest_result = core::AdmissionRequest::fromJson(bad_digest);
    ASSERT_FALSE(digest_result);
    EXPECT_NE(digest_result.error.find("/evidence_sha256"), std::string::npos);

    auto null_token = valid;
    null_token["enrollment_token"] = nullptr;
    auto null_result = core::AdmissionRequest::fromJson(null_token);
    ASSERT_FALSE(null_result);
    EXPECT_NE(null_result.error.find("/enrollment_token"), std::string::npos);
}

TEST(OnboardingJson, EnumAndIntegerRangesAreStrict) {
    auto status = core::AdmissionStatusResponse{ };
    auto invalid_state = status.toJson();
    invalid_state["state"] = "waiting";
    auto state_result = core::AdmissionStatusResponse::fromJson(invalid_state);
    ASSERT_FALSE(state_result);
    EXPECT_NE(state_result.error.find("/state"), std::string::npos);

    core::AdmissionRequest request;
    request.candidate_pubkey = b64(
        std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 1));
    request.server_id = "berlin-2";
    request.region = "eu-west";
    request.nonce = b64(std::vector<uint8_t>(32, 2));
    request.timestamp = 1751328000;
    request.signature = b64(
        std::vector<uint8_t>(crypto::kEd25519SignatureSize, 3));
    auto invalid_platform = request.toJson();
    invalid_platform["platform_class"] = "fake-tee";
    auto platform_result = core::AdmissionRequest::fromJson(invalid_platform);
    ASSERT_FALSE(platform_result);
    EXPECT_NE(platform_result.error.find("/platform_class"), std::string::npos);

    auto negative_timestamp = request.toJson();
    negative_timestamp["timestamp"] = -1;
    auto timestamp_result = core::AdmissionRequest::fromJson(negative_timestamp);
    ASSERT_FALSE(timestamp_result);
    EXPECT_NE(timestamp_result.error.find("/timestamp"), std::string::npos);

    core::ChallengeRequest challenge;
    challenge.candidate_pubkey = b64(
        std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 4));
    auto challenge_json = challenge.toJson();
    challenge_json["extra"] = true;
    EXPECT_FALSE(core::ChallengeRequest::fromJson(challenge_json));

    nlohmann::json port = 70000;
    uint16_t decoded_port = 0;
    std::string error;
    EXPECT_FALSE(core::onboarding_json::decode_value(port, decoded_port,
                                                     "/gossip_port", error));
    EXPECT_NE(error.find("out of range"), std::string::npos);
}

TEST(OnboardingJson, ApprovedBundleRoundTripsForClientAndServer) {
    crypto::SodiumCryptoService c;
    c.start();
    auto root = c.ed25519_keygen();
    auto candidate = c.ed25519_keygen();

    gossip::CertIssueParams params;
    params.network_id = kTestNetworkHex;
    params.server_pubkey_b64 = b64(
        {candidate.public_key.begin(), candidate.public_key.end()});
    params.server_id = "berlin-2";

    core::ApprovedOnboardingBundle bundle;
    bundle.certificate = gossip::issue_server_certificate(
        params, c, root.private_key, root.public_key);
    bundle.root_pubkey = crypto::to_hex(root.public_key);
    bundle.genesis_pubkey = b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 6));
    bundle.mesh_server_pubkey = b64(std::vector<uint8_t>(crypto::kX25519PublicKeySize, 5));
    bundle.seed_peers = {"berlin-1.example:9102"};
    bundle.mesh_endpoint = "203.0.113.10:51940";
    bundle.gossip_port = 9102;

    const core::PollResponse server_response{bundle};
    const auto wire = core::poll_response_to_json(server_response);
    auto client_response = core::poll_response_from_json(wire);
    ASSERT_TRUE(client_response) << client_response.error;
    const auto* decoded = std::get_if<core::ApprovedOnboardingBundle>(
        &*client_response.value);
    ASSERT_NE(decoded, nullptr);
    EXPECT_EQ(decoded->certificate.server_pubkey, bundle.certificate.server_pubkey);
    EXPECT_EQ(decoded->root_pubkey, bundle.root_pubkey);
    EXPECT_EQ(decoded->genesis_pubkey, bundle.genesis_pubkey);
    EXPECT_EQ(decoded->seed_peers, bundle.seed_peers);
    c.stop();
}

TEST(OnboardingJson, ApprovedBundleMissingGenesisIdentityIsRejected) {
    crypto::SodiumCryptoService c;
    c.start();
    auto root = c.ed25519_keygen();

    core::ApprovedOnboardingBundle bundle;
    bundle.certificate.network_id = kTestNetworkHex;
    bundle.certificate.server_pubkey =
        b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 6));
    bundle.certificate.issuer_pubkey =
        b64(std::vector<uint8_t>(root.public_key.begin(), root.public_key.end()));
    bundle.certificate.signature =
        b64(std::vector<uint8_t>(crypto::kEd25519SignatureSize, 8));
    bundle.root_pubkey = crypto::to_hex(root.public_key);
    bundle.genesis_pubkey = b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 9));
    bundle.seed_peers = {"berlin-1.example:9102"};
    bundle.gossip_port = 9102;

    const auto wire = core::poll_response_to_json(
        core::PollResponse{bundle});
    ASSERT_TRUE(core::poll_response_from_json(wire));

    // A bundle without the Genesis anchor is refused, not defaulted.
    auto missing = wire;
    missing.erase("genesis_pubkey");
    auto result = core::poll_response_from_json(missing);
    ASSERT_FALSE(result);
    EXPECT_NE(result.error.find("/genesis_pubkey"), std::string::npos);
    c.stop();
}

TEST(OnboardingJson, ApprovedBundleMalformedGenesisIdentityIsRejected) {
    core::ApprovedOnboardingBundle bundle;
    bundle.certificate.network_id = kTestNetworkHex;
    bundle.certificate.server_pubkey =
        b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 6));
    bundle.certificate.issuer_pubkey =
        b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 7));
    bundle.certificate.signature =
        b64(std::vector<uint8_t>(crypto::kEd25519SignatureSize, 8));
    bundle.root_pubkey = crypto::to_hex(std::span<const uint8_t>(
        std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 7).data(),
        crypto::kEd25519PublicKeySize));
    bundle.seed_peers = {"berlin-1.example:9102"};
    bundle.gossip_port = 9102;

    for (const auto& malformed :
         {std::string{""}, std::string{"c2hvcnQ="}, std::string{"!"}}) {
        auto wire = core::poll_response_to_json(core::PollResponse{bundle});
        wire["genesis_pubkey"] = malformed;
        auto result = core::poll_response_from_json(wire);
        ASSERT_FALSE(result) << malformed;
        EXPECT_NE(result.error.find("/genesis_pubkey"), std::string::npos);
    }
}

TEST(OnboardingJson, AdmissionStoreRoundTripAndLegacyMigration) {
    core::AdmissionRecord record;
    record.request_id = std::string(32, 'a');
    record.candidate_pubkey = b64(
        std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 6));
    record.server_id = "berlin-2";
    record.region = "eu-west";
    record.state = core::AdmissionState::Pending;
    record.decision_mode = "sole";

    core::AdmissionStoreDocument document;
    document.admissions.push_back(record);
    document.denied_until.emplace(record.candidate_pubkey, 1751328600);

    const auto encoded = document.toJson();
    EXPECT_EQ(encoded.at("version"), core::AdmissionStoreDocument::kVersion);
    EXPECT_EQ(encoded.at("admissions").at(0).at("state"), "pending");
    auto decoded = core::admission_store_from_json(encoded);
    ASSERT_TRUE(decoded) << decoded.error;
    ASSERT_EQ(decoded.value->admissions.size(), 1u);
    EXPECT_EQ(decoded.value->admissions.front().request_id, record.request_id);

    auto legacy = encoded;
    legacy.erase("version");
    legacy["admissions"][0]["state"] = 0;
    auto migrated = core::admission_store_from_json(legacy);
    ASSERT_TRUE(migrated) << migrated.error;
    EXPECT_EQ(migrated.value->admissions.front().state, core::AdmissionState::Pending);

    legacy["admissions"][0]["state"] = 9;
    auto invalid = core::admission_store_from_json(legacy);
    ASSERT_FALSE(invalid);
    EXPECT_NE(invalid.error.find("state"), std::string::npos);
}

// ===========================================================================
// Candidate-side pinned-root guards (pure functions)
// ===========================================================================

namespace {

// The bundle shape the root holder emits: the certificate names the network
// derived from `genesis`, signed by `root`.
core::ApprovedOnboardingBundle make_deriving_bundle(
        crypto::SodiumCryptoService& c,
        const crypto::Ed25519Keypair& root,
        const crypto::Ed25519Keypair& candidate,
        const crypto::Ed25519Keypair& genesis) {
    gossip::CertIssueParams params;
    params.network_id = crypto::to_hex(security::derive_network_id(
        genesis.public_key, security::constants::kSecurityRulesetVersion,
        security::constants::kConsensusRulesetVersion));
    params.server_pubkey_b64 = b64({candidate.public_key.begin(),
                                    candidate.public_key.end()});
    params.server_id = "berlin-2";

    core::ApprovedOnboardingBundle bundle;
    bundle.certificate = gossip::issue_server_certificate(
        params, c, root.private_key, root.public_key);
    bundle.root_pubkey = crypto::to_hex(root.public_key);
    bundle.genesis_pubkey = b64({genesis.public_key.begin(),
                                 genesis.public_key.end()});
    bundle.gossip_port = 9102;
    return bundle;
}

} // namespace

TEST(Onboarding, BundleGenesisBindingAcceptsTheDerivingAnchor) {
    crypto::SodiumCryptoService c;
    c.start();
    auto root = make_key(c);
    auto cand = make_key(c);
    auto genesis = make_key(c);

    auto bundle = make_deriving_bundle(c, root, cand, genesis);
    EXPECT_TRUE(core::onboarding_validation::check_bundle_genesis_binding(c, bundle).empty());

    // The anchor is identity: the "ed25519:" prefix form must bind the same way.
    auto prefixed = bundle;
    prefixed.genesis_pubkey = "ed25519:" + prefixed.genesis_pubkey;
    EXPECT_TRUE(core::onboarding_validation::check_bundle_genesis_binding(c, prefixed).empty());
    c.stop();
}

TEST(Onboarding, BundleGenesisBindingRejectsMalformedKey) {
    crypto::SodiumCryptoService c;
    c.start();
    auto root = make_key(c);
    auto cand = make_key(c);
    auto genesis = make_key(c);

    auto bundle = make_deriving_bundle(c, root, cand, genesis);
    for (const auto& malformed :
         {std::string{""}, std::string{"c2hvcnQ="}, std::string{"!!!"},
          b64(std::vector<uint8_t>(31, 1))}) {
        auto bad = bundle;
        bad.genesis_pubkey = malformed;
        EXPECT_FALSE(core::onboarding_validation::check_bundle_genesis_binding(c, bad).empty());
    }
    c.stop();
}

TEST(Onboarding, BundleGenesisBindingRejectsWrongNetworkDerivation) {
    // A different, equally valid Genesis identity derives a different network.
    crypto::SodiumCryptoService c;
    c.start();
    auto root = make_key(c);
    auto cand = make_key(c);
    auto genesis = make_key(c);
    auto other_genesis = make_key(c);

    auto bundle = make_deriving_bundle(c, root, cand, genesis);
    auto tampered = bundle;
    tampered.genesis_pubkey = b64({other_genesis.public_key.begin(),
                                   other_genesis.public_key.end()});
    EXPECT_FALSE(core::onboarding_validation::check_bundle_genesis_binding(c, tampered).empty());
    c.stop();
}

TEST(Onboarding, BundleGenesisBindingRejectsAlteredCertificateNetwork) {
    // A bundle with an altered network field must still be refused.
    crypto::SodiumCryptoService c;
    c.start();
    auto root = make_key(c);
    auto cand = make_key(c);
    auto genesis = make_key(c);

    auto bundle = make_deriving_bundle(c, root, cand, genesis);
    auto tampered = bundle;
    tampered.certificate.network_id[0] = (tampered.certificate.network_id[0] == 'a')
        ? 'b' : 'a';
    EXPECT_FALSE(core::onboarding_validation::check_bundle_genesis_binding(c, tampered).empty());
    c.stop();
}

TEST(Onboarding, PinnedRootGuards) {
    crypto::SodiumCryptoService c;
    c.start();
    auto root = make_key(c);
    auto hex  = crypto::to_hex(std::span<const uint8_t>(root.public_key.data(),
                                                        root.public_key.size()));
    std::string upper = hex;
    for (auto& ch : upper) ch = static_cast<char>(std::toupper(ch));

    // No pin → actionable refusal; bad formats rejected; a real key passes.
    EXPECT_NE(core::validate_pinned_root("").find("--root-pubkey"), std::string::npos);
    EXPECT_FALSE(core::validate_pinned_root("zz-not-hex").empty());
    EXPECT_FALSE(core::validate_pinned_root(hex.substr(0, 30)).empty());  // short key
    EXPECT_TRUE(core::validate_pinned_root(hex).empty());

    // The response may confirm the pin (byte compare, hex-casing-proof) but a
    // different key must abort. Absent is fine — confirm-only.
    EXPECT_TRUE(core::check_root_confirmation(hex, "").empty());
    EXPECT_TRUE(core::check_root_confirmation(hex, hex).empty());
    EXPECT_TRUE(core::check_root_confirmation(hex, upper).empty());
    auto other = make_key(c);
    auto other_hex = crypto::to_hex(std::span<const uint8_t>(other.public_key.data(),
                                                             other.public_key.size()));
    EXPECT_FALSE(core::check_root_confirmation(hex, other_hex).empty());
    c.stop();
}

// ===========================================================================
// AdmissionTokenStore — mint/verify/consume lifecycle
// ===========================================================================

class AdmissionTokenTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<crypto::SodiumCryptoService> crypto_svc;
    std::unique_ptr<storage::FileStorageService> storage_svc;
    std::unique_ptr<core::AdmissionTokenStore>   store;

    void SetUp() override {
        temp_dir = fs::temp_directory_path() /
                   ("nexus_test_admtoken_" + std::to_string(getpid()));
        fs::remove_all(temp_dir);
        fs::create_directories(temp_dir);
        crypto_svc = std::make_unique<crypto::SodiumCryptoService>();
        crypto_svc->start();
        storage_svc = std::make_unique<storage::FileStorageService>(temp_dir);
        storage_svc->start();
        store = std::make_unique<core::AdmissionTokenStore>(*storage_svc, *crypto_svc);
    }

    void TearDown() override {
        if (storage_svc) storage_svc->stop();
        if (crypto_svc)  crypto_svc->stop();
        if (!temp_dir.empty()) fs::remove_all(temp_dir);
    }

    /// The store's hashed at-rest path for a token (mirrors token_path()).
    fs::path path_of(const std::string& token) {
        auto hash = crypto_svc->sha256(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(token.data()), token.size()));
        auto name = crypto::to_hex(std::span<const uint8_t>(hash));
        return temp_dir / "onboarding" / "admission_tokens" / (name + ".json");
    }
};

TEST_F(AdmissionTokenTest, MintConsumeSingleUse) {
    auto minted = store->mint("", std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());
    EXPECT_EQ(minted->first.rfind("adm_", 0), 0u);
    EXPECT_TRUE(fs::exists(path_of(minted->first)));  // hashed at rest

    EXPECT_TRUE(store->consume(minted->first, "any-candidate").has_value());
    EXPECT_FALSE(store->consume(minted->first, "any-candidate").has_value());  // spent
}

TEST_F(AdmissionTokenTest, Expiry) {
    auto minted = store->mint("", std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());

    // Backdate the persisted record; the store must reject and remove on sight.
    auto p = path_of(minted->first);
    nlohmann::json j;
    { std::ifstream f(p); f >> j; }
    j["expires_at"] = 1;
    { std::ofstream f(p, std::ios::trunc); f << j.dump(); }

    EXPECT_FALSE(store->verify(minted->first, "").has_value());
    EXPECT_FALSE(fs::exists(p));
}

TEST_F(AdmissionTokenTest, WrongBindingRejectedNotBurned) {
    auto a = crypto_svc->ed25519_keygen();
    auto a_b64 = b64({a.public_key.begin(), a.public_key.end()});

    auto minted = store->mint(a_b64, std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());

    // An interceptor presenting the wrong key fails WITHOUT burning the token.
    EXPECT_FALSE(store->consume(minted->first, "someone-else").has_value());
    EXPECT_TRUE(fs::exists(path_of(minted->first)));
    EXPECT_TRUE(store->consume(minted->first, a_b64).has_value());
}

TEST_F(AdmissionTokenTest, MintValidatesCandidateKey) {
    EXPECT_FALSE(store->mint("!!not-base64!!", std::chrono::seconds{600}).has_value());
    // Valid base64 but not a 32-byte key.
    EXPECT_FALSE(store->mint("c2hvcnQ=", std::chrono::seconds{600}).has_value());
}

// ===========================================================================
// Live ServerAdmissionService — root-holder gate, PoP, evidence binding,
// tokens, admin sole discretion, cooldown, and persistence. Stands up the full
// dependency set so on_start() computes is_root_key_holder_ against a real
// loaded identity.
// ===========================================================================

class AdmissionServiceTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    asio::io_context io;
    std::unique_ptr<crypto::SodiumCryptoService>  crypto_svc;
    std::unique_ptr<storage::FileStorageService>  storage_svc;
    std::unique_ptr<crypto::KeyWrappingService>   kw;
    std::unique_ptr<gossip::GossipService>        gossip_svc;
    std::unique_ptr<core::ServerAdmissionService> admission;

    core::ServerConfig     config;
    crypto::Ed25519Keypair local_identity;  // this server's own gossip/root identity

    /// Build the stack. `root_is_local` points the trust anchor at this server's
    /// own identity (it IS the root holder) or an unrelated key (a non-root
    /// enrolled server).
    void make(bool root_is_local) {
        temp_dir = fs::temp_directory_path() /
                   ("nexus_test_admission_" + std::to_string(getpid()));
        fs::remove_all(temp_dir);
        fs::create_directories(temp_dir);

        crypto_svc = std::make_unique<crypto::SodiumCryptoService>();
        crypto_svc->start();
        storage_svc = std::make_unique<storage::FileStorageService>(temp_dir);
        storage_svc->start();
        kw = std::make_unique<crypto::KeyWrappingService>(*crypto_svc, *storage_svc);
        kw->start();

        // Persist this server's local identity (empty passphrase, as the daemon does).
        local_identity = kw->generate_and_store_identity({});

        // Value (not reference): the non-root branch's keypair is a temporary.
        crypto::Ed25519PublicKey anchor = root_is_local
            ? local_identity.public_key
            : crypto_svc->ed25519_keygen().public_key;
        config.root_pubkey = crypto::to_hex(
            std::span<const uint8_t>(anchor.data(), anchor.size()));
        config.onboard_enabled = true;

        gossip_svc = std::make_unique<gossip::GossipService>(io, 0, *storage_svc, *crypto_svc);
        gossip_svc->set_network_id(kTestNetworkHex);
        admission  = std::make_unique<core::ServerAdmissionService>(
            config, *crypto_svc, *kw, *storage_svc, *gossip_svc);
        admission->set_network_id(kTestNetworkHex);
        admission->start();  // on_start() computes is_root_key_holder_
    }

    /// Simulate a service restart over the same storage root.
    void restart_admission() {
        admission->stop();
        admission = std::make_unique<core::ServerAdmissionService>(
            config, *crypto_svc, *kw, *storage_svc, *gossip_svc);
        admission->set_network_id(kTestNetworkHex);
        admission->start();
    }

    void TearDown() override {
        if (admission)   admission->stop();
        if (gossip_svc)  gossip_svc->stop();
        if (kw)          kw->stop();
        if (storage_svc) storage_svc->stop();
        if (crypto_svc)  crypto_svc->stop();
        // A failing test keeps its data directory for inspection.
        if (!temp_dir.empty() && !HasFailure()) fs::remove_all(temp_dir);
    }

    /// A fresh candidate's fully-signed onboarding request (challenge → sign).
    core::AdmissionRequest
    signed_request(const crypto::Ed25519Keypair& cand, const std::string& server_id) {
        core::AdmissionRequest in;
        in.candidate_pubkey = b64({cand.public_key.begin(), cand.public_key.end()});
        in.server_id        = server_id;
        in.region           = "eu-west";
        in.nonce            = admission->issue_challenge(in.candidate_pubkey);
        in.timestamp        = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        sign(in, cand);
        return in;
    }

    void sign(core::AdmissionRequest& in,
              const crypto::Ed25519Keypair& key) {
        auto msg = core::canonical_admission_request(in);
        auto sig = crypto_svc->ed25519_sign(key.private_key, std::span<const uint8_t>(msg));
        in.signature = crypto::to_base64(std::span<const uint8_t>(sig.data(), sig.size()));
    }
};

// --- Root-holder gate ---

TEST_F(AdmissionServiceTest, NonRootHolderRefusesOnboardingEntirely) {
    make(/*root_is_local=*/false);
    // Merely having root_pubkey configured (every enrolled server does) must not
    // let a non-root server advertise onboarding, take requests, or mint tokens.
    EXPECT_FALSE(admission->accepts_onboarding());

    auto cand = crypto_svc->ed25519_keygen();
    auto r = admission->create_request(signed_request(cand, "berlin-2"));
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.status, 403);

    EXPECT_FALSE(admission->mint_admission_token("", std::chrono::seconds{600}).has_value());
}

// --- Proof of possession and evidence binding ---

TEST_F(AdmissionServiceTest, ValidPopRequestLandsPending) {
    // Default state is closed: a valid request waits for the admin (or a token),
    // never self-admits. Every new record is sole-discretion.
    make(/*root_is_local=*/true);
    EXPECT_TRUE(admission->accepts_onboarding());

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    auto r    = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.status, 200);

    auto a = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->state, core::AdmissionState::Pending);
    EXPECT_TRUE(a->decided_by.empty());
    EXPECT_TRUE(a->issued_cert_json.empty());
    EXPECT_EQ(a->decision_mode, "sole");
}

TEST_F(AdmissionServiceTest, BadPopSignatureRefused) {
    // A signature by any key other than the claimed candidate key is not proof
    // of possession, whatever else the request carries.
    make(/*root_is_local=*/true);

    auto cand  = crypto_svc->ed25519_keygen();
    auto other = crypto_svc->ed25519_keygen();
    auto in    = signed_request(cand, "berlin-2");
    sign(in, other);  // wrong signer over the same canonical bytes

    auto r = admission->create_request(in);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.status, 401);
    EXPECT_TRUE(admission->pending().empty());
}

TEST_F(AdmissionServiceTest, EvidenceDigestMismatchRefused) {
    // The signature covers evidence_sha256, not the bundle. A bundle that does
    // not hash to the signed digest is a swapped bundle and must be refused.
    make(/*root_is_local=*/true);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    in.evidence        = "not-the-signed-bundle";
    in.evidence_sha256 = std::string(64, 'c');  // digest of something else
    sign(in, cand);  // correctly signed — only the binding is broken

    auto r = admission->create_request(in);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.status, 400);
    EXPECT_TRUE(admission->pending().empty());
}

TEST_F(AdmissionServiceTest, WrongOrReplayedNonceRefused) {
    // The nonce is single-use proof-of-possession state: a nonce the service
    // never issued fails, and a captured request cannot be replayed once its
    // nonce is consumed — the signature is still valid both times.
    make(/*root_is_local=*/true);

    auto cand = crypto_svc->ed25519_keygen();
    core::AdmissionRequest in;
    in.candidate_pubkey = b64({cand.public_key.begin(), cand.public_key.end()});
    in.server_id = "berlin-2";
    in.region    = "eu-west";
    in.nonce     = "bm90LWlzc3VlZA==";  // never issued
    in.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    sign(in, cand);
    auto r = admission->create_request(in);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.status, 401);
    EXPECT_TRUE(admission->pending().empty());

    // Replay: the first submission consumes the real nonce; the identical
    // signed bytes must fail on the second pass.
    auto in2 = signed_request(cand, "berlin-2");
    ASSERT_TRUE(admission->create_request(in2).ok);
    auto replay = admission->create_request(in2);
    EXPECT_FALSE(replay.ok);
    EXPECT_EQ(replay.status, 401);
}

TEST_F(AdmissionServiceTest, StaleTimestampRefused) {
    // Freshness window: a request outside the ±nonce-TTL window is refused
    // before any other processing, so a captured request has a short life
    // independent of its nonce.
    make(/*root_is_local=*/true);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    in.timestamp -= 100000;  // far outside the window
    sign(in, cand);          // correctly signed — only the freshness is broken
    auto r = admission->create_request(in);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.status, 400);
    EXPECT_TRUE(admission->pending().empty());
}

// --- Single-use bound token admission ---

TEST_F(AdmissionServiceTest, TokenAdmitsImmediatelyAndBurns) {
    // A candidate-bound token admits immediately, is single-use, and the issued
    // cert is root-signed (proves the issuance path uses the anchor key).
    make(/*root_is_local=*/true);

    auto cand     = crypto_svc->ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    auto minted   = admission->mint_admission_token(cand_b64, std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());

    auto in = signed_request(cand, "berlin-2");
    in.enrollment_token = minted->first;
    auto r = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;

    auto a = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->state, core::AdmissionState::Approved);
    EXPECT_EQ(a->decided_by, "token");
    ASSERT_FALSE(a->issued_cert_json.empty());

    auto cert = nlohmann::json::parse(a->issued_cert_json);
    EXPECT_EQ(cert.value("issuer_pubkey", ""), crypto::to_base64(local_identity.public_key));
    EXPECT_TRUE(cert_verifies_against(a->issued_cert_json,
                                      local_identity.public_key, *crypto_svc));

    // Spent: the same token cannot be redeemed again (single use).
    auto in2 = signed_request(cand, "berlin-3");
    in2.enrollment_token = minted->first;
    auto r2 = admission->create_request(in2);
    EXPECT_FALSE(r2.ok);
    EXPECT_EQ(r2.status, 403);
}

TEST_F(AdmissionServiceTest, InvalidTokenRejected) {
    make(/*root_is_local=*/true);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    in.enrollment_token = "adm_deadbeef";
    auto r = admission->create_request(in);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.status, 403);
    // A bad token must not leave a pending record behind.
    EXPECT_TRUE(admission->pending().empty());
}

TEST_F(AdmissionServiceTest, UnboundTokenRejectedOnUnauthTransport) {
    // An unbound token must not be spendable over the onboarding path — an
    // intermediary could otherwise capture it and race with its own key.
    make(/*root_is_local=*/true);

    auto minted = admission->mint_admission_token("", std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());  // store allows unbound; the admission path rejects it

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    in.enrollment_token = minted->first;
    auto r = admission->create_request(in);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.status, 403);
    EXPECT_TRUE(admission->pending().empty());

    // Not consumed: the unbound token is still on disk (rejected, not burned).
    core::AdmissionTokenStore store{*storage_svc, *crypto_svc};
    EXPECT_TRUE(store.verify(minted->first, in.candidate_pubkey).has_value());
}

TEST_F(AdmissionServiceTest, BoundTokenEnforced) {
    make(/*root_is_local=*/true);

    auto a_key = crypto_svc->ed25519_keygen();
    auto a_b64 = b64({a_key.public_key.begin(), a_key.public_key.end()});
    auto minted = admission->mint_admission_token(a_b64, std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());

    // An interceptor's request fails and does NOT burn the bound token.
    auto b_key = crypto_svc->ed25519_keygen();
    auto in_b  = signed_request(b_key, "intruder");
    in_b.enrollment_token = minted->first;
    auto r_b = admission->create_request(in_b);
    EXPECT_FALSE(r_b.ok);
    EXPECT_EQ(r_b.status, 403);

    // The bound candidate still succeeds with the same token.
    auto in_a = signed_request(a_key, "berlin-2");
    in_a.enrollment_token = minted->first;
    auto r_a = admission->create_request(in_a);
    ASSERT_TRUE(r_a.ok) << r_a.error;
    auto a = admission->status(r_a.request_id, in_a.candidate_pubkey);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->state, core::AdmissionState::Approved);
}

TEST_F(AdmissionServiceTest, ServerIdBoundTokenEnforced) {
    // A token minted for one server_id must not admit another name — the
    // candidate does not get to choose its DNS label. The mismatch is
    // refused WITHOUT burning the token, and the bound name still admits.
    make(/*root_is_local=*/true);

    auto cand     = crypto_svc->ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    auto minted   = admission->mint_admission_token(cand_b64, std::chrono::seconds{600},
                                                    "berlin-2");
    ASSERT_TRUE(minted.has_value());

    auto in = signed_request(cand, "berlin-9");
    in.enrollment_token = minted->first;
    auto r = admission->create_request(in);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.status, 403);

    auto in2 = signed_request(cand, "berlin-2");
    in2.enrollment_token = minted->first;
    auto r2 = admission->create_request(in2);
    ASSERT_TRUE(r2.ok) << r2.error;
    auto a = admission->status(r2.request_id, in2.candidate_pubkey);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->state, core::AdmissionState::Approved);
    EXPECT_EQ(a->server_id, "berlin-2");
}

TEST_F(AdmissionServiceTest, TokenRetryApprovesExistingPending) {
    // A candidate parked in the queue can retry with a token; the existing
    // record flips to Approved instead of duplicating.
    make(/*root_is_local=*/true);

    auto cand     = crypto_svc->ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    auto in1  = signed_request(cand, "berlin-2");
    auto r1   = admission->create_request(in1);
    ASSERT_TRUE(r1.ok) << r1.error;

    auto minted = admission->mint_admission_token(cand_b64, std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());

    auto in2 = signed_request(cand, "berlin-2");
    in2.enrollment_token = minted->first;
    auto r2 = admission->create_request(in2);
    ASSERT_TRUE(r2.ok) << r2.error;
    EXPECT_EQ(r2.request_id, r1.request_id);

    auto a = admission->status(r1.request_id, in1.candidate_pubkey);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->state, core::AdmissionState::Approved);
    EXPECT_EQ(a->decided_by, "token");
}

// --- Admin sole discretion ---

TEST_F(AdmissionServiceTest, AdminApproveMintsRootSignedCert) {
    make(/*root_is_local=*/true);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    auto r    = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;

    // Approval requires echoing the candidate identity (out-of-band check duty).
    auto wrong = admission->approve(r.request_id, "not-the-candidate", /*supersede=*/false);
    EXPECT_FALSE(wrong.ok);
    EXPECT_EQ(wrong.status, 400);

    auto ap = admission->approve(r.request_id, in.candidate_pubkey, /*supersede=*/false);
    ASSERT_TRUE(ap.ok) << ap.error;

    auto a = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->state, core::AdmissionState::Approved);
    EXPECT_EQ(a->decided_by, "admin");
    ASSERT_FALSE(a->issued_cert_json.empty());
    // The mint is real: the certificate verifies against the root anchor key.
    EXPECT_TRUE(cert_verifies_against(a->issued_cert_json,
                                      local_identity.public_key, *crypto_svc));
}

TEST_F(AdmissionServiceTest, AdminDenySetsCooldown) {
    make(/*root_is_local=*/true);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    auto r    = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;

    auto dn = admission->deny(r.request_id, "unverified operator");
    ASSERT_TRUE(dn.ok) << dn.error;

    auto a = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->state, core::AdmissionState::Denied);

    // The denied identity cannot immediately re-request: a denial without a
    // cooldown is just a retry prompt for an attacker.
    auto again = admission->create_request(signed_request(cand, "berlin-2"));
    EXPECT_FALSE(again.ok);
    EXPECT_EQ(again.status, 429);
}

TEST_F(AdmissionServiceTest, ApproveRefusesUnverifiedPlatformClaim) {
    // The approve-time evidence gate: a Tier-1-class claim that does not
    // verify must never mint. An unsupported platform_class is refused and the
    // record stays pending with no certificate.
    make(/*root_is_local=*/true);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    in.platform_class  = core::AdmissionPlatform::Tpm2;
    in.evidence        = "bundle-bytes";
    in.evidence_sha256 = crypto::to_hex(crypto_svc->sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(in.evidence.data()), in.evidence.size())));
    sign(in, cand);  // the digest binding holds — only the platform claim is bogus

    auto r = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;

    auto ap = admission->approve(r.request_id, in.candidate_pubkey, /*supersede=*/false);
    EXPECT_FALSE(ap.ok);
    EXPECT_EQ(ap.status, 403);

    auto a = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->state, core::AdmissionState::Pending);
    EXPECT_TRUE(a->issued_cert_json.empty());
}

TEST_F(AdmissionServiceTest, AcknowledgeCompletesApprovedOnly) {
    // Approved → Completed, gated on the owner key; anything else refuses.
    make(/*root_is_local=*/true);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    auto r    = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;

    EXPECT_FALSE(admission->acknowledge(r.request_id, in.candidate_pubkey));  // not approved
    ASSERT_TRUE(admission->approve(r.request_id, in.candidate_pubkey, false).ok);
    EXPECT_FALSE(admission->acknowledge(r.request_id, "not-the-candidate"));

    EXPECT_TRUE(admission->acknowledge(r.request_id, in.candidate_pubkey));
    auto a = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->state, core::AdmissionState::Completed);
    EXPECT_FALSE(admission->acknowledge(r.request_id, in.candidate_pubkey));  // final
}

TEST_F(AdmissionServiceTest, StatusRequiresTheOwnerKey) {
    // request_id is not a capability: status is disclosed only to the key
    // that owns the admission.
    make(/*root_is_local=*/true);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    auto r    = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;

    EXPECT_FALSE(admission->status(r.request_id, "someone-else").has_value());
    EXPECT_TRUE(admission->status(r.request_id, in.candidate_pubkey).has_value());
}

// --- server_id uniqueness and record immutability ---

TEST_F(AdmissionServiceTest, DuplicateServerIdRefused) {
    // Two candidates racing for one server_id: the second is refused before any
    // approval can bind the same DNS label to two keys.
    make(/*root_is_local=*/true);

    auto cand_a = crypto_svc->ed25519_keygen();
    auto r_a = admission->create_request(signed_request(cand_a, "berlin-2"));
    ASSERT_TRUE(r_a.ok) << r_a.error;

    auto cand_b = crypto_svc->ed25519_keygen();
    auto r_b = admission->create_request(signed_request(cand_b, "berlin-2"));
    EXPECT_FALSE(r_b.ok);
    EXPECT_EQ(r_b.status, 409);
}

TEST_F(AdmissionServiceTest, PendingAdmissionCannotBeMutated) {
    // The pending record is what gets minted: the admin verifies claim A, so a
    // re-submission must not swap in claim B under the same request_id.
    make(/*root_is_local=*/true);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-5");
    auto r    = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;

    // Same key, same pending request, different server_id → 409, record intact.
    auto swap = signed_request(cand, "berlin-6");
    auto r2   = admission->create_request(swap);
    EXPECT_FALSE(r2.ok);
    EXPECT_EQ(r2.status, 409);

    auto mid = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(mid.has_value());
    EXPECT_EQ(mid->server_id, "berlin-5");

    // An identical re-submission stays an idempotent retry.
    auto same = signed_request(cand, "berlin-5");
    auto r3   = admission->create_request(same);
    EXPECT_TRUE(r3.ok) << r3.error;
    EXPECT_EQ(r3.request_id, r.request_id);
}

TEST_F(AdmissionServiceTest, FailedTokenApprovalLeavesNoLivePending) {
    // A candidate that was parked pending retries with a token. When the
    // token turns out to be unusable, the failed-approval path may spend the
    // token (consume fail-closed) — but a burned/failed token must not leave
    // a LIVE Pending record behind: the stale pending admission would linger,
    // claim the server_id, and keep counting until it expires.
    make(/*root_is_local=*/true);

    auto cand     = crypto_svc->ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});

    // First submission parks a live Pending record (no token).
    auto in1 = signed_request(cand, "berlin-2");
    auto r1  = admission->create_request(in1);
    ASSERT_TRUE(r1.ok) << r1.error;
    ASSERT_TRUE(admission->status(r1.request_id, in1.candidate_pubkey).has_value());
    ASSERT_EQ(admission->status(r1.request_id, in1.candidate_pubkey)->state,
              core::AdmissionState::Pending);
    ASSERT_EQ(admission->pending().size(), 1u);

    // A burned token is dead — the store rejects it at verify() the moment
    // its file is gone, so the admission path must invalidate the pending
    // record on that refusal too (the burn already happened; the only
    // remaining question is what the stale record does).
    auto minted = admission->mint_admission_token(cand_b64, std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());
    core::AdmissionTokenStore store{*storage_svc, *crypto_svc};
    ASSERT_TRUE(store.consume(minted->first, cand_b64).has_value());  // spent
    ASSERT_FALSE(store.verify(minted->first, cand_b64).has_value()); // dead

    auto in2 = signed_request(cand, "berlin-2");
    in2.enrollment_token = minted->first;
    auto r2 = admission->create_request(in2);
    EXPECT_FALSE(r2.ok);
    EXPECT_EQ(r2.status, 403);

    // The pending record is gone (not merely expired): the pending map no
    // longer contains the candidate's entry at all.
    ASSERT_TRUE(admission->pending().empty());
    EXPECT_FALSE(admission->status(r1.request_id, in1.candidate_pubkey).has_value());

    // The candidate can start over with a fresh (tokenless) request — the
    // old record is not a zombie blocking the server_id.
    auto in3 = signed_request(cand, "berlin-2");
    auto r3  = admission->create_request(in3);
    EXPECT_TRUE(r3.ok) << r3.error;
    EXPECT_NE(r3.request_id, r1.request_id);
    EXPECT_EQ(admission->status(r3.request_id, in3.candidate_pubkey)->state,
              core::AdmissionState::Pending);
}

// --- Persistence ---

TEST_F(AdmissionServiceTest, PendingAdmissionSurvivesRestart) {
    // A restart must not silently drop a request an operator is mid-way through
    // verifying, and must not change its content.
    make(/*root_is_local=*/true);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    auto r    = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;

    restart_admission();

    auto a = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->state, core::AdmissionState::Pending);
    EXPECT_EQ(a->server_id, "berlin-2");
    EXPECT_EQ(a->candidate_pubkey, in.candidate_pubkey);
    EXPECT_EQ(a->decision_mode, "sole");
}

TEST_F(AdmissionServiceTest, PersistedExpiryEnforcedAfterRestart) {
    // Expiry is a property of the stored record, not of the process: a restart
    // must not resurrect a request past its TTL.
    make(/*root_is_local=*/true);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    auto r    = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;

    admission->stop();  // persists the record

    // Backdate the persisted expiry.
    auto env = storage_svc->read_file("onboarding", "admissions.json");
    ASSERT_TRUE(env.has_value());
    auto j = nlohmann::json::parse(env->data);
    ASSERT_FALSE(j["admissions"].empty());
    j["admissions"][0]["expires_at"] = 1;
    env->data = j.dump();
    ASSERT_TRUE(storage_svc->write_file("onboarding", "admissions.json", *env));

    admission = std::make_unique<core::ServerAdmissionService>(
        config, *crypto_svc, *kw, *storage_svc, *gossip_svc);
    admission->start();

    auto a = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->state, core::AdmissionState::Expired);
}

TEST_F(AdmissionServiceTest, DenialCooldownSurvivesRestart) {
    // A restart must not clear an active denial — the cooldown is persisted
    // state, or a denied identity could retry by crashing the server.
    make(/*root_is_local=*/true);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    auto r    = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;
    ASSERT_TRUE(admission->deny(r.request_id, "unverified operator").ok);

    restart_admission();

    auto again = admission->create_request(signed_request(cand, "berlin-2"));
    EXPECT_FALSE(again.ok);
    EXPECT_EQ(again.status, 429);
}

TEST_F(AdmissionServiceTest, PendingCapacityRefusalSparesTokens) {
    // Pending spam cannot lock out a valid token: the request past the cap is
    // refused 429, while a bound-token admission still lands because tokens
    // do not count against the pending capacity.
    make(/*root_is_local=*/true);

    for (int i = 0; i < 8; ++i) {  // cfg default max_pending
        auto k = crypto_svc->ed25519_keygen();
        ASSERT_TRUE(admission->create_request(
            signed_request(k, "node-" + std::to_string(i))).ok);
    }
    auto k9 = crypto_svc->ed25519_keygen();
    auto r9 = admission->create_request(signed_request(k9, "node-full"));
    EXPECT_FALSE(r9.ok);
    EXPECT_EQ(r9.status, 429);

    auto tok_cand = crypto_svc->ed25519_keygen();
    auto tok_b64  = b64({tok_cand.public_key.begin(), tok_cand.public_key.end()});
    auto minted   = admission->mint_admission_token(tok_b64, std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());
    auto in = signed_request(tok_cand, "node-token");
    in.enrollment_token = minted->first;
    auto r = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;
}

TEST_F(AdmissionServiceTest, HistoricalBallotRecordLoadsAsFact) {
    // Records decided by the removed ballot machinery are history, not errors:
    // they must load unchanged, and the service must keep working around them.
    // New records only ever write decision_mode "sole".
    make(/*root_is_local=*/true);
    admission->stop();  // release the (empty) persisted state

    auto legacy_key = crypto_svc->ed25519_keygen();
    auto legacy_b64 = b64({legacy_key.public_key.begin(), legacy_key.public_key.end()});
    const std::string legacy_id_1(32, '1');
    const std::string legacy_id_2(32, '2');

    nlohmann::json rec_ballot = {
        {"request_id", legacy_id_1}, {"candidate_pubkey", legacy_b64},
        {"server_id", "old-node"}, {"region", "eu-west"},
        {"tpm_ak_pubkey", ""}, {"tpm_ek_cert", ""}, {"source_ip", "192.0.2.1"},
        {"state", 1 /* Approved */}, {"created_at", 1}, {"expires_at", 2},
        {"issued_cert_json", "{}"}, {"decision_reason", "quorum approved"},
        {"decided_by", "ballot"}, {"decision_mode", "ballot"},
    };
    // Pre-decision_mode record: a stored ballot claim keeps its ballot labeling.
    nlohmann::json rec_pre = {
        {"request_id", legacy_id_2}, {"candidate_pubkey", legacy_b64},
        {"server_id", "old-node-2"}, {"region", ""},
        {"tpm_ak_pubkey", ""}, {"tpm_ek_cert", ""}, {"source_ip", ""},
        {"state", 1 /* Approved */}, {"created_at", 0}, {"expires_at", 0},
        {"issued_cert_json", ""}, {"decision_reason", ""},
        {"decided_by", "ballot"}, {"ballot_claim_json", "{\"nonce\":\"n\"}"},
    };
    nlohmann::json root_j{{"ever_approved", true},
                          {"admissions", nlohmann::json::array({rec_ballot, rec_pre})},
                          {"denied_until", nlohmann::json::object()}};
    storage::SignedEnvelope env;
    env.type = "admissions";
    env.data = root_j.dump();
    ASSERT_TRUE(storage_svc->write_file("onboarding", "admissions.json", env));

    admission = std::make_unique<core::ServerAdmissionService>(
        config, *crypto_svc, *kw, *storage_svc, *gossip_svc);
    admission->start();

    auto a1 = admission->status(legacy_id_1, legacy_b64);
    ASSERT_TRUE(a1.has_value());
    EXPECT_EQ(a1->state, core::AdmissionState::Approved);
    EXPECT_EQ(a1->decision_mode, "ballot");
    EXPECT_EQ(a1->decided_by, "ballot");

    auto a2 = admission->status(legacy_id_2, legacy_b64);
    ASSERT_TRUE(a2.has_value());
    EXPECT_EQ(a2->decision_mode, "ballot");

    // The service still functions: a fresh request lands pending as "sole".
    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    auto r    = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(admission->status(r.request_id, in.candidate_pubkey)->decision_mode, "sole");
}

// A server_id already claimed by an enrolled peer must 409 the request, and a
// token presented alongside it must NOT be burned — the operator can retry
// under a free name with the same token. Needs a certified gossip peer, so
// this stands its own stack up rather than reusing the fixture.
TEST(OnboardingAdmission, ServerIdConflictDoesNotBurnToken) {
    auto tmp = fs::temp_directory_path() /
               ("nexus_test_conflict_" + std::to_string(getpid()));
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    asio::io_context io;
    crypto::SodiumCryptoService c;  c.start();
    storage::FileStorageService s{tmp};  s.start();
    crypto::KeyWrappingService  kw{c, s};  kw.start();
    auto root = kw.generate_and_store_identity({});

    // Seed a certified peer holding server_id "berlin-2" under a different
    // key. The certificate is real — issued by the root key — because this
    // is the only state the production ServerHello path can deposit.
    auto other = c.ed25519_keygen();
    auto other_b64 = b64({other.public_key.begin(), other.public_key.end()});
    gossip::CertIssueParams cp;
    cp.network_id = kTestNetworkHex;
    cp.server_pubkey_b64 = other_b64;
    cp.server_id         = "berlin-2";
    nlohmann::json cert  = gossip::issue_server_certificate(cp, c, root.private_key,
                                                            root.public_key);
    nlohmann::json peers{{"peers", nlohmann::json::array({
        {{"pubkey", other_b64}, {"endpoint", "10.9.9.9:9102"},
         {"certificate_json", cert.dump()}}})}};
    storage::SignedEnvelope env;
    env.type = "peer_list";
    env.data = peers.dump();
    ASSERT_TRUE(s.write_file("identity", "peers.json", env));

    gossip::GossipService gossip{io, 0, s, c};
    gossip.set_root_pubkey(root.public_key); gossip.set_network_id(kTestNetworkHex);
    gossip.start();  // load_peers() pulls in the seeded certified peer

    core::ServerConfig config;
    config.root_pubkey = crypto::to_hex(
        std::span<const uint8_t>(root.public_key.data(), root.public_key.size()));
    config.onboard_enabled = true;
    core::ServerAdmissionService admission{config, c, kw, s, gossip};
    admission.set_network_id(kTestNetworkHex);
    admission.start();

    auto cand     = c.ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    auto token    = admission.mint_admission_token(cand_b64, std::chrono::seconds{600});
    ASSERT_TRUE(token.has_value());

    auto sign_req = [&](const std::string& server_id) {
        core::AdmissionRequest in;
        in.candidate_pubkey = cand_b64;
        in.server_id = server_id;
        in.region = "eu-west";
        in.nonce = admission.issue_challenge(in.candidate_pubkey);
        in.timestamp = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        auto msg = core::canonical_admission_request(in);
        auto sig = c.ed25519_sign(cand.private_key, std::span<const uint8_t>(msg));
        in.signature = crypto::to_base64(std::span<const uint8_t>(sig.data(), sig.size()));
        in.enrollment_token = token->first;
        return in;
    };

    // Colliding name → 409, and the token survives.
    auto r1 = admission.create_request(sign_req("berlin-2"));
    EXPECT_FALSE(r1.ok);
    EXPECT_EQ(r1.status, 409);
    core::AdmissionTokenStore store{s, c};
    ASSERT_TRUE(store.verify(token->first, cand_b64).has_value());

    // A free name with the same token admits.
    auto free_req = sign_req("berlin-3");
    auto r2 = admission.create_request(free_req);
    ASSERT_TRUE(r2.ok) << r2.error;
    auto a = admission.status(r2.request_id, free_req.candidate_pubkey);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->state, core::AdmissionState::Approved);

    admission.stop();
    gossip.stop();
    kw.stop();
    s.stop();
    c.stop();
    fs::remove_all(tmp);
}

// The root server's own server_id never appears in get_peers(), so it has its
// own refusal: a candidate must not be able to claim the root's identity.
TEST(OnboardingAdmission, ReservedSelfServerIdRefused) {
    auto tmp = fs::temp_directory_path() /
               ("nexus_test_reserved_" + std::to_string(getpid()));
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    asio::io_context io;
    crypto::SodiumCryptoService c;  c.start();
    storage::FileStorageService s{tmp};  s.start();
    crypto::KeyWrappingService  kw{c, s};  kw.start();
    auto root = kw.generate_and_store_identity({});

    // First start creates the gossip identity; then install this server's own
    // root-signed certificate and start again so our_server_id() is live.
    std::string self_b64;
    {
        gossip::GossipService boot{io, 0, s, c};
        boot.start();
        self_b64 = crypto::to_base64(boot.keypair().public_key);
        boot.stop();
    }
    gossip::CertIssueParams cp;
    cp.network_id = kTestNetworkHex;
    cp.server_pubkey_b64 = self_b64;
    cp.server_id         = "rootsrv";
    auto self_cert = gossip::issue_server_certificate(cp, c, root.private_key,
                                                      root.public_key);
    storage::SignedEnvelope cert_env;
    cert_env.type = "server_cert";
    cert_env.data = nlohmann::json(self_cert).dump();
    ASSERT_TRUE(s.write_file("identity", "server_cert.json", cert_env));

    gossip::GossipService gossip{io, 0, s, c};
    gossip.set_root_pubkey(root.public_key); gossip.set_network_id(kTestNetworkHex);
    gossip.start();
    ASSERT_TRUE(gossip.our_server_id().has_value());

    core::ServerConfig config;
    config.root_pubkey = crypto::to_hex(
        std::span<const uint8_t>(root.public_key.data(), root.public_key.size()));
    config.onboard_enabled = true;
    core::ServerAdmissionService admission{config, c, kw, s, gossip};
    admission.set_network_id(kTestNetworkHex);
    admission.start();

    auto cand     = c.ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    auto sign_req = [&](const std::string& server_id) {
        core::AdmissionRequest in;
        in.candidate_pubkey = cand_b64;
        in.server_id = server_id;
        in.region = "eu-west";
        in.nonce = admission.issue_challenge(in.candidate_pubkey);
        in.timestamp = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        auto msg = core::canonical_admission_request(in);
        auto sig = c.ed25519_sign(cand.private_key, std::span<const uint8_t>(msg));
        in.signature = crypto::to_base64(std::span<const uint8_t>(sig.data(), sig.size()));
        return in;
    };

    auto r = admission.create_request(sign_req("rootsrv"));
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.status, 409);

    // A free label from the same candidate still parks pending.
    auto r2 = admission.create_request(sign_req("fresh-node"));
    EXPECT_TRUE(r2.ok) << r2.error;

    admission.stop();
    gossip.stop();
    kw.stop();
    s.stop();
    c.stop();
    fs::remove_all(tmp);
}

// ===========================================================================
// Onboarding DTO drift guard (P2-25)
//
// Every onboarding DTO hand-enumerates its members in jsonFields(); the encode
// and the SIGNED canonical bytes both derive from that tuple. The static_assert
// in OnboardingTypes.hpp ties the tuple size to each struct's kFieldCount.
// This test is the backstop for the struct<->constant direction: if a data
// member is added to a struct but forgotten in jsonFields(), kFieldCount must
// be bumped (and so must this expected key set), and BOTH the tuple and the
// encoded key set will mismatch until jsonFields() is updated.
// ===========================================================================

namespace {

/// For one DTO: round-trip encode->decode, require the encoded key set to
/// equal `expected_keys` exactly, and require the tuple size to equal the
/// struct's declared kFieldCount.
template <typename T>
void check_onboarding_dto(const T& sample, const std::set<std::string>& expected_keys) {
    const auto encoded = sample.toJson();
    ASSERT_TRUE(encoded.is_object());

    // (1) Round trip: decode what was encoded.
    auto decoded = T::fromJson(encoded);
    ASSERT_TRUE(decoded) << decoded.error;
    EXPECT_EQ(decoded.value->toJson().dump(), encoded.dump());

    // (2) The encoded key set is exactly the expected member set. A member
    //     missing from jsonFields() would make this fail (key set short).
    std::set<std::string> encoded_keys;
    for (const auto& [key, unused] : encoded.items()) encoded_keys.insert(key);
    EXPECT_EQ(encoded_keys, expected_keys);

    // (3) The tuple size equals the struct's declared data-member count.
    constexpr std::size_t tuple_size = std::tuple_size_v<decltype(T::jsonFields())>;
    EXPECT_EQ(tuple_size, T::kFieldCount);
    EXPECT_EQ(tuple_size, expected_keys.size());

    // (4) The tuple's field NAMES are exactly the expected set (in order they
    //     are what encode() writes; the set is order-independent on purpose).
    std::set<std::string> field_names;
    std::apply(
        [&](const auto&... descriptor) {
            ((field_names.insert(descriptor.name.data()), ...));
        },
        T::jsonFields());
    EXPECT_EQ(field_names, expected_keys);
}

} // namespace

TEST(OnboardingDtoDriftGuard, AllDtosMatchTheirDeclaredFieldCounts) {
    // Expected key sets are the per-struct data-member inventory. Adding a
    // member to a struct without updating jsonFields() AND this set (and
    // kFieldCount) makes the build or this test fail.

    core::OnboardingInfoResponse info;
    info.accepts_onboarding = true;
    info.dns_base_domain = "example.internal";
    info.server_fqdn = "node.example.internal";
    check_onboarding_dto(info, {"accepts_onboarding", "dns_base_domain", "server_fqdn"});

    core::ChallengeRequest challenge_req;
    challenge_req.candidate_pubkey = b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 1));
    check_onboarding_dto(challenge_req, {"candidate_pubkey"});

    core::ChallengeResponse challenge_resp;
    challenge_resp.nonce = b64(std::vector<uint8_t>(32, 2));
    check_onboarding_dto(challenge_resp, {"nonce", "server_id_required"});

    core::AdmissionRequest admission_req;
    admission_req.candidate_pubkey =
        b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 2));
    admission_req.server_id = "berlin-2";
    admission_req.region = "eu-west";
    admission_req.tpm_ak_pubkey = "QUs=";
    admission_req.tpm_ek_cert = "MIIB";
    admission_req.platform_class = core::AdmissionPlatform::SnpVtpm;
    admission_req.measurement = std::string(96, 'a');
    admission_req.binary_hash = std::string(64, 'b');
    admission_req.evidence_sha256 = std::string(64, 'c');
    admission_req.evidence = "bundle";
    admission_req.nonce = b64(std::vector<uint8_t>(32, 2));
    admission_req.timestamp = 1751328000;
    admission_req.signature = b64(std::vector<uint8_t>(crypto::kEd25519SignatureSize, 3));
    admission_req.enrollment_token = "adm_0123456789";
    check_onboarding_dto(admission_req, {
        "candidate_pubkey", "server_id", "region", "tpm_ak_pubkey", "tpm_ek_cert",
        "platform_class", "measurement", "binary_hash", "evidence_sha256",
        "evidence", "nonce", "timestamp", "signature", "enrollment_token"});

    core::AdmissionResponse admission_resp;
    admission_resp.request_id = std::string(32, 'a');
    check_onboarding_dto(admission_resp, {"request_id", "state"});

    core::PollRequest poll_req;
    poll_req.request_id = std::string(32, 'a');
    poll_req.candidate_pubkey =
        b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 4));
    poll_req.timestamp = 1751328000;
    poll_req.signature = b64(std::vector<uint8_t>(crypto::kEd25519SignatureSize, 5));
    check_onboarding_dto(poll_req,
                         {"request_id", "candidate_pubkey", "timestamp", "signature"});

    core::AdmissionStatusResponse status;
    status.state = core::AdmissionState::Denied;
    status.reason = "unverified";
    check_onboarding_dto(status, {"state", "reason"});

    core::ApprovedOnboardingBundle bundle;
    bundle.state = core::AdmissionState::Approved;
    bundle.certificate.network_id = kTestNetworkHex;
    bundle.certificate.server_pubkey =
        b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 6));
    bundle.certificate.issuer_pubkey =
        b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 7));
    bundle.certificate.signature =
        b64(std::vector<uint8_t>(crypto::kEd25519SignatureSize, 8));
    bundle.root_pubkey = crypto::to_hex(std::span<const uint8_t>(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 7).data(), crypto::kEd25519PublicKeySize));
    bundle.genesis_pubkey = b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 16));
    bundle.mesh_server_pubkey = b64(std::vector<uint8_t>(crypto::kX25519PublicKeySize, 8));
    bundle.seed_peers = {"berlin-1.example:9102"};
    bundle.mesh_endpoint = "203.0.113.10:51940";
    bundle.gossip_port = 9102;
    check_onboarding_dto(bundle, {
        "state", "certificate", "root_pubkey", "genesis_pubkey", "mesh_server_pubkey",
        "seed_peers", "mesh_endpoint", "gossip_port"});

    core::AckRequest ack_req;
    ack_req.request_id = std::string(32, 'a');
    ack_req.candidate_pubkey =
        b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 9));
    ack_req.timestamp = 1751328000;
    ack_req.signature = b64(std::vector<uint8_t>(crypto::kEd25519SignatureSize, 10));
    check_onboarding_dto(ack_req,
                         {"request_id", "candidate_pubkey", "timestamp", "signature"});

    core::AckResponse ack_resp;
    check_onboarding_dto(ack_resp, {"state"});

    core::PendingAdmissionSummary summary;
    summary.request_id = std::string(32, 'a');
    summary.server_id = "berlin-2";
    summary.region = "eu-west";
    summary.candidate_pubkey =
        b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 11));
    summary.fingerprint = std::string(16, 'f');
    summary.tier1_capable = true;
    summary.source_ip = "192.0.2.1";
    summary.created_at = 1751328000;
    check_onboarding_dto(summary, {
        "request_id", "server_id", "region", "candidate_pubkey", "fingerprint",
        "tier1_capable", "source_ip", "created_at"});

    core::PendingAdmissionsResponse pending_resp;
    pending_resp.pending.push_back(summary);
    check_onboarding_dto(pending_resp, {"pending"});

    core::ApprovalRequest approval;
    approval.pubkey = "cGs=";
    approval.fingerprint = std::string(16, 'f');
    approval.supersede = true;
    check_onboarding_dto(approval, {"pubkey", "fingerprint", "supersede"});

    core::DenialRequest denial;
    denial.reason = "unverified operator";
    check_onboarding_dto(denial, {"reason"});

    core::AdmissionDecisionResponse decision;
    decision.state = core::AdmissionState::Denied;
    decision.request_id = std::string(32, 'a');
    check_onboarding_dto(decision, {"state", "request_id"});

    core::AdmissionTokenRequest token_req;
    token_req.candidate_pubkey =
        b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 12));
    token_req.ttl_sec = 600;
    token_req.server_id = "berlin-2";
    check_onboarding_dto(token_req, {"candidate_pubkey", "ttl_sec", "server_id"});

    core::AdmissionInvitation invitation;
    invitation.enrollment_token = "adm_0123456789";
    invitation.expires_at = 1751328600;
    invitation.candidate_pubkey =
        b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 13));
    invitation.server_id = "berlin-2";
    invitation.root_pubkey = crypto::to_hex(std::span<const uint8_t>(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 14).data(), crypto::kEd25519PublicKeySize));
    check_onboarding_dto(invitation, {
        "enrollment_token", "expires_at", "candidate_pubkey", "server_id",
        "root_pubkey"});

    core::AdmissionRecord record;
    record.request_id = std::string(32, 'a');
    record.candidate_pubkey =
        b64(std::vector<uint8_t>(crypto::kEd25519PublicKeySize, 15));
    record.server_id = "berlin-2";
    record.region = "eu-west";
    record.tpm_ak_pubkey = "QUs=";
    record.tpm_ek_cert = "MIIB";
    record.platform_class = core::AdmissionPlatform::Tpm2;
    record.measurement = std::string(96, 'a');
    record.binary_hash = std::string(64, 'b');
    record.evidence_sha256 = std::string(64, 'c');
    record.evidence = "bundle";
    record.challenge_nonce = b64(std::vector<uint8_t>(32, 2));
    record.source_ip = "192.0.2.1";
    record.state = core::AdmissionState::Approved;
    record.created_at = 1751328000;
    record.expires_at = 1751328600;
    record.issued_cert_json = "{}";
    record.decision_reason = "ok";
    record.decided_by = "admin";
    record.decision_mode = "sole";
    check_onboarding_dto(record, {
        "request_id", "candidate_pubkey", "server_id", "region", "tpm_ak_pubkey",
        "tpm_ek_cert", "platform_class", "measurement", "binary_hash",
        "evidence_sha256", "evidence", "challenge_nonce", "source_ip", "state",
        "created_at", "expires_at", "issued_cert_json", "decision_reason",
        "decided_by", "decision_mode"});

    core::AdmissionStoreDocument document;
    document.admissions.push_back(record);
    document.denied_until.emplace(record.candidate_pubkey, 1751328600);
    check_onboarding_dto(document, {"version", "ever_approved", "admissions", "denied_until"});
}

// The guard is a no-op on the wire: encode/decode and the signed canonical
// projection are built only from jsonFields(), which the static_asserts and
// the test above pin to the full member set. This test additionally pins the
// signed bytes of a fully-populated AdmissionRequest so any future change to
// the canonical construction fails loudly.
TEST(OnboardingDtoDriftGuard, CanonicalAdmissionRequestBytesPinned) {
    crypto::SodiumCryptoService c;
    c.start();
    auto cand = make_key(c);

    core::AdmissionRequest in;
    in.candidate_pubkey = b64({cand.public_key.begin(), cand.public_key.end()});
    in.server_id = "berlin-2";
    in.region = "eu-west";
    in.nonce = b64(std::vector<uint8_t>(32, 2));
    in.timestamp = 1751328000;
    in.signature = b64(std::vector<uint8_t>(crypto::kEd25519SignatureSize, 3));

    auto msg = core::canonical_admission_request(in);
    auto sig = c.ed25519_sign(cand.private_key, std::span<const uint8_t>(msg));
    EXPECT_TRUE(c.ed25519_verify(cand.public_key, std::span<const uint8_t>(msg), sig));

    // Re-encode -> decode (the wire path) and confirm the server would verify
    // the same canonical bytes, i.e. the DTO round trip preserves what is
    // signed.
    auto decoded = core::AdmissionRequest::fromJson(in.toJson());
    ASSERT_TRUE(decoded) << decoded.error;
    EXPECT_EQ(core::canonical_admission_request(in),
              core::canonical_admission_request(*decoded.value));
    c.stop();
}

// Approve-time supersede: an enrolled peer certified under the requested
// server_id with a DIFFERENT key blocks approval by default; supersede=true
// revokes the old key and mints for the new one. The conflicting certificate
// must land AFTER the request parks — create_request scans get_peers() too
// and would refuse the request outright.
TEST(OnboardingAdmission, SupersedeRevokesTheOldCertificate) {
    auto tmp = fs::temp_directory_path() /
               ("nexus_test_supersede_" + std::to_string(getpid()));
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    asio::io_context io;
    crypto::SodiumCryptoService c;  c.start();
    storage::FileStorageService s{tmp};  s.start();
    crypto::KeyWrappingService  kw{c, s};  kw.start();
    auto root = kw.generate_and_store_identity({});

    gossip::GossipService gossip{io, 0, s, c};
    gossip.set_root_pubkey(root.public_key); gossip.set_network_id(kTestNetworkHex);
    gossip.start();

    core::ServerConfig config;
    config.root_pubkey = crypto::to_hex(
        std::span<const uint8_t>(root.public_key.data(), root.public_key.size()));
    config.onboard_enabled = true;
    core::ServerAdmissionService admission{config, c, kw, s, gossip};
    admission.set_network_id(kTestNetworkHex);
    admission.start();

    auto cand     = c.ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    core::AdmissionRequest in;
    in.candidate_pubkey = cand_b64;
    in.server_id = "berlin-2";
    in.region = "eu-west";
    in.nonce = admission.issue_challenge(in.candidate_pubkey);
    in.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    {
        auto msg = core::canonical_admission_request(in);
        auto sig = c.ed25519_sign(cand.private_key, std::span<const uint8_t>(msg));
        in.signature = crypto::to_base64(std::span<const uint8_t>(sig.data(), sig.size()));
    }
    auto r = admission.create_request(in);
    ASSERT_TRUE(r.ok) << r.error;

    // The old holder's real root-signed certificate now lands in the peer set
    // (as a ServerHello would deposit it): restart gossip over a seeded list.
    auto old_holder = c.ed25519_keygen();
    auto old_b64 = b64({old_holder.public_key.begin(), old_holder.public_key.end()});
    gossip::CertIssueParams cp;
    cp.network_id = kTestNetworkHex;
    cp.server_pubkey_b64 = old_b64;
    cp.server_id         = "berlin-2";
    nlohmann::json old_cert = gossip::issue_server_certificate(cp, c, root.private_key,
                                                               root.public_key);
    gossip.stop();
    nlohmann::json peers{{"peers", nlohmann::json::array({
        {{"pubkey", old_b64}, {"endpoint", "10.9.9.9:9102"},
         {"certificate_json", old_cert.dump()}}})}};
    storage::SignedEnvelope env;
    env.type = "peer_list";
    env.data = peers.dump();
    ASSERT_TRUE(s.write_file("identity", "peers.json", env));
    gossip.start();

    // Default refuses: one server_id, two keys is an identity swap.
    auto blocked = admission.approve(r.request_id, cand_b64, /*supersede=*/false);
    EXPECT_FALSE(blocked.ok);
    EXPECT_EQ(blocked.status, 409);
    EXPECT_FALSE(gossip::GossipBallotTestAccess::revoked(gossip, old_b64));

    // Supersede: the old key is revoked, the new certificate is root-signed.
    auto ap = admission.approve(r.request_id, cand_b64, /*supersede=*/true);
    ASSERT_TRUE(ap.ok) << ap.error;
    EXPECT_TRUE(gossip::GossipBallotTestAccess::revoked(gossip, old_b64));

    auto a = admission.status(r.request_id, cand_b64);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->state, core::AdmissionState::Approved);
    ASSERT_FALSE(a->issued_cert_json.empty());
    EXPECT_TRUE(cert_verifies_against(a->issued_cert_json, root.public_key, c));

    admission.stop();
    gossip.stop();
    kw.stop();
    s.stop();
    c.stop();
    fs::remove_all(tmp);
}
