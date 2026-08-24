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
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <asio.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <cctype>
#include <chrono>
#include <cstring>
#include <filesystem>
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

TEST(Onboarding, EveryPlatformEvidenceFieldIsSigned) {
    // A peer that could edit any of these after signing would be choosing its own
    // platform policy. Each must break the signature on its own.
    crypto::SodiumCryptoService c;
    c.start();
    auto cand = make_key(c);

    core::ServerAdmissionService::RequestInput in;
    in.candidate_pubkey = b64({cand.public_key.begin(), cand.public_key.end()});
    in.server_id      = "berlin-2";
    in.region         = "eu-west";
    in.tpm_ak_pubkey  = "QUs=";
    in.platform_class = "snp-vtpm";
    in.measurement    = std::string(96, 'a');
    in.binary_hash    = std::string(64, 'b');
    in.evidence_sha256 = std::string(64, 'c');
    in.nonce          = "bm9uY2U=";
    in.timestamp      = 1751328000;

    const auto msg = core::ServerAdmissionService::canonical_request(in);
    const auto sig = c.ed25519_sign(cand.private_key, std::span<const uint8_t>(msg));

    auto breaks = [&](core::ServerAdmissionService::RequestInput edited) {
        auto m = core::ServerAdmissionService::canonical_request(edited);
        return !c.ed25519_verify(cand.public_key, std::span<const uint8_t>(m), sig);
    };
    { auto e = in; e.platform_class  = "tpm2";              EXPECT_TRUE(breaks(e)); }
    { auto e = in; e.measurement     = std::string(96, 'f'); EXPECT_TRUE(breaks(e)); }
    { auto e = in; e.binary_hash     = std::string(64, 'f'); EXPECT_TRUE(breaks(e)); }
    { auto e = in; e.evidence_sha256 = std::string(64, 'f'); EXPECT_TRUE(breaks(e)); }
    { auto e = in; e.tpm_ak_pubkey   = "b3RoZXI=";           EXPECT_TRUE(breaks(e)); }
    c.stop();
}

TEST(Onboarding, RequestCanonicalIsTaggedV2) {
    // A v1 client signs different bytes; the tag makes that a signature failure
    // rather than a silently narrower set of fields.
    core::ServerAdmissionService::RequestInput in;
    in.nonce = "n";
    const auto msg = core::ServerAdmissionService::canonical_request(in);
    const std::string text(msg.begin(), msg.end());
    EXPECT_NE(text.find("ln-onboard:v2"), std::string::npos);
    EXPECT_EQ(text.find("ln-onboard:v1"), std::string::npos);
}

TEST(Onboarding, ClaimReproducesTheSignedBytesExactly) {
    // The receiver re-derives the canonical form from the request body. A lost
    // field means the server verifies different bytes than the candidate signed.
    core::ServerAdmissionService::RequestInput in;
    in.candidate_pubkey = "Y2FuZA==";
    in.server_id       = "tokyo-1";
    in.region          = "ap-northeast";
    in.tpm_ak_pubkey   = "QUs=";
    in.platform_class  = "snp-vtpm";
    in.measurement     = std::string(96, 'a');
    in.binary_hash     = std::string(64, 'b');
    in.evidence_sha256 = std::string(64, 'c');
    in.nonce           = "bm9uY2U=";
    in.timestamp       = 1751328000;
    in.signature       = "c2ln";

    const auto claim = core::ServerAdmissionService::claim_from_request(in);
    const auto back  = core::ServerAdmissionService::request_from_claim(claim);

    EXPECT_EQ(core::ServerAdmissionService::canonical_request(in),
              core::ServerAdmissionService::canonical_request(back));
    EXPECT_EQ(back.signature, in.signature);
    // The bundle stays out (bound by evidence_sha256 instead), and the bearer
    // token is never part of any signed or replicated body.
    EXPECT_FALSE(claim.contains("evidence"));
    EXPECT_FALSE(claim.contains("enrollment_token"));
}

TEST(Onboarding, PollSignatureIsDomainSeparated) {
    // poll and ack share a shape but must not be cross-usable. Assert on the
    // production constants both endpoints verify with (OnboardApiHandler uses
    // kOnboardPollTag / kOnboardAckTag) — not on re-typed literals, which
    // would keep passing if the endpoints drifted to one shared tag.
    ASSERT_STRNE(core::kOnboardPollTag, core::kOnboardAckTag);
    auto poll = core::ServerAdmissionService::canonical_poll(core::kOnboardPollTag, "rid", 42);
    auto ack  = core::ServerAdmissionService::canonical_poll(core::kOnboardAckTag, "rid", 42);
    EXPECT_NE(poll, ack);
}

// ===========================================================================
// Candidate-side pinned-root guards (pure functions)
// ===========================================================================

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
        admission  = std::make_unique<core::ServerAdmissionService>(
            config, *crypto_svc, *kw, *storage_svc, *gossip_svc);
        admission->start();  // on_start() computes is_root_key_holder_
    }

    /// Simulate a service restart over the same storage root.
    void restart_admission() {
        admission->stop();
        admission = std::make_unique<core::ServerAdmissionService>(
            config, *crypto_svc, *kw, *storage_svc, *gossip_svc);
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
    core::ServerAdmissionService::RequestInput
    signed_request(const crypto::Ed25519Keypair& cand, const std::string& server_id) {
        core::ServerAdmissionService::RequestInput in;
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

    void sign(core::ServerAdmissionService::RequestInput& in,
              const crypto::Ed25519Keypair& key) {
        auto msg = core::ServerAdmissionService::canonical_request(in);
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
    EXPECT_EQ(a->state, core::ServerAdmissionService::State::Pending);
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
    core::ServerAdmissionService::RequestInput in;
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
    EXPECT_EQ(a->state, core::ServerAdmissionService::State::Approved);
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
    EXPECT_EQ(a->state, core::ServerAdmissionService::State::Approved);
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
    EXPECT_EQ(a->state, core::ServerAdmissionService::State::Approved);
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
    EXPECT_EQ(a->state, core::ServerAdmissionService::State::Approved);
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
    EXPECT_EQ(a->state, core::ServerAdmissionService::State::Approved);
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
    EXPECT_EQ(a->state, core::ServerAdmissionService::State::Denied);

    // The denied identity cannot immediately re-request: a denial without a
    // cooldown is just a retry prompt for an attacker.
    auto again = admission->create_request(signed_request(cand, "berlin-2"));
    EXPECT_FALSE(again.ok);
    EXPECT_EQ(again.status, 429);
}

TEST_F(AdmissionServiceTest, ApproveRefusesUnverifiedPlatformClaim) {
    // The approve-time evidence gate: a Tier-1-class claim that does not
    // verify must never mint. An unknown platform_class is refused and the
    // record stays pending with no certificate.
    make(/*root_is_local=*/true);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    in.platform_class  = "fake-tee";
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
    EXPECT_EQ(a->state, core::ServerAdmissionService::State::Pending);
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
    EXPECT_EQ(a->state, core::ServerAdmissionService::State::Completed);
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
    EXPECT_EQ(a->state, core::ServerAdmissionService::State::Pending);
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
    EXPECT_EQ(a->state, core::ServerAdmissionService::State::Expired);
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

    nlohmann::json rec_ballot = {
        {"request_id", "legacy-1"}, {"candidate_pubkey", legacy_b64},
        {"server_id", "old-node"}, {"region", "eu-west"},
        {"state", 1 /* Approved */}, {"created_at", 1}, {"expires_at", 2},
        {"issued_cert_json", "{}"}, {"decision_reason", "quorum approved"},
        {"decided_by", "ballot"}, {"decision_mode", "ballot"},
    };
    // Pre-decision_mode record: a stored ballot claim keeps its ballot labeling.
    nlohmann::json rec_pre = {
        {"request_id", "legacy-2"}, {"candidate_pubkey", legacy_b64},
        {"server_id", "old-node-2"}, {"state", 1 /* Approved */},
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

    auto a1 = admission->status("legacy-1", legacy_b64);
    ASSERT_TRUE(a1.has_value());
    EXPECT_EQ(a1->state, core::ServerAdmissionService::State::Approved);
    EXPECT_EQ(a1->decision_mode, "ballot");
    EXPECT_EQ(a1->decided_by, "ballot");

    auto a2 = admission->status("legacy-2", legacy_b64);
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
    gossip.set_root_pubkey(root.public_key);
    gossip.start();  // load_peers() pulls in the seeded certified peer

    core::ServerConfig config;
    config.root_pubkey = crypto::to_hex(
        std::span<const uint8_t>(root.public_key.data(), root.public_key.size()));
    config.onboard_enabled = true;
    core::ServerAdmissionService admission{config, c, kw, s, gossip};
    admission.start();

    auto cand     = c.ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    auto token    = admission.mint_admission_token(cand_b64, std::chrono::seconds{600});
    ASSERT_TRUE(token.has_value());

    auto sign_req = [&](const std::string& server_id) {
        core::ServerAdmissionService::RequestInput in;
        in.candidate_pubkey = cand_b64;
        in.server_id = server_id;
        in.region = "eu-west";
        in.nonce = admission.issue_challenge(in.candidate_pubkey);
        in.timestamp = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        auto msg = core::ServerAdmissionService::canonical_request(in);
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
    EXPECT_EQ(a->state, core::ServerAdmissionService::State::Approved);

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
    cp.server_pubkey_b64 = self_b64;
    cp.server_id         = "rootsrv";
    auto self_cert = gossip::issue_server_certificate(cp, c, root.private_key,
                                                      root.public_key);
    storage::SignedEnvelope cert_env;
    cert_env.type = "server_cert";
    cert_env.data = nlohmann::json(self_cert).dump();
    ASSERT_TRUE(s.write_file("identity", "server_cert.json", cert_env));

    gossip::GossipService gossip{io, 0, s, c};
    gossip.set_root_pubkey(root.public_key);
    gossip.start();
    ASSERT_TRUE(gossip.our_server_id().has_value());

    core::ServerConfig config;
    config.root_pubkey = crypto::to_hex(
        std::span<const uint8_t>(root.public_key.data(), root.public_key.size()));
    config.onboard_enabled = true;
    core::ServerAdmissionService admission{config, c, kw, s, gossip};
    admission.start();

    auto cand     = c.ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    auto sign_req = [&](const std::string& server_id) {
        core::ServerAdmissionService::RequestInput in;
        in.candidate_pubkey = cand_b64;
        in.server_id = server_id;
        in.region = "eu-west";
        in.nonce = admission.issue_challenge(in.candidate_pubkey);
        in.timestamp = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        auto msg = core::ServerAdmissionService::canonical_request(in);
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
    gossip.set_root_pubkey(root.public_key);
    gossip.start();

    core::ServerConfig config;
    config.root_pubkey = crypto::to_hex(
        std::span<const uint8_t>(root.public_key.data(), root.public_key.size()));
    config.onboard_enabled = true;
    core::ServerAdmissionService admission{config, c, kw, s, gossip};
    admission.start();

    auto cand     = c.ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    core::ServerAdmissionService::RequestInput in;
    in.candidate_pubkey = cand_b64;
    in.server_id = "berlin-2";
    in.region = "eu-west";
    in.nonce = admission.issue_challenge(in.candidate_pubkey);
    in.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    {
        auto msg = core::ServerAdmissionService::canonical_request(in);
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
    EXPECT_EQ(a->state, core::ServerAdmissionService::State::Approved);
    ASSERT_FALSE(a->issued_cert_json.empty());
    EXPECT_TRUE(cert_verifies_against(a->issued_cert_json, root.public_key, c));

    admission.stop();
    gossip.stop();
    kw.stop();
    s.stop();
    c.stop();
    fs::remove_all(tmp);
}
