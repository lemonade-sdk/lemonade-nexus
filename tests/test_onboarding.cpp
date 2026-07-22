#include <LemonadeNexus/Core/AdmissionTokenStore.hpp>
#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/OnboardingClient.hpp>
#include <LemonadeNexus/Core/ServerAdmissionService.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Core/TeeAttestation.hpp>
#include <LemonadeNexus/Core/TrustPolicy.hpp>
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
// Live ServerAdmissionService — root-holder issuance gate and the
// enrollment-token admission flow. Stands up the full dependency set so
// on_start() computes is_root_key_holder_ against a real loaded identity.
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

    core::ServerConfig       config;
    crypto::Ed25519Keypair   local_identity;  // this server's own gossip/root identity

    /// Build the stack. `root_is_local` points the trust anchor at this server's
    /// own identity (it IS the root holder) or an unrelated key (a non-root
    /// enrolled server). `min_tier1 = 0` puts a peerless service into the vote
    /// regime (eligible_voter_count() >= 0) without needing live gossip peers.
    void make(bool root_is_local, uint32_t min_tier1 = 6) {
        temp_dir = fs::temp_directory_path() /
                   ("nexus_test_admission_" + std::to_string(getpid()));
        fs::create_directories(temp_dir);

        crypto_svc = std::make_unique<crypto::SodiumCryptoService>();
        crypto_svc->start();
        storage_svc = std::make_unique<storage::FileStorageService>(temp_dir);
        storage_svc->start();
        kw = std::make_unique<crypto::KeyWrappingService>(*crypto_svc, *storage_svc);
        kw->start();

        // Persist this server's local identity (empty passphrase, as the daemon does).
        local_identity = kw->generate_and_store_identity({});

        // Value (not reference): the non-root branch's keypair is a temporary,
        // and a ternary binding would not extend its lifetime.
        crypto::Ed25519PublicKey anchor = root_is_local
            ? local_identity.public_key
            : crypto_svc->ed25519_keygen().public_key;
        config.root_pubkey = crypto::to_hex(
            std::span<const uint8_t>(anchor.data(), anchor.size()));
        config.onboard_enabled            = true;
        config.onboard_min_tier1_for_vote = min_tier1;

        gossip_svc = std::make_unique<gossip::GossipService>(io, 0, *storage_svc, *crypto_svc);
        admission  = std::make_unique<core::ServerAdmissionService>(
            config, *crypto_svc, *kw, *storage_svc, *gossip_svc, nullptr);
        admission->start();  // on_start() computes is_root_key_holder_
    }

    void TearDown() override {
        if (admission)   admission->stop();
        if (gossip_svc)  gossip_svc->stop();
        if (kw)          kw->stop();
        if (storage_svc) storage_svc->stop();
        if (crypto_svc)  crypto_svc->stop();
        if (!temp_dir.empty()) fs::remove_all(temp_dir);
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
        auto msg = core::ServerAdmissionService::canonical_request(in);
        auto sig = crypto_svc->ed25519_sign(cand.private_key, std::span<const uint8_t>(msg));
        in.signature = crypto::to_base64(std::span<const uint8_t>(sig.data(), sig.size()));
        return in;
    }
};

// --- Only the root-key holder may accept/issue ---

TEST_F(AdmissionServiceTest, NonRootServerCannotIssue) {
    make(/*root_is_local=*/false);
    // Merely having root_pubkey configured (every enrolled server does) must not
    // let a non-root server advertise onboarding or issue a certificate.
    EXPECT_FALSE(admission->accepts_onboarding());

    auto cand = crypto_svc->ed25519_keygen();
    auto r = admission->create_request(signed_request(cand, "berlin-2"));
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.status, 403);
}

TEST_F(AdmissionServiceTest, RootHolderCanIssue) {
    make(/*root_is_local=*/true);
    EXPECT_TRUE(admission->accepts_onboarding());

    auto cand = crypto_svc->ed25519_keygen();
    auto r = admission->create_request(signed_request(cand, "berlin-2"));
    EXPECT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.status, 200);
}

// --- No unattended admission; the enrollment token is the only bypass ---

TEST_F(AdmissionServiceTest, FirstRequestParksInPending) {
    // Default state is closed: the first request on a fresh genesis must wait
    // for an admin (or carry a token), never self-admit.
    make(/*root_is_local=*/true);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    auto r    = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;

    auto a = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->state, core::ServerAdmissionService::State::Pending);
    EXPECT_TRUE(a->decided_by.empty());
    EXPECT_TRUE(a->issued_cert_json.empty());
}

TEST_F(AdmissionServiceTest, RequestWithValidTokenApproved) {
    // A candidate-bound token admits immediately, is single-use, and the issued
    // cert is signed by the root anchor (proves the issuance path uses it).
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
    EXPECT_EQ(cert.value("issuer_pubkey", ""),
              crypto::to_base64(std::span<const uint8_t>(
                  local_identity.public_key.data(), local_identity.public_key.size())));

    // Spent: the same token cannot be redeemed again (single-use).
    auto in2 = signed_request(cand, "berlin-3");
    in2.enrollment_token = minted->first;
    auto r2 = admission->create_request(in2);
    EXPECT_FALSE(r2.ok);
    EXPECT_EQ(r2.status, 403);
}

TEST_F(AdmissionServiceTest, RequestWithInvalidTokenRejected) {
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

TEST_F(AdmissionServiceTest, VoteRegimeBallotGoverns) {
    // At/above the vote threshold the quorum ballot decides. A presented token
    // cannot admit — and it IS consumed (burned) at first submission so it can
    // never be re-spent to bypass the ballot if churn later drops the mesh below
    // the vote threshold (the H1 restart/regime bypass).
    make(/*root_is_local=*/true, /*min_tier1=*/0);

    auto minted = admission->mint_admission_token("", std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    in.enrollment_token = minted->first;
    auto r = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_TRUE(r.needs_ballot);

    auto a = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(a.has_value());
    EXPECT_EQ(a->state, core::ServerAdmissionService::State::Pending);

    // The gossip-replicated ballot claim must never carry token material.
    EXPECT_EQ(a->ballot_claim_json.find(minted->first), std::string::npos);

    // Consumed: the token is burned at first submission and cannot be re-spent
    // after a later regime drop below the vote threshold (H1).
    core::AdmissionTokenStore store{*storage_svc, *crypto_svc};
    EXPECT_FALSE(store.verify(minted->first, in.candidate_pubkey).has_value());
}

TEST_F(AdmissionServiceTest, VoteRegimeAdminCannotBypassBallot) {
    // In the vote regime neither approve() nor deny() may resolve a
    // ballot-governed admission — only the Tier-1 quorum callback can. Otherwise
    // a root admin could admit (or reject) ahead of the vote and the quorum
    // would be advisory.
    make(/*root_is_local=*/true, /*min_tier1=*/0);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    auto r    = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;
    ASSERT_TRUE(r.needs_ballot);

    // Direct admin approve/deny are both rejected with 409 while the ballot governs.
    auto ap = admission->approve(r.request_id, in.candidate_pubkey, /*supersede=*/false);
    EXPECT_FALSE(ap.ok);
    EXPECT_EQ(ap.status, 409);
    auto dn = admission->deny(r.request_id, "nope");
    EXPECT_FALSE(dn.ok);
    EXPECT_EQ(dn.status, 409);

    // Still pending and unissued after both attempts.
    auto mid = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(mid.has_value());
    EXPECT_EQ(mid->state, core::ServerAdmissionService::State::Pending);
    EXPECT_TRUE(mid->issued_cert_json.empty());

    // Only the quorum callback resolves it.
    admission->on_ballot_decision(r.request_id, /*approved=*/true, in.candidate_pubkey, "", "");
    auto after = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(after->state, core::ServerAdmissionService::State::Approved);
    EXPECT_EQ(after->decided_by, "ballot");
}

TEST_F(AdmissionServiceTest, BallotDecisionModeSurvivesRestart) {
    // The ballot gate must be persisted: after a restart, a ballot-governed
    // admission must still reject direct approve()/deny(), or the quorum bypass
    // reopens.
    make(/*root_is_local=*/true, /*min_tier1=*/0);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-2");
    auto r    = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;
    ASSERT_TRUE(r.needs_ballot);

    // Simulate a restart: tear down the service and rebuild it from the SAME
    // data root, so on_start()->load() restores the persisted admission.
    admission->stop();
    admission = std::make_unique<core::ServerAdmissionService>(
        config, *crypto_svc, *kw, *storage_svc, *gossip_svc, nullptr);
    admission->start();

    // Reloaded as ballot-governed: direct approve/deny still 409.
    auto ap = admission->approve(r.request_id, in.candidate_pubkey, /*supersede=*/false);
    EXPECT_FALSE(ap.ok);
    EXPECT_EQ(ap.status, 409);
    auto dn = admission->deny(r.request_id, "nope");
    EXPECT_FALSE(dn.ok);
    EXPECT_EQ(dn.status, 409);

    auto mid = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(mid.has_value());
    EXPECT_EQ(mid->state, core::ServerAdmissionService::State::Pending);
    EXPECT_TRUE(mid->issued_cert_json.empty());

    // Only the quorum callback resolves it, even after the restart.
    admission->on_ballot_decision(r.request_id, /*approved=*/true, in.candidate_pubkey, "", "");
    auto after = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(after->state, core::ServerAdmissionService::State::Approved);
    EXPECT_EQ(after->decided_by, "ballot");
}

// A record awaiting admin discretion must not be resolvable by a ballot: the
// request_id is public, so a candidate could otherwise open its own ballot and
// have honest voters approve away the admin gate.
TEST_F(AdmissionServiceTest, SoleDiscretionRecordIgnoresBallotDecision) {
    make(/*root_is_local=*/true, /*min_tier1=*/6);   // above the mesh size -> "sole"

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-3");
    auto r    = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;
    ASSERT_FALSE(r.needs_ballot);   // admin must decide this one

    admission->on_ballot_decision(r.request_id, /*approved=*/true, in.candidate_pubkey, "", "");

    auto after = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(after->state, core::ServerAdmissionService::State::Pending);
    EXPECT_TRUE(after->issued_cert_json.empty());
}

// A ballot may only resolve the record it is actually about.
TEST_F(AdmissionServiceTest, BallotForOtherCandidateIgnored) {
    make(/*root_is_local=*/true, /*min_tier1=*/0);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-4");
    auto r    = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;
    ASSERT_TRUE(r.needs_ballot);

    auto other = crypto_svc->ed25519_keygen();
    auto other_b64 = b64({other.public_key.begin(), other.public_key.end()});
    admission->on_ballot_decision(r.request_id, /*approved=*/true, other_b64, "", "");

    auto after = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(after->state, core::ServerAdmissionService::State::Pending);
}

// The pending record is what gets minted: peers vote on claim A, the candidate
// re-submits claim B on the same key, and the old votes would issue B.
TEST_F(AdmissionServiceTest, PendingAdmissionCannotBeMutated) {
    make(/*root_is_local=*/true, /*min_tier1=*/0);

    auto cand = crypto_svc->ed25519_keygen();
    auto in   = signed_request(cand, "berlin-5");
    auto r    = admission->create_request(in);
    ASSERT_TRUE(r.ok) << r.error;
    const auto first_hash = admission->status(r.request_id, in.candidate_pubkey)->claim_hash;
    ASSERT_FALSE(first_hash.empty());

    // Same key, same pending request, different server_id -> 409, record intact.
    auto swap = signed_request(cand, "berlin-6");
    auto r2   = admission->create_request(swap);
    EXPECT_FALSE(r2.ok);
    EXPECT_EQ(r2.status, 409);

    auto mid = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(mid.has_value());
    EXPECT_EQ(mid->server_id, "berlin-5");
    EXPECT_EQ(mid->claim_hash, first_hash);

    // Region is material too.
    auto region_swap   = signed_request(cand, "berlin-5");
    region_swap.region = "ap-south";
    {
        auto msg = core::ServerAdmissionService::canonical_request(region_swap);
        auto sig = crypto_svc->ed25519_sign(cand.private_key, std::span<const uint8_t>(msg));
        region_swap.signature = crypto::to_base64(
            std::span<const uint8_t>(sig.data(), sig.size()));
    }
    EXPECT_EQ(admission->create_request(region_swap).status, 409);

    // An identical re-submission stays an idempotent retry and keeps the hash
    // voters signed rather than rebinding to the new nonce.
    auto same = signed_request(cand, "berlin-5");
    auto r3   = admission->create_request(same);
    EXPECT_TRUE(r3.ok) << r3.error;
    EXPECT_EQ(r3.request_id, r.request_id);
    EXPECT_TRUE(r3.needs_ballot);   // re-arms the ballot
    EXPECT_EQ(admission->status(r.request_id, in.candidate_pubkey)->claim_hash, first_hash);

    // And a ballot that approves some other claim cannot mint this record.
    admission->on_ballot_decision(r.request_id, /*approved=*/true, in.candidate_pubkey,
                                  "0000000000000000000000000000000000000000000000000000000000000000",
                                  "");
    EXPECT_EQ(admission->status(r.request_id, in.candidate_pubkey)->state,
              core::ServerAdmissionService::State::Pending);

    // The claim the quorum actually voted on issues normally.
    admission->on_ballot_decision(r.request_id, /*approved=*/true, in.candidate_pubkey,
                                  first_hash, "");
    EXPECT_EQ(admission->status(r.request_id, in.candidate_pubkey)->state,
              core::ServerAdmissionService::State::Approved);
}

TEST_F(AdmissionServiceTest, MintRefusedOnNonRootHolder) {
    make(/*root_is_local=*/false);
    EXPECT_FALSE(admission->mint_admission_token("", std::chrono::seconds{600}).has_value());
}

// A server_id already claimed by an enrolled peer must 409 the request, and a
// token presented alongside it must NOT be burned — the operator can retry
// under a free name with the same token. Needs a live gossip peer, so this
// stands its own stack up rather than reusing the fixture.
TEST(OnboardingAdmission, ServerIdConflictDoesNotBurnToken) {
    auto tmp = fs::temp_directory_path() /
               ("nexus_test_conflict_" + std::to_string(getpid()));
    fs::create_directories(tmp);

    asio::io_context io;
    crypto::SodiumCryptoService c;  c.start();
    storage::FileStorageService s{tmp};  s.start();
    crypto::KeyWrappingService  kw{c, s};  kw.start();
    auto root = kw.generate_and_store_identity({});

    // Seed a certified peer holding server_id "berlin-2" under a different key.
    auto other = c.ed25519_keygen();
    auto other_b64 = b64({other.public_key.begin(), other.public_key.end()});
    nlohmann::json cert{{"server_id", "berlin-2"}, {"server_pubkey", other_b64}};
    nlohmann::json peers{{"peers", nlohmann::json::array({
        {{"pubkey", other_b64}, {"endpoint", "10.9.9.9:9102"},
         {"certificate_json", cert.dump()}}})}};
    storage::SignedEnvelope env;
    env.type = "peer_list";
    env.data = peers.dump();
    ASSERT_TRUE(s.write_file("identity", "peers.json", env));

    gossip::GossipService gossip{io, 0, s, c};
    gossip.start();  // load_peers() pulls in the seeded certified peer

    core::ServerConfig config;
    config.root_pubkey = crypto::to_hex(
        std::span<const uint8_t>(root.public_key.data(), root.public_key.size()));
    config.onboard_enabled = true;
    core::ServerAdmissionService admission{config, c, kw, s, gossip, nullptr};
    admission.start();

    auto cand     = c.ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    auto token    = admission.mint_admission_token(cand_b64, std::chrono::seconds{600});
    ASSERT_TRUE(token.has_value());

    auto sign_req = [&](const std::string& server_id) {
        core::ServerAdmissionService::RequestInput in;
        in.candidate_pubkey = b64({cand.public_key.begin(), cand.public_key.end()});
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

// ---------------------------------------------------------------------------
// Real admission-quorum electorate — regression tests for the forgeable-quorum
// CRITICAL. The quorum electorate is the ROOT-SIGNED peer set
// (peer_certificate_is_root_signed), NEVER peers_.size(), and it fails closed
// when no root anchor is configured. start_admission_ballot() casts the
// sponsor's self-vote and tallies synchronously, so these need no live UDP.
// ---------------------------------------------------------------------------

TEST(AdmissionQuorum, NoRootAnchorAdmissionFailsClosed) {
    auto tmp = fs::temp_directory_path() /
               ("nexus_quorum_noroot_" + std::to_string(getpid()));
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    asio::io_context io;
    crypto::SodiumCryptoService c;  c.start();
    storage::FileStorageService s{tmp};  s.start();
    crypto::KeyWrappingService kw{c, s};  kw.start();
    kw.generate_and_store_identity({});   // the gossip node's own keypair

    // Seed a peer that carries a (self-consistent) certificate. Pre-fix, a null
    // trust policy made the quorum denominator peers_.size(), so this single
    // seeded peer plus the sponsor's self-vote could resolve a 75% ballot.
    // Post-fix, with NO root anchor the attested electorate is empty and
    // admission MUST fail closed.
    auto fake = c.ed25519_keygen();
    auto fake_b64 = b64({fake.public_key.begin(), fake.public_key.end()});
    nlohmann::json fake_cert{{"server_id", "fake-1"}, {"server_pubkey", fake_b64}};
    nlohmann::json peers{{"peers", nlohmann::json::array({
        {{"pubkey", fake_b64}, {"endpoint", "10.0.0.9:9102"},
         {"certificate_json", fake_cert.dump()}}})}};
    storage::SignedEnvelope env;
    env.type = "peer_list";
    env.data = peers.dump();
    ASSERT_TRUE(s.write_file("identity", "peers.json", env));

    gossip::GossipService gossip{io, 0, s, c};
    // Deliberately NO set_root_pubkey() — the genuine shipped default.
    gossip.set_enrollment_config(true, 0.75f, 60, 3);
    gossip.start();

    bool approved = false;
    gossip.set_enrollment_decision_callback([&](const gossip::EnrollmentBallot& bal) {
        if (bal.state == gossip::EnrollmentBallot::State::Approved) approved = true;
    });

    auto cand = c.ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    gossip.start_admission_ballot("req-noroot", cand_b64, "worker-1", "", "", 0.75f);

    // Empty attested electorate (tier1_count == 0) -> Admission fails closed.
    EXPECT_FALSE(approved);

    gossip.stop();
    kw.stop();
    s.stop();
    c.stop();
    fs::remove_all(tmp);
}

namespace {

void seed_peers(storage::FileStorageService& s, const nlohmann::json& arr) {
    storage::SignedEnvelope env;
    env.type = "peer_list";
    env.data = nlohmann::json{{"peers", arr}}.dump();
    (void)s.write_file("identity", "peers.json", env);
}

// Install a certificate as THIS server's own identity cert.
void seed_own_cert(storage::FileStorageService& s, const gossip::ServerCertificate& cert) {
    storage::SignedEnvelope env;
    env.type = "server_cert";
    env.data = nlohmann::json(cert).dump();
    (void)s.write_file("identity", "server_cert.json", env);
}

nlohmann::json peer_entry(const std::string& pk, const std::string& ep,
                          const nlohmann::json& cert) {
    return {{"pubkey", pk}, {"endpoint", ep}, {"certificate_json", cert.dump()}};
}

gossip::ServerCertificate sign_cert(crypto::SodiumCryptoService& c,
                                    const crypto::Ed25519Keypair& root,
                                    const std::string& pk_b64,
                                    const std::string& server_id) {
    gossip::CertIssueParams p;
    p.server_pubkey_b64 = pk_b64;
    p.server_id         = server_id;
    return gossip::issue_server_certificate(p, c, root.private_key, root.public_key);
}

}  // namespace

// An eligible sponsor also occupies a denominator slot, so its own vote can
// never clear the threshold alone.
TEST(AdmissionQuorum, SponsorAloneCannotSatisfyQuorum) {
    auto tmp = fs::temp_directory_path() /
               ("nexus_quorum_sponsor_" + std::to_string(getpid()));
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    asio::io_context io;
    crypto::SodiumCryptoService c;  c.start();
    storage::FileStorageService s{tmp};  s.start();
    crypto::KeyWrappingService kw{c, s};  kw.start();
    auto self = kw.generate_and_store_identity({});
    auto root = c.ed25519_keygen();

    // This server is itself a fully eligible voter.
    auto self_b64 = b64({self.public_key.begin(), self.public_key.end()});
    seed_own_cert(s, sign_cert(c, root, self_b64, "sponsor-1"));

    // ...and exactly one other eligible peer exists.
    auto p1 = c.ed25519_keygen();
    auto p1_b64 = b64({p1.public_key.begin(), p1.public_key.end()});
    nlohmann::json p1_cj = sign_cert(c, root, p1_b64, "voter-1");
    seed_peers(s, nlohmann::json::array({peer_entry(p1_b64, "10.0.0.1:9102", p1_cj)}));

    gossip::GossipService gossip{io, 0, s, c};
    gossip.set_root_pubkey(root.public_key);
    gossip.set_enrollment_config(true, 0.75f, 60, 3);
    gossip.start();

    bool approved = false;
    gossip.set_enrollment_decision_callback([&](const gossip::EnrollmentBallot& bal) {
        if (bal.state == gossip::EnrollmentBallot::State::Approved) approved = true;
    });

    auto cand = c.ed25519_keygen();
    gossip.start_admission_ballot(
        "req-sponsor", b64({cand.public_key.begin(), cand.public_key.end()}),
        "worker-1", "", "", 0.75f);

    // Electorate = {peer, sponsor} -> needed 2, sponsor supplies only 1.
    EXPECT_FALSE(approved);

    gossip.stop(); kw.stop(); s.stop(); c.stop();
    fs::remove_all(tmp);
}

// A sponsor that does not satisfy the voter predicate casts no vote at all.
TEST(AdmissionQuorum, IneligibleSponsorCastsNoVote) {
    auto tmp = fs::temp_directory_path() /
               ("nexus_quorum_inelig_" + std::to_string(getpid()));
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    asio::io_context io;
    crypto::SodiumCryptoService c;  c.start();
    storage::FileStorageService s{tmp};  s.start();
    crypto::KeyWrappingService kw{c, s};  kw.start();
    kw.generate_and_store_identity({});
    auto root = c.ed25519_keygen();
    // NOTE: no seed_own_cert() -> this server holds no root-signed certificate.

    auto p1 = c.ed25519_keygen();
    auto p1_b64 = b64({p1.public_key.begin(), p1.public_key.end()});
    nlohmann::json p1_cj = sign_cert(c, root, p1_b64, "voter-1");
    seed_peers(s, nlohmann::json::array({peer_entry(p1_b64, "10.0.0.1:9102", p1_cj)}));

    gossip::GossipService gossip{io, 0, s, c};
    gossip.set_root_pubkey(root.public_key);
    gossip.set_enrollment_config(true, 0.75f, 60, 3);
    gossip.start();

    bool approved = false;
    gossip.set_enrollment_decision_callback([&](const gossip::EnrollmentBallot& bal) {
        if (bal.state == gossip::EnrollmentBallot::State::Approved) approved = true;
    });

    auto cand = c.ed25519_keygen();
    gossip.start_admission_ballot(
        "req-inelig", b64({cand.public_key.begin(), cand.public_key.end()}),
        "worker-2", "", "", 0.75f);

    bool found = false;
    for (const auto& bal : gossip.pending_enrollments()) {
        if (bal.request_id == "req-inelig") { found = true; EXPECT_TRUE(bal.votes.empty()); }
    }
    EXPECT_TRUE(found);
    EXPECT_FALSE(approved);

    gossip.stop(); kw.stop(); s.stop(); c.stop();
    fs::remove_all(tmp);
}

// A peer whose cert is not root-signed forms no electorate: at a 10% ratio the
// sponsor's vote would clear the bar if that peer were counted.
TEST(AdmissionQuorum, FabricatedPeerCannotFormElectorate) {
    auto tmp = fs::temp_directory_path() /
               ("nexus_quorum_fab_" + std::to_string(getpid()));
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    asio::io_context io;
    crypto::SodiumCryptoService c;  c.start();
    storage::FileStorageService s{tmp};  s.start();
    crypto::KeyWrappingService kw{c, s};  kw.start();
    auto self = kw.generate_and_store_identity({});
    auto root = c.ed25519_keygen();

    auto self_b64 = b64({self.public_key.begin(), self.public_key.end()});
    seed_own_cert(s, sign_cert(c, root, self_b64, "sponsor-3"));

    auto p2 = c.ed25519_keygen();
    auto p2_b64 = b64({p2.public_key.begin(), p2.public_key.end()});
    nlohmann::json fake{{"server_id", "voter-x"}, {"server_pubkey", p2_b64},
                        {"issuer_pubkey", p2_b64}, {"signature", "AAAA"}};
    seed_peers(s, nlohmann::json::array({peer_entry(p2_b64, "10.0.0.2:9102", fake)}));

    gossip::GossipService gossip{io, 0, s, c};
    gossip.set_root_pubkey(root.public_key);
    gossip.set_enrollment_config(true, 0.10f, 60, 3);
    gossip.start();

    bool approved = false;
    gossip.set_enrollment_decision_callback([&](const gossip::EnrollmentBallot& bal) {
        if (bal.state == gossip::EnrollmentBallot::State::Approved) approved = true;
    });

    auto cand = c.ed25519_keygen();
    gossip.start_admission_ballot(
        "req-fab", b64({cand.public_key.begin(), cand.public_key.end()}),
        "worker-3", "", "", 0.10f);

    EXPECT_FALSE(approved);

    gossip.stop(); kw.stop(); s.stop(); c.stop();
    fs::remove_all(tmp);
}

// ---------------------------------------------------------------------------
// Ballot trust-boundary regressions.
//
// The vote handlers sit behind packet-signature verification on a bound socket,
// which a unit test cannot drive, so reach them through the friend seam. The
// dispatcher only ever hands these a signature-verified sender key, so supplying
// `signer` directly provides the same guarantee the wire path does.
// ---------------------------------------------------------------------------

// Defined inside its namespace: a qualified-name definition at global scope
// (`struct nexus::gossip::GossipBallotTestAccess {...}`) is an MSVC extension
// that GCC rejects — the friend declaration is not a prior declaration.
namespace nexus::gossip {
struct GossipBallotTestAccess {
    static void vote_request(gossip::GossipService& g, const std::string& signer,
                             const nlohmann::json& body) {
        auto s = body.dump();
        g.handle_enrollment_vote_request(asio::ip::udp::endpoint{}, signer,
            reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }
    static void vote(gossip::GossipService& g, const std::string& signer,
                     const nlohmann::json& body) {
        auto s = body.dump();
        g.handle_enrollment_vote(asio::ip::udp::endpoint{}, signer,
            reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }
    static void retally(gossip::GossipService& g, const std::string& rid) {
        g.check_enrollment_quorum(rid);
    }
    static bool has_ballot(gossip::GossipService& g, const std::string& rid) {
        std::lock_guard lock(g.peers_mutex_);
        return g.pending_enrollments_.contains(rid);
    }
    static std::size_t vote_count(gossip::GossipService& g, const std::string& rid) {
        std::lock_guard lock(g.peers_mutex_);
        auto it = g.pending_enrollments_.find(rid);
        return it == g.pending_enrollments_.end() ? 0 : it->second.votes.size();
    }
    static float ratio(gossip::GossipService& g, const std::string& rid) {
        std::lock_guard lock(g.peers_mutex_);
        auto it = g.pending_enrollments_.find(rid);
        return it == g.pending_enrollments_.end() ? -1.0f : it->second.required_ratio;
    }
    static void occupy_ns_slot(gossip::GossipService& g, uint8_t slot,
                               const std::string& holder_pubkey) {
        std::lock_guard lock(g.peers_mutex_);
        g.ns_slots_[slot - 1].slot          = slot;
        g.ns_slots_[slot - 1].server_pubkey = holder_pubkey;
    }
};
}  // namespace nexus::gossip

namespace {

using Access = nexus::gossip::GossipBallotTestAccess;

// A vote signed exactly the way cast_enrollment_vote signs one.
nlohmann::json signed_vote(crypto::SodiumCryptoService& c,
                           const crypto::Ed25519Keypair& voter,
                           const std::string& rid, const std::string& cand,
                           bool approve, const std::string& claim_hash = "") {
    auto voter_b64 = b64({voter.public_key.begin(), voter.public_key.end()});
    const uint64_t ts = 1;
    const std::string reason = "test";
    nlohmann::json canonical = {
        {"approve",          approve},
        {"candidate_pubkey", cand},
        {"claim_hash",       claim_hash},
        {"reason",           reason},
        {"request_id",       rid},
        {"timestamp",        ts},
        {"voter_pubkey",     voter_b64},
    };
    auto str = canonical.dump();
    auto sig = c.ed25519_sign(voter.private_key,
                              std::vector<uint8_t>(str.begin(), str.end()));
    return {
        {"request_id",       rid},
        {"candidate_pubkey", cand},
        {"voter_pubkey",     voter_b64},
        {"approve",          approve},
        {"reason",           reason},
        {"timestamp",        ts},
        {"claim_hash",       claim_hash},
        {"signature",        crypto::to_base64(sig)},
    };
}

// A well-formed admission vote-request body. The claim signature is deliberately
// junk: these tests assert on ballot ADMISSION, not on candidate verification.
nlohmann::json vote_request_body(const std::string& rid, const std::string& cand,
                                 const std::string& sponsor, float ratio) {
    std::vector<uint8_t> zeros(crypto::kEd25519SignatureSize, 0);
    return {
        {"request_id",       rid},
        {"candidate_pubkey", cand},
        {"sponsor_pubkey",   sponsor},
        {"required_ratio",   ratio},
        {"admission_claim", {
            {"candidate_pubkey", cand},
            {"nonce",            "n"},
            {"region",           "eu-west"},
            {"tpm_ak_pubkey",    ""},
            {"server_id",        "worker-x"},
            {"timestamp",        uint64_t{1}},
            {"signature",        crypto::to_base64(zeros)},
        }},
    };
}

}  // namespace

// A vote request only ever travels sponsor->voter, so a signer that is not the
// claimed sponsor must not be able to open a ballot in the sponsor's name.
TEST(BallotBinding, VoteRequestFromNonSponsorRejected) {
    auto tmp = fs::temp_directory_path() /
               ("nexus_ballot_sponsor_" + std::to_string(getpid()));
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    asio::io_context io;
    crypto::SodiumCryptoService c;  c.start();
    storage::FileStorageService s{tmp};  s.start();
    crypto::KeyWrappingService kw{c, s};  kw.start();
    (void)kw.generate_and_store_identity({});
    auto root = c.ed25519_keygen();

    // A genuine enrolled sponsor, and an attacker that is also enrolled.
    auto sponsor = c.ed25519_keygen();
    auto sponsor_b64 = b64({sponsor.public_key.begin(), sponsor.public_key.end()});
    auto attacker = c.ed25519_keygen();
    auto attacker_b64 = b64({attacker.public_key.begin(), attacker.public_key.end()});
    seed_peers(s, nlohmann::json::array({
        peer_entry(sponsor_b64, "10.0.0.1:9102", sign_cert(c, root, sponsor_b64, "sponsor")),
        peer_entry(attacker_b64, "10.0.0.2:9102", sign_cert(c, root, attacker_b64, "attacker")),
    }));

    gossip::GossipService gossip{io, 0, s, c};
    gossip.set_root_pubkey(root.public_key);
    gossip.set_enrollment_config(true, 0.75f, 60, 3);
    gossip.start();

    auto cand = c.ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});

    // Signed by the attacker but claiming the sponsor -> dropped.
    Access::vote_request(gossip, attacker_b64,
                         vote_request_body("req-spoof", cand_b64, sponsor_b64, 0.75f));
    EXPECT_FALSE(Access::has_ballot(gossip, "req-spoof"));

    // Positive control: the real sponsor opens the same ballot.
    Access::vote_request(gossip, sponsor_b64,
                         vote_request_body("req-real", cand_b64, sponsor_b64, 0.75f));
    EXPECT_TRUE(Access::has_ballot(gossip, "req-real"));

    gossip.stop(); kw.stop(); s.stop(); c.stop();
    fs::remove_all(tmp);
}

// Under a trust policy the sponsor attestation is REQUIRED: omitting the field
// used to skip the check entirely, and a token owned by another key must not
// vouch for the claimed sponsor.
TEST(BallotBinding, MissingSponsorAttestationRejectedUnderTrustPolicy) {
    auto tmp = fs::temp_directory_path() /
               ("nexus_ballot_attest_" + std::to_string(getpid()));
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    asio::io_context io;
    crypto::SodiumCryptoService c;  c.start();
    storage::FileStorageService s{tmp};  s.start();
    crypto::KeyWrappingService kw{c, s};  kw.start();
    (void)kw.generate_and_store_identity({});
    auto root = c.ed25519_keygen();

    auto sponsor = c.ed25519_keygen();
    auto sponsor_b64 = b64({sponsor.public_key.begin(), sponsor.public_key.end()});
    seed_peers(s, nlohmann::json::array({
        peer_entry(sponsor_b64, "10.0.0.1:9102", sign_cert(c, root, sponsor_b64, "sponsor")),
    }));

    core::BinaryAttestationService att{c, s};  att.start();
    core::TeeAttestationService tee{c, s, att};  tee.start();
    core::TrustPolicyService policy{tee, att, c};  policy.start();
    // Pre-promote the sponsor: on a machine with no TEE a generated token fails
    // verification, and verify_and_update then falls back to the peer's standing
    // tier — which must be above Untrusted for the positive control to pass.
    policy.set_peer_tier2(sponsor_b64);

    gossip::GossipService gossip{io, 0, s, c};
    gossip.set_root_pubkey(root.public_key);
    gossip.set_enrollment_config(true, 0.75f, 60, 3);
    gossip.set_trust_policy(&policy);
    gossip.start();

    auto cand = c.ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});

    // No attestation_token at all -> dropped.
    Access::vote_request(gossip, sponsor_b64,
                         vote_request_body("req-noattest", cand_b64, sponsor_b64, 0.75f));
    EXPECT_FALSE(Access::has_ballot(gossip, "req-noattest"));

    // Token owned by a DIFFERENT key, claiming the sponsor -> dropped.
    auto attacker = c.ed25519_keygen();
    auto body = vote_request_body("req-wrongtok", cand_b64, sponsor_b64, 0.75f);
    body["attestation_token"] = policy.generate_attestation_token(attacker);
    Access::vote_request(gossip, sponsor_b64, body);
    EXPECT_FALSE(Access::has_ballot(gossip, "req-wrongtok"));

    // Positive control: the sponsor's own token is accepted.
    auto good = vote_request_body("req-attest", cand_b64, sponsor_b64, 0.75f);
    good["attestation_token"] = policy.generate_attestation_token(sponsor);
    Access::vote_request(gossip, sponsor_b64, good);
    EXPECT_TRUE(Access::has_ballot(gossip, "req-attest"));

    gossip.stop(); policy.stop(); tee.stop(); att.stop();
    kw.stop(); s.stop(); c.stop();
    fs::remove_all(tmp);
}

// required_ratio arrives from the wire: it may raise our bar, never lower it.
TEST(BallotBinding, RemoteRequestCannotLowerQuorumRatio) {
    auto tmp = fs::temp_directory_path() /
               ("nexus_ballot_ratio_" + std::to_string(getpid()));
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    asio::io_context io;
    crypto::SodiumCryptoService c;  c.start();
    storage::FileStorageService s{tmp};  s.start();
    crypto::KeyWrappingService kw{c, s};  kw.start();
    (void)kw.generate_and_store_identity({});
    auto root = c.ed25519_keygen();

    auto sponsor = c.ed25519_keygen();
    auto sponsor_b64 = b64({sponsor.public_key.begin(), sponsor.public_key.end()});
    seed_peers(s, nlohmann::json::array({
        peer_entry(sponsor_b64, "10.0.0.1:9102", sign_cert(c, root, sponsor_b64, "sponsor")),
    }));

    gossip::GossipService gossip{io, 0, s, c};
    gossip.set_root_pubkey(root.public_key);
    // Deliberately DIFFERENT ratios: an admission ballot must floor against the
    // admission bar, not the lower enrollment one.
    gossip.set_enrollment_config(true, 0.5f, 60, 3);
    gossip.set_admission_quorum_ratio(0.75f);
    gossip.start();

    auto cand = c.ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});

    // A 1% bar would let a single vote decide; it must clamp up to the admission 75%.
    Access::vote_request(gossip, sponsor_b64,
                         vote_request_body("req-low", cand_b64, sponsor_b64, 0.01f));
    ASSERT_TRUE(Access::has_ballot(gossip, "req-low"));
    EXPECT_FLOAT_EQ(Access::ratio(gossip, "req-low"), 0.75f);

    // Omitting the field entirely must not downgrade to the enrollment ratio either.
    auto no_ratio = vote_request_body("req-none", cand_b64, sponsor_b64, 0.0f);
    no_ratio.erase("required_ratio");
    Access::vote_request(gossip, sponsor_b64, no_ratio);
    ASSERT_TRUE(Access::has_ballot(gossip, "req-none"));
    EXPECT_FLOAT_EQ(Access::ratio(gossip, "req-none"), 0.75f);

    // A stricter remote bar is honoured as-is.
    Access::vote_request(gossip, sponsor_b64,
                         vote_request_body("req-high", cand_b64, sponsor_b64, 0.9f));
    ASSERT_TRUE(Access::has_ballot(gossip, "req-high"));
    EXPECT_FLOAT_EQ(Access::ratio(gossip, "req-high"), 0.9f);

    gossip.stop(); kw.stop(); s.stop(); c.stop();
    fs::remove_all(tmp);
}

// The vote signature covers candidate_pubkey, but the ballot was matched on
// request_id alone -- so a genuine vote for one candidate could be counted
// toward a ballot about a different candidate.
TEST(BallotBinding, VoteForOtherCandidateNotCounted) {
    auto tmp = fs::temp_directory_path() /
               ("nexus_ballot_cand_" + std::to_string(getpid()));
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    asio::io_context io;
    crypto::SodiumCryptoService c;  c.start();
    storage::FileStorageService s{tmp};  s.start();
    crypto::KeyWrappingService kw{c, s};  kw.start();
    auto self = kw.generate_and_store_identity({});
    auto root = c.ed25519_keygen();

    auto self_b64 = b64({self.public_key.begin(), self.public_key.end()});
    seed_own_cert(s, sign_cert(c, root, self_b64, "sponsor-c"));

    auto p1 = c.ed25519_keygen();
    auto p1_b64 = b64({p1.public_key.begin(), p1.public_key.end()});
    seed_peers(s, nlohmann::json::array({
        peer_entry(p1_b64, "10.0.0.1:9102", sign_cert(c, root, p1_b64, "voter-1")),
    }));

    gossip::GossipService gossip{io, 0, s, c};
    gossip.set_root_pubkey(root.public_key);
    gossip.set_enrollment_config(true, 0.75f, 60, 3);
    gossip.start();

    auto cand = c.ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    auto other = c.ed25519_keygen();
    auto other_b64 = b64({other.public_key.begin(), other.public_key.end()});

    gossip.start_admission_ballot("req-cand", cand_b64, "worker-1", "", "", 0.75f);
    ASSERT_TRUE(Access::has_ballot(gossip, "req-cand"));
    const auto before = Access::vote_count(gossip, "req-cand");

    // Genuine, correctly signed vote -- for the WRONG candidate.
    Access::vote(gossip, p1_b64, signed_vote(c, p1, "req-cand", other_b64, true));
    EXPECT_EQ(Access::vote_count(gossip, "req-cand"), before);

    // The same voter's vote for the ballot's actual candidate is accepted.
    Access::vote(gossip, p1_b64, signed_vote(c, p1, "req-cand", cand_b64, true));
    EXPECT_EQ(Access::vote_count(gossip, "req-cand"), before + 1);

    gossip.stop(); kw.stop(); s.stop(); c.stop();
    fs::remove_all(tmp);
}

// A voter that leaves the electorate must leave the numerator at the same
// instant: otherwise revoking a voter SHRINKS the denominator while its stale
// approve survives, and a ballot that was short of quorum suddenly passes.
TEST(BallotBinding, RevokedVoterStaleVoteStopsCounting) {
    auto tmp = fs::temp_directory_path() /
               ("nexus_ballot_stale_" + std::to_string(getpid()));
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    asio::io_context io;
    crypto::SodiumCryptoService c;  c.start();
    storage::FileStorageService s{tmp};  s.start();
    crypto::KeyWrappingService kw{c, s};  kw.start();
    auto self = kw.generate_and_store_identity({});
    auto root = c.ed25519_keygen();

    auto self_b64 = b64({self.public_key.begin(), self.public_key.end()});
    seed_own_cert(s, sign_cert(c, root, self_b64, "sponsor-s"));

    auto p1 = c.ed25519_keygen();
    auto p1_b64 = b64({p1.public_key.begin(), p1.public_key.end()});
    auto p2 = c.ed25519_keygen();
    auto p2_b64 = b64({p2.public_key.begin(), p2.public_key.end()});
    seed_peers(s, nlohmann::json::array({
        peer_entry(p1_b64, "10.0.0.1:9102", sign_cert(c, root, p1_b64, "voter-1")),
        peer_entry(p2_b64, "10.0.0.2:9102", sign_cert(c, root, p2_b64, "voter-2")),
    }));

    gossip::GossipService gossip{io, 0, s, c};
    gossip.set_root_pubkey(root.public_key);
    gossip.set_enrollment_config(true, 0.75f, 60, 3);
    gossip.start();

    bool approved = false;
    gossip.set_enrollment_decision_callback([&](const gossip::EnrollmentBallot& bal) {
        if (bal.state == gossip::EnrollmentBallot::State::Approved) approved = true;
    });

    auto cand = c.ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});

    // Electorate {self, p1, p2} -> needed ceil(3*0.75) = 3. Sponsor supplies 1.
    gossip.start_admission_ballot("req-stale", cand_b64, "worker-1", "", "", 0.75f);
    ASSERT_FALSE(approved);

    // p1 approves -> 2 of 3. Still short.
    Access::vote(gossip, p1_b64, signed_vote(c, p1, "req-stale", cand_b64, true));
    ASSERT_FALSE(approved);

    // Revoking p1 drops the electorate to {self, p2}: needed 2. Counting p1's
    // stale approve would give 2 and pass the ballot.
    gossip.add_revoked_server(p1_b64);
    Access::retally(gossip, "req-stale");
    EXPECT_FALSE(approved);

    gossip.stop(); kw.stop(); s.stop(); c.stop();
    fs::remove_all(tmp);
}


// ===========================================================================
// NS slot pinning
// ===========================================================================

namespace {

// Minimal service stack for slot-claim tests; returns started services.
struct NsSlotRig {
    asio::io_context io;
    crypto::SodiumCryptoService c;
    std::unique_ptr<storage::FileStorageService> s;
    std::unique_ptr<crypto::KeyWrappingService> kw;
    std::unique_ptr<gossip::GossipService> gossip;
    fs::path tmp;

    explicit NsSlotRig(const std::string& tag) {
        tmp = fs::temp_directory_path() / (tag + std::to_string(getpid()));
        fs::remove_all(tmp);
        fs::create_directories(tmp);
        c.start();
        s = std::make_unique<storage::FileStorageService>(tmp);
        s->start();
        kw = std::make_unique<crypto::KeyWrappingService>(c, *s);
        kw->start();
        (void)kw->generate_and_store_identity({});
        gossip = std::make_unique<gossip::GossipService>(io, 0, *s, c);
        gossip->start();
    }
    ~NsSlotRig() {
        gossip->stop(); kw->stop(); s->stop(); c.stop();
        fs::remove_all(tmp);
    }
};

}  // namespace

TEST(NsSlot, AutoClaimsLowestFree) {
    NsSlotRig rig{"nexus_nsslot_auto_"};
    rig.gossip->try_claim_ns_slot("203.0.113.10");
    ASSERT_TRUE(rig.gossip->our_ns_slot().has_value());
    EXPECT_EQ(*rig.gossip->our_ns_slot(), 1);
}

TEST(NsSlot, PreferredSlotClaimed) {
    NsSlotRig rig{"nexus_nsslot_pin_"};
    rig.gossip->set_preferred_ns_slot(3);
    rig.gossip->try_claim_ns_slot("203.0.113.10");
    ASSERT_TRUE(rig.gossip->our_ns_slot().has_value());
    EXPECT_EQ(*rig.gossip->our_ns_slot(), 3);
}

// A pinned server must claim its slot or none: the registrar glue points the
// pinned name at this IP, so falling back to another slot advertises a
// nameserver record the registry contradicts.
TEST(NsSlot, OccupiedPreferredSlotNotClaimed) {
    NsSlotRig rig{"nexus_nsslot_busy_"};
    rig.gossip->set_preferred_ns_slot(3);
    Access::occupy_ns_slot(*rig.gossip, 3, "someone-else");
    rig.gossip->try_claim_ns_slot("203.0.113.10");
    EXPECT_FALSE(rig.gossip->our_ns_slot().has_value());
}

// ===========================================================================
// Ballot lifecycle across a restart
// ===========================================================================

// Ballots are in-memory but the record persists as ballot-governed, so after a
// restart approve()/deny() refuse it while no ballot exists to resolve it.
// Driven end to end: real votes, real quorum, no manual decision callback.
TEST(BallotLifecycle, RestartReopensBallotAndReachesQuorum) {
    auto tmp = fs::temp_directory_path() /
               ("nexus_ballot_restart_" + std::to_string(getpid()));
    fs::remove_all(tmp);
    fs::create_directories(tmp);

    asio::io_context io;
    crypto::SodiumCryptoService c;  c.start();
    storage::FileStorageService s{tmp};  s.start();
    crypto::KeyWrappingService kw{c, s};  kw.start();

    // Root anchor with its own root-signed cert (an eligible voter); one
    // enrolled peer makes an electorate of 2.
    auto root = kw.generate_and_store_identity({});
    auto root_b64 = b64({root.public_key.begin(), root.public_key.end()});
    seed_own_cert(s, sign_cert(c, root, root_b64, "genesis"));

    auto p1 = c.ed25519_keygen();
    auto p1_b64 = b64({p1.public_key.begin(), p1.public_key.end()});
    seed_peers(s, nlohmann::json::array({
        peer_entry(p1_b64, "10.0.0.1:9102", sign_cert(c, root, p1_b64, "voter-1")),
    }));

    core::ServerConfig config;
    config.root_pubkey = crypto::to_hex(
        std::span<const uint8_t>(root.public_key.data(), root.public_key.size()));
    config.onboard_enabled            = true;
    config.onboard_min_tier1_for_vote = 0;   // always the vote regime

    // Mirrors main.cpp: the callback is the ONLY path from ballot to issuance.
    auto wire = [&](gossip::GossipService& g, core::ServerAdmissionService& adm) {
        g.set_enrollment_decision_callback([&adm, &g](const gossip::EnrollmentBallot& b) {
            if (b.kind != gossip::EnrollmentBallot::Kind::Admission) return;
            if (b.sponsor_pubkey != crypto::to_base64(g.keypair().public_key)) return;
            adm.on_ballot_decision(b.request_id,
                                   b.state == gossip::EnrollmentBallot::State::Approved,
                                   b.candidate_pubkey, b.claim_hash, "");
        });
    };

    auto make_gossip = [&] {
        auto g = std::make_unique<gossip::GossipService>(io, 0, s, c);
        g->set_root_pubkey(root.public_key);
        g->set_enrollment_config(true, 0.75f, 60, 3);
        g->set_admission_quorum_ratio(0.75f);
        g->start();
        return g;
    };

    auto cand = c.ed25519_keygen();
    auto cand_b64 = b64({cand.public_key.begin(), cand.public_key.end()});
    std::string request_id, claim_hash;

    // --- First boot: open a ballot-governed admission ------------------------
    {
        auto gossip = make_gossip();
        core::ServerAdmissionService adm{config, c, kw, s, *gossip, nullptr};
        wire(*gossip, adm);
        adm.start();

        core::ServerAdmissionService::RequestInput in;
        in.candidate_pubkey = cand_b64;
        in.server_id        = "worker-restart";
        in.region           = "eu-west";
        in.nonce            = adm.issue_challenge(cand_b64);
        in.timestamp        = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        auto msg = core::ServerAdmissionService::canonical_request(in);
        auto sig = c.ed25519_sign(cand.private_key, std::span<const uint8_t>(msg));
        in.signature = crypto::to_base64(std::span<const uint8_t>(sig.data(), sig.size()));

        auto r = adm.create_request(in);
        ASSERT_TRUE(r.ok) << r.error;
        ASSERT_TRUE(r.needs_ballot);
        adm.start_pending_ballot(r.request_id);
        request_id = r.request_id;
        claim_hash = adm.status(request_id, cand_b64)->claim_hash;
        ASSERT_TRUE(Access::has_ballot(*gossip, request_id));

        adm.stop();
        gossip->stop();
    }

    // --- Restart: fresh gossip (empty ballots) + service from the same root ---
    auto gossip = make_gossip();
    ASSERT_FALSE(Access::has_ballot(*gossip, request_id));   // in-memory state is gone

    core::ServerAdmissionService adm{config, c, kw, s, *gossip, nullptr};
    wire(*gossip, adm);
    adm.start();

    // The ballot is re-opened by start(), bound to the same claim.
    ASSERT_TRUE(Access::has_ballot(*gossip, request_id));
    EXPECT_EQ(adm.status(request_id, cand_b64)->claim_hash, claim_hash);
    EXPECT_EQ(adm.status(request_id, cand_b64)->state,
              core::ServerAdmissionService::State::Pending);

    // Electorate {self, peer} = 2 at 0.75 -> needs both. The sponsor voted when
    // the ballot re-opened; the peer's vote closes the quorum.
    Access::vote(*gossip, p1_b64, signed_vote(c, p1, request_id, cand_b64, true, claim_hash));

    auto after = adm.status(request_id, cand_b64);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(after->state, core::ServerAdmissionService::State::Approved);
    EXPECT_EQ(after->decided_by, "ballot");
    EXPECT_FALSE(after->issued_cert_json.empty());

    adm.stop(); gossip->stop(); kw.stop(); s.stop(); c.stop();
    fs::remove_all(tmp);
}
