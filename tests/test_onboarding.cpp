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
    // At/above the vote threshold the quorum ballot decides; a token is
    // neither honored nor consumed.
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

    // Unconsumed: still spendable once the mesh is back below the threshold.
    core::AdmissionTokenStore store{*storage_svc, *crypto_svc};
    EXPECT_TRUE(store.verify(minted->first, in.candidate_pubkey).has_value());
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
    admission->on_ballot_decision(r.request_id, /*approved=*/true, "");
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
    admission->on_ballot_decision(r.request_id, /*approved=*/true, "");
    auto after = admission->status(r.request_id, in.candidate_pubkey);
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(after->state, core::ServerAdmissionService::State::Approved);
    EXPECT_EQ(after->decided_by, "ballot");
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
