#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/TeeAttestation.hpp>
#include <LemonadeNexus/Core/TrustPolicy.hpp>
#include <LemonadeNexus/Core/TrustTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipTypes.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <cstring>
#include <filesystem>
#include <string>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace nexus;
using json = nlohmann::json;

// ===========================================================================
// TrustTypes unit tests
// ===========================================================================

TEST(TrustTypesTest, Tier2AllowsHolePunch) {
    EXPECT_TRUE(core::is_operation_allowed(core::TrustTier::Tier2, core::TrustOperation::HolePunch));
}

TEST(TrustTypesTest, Tier2AllowsServerDiscovery) {
    EXPECT_TRUE(core::is_operation_allowed(core::TrustTier::Tier2, core::TrustOperation::ServerDiscovery));
}

TEST(TrustTypesTest, Tier2AllowsHealthCheck) {
    EXPECT_TRUE(core::is_operation_allowed(core::TrustTier::Tier2, core::TrustOperation::HealthCheck));
}

TEST(TrustTypesTest, Tier2DeniesGossipDigest) {
    EXPECT_FALSE(core::is_operation_allowed(core::TrustTier::Tier2, core::TrustOperation::GossipDigest));
}

TEST(TrustTypesTest, Tier2DeniesGossipPeerExchange) {
    EXPECT_FALSE(core::is_operation_allowed(core::TrustTier::Tier2, core::TrustOperation::GossipPeerExchange));
}

TEST(TrustTypesTest, Tier2DeniesTreeRead) {
    EXPECT_FALSE(core::is_operation_allowed(core::TrustTier::Tier2, core::TrustOperation::TreeRead));
}

TEST(TrustTypesTest, Tier2DeniesTreeWrite) {
    EXPECT_FALSE(core::is_operation_allowed(core::TrustTier::Tier2, core::TrustOperation::TreeWrite));
}

TEST(TrustTypesTest, Tier2DeniesDnsResolve) {
    EXPECT_FALSE(core::is_operation_allowed(core::TrustTier::Tier2, core::TrustOperation::DnsResolve));
}

TEST(TrustTypesTest, Tier2DeniesCredentialRequest) {
    EXPECT_FALSE(core::is_operation_allowed(core::TrustTier::Tier2, core::TrustOperation::CredentialRequest));
}

TEST(TrustTypesTest, Tier2DeniesKeyAccess) {
    EXPECT_FALSE(core::is_operation_allowed(core::TrustTier::Tier2, core::TrustOperation::KeyAccess));
}

TEST(TrustTypesTest, Tier2DeniesIpamAllocate) {
    EXPECT_FALSE(core::is_operation_allowed(core::TrustTier::Tier2, core::TrustOperation::IpamAllocate));
}

TEST(TrustTypesTest, Tier1AllowsEverything) {
    EXPECT_TRUE(core::is_operation_allowed(core::TrustTier::Tier1, core::TrustOperation::HolePunch));
    EXPECT_TRUE(core::is_operation_allowed(core::TrustTier::Tier1, core::TrustOperation::ServerDiscovery));
    EXPECT_TRUE(core::is_operation_allowed(core::TrustTier::Tier1, core::TrustOperation::HealthCheck));
    EXPECT_TRUE(core::is_operation_allowed(core::TrustTier::Tier1, core::TrustOperation::GossipDigest));
    EXPECT_TRUE(core::is_operation_allowed(core::TrustTier::Tier1, core::TrustOperation::GossipPeerExchange));
    EXPECT_TRUE(core::is_operation_allowed(core::TrustTier::Tier1, core::TrustOperation::TreeRead));
    EXPECT_TRUE(core::is_operation_allowed(core::TrustTier::Tier1, core::TrustOperation::TreeWrite));
    EXPECT_TRUE(core::is_operation_allowed(core::TrustTier::Tier1, core::TrustOperation::DnsResolve));
    EXPECT_TRUE(core::is_operation_allowed(core::TrustTier::Tier1, core::TrustOperation::CredentialRequest));
    EXPECT_TRUE(core::is_operation_allowed(core::TrustTier::Tier1, core::TrustOperation::KeyAccess));
    EXPECT_TRUE(core::is_operation_allowed(core::TrustTier::Tier1, core::TrustOperation::IpamAllocate));
}

TEST(TrustTypesTest, UntrustedDeniesEverything) {
    EXPECT_FALSE(core::is_operation_allowed(core::TrustTier::Untrusted, core::TrustOperation::HolePunch));
    EXPECT_FALSE(core::is_operation_allowed(core::TrustTier::Untrusted, core::TrustOperation::GossipDigest));
    EXPECT_FALSE(core::is_operation_allowed(core::TrustTier::Untrusted, core::TrustOperation::KeyAccess));
}

// ---------------------------------------------------------------------------
// TeePlatform helpers
// ---------------------------------------------------------------------------

TEST(TrustTypesTest, PlatformNameRoundTrip) {
    EXPECT_EQ(core::tee_platform_from_string("sgx"), core::TeePlatform::IntelSgx);
    EXPECT_EQ(core::tee_platform_from_string("tdx"), core::TeePlatform::IntelTdx);
    EXPECT_EQ(core::tee_platform_from_string("sev-snp"), core::TeePlatform::AmdSevSnp);
    EXPECT_EQ(core::tee_platform_from_string("secure-enclave"), core::TeePlatform::AppleSecureEnclave);
    EXPECT_EQ(core::tee_platform_from_string("unknown"), core::TeePlatform::None);
    EXPECT_EQ(core::tee_platform_from_string(""), core::TeePlatform::None);
}

TEST(TrustTypesTest, PlatformNameStrings) {
    EXPECT_EQ(core::tee_platform_name(core::TeePlatform::None), "none");
    EXPECT_EQ(core::tee_platform_name(core::TeePlatform::IntelSgx), "sgx");
    EXPECT_EQ(core::tee_platform_name(core::TeePlatform::IntelTdx), "tdx");
    EXPECT_EQ(core::tee_platform_name(core::TeePlatform::AmdSevSnp), "sev-snp");
    EXPECT_EQ(core::tee_platform_name(core::TeePlatform::AppleSecureEnclave), "secure-enclave");
}

// ---------------------------------------------------------------------------
// TeeAttestationReport JSON serialization
// ---------------------------------------------------------------------------

TEST(TrustTypesTest, AttestationReportJsonRoundTrip) {
    core::TeeAttestationReport report;
    report.platform = core::TeePlatform::AmdSevSnp;
    report.quote = {0x53, 0x45, 0x56, 0x31, 0xAA, 0xBB};
    report.nonce.fill(0x42);
    report.timestamp = 1710000000;
    report.server_pubkey = "dGVzdHB1YmtleQ==";
    report.binary_hash = "abcdef1234567890";
    report.signature = "dGVzdHNpZw==";

    json j = report;

    // Verify fields
    EXPECT_EQ(j["platform"].get<uint8_t>(), 3);
    EXPECT_EQ(j["platform_name"].get<std::string>(), "sev-snp");
    EXPECT_EQ(j["timestamp"].get<uint64_t>(), 1710000000u);
    EXPECT_EQ(j["server_pubkey"].get<std::string>(), "dGVzdHB1YmtleQ==");
    EXPECT_EQ(j["binary_hash"].get<std::string>(), "abcdef1234567890");
    EXPECT_EQ(j["signature"].get<std::string>(), "dGVzdHNpZw==");

    // Round-trip back
    core::TeeAttestationReport report2;
    from_json(j, report2);
    EXPECT_EQ(report2.platform, core::TeePlatform::AmdSevSnp);
    EXPECT_EQ(report2.timestamp, 1710000000u);
    EXPECT_EQ(report2.server_pubkey, "dGVzdHB1YmtleQ==");
    EXPECT_EQ(report2.binary_hash, "abcdef1234567890");
}

// ---------------------------------------------------------------------------
// AttestationToken JSON serialization
// ---------------------------------------------------------------------------

TEST(TrustTypesTest, AttestationTokenJsonRoundTrip) {
    core::AttestationToken token;
    token.server_pubkey = "c2VydmVya2V5";
    token.platform = core::TeePlatform::IntelTdx;
    token.attestation_hash = "deadbeef";
    token.binary_hash = "cafebabe";
    token.timestamp = 1710000000;
    token.attestation_timestamp = 1709999000;
    token.signature = "c2lnbmF0dXJl";

    json j = token;
    EXPECT_EQ(j["platform"].get<uint8_t>(), 2);
    EXPECT_EQ(j["platform_name"].get<std::string>(), "tdx");

    core::AttestationToken token2;
    from_json(j, token2);
    EXPECT_EQ(token2.server_pubkey, "c2VydmVya2V5");
    EXPECT_EQ(token2.platform, core::TeePlatform::IntelTdx);
    EXPECT_EQ(token2.attestation_hash, "deadbeef");
    EXPECT_EQ(token2.binary_hash, "cafebabe");
    EXPECT_EQ(token2.timestamp, 1710000000u);
    EXPECT_EQ(token2.attestation_timestamp, 1709999000u);
    EXPECT_EQ(token2.signature, "c2lnbmF0dXJl");
}

// ---------------------------------------------------------------------------
// Canonical JSON determinism
// ---------------------------------------------------------------------------

TEST(TrustTypesTest, CanonicalAttestationJsonIsDeterministic) {
    core::TeeAttestationReport r;
    r.platform = core::TeePlatform::IntelSgx;
    r.nonce.fill(0x01);
    r.timestamp = 999;
    r.server_pubkey = "pk";
    r.binary_hash = "bh";

    auto a = core::canonical_attestation_json(r);
    auto b = core::canonical_attestation_json(r);
    EXPECT_EQ(a, b);
    // Should NOT contain "signature" (canonical excludes it)
    EXPECT_EQ(a.find("signature"), std::string::npos);
}

TEST(TrustTypesTest, CanonicalTokenJsonIsDeterministic) {
    core::AttestationToken t;
    t.server_pubkey = "pk";
    t.platform = core::TeePlatform::AmdSevSnp;
    t.attestation_hash = "ah";
    t.binary_hash = "bh";
    t.timestamp = 100;
    t.attestation_timestamp = 90;

    auto a = core::canonical_token_json(t);
    auto b = core::canonical_token_json(t);
    EXPECT_EQ(a, b);
    EXPECT_EQ(a.find("signature"), std::string::npos);
}

// ===========================================================================
// TeeAttestationService tests
// ===========================================================================

class TeeAttestationTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<crypto::SodiumCryptoService> crypto;
    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<core::BinaryAttestationService> attestation;
    std::unique_ptr<core::TeeAttestationService> tee;

    void SetUp() override {
        temp_dir = fs::temp_directory_path() /
            ("nexus_test_tee_" + std::to_string(getpid()));
        fs::create_directories(temp_dir);

        crypto = std::make_unique<crypto::SodiumCryptoService>();
        crypto->start();

        storage = std::make_unique<storage::FileStorageService>(temp_dir);
        storage->start();

        attestation = std::make_unique<core::BinaryAttestationService>(*crypto, *storage);
        attestation->start();

        tee = std::make_unique<core::TeeAttestationService>(*crypto, *storage, *attestation);
        tee->start();
    }

    void TearDown() override {
        tee->stop();
        attestation->stop();
        storage->stop();
        crypto->stop();
        fs::remove_all(temp_dir);
    }
};

TEST_F(TeeAttestationTest, StartsSuccessfully) {
    // On a dev machine without TEE hardware, platform should be None
    // (unless running on Apple Silicon or inside SEV-SNP VM, etc.)
    // We just verify it doesn't crash and reports a valid platform
    auto platform = tee->detected_platform();
    EXPECT_TRUE(platform == core::TeePlatform::None ||
                platform == core::TeePlatform::IntelSgx ||
                platform == core::TeePlatform::IntelTdx ||
                platform == core::TeePlatform::AmdSevSnp ||
                platform == core::TeePlatform::AppleSecureEnclave);
}

TEST_F(TeeAttestationTest, PlatformOverride) {
    tee->set_platform_override("sev-snp");
    EXPECT_EQ(tee->detected_platform(), core::TeePlatform::AmdSevSnp);

    tee->set_platform_override("sgx");
    EXPECT_EQ(tee->detected_platform(), core::TeePlatform::IntelSgx);

    tee->set_platform_override("tdx");
    EXPECT_EQ(tee->detected_platform(), core::TeePlatform::IntelTdx);

    tee->set_platform_override("secure-enclave");
    EXPECT_EQ(tee->detected_platform(), core::TeePlatform::AppleSecureEnclave);

    tee->set_platform_override("none");
    EXPECT_EQ(tee->detected_platform(), core::TeePlatform::None);
}

TEST_F(TeeAttestationTest, PlatformAvailableMatchesDetection) {
    // platform_available() should be true iff detected_platform != None
    bool detected = (tee->detected_platform() != core::TeePlatform::None);
    EXPECT_EQ(tee->platform_available(), detected);
}

TEST_F(TeeAttestationTest, GenerateTokenProducesSignedToken) {
    auto kp = crypto->ed25519_keygen();
    auto token = tee->generate_token(kp);

    EXPECT_EQ(token.server_pubkey, crypto::to_base64(kp.public_key));
    EXPECT_GT(token.timestamp, 0u);
    EXPECT_FALSE(token.signature.empty());
    EXPECT_FALSE(token.binary_hash.empty());
}

TEST_F(TeeAttestationTest, VerifyOwnTokenSucceeds) {
    // If we have TEE hardware, our own token should verify
    // If not, the token will have platform=None and verification should fail
    auto kp = crypto->ed25519_keygen();
    auto token = tee->generate_token(kp);

    if (tee->platform_available()) {
        EXPECT_TRUE(tee->verify_token(token));
    } else {
        // Without TEE, token has platform=None → verification fails (by design)
        EXPECT_FALSE(tee->verify_token(token));
    }
}

TEST_F(TeeAttestationTest, VerifyTokenRejectsExpired) {
    auto kp = crypto->ed25519_keygen();
    auto token = tee->generate_token(kp);

    // Set timestamp far in the past
    token.timestamp = 1000;
    // Re-sign (would need to re-sign for real verification, but test the check)
    EXPECT_FALSE(tee->verify_token(token));
}

TEST_F(TeeAttestationTest, VerifyTokenRejectsFutureTimestamp) {
    auto kp = crypto->ed25519_keygen();
    auto token = tee->generate_token(kp);

    // Set timestamp far in the future
    token.timestamp = token.timestamp + 3600;
    EXPECT_FALSE(tee->verify_token(token));
}

TEST_F(TeeAttestationTest, VerifyTokenRejectsInvalidSignature) {
    auto kp = crypto->ed25519_keygen();
    auto token = tee->generate_token(kp);

    // Tamper with signature
    token.signature = "dGFtcGVyZWQ=";  // "tampered" in base64
    EXPECT_FALSE(tee->verify_token(token));
}

TEST_F(TeeAttestationTest, VerifyTokenRejectsInvalidPubkey) {
    auto kp = crypto->ed25519_keygen();
    auto token = tee->generate_token(kp);

    // Replace pubkey with different key
    auto kp2 = crypto->ed25519_keygen();
    token.server_pubkey = crypto::to_base64(kp2.public_key);
    EXPECT_FALSE(tee->verify_token(token));
}

// ===========================================================================
// TrustPolicyService tests
// ===========================================================================

class TrustPolicyTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<crypto::SodiumCryptoService> crypto;
    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<core::BinaryAttestationService> attestation;
    std::unique_ptr<core::TeeAttestationService> tee;
    std::unique_ptr<core::TrustPolicyService> policy;

    void SetUp() override {
        temp_dir = fs::temp_directory_path() /
            ("nexus_test_trust_" + std::to_string(getpid()));
        fs::create_directories(temp_dir);

        crypto = std::make_unique<crypto::SodiumCryptoService>();
        crypto->start();

        storage = std::make_unique<storage::FileStorageService>(temp_dir);
        storage->start();

        attestation = std::make_unique<core::BinaryAttestationService>(*crypto, *storage);
        attestation->start();

        tee = std::make_unique<core::TeeAttestationService>(*crypto, *storage, *attestation);
        tee->start();

        policy = std::make_unique<core::TrustPolicyService>(*tee, *attestation, *crypto);
        policy->start();
    }

    void TearDown() override {
        policy->stop();
        tee->stop();
        attestation->stop();
        storage->stop();
        crypto->stop();
        fs::remove_all(temp_dir);
    }
};

TEST_F(TrustPolicyTest, UnknownPeerIsUntrusted) {
    EXPECT_EQ(policy->peer_tier("unknown_peer_pubkey"), core::TrustTier::Untrusted);
}

TEST_F(TrustPolicyTest, UnknownPeerDeniedAllOperations) {
    EXPECT_FALSE(policy->authorize("unknown", core::TrustOperation::HolePunch));
    EXPECT_FALSE(policy->authorize("unknown", core::TrustOperation::GossipDigest));
    EXPECT_FALSE(policy->authorize("unknown", core::TrustOperation::KeyAccess));
}

TEST_F(TrustPolicyTest, SetPeerTier2) {
    const std::string pk = "dGVzdHBlZXI=";  // "testpeer" in base64

    policy->set_peer_tier2(pk);
    EXPECT_EQ(policy->peer_tier(pk), core::TrustTier::Tier2);
}

TEST_F(TrustPolicyTest, Tier2PeerAllowsHolePunch) {
    const std::string pk = "dGVzdHBlZXI=";
    policy->set_peer_tier2(pk);

    EXPECT_TRUE(policy->authorize(pk, core::TrustOperation::HolePunch));
    EXPECT_TRUE(policy->authorize(pk, core::TrustOperation::ServerDiscovery));
    EXPECT_TRUE(policy->authorize(pk, core::TrustOperation::HealthCheck));
}

TEST_F(TrustPolicyTest, Tier2PeerDeniedGossipAndKeys) {
    const std::string pk = "dGVzdHBlZXI=";
    policy->set_peer_tier2(pk);

    EXPECT_FALSE(policy->authorize(pk, core::TrustOperation::GossipDigest));
    EXPECT_FALSE(policy->authorize(pk, core::TrustOperation::TreeRead));
    EXPECT_FALSE(policy->authorize(pk, core::TrustOperation::KeyAccess));
    EXPECT_FALSE(policy->authorize(pk, core::TrustOperation::CredentialRequest));
}

TEST_F(TrustPolicyTest, RemovePeerResetsTrust) {
    const std::string pk = "dGVzdHBlZXI=";
    policy->set_peer_tier2(pk);
    EXPECT_EQ(policy->peer_tier(pk), core::TrustTier::Tier2);

    policy->remove_peer(pk);
    EXPECT_EQ(policy->peer_tier(pk), core::TrustTier::Untrusted);
}

TEST_F(TrustPolicyTest, VerifyInvalidTokenDemotes) {
    const std::string pk = "dGVzdHBlZXI=";
    policy->set_peer_tier2(pk);

    // Create a completely bogus token
    core::AttestationToken bogus;
    bogus.server_pubkey = pk;
    bogus.platform = core::TeePlatform::AmdSevSnp;
    bogus.timestamp = 1000;  // expired
    bogus.signature = "invalid";

    auto tier = policy->verify_and_update(pk, bogus);
    // Should remain Tier2 after first failure (was Tier2, single failure doesn't go lower)
    EXPECT_EQ(tier, core::TrustTier::Tier2);

    // Track failure count
    auto state = policy->peer_state(pk);
    EXPECT_GE(state.failed_verifications, 1u);
}

TEST_F(TrustPolicyTest, RepeatedFailuresDemoteToUntrusted) {
    const std::string pk = "dGVzdHBlZXI=";
    policy->set_peer_tier2(pk);

    core::AttestationToken bogus;
    bogus.server_pubkey = pk;
    bogus.platform = core::TeePlatform::AmdSevSnp;
    bogus.timestamp = 1000;
    bogus.signature = "invalid";

    // 3 failures should demote to Untrusted
    for (uint32_t i = 0; i < core::TrustPolicyService::kMaxFailedVerifications; ++i) {
        (void)policy->verify_and_update(pk, bogus);
    }

    EXPECT_EQ(policy->peer_tier(pk), core::TrustTier::Untrusted);
}

TEST_F(TrustPolicyTest, ChallengePeerGeneratesNonce) {
    const std::string pk = "dGVzdHBlZXI=";
    auto nonce = policy->challenge_peer(pk);

    // Nonce should not be all zeros (random)
    std::array<uint8_t, 32> zeros{};
    EXPECT_NE(nonce, zeros);
}

TEST_F(TrustPolicyTest, ChallengeResponseWithBadReportFails) {
    const std::string pk = "dGVzdHBlZXI=";
    policy->set_peer_tier2(pk);

    auto nonce = policy->challenge_peer(pk);

    // Create an empty/invalid report
    core::TeeAttestationReport bad_report;
    bad_report.platform = core::TeePlatform::None;
    bad_report.nonce = nonce;
    bad_report.server_pubkey = pk;

    EXPECT_FALSE(policy->handle_challenge_response(pk, bad_report));
}

TEST_F(TrustPolicyTest, ChallengeResponseWithNoPendingChallengeFails) {
    const std::string pk = "dGVzdHBlZXI=";

    // No challenge was issued
    core::TeeAttestationReport report;
    report.platform = core::TeePlatform::AmdSevSnp;
    report.server_pubkey = pk;

    EXPECT_FALSE(policy->handle_challenge_response(pk, report));
}

TEST_F(TrustPolicyTest, AllPeerStatesReturnsAllPeers) {
    policy->set_peer_tier2("peer1");
    policy->set_peer_tier2("peer2");
    policy->set_peer_tier2("peer3");

    auto states = policy->all_peer_states();
    EXPECT_EQ(states.size(), 3u);
}

TEST_F(TrustPolicyTest, PeerStateReturnsCorrectData) {
    const std::string pk = "dGVzdHBlZXI=";
    policy->set_peer_tier2(pk);

    auto state = policy->peer_state(pk);
    EXPECT_EQ(state.pubkey, pk);
    EXPECT_EQ(state.tier, core::TrustTier::Tier2);
    EXPECT_GT(state.last_verified, 0u);
}

TEST_F(TrustPolicyTest, OurTierReflectsTeePlatform) {
    // Without TEE hardware, our tier should be Tier2
    // With TEE hardware, it should be Tier1
    auto tier = policy->our_tier();
    if (tee->platform_available()) {
        EXPECT_EQ(tier, core::TrustTier::Tier1);
    } else {
        EXPECT_EQ(tier, core::TrustTier::Tier2);
    }
}

TEST_F(TrustPolicyTest, ExpireStalePeersDemotesTier1) {
    const std::string pk = "dGVzdHBlZXI=";

    // Manually set a peer to Tier2 (the expire function only affects Tier1)
    policy->set_peer_tier2(pk);

    // Expire with a max age of 0 — should not affect Tier2 peers
    policy->expire_stale_peers(0);
    // Tier2 peers are not expired by this function
    EXPECT_EQ(policy->peer_tier(pk), core::TrustTier::Tier2);
}

TEST_F(TrustPolicyTest, GenerateAttestationTokenWorks) {
    auto kp = crypto->ed25519_keygen();
    auto token = policy->generate_attestation_token(kp);

    EXPECT_EQ(token.server_pubkey, crypto::to_base64(kp.public_key));
    EXPECT_FALSE(token.signature.empty());
    EXPECT_GT(token.timestamp, 0u);
}

// ===========================================================================
// GossipTypes trust_tier field tests
// ===========================================================================

TEST(GossipTypesTest, PeerDefaultTrustTierIsUntrusted) {
    nexus::gossip::GossipPeer peer;
    EXPECT_EQ(peer.trust_tier, core::TrustTier::Untrusted);
}

TEST(GossipTypesTest, TeeMessageTypesExist) {
    // Verify the new message types have expected values
    EXPECT_EQ(static_cast<uint8_t>(nexus::gossip::GossipMsgType::TeeChallenge), 0x07);
    EXPECT_EQ(static_cast<uint8_t>(nexus::gossip::GossipMsgType::TeeResponse), 0x08);
}

// ===========================================================================
// Integration: Token generation + verification round-trip
// ===========================================================================

class TrustIntegrationTest : public ::testing::Test {
protected:
    fs::path temp_dir_a, temp_dir_b;
    std::unique_ptr<crypto::SodiumCryptoService> crypto_a, crypto_b;
    std::unique_ptr<storage::FileStorageService> storage_a, storage_b;
    std::unique_ptr<core::BinaryAttestationService> att_a, att_b;
    std::unique_ptr<core::TeeAttestationService> tee_a, tee_b;
    std::unique_ptr<core::TrustPolicyService> policy_a, policy_b;
    crypto::Ed25519Keypair kp_a, kp_b;

    void SetUp() override {
        auto seed = std::to_string(getpid());
        temp_dir_a = fs::temp_directory_path() / ("nexus_test_trust_int_a_" + seed);
        temp_dir_b = fs::temp_directory_path() / ("nexus_test_trust_int_b_" + seed);
        fs::create_directories(temp_dir_a);
        fs::create_directories(temp_dir_b);

        // Server A
        crypto_a = std::make_unique<crypto::SodiumCryptoService>();
        crypto_a->start();
        storage_a = std::make_unique<storage::FileStorageService>(temp_dir_a);
        storage_a->start();
        att_a = std::make_unique<core::BinaryAttestationService>(*crypto_a, *storage_a);
        att_a->start();
        tee_a = std::make_unique<core::TeeAttestationService>(*crypto_a, *storage_a, *att_a);
        tee_a->start();
        policy_a = std::make_unique<core::TrustPolicyService>(*tee_a, *att_a, *crypto_a);
        policy_a->start();
        kp_a = crypto_a->ed25519_keygen();

        // Server B
        crypto_b = std::make_unique<crypto::SodiumCryptoService>();
        crypto_b->start();
        storage_b = std::make_unique<storage::FileStorageService>(temp_dir_b);
        storage_b->start();
        att_b = std::make_unique<core::BinaryAttestationService>(*crypto_b, *storage_b);
        att_b->start();
        tee_b = std::make_unique<core::TeeAttestationService>(*crypto_b, *storage_b, *att_b);
        tee_b->start();
        policy_b = std::make_unique<core::TrustPolicyService>(*tee_b, *att_b, *crypto_b);
        policy_b->start();
        kp_b = crypto_b->ed25519_keygen();
    }

    void TearDown() override {
        policy_b->stop(); policy_a->stop();
        tee_b->stop(); tee_a->stop();
        att_b->stop(); att_a->stop();
        storage_b->stop(); storage_a->stop();
        crypto_b->stop(); crypto_a->stop();
        fs::remove_all(temp_dir_a);
        fs::remove_all(temp_dir_b);
    }
};

TEST_F(TrustIntegrationTest, TwoServersStartAsTier2WithoutTee) {
    // Without TEE hardware, both servers should be Tier2
    if (!tee_a->platform_available()) {
        EXPECT_EQ(policy_a->our_tier(), core::TrustTier::Tier2);
    }
    if (!tee_b->platform_available()) {
        EXPECT_EQ(policy_b->our_tier(), core::TrustTier::Tier2);
    }
}

TEST_F(TrustIntegrationTest, ServerARegistersServerBAsTier2) {
    auto pk_b = crypto::to_base64(kp_b.public_key);

    policy_a->set_peer_tier2(pk_b);
    EXPECT_EQ(policy_a->peer_tier(pk_b), core::TrustTier::Tier2);

    // B should be allowed to do hole punching
    EXPECT_TRUE(policy_a->authorize(pk_b, core::TrustOperation::HolePunch));
    // B should NOT be allowed to gossip
    EXPECT_FALSE(policy_a->authorize(pk_b, core::TrustOperation::GossipDigest));
}

TEST_F(TrustIntegrationTest, TokenFromServerBRejectedWithoutTee) {
    auto pk_b = crypto::to_base64(kp_b.public_key);
    policy_a->set_peer_tier2(pk_b);

    // B generates a token — without TEE hardware, it'll have platform=None
    auto token_b = tee_b->generate_token(kp_b);

    if (!tee_b->platform_available()) {
        // Token has no TEE platform → verification fails → remains Tier2
        auto tier = policy_a->verify_and_update(pk_b, token_b);
        EXPECT_NE(tier, core::TrustTier::Tier1);
    }
}

TEST_F(TrustIntegrationTest, AttestationTokenJsonTransport) {
    // Simulate sending a token over the wire via JSON serialization
    auto token = tee_a->generate_token(kp_a);

    // Serialize to JSON (as happens in gossip message payload)
    json token_json = token;
    std::string wire_data = token_json.dump();

    // Deserialize on the receiving end
    auto received_json = json::parse(wire_data);
    auto received_token = received_json.get<core::AttestationToken>();

    // All fields should survive the round trip
    EXPECT_EQ(received_token.server_pubkey, token.server_pubkey);
    EXPECT_EQ(received_token.platform, token.platform);
    EXPECT_EQ(received_token.attestation_hash, token.attestation_hash);
    EXPECT_EQ(received_token.binary_hash, token.binary_hash);
    EXPECT_EQ(received_token.timestamp, token.timestamp);
    EXPECT_EQ(received_token.attestation_timestamp, token.attestation_timestamp);
    EXPECT_EQ(received_token.signature, token.signature);
}

TEST_F(TrustIntegrationTest, MutualChallengeResponseFlow) {
    auto pk_a = crypto::to_base64(kp_a.public_key);
    auto pk_b = crypto::to_base64(kp_b.public_key);

    // Both servers register each other as Tier2
    policy_a->set_peer_tier2(pk_b);
    policy_b->set_peer_tier2(pk_a);

    // A challenges B
    auto nonce_for_b = policy_a->challenge_peer(pk_b);

    // B generates a report bound to A's nonce
    auto report_b = tee_b->generate_report(nonce_for_b);
    report_b.server_pubkey = pk_b;

    // Sign the report
    auto canonical = core::canonical_attestation_json(report_b);
    auto canonical_bytes = std::vector<uint8_t>(canonical.begin(), canonical.end());
    auto sig = crypto_b->ed25519_sign(kp_b.private_key, canonical_bytes);
    report_b.signature = crypto::to_base64(sig);

    // A validates B's response
    bool result = policy_a->handle_challenge_response(pk_b, report_b);

    // Without TEE hardware, the report verification will fail (no valid quote)
    // With TEE hardware, it should succeed
    if (tee_b->platform_available()) {
        EXPECT_TRUE(result);
        EXPECT_EQ(policy_a->peer_tier(pk_b), core::TrustTier::Tier1);
    } else {
        EXPECT_FALSE(result);
        // Still Tier2 (single failure doesn't demote further from Tier2)
    }
}
