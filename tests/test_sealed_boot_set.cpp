// Sealed blobs and the boot set, without a TPM.
//
//   - the policy math against known answers taken from a TPM trial session;
//   - the strict blob parser;
//   - SealedBlobStore: current and next slots, upgrade staging, promotion;
//   - load_gossip_identity: the one-way migration and every restart case.
//
// The store and boot-set tests use FakeSealer, a test double that models PCR
// state, bindings, and tampering. It is not a TPM and these tests are not TPM
// evidence. test_tpm_seal_simulator.cpp runs the real TPM path against swtpm.

#include <LemonadeNexus/Core/BootSet.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseApproval.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlob.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlobStore.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#ifndef _WIN32
#  include <unistd.h>
#endif

namespace fs = std::filesystem;
namespace crypto = nexus::crypto;
namespace core = nexus::core;
using namespace nexus::security;
using json = nlohmann::json;

namespace {

BootPcrValues pcrs_of(uint8_t pcr8, uint8_t pcr9) {
    BootPcrValues values{};
    values[0].fill(pcr8);
    values[1].fill(pcr9);
    return values;
}

std::string read_text(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void write_text(const fs::path& path, std::string_view text) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
}

/// Test double for nexus-attestd's seal and unseal. It models what the store
/// and the boot set act on: the running PCR values, the binding a blob
/// carries, the TPM a blob belongs to (`owner_seed`), and tampering (a real
/// AEAD over the real blob format). It is not a TPM.
struct FakeSealer {
    BootPcrValues pcrs = pcrs_of(0x11, 0x22);
    std::string owner_seed = "owner-seed-A";
    bool reachable = true;
    bool available = true;
    int seal_calls = 0;
    int unseal_calls = 0;

    crypto::AeadKey key() const {
        crypto::AeadKey k{};
        crypto_hash_sha256(k.data(), reinterpret_cast<const uint8_t*>(owner_seed.data()),
                           owner_seed.size());
        return k;
    }

    SealBackend backend() {
        SealBackend b;
        b.seal = [this](std::string_view domain, std::span<const uint8_t> plaintext,
                        const std::optional<BootPcrValues>& target) {
            ++seal_calls;
            SealReply reply;
            if (!reachable) {
                reply.status = SealStatus::Unreachable;
                return reply;
            }
            if (!available) {
                reply.status = SealStatus::Unavailable;
                return reply;
            }
            SealedBlob blob;
            blob.domain = std::string(domain);
            blob.pcr_digest = boot_pcr_digest(target ? *target : pcrs);
            blob.tpm_public.assign(owner_seed.begin(), owner_seed.end());
            blob.tpm_private.assign(16, 0x5A);
            blob.nonce.resize(crypto::kAeadNonceSize);
            randombytes_buf(blob.nonce.data(), blob.nonce.size());
            const auto aad = sealed_blob_aad(blob.domain, blob.pcr_digest, blob.tpm_public);
            blob.ciphertext.resize(plaintext.size() + crypto::kAeadTagSize);
            unsigned long long n = 0;
            const auto k = key();
            crypto_aead_xchacha20poly1305_ietf_encrypt(blob.ciphertext.data(), &n,
                                                       plaintext.data(), plaintext.size(),
                                                       aad.data(), aad.size(), nullptr,
                                                       blob.nonce.data(), k.data());
            reply.status = SealStatus::Ok;
            reply.blob = encode_sealed_blob(blob);
            return reply;
        };
        b.unseal = [this](std::string_view domain, std::string_view text) {
            ++unseal_calls;
            UnsealReply reply;
            if (!reachable) {
                reply.status = SealStatus::Unreachable;
                return reply;
            }
            if (!available) {
                reply.status = SealStatus::Unavailable;
                return reply;
            }
            const auto blob = decode_sealed_blob(text);
            if (!blob || blob->domain != domain ||
                std::string(blob->tpm_public.begin(), blob->tpm_public.end()) != owner_seed) {
                reply.status = SealStatus::Corrupt;
                return reply;
            }
            if (blob->pcr_digest != boot_pcr_digest(pcrs)) {
                reply.status = SealStatus::PolicyMismatch;
                return reply;
            }
            const auto aad = sealed_blob_aad(blob->domain, blob->pcr_digest, blob->tpm_public);
            crypto::SecureBuffer out(blob->ciphertext.size() - crypto::kAeadTagSize);
            unsigned long long n = 0;
            const auto k = key();
            if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                    out.data(), &n, nullptr, blob->ciphertext.data(), blob->ciphertext.size(),
                    aad.data(), aad.size(), blob->nonce.data(), k.data()) != 0) {
                reply.status = SealStatus::Corrupt;
                return reply;
            }
            reply.status = SealStatus::Ok;
            reply.plaintext = std::move(out);
            return reply;
        };
        return b;
    }
};

struct TempDir {
    TempDir() {
        path = fs::temp_directory_path() /
               ("nexus_sealed_" + std::to_string(::getpid()) + "_" +
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
        fs::remove_all(path);
        fs::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
    fs::path path;
};

std::vector<uint8_t> bytes_of(std::string_view text) {
    return {text.begin(), text.end()};
}

}  // namespace

// ---------------------------------------------------------------------------
// Policy math. Expected values come from tpm2_createpolicy --policy-pcr
// -l sha256:8,9, which runs TPM2_PolicyPCR in a trial session (swtpm 0.7,
// tpm2-tools 5.6). A simulator answer, recorded as a known answer.
// ---------------------------------------------------------------------------

TEST(SealPolicy, SelectionIsSha256Pcr8And9) {
    const std::vector<uint8_t> expected{0, 0, 0, 1, 0x00, 0x0B, 3, 0x00, 0x03, 0x00};
    EXPECT_EQ(boot_pcr_selection_wire(), expected);
}

TEST(SealPolicy, MatchesTheTpmTrialSessionForZeroPcrs) {
    EXPECT_EQ(crypto::to_hex(boot_pcr_policy_digest(boot_pcr_digest(pcrs_of(0, 0)))),
              "e2ca6425ece5aaa64a96ea8aff2b96fd2783a74e3358102f5455e275f6b48527");
}

TEST(SealPolicy, MatchesTheTpmTrialSessionForChosenPcrs) {
    EXPECT_EQ(crypto::to_hex(boot_pcr_policy_digest(boot_pcr_digest(pcrs_of(0x11, 0x22)))),
              "00429565dfc88ac9d07c58c958c656a5f9872106185b9ea88158086351063589");
}

TEST(SealPolicy, EachPcrChangesTheBinding) {
    const auto base = boot_pcr_digest(pcrs_of(0x11, 0x22));
    EXPECT_NE(base, boot_pcr_digest(pcrs_of(0x12, 0x22)));
    EXPECT_NE(base, boot_pcr_digest(pcrs_of(0x11, 0x23)));
    // Order matters: PCR 8 then PCR 9.
    EXPECT_NE(base, boot_pcr_digest(pcrs_of(0x22, 0x11)));
}

TEST(SealDomain, AcceptsRoleNamesOnly) {
    EXPECT_TRUE(valid_seal_domain("gossip-identity"));
    EXPECT_TRUE(valid_seal_domain("storage-share"));
    EXPECT_FALSE(valid_seal_domain(""));
    EXPECT_FALSE(valid_seal_domain("Gossip"));
    EXPECT_FALSE(valid_seal_domain("-lead"));
    EXPECT_FALSE(valid_seal_domain("9lead"));
    EXPECT_FALSE(valid_seal_domain("../escape"));
    EXPECT_FALSE(valid_seal_domain("a/b"));
    EXPECT_FALSE(valid_seal_domain(std::string(kMaxSealDomainBytes + 1, 'a')));
    EXPECT_TRUE(valid_seal_domain(std::string(kMaxSealDomainBytes, 'a')));
}

// ---------------------------------------------------------------------------
// Blob format
// ---------------------------------------------------------------------------

namespace {

SealedBlob sample_blob() {
    SealedBlob blob;
    blob.domain = "gossip-identity";
    blob.pcr_digest = boot_pcr_digest(pcrs_of(1, 2));
    blob.tpm_public = {0x00, 0x04, 1, 2, 3, 4};
    blob.tpm_private = {0x00, 0x02, 9, 9};
    blob.nonce.assign(crypto::kAeadNonceSize, 0x33);
    blob.ciphertext.assign(64 + crypto::kAeadTagSize, 0x44);
    return blob;
}

}  // namespace

TEST(SealedBlobFormat, RoundTrips) {
    const auto blob = sample_blob();
    const auto decoded = decode_sealed_blob(encode_sealed_blob(blob));
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->domain, blob.domain);
    EXPECT_EQ(decoded->pcr_digest, blob.pcr_digest);
    EXPECT_EQ(decoded->tpm_public, blob.tpm_public);
    EXPECT_EQ(decoded->tpm_private, blob.tpm_private);
    EXPECT_EQ(decoded->nonce, blob.nonce);
    EXPECT_EQ(decoded->ciphertext, blob.ciphertext);
}

TEST(SealedBlobFormat, RefusesEveryDeviation) {
    const json good = json::parse(encode_sealed_blob(sample_blob()));
    auto refuse = [](const json& j, const char* what) {
        EXPECT_FALSE(decode_sealed_blob(j.dump()).has_value()) << what;
    };
    {
        auto j = good;
        j["extra"] = 1;
        refuse(j, "unknown key");
    }
    {
        auto j = good;
        j.erase("nonce");
        refuse(j, "missing key");
    }
    {
        auto j = good;
        j["version"] = 2;
        refuse(j, "future version");
    }
    {
        auto j = good;
        j["pcrs"] = json::array({8, 9, 10});
        refuse(j, "a caller-chosen PCR selection");
    }
    {
        auto j = good;
        j["pcrs"] = json::array({9, 8});
        refuse(j, "reordered PCRs");
    }
    {
        auto j = good;
        j["pcr_bank"] = "sha1";
        refuse(j, "another bank");
    }
    {
        auto j = good;
        j["domain"] = "Not/A/Domain";
        refuse(j, "bad domain");
    }
    {
        auto j = good;
        j["pcr_digest"] = std::string(64, 'A');
        refuse(j, "uppercase digest");
    }
    {
        auto j = good;
        j["nonce"] = crypto::to_base64(std::vector<uint8_t>(12, 1));
        refuse(j, "short nonce");
    }
    {
        auto j = good;
        j["ciphertext"] = crypto::to_base64(std::vector<uint8_t>(crypto::kAeadTagSize, 1));
        refuse(j, "ciphertext without a body");
    }
    EXPECT_FALSE(decode_sealed_blob(std::string(kMaxSealedBlobBytes + 1, ' ')).has_value());
    EXPECT_FALSE(decode_sealed_blob("not json").has_value());
}

TEST(SealedBlobFormat, AadBindsDomainBindingAndObject) {
    const auto blob = sample_blob();
    const auto base = sealed_blob_aad(blob.domain, blob.pcr_digest, blob.tpm_public);
    EXPECT_NE(base, sealed_blob_aad("storage-share", blob.pcr_digest, blob.tpm_public));
    EXPECT_NE(base, sealed_blob_aad(blob.domain, boot_pcr_digest(pcrs_of(1, 3)),
                                    blob.tpm_public));
    auto other_public = blob.tpm_public;
    other_public.back() ^= 1;
    EXPECT_NE(base, sealed_blob_aad(blob.domain, blob.pcr_digest, other_public));
}

TEST(SealedBlobFormat, ReadsBootPcrsFromAQualifiedApprovalOnly) {
    ReleaseApprovalV1 approval;
    EXPECT_FALSE(boot_pcrs_from_approval(approval).has_value()) << "pending approval";
    approval.expected_pcrs = {{8, std::string(64, 'a')}, {9, std::string(64, 'b')}};
    const auto values = boot_pcrs_from_approval(approval);
    ASSERT_TRUE(values.has_value());
    EXPECT_EQ((*values)[0][0], 0xAA);
    EXPECT_EQ((*values)[1][31], 0xBB);
    approval.expected_pcrs = {{9, std::string(64, 'a')}, {8, std::string(64, 'b')}};
    EXPECT_FALSE(boot_pcrs_from_approval(approval).has_value()) << "wrong order";
    approval.expected_pcrs = {{8, std::string(64, 'A')}, {9, std::string(64, 'b')}};
    EXPECT_FALSE(boot_pcrs_from_approval(approval).has_value()) << "uppercase hex";
}

// ---------------------------------------------------------------------------
// SealedBlobStore
// ---------------------------------------------------------------------------

struct SealedStore : ::testing::Test {
    void SetUp() override { ASSERT_GE(sodium_init(), 0); }
    TempDir dir;
    FakeSealer tpm;
    const std::vector<uint8_t> secret = bytes_of("the storage share or the gossip key");
};

TEST_F(SealedStore, SealsAndUnsealsUnderAName) {
    SealedBlobStore store{dir.path / "sealed", tpm.backend()};
    ASSERT_EQ(store.seal("storage-share", secret).status, SealStatus::Ok);
    EXPECT_TRUE(fs::exists(store.current_path("storage-share")));
    EXPECT_FALSE(fs::exists(store.next_path("storage-share")));
#ifndef _WIN32
    EXPECT_EQ(fs::status(dir.path / "sealed").permissions(), fs::perms::owner_all);
    EXPECT_EQ(fs::status(store.current_path("storage-share")).permissions(),
              fs::perms::owner_read | fs::perms::owner_write);
#endif
    const auto out = store.unseal("storage-share");
    ASSERT_EQ(out.status, SealStatus::Ok);
    EXPECT_EQ(std::vector<uint8_t>(out.plaintext.span().begin(), out.plaintext.span().end()),
              secret);
}

TEST_F(SealedStore, ReportsMissingAndRefusesBadNames) {
    SealedBlobStore store{dir.path / "sealed", tpm.backend()};
    EXPECT_EQ(store.unseal("storage-share").status, SealStatus::Missing);
    EXPECT_NE(store.seal("../escape", secret).status, SealStatus::Ok);
    EXPECT_NE(store.unseal("../escape").status, SealStatus::Ok);
    EXPECT_FALSE(fs::exists(dir.path / "escape.sealed"));
}

TEST_F(SealedStore, AnEmptyBackendIsUnavailable) {
    SealedBlobStore store{dir.path / "sealed", SealBackend{}};
    EXPECT_FALSE(store.sealing_available());
    EXPECT_EQ(store.seal("storage-share", secret).status, SealStatus::Unavailable);
}

TEST_F(SealedStore, AChangedBootChainFailsClosedAndChangesNothing) {
    SealedBlobStore store{dir.path / "sealed", tpm.backend()};
    ASSERT_EQ(store.seal("storage-share", secret).status, SealStatus::Ok);
    const auto before = read_text(store.current_path("storage-share"));
    tpm.pcrs = pcrs_of(0x99, 0x22);
    const auto out = store.unseal("storage-share");
    EXPECT_EQ(out.status, SealStatus::PolicyMismatch);
    EXPECT_TRUE(out.plaintext.empty());
    EXPECT_EQ(read_text(store.current_path("storage-share")), before);
}

TEST_F(SealedStore, ABlobFromAnotherTpmIsCorrupt) {
    SealedBlobStore store{dir.path / "sealed", tpm.backend()};
    ASSERT_EQ(store.seal("storage-share", secret).status, SealStatus::Ok);
    tpm.owner_seed = "owner-seed-B";  // a cleared or re-manufactured vTPM
    EXPECT_EQ(store.unseal("storage-share").status, SealStatus::Corrupt);
}

TEST_F(SealedStore, ATamperedBlobIsCorrupt) {
    SealedBlobStore store{dir.path / "sealed", tpm.backend()};
    ASSERT_EQ(store.seal("storage-share", secret).status, SealStatus::Ok);
    auto j = json::parse(read_text(store.current_path("storage-share")));
    auto ct = crypto::from_base64(j["ciphertext"].get<std::string>());
    ct[0] ^= 0x01;
    j["ciphertext"] = crypto::to_base64(ct);
    write_text(store.current_path("storage-share"), j.dump());
    EXPECT_EQ(store.unseal("storage-share").status, SealStatus::Corrupt);
    write_text(store.current_path("storage-share"), "garbage");
    EXPECT_EQ(store.unseal("storage-share").status, SealStatus::Corrupt);
}

TEST_F(SealedStore, ABlobDoesNotUnsealUnderAnotherDomain) {
    SealedBlobStore store{dir.path / "sealed", tpm.backend()};
    ASSERT_EQ(store.seal("storage-share", secret).status, SealStatus::Ok);
    fs::copy_file(store.current_path("storage-share"), store.current_path("gossip-identity"));
    EXPECT_EQ(store.unseal("gossip-identity").status, SealStatus::Corrupt);
}

TEST_F(SealedStore, AnApprovedUpgradeIsStagedPromotedAndCleanedUp) {
    const auto next_chain = pcrs_of(0x33, 0x44);
    {
        SealedBlobStore store{dir.path / "sealed", tpm.backend()};
        ASSERT_EQ(store.seal("storage-share", secret).status, SealStatus::Ok);
    }
    // The new release is installed: its approval expects other PCR 8/9.
    {
        SealedBlobStore store{dir.path / "sealed", tpm.backend()};
        store.set_next_boot_chain(next_chain);
        ASSERT_EQ(store.unseal("storage-share").status, SealStatus::Ok);
        ASSERT_TRUE(fs::exists(store.next_path("storage-share")));
        const auto staged = decode_sealed_blob(read_text(store.next_path("storage-share")));
        ASSERT_TRUE(staged.has_value());
        EXPECT_EQ(staged->pcr_digest, boot_pcr_digest(next_chain));
        // A second start stages nothing new.
        const int seals = tpm.seal_calls;
        ASSERT_EQ(store.unseal("storage-share").status, SealStatus::Ok);
        EXPECT_EQ(tpm.seal_calls, seals);
    }
    // Reboot into the new chain.
    tpm.pcrs = next_chain;
    {
        SealedBlobStore store{dir.path / "sealed", tpm.backend()};
        store.set_next_boot_chain(next_chain);
        const auto out = store.unseal("storage-share");
        ASSERT_EQ(out.status, SealStatus::Ok);
        EXPECT_EQ(std::vector<uint8_t>(out.plaintext.span().begin(), out.plaintext.span().end()),
                  secret);
        const auto current = decode_sealed_blob(read_text(store.current_path("storage-share")));
        ASSERT_TRUE(current.has_value());
        EXPECT_EQ(current->pcr_digest, boot_pcr_digest(next_chain));
        EXPECT_FALSE(fs::exists(store.next_path("storage-share")));
    }
    // The next start unseals the promoted blob directly.
    {
        SealedBlobStore store{dir.path / "sealed", tpm.backend()};
        const int unseals = tpm.unseal_calls;
        ASSERT_EQ(store.unseal("storage-share").status, SealStatus::Ok);
        EXPECT_EQ(tpm.unseal_calls, unseals + 1);
    }
}

TEST_F(SealedStore, BootingBackIntoTheOldChainStillUnsealsBeforePromotion) {
    const auto old_chain = tpm.pcrs;
    SealedBlobStore store{dir.path / "sealed", tpm.backend()};
    store.set_next_boot_chain(pcrs_of(0x33, 0x44));
    ASSERT_EQ(store.seal("storage-share", secret).status, SealStatus::Ok);
    ASSERT_TRUE(fs::exists(store.next_path("storage-share")));
    // The new chain never booted (an operator rolled back): the current blob
    // still works and the staged one is kept.
    tpm.pcrs = old_chain;
    EXPECT_EQ(store.unseal("storage-share").status, SealStatus::Ok);
    EXPECT_TRUE(fs::exists(store.next_path("storage-share")));
}

TEST_F(SealedStore, AnApprovalForTheRunningChainStagesNothing) {
    SealedBlobStore store{dir.path / "sealed", tpm.backend()};
    store.set_next_boot_chain(tpm.pcrs);
    ASSERT_EQ(store.seal("storage-share", secret).status, SealStatus::Ok);
    EXPECT_FALSE(fs::exists(store.next_path("storage-share")));
}

TEST_F(SealedStore, AnUnexpectedBootChainUnsealsNeitherSlot) {
    SealedBlobStore store{dir.path / "sealed", tpm.backend()};
    store.set_next_boot_chain(pcrs_of(0x33, 0x44));
    ASSERT_EQ(store.seal("storage-share", secret).status, SealStatus::Ok);
    tpm.pcrs = pcrs_of(0x55, 0x66);
    EXPECT_EQ(store.unseal("storage-share").status, SealStatus::PolicyMismatch);
    EXPECT_TRUE(fs::exists(store.current_path("storage-share")));
    EXPECT_TRUE(fs::exists(store.next_path("storage-share")));
}

TEST_F(SealedStore, ACorruptCurrentBlobRecoversFromTheStagedOne) {
    SealedBlobStore store{dir.path / "sealed", tpm.backend()};
    store.set_next_boot_chain(pcrs_of(0x33, 0x44));
    ASSERT_EQ(store.seal("storage-share", secret).status, SealStatus::Ok);
    write_text(store.current_path("storage-share"), "garbage");
    tpm.pcrs = pcrs_of(0x33, 0x44);
    EXPECT_EQ(store.unseal("storage-share").status, SealStatus::Ok);
    EXPECT_FALSE(fs::exists(store.next_path("storage-share")));
}

TEST_F(SealedStore, AnUnreachableDaemonTriesNothingElse) {
    SealedBlobStore store{dir.path / "sealed", tpm.backend()};
    store.set_next_boot_chain(pcrs_of(0x33, 0x44));
    ASSERT_EQ(store.seal("storage-share", secret).status, SealStatus::Ok);
    tpm.reachable = false;
    const int calls = tpm.unseal_calls;
    EXPECT_EQ(store.unseal("storage-share").status, SealStatus::Unreachable);
    EXPECT_EQ(tpm.unseal_calls, calls + 1);
}

TEST_F(SealedStore, SealingANewSecretReplacesTheStagedCopy) {
    SealedBlobStore store{dir.path / "sealed", tpm.backend()};
    store.set_next_boot_chain(pcrs_of(0x33, 0x44));
    ASSERT_EQ(store.seal("storage-share", secret).status, SealStatus::Ok);
    const auto refreshed = bytes_of("a refreshed share");
    ASSERT_EQ(store.seal("storage-share", refreshed).status, SealStatus::Ok);
    tpm.pcrs = pcrs_of(0x33, 0x44);
    const auto out = store.unseal("storage-share");
    ASSERT_EQ(out.status, SealStatus::Ok);
    EXPECT_EQ(std::vector<uint8_t>(out.plaintext.span().begin(), out.plaintext.span().end()),
              refreshed);
}

TEST_F(SealedStore, WithoutAKnownNextChainSealingDropsAStaleStagedCopy) {
    SealedBlobStore store{dir.path / "sealed", tpm.backend()};
    store.set_next_boot_chain(pcrs_of(0x33, 0x44));
    ASSERT_EQ(store.seal("storage-share", secret).status, SealStatus::Ok);
    store.set_next_boot_chain(std::nullopt);
    ASSERT_EQ(store.seal("storage-share", bytes_of("new")).status, SealStatus::Ok);
    EXPECT_FALSE(fs::exists(store.next_path("storage-share")));
}

// ---------------------------------------------------------------------------
// Boot set: the gossip identity and its one-way migration
// ---------------------------------------------------------------------------

struct BootSet : ::testing::Test {
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        storage.emplace(dir.path);
        storage->start();
    }
    void TearDown() override {
        if (storage) storage->stop();
    }

    core::BootSetConfig config(bool with_backend = true) {
        core::BootSetConfig c;
        c.data_root = dir.path;
        if (with_backend) c.backend = tpm.backend();
        c.boot_id = [this] { return boot; };
        c.retry_delay = std::chrono::milliseconds(1);
        c.unreachable_attempts = 3;
        return c;
    }

    std::optional<core::GossipIdentity> load(const core::BootSetConfig& c) {
        error.clear();
        return core::load_gossip_identity(*storage, c, error);
    }

    fs::path legacy() const { return dir.path / "identity" / "keypair.json"; }
    fs::path blob() const { return dir.path / "sealed" / "gossip-identity.sealed"; }
    fs::path next_blob() const { return dir.path / "sealed" / "gossip-identity.next.sealed"; }
    fs::path state() const { return dir.path / "sealed" / "gossip-identity.state.json"; }

    /// Run the migration to completion: seal in one boot, unseal in the next.
    crypto::Ed25519Keypair sealed_identity() {
        const auto first = load(config());
        EXPECT_TRUE(first) << error;
        boot = "boot-2";
        const auto second = load(config());
        EXPECT_TRUE(second) << error;
        EXPECT_EQ(second->protection, core::GossipIdentityProtection::Sealed);
        return second ? second->keypair : crypto::Ed25519Keypair{};
    }

    TempDir dir;
    FakeSealer tpm;
    std::string boot = "boot-1";
    std::optional<nexus::storage::FileStorageService> storage;
    std::string error;
};

TEST_F(BootSet, WithoutSealingTheIdentityStaysInTheLegacyFile) {
    const auto id = load(config(false));
    ASSERT_TRUE(id) << error;
    EXPECT_TRUE(id->created);
    EXPECT_EQ(id->protection, core::GossipIdentityProtection::LegacyFile);
    EXPECT_TRUE(fs::exists(legacy()));
    EXPECT_FALSE(fs::exists(blob()));
    const auto again = load(config(false));
    ASSERT_TRUE(again) << error;
    EXPECT_FALSE(again->created);
    EXPECT_EQ(again->keypair.public_key, id->keypair.public_key);
}

TEST_F(BootSet, AHostThatCannotSealKeepsTheLegacyFile) {
    tpm.available = false;
    const auto id = load(config());
    ASSERT_TRUE(id) << error;
    EXPECT_EQ(id->protection, core::GossipIdentityProtection::LegacyFile);
    EXPECT_TRUE(fs::exists(legacy()));
    EXPECT_FALSE(fs::exists(blob()));
    EXPECT_FALSE(fs::exists(state()));
}

TEST_F(BootSet, TheLegacyFileIsKeptUntilALaterBootUnsealsTheSealedCopy) {
    const auto first = load(config());
    ASSERT_TRUE(first) << error;
    EXPECT_EQ(first->protection, core::GossipIdentityProtection::SealedPending);
    EXPECT_TRUE(fs::exists(legacy()));
    EXPECT_TRUE(fs::exists(blob()));

    // A restart in the same boot proves nothing about the vTPM keeping its seed.
    const auto restart = load(config());
    ASSERT_TRUE(restart) << error;
    EXPECT_EQ(restart->protection, core::GossipIdentityProtection::SealedPending);
    EXPECT_TRUE(fs::exists(legacy()));

    boot = "boot-2";
    const auto rebooted = load(config());
    ASSERT_TRUE(rebooted) << error;
    EXPECT_EQ(rebooted->protection, core::GossipIdentityProtection::Sealed);
    EXPECT_EQ(rebooted->keypair.public_key, first->keypair.public_key);
    EXPECT_EQ(rebooted->keypair.private_key, first->keypair.private_key);
    EXPECT_FALSE(fs::exists(legacy()));

    const auto after = load(config());
    ASSERT_TRUE(after) << error;
    EXPECT_EQ(after->protection, core::GossipIdentityProtection::Sealed);
    EXPECT_EQ(after->keypair.public_key, first->keypair.public_key);
}

TEST_F(BootSet, AnExistingLegacyIdentityIsMigratedNotReplaced) {
    const auto plain = load(config(false));
    ASSERT_TRUE(plain) << error;
    const auto migrated = load(config());
    ASSERT_TRUE(migrated) << error;
    EXPECT_FALSE(migrated->created);
    EXPECT_EQ(migrated->protection, core::GossipIdentityProtection::SealedPending);
    EXPECT_EQ(migrated->keypair.public_key, plain->keypair.public_key);
}

TEST_F(BootSet, AnUnknownBootIdNeverFinishesTheMigration) {
    boot.clear();
    ASSERT_TRUE(load(config())) << error;
    const auto again = load(config());
    ASSERT_TRUE(again) << error;
    EXPECT_EQ(again->protection, core::GossipIdentityProtection::SealedPending);
    EXPECT_TRUE(fs::exists(legacy()));
}

TEST_F(BootSet, AVtpmThatLosesItsSeedAtRebootKeepsTheLegacyFile) {
    const auto first = load(config());
    ASSERT_TRUE(first) << error;
    tpm.owner_seed = "owner-seed-after-reboot";  // an ephemeral vTPM
    boot = "boot-2";
    const auto rebooted = load(config());
    ASSERT_TRUE(rebooted) << error;
    EXPECT_EQ(rebooted->keypair.public_key, first->keypair.public_key);
    EXPECT_EQ(rebooted->protection, core::GossipIdentityProtection::SealedPending);
    EXPECT_TRUE(fs::exists(legacy()));
}

TEST_F(BootSet, PcrsChangedWhilePendingFallsBackAndReseals) {
    const auto first = load(config());
    ASSERT_TRUE(first) << error;
    tpm.pcrs = pcrs_of(0x77, 0x88);
    const auto again = load(config());
    ASSERT_TRUE(again) << error;
    EXPECT_EQ(again->keypair.public_key, first->keypair.public_key);
    EXPECT_EQ(again->protection, core::GossipIdentityProtection::SealedPending);
    const auto rebound = decode_sealed_blob(read_text(blob()));
    ASSERT_TRUE(rebound);
    EXPECT_EQ(rebound->pcr_digest, boot_pcr_digest(tpm.pcrs));
}

TEST_F(BootSet, RestartWithMatchingPcrsUnsealsTheSameKey) {
    const auto key = sealed_identity();
    for (int i = 0; i < 3; ++i) {
        const auto id = load(config());
        ASSERT_TRUE(id) << error;
        EXPECT_EQ(id->keypair.public_key, key.public_key);
        EXPECT_EQ(id->keypair.private_key, key.private_key);
        EXPECT_FALSE(id->created);
    }
}

TEST_F(BootSet, ChangedPcrsAfterMigrationStopStartupAndKeepTheBlob) {
    sealed_identity();
    const auto before = read_text(blob());
    tpm.pcrs = pcrs_of(0x77, 0x88);
    EXPECT_FALSE(load(config()));
    EXPECT_NE(error.find("PCR 8/9"), std::string::npos) << error;
    EXPECT_NE(error.find("previous boot entry"), std::string::npos) << error;
    EXPECT_EQ(read_text(blob()), before);
    EXPECT_FALSE(fs::exists(legacy())) << "no new identity may appear";
}

TEST_F(BootSet, ACorruptBlobAfterMigrationStopsStartup) {
    sealed_identity();
    write_text(blob(), "{\"damaged\":true}");
    EXPECT_FALSE(load(config()));
    EXPECT_NE(error.find("Restore"), std::string::npos) << error;
    EXPECT_FALSE(fs::exists(legacy()));
}

TEST_F(BootSet, AMissingBlobAfterMigrationStopsStartup) {
    sealed_identity();
    fs::remove(blob());
    EXPECT_FALSE(load(config()));
    EXPECT_NE(error.find("missing"), std::string::npos) << error;
    EXPECT_FALSE(fs::exists(legacy())) << "no new identity may appear";
}

TEST_F(BootSet, AMissingBlobWhilePendingFallsBackToTheLegacyFile) {
    const auto first = load(config());
    ASSERT_TRUE(first) << error;
    fs::remove(blob());
    const auto again = load(config());
    ASSERT_TRUE(again) << error;
    EXPECT_EQ(again->keypair.public_key, first->keypair.public_key);
    EXPECT_TRUE(fs::exists(blob())) << "sealed again";
}

TEST_F(BootSet, AStateFileWithNoKeyAnywhereStopsStartup) {
    const auto first = load(config());
    ASSERT_TRUE(first) << error;
    fs::remove(blob());
    fs::remove(legacy());
    EXPECT_FALSE(load(config()));
    EXPECT_FALSE(fs::exists(legacy())) << "no new identity may appear";
}

TEST_F(BootSet, AnUnreachableDaemonAfterMigrationRetriesThenStops) {
    sealed_identity();
    tpm.reachable = false;
    const int calls = tpm.unseal_calls;
    EXPECT_FALSE(load(config()));
    EXPECT_EQ(tpm.unseal_calls, calls + 3);
    EXPECT_NE(error.find("nexus-attestd"), std::string::npos) << error;
    EXPECT_FALSE(fs::exists(legacy()));
}

TEST_F(BootSet, ABuildWithoutSealingCannotOpenASealedIdentity) {
    sealed_identity();
    EXPECT_FALSE(load(config(false)));
    EXPECT_FALSE(fs::exists(legacy()));
}

TEST_F(BootSet, ALegacyFileThatDisagreesWithTheSealedCopyStopsStartup) {
    ASSERT_TRUE(load(config())) << error;
    // Replace keypair.json with another valid key.
    crypto::Ed25519Keypair other;
    crypto_sign_ed25519_keypair(other.public_key.data(), other.private_key.data());
    nexus::storage::SignedEnvelope env;
    json kp;
    kp["public_key"] = crypto::to_base64(other.public_key);
    kp["private_key"] = crypto::to_base64(other.private_key);
    env.data = kp.dump();
    ASSERT_TRUE(storage->write_file("identity", "keypair.json", env));
    EXPECT_FALSE(load(config()));
    EXPECT_NE(error.find("different key"), std::string::npos) << error;
}

TEST_F(BootSet, AnUnreadableLegacyFileIsNotReplaced) {
    std::error_code ec;
    fs::create_directories(legacy().parent_path(), ec);
    write_text(legacy(), "{not json");
    EXPECT_FALSE(load(config()));
    EXPECT_EQ(read_text(legacy()), "{not json");
    EXPECT_FALSE(fs::exists(blob()));
}

TEST_F(BootSet, ALegacyKeyWhoseHalvesDisagreeIsRefused) {
    crypto::Ed25519Keypair a;
    crypto::Ed25519Keypair b;
    crypto_sign_ed25519_keypair(a.public_key.data(), a.private_key.data());
    crypto_sign_ed25519_keypair(b.public_key.data(), b.private_key.data());
    nexus::storage::SignedEnvelope env;
    json kp;
    kp["public_key"] = crypto::to_base64(b.public_key);
    kp["private_key"] = crypto::to_base64(a.private_key);
    env.data = kp.dump();
    ASSERT_TRUE(storage->write_file("identity", "keypair.json", env));
    EXPECT_FALSE(load(config()));
}

TEST_F(BootSet, AnUpgradeWithAnApprovedBootChainKeepsTheIdentity) {
    const auto key = sealed_identity();
    const auto next_chain = pcrs_of(0x33, 0x44);
    // New release installed, old boot chain still running.
    auto c = config();
    c.next_boot_chain = next_chain;
    ASSERT_TRUE(load(c)) << error;
    EXPECT_TRUE(fs::exists(next_blob()));
    // Reboot into the new chain.
    tpm.pcrs = next_chain;
    boot = "boot-3";
    const auto upgraded = load(c);
    ASSERT_TRUE(upgraded) << error;
    EXPECT_EQ(upgraded->keypair.public_key, key.public_key);
    EXPECT_EQ(upgraded->protection, core::GossipIdentityProtection::Sealed);
    EXPECT_FALSE(fs::exists(next_blob()));
    const auto rebound = decode_sealed_blob(read_text(blob()));
    ASSERT_TRUE(rebound);
    EXPECT_EQ(rebound->pcr_digest, boot_pcr_digest(next_chain));
}

TEST_F(BootSet, ABinaryOnlyUpgradeNeedsNoReseal) {
    const auto key = sealed_identity();
    auto c = config();
    c.next_boot_chain = tpm.pcrs;  // the approval pins the running PCR 8/9
    const int seals = tpm.seal_calls;
    const auto id = load(c);
    ASSERT_TRUE(id) << error;
    EXPECT_EQ(id->keypair.public_key, key.public_key);
    EXPECT_EQ(tpm.seal_calls, seals);
    EXPECT_FALSE(fs::exists(next_blob()));
}

TEST_F(BootSet, ThePublicKeyIsReadableWithoutUnsealing) {
    const auto key = sealed_identity();
    const auto pub = core::gossip_public_key_b64(*storage, dir.path);
    ASSERT_TRUE(pub);
    EXPECT_EQ(*pub, crypto::to_base64(key.public_key));
}

TEST_F(BootSet, CreateIfAbsentFalseNeverCreates) {
    auto c = config();
    c.create_if_absent = false;
    EXPECT_FALSE(load(c));
    EXPECT_FALSE(fs::exists(legacy()));
}
