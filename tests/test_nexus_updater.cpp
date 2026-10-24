// nexus-updater: release verification, provenance, the file swap, the OS
// package plan, the health gate, and whole update cycles. GitHub, the server
// socket, and host commands are fakes; the provenance cases use a real public
// Sigstore bundle (tests/fixtures/sigstore) against the pinned trusted root.

#include <LemonadeNexusUpdater/FileSwap.hpp>
#include <LemonadeNexusUpdater/HealthGate.hpp>
#include <LemonadeNexusUpdater/OsPackages.hpp>
#include <LemonadeNexusUpdater/ReleaseTag.hpp>
#include <LemonadeNexusUpdater/ReleaseVerifier.hpp>
#include <LemonadeNexusUpdater/SigstoreVerifier.hpp>
#include <LemonadeNexusUpdater/Transport.hpp>
#include <LemonadeNexusUpdater/Updater.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseApproval.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseBundleGenerator.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Update/UpdateControl.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <random>
#include <set>

namespace {

namespace fs = std::filesystem;
using namespace nexus;
using namespace nexus::updater;
using json = nlohmann::json;

constexpr const char* kRepo = "lemonade-sdk/lemonade-nexus";

std::string read_text(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void write_text(const fs::path& p, std::string_view text) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out << text;
}

struct TempDir {
    fs::path path;
    TempDir() {
        std::random_device rd;
        path = fs::temp_directory_path() /
               ("nexus-updater-test-" + std::to_string(rd()) + std::to_string(rd()));
        fs::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

std::string pcr_hex(char c) { return std::string(64, c); }

// ---------------------------------------------------------------------------
// Keys and signed release objects
// ---------------------------------------------------------------------------

struct Keys {
    crypto::Ed25519PublicKey genesis_pk{};
    crypto::Ed25519PrivateKey genesis_sk{};
    crypto::Ed25519PublicKey release_pk{};
    crypto::Ed25519PrivateKey release_sk{};
    security::NetworkId network{};

    Keys() {
        EXPECT_GE(sodium_init(), 0);
        crypto_sign_keypair(genesis_pk.data(), genesis_sk.data());
        crypto_sign_keypair(release_pk.data(), release_sk.data());
        network = security::derive_network_id(genesis_pk, security::constants::kSecurityRulesetVersion,
                                              security::constants::kConsensusRulesetVersion);
    }

    [[nodiscard]] ReleaseTrust trust() const {
        return {genesis_pk, network, kRepo};
    }
};

std::string sign_b64(const crypto::Ed25519PrivateKey& sk, std::string_view message) {
    std::array<unsigned char, crypto_sign_BYTES> sig{};
    crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<const unsigned char*>(message.data()),
                         message.size(), sk.data());
    return crypto::to_base64(sig);
}

struct ApprovalSpec {
    std::string tag;
    std::vector<security::ApprovedPath> paths;
    std::string pcr8 = pcr_hex('8');
    std::string pcr9 = pcr_hex('9');
};

/// A signed release-approval bundle, as release.yml publishes it.
std::string signed_approval(const Keys& k, const ApprovalSpec& spec,
                            const crypto::Ed25519PrivateKey* release_sk = nullptr,
                            const security::NetworkId* network = nullptr) {
    auto a = security::release_approval_template();
    a.release_id = spec.tag;
    a.nexus_version = spec.tag.substr(1);
    a.final_patched_tree = std::string(40, 'a');
    a.network_id_hex = crypto::to_hex(network ? *network : k.network);
    a.signer_pubkey_b64 = crypto::to_base64(k.release_pk);
    a.qualification_state = "LIVE_BOOT_APPROVED";
    a.expected_pcrs = {{8, spec.pcr8}, {9, spec.pcr9}};
    a.approved_paths = spec.paths;
    security::ReleaseAuthorityV1 authority;
    authority.network_id_hex = a.network_id_hex;
    authority.release_signing_pubkey_b64 = a.signer_pubkey_b64;
    auto root = json::parse(security::unsigned_release_bundle_json(a));
    root["authority"]["genesis_signature"] =
        sign_b64(k.genesis_sk, security::canonical_release_authority_json(authority));
    root["approval"]["signature"] = sign_b64(release_sk ? *release_sk : k.release_sk,
                                             security::canonical_release_approval_json(a));
    return root.dump(2);
}

std::string approval_digest(std::string_view bundle_json) {
    std::string error;
    const auto b = security::parse_release_approval_bundle(bundle_json, error);
    return b ? security::release_approval_digest_hex(b->approval) : std::string();
}

struct ReleaseFiles {
    std::string tag;
    std::string nexus_bin;
    std::string attestd_bin;
    std::string lock;
    std::string approval;
    std::string manifest;
    std::string signature;
    bool boot_chain_changed = false;
};

std::string manifest_for(const ReleaseFiles& r, uint64_t number) {
    json m = {
        {"format_version", 1},
        {"repository", kRepo},
        {"tag", r.tag},
        {"version", r.tag.substr(1)},
        {"release_number", number},
        {"source_commit", std::string(40, 'c')},
        {"approval",
         {{"asset", "release-approval.json"},
          {"sha256", sha256_hex(r.approval)},
          {"digest", approval_digest(r.approval)}}},
        {"server_files",
         json::array({{{"asset", "lemonade-nexus-linux-x86_64"},
                       {"path", "/usr/bin/lemonade-nexus"},
                       {"sha256", sha256_hex(r.nexus_bin)}},
                      {{"asset", "nexus-attestd-linux-x86_64"},
                       {"path", "/usr/bin/nexus-attestd"},
                       {"sha256", sha256_hex(r.attestd_bin)}}})},
        {"os_packages",
         {{"asset", "os-packages.lock"},
          {"sha256", sha256_hex(r.lock)},
          {"boot_chain_changed", r.boot_chain_changed}}},
        {"artifacts", json::array()},
    };
    return m.dump(2);
}

std::string sign_manifest(const crypto::Ed25519PrivateKey& sk, std::string_view manifest) {
    std::string preimage(kManifestSignatureDomain);
    preimage.append(manifest);
    return sign_b64(sk, preimage);
}

/// A complete, correctly signed release built from binary contents.
ReleaseFiles make_release(const Keys& k, const std::string& tag, const std::string& nexus_bin,
                          const std::string& attestd_bin, const std::string& lock,
                          const std::vector<std::string>& previous_nexus = {},
                          const std::vector<std::string>& previous_attestd = {},
                          char pcr = '8') {
    ReleaseFiles r;
    r.tag = tag;
    r.nexus_bin = nexus_bin;
    r.attestd_bin = attestd_bin;
    r.lock = lock;
    ApprovalSpec spec;
    spec.tag = tag;
    spec.pcr8 = pcr_hex(pcr);
    std::vector<std::string> nexus_hashes{sha256_hex(nexus_bin)};
    nexus_hashes.insert(nexus_hashes.end(), previous_nexus.begin(), previous_nexus.end());
    std::vector<std::string> attestd_hashes{sha256_hex(attestd_bin)};
    attestd_hashes.insert(attestd_hashes.end(), previous_attestd.begin(), previous_attestd.end());
    spec.paths = {{"/usr/bin/lemonade-nexus", nexus_hashes},
                  {"/usr/bin/nexus-attestd", attestd_hashes}};
    r.approval = signed_approval(k, spec);
    const auto number = parse_release_tag(tag)->number;
    r.manifest = manifest_for(r, number);
    r.signature = sign_manifest(k.release_sk, r.manifest);
    return r;
}

const std::string kEmptyLock = "format 1\n";

// ---------------------------------------------------------------------------
// Release tags
// ---------------------------------------------------------------------------

TEST(ReleaseTag, ParsesTheDateFormAndDerivesTheNumber) {
    const auto a = parse_release_tag("v2026.10.24");
    ASSERT_TRUE(a);
    EXPECT_EQ(a->number, 2026102401u);
    const auto b = parse_release_tag("v2026.10.24.2");
    ASSERT_TRUE(b);
    EXPECT_EQ(b->number, 2026102402u);
    EXPECT_EQ(parse_release_tag("v2026.10.24.99")->number, 2026102499u);
    EXPECT_GT(parse_release_tag("v2026.10.25")->number, b->number);
    EXPECT_EQ(format_release_tag(2026, 10, 24, 1), "v2026.10.24");
    EXPECT_EQ(format_release_tag(2026, 10, 24, 3), "v2026.10.24.3");
}

TEST(ReleaseTag, RefusesNonCanonicalTags) {
    for (const char* bad : {"2026.10.24", "v2026.10.24.1", "v2026.10.24.02", "v2026.10.24.100",
                            "v2026.02.30", "v2026.13.01", "v26.10.24", "v2026.10.24-alpha",
                            "v0.9.8-tier1-svsm-epoch1-r21", "v2026.1.24"}) {
        EXPECT_FALSE(parse_release_tag(bad)) << bad;
    }
}

// ---------------------------------------------------------------------------
// Approval and manifest verification
// ---------------------------------------------------------------------------

struct VerifyFixture : ::testing::Test {
    Keys keys;
    ReleaseFiles release = make_release(keys, "v2026.10.24", "nexus-new", "attestd-new", kEmptyLock);
    std::string error;

    std::optional<VerifiedRelease> verify(uint64_t installed = 2026100101) {
        return verify_release_metadata(keys.trust(), release.manifest, release.signature,
                                       release.approval, installed, error);
    }
};

TEST_F(VerifyFixture, AcceptsACorrectlySignedRelease) {
    const auto v = verify();
    ASSERT_TRUE(v) << error;
    EXPECT_EQ(v->tag.number, 2026102401u);
    EXPECT_EQ(v->manifest.server_files.size(), 2u);
}

TEST_F(VerifyFixture, RefusesAForgedApprovalSignature) {
    crypto::Ed25519PublicKey pk{};
    crypto::Ed25519PrivateKey other{};
    crypto_sign_keypair(pk.data(), other.data());
    ApprovalSpec spec;
    spec.tag = release.tag;
    spec.paths = {{"/usr/bin/lemonade-nexus", {sha256_hex(release.nexus_bin)}},
                  {"/usr/bin/nexus-attestd", {sha256_hex(release.attestd_bin)}}};
    release.approval = signed_approval(keys, spec, &other);
    release.manifest = manifest_for(release, 2026102401);
    release.signature = sign_manifest(keys.release_sk, release.manifest);
    EXPECT_FALSE(verify());
    EXPECT_NE(error.find("signature is invalid"), std::string::npos) << error;
}

TEST_F(VerifyFixture, RefusesAForgedManifestSignature) {
    crypto::Ed25519PublicKey pk{};
    crypto::Ed25519PrivateKey other{};
    crypto_sign_keypair(pk.data(), other.data());
    release.signature = sign_manifest(other, release.manifest);
    EXPECT_FALSE(verify());
    EXPECT_NE(error.find("manifest signature"), std::string::npos) << error;
}

TEST_F(VerifyFixture, RefusesAManifestSignedWithoutTheDomain) {
    release.signature = sign_b64(keys.release_sk, release.manifest);
    EXPECT_FALSE(verify());
}

TEST_F(VerifyFixture, RefusesAWrongNetwork) {
    security::NetworkId other{};
    other.fill(0x42);
    ApprovalSpec spec;
    spec.tag = release.tag;
    spec.paths = {{"/usr/bin/lemonade-nexus", {sha256_hex(release.nexus_bin)}},
                  {"/usr/bin/nexus-attestd", {sha256_hex(release.attestd_bin)}}};
    release.approval = signed_approval(keys, spec, nullptr, &other);
    EXPECT_FALSE(verify());
    EXPECT_NE(error.find("not delegated for this network"), std::string::npos) << error;

    // The same release under another Genesis anchor is refused too.
    Keys stranger;
    release = make_release(keys, "v2026.10.24", "nexus-new", "attestd-new", kEmptyLock);
    EXPECT_FALSE(verify_release_metadata(stranger.trust(), release.manifest, release.signature,
                                         release.approval, 0, error));
}

TEST_F(VerifyFixture, RefusesAnEqualOrLowerReleaseNumber) {
    EXPECT_FALSE(verify(2026102401));
    EXPECT_NE(error.find("not newer"), std::string::npos) << error;
    EXPECT_FALSE(verify(2026102402));
    EXPECT_TRUE(verify(2026102399 - 99));
}

TEST_F(VerifyFixture, RefusesANonDateReleaseId) {
    release = make_release(keys, "v2026.10.24", "n", "a", kEmptyLock);
    ApprovalSpec spec;
    spec.tag = "v0.9.8-tier1-svsm-epoch1-r21";
    spec.paths = {{"/usr/bin/lemonade-nexus", {sha256_hex("n")}},
                  {"/usr/bin/nexus-attestd", {sha256_hex("a")}}};
    release.approval = signed_approval(keys, spec);
    EXPECT_FALSE(verify(0));
    EXPECT_NE(error.find("not a release tag"), std::string::npos) << error;
}

TEST_F(VerifyFixture, RefusesAHashMismatch) {
    const auto v = verify();
    ASSERT_TRUE(v) << error;
    EXPECT_TRUE(verify_asset_hash(*v, "lemonade-nexus-linux-x86_64", sha256_hex("nexus-new"), error));
    EXPECT_FALSE(verify_asset_hash(*v, "lemonade-nexus-linux-x86_64", sha256_hex("nexus-evil"), error));
    EXPECT_NE(error.find("signed manifest lists"), std::string::npos);
    EXPECT_FALSE(verify_asset_hash(*v, "os-packages.lock", sha256_hex("format 1\npackage x 1 boot\n"), error));
    EXPECT_FALSE(verify_asset_hash(*v, "unlisted-asset", sha256_hex("x"), error));
}

TEST_F(VerifyFixture, RefusesAManifestHashTheApprovalDoesNotList) {
    // A manifest signed by the release key cannot point a path at bytes the
    // approval does not approve as the newest build.
    auto m = json::parse(release.manifest);
    m["server_files"][0]["sha256"] = sha256_hex("nexus-other");
    release.manifest = m.dump(2);
    release.signature = sign_manifest(keys.release_sk, release.manifest);
    EXPECT_FALSE(verify());
    EXPECT_NE(error.find("does not list"), std::string::npos) << error;
}

TEST_F(VerifyFixture, RefusesAManifestForAnotherRepositoryOrPath) {
    auto m = json::parse(release.manifest);
    m["repository"] = "someone/else";
    release.manifest = m.dump(2);
    release.signature = sign_manifest(keys.release_sk, release.manifest);
    EXPECT_FALSE(verify());

    m["repository"] = kRepo;
    m["server_files"][0]["path"] = "/usr/bin/sudo";
    release.manifest = m.dump(2);
    release.signature = sign_manifest(keys.release_sk, release.manifest);
    EXPECT_FALSE(verify());
    EXPECT_NE(error.find("does not replace"), std::string::npos) << error;

    m["server_files"][0]["path"] = "/usr/bin/lemonade-nexus";
    m["server_files"][0]["asset"] = "../../etc/shadow";
    release.manifest = m.dump(2);
    release.signature = sign_manifest(keys.release_sk, release.manifest);
    EXPECT_FALSE(verify());
}

// ---------------------------------------------------------------------------
// Sigstore provenance (real public bundle: cli/cli v2.103.2, built by
// .github/workflows/deployment.yml on refs/heads/trunk)
// ---------------------------------------------------------------------------

struct ProvenanceFixture : ::testing::Test {
    std::string bundle = read_text(fs::path(NEXUS_TEST_FIXTURE_DIR) / "sigstore" /
                                   "gh-cli-v2.103.2-provenance.sigstore.json");
    std::string root_text = read_text(fs::path(NEXUS_SOURCE_DIR) / "release" /
                                      "sigstore-trusted-root.json");
    std::optional<SigstoreTrustedRoot> root;
    ProvenancePolicy policy{"cli/cli", ".github/workflows/deployment.yml", "refs/heads/trunk"};
    const std::string digest = "62ccf747115ddc61237efffdde66a3c8f70ba249433dc64f70801089b59c59c8";
    std::string error;

    void SetUp() override {
        ASSERT_FALSE(bundle.empty());
        root = parse_sigstore_trusted_root(root_text, error);
        ASSERT_TRUE(root) << error;
    }
};

TEST_F(ProvenanceFixture, AcceptsTheExpectedIdentity) {
    EXPECT_TRUE(verify_provenance_bundle(*root, bundle, digest, policy, error)) << error;
}

TEST_F(ProvenanceFixture, RefusesAWrongRepository) {
    policy.repository = "cli/cli-fork";
    EXPECT_FALSE(verify_provenance_bundle(*root, bundle, digest, policy, error));
    EXPECT_NE(error.find("source repository"), std::string::npos) << error;
}

TEST_F(ProvenanceFixture, RefusesAWrongWorkflow) {
    policy.workflow_path = ".github/workflows/release.yml";
    EXPECT_FALSE(verify_provenance_bundle(*root, bundle, digest, policy, error));
    EXPECT_NE(error.find("workflow"), std::string::npos) << error;
}

TEST_F(ProvenanceFixture, RefusesAWrongRef) {
    policy.ref = "refs/heads/main";
    EXPECT_FALSE(verify_provenance_bundle(*root, bundle, digest, policy, error));
    EXPECT_NE(error.find("source ref"), std::string::npos) << error;
    policy.ref = "refs/tags/v2.103.2";
    EXPECT_FALSE(verify_provenance_bundle(*root, bundle, digest, policy, error));
}

TEST_F(ProvenanceFixture, RefusesMissingOrMalformedProvenance) {
    EXPECT_FALSE(verify_provenance_bundle(*root, "", digest, policy, error));
    EXPECT_FALSE(verify_provenance_bundle(*root, "{}", digest, policy, error));
    auto j = json::parse(bundle);
    j["verificationMaterial"].erase("tlogEntries");
    EXPECT_FALSE(verify_provenance_bundle(*root, j.dump(), digest, policy, error));
}

TEST_F(ProvenanceFixture, RefusesAnArtifactTheProvenanceDoesNotName) {
    EXPECT_FALSE(verify_provenance_bundle(*root, bundle, std::string(64, '0'), policy, error));
    EXPECT_NE(error.find("does not name this artifact"), std::string::npos) << error;
}

TEST_F(ProvenanceFixture, RefusesATamperedPayloadOrSignature) {
    auto j = json::parse(bundle);
    auto payload = crypto::from_base64(j["dsseEnvelope"]["payload"].get<std::string>());
    std::string text(payload.begin(), payload.end());
    const auto pos = text.find("refs/heads/trunk");
    ASSERT_NE(pos, std::string::npos);
    text.replace(pos, 16, "refs/heads/maim!");
    j["dsseEnvelope"]["payload"] = crypto::to_base64(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
    EXPECT_FALSE(verify_provenance_bundle(*root, j.dump(), digest, policy, error));

    auto k = json::parse(bundle);
    auto sig = crypto::from_base64(k["dsseEnvelope"]["signatures"][0]["sig"].get<std::string>());
    sig[sig.size() / 2] ^= 0x01;
    k["dsseEnvelope"]["signatures"][0]["sig"] = crypto::to_base64(sig);
    EXPECT_FALSE(verify_provenance_bundle(*root, k.dump(), digest, policy, error));
}

TEST_F(ProvenanceFixture, RefusesATamperedTransparencyLogEntry) {
    auto flip = [](std::string b64) {
        auto bytes = crypto::from_base64(b64);
        bytes[bytes.size() / 2] ^= 0x01;
        return crypto::to_base64(bytes);
    };
    const auto base = json::parse(bundle);
    auto& entry0 = base["verificationMaterial"]["tlogEntries"][0];
    {
        auto j = base;
        j["verificationMaterial"]["tlogEntries"][0]["inclusionPromise"]["signedEntryTimestamp"] =
            flip(entry0["inclusionPromise"]["signedEntryTimestamp"].get<std::string>());
        EXPECT_FALSE(verify_provenance_bundle(*root, j.dump(), digest, policy, error));
        EXPECT_NE(error.find("signed entry timestamp"), std::string::npos) << error;
    }
    {
        auto j = base;
        j["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["hashes"][0] =
            flip(entry0["inclusionProof"]["hashes"][0].get<std::string>());
        EXPECT_FALSE(verify_provenance_bundle(*root, j.dump(), digest, policy, error));
        EXPECT_NE(error.find("inclusion proof"), std::string::npos) << error;
    }
    {
        auto j = base;
        auto env = entry0["inclusionProof"]["checkpoint"]["envelope"].get<std::string>();
        env[env.size() - 5] = env[env.size() - 5] == 'A' ? 'B' : 'A';
        j["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]["checkpoint"]["envelope"] = env;
        EXPECT_FALSE(verify_provenance_bundle(*root, j.dump(), digest, policy, error));
        EXPECT_NE(error.find("checkpoint"), std::string::npos) << error;
    }
    {
        auto j = base;
        j["verificationMaterial"]["tlogEntries"][0]["integratedTime"] = "1700000000";
        EXPECT_FALSE(verify_provenance_bundle(*root, j.dump(), digest, policy, error));
    }
}

TEST_F(ProvenanceFixture, RefusesAnUnpinnedTrustedRoot) {
    auto j = json::parse(root_text);
    j["tlogs"] = json::array();
    EXPECT_FALSE(parse_sigstore_trusted_root(j.dump(), error));
}

TEST(Rfc3339, ParsesUtcTimes) {
    EXPECT_EQ(parse_rfc3339_utc("1970-01-01T00:00:00Z"), 0);
    EXPECT_EQ(parse_rfc3339_utc("2021-01-12T11:53:27Z"), 1610452407);
    EXPECT_EQ(parse_rfc3339_utc("2022-12-31T23:59:59.999Z"), 1672531199);
    EXPECT_FALSE(parse_rfc3339_utc("2021-01-12 11:53:27Z"));
    EXPECT_FALSE(parse_rfc3339_utc("2021-01-12T11:53:27+01:00"));
}

// ---------------------------------------------------------------------------
// File swap
// ---------------------------------------------------------------------------

struct SwapFixture : ::testing::Test {
    TempDir dir;
    SwapPlan plan;
    std::string error;

    void SetUp() override {
        for (const char* name : {"a", "b", "c"}) {
            write_text(dir.path / "bin" / name, std::string("old-") + name);
            write_text(dir.path / "staged" / name, std::string("new-") + name);
            plan.files.push_back({dir.path / "bin" / name, dir.path / "staged" / name,
                                  sha256_hex(std::string("new-") + name)});
        }
        plan.release_tag = "v2026.10.24";
        plan.backup_dir = dir.path / "previous" / plan.release_tag;
    }

    void expect_all(const std::string& prefix) {
        for (const char* name : {"a", "b", "c"}) {
            EXPECT_EQ(read_text(dir.path / "bin" / name), prefix + name);
        }
    }
};

TEST_F(SwapFixture, SwapsEveryFileAndKeepsThePreviousFiles) {
    FileSwapper swapper(dir.path / "journal.json");
    ASSERT_TRUE(swapper.apply(plan, error)) << error;
    expect_all("new-");
    for (const char* name : {"a", "b", "c"}) {
        EXPECT_EQ(read_text(plan.backup_dir / name), std::string("old-") + name);
    }
    EXPECT_EQ(swapper.load()->first, SwapPhase::Swapped);
}

TEST_F(SwapFixture, AnInterruptedSwapResumes) {
    {
        FileSwapper swapper(dir.path / "journal.json");
        swapper.before_rename = [](std::size_t i) { return i < 1; };  // "crash" before file 2
        EXPECT_FALSE(swapper.apply(plan, error));
    }
    EXPECT_EQ(read_text(dir.path / "bin" / "a"), "new-a");
    EXPECT_EQ(read_text(dir.path / "bin" / "b"), "old-b");
    // A new process finds the journal and finishes the swap.
    FileSwapper restarted(dir.path / "journal.json");
    ASSERT_EQ(restarted.load()->first, SwapPhase::BackedUp);
    ASSERT_TRUE(restarted.resume(error)) << error;
    expect_all("new-");
    EXPECT_EQ(restarted.load()->first, SwapPhase::Swapped);
    // The backups still hold the bytes from before the first attempt.
    EXPECT_EQ(read_text(plan.backup_dir / "a"), "old-a");
}

TEST_F(SwapFixture, AnInterruptedApplyRetriedKeepsTheOriginalBackups) {
    FileSwapper swapper(dir.path / "journal.json");
    swapper.before_rename = [](std::size_t i) { return i < 2; };
    EXPECT_FALSE(swapper.apply(plan, error));
    swapper.before_rename = nullptr;
    ASSERT_TRUE(swapper.apply(plan, error)) << error;
    EXPECT_EQ(read_text(plan.backup_dir / "a"), "old-a");
    EXPECT_EQ(read_text(plan.backup_dir / "b"), "old-b");
}

TEST_F(SwapFixture, RollbackRestoresThePreviousFiles) {
    FileSwapper swapper(dir.path / "journal.json");
    ASSERT_TRUE(swapper.apply(plan, error)) << error;
    ASSERT_TRUE(swapper.rollback(error)) << error;
    expect_all("old-");
    EXPECT_EQ(swapper.load()->first, SwapPhase::RolledBack);
}

TEST_F(SwapFixture, RefusesAStagedFileWithTheWrongHash) {
    write_text(dir.path / "staged" / "b", "tampered");
    FileSwapper swapper(dir.path / "journal.json");
    EXPECT_FALSE(swapper.apply(plan, error));
    expect_all("old-");
}

// ---------------------------------------------------------------------------
// OS packages and GRUB
// ---------------------------------------------------------------------------

TEST(OsPackages, ParsesTheLockStrictly) {
    std::string error;
    const auto lock = parse_os_package_lock(
        "# comment\nformat 1\npackage linux-image-6.8.0-45-generic 6.8.0-45.45 boot\n"
        "package libc6 2.39-0ubuntu8.4 library\n",
        error);
    ASSERT_TRUE(lock) << error;
    ASSERT_EQ(lock->packages.size(), 2u);
    EXPECT_EQ(lock->packages[0].role, PackageRole::Boot);
    EXPECT_FALSE(parse_os_package_lock("package libc6 2.39 library\n", error));
    EXPECT_FALSE(parse_os_package_lock("format 1\npackage libc6 2.39 library\npackage libc6 2.40 library\n", error));
    EXPECT_FALSE(parse_os_package_lock("format 1\npackage libc6 2.39;rm library\n", error));
    EXPECT_FALSE(parse_os_package_lock("format 1\npackage -libc6 2.39 library\n", error));
    EXPECT_FALSE(parse_os_package_lock("format 1\npackage libc6 2.39 kernel\n", error));
    EXPECT_FALSE(parse_os_package_lock("format 2\n", error));
}

TEST(OsPackages, PlansOnlyChangedPackagesAndDetectsBootChanges) {
    std::string error;
    const auto lock = parse_os_package_lock(
        "format 1\npackage grub-efi-amd64-signed 1.2 boot\npackage libc6 2.40 library\n", error);
    ASSERT_TRUE(lock);
    auto plan = plan_os_packages(*lock, {{"grub-efi-amd64-signed", "1.2"}, {"libc6", "2.39"}});
    ASSERT_EQ(plan.install.size(), 1u);
    EXPECT_EQ(plan.install[0].name, "libc6");
    EXPECT_EQ(plan.previous[0].version, "2.39");
    EXPECT_FALSE(plan.boot_chain_changed);
    plan = plan_os_packages(*lock, {{"grub-efi-amd64-signed", "1.1"}, {"libc6", "2.40"}});
    EXPECT_TRUE(plan.boot_chain_changed);
    const auto argv = apt_install_argv(plan.install);
    EXPECT_EQ(argv.back(), "grub-efi-amd64-signed=1.2");
    EXPECT_TRUE(apt_install_argv({}).empty());
}

TEST(OsPackages, ParsesDpkgQueryOutput) {
    const auto m = parse_dpkg_query("libc6:amd64\t2.39-0ubuntu8.4\tii \ngrub\t1.0\trc \nbad line\n");
    ASSERT_EQ(m.size(), 1u);
    EXPECT_EQ(m.at("libc6"), "2.39-0ubuntu8.4");
}

TEST(OsPackages, RebootOnlyWhenTheBootChainAndPcrsChangeTogether) {
    EXPECT_FALSE(decide_reboot(false, false).reboot);
    EXPECT_TRUE(decide_reboot(false, false).error.empty());
    EXPECT_TRUE(decide_reboot(true, true).reboot);
    EXPECT_FALSE(decide_reboot(true, false).error.empty());
    EXPECT_FALSE(decide_reboot(false, true).error.empty());
}

const char* kGrubCfg = R"(menuentry 'Ubuntu' --class ubuntu $menuentry_id_option 'gnulinux-simple-1234' {
	linux	/boot/vmlinuz-6.8.0-47-generic root=UUID=1234 ro
	initrd	/boot/initrd.img-6.8.0-47-generic
}
submenu 'Advanced options for Ubuntu' $menuentry_id_option 'gnulinux-advanced-1234' {
	menuentry 'Ubuntu, with Linux 6.8.0-47-generic' --class ubuntu $menuentry_id_option 'gnulinux-6.8.0-47-generic-advanced-1234' {
		linux	/boot/vmlinuz-6.8.0-47-generic root=UUID=1234 ro
	}
	menuentry 'Ubuntu, with Linux 6.8.0-45-generic' --class ubuntu $menuentry_id_option 'gnulinux-6.8.0-45-generic-advanced-1234' {
		linux	/boot/vmlinuz-6.8.0-45-generic root=UUID=1234 ro
	}
}
)";

TEST(Grub, FindsTheEntryOfARunningKernel) {
    EXPECT_EQ(grub_entry_for_kernel(kGrubCfg, "6.8.0-45-generic"),
              "gnulinux-advanced-1234>gnulinux-6.8.0-45-generic-advanced-1234");
    EXPECT_EQ(grub_entry_for_kernel(kGrubCfg, "6.8.0-47-generic"), "gnulinux-simple-1234");
    EXPECT_FALSE(grub_entry_for_kernel(kGrubCfg, "6.8.0-4-generic"));
    EXPECT_TRUE(grub_default_is_saved("GRUB_DEFAULT=saved\n"));
    EXPECT_TRUE(grub_default_is_saved("GRUB_DEFAULT=0\nGRUB_DEFAULT=\"saved\"\n"));
    EXPECT_FALSE(grub_default_is_saved("GRUB_DEFAULT=0\n"));
}

// ---------------------------------------------------------------------------
// GitHub release document
// ---------------------------------------------------------------------------

TEST(GitHubRelease, KeepsOnlyAssetsUnderTheReleaseTag) {
    const json doc = {
        {"tag_name", "v2026.10.24"},
        {"assets",
         json::array({{{"name", "manifest.json"},
                       {"browser_download_url",
                        "https://github.com/lemonade-sdk/lemonade-nexus/releases/download/v2026.10.24/manifest.json"}},
                      {{"name", "evil"},
                       {"browser_download_url", "https://example.com/evil"}},
                      {{"name", "other"},
                       {"browser_download_url",
                        "https://github.com/lemonade-sdk/lemonade-nexus/releases/download/v2026.10.23/other"}}})}};
    std::string error;
    const auto r = parse_github_release(doc.dump(), kRepo, error);
    ASSERT_TRUE(r) << error;
    ASSERT_EQ(r->assets.size(), 1u);
    EXPECT_EQ(r->assets[0].name, "manifest.json");
    EXPECT_TRUE(allowed_github_host("objects.githubusercontent.com"));
    EXPECT_TRUE(allowed_github_host("api.github.com"));
    EXPECT_FALSE(allowed_github_host("githubusercontent.com.evil.example"));
    EXPECT_FALSE(allowed_github_host("evilgithub.com"));
}

// ---------------------------------------------------------------------------
// Health gate
// ---------------------------------------------------------------------------

update::UpdateServerStatus status_of(const std::string& version, const std::string& release_id,
                                     const std::string& digest) {
    update::UpdateServerStatus s;
    s.version = version;
    s.release_id = release_id;
    s.approval_digest_hex = digest;
    s.storage_files_ready = true;
    s.storage_phase = "migrated";
    return s;
}

TEST(HealthGate, ComparesWithTheBaseline) {
    auto baseline = status_of("2026.10.01", "v2026.10.01", "d0");
    baseline.tier1_member = true;
    baseline.epoch_known = true;
    baseline.epoch = 7;
    baseline.tree_enabled = true;
    baseline.tree_healthy = true;
    baseline.tree_height = 100;
    baseline.tree_applied_height = 100;
    const HealthExpectation expected{"2026.10.24", "v2026.10.24", "d1"};

    EXPECT_EQ(evaluate_health(baseline, std::nullopt, expected).verdict, HealthVerdict::Pending);
    auto now = status_of("2026.10.01", "v2026.10.01", "d0");
    EXPECT_EQ(evaluate_health(baseline, now, expected).verdict, HealthVerdict::Failed);
    now = status_of("2026.10.24", "v2026.10.24", "d1");
    now.storage_files_ready = false;
    EXPECT_EQ(evaluate_health(baseline, now, expected).verdict, HealthVerdict::Pending);
    now.storage_files_ready = true;
    EXPECT_EQ(evaluate_health(baseline, now, expected).verdict, HealthVerdict::Pending);  // not a member
    now.epoch_known = true;
    now.tier1_member = true;
    now.epoch = 7;
    EXPECT_EQ(evaluate_health(baseline, now, expected).verdict, HealthVerdict::Failed);  // tree off
    now.tree_enabled = true;
    now.tree_healthy = true;
    now.tree_height = 99;
    now.tree_applied_height = 99;
    EXPECT_EQ(evaluate_health(baseline, now, expected).verdict, HealthVerdict::Pending);
    now.tree_height = 101;
    now.tree_applied_height = 101;
    EXPECT_EQ(evaluate_health(baseline, now, expected).verdict, HealthVerdict::Healthy);
    now.tree_healthy = false;
    EXPECT_EQ(evaluate_health(baseline, now, expected).verdict, HealthVerdict::Failed);
}

// ---------------------------------------------------------------------------
// Whole cycles
// ---------------------------------------------------------------------------

/// A host: files under a temporary root, a fake server behind the control
/// socket, fake GitHub, and a fake command runner.
struct Host {
    TempDir dir;
    Keys keys;
    ReleaseFiles installed;
    ReleaseFiles next;
    std::map<std::string, std::string> assets;  // GitHub asset name to bytes
    std::set<std::string> drop_assets;
    std::map<std::string, std::string> packages{{"libc6", "2.39-0ubuntu8.4"},
                                                {"grub-efi-amd64-signed", "1.202+2.12-1ubuntu7"}};
    std::vector<std::vector<std::string>> commands;
    bool running = true;
    bool grant_turn = true;
    bool new_binary_is_broken = false;
    bool tier1 = false;
    bool loses_membership_on_new_binary = false;
    int stage_calls = 0;
    std::string boot_id = "boot-1";
    std::chrono::steady_clock::time_point clock{};
    std::vector<std::string> reports;

    fs::path host(std::string_view p) const { return dir.path / fs::path(p).relative_path(); }

    Host() {
        installed = make_release(keys, "v2026.10.01", "nexus-old", "attestd-old", kEmptyLock);
        write_text(host("/usr/bin/lemonade-nexus"), installed.nexus_bin);
        write_text(host("/usr/bin/nexus-attestd"), installed.attestd_bin);
        write_text(host(security::kReleaseApprovalPath), installed.approval);
        write_text(host("/proc/sys/kernel/random/boot_id"), boot_id + "\n");
        write_text(host("/etc/default/grub"), "GRUB_DEFAULT=saved\n");
        write_text(host("/boot/grub/grub.cfg"), kGrubCfg);
        set_next(make_release(keys, "v2026.10.24", "nexus-new", "attestd-new", kEmptyLock,
                              {sha256_hex("nexus-old")}, {sha256_hex("attestd-old")}));
    }

    void set_next(ReleaseFiles r) {
        next = std::move(r);
        assets = {{"manifest.json", next.manifest},
                  {"manifest.json.sig", next.signature + "\n"},
                  {"release-approval.json", next.approval},
                  {"os-packages.lock", next.lock},
                  {"lemonade-nexus-linux-x86_64", next.nexus_bin},
                  {"nexus-attestd-linux-x86_64", next.attestd_bin}};
        for (const auto& name : {"manifest.json", "release-approval.json", "os-packages.lock",
                                 "lemonade-nexus-linux-x86_64", "nexus-attestd-linux-x86_64"}) {
            assets[std::string(name) + ".sigstore.json"] =
                "provenance:" + sha256_hex(assets[name]);
        }
    }

    /// What the server reports: derived from the files it would have loaded.
    std::optional<update::UpdateServerStatus> status() const {
        if (!running) return std::nullopt;
        const auto bin = read_text(host("/usr/bin/lemonade-nexus"));
        const auto approval = read_text(host(security::kReleaseApprovalPath));
        std::string error;
        const auto b = security::parse_release_approval_bundle(approval, error);
        update::UpdateServerStatus s;
        s.version = bin == next.nexus_bin ? next.tag.substr(1) : installed.tag.substr(1);
        if (bin == next.nexus_bin && new_binary_is_broken) s.version = "crashed";
        s.release_id = b ? b->approval.release_id : "";
        s.approval_digest_hex = b ? security::release_approval_digest_hex(b->approval) : "";
        s.storage_files_ready = true;
        s.storage_phase = "migrated";
        s.epoch_known = true;
        s.epoch = 3;
        s.tier1_member = tier1 && !(bin == next.nexus_bin && loses_membership_on_new_binary);
        return s;
    }

    Updater updater() {
        UpdaterConfig cfg;
        cfg.root = dir.path;
        cfg.trust = keys.trust();
        cfg.health_timeout = std::chrono::seconds(60);
        cfg.health_poll = std::chrono::seconds(5);
        UpdaterEnv env;
        env.http = [this](const std::string& url, std::size_t, std::string& error)
            -> std::optional<std::string> {
            if (url == latest_release_url(kRepo)) {
                json assets_json = json::array();
                for (const auto& [name, bytes] : assets) {
                    if (drop_assets.count(name)) continue;
                    assets_json.push_back(
                        {{"name", name},
                         {"size", bytes.size()},
                         {"browser_download_url", "https://github.com/" + std::string(kRepo) +
                                                      "/releases/download/" + next.tag + "/" + name}});
                }
                return json{{"tag_name", next.tag}, {"draft", false}, {"prerelease", false},
                            {"assets", assets_json}}
                    .dump();
            }
            const auto slash = url.rfind('/');
            const auto it = assets.find(url.substr(slash + 1));
            if (it == assets.end() || drop_assets.count(it->first)) {
                error = "404";
                return std::nullopt;
            }
            return it->second;
        };
        env.control = [this](std::string_view request) -> std::optional<std::string> {
            if (!running) return std::nullopt;
            update::UpdateControlHandlers h;
            h.status = [this] { return *status(); };
            h.may_restart = [this](const update::TurnRequest&) {
                update::RefusingTurnGate stub;
                return grant_turn ? update::TurnDecision{true, "granted"} : stub.may_restart({});
            };
            h.report = [this](const update::UpgradeReport& r) {
                reports.push_back(r.outcome == update::UpgradeOutcome::Upgraded ? "upgraded"
                                                                                 : "failed");
                return update::ReportAck{true, ""};
            };
            h.stage_boot_chain = [this](std::string_view) {
                ++stage_calls;
                write_text(host("/var/lib/lemonade-nexus/data/sealed/gossip-identity.next.sealed"),
                           "staged");
                update::BootChainStageResult r;
                r.ok = true;
                r.staged = {"gossip-identity"};
                return r;
            };
            return update::handle_control_request(request, h);
        };
        env.run = [this](const std::vector<std::string>& argv) -> CommandResult {
            commands.push_back(argv);
            if (argv[0] == "dpkg-query") {
                std::string out;
                for (const auto& [n, v] : packages) out += n + "\t" + v + "\tii \n";
                return {0, out};
            }
            if (argv[0] == "apt-get" && argv[1] == "install") {
                for (std::size_t i = 0; i < argv.size(); ++i) {
                    const auto eq = argv[i].find('=');
                    if (eq != std::string::npos && argv[i].rfind("Dpkg", 0) != 0) {
                        packages[argv[i].substr(0, eq)] = argv[i].substr(eq + 1);
                    }
                }
                return {0, ""};
            }
            if (argv[0] == "systemctl" && argv[1] == "stop") running = false;
            if (argv[0] == "systemctl" && argv[1] == "start") running = true;
            return {0, ""};
        };
        env.provenance = [](std::string_view bundle, std::string_view sha, std::string& why) {
            if (bundle == "provenance:" + std::string(sha)) return true;
            why = "fake provenance mismatch";
            return false;
        };
        env.sleep = [this](std::chrono::seconds s) { clock += s; };
        env.now = [this] { return clock; };
        env.kernel_release = [] { return std::string("6.8.0-45-generic"); };
        return Updater(cfg, env);
    }

    bool ran(const std::vector<std::string>& prefix) const {
        return std::any_of(commands.begin(), commands.end(), [&](const auto& argv) {
            return argv.size() >= prefix.size() && std::equal(prefix.begin(), prefix.end(), argv.begin());
        });
    }

    void reboot() {
        boot_id = "boot-2";
        write_text(host("/proc/sys/kernel/random/boot_id"), boot_id + "\n");
        running = true;  // systemd starts the services at boot
    }
};

TEST(UpdaterCycle, StagesAndWaitsWhileTheTurnGateRefuses) {
    Host h;
    h.grant_turn = false;
    auto u = h.updater();
    const auto r = u.run_once();
    EXPECT_EQ(r.outcome, CycleOutcome::Waiting) << r.detail;
    EXPECT_NE(r.detail.find("not implemented"), std::string::npos) << r.detail;
    EXPECT_EQ(read_text(h.host("/usr/bin/lemonade-nexus")), "nexus-old");
    EXPECT_TRUE(fs::exists(u.state_dir() / "staged" / "v2026.10.24" / "lemonade-nexus-linux-x86_64"));
    EXPECT_FALSE(h.ran({"systemctl", "stop"}));
}

TEST(UpdaterCycle, UpgradesInPlaceWithoutARebootWhenTheBootChainIsUnchanged) {
    Host h;
    h.set_next(make_release(h.keys, "v2026.10.24", "nexus-new", "attestd-new",
                            "format 1\npackage libc6 2.39-0ubuntu8.5 library\n",
                            {sha256_hex("nexus-old")}, {sha256_hex("attestd-old")}));
    auto u = h.updater();
    const auto r = u.run_once();
    ASSERT_EQ(r.outcome, CycleOutcome::Upgraded) << r.detail;
    EXPECT_EQ(read_text(h.host("/usr/bin/lemonade-nexus")), "nexus-new");
    EXPECT_EQ(read_text(h.host("/usr/bin/nexus-attestd")), "attestd-new");
    EXPECT_EQ(read_text(h.host(security::kReleaseApprovalPath)), h.next.approval);
    EXPECT_EQ(read_text(u.state_dir() / "previous" / "v2026.10.24" / "lemonade-nexus"), "nexus-old");
    EXPECT_EQ(h.packages["libc6"], "2.39-0ubuntu8.5");
    EXPECT_FALSE(h.ran({"systemctl", "reboot"}));
    EXPECT_EQ(h.stage_calls, 0);
    EXPECT_EQ(h.reports, std::vector<std::string>{"upgraded"});
    // The same release is now installed.
    EXPECT_EQ(u.run_once().outcome, CycleOutcome::NoUpdate);
}

TEST(UpdaterCycle, RollsBackAndHaltsWhenTheHealthGateFails) {
    Host h;
    h.new_binary_is_broken = true;
    auto u = h.updater();
    const auto r = u.run_once();
    ASSERT_EQ(r.outcome, CycleOutcome::Failed) << r.detail;
    EXPECT_EQ(read_text(h.host("/usr/bin/lemonade-nexus")), "nexus-old");
    EXPECT_EQ(read_text(h.host("/usr/bin/nexus-attestd")), "attestd-old");
    EXPECT_EQ(read_text(h.host(security::kReleaseApprovalPath)), h.installed.approval);
    EXPECT_TRUE(h.running);
    EXPECT_EQ(h.reports, std::vector<std::string>{"failed"});
    // The failed release halts until a newer one appears.
    EXPECT_EQ(u.run_once().outcome, CycleOutcome::Halted);
    h.new_binary_is_broken = false;
    h.set_next(make_release(h.keys, "v2026.10.24.2", "nexus-new", "attestd-new", kEmptyLock,
                            {sha256_hex("nexus-old")}, {sha256_hex("attestd-old")}));
    EXPECT_EQ(u.run_once().outcome, CycleOutcome::Upgraded);
}

TEST(UpdaterCycle, RollsBackWhenATier1ServerDoesNotRejoinBeforeTheDeadline) {
    Host h;
    h.tier1 = true;
    h.loses_membership_on_new_binary = true;
    auto u = h.updater();
    const auto r = u.run_once();
    ASSERT_EQ(r.outcome, CycleOutcome::Failed) << r.detail;
    EXPECT_NE(r.detail.find("timed out"), std::string::npos) << r.detail;
    EXPECT_EQ(read_text(h.host("/usr/bin/lemonade-nexus")), "nexus-old");
    EXPECT_EQ(h.reports, std::vector<std::string>{"failed"});
}

TEST(UpdaterCycle, DoesNotRebootWhenTheBootChainIsUnchanged) {
    Host h;
    auto u = h.updater();
    ASSERT_EQ(u.run_once().outcome, CycleOutcome::Upgraded);
    EXPECT_FALSE(h.ran({"systemctl", "reboot"}));
    EXPECT_FALSE(h.ran({"apt-get", "install"}));
    EXPECT_FALSE(h.ran({"grub-editenv"}));
    EXPECT_EQ(h.stage_calls, 0);
}

TEST(UpdaterCycle, RebootsForABootChainChangeAfterStagingTheSealedBootSet) {
    Host h;
    h.set_next(make_release(h.keys, "v2026.10.24", "nexus-new", "attestd-new",
                            "format 1\npackage grub-efi-amd64-signed 1.202+2.12-1ubuntu8 boot\n",
                            {sha256_hex("nexus-old")}, {sha256_hex("attestd-old")}, 'a'));
    auto u = h.updater();
    auto r = u.run_once();
    ASSERT_EQ(r.outcome, CycleOutcome::Rebooting) << r.detail;
    EXPECT_EQ(h.stage_calls, 1);
    EXPECT_TRUE(h.ran({"systemctl", "reboot"}));
    EXPECT_TRUE(h.ran({"grub-editenv"}));
    EXPECT_EQ(h.packages["grub-efi-amd64-signed"], "1.202+2.12-1ubuntu8");
    // The next cycle after boot runs the health gate and commits.
    h.reboot();
    r = u.run_once();
    ASSERT_EQ(r.outcome, CycleOutcome::Upgraded) << r.detail;
    EXPECT_EQ(h.reports, std::vector<std::string>{"upgraded"});
}

TEST(UpdaterCycle, BootsThePreviousGrubEntryWhenTheHealthGateFailsAfterReboot) {
    Host h;
    h.new_binary_is_broken = true;
    h.set_next(make_release(h.keys, "v2026.10.24", "nexus-new", "attestd-new",
                            "format 1\npackage grub-efi-amd64-signed 1.202+2.12-1ubuntu8 boot\n",
                            {sha256_hex("nexus-old")}, {sha256_hex("attestd-old")}, 'a'));
    auto u = h.updater();
    ASSERT_EQ(u.run_once().outcome, CycleOutcome::Rebooting);
    h.reboot();
    auto r = u.run_once();
    ASSERT_EQ(r.outcome, CycleOutcome::Rebooting) << r.detail;
    EXPECT_TRUE(h.ran({"grub-set-default", "gnulinux-advanced-1234>gnulinux-6.8.0-45-generic-advanced-1234"}));
    EXPECT_EQ(read_text(h.host("/usr/bin/lemonade-nexus")), "nexus-old");
    // Back in the previous boot chain: restore packages, report, halt.
    h.reboot();
    r = u.run_once();
    EXPECT_EQ(r.outcome, CycleOutcome::Failed) << r.detail;
    EXPECT_EQ(h.packages["grub-efi-amd64-signed"], "1.202+2.12-1ubuntu7");
    EXPECT_EQ(h.reports, std::vector<std::string>{"failed"});
    EXPECT_EQ(u.run_once().outcome, CycleOutcome::Halted);
}

TEST(UpdaterCycle, RefusesABootPackageChangeWithoutNewPcrs) {
    Host h;
    h.set_next(make_release(h.keys, "v2026.10.24", "nexus-new", "attestd-new",
                            "format 1\npackage grub-efi-amd64-signed 1.202+2.12-1ubuntu8 boot\n",
                            {sha256_hex("nexus-old")}, {sha256_hex("attestd-old")}));
    auto u = h.updater();
    const auto r = u.run_once();
    EXPECT_EQ(r.outcome, CycleOutcome::Refused) << r.detail;
    EXPECT_EQ(read_text(h.host("/usr/bin/lemonade-nexus")), "nexus-old");
    EXPECT_FALSE(h.ran({"systemctl", "stop"}));
}

TEST(UpdaterCycle, RefusesAReleaseWithMissingProvenance) {
    Host h;
    h.drop_assets.insert("lemonade-nexus-linux-x86_64.sigstore.json");
    auto u = h.updater();
    const auto r = u.run_once();
    EXPECT_EQ(r.outcome, CycleOutcome::Refused);
    EXPECT_NE(r.detail.find("no provenance"), std::string::npos) << r.detail;
    EXPECT_EQ(read_text(h.host("/usr/bin/lemonade-nexus")), "nexus-old");
    EXPECT_FALSE(fs::exists(u.state_dir() / "staged" / "v2026.10.24"));
}

TEST(UpdaterCycle, RefusesATamperedArtifact) {
    Host h;
    h.assets["lemonade-nexus-linux-x86_64"] = "nexus-evil";
    auto u = h.updater();
    const auto r = u.run_once();
    EXPECT_EQ(r.outcome, CycleOutcome::Refused);
    EXPECT_NE(r.detail.find("signed manifest lists"), std::string::npos) << r.detail;
    EXPECT_EQ(read_text(h.host("/usr/bin/lemonade-nexus")), "nexus-old");
}

TEST(UpdaterCycle, RefusesAReplayedOlderRelease) {
    Host h;
    h.set_next(make_release(h.keys, "v2026.09.30", "nexus-older", "attestd-older", kEmptyLock));
    auto u = h.updater();
    EXPECT_EQ(u.run_once().outcome, CycleOutcome::NoUpdate);
    EXPECT_FALSE(h.ran({"systemctl", "stop"}));
}

TEST(UpdaterCycle, ResumesASwapInterruptedByACrash) {
    Host h;
    auto u = h.updater();
    // Run the swap as far as the journal, then "crash": write the state the
    // updater records before swapping and a half-applied swap journal.
    const auto staged = u.state_dir() / "staged" / h.next.tag;
    write_text(staged / "lemonade-nexus-linux-x86_64", h.next.nexus_bin);
    write_text(staged / "nexus-attestd-linux-x86_64", h.next.attestd_bin);
    write_text(staged / "release-approval.json", h.next.approval);
    SwapPlan plan;
    plan.release_tag = h.next.tag;
    plan.backup_dir = u.state_dir() / "previous" / h.next.tag;
    plan.files = {{h.host("/usr/bin/lemonade-nexus"), staged / "lemonade-nexus-linux-x86_64",
                   sha256_hex(h.next.nexus_bin)},
                  {h.host("/usr/bin/nexus-attestd"), staged / "nexus-attestd-linux-x86_64",
                   sha256_hex(h.next.attestd_bin)},
                  {h.host(security::kReleaseApprovalPath), staged / "release-approval.json",
                   sha256_hex(h.next.approval)}};
    FileSwapper crashing(u.state_dir() / "swap-journal.json");
    crashing.before_rename = [](std::size_t i) { return i < 1; };
    std::string error;
    ASSERT_FALSE(crashing.apply(plan, error));
    const auto baseline = h.status();
    update::UpdateControlHandlers handlers;
    handlers.status = [&] { return *baseline; };
    const json state = {
        {"installed_release_number", 0},
        {"halted_release_number", 0},
        {"phase", "swapping"},
        {"tag", h.next.tag},
        {"number", 2026102401},
        {"expected_version", h.next.tag.substr(1)},
        {"expected_release_id", h.next.tag},
        {"expected_approval_digest", approval_digest(h.next.approval)},
        {"baseline", update::handle_control_request(update::encode_status_request(), handlers)},
        {"packages_install", json::array()},
        {"packages_previous", json::array()},
        {"reboot", false},
        {"previous_grub_entry", ""},
        {"boot_id", ""},
        {"staged_seal_names", json::array()},
        {"last_result", ""},
    };
    write_text(u.state_dir() / "state.json", state.dump());
    h.running = false;  // the crash left the services stopped

    const auto r = u.run_once();
    ASSERT_EQ(r.outcome, CycleOutcome::Upgraded) << r.detail;
    EXPECT_EQ(read_text(h.host("/usr/bin/lemonade-nexus")), "nexus-new");
    EXPECT_EQ(read_text(h.host("/usr/bin/nexus-attestd")), "attestd-new");
    EXPECT_EQ(read_text(h.host(security::kReleaseApprovalPath)), h.next.approval);
}

}  // namespace
