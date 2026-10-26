// Files under the data key (design B9, B10, B5a; Phase 7): StorageVault with a
// fake data key source. The multi-server cases (unlock through holders, cold
// start, rotation through the holders) run on the memory mesh in
// security/lifecycle/storage_key_path.cpp.

#include <LemonadeNexus/Acme/AcmeService.hpp>
#include <LemonadeNexus/Auth/Ed25519AuthProvider.hpp>
#include <LemonadeNexus/Auth/PasskeyAuthProvider.hpp>
#include <LemonadeNexus/Core/SecurityMeshStartup.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Security/Lifecycle/SecurityMeshService.hpp>
#include <LemonadeNexus/Security/Storage/StorageVault.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include <asio.hpp>
#include <nlohmann/json.hpp>
#include <gtest/gtest.h>
#include <sodium.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <unistd.h>

using namespace nexus::security;
namespace fs = std::filesystem;

namespace {

using Key = std::vector<uint8_t>;

Key random_key() {
    Key key(32);
    randombytes_buf(key.data(), key.size());
    return key;
}

/// The DataKeyService contract without holders. `persisted` and
/// `persisted_next` model data-key.json and data-key.next.json; restart()
/// drops memory and an uncommitted replacement, like DataKeyService::load().
struct FakeKeys final : DataKeySource {
    Key persisted = random_key();
    std::optional<Key> persisted_next;
    std::optional<Key> dek;
    std::optional<Key> next;
    bool verified = false;
    bool next_verified = false;
    bool holders_answer = true;
    int verification_requests = 0;

    std::optional<nexus::crypto::SecureBuffer> data_key() const override {
        if (!dek) return std::nullopt;
        return nexus::crypto::SecureBuffer(std::span<const uint8_t>(*dek));
    }
    bool unlock_verified() const override { return verified; }
    void request_verification() override {
        ++verification_requests;
        verified = holders_answer;
    }
    bool begin_replacement() override {
        if (!dek || next) return false;
        next = random_key();
        persisted_next = next;
        next_verified = holders_answer;
        return true;
    }
    std::optional<nexus::crypto::SecureBuffer> replacement_key() const override {
        if (!next) return std::nullopt;
        return nexus::crypto::SecureBuffer(std::span<const uint8_t>(*next));
    }
    bool replacement_verified() const override { return next && next_verified; }
    bool commit_replacement() override {
        if (!next || !next_verified) return false;
        persisted = *next;
        persisted_next.reset();
        dek = next;
        next.reset();
        verified = true;
        return true;
    }
    void abort_replacement() override {
        next.reset();
        persisted_next.reset();
    }
    void restart() {
        dek.reset();
        next.reset();
        persisted_next.reset();
        verified = false;
        next_verified = false;
    }
    /// t holders answered the unlock: the DEK is back and proven.
    void unlock() {
        dek = persisted;
        verified = true;
    }
};

std::string read_raw(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void write_raw(const fs::path& path, std::string_view text) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
}

bool encrypted(std::string_view raw) { return raw.starts_with("LNXVAULT"); }

/// The coverage of the first Phase 7 release: generation 1 only.
std::vector<VaultCoverage> first_generation_coverage() {
    auto coverage = StorageVault::default_coverage();
    std::erase_if(coverage, [](const VaultCoverage& c) { return c.since > 1; });
    return coverage;
}

/// Files of groups that coverage generation 2 added.
const std::vector<std::string> kGenerationTwo = {
    "tree/committed-ops.json",
    "onboarding/admissions.json",
    "chat-aa11/c1.json",
    "keyenv-bb22/p1.json",
    "credentials/u1.json",
    "credentials/revoked.json",
};

class StorageVaultTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        crypto.start();
        root = fs::temp_directory_path() /
               ("nexus_vault_" + std::to_string(::getpid()) + "_" +
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
        fs::remove_all(root);
        data = root / "data";
        originals = {
            {"identity/keypair.enc", "v2:1:00112233:deadbeef"},
            {"identity/jwt_secret.hex", "7f7f7f7f7f7f7f7f"},
            {"identity/ddns_credentials.enc", "{\"data\":\"x\"}"},
            {"account/replica.json", "{\"entries\":[]}"},
            {"tree/nodes/alpha.json", "{\"id\":\"alpha\"}"},
            {"tree/nodes/beta.json", "{\"id\":\"beta\"}"},
            {"tree/deltas/000001.json", "{\"sequence\":1}"},
            {"tree/log/1.json", "{\"height\":1}"},
            {"tree/log/snapshot-0.json", "{\"height\":0}"},
            {"tree/committed-ops.json", "{\"format\":1,\"ids\":[]}"},
            {"onboarding/admissions.json", "{\"data\":{\"admissions\":[]}}"},
            {"chat-aa11/c1.json", "{\"data\":\"chat blob\"}"},
            {"keyenv-bb22/p1.json", "{\"data\":\"key envelope\"}"},
            {"credentials/u1.json", "{\"user_id\":\"u1\",\"ed25519_pubkeys\":[]}"},
            {"credentials/revoked.json", "[]"},
        };
        for (const auto& [rel, text] : originals) write_raw(data / rel, text);
        write_raw(data / "identity/keypair.pub", "public");
    }

    void TearDown() override {
        vault.reset();
        std::error_code ec;
        fs::remove_all(root, ec);
        crypto.stop();
    }

    void build(std::size_t batch = 1,
               std::vector<VaultCoverage> coverage = StorageVault::default_coverage()) {
        vault.reset();
        StorageVaultOptions options;
        options.batch = batch;
        options.rotation_interval_ms = kMonth;
        vault = std::make_unique<StorageVault>(data, data / "security" / "storage", crypto,
                                               std::move(coverage), options);
        vault->load();
        vault->attach(&keys);
    }

    void tick(int n = 1) {
        for (int i = 0; i < n; ++i) vault->tick(now_ms += 1000);
    }

    bool done() const {
        return vault->mode() == VaultMode::Encrypted && vault->phase() == VaultPhase::Idle &&
               !vault->rotation_requested();
    }

    bool run_to_done(int limit = 400) {
        for (int i = 0; i < limit && !done(); ++i) tick();
        return done();
    }

    /// A process restart: the vault object and the DEK in memory are gone.
    void crash_and_restart(bool holders_up = true) {
        vault.reset();
        keys.restart();
        if (holders_up) keys.unlock();
        build();
    }

    void expect_encrypted_contents() {
        for (const auto& [rel, text] : originals) {
            const auto read = vault->read(data / rel);
            ASSERT_EQ(read.status, VaultReadStatus::Ok) << rel;
            EXPECT_EQ(read.bytes, text) << rel;
            EXPECT_TRUE(encrypted(read_raw(data / rel))) << rel;
            EXPECT_FALSE(fs::exists(data / (rel + ".vault-new"))) << rel;
        }
        EXPECT_EQ(read_raw(data / "identity/keypair.pub"), "public");
    }

    void migrate() {
        keys.unlock();
        build();
        ASSERT_TRUE(run_to_done());
        expect_encrypted_contents();
    }

    /// A server that migrated under the first Phase 7 release: its vault is
    /// "encrypted", the generation-2 files are plaintext, and its state file
    /// has no coverage generation.
    void migrate_first_generation() {
        keys.unlock();
        build(1, first_generation_coverage());
        ASSERT_TRUE(run_to_done());
        for (const auto& rel : kGenerationTwo) {
            ASSERT_EQ(read_raw(data / rel), originals.at(rel)) << rel;
        }
        EXPECT_TRUE(encrypted(read_raw(data / "tree/nodes/alpha.json")));
        vault.reset();
        auto state = nlohmann::json::parse(read_raw(state_path()));
        state.erase("coverage");
        write_raw(state_path(), state.dump());
    }

    fs::path state_path() const { return data / "security/storage/vault-state.json"; }

    static constexpr uint64_t kMonth = 30ULL * 24 * 3600 * 1000;
    nexus::crypto::SodiumCryptoService crypto;
    fs::path root;
    fs::path data;
    std::map<std::string, std::string> originals;
    FakeKeys keys;
    std::unique_ptr<StorageVault> vault;
    uint64_t now_ms = 1'800'000'000'000ULL;
};

// --- Valid path --------------------------------------------------------------------

TEST_F(StorageVaultTest, MigrationEncryptsEveryCoveredFileAfterAFreshRoundTrip) {
    keys.unlock();
    build(64);
    EXPECT_EQ(vault->mode(), VaultMode::Plaintext);
    tick();
    // Staged, then a fresh unlock round trip before any plaintext goes.
    EXPECT_EQ(vault->mode(), VaultMode::Migrating);
    EXPECT_EQ(keys.verification_requests, 1);
    for (const auto& [rel, text] : originals) EXPECT_EQ(read_raw(data / rel), text);
    ASSERT_TRUE(run_to_done());
    expect_encrypted_contents();
    EXPECT_NE(vault->last_rotation_ms(), 0u);
    // A write after the migration is encrypted too.
    ASSERT_TRUE(vault->write(data / "tree/nodes/gamma.json", "{\"id\":\"gamma\"}"));
    EXPECT_TRUE(encrypted(read_raw(data / "tree/nodes/gamma.json")));
    EXPECT_EQ(vault->read(data / "tree/nodes/gamma.json").bytes, "{\"id\":\"gamma\"}");
}

// Phase 7b: the ACME account key and every issued cert private key are covered
// by the default storage coverage, so they are DEK-encrypted at rest. The
// public fullchain and the metadata file stay plaintext (they are not secret).
TEST_F(StorageVaultTest, CoverageCoversAcmeKeysNotPublicCerts) {
    build();
    EXPECT_TRUE(vault->covers(data / "certs" / "account.key"));
    EXPECT_TRUE(vault->covers(data / "certs" / "server-abc.eu-west.seip.lemonade-nexus.io" / "privkey.pem"));
    EXPECT_TRUE(vault->covers(data / "certs" / "private.server-abc.eu-west.seip.lemonade-nexus.io" / "privkey.pem"));
    // Public, non-secret files are not covered.
    EXPECT_FALSE(vault->covers(data / "certs" / "server-abc.eu-west.seip.lemonade-nexus.io" / "fullchain.pem"));
    EXPECT_FALSE(vault->covers(data / "certs" / "server-abc.eu-west.seip.lemonade-nexus.io" / "meta.json"));
}

// Link token (invite) state is encrypted at rest: the provider's ledger and
// the gossip replica file. A plaintext token file from an earlier release is
// not covered, so the provider still reads it during the upgrade window.
TEST_F(StorageVaultTest, CoverageCoversLinkTokenState) {
    build();
    EXPECT_TRUE(vault->covers(data / "link_tokens" / "ledger.json"));
    EXPECT_TRUE(vault->covers(data / "link_replica" / "replica.json"));
    EXPECT_FALSE(vault->covers(data / "link_tokens" / (std::string(64, 'a') + ".json")));
}

// A symlink anywhere in a covered directory makes the scan incomplete, and an
// incomplete scan must not be treated as a complete empty one. A symlinked
// privkey.pem must not be staged, promoted, or reported as migrated: the
// plaintext it points at has to stay on disk and the vault must refuse the
// scan. A symlink defeats no permissions, so this holds for a root test run
// too. (A symlink is never trusted vault content: followed, it could loop the
// walk; ignored, it could hide or impersonate a real file.)
TEST_F(StorageVaultTest, SymlinkInCoveredDirectoryKeepsThePlaintextAndBlocksMigration) {
    write_raw(data / "certs/account.key", "acme-account-secret");
    const auto fqdn = data / "certs" / "server-abc.example";
    fs::create_directories(fqdn);
    fs::create_directories(data / "certs" / "outside");
    write_raw(data / "certs" / "outside" / "real-key.pem", "target-key");
    ASSERT_EQ(::symlink("../outside/real-key.pem",
                        (fqdn / "privkey.pem").c_str()),
              0);

    build(64);
    // The scan fails: a symlink in a covered directory means the list is
    // incomplete or unsafe, so enumerate() returns empty.
    const auto files = vault->test_enumerate_relative();
    EXPECT_TRUE(files.empty());

    keys.unlock();
    tick(40);
    // Migration must not have finished: a private key file is still unscannable.
    EXPECT_NE(vault->mode(), VaultMode::Encrypted);
    EXPECT_FALSE(done());
    // The symlinked file was never staged; the plaintext it points at is
    // untouched, and no plaintext anywhere was promoted to ciphertext in its
    // place of a staged copy.
    EXPECT_FALSE(fs::exists(fqdn / "privkey.pem.vault-new"));
    EXPECT_EQ(read_raw(fqdn / "privkey.pem"), "target-key");  // via the symlink
    EXPECT_EQ(read_raw(data / "certs" / "outside" / "real-key.pem"), "target-key");
    EXPECT_FALSE(encrypted(read_raw(data / "certs" / "account.key")));
    for (const auto& [rel, text] : originals) EXPECT_EQ(read_raw(data / rel), text);

    // Remove the symlink: the scan is clean again and migration completes.
    fs::remove(fqdn / "privkey.pem");
    ASSERT_TRUE(run_to_done());
    expect_encrypted_contents();
    EXPECT_TRUE(encrypted(read_raw(data / "certs" / "account.key")));
    EXPECT_EQ(vault->read(data / "certs" / "account.key").bytes,
              "acme-account-secret");
}

TEST_F(StorageVaultTest, WithoutTHoldersThePlaintextStaysAndMigrationRetries) {
    // Locked: never starts.
    build();
    tick(20);
    EXPECT_EQ(vault->mode(), VaultMode::Plaintext);
    // Unlocked but the round trip after staging does not come back.
    keys.dek = keys.persisted;
    keys.verified = true;
    keys.holders_answer = false;
    tick(40);
    EXPECT_EQ(vault->mode(), VaultMode::Migrating);
    EXPECT_EQ(vault->phase(), VaultPhase::Verifying);
    for (const auto& [rel, text] : originals) EXPECT_EQ(read_raw(data / rel), text);
    EXPECT_TRUE(vault->files_ready());
    // The holders return: it completes.
    keys.verified = true;
    ASSERT_TRUE(run_to_done());
    expect_encrypted_contents();
}

TEST_F(StorageVaultTest, InterruptedMigrationResumesAfterACrashAtEveryStep) {
    for (int k = 0;; ++k) {
        ASSERT_LT(k, 100);
        vault.reset();
        SetUp();
        keys = FakeKeys{};
        keys.unlock();
        build(1);
        tick(k);
        const bool finished = done();
        crash_and_restart();
        ASSERT_TRUE(run_to_done()) << "crash after " << k << " ticks";
        expect_encrypted_contents();
        if (::testing::Test::HasFailure()) return;
        if (finished) break;
    }
}

TEST_F(StorageVaultTest, CrashBetweenOverwriteAndReplacementLosesNothing) {
    keys.unlock();
    build(64);
    tick();  // staged; verification requested
    ASSERT_EQ(vault->phase(), VaultPhase::Verifying);
    vault.reset();
    // The commit was recorded and one plaintext was already overwritten, but
    // its staged copy was not yet moved over it.
    const auto state = data / "security/storage/vault-state.json";
    auto text = read_raw(state);
    const auto at = text.find("\"migrating\"");
    ASSERT_NE(at, std::string::npos);
    text.replace(at, 11, "\"encrypted\"");
    const auto phase = text.find("\"verifying\"");
    ASSERT_NE(phase, std::string::npos);
    text.replace(phase, 11, "\"promoting\"");
    write_raw(state, text);
    write_raw(data / "tree/nodes/alpha.json", std::string(14, '\0'));
    build();
    expect_encrypted_contents();
}

TEST_F(StorageVaultTest, InterruptedRotationResumesWithoutDataLossAtEveryStep) {
    for (int k = 0;; ++k) {
        ASSERT_LT(k, 100);
        vault.reset();
        SetUp();
        keys = FakeKeys{};
        migrate();
        const Key before = keys.persisted;
        ASSERT_TRUE(vault->request_rotation());
        tick(k);
        const bool finished = done();
        crash_and_restart();
        ASSERT_TRUE(run_to_done()) << "crash after " << k << " ticks";
        expect_encrypted_contents();
        // The rotation completed: the files are under a new DEK, and the old
        // one opens none of them.
        EXPECT_NE(keys.persisted, before);
        keys.dek = before;
        EXPECT_EQ(vault->read(data / "tree/nodes/alpha.json").status, VaultReadStatus::Rejected);
        if (::testing::Test::HasFailure()) return;
        if (finished) break;
    }
}

TEST_F(StorageVaultTest, RotationRunsMonthlyOnTheLocalClockAndOnRequest) {
    migrate();
    const Key first = keys.persisted;
    tick(10);
    EXPECT_EQ(keys.persisted, first);
    now_ms += kMonth;
    tick(60);
    ASSERT_TRUE(done());
    EXPECT_NE(keys.persisted, first);
    expect_encrypted_contents();
    const Key second = keys.persisted;
    EXPECT_TRUE(vault->request_rotation());
    EXPECT_TRUE(vault->rotation_requested());
    ASSERT_TRUE(run_to_done());
    EXPECT_NE(keys.persisted, second);
    expect_encrypted_contents();
}

TEST_F(StorageVaultTest, RotationRequestIsRefusedBeforeMigration) {
    keys.unlock();
    build();
    EXPECT_FALSE(vault->request_rotation());
}

// --- Rejections --------------------------------------------------------------------

TEST_F(StorageVaultTest, WrongKeyTamperedFileAndSwappedPathAreRejected) {
    migrate();
    const auto alpha = data / "tree/nodes/alpha.json";
    const auto beta = data / "tree/nodes/beta.json";
    // Wrong DEK.
    const Key right = *keys.dek;
    keys.dek = random_key();
    EXPECT_EQ(vault->read(alpha).status, VaultReadStatus::Rejected);
    keys.dek = right;
    // Tampered ciphertext.
    auto raw = read_raw(alpha);
    raw.back() = static_cast<char>(raw.back() ^ 0x01);
    write_raw(alpha, raw);
    EXPECT_EQ(vault->read(alpha).status, VaultReadStatus::Rejected);
    // Another file's valid object at this path (same domain), and another
    // domain's valid object at this path: the AAD binds both.
    write_raw(alpha, read_raw(beta));
    EXPECT_EQ(vault->read(alpha).status, VaultReadStatus::Rejected);
    write_raw(data / "identity/keypair.enc", read_raw(data / "identity/jwt_secret.hex"));
    EXPECT_EQ(vault->read(data / "identity/keypair.enc").status, VaultReadStatus::Rejected);
    // A planted plaintext is never accepted after the migration.
    write_raw(beta, "{\"id\":\"beta\"}");
    EXPECT_EQ(vault->read(beta).status, VaultReadStatus::Rejected);
}

TEST_F(StorageVaultTest, DeletedStateFileDoesNotTurnEncryptedFilesIntoPlaintext) {
    migrate();
    fs::remove(data / "security/storage/vault-state.json");
    build();
    EXPECT_EQ(vault->mode(), VaultMode::Encrypted);
    EXPECT_EQ(StorageVault::recorded_mode(data / "security/storage"), std::nullopt);
    write_raw(data / "tree/nodes/beta.json", "{\"id\":\"beta\"}");
    EXPECT_EQ(vault->read(data / "tree/nodes/beta.json").status, VaultReadStatus::Rejected);
    EXPECT_EQ(vault->read(data / "tree/nodes/alpha.json").status, VaultReadStatus::Ok);
}

// --- Restart with the DEK locked ---------------------------------------------------

TEST_F(StorageVaultTest, LockedRestartServesNothingAndDependentsWait) {
    migrate();
    crash_and_restart(/*holders_up=*/false);
    EXPECT_FALSE(vault->files_ready());
    EXPECT_EQ(StorageVault::recorded_mode(data / "security/storage"), VaultMode::Encrypted);

    nexus::storage::FileStorageService files{data};
    files.start();
    files.set_vault(vault.get());
    EXPECT_FALSE(files.read_node("alpha").has_value());
    const auto before = read_raw(data / "tree/nodes/alpha.json");
    nexus::storage::SignedEnvelope envelope;
    envelope.type = "tree_node";
    envelope.data = "{\"changed\":true,\"id\":\"alpha\"}";
    EXPECT_FALSE(files.write_node("alpha", envelope));
    EXPECT_EQ(read_raw(data / "tree/nodes/alpha.json"), before);
    EXPECT_EQ(vault->read(data / "identity/jwt_secret.hex").status, VaultReadStatus::Locked);

    // The startup gate keeps waiting while locked and returns once unlocked.
    asio::io_context io;
    int polls = 0;
    EXPECT_FALSE(nexus::core::wait_for_storage_unlock(io, *vault, [&] { return ++polls > 2; }));
    keys.unlock();
    EXPECT_TRUE(nexus::core::wait_for_storage_unlock(io, *vault, [] { return false; }));
    EXPECT_TRUE(files.write_node("alpha", envelope));
    const auto read = files.read_node("alpha");
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read->data, envelope.data);
    EXPECT_TRUE(encrypted(read_raw(data / "tree/nodes/alpha.json")));
    files.stop();
}

// --- Startup with encrypted files and lost storage state ----------------------------

TEST_F(StorageVaultTest, ProductionStartupRefusesEncryptedFilesWithoutTheirStorageState) {
    migrate();
    crash_and_restart(/*holders_up=*/false);
    ASSERT_EQ(vault->mode(), VaultMode::Encrypted);
    // records.json and data-key.json are gone (a re-found, or the directory
    // moved aside); the vault state still records `encrypted`.
    ASSERT_FALSE(fs::exists(data / "security/storage/records.json"));
    ASSERT_FALSE(fs::exists(data / "security/storage/data-key.json"));

    // The fixture's placeholder public key file is not a key.
    fs::remove(data / "identity/keypair.pub");
    asio::io_context io;
    nexus::storage::FileStorageService files{data};
    files.start();
    nexus::crypto::KeyWrappingService wrapping{crypto, files};
    wrapping.start();
    nexus::gossip::GossipService gossip{io, 0, files, crypto};
    gossip.start();
    nexus::core::ServerConfig config;
    config.data_root = data.string();
    const auto genesis = crypto.ed25519_keygen();
    config.genesis_pubkey = nexus::crypto::to_base64(genesis.public_key);

    std::string error;
    auto startup = nexus::core::start_security_mesh(
        io, config, gossip, wrapping, PlatformEvidenceSource{}, PlatformActivationSource{}, error,
        {}, nexus::core::SecurityMeshStorageInputs{.vault = vault.get()});
    EXPECT_FALSE(startup.has_value());
    EXPECT_NE(error.find("records.json"), std::string::npos) << error;
    EXPECT_NE(error.find("data-key.json"), std::string::npos) << error;
    // Nothing was created in their place, and the files are untouched.
    EXPECT_FALSE(fs::exists(data / "security/storage/records.json"));
    EXPECT_FALSE(fs::exists(data / "security/storage/data-key.json"));
    EXPECT_TRUE(encrypted(read_raw(data / "identity/keypair.enc")));
    vault->attach(&keys);
    gossip.stop();
    wrapping.stop();
    files.stop();
}

TEST_F(StorageVaultTest, ProductionStartupRunsWithPlaintextFilesAndNoStorageState) {
    keys.holders_answer = false;
    build();
    ASSERT_EQ(vault->mode(), VaultMode::Plaintext);
    // The fixture's placeholder public key file is not a key.
    fs::remove(data / "identity/keypair.pub");
    asio::io_context io;
    nexus::storage::FileStorageService files{data};
    files.start();
    nexus::crypto::KeyWrappingService wrapping{crypto, files};
    wrapping.start();
    nexus::gossip::GossipService gossip{io, 0, files, crypto};
    gossip.start();
    nexus::core::ServerConfig config;
    config.data_root = data.string();
    const auto genesis = crypto.ed25519_keygen();
    config.genesis_pubkey = nexus::crypto::to_base64(genesis.public_key);

    std::string error;
    auto startup = nexus::core::start_security_mesh(
        io, config, gossip, wrapping, PlatformEvidenceSource{}, PlatformActivationSource{}, error,
        {}, nexus::core::SecurityMeshStorageInputs{.vault = vault.get()});
    ASSERT_TRUE(startup.has_value()) << error;
    EXPECT_TRUE(startup->service->storage_key()->halt_reason().empty());
    startup->service->stop();
    startup.reset();
    gossip.stop();
    wrapping.stop();
    files.stop();
}

// --- Flag off ----------------------------------------------------------------------

TEST_F(StorageVaultTest, WithoutAVaultFileStorageIsUnchanged) {
    nexus::storage::FileStorageService files{data};
    files.start();
    nexus::storage::SignedEnvelope envelope;
    envelope.type = "tree_node";
    envelope.data = "{\"id\":\"gamma\"}";
    ASSERT_TRUE(files.write_node("gamma", envelope));
    const auto raw = read_raw(data / "tree/nodes/gamma.json");
    EXPECT_FALSE(encrypted(raw));
    EXPECT_NE(raw.find("tree_node"), std::string::npos);
    EXPECT_EQ(files.vault_for(data / "tree/nodes/gamma.json"), nullptr);
    EXPECT_EQ(StorageVault::recorded_mode(data / "security/storage"), std::nullopt);
    files.stop();
}

// A device certificate key is written through the vault (write_secret_file),
// so it must be read back through the vault. A raw read hands the DEK
// ciphertext to /api/certs/issue, which then encrypts it for the device.
TEST_F(StorageVaultTest, AcmeCertificateKeyIsReadThroughTheVault) {
    migrate();
    nexus::storage::FileStorageService files(data);
    nexus::acme::AcmeService acme(files);
    acme.set_vault(vault.get());

    const std::string fqdn = "laptop.capi.example.test";
    const auto dir = data / "certs" / fqdn;
    write_raw(dir / "fullchain.pem", "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n");
    ASSERT_TRUE(vault->write(dir / "privkey.pem", "device-private-key"));
    ASSERT_TRUE(encrypted(read_raw(dir / "privkey.pem")));

    const auto bundle = acme.get_certificate(fqdn);
    ASSERT_TRUE(bundle.has_value());
    EXPECT_EQ(bundle->privkey_pem, "device-private-key");

    // Locked after a restart: the key is absent, never ciphertext.
    crash_and_restart(/*holders_up=*/false);
    acme.set_vault(vault.get());
    EXPECT_FALSE(acme.get_certificate(fqdn).has_value());
}

// The tree merge reads a backup of this server's data directory with the data
// key the running server holds (StorageVault::copy_view). Only a genuine copy
// under the current DEK opens, at the same relative path; the copy is never
// written.
TEST_F(StorageVaultTest, ACopyViewReadsABackupWithTheCurrentDataKeyAndWritesNothing) {
    migrate();
    const auto backup = root / "backup" / "data";
    fs::create_directories(backup.parent_path());
    fs::copy(data, backup, fs::copy_options::recursive);

    const auto view = vault->copy_view(backup);
    EXPECT_EQ(view->mode(), VaultMode::Encrypted);
    for (const auto& [rel, text] : originals) {
        const auto read = view->read(backup / rel);
        ASSERT_EQ(read.status, VaultReadStatus::Ok) << rel;
        EXPECT_EQ(read.bytes, text) << rel;
    }
    // Nothing is written, removed, or rotated through the view.
    const auto alpha = backup / "tree/nodes/alpha.json";
    const auto raw = read_raw(alpha);
    EXPECT_FALSE(view->write(alpha, "{\"id\":\"forged\"}"));
    EXPECT_FALSE(view->remove(alpha));
    EXPECT_FALSE(view->request_rotation());
    view->tick(now_ms + kMonth * 2);
    EXPECT_EQ(read_raw(alpha), raw);

    // A file moved to another path does not open, and neither does the copy
    // once the DEK in memory is another one.
    write_raw(backup / "tree/nodes/beta.json", raw);
    EXPECT_EQ(view->read(backup / "tree/nodes/beta.json").status, VaultReadStatus::Rejected);
    keys.dek = random_key();
    EXPECT_EQ(view->read(alpha).status, VaultReadStatus::Rejected);
}

// A backup taken before the files were encrypted reads as plaintext: its own
// state file says so.
TEST_F(StorageVaultTest, ACopyViewOfAPlaintextBackupReadsItsPlaintext) {
    keys.unlock();
    build();
    const auto backup = root / "backup" / "data";
    fs::create_directories(backup.parent_path());
    fs::copy(data, backup, fs::copy_options::recursive);
    ASSERT_TRUE(run_to_done());  // the live files are encrypted now

    const auto view = vault->copy_view(backup);
    EXPECT_EQ(view->mode(), VaultMode::Plaintext);
    const auto read = view->read(backup / "tree/nodes/alpha.json");
    ASSERT_EQ(read.status, VaultReadStatus::Ok);
    EXPECT_EQ(read.bytes, "{\"id\":\"alpha\"}");
}

// --- Coverage generation 2 --------------------------------------------------------

TEST_F(StorageVaultTest, CoverageGenerationTwoCoversTreeAdmissionAndAccountData) {
    build();
    EXPECT_TRUE(vault->covers(data / "tree" / "committed-ops.json"));
    EXPECT_TRUE(vault->covers(data / "onboarding" / "admissions.json"));
    EXPECT_TRUE(vault->covers(data / ("chat-" + std::string(64, 'a')) / "0123.json"));
    EXPECT_TRUE(vault->covers(data / ("keyenv-" + std::string(64, 'b')) / "4567.json"));
    // A prefix group covers files directly inside a top-level directory only.
    EXPECT_FALSE(vault->covers(data / "chat-" / "0123.json"));
    EXPECT_FALSE(vault->covers(data / "chat-aa" / "sub" / "0123.json"));
    EXPECT_FALSE(vault->covers(data / "account" / "chat-aa" / "0123.json"));
    EXPECT_FALSE(vault->covers(data / "keyenv-bb" / "4567.json.tmp"));
    // The tree's transfer pool and other files stay as they were.
    EXPECT_FALSE(vault->covers(data / "tree" / "retained_deltas" / (std::string(64, 'c') + ".json")));
    EXPECT_FALSE(vault->covers(data / "onboarding" / "other.json"));

    // A symlink with a covered prefix makes the scan incomplete.
    fs::create_directories(root / "elsewhere");
    fs::create_directory_symlink(root / "elsewhere", data / "keyenv-cc33");
    EXPECT_TRUE(vault->test_enumerate_relative().empty());
    fs::remove(data / "keyenv-cc33");
    EXPECT_FALSE(vault->test_enumerate_relative().empty());
}

// A fresh migration encrypts the generation-2 groups with every other group
// and records the generation, so nothing waits for adoption.
TEST_F(StorageVaultTest, FreshMigrationRecordsTheCurrentCoverageGeneration) {
    migrate();
    EXPECT_FALSE(vault->adoption_pending());
    EXPECT_TRUE(vault->files_ready());
    EXPECT_EQ(nlohmann::json::parse(read_raw(state_path())).value("coverage", 0), 2);
}

// The in-place update: a server already "encrypted" under generation 1 adopts
// the new groups with no manual step, and loses nothing.
TEST_F(StorageVaultTest, AddedCoverageIsAdoptedOnAnEncryptedVault) {
    migrate_first_generation();
    build();
    EXPECT_EQ(vault->mode(), VaultMode::Encrypted);
    EXPECT_TRUE(vault->adoption_pending());
    // The DEK is in memory, but the services that read covered files wait.
    EXPECT_FALSE(vault->files_ready());
    // Until the adoption commits, the plaintext of the new groups is
    // authoritative, and the earlier groups stay encrypted.
    for (const auto& rel : kGenerationTwo) {
        const auto read = vault->read(data / rel);
        ASSERT_EQ(read.status, VaultReadStatus::Ok) << rel;
        EXPECT_EQ(read.bytes, originals.at(rel)) << rel;
    }
    EXPECT_EQ(vault->read(data / "tree/nodes/alpha.json").bytes,
              originals.at("tree/nodes/alpha.json"));

    tick();
    EXPECT_FALSE(vault->adoption_pending());
    EXPECT_TRUE(vault->files_ready());
    expect_encrypted_contents();
    EXPECT_EQ(nlohmann::json::parse(read_raw(state_path())).value("coverage", 0), 2);

    // A restart unlocks and reads the adopted files without a new adoption.
    crash_and_restart();
    EXPECT_FALSE(vault->adoption_pending());
    EXPECT_TRUE(vault->files_ready());
    expect_encrypted_contents();
    // A rotation re-encrypts the adopted files too.
    const Key before = keys.persisted;
    ASSERT_TRUE(vault->request_rotation());
    ASSERT_TRUE(run_to_done());
    EXPECT_NE(keys.persisted, before);
    expect_encrypted_contents();
}

TEST_F(StorageVaultTest, AdoptionWaitsForTheDataKeyAndAVerifiedUnlock) {
    migrate_first_generation();
    keys.restart();
    build();
    tick(3);
    EXPECT_TRUE(vault->adoption_pending());
    EXPECT_FALSE(vault->files_ready());
    for (const auto& rel : kGenerationTwo) EXPECT_EQ(read_raw(data / rel), originals.at(rel));
    keys.dek = keys.persisted;  // in memory, but no round trip proved it yet
    tick(3);
    EXPECT_TRUE(vault->adoption_pending());
    for (const auto& rel : kGenerationTwo) EXPECT_EQ(read_raw(data / rel), originals.at(rel));
    keys.unlock();
    tick();
    EXPECT_FALSE(vault->adoption_pending());
    expect_encrypted_contents();
}

// After the adoption the new groups fail closed like every other group.
TEST_F(StorageVaultTest, AdoptedFilesRefusePlaintextAndMovedObjectsAfterRestart) {
    migrate_first_generation();
    build();
    tick();
    ASSERT_FALSE(vault->adoption_pending());
    const auto ops = data / "tree/committed-ops.json";
    const auto admissions = data / "onboarding/admissions.json";
    const auto ops_object = read_raw(ops);

    write_raw(ops, "{\"format\":1,\"ids\":[]}");
    EXPECT_EQ(vault->read(ops).status, VaultReadStatus::Rejected);
    crash_and_restart();
    EXPECT_FALSE(vault->adoption_pending());
    EXPECT_TRUE(vault->files_ready());
    EXPECT_EQ(vault->read(ops).status, VaultReadStatus::Rejected);
    tick();
    // The plaintext is not adopted after a restart either.
    EXPECT_FALSE(encrypted(read_raw(ops)));

    // Another path's valid object: the AAD binds the domain and the path.
    write_raw(ops, read_raw(admissions));
    EXPECT_EQ(vault->read(ops).status, VaultReadStatus::Rejected);
    write_raw(data / "keyenv-bb22/p2.json", read_raw(data / "keyenv-bb22/p1.json"));
    EXPECT_EQ(vault->read(data / "keyenv-bb22/p2.json").status, VaultReadStatus::Rejected);
    // Tampered ciphertext.
    auto tampered = ops_object;
    tampered.back() = static_cast<char>(tampered.back() ^ 0x01);
    write_raw(ops, tampered);
    EXPECT_EQ(vault->read(ops).status, VaultReadStatus::Rejected);
    // The original object still opens.
    write_raw(ops, ops_object);
    EXPECT_EQ(vault->read(ops).bytes, originals.at("tree/committed-ops.json"));
}

// The adoption applies to the new groups only: plaintext planted in a group
// of an earlier generation stays refused and is never encrypted.
TEST_F(StorageVaultTest, AdoptionNeverAcceptsPlaintextInAnEarlierGroup) {
    migrate_first_generation();
    write_raw(data / "tree/nodes/planted.json", "{\"id\":\"planted\"}");
    write_raw(data / "identity/jwt_secret.hex", "planted-secret");
    build();
    EXPECT_EQ(vault->read(data / "tree/nodes/planted.json").status, VaultReadStatus::Rejected);
    EXPECT_EQ(vault->read(data / "identity/jwt_secret.hex").status, VaultReadStatus::Rejected);
    tick();
    EXPECT_FALSE(vault->adoption_pending());
    EXPECT_EQ(read_raw(data / "tree/nodes/planted.json"), "{\"id\":\"planted\"}");
    EXPECT_EQ(read_raw(data / "identity/jwt_secret.hex"), "planted-secret");
    EXPECT_EQ(vault->read(data / "tree/nodes/planted.json").status, VaultReadStatus::Rejected);
    EXPECT_EQ(vault->read(data / "identity/jwt_secret.hex").status, VaultReadStatus::Rejected);
}

// A file in a new group that holds the header but does not open under the
// current DEK is neither adopted nor dropped: the files stay locked.
TEST_F(StorageVaultTest, AdoptionStopsAtAnEncryptedFileThatDoesNotOpen) {
    migrate_first_generation();
    const auto foreign = data / "keyenv-bb22/foreign.json";
    {
        StorageVault other(data, root / "other-state", crypto);
        const auto object = other.seal_for(foreign, random_key(), "{\"data\":\"x\"}");
        ASSERT_TRUE(object.has_value());
        write_raw(foreign, *object);
    }
    build();
    tick(3);
    EXPECT_TRUE(vault->adoption_pending());
    EXPECT_FALSE(vault->files_ready());
    for (const auto& rel : kGenerationTwo) EXPECT_EQ(read_raw(data / rel), originals.at(rel));
    // Removing the foreign file lets the adoption finish.
    fs::remove(foreign);
    tick();
    EXPECT_FALSE(vault->adoption_pending());
    expect_encrypted_contents();
}

// A crash after the adoption record and before every replacement: load()
// finishes the replacements without the DEK, and nothing is lost, even when
// a plaintext was already overwritten.
TEST_F(StorageVaultTest, CrashAfterTheAdoptionRecordFinishesTheReplacements) {
    migrate_first_generation();
    {
        StorageVault sealer(data, root / "unused-state", crypto);
        for (const auto& rel : kGenerationTwo) {
            const auto object = sealer.seal_for(data / rel, *keys.dek, originals.at(rel));
            ASSERT_TRUE(object.has_value()) << rel;
            write_raw(data / (rel + ".vault-new"), *object);
        }
    }
    auto state = nlohmann::json::parse(read_raw(state_path()));
    state["coverage"] = 2;
    state["phase"] = "promoting";
    write_raw(state_path(), state.dump());
    write_raw(data / "tree/committed-ops.json", std::string(20, '\0'));

    keys.restart();  // load() needs no key
    build();
    EXPECT_FALSE(vault->adoption_pending());
    EXPECT_EQ(vault->phase(), VaultPhase::Idle);
    keys.unlock();
    expect_encrypted_contents();
}

// A crash before the record leaves staged copies beside the plaintext; the
// plaintext stays authoritative and the next adoption replaces them.
TEST_F(StorageVaultTest, CrashBeforeTheAdoptionRecordKeepsThePlaintext) {
    migrate_first_generation();
    write_raw(data / "tree/committed-ops.json.vault-new", "LNXVAULT-stale");
    write_raw(data / "chat-aa11/gone.json.vault-new", "LNXVAULT-orphan");
    build();
    EXPECT_EQ(vault->read(data / "tree/committed-ops.json").bytes,
              originals.at("tree/committed-ops.json"));
    tick();
    EXPECT_FALSE(vault->adoption_pending());
    expect_encrypted_contents();
    EXPECT_FALSE(fs::exists(data / "chat-aa11/gone.json.vault-new"));
    EXPECT_FALSE(fs::exists(data / "chat-aa11/gone.json"));
}

// A rotation that a generation-1 server began before the update: before its
// commit it is discarded, the adoption runs, and the rotation runs again.
TEST_F(StorageVaultTest, RotationInterruptedByTheUpdateIsDiscardedAndRunsAgain) {
    for (const bool restart : {false, true}) {
        SCOPED_TRACE(restart ? "process restart" : "same process");
        vault.reset();
        SetUp();
        keys = FakeKeys{};
        keys.unlock();
        build(1, first_generation_coverage());
        ASSERT_TRUE(run_to_done());
        const Key before = keys.persisted;
        ASSERT_TRUE(vault->request_rotation());
        tick(2);
        ASSERT_EQ(vault->phase(), VaultPhase::RotateStaging);
        if (restart) {
            crash_and_restart();
        } else {
            build();
        }
        ASSERT_TRUE(vault->adoption_pending());
        ASSERT_TRUE(run_to_done());
        EXPECT_FALSE(vault->adoption_pending());
        expect_encrypted_contents();
        EXPECT_NE(keys.persisted, before);
        if (::testing::Test::HasFailure()) return;
    }
}

TEST_F(StorageVaultTest, ACopyViewOfAFirstGenerationBackupReadsItsNewGroupsAsPlaintext) {
    migrate_first_generation();
    const auto backup = root / "backup" / "data";
    fs::create_directories(backup.parent_path());
    fs::copy(data, backup, fs::copy_options::recursive);
    build();
    tick();
    ASSERT_FALSE(vault->adoption_pending());

    const auto view = vault->copy_view(backup);
    for (const auto& [rel, text] : originals) {
        const auto read = view->read(backup / rel);
        ASSERT_EQ(read.status, VaultReadStatus::Ok) << rel;
        EXPECT_EQ(read.bytes, text) << rel;
    }
    EXPECT_EQ(read_raw(backup / "tree/committed-ops.json"),
              originals.at("tree/committed-ops.json"));
}

// --- Services on the generation-2 groups ---------------------------------------------

TEST_F(StorageVaultTest, TreeCommittedOpsAreSealedAndAPlantedPlaintextIsRefused) {
    migrate();
    nexus::storage::FileStorageService files{data};
    files.start();
    files.set_vault(vault.get());
    const std::string id(64, 'a');
    const auto refusal = [](const nexus::tree::PermissionTreeService& tree) {
        return tree.validate_local_op(nexus::tree::TreeOp{}, nexus::tree::TreeOpPolicy{}, 0)
            .refusal;
    };
    {
        nexus::tree::PermissionTreeService tree{files, crypto};
        tree.start();
        nexus::tree::CommittedOpIds ids;
        ids.insert(id, 1'800'000'000);
        ASSERT_TRUE(tree.replace_all(tree.nodes_snapshot(), ids));
        tree.stop();
    }
    const auto path = data / "tree/committed-ops.json";
    EXPECT_TRUE(encrypted(read_raw(path)));
    {
        nexus::tree::PermissionTreeService tree{files, crypto};
        tree.start();
        EXPECT_TRUE(tree.committed_ids().contains(id));
        EXPECT_NE(refusal(tree), nexus::tree::TreeOpRefusal::StorageError);
        tree.stop();
    }
    // A plaintext record is refused, and the tree refuses operations rather
    // than forget the committed ids.
    write_raw(path, "{\"format\":1,\"ids\":[]}");
    {
        nexus::tree::PermissionTreeService tree{files, crypto};
        tree.start();
        EXPECT_FALSE(tree.committed_ids().contains(id));
        EXPECT_EQ(refusal(tree), nexus::tree::TreeOpRefusal::StorageError);
        tree.stop();
    }
    // Locked: the ids are unknown, not empty.
    crash_and_restart(/*holders_up=*/false);
    files.set_vault(vault.get());
    {
        nexus::tree::PermissionTreeService tree{files, crypto};
        tree.start();
        EXPECT_EQ(refusal(tree), nexus::tree::TreeOpRefusal::StorageError);
        tree.stop();
    }
    files.stop();
}

TEST_F(StorageVaultTest, AdmissionsAndAccountDataAreWrittenThroughTheVault) {
    migrate();
    nexus::storage::FileStorageService files{data};
    files.start();
    files.set_vault(vault.get());
    nexus::storage::SignedEnvelope envelope;
    envelope.type = "admissions";
    envelope.data = "{\"admissions\":[]}";
    ASSERT_TRUE(files.write_file("onboarding", "admissions.json", envelope));
    EXPECT_TRUE(encrypted(read_raw(data / "onboarding/admissions.json")));
    const auto admissions = files.read_file("onboarding", "admissions.json");
    ASSERT_TRUE(admissions.has_value());
    EXPECT_EQ(admissions->data, envelope.data);

    const std::string category = "keyenv-" + std::string(64, 'd');
    envelope.type = "key_envelope";
    envelope.data = "{\"wrapped\":\"opaque\"}";
    ASSERT_TRUE(files.write_file(category, "p9.json", envelope));
    EXPECT_TRUE(encrypted(read_raw(data / category / "p9.json")));
    EXPECT_EQ(files.list_files(category), std::vector<std::string>{"p9"});
    const auto key_envelope = files.read_file(category, "p9.json");
    ASSERT_TRUE(key_envelope.has_value());
    EXPECT_EQ(key_envelope->data, envelope.data);
    EXPECT_TRUE(files.delete_file(category, "p9.json"));
    EXPECT_TRUE(files.list_files(category).empty());
    files.stop();
}

// --- User credentials --------------------------------------------------------------

/// One Ed25519 device that signs in through Ed25519AuthProvider.
struct Device {
    nexus::crypto::Ed25519Keypair keys;
    std::string pubkey_b64;
};

Device make_device(nexus::crypto::SodiumCryptoService& crypto) {
    Device d;
    d.keys = crypto.ed25519_keygen();
    d.pubkey_b64 = nexus::crypto::to_base64(std::span<const uint8_t>(d.keys.public_key));
    return d;
}

nexus::auth::AuthResult sign_in(nexus::auth::Ed25519AuthProvider& provider,
                                nexus::crypto::SodiumCryptoService& crypto, const Device& d) {
    const auto challenge = provider.issue_challenge(d.pubkey_b64)["challenge"].get<std::string>();
    const auto bytes = nexus::crypto::from_base64(challenge);
    const auto signature =
        crypto.ed25519_sign(d.keys.private_key, std::span<const uint8_t>(bytes));
    return provider.do_authenticate(
        {{"pubkey", d.pubkey_b64},
         {"challenge", challenge},
         {"signature", nexus::crypto::to_base64(std::span<const uint8_t>(signature))}});
}

nlohmann::json passkey_registration(const std::string& user_id, const std::string& id) {
    return {{"user_id", user_id},
            {"credential_id", id},
            {"public_key_x", std::string(64, 'a')},
            {"public_key_y", std::string(64, 'b')}};
}

std::map<std::string, std::string> snapshot(const fs::path& dir) {
    std::map<std::string, std::string> out;
    for (const auto& entry : fs::directory_iterator(dir)) {
        out[entry.path().filename().string()] = read_raw(entry.path());
    }
    return out;
}

// Credentials that a generation-1 server wrote as plaintext are adopted in
// place; sign-in and revocation work through the vault afterwards, also after
// a restart.
TEST_F(StorageVaultTest, PlaintextCredentialsAreAdoptedAndSignInWorksAfterRestart) {
    const auto alice = make_device(crypto);
    const auto revoked = make_device(crypto);
    std::string alice_id;
    keys.unlock();
    build(1, first_generation_coverage());
    ASSERT_TRUE(run_to_done());
    {
        nexus::storage::FileStorageService files{data};
        files.start();
        files.set_vault(vault.get());
        nexus::auth::Ed25519AuthProvider provider{files, crypto, "jwt-secret"};
        const auto first = sign_in(provider, crypto, alice);
        ASSERT_TRUE(first.authenticated) << first.error_message;
        alice_id = first.user_id;
        ASSERT_TRUE(sign_in(provider, crypto, revoked).authenticated);
        ASSERT_TRUE(provider.revoke_pubkey(revoked.pubkey_b64));
        files.stop();
    }
    const auto alice_file = data / "credentials" / (alice_id + ".json");
    ASSERT_FALSE(encrypted(read_raw(alice_file)));
    ASSERT_FALSE(encrypted(read_raw(data / "credentials/revoked.json")));
    vault.reset();
    auto state = nlohmann::json::parse(read_raw(state_path()));
    state.erase("coverage");
    write_raw(state_path(), state.dump());

    build();
    ASSERT_TRUE(vault->adoption_pending());
    tick();
    ASSERT_FALSE(vault->adoption_pending());
    EXPECT_TRUE(encrypted(read_raw(alice_file)));
    EXPECT_TRUE(encrypted(read_raw(data / "credentials/revoked.json")));

    for (int run = 0; run < 2; ++run) {
        SCOPED_TRACE(run == 0 ? "after the adoption" : "after a restart");
        nexus::storage::FileStorageService files{data};
        files.start();
        files.set_vault(vault.get());
        nexus::auth::Ed25519AuthProvider provider{files, crypto, "jwt-secret"};
        const auto again = sign_in(provider, crypto, alice);
        ASSERT_TRUE(again.authenticated) << again.error_message;
        EXPECT_EQ(again.user_id, alice_id);
        EXPECT_FALSE(sign_in(provider, crypto, revoked).authenticated);
        EXPECT_TRUE(provider.is_pubkey_revoked(revoked.pubkey_b64));
        files.stop();
        crash_and_restart();
    }
}

TEST_F(StorageVaultTest, NewUsersRegisterUnderTheDataKey) {
    migrate();
    nexus::storage::FileStorageService files{data};
    files.start();
    files.set_vault(vault.get());
    nexus::auth::Ed25519AuthProvider ed25519{files, crypto, "jwt-secret"};
    const auto device = make_device(crypto);
    const auto result = sign_in(ed25519, crypto, device);
    ASSERT_TRUE(result.authenticated) << result.error_message;
    EXPECT_TRUE(encrypted(read_raw(data / "credentials" / (result.user_id + ".json"))));

    nexus::auth::PasskeyAuthProvider passkey{files, crypto, "example.test", "jwt-secret"};
    const auto registered = passkey.do_register(passkey_registration("carol", "cred-carol"));
    ASSERT_TRUE(registered.authenticated) << registered.error_message;
    const auto carol = data / "credentials/carol.json";
    EXPECT_TRUE(encrypted(read_raw(carol)));
    const auto opened = vault->read(carol);
    ASSERT_EQ(opened.status, VaultReadStatus::Ok);
    EXPECT_NE(opened.bytes.find("cred-carol"), std::string::npos);
    files.stop();
}

// A credential file that does not open refuses sign-in, registration, and
// every change, and stays byte for byte as it was.
TEST_F(StorageVaultTest, ATamperedCredentialFileRefusesSignInAndIsNotOverwritten) {
    migrate();
    const auto device = make_device(crypto);
    std::string user_id;
    {
        nexus::storage::FileStorageService files{data};
        files.start();
        files.set_vault(vault.get());
        nexus::auth::Ed25519AuthProvider provider{files, crypto, "jwt-secret"};
        const auto result = sign_in(provider, crypto, device);
        ASSERT_TRUE(result.authenticated) << result.error_message;
        user_id = result.user_id;
        nexus::auth::PasskeyAuthProvider passkey{files, crypto, "example.test", "jwt-secret"};
        ASSERT_TRUE(passkey.do_register(passkey_registration(user_id, "cred-1")).authenticated);
        files.stop();
    }
    const auto path = data / "credentials" / (user_id + ".json");
    auto tampered = read_raw(path);
    tampered.back() = static_cast<char>(tampered.back() ^ 0x01);
    write_raw(path, tampered);
    const auto before = snapshot(data / "credentials");

    nexus::storage::FileStorageService files{data};
    files.start();
    files.set_vault(vault.get());
    nexus::auth::Ed25519AuthProvider provider{files, crypto, "jwt-secret"};
    // The key is in the unreadable file, so it is neither found nor
    // registered again as a new identity.
    EXPECT_FALSE(sign_in(provider, crypto, device).authenticated);
    EXPECT_FALSE(sign_in(provider, crypto, make_device(crypto)).authenticated);
    nexus::auth::PasskeyAuthProvider passkey{files, crypto, "example.test", "jwt-secret"};
    EXPECT_FALSE(passkey.do_register(passkey_registration(user_id, "cred-2")).authenticated);
    EXPECT_FALSE(passkey.do_register(passkey_registration("dave", "cred-3")).authenticated);
    EXPECT_FALSE(passkey.remove_user_credentials(user_id));
    EXPECT_EQ(snapshot(data / "credentials"), before);
    files.stop();
}

// An unreadable revocation list counts every key as revoked and is never
// replaced by a partial list.
TEST_F(StorageVaultTest, ATamperedRevocationListRefusesEverySessionAndIsNotOverwritten) {
    migrate();
    const auto device = make_device(crypto);
    const auto other = make_device(crypto);
    {
        nexus::storage::FileStorageService files{data};
        files.start();
        files.set_vault(vault.get());
        nexus::auth::Ed25519AuthProvider provider{files, crypto, "jwt-secret"};
        ASSERT_TRUE(sign_in(provider, crypto, device).authenticated);
        ASSERT_TRUE(sign_in(provider, crypto, other).authenticated);
        ASSERT_TRUE(provider.revoke_pubkey(other.pubkey_b64));
        files.stop();
    }
    const auto revoked = data / "credentials/revoked.json";
    const auto good = read_raw(revoked);
    write_raw(revoked, "[]");  // planted plaintext
    const auto before = snapshot(data / "credentials");

    nexus::storage::FileStorageService files{data};
    files.start();
    files.set_vault(vault.get());
    {
        nexus::auth::Ed25519AuthProvider provider{files, crypto, "jwt-secret"};
        EXPECT_FALSE(sign_in(provider, crypto, device).authenticated);
        EXPECT_FALSE(sign_in(provider, crypto, other).authenticated);
        EXPECT_TRUE(provider.is_pubkey_revoked(device.pubkey_b64));
        EXPECT_TRUE(provider.is_user_revoked("any-user"));
        EXPECT_FALSE(provider.revoke_pubkey(device.pubkey_b64));
        EXPECT_FALSE(provider.unrevoke_pubkey(other.pubkey_b64));
        EXPECT_EQ(snapshot(data / "credentials"), before);
    }
    // The same provider recovers once the file opens again.
    write_raw(revoked, good);
    {
        nexus::auth::Ed25519AuthProvider provider{files, crypto, "jwt-secret"};
        EXPECT_TRUE(sign_in(provider, crypto, device).authenticated);
        EXPECT_FALSE(sign_in(provider, crypto, other).authenticated);
    }
    files.stop();
}

// With the data key locked, nothing signs in, registers, or writes.
TEST_F(StorageVaultTest, LockedCredentialsRefuseSignInAndWriteNothing) {
    migrate();
    const auto device = make_device(crypto);
    {
        nexus::storage::FileStorageService files{data};
        files.start();
        files.set_vault(vault.get());
        nexus::auth::Ed25519AuthProvider provider{files, crypto, "jwt-secret"};
        ASSERT_TRUE(sign_in(provider, crypto, device).authenticated);
        files.stop();
    }
    crash_and_restart(/*holders_up=*/false);
    const auto before = snapshot(data / "credentials");
    nexus::storage::FileStorageService files{data};
    files.start();
    files.set_vault(vault.get());
    nexus::auth::Ed25519AuthProvider provider{files, crypto, "jwt-secret"};
    EXPECT_FALSE(sign_in(provider, crypto, device).authenticated);
    EXPECT_FALSE(sign_in(provider, crypto, make_device(crypto)).authenticated);
    nexus::auth::PasskeyAuthProvider passkey{files, crypto, "example.test", "jwt-secret"};
    EXPECT_FALSE(passkey.do_register(passkey_registration("erin", "cred-4")).authenticated);
    EXPECT_EQ(snapshot(data / "credentials"), before);

    // After the unlock the same Ed25519 provider reads the files again.
    keys.unlock();
    EXPECT_TRUE(sign_in(provider, crypto, device).authenticated);
    files.stop();
}

}  // namespace
