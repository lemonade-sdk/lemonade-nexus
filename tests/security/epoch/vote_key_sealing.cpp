// Own vote keys at rest under the boot-set seal (EpochStore, design B6): the
// one-way migration from the machine-bound copies, restart, new epochs,
// deletion, crashes between steps, tampering, the fail-closed cases after the
// migration, and hosts that cannot seal.
//
// FakeSealer is a test double for nexus-attestd. It models PCR state, the TPM
// a blob belongs to, and tampering. It is not a TPM, and these tests are not
// TPM evidence.

#include "support/fake_sealer.hpp"

#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/Epoch/EpochStore.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlobStore.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <vector>

#include <unistd.h>

using namespace nexus::security;
namespace fs = std::filesystem;
using json = nlohmann::json;
using seal_test::FakeSealer;
using seal_test::pcrs_of;

namespace {

std::string read_text(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void write_text(const fs::path& path, std::string_view text) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
}

std::vector<uint8_t> secret_of(const EpochVoteKey& key) {
    return {key.private_key.data(), key.private_key.data() + key.private_key.size()};
}

bool holds(const std::optional<EpochVoteKey>& loaded, const EpochVoteKey& expected) {
    return loaded.has_value() && loaded->public_key == expected.public_key &&
           secret_of(*loaded) == secret_of(expected);
}

struct VoteKeySealingTest : ::testing::Test {
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        root = fs::temp_directory_path() /
               ("nexus_vote_key_seal_" + std::to_string(::getpid()) + "_" +
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
        fs::remove_all(root);
        fs::create_directories(root);
        crypto.start();
        files.emplace((root / "data").string());
        files->start();
        wrapping.emplace(crypto, *files);
        wrapping->start();
        self.bytes.fill(0x07);
    }

    void TearDown() override {
        wrapping->stop();
        files->stop();
        crypto.stop();
        std::error_code ec;
        fs::remove_all(root, ec);
    }

    /// One server start: a new EpochStore and a new SealedBlobStore over the
    /// same directories, as after a process restart.
    std::unique_ptr<EpochStore> start(bool with_backend = true,
                                      std::optional<BootPcrValues> next_chain = std::nullopt) {
        auto store = std::make_unique<EpochStore>(security_dir(), &*wrapping);
        SealedBlobStore sealed{sealed_dir(), with_backend ? tpm.backend() : SealBackend{}};
        sealed.set_next_boot_chain(next_chain);
        VoteKeySealing sealing;
        sealing.sealed = &sealed;
        sealing.crypto = &crypto;
        sealing.boot_id = [this] { return boot; };
        sealing.unreachable_attempts = 3;
        sealing.retry_delay = std::chrono::milliseconds(1);
        error.clear();
        protection = store->open_vote_key_sealing(sealing, error);
        return store;
    }

    /// A store as today's binary runs it: machine-bound copies only.
    std::unique_ptr<EpochStore> unsealed_store() {
        return std::make_unique<EpochStore>(security_dir(), &*wrapping);
    }

    /// Runs the migration to completion: seal in one boot, unseal in the next.
    std::unique_ptr<EpochStore> sealed_store() {
        auto first = start();
        EXPECT_EQ(protection, VoteKeyProtection::SealedPending) << error;
        boot = "boot-2";
        auto second = start();
        EXPECT_EQ(protection, VoteKeyProtection::Sealed) << error;
        return second;
    }

    fs::path security_dir() const { return root / "security"; }
    fs::path sealed_dir() const { return root / "sealed"; }
    fs::path machine_bound(uint64_t epoch) const {
        return security_dir() / ("vote-key-" + std::to_string(epoch) + ".json");
    }
    fs::path sealed_copy(uint64_t epoch) const {
        return security_dir() / ("vote-key-" + std::to_string(epoch) + ".sealed.json");
    }
    fs::path blob() const { return sealed_dir() / "vote-key-wrap.sealed"; }
    fs::path next_blob() const { return sealed_dir() / "vote-key-wrap.next.sealed"; }
    fs::path state() const { return sealed_dir() / "vote-key-wrap.state.json"; }
    json state_json() const { return json::parse(read_text(state())); }

    fs::path root;
    nexus::crypto::SodiumCryptoService crypto;
    std::optional<nexus::storage::FileStorageService> files;
    std::optional<nexus::crypto::KeyWrappingService> wrapping;
    FakeSealer tpm;
    std::string boot = "boot-1";
    NodeId self;
    std::string error;
    VoteKeyProtection protection = VoteKeyProtection::MachineBound;
};

// --- Hosts that cannot seal ----------------------------------------------------

TEST_F(VoteKeySealingTest, AHostWithoutSealingKeepsTodaysMachineBoundFile) {
    auto store = start(/*with_backend=*/false);
    EXPECT_EQ(protection, VoteKeyProtection::MachineBound);
    EXPECT_TRUE(error.empty());

    const auto key = make_epoch_vote_key(3, self);
    ASSERT_TRUE(store->store_vote_key(key));
    EXPECT_TRUE(fs::exists(machine_bound(3)));
    EXPECT_FALSE(fs::exists(sealed_copy(3)));
    EXPECT_FALSE(fs::exists(blob()));
    EXPECT_FALSE(fs::exists(state()));
    // Today's format, field for field.
    const auto j = json::parse(read_text(machine_bound(3)));
    EXPECT_EQ(j.size(), 6u);
    EXPECT_EQ(read_text(machine_bound(3)).find(nexus::crypto::to_base64(secret_of(key))),
              std::string::npos);

    auto restarted = start(/*with_backend=*/false);
    EXPECT_EQ(protection, VoteKeyProtection::MachineBound);
    EXPECT_TRUE(holds(restarted->load_vote_key(3, self), key));
}

TEST_F(VoteKeySealingTest, AHostWhoseDaemonCannotSealKeepsTheMachineBoundFile) {
    tpm.available = false;
    auto store = start();
    EXPECT_EQ(protection, VoteKeyProtection::MachineBound);
    EXPECT_FALSE(fs::exists(blob()));
    const auto key = make_epoch_vote_key(3, self);
    ASSERT_TRUE(store->store_vote_key(key));
    EXPECT_FALSE(fs::exists(sealed_copy(3)));
    EXPECT_TRUE(holds(store->load_vote_key(3, self), key));
}

TEST_F(VoteKeySealingTest, WithoutOpeningTheStoreStaysMachineBound) {
    auto store = unsealed_store();
    EXPECT_EQ(store->vote_key_protection(), VoteKeyProtection::MachineBound);
    const auto key = make_epoch_vote_key(2, self);
    ASSERT_TRUE(store->store_vote_key(key));
    EXPECT_TRUE(holds(store->load_vote_key(2, self), key));
}

// --- Migration and restart -----------------------------------------------------

TEST_F(VoteKeySealingTest, ExistingFilesConvertAndTheMachineBoundCopiesStayUntilALaterBoot) {
    const auto three = make_epoch_vote_key(3, self);
    const auto four = make_epoch_vote_key(4, self);
    {
        auto today = unsealed_store();
        ASSERT_TRUE(today->store_vote_key(three));
        ASSERT_TRUE(today->store_vote_key(four));
    }

    auto first = start();
    ASSERT_EQ(protection, VoteKeyProtection::SealedPending) << error;
    EXPECT_TRUE(fs::exists(blob()));
    EXPECT_EQ(state_json()["protection"], "sealed-pending");
    EXPECT_EQ(state_json()["sealed_boot_id"], "boot-1");
    for (const uint64_t epoch : {3u, 4u}) {
        EXPECT_TRUE(fs::exists(machine_bound(epoch)));
        EXPECT_TRUE(fs::exists(sealed_copy(epoch)));
    }
    EXPECT_EQ(read_text(sealed_copy(3)).find(nexus::crypto::to_base64(secret_of(three))),
              std::string::npos);
    EXPECT_TRUE(holds(first->load_vote_key(3, self), three));
    EXPECT_TRUE(holds(first->load_vote_key(4, self), four));

    // A process restart in the same boot changes nothing.
    auto same_boot = start();
    EXPECT_EQ(protection, VoteKeyProtection::SealedPending);
    EXPECT_TRUE(fs::exists(machine_bound(3)));
    EXPECT_TRUE(holds(same_boot->load_vote_key(3, self), three));

    // The sealed wrapping key unseals after a reboot: migration completes.
    boot = "boot-2";
    auto rebooted = start();
    ASSERT_EQ(protection, VoteKeyProtection::Sealed) << error;
    EXPECT_EQ(state_json()["protection"], "sealed");
    EXPECT_EQ(state_json()["sealed_boot_id"], "boot-1");
    EXPECT_FALSE(fs::exists(machine_bound(3)));
    EXPECT_FALSE(fs::exists(machine_bound(4)));
    EXPECT_TRUE(holds(rebooted->load_vote_key(3, self), three));
    EXPECT_TRUE(holds(rebooted->load_vote_key(4, self), four));

    // Later restarts unseal the same key and need no seal call.
    const int seals = tpm.seal_calls;
    boot = "boot-3";
    auto later = start();
    EXPECT_EQ(protection, VoteKeyProtection::Sealed);
    EXPECT_EQ(tpm.seal_calls, seals);
    EXPECT_TRUE(holds(later->load_vote_key(4, self), four));
    // The node and epoch still bind the key.
    EXPECT_FALSE(later->load_vote_key(4, NodeId{}).has_value());
    EXPECT_FALSE(later->load_vote_key(5, self).has_value());
}

TEST_F(VoteKeySealingTest, AnUnknownBootIdNeverFinishesTheMigration) {
    boot.clear();
    const auto key = make_epoch_vote_key(3, self);
    auto first = start();
    ASSERT_EQ(protection, VoteKeyProtection::SealedPending);
    ASSERT_TRUE(first->store_vote_key(key));
    auto second = start();
    EXPECT_EQ(protection, VoteKeyProtection::SealedPending);
    EXPECT_TRUE(fs::exists(machine_bound(3)));
    EXPECT_TRUE(holds(second->load_vote_key(3, self), key));
}

TEST_F(VoteKeySealingTest, ANewEpochKeyIsWrittenToBothFilesWhilePendingAndSealedAfter) {
    auto pending = start();
    ASSERT_EQ(protection, VoteKeyProtection::SealedPending);
    const auto five = make_epoch_vote_key(5, self);
    ASSERT_TRUE(pending->store_vote_key(five));
    EXPECT_TRUE(fs::exists(machine_bound(5)));
    EXPECT_TRUE(fs::exists(sealed_copy(5)));

    boot = "boot-2";
    auto sealed = start();
    ASSERT_EQ(protection, VoteKeyProtection::Sealed);
    const auto six = make_epoch_vote_key(6, self);
    ASSERT_TRUE(sealed->store_vote_key(six));
    EXPECT_FALSE(fs::exists(machine_bound(6)));
    ASSERT_TRUE(fs::exists(sealed_copy(6)));
    EXPECT_EQ(read_text(sealed_copy(6)).find(nexus::crypto::to_base64(secret_of(six))),
              std::string::npos);
#ifndef _WIN32
    EXPECT_EQ(fs::status(sealed_copy(6)).permissions() & fs::perms::all,
              fs::perms::owner_read | fs::perms::owner_write);
#endif

    auto restarted = start();
    EXPECT_EQ(protection, VoteKeyProtection::Sealed);
    EXPECT_TRUE(holds(restarted->load_vote_key(5, self), five));
    EXPECT_TRUE(holds(restarted->load_vote_key(6, self), six));
}

TEST_F(VoteKeySealingTest, DiscardingAnOldEpochRemovesBothCopies) {
    auto pending = start();
    const auto three = make_epoch_vote_key(3, self);
    const auto four = make_epoch_vote_key(4, self);
    ASSERT_TRUE(pending->store_vote_key(three));
    ASSERT_TRUE(pending->store_vote_key(four));
    pending->discard_vote_key(3);
    EXPECT_FALSE(fs::exists(machine_bound(3)));
    EXPECT_FALSE(fs::exists(sealed_copy(3)));
    EXPECT_FALSE(pending->load_vote_key(3, self).has_value());

    boot = "boot-2";
    auto sealed = start();
    ASSERT_EQ(protection, VoteKeyProtection::Sealed);
    sealed->discard_vote_key(4);
    EXPECT_FALSE(fs::exists(sealed_copy(4)));
    EXPECT_FALSE(sealed->load_vote_key(4, self).has_value());
    // The wrapping key stays for the next epoch.
    EXPECT_TRUE(fs::exists(blob()));
}

TEST_F(VoteKeySealingTest, AnApprovedBootChainUpgradeKeepsTheVoteKeys) {
    auto store = sealed_store();
    const auto key = make_epoch_vote_key(3, self);
    ASSERT_TRUE(store->store_vote_key(key));

    const auto next_chain = pcrs_of(0x33, 0x44);
    auto staged = start(true, next_chain);
    ASSERT_EQ(protection, VoteKeyProtection::Sealed);
    EXPECT_TRUE(fs::exists(next_blob()));

    tpm.pcrs = next_chain;
    boot = "boot-new-chain";
    auto upgraded = start(true, next_chain);
    ASSERT_EQ(protection, VoteKeyProtection::Sealed) << error;
    EXPECT_FALSE(fs::exists(next_blob()));
    EXPECT_TRUE(holds(upgraded->load_vote_key(3, self), key));
}

// --- Crashes between steps -----------------------------------------------------

TEST_F(VoteKeySealingTest, ACrashAfterSealingBeforeTheStateFileLosesNothing) {
    const auto key = make_epoch_vote_key(3, self);
    ASSERT_TRUE(unsealed_store()->store_vote_key(key));
    (void)start();
    ASSERT_EQ(protection, VoteKeyProtection::SealedPending);
    // As if the process died after the blob was durable: no state file and no
    // sealed copies yet.
    fs::remove(state());
    fs::remove(sealed_copy(3));

    auto restarted = start();
    ASSERT_EQ(protection, VoteKeyProtection::SealedPending) << error;
    EXPECT_TRUE(fs::exists(state()));
    EXPECT_TRUE(fs::exists(sealed_copy(3)));
    EXPECT_TRUE(fs::exists(machine_bound(3)));
    EXPECT_TRUE(holds(restarted->load_vote_key(3, self), key));
}

TEST_F(VoteKeySealingTest, ACrashMidConversionIsFinishedBeforeTheStateAdvances) {
    const auto three = make_epoch_vote_key(3, self);
    const auto four = make_epoch_vote_key(4, self);
    (void)start();
    ASSERT_EQ(protection, VoteKeyProtection::SealedPending);
    {
        // An older binary or a crash between the two writes of store_vote_key:
        // epoch 4 has only its machine-bound copy, and epoch 3's sealed copy is
        // gone.
        auto today = unsealed_store();
        ASSERT_TRUE(today->store_vote_key(three));
        ASSERT_TRUE(today->store_vote_key(four));
    }
    ASSERT_FALSE(fs::exists(sealed_copy(3)));

    boot = "boot-2";
    auto rebooted = start();
    ASSERT_EQ(protection, VoteKeyProtection::Sealed) << error;
    EXPECT_FALSE(fs::exists(machine_bound(3)));
    EXPECT_FALSE(fs::exists(machine_bound(4)));
    EXPECT_TRUE(holds(rebooted->load_vote_key(3, self), three));
    EXPECT_TRUE(holds(rebooted->load_vote_key(4, self), four));
}

TEST_F(VoteKeySealingTest, ACrashBeforeTheMachineBoundCopiesAreRemovedIsFinishedLater) {
    const auto key = make_epoch_vote_key(3, self);
    auto pending = start();
    ASSERT_TRUE(pending->store_vote_key(key));
    const auto leftover = read_text(machine_bound(3));

    boot = "boot-2";
    (void)start();
    ASSERT_EQ(protection, VoteKeyProtection::Sealed);
    ASSERT_FALSE(fs::exists(machine_bound(3)));
    // As if the process died after recording Sealed but before the scrub.
    write_text(machine_bound(3), leftover);

    auto restarted = start();
    ASSERT_EQ(protection, VoteKeyProtection::Sealed);
    EXPECT_FALSE(fs::exists(machine_bound(3)));
    EXPECT_TRUE(holds(restarted->load_vote_key(3, self), key));
}

// --- Tampering ----------------------------------------------------------------

TEST_F(VoteKeySealingTest, ATamperedOrMovedSealedCopyIsRefused) {
    auto store = sealed_store();
    const auto key = make_epoch_vote_key(3, self);
    ASSERT_TRUE(store->store_vote_key(key));
    const auto original = read_text(sealed_copy(3));

    // Moved to another epoch, with the epoch field edited to match.
    auto moved = json::parse(original);
    moved["epoch"] = 4;
    write_text(sealed_copy(4), moved.dump());
    EXPECT_FALSE(store->load_vote_key(4, self).has_value());

    // Edited node id.
    auto other_node = json::parse(original);
    NodeId other;
    other.bytes.fill(0x09);
    other_node["node_id"] = nexus::crypto::to_base64(other.bytes);
    write_text(sealed_copy(3), other_node.dump());
    EXPECT_FALSE(store->load_vote_key(3, other).has_value());

    // A flipped ciphertext byte.
    auto flipped = json::parse(original);
    auto bytes = nexus::crypto::from_base64(flipped["ciphertext"].get<std::string>());
    bytes[0] ^= 0x01;
    flipped["ciphertext"] = nexus::crypto::to_base64(bytes);
    write_text(sealed_copy(3), flipped.dump());
    EXPECT_FALSE(store->load_vote_key(3, self).has_value());

    // An extra field.
    auto extra = json::parse(original);
    extra["note"] = "x";
    write_text(sealed_copy(3), extra.dump());
    EXPECT_FALSE(store->load_vote_key(3, self).has_value());

    write_text(sealed_copy(3), original);
    EXPECT_TRUE(holds(store->load_vote_key(3, self), key));
}

TEST_F(VoteKeySealingTest, ASealedCopyFromAnotherServerDoesNotOpen) {
    auto store = sealed_store();
    const auto key = make_epoch_vote_key(3, self);
    ASSERT_TRUE(store->store_vote_key(key));
    const auto copied = read_text(sealed_copy(3));

    // Another server: its own data directory and its own wrapping key.
    const auto other_root = root / "other";
    fs::create_directories(other_root);
    EpochStore other(other_root / "security", &*wrapping);
    SealedBlobStore other_sealed{other_root / "sealed", tpm.backend()};
    VoteKeySealing sealing;
    sealing.sealed = &other_sealed;
    sealing.crypto = &crypto;
    std::string other_error;
    ASSERT_EQ(other.open_vote_key_sealing(sealing, other_error),
              VoteKeyProtection::SealedPending);
    write_text(other_root / "security" / "vote-key-3.sealed.json", copied);
    EXPECT_FALSE(other.load_vote_key(3, self).has_value());
}

TEST_F(VoteKeySealingTest, AMachineBoundFileAfterTheMigrationIsNeverUsed) {
    auto store = sealed_store();
    const auto planted = make_epoch_vote_key(7, self);
    ASSERT_TRUE(unsealed_store()->store_vote_key(planted));

    auto restarted = start();
    ASSERT_EQ(protection, VoteKeyProtection::Sealed);
    EXPECT_FALSE(restarted->load_vote_key(7, self).has_value());
    // It does not gain a sealed copy either.
    EXPECT_FALSE(fs::exists(sealed_copy(7)));
}

TEST_F(VoteKeySealingTest, TwoCopiesThatDisagreeWhilePendingAreNotUsed) {
    auto store = start();
    ASSERT_EQ(protection, VoteKeyProtection::SealedPending);
    const auto first = make_epoch_vote_key(3, self);
    ASSERT_TRUE(store->store_vote_key(first));
    const auto first_sealed = read_text(sealed_copy(3));
    const auto second = make_epoch_vote_key(3, self);
    ASSERT_TRUE(store->store_vote_key(second));
    write_text(sealed_copy(3), first_sealed);
    EXPECT_FALSE(store->load_vote_key(3, self).has_value());
}

// --- Fail closed after the migration -------------------------------------------

TEST_F(VoteKeySealingTest, ChangedPcrsAfterTheMigrationRefuseAndChangeNothing) {
    auto store = sealed_store();
    const auto key = make_epoch_vote_key(3, self);
    ASSERT_TRUE(store->store_vote_key(key));
    const auto blob_before = read_text(blob());
    const auto copy_before = read_text(sealed_copy(3));

    tpm.pcrs = pcrs_of(0x55, 0x66);
    auto refused = start();
    EXPECT_EQ(protection, VoteKeyProtection::Refused);
    EXPECT_NE(error.find("policy_mismatch"), std::string::npos) << error;
    EXPECT_FALSE(refused->load_vote_key(3, self).has_value());
    EXPECT_FALSE(refused->store_vote_key(make_epoch_vote_key(4, self)));
    EXPECT_FALSE(fs::exists(machine_bound(4)));
    EXPECT_FALSE(fs::exists(sealed_copy(4)));
    EXPECT_EQ(read_text(blob()), blob_before);
    EXPECT_EQ(read_text(sealed_copy(3)), copy_before);

    // Booting the previous entry recovers everything.
    tpm.pcrs = pcrs_of(0x11, 0x22);
    auto recovered = start();
    EXPECT_EQ(protection, VoteKeyProtection::Sealed);
    EXPECT_TRUE(holds(recovered->load_vote_key(3, self), key));
}

TEST_F(VoteKeySealingTest, ACorruptWrappingKeyAfterTheMigrationRefuses) {
    (void)sealed_store();
    tpm.owner_seed = "owner-seed-B";
    (void)start();
    EXPECT_EQ(protection, VoteKeyProtection::Refused);
    EXPECT_NE(error.find("corrupt"), std::string::npos) << error;
    EXPECT_TRUE(fs::exists(blob()));
}

TEST_F(VoteKeySealingTest, AMissingWrappingKeyAfterTheMigrationRefuses) {
    (void)sealed_store();
    fs::remove(blob());
    (void)start();
    EXPECT_EQ(protection, VoteKeyProtection::Refused);
    EXPECT_NE(error.find("missing"), std::string::npos) << error;
    // No new key is sealed in place of the lost one.
    EXPECT_FALSE(fs::exists(blob()));
}

TEST_F(VoteKeySealingTest, AnUnreachableDaemonAfterTheMigrationRetriesThenRefuses) {
    (void)sealed_store();
    tpm.reachable = false;
    const int before = tpm.unseal_calls;
    (void)start();
    EXPECT_EQ(protection, VoteKeyProtection::Refused);
    EXPECT_EQ(tpm.unseal_calls - before, 3);
    EXPECT_NE(error.find("nexus-attestd"), std::string::npos) << error;
}

TEST_F(VoteKeySealingTest, ABuildWithoutSealingCannotOpenASealedWrappingKey) {
    auto store = sealed_store();
    ASSERT_TRUE(store->store_vote_key(make_epoch_vote_key(3, self)));
    auto unsealed = start(/*with_backend=*/false);
    EXPECT_EQ(protection, VoteKeyProtection::Refused);
    EXPECT_FALSE(unsealed->load_vote_key(3, self).has_value());
}

TEST_F(VoteKeySealingTest, AStateFileThatNamesAnotherKeyRefuses) {
    (void)start();
    ASSERT_EQ(protection, VoteKeyProtection::SealedPending);
    auto j = state_json();
    std::vector<uint8_t> other(16, 0xEE);
    j["key_id"] = nexus::crypto::to_base64(other);
    write_text(state(), j.dump());
    (void)start();
    EXPECT_EQ(protection, VoteKeyProtection::Refused);
}

TEST_F(VoteKeySealingTest, AnUnreadableStateFileRefuses) {
    (void)start();
    write_text(state(), "{not json");
    (void)start();
    EXPECT_EQ(protection, VoteKeyProtection::Refused);
    EXPECT_NE(error.find("unreadable"), std::string::npos);
}

// --- Fallback while pending ----------------------------------------------------

TEST_F(VoteKeySealingTest, ChangedPcrsWhilePendingFallBackToTheMachineBoundCopies) {
    auto pending = start();
    const auto key = make_epoch_vote_key(3, self);
    ASSERT_TRUE(pending->store_vote_key(key));
    const auto old_id = state_json()["key_id"];

    tpm.pcrs = pcrs_of(0x55, 0x66);
    auto fallback = start();
    ASSERT_EQ(protection, VoteKeyProtection::SealedPending) << error;
    EXPECT_NE(state_json()["key_id"], old_id);
    EXPECT_TRUE(fs::exists(machine_bound(3)));
    EXPECT_TRUE(holds(fallback->load_vote_key(3, self), key));

    boot = "boot-2";
    auto sealed = start();
    ASSERT_EQ(protection, VoteKeyProtection::Sealed);
    EXPECT_TRUE(holds(sealed->load_vote_key(3, self), key));
}

TEST_F(VoteKeySealingTest, AVtpmThatLosesItsSeedAtRebootKeepsTheMachineBoundCopies) {
    auto pending = start();
    const auto key = make_epoch_vote_key(3, self);
    ASSERT_TRUE(pending->store_vote_key(key));

    boot = "boot-2";
    tpm.owner_seed = "owner-seed-after-reboot";
    auto after = start();
    ASSERT_EQ(protection, VoteKeyProtection::SealedPending) << error;
    EXPECT_TRUE(fs::exists(machine_bound(3)));
    EXPECT_TRUE(holds(after->load_vote_key(3, self), key));
}

TEST_F(VoteKeySealingTest, AMissingWrappingKeyWhilePendingSealsANewOne) {
    auto pending = start();
    const auto key = make_epoch_vote_key(3, self);
    ASSERT_TRUE(pending->store_vote_key(key));
    fs::remove(blob());

    auto restarted = start();
    ASSERT_EQ(protection, VoteKeyProtection::SealedPending) << error;
    EXPECT_TRUE(fs::exists(blob()));
    EXPECT_TRUE(holds(restarted->load_vote_key(3, self), key));
}

TEST_F(VoteKeySealingTest, AnUnreachableDaemonWhilePendingKeepsTheMachineBoundWrapping) {
    auto pending = start();
    const auto key = make_epoch_vote_key(3, self);
    ASSERT_TRUE(pending->store_vote_key(key));

    tpm.reachable = false;
    auto offline = start();
    EXPECT_EQ(protection, VoteKeyProtection::MachineBound);
    EXPECT_TRUE(fs::exists(blob()));
    EXPECT_TRUE(holds(offline->load_vote_key(3, self), key));
    const auto four = make_epoch_vote_key(4, self);
    ASSERT_TRUE(offline->store_vote_key(four));
    EXPECT_FALSE(fs::exists(sealed_copy(4)));

    // The daemon is back: the key written meanwhile gets its sealed copy.
    tpm.reachable = true;
    boot = "boot-2";
    auto back = start();
    ASSERT_EQ(protection, VoteKeyProtection::Sealed) << error;
    EXPECT_TRUE(holds(back->load_vote_key(3, self), key));
    EXPECT_TRUE(holds(back->load_vote_key(4, self), four));
    EXPECT_FALSE(fs::exists(machine_bound(4)));
}

}  // namespace
