#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/Epoch/EpochStore.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <unistd.h>

using namespace nexus::security;
namespace fs = std::filesystem;

namespace {

NodeId node(uint8_t byte) {
    NodeId id;
    id.bytes.fill(byte);
    return id;
}

nexus::crypto::Ed25519PublicKey key(uint8_t byte) {
    nexus::crypto::Ed25519PublicKey value{};
    value.fill(byte);
    return value;
}

struct EpochStoreFixture : ::testing::Test {
    void SetUp() override {
        root = fs::temp_directory_path() / ("nexus_epoch_store_" + std::to_string(::getpid()));
        fs::create_directories(root);
        crypto.start();
        storage.emplace((root / "data").string());
        storage->start();
        wrapping.emplace(crypto, *storage);
        wrapping->start();
        store.emplace(root / "security", &*wrapping);
    }

    void TearDown() override {
        wrapping->stop();
        storage->stop();
        crypto.stop();
        fs::remove_all(root);
    }

    StoredEpoch sample_epoch() const {
        std::vector<NodeId> members;
        for (uint8_t i = 1; i <= 5; ++i) members.push_back(node(i));
        NetworkId network;
        network.fill(0x0F);
        Digest root_digest;
        root_digest.fill(0x11);
        StoredEpoch epoch{make_epoch_state(3, network, *Tier1Set::from_nodes(members), key(0xA0),
                                           root_digest),
                          {},
                          {}};
        for (const auto& member : members) epoch.vote_keys[member] = key(member.bytes[0]);
        epoch.checkpoint.fill(0x22);
        return epoch;
    }

    fs::path root;
    nexus::crypto::SodiumCryptoService crypto;
    std::optional<nexus::storage::FileStorageService> storage;
    std::optional<nexus::crypto::KeyWrappingService> wrapping;
    std::optional<EpochStore> store;
};

TEST_F(EpochStoreFixture, EpochRoundTripRecomputesThresholds) {
    const auto epoch = sample_epoch();
    ASSERT_TRUE(store->store_epoch(epoch));
    const auto loaded = store->load_epoch();
    ASSERT_TRUE(std::holds_alternative<StoredEpoch>(loaded));
    const auto& back = std::get<StoredEpoch>(loaded);
    EXPECT_EQ(back.state.id, 3u);
    EXPECT_EQ(back.state.tier1_members.members(), epoch.state.tier1_members.members());
    EXPECT_EQ(back.state.consensus_quorum, 4u);
    EXPECT_EQ(back.state.authority_threshold, 5u);
    EXPECT_EQ(back.state.authority_public_key, key(0xA0));
    EXPECT_EQ(back.vote_keys, epoch.vote_keys);
    EXPECT_EQ(back.checkpoint, epoch.checkpoint);
}

TEST_F(EpochStoreFixture, AbsentAndCorruptAreDistinct) {
    EXPECT_EQ(std::get<EpochLoadResult>(store->load_epoch()), EpochLoadResult::Absent);
    EXPECT_EQ(std::get<EpochLoadResult>(store->load_bootstrap()), EpochLoadResult::Absent);

    std::ofstream(store->directory() / "epoch-current.json") << "{not json";
    EXPECT_EQ(std::get<EpochLoadResult>(store->load_epoch()), EpochLoadResult::Corrupt);

    std::ofstream(store->directory() / "bootstrap-certificate.json") << "[]";
    EXPECT_EQ(std::get<EpochLoadResult>(store->load_bootstrap()), EpochLoadResult::Corrupt);

    // A leftover temp file from a crashed write is ignored.
    ASSERT_TRUE(store->store_epoch(sample_epoch()));
    std::ofstream(store->directory() / "epoch-current.json.tmp") << "garbage";
    EXPECT_TRUE(std::holds_alternative<StoredEpoch>(store->load_epoch()));
}

TEST_F(EpochStoreFixture, BootstrapCertificateRoundTrip) {
    BootstrapCertificate certificate;
    certificate.network_id.fill(0x0F);
    certificate.epoch = 1;
    certificate.tier1_set_digest.fill(0x31);
    certificate.authority_threshold = 5;
    certificate.authority_public_key = key(0xA0);
    certificate.dkg_transcript_digest.fill(0x32);
    certificate.attestation_root.fill(0x33);
    certificate.security_ruleset = 1;
    certificate.consensus_ruleset = 1;
    certificate.genesis_signature.fill(0x44);
    ASSERT_TRUE(store->store_bootstrap(certificate));
    const auto loaded = store->load_bootstrap();
    ASSERT_TRUE(std::holds_alternative<BootstrapCertificate>(loaded));
    EXPECT_EQ(bootstrap_certificate_signing_digest(std::get<BootstrapCertificate>(loaded)),
              bootstrap_certificate_signing_digest(certificate));
    EXPECT_EQ(std::get<BootstrapCertificate>(loaded).genesis_signature,
              certificate.genesis_signature);
}

TEST_F(EpochStoreFixture, AuthorityHistoryAppendsOncePerEpoch) {
    EXPECT_EQ(std::get<EpochLoadResult>(store->load_authority_history()),
              EpochLoadResult::Absent);
    EpochAuthorityRecord one{1, key(0xA1), {}, {}};
    EpochAuthorityRecord two{2, key(0xA2), {}, {}};
    ASSERT_TRUE(store->append_authority(one));
    ASSERT_TRUE(store->append_authority(two));
    // Same epoch, same key: idempotent. Same epoch, other key: refused.
    EXPECT_TRUE(store->append_authority(one));
    EpochAuthorityRecord forged{1, key(0xEE), {}, {}};
    EXPECT_FALSE(store->append_authority(forged));

    const auto history = store->load_authority_history();
    ASSERT_TRUE(std::holds_alternative<std::vector<EpochAuthorityRecord>>(history));
    const auto& records = std::get<std::vector<EpochAuthorityRecord>>(history);
    ASSERT_EQ(records.size(), 2u);
    EXPECT_EQ(records[0].epoch, 1u);
    EXPECT_EQ(records[1].group_public_key, key(0xA2));
}

TEST_F(EpochStoreFixture, VoteKeyIsWrappedAtRestAndRestored) {
    const NodeId self = node(0x07);
    EpochVoteKey original = make_epoch_vote_key(3, self);
    const std::vector<uint8_t> secret(original.private_key.data(),
                                      original.private_key.data() + original.private_key.size());
    ASSERT_TRUE(store->store_vote_key(original));

    // The file holds no plaintext key bytes.
    std::ifstream in(store->directory() / "vote-key-3.json");
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_EQ(text.find(nexus::crypto::to_base64(secret)), std::string::npos);

    auto restored = store->load_vote_key(3, self);
    ASSERT_TRUE(restored.has_value());
    EXPECT_EQ(restored->public_key, original.public_key);
    EXPECT_TRUE(std::equal(secret.begin(), secret.end(), restored->private_key.data()));

    // Another node identity or epoch does not unlock it.
    EXPECT_FALSE(store->load_vote_key(3, node(0x08)).has_value());
    EXPECT_FALSE(store->load_vote_key(4, self).has_value());

    store->discard_vote_key(3);
    EXPECT_FALSE(store->load_vote_key(3, self).has_value());
}

TEST(EpochStoreWithoutWrapping, VoteKeyIsNotPersisted) {
    const fs::path dir = fs::temp_directory_path() / ("nexus_epoch_store_nowrap_" +
                                                      std::to_string(::getpid()));
    EpochStore store(dir, nullptr);
    EpochVoteKey key = make_epoch_vote_key(1, node(0x01));
    EXPECT_FALSE(store.store_vote_key(key));
    EXPECT_FALSE(store.load_vote_key(1, node(0x01)).has_value());
    fs::remove_all(dir);
}

}  // namespace
