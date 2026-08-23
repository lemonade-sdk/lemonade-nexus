#include <LemonadeNexus/Security/Consensus/ConsensusStore.hpp>
#include <LemonadeNexus/Security/Consensus/ConsensusTypes.hpp>
#include <LemonadeNexus/Security/Consensus/HotStuffState.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <unistd.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <variant>

namespace constants = nexus::security::constants;
namespace fs = std::filesystem;
using nexus::security::ConsensusCommit;
using nexus::security::Digest;
using nexus::security::EpochId;
using nexus::security::FileConsensusStore;
using nexus::security::HotStuffState;
using nexus::security::IConsensusStore;
using nexus::security::NodeId;
using nexus::security::QcSigner;
using nexus::security::QuorumCertificate;
using nexus::security::View;
using LoadResult = IConsensusStore::LoadResult;

namespace {

[[nodiscard]] Digest filled_digest(uint8_t value) {
    Digest digest{};
    digest.fill(value);
    return digest;
}

[[nodiscard]] NodeId filled_node(uint8_t value) {
    NodeId node{};
    node.bytes.fill(value);
    return node;
}

[[nodiscard]] QuorumCertificate make_qc(EpochId epoch, View view, uint8_t seed) {
    QuorumCertificate certificate{};
    certificate.qc_format_version = constants::kQcFormatVersion;
    certificate.consensus_ruleset = constants::kConsensusRulesetVersion;
    certificate.network_id = filled_digest(0xAA);
    certificate.epoch = epoch;
    certificate.height = view;
    certificate.view = view;
    certificate.proposal_digest = filled_digest(seed);
    for (uint8_t i = 0; i < 3; ++i) {
        QcSigner signer{};
        signer.node_id = filled_node(static_cast<uint8_t>(i + 1));
        signer.signature.fill(static_cast<uint8_t>(seed + i));
        certificate.signers.push_back(signer);
    }
    return certificate;
}

[[nodiscard]] HotStuffState make_state(EpochId epoch,
                                       View last_voted,
                                       View high_view,
                                       View locked_view) {
    HotStuffState state;
    state.epoch = epoch;
    state.last_voted_view = last_voted;
    state.high_qc = make_qc(epoch, high_view, 0x30);
    state.locked_qc = make_qc(epoch, locked_view, 0x40);
    return state;
}

void expect_qc_eq(const QuorumCertificate& a, const QuorumCertificate& b) {
    EXPECT_EQ(a.qc_format_version, b.qc_format_version);
    EXPECT_EQ(a.consensus_ruleset, b.consensus_ruleset);
    EXPECT_EQ(a.network_id, b.network_id);
    EXPECT_EQ(a.epoch, b.epoch);
    EXPECT_EQ(a.height, b.height);
    EXPECT_EQ(a.view, b.view);
    EXPECT_EQ(a.proposal_digest, b.proposal_digest);
    ASSERT_EQ(a.signers.size(), b.signers.size());
    for (std::size_t i = 0; i < a.signers.size(); ++i) {
        EXPECT_EQ(a.signers[i].node_id, b.signers[i].node_id);
        EXPECT_EQ(a.signers[i].signature, b.signers[i].signature);
    }
}

void expect_state_eq(const HotStuffState& a, const HotStuffState& b) {
    EXPECT_EQ(a.epoch, b.epoch);
    EXPECT_EQ(a.consensus_ruleset, b.consensus_ruleset);
    EXPECT_EQ(a.last_voted_view, b.last_voted_view);
    expect_qc_eq(a.high_qc, b.high_qc);
    expect_qc_eq(a.locked_qc, b.locked_qc);
}

[[nodiscard]] const HotStuffState& loaded(const std::variant<HotStuffState, LoadResult>& result) {
    return std::get<HotStuffState>(result);
}

class ConsensusStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        directory_ = fs::temp_directory_path() /
                     ("nexus_test_consensus_store_" + std::string(info->name()) + "_" +
                      std::to_string(::getpid()));
        fs::remove_all(directory_);
    }

    void TearDown() override { fs::remove_all(directory_); }

    [[nodiscard]] fs::path safety_file(EpochId epoch) const {
        return directory_ / ("hotstuff-safety-" + std::to_string(epoch) + ".json");
    }

    void write_raw(const fs::path& path, const std::string& content) const {
        std::ofstream stream(path, std::ios::binary | std::ios::trunc);
        stream << content;
    }

    fs::path directory_;
};

TEST_F(ConsensusStoreTest, ConstructorCreatesDirectory) {
    EXPECT_FALSE(fs::exists(directory_));
    FileConsensusStore store(directory_);
    EXPECT_TRUE(fs::is_directory(directory_));
}

TEST_F(ConsensusStoreTest, RoundTripsFullStateWithCertificates) {
    FileConsensusStore store(directory_);
    const auto state = make_state(7, 12, 11, 10);
    ASSERT_TRUE(store.store_before_vote(state));
    EXPECT_TRUE(fs::exists(safety_file(7)));
    EXPECT_FALSE(fs::exists(safety_file(7).string() + ".tmp"));

    const auto result = store.load(7);
    ASSERT_TRUE(std::holds_alternative<HotStuffState>(result));
    expect_state_eq(loaded(result), state);
}

TEST_F(ConsensusStoreTest, LoadIsAbsentWhenNothingStored) {
    FileConsensusStore store(directory_);
    const auto result = store.load(42);
    ASSERT_TRUE(std::holds_alternative<LoadResult>(result));
    EXPECT_EQ(std::get<LoadResult>(result), LoadResult::Absent);
}

TEST_F(ConsensusStoreTest, LoadIsCorruptOnGarbage) {
    FileConsensusStore store(directory_);
    write_raw(safety_file(7), "\xff\xfe this is not json{{{");
    const auto result = store.load(7);
    ASSERT_TRUE(std::holds_alternative<LoadResult>(result));
    // Corrupt is NOT Absent.
    EXPECT_EQ(std::get<LoadResult>(result), LoadResult::Corrupt);
}

TEST_F(ConsensusStoreTest, LoadIsCorruptOnTruncatedJson) {
    FileConsensusStore store(directory_);
    ASSERT_TRUE(store.store_before_vote(make_state(7, 5, 4, 3)));
    const auto full = nexus::security::hotstuff_state_to_json(make_state(7, 5, 4, 3)).dump();
    write_raw(safety_file(7), full.substr(0, full.size() / 2));
    const auto result = store.load(7);
    ASSERT_TRUE(std::holds_alternative<LoadResult>(result));
    EXPECT_EQ(std::get<LoadResult>(result), LoadResult::Corrupt);
}

TEST_F(ConsensusStoreTest, LoadIsCorruptOnMalformedField) {
    FileConsensusStore store(directory_);
    auto document = nexus::security::hotstuff_state_to_json(make_state(7, 5, 4, 3));
    // A digest that is not 32 bytes.
    document["high_qc"]["proposal_digest"] = "AAEC";
    write_raw(safety_file(7), document.dump());
    const auto result = store.load(7);
    ASSERT_TRUE(std::holds_alternative<LoadResult>(result));
    EXPECT_EQ(std::get<LoadResult>(result), LoadResult::Corrupt);
}

TEST_F(ConsensusStoreTest, LeftoverTempFileIsIgnored) {
    FileConsensusStore store(directory_);
    write_raw(safety_file(7).string() + ".tmp", "torn write garbage");

    // No final file: the temp file does not count as state.
    auto result = store.load(7);
    ASSERT_TRUE(std::holds_alternative<LoadResult>(result));
    EXPECT_EQ(std::get<LoadResult>(result), LoadResult::Absent);

    // A real store replaces it and loads normally.
    const auto state = make_state(7, 3, 2, 1);
    ASSERT_TRUE(store.store_before_vote(state));
    result = store.load(7);
    ASSERT_TRUE(std::holds_alternative<HotStuffState>(result));
    expect_state_eq(loaded(result), state);

    // The final file is authoritative even next to a torn temp file.
    write_raw(safety_file(7).string() + ".tmp", "torn write garbage again");
    result = store.load(7);
    ASSERT_TRUE(std::holds_alternative<HotStuffState>(result));
    expect_state_eq(loaded(result), state);
}

TEST_F(ConsensusStoreTest, RefusesLowerLastVotedView) {
    FileConsensusStore store(directory_);
    const auto stored = make_state(7, 5, 4, 3);
    ASSERT_TRUE(store.store_before_vote(stored));

    EXPECT_FALSE(store.store_before_vote(make_state(7, 4, 4, 3)));

    // The file is unchanged.
    const auto result = store.load(7);
    ASSERT_TRUE(std::holds_alternative<HotStuffState>(result));
    expect_state_eq(loaded(result), stored);
}

TEST_F(ConsensusStoreTest, RefusesHighQcOrLockedQcRegression) {
    FileConsensusStore store(directory_);
    const auto stored = make_state(7, 5, 4, 3);
    ASSERT_TRUE(store.store_before_vote(stored));

    EXPECT_FALSE(store.store_before_vote(make_state(7, 6, 3, 3)));
    EXPECT_FALSE(store.store_before_vote(make_state(7, 6, 4, 2)));

    const auto result = store.load(7);
    ASSERT_TRUE(std::holds_alternative<HotStuffState>(result));
    expect_state_eq(loaded(result), stored);

    // Equal values are not a regression.
    EXPECT_TRUE(store.store_before_vote(make_state(7, 5, 4, 3)));
    EXPECT_TRUE(store.store_before_vote(make_state(7, 6, 5, 4)));
}

TEST_F(ConsensusStoreTest, EpochInsideFileMustMatchItsSlot) {
    FileConsensusStore store(directory_);
    // An epoch-8 state written into the epoch-7 slot is a misplaced disk.
    write_raw(safety_file(7), nexus::security::hotstuff_state_to_json(make_state(8, 2, 1, 0)).dump());

    const auto result = store.load(7);
    ASSERT_TRUE(std::holds_alternative<LoadResult>(result));
    EXPECT_EQ(std::get<LoadResult>(result), LoadResult::Corrupt);

    // Storing over it is refused; voting must stop.
    EXPECT_FALSE(store.store_before_vote(make_state(7, 9, 8, 7)));
}

TEST_F(ConsensusStoreTest, CommitRoundTrip) {
    FileConsensusStore store(directory_);
    EXPECT_EQ(store.latest_commit(7), std::nullopt);

    ConsensusCommit commit{};
    commit.epoch = 7;
    commit.height = 3;
    commit.view = 5;
    commit.proposal_digest = filled_digest(0x51);
    commit.proposed_state_root = filled_digest(0x52);
    commit.qc_digest = filled_digest(0x53);
    ASSERT_TRUE(store.store_commit(commit));

    const auto latest = store.latest_commit(7);
    ASSERT_TRUE(latest.has_value());
    EXPECT_EQ(latest->epoch, commit.epoch);
    EXPECT_EQ(latest->height, commit.height);
    EXPECT_EQ(latest->view, commit.view);
    EXPECT_EQ(latest->proposal_digest, commit.proposal_digest);
    EXPECT_EQ(latest->proposed_state_root, commit.proposed_state_root);
    EXPECT_EQ(latest->qc_digest, commit.qc_digest);

    // A later commit replaces the record.
    commit.height = 4;
    commit.view = 6;
    ASSERT_TRUE(store.store_commit(commit));
    ASSERT_TRUE(store.latest_commit(7).has_value());
    EXPECT_EQ(store.latest_commit(7)->height, 4u);
}

TEST_F(ConsensusStoreTest, TwoEpochsStoreSideBySide) {
    FileConsensusStore store(directory_);
    const auto seven = make_state(7, 5, 4, 3);
    const auto eight = make_state(8, 2, 1, 0);
    ASSERT_TRUE(store.store_before_vote(seven));
    ASSERT_TRUE(store.store_before_vote(eight));
    EXPECT_TRUE(fs::exists(safety_file(7)));
    EXPECT_TRUE(fs::exists(safety_file(8)));

    const auto loaded_seven = store.load(7);
    const auto loaded_eight = store.load(8);
    ASSERT_TRUE(std::holds_alternative<HotStuffState>(loaded_seven));
    ASSERT_TRUE(std::holds_alternative<HotStuffState>(loaded_eight));
    expect_state_eq(loaded(loaded_seven), seven);
    expect_state_eq(loaded(loaded_eight), eight);

    // The epoch-8 view floor is lower; it never guards epoch 7.
    EXPECT_FALSE(store.store_before_vote(make_state(7, 4, 4, 3)));
    EXPECT_TRUE(store.store_before_vote(make_state(8, 3, 2, 1)));
}

}  // namespace
