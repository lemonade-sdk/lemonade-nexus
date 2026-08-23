#include "hotstuff_harness.hpp"

#include <gtest/gtest.h>

#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>

namespace {

using namespace hotstuff_test;
using nexus::security::FileConsensusStore;

namespace fs = std::filesystem;

// Restart behavior over a real FileConsensusStore (architecture 11.12).
class HotStuffRestart : public ::testing::Test {
protected:
    void SetUp() override {
        const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
        directory_ = fs::temp_directory_path() /
                     ("nexus_test_hotstuff_restart_" + std::string(info->name()) + "_" +
                      std::to_string(::getpid()));
        fs::remove_all(directory_);
    }

    void TearDown() override { fs::remove_all(directory_); }

    [[nodiscard]] fs::path safety_file() const {
        return directory_ / ("hotstuff-safety-" + std::to_string(kEpoch) + ".json");
    }

    // Votes at views 1 and 2, then goes away.
    void run_first_incarnation() {
        FileConsensusStore store(directory_);
        HotStuffService first(harness.config_for(0), clone_key(harness.keys[0]), store);
        ASSERT_TRUE(first.synced());
        const auto chain = harness.build_chain(2);
        ASSERT_TRUE(first.receive_proposal(chain[0].proposal, chain[0].justify).vote.has_value());
        ASSERT_TRUE(first.receive_proposal(chain[1].proposal, chain[1].justify).vote.has_value());
        ASSERT_TRUE(fs::exists(safety_file()));
    }

    Harness harness{4};
    fs::path directory_;
    const Digest digest = filled_digest(0x99);
};

TEST_F(HotStuffRestart, RestartRequiresCertifiedSyncBeforeAnyVote) {
    run_first_incarnation();

    FileConsensusStore store(directory_);
    HotStuffService second(harness.config_for(0), clone_key(harness.keys[0]), store);
    EXPECT_TRUE(second.usable());
    EXPECT_FALSE(second.synced());
    EXPECT_EQ(second.state().last_voted_view, 2u);
    EXPECT_EQ(second.state().high_qc.view, 1u);

    const auto chain = harness.build_chain(3);
    const auto blocked = second.receive_proposal(chain[2].proposal, chain[2].justify);
    EXPECT_EQ(blocked.rejected, ConsensusFailure::NotSynced);
    EXPECT_FALSE(blocked.vote.has_value());
    EXPECT_EQ(std::get<ConsensusFailure>(second.make_proposal(digest, digest, digest)),
              ConsensusFailure::NotSynced);
    EXPECT_EQ(std::get<ConsensusFailure>(second.receive_vote(harness.make_vote(2, 3, 3, digest))),
              ConsensusFailure::NotSynced);
    EXPECT_EQ(std::get<ConsensusFailure>(
                  second.receive_timeout(harness.make_timeout(2, 3, digest))),
              ConsensusFailure::NotSynced);
    EXPECT_THROW(static_cast<void>(second.make_timeout_vote()), std::logic_error);

    // The certified floor from the active set is above the stored view.
    second.sync_to_certified(5);
    EXPECT_TRUE(second.synced());
    EXPECT_EQ(second.state().last_voted_view, 5u);
    EXPECT_EQ(second.current_view(), 6u);

    // At or below the floor: no vote.
    const auto below = second.receive_proposal(chain[2].proposal, chain[2].justify);
    EXPECT_FALSE(below.vote.has_value());
    EXPECT_EQ(below.rejected, ConsensusFailure::StaleView);

    // Above the floor normal operation resumes. Chain state did not survive
    // the restart, so the first votable block builds on genesis.
    const Block fresh = harness.make_block(1, 8, test_genesis(), harness.genesis_qc(), 0x30);
    const auto above = second.receive_proposal(fresh.proposal, fresh.justify);
    EXPECT_FALSE(above.rejected.has_value());
    ASSERT_TRUE(above.vote.has_value());
    EXPECT_EQ(above.vote->view, 8u);
    EXPECT_GT(above.vote->view, 5u);
    EXPECT_EQ(second.state().last_voted_view, 8u);

    // The floor is on disk for the next incarnation.
    const auto stored = store.load(kEpoch);
    ASSERT_TRUE(std::holds_alternative<HotStuffState>(stored));
    EXPECT_EQ(std::get<HotStuffState>(stored).last_voted_view, 8u);
}

TEST_F(HotStuffRestart, SyncFloorBelowStoredViewKeepsStoredView) {
    run_first_incarnation();

    FileConsensusStore store(directory_);
    HotStuffService second(harness.config_for(0), clone_key(harness.keys[0]), store);
    second.sync_to_certified(1);
    EXPECT_TRUE(second.synced());
    EXPECT_EQ(second.state().last_voted_view, 2u);

    // View 2 was already voted before the restart.
    const auto chain = harness.build_chain(2);
    const auto replay = second.receive_proposal(chain[1].proposal, chain[1].justify);
    EXPECT_FALSE(replay.vote.has_value());
}

TEST_F(HotStuffRestart, CorruptSafetyStateIsPermanentlyUnusable) {
    run_first_incarnation();
    {
        std::ofstream stream(safety_file(), std::ios::binary | std::ios::trunc);
        stream << "\xff\xfe garbage that is not json";
    }

    FileConsensusStore store(directory_);
    HotStuffService broken(harness.config_for(0), clone_key(harness.keys[0]), store);
    EXPECT_FALSE(broken.usable());
    EXPECT_FALSE(broken.synced());

    const auto chain = harness.build_chain(1);
    EXPECT_EQ(broken.receive_proposal(chain[0].proposal, chain[0].justify).rejected,
              ConsensusFailure::NotSynced);
    EXPECT_EQ(std::get<ConsensusFailure>(broken.receive_vote(harness.make_vote(2, 1, 1, digest))),
              ConsensusFailure::NotSynced);
    EXPECT_EQ(std::get<ConsensusFailure>(
                  broken.receive_timeout(harness.make_timeout(2, 1, digest))),
              ConsensusFailure::NotSynced);
    EXPECT_EQ(std::get<ConsensusFailure>(broken.make_proposal(digest, digest, digest)),
              ConsensusFailure::NotSynced);
    EXPECT_THROW(static_cast<void>(broken.make_timeout_vote()), std::logic_error);

    // Sync cannot revive it: Corrupt is never treated as fresh.
    broken.sync_to_certified(100);
    EXPECT_FALSE(broken.usable());
    EXPECT_FALSE(broken.synced());
    EXPECT_EQ(broken.receive_proposal(chain[0].proposal, chain[0].justify).rejected,
              ConsensusFailure::NotSynced);
}

TEST_F(HotStuffRestart, FreshEpochStartsSynced) {
    FileConsensusStore store(directory_);
    EXPECT_FALSE(fs::exists(safety_file()));

    HotStuffService fresh(harness.config_for(0), clone_key(harness.keys[0]), store);
    EXPECT_TRUE(fresh.usable());
    EXPECT_TRUE(fresh.synced());
    EXPECT_EQ(fresh.current_view(), 1u);
    EXPECT_EQ(fresh.state().last_voted_view, 0u);

    const auto chain = harness.build_chain(1);
    const auto result = fresh.receive_proposal(chain[0].proposal, chain[0].justify);
    ASSERT_TRUE(result.vote.has_value());
    EXPECT_EQ(result.vote->view, 1u);
    EXPECT_TRUE(fs::exists(safety_file()));
}

TEST_F(HotStuffRestart, RecordingStoreSeedsRestartAndCorruptPaths) {
    RecordingStore store;
    store.seed_state = HotStuffState{};
    store.seed_state->epoch = kEpoch;
    store.seed_state->last_voted_view = 4;
    store.seed_state->high_qc = harness.genesis_qc();
    store.seed_state->locked_qc = harness.genesis_qc();
    HotStuffService restarted(harness.config_for(0), clone_key(harness.keys[0]), store);
    EXPECT_TRUE(restarted.usable());
    EXPECT_FALSE(restarted.synced());
    EXPECT_EQ(restarted.state().last_voted_view, 4u);

    RecordingStore corrupt;
    corrupt.seed_corrupt = true;
    HotStuffService broken(harness.config_for(0), clone_key(harness.keys[0]), corrupt);
    EXPECT_FALSE(broken.usable());

    // Stored state from another epoch or ruleset is not adopted.
    RecordingStore foreign;
    foreign.seed_state = HotStuffState{};
    foreign.seed_state->epoch = kEpoch + 1;
    HotStuffService mismatched(harness.config_for(0), clone_key(harness.keys[0]), foreign);
    EXPECT_FALSE(mismatched.usable());
}

}  // namespace
