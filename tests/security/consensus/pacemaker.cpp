#include <LemonadeNexus/Security/Consensus/Pacemaker.hpp>

#include <gtest/gtest.h>

#include <chrono>

using nexus::security::Pacemaker;
using std::chrono::milliseconds;

namespace {

TEST(Pacemaker, BackoffSequenceMatchesArchitecture) {
    // 2 s, 4 s, 8 s, 16 s, 30 s, 30 s, ...
    Pacemaker pacemaker;
    EXPECT_EQ(pacemaker.timeout(), milliseconds(2000));
    pacemaker.on_timeout();
    EXPECT_EQ(pacemaker.timeout(), milliseconds(4000));
    pacemaker.on_timeout();
    EXPECT_EQ(pacemaker.timeout(), milliseconds(8000));
    pacemaker.on_timeout();
    EXPECT_EQ(pacemaker.timeout(), milliseconds(16000));
    pacemaker.on_timeout();
    EXPECT_EQ(pacemaker.timeout(), milliseconds(30000));
    pacemaker.on_timeout();
    EXPECT_EQ(pacemaker.timeout(), milliseconds(30000));
}

TEST(Pacemaker, ResetsAfterExactlyThreeConsecutiveCommits) {
    Pacemaker pacemaker;
    pacemaker.on_timeout();
    pacemaker.on_timeout();
    ASSERT_EQ(pacemaker.timeout(), milliseconds(8000));

    pacemaker.on_committed_block();
    EXPECT_EQ(pacemaker.timeout(), milliseconds(8000));
    pacemaker.on_committed_block();
    EXPECT_EQ(pacemaker.timeout(), milliseconds(8000));
    pacemaker.on_committed_block();
    EXPECT_EQ(pacemaker.timeout(), milliseconds(2000));
}

TEST(Pacemaker, TimeoutBetweenCommitsRestartsTheCount) {
    Pacemaker pacemaker;
    pacemaker.on_timeout();
    ASSERT_EQ(pacemaker.timeout(), milliseconds(4000));

    pacemaker.on_committed_block();
    pacemaker.on_committed_block();
    pacemaker.on_timeout();
    EXPECT_EQ(pacemaker.timeout(), milliseconds(8000));

    // The two commits before the timeout must not count any more.
    pacemaker.on_committed_block();
    EXPECT_EQ(pacemaker.timeout(), milliseconds(8000));
    pacemaker.on_committed_block();
    EXPECT_EQ(pacemaker.timeout(), milliseconds(8000));
    pacemaker.on_committed_block();
    EXPECT_EQ(pacemaker.timeout(), milliseconds(2000));
}

TEST(Pacemaker, CommitsAtBaseKeepTheBaseTimeout) {
    Pacemaker pacemaker;
    for (int i = 0; i < 10; ++i) {
        pacemaker.on_committed_block();
        EXPECT_EQ(pacemaker.timeout(), milliseconds(2000));
    }
}

TEST(Pacemaker, BackoffRestartsFromBaseAfterReset) {
    Pacemaker pacemaker;
    pacemaker.on_timeout();
    pacemaker.on_timeout();
    pacemaker.on_committed_block();
    pacemaker.on_committed_block();
    pacemaker.on_committed_block();
    ASSERT_EQ(pacemaker.timeout(), milliseconds(2000));

    pacemaker.on_timeout();
    EXPECT_EQ(pacemaker.timeout(), milliseconds(4000));
}

}  // namespace
