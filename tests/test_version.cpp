#include <LemonadeNexus/Core/Version.hpp>

#include <gtest/gtest.h>

#include <string>

using namespace nexus::core;

TEST(VersionTest, VersionIsNonEmpty) {
    EXPECT_FALSE(std::string(kVersion).empty());
}

TEST(VersionTest, GitCommitIsNonEmpty) {
    EXPECT_FALSE(std::string(kGitCommit).empty());
}

TEST(VersionTest, SidecarApiVersionIsAtLeastOne) {
    EXPECT_GE(kSidecarApiVersion, 1);
}
