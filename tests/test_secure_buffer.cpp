#include <LemonadeNexus/Crypto/SecureBuffer.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <utility>
#include <vector>

using nexus::crypto::SecureBuffer;

namespace {

TEST(SecureBuffer, DefaultIsEmpty) {
    const SecureBuffer buffer;
    EXPECT_TRUE(buffer.empty());
    EXPECT_EQ(buffer.size(), 0u);
    EXPECT_EQ(buffer.data(), nullptr);
}

TEST(SecureBuffer, AllocatesZeroedMemory) {
    SecureBuffer buffer(64);
    ASSERT_EQ(buffer.size(), 64u);
    ASSERT_NE(buffer.data(), nullptr);
    for (const uint8_t byte : buffer.span()) {
        EXPECT_EQ(byte, 0u);
    }
}

TEST(SecureBuffer, CopiesInitialContent) {
    const std::vector<uint8_t> secret{1, 2, 3, 4, 5};
    SecureBuffer buffer{std::span<const uint8_t>(secret)};
    ASSERT_EQ(buffer.size(), secret.size());
    EXPECT_TRUE(std::equal(secret.begin(), secret.end(), buffer.data()));
}

TEST(SecureBuffer, ZeroSizeAllocatesNothing) {
    const SecureBuffer buffer(0);
    EXPECT_TRUE(buffer.empty());
    EXPECT_EQ(buffer.data(), nullptr);
}

TEST(SecureBuffer, MoveTransfersOwnership) {
    const std::vector<uint8_t> secret{9, 8, 7};
    SecureBuffer source{std::span<const uint8_t>(secret)};
    const uint8_t* original = source.data();

    SecureBuffer moved(std::move(source));
    EXPECT_EQ(moved.data(), original);
    EXPECT_EQ(moved.size(), 3u);
    EXPECT_TRUE(source.empty());
    EXPECT_EQ(source.data(), nullptr);
}

TEST(SecureBuffer, MoveAssignReleasesPrevious) {
    SecureBuffer target(16);
    SecureBuffer source(8);
    source.span()[0] = 0x42;

    target = std::move(source);
    EXPECT_EQ(target.size(), 8u);
    EXPECT_EQ(target.span()[0], 0x42);
    EXPECT_TRUE(source.empty());
}

TEST(SecureBuffer, ClearReleasesAndEmpties) {
    SecureBuffer buffer(32);
    buffer.span()[0] = 0xFF;
    buffer.clear();
    EXPECT_TRUE(buffer.empty());
    EXPECT_EQ(buffer.data(), nullptr);
}

TEST(SecureBuffer, WritableThroughSpan) {
    SecureBuffer buffer(4);
    auto span = buffer.span();
    span[0] = 0xDE;
    span[3] = 0xAD;
    EXPECT_EQ(buffer.data()[0], 0xDE);
    EXPECT_EQ(buffer.data()[3], 0xAD);
}

}  // namespace
