// The shared key-generation race fix (design Part C): one message per sender
// per round, early messages held until the round starts, and a paced re-send
// cadence. The FROST epoch DKG and the storage-key sessions both use it.

#include <LemonadeNexus/Security/Authority/RoundRelay.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

using nexus::security::ResendCadence;
using nexus::security::RoundAccept;
using nexus::security::RoundInbox;

namespace {

using Bytes = std::vector<uint8_t>;

TEST(RoundInbox, OneMessagePerSenderAndEquivocationIsDetected) {
    RoundInbox<uint16_t, Bytes> inbox;
    EXPECT_EQ(inbox.accept(1, Bytes{1, 2}, false), RoundAccept::Accepted);
    EXPECT_EQ(inbox.accept(1, Bytes{1, 2}, false), RoundAccept::Duplicate);
    EXPECT_EQ(inbox.accept(1, Bytes{9}, false), RoundAccept::Equivocation);
    EXPECT_EQ(inbox.size(), 1u);
    EXPECT_EQ(inbox.messages().at(1), (Bytes{1, 2}));
}

TEST(RoundInbox, EarlyMessagesCountOnlyAfterTheRoundStarts) {
    RoundInbox<uint16_t, Bytes> inbox;
    EXPECT_EQ(inbox.accept(2, Bytes{7}, true), RoundAccept::Accepted);
    EXPECT_TRUE(inbox.contains(2));
    EXPECT_EQ(inbox.size(), 0u);
    // A re-send while still early is benign; a different package is not.
    EXPECT_EQ(inbox.accept(2, Bytes{7}, true), RoundAccept::Duplicate);
    EXPECT_EQ(inbox.accept(2, Bytes{8}, true), RoundAccept::Equivocation);
    inbox.release_early();
    EXPECT_EQ(inbox.size(), 1u);
    // After release the held package is compared like any other.
    EXPECT_EQ(inbox.accept(2, Bytes{7}, false), RoundAccept::Duplicate);
    EXPECT_EQ(inbox.accept(2, Bytes{8}, false), RoundAccept::Equivocation);
    inbox.clear();
    EXPECT_FALSE(inbox.contains(2));
}

TEST(ResendCadence, DueAtMostOncePerInterval) {
    ResendCadence cadence(5000);
    EXPECT_FALSE(cadence.due(1000));  // within the first interval of zero
    EXPECT_TRUE(cadence.due(5000));
    EXPECT_FALSE(cadence.due(9999));
    EXPECT_TRUE(cadence.due(10000));
    // A send outside the cadence pushes the next re-send a full interval out.
    cadence.mark(12000);
    EXPECT_FALSE(cadence.due(16999));
    EXPECT_TRUE(cadence.due(17000));
}

}  // namespace
