// Device presence table and PresenceSync codec (Gossip/DevicePresence.hpp).

#include <LemonadeNexus/Gossip/DevicePresence.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

using namespace nexus::gossip;

namespace {

constexpr uint64_t kNow = 1'800'000'000;

std::vector<uint8_t> msgpack_of(const nlohmann::json& j) {
    return nlohmann::json::to_msgpack(j);
}

}  // namespace

// A local presence is online for the window and offline from its last second.
TEST(DevicePresenceTest, LocalPresenceExpiresAfterTheWindow) {
    DevicePresence p;
    EXPECT_FALSE(p.status("dev1", kNow).online);
    EXPECT_EQ(p.status("dev1", kNow).last_seen, 0u);

    const auto first = p.record_local("dev1", kNow);
    EXPECT_TRUE(first.accepted);
    EXPECT_TRUE(first.became_online);
    EXPECT_TRUE(first.locally_new);
    EXPECT_TRUE(p.status("dev1", kNow).online);
    EXPECT_TRUE(p.status("dev1", kNow + kDevicePresenceOnlineSec - 1).online);
    const auto expired = p.status("dev1", kNow + kDevicePresenceOnlineSec);
    EXPECT_FALSE(expired.online);
    EXPECT_EQ(expired.last_seen, kNow) << "an offline device keeps its last presence time";

    // A refresh within the window is neither a transition nor new here.
    const auto again = p.record_local("dev1", kNow + 3);
    EXPECT_FALSE(again.became_online);
    EXPECT_FALSE(again.locally_new);
    EXPECT_EQ(p.status("dev1", kNow + 3).last_seen, kNow + 3);
}

// Merges keep the largest time from every source; an older time changes
// nothing, and a remote time never counts as local presence.
TEST(DevicePresenceTest, MergeKeepsTheMaximum) {
    DevicePresence p;
    auto r = p.merge_remote({{"dev1", kNow - 2}}, kNow);
    EXPECT_EQ(r.merged, 1u);
    EXPECT_TRUE(r.became_online);
    EXPECT_EQ(p.status("dev1", kNow).last_seen, kNow - 2);

    r = p.merge_remote({{"dev1", kNow - 5}}, kNow);
    EXPECT_EQ(r.merged, 0u);
    EXPECT_FALSE(r.became_online);
    EXPECT_EQ(p.status("dev1", kNow).last_seen, kNow - 2);

    (void)p.record_local("dev1", kNow - 1);
    (void)p.merge_remote({{"dev1", kNow - 4}}, kNow);
    EXPECT_EQ(p.status("dev1", kNow).last_seen, kNow - 1);

    // Two senders, one entry each: the newer wins whatever the order.
    (void)p.merge_remote({{"dev2", kNow}, {"dev2", kNow - 7}}, kNow);
    EXPECT_EQ(p.status("dev2", kNow).last_seen, kNow);

    // Only local presence is sent on, so a server never relays a time.
    const auto local = p.local_online(kNow);
    ASSERT_EQ(local.size(), 1u);
    EXPECT_EQ(local[0], (PresenceEntry{"dev1", kNow - 1}));
}

// A gossiped time ahead of the local clock counts as "now" within the skew
// and is ignored beyond it, so a fast clock cannot hold a device online.
TEST(DevicePresenceTest, FuturePresenceBeyondSkewIsIgnored) {
    DevicePresence p;
    auto r = p.merge_remote({{"far", kNow + kDevicePresenceMaxSkewSec + 1}}, kNow);
    EXPECT_EQ(r.ahead, 1u);
    EXPECT_EQ(r.merged, 0u);
    EXPECT_FALSE(r.became_online);
    EXPECT_FALSE(p.status("far", kNow).online);
    EXPECT_EQ(p.status("far", kNow).last_seen, 0u);
    EXPECT_EQ(p.size(), 0u);

    r = p.merge_remote({{"near", kNow + kDevicePresenceMaxSkewSec}}, kNow);
    EXPECT_EQ(r.ahead, 0u);
    EXPECT_EQ(r.merged, 1u);
    EXPECT_EQ(p.status("near", kNow).last_seen, kNow) << "a time within the skew counts as now";
    EXPECT_FALSE(p.status("near", kNow + kDevicePresenceOnlineSec).online);

    // A time older than the retention adds nothing.
    r = p.merge_remote({{"old", kNow - kDevicePresenceRetentionSec}}, kNow);
    EXPECT_EQ(r.merged, 0u);
    EXPECT_EQ(p.status("old", kNow).last_seen, 0u);
}

// The sweep reports a device that went offline once, gives the next expiry,
// and drops entries past the retention.
TEST(DevicePresenceTest, SweepReportsOfflineTransitionsAndNextExpiry) {
    DevicePresence p;
    (void)p.record_local("dev1", kNow);
    (void)p.merge_remote({{"dev2", kNow - 4}}, kNow);
    auto s = p.sweep(kNow);
    EXPECT_FALSE(s.went_offline);
    EXPECT_EQ(s.next_expiry, kNow - 4 + kDevicePresenceOnlineSec);

    s = p.sweep(kNow - 4 + kDevicePresenceOnlineSec);
    EXPECT_TRUE(s.went_offline);
    EXPECT_EQ(s.next_expiry, kNow + kDevicePresenceOnlineSec);
    s = p.sweep(kNow - 4 + kDevicePresenceOnlineSec);
    EXPECT_FALSE(s.went_offline) << "a transition is reported once";

    s = p.sweep(kNow + kDevicePresenceOnlineSec);
    EXPECT_TRUE(s.went_offline);
    EXPECT_EQ(s.next_expiry, 0u);
    EXPECT_EQ(p.size(), 2u);

    (void)p.sweep(kNow + kDevicePresenceRetentionSec);
    EXPECT_EQ(p.size(), 0u);
}

// The changed hook runs when a device becomes online, not on a refresh.
TEST(DevicePresenceTest, ChangedHookRunsOnlyWhenADeviceBecomesOnline) {
    DevicePresence p;
    int calls = 0;
    p.set_changed_hook([&calls] { ++calls; });
    (void)p.record_local("dev1", kNow);
    EXPECT_EQ(calls, 1);
    (void)p.record_local("dev1", kNow + 3);
    (void)p.merge_remote({{"dev1", kNow + 4}}, kNow + 4);
    EXPECT_EQ(calls, 1);
    (void)p.merge_remote({{"dev2", kNow}, {"dev3", kNow}}, kNow);
    EXPECT_EQ(calls, 2) << "one call per merge";
    (void)p.record_local("dev1", kNow + 30);
    EXPECT_EQ(calls, 3) << "back online after the window";
    p.set_changed_hook({});
    (void)p.record_local("dev4", kNow + 30);
    EXPECT_EQ(calls, 3);
}

// Node ids outside the mesh route alphabet are refused everywhere.
TEST(DevicePresenceTest, InvalidNodeIdsAreRefused) {
    EXPECT_TRUE(presence_node_id_valid("0123abcdef_-XYZ"));
    EXPECT_FALSE(presence_node_id_valid(""));
    EXPECT_FALSE(presence_node_id_valid("dev/1"));
    EXPECT_FALSE(presence_node_id_valid("dev 1"));
    EXPECT_FALSE(presence_node_id_valid(std::string(kDevicePresenceMaxNodeIdBytes + 1, 'a')));
    EXPECT_TRUE(presence_node_id_valid(std::string(kDevicePresenceMaxNodeIdBytes, 'a')));

    DevicePresence p;
    EXPECT_FALSE(p.record_local("dev/1", kNow).accepted);
    EXPECT_FALSE(p.record_local("dev1", 0).accepted);
    EXPECT_EQ(p.merge_remote({{"dev/1", kNow}}, kNow).merged, 0u);
    EXPECT_EQ(p.size(), 0u);
}

// Encoding pages a large set within both bounds, and decoding gives back
// every entry.
TEST(PresenceSyncCodecTest, RoundTripPagesWithinTheBounds) {
    std::vector<PresenceEntry> entries;
    for (int i = 0; i < 700; ++i) {
        entries.push_back({"dev" + std::to_string(i), kNow - static_cast<uint64_t>(i % 9)});
    }
    entries.push_back({"bad/id", kNow});  // left out
    entries.push_back({"zero", 0});       // left out
    const auto pages = encode_presence_sync(entries);
    ASSERT_GE(pages.size(), 3u);
    std::vector<PresenceEntry> decoded;
    for (const auto& page : pages) {
        EXPECT_LE(page.size(), kPresenceSyncMaxPayloadBytes);
        const auto one = decode_presence_sync(page);
        ASSERT_TRUE(one.has_value());
        EXPECT_LE(one->size(), kPresenceSyncMaxEntries);
        decoded.insert(decoded.end(), one->begin(), one->end());
    }
    entries.resize(700);
    EXPECT_EQ(decoded, entries);

    // Long ids fill the byte budget before the entry cap.
    std::vector<PresenceEntry> long_ids;
    for (int i = 0; i < 300; ++i) {
        long_ids.push_back({std::string(120, 'a') + std::to_string(i), kNow});
    }
    for (const auto& page : encode_presence_sync(long_ids)) {
        EXPECT_LE(page.size(), kPresenceSyncMaxPayloadBytes);
        EXPECT_TRUE(decode_presence_sync(page).has_value());
    }
    EXPECT_TRUE(encode_presence_sync({}).empty());
}

// Malformed or oversized payloads are refused whole.
TEST(PresenceSyncCodecTest, MalformedAndOversizedPayloadsAreRefused) {
    const auto entry = [](const nlohmann::json& id, const nlohmann::json& seen) {
        return nlohmann::json{{"node_id", id}, {"seen", seen}};
    };
    ASSERT_TRUE(decode_presence_sync(msgpack_of({{"entries", {entry("dev1", kNow)}}})));

    EXPECT_FALSE(decode_presence_sync({}));
    const std::vector<uint8_t> garbage{0xc1, 0x00, 0xff};
    EXPECT_FALSE(decode_presence_sync(garbage));
    EXPECT_FALSE(decode_presence_sync(msgpack_of(nlohmann::json::array())));
    EXPECT_FALSE(decode_presence_sync(msgpack_of({{"entries", "dev1"}})));
    EXPECT_FALSE(decode_presence_sync(msgpack_of({{"entries", nlohmann::json::array()}})));
    EXPECT_FALSE(decode_presence_sync(msgpack_of({{"entries", {"dev1"}}})));
    EXPECT_FALSE(decode_presence_sync(msgpack_of({{"entries", {entry("dev/1", kNow)}}})));
    EXPECT_FALSE(decode_presence_sync(msgpack_of({{"entries", {entry(7, kNow)}}})));
    EXPECT_FALSE(decode_presence_sync(msgpack_of({{"entries", {entry("dev1", 0)}}})));
    EXPECT_FALSE(decode_presence_sync(msgpack_of({{"entries", {entry("dev1", -5)}}})));
    EXPECT_FALSE(decode_presence_sync(msgpack_of({{"entries", {entry("dev1", "now")}}})));
    EXPECT_FALSE(decode_presence_sync(
        msgpack_of({{"entries", {{{"node_id", "dev1"}}}}})));

    // One entry more than the cap.
    nlohmann::json many = nlohmann::json::array();
    for (std::size_t i = 0; i <= kPresenceSyncMaxEntries; ++i) {
        many.push_back(entry("d" + std::to_string(i), kNow));
    }
    EXPECT_FALSE(decode_presence_sync(msgpack_of({{"entries", many}})));

    // A payload over the byte bound is refused before it is parsed.
    auto big = msgpack_of({{"entries", {entry("dev1", kNow)}}, {"pad", std::string(20000, 'x')}});
    ASSERT_GT(big.size(), kPresenceSyncMaxPayloadBytes);
    EXPECT_FALSE(decode_presence_sync(big));
    // The same shape within the bound is accepted (unknown keys are ignored).
    EXPECT_TRUE(decode_presence_sync(
        msgpack_of({{"entries", {entry("dev1", kNow)}}, {"pad", std::string(100, 'x')}})));
}
