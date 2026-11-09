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

// LAN endpoints recorded with a local presence are listed for the TTL from
// the heartbeat that reported them, a heartbeat without the field keeps
// them, an empty list removes them, and the hook runs on a change only.
TEST(DevicePresenceTest, LocalLanEndpointsFollowTheHeartbeatAndExpire) {
    const std::vector<std::string> lan{"192.168.1.20:41234", "10.0.0.5:41234"};
    DevicePresence p;
    int calls = 0;
    p.set_changed_hook([&calls] { ++calls; });

    auto r = p.record_local("dev1", kNow, lan);
    EXPECT_TRUE(r.accepted);
    EXPECT_TRUE(r.became_online);
    EXPECT_TRUE(r.lan_changed);
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(p.lan_endpoints("dev1", kNow), lan);
    EXPECT_EQ(p.lan_endpoints("dev1", kNow + kDevicePresenceLanTtlSec - 1), lan);
    EXPECT_TRUE(p.lan_endpoints("dev1", kNow + kDevicePresenceLanTtlSec).empty());
    EXPECT_TRUE(p.lan_endpoints("other", kNow).empty());

    // The same list again restarts the TTL and is not a change.
    r = p.record_local("dev1", kNow + 3, lan);
    EXPECT_FALSE(r.lan_changed);
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(p.lan_endpoints("dev1", kNow + 3 + kDevicePresenceLanTtlSec - 1), lan);

    // Without the field (an older client or an event socket) the list stays,
    // and its TTL still counts from the last report.
    r = p.record_local("dev1", kNow + 6);
    EXPECT_FALSE(r.lan_changed);
    EXPECT_EQ(p.lan_endpoints("dev1", kNow + 6), lan);
    EXPECT_TRUE(p.lan_endpoints("dev1", kNow + 3 + kDevicePresenceLanTtlSec).empty());

    // Local presence carries the list to the other Tier 1 servers.
    auto local = p.local_online(kNow + 6);
    ASSERT_EQ(local.size(), 1u);
    EXPECT_EQ(local[0], (PresenceEntry{"dev1", kNow + 6, lan}));

    // A new list is a change; an empty list removes it; removing nothing is
    // not a change.
    const std::vector<std::string> moved{"172.16.4.9:41234"};
    r = p.record_local("dev1", kNow + 9, moved);
    EXPECT_TRUE(r.lan_changed);
    EXPECT_EQ(calls, 2);
    EXPECT_EQ(p.lan_endpoints("dev1", kNow + 9), moved);
    r = p.record_local("dev1", kNow + 12, std::vector<std::string>{});
    EXPECT_TRUE(r.lan_changed);
    EXPECT_EQ(calls, 3);
    EXPECT_TRUE(p.lan_endpoints("dev1", kNow + 12).empty());
    r = p.record_local("dev1", kNow + 15, std::vector<std::string>{});
    EXPECT_FALSE(r.lan_changed);
    EXPECT_EQ(calls, 3);
    local = p.local_online(kNow + 15);
    ASSERT_EQ(local.size(), 1u);
    EXPECT_TRUE(local[0].lan.empty());

    // An expired list reads as a change when it is reported again, and the
    // sweep drops it.
    (void)p.record_local("dev1", kNow + 20, lan);
    const auto later = kNow + 20 + kDevicePresenceLanTtlSec;
    (void)p.sweep(later);
    EXPECT_TRUE(p.lan_endpoints("dev1", later).empty());
    r = p.record_local("dev1", later, lan);
    EXPECT_TRUE(r.lan_changed);
}

// Gossiped presence carries the LAN endpoints the other server heard: the
// entry that raises a device's time sets its list, dated at that time; an
// older entry changes nothing; an entry without a list removes it; and the
// list is never relayed as local presence.
TEST(DevicePresenceTest, MergedLanEndpointsFollowTheNewestPresence) {
    const std::vector<std::string> lan{"192.168.1.20:41234"};
    const std::vector<std::string> other{"10.9.8.7:5000", "192.168.1.21:5000"};
    DevicePresence p;
    int calls = 0;
    p.set_changed_hook([&calls] { ++calls; });

    auto r = p.merge_remote({{"dev1", kNow - 2, lan}}, kNow);
    EXPECT_EQ(r.merged, 1u);
    EXPECT_TRUE(r.became_online);
    EXPECT_TRUE(r.lan_changed);
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(p.lan_endpoints("dev1", kNow), lan);
    EXPECT_EQ(p.lan_endpoints("dev1", kNow - 2 + kDevicePresenceLanTtlSec - 1), lan);
    EXPECT_TRUE(p.lan_endpoints("dev1", kNow - 2 + kDevicePresenceLanTtlSec).empty());
    EXPECT_TRUE(p.local_online(kNow).empty()) << "a gossiped list counted as local";

    // Older presence, even with another list, changes nothing.
    r = p.merge_remote({{"dev1", kNow - 5, other}}, kNow);
    EXPECT_EQ(r.merged, 0u);
    EXPECT_FALSE(r.lan_changed);
    EXPECT_EQ(p.lan_endpoints("dev1", kNow), lan);

    // The same presence again is not a change; a newer one with the same
    // list is not a change either, but restarts the TTL.
    r = p.merge_remote({{"dev1", kNow - 2, lan}}, kNow);
    EXPECT_FALSE(r.lan_changed);
    r = p.merge_remote({{"dev1", kNow, lan}}, kNow);
    EXPECT_EQ(r.merged, 1u);
    EXPECT_FALSE(r.lan_changed);
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(p.lan_endpoints("dev1", kNow + kDevicePresenceLanTtlSec - 1), lan);

    // The server that heard the device last decides: a newer presence with
    // another list replaces it, and one without a list removes it.
    r = p.merge_remote({{"dev1", kNow + 3, other}}, kNow + 3);
    EXPECT_TRUE(r.lan_changed);
    EXPECT_EQ(calls, 2);
    EXPECT_EQ(p.lan_endpoints("dev1", kNow + 3), other);
    r = p.merge_remote({{"dev1", kNow + 6}}, kNow + 6);
    EXPECT_TRUE(r.lan_changed);
    EXPECT_EQ(calls, 3);
    EXPECT_TRUE(p.lan_endpoints("dev1", kNow + 6).empty());

    // A list that arrives with a presence already past the TTL is not listed.
    r = p.merge_remote({{"dev2", kNow - kDevicePresenceLanTtlSec, lan}}, kNow);
    EXPECT_EQ(r.merged, 1u);
    EXPECT_FALSE(r.lan_changed);
    EXPECT_TRUE(p.lan_endpoints("dev2", kNow).empty());

    // A local heartbeat and a newer gossiped presence: the newest wins both ways.
    (void)p.record_local("dev3", kNow, lan);
    (void)p.merge_remote({{"dev3", kNow + 1, other}}, kNow + 1);
    EXPECT_EQ(p.lan_endpoints("dev3", kNow + 1), other);
    (void)p.record_local("dev3", kNow + 2, lan);
    EXPECT_EQ(p.lan_endpoints("dev3", kNow + 2), lan);
}

// The LAN endpoint rule: private IPv4 "a.b.c.d:port" only, loopback only
// when allowed.
TEST(DevicePresenceTest, LanEndpointRule) {
    for (const char* ok : {"10.0.0.1:1", "10.255.255.255:65535", "172.16.0.1:7", "172.31.255.254:7",
                           "192.168.0.1:41234", "100.64.0.1:9", "100.127.255.255:9"}) {
        EXPECT_TRUE(presence_lan_endpoint_valid(ok, false)) << ok;
    }
    for (const char* bad : {"", "8.8.8.8:1", "203.0.113.5:1", "169.254.1.1:1", "172.32.0.1:1",
                            "100.128.0.1:1", "256.1.1.1:1", "192.168.1.20:0", "192.168.1.20:65536",
                            "192.168.1.20", "192.168.01.20:1", "192.168.1.20:041", "192.168.1.20:1 ",
                            "192.168.1.20:+1", "192.168.1:1", "192.168.1.2.3:1", "[fd00::1]:1",
                            "192.168.1.20:1:2", "garbage"}) {
        EXPECT_FALSE(presence_lan_endpoint_valid(bad, true)) << bad;
    }
    EXPECT_FALSE(presence_lan_endpoint_valid("127.0.0.1:9", false));
    EXPECT_TRUE(presence_lan_endpoint_valid("127.0.0.1:9", true));
}

// PresenceSync carries a device's LAN endpoints as `lan`, only when it has
// any; a sender from before the field is decoded with none; and a list that
// fails the heartbeat rules refuses the payload, since a gossip peer is not
// the device.
TEST(PresenceSyncCodecTest, LanEndpointsRoundTripAndInvalidOnesAreRefused) {
    const std::vector<std::string> lan{"192.168.1.20:41234", "10.0.0.5:41234"};
    const std::vector<PresenceEntry> entries{{"dev1", kNow, lan}, {"dev2", kNow - 1}};
    const auto pages = encode_presence_sync(entries);
    ASSERT_EQ(pages.size(), 1u);
    const auto decoded = decode_presence_sync(pages[0]);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(*decoded, entries);
    const auto doc = nlohmann::json::from_msgpack(pages[0]);
    EXPECT_EQ(doc["entries"][0]["lan"], nlohmann::json(lan));
    EXPECT_FALSE(doc["entries"][1].contains("lan")) << "an empty list was sent";

    // Loopback never goes on the wire, and the count is capped.
    std::vector<std::string> many{"127.0.0.1:1"};
    for (int i = 1; i <= static_cast<int>(kDevicePresenceMaxLanEndpoints) + 1; ++i) {
        many.push_back("10.0.0." + std::to_string(i) + ":1");
    }
    const auto capped = decode_presence_sync(encode_presence_sync({{"dev1", kNow, many}})[0]);
    ASSERT_TRUE(capped.has_value());
    ASSERT_EQ(capped->size(), 1u);
    EXPECT_EQ((*capped)[0].lan.size(), kDevicePresenceMaxLanEndpoints);
    EXPECT_EQ((*capped)[0].lan[0], "10.0.0.1:1");

    // Every long id with a full list stays within the byte bound.
    std::vector<PresenceEntry> long_ids;
    for (int i = 0; i < 300; ++i) {
        long_ids.push_back({std::string(120, 'a') + std::to_string(i), kNow,
                            {"192.168.100.100:65535", "172.31.255.255:65535",
                             "10.255.255.255:65535", "100.127.255.255:65535"}});
    }
    std::size_t total = 0;
    for (const auto& page : encode_presence_sync(long_ids)) {
        EXPECT_LE(page.size(), kPresenceSyncMaxPayloadBytes);
        const auto one = decode_presence_sync(page);
        ASSERT_TRUE(one.has_value());
        total += one->size();
    }
    EXPECT_EQ(total, 300u);

    const auto with_lan = [](const nlohmann::json& lan_value) {
        return msgpack_of({{"entries", {{{"node_id", "dev1"}, {"seen", kNow}, {"lan", lan_value}}}}});
    };
    EXPECT_TRUE(decode_presence_sync(with_lan(nlohmann::json::array())));
    EXPECT_TRUE(decode_presence_sync(with_lan({"10.0.0.1:1"})));
    EXPECT_FALSE(decode_presence_sync(with_lan({"8.8.8.8:41234"})));       // public
    EXPECT_FALSE(decode_presence_sync(with_lan({"127.0.0.1:41234"})));     // loopback
    EXPECT_FALSE(decode_presence_sync(with_lan({"192.168.1.20:0"})));      // port 0
    EXPECT_FALSE(decode_presence_sync(with_lan({"192.168.1.20"})));        // no port
    EXPECT_FALSE(decode_presence_sync(with_lan({"[fd00::1]:41234"})));     // IPv6
    EXPECT_FALSE(decode_presence_sync(with_lan({41234})));                 // not a string
    EXPECT_FALSE(decode_presence_sync(with_lan("10.0.0.1:1")));            // not an array
    EXPECT_FALSE(decode_presence_sync(with_lan({"10.0.0.1:1", "10.0.0.1:1"})));  // repeated
    nlohmann::json too_many = nlohmann::json::array();
    for (std::size_t i = 0; i <= kDevicePresenceMaxLanEndpoints; ++i) {
        too_many.push_back("10.0.0." + std::to_string(i + 1) + ":1");
    }
    EXPECT_FALSE(decode_presence_sync(with_lan(too_many)));
    // One bad list spoils the message, as one bad id does.
    EXPECT_FALSE(decode_presence_sync(msgpack_of(
        {{"entries", {{{"node_id", "dev1"}, {"seen", kNow}},
                      {{"node_id", "dev2"}, {"seen", kNow}, {"lan", {"8.8.8.8:1"}}}}}})));
}
