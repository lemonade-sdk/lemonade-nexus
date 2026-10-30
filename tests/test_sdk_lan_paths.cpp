// LAN-direct paths: which local addresses a device advertises, and which LAN
// endpoints of a peer it probes.

#include <LemonadeNexusSDK/LanPaths.hpp>

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace {

lnsdk::InterfaceAddress itf(const std::string& name, const std::string& address,
                            uint8_t prefix = 24) {
    lnsdk::InterfaceAddress a;
    a.name = name;
    a.address = address;
    a.prefix_len = prefix;
    return a;
}

lnsdk::LocalEndpointRules mesh_rules() {
    lnsdk::LocalEndpointRules rules;
    rules.mesh_ranges = {"10.64.0.0/10"};
    rules.reflexive = "203.0.113.7:41000";
    return rules;
}

}  // namespace

TEST(SdkLanPaths, AdvertisesPrivateLanAddressesWithTheDataplanePort) {
    const std::vector<lnsdk::InterfaceAddress> host = {
        itf("en0", "192.168.1.20"),
        itf("en1", "10.1.2.3", 16),
        itf("en2", "172.20.0.4", 20),
    };
    EXPECT_EQ(lnsdk::select_local_endpoints(host, 41234, mesh_rules()),
              (std::vector<std::string>{"192.168.1.20:41234", "10.1.2.3:41234",
                                        "172.20.0.4:41234"}));
    // No dataplane port, nothing to advertise.
    EXPECT_TRUE(lnsdk::select_local_endpoints(host, 0, mesh_rules()).empty());
}

TEST(SdkLanPaths, SkipsAddressesPeersCannotReachOnTheLan) {
    auto down = itf("en3", "192.168.7.7");
    down.up = false;
    auto ptp = itf("en4", "10.9.9.9");
    ptp.tunnel = true;
    auto lo = itf("lo0", "127.0.0.1", 8);
    lo.loopback = true;
    const std::vector<lnsdk::InterfaceAddress> host = {
        lo,
        itf("en0", "169.254.10.2", 16),   // link-local
        itf("en0", "198.51.100.4"),       // public
        itf("en0", "100.72.1.2", 10),     // carrier NAT, not the reflexive address
        itf("en0", "10.64.0.9", 10),      // the mesh's own plane
        itf("utun3", "10.8.0.2"),         // VPN
        itf("wg0", "10.7.0.2"),
        itf("tun0", "10.6.0.2"),
        itf("ppp0", "10.5.0.2"),
        itf("docker0", "172.17.0.1", 16),
        itf("veth12ab", "172.18.0.1", 16),
        itf("rmnet_data0", "10.33.4.5"),  // cellular
        itf("pdp_ip0", "10.44.4.5"),
        itf("bogus", "not-an-address"),
        down,
        ptp,
    };
    EXPECT_TRUE(lnsdk::select_local_endpoints(host, 41234, mesh_rules()).empty());
}

TEST(SdkLanPaths, CarrierNatAddressOnlyWhenStunSawIt) {
    const std::vector<lnsdk::InterfaceAddress> host = {itf("en0", "100.72.1.2", 10)};
    auto rules = mesh_rules();
    EXPECT_TRUE(lnsdk::select_local_endpoints(host, 5000, rules).empty());
    rules.reflexive = "100.72.1.2:5000";
    EXPECT_EQ(lnsdk::select_local_endpoints(host, 5000, rules),
              std::vector<std::string>{"100.72.1.2:5000"});
}

TEST(SdkLanPaths, CapsAndDeduplicates) {
    const std::vector<lnsdk::InterfaceAddress> host = {
        itf("en0", "192.168.1.20"), itf("en0", "192.168.1.20"), itf("en1", "192.168.2.20"),
        itf("en2", "192.168.3.20"), itf("en3", "192.168.4.20"), itf("en4", "192.168.5.20"),
    };
    const auto out = lnsdk::select_local_endpoints(host, 7, mesh_rules());
    ASSERT_EQ(out.size(), lnsdk::kMaxLocalEndpoints);
    EXPECT_EQ(out.front(), "192.168.1.20:7");
    EXPECT_EQ(out.back(), "192.168.4.20:7");
}

TEST(SdkLanPaths, LoopbackOnlyForASingleHostDeployment) {
    auto lo = itf("lo0", "127.0.0.1", 8);
    lo.loopback = true;
    auto rules = mesh_rules();
    EXPECT_TRUE(lnsdk::select_local_endpoints({lo}, 9, rules).empty());
    rules.allow_loopback = true;
    EXPECT_EQ(lnsdk::select_local_endpoints({lo}, 9, rules),
              std::vector<std::string>{"127.0.0.1:9"});
}

TEST(SdkLanPaths, VirtualInterfaceNames) {
    for (const char* name : {"utun0", "UTUN4", "tun0", "tap1", "wg0", "ppp0", "ipsec0", "gif0",
                             "stf0", "awdl0", "llw0", "docker0", "veth9", "br-12ab", "virbr0",
                             "vmnet8", "vboxnet0", "zt0", "tailscale0", "rmnet_data1", "ccmni0",
                             "pdp_ip0", "clat4", "v4-rmnet"}) {
        EXPECT_TRUE(lnsdk::virtual_interface_name(name)) << name;
    }
    for (const char* name : {"en0", "eth0", "wlan0", "Wi-Fi", "Ethernet 2", "bridge100", "enp3s0",
                             "wlp2s0"}) {
        EXPECT_FALSE(lnsdk::virtual_interface_name(name)) << name;
    }
}

TEST(SdkLanPaths, ListedLanEndpointsMustBePrivate) {
    EXPECT_TRUE(lnsdk::lan_endpoint_usable("192.168.1.20:41234", false));
    EXPECT_TRUE(lnsdk::lan_endpoint_usable("100.64.0.1:41234", false));
    EXPECT_FALSE(lnsdk::lan_endpoint_usable("203.0.113.1:41234", false));
    EXPECT_FALSE(lnsdk::lan_endpoint_usable("169.254.1.1:41234", false));
    EXPECT_FALSE(lnsdk::lan_endpoint_usable("192.168.1.20", false));
    EXPECT_FALSE(lnsdk::lan_endpoint_usable("192.168.1.20:0", false));
    EXPECT_FALSE(lnsdk::lan_endpoint_usable("127.0.0.1:41234", false));
    EXPECT_TRUE(lnsdk::lan_endpoint_usable("127.0.0.1:41234", true));
}

// A peer is on this device's network when both share one public address
// (one NAT), or when one of its LAN endpoints is inside one of this device's
// LAN subnets. Then every LAN endpoint of the peer is probed.
TEST(SdkLanPaths, SameNetworkDetection) {
    lnsdk::MeshPeer peer;
    peer.endpoint = "203.0.113.7:50001";
    peer.local_endpoints = {"192.168.1.30:50001", "10.20.0.5:50001"};
    const std::vector<lnsdk::InterfaceAddress> own = {itf("en0", "192.168.1.20", 24)};

    // Same NAT.
    EXPECT_EQ(lnsdk::lan_probe_targets(peer, "203.0.113.7:41000", {}), peer.local_endpoints);
    // Another NAT, but a shared subnet.
    EXPECT_EQ(lnsdk::lan_probe_targets(peer, "198.51.100.1:41000", own), peer.local_endpoints);
    // Another NAT and no shared subnet: another network.
    EXPECT_TRUE(lnsdk::lan_probe_targets(peer, "198.51.100.1:41000",
                                         {itf("en0", "192.168.2.20", 24)})
                    .empty());
    // No reflexive address yet and no shared subnet.
    EXPECT_TRUE(lnsdk::lan_probe_targets(peer, "", {itf("en0", "172.16.0.2", 16)}).empty());
    // A peer without LAN endpoints has nothing to probe.
    peer.local_endpoints.clear();
    EXPECT_TRUE(lnsdk::lan_probe_targets(peer, "203.0.113.7:41000", own).empty());
}

// The host's own interface list: the call works and its entries parse. The
// contents depend on the machine, so only the shape is checked.
TEST(SdkLanPaths, HostInterfacesAreListed) {
    const auto host = lnsdk::list_interface_addresses();
    for (const auto& a : host) {
        EXPECT_FALSE(a.address.empty());
        EXPECT_LE(a.prefix_len, 32);
    }
    lnsdk::LocalEndpointRules rules;
    rules.allow_loopback = true;
    const auto with_loopback = lnsdk::select_local_endpoints(host, 9, rules);
    EXPECT_LE(with_loopback.size(), lnsdk::kMaxLocalEndpoints);
}
