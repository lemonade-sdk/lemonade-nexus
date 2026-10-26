#include <LemonadeNexus/Core/ServerIdentity.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <set>
#include <string>
#include <vector>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
namespace fs = std::filesystem;

class IPAMTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<ipam::IPAMService> ipam;

    void SetUp() override {
        temp_dir = fs::temp_directory_path() / ("nexus_test_ipam_" + std::to_string(getpid()));
        fs::create_directories(temp_dir);

        storage = std::make_unique<storage::FileStorageService>(temp_dir);
        storage->start();

        ipam = std::make_unique<ipam::IPAMService>(*storage);
        ipam->start();
    }

    void TearDown() override {
        ipam->stop();
        storage->stop();
        fs::remove_all(temp_dir);
    }
};

// --- Tunnel IP allocation ---

TEST_F(IPAMTest, AllocateTunnelIP) {
    auto alloc = ipam->allocate_tunnel_ip("node1");
    EXPECT_FALSE(alloc.base_network.empty());
    EXPECT_EQ(alloc.customer_node_id, "node1");
    EXPECT_EQ(alloc.block_type, ipam::BlockType::Tunnel);
    // Tunnel IPs should be /32
    EXPECT_NE(alloc.base_network.find("/32"), std::string::npos);
}

TEST_F(IPAMTest, AllocateTunnelIPSequential) {
    auto a1 = ipam->allocate_tunnel_ip("n1");
    auto a2 = ipam->allocate_tunnel_ip("n2");
    auto a3 = ipam->allocate_tunnel_ip("n3");

    // All should be different
    EXPECT_NE(a1.base_network, a2.base_network);
    EXPECT_NE(a2.base_network, a3.base_network);

    // Should start in the 10.64.x.x range
    EXPECT_EQ(a1.base_network.substr(0, 5), "10.64");
}

TEST_F(IPAMTest, DuplicateTunnelAllocationReturnsSame) {
    auto a1 = ipam->allocate_tunnel_ip("node1");
    auto a2 = ipam->allocate_tunnel_ip("node1");
    EXPECT_EQ(a1.base_network, a2.base_network);
}

// --- Private subnet allocation ---

TEST_F(IPAMTest, AllocatePrivateSubnet) {
    auto alloc = ipam->allocate_private_subnet("node1", 30);
    EXPECT_FALSE(alloc.base_network.empty());
    EXPECT_EQ(alloc.block_type, ipam::BlockType::Private);
    EXPECT_NE(alloc.base_network.find("/30"), std::string::npos);
    EXPECT_EQ(alloc.base_network.substr(0, 6), "10.128");
}

TEST_F(IPAMTest, AllocatePrivateSubnetDifferentPrefixes) {
    auto a1 = ipam->allocate_private_subnet("n1", 30);
    auto a2 = ipam->allocate_private_subnet("n2", 28);

    EXPECT_NE(a1.base_network, a2.base_network);
    EXPECT_NE(a1.base_network.find("/30"), std::string::npos);
    EXPECT_NE(a2.base_network.find("/28"), std::string::npos);
}

// --- Shared block allocation ---

TEST_F(IPAMTest, AllocateSharedBlock) {
    auto alloc = ipam->allocate_shared_block("node1", 30);
    EXPECT_FALSE(alloc.base_network.empty());
    EXPECT_EQ(alloc.block_type, ipam::BlockType::Shared);
    EXPECT_NE(alloc.base_network.find("/30"), std::string::npos);
    EXPECT_EQ(alloc.base_network.substr(0, 6), "172.20");
}

// --- Release ---

TEST_F(IPAMTest, ReleaseAllocation) {
    ipam->allocate_tunnel_ip("node1");
    EXPECT_TRUE(ipam->release("node1", ipam::BlockType::Tunnel));

    // After release, get_allocation should return nullopt
    auto alloc = ipam->get_allocation("node1");
    EXPECT_FALSE(alloc.has_value());
}

TEST_F(IPAMTest, ReleaseNonExistentAllocation) {
    EXPECT_FALSE(ipam->release("nonexistent", ipam::BlockType::Tunnel));
}

// --- Get allocation ---

TEST_F(IPAMTest, GetAllocationReturnsFullSet) {
    ipam->allocate_tunnel_ip("node1");
    ipam->allocate_private_subnet("node1", 30);
    ipam->allocate_shared_block("node1", 30);

    auto alloc = ipam->get_allocation("node1");
    ASSERT_TRUE(alloc.has_value());
    EXPECT_TRUE(alloc->tunnel.has_value());
    EXPECT_TRUE(alloc->private_subnet.has_value());
    EXPECT_TRUE(alloc->shared_block.has_value());
}

TEST_F(IPAMTest, GetNonExistentAllocation) {
    auto alloc = ipam->get_allocation("nonexistent");
    EXPECT_FALSE(alloc.has_value());
}

// --- Expand ---

TEST_F(IPAMTest, ExpandPrivateSubnet) {
    ipam->allocate_private_subnet("node1", 30);
    auto expanded = ipam->expand_allocation("node1", ipam::BlockType::Private, 28);
    EXPECT_NE(expanded.base_network.find("/28"), std::string::npos);
}

TEST_F(IPAMTest, ExpandTunnelThrows) {
    ipam->allocate_tunnel_ip("node1");
    EXPECT_THROW(
        ipam->expand_allocation("node1", ipam::BlockType::Tunnel, 30),
        std::runtime_error);
}

// --- Conflict check ---

TEST_F(IPAMTest, CheckConflictDetectsOverlap) {
    auto alloc = ipam->allocate_tunnel_ip("node1");
    EXPECT_TRUE(ipam->check_conflict(alloc.base_network));
}

TEST_F(IPAMTest, CheckConflictNoOverlap) {
    // 192.168.0.0/24 should not conflict with any IPAM ranges
    EXPECT_FALSE(ipam->check_conflict("192.168.0.0/24"));
}

// --- Persistence ---

TEST_F(IPAMTest, AllocationsSurviveRestart) {
    auto a1 = ipam->allocate_tunnel_ip("node1");
    auto a2 = ipam->allocate_private_subnet("node1", 30);

    // Restart
    ipam->stop();
    ipam = std::make_unique<ipam::IPAMService>(*storage);
    ipam->start();

    auto alloc = ipam->get_allocation("node1");
    ASSERT_TRUE(alloc.has_value());
    ASSERT_TRUE(alloc->tunnel.has_value());
    EXPECT_EQ(alloc->tunnel->base_network, a1.base_network);
    ASSERT_TRUE(alloc->private_subnet.has_value());
    EXPECT_EQ(alloc->private_subnet->base_network, a2.base_network);
}

// --- Service interface ---

TEST_F(IPAMTest, ServiceName) {
    EXPECT_EQ(ipam->service_name(), "IPAMService");
}

// --- Tree-derived tunnel addresses (tree operations on) ---

TEST_F(IPAMTest, TreeAddressesAreRecordedAndFollowTheTree) {
    const auto server = ipam->allocate_tunnel_ip("server-a");  // IPAM's own range
    EXPECT_EQ(ipam->sync_tree_tunnel_addresses({{"d1", "10.65.0.7/32"},
                                                {"d2", "10.70.1.2/32"},
                                                {"legacy", "10.64.0.99/32"}}),
              2u);  // the IPAM-range address is not the tree's to record
    ASSERT_TRUE(ipam->get_allocation("d1").has_value());
    EXPECT_EQ(ipam->get_allocation("d1")->tunnel->base_network, "10.65.0.7/32");
    EXPECT_FALSE(ipam->get_allocation("legacy").has_value());
    EXPECT_TRUE(ipam->check_conflict("10.65.0.7/32"));

    // Nothing changed: nothing is written.
    EXPECT_EQ(ipam->sync_tree_tunnel_addresses({{"d1", "10.65.0.7/32"}, {"d2", "10.70.1.2/32"}}),
              0u);
    // d2 left the tree and d1 moved: the records follow, and IPAM's own
    // allocations stay.
    EXPECT_EQ(ipam->sync_tree_tunnel_addresses({{"d1", "10.65.0.8/32"}}), 2u);
    EXPECT_FALSE(ipam->get_allocation("d2").has_value());
    EXPECT_EQ(ipam->get_allocation("d1")->tunnel->base_network, "10.65.0.8/32");
    EXPECT_EQ(ipam->get_allocation("server-a")->tunnel->base_network, server.base_network);

    // After a restart the records come back, and the sequential cursor stays
    // in IPAM's range instead of jumping past the tree's addresses.
    ipam->stop();
    ipam = std::make_unique<ipam::IPAMService>(*storage);
    ipam->start();
    EXPECT_EQ(ipam->get_allocation("d1")->tunnel->base_network, "10.65.0.8/32");
    const auto next = ipam->allocate_tunnel_ip("server-b");
    EXPECT_EQ(next.base_network.rfind("10.64.", 0), 0u) << next.base_network;
}

// --- Server tunnel addresses ---

TEST(ServerTunnelAddress, FollowsTheBackboneOffset) {
    using ipam::IPAMService;
    EXPECT_EQ(IPAMService::server_tunnel_for_backbone("172.16.0.10/32"), "10.64.252.10/32");
    EXPECT_EQ(IPAMService::server_tunnel_for_backbone("172.16.1.7"), "10.64.253.7/32");
    EXPECT_EQ(IPAMService::server_tunnel_for_backbone("172.16.3.255/32"), "10.64.255.255/32");

    for (const char* bad : {"172.16.0.9/32",   // reserved backbone offset
                            "172.16.4.1/32",   // outside 172.16.0.0/22
                            "10.64.0.10/32",   // not a backbone address
                            "172.16.0.10/24",  // not one address
                            "172.16.0.010/32", "172.16.0.10.1/32", "172.16.0/32",
                            "172.16.0.x/32", "", "/32"}) {
        EXPECT_FALSE(IPAMService::server_tunnel_for_backbone(bad).has_value()) << bad;
    }
}

TEST_F(IPAMTest, ServerTunnelRecordReplacesASequentialOne) {
    // The address the old startup path gave every server.
    ASSERT_EQ(ipam->allocate_tunnel_ip("srv").base_network, "10.64.0.10/32");
    EXPECT_TRUE(ipam->assign_server_tunnel_ip("srv").base_network.empty())
        << "no backbone allocation, so no server address";

    const auto backbone = ipam->allocate_backbone_ip("srv", "c3J2LWtleS1zcnYtMDAwMDAwMDAwMDAw");
    const auto expected = ipam::IPAMService::server_tunnel_for_backbone(backbone.base_network);
    ASSERT_TRUE(expected.has_value());
    const auto record = ipam->assign_server_tunnel_ip("srv");
    EXPECT_EQ(record.base_network, *expected);
    EXPECT_EQ(ipam->get_allocation("srv")->tunnel->base_network, *expected);
    EXPECT_TRUE(ipam->check_conflict(*expected));
    EXPECT_FALSE(ipam->check_conflict("10.64.0.10/32"));

    // The record survives a restart and does not move the sequential cursor
    // into the server range.
    ipam->stop();
    ipam = std::make_unique<ipam::IPAMService>(*storage);
    ipam->start();
    EXPECT_EQ(ipam->get_allocation("srv")->tunnel->base_network, *expected);
    EXPECT_EQ(ipam->assign_server_tunnel_ip("srv").base_network, *expected);
    EXPECT_EQ(ipam->allocate_tunnel_ip("legacy").base_network, "10.64.0.10/32");
}

// Each server keeps its own IPAM file. Before servers derived their address
// from the backbone allocation, a server took the first sequential address
// (from its own file or a peer's), so every server in the fleet bound
// 10.64.0.10 and private API traffic could not tell the servers apart.
TEST(ServerTunnelAddress, EveryServerInAFleetGetsItsOwnAddress) {
    struct Server {
        fs::path dir;
        std::unique_ptr<storage::FileStorageService> storage;
        std::unique_ptr<ipam::IPAMService> ipam;
        std::string id;
        std::string key;
        std::string tunnel;
    };
    // The first two keys share the 16 characters that pick the preferred
    // backbone offset, so the second server must probe to another address.
    const std::vector<std::string> keys = {
        "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=",
        "QUFBQUFBQUFBQUFBQUFBQkJCQkJCQkJCQkJCQkJCQkI=",
        "Q0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0NDQ0M=",
        "RERERERERERERERERERERERERERERERERERERERERE=",
        "RUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUU=",
        "RkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkZGRkY=",
    };
    const auto base = fs::temp_directory_path() /
                      ("nexus_test_server_tunnel_" + std::to_string(getpid()));
    std::vector<Server> fleet(keys.size());
    std::vector<ipam::BackboneAllocationDelta> claims;
    std::set<std::string> addresses;

    const auto open = [](Server& s) {
        s.storage = std::make_unique<storage::FileStorageService>(s.dir);
        s.storage->start();
        s.ipam = std::make_unique<ipam::IPAMService>(*s.storage);
        s.ipam->start();
    };
    const auto close = [](Server& s) {
        s.ipam->stop();
        s.storage->stop();
    };

    // Servers start one at a time, as in a rollout. Each one has already
    // received the backbone claims of the servers before it through gossip.
    for (std::size_t i = 0; i < fleet.size(); ++i) {
        auto& s = fleet[i];
        s.dir = base / ("srv" + std::to_string(i));
        fs::create_directories(s.dir);
        open(s);
        s.id = "srv-" + std::to_string(i);
        s.key = keys[i];
        for (const auto& claim : claims) (void)s.ipam->apply_remote_backbone_allocation(claim);

        s.tunnel = core::resolve_tunnel_ip(s.id, s.key, *s.ipam);
        ASSERT_FALSE(s.tunnel.empty()) << s.id;
        EXPECT_NE(s.tunnel, "10.64.0.10") << s.id;
        EXPECT_EQ(s.tunnel.rfind("10.64.25", 0), 0u) << s.id << " " << s.tunnel;
        addresses.insert(s.tunnel);

        const auto backbone = s.ipam->get_allocation(s.id)->backbone;
        ASSERT_TRUE(backbone.has_value());
        ipam::BackboneAllocationDelta claim;
        claim.delta_id = "claim-" + s.id;
        claim.operation = "allocate";
        claim.server_node_id = s.id;
        claim.server_pubkey = s.key;
        claim.backbone_ip = backbone->base_network;
        claim.timestamp = 1;
        claims.push_back(claim);
    }
    EXPECT_EQ(addresses.size(), fleet.size()) << "two servers share a tunnel address";

    // A restart gives every server the same address again.
    for (auto& s : fleet) {
        close(s);
        open(s);
        EXPECT_EQ(core::resolve_tunnel_ip(s.id, s.key, *s.ipam), s.tunnel) << s.id;
        close(s);
    }
    std::error_code ec;
    fs::remove_all(base, ec);
}

TEST(ServerTunnelAddress, NoIdentityGivesNoAddress) {
    const auto dir = fs::temp_directory_path() /
                     ("nexus_test_server_tunnel_none_" + std::to_string(getpid()));
    fs::create_directories(dir);
    {
        storage::FileStorageService storage{dir};
        storage.start();
        ipam::IPAMService ipam{storage};
        ipam.start();
        EXPECT_TRUE(core::resolve_tunnel_ip("", "a2V5", ipam).empty());
        EXPECT_TRUE(core::resolve_tunnel_ip("srv", "", ipam).empty());
        EXPECT_FALSE(ipam.get_allocation("srv").has_value());
        ipam.stop();
        storage.stop();
    }
    std::error_code ec;
    fs::remove_all(dir, ec);
}
