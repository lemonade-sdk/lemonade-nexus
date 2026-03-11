#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <string>

using namespace nexus;
namespace fs = std::filesystem;

class IPAMTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<ipam::IPAMService> ipam;

    void SetUp() override {
        temp_dir = fs::temp_directory_path() / ("nexus_test_ipam_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()));
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
