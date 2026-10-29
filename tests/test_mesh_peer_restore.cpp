// Regression: a server restores its client mesh peers from the finalized tree
// at Tier 1 entry. The dataplane peer table is in-memory, so an in-place
// restart (a rolling self-update) drops every already-connected endpoint
// unless it is re-added from the tree. Before the fix the restore never ran,
// and sync_peers_from_tree always removed peers absent from the desired set,
// which would also drop the server-to-server backbone peers that are not tree
// nodes. The restore uses the additive form (remove_stale == false).

#include <gtest/gtest.h>

#include <LemonadeNexus/Boringtun/BoringtunService.hpp>
#include <LemonadeNexus/Boringtun/IBoringtunProvider.hpp>

#include <sodium.h>

#include <filesystem>
#include <string>
#include <vector>

#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using nexus::boringtun::BoringtunService;
using nexus::boringtun::BoringtunInterfaceConfig;
using nexus::boringtun::TreeNodePeer;

namespace {

// A listen port unlikely to collide, spread per run so repeated local runs do
// not race on TIME_WAIT. The dataplane binds UDP only; no peer traffic flows.
uint16_t test_port() {
    return static_cast<uint16_t>(42000 + (getpid() % 2000));
}

class MeshPeerRestoreTest : public ::testing::Test {
protected:
    std::filesystem::path dir;
    BoringtunService svc{"nexus-test", {}};

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        dir = std::filesystem::temp_directory_path() /
              ("nexus_peer_restore_" + std::to_string(getpid()));
        std::filesystem::create_directories(dir);
        svc.start();
        const auto server_keys = svc.generate_keypair();
        BoringtunInterfaceConfig cfg;
        cfg.private_key = server_keys.private_key;
        cfg.address = "10.64.0.1/10";
        cfg.listen_port = test_port();
        ASSERT_TRUE(svc.setup_interface(cfg, {}));
    }

    void TearDown() override {
        svc.stop();
        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
    }

    TreeNodePeer endpoint(const std::string& tunnel_ip) {
        TreeNodePeer p;
        p.public_key = svc.generate_keypair().public_key;
        p.tunnel_ip = tunnel_ip;
        return p;
    }
};

// The core regression: an endpoint listed in the tree becomes a dataplane peer
// again, so its surviving tunnel can re-handshake after the server restarts.
TEST_F(MeshPeerRestoreTest, RestoresTreeEndpointsAsDataplanePeers) {
    const auto peer = endpoint("10.108.51.77/32");
    EXPECT_FALSE(svc.dataplane().has_peer(peer.public_key));

    const int changes = svc.sync_peers_from_tree({peer}, /*remove_stale=*/false);
    EXPECT_EQ(changes, 1);
    EXPECT_TRUE(svc.dataplane().has_peer(peer.public_key));
}

// The additive restore must not remove a peer that is not a tree node — on the
// server that is the server-to-server backbone peer GossipService adds.
TEST_F(MeshPeerRestoreTest, AdditiveRestoreKeepsNonTreePeers) {
    const auto backbone = svc.generate_keypair();
    ASSERT_TRUE(svc.add_peer(backbone.public_key, "172.16.3.236/32", ""));
    ASSERT_TRUE(svc.dataplane().has_peer(backbone.public_key));

    const auto client = endpoint("10.108.51.77/32");
    const int changes = svc.sync_peers_from_tree({client}, /*remove_stale=*/false);
    EXPECT_EQ(changes, 1);  // only the client was added
    EXPECT_TRUE(svc.dataplane().has_peer(client.public_key));
    EXPECT_TRUE(svc.dataplane().has_peer(backbone.public_key));  // kept
}

// The full reconcile (remove_stale default) still drops peers absent from the
// desired set, so the additive flag is the only behavior change.
TEST_F(MeshPeerRestoreTest, FullReconcileStillRemovesStalePeers) {
    const auto stale = svc.generate_keypair();
    ASSERT_TRUE(svc.add_peer(stale.public_key, "10.64.9.9/32", ""));
    ASSERT_TRUE(svc.dataplane().has_peer(stale.public_key));

    const auto client = endpoint("10.108.51.77/32");
    (void)svc.sync_peers_from_tree({client});  // remove_stale defaults to true
    EXPECT_TRUE(svc.dataplane().has_peer(client.public_key));
    EXPECT_FALSE(svc.dataplane().has_peer(stale.public_key));  // removed
}

}  // namespace
