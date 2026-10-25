// Forwarding authorization in the server's userspace dataplane.
//
// A client's server peer covers the whole tunnel plane, so the server sees
// every packet one endpoint sends toward another. The server must forward it
// only when the source endpoint's key may connect to the destination endpoint
// (ConnectPrivate or ConnectShared on that device, inside the source's group),
// let replies to an allowed flow return, and keep infrastructure addresses
// outside the plane and admin-placed relays on the open rule. A node's
// tunnel_ip counts only when the server's dataplane peer for that address has
// the node's mesh key.
//
// Each test runs real dataplanes with Noise sessions over loopback UDP. The
// policy comes from a real PermissionTreeService through ForwardAuthorizer.

#include <gtest/gtest.h>

#include <LemonadeNexus/Boringtun/ForwardAuthorizer.hpp>
#include <LemonadeNexus/Boringtun/UserspaceDataplane.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexusSDK/BoringtunMesh.hpp>
#include <LemonadeNexusSDK/Types.hpp>

#include <httplib.h>
#include <sodium.h>

#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
using namespace nexus::boringtun;
using namespace std::chrono_literals;
namespace fs = std::filesystem;

namespace {

struct Keypair {
    std::string pub_b64;
    std::string priv_b64;
};

Keypair make_keypair() {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);
    char pub[sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL)];
    char priv[sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL)];
    sodium_bin2base64(pub, sizeof(pub), pk, 32, sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(priv, sizeof(priv), sk, 32, sodium_base64_VARIANT_ORIGINAL);
    sodium_memzero(sk, sizeof sk);
    return {pub, priv};
}

uint32_t addr_of(const std::string& dotted) {
    return Cidr::parse(dotted)->network;
}

constexpr uint8_t kTcpSyn = 0x02;
constexpr uint8_t kTcpAck = 0x10;

/// A minimal IPv4/TCP segment with the given flags and a payload marker.
std::vector<uint8_t> make_tcp(uint32_t src, uint32_t dst, uint8_t flags,
                              const std::string& payload) {
    std::vector<uint8_t> pkt(20 + 20 + payload.size(), 0);
    pkt[0] = 0x45;
    const auto total = static_cast<uint16_t>(pkt.size());
    pkt[2] = static_cast<uint8_t>(total >> 8);
    pkt[3] = static_cast<uint8_t>(total & 0xFF);
    pkt[8] = 64;
    pkt[9] = 6;
    for (int i = 0; i < 4; ++i) {
        pkt[12 + i] = static_cast<uint8_t>(src >> (8 * (3 - i)));
        pkt[16 + i] = static_cast<uint8_t>(dst >> (8 * (3 - i)));
    }
    pkt[20 + 12] = 0x50;  // data offset 5
    pkt[20 + 13] = flags;
    std::memcpy(pkt.data() + 40, payload.data(), payload.size());
    return pkt;
}

struct Inbox {
    std::mutex mtx;
    std::condition_variable cv;
    std::vector<std::string> payloads;

    UserspaceDataplane::InboundIpHandler handler() {
        return [this](std::span<const uint8_t> pkt) {
            std::lock_guard lock(mtx);
            payloads.emplace_back(reinterpret_cast<const char*>(pkt.data()), pkt.size());
            cv.notify_all();
        };
    }

    bool wait_for(const std::string& needle, std::chrono::milliseconds timeout) {
        std::unique_lock lock(mtx);
        return cv.wait_for(lock, timeout, [&] { return contains_locked(needle); });
    }

    bool contains(const std::string& needle) {
        std::lock_guard lock(mtx);
        return contains_locked(needle);
    }

private:
    bool contains_locked(const std::string& needle) {
        for (const auto& p : payloads)
            if (p.find(needle) != std::string::npos) return true;
        return false;
    }
};

/// One dataplane: the server or a client endpoint.
struct Node {
    Keypair            keys = make_keypair();
    UserspaceDataplane dataplane;
    Inbox              inbox;
    std::string        ip;  // tunnel IP without a prefix

    bool start(const std::string& tunnel_ip) {
        ip = tunnel_ip;
        dataplane.set_inbound_handler(inbox.handler());
        if (!dataplane.start({keys.priv_b64, keys.pub_b64, 0, 2})) return false;
        dataplane.add_local_ip(addr_of(ip));
        return true;
    }

    std::string endpoint() const { return "127.0.0.1:" + std::to_string(dataplane.bound_port()); }
};

class ForwardAuthzTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<crypto::SodiumCryptoService> crypto_svc;
    std::unique_ptr<storage::FileStorageService> storage_svc;
    std::unique_ptr<tree::PermissionTreeService> tree_svc;

    Node server;
    std::map<std::string, std::unique_ptr<Node>> clients;  // by tree node id
    std::map<std::string, std::string>           principal;  // node id -> mgmt key
    std::unique_ptr<ForwardAuthorizer>           authorizer;
    const Cidr plane = *Cidr::parse("10.64.0.0/10");

    static void SetUpTestSuite() { ASSERT_GE(sodium_init(), 0); }

    void SetUp() override {
        temp_dir = fs::temp_directory_path() /
                   ("nexus_test_forward_authz_" + std::to_string(getpid()) + "_" +
                    std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(temp_dir);
        crypto_svc = std::make_unique<crypto::SodiumCryptoService>();
        crypto_svc->start();
        storage_svc = std::make_unique<storage::FileStorageService>(temp_dir);
        storage_svc->start();
        tree_svc = std::make_unique<tree::PermissionTreeService>(*storage_svc, *crypto_svc);
        tree_svc->start();
        tree::TreeNode root;
        root.id   = "root";
        root.type = tree::NodeType::Root;
        tree_svc->bootstrap_root(root);
        add_group("group-1");
        add_group("group-2");

        ASSERT_TRUE(server.start("10.64.0.1"));
        authorizer = std::make_unique<ForwardAuthorizer>(*tree_svc, server.dataplane, plane, 50ms);
    }

    void TearDown() override {
        if (authorizer) authorizer->stop();
        for (auto& [id, node] : clients) node->dataplane.stop();
        server.dataplane.stop();
        tree_svc->stop();
        storage_svc->stop();
        crypto_svc->stop();
        std::error_code ec;
        fs::remove_all(temp_dir, ec);
    }

    std::string new_principal() {
        return "ed25519:" + crypto::to_base64(crypto_svc->ed25519_keygen().public_key);
    }

    void add_group(const std::string& id) {
        tree::TreeNode n;
        n.id        = id;
        n.parent_id = "root";
        n.type      = tree::NodeType::Customer;
        ASSERT_TRUE(tree_svc->insert_join_node(n));
    }

    /// Add a client dataplane with a session to the server, and a tree node
    /// that holds the client's mesh key, as a join records it.
    void add_node(const std::string& id, const std::string& group, tree::NodeType type,
                  const std::string& tunnel_ip,
                  std::vector<tree::Assignment> assignments = {}) {
        principal[id] = new_principal();
        add_client(id, tunnel_ip);
        if (HasFatalFailure()) return;
        tree::TreeNode n;
        n.id          = id;
        n.parent_id   = group;
        n.type        = type;
        n.mgmt_pubkey = principal[id];
        n.mesh_pubkey = clients.at(id)->keys.pub_b64;
        n.tunnel_ip   = tunnel_ip + "/32";
        n.assignments = std::move(assignments);
        ASSERT_TRUE(tree_svc->insert_join_node(n));
    }

    /// A tree node with no dataplane of its own: what a writer could store by
    /// creating a child node.
    void add_claim(const std::string& id, const std::string& parent, tree::NodeType type,
                   const std::string& tunnel_ip, const std::string& mesh_pubkey,
                   const std::string& owner) {
        tree::TreeNode n;
        n.id          = id;
        n.parent_id   = parent;
        n.type        = type;
        n.mgmt_pubkey = principal.at(owner);
        n.mesh_pubkey = mesh_pubkey;
        n.tunnel_ip   = tunnel_ip + "/32";
        n.assignments = {{principal.at(owner), {"read", "connect_private", "admin"}}};
        ASSERT_TRUE(tree_svc->insert_join_node(n));
    }

    /// The policy for the current tree and the server's current peers.
    std::shared_ptr<const ForwardPolicy> policy_now() {
        return build_forward_policy(*tree_svc, plane, server.dataplane.primary_address_peers());
    }

    bool allowed(const std::string& from_ip, const std::string& to_ip) {
        return policy_now()->allowed.contains(
            ForwardPolicy::key(addr_of(from_ip), addr_of(to_ip)));
    }

    /// A client dataplane that routes the whole plane to the server, and the
    /// server's peer entry for it.
    void add_client(const std::string& id, const std::string& tunnel_ip,
                    const std::optional<Keypair>& keys = std::nullopt) {
        auto node = std::make_unique<Node>();
        if (keys) node->keys = *keys;
        ASSERT_TRUE(node->start(tunnel_ip));
        ASSERT_TRUE(node->dataplane.add_peer(server.keys.pub_b64, "10.64.0.0/10",
                                             server.endpoint()));
        ASSERT_TRUE(server.dataplane.add_peer(node->keys.pub_b64, tunnel_ip + "/32", ""));
        // The server learns the client's endpoint from its first packet.
        const auto hello = make_tcp(addr_of(tunnel_ip), addr_of(server.ip), kTcpAck,
                                    "hello-" + id);
        ASSERT_TRUE(send_until(*node, server.inbox, hello, "hello-" + id));
        clients[id] = std::move(node);
    }

    void grant(const std::string& target, const std::string& holder,
               std::vector<std::string> perms) {
        auto node = tree_svc->get_node(target);
        ASSERT_TRUE(node.has_value());
        node->assignments.push_back({principal.at(holder), std::move(perms)});
        ASSERT_TRUE(tree_svc->update_node_direct(target, *node));
    }

    static bool send_until(Node& from, Inbox& to, const std::vector<uint8_t>& pkt,
                           const std::string& needle,
                           std::chrono::milliseconds timeout = 5000ms) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            (void)from.dataplane.send_outbound_ip_packet(pkt);
            if (to.wait_for(needle, 100ms)) return true;
        }
        return false;
    }

    /// Send a TCP segment from client `from` to client `to` through the server.
    bool reaches(const std::string& from, const std::string& to, uint8_t flags,
                 const std::string& marker, std::chrono::milliseconds timeout = 3000ms) {
        auto& a = *clients.at(from);
        auto& b = *clients.at(to);
        return send_until(a, b.inbox, make_tcp(addr_of(a.ip), addr_of(b.ip), flags, marker),
                          marker, timeout);
    }

    /// Send a few times and confirm nothing arrives.
    bool blocked(const std::string& from, const std::string& to, uint8_t flags,
                 const std::string& marker) {
        return !reaches(from, to, flags, marker, 600ms);
    }
};

}  // namespace

TEST_F(ForwardAuthzTest, ConnectGrantPassesAndRepliesReturn) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("b", "group-1", tree::NodeType::Endpoint, "10.64.0.3");
    grant("b", "a", {"read", "connect_private"});
    authorizer->start();

    EXPECT_TRUE(reaches("a", "b", kTcpSyn, "a-syn-to-b"));
    EXPECT_TRUE(reaches("b", "a", kTcpSyn | kTcpAck, "b-synack-to-a"));
    EXPECT_TRUE(reaches("b", "a", kTcpAck, "b-data-to-a"));
    // B holds no grant on A, so B cannot open a connection to A.
    EXPECT_TRUE(blocked("b", "a", kTcpSyn, "b-syn-to-a"));
    EXPECT_GT(server.dataplane.forward_denied_count(), 0u);
}

TEST_F(ForwardAuthzTest, ConnectSharedAndAdminGrantsPass) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("shared", "group-1", tree::NodeType::Endpoint, "10.64.0.3");
    add_node("admin", "group-1", tree::NodeType::Endpoint, "10.64.0.4");
    grant("shared", "a", {"connect_shared"});
    grant("admin", "a", {"admin"});
    authorizer->start();
    EXPECT_TRUE(reaches("a", "shared", kTcpSyn, "a-to-shared"));
    EXPECT_TRUE(reaches("a", "admin", kTcpSyn, "a-to-admin"));
}

TEST_F(ForwardAuthzTest, ReadOnlyIsDropped) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("c", "group-1", tree::NodeType::Endpoint, "10.64.0.4");
    grant("c", "a", {"read"});
    authorizer->start();
    EXPECT_TRUE(blocked("a", "c", kTcpSyn, "a-syn-to-c"));
    EXPECT_TRUE(blocked("a", "c", kTcpAck, "a-ack-to-c"));
}

TEST_F(ForwardAuthzTest, CrossGroupGrantIsDropped) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("x", "group-2", tree::NodeType::Endpoint, "10.64.0.5");
    grant("x", "a", {"read", "connect_private"});
    authorizer->start();
    EXPECT_TRUE(blocked("a", "x", kTcpSyn, "a-syn-to-x"));
}

// An accepted invite is a connect entry for the member's key on the target
// group. The member's device and the group's devices reach each other; the
// member's other devices (other keys) and the rest of its network do not.
TEST_F(ForwardAuthzTest, AnInviteMembershipReachesOnlyTheMembersDevice) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("b", "group-2", tree::NodeType::Endpoint, "10.64.0.3");
    add_node("b2", "group-2", tree::NodeType::Endpoint, "10.64.0.4");
    grant("b2", "b", {"read", "connect_private"});
    grant("group-1", "b", {"connect_private", "read"});
    authorizer->start();

    EXPECT_TRUE(allowed("10.64.0.3", "10.64.0.2"));
    EXPECT_TRUE(allowed("10.64.0.2", "10.64.0.3"));
    EXPECT_FALSE(allowed("10.64.0.2", "10.64.0.4"));
    EXPECT_FALSE(allowed("10.64.0.4", "10.64.0.2"));
    EXPECT_TRUE(reaches("b", "a", kTcpSyn, "member-to-group"));
    EXPECT_TRUE(reaches("a", "b", kTcpSyn, "group-to-member"));
    EXPECT_TRUE(blocked("a", "b2", kTcpSyn, "group-to-other-device"));

    // Removing the membership entry removes the reach.
    auto group = tree_svc->get_node("group-1");
    ASSERT_TRUE(group.has_value());
    group->assignments.clear();
    ASSERT_TRUE(tree_svc->update_node_direct("group-1", *group));
    EXPECT_FALSE(allowed("10.64.0.3", "10.64.0.2"));
    EXPECT_FALSE(allowed("10.64.0.2", "10.64.0.3"));
}

// An admin entry on a group is not a membership: it opens no device.
TEST_F(ForwardAuthzTest, AGroupAdminEntryOpensNoDevice) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("x", "group-2", tree::NodeType::Endpoint, "10.64.0.5");
    grant("group-2", "a", {"admin"});
    authorizer->start();
    EXPECT_FALSE(allowed("10.64.0.2", "10.64.0.5"));
    EXPECT_FALSE(allowed("10.64.0.5", "10.64.0.2"));
}

// Linked devices get read + connect_private on each other at join.
TEST_F(ForwardAuthzTest, LinkedDevicesReachEachOther) {
    add_node("laptop", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("desktop", "group-1", tree::NodeType::Endpoint, "10.64.0.3");
    grant("laptop", "desktop", {"read", "connect_private"});
    grant("desktop", "laptop", {"read", "connect_private"});
    authorizer->start();
    EXPECT_TRUE(reaches("laptop", "desktop", kTcpSyn, "laptop-to-desktop"));
    EXPECT_TRUE(reaches("desktop", "laptop", kTcpSyn, "desktop-to-laptop"));
}

// A relay placed by a root admin and an address outside the client plane (a
// backbone server) keep the open rule. An address inside the plane that is
// not in the tree is dropped.
TEST_F(ForwardAuthzTest, RelayAndBackbonePathsAreUnchangedAndUnknownIsDropped) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("relay", "group-1", tree::NodeType::Relay, "10.64.0.7");
    grant("root", "relay", {"admin"});
    add_client("backbone", "172.16.0.2");
    add_client("stranger", "10.64.0.9");
    // Let A accept the backbone source from its server peer, so the test sees
    // what the server forwards.
    ASSERT_TRUE(clients.at("a")->dataplane.add_peer(
        server.keys.pub_b64, "10.64.0.0/10,172.16.0.0/22", server.endpoint()));
    authorizer->start();
    EXPECT_TRUE(reaches("a", "relay", kTcpSyn, "a-to-relay"));
    EXPECT_TRUE(reaches("relay", "a", kTcpSyn, "relay-to-a"));
    EXPECT_TRUE(reaches("backbone", "a", kTcpSyn, "backbone-to-a"));
    EXPECT_TRUE(blocked("a", "stranger", kTcpSyn, "a-to-stranger"));
    EXPECT_TRUE(blocked("stranger", "a", kTcpSyn, "stranger-to-a"));
}

// The inner source must lie in the sender's allowed IPs (route_decrypted), so
// an endpoint cannot borrow an authorized peer's address.
TEST_F(ForwardAuthzTest, SpoofedSourceIsDropped) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("b", "group-1", tree::NodeType::Endpoint, "10.64.0.3");
    add_node("c", "group-1", tree::NodeType::Endpoint, "10.64.0.4");
    grant("b", "a", {"read", "connect_private"});
    authorizer->start();
    // C claims A's address to reach B, which only A may reach.
    auto& c = *clients.at("c");
    auto& b = *clients.at("b");
    const auto forged = make_tcp(addr_of("10.64.0.2"), addr_of(b.ip), kTcpSyn, "forged-as-a");
    EXPECT_FALSE(send_until(c, b.inbox, forged, "forged-as-a", 600ms));
    EXPECT_TRUE(reaches("a", "b", kTcpSyn, "real-a-to-b"));
}

TEST_F(ForwardAuthzTest, RevokedConnectIsDroppedAfterOneRebuild) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("b", "group-1", tree::NodeType::Endpoint, "10.64.0.3");
    grant("b", "a", {"read", "connect_private"});
    authorizer->start();
    ASSERT_TRUE(reaches("a", "b", kTcpSyn, "before-revoke"));

    // Stop the background poll so this test drives the one rebuild itself.
    authorizer->stop();
    auto node = tree_svc->get_node("b");
    ASSERT_TRUE(node.has_value());
    node->assignments.clear();
    ASSERT_TRUE(tree_svc->update_node_direct("b", *node));
    EXPECT_TRUE(reaches("a", "b", kTcpSyn, "before-rebuild"))
        << "the installed policy changed before a rebuild";
    EXPECT_TRUE(authorizer->refresh());
    EXPECT_TRUE(blocked("a", "b", kTcpSyn, "after-revoke"));
    EXPECT_FALSE(authorizer->refresh()) << "an unchanged tree must not rebuild";
}

TEST_F(ForwardAuthzTest, BackgroundPollAppliesAGrant) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("b", "group-1", tree::NodeType::Endpoint, "10.64.0.3");
    authorizer->start();
    ASSERT_TRUE(blocked("a", "b", kTcpSyn, "before-grant"));
    grant("b", "a", {"connect_private"});
    EXPECT_TRUE(reaches("a", "b", kTcpSyn, "after-grant", 5000ms));
}

// End to end: an SDK client with only Read on a device cannot open a TCP
// connection to that device's published service through the server, and a
// client with Connect can. Without the policy, the Read-only client reached
// the service (the defect this test pins).
TEST_F(ForwardAuthzTest, ReadOnlyClientCannotReachAServiceThroughTheServer) {
    httplib::Server api;
    api.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("pong", "text/plain");
    });
    const int api_port = api.bind_to_any_port("127.0.0.1");
    ASSERT_GT(api_port, 0);
    std::thread api_thread([&api] { api.listen_after_bind(); });

    struct Device {
        std::string id;
        std::string ip;
        std::pair<std::string, std::string> keys = lnsdk::BoringtunMesh::generate_keypair();
        lnsdk::BoringtunMesh mesh;
    };
    Device svc{"svc", "10.64.0.3"};
    Device reader{"reader", "10.64.0.4"};
    Device dialer{"dialer", "10.64.0.5"};
    for (Device* d : {&svc, &reader, &dialer}) {
        principal[d->id] = new_principal();
        tree::TreeNode n;
        n.id          = d->id;
        n.parent_id   = "group-1";
        n.type        = tree::NodeType::Endpoint;
        n.mgmt_pubkey = principal[d->id];
        n.mesh_pubkey = d->keys.second;
        n.tunnel_ip   = d->ip + "/32";
        ASSERT_TRUE(tree_svc->insert_join_node(n));
        lnsdk::BoringtunConfig cfg;
        cfg.private_key       = d->keys.first;
        cfg.public_key        = d->keys.second;
        cfg.tunnel_ip         = d->ip + "/32";
        cfg.allowed_ips       = {"10.64.0.0/10"};
        cfg.server_public_key = server.keys.pub_b64;
        cfg.server_endpoint   = server.endpoint();
        ASSERT_TRUE(d->mesh.start(cfg));
        ASSERT_TRUE(server.dataplane.add_peer(d->keys.second, d->ip + "/32", ""));
    }
    grant("svc", "reader", {"read"});
    grant("svc", "dialer", {"read", "connect_private"});
    authorizer->start();
    ASSERT_TRUE(svc.mesh.tcp_ingress(8080, "tcp:127.0.0.1:" + std::to_string(api_port)));

    // The service device contacts the server so the server learns its endpoint.
    const uint16_t warm = svc.mesh.tcp_egress(server.ip, 1);
    {
        httplib::Client w("127.0.0.1", warm);
        w.set_connection_timeout(1);
        w.set_read_timeout(1);
        (void)w.Get("/");
    }

    auto get_ping = [&](Device& from, std::chrono::seconds budget) {
        const uint16_t port = from.mesh.tcp_egress(svc.ip, 8080);
        httplib::Client c("127.0.0.1", port);
        c.set_connection_timeout(2);
        c.set_read_timeout(2);
        const auto deadline = std::chrono::steady_clock::now() + budget;
        do {
            auto res = c.Get("/ping");
            if (res && res->status == 200 && res->body == "pong") return true;
            std::this_thread::sleep_for(200ms);
        } while (std::chrono::steady_clock::now() < deadline);
        return false;
    };

    EXPECT_TRUE(get_ping(dialer, 15s)) << "a client with Connect could not reach the service";
    EXPECT_FALSE(get_ping(reader, 5s)) << "a Read-only client reached the service";

    for (Device* d : {&svc, &reader, &dialer}) d->mesh.stop();
    api.stop();
    api_thread.join();
}

// The attack: a device holds add_child on its own endpoint, so it could store
// a child node that names a victim's address and grants the device
// connect_private. The policy must not map the victim's address to that
// child, because the server's peer for the address has the victim's key.
TEST_F(ForwardAuthzTest, AChildNodeNamingAVictimAddressGrantsNothing) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("v", "group-1", tree::NodeType::Endpoint, "10.64.0.3");
    add_claim("a-child", "a", tree::NodeType::Endpoint, "10.64.0.3", make_keypair().pub_b64, "a");
    EXPECT_FALSE(allowed("10.64.0.2", "10.64.0.3"));
    authorizer->start();
    EXPECT_TRUE(blocked("a", "v", kTcpSyn, "a-via-child-to-v"));
}

// The same attack with a Relay child: a relay address is open in both
// directions, so the victim's address must not become a relay address.
TEST_F(ForwardAuthzTest, ARelayChildNamingAVictimAddressIsNotOpen) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("v", "group-1", tree::NodeType::Endpoint, "10.64.0.3");
    add_claim("a-relay", "a", tree::NodeType::Relay, "10.64.0.3", make_keypair().pub_b64, "a");
    EXPECT_FALSE(policy_now()->open.contains(addr_of("10.64.0.3")));
    authorizer->start();
    EXPECT_TRUE(blocked("a", "v", kTcpSyn, "a-via-relay-to-v"));
}

// The tree refuses a second node with the same mesh key text, but an
// "ed25519:" spelling of the victim's identity-bound key is different text
// that normalizes to the same peer key. A node that copies the victim's
// address with that spelling makes the owner ambiguous: the address gets no
// rule at all, so the copy gains nothing.
TEST_F(ForwardAuthzTest, TwoNodesClaimingOnePeerLeaveTheAddressWithoutRules) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("b", "group-1", tree::NodeType::Endpoint, "10.64.0.4");

    // The victim's mesh key is the X25519 form of its Ed25519 identity.
    const auto identity = crypto_svc->ed25519_keygen();
    const auto x_pk = crypto::SodiumCryptoService::ed25519_pk_to_x25519(identity.public_key);
    const auto x_sk = crypto::SodiumCryptoService::ed25519_sk_to_x25519(identity.private_key);
    const Keypair victim_keys{crypto::to_base64(x_pk), crypto::to_base64(x_sk)};
    principal["v"] = new_principal();
    add_client("v", "10.64.0.3", victim_keys);
    if (HasFatalFailure()) return;
    tree::TreeNode v;
    v.id = "v";
    v.parent_id = "group-1";
    v.type = tree::NodeType::Endpoint;
    v.mgmt_pubkey = principal["v"];
    v.mesh_pubkey = victim_keys.pub_b64;
    v.tunnel_ip = "10.64.0.3/32";
    v.assignments = {{principal["b"], {"connect_private"}}};
    ASSERT_TRUE(tree_svc->insert_join_node(v));
    EXPECT_TRUE(allowed("10.64.0.4", "10.64.0.3"));

    add_claim("a-copy", "a", tree::NodeType::Endpoint, "10.64.0.3",
              "ed25519:" + crypto::to_base64(identity.public_key), "a");
    EXPECT_FALSE(allowed("10.64.0.2", "10.64.0.3"));
    EXPECT_FALSE(allowed("10.64.0.4", "10.64.0.3"));
    EXPECT_FALSE(policy_now()->open.contains(addr_of("10.64.0.3")));
}

// A relay is open only when a root admin placed it: its management key must
// administer the tree root. Admin on the relay itself (a creator can give
// itself that) or on its group does not count.
TEST_F(ForwardAuthzTest, ARelayWithoutARootAdminIsNotOpen) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("relay", "group-1", tree::NodeType::Relay, "10.64.0.7");
    grant("relay", "relay", {"admin"});
    grant("group-1", "relay", {"admin"});
    EXPECT_FALSE(policy_now()->open.contains(addr_of("10.64.0.7")));
    authorizer->start();
    EXPECT_TRUE(blocked("a", "relay", kTcpSyn, "a-to-unanchored-relay"));
    grant("root", "relay", {"admin"});
    EXPECT_TRUE(policy_now()->open.contains(addr_of("10.64.0.7")));
}

// A node whose stored mesh key is not the key of the server's peer for its
// address gets no rule, even with a valid grant.
TEST_F(ForwardAuthzTest, ANodeWhoseKeyIsNotThePeerKeyGetsNoRule) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("b", "group-1", tree::NodeType::Endpoint, "10.64.0.3");
    grant("b", "a", {"connect_private"});
    EXPECT_TRUE(allowed("10.64.0.2", "10.64.0.3"));
    auto node = tree_svc->get_node("b");
    ASSERT_TRUE(node.has_value());
    node->mesh_pubkey = make_keypair().pub_b64;
    ASSERT_TRUE(tree_svc->update_node_direct("b", *node));
    EXPECT_FALSE(allowed("10.64.0.2", "10.64.0.3"));
}

// The policy depends on the dataplane's peers too, so a peer change rebuilds
// it even when the tree did not change.
TEST_F(ForwardAuthzTest, APeerChangeRebuildsThePolicy) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    authorizer->start();
    authorizer->stop();
    EXPECT_FALSE(authorizer->refresh());
    ASSERT_TRUE(server.dataplane.add_peer(make_keypair().pub_b64, "10.64.0.9/32", ""));
    EXPECT_TRUE(authorizer->refresh());
    EXPECT_FALSE(authorizer->refresh());
}

// Without a known tunnel plane the server installs the deny policy: nothing is
// forwarded between peers, not even an address outside any plane.
TEST_F(ForwardAuthzTest, TheDenyPolicyForwardsNothing) {
    add_node("a", "group-1", tree::NodeType::Endpoint, "10.64.0.2");
    add_node("b", "group-1", tree::NodeType::Endpoint, "10.64.0.3");
    grant("b", "a", {"connect_private"});
    server.dataplane.set_forward_policy(deny_forward_policy());
    EXPECT_TRUE(blocked("a", "b", kTcpSyn, "a-to-b-denied"));
    EXPECT_TRUE(blocked("b", "a", kTcpAck, "b-to-a-denied"));
}
