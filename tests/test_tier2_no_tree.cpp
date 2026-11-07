// Tier 2 servers hold no tree. Only a current Tier 1 member, by finalized
// epoch membership, loads, serves, and keeps the permission tree. This suite
// covers the role state machine, the deletion of tree files when a server is
// not (or stops being) a Tier 1 member, the refusal of every tree route on
// such a server, and the Tier 1 endpoints a client verifies membership with.

#include <LemonadeNexus/Acme/AcmeService.hpp>
#include <LemonadeNexus/Api/AccountDataApiHandler.hpp>
#include <LemonadeNexus/Api/AdminApiHandler.hpp>
#include <LemonadeNexus/Api/AuthApiHandler.hpp>
#include <LemonadeNexus/Api/CertApiHandler.hpp>
#include <LemonadeNexus/Api/IRequestHandler.hpp>
#include <LemonadeNexus/Api/MeshApiHandler.hpp>
#include <LemonadeNexus/Api/OnboardApiHandler.hpp>
#include <LemonadeNexus/Api/PublicApiHandler.hpp>
#include <LemonadeNexus/Api/RelayApiHandler.hpp>
#include <LemonadeNexus/Api/RoutingApiHandler.hpp>
#include <LemonadeNexus/Api/Tier1ApiHandler.hpp>
#include <LemonadeNexus/Api/TreeApiHandler.hpp>
#include <LemonadeNexus/Api/TreeRouteGate.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/ServerAdmissionService.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Network/DdnsService.hpp>
#include <LemonadeNexus/Network/HttpServer.hpp>
#include <LemonadeNexus/Relay/RelayDiscoveryService.hpp>
#include <LemonadeNexus/Relay/RelayService.hpp>
#include <LemonadeNexus/Routing/RoutingCoordinationService.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Membership.hpp>
#include <LemonadeNexus/Security/Transport/AuthorityChainCodec.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeRole.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <asio.hpp>
#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include "support/tier1_chain.hpp"

#include <atomic>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>
#include "support/tree_seed.hpp"
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
namespace fs = std::filesystem;
using json = nlohmann::json;
using tree::MembershipView;
using tree::TreeRole;
using tree::TreeRoleState;

namespace {

fs::path unique_dir(const std::string& name) {
    static std::atomic<int> counter{0};
    return fs::temp_directory_path() /
           ("nexus_tier2_" + name + "_" + std::to_string(getpid()) + "_" +
            std::to_string(counter.fetch_add(1)));
}

void write_text(const fs::path& path, const std::string& text) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
}

std::string read_text(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

}  // namespace

// ===========================================================================
// The role state machine
// ===========================================================================

namespace {

struct RoleProbe {
    int enters = 0;
    int leaves = 0;
    int purges = 0;
    bool enter_result = true;
    bool held_during_leave = true;
    TreeRole* role = nullptr;

    TreeRole::Hooks hooks() {
        return TreeRole::Hooks{
            .enter = [this] { ++enters; return enter_result; },
            .leave =
                [this] {
                    ++leaves;
                    held_during_leave = role->holds_tree();
                },
            .purge = [this] { ++purges; },
        };
    }
};

}  // namespace

TEST(TreeRoleTest, UnknownMembershipHoldsNoTreeAndDeletesNothing) {
    RoleProbe probe;
    TreeRole role{probe.hooks()};
    probe.role = &role;
    role.update(MembershipView::Unknown, true);
    EXPECT_EQ(role.state(), TreeRoleState::Pending);
    EXPECT_FALSE(role.holds_tree());
    EXPECT_EQ(probe.enters + probe.leaves + probe.purges, 0);
}

TEST(TreeRoleTest, AMemberEntersOnlyWhenTheFilesCanBeRead) {
    RoleProbe probe;
    TreeRole role{probe.hooks()};
    probe.role = &role;
    role.update(MembershipView::Member, false);  // data key still locked
    EXPECT_FALSE(role.holds_tree());
    EXPECT_EQ(probe.enters, 0);
    role.update(MembershipView::Member, true);
    EXPECT_TRUE(role.holds_tree());
    EXPECT_EQ(probe.enters, 1);
    role.update(MembershipView::Member, true);  // no repeat
    EXPECT_EQ(probe.enters, 1);
}

TEST(TreeRoleTest, AFailedEntryStaysOutAndRetries) {
    RoleProbe probe;
    probe.enter_result = false;
    TreeRole role{probe.hooks()};
    probe.role = &role;
    role.update(MembershipView::Member, true);
    EXPECT_FALSE(role.holds_tree());
    probe.enter_result = true;
    role.update(MembershipView::Member, true);
    EXPECT_TRUE(role.holds_tree());
    EXPECT_EQ(probe.enters, 2);
}

TEST(TreeRoleTest, LeavingTier1ClosesTheGateThenStopsAndDeletes) {
    RoleProbe probe;
    TreeRole role{probe.hooks()};
    probe.role = &role;
    role.update(MembershipView::Member, true);
    role.update(MembershipView::NonMember, true);
    EXPECT_EQ(role.state(), TreeRoleState::Tier2);
    EXPECT_FALSE(role.holds_tree());
    EXPECT_EQ(probe.leaves, 1);
    EXPECT_EQ(probe.purges, 1);
    EXPECT_FALSE(probe.held_during_leave) << "the gate must close before the services stop";
    role.update(MembershipView::NonMember, true);  // no repeat
    EXPECT_EQ(probe.purges, 1);
}

TEST(TreeRoleTest, AServerThatStartsOutsideTier1ClosesAndDeletes) {
    RoleProbe probe;
    TreeRole role{probe.hooks()};
    probe.role = &role;
    role.update(MembershipView::NonMember, false);  // deletion never waits for the key
    EXPECT_EQ(role.state(), TreeRoleState::Tier2);
    EXPECT_EQ(probe.enters, 0);
    EXPECT_EQ(probe.leaves, 1);
    EXPECT_EQ(probe.purges, 1);
    EXPECT_FALSE(probe.held_during_leave);
}

TEST(TreeRoleTest, LostMembershipStopsServingButDeletesNothing) {
    RoleProbe probe;
    TreeRole role{probe.hooks()};
    probe.role = &role;
    role.update(MembershipView::Member, true);
    role.update(MembershipView::Unknown, true);
    EXPECT_EQ(role.state(), TreeRoleState::Pending);
    EXPECT_FALSE(role.holds_tree());
    EXPECT_EQ(probe.leaves, 1);
    EXPECT_EQ(probe.purges, 0);
}

TEST(TreeRoleTest, ATier2ServerThatJoinsTier1EntersAgain) {
    RoleProbe probe;
    TreeRole role{probe.hooks()};
    probe.role = &role;
    role.update(MembershipView::NonMember, true);
    role.update(MembershipView::Member, true);
    EXPECT_TRUE(role.holds_tree());
    EXPECT_EQ(probe.enters, 1);
}

// ===========================================================================
// Tree files on a server that is not a Tier 1 member
// ===========================================================================

namespace {

class Tier2TreeFilesTest : public ::testing::Test {
protected:
    fs::path dir;
    std::unique_ptr<crypto::SodiumCryptoService> crypto_svc;
    std::unique_ptr<storage::FileStorageService> storage_svc;
    std::unique_ptr<tree::PermissionTreeService> tree_svc;
    crypto::Ed25519Keypair root_kp{};
    std::string root_key;

    void SetUp() override {
        dir = unique_dir("files");
        fs::create_directories(dir);
        crypto_svc = std::make_unique<crypto::SodiumCryptoService>();
        crypto_svc->start();
        storage_svc = std::make_unique<storage::FileStorageService>(dir / "data");
        storage_svc->start();
        tree_svc = std::make_unique<tree::PermissionTreeService>(*storage_svc, *crypto_svc);
        root_kp = crypto_svc->ed25519_keygen();
        root_key = "ed25519:" + crypto::to_base64(root_kp.public_key);
    }

    void TearDown() override {
        tree_svc.reset();
        storage_svc->stop();
        crypto_svc->stop();
        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    [[nodiscard]] fs::path tree_dir() const { return dir / "data" / "tree"; }

    /// The hooks main.cpp installs, without the network services.
    TreeRole::Hooks hooks() {
        return TreeRole::Hooks{
            .enter =
                [this] {
                    storage_svc->ensure_tree_directories();
                    tree_svc->start();
                    return true;
                },
            .leave = [this] { tree_svc->close(); },
            .purge = [this] { (void)storage_svc->purge_tree_files(); },
        };
    }

    /// Every kind of tree file a server can hold: nodes, the delta log, the
    /// transfer pool, the committed op ids, and the tree log.
    void hold_a_full_tree() {
        ASSERT_TRUE(test_support::put_node(*tree_svc, tree::make_root_node(root_key)));
        tree::TreeNode child;
        child.id = "customer-a";
        child.parent_id = "root";
        child.type = tree::NodeType::Customer;
        child.mgmt_pubkey = root_key;
        ASSERT_TRUE(test_support::put_node(*tree_svc, child));
        storage::SignedDelta delta;
        delta.operation = "create_node";
        delta.target_node_id = "customer-a";
        ASSERT_GT(storage_svc->append_delta(delta), 0u);
        write_text(tree_dir() / "retained_deltas" / "generation.json", R"({"generation":"x"})");
        write_text(tree_dir() / "committed-ops.json", R"({"format":1,"ids":[]})");
        write_text(tree_dir() / "log" / "1.json", R"({"height":1})");
        write_text(tree_dir() / "log" / "snapshot-0.json", R"({"height":0})");
        ASSERT_TRUE(fs::exists(tree_dir() / "nodes" / "root.json"));
    }
};

}  // namespace

TEST_F(Tier2TreeFilesTest, AServerThatStartsAsTier2HoldsNoTreeFiles) {
    // An older release left a full tree behind on this host.
    tree_svc->start();
    hold_a_full_tree();
    tree_svc->close();

    TreeRole role{hooks()};
    role.update(MembershipView::NonMember, true);
    EXPECT_FALSE(fs::exists(tree_dir())) << "tree files survived on a Tier 2 server";
    EXPECT_FALSE(tree_svc->get_node("root").has_value());
    EXPECT_FALSE(role.holds_tree());
}

TEST_F(Tier2TreeFilesTest, ATier1ServerThatLeavesDeletesItsTree) {
    TreeRole role{hooks()};
    role.update(MembershipView::Member, true);
    ASSERT_TRUE(role.holds_tree());
    hold_a_full_tree();
    ASSERT_TRUE(tree_svc->get_node("customer-a").has_value());

    // Its last epoch ends: finalized membership no longer names it.
    role.update(MembershipView::NonMember, true);
    EXPECT_FALSE(role.holds_tree());
    EXPECT_FALSE(fs::exists(tree_dir()));
    EXPECT_FALSE(tree_svc->get_node("root").has_value());
    EXPECT_FALSE(tree_svc->get_node("customer-a").has_value());
}

TEST_F(Tier2TreeFilesTest, AClosedTreeWritesNoFile) {
    TreeRole role{hooks()};
    role.update(MembershipView::NonMember, true);
    ASSERT_FALSE(tree_svc->is_open());
    // A request that raced the gate cannot recreate tree files.
    EXPECT_FALSE(test_support::put_node(*tree_svc, tree::make_root_node(root_key)));
    tree::TreeNode child;
    child.id = "late";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;
    EXPECT_FALSE(test_support::put_node(*tree_svc, child));
    EXPECT_FALSE(fs::exists(tree_dir() / "nodes" / "root.json"));
    EXPECT_FALSE(fs::exists(tree_dir() / "nodes" / "late.json"));
}

TEST_F(Tier2TreeFilesTest, DeletionNeverFollowsALinkOutOfTheTree) {
    tree_svc->start();
    hold_a_full_tree();
    tree_svc->close();
    const auto outside = dir / "outside.txt";
    write_text(outside, "keep me");
    std::error_code ec;
    fs::create_symlink(outside, tree_dir() / "nodes" / "link.json", ec);
    if (ec) GTEST_SKIP() << "symbolic links are not available here: " << ec.message();

    EXPECT_TRUE(storage_svc->purge_tree_files());
    EXPECT_FALSE(fs::exists(tree_dir()));
    EXPECT_EQ(read_text(outside), "keep me");
}

TEST_F(Tier2TreeFilesTest, UnknownMembershipKeepsTheFiles) {
    TreeRole role{hooks()};
    role.update(MembershipView::Member, true);
    hold_a_full_tree();
    role.update(MembershipView::Unknown, true);
    EXPECT_FALSE(role.holds_tree());
    EXPECT_FALSE(tree_svc->get_node("root").has_value()) << "an unserved tree stays in memory";
    EXPECT_TRUE(fs::exists(tree_dir() / "nodes" / "root.json"));
    // Membership comes back: the same tree loads again.
    role.update(MembershipView::Member, true);
    EXPECT_TRUE(tree_svc->get_node("customer-a").has_value());
}

TEST_F(Tier2TreeFilesTest, AFormerTier2ServerStartsAnEmptyTreeOnTier1Entry) {
    TreeRole role{hooks()};
    role.update(MembershipView::NonMember, true);
    role.update(MembershipView::Member, true);
    ASSERT_TRUE(role.holds_tree());
    EXPECT_TRUE(tree_svc->nodes_snapshot().empty());
    // The tree writes again once it is held.
    EXPECT_TRUE(test_support::put_node(*tree_svc, tree::make_root_node(root_key)));
    EXPECT_TRUE(fs::exists(tree_dir() / "nodes" / "root.json"));
}

TEST(GossipTreeRoleTest, AServerWithoutTheTreeRetainsNoTreeRecord) {
    const auto dir = unique_dir("gossip");
    fs::create_directories(dir);
    crypto::SodiumCryptoService crypto_svc;
    crypto_svc.start();
    storage::FileStorageService storage_svc{dir};
    storage_svc.start();
    asio::io_context io;
    gossip::GossipService gossip{io, 0, storage_svc, crypto_svc};
    gossip.set_tree_role(false);
    storage::FileStorageService::RetainedDelta rec;
    rec.operation = "create_node";
    rec.target_node_id = "x";
    rec.record_hash = std::string(64, 'a');
    EXPECT_FALSE(gossip.retain_local_delta(rec));
    EXPECT_FALSE(gossip.tree_sync_status().value("holds_tree", true));
    storage_svc.stop();
    crypto_svc.stop();
    std::error_code ec;
    fs::remove_all(dir, ec);
}

// ===========================================================================
// Tree routes on a server that does not hold the tree
// ===========================================================================

TEST(TreeRouteGateTest, TreeRoutesMatchWholeSegments) {
    EXPECT_TRUE(api::is_tree_route("/api/tree"));
    EXPECT_TRUE(api::is_tree_route("/api/tree/node/root"));
    EXPECT_TRUE(api::is_tree_route("/api/auth"));
    EXPECT_TRUE(api::is_tree_route("/api/auth/challenge"));
    EXPECT_FALSE(api::is_tree_route("/api/treehouse"));
    EXPECT_FALSE(api::is_tree_route("/api/authority"));
    EXPECT_FALSE(api::is_tree_route("/api/health"));
    EXPECT_FALSE(api::is_tree_route("/api/tier1/proof"));
    EXPECT_FALSE(api::is_tree_route("/api/relay/list"));
    EXPECT_FALSE(api::is_tree_route("/api/credentials/request"));
    // A loose spelling of a tree route does not slip past.
    EXPECT_TRUE(api::is_tree_route("/api//tree/node/root"));
    EXPECT_TRUE(api::is_tree_route("/api/x/../tree/node/root"));
}

namespace {

/// Every handler that main.cpp registers, over real services, behind the same
/// pre-routing gate main.cpp installs.
class TreeRouteHttpTest : public ::testing::Test {
protected:
    fs::path dir;
    asio::io_context io;
    core::ServerConfig config;
    std::unique_ptr<crypto::SodiumCryptoService> crypto_svc;
    std::unique_ptr<storage::FileStorageService> storage_svc;
    std::unique_ptr<crypto::KeyWrappingService> key_wrapping;
    std::unique_ptr<tree::PermissionTreeService> tree_svc;
    std::unique_ptr<auth::AuthService> auth_svc;
    std::unique_ptr<ipam::IPAMService> ipam_svc;
    std::unique_ptr<network::HttpServer> http_object;
    std::unique_ptr<relay::RelayService> relay_svc;
    std::unique_ptr<relay::RelayDiscoveryService> relay_discovery;
    std::unique_ptr<gossip::GossipService> gossip_svc;
    std::unique_ptr<routing::RoutingCoordinationService> routing_svc;
    std::unique_ptr<core::BinaryAttestationService> attestation;
    std::unique_ptr<core::ServerAdmissionService> admission;
    std::unique_ptr<network::DdnsService> ddns;
    std::unique_ptr<acme::AcmeService> acme_svc;
    std::unique_ptr<api::ApiContext> ctx;

    std::unique_ptr<api::PublicApiHandler> public_api;
    std::unique_ptr<api::AuthApiHandler> auth_api;
    std::unique_ptr<api::TreeApiHandler> tree_api;
    std::unique_ptr<api::RelayApiHandler> relay_api;
    std::unique_ptr<api::CertApiHandler> cert_api;
    std::unique_ptr<api::AdminApiHandler> admin_api;
    std::unique_ptr<api::MeshApiHandler> mesh_api;
    std::unique_ptr<api::RoutingApiHandler> routing_api;
    std::unique_ptr<api::OnboardApiHandler> onboard_api;
    std::unique_ptr<api::AccountDataApiHandler> account_api;
    std::unique_ptr<api::Tier1ApiHandler> tier1_api;

    httplib::Server server;
    std::thread server_thread;
    int port = 0;
    std::atomic<bool> holds_tree{false};
    crypto::Ed25519Keypair identity_kp{};
    std::function<std::vector<uint8_t>(uint64_t, std::size_t)> chain_pages;
    uint64_t latest_epoch = 0;  // the authority route's latest_epoch hint
    std::function<std::optional<api::Tier1Identity>()> identity;

    void SetUp() override {
        dir = unique_dir("http");
        fs::create_directories(dir);
        crypto_svc = std::make_unique<crypto::SodiumCryptoService>();
        crypto_svc->start();
        storage_svc = std::make_unique<storage::FileStorageService>(dir);
        storage_svc->start();
        key_wrapping = std::make_unique<crypto::KeyWrappingService>(*crypto_svc, *storage_svc);
        key_wrapping->start();
        tree_svc = std::make_unique<tree::PermissionTreeService>(*storage_svc, *crypto_svc);
        tree_svc->close();
        std::array<uint8_t, 32> secret{};
        crypto_svc->random_bytes(std::span<uint8_t>(secret));
        auth_svc = std::make_unique<auth::AuthService>(*storage_svc, *crypto_svc, "test.local",
                                                       crypto::to_hex(secret));
        auth_svc->start();
        ipam_svc = std::make_unique<ipam::IPAMService>(*storage_svc);
        ipam_svc->start();
        http_object = std::make_unique<network::HttpServer>(0);
        relay_svc = std::make_unique<relay::RelayService>(io, 0, *crypto_svc);
        relay_discovery = std::make_unique<relay::RelayDiscoveryService>(*storage_svc);
        gossip_svc = std::make_unique<gossip::GossipService>(io, 0, *storage_svc, *crypto_svc);
        identity_kp = crypto_svc->ed25519_keygen();
        gossip_svc->set_identity(identity_kp);
        routing_svc = std::make_unique<routing::RoutingCoordinationService>(*crypto_svc,
                                                                            *gossip_svc);
        attestation = std::make_unique<core::BinaryAttestationService>(*crypto_svc, *storage_svc);
        admission = std::make_unique<core::ServerAdmissionService>(config, *crypto_svc,
                                                                   *key_wrapping, *storage_svc,
                                                                   *gossip_svc);
        ddns = std::make_unique<network::DdnsService>(io, *crypto_svc, *storage_svc, *attestation,
                                                      *gossip_svc);
        acme_svc = std::make_unique<acme::AcmeService>(*storage_svc);
        ctx.reset(new api::ApiContext{
            .config = config,
            .auth = *auth_svc,
            .tree = *tree_svc,
            .ipam = *ipam_svc,
            .gossip = *gossip_svc,
            .crypto = *crypto_svc,
            .key_wrapping = *key_wrapping,
            .storage = *storage_svc,
            .acme = *acme_svc,
            .http_server = *http_object,
            .ddns = *ddns,
            .relay = *relay_svc,
            .relay_discovery = *relay_discovery,
            .routing = *routing_svc,
            .attestation = *attestation,
            .admission = *admission,
            .server_fqdn = "srv.test.local",
            .server_seip_fqdn = "t1.test.local",
            .authority_chain_page = [this](uint64_t have, std::size_t max_links) {
                return chain_pages ? chain_pages(have, max_links) : std::vector<uint8_t>{};
            },
            .authority_latest_epoch = [this] { return latest_epoch; },
            .tier1_identity = [this] {
                return identity ? identity() : std::optional<api::Tier1Identity>{};
            },
        });
        public_api = std::make_unique<api::PublicApiHandler>(*ctx);
        auth_api = std::make_unique<api::AuthApiHandler>(*ctx);
        tree_api = std::make_unique<api::TreeApiHandler>(*ctx);
        relay_api = std::make_unique<api::RelayApiHandler>(*ctx);
        cert_api = std::make_unique<api::CertApiHandler>(*ctx);
        admin_api = std::make_unique<api::AdminApiHandler>(*ctx);
        mesh_api = std::make_unique<api::MeshApiHandler>(*ctx);
        routing_api = std::make_unique<api::RoutingApiHandler>(*ctx);
        onboard_api = std::make_unique<api::OnboardApiHandler>(*ctx);
        account_api = std::make_unique<api::AccountDataApiHandler>(*ctx);
        tier1_api = std::make_unique<api::Tier1ApiHandler>(*ctx);

        const std::function<bool()> gate_source = [this] { return holds_tree.load(); };
        server.set_pre_routing_handler(
            [gate_source](const httplib::Request& req, httplib::Response& res) {
                return api::gate_tree_route(req, res, gate_source)
                           ? httplib::Server::HandlerResponse::Handled
                           : httplib::Server::HandlerResponse::Unhandled;
            });
        // One server stands in for both listeners, as on a host without a
        // tunnel address.
        public_api->register_routes(server, server);
        auth_api->register_routes(server, server);
        tree_api->register_routes(server, server);
        relay_api->register_routes(server, server);
        cert_api->register_routes(server, server);
        admin_api->register_routes(server, server);
        mesh_api->register_routes(server, server);
        routing_api->register_routes(server, server);
        onboard_api->register_routes(server, server);
        account_api->register_routes(server, server);
        tier1_api->register_routes(server, server);
        port = server.bind_to_any_port("127.0.0.1");
        ASSERT_GT(port, 0);
        server_thread = std::thread([this] { server.listen_after_bind(); });
        server.wait_until_ready();
    }

    void TearDown() override {
        server.stop();
        if (server_thread.joinable()) server_thread.join();
        account_api.reset();
        ipam_svc->stop();
        auth_svc->stop();
        key_wrapping->stop();
        storage_svc->stop();
        crypto_svc->stop();
        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    httplib::Result send(const std::string& method, const std::string& path) {
        httplib::Client client("127.0.0.1", port);
        client.set_connection_timeout(5);
        // A session header, so a route that checks auth first still reaches
        // the gate decision only through pre-routing.
        httplib::Headers headers{{"Authorization", "Bearer not-a-session"}};
        if (method == "GET") return client.Get(path, headers);
        return client.Post(path, headers, "{}", "application/json");
    }
};

/// Every tree route main.cpp mounts, with a concrete path for each pattern.
const std::vector<std::pair<std::string, std::string>> kTreeRoutes = {
    {"POST", "/api/join"},
    {"POST", "/api/auth"},
    {"POST", "/api/auth/register"},
    {"POST", "/api/auth/challenge"},
    {"POST", "/api/link/token"},
    {"POST", "/api/link/accept"},
    {"GET", "/api/tree/memberships"},
    {"POST", "/api/tree/node/move/node-1"},
    {"GET", "/api/tree/node/root"},
    {"POST", "/api/tree/delta"},
    {"GET", "/api/tree/children/root"},
    {"POST", "/api/tree/node"},
    {"POST", "/api/tree/node/update/root"},
    {"POST", "/api/tree/node/assignments/root"},
    {"POST", "/api/tree/node/delete/root"},
    {"GET", "/api/tree/op/" + std::string(64, 'a')},
    {"GET", "/api/tree/sync"},
    {"POST", "/api/ipam/allocate"},
    {"GET", "/api/mesh/peers/node-1"},
    {"POST", "/api/mesh/heartbeat"},
    {"GET", "/api/mesh/status/node-1"},
    {"GET", "/api/routing/profile"},
    {"POST", "/api/routing/request"},
    {"POST", "/api/routing/endpoint/register"},
    {"POST", "/api/routing/endpoint/ready"},
    {"POST", "/api/routing/connect"},
    {"GET", "/api/routing/session/abcd"},
    {"POST", "/api/routing/internal/broker"},
    {"POST", "/api/chats"},
    {"GET", "/api/chats"},
    {"GET", "/api/chats/chat-1"},
    {"POST", "/api/chats/chat-1/delete"},
    {"POST", "/api/chats/chat-1"},
    {"GET", "/api/account/keys/envelope"},
    {"POST", "/api/account/keys/envelope"},
    {"GET", "/api/account/keys/pending"},
    {"POST", "/api/account/delete/challenge"},
    {"POST", "/api/account/delete"},
    {"GET", "/api/certs/host.example"},
    {"POST", "/api/certs/issue"},
    {"POST", "/api/relay/register"},
    {"GET", "/api/onboard/pending"},
    {"POST", "/api/onboard/approve/ab12"},
    {"POST", "/api/onboard/deny/ab12"},
    {"POST", "/api/onboard/token"},
    {"GET", "/api/storage/status"},
    {"POST", "/api/storage/rotate-data-key"},
    {"POST", "/api/credentials/unrevoke"},
};

}  // namespace

TEST_F(TreeRouteHttpTest, ATier2ServerRefusesEveryTreeRouteWithNoRedirectAndNoData) {
    holds_tree = false;
    for (const auto& [method, path] : kTreeRoutes) {
        SCOPED_TRACE(method + " " + path);
        auto res = send(method, path);
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, api::kTreeRouteRefusedStatus);
        EXPECT_FALSE(res->has_header("Location"));
        const auto body = json::parse(res->body, nullptr, false);
        ASSERT_TRUE(body.is_object());
        EXPECT_EQ(body.size(), 1u) << "the refusal carries data: " << res->body;
        EXPECT_EQ(body.value("error", ""), std::string(api::kTreeRouteRefusedError));
    }
}

TEST_F(TreeRouteHttpTest, ATier1ServerReachesTheHandlers) {
    holds_tree = true;
    for (const auto& [method, path] : kTreeRoutes) {
        SCOPED_TRACE(method + " " + path);
        auto res = send(method, path);
        ASSERT_TRUE(res);
        EXPECT_NE(res->status, api::kTreeRouteRefusedStatus);
    }
}

TEST_F(TreeRouteHttpTest, ProxyAndDiscoveryRoutesStayOpenOnTier2) {
    holds_tree = false;
    auto health = send("GET", "/api/health");
    ASSERT_TRUE(health);
    EXPECT_EQ(health->status, 200);
    auto servers = send("GET", "/api/servers");
    ASSERT_TRUE(servers);
    EXPECT_EQ(servers->status, 200);
    // A private route that needs no tree reaches its own session check.
    auto relays = send("GET", "/api/relay/list");
    ASSERT_TRUE(relays);
    EXPECT_NE(relays->status, api::kTreeRouteRefusedStatus);
}

TEST_F(TreeRouteHttpTest, OnlyACurrentMemberProvesItsEndpoint) {
    const std::string nonce_hex(64, 'b');
    auto refused = send("GET", "/api/tier1/proof?nonce=" + nonce_hex);
    ASSERT_TRUE(refused);
    EXPECT_EQ(refused->status, 421);
    EXPECT_FALSE(json::parse(refused->body).contains("signature"));

    auto bad = send("GET", "/api/tier1/proof?nonce=xyz");
    ASSERT_TRUE(bad);
    EXPECT_EQ(bad->status, 400);

    // A member: the proof verifies for this server's name and port.
    auto chain = tier1_chain_test::Chain::make(
        {{identity_kp, tier1_chain_test::new_identity(), tier1_chain_test::new_identity(),
          tier1_chain_test::new_identity()}});
    identity = [&chain]() -> std::optional<api::Tier1Identity> {
        api::Tier1Identity id;
        std::copy(chain.network.begin(), chain.network.end(), id.network_id.begin());
        id.epoch = 1;
        return id;
    };
    auto res = send("GET", "/api/tier1/proof?nonce=" + nonce_hex);
    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200) << res->body;
    const auto doc = json::parse(res->body);
    security::Tier1EndpointProof proof;
    const auto node = crypto::from_base64(doc["node_id"].get<std::string>());
    const auto signature = crypto::from_base64(doc["signature"].get<std::string>());
    ASSERT_EQ(node.size(), 32u);
    ASSERT_EQ(signature.size(), 64u);
    std::copy(node.begin(), node.end(), proof.node.bytes.begin());
    std::copy(signature.begin(), signature.end(), proof.signature.begin());
    proof.epoch = security::EpochId{doc["epoch"].get<uint64_t>()};
    proof.host = doc["host"].get<std::string>();
    proof.port = doc["port"].get<uint16_t>();
    EXPECT_EQ(proof.host, "t1.test.local");
    const auto nonce = crypto::from_hex(nonce_hex);
    EXPECT_EQ(security::check_tier1_endpoint_proof(chain.latest(), proof, "t1.test.local",
                                                   config.http_port, nonce),
              security::EndpointProofCheck::Valid);
}

TEST_F(TreeRouteHttpTest, AnyServerServesTheAuthorityChainAsCandidateData) {
    auto chain = tier1_chain_test::Chain::make(
        {{tier1_chain_test::new_identity(), tier1_chain_test::new_identity(),
          tier1_chain_test::new_identity(), tier1_chain_test::new_identity()}});
    chain_pages = [&chain](uint64_t have, std::size_t) {
        const auto page = chain.page_after(have);
        return page ? security::encode_authority_chain_page(*page) : std::vector<uint8_t>{};
    };
    holds_tree = false;  // a Tier 2 server serves it too
    auto res = send("GET", "/api/tier1/authority?have_epoch=0");
    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200);
    const auto doc = json::parse(res->body);
    const auto bytes = crypto::from_base64(doc["page"].get<std::string>());
    const auto page = security::decode_authority_chain_page(bytes);
    ASSERT_TRUE(page.has_value());
    security::AuthorityChainWalker walker(chain.genesis.public_key);
    EXPECT_EQ(walker.apply(*page), security::ChainPageResult::Advanced);

    // Nothing after the latest epoch: the 404 names that epoch, so a client
    // that holds a longer chain of another Epoch 1 under the same key can
    // tell a short store from a network founded again.
    latest_epoch = 1;
    auto none = send("GET", "/api/tier1/authority?have_epoch=1");
    ASSERT_TRUE(none);
    EXPECT_EQ(none->status, 404);
    EXPECT_EQ(json::parse(none->body)["latest_epoch"].get<uint64_t>(), 1u);
    latest_epoch = 0;
    auto unhinted = send("GET", "/api/tier1/authority?have_epoch=1");
    ASSERT_TRUE(unhinted);
    EXPECT_EQ(unhinted->status, 404);
    EXPECT_FALSE(json::parse(unhinted->body).contains("latest_epoch"));
    auto bad = send("GET", "/api/tier1/authority?have_epoch=-1");
    ASSERT_TRUE(bad);
    EXPECT_EQ(bad->status, 400);
}

// A client that asks gets pages of up to kMaxHttpChainLinks links; one that
// does not ask gets kMaxHandoffChainLinks, the size every SDK decodes.
TEST_F(TreeRouteHttpTest, TheAuthorityRouteServesLargerPagesOnlyWhenAsked) {
    // Each handoff introduces a valid Tier 1 set (five members) with fresh keys.
    std::vector<std::vector<crypto::Ed25519Keypair>> rosters;
    for (int i = 0; i < 10; ++i) {
        rosters.push_back({tier1_chain_test::new_identity(), tier1_chain_test::new_identity(),
                           tier1_chain_test::new_identity(), tier1_chain_test::new_identity(),
                           tier1_chain_test::new_identity()});
    }
    auto chain = tier1_chain_test::Chain::make(rosters);
    std::size_t asked = 0;
    chain_pages = [&chain, &asked](uint64_t have, std::size_t max_links) {
        asked = max_links;
        const auto page = chain.page_after(have, chain.epochs.size(), max_links);
        return page ? security::encode_authority_chain_page(*page, max_links)
                    : std::vector<uint8_t>{};
    };
    const auto links_in = [](const httplib::Result& res) -> std::size_t {
        const auto bytes = crypto::from_base64(json::parse(res->body)["page"].get<std::string>());
        const auto page = security::decode_authority_chain_page(
            bytes, security::constants::kMaxHttpChainLinks,
            security::constants::kMaxHttpChainPageBytes);
        return page ? page->links.size() : 0;
    };

    auto plain = send("GET", "/api/tier1/authority?have_epoch=0");
    ASSERT_TRUE(plain);
    ASSERT_EQ(plain->status, 200);
    EXPECT_EQ(asked, security::constants::kMaxHandoffChainLinks);
    EXPECT_EQ(links_in(plain), security::constants::kMaxHandoffChainLinks);

    auto large = send("GET", "/api/tier1/authority?have_epoch=0&max_links=32");
    ASSERT_TRUE(large);
    ASSERT_EQ(large->status, 200);
    EXPECT_EQ(asked, 32u);
    EXPECT_EQ(links_in(large), 9u) << "all nine handoffs of the ten epochs in one page";

    auto clamped = send("GET", "/api/tier1/authority?have_epoch=0&max_links=100000");
    ASSERT_TRUE(clamped);
    EXPECT_EQ(clamped->status, 200);
    EXPECT_EQ(asked, security::constants::kMaxHttpChainLinks);

    for (const auto* bad : {"0", "-3", "x"}) {
        auto res = send("GET", std::string("/api/tier1/authority?have_epoch=0&max_links=") + bad);
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 400) << bad;
    }
}

// The security wire's bounds stay the default: a page with more links than
// kMaxHandoffChainLinks neither encodes nor decodes without the HTTP bounds.
TEST(AuthorityChainCodecBounds, LargerPagesNeedTheHttpBounds) {
    // Each handoff introduces a valid Tier 1 set (five members) with fresh keys.
    std::vector<std::vector<crypto::Ed25519Keypair>> rosters;
    for (int i = 0; i < 8; ++i) {
        rosters.push_back({tier1_chain_test::new_identity(), tier1_chain_test::new_identity(),
                           tier1_chain_test::new_identity(), tier1_chain_test::new_identity(),
                           tier1_chain_test::new_identity()});
    }
    const auto chain = tier1_chain_test::Chain::make(rosters);
    const auto page = chain.page_after(0, chain.epochs.size(), 32);
    ASSERT_TRUE(page.has_value());
    ASSERT_EQ(page->links.size(), 7u);

    EXPECT_TRUE(security::encode_authority_chain_page(*page).empty());
    const auto bytes = security::encode_authority_chain_page(
        *page, security::constants::kMaxHttpChainLinks);
    ASSERT_FALSE(bytes.empty());
    EXPECT_FALSE(security::decode_authority_chain_page(bytes).has_value());
    const auto decoded = security::decode_authority_chain_page(
        bytes, security::constants::kMaxHttpChainLinks,
        security::constants::kMaxHttpChainPageBytes);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->links.size(), 7u);
    EXPECT_FALSE(security::decode_authority_chain_page(
                     bytes, 6, security::constants::kMaxHttpChainPageBytes)
                     .has_value());
}
