#include <LemonadeNexus/Network/DnsService.hpp>
#include <LemonadeNexus/Network/IDnsProvider.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>

#include <filesystem>

using namespace nexus;
namespace fs = std::filesystem;

// ===========================================================================
// Unit tests for DnsService helper functions (no network needed)
// ===========================================================================

TEST(DnsHelpers, StripCidrWithPrefix) {
    EXPECT_EQ(network::DnsService::strip_cidr("10.64.0.1/32"), "10.64.0.1");
    EXPECT_EQ(network::DnsService::strip_cidr("10.128.0.0/24"), "10.128.0.0");
}

TEST(DnsHelpers, StripCidrWithoutPrefix) {
    EXPECT_EQ(network::DnsService::strip_cidr("192.168.1.1"), "192.168.1.1");
    EXPECT_EQ(network::DnsService::strip_cidr("10.0.0.1"), "10.0.0.1");
}

TEST(DnsHelpers, StripCidrEmpty) {
    EXPECT_EQ(network::DnsService::strip_cidr(""), "");
}

TEST(DnsHelpers, StripCidrSlashOnly) {
    EXPECT_EQ(network::DnsService::strip_cidr("/32"), "");
}

// ---------------------------------------------------------------------------
// Type qualifier mapping
// ---------------------------------------------------------------------------

TEST(DnsHelpers, TypeQualifierEndpoint) {
    auto result = network::DnsService::type_qualifier_to_node_type("ep");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, tree::NodeType::Endpoint);

    result = network::DnsService::type_qualifier_to_node_type("endpoint");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, tree::NodeType::Endpoint);
}

TEST(DnsHelpers, TypeQualifierServer) {
    auto result = network::DnsService::type_qualifier_to_node_type("srv");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, tree::NodeType::Root);

    result = network::DnsService::type_qualifier_to_node_type("server");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, tree::NodeType::Root);
}

TEST(DnsHelpers, TypeQualifierRelay) {
    auto result = network::DnsService::type_qualifier_to_node_type("relay");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, tree::NodeType::Relay);
}

TEST(DnsHelpers, TypeQualifierCustomer) {
    auto result = network::DnsService::type_qualifier_to_node_type("cust");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, tree::NodeType::Customer);

    result = network::DnsService::type_qualifier_to_node_type("customer");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, tree::NodeType::Customer);
}

TEST(DnsHelpers, TypeQualifierClientApi) {
    auto result = network::DnsService::type_qualifier_to_node_type("capi");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, tree::NodeType::Endpoint);

    result = network::DnsService::type_qualifier_to_node_type("client");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, tree::NodeType::Endpoint);
}

TEST(DnsHelpers, TypeQualifierUnknown) {
    EXPECT_FALSE(network::DnsService::type_qualifier_to_node_type("foo").has_value());
    EXPECT_FALSE(network::DnsService::type_qualifier_to_node_type("").has_value());
    EXPECT_FALSE(network::DnsService::type_qualifier_to_node_type("dns").has_value());
}

// ===========================================================================
// DnsService resolve tests (need tree with nodes)
// ===========================================================================

class DnsResolveTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<crypto::SodiumCryptoService> crypto_svc;
    std::unique_ptr<storage::FileStorageService> storage_svc;
    std::unique_ptr<tree::PermissionTreeService> tree_svc;
    std::unique_ptr<asio::io_context> io;
    std::unique_ptr<network::DnsService> dns_svc;

    crypto::Ed25519Keypair root_keypair;
    std::string root_pubkey_str;

    void SetUp() override {
        temp_dir = fs::temp_directory_path() /
            ("nexus_test_dns_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()));
        fs::create_directories(temp_dir);

        crypto_svc = std::make_unique<crypto::SodiumCryptoService>();
        crypto_svc->start();

        storage_svc = std::make_unique<storage::FileStorageService>(temp_dir);
        storage_svc->start();

        tree_svc = std::make_unique<tree::PermissionTreeService>(*storage_svc, *crypto_svc);

        root_keypair = crypto_svc->ed25519_keygen();
        root_pubkey_str = "ed25519:" + crypto::to_base64(root_keypair.public_key);

        bootstrap_root_node();
        add_endpoint("ep1", "my-laptop", "10.64.0.2/32");
        add_endpoint("ep2", "work-pc", "10.64.0.3/32");
        add_relay("relay1", "us-east-relay", "10.64.1.1/32", "us-ny");
        add_relay("relay2", "us-west-relay", "10.64.1.2/32", "us-ca");
        add_relay("relay3", "eu-relay", "10.64.1.3/32", "eu-de");

        tree_svc->start();

        io = std::make_unique<asio::io_context>();
        // Use port 0 to let OS assign an available port
        dns_svc = std::make_unique<network::DnsService>(*io, 0, *tree_svc, "lemonade-nexus.io");
    }

    void TearDown() override {
        dns_svc.reset();
        io.reset();
        tree_svc->stop();
        storage_svc->stop();
        crypto_svc->stop();
        fs::remove_all(temp_dir);
    }

    void bootstrap_root_node() {
        tree::TreeNode root;
        root.id = "root";
        root.parent_id = "";
        root.type = tree::NodeType::Root;
        root.hostname = "central";
        root.tunnel_ip = "10.64.0.1/32";
        root.mgmt_pubkey = root_pubkey_str;
        root.assignments = {{root_pubkey_str, {"admin"}}};

        auto canonical = tree::canonical_node_json(root);
        auto msg = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
        auto sig = crypto_svc->ed25519_sign(root_keypair.private_key, msg);
        root.signature = crypto::to_base64(sig);

        storage::SignedEnvelope env;
        env.version = 1;
        env.type = "tree_node";
        env.data = nlohmann::json(root).dump();
        env.signer_pubkey = root_pubkey_str;
        env.signature = root.signature;
        (void)storage_svc->write_node("root", env);
    }

    void add_endpoint(const std::string& id, const std::string& hostname,
                      const std::string& tunnel_ip) {
        tree::TreeNode node;
        node.id = id;
        node.parent_id = "root";
        node.type = tree::NodeType::Endpoint;
        node.hostname = hostname;
        node.tunnel_ip = tunnel_ip;
        node.mgmt_pubkey = root_pubkey_str;

        auto canonical = tree::canonical_node_json(node);
        auto msg = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
        auto sig = crypto_svc->ed25519_sign(root_keypair.private_key, msg);
        node.signature = crypto::to_base64(sig);

        storage::SignedEnvelope env;
        env.version = 1;
        env.type = "tree_node";
        env.data = nlohmann::json(node).dump();
        env.signer_pubkey = root_pubkey_str;
        env.signature = node.signature;
        (void)storage_svc->write_node(id, env);
    }

    void add_relay(const std::string& id, const std::string& hostname,
                   const std::string& tunnel_ip,
                   const std::string& region = "us-ca") {
        tree::TreeNode node;
        node.id = id;
        node.parent_id = "root";
        node.type = tree::NodeType::Relay;
        node.hostname = hostname;
        node.tunnel_ip = tunnel_ip;
        node.mgmt_pubkey = root_pubkey_str;
        node.region = region;

        auto canonical = tree::canonical_node_json(node);
        auto msg = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
        auto sig = crypto_svc->ed25519_sign(root_keypair.private_key, msg);
        node.signature = crypto::to_base64(sig);

        storage::SignedEnvelope env;
        env.version = 1;
        env.type = "tree_node";
        env.data = nlohmann::json(node).dump();
        env.signer_pubkey = root_pubkey_str;
        env.signature = node.signature;
        (void)storage_svc->write_node(id, env);
    }
};

// ---------------------------------------------------------------------------
// Resolve with type qualifier
// ---------------------------------------------------------------------------

TEST_F(DnsResolveTest, ResolveEndpointWithTypeQualifier) {
    auto result = dns_svc->resolve("my-laptop.ep.lemonade-nexus.io");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.0.2");
    EXPECT_EQ(result->ttl, 60u);
}

TEST_F(DnsResolveTest, ResolveEndpointWithLongQualifier) {
    auto result = dns_svc->resolve("my-laptop.endpoint.lemonade-nexus.io");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.0.2");
}

TEST_F(DnsResolveTest, ResolveServerWithTypeQualifier) {
    auto result = dns_svc->resolve("central.srv.lemonade-nexus.io");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.0.1");
}

TEST_F(DnsResolveTest, ResolveRelayWithTypeQualifier) {
    auto result = dns_svc->resolve("us-east-relay.relay.lemonade-nexus.io");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.1.1");
}

// ---------------------------------------------------------------------------
// Resolve without type qualifier (searches all types)
// ---------------------------------------------------------------------------

TEST_F(DnsResolveTest, ResolveWithoutQualifierFindsEndpoint) {
    auto result = dns_svc->resolve("my-laptop.lemonade-nexus.io");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.0.2");
}

TEST_F(DnsResolveTest, ResolveWithoutQualifierFindsRoot) {
    auto result = dns_svc->resolve("central.lemonade-nexus.io");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.0.1");
}

// ---------------------------------------------------------------------------
// Case insensitivity
// ---------------------------------------------------------------------------

TEST_F(DnsResolveTest, CaseInsensitiveHostname) {
    auto result = dns_svc->resolve("MY-LAPTOP.ep.lemonade-nexus.io");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.0.2");
}

TEST_F(DnsResolveTest, CaseInsensitiveBaseDomain) {
    auto result = dns_svc->resolve("my-laptop.ep.LEMONADE-NEXUS.IO");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.0.2");
}

// ---------------------------------------------------------------------------
// Trailing dot (common in DNS)
// ---------------------------------------------------------------------------

TEST_F(DnsResolveTest, TrailingDotHandled) {
    auto result = dns_svc->resolve("my-laptop.ep.lemonade-nexus.io.");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.0.2");
}

// ---------------------------------------------------------------------------
// NXDOMAIN cases
// ---------------------------------------------------------------------------

TEST_F(DnsResolveTest, NonexistentHostReturnsNullopt) {
    auto result = dns_svc->resolve("does-not-exist.ep.lemonade-nexus.io");
    EXPECT_FALSE(result.has_value());
}

TEST_F(DnsResolveTest, WrongZoneReturnsNullopt) {
    auto result = dns_svc->resolve("my-laptop.ep.other-domain.io");
    EXPECT_FALSE(result.has_value());
}

TEST_F(DnsResolveTest, EmptyQueryReturnsNullopt) {
    auto result = dns_svc->resolve("");
    EXPECT_FALSE(result.has_value());
}

TEST_F(DnsResolveTest, BaseDomainOnlyReturnsNullopt) {
    auto result = dns_svc->resolve("lemonade-nexus.io");
    EXPECT_FALSE(result.has_value());
}

TEST_F(DnsResolveTest, WrongTypeQualifierReturnsNullopt) {
    // my-laptop is an Endpoint, not a Relay
    auto result = dns_svc->resolve("my-laptop.relay.lemonade-nexus.io");
    EXPECT_FALSE(result.has_value());
}

// ---------------------------------------------------------------------------
// DnsRecord struct
// ---------------------------------------------------------------------------

TEST(DnsRecord, DefaultTTL) {
    network::DnsRecord rec;
    EXPECT_EQ(rec.ttl, 60u);
}

// ---------------------------------------------------------------------------
// CRTP concept check
// ---------------------------------------------------------------------------

TEST(DnsConcept, DnsServiceSatisfiesConcept) {
    static_assert(network::DnsProviderType<network::DnsService>,
                  "DnsService must satisfy DnsProviderType concept");
}

// ---------------------------------------------------------------------------
// Service lifecycle
// ---------------------------------------------------------------------------

TEST(DnsServiceLifecycle, ConstructWithPort0) {
    // Verify DnsService can be constructed without binding to a fixed port
    crypto::SodiumCryptoService crypto;
    crypto.start();

    auto temp = fs::temp_directory_path() / "nexus_dns_lifecycle_test";
    fs::create_directories(temp);

    storage::FileStorageService storage{temp};
    storage.start();

    tree::PermissionTreeService tree{storage, crypto};
    tree.start();

    asio::io_context io;
    // Port 0 = OS-assigned ephemeral port
    network::DnsService dns{io, 0, tree, "test.local"};
    dns.start();
    dns.stop();

    tree.stop();
    storage.stop();
    crypto.stop();
    fs::remove_all(temp);
}

TEST(DnsServiceLifecycle, NameReturnsExpected) {
    EXPECT_EQ(network::DnsService::name(), "DnsService");
}

// ===========================================================================
// Relay subdomain resolution tests
// ===========================================================================

TEST_F(DnsResolveTest, RelaySubdomainByHostname) {
    // relay-hostname.relays.lemonade-nexus.io
    auto result = dns_svc->resolve("us-east-relay.relays.lemonade-nexus.io");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.1.1");
}

TEST_F(DnsResolveTest, RelaySubdomainByHostnameAndRegion) {
    // relay-hostname.region.relays.lemonade-nexus.io
    auto result = dns_svc->resolve("us-west-relay.us-ca.relays.lemonade-nexus.io");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.1.2");
}

TEST_F(DnsResolveTest, RelaySubdomainWrongRegionReturnsNullopt) {
    // us-east-relay is in us-ny, not us-ca
    auto result = dns_svc->resolve("us-east-relay.us-ca.relays.lemonade-nexus.io");
    EXPECT_FALSE(result.has_value());
}

TEST_F(DnsResolveTest, RelaySubdomainCorrectRegion) {
    auto result = dns_svc->resolve("us-east-relay.us-ny.relays.lemonade-nexus.io");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.1.1");
}

TEST_F(DnsResolveTest, RelaySubdomainEuropeanRelay) {
    auto result = dns_svc->resolve("eu-relay.eu-de.relays.lemonade-nexus.io");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.1.3");
}

TEST_F(DnsResolveTest, RelaySubdomainNonexistentRelay) {
    auto result = dns_svc->resolve("nonexistent.relays.lemonade-nexus.io");
    EXPECT_FALSE(result.has_value());
}

TEST_F(DnsResolveTest, RelaySubdomainCaseInsensitive) {
    auto result = dns_svc->resolve("US-EAST-RELAY.US-NY.RELAYS.LEMONADE-NEXUS.IO");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.1.1");
}

TEST_F(DnsResolveTest, RelaySubdomainTrailingDot) {
    auto result = dns_svc->resolve("us-west-relay.relays.lemonade-nexus.io.");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.1.2");
}

// ===========================================================================
// Client API (capi) subdomain resolution tests
// ===========================================================================

TEST_F(DnsResolveTest, ResolveClientApiEndpoint) {
    auto result = dns_svc->resolve("my-laptop.capi.lemonade-nexus.io");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.0.2");
}

TEST_F(DnsResolveTest, ResolveClientApiWithClientAlias) {
    auto result = dns_svc->resolve("my-laptop.client.lemonade-nexus.io");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.0.2");
}

TEST_F(DnsResolveTest, ResolveClientApiCaseInsensitive) {
    auto result = dns_svc->resolve("MY-LAPTOP.CAPI.LEMONADE-NEXUS.IO");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->ipv4_address, "10.64.0.2");
}

TEST_F(DnsResolveTest, ResolveClientApiWrongTypeNxdomain) {
    // central is a Root node, not an Endpoint — capi only finds Endpoints
    auto result = dns_svc->resolve("central.capi.lemonade-nexus.io");
    EXPECT_FALSE(result.has_value());
}

// ===========================================================================
// TXT record: _config. subdomain for port configuration
// ===========================================================================

TEST_F(DnsResolveTest, ConfigTxtWithoutPortConfig) {
    // No port config set → should return nullopt
    auto result = dns_svc->resolve_config_txt("my-laptop");
    EXPECT_FALSE(result.has_value());
}

TEST_F(DnsResolveTest, ConfigTxtWithPortConfig) {
    network::DnsService::PortConfig ports;
    ports.http_port   = 9100;
    ports.udp_port    = 9101;
    ports.gossip_port = 9102;
    ports.stun_port   = 3478;
    ports.relay_port  = 9103;
    ports.dns_port    = 5353;
    ports.private_http_port = 9101;
    dns_svc->set_port_config(ports);

    auto result = dns_svc->resolve_config_txt("my-laptop");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "v=sp1 http=9100 udp=9101 gossip=9102 stun=3478 relay=9103 dns=5353 private_http=9101");
}

TEST_F(DnsResolveTest, ConfigTxtWithTypeQualifier) {
    network::DnsService::PortConfig ports;
    dns_svc->set_port_config(ports);

    auto result = dns_svc->resolve_config_txt("my-laptop.ep");
    ASSERT_TRUE(result.has_value());
    // Should resolve since my-laptop is an Endpoint
}

TEST_F(DnsResolveTest, ConfigTxtWrongTypeReturnsNullopt) {
    network::DnsService::PortConfig ports;
    dns_svc->set_port_config(ports);

    // my-laptop is an Endpoint, not a Relay
    auto result = dns_svc->resolve_config_txt("my-laptop.relay");
    EXPECT_FALSE(result.has_value());
}

TEST_F(DnsResolveTest, ConfigTxtNonexistentHostReturnsNullopt) {
    network::DnsService::PortConfig ports;
    dns_svc->set_port_config(ports);

    auto result = dns_svc->resolve_config_txt("does-not-exist");
    EXPECT_FALSE(result.has_value());
}

TEST_F(DnsResolveTest, ConfigTxtCustomPorts) {
    network::DnsService::PortConfig ports;
    ports.http_port   = 8443;
    ports.udp_port    = 8444;
    ports.gossip_port = 8445;
    ports.stun_port   = 8446;
    ports.relay_port  = 8447;
    ports.dns_port    = 8448;
    ports.private_http_port = 8449;
    dns_svc->set_port_config(ports);

    auto result = dns_svc->resolve_config_txt("my-laptop");
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(*result, "v=sp1 http=8443 udp=8444 gossip=8445 stun=8446 relay=8447 dns=8448 private_http=8449");
}

TEST_F(DnsResolveTest, ConfigTxtCaseInsensitive) {
    network::DnsService::PortConfig ports;
    dns_svc->set_port_config(ports);

    auto result = dns_svc->resolve_config_txt("MY-LAPTOP");
    ASSERT_TRUE(result.has_value());
}

TEST_F(DnsResolveTest, ConfigTxtServerNode) {
    network::DnsService::PortConfig ports;
    dns_svc->set_port_config(ports);

    auto result = dns_svc->resolve_config_txt("central");
    ASSERT_TRUE(result.has_value());
    // central is the root server node — _config. works for all node types
}

// ===========================================================================
// publish_port_config() — dynamic TXT record for gossip-synced discovery
// ===========================================================================

TEST_F(DnsResolveTest, PublishPortConfigCreatesDynamicTxtRecord) {
    network::DnsService::PortConfig ports;
    ports.http_port   = 9100;
    ports.udp_port    = 51940;
    ports.gossip_port = 9102;
    ports.stun_port   = 3478;
    ports.relay_port  = 9103;
    ports.dns_port    = 5353;
    ports.private_http_port = 9101;
    dns_svc->set_port_config(ports);

    // Publish the config — this creates a dynamic TXT record
    dns_svc->publish_port_config("central");

    // The dynamic TXT record should now be discoverable
    // Query via resolve_config_txt (which checks dynamic records first)
    // But we can also verify the SOA serial bumped (set_record increments it)
    EXPECT_GT(dns_svc->soa_serial(), 1u);
}

TEST_F(DnsResolveTest, PublishPortConfigEmptyServerIdIsNoop) {
    network::DnsService::PortConfig ports;
    dns_svc->set_port_config(ports);

    uint32_t serial_before = dns_svc->soa_serial();
    dns_svc->publish_port_config("");  // should be a no-op
    EXPECT_EQ(dns_svc->soa_serial(), serial_before);
}

TEST_F(DnsResolveTest, PublishPortConfigWithoutPortConfigIsNoop) {
    // Don't call set_port_config — publish should be a no-op
    uint32_t serial_before = dns_svc->soa_serial();
    dns_svc->publish_port_config("central");
    EXPECT_EQ(dns_svc->soa_serial(), serial_before);
}
