// Device and group loopback certificates over the real /api/certs/issue route:
//  - the group loopback wildcard "*.<label>.lo.<base>" goes to joined members
//    of the group only, encrypted to the member's own key;
//  - a stored certificate is issued again when less than one third of its
//    lifetime remains, and an expired one is never served;
//  - a device hostname shared with another owner is refused;
//  - the renewal monitor lists due device and group certificates;
//  - the post-delete cleanup removes the stored certificates.
// The ACME provider points at an unreachable local address, so no test sends
// a request to a real certificate authority.

#include <LemonadeNexus/Acme/AcmeService.hpp>
#include <LemonadeNexus/Api/CertApiHandler.hpp>
#include <LemonadeNexus/Api/TreeApiHandler.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/ServerAdmissionService.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Network/DdnsService.hpp>
#include <LemonadeNexus/Network/DnsService.hpp>
#include <LemonadeNexus/Network/HttpServer.hpp>
#include <LemonadeNexus/Relay/RelayDiscoveryService.hpp>
#include <LemonadeNexus/Relay/RelayService.hpp>
#include <LemonadeNexus/Routing/RoutingCoordinationService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include "test_http_ready.hpp"

#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <memory>
#include <span>
#include <string>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

constexpr const char* kBase = "example.test";
constexpr int64_t kDay = 24 * 3600;

struct Pem {
    std::string cert;
    std::string key;
};

/// A self-signed P-256 certificate for `name`, valid from now + `from_s`
/// to now + `to_s`.
Pem make_cert(const std::string& name, int64_t from_s, int64_t to_s) {
    Pem out;
    EVP_PKEY* pkey = EVP_EC_gen("P-256");
    if (!pkey) return out;
    X509* x = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x), 7);
    X509_gmtime_adj(X509_getm_notBefore(x), static_cast<long>(from_s));
    X509_gmtime_adj(X509_getm_notAfter(x), static_cast<long>(to_s));
    X509_set_pubkey(x, pkey);
    X509_NAME* subject = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(name.c_str()), -1, -1, 0);
    X509_set_issuer_name(x, subject);
    const std::string san = "DNS:" + name;
    if (X509_EXTENSION* ext =
            X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, san.c_str())) {
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
    }
    if (X509_sign(x, pkey, EVP_sha256()) != 0) {
        BIO* cb = BIO_new(BIO_s_mem());
        PEM_write_bio_X509(cb, x);
        char* data = nullptr;
        long len = BIO_get_mem_data(cb, &data);
        out.cert.assign(data, static_cast<std::size_t>(len));
        BIO_free(cb);
        BIO* kb = BIO_new(BIO_s_mem());
        PEM_write_bio_PrivateKey(kb, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        len = BIO_get_mem_data(kb, &data);
        out.key.assign(data, static_cast<std::size_t>(len));
        BIO_free(kb);
    }
    X509_free(x);
    EVP_PKEY_free(pkey);
    return out;
}

void write_file(const fs::path& path, const std::string& text) {
    fs::create_directories(path.parent_path());
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
}

std::string pubkey_of(const crypto::Ed25519Keypair& kp) {
    return "ed25519:" + crypto::to_base64(
        std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));
}

acme::AcmeProviderConfig unreachable_provider() {
    // Loopback port 443: nothing listens there in the test environment, so
    // every ACME call fails fast and no CA ever sees a request.
    return {
        .name          = "unreachable",
        .host          = "127.0.0.1",
        .directory_url = "https://127.0.0.1/directory",
        .staging       = true,
    };
}

} // namespace

class DeviceCertTest : public ::testing::Test {
protected:
    uint16_t port_{0};
    fs::path temp_dir;
    asio::io_context io;

    std::unique_ptr<crypto::SodiumCryptoService> crypto;
    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<crypto::KeyWrappingService> key_wrapping;
    std::unique_ptr<tree::PermissionTreeService> tree;
    std::unique_ptr<auth::AuthService> auth;
    std::unique_ptr<ipam::IPAMService> ipam;
    std::unique_ptr<network::HttpServer> http;
    std::unique_ptr<relay::RelayService> relay;
    std::unique_ptr<relay::RelayDiscoveryService> relay_discovery;
    std::unique_ptr<gossip::GossipService> gossip;
    std::unique_ptr<routing::RoutingCoordinationService> routing;
    std::unique_ptr<core::BinaryAttestationService> attestation;
    std::unique_ptr<core::ServerAdmissionService> admission;
    std::unique_ptr<network::DdnsService> ddns;
    std::unique_ptr<acme::AcmeService> acme;
    std::unique_ptr<api::ApiContext> ctx;
    std::unique_ptr<api::CertApiHandler> cert_handler;
    std::unique_ptr<api::TreeApiHandler> tree_handler;

    core::ServerConfig config;
    crypto::Ed25519Keypair root_kp;
    crypto::Ed25519Keypair alice;   // owns group A and endpoint "alice-laptop"
    crypto::Ed25519Keypair bob;     // linked device in group A
    crypto::Ed25519Keypair carol;   // owns group C
    std::string alice_id, bob_id, carol_id;

    void SetUp() override {
        port_ = static_cast<uint16_t>(30500 + (getpid() % 9000));
        temp_dir = fs::temp_directory_path() / ("nexus_test_device_certs_" + std::to_string(getpid()));
        fs::remove_all(temp_dir);
        fs::create_directories(temp_dir);

        crypto = std::make_unique<crypto::SodiumCryptoService>();
        crypto->start();
        storage = std::make_unique<storage::FileStorageService>(temp_dir);
        storage->start();
        key_wrapping = std::make_unique<crypto::KeyWrappingService>(*crypto, *storage);
        key_wrapping->start();
        config.dns_base_domain = kBase;

        tree = std::make_unique<tree::PermissionTreeService>(*storage, *crypto);
        tree->start();

        std::array<uint8_t, 32> secret{};
        crypto->random_bytes(std::span<uint8_t>(secret));
        auth = std::make_unique<auth::AuthService>(*storage, *crypto, "lemonade-nexus.local",
                                                   crypto::to_hex(std::span<const uint8_t>(secret)));
        auth->start();
        ipam = std::make_unique<ipam::IPAMService>(*storage);
        ipam->start();
        http = std::make_unique<network::HttpServer>(port_, "127.0.0.1");
        root_kp = crypto->ed25519_keygen();
        relay = std::make_unique<relay::RelayService>(io, 0, *crypto, root_kp.public_key);
        relay_discovery = std::make_unique<relay::RelayDiscoveryService>(*storage);
        gossip = std::make_unique<gossip::GossipService>(io, 0, *storage, *crypto);
        routing = std::make_unique<routing::RoutingCoordinationService>(*crypto, *gossip);
        attestation = std::make_unique<core::BinaryAttestationService>(*crypto, *storage);
        admission = std::make_unique<core::ServerAdmissionService>(
            config, *crypto, *key_wrapping, *storage, *gossip);
        ddns = std::make_unique<network::DdnsService>(io, *crypto, *storage, *attestation, *gossip);
        acme = std::make_unique<acme::AcmeService>(*storage, unreachable_provider());

        ctx.reset(new api::ApiContext{
            .config           = config,
            .auth             = *auth,
            .tree             = *tree,
            .ipam             = *ipam,
            .gossip           = *gossip,
            .crypto           = *crypto,
            .key_wrapping     = *key_wrapping,
            .storage          = *storage,
            .acme             = *acme,
            .http_server      = *http,
            .ddns             = *ddns,
            .relay            = *relay,
            .relay_discovery  = *relay_discovery,
            .routing          = *routing,
            .attestation      = *attestation,
            .admission        = *admission,
            .boringtun        = nullptr,
            .dns              = nullptr,
            .server_fqdn      = "test.local",
            .server_seip_fqdn = "",
            .server_private_fqdn = "",
            .server_public_ip = "",
            .tunnel_bind_ip   = "",
        });
        cert_handler = std::make_unique<api::CertApiHandler>(*ctx);
        cert_handler->register_routes(http->server(), http->server());
        tree_handler = std::make_unique<api::TreeApiHandler>(*ctx);
        http->start();
        ASSERT_TRUE(wait_http_ready(port_)) << "HTTP server not accepting on " << port_;

        seed_tree();
    }

    void TearDown() override {
        if (http) http->stop();
        tree_handler.reset();
        cert_handler.reset();
        ctx.reset();
        if (auth) auth->stop();
        if (ipam) ipam->stop();
        if (tree) tree->stop();
        if (key_wrapping) key_wrapping->stop();
        if (storage) storage->stop();
        if (crypto) crypto->stop();
        fs::remove_all(temp_dir);
    }

    /// Ed25519 challenge-response through AuthService; returns {token, user_id}.
    std::pair<std::string, std::string> login(const crypto::Ed25519Keypair& kp) {
        const auto bare = crypto::to_base64(
            std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));
        const auto challenge = auth->issue_ed25519_challenge(bare).value("challenge", std::string{});
        const auto bytes = crypto::from_base64(challenge);
        const auto sig = crypto->ed25519_sign(kp.private_key, std::span<const uint8_t>(bytes));
        const auto result = auth->authenticate(json{
            {"method", "ed25519"},
            {"pubkey", bare},
            {"challenge", challenge},
            {"signature", crypto::to_base64(std::span<const uint8_t>(sig.data(), sig.size()))},
        });
        EXPECT_TRUE(result.authenticated) << result.error_message;
        return {result.session_token, result.user_id};
    }

    void add_node(const std::string& id, const std::string& parent, tree::NodeType type,
                  const std::string& hostname, const crypto::Ed25519Keypair& owner,
                  const std::string& tunnel_ip) {
        tree::TreeNode node;
        node.id          = id;
        node.parent_id   = parent;
        node.type        = type;
        node.hostname    = hostname;
        node.mgmt_pubkey = pubkey_of(owner);
        node.tunnel_ip   = tunnel_ip;
        node.assignments = {{.management_pubkey = pubkey_of(owner),
                             .permissions = {"read", "write", "edit_node"}}};
        ASSERT_TRUE(tree->insert_join_node(node)) << id;
    }

    void seed_tree() {
        tree::TreeNode root;
        root.id          = "root";
        root.type        = tree::NodeType::Root;
        root.hostname    = "root";
        root.mgmt_pubkey = pubkey_of(root_kp);
        root.assignments = {{.management_pubkey = pubkey_of(root_kp), .permissions = {"admin"}}};
        ASSERT_TRUE(tree->bootstrap_root(root));

        alice = crypto->ed25519_keygen();
        bob   = crypto->ed25519_keygen();
        carol = crypto->ed25519_keygen();
        alice_id = login(alice).second;
        bob_id   = login(bob).second;
        carol_id = login(carol).second;

        add_node("customer-" + alice_id, "root", tree::NodeType::Customer, "alice", alice, "");
        add_node(alice_id, "customer-" + alice_id, tree::NodeType::Endpoint, "alice-laptop",
                 alice, "10.64.0.2/32");
        add_node(bob_id, "customer-" + alice_id, tree::NodeType::Endpoint, "bob-desk", bob,
                 "10.64.0.3/32");
        add_node("customer-" + carol_id, "root", tree::NodeType::Customer, "carol", carol, "");
        add_node(carol_id, "customer-" + carol_id, tree::NodeType::Endpoint, "carol-pc", carol,
                 "10.64.0.4/32");
    }

    fs::path cert_dir(const std::string& domain) const {
        return temp_dir / "certs" / acme::AcmeService::certificate_directory_name(domain);
    }

    Pem store_cert(const std::string& domain, int64_t from_s, int64_t to_s) {
        auto pem = make_cert(domain, from_s, to_s);
        write_file(cert_dir(domain) / "fullchain.pem", pem.cert);
        write_file(cert_dir(domain) / "privkey.pem", pem.key);
        return pem;
    }

    httplib::Result issue(const std::string& token, const json& body) {
        httplib::Client cli("127.0.0.1", port_);
        cli.set_read_timeout(60, 0);
        return cli.Post("/api/certs/issue", {{"Authorization", "Bearer " + token}}, body.dump(),
                        "application/json");
    }

    /// Decrypt a bundle the way the SDK does (ln_cert_decrypt).
    std::optional<std::string> decrypt(const json& bundle, const crypto::Ed25519Keypair& kp) {
        const auto eph_bytes = crypto::from_base64(bundle.value("ephemeral_pubkey", ""));
        if (eph_bytes.size() != 32) return std::nullopt;
        crypto::X25519PublicKey eph{};
        std::copy(eph_bytes.begin(), eph_bytes.end(), eph.begin());
        const auto x_sk = crypto::SodiumCryptoService::ed25519_sk_to_x25519(kp.private_key);
        const auto shared = crypto->x25519_dh(x_sk, eph);
        const std::string info = "lemonade-nexus-cert-issue";
        const auto key_bytes = crypto->hkdf_sha256(
            shared, {}, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(info.data()),
                                                 info.size()), 32);
        crypto::AeadKey key{};
        std::copy(key_bytes.begin(), key_bytes.end(), key.begin());
        crypto::EncryptedBlob blob;
        blob.version    = static_cast<uint8_t>(bundle.value("crypto_version", 0u));
        blob.nonce      = crypto::from_base64(bundle.value("nonce", ""));
        blob.ciphertext = crypto::from_base64(bundle.value("encrypted_privkey", ""));
        const auto domain = bundle.value("domain", "");
        const auto aad = crypto::aead_aad(
            crypto::aead_purpose::kCertBundle,
            {std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()),
             std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(domain.data()),
                                      domain.size())});
        auto plain = crypto->aead_decrypt(key, blob, std::span<const uint8_t>(aad));
        if (!plain) return std::nullopt;
        return std::string(plain->begin(), plain->end());
    }

    std::string group_wildcard(const std::string& group_id) const {
        return network::group_loopback_wildcard(group_id, kBase);
    }
};

// --- Group loopback wildcard: delivery and authorization ---------------------

TEST_F(DeviceCertTest, GroupWildcardGoesToEveryMemberEncryptedToItsOwnKey) {
    const auto wildcard = group_wildcard("customer-" + alice_id);
    ASSERT_TRUE(wildcard.starts_with("*.g"));
    ASSERT_TRUE(wildcard.ends_with(std::string(".lo.") + kBase));
    const auto stored = store_cert(wildcard, -kDay, 89 * kDay);

    for (const auto* member : {&alice, &bob}) {
        const auto [token, uid] = login(*member);
        auto res = issue(token, {{"scope", "group_loopback"}, {"client_pubkey", pubkey_of(*member)}});
        ASSERT_TRUE(res);
        ASSERT_EQ(res->status, 200) << res->body;
        const auto bundle = json::parse(res->body);
        EXPECT_EQ(bundle.value("domain", ""), wildcard);
        EXPECT_EQ(bundle.value("fullchain_pem", ""), stored.cert);
        const auto key = decrypt(bundle, *member);
        ASSERT_TRUE(key.has_value());
        EXPECT_EQ(*key, stored.key);
    }
}

TEST_F(DeviceCertTest, GroupWildcardRefusedToANonMember) {
    store_cert(group_wildcard("customer-" + alice_id), -kDay, 89 * kDay);
    const auto carol_wildcard = group_wildcard("customer-" + carol_id);

    // Carol is a member of her own group only: she gets her group's name,
    // never Alice's. With no stored certificate and an unreachable CA, her
    // own request fails at issuance (502), not at authorization.
    const auto [token, uid] = login(carol);
    auto res = issue(token, {{"scope", "group_loopback"}, {"client_pubkey", pubkey_of(carol)}});
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 502);
    EXPECT_FALSE(fs::exists(cert_dir(carol_wildcard) / "privkey.pem"));

    // An identity with no endpoint is not a member of any group.
    const auto stranger = crypto->ed25519_keygen();
    const auto [s_token, s_uid] = login(stranger);
    res = issue(s_token, {{"scope", "group_loopback"}, {"client_pubkey", pubkey_of(stranger)}});
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 403);
}

TEST_F(DeviceCertTest, GroupWildcardRefusedForAnotherKeyOrADeviceNotJoined) {
    store_cert(group_wildcard("customer-" + alice_id), -kDay, 89 * kDay);
    const auto [token, uid] = login(bob);
    // The bundle may only be encrypted to the caller's own key.
    auto res = issue(token, {{"scope", "group_loopback"}, {"client_pubkey", pubkey_of(carol)}});
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 403);

    // An endpoint without a tunnel address has not joined.
    auto node = tree->get_node(bob_id);
    ASSERT_TRUE(node);
    node->tunnel_ip.clear();
    ASSERT_TRUE(tree->update_node_direct(bob_id, *node));
    res = issue(token, {{"scope", "group_loopback"}, {"client_pubkey", pubkey_of(bob)}});
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 403);

    res = issue(token, {{"scope", "nonsense"}, {"client_pubkey", pubkey_of(bob)}});
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 400);
}

// --- Renewal at the issue route ---------------------------------------------

TEST_F(DeviceCertTest, IssueRouteServesAFreshCertificateWithoutRenewal) {
    const std::string fqdn = std::string("alice-laptop.capi.") + kBase;
    const auto stored = store_cert(fqdn, -kDay, 89 * kDay);
    const auto [token, uid] = login(alice);
    auto res = issue(token, {{"hostname", "alice-laptop"}, {"client_pubkey", pubkey_of(alice)}});
    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200) << res->body;
    EXPECT_EQ(json::parse(res->body).value("fullchain_pem", ""), stored.cert);
}

TEST_F(DeviceCertTest, IssueRouteNeverServesAnExpiredCertificate) {
    const std::string fqdn = std::string("alice-laptop.capi.") + kBase;
    store_cert(fqdn, -90 * kDay, -kDay);
    const auto [token, uid] = login(alice);
    // Due, so the route asks the CA; the CA is unreachable and the stored
    // certificate has expired, so nothing is served.
    auto res = issue(token, {{"hostname", "alice-laptop"}, {"client_pubkey", pubkey_of(alice)}});
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 502);
}

TEST_F(DeviceCertTest, IssueRouteKeepsServingAValidCertificateWhenRenewalFails) {
    const std::string fqdn = std::string("alice-laptop.capi.") + kBase;
    const auto stored = store_cert(fqdn, -80 * kDay, 10 * kDay);  // due: 10 of 90 days left
    const auto [token, uid] = login(alice);
    auto res = issue(token, {{"hostname", "alice-laptop"}, {"client_pubkey", pubkey_of(alice)}});
    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200) << res->body;
    EXPECT_EQ(json::parse(res->body).value("fullchain_pem", ""), stored.cert);
}

TEST_F(DeviceCertTest, DeviceHostnameSharedWithAnotherOwnerIsRefused) {
    store_cert(std::string("alice-laptop.capi.") + kBase, -kDay, 89 * kDay);
    // Carol names a second endpoint like Alice's laptop.
    add_node("carol-2", "customer-" + carol_id, tree::NodeType::Endpoint, "alice-laptop", carol,
             "10.64.0.5/32");
    const auto [token, uid] = login(alice);
    auto res = issue(token, {{"hostname", "alice-laptop"}, {"client_pubkey", pubkey_of(alice)}});
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 409);
}

// --- Renewal monitor --------------------------------------------------------

TEST_F(DeviceCertTest, RenewalMonitorListsOnlyDueCertificatesOfExistingOwners) {
    const auto now = api::epoch_seconds();
    const std::string laptop = std::string("alice-laptop.capi.") + kBase;
    const std::string desk   = std::string("bob-desk.capi.") + kBase;
    const std::string gone   = std::string("deleted-host.capi.") + kBase;
    const auto group_a = group_wildcard("customer-" + alice_id);
    const auto group_c = group_wildcard("customer-" + carol_id);
    store_cert(laptop, -80 * kDay, 10 * kDay);   // due
    store_cert(desk, -kDay, 89 * kDay);          // fresh
    store_cert(gone, -80 * kDay, 10 * kDay);     // due, but no endpoint
    store_cert(group_a, -61 * kDay, 29 * kDay);  // due: 29 of 90 days left
    store_cert(group_c, -59 * kDay, 31 * kDay);  // not due: 31 of 90 days left
    store_cert(std::string("server.seip.") + kBase, -89 * kDay, kDay);  // server's own

    const auto due = api::device_certificates_due(*acme, *tree, kBase, now);
    std::vector<std::string> expected{group_a, laptop};
    std::sort(expected.begin(), expected.end());
    EXPECT_EQ(due, expected);
}

// --- Post-delete cleanup ----------------------------------------------------

TEST_F(DeviceCertTest, DeleteCleanupRemovesTheStoredCertificates) {
    const std::string laptop = std::string("alice-laptop.capi.") + kBase;
    const std::string desk   = std::string("bob-desk.capi.") + kBase;
    const auto group_a = group_wildcard("customer-" + alice_id);
    store_cert(laptop, -kDay, 89 * kDay);
    store_cert(desk, -kDay, 89 * kDay);
    store_cert(group_a, -kDay, 89 * kDay);

    // Bob's device leaves: its device certificate goes, the group's stays.
    auto bob_node = tree->get_node(bob_id);
    ASSERT_TRUE(bob_node);
    ASSERT_TRUE(tree->delete_node_direct(bob_id));
    tree_handler->cleanup_removed_nodes({*bob_node});
    EXPECT_FALSE(fs::exists(cert_dir(desk)));
    EXPECT_TRUE(fs::exists(cert_dir(group_a) / "privkey.pem"));

    // The group goes: its wildcard goes too.
    auto alice_node = tree->get_node(alice_id);
    auto group_node = tree->get_node("customer-" + alice_id);
    ASSERT_TRUE(alice_node && group_node);
    ASSERT_TRUE(tree->delete_node_direct(alice_id));
    ASSERT_TRUE(tree->delete_node_direct("customer-" + alice_id));
    tree_handler->cleanup_removed_nodes({*alice_node, *group_node});
    EXPECT_FALSE(fs::exists(cert_dir(laptop)));
    EXPECT_FALSE(fs::exists(cert_dir(group_a)));
}
