// SDK public transport: one kept-alive connection per server, safe to use from
// several threads at once.
//
// The Flutter client calls the SDK from worker isolates, so requests and
// session-token updates arrive concurrently. The client must not tear its
// shared state, and it must reuse its HTTPS connection instead of paying a TCP
// and TLS handshake on every call.

#include <LemonadeNexusSDK/BoringtunMesh.hpp>
#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>
#include <LemonadeNexusSDK/lemonade_nexus.h>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Network/StunService.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Membership.hpp>
#include <LemonadeNexus/Security/Transport/AuthorityChainCodec.hpp>

#include "support/localhost_cert.hpp"
#include "support/tier1_chain.hpp"

#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {

using test_support::make_localhost_cert;

class SdkTransportTest : public ::testing::Test {
protected:
    fs::path dir;
    std::unique_ptr<httplib::SSLServer> server;
    std::thread server_thread;
    int port = 0;

    std::mutex seen_mutex;
    std::set<int> client_ports;        // one per TCP connection
    std::set<std::string> auth_values;  // every Authorization header received

    void SetUp() override {
        dir = fs::temp_directory_path() /
              ("nexus_sdk_transport_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()) +
               "_" + std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(dir);
        const auto cert = dir / "cert.pem";
        const auto key = dir / "key.pem";
        ASSERT_TRUE(make_localhost_cert(cert, key));
#ifdef _WIN32
        (void)_putenv_s("SSL_CERT_FILE", cert.string().c_str());
#else
        ::setenv("SSL_CERT_FILE", cert.string().c_str(), 1);
#endif
        server = std::make_unique<httplib::SSLServer>(cert.string().c_str(), key.string().c_str());
        ASSERT_TRUE(server->is_valid());
        server->Get("/api/health", [this](const httplib::Request& req, httplib::Response& res) {
            {
                std::lock_guard lock(seen_mutex);
                client_ports.insert(req.remote_port);
                auth_values.insert(req.get_header_value("Authorization"));
            }
            res.set_content(R"({"status":"ok","service":"lemonade-nexus","rp_id":"lemonade-nexus.local"})", "application/json");
        });
        port = server->bind_to_any_port("127.0.0.1");
        ASSERT_GT(port, 0);
        server_thread = std::thread([this] { server->listen_after_bind(); });
        server->wait_until_ready();
    }

    void TearDown() override {
        server->stop();
        if (server_thread.joinable()) server_thread.join();
        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    /// True when the platform's default TLS trust follows SSL_CERT_FILE. It
    /// does on Linux; the macOS keychain ignores it, so there the tests skip.
    bool default_trust_reaches_server() {
        httplib::Client probe("https://localhost:" + std::to_string(port));
        probe.set_connection_timeout(3);
        auto res = probe.Get("/api/health");
        std::lock_guard lock(seen_mutex);
        client_ports.clear();
        auth_values.clear();
        return res && res->status == 200;
    }

    lnsdk::ServerConfig config() const {
        lnsdk::ServerConfig cfg;
        cfg.servers = {{"localhost", static_cast<uint16_t>(port), true}};
        cfg.auto_discover = false;
        return cfg;
    }
};

}  // namespace

TEST_F(SdkTransportTest, SequentialCallsReuseOneConnection) {
    if (!default_trust_reaches_server()) {
#ifdef __linux__
        FAIL() << "default TLS trust cannot reach the test server; SSL_CERT_FILE is "
                  "deterministic on Linux";
#else
        GTEST_SKIP() << "default TLS trust here ignores SSL_CERT_FILE (macOS keychain)";
#endif
    }
    lnsdk::LemonadeNexusClient client(config());
    for (int i = 0; i < 10; ++i) {
        auto r = client.check_health();
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(r.value.status, "ok");
        EXPECT_EQ(r.value.rp_id, "lemonade-nexus.local") << "the passkey RP ID reaches the caller";
    }
    std::lock_guard lock(seen_mutex);
    EXPECT_EQ(client_ports.size(), 1u) << "each call opened a new connection";
}

TEST_F(SdkTransportTest, ConcurrentCallsAndTokenChangesStayConsistent) {
    if (!default_trust_reaches_server()) {
#ifdef __linux__
        FAIL() << "default TLS trust cannot reach the test server; SSL_CERT_FILE is "
                  "deterministic on Linux";
#else
        GTEST_SKIP() << "default TLS trust here ignores SSL_CERT_FILE (macOS keychain)";
#endif
    }
    lnsdk::LemonadeNexusClient client(config());
    const std::vector<std::string> tokens = {"token-a", "token-b-longer-than-a",
                                             "token-c-even-longer-than-token-b"};
    std::atomic<int> failures{0};
    std::atomic<bool> stop{false};

    // Token writer racing the requests, as the app does on re-auth.
    std::thread writer([&] {
        for (int i = 0; !stop.load(); ++i) {
            client.set_session_token(tokens[static_cast<std::size_t>(i) % tokens.size()]);
        }
    });
    std::vector<std::thread> callers;
    for (int t = 0; t < 8; ++t) {
        callers.emplace_back([&] {
            for (int i = 0; i < 20; ++i) {
                if (!client.check_health().ok) ++failures;
            }
        });
    }
    for (auto& c : callers) c.join();
    stop = true;
    writer.join();

    EXPECT_EQ(failures.load(), 0);
    std::lock_guard lock(seen_mutex);
    // Requests to one server share its pooled connection.
    EXPECT_LE(client_ports.size(), 2u);
    // A session is a bearer token for the Tier 1 server that issued it. This
    // server issued none, so no request carried a session, whole or torn.
    for (const auto& v : auth_values) {
        EXPECT_TRUE(v.empty()) << "a session went to a server that did not issue it: " << v;
    }
}

// ---------------------------------------------------------------------------
// Private API over the mesh.
//
// A stand-in server: the public API answers the join, and the private API is
// reachable only through a BoringtunMesh that acts as the server's dataplane.
// A second BoringtunMesh is another endpoint in the client's peer list. The
// client runs its real join, private transport, orchestrator, and leave paths.
// ---------------------------------------------------------------------------

namespace {

constexpr const char* kNodeId   = "node-self";
constexpr const char* kPeerId   = "node-peer";
constexpr uint16_t    kPrivPort = 9101;

/// The stand-in server's answer to one private request.
enum class Reply { Ok, Reject, CutAfterHeaders };

/// Send the status line and headers, then close the connection before the
/// body. The client gets no response, although the server ran the request.
void cut_after_headers(httplib::Response& res) {
    res.set_chunked_content_provider("application/json",
                                     [](size_t, httplib::DataSink&) { return false; });
}

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return pred();
}

class SdkMeshPrivateApiTest : public ::testing::Test {
protected:
    fs::path dir;
    std::unique_ptr<httplib::SSLServer> pub;
    std::unique_ptr<httplib::SSLServer> priv;
    std::thread pub_thread;
    std::thread priv_thread;
    int pub_port  = 0;
    int priv_port = 0;  // the private listener's port, kept across a restart
    fs::path cert_file;
    fs::path key_file;

    lnsdk::BoringtunMesh server_mesh;  // the server's dataplane
    lnsdk::BoringtunMesh peer_mesh;    // another endpoint in the client's peer list
    std::pair<std::string, std::string> server_keys;
    std::pair<std::string, std::string> peer_keys;

    std::atomic<int>   peer_list_gets{0};
    std::atomic<int>   delete_posts{0};
    std::atomic<Reply> peer_list_reply{Reply::Ok};
    std::atomic<Reply> delete_reply{Reply::Ok};

    // Joins answered 202 pending before one answers 200, and whether each
    // join request carried a link token.
    std::atomic<int>  pending_join_replies{0};
    std::mutex        join_mtx;
    std::vector<bool> join_had_link_token;

    std::vector<bool> joins_with_link_token() {
        std::lock_guard lock(join_mtx);
        return join_had_link_token;
    }
    // The hostname of each join request ("<none>" without one), and whether
    // a join that names its device is refused as a taken name.
    std::vector<std::string> join_hostname_seen;
    std::atomic<bool>        device_name_taken{false};
    std::vector<nlohmann::json> name_checks_seen;  // device-name check bodies

    std::vector<std::string> join_hostnames() {
        std::lock_guard lock(join_mtx);
        return join_hostname_seen;
    }
    std::vector<nlohmann::json> name_checks() {
        std::lock_guard lock(join_mtx);
        return name_checks_seen;
    }
    std::mutex               heartbeat_mtx;
    std::vector<std::string> heartbeat_endpoints;  // the "endpoint" of each heartbeat

    std::vector<std::string> heartbeats() {
        std::lock_guard lock(heartbeat_mtx);
        return heartbeat_endpoints;
    }

    // POST /api/auth answers, and the Authorization header of each join
    // request ("" when it carried none).
    std::atomic<int>         auth_posts{0};
    std::mutex               bearer_mtx;
    std::vector<std::string> join_bearers_seen;

    std::vector<std::string> join_bearers() {
        std::lock_guard lock(bearer_mtx);
        return join_bearers_seen;
    }

    // The mesh public key the last join registered: the client's peer as the
    // server's dataplane knows it.
    std::mutex  client_key_mtx;
    std::string client_mesh_pubkey;

    std::string joined_mesh_pubkey() {
        std::lock_guard lock(client_key_mtx);
        return client_mesh_pubkey;
    }

    // The tunnel address the peer list gives the other endpoint.
    std::mutex  listed_peer_mtx;
    std::string listed_peer_ip{"10.64.0.4/32"};

    void set_listed_peer_ip(std::string ip) {
        std::lock_guard lock(listed_peer_mtx);
        listed_peer_ip = std::move(ip);
    }
    std::string listed_peer_tunnel_ip() {
        std::lock_guard lock(listed_peer_mtx);
        return listed_peer_ip;
    }

    // The stand-in server is the one reachable Tier 1 member of a five-member
    // epoch: the client verifies it before it sends a tree request. In Epoch 2
    // its node leaves Tier 1 and `next_identity` takes the seat. Once
    // `server_left_tier1` is set, the server serves Epoch 2 and signs its
    // endpoint proofs as the new member, and its private API refuses the
    // session the departed member issued ("session-token") with 421, as the
    // tree route gate does on a server that no longer holds the tree.
    nexus::crypto::Ed25519Keypair server_identity{};
    nexus::crypto::Ed25519Keypair next_identity{};
    std::atomic<bool>             server_left_tier1{false};
    tier1_chain_test::Chain chain;

    std::size_t served_epochs() const { return server_left_tier1.load() ? 2 : 1; }

    // The heartbeat answer carries a departure notice for this next epoch
    // when set (0: none), as a member that the finalized plan leaves out
    // sends it.
    std::atomic<uint64_t> departure_next_epoch{0};
    // Authority chain pages served: how often a client walked the chain.
    std::atomic<int> authority_gets{0};

    // A second public server on another port: another verified member of
    // both epochs (`second_identity`), listed by /api/servers once
    // `list_second_server` is set. Its joins issue "session-token-3".
    std::unique_ptr<httplib::SSLServer> pub2;
    std::thread                         pub2_thread;
    int                                 pub2_port = 0;
    nexus::crypto::Ed25519Keypair       second_identity{};
    std::atomic<bool>                   list_second_server{false};
    std::atomic<int>                    second_auth_posts{0};
    // A server that has not received an invite's mint refuses the invite as
    // unknown: /api/join with a link token answers 403 there. The refusals
    // each server sent are counted.
    std::atomic<bool>                   first_server_lacks_invites{false};
    std::atomic<bool>                   second_server_lacks_invites{false};
    std::atomic<int>                    first_invite_refusals{0};
    std::atomic<int>                    second_invite_refusals{0};

    // A third public server: another verified member of both epochs
    // (`third_identity`), listed by /api/servers once `list_third_server` is
    // set. It answers every challenge 421, so no join is ever pinned to it:
    // the failover in Tier1Directory::send passes over it to another member.
    std::unique_ptr<httplib::SSLServer> pub3;
    std::thread                         pub3_thread;
    int                                 pub3_port = 0;
    nexus::crypto::Ed25519Keypair       third_identity{};
    std::atomic<bool>                   list_third_server{false};
    std::atomic<int>                    third_auth_posts{0};

    // The session moves the SDK reported.
    std::mutex                          moves_mtx;
    std::vector<lnsdk::SessionMoveEvent> moves_seen;

    std::vector<lnsdk::SessionMoveEvent> moves() {
        std::lock_guard lock(moves_mtx);
        return moves_seen;
    }

    static std::string node_b64(const nexus::crypto::Ed25519Keypair& kp) {
        return nexus::crypto::to_base64(kp.public_key);
    }

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        dir = fs::temp_directory_path() /
              ("nexus_sdk_mesh_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()) +
               "_" + std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(dir);
        cert_file = dir / "cert.pem";
        key_file  = dir / "key.pem";
        const auto& cert = cert_file;
        const auto& key  = key_file;
        ASSERT_TRUE(make_localhost_cert(cert, key));
#ifdef _WIN32
        (void)_putenv_s("SSL_CERT_FILE", cert.string().c_str());
#else
        ::setenv("SSL_CERT_FILE", cert.string().c_str(), 1);
#endif

        server_keys = lnsdk::BoringtunMesh::generate_keypair();
        peer_keys   = lnsdk::BoringtunMesh::generate_keypair();
        ASSERT_TRUE(server_mesh.start(mesh_config(server_keys, "10.64.0.1/32")));
        ASSERT_TRUE(peer_mesh.start(mesh_config(peer_keys, "10.64.0.4/32")));

        ASSERT_NO_FATAL_FAILURE(start_private_listener());
        ASSERT_TRUE(server_mesh.tcp_ingress(kPrivPort,
                                            "tcp:127.0.0.1:" + std::to_string(priv_port)));

        server_identity = tier1_chain_test::new_identity();
        next_identity   = tier1_chain_test::new_identity();
        second_identity = tier1_chain_test::new_identity();
        std::vector<nexus::crypto::Ed25519Keypair> epoch1 = {server_identity, second_identity};
        std::vector<nexus::crypto::Ed25519Keypair> epoch2 = {next_identity, second_identity};
        third_identity = tier1_chain_test::new_identity();
        epoch1.push_back(third_identity);
        epoch2.push_back(third_identity);
        for (int i = 0; i < 2; ++i) {
            const auto member = tier1_chain_test::new_identity();
            epoch1.push_back(member);
            epoch2.push_back(member);
        }
        chain = tier1_chain_test::Chain::make({epoch1, epoch2});

        ASSERT_NO_FATAL_FAILURE(start_public_listener());

        pub2 = std::make_unique<httplib::SSLServer>(cert.string().c_str(), key.string().c_str());
        ASSERT_TRUE(pub2->is_valid());
        add_public_routes(*pub2, pub2_port, &second_identity, second_auth_posts,
                          "session-token-3");
        pub2_port = pub2->bind_to_any_port("127.0.0.1");
        ASSERT_GT(pub2_port, 0);
        pub2_thread = std::thread([this] { pub2->listen_after_bind(); });
        pub2->wait_until_ready();

        pub3 = std::make_unique<httplib::SSLServer>(cert.string().c_str(), key.string().c_str());
        ASSERT_TRUE(pub3->is_valid());
        add_public_routes(*pub3, pub3_port, &third_identity, third_auth_posts,
                          "session-token-4");
        pub3_port = pub3->bind_to_any_port("127.0.0.1");
        ASSERT_GT(pub3_port, 0);
        pub3_thread = std::thread([this] { pub3->listen_after_bind(); });
        pub3->wait_until_ready();
    }

    /// Serve the first server's public API on `pub_port` (any free port the
    /// first time).
    void start_public_listener() {
        pub = std::make_unique<httplib::SSLServer>(cert_file.string().c_str(),
                                                   key_file.string().c_str());
        ASSERT_TRUE(pub->is_valid());
        add_public_routes(*pub, pub_port, nullptr, auth_posts, "session-token");
        if (pub_port == 0) {
            pub_port = pub->bind_to_any_port("127.0.0.1");
        } else {
            ASSERT_TRUE(pub->bind_to_port("127.0.0.1", pub_port));
        }
        ASSERT_GT(pub_port, 0);
        pub_thread = std::thread([this] { pub->listen_after_bind(); });
        pub->wait_until_ready();
    }

    /// Take the first server's public API off the network.
    void stop_public_listener() {
        pub->stop();
        if (pub_thread.joinable()) pub_thread.join();
    }

    /// Serve the private API on `priv_port` (any free port the first time)
    /// behind the server's dataplane ingress.
    void start_private_listener() {
        priv = std::make_unique<httplib::SSLServer>(cert_file.string().c_str(),
                                                    key_file.string().c_str());
        ASSERT_TRUE(priv->is_valid());
        add_private_routes(*priv);
        if (priv_port == 0) {
            priv_port = priv->bind_to_any_port("127.0.0.1");
        } else {
            ASSERT_TRUE(priv->bind_to_port("127.0.0.1", priv_port));
        }
        ASSERT_GT(priv_port, 0);
        priv_thread = std::thread([this] { priv->listen_after_bind(); });
        priv->wait_until_ready();
    }

    /// Take the private API down: the dataplane ingress still accepts the
    /// client's connections, and closes each one before any TLS byte.
    void stop_private_listener() {
        priv->stop();
        if (priv_thread.joinable()) priv_thread.join();
    }

    void add_private_routes(httplib::SSLServer& srv) {
        srv.Get(std::string("/api/mesh/peers/") + kNodeId,
                [this](const httplib::Request&, httplib::Response& res) {
            ++peer_list_gets;
            if (peer_list_reply.load() == Reply::CutAfterHeaders) return cut_after_headers(res);
            nlohmann::json peer = {
                {"node_id", kPeerId},
                {"mesh_pubkey", peer_keys.second},
                {"tunnel_ip", listed_peer_tunnel_ip()},
                {"endpoint", "127.0.0.1:" + std::to_string(peer_mesh.bound_port())},
                {"last_seen", 0},
                {"mgmt_pubkey", "ed25519:cGVlci1tZ210LWtleQ=="},
                // What the peer's key holds on this device: one malformed
                // entry, which the client must drop.
                {"peer_permissions", nlohmann::json::array({"read", "svc:inference", "bad perm", 7})},
            };
            nlohmann::json body;
            body["peers"] = nlohmann::json::array({peer});
            res.set_content(body.dump(), "application/json");
        });
        srv.Post(std::string("/api/tree/node/delete/") + kNodeId,
                 [this](const httplib::Request&, httplib::Response& res) {
            ++delete_posts;
            switch (delete_reply.load()) {
            case Reply::Ok:
                res.set_content(R"({"success":true})", "application/json");
                break;
            case Reply::Reject:
                res.status = 403;
                res.set_content(R"({"success":false,"error":"denied"})", "application/json");
                break;
            case Reply::CutAfterHeaders:
                cut_after_headers(res);
                break;
            }
        });
        srv.Post("/api/account/delete/challenge",
                 [](const httplib::Request&, httplib::Response& res) {
            const std::vector<uint8_t> challenge(32, 0x5a);
            res.set_content(nlohmann::json{{"challenge", lnsdk::Identity::to_base64(challenge)}}
                                .dump(),
                            "application/json");
        });
        srv.Post("/api/account/delete", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(R"({"success":true,"status":"deleted","account_id":"node-self"})",
                            "application/json");
        });
        srv.Post("/api/mesh/heartbeat", [this](const httplib::Request& req,
                                               httplib::Response& res) {
            if (server_left_tier1.load() &&
                req.get_header_value("Authorization") == "Bearer session-token") {
                res.status = 421;
                res.set_content(R"({"error":"this server does not hold the tree"})",
                                "application/json");
                return;
            }
            const auto body = nlohmann::json::parse(req.body, nullptr, false);
            {
                std::lock_guard lock(heartbeat_mtx);
                heartbeat_endpoints.push_back(
                    body.is_object() ? body.value("endpoint", std::string{"<none>"}) : "<bad>");
            }
            nlohmann::json answer{{"success", true}};
            if (const auto next_epoch = departure_next_epoch.load(); next_epoch != 0) {
                answer["tier1_departure"] = {{"next_epoch", next_epoch}};
            }
            res.set_content(answer.dump(), "application/json");
        });
    }

    /// The public routes of one stand-in Tier 1 server on `port`. It signs
    /// endpoint proofs as `fixed_identity`, or, when that is null, as the
    /// member that holds the first server's seat in the served epoch. Its
    /// joins issue `join_token`; "session-token" is the token the departed
    /// member issued, and the first server issues "session-token-2" after it
    /// left.
    void add_public_routes(httplib::SSLServer& srv, int& port,
                           const nexus::crypto::Ed25519Keypair* fixed_identity,
                           std::atomic<int>& auths, std::string join_token) {
        srv.Get("/api/health", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(R"({"status":"ok"})", "application/json");
        });
        srv.Get("/api/tier1/authority", [this](const httplib::Request& req,
                                               httplib::Response& res) {
            ++authority_gets;
            const auto page = chain.page_after(std::stoull(req.get_param_value("have_epoch")),
                                               served_epochs());
            if (!page) {
                res.status = 404;
                return;
            }
            const auto bytes = nexus::security::encode_authority_chain_page(*page);
            res.set_content(nlohmann::json{{"page", nexus::crypto::to_base64(bytes)}}.dump(),
                            "application/json");
        });
        srv.Get("/api/servers", [this](const httplib::Request&, httplib::Response& res) {
            nlohmann::json list = nlohmann::json::array();
            if (list_second_server.load()) {
                list.push_back({{"fqdn", "localhost"}, {"http_port", pub2_port}});
            }
            if (list_third_server.load()) {
                list.push_back({{"fqdn", "localhost"}, {"http_port", pub3_port}});
            }
            res.set_content(list.dump(), "application/json");
        });
        srv.Get("/api/tier1/proof", [this, &port, fixed_identity](const httplib::Request& req,
                                                                  httplib::Response& res) {
            const auto nonce = nexus::crypto::from_hex(req.get_param_value("nonce"));
            const bool left  = server_left_tier1.load();
            const auto epoch = static_cast<uint64_t>(served_epochs());
            const auto& signer =
                fixed_identity ? *fixed_identity : (left ? next_identity : server_identity);
            const auto proof = nexus::security::sign_tier1_endpoint_proof(
                chain.network, nexus::security::EpochId{epoch}, "localhost",
                static_cast<uint16_t>(port), nonce, signer);
            res.set_content(
                nlohmann::json{{"node_id", nexus::crypto::to_base64(proof.node.bytes)},
                               {"epoch", epoch},
                               {"host", proof.host},
                               {"port", proof.port},
                               {"signature", nexus::crypto::to_base64(proof.signature)}}
                    .dump(),
                "application/json");
        });
        srv.Post("/api/auth/challenge", [this, fixed_identity](const httplib::Request&,
                                                               httplib::Response& res) {
            if (fixed_identity == &third_identity) {
                res.status = 421;
                res.set_content(R"({"error":"this server does not hold the tree"})",
                                "application/json");
                return;
            }
            std::array<uint8_t, 32> challenge{};
            randombytes_buf(challenge.data(), challenge.size());
            res.set_content(
                nlohmann::json{{"challenge", nexus::crypto::to_base64(challenge)}}.dump(),
                "application/json");
        });
        srv.Post("/api/tree/device-name/check", [this](const httplib::Request& req,
                                                       httplib::Response& res) {
            {
                std::lock_guard lock(join_mtx);
                name_checks_seen.push_back(nlohmann::json::parse(req.body, nullptr, false));
            }
            res.set_content(R"({"label":"work-pc","available":false,)"
                            R"("conflicts":[{"node_id":"dev-1","device_name":"work-pc"}],)"
                            R"("suggestion":"work-pc-2"})",
                            "application/json");
        });
        srv.Post("/api/auth", [&auths](const httplib::Request&, httplib::Response& res) {
            ++auths;
            res.set_content(
                R"({"authenticated":true,"user_id":"user","session_token":"auth-token"})",
                "application/json");
        });
        srv.Post("/api/join", [this, fixed_identity, join_token](const httplib::Request& req,
                                                                 httplib::Response& res) {
            const auto body = nlohmann::json::parse(req.body, nullptr, false);
            {
                std::lock_guard lock(join_mtx);
                join_had_link_token.push_back(body.is_object() && body.contains("link_token"));
                join_hostname_seen.push_back(body.is_object() && body.contains("hostname")
                                                 ? body.value("hostname", std::string{})
                                                 : std::string{"<none>"});
            }
            if (device_name_taken.load() && body.is_object() && body.contains("hostname")) {
                // The tree's refusal text (tree::rules::device_name_refusal).
                res.status = 409;
                res.set_content(nlohmann::json{{"error", "device name '" + body.value("hostname", std::string{}) +
                                                             "' is the same as device 'work-pc' (dev-1) on "
                                                             "the mesh port; pick another name"}}
                                    .dump(),
                                "application/json");
                return;
            }
            {
                std::lock_guard lock(bearer_mtx);
                join_bearers_seen.push_back(req.get_header_value("Authorization"));
            }
            const bool second = fixed_identity == &second_identity;
            const bool lacks_invites = fixed_identity == &third_identity ? false
                                       : second ? second_server_lacks_invites.load()
                                                : first_server_lacks_invites.load();
            if (lacks_invites && body.is_object() && body.contains("link_token")) {
                ++(second ? second_invite_refusals : first_invite_refusals);
                res.status = 403;
                res.set_content(R"({"error":"invalid or expired link token"})", "application/json");
                return;
            }
            if (pending_join_replies.load() > 0) {
                --pending_join_replies;
                res.status = 202;
                res.set_content(nlohmann::json{{"success", true},
                                               {"status", "pending"},
                                               {"op_id", std::string(64, 'b')},
                                               {"node_id", kNodeId}}
                                    .dump(),
                                "application/json");
                return;
            }
            lnsdk::MeshPeer self;
            self.mesh_pubkey = body.is_object() ? body.value("mesh_pubkey", "") : "";
            self.tunnel_ip   = "10.64.0.3/32";
            {
                std::lock_guard lock(client_key_mtx);
                client_mesh_pubkey = self.mesh_pubkey;
            }
            (void)server_mesh.sync_peers({self});
            (void)peer_mesh.sync_peers({self});
            nlohmann::json j;
            j["token"] = (!fixed_identity && server_left_tier1.load()) ? "session-token-2"
                                                                        : join_token;
            j["node_id"]             = kNodeId;
            j["tunnel_ip"]           = "10.64.0.3/32";
            j["server_tunnel_ip"]    = "10.64.0.1";
            j["server_private_fqdn"] = "localhost";
            j["private_api_port"]    = kPrivPort;
            j["mesh_server_pubkey"]  = server_keys.second;
            j["mesh_endpoint"]       = "127.0.0.1:" + std::to_string(server_mesh.bound_port());
            j["tunnel_subnet"]       = "10.64.0.0/10";
            res.set_content(j.dump(), "application/json");
        });
    }

    void TearDown() override {
        if (pub) pub->stop();
        if (pub2) pub2->stop();
        if (pub3) pub3->stop();
        if (priv) priv->stop();
        if (pub_thread.joinable()) pub_thread.join();
        if (pub2_thread.joinable()) pub2_thread.join();
        if (pub3_thread.joinable()) pub3_thread.join();
        if (priv_thread.joinable()) priv_thread.join();
        peer_mesh.stop();
        server_mesh.stop();
        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    static lnsdk::BoringtunConfig mesh_config(const std::pair<std::string, std::string>& keys,
                                              const std::string& tunnel_ip) {
        lnsdk::BoringtunConfig cfg;
        cfg.private_key = keys.first;
        cfg.public_key  = keys.second;
        cfg.tunnel_ip   = tunnel_ip;
        cfg.allowed_ips = {"10.64.0.0/10"};
        return cfg;
    }

    bool default_trust_reaches_server() const {
        httplib::Client probe("https://localhost:" + std::to_string(pub_port));
        probe.set_connection_timeout(3);
        auto res = probe.Get("/api/health");
        return res && res->status == 200;
    }

    /// A client that has joined through the stand-in server, with
    /// `link_token` when one is given.
    std::unique_ptr<lnsdk::LemonadeNexusClient> joined_client(const std::string& link_token = {}) {
        lnsdk::ServerConfig cfg;
        cfg.servers = {{"localhost", static_cast<uint16_t>(pub_port), true}};
        cfg.auto_discover = false;
        auto client = std::make_unique<lnsdk::LemonadeNexusClient>(cfg);
        EXPECT_TRUE(client->set_genesis_key(
            nexus::crypto::to_base64(chain.genesis.public_key)).ok);
        client->set_session_moved_callback([this](const lnsdk::SessionMoveEvent& event) {
            std::lock_guard lock(moves_mtx);
            moves_seen.push_back(event);
        });
        client->set_session_token("session-token");
        if (!link_token.empty()) client->set_link_token(link_token);
        auto joined = client->join_network("user", "password");
        EXPECT_TRUE(joined.ok) << joined.error;
        EXPECT_TRUE(client->is_mesh_active());
        return client;
    }

    /// Epoch 2 takes effect: the server's node is no longer a member, and the
    /// client verifies the membership again, as it does every five minutes.
    void server_leaves_tier1(lnsdk::LemonadeNexusClient& client) {
        server_left_tier1 = true;
        auto refreshed = client.refresh_tier1();
        ASSERT_TRUE(refreshed.ok) << refreshed.error;
        ASSERT_EQ(refreshed.value.epoch, 2u);
    }

    /// The server restarted in place: its dataplane forgot the client's
    /// peer, while its public API and its Tier 1 seat stay. The client's
    /// handshakes go unanswered until a join adds the peer back.
    void server_forgets_client() {
        const auto key = joined_mesh_pubkey();
        ASSERT_FALSE(key.empty());
        ASSERT_TRUE(server_mesh.remove_peer(key).ok);
    }

    /// A client with the mesh orchestrator running at a one-second heartbeat
    /// cadence and an identity to re-authenticate with.
    std::unique_ptr<lnsdk::LemonadeNexusClient> heartbeating_client() {
        auto client = joined_client();
        lnsdk::Identity identity;
        identity.generate();
        client->set_identity(identity);
        lnsdk::MeshConfig cfg;
        cfg.peer_refresh_interval_sec = 3600;
        cfg.heartbeat_interval_sec    = 1;
        client->enable_mesh(cfg);
        EXPECT_TRUE(wait_for([&] { return !heartbeats().empty(); }, std::chrono::seconds(10)));
        return client;
    }
};

}  // namespace

#ifdef __linux__
#define LN_REQUIRE_TEST_TRUST()                                                     \
    if (!default_trust_reaches_server())                                            \
    FAIL() << "default TLS trust cannot reach the test server; SSL_CERT_FILE is "   \
              "deterministic on Linux"
#else
#define LN_REQUIRE_TEST_TRUST()                                                     \
    if (!default_trust_reaches_server())                                            \
    GTEST_SKIP() << "default TLS trust here ignores SSL_CERT_FILE (macOS keychain)"
#endif

// A link join that the server answers 202 pending has spent its token with
// the pending op. The client joins again without the token until the committed
// node answers 200, and the join succeeds in one call.
TEST_F(SdkMeshPrivateApiTest, APendingJoinIsRepeatedWithoutTheLinkTokenUntilItCommits) {
    LN_REQUIRE_TEST_TRUST();
    pending_join_replies = 1;
    auto client = joined_client("12345678");  // an invite code takes the link-token path
    ASSERT_TRUE(client->is_mesh_active());
    EXPECT_EQ(joins_with_link_token(), (std::vector<bool>{true, false}));
    EXPECT_EQ(pending_join_replies.load(), 0);
}

// A device name set before the join goes with the join, so the server names
// the new node with it instead of "endpoint-<8>".
TEST_F(SdkMeshPrivateApiTest, TheJoinCarriesTheDeviceName) {
    LN_REQUIRE_TEST_TRUST();
    lnsdk::ServerConfig cfg;
    cfg.servers = {{"localhost", static_cast<uint16_t>(pub_port), true}};
    cfg.auto_discover = false;
    lnsdk::LemonadeNexusClient client(cfg);
    ASSERT_TRUE(client.set_genesis_key(nexus::crypto::to_base64(chain.genesis.public_key)).ok);
    client.set_session_token("session-token");
    ASSERT_TRUE(client.set_device_name("Work PC"));
    const auto joined = client.join_network("user", "password");
    ASSERT_TRUE(joined.ok) << joined.error;
    EXPECT_FALSE(joined.value.device_name_refused);
    EXPECT_EQ(join_hostnames(), (std::vector<std::string>{"Work PC"}));
    client.disable_mesh();
}

// A name that another device of the invite's group holds never fails the
// join: the device joins again under the server's default name, keeps the
// invite, and learns a free name for a rename.
TEST_F(SdkMeshPrivateApiTest, ATakenDeviceNameFallsBackToTheServerDefault) {
    LN_REQUIRE_TEST_TRUST();
    device_name_taken = true;
    lnsdk::ServerConfig cfg;
    cfg.servers = {{"localhost", static_cast<uint16_t>(pub_port), true}};
    cfg.auto_discover = false;
    lnsdk::LemonadeNexusClient client(cfg);
    ASSERT_TRUE(client.set_genesis_key(nexus::crypto::to_base64(chain.genesis.public_key)).ok);
    client.set_session_token("session-token");
    ASSERT_TRUE(client.set_link_token("12345678"));
    ASSERT_TRUE(client.set_device_name("Work PC"));
    const auto joined = client.join_network("user", "password");
    ASSERT_TRUE(joined.ok) << joined.error;
    EXPECT_TRUE(joined.value.device_name_refused);
    EXPECT_EQ(joined.value.device_name_suggestion, "work-pc-2");
    EXPECT_EQ(join_hostnames(), (std::vector<std::string>{"Work PC", "<none>"}));
    EXPECT_EQ(joins_with_link_token(), (std::vector<bool>{true, true})) << "the invite is kept";
    const auto checks = name_checks();
    ASSERT_EQ(checks.size(), 1u);
    EXPECT_EQ(checks[0].value("name", ""), "Work PC");
    EXPECT_EQ(checks[0].value("link_token", ""), "12345678");
    client.disable_mesh();
}

// Tier 1 rotates a member out at an epoch boundary. A session bound to that
// server can no longer carry private calls. With an identity the SDK moves
// the session by itself: the private call that finds the server gone is
// refused and never sent, then the SDK authenticates with the identity
// through a current member (never carrying the stale token to the old
// server), joins again, restarts the mesh orchestrator as it was, and
// reports the move. The application never sees needs_rejoin.
TEST_F(SdkMeshPrivateApiTest, ASessionWhoseServerLeftTier1MovesToACurrentMemberByItself) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    lnsdk::Identity identity;
    identity.generate();
    client->set_identity(identity);
    lnsdk::MeshConfig cfg;
    cfg.peer_refresh_interval_sec = 3600;
    cfg.heartbeat_interval_sec    = 3600;
    client->enable_mesh(cfg);
    ASSERT_TRUE(wait_for([&] { return peer_list_gets.load() >= 1; }, std::chrono::seconds(10)));
    ASSERT_TRUE(client->mesh_heartbeat(kNodeId, "").ok);
    EXPECT_EQ(client->session_token(), "session-token");
    EXPECT_FALSE(client->mesh_status().needs_rejoin);

    ASSERT_NO_FATAL_FAILURE(server_leaves_tier1(*client));
    const auto sent_before = heartbeats().size();
    const int  peer_gets_before = peer_list_gets.load();
    EXPECT_FALSE(client->mesh_heartbeat(kNodeId, "").ok);
    EXPECT_EQ(heartbeats().size(), sent_before);

    ASSERT_TRUE(wait_for([&] { return moves().size() == 1; }, std::chrono::seconds(20)));
    const auto move = moves().front();
    EXPECT_TRUE(move.silent) << move.error;
    EXPECT_EQ(move.from_node_id, node_b64(server_identity));
    EXPECT_EQ(move.to_node_id, node_b64(next_identity));
    EXPECT_EQ(move.to_host, "localhost");
    EXPECT_EQ(move.epoch, 2u);
    EXPECT_TRUE(move.error.empty());
    EXPECT_EQ(auth_posts.load(), 1);
    EXPECT_EQ(join_bearers(), (std::vector<std::string>{"", "Bearer auth-token"}));
    EXPECT_FALSE(client->mesh_status().needs_rejoin);
    EXPECT_EQ(client->session_token(), "session-token-2");
    EXPECT_EQ(client->node_id(), kNodeId);
    // The orchestrator came back for the new session.
    EXPECT_TRUE(wait_for([&] { return peer_list_gets.load() > peer_gets_before; },
                         std::chrono::seconds(10)));
    EXPECT_TRUE(client->mesh_heartbeat(kNodeId, "").ok);
    EXPECT_GE(heartbeats().size(), sent_before + 1);
    client->disable_mesh();
}

// After the handoff the departed server refuses tree routes (421) on its
// private API. That refusal alone starts the move: the SDK verifies the
// membership again, finds the server gone, and moves the session without
// waiting for its periodic refresh.
TEST_F(SdkMeshPrivateApiTest, ATreeRefusalFromTheSessionServerStartsTheMove) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    lnsdk::Identity identity;
    identity.generate();
    client->set_identity(identity);
    ASSERT_TRUE(client->mesh_heartbeat(kNodeId, "").ok);
    EXPECT_EQ(client->tier1_membership().epoch, 1u);

    server_left_tier1 = true;
    auto refused = client->mesh_heartbeat(kNodeId, "");
    EXPECT_FALSE(refused.ok);
    EXPECT_EQ(refused.http_status, 421);

    ASSERT_TRUE(wait_for([&] { return moves().size() == 1; }, std::chrono::seconds(20)));
    const auto move = moves().front();
    EXPECT_TRUE(move.silent) << move.error;
    EXPECT_EQ(move.from_node_id, node_b64(server_identity));
    EXPECT_EQ(move.to_node_id, node_b64(next_identity));
    EXPECT_EQ(move.epoch, 2u);
    EXPECT_EQ(client->tier1_membership().epoch, 2u);
    EXPECT_EQ(auth_posts.load(), 1);
    EXPECT_EQ(client->session_token(), "session-token-2");
    EXPECT_FALSE(client->mesh_status().needs_rejoin);
    EXPECT_TRUE(client->mesh_heartbeat(kNodeId, "").ok);
}

// Without an identity the SDK cannot authenticate by itself, so it keeps the
// earlier behavior: the session is dropped, needs_rejoin is set, the move is
// reported as not silent, and join_network() authenticates afresh instead of
// carrying the stale token to the old server.
TEST_F(SdkMeshPrivateApiTest, ASessionWhoseServerLeftTier1IsDroppedWhenNoIdentityCanMoveIt) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    ASSERT_TRUE(client->mesh_heartbeat(kNodeId, "").ok);
    EXPECT_EQ(client->session_token(), "session-token");
    EXPECT_FALSE(client->mesh_status().needs_rejoin);

    ASSERT_NO_FATAL_FAILURE(server_leaves_tier1(*client));
    const auto sent_before = heartbeats().size();
    EXPECT_FALSE(client->mesh_heartbeat(kNodeId, "").ok);
    EXPECT_EQ(heartbeats().size(), sent_before);
    EXPECT_TRUE(client->session_token().empty());
    EXPECT_TRUE(client->mesh_status().needs_rejoin);
    EXPECT_EQ(auth_posts.load(), 0);
    ASSERT_EQ(moves().size(), 1u);
    EXPECT_FALSE(moves().front().silent);
    EXPECT_EQ(moves().front().from_node_id, node_b64(server_identity));
    EXPECT_TRUE(moves().front().to_node_id.empty());
    EXPECT_EQ(moves().front().error, "no identity for a silent re-authentication");

    lnsdk::Identity identity;
    identity.generate();
    client->set_identity(identity);
    auto joined = client->join_network("user", "password");
    ASSERT_TRUE(joined.ok) << joined.error;
    EXPECT_EQ(auth_posts.load(), 1);
    EXPECT_EQ(join_bearers(), (std::vector<std::string>{"", "Bearer auth-token"}));
    EXPECT_FALSE(client->mesh_status().needs_rejoin);
    EXPECT_EQ(client->session_token(), "session-token-2");
    EXPECT_TRUE(client->mesh_heartbeat(kNodeId, "").ok);
    EXPECT_EQ(heartbeats().size(), sent_before + 1);
}

// Before the handoff, a member that the finalized plan leaves out says so in
// its heartbeat answers. The SDK verifies the membership and, while the
// server still serves, moves the session early onto another verified member
// of the current epoch, chosen from the verified list and not by the server.
// The same notice again starts no second move.
TEST_F(SdkMeshPrivateApiTest, ADepartureNoticeMovesTheSessionBeforeTheHandoff) {
    LN_REQUIRE_TEST_TRUST();
    list_second_server = true;
    auto client = joined_client();
    lnsdk::Identity identity;
    identity.generate();
    client->set_identity(identity);
    ASSERT_EQ(client->tier1_membership().servers.size(), 2u);
    ASSERT_TRUE(client->mesh_heartbeat(kNodeId, "").ok);

    departure_next_epoch = 2;
    ASSERT_TRUE(client->mesh_heartbeat(kNodeId, "").ok);
    ASSERT_TRUE(wait_for([&] { return moves().size() == 1; }, std::chrono::seconds(20)));
    const auto move = moves().front();
    EXPECT_TRUE(move.silent) << move.error;
    EXPECT_EQ(move.from_node_id, node_b64(server_identity));
    EXPECT_EQ(move.to_node_id, node_b64(second_identity));
    EXPECT_EQ(move.epoch, 1u);
    EXPECT_EQ(second_auth_posts.load(), 1);
    EXPECT_EQ(auth_posts.load(), 0);
    EXPECT_EQ(client->session_token(), "session-token-3");
    EXPECT_FALSE(client->mesh_status().needs_rejoin);

    const int walks_before = authority_gets.load();
    ASSERT_TRUE(client->mesh_heartbeat(kNodeId, "").ok);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    EXPECT_EQ(moves().size(), 1u);
    EXPECT_EQ(authority_gets.load(), walks_before);
    EXPECT_EQ(client->session_token(), "session-token-3");
}

// A departure notice is a hint. One that names an epoch the SDK cannot verify
// from the chain, with no other verified server to move to, changes nothing:
// the SDK verifies, finds its server a current member, and keeps the session.
// A notice for an epoch at or below the verified one is not even looked up.
TEST_F(SdkMeshPrivateApiTest, ADepartureNoticeTheClientCannotVerifyChangesNothing) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    lnsdk::Identity identity;
    identity.generate();
    client->set_identity(identity);
    ASSERT_TRUE(client->mesh_heartbeat(kNodeId, "").ok);

    int walks_before = authority_gets.load();
    departure_next_epoch = 2;
    ASSERT_TRUE(client->mesh_heartbeat(kNodeId, "").ok);
    EXPECT_TRUE(wait_for([&] { return authority_gets.load() > walks_before; },
                         std::chrono::seconds(10)))
        << "the notice did not make the SDK verify the membership";
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    EXPECT_TRUE(moves().empty());
    EXPECT_EQ(auth_posts.load(), 0);
    EXPECT_EQ(client->session_token(), "session-token");
    EXPECT_EQ(client->tier1_membership().epoch, 1u);
    EXPECT_FALSE(client->mesh_status().needs_rejoin);
    EXPECT_TRUE(client->mesh_heartbeat(kNodeId, "").ok);

    departure_next_epoch = 1;
    walks_before = authority_gets.load();
    ASSERT_TRUE(client->mesh_heartbeat(kNodeId, "").ok);
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    EXPECT_EQ(authority_gets.load(), walks_before);
    EXPECT_TRUE(moves().empty());
    EXPECT_EQ(client->session_token(), "session-token");
}

// A Tier 1 server that restarts in place keeps its seat and its public API
// but forgets the client's dataplane peer: every private request fails before
// the handshake completes, while the verified membership still lists the
// server, so no departure notice, 421, or membership change starts a move.
// Once private requests have gone unanswered for the window, the SDK verifies
// the membership, finds the server a member whose public API answers, and
// joins again anyway, through the same server: the fresh join adds the peer
// back, the orchestrator comes back, and private requests answer again. One
// lost handshake starts no move, and the one move is reported as silent.
TEST_F(SdkMeshPrivateApiTest, ASessionServerThatStopsAnsweringOverTheMeshIsJoinedAgain) {
    LN_REQUIRE_TEST_TRUST();
    auto client = heartbeating_client();
    const int walks_before = authority_gets.load();

    ASSERT_NO_FATAL_FAILURE(server_forgets_client());
    // The window starts at the first unanswered request, so nothing moves
    // this early.
    std::this_thread::sleep_for(std::chrono::seconds(20));
    EXPECT_TRUE(moves().empty());
    EXPECT_EQ(auth_posts.load(), 0);

    ASSERT_TRUE(wait_for([&] { return moves().size() == 1; }, std::chrono::seconds(120)));
    const auto move = moves().front();
    EXPECT_TRUE(move.silent) << move.error;
    EXPECT_EQ(move.from_node_id, node_b64(server_identity));
    EXPECT_EQ(move.to_node_id, node_b64(server_identity));
    EXPECT_EQ(move.from_host, "localhost");
    EXPECT_EQ(move.to_host, "localhost");
    EXPECT_EQ(move.epoch, 1u);
    EXPECT_TRUE(move.error.empty());
    EXPECT_GT(authority_gets.load(), walks_before) << "the move did not verify the membership";
    EXPECT_EQ(auth_posts.load(), 1);
    EXPECT_EQ(client->session_token(), "session-token");
    EXPECT_FALSE(client->mesh_status().needs_rejoin);
    EXPECT_TRUE(client->is_mesh_active());

    // The orchestrator came back and its heartbeats reach the server again.
    const auto sent_after_move = heartbeats().size();
    EXPECT_TRUE(wait_for([&] { return heartbeats().size() > sent_after_move; },
                         std::chrono::seconds(30)));
    EXPECT_TRUE(client->mesh_heartbeat(kNodeId, "").ok);
    EXPECT_EQ(moves().size(), 1u);
    client->disable_mesh();
}

// The same dead private path while the public API is out of reach too: this
// device, not the server, lost the network. The window ends, but nothing
// verifies, so nothing moves: the session, the token, and the dataplane stay.
// Once the network returns, the still-dead private path moves the session in
// a later window.
TEST_F(SdkMeshPrivateApiTest, NoMoveWhileThePublicApiIsOutOfReachToo) {
    LN_REQUIRE_TEST_TRUST();
    auto client = heartbeating_client();

    ASSERT_NO_FATAL_FAILURE(stop_public_listener());
    ASSERT_NO_FATAL_FAILURE(server_forgets_client());
    // Well past the first window's end: the first unanswered request is
    // counted within about 35 s (one read timeout on the pooled connection,
    // the breaker, one failed handshake), the window ends 30 s later, and
    // the move thread then finds nothing to verify.
    std::this_thread::sleep_for(std::chrono::seconds(100));
    EXPECT_TRUE(moves().empty());
    EXPECT_EQ(auth_posts.load(), 0);
    EXPECT_EQ(client->session_token(), "session-token");
    EXPECT_EQ(client->node_id(), kNodeId);
    EXPECT_FALSE(client->mesh_status().needs_rejoin);
    EXPECT_TRUE(client->is_mesh_active());

    ASSERT_NO_FATAL_FAILURE(start_public_listener());
    ASSERT_TRUE(wait_for([&] { return moves().size() == 1; }, std::chrono::seconds(120)));
    EXPECT_TRUE(moves().front().silent) << moves().front().error;
    EXPECT_EQ(moves().front().to_node_id, node_b64(server_identity));
    EXPECT_EQ(auth_posts.load(), 1);
    EXPECT_TRUE(wait_for([&] { return client->mesh_heartbeat(kNodeId, "").ok; },
                         std::chrono::seconds(30)));
    client->disable_mesh();
}

// An answered private request ends the run of unanswered ones: the window
// starts again at the next failure. Private requests fail for part of a
// window, answer once, then fail again; a window counted from the first
// failure would have moved the session, a window restarted by the answer has
// not. The restarted window still ends in a move, and once the private API
// answers again no further move follows.
TEST_F(SdkMeshPrivateApiTest, AnAnsweredPrivateRequestRestartsTheUnansweredWindow) {
    LN_REQUIRE_TEST_TRUST();
    auto client = heartbeating_client();

    // The private listener goes away: the dataplane ingress closes each
    // connection before the TLS handshake, so every request fails fast.
    ASSERT_NO_FATAL_FAILURE(stop_private_listener());
    std::this_thread::sleep_for(std::chrono::seconds(15));
    EXPECT_TRUE(moves().empty());

    ASSERT_NO_FATAL_FAILURE(start_private_listener());
    const auto sent_before_answer = heartbeats().size();
    ASSERT_TRUE(wait_for([&] { return heartbeats().size() > sent_before_answer; },
                         std::chrono::seconds(20)))
        << "no heartbeat reached the restored private API";

    ASSERT_NO_FATAL_FAILURE(stop_private_listener());
    std::this_thread::sleep_for(std::chrono::seconds(24));
    EXPECT_TRUE(moves().empty()) << "the answered request did not restart the window";
    EXPECT_EQ(auth_posts.load(), 0);

    ASSERT_TRUE(wait_for([&] { return moves().size() == 1; }, std::chrono::seconds(90)));
    EXPECT_TRUE(moves().front().silent) << moves().front().error;
    EXPECT_EQ(moves().front().to_node_id, node_b64(server_identity));
    EXPECT_EQ(auth_posts.load(), 1);

    ASSERT_NO_FATAL_FAILURE(start_private_listener());
    const auto sent_after_move = heartbeats().size();
    ASSERT_TRUE(wait_for([&] { return heartbeats().size() > sent_after_move; },
                         std::chrono::seconds(30)));
    std::this_thread::sleep_for(std::chrono::seconds(3));
    EXPECT_EQ(moves().size(), 1u);
    client->disable_mesh();
}

// check_health() names the reason once, when it finds the session's server
// gone. Without an identity the session is dropped with it, so health itself
// answers afterwards.
TEST_F(SdkMeshPrivateApiTest, HealthReportsTheDepartedSessionServerOnce) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    ASSERT_TRUE(client->check_health().ok);

    ASSERT_NO_FATAL_FAILURE(server_leaves_tier1(*client));
    auto health = client->check_health();
    EXPECT_FALSE(health.ok);
    EXPECT_EQ(health.error,
              "the session's server is no longer a verified Tier 1 server: join again");
    EXPECT_TRUE(client->session_token().empty());
    EXPECT_TRUE(client->mesh_status().needs_rejoin);
    EXPECT_TRUE(client->check_health().ok);
}

// The node delete travels over the mesh, so leave_network must delete the node
// before it stops the mesh.
TEST_F(SdkMeshPrivateApiTest, LeaveDeletesTheNodeBeforeItStopsTheMesh) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    auto left = client->leave_network();
    EXPECT_TRUE(left.ok) << left.error;
    EXPECT_EQ(delete_posts.load(), 1);
    EXPECT_FALSE(client->is_mesh_active());
    EXPECT_TRUE(client->node_id().empty());
    // The session belonged to the removed device; a later join starts afresh.
    EXPECT_TRUE(client->session_token().empty());
}

// A device that left keeps no session bound to its former server. When that
// server later leaves Tier 1, a private-path check starts no session move,
// so nothing joins the device again.
TEST_F(SdkMeshPrivateApiTest, LeavingEndsTheSessionSoNoMoveJoinsTheDeviceAgain) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    lnsdk::Identity identity;
    identity.generate();
    client->set_identity(identity);
    auto left = client->leave_network();
    ASSERT_TRUE(left.ok) << left.error;

    ASSERT_NO_FATAL_FAILURE(server_leaves_tier1(*client));
    EXPECT_TRUE(client->check_health().ok);
    EXPECT_FALSE(wait_for([&] { return !moves().empty(); }, std::chrono::seconds(2)));
    EXPECT_EQ(auth_posts.load(), 0);
    EXPECT_EQ(join_bearers().size(), 1u);
    EXPECT_TRUE(client->node_id().empty());
}

// The same holds after an account deletion: the session ends with its
// server binding, so no session move joins the deleted account again.
TEST_F(SdkMeshPrivateApiTest, DeletingTheAccountEndsTheSessionSoNoMoveJoinsAgain) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    lnsdk::Identity identity;
    identity.generate();
    client->set_identity(identity);
    auto deleted = client->delete_account();
    ASSERT_TRUE(deleted.ok) << deleted.error;
    EXPECT_TRUE(client->session_token().empty());
    EXPECT_TRUE(client->node_id().empty());

    ASSERT_NO_FATAL_FAILURE(server_leaves_tier1(*client));
    EXPECT_TRUE(client->check_health().ok);
    EXPECT_FALSE(wait_for([&] { return !moves().empty(); }, std::chrono::seconds(2)));
    EXPECT_EQ(auth_posts.load(), 0);
    EXPECT_EQ(join_bearers().size(), 1u);
}

// A rejected delete leaves the node joined: the mesh stays up so the caller can
// retry, and the error reaches the caller.
TEST_F(SdkMeshPrivateApiTest, LeaveKeepsTheMeshUpWhenTheDeleteFails) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    delete_reply = Reply::Reject;
    auto left = client->leave_network();
    EXPECT_FALSE(left.ok);
    EXPECT_EQ(left.http_status, 403);
    // The error says what failed: the node, the status, and the server's reason.
    EXPECT_NE(left.error.find(kNodeId), std::string::npos) << left.error;
    EXPECT_NE(left.error.find("HTTP 403"), std::string::npos) << left.error;
    EXPECT_NE(left.error.find("denied"), std::string::npos) << left.error;
    EXPECT_EQ(delete_posts.load(), 1);
    EXPECT_TRUE(client->is_mesh_active());
    EXPECT_EQ(client->node_id(), kNodeId);
    EXPECT_EQ(client->session_token(), "session-token");
}

// The server can apply a POST and then lose the response. The client must not
// send that POST a second time.
TEST_F(SdkMeshPrivateApiTest, PostWithoutAResponseIsNotSentAgain) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    delete_reply = Reply::CutAfterHeaders;
    auto deleted = client->delete_node(kNodeId);
    EXPECT_FALSE(deleted.ok);
    EXPECT_EQ(delete_posts.load(), 1);
}

// A GET has no side effect, so the client still retries it once.
TEST_F(SdkMeshPrivateApiTest, GetWithoutAResponseIsRetriedOnce) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    peer_list_reply = Reply::CutAfterHeaders;
    auto peers = client->fetch_mesh_peers(kNodeId);
    EXPECT_FALSE(peers.ok);
    EXPECT_EQ(peer_list_gets.load(), 2);
}

// refresh_mesh_peers must run a refresh now, not at the next interval.
TEST_F(SdkMeshPrivateApiTest, RefreshNowFetchesPeersImmediately) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    lnsdk::MeshConfig cfg;
    cfg.peer_refresh_interval_sec = 3600;
    cfg.heartbeat_interval_sec    = 3600;
    client->enable_mesh(cfg);
    ASSERT_TRUE(wait_for([&] { return peer_list_gets.load() >= 1; }, std::chrono::seconds(10)));
    const int before = peer_list_gets.load();
    client->refresh_mesh_peers();
    EXPECT_TRUE(wait_for([&] { return peer_list_gets.load() > before; }, std::chrono::seconds(3)))
        << "refresh_mesh_peers did not wake the orchestrator";
    client->disable_mesh();
}

// The peer list carries each peer's management key and the permissions its
// key holds on this device (peer_permissions). The client keeps the valid
// tokens, which the service ingress enforces, and drops anything else.
TEST_F(SdkMeshPrivateApiTest, PeerPermissionsAndManagementKeyComeFromThePeerList) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    lnsdk::MeshConfig cfg;
    cfg.peer_refresh_interval_sec = 3600;
    cfg.heartbeat_interval_sec    = 3600;
    client->enable_mesh(cfg);
    ASSERT_TRUE(wait_for([&] { return !client->get_mesh_peers().empty(); }, std::chrono::seconds(10)));
    const auto peers = client->get_mesh_peers();
    ASSERT_EQ(peers.size(), 1u);
    EXPECT_EQ(peers[0].node_id, kPeerId);
    EXPECT_EQ(peers[0].mgmt_pubkey, "ed25519:cGVlci1tZ210LWtleQ==");
    EXPECT_EQ(peers[0].permissions, (std::vector<std::string>{"read", "svc:inference"}));
    client->disable_mesh();
}

// The C ABI peer list carries every field the header documents, through the
// same serialization as the C++ types: lemond and the Flutter plugin read the
// peer's permissions and management key from it.
TEST_F(SdkMeshPrivateApiTest, CApiPeerListCarriesPermissionsKeyAndTimestamps) {
    LN_REQUIRE_TEST_TRUST();
    ln_client_t* c = ln_create_tls("localhost", static_cast<uint16_t>(pub_port));
    ASSERT_NE(c, nullptr);
    struct Destroy {
        ln_client_t* c;
        ~Destroy() { ln_destroy(c); }
    } destroy{c};
    ASSERT_EQ(ln_set_genesis_key(c, nexus::crypto::to_base64(chain.genesis.public_key).c_str(), 0),
              LN_OK);
    ASSERT_EQ(ln_set_session_token(c, "session-token"), LN_OK);
    char* out = nullptr;
    ASSERT_EQ(ln_join_network(c, "user", "password", &out), LN_OK) << (out ? out : "");
    ln_free(out);
    ASSERT_EQ(ln_mesh_enable_config(
                  c, R"({"peer_refresh_interval_sec":3600,"heartbeat_interval_sec":3600})"),
              LN_OK);

    nlohmann::json peers;
    ASSERT_TRUE(wait_for([&] {
        char* listed = nullptr;
        if (ln_mesh_peers(c, &listed) != LN_OK || !listed) return false;
        peers = nlohmann::json::parse(listed, nullptr, false);
        ln_free(listed);
        return peers.is_array() && !peers.empty();
    }, std::chrono::seconds(10)));
    ASSERT_EQ(peers.size(), 1u) << peers.dump();
    const auto& peer = peers[0];
    EXPECT_EQ(peer["node_id"], kPeerId);
    EXPECT_EQ(peer["mgmt_pubkey"], "ed25519:cGVlci1tZ210LWtleQ==");
    EXPECT_EQ(peer["peer_permissions"], nlohmann::json::array({"read", "svc:inference"}));
    for (const char* field : {"last_seen", "last_rx", "last_handshake", "is_online"}) {
        EXPECT_TRUE(peer.contains(field)) << field << " missing: " << peer.dump();
    }

    char* status = nullptr;
    ASSERT_EQ(ln_mesh_status(c, &status), LN_OK);
    const auto st = nlohmann::json::parse(status ? status : "null", nullptr, false);
    ln_free(status);
    ASSERT_TRUE(st.is_object());
    EXPECT_EQ(st.value("needs_rejoin", true), false);
    ASSERT_TRUE(st.contains("peers") && st["peers"].is_array());
    for (const auto& p : st["peers"]) {
        EXPECT_TRUE(p.contains("peer_permissions") && p.contains("last_rx")) << p.dump();
    }
    ln_mesh_disable(c);
}

// A mesh state callback runs on the orchestrator thread and may call back into
// the client. leave_network stops the orchestrator; it must not hold the
// client mutex while it waits for that thread, or the callback and the leave
// wait on each other forever.
TEST_F(SdkMeshPrivateApiTest, LeaveDoesNotDeadlockWithACallbackThatCallsTheClient) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    auto* raw = client.get();
    std::atomic<bool> in_callback{false};
    std::atomic<bool> callback_done{false};
    client->set_mesh_callback([&, raw](const lnsdk::MeshTunnelStatus&) {
        if (in_callback.exchange(true)) return;
        // Hold the orchestrator thread here until the leave has deleted the
        // node and is stopping the orchestrator, then call into the client.
        (void)wait_for([&] { return delete_posts.load() > 0; }, std::chrono::seconds(20));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        (void)raw->get_mesh_peers();
        (void)raw->mesh_status();
        callback_done = true;
    });
    lnsdk::MeshConfig cfg;
    cfg.heartbeat_interval_sec = 3600;
    client->enable_mesh(cfg);
    ASSERT_TRUE(wait_for([&] { return in_callback.load(); }, std::chrono::seconds(15)));

    auto left = std::make_shared<std::promise<bool>>();
    auto done = left->get_future();
    std::thread leaver([left, raw] { left->set_value(raw->leave_network().ok); });
    if (done.wait_for(std::chrono::seconds(20)) != std::future_status::ready) {
        // The threads are deadlocked and cannot be joined; end the process so
        // the run reports the failure instead of hanging.
        ADD_FAILURE() << "leave_network deadlocked with the mesh state callback";
        std::fprintf(stderr, "deadlock detected; exiting\n");
        std::_Exit(1);
    }
    leaver.join();
    EXPECT_TRUE(done.get());
    EXPECT_TRUE(callback_done.load());
    EXPECT_FALSE(client->is_mesh_active());
}

// The orchestrator takes a peer's handshake time from the dataplane entry with
// the same mesh public key. The server lists tunnel_ip with a prefix and the
// dataplane has no node_id, so neither of those fields can match.
TEST_F(SdkMeshPrivateApiTest, HandshakeIsMatchedToItsPeerByMeshKey) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    lnsdk::MeshConfig cfg;
    cfg.heartbeat_interval_sec = 3600;
    client->enable_mesh(cfg);
    ASSERT_TRUE(wait_for([&] { return client->get_mesh_peers().size() == 1; },
                         std::chrono::seconds(10)));

    // Traffic toward the peer starts the Noise handshake with it.
    const uint16_t egress = client->open_egress("10.64.0.4", 80);
    ASSERT_GT(egress, 0);
    httplib::Client poke("127.0.0.1", egress);
    poke.set_connection_timeout(1);
    poke.set_read_timeout(1);
    (void)poke.Get("/");

    EXPECT_TRUE(wait_for([&] {
        auto peers = client->get_mesh_peers();
        return peers.size() == 1 && peers[0].last_handshake > 0 && peers[0].is_online;
    }, std::chrono::seconds(15))) << "the peer's handshake was not attributed to it";
    client->disable_mesh();
}

// The private API answers on the tunnel address of the server that the client
// joined. A listed peer that claims the same address (all servers and the
// first endpoint each server allocated once held 10.64.0.10) must not take
// that traffic: the private API must still reach the server.
TEST_F(SdkMeshPrivateApiTest, APeerOnTheServerAddressDoesNotTakeThePrivateApi) {
    LN_REQUIRE_TEST_TRUST();
    set_listed_peer_ip("10.64.0.1/32");  // the stand-in server's tunnel address
    auto client = joined_client();
    lnsdk::MeshConfig cfg;
    cfg.heartbeat_interval_sec = 3600;
    client->enable_mesh(cfg);
    // The orchestrator stores the list only after it synced the routes.
    ASSERT_TRUE(wait_for([&] { return client->get_mesh_peers().size() == 1; },
                         std::chrono::seconds(10)));

    const int before = peer_list_gets.load();
    auto peers = client->fetch_mesh_peers(kNodeId);
    EXPECT_TRUE(peers.ok) << "the private API did not reach the server: " << peers.error;
    EXPECT_GT(peer_list_gets.load(), before);
    client->disable_mesh();
}

// The orchestrator learns its reflexive address from the session server's
// STUN service (the canonical port 3478 on the server's host) and publishes
// it with the heartbeat. The address is the mapping the server's own
// dataplane sees, because the query leaves from the dataplane socket.
TEST_F(SdkMeshPrivateApiTest, HeartbeatPublishesTheReflexiveEndpoint) {
    LN_REQUIRE_TEST_TRUST();
    asio::io_context io;
    nexus::crypto::SodiumCryptoService crypto;
    crypto.start();
    std::unique_ptr<nexus::network::StunService> stun;
    try {
        stun = std::make_unique<nexus::network::StunService>(io, 3478, crypto, "test-stun");
    } catch (const std::exception&) {
        crypto.stop();
        GTEST_SKIP() << "UDP port 3478 is in use on this host";
    }
    stun->start();
    auto guard = asio::make_work_guard(io);
    std::thread io_thread([&io] { io.run(); });

    auto client = joined_client();
    lnsdk::MeshConfig cfg;
    cfg.heartbeat_interval_sec    = 1;
    cfg.stun_refresh_interval_sec = 60;
    client->enable_mesh(cfg);

    std::string seen_by_server;
    EXPECT_TRUE(wait_for([&] {
        for (const auto& p : server_mesh.mesh_status().peers) {
            if (!p.endpoint.empty()) seen_by_server = p.endpoint;
        }
        if (seen_by_server.empty()) return false;
        for (const auto& endpoint : heartbeats()) {
            if (endpoint == seen_by_server) return true;
        }
        return false;
    }, std::chrono::seconds(15))) << "no heartbeat carried the reflexive endpoint "
                                  << seen_by_server;

    client->disable_mesh();
    stun->stop();
    guard.reset();
    io.stop();
    io_thread.join();
    crypto.stop();
}

// Without a reflexive address (STUN refresh off) the heartbeat carries an
// empty endpoint, which the server treats as liveness only.
TEST_F(SdkMeshPrivateApiTest, HeartbeatWithoutStunSendsAnEmptyEndpoint) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    lnsdk::MeshConfig cfg;
    cfg.heartbeat_interval_sec    = 1;
    cfg.stun_refresh_interval_sec = 0;
    client->enable_mesh(cfg);
    ASSERT_TRUE(wait_for([&] { return heartbeats().size() >= 2; }, std::chrono::seconds(10)));
    client->disable_mesh();
    for (const auto& endpoint : heartbeats()) EXPECT_EQ(endpoint, "");
}

// An invite is minted on the inviter's session server and replicates to the
// other Tier 1 members over the backbone. A member that has not received the
// mint (one that restarted minutes ago and has no backbone peers yet, or any
// member within the replication delay) refuses the invite as unknown, with
// the same answer as an expired one. The join is pinned to the member that
// issued its challenge, so the SDK asks another verified member, challenge
// and join, before it reports the invite invalid.
TEST_F(SdkMeshPrivateApiTest, AnInviteUnknownToOneMemberIsRedeemedThroughAnother) {
    LN_REQUIRE_TEST_TRUST();
    list_second_server = true;
    first_server_lacks_invites = true;

    lnsdk::ServerConfig cfg;
    cfg.servers = {{"localhost", static_cast<uint16_t>(pub_port), true}};
    cfg.auto_discover = false;
    lnsdk::LemonadeNexusClient client(cfg);
    ASSERT_TRUE(client.set_genesis_key(nexus::crypto::to_base64(chain.genesis.public_key)).ok);
    lnsdk::Identity identity;
    identity.generate();
    client.set_identity(identity);
    client.set_session_token("session-token");
    ASSERT_TRUE(client.set_link_token("12345678"));
    const auto refreshed = client.refresh_tier1();
    ASSERT_TRUE(refreshed.ok) << refreshed.error;
    ASSERT_EQ(client.tier1_membership().servers.size(), 2u);

    const auto joined = client.join_network("user", "password");
    ASSERT_TRUE(joined.ok) << joined.error;
    // The first member refused the invite; the second redeemed it and issued
    // the session, so the session is bound to the second member.
    EXPECT_EQ(joins_with_link_token(), (std::vector<bool>{true, true}));
    EXPECT_EQ(client.session_token(), "session-token-3");
    EXPECT_EQ(client.node_id(), kNodeId);
    EXPECT_TRUE(client.is_mesh_active());
}

// When every verified member refuses the invite, the refusal is final: each
// member was asked once, and the error names the invite.
TEST_F(SdkMeshPrivateApiTest, AnInviteEveryMemberRefusesIsReportedInvalidOnce) {
    LN_REQUIRE_TEST_TRUST();
    list_second_server = true;
    first_server_lacks_invites = true;
    second_server_lacks_invites = true;

    lnsdk::ServerConfig cfg;
    cfg.servers = {{"localhost", static_cast<uint16_t>(pub_port), true}};
    cfg.auto_discover = false;
    lnsdk::LemonadeNexusClient client(cfg);
    ASSERT_TRUE(client.set_genesis_key(nexus::crypto::to_base64(chain.genesis.public_key)).ok);
    lnsdk::Identity identity;
    identity.generate();
    client.set_identity(identity);
    client.set_session_token("session-token");
    ASSERT_TRUE(client.set_link_token("12345678"));
    const auto refreshed = client.refresh_tier1();
    ASSERT_TRUE(refreshed.ok) << refreshed.error;
    ASSERT_EQ(client.tier1_membership().servers.size(), 2u);

    const auto joined = client.join_network("user", "password");
    EXPECT_FALSE(joined.ok);
    EXPECT_EQ(joined.http_status, 403);
    EXPECT_EQ(joined.error, "invalid or expired link token");
    EXPECT_EQ(joins_with_link_token(), (std::vector<bool>{true, true}));
    EXPECT_FALSE(client.is_mesh_active());
}

// A join waits before it asks another member, so a mint seconds old can
// replicate there: the hop does not follow the refusal at once.
TEST_F(SdkMeshPrivateApiTest, AnInviteHopWaitsForReplicationFirst) {
    LN_REQUIRE_TEST_TRUST();
    list_second_server = true;
    first_server_lacks_invites = true;

    lnsdk::ServerConfig cfg;
    cfg.servers = {{"localhost", static_cast<uint16_t>(pub_port), true}};
    cfg.auto_discover = false;
    lnsdk::LemonadeNexusClient client(cfg);
    ASSERT_TRUE(client.set_genesis_key(nexus::crypto::to_base64(chain.genesis.public_key)).ok);
    lnsdk::Identity identity;
    identity.generate();
    client.set_identity(identity);
    client.set_session_token("session-token");
    ASSERT_TRUE(client.set_link_token("12345678"));
    constexpr std::chrono::milliseconds kDelay{800};
    client.set_invite_hop_delay(kDelay);
    const auto refreshed = client.refresh_tier1();
    ASSERT_TRUE(refreshed.ok) << refreshed.error;
    ASSERT_EQ(client.tier1_membership().servers.size(), 2u);

    const auto started = std::chrono::steady_clock::now();
    const auto joined = client.join_network("user", "password");
    const auto elapsed = std::chrono::steady_clock::now() - started;
    ASSERT_TRUE(joined.ok) << joined.error;
    EXPECT_GE(elapsed, kDelay);
    EXPECT_EQ(first_invite_refusals.load(), 1);
    EXPECT_EQ(joins_with_link_token(), (std::vector<bool>{true, true}));
    EXPECT_EQ(client.session_token(), "session-token-3");
}

// Two members refuse the invite while a third verified member takes no
// challenge, so the challenge failover keeps landing on the two that refused.
// The join asks each of them once, makes at most three attempts, and reports
// the refusal; it does not alternate between them.
TEST_F(SdkMeshPrivateApiTest, MembersThatRefusedAnInviteAreNotAskedAgain) {
    LN_REQUIRE_TEST_TRUST();
    list_second_server = true;
    list_third_server = true;
    first_server_lacks_invites = true;
    second_server_lacks_invites = true;

    lnsdk::ServerConfig cfg;
    cfg.servers = {{"localhost", static_cast<uint16_t>(pub_port), true}};
    cfg.auto_discover = false;
    lnsdk::LemonadeNexusClient client(cfg);
    ASSERT_TRUE(client.set_genesis_key(nexus::crypto::to_base64(chain.genesis.public_key)).ok);
    lnsdk::Identity identity;
    identity.generate();
    client.set_identity(identity);
    client.set_session_token("session-token");
    ASSERT_TRUE(client.set_link_token("12345678"));
    constexpr std::chrono::milliseconds kDelay{200};
    client.set_invite_hop_delay(kDelay);
    const auto refreshed = client.refresh_tier1();
    ASSERT_TRUE(refreshed.ok) << refreshed.error;
    ASSERT_EQ(client.tier1_membership().servers.size(), 3u);

    auto pending = std::async(std::launch::async,
                              [&client] { return client.join_network("user", "password"); });
    ASSERT_EQ(pending.wait_for(std::chrono::seconds(30)), std::future_status::ready)
        << "the join kept asking the members that refused";
    const auto joined = pending.get();
    EXPECT_FALSE(joined.ok);
    EXPECT_EQ(joined.http_status, 403);
    EXPECT_EQ(joined.error, "invalid or expired link token");
    EXPECT_EQ(first_invite_refusals.load(), 1);
    EXPECT_EQ(second_invite_refusals.load(), 1);
    EXPECT_LE(joins_with_link_token().size(), 3u);
    EXPECT_EQ(joins_with_link_token(), (std::vector<bool>{true, true}));
    EXPECT_EQ(third_auth_posts.load(), 0);
    EXPECT_FALSE(client.is_mesh_active());
}
