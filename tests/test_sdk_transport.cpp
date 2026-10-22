// SDK public transport: one kept-alive connection per server, safe to use from
// several threads at once.
//
// The Flutter client calls the SDK from worker isolates, so requests and
// session-token updates arrive concurrently. The client must not tear its
// shared state, and it must reuse its HTTPS connection instead of paying a TCP
// and TLS handshake on every call.

#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>

#include <gtest/gtest.h>
#include <httplib.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {

bool write_pem(const fs::path& path, const X509* cert, const EVP_PKEY* key) {
    FILE* f = std::fopen(path.string().c_str(), "wb");
    if (!f) return false;
    const bool ok = cert ? PEM_write_X509(f, cert)
                         : PEM_write_PrivateKey(f, key, nullptr, nullptr, 0, nullptr, nullptr);
    std::fclose(f);
    return ok;
}

/// A self-signed "localhost" certificate. Listed in SSL_CERT_FILE it is a trust
/// anchor, so the SDK's always-on verification accepts the test server.
bool make_localhost_cert(const fs::path& cert_p, const fs::path& key_p) {
    EVP_PKEY* key = EVP_RSA_gen(2048);
    if (!key) return false;
    X509* x = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 3600);
    X509_set_pubkey(x, key);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
    X509_set_issuer_name(x, name);
    for (const char* spec : {"critical,CA:TRUE", "DNS:localhost"}) {
        const int nid = spec[0] == 'D' ? NID_subject_alt_name : NID_basic_constraints;
        if (X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, nid, spec)) {
            X509_add_ext(x, ext, -1);
            X509_EXTENSION_free(ext);
        }
    }
    bool ok = X509_sign(x, key, EVP_sha256()) != 0;
    ok = ok && write_pem(cert_p, x, nullptr) && write_pem(key_p, nullptr, key);
    X509_free(x);
    EVP_PKEY_free(key);
    return ok;
}

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
            res.set_content(R"({"status":"ok","service":"lemonade-nexus"})", "application/json");
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
    // Every header carried one whole token, never a torn mix.
    for (const auto& v : auth_values) {
        if (v.empty()) continue;  // a request sent before the first token
        bool whole = false;
        for (const auto& t : tokens) whole = whole || v == "Bearer " + t;
        EXPECT_TRUE(whole) << "torn Authorization header: " << v;
    }
}
