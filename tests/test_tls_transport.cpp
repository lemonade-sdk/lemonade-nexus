// Locks the split-horizon TLS mechanism the SDK/onboarding paths rely on: a
// client connects BY the certificate FQDN (SNI + verification) while the socket
// lands on the loopback egress via httplib's hostname->addr map. Plain HTTP, a
// wrong hostname, and a missing CA must all be rejected.

#include <LemonadeNexus/Network/HttpServer.hpp>
#include <LemonadeNexusSDK/ServerDiscovery.hpp>

#include <gtest/gtest.h>
#include <httplib.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <chrono>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
using namespace std::chrono_literals;
namespace fs = std::filesystem;

namespace {

// Write a self-signed cert + key for `cn` (with a matching DNS SAN) to disk.
bool make_self_signed(const std::string& cn, const fs::path& cert_p, const fs::path& key_p) {
    EVP_PKEY* pkey = EVP_RSA_gen(2048);
    if (!pkey) return false;
    X509* x = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 60 * 60 * 24);
    X509_set_pubkey(x, pkey);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509_set_issuer_name(x, name);
    std::string san = "DNS:" + cn;
    if (X509_EXTENSION* ext =
            X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, san.c_str())) {
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
    }
    bool ok = X509_sign(x, pkey, EVP_sha256()) != 0;
    if (ok) {
        if (FILE* cf = std::fopen(cert_p.string().c_str(), "wb")) {
            ok = ok && PEM_write_X509(cf, x); std::fclose(cf);
        }
        if (FILE* kf = std::fopen(key_p.string().c_str(), "wb")) {
            ok = ok && PEM_write_PrivateKey(kf, pkey, nullptr, nullptr, 0, nullptr, nullptr);
            std::fclose(kf);
        }
    }
    X509_free(x);
    EVP_PKEY_free(pkey);
    return ok;
}

}  // namespace

TEST(TlsTransport, VerifiedByFqdnWhileConnectingToLoopback) {
    auto tmp = fs::temp_directory_path() / ("nexus_tls_" + std::to_string(getpid()));
    fs::create_directories(tmp);
    const auto cert = tmp / "cert.pem";
    const auto key  = tmp / "key.pem";
    const std::string fqdn = "test-node.eu-west.seip.lemonade-nexus.io";
    ASSERT_TRUE(make_self_signed(fqdn, cert, key));

    const uint16_t port = static_cast<uint16_t>(18000 + (getpid() % 1000));
    network::HttpServer srv(port, "127.0.0.1");
    ASSERT_TRUE(srv.enable_tls_from_paths(cert.string(), key.string()));
    ASSERT_TRUE(srv.is_tls());
    srv.server().Get("/ping", [](const httplib::Request&, httplib::Response& r) {
        r.set_content("pong", "text/plain");
    });
    srv.start();
    std::this_thread::sleep_for(300ms);

    // (1) Connect BY the cert FQDN, verify against our CA, but land on loopback.
    {
        httplib::SSLClient cli(fqdn, port);
        cli.set_hostname_addr_map({{fqdn, "127.0.0.1"}});
        cli.set_ca_cert_path(cert.string());
        cli.set_connection_timeout(3);
        auto r = cli.Get("/ping");
        ASSERT_TRUE(r) << "verified TLS by FQDN over loopback should succeed";
        EXPECT_EQ(r->status, 200);
        EXPECT_EQ(r->body, "pong");
    }

    // (2) Plain HTTP to a TLS listener is refused.
    {
        httplib::Client cli("127.0.0.1", port);
        cli.set_connection_timeout(3);
        EXPECT_FALSE(cli.Get("/ping"));
    }

    // (3) Wrong hostname (cert is for `fqdn`) fails verification even with the CA.
    {
        httplib::SSLClient cli("wrong.example.com", port);
        cli.set_hostname_addr_map({{"wrong.example.com", "127.0.0.1"}});
        cli.set_ca_cert_path(cert.string());
        cli.set_connection_timeout(3);
        EXPECT_FALSE(cli.Get("/ping"));
    }

    // (4) No CA: the self-signed cert isn't in the default store → rejected.
    {
        httplib::SSLClient cli(fqdn, port);
        cli.set_hostname_addr_map({{fqdn, "127.0.0.1"}});
        cli.set_connection_timeout(3);
        EXPECT_FALSE(cli.Get("/ping"));
    }

    srv.stop();
    fs::remove_all(tmp);
}

// ===========================================================================
// Phase 7b: in-memory-key TLS. The key is a vault-covered file decrypted into
// memory; enable_tls_inmemory_key loads it with the cert still read by path.
// Fail closed: an empty (still-locked) key withholds the listener.
// ===========================================================================

namespace {
std::string read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f) return {};
    std::ostringstream ss; ss << f.rdbuf();
    return ss.str();
}
}

TEST(TlsInMemoryKey, FailClosedWhenKeyEmpty) {
    auto tmp = fs::temp_directory_path() / ("nexus_tls_imem_locked_" + std::to_string(getpid()));
    fs::create_directories(tmp);
    const auto cert = tmp / "cert.pem";
    const auto key  = tmp / "key.pem";
    const std::string fqdn = "locked.eu-west.seip.lemonade-nexus.io";
    ASSERT_TRUE(make_self_signed(fqdn, cert, key));

    // A vault-covered key while the DEK is locked yields no in-memory bytes.
    // The cert is still on disk (public, not secret) but the listener must be
    // withheld rather than serving plaintext.
    network::HttpServer srv(static_cast<uint16_t>(18200 + (getpid() % 1000)), "127.0.0.1");
    EXPECT_FALSE(srv.enable_tls_inmemory_key(cert.string(), /*key_pem=*/"", key.string()));
    EXPECT_FALSE(srv.is_tls());
    srv.stop();
    fs::remove_all(tmp);
}

TEST(TlsInMemoryKey, ServesTlsFromInMemoryKey) {
    auto tmp = fs::temp_directory_path() / ("nexus_tls_imem_" + std::to_string(getpid()));
    fs::create_directories(tmp);
    const auto cert = tmp / "cert.pem";
    const auto key  = tmp / "key.pem";
    const std::string fqdn = "imem.eu-west.seip.lemonade-nexus.io";
    ASSERT_TRUE(make_self_signed(fqdn, cert, key));
    const std::string key_pem = read_file(key);  // decrypted in memory
    ASSERT_FALSE(key_pem.empty());

    const uint16_t port = static_cast<uint16_t>(18250 + (getpid() % 1000));
    network::HttpServer srv(port, "127.0.0.1");
    ASSERT_TRUE(srv.enable_tls_inmemory_key(cert.string(), key_pem, key.string()));
    ASSERT_TRUE(srv.is_tls());
    srv.server().Get("/ping", [](const httplib::Request&, httplib::Response& r) {
        r.set_content("pong", "text/plain");
    });
    srv.start();
    std::this_thread::sleep_for(300ms);

    // Connect by the cert FQDN, verify against the on-disk cert as CA, land on
    // loopback. Proves the in-memory key produced a working TLS context.
    httplib::SSLClient cli(fqdn, port);
    cli.set_hostname_addr_map({{fqdn, "127.0.0.1"}});
    cli.set_ca_cert_path(cert.string());
    cli.set_connection_timeout(3);
    auto res = cli.Get("/ping");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->body, "pong");

    srv.stop();
    fs::remove_all(tmp);
}

// ---------------------------------------------------------------------------
// First-connect server discovery: the certificate name is the candidate.
// ---------------------------------------------------------------------------

namespace {

struct TlsEcho {
    fs::path tmp;
    std::unique_ptr<network::HttpServer> srv;
    uint16_t port{0};

    TlsEcho(const std::string& cn, uint16_t p) : port(p) {
        tmp = fs::temp_directory_path() / ("nexus_discovery_" + std::to_string(getpid()) + "_" + std::to_string(p));
        fs::create_directories(tmp);
        const auto cert = tmp / "cert.pem";
        const auto key  = tmp / "key.pem";
        if (!make_self_signed(cn, cert, key)) return;
        srv = std::make_unique<network::HttpServer>(port, "127.0.0.1");
        if (!srv->enable_tls_from_paths(cert.string(), key.string())) { srv.reset(); return; }
        srv->server().Get("/api/health", [](const httplib::Request&, httplib::Response& r) {
            r.set_content("{}", "application/json");
        });
        srv->start();
        std::this_thread::sleep_for(300ms);
    }
    ~TlsEcho() {
        if (srv) srv->stop();
        std::error_code ec;
        fs::remove_all(tmp, ec);
    }
};

}  // namespace

TEST(ServerDiscovery, DomainRulesKeepOnlyHostnamesBelowTheDomain) {
    using lnsdk::discovered_name_in_domain;
    EXPECT_TRUE(discovered_name_in_domain("sn01.us-west.seip.lemonade-nexus.io", "lemonade-nexus.io"));
    EXPECT_TRUE(discovered_name_in_domain("SN01.US-West.seip.Lemonade-Nexus.IO.", "lemonade-nexus.io"))
        << "case and a trailing dot do not matter";
    EXPECT_FALSE(discovered_name_in_domain("lemonade-nexus.io", "lemonade-nexus.io")) << "the apex is not a server";
    EXPECT_FALSE(discovered_name_in_domain("evil-lemonade-nexus.io", "lemonade-nexus.io"))
        << "a suffix without a dot is outside the domain";
    EXPECT_FALSE(discovered_name_in_domain("*.lemonade-nexus.io", "lemonade-nexus.io")) << "a wildcard is refused";
    EXPECT_FALSE(discovered_name_in_domain("a b.lemonade-nexus.io", "lemonade-nexus.io"));
    EXPECT_FALSE(discovered_name_in_domain("sn01.lemonade-nexus.io", "")) << "an empty domain matches nothing";
}

TEST(ServerDiscovery, KeepsTheCertificateNameBelowTheDomainAndDropsTheRest) {
    const uint16_t base = static_cast<uint16_t>(19000 + (getpid() % 1000));
    TlsEcho inside("sn01.us-west.seip.lemonade-nexus.io", base);
    TlsEcho apex("lemonade-nexus.io", static_cast<uint16_t>(base + 1));
    ASSERT_TRUE(inside.srv && apex.srv);

    auto found = lnsdk::discover_servers_at({"127.0.0.1"}, "lemonade-nexus.io", inside.port);
    ASSERT_TRUE(found.ok) << found.error;
    ASSERT_EQ(found.value.size(), 1u);
    EXPECT_EQ(found.value[0].host, "sn01.us-west.seip.lemonade-nexus.io");
    EXPECT_EQ(found.value[0].port, inside.port);
    EXPECT_EQ(found.value[0].address, "127.0.0.1");

    auto twice = lnsdk::discover_servers_at({"127.0.0.1", "127.0.0.1"}, "lemonade-nexus.io", inside.port);
    ASSERT_TRUE(twice.ok);
    EXPECT_EQ(twice.value.size(), 1u) << "the same name is reported once";

    EXPECT_FALSE(lnsdk::discover_servers_at({"127.0.0.1"}, "lemonade-nexus.io", apex.port).ok)
        << "the apex certificate is not a server";
    EXPECT_FALSE(lnsdk::discover_servers_at({"127.0.0.1"}, "other.example", inside.port).ok)
        << "a name outside the domain is dropped";
    const auto closed = lnsdk::discover_servers_at({"127.0.0.1"}, "lemonade-nexus.io", static_cast<uint16_t>(base + 2));
    EXPECT_FALSE(closed.ok) << "a closed port finds nothing";
    EXPECT_EQ(closed.http_status, 0);
}

TEST(ServerDiscovery, RefusesNamesThatAreNotHostnameLabels) {
    EXPECT_FALSE(lnsdk::discover_servers("lemonade-nexus.io", "us west").ok);
    EXPECT_FALSE(lnsdk::discover_servers("lemonade-nexus.io", "us.west").ok) << "a region is one label";
    EXPECT_FALSE(lnsdk::discover_servers("", "us-west").ok);
    EXPECT_FALSE(lnsdk::discover_servers_at({"127.0.0.1"}, "lemonade-nexus.io", 0).ok);
}
