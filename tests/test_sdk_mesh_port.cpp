// Mesh port: routing rules, the selection and auto router, TLS by group wildcard
// certificate, streaming passthrough, single-owner binding, and the C ABI.

#include <LemonadeNexusSDK/MeshPort.hpp>
#include <LemonadeNexusSDK/lemonade_nexus.h>

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <gtest/gtest.h>

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace {

using json = nlohmann::json;
using lnsdk::MeshPort;
using lnsdk::MeshPortMember;
using lnsdk::MeshPortStartResult;
namespace rules = lnsdk::mesh_port;

const std::string kDomain = ".team.lo.example";

std::vector<MeshPortMember> group_members() {
    return {
        {"self", "My Laptop", "10.64.0.2/32", true, true, true, 0.0},
        {"gpu", "GPU tower", "10.64.0.3/32", true, true, true, 20.0},
        {"fast", "Fast box", "10.64.0.4/32", true, true, true, 2.0},
        {"sleeper", "Sleeper", "10.64.0.5/32", true, false, true, 0.0},
        {"laptop", "Laptop", "10.64.0.6/32", false, true, true, 0.0},
        {"locked", "Locked box", "10.64.0.7/32", true, true, false, 1.0},
    };
}

uint16_t free_port() {
    httplib::Server probe;
    const int port = probe.bind_to_any_port("127.0.0.1");
    return static_cast<uint16_t>(port);
}

/// A running httplib server on a loopback port, stopped on destruction.
struct TestServer {
    httplib::Server server;
    std::thread thread;
    int port = 0;
    void start() {
        port = server.bind_to_any_port("127.0.0.1");
        thread = std::thread([this] { server.listen_after_bind(); });
        server.wait_until_ready();
    }
    ~TestServer() {
        server.stop();
        if (thread.joinable()) thread.join();
    }
};

/// A self-signed certificate and key in PEM.
struct TestCertificate {
    std::string certificate;
    std::string key;
};

TestCertificate make_certificate(const std::string& dns_name, long serial) {
    EVP_PKEY* key = EVP_EC_gen("P-256");
    X509* cert = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
    X509_gmtime_adj(X509_getm_notBefore(cert), -60);
    X509_gmtime_adj(X509_getm_notAfter(cert), 24 * 3600);
    X509_set_pubkey(cert, key);
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(dns_name.c_str()), -1, -1, 0);
    X509_set_issuer_name(cert, name);
    const auto san_text = "DNS:" + dns_name;
    X509_EXTENSION* san = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, san_text.c_str());
    X509_add_ext(cert, san, -1);
    X509_EXTENSION_free(san);
    X509_sign(cert, key, EVP_sha256());
    const auto drain = [](BIO* bio) {
        char* data = nullptr;
        const long size = BIO_get_mem_data(bio, &data);
        std::string text(data, static_cast<size_t>(size));
        BIO_free(bio);
        return text;
    };
    TestCertificate out;
    BIO* bio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(bio, cert);
    out.certificate = drain(bio);
    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr);
    out.key = drain(bio);
    X509_free(cert);
    EVP_PKEY_free(key);
    return out;
}

lnsdk::MeshPortCertificate wildcard(long serial = 1) {
    const auto pem = make_certificate("*.team.lo.example", serial);
    return {"*.team.lo.example", pem.certificate, pem.key, 0};
}

/// A peer lemond reached through mesh egress, and a local service.
class MeshPortTest : public ::testing::Test {
protected:
    TestServer peer;
    TestServer local;
    std::mutex seen_mutex;
    std::string peer_authorization;
    std::string peer_model;
    std::string local_authorization;
    std::atomic<int> closed_egress{0};
    std::unique_ptr<MeshPort> port;
    uint16_t number = 0;
    std::mutex members_mutex;
    std::vector<MeshPortMember> members = group_members();

    void SetUp() override {
        peer.server.Get("/api/v1/health", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(R"({"status":"ok","all_models_loaded":[{"model_name":"PeerModel","is_busy":false}]})",
                            "application/json");
        });
        peer.server.Get("/api/v1/models", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(R"({"object":"list","data":[{"id":"PeerModel"},{"id":"Shared"}]})", "application/json");
        });
        peer.server.Get("/created", [](const httplib::Request&, httplib::Response& res) {
            res.status = 201;
            res.set_content("made", "application/x-mesh-test");
        });
        peer.server.Post("/api/v1/chat/completions", [this](const httplib::Request& req, httplib::Response& res) {
            const auto body = json::parse(req.body, nullptr, false);
            {
                std::lock_guard lock(seen_mutex);
                peer_authorization = req.get_header_value("Authorization");
                peer_model = body.is_object() ? body.value("model", "") : "";
            }
            if (body.is_object() && body.value("stream", false)) {
                res.set_chunked_content_provider("text/event-stream", [](size_t offset, httplib::DataSink& sink) {
                    if (offset > 0) { sink.done(); return true; }
                    const std::string first = "data: {\"n\":1}\n\n";
                    const std::string rest = "data: {\"n\":2}\n\ndata: [DONE]\n\n";
                    sink.write(first.data(), first.size());
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    sink.write(rest.data(), rest.size());
                    return true;
                });
                return;
            }
            res.set_content(json{{"served_by", "peer"}, {"model", body.value("model", "")}}.dump(), "application/json");
        });
        peer.start();

        local.server.Get("/api/v1/models", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(R"({"object":"list","data":[{"id":"LocalModel"}]})", "application/json");
        });
        local.server.Post("/api/v1/chat/completions", [this](const httplib::Request& req, httplib::Response& res) {
            {
                std::lock_guard lock(seen_mutex);
                local_authorization = req.get_header_value("Authorization");
            }
            const auto body = json::parse(req.body, nullptr, false);
            res.set_content(json{{"served_by", "local"}, {"model", body.value("model", "")}}.dump(), "application/json");
        });
        local.start();
    }

    lnsdk::MeshPortBackend backend(std::function<std::optional<lnsdk::MeshPortCertificate>(const std::string&)> cert = {}) {
        lnsdk::MeshPortBackend b;
        b.load_members = [this]() -> std::optional<std::vector<MeshPortMember>> {
            std::lock_guard lock(members_mutex);
            return members;
        };
        b.self_node_id = [] { return std::string("self"); };
        const auto peer_port = static_cast<uint16_t>(peer.port);
        b.open_egress = [peer_port](const std::string& ip, uint16_t vport) -> uint16_t {
            return ip == "10.64.0.3" && vport == lnsdk::kMeshPortPeerServicePort ? peer_port : 0;
        };
        b.close_egress = [this](const std::string&, uint16_t) { ++closed_egress; };
        b.request_certificate = std::move(cert);
        return b;
    }

    void start(bool with_local = true) {
        MeshPort::Options options;
        options.refresh_interval = std::chrono::hours(1);
        port = std::make_unique<MeshPort>(backend(), options);
        number = free_port();
        const auto url = with_local ? "http://127.0.0.1:" + std::to_string(local.port) : std::string();
        ASSERT_EQ(port->start(number, url), MeshPortStartResult::Ok);
        port->refresh_now();
    }

    httplib::Result chat(httplib::Client& client, const std::string& model, bool stream = false,
                         const httplib::Headers& headers = {}) {
        return client.Post("/api/v1/chat/completions", headers, json{{"model", model}, {"stream", stream}}.dump(),
                           "application/json");
    }

    std::unique_ptr<httplib::SSLClient> secure(const std::string& name) {
        auto client = std::make_unique<httplib::SSLClient>(name, number);
        client->set_hostname_addr_map({{name, "127.0.0.1"}});
        client->enable_server_certificate_verification(false);
        return client;
    }
};

// ---------------------------------------------------------------------------
// Routing rules
// ---------------------------------------------------------------------------

TEST(MeshPortRules, HostRouting) {
    const auto members = group_members();
    const auto host = [&](const std::string& h, const std::string& sni = "") {
        return rules::host_target(h, sni, kDomain, members, "self");
    };
    EXPECT_EQ(rules::device_label("GPU Tower #2"), "gpu-tower-2");
    EXPECT_EQ(host("gpu-tower.team.lo.example:13306"), std::make_pair(0, std::string("gpu")));
    EXPECT_EQ(host("GPU-TOWER.team.lo.example", "gpu-tower.team.lo.example").second, "gpu");
    EXPECT_EQ(host("my-laptop.team.lo.example"), std::make_pair(0, std::string("local")));
    EXPECT_EQ(host("127.0.0.1:13306").second, "local");
    EXPECT_EQ(host("gpu-tower.team.lo.example", "fast-box.team.lo.example").first, 421);
    EXPECT_EQ(host("nobody.team.lo.example").first, 404);
    EXPECT_EQ(host("a.gpu-tower.team.lo.example").first, 404);
    EXPECT_EQ(host("gpu-tower.other.example").first, 421);
    EXPECT_EQ(rules::host_target("gpu-tower.team.lo.example", "", "", members, "self").first, 421);
}

TEST(MeshPortRules, ForwardTargetNeedsOnlineTier3AndConnect) {
    const auto members = group_members();
    EXPECT_EQ(rules::forward_target(members, "self", "gpu"), std::make_pair(0, std::string("10.64.0.3")));
    EXPECT_EQ(rules::forward_target(members, "self", "locked").first, 403);
    EXPECT_EQ(rules::forward_target(members, "self", "sleeper").first, 409);
    EXPECT_EQ(rules::forward_target(members, "self", "laptop").first, 409);
    EXPECT_EQ(rules::forward_target(members, "self", "missing").first, 404);
    EXPECT_EQ(rules::forward_target(members, "self", "self").first, 409);
}

TEST(MeshPortRules, AutoRouteOrder) {
    const auto members = group_members();
    std::vector<lnsdk::MeshPortPeerModels> peers(3);
    peers[0] = {"gpu", "GPU tower", 20, json::array({{{"model_name", "Big"}, {"is_busy", false}},
                                                     {{"model_name", "Both"}, {"is_busy", false}}}),
                {"Big", "Both", "Spare"}};
    peers[1] = {"fast", "Fast box", 2, json::array({{{"model_name", "Big"}, {"is_busy", true}},
                                                    {{"model_name", "Both"}, {"is_busy", false}}}),
                {"Big", "Both"}};
    peers[2] = {"locked", "Locked box", 1, json::array({{{"model_name", "Secret"}, {"is_busy", false}}}), {"Secret"}};
    const std::vector<std::string> local = {"Small"};
    const auto route = [&](const std::string& model) { return rules::auto_route(model, members, "self", local, peers); };
    EXPECT_EQ(route("GPU tower/Big").target, "gpu");
    EXPECT_EQ(route("GPU tower/Big").model, "Big");
    EXPECT_EQ(route("fast/Big").target, "fast");
    EXPECT_EQ(route("My Laptop/Small").target, "local");
    EXPECT_EQ(route("Sleeper/Big").status, 409);
    EXPECT_EQ(route("Locked box/Secret").status, 409);
    EXPECT_EQ(route("Small").target, "local");
    EXPECT_EQ(route("Big").target, "gpu") << "an idle loaded peer beats a busy one";
    EXPECT_EQ(route("Both").target, "fast") << "among idle loaded peers the lowest latency wins";
    EXPECT_EQ(route("Spare").target, "gpu") << "a peer that lists the model is the last choice";
    EXPECT_EQ(route("Secret").status, 404) << "a peer without connect permission is never chosen";
    EXPECT_EQ(route("").target, "local");

    const auto merged = rules::merge_models({{"object", "list"}, {"data", json::array({{{"id", "Small"}}})}},
                                            {peers[0], peers[1]});
    ASSERT_EQ(merged["data"].size(), 6u);
    EXPECT_EQ(merged["data"][1]["id"], "GPU tower/Big");
    EXPECT_EQ(merged["data"][4]["id"], "Fast box/Big");
}

TEST(MeshPortRules, UrlsDomainsAndLocalService) {
    const auto members = group_members();
    const auto urls = rules::device_urls(members, "self", kDomain, 13306, true);
    ASSERT_EQ(urls.size(), 3u);
    EXPECT_EQ(urls[0]["url"], "https://my-laptop.team.lo.example:13306");
    EXPECT_EQ(urls[0]["self"], true);
    EXPECT_EQ(urls[1]["url"], "https://gpu-tower.team.lo.example:13306");
    EXPECT_EQ(urls[2]["url"], "https://fast-box.team.lo.example:13306");
    EXPECT_EQ(rules::device_urls(members, "self", "", 13306, false)[0]["url"], "http://127.0.0.1:13306");

    EXPECT_EQ(rules::local_domain_from_certificate("*.Team.lo.example"), ".team.lo.example");
    EXPECT_EQ(rules::local_domain_from_certificate("laptop.capi.example"), "");
    EXPECT_EQ(rules::local_domain_from_certificate("*.capi.example"), "");
    EXPECT_EQ(rules::local_domain_from_certificate("*.a.b.lo.example"), "");
    EXPECT_EQ(rules::local_domain_from_certificate("*.team.lo."), "");

    EXPECT_EQ(rules::parse_local_service_url("http://127.0.0.1:13305"), std::make_pair(std::string("127.0.0.1"), uint16_t{13305}));
    EXPECT_EQ(rules::parse_local_service_url("http://[::1]:8000/")->first, "::1");
    EXPECT_FALSE(rules::parse_local_service_url("http://10.0.0.1:13305"));
    EXPECT_FALSE(rules::parse_local_service_url("https://127.0.0.1:13305"));
    EXPECT_FALSE(rules::parse_local_service_url("http://127.0.0.1:13305/api"));
    EXPECT_FALSE(rules::parse_local_service_url("http://127.0.0.1:70000"));
    EXPECT_FALSE(rules::parse_local_service_url("http://127.0.0.1.evil:80"));
}

// ---------------------------------------------------------------------------
// Listener
// ---------------------------------------------------------------------------

TEST_F(MeshPortTest, PlainHttpSelection) {
    start();
    auto status = port->status();
    EXPECT_EQ(status["running"], true);
    EXPECT_EQ(status["scheme"], "http");
    EXPECT_EQ(status["tls"]["state"], "waiting");
    ASSERT_EQ(status["urls"].size(), 1u);
    EXPECT_EQ(status["urls"][0]["url"], "http://127.0.0.1:" + std::to_string(number));
    EXPECT_EQ(status["devices"].size(), 3u);

    httplib::Client client("127.0.0.1", number);
    auto unselected = chat(client, "LocalModel");
    ASSERT_TRUE(unselected);
    EXPECT_EQ(unselected->status, 409) << "nothing is served before a selection";

    EXPECT_EQ(port->set_selection("laptop", ""), 409);
    EXPECT_EQ(port->set_selection("missing", ""), 404);
    EXPECT_EQ(port->set_selection("locked", ""), 403);

    ASSERT_EQ(port->set_selection("gpu", "peer-key"), 0);
    EXPECT_EQ(port->status()["selection"]["target"], "gpu");
    EXPECT_EQ(port->status()["selection"]["peer_key_set"], true);
    auto streamed = chat(client, "PeerModel", true, {{"Authorization", "Bearer caller-key"}});
    ASSERT_TRUE(streamed);
    EXPECT_EQ(streamed->status, 200);
    EXPECT_EQ(streamed->get_header_value("Content-Type"), "text/event-stream");
    EXPECT_EQ(streamed->body, "data: {\"n\":1}\n\ndata: {\"n\":2}\n\ndata: [DONE]\n\n");
    {
        std::lock_guard lock(seen_mutex);
        EXPECT_EQ(peer_authorization, "Bearer peer-key") << "the peer gets the selection key, never the caller's";
    }
    auto created = client.Get("/created");
    ASSERT_TRUE(created);
    EXPECT_EQ(created->status, 201);
    EXPECT_EQ(created->get_header_value("Content-Type"), "application/x-mesh-test");
    EXPECT_EQ(created->body, "made");

    ASSERT_EQ(port->set_selection("sleeper", ""), 0) << "an offline Tier 3 device can be selected";
    auto offline = chat(client, "PeerModel");
    ASSERT_TRUE(offline);
    EXPECT_EQ(offline->status, 409) << "an offline selection is refused, not served elsewhere";

    ASSERT_EQ(port->set_selection("self", ""), 0);
    EXPECT_EQ(port->status()["selection"]["target"], "local");
    EXPECT_EQ(port->status()["selection"]["peer_key_set"], false) << "a new target clears the peer key";
    auto served = chat(client, "LocalModel", false, {{"Authorization", "Bearer caller-key"}});
    ASSERT_TRUE(served);
    EXPECT_EQ(json::parse(served->body)["served_by"], "local");
    {
        std::lock_guard lock(seen_mutex);
        EXPECT_EQ(local_authorization, "Bearer caller-key");
    }

    ASSERT_EQ(port->set_selection("", ""), 0);
    unselected = chat(client, "LocalModel");
    ASSERT_TRUE(unselected);
    EXPECT_EQ(unselected->status, 409);

    auto foreign = client.Get("/api/v1/models", {{"Host", "attacker.example"}});
    ASSERT_TRUE(foreign);
    EXPECT_EQ(foreign->status, 421) << "a rebinding name is refused";
    auto cross = client.Get("/api/v1/models", {{"Origin", "https://attacker.example"}});
    ASSERT_TRUE(cross);
    EXPECT_EQ(cross->status, 403);
}

TEST_F(MeshPortTest, AutoRouter) {
    start();
    ASSERT_EQ(port->set_selection("auto", ""), 0);
    httplib::Client client("127.0.0.1", number);
    auto prefixed = chat(client, "GPU tower/PeerModel");
    ASSERT_TRUE(prefixed);
    EXPECT_EQ(json::parse(prefixed->body)["served_by"], "peer");
    {
        std::lock_guard lock(seen_mutex);
        EXPECT_EQ(peer_model, "PeerModel") << "the device prefix is removed";
    }
    auto loaded = chat(client, "PeerModel");
    ASSERT_TRUE(loaded);
    EXPECT_EQ(json::parse(loaded->body)["served_by"], "peer");
    auto kept = chat(client, "LocalModel");
    ASSERT_TRUE(kept);
    EXPECT_EQ(json::parse(kept->body)["served_by"], "local");
    auto missing = chat(client, "Nowhere");
    ASSERT_TRUE(missing);
    EXPECT_EQ(missing->status, 404);
    auto listing = client.Get("/api/v1/models");
    ASSERT_TRUE(listing);
    const auto ids = json::parse(listing->body)["data"];
    ASSERT_EQ(ids.size(), 3u);
    EXPECT_EQ(ids[0]["id"], "LocalModel");
    EXPECT_EQ(ids[1]["id"], "GPU tower/PeerModel");
}

TEST_F(MeshPortTest, LocalNeedsALocalService) {
    start(false);
    EXPECT_EQ(port->set_selection("local", ""), 409);
    EXPECT_EQ(port->set_selection("self", ""), 409);
    EXPECT_EQ(port->status()["local_service"], false);
}

TEST_F(MeshPortTest, TlsRoutesByName) {
    start();
    ASSERT_TRUE(port->install_certificate(wildcard()));
    auto status = port->status();
    EXPECT_EQ(status["scheme"], "https");
    EXPECT_EQ(status["tls"]["state"], "active");
    EXPECT_EQ(status["local_domain"], kDomain);
    ASSERT_EQ(status["urls"].size(), 3u);
    EXPECT_EQ(status["urls"][1]["url"], "https://gpu-tower.team.lo.example:" + std::to_string(number));

    auto gpu = secure("gpu-tower.team.lo.example");
    auto named = chat(*gpu, "PeerModel", false,
                      {{"Authorization", "Bearer caller-key"}, {"X-Lemonade-Peer-Authorization", "Bearer named-key"}});
    ASSERT_TRUE(named);
    EXPECT_EQ(json::parse(named->body)["served_by"], "peer");
    {
        std::lock_guard lock(seen_mutex);
        EXPECT_EQ(peer_authorization, "Bearer named-key");
    }
    auto mismatch = chat(*gpu, "LocalModel", false, {{"Host", "my-laptop.team.lo.example"}});
    ASSERT_TRUE(mismatch);
    EXPECT_EQ(mismatch->status, 421);

    auto nobody = secure("nobody.team.lo.example");
    auto unknown = chat(*nobody, "PeerModel");
    ASSERT_TRUE(unknown);
    EXPECT_EQ(unknown->status, 404);

    auto locked = secure("locked-box.team.lo.example");
    auto refused = chat(*locked, "PeerModel");
    ASSERT_TRUE(refused);
    EXPECT_EQ(refused->status, 403) << "no connect permission on that device";

    auto sleeper = secure("sleeper.team.lo.example");
    auto asleep = chat(*sleeper, "PeerModel");
    ASSERT_TRUE(asleep);
    EXPECT_EQ(asleep->status, 409);

    auto own = secure("my-laptop.team.lo.example");
    auto unselected = chat(*own, "LocalModel");
    ASSERT_TRUE(unselected);
    EXPECT_EQ(unselected->status, 409);
    ASSERT_EQ(port->set_selection("local", ""), 0);
    auto served = chat(*own, "LocalModel");
    ASSERT_TRUE(served);
    EXPECT_EQ(json::parse(served->body)["served_by"], "local") << "this device's name serves the selection";

    httplib::Client plain("127.0.0.1", number);
    EXPECT_FALSE(plain.Get("/api/v1/models")) << "plain HTTP stops after the switch to TLS";
}

TEST_F(MeshPortTest, TlsReloadsTheCertificateInPlace) {
    start();
    const auto serial_seen = [&] {
        long serial = 0;
        auto client = secure("my-laptop.team.lo.example");
        client->enable_server_certificate_verification(true);
        client->set_server_certificate_verifier([&](SSL* ssl) {
            X509* cert = SSL_get1_peer_certificate(ssl);
            if (cert) {
                serial = ASN1_INTEGER_get(X509_get0_serialNumber(cert));
                X509_free(cert);
            }
            return true;
        });
        client->Get("/api/v1/models");
        return serial;
    };
    ASSERT_TRUE(port->install_certificate(wildcard(11)));
    EXPECT_EQ(serial_seen(), 11);
    ASSERT_TRUE(port->install_certificate(wildcard(12)));
    EXPECT_EQ(serial_seen(), 12) << "a renewed certificate applies to new connections";
}

TEST_F(MeshPortTest, RejectsCertificatesItCannotServe) {
    start();
    auto single = wildcard();
    single.domain = "laptop.capi.example";
    EXPECT_FALSE(port->install_certificate(single));
    EXPECT_EQ(port->status()["tls"]["state"], "unsupported_certificate");
    EXPECT_EQ(port->status()["scheme"], "http");

    auto other = make_certificate("*.other.lo.example", 3);
    EXPECT_FALSE(port->install_certificate({"*.team.lo.example", other.certificate, other.key, 0}))
        << "the certificate must cover the domain it claims";
    auto mismatched = wildcard();
    mismatched.privkey_pem = other.key;
    EXPECT_FALSE(port->install_certificate(mismatched));
    EXPECT_FALSE(port->install_certificate({"*.team.lo.example", "not a certificate", "not a key", 0}));
    EXPECT_EQ(port->status()["scheme"], "http");
}

TEST_F(MeshPortTest, RequestsTheCertificateThroughTheBackend) {
    std::atomic<int> requests{0};
    std::mutex hostname_mutex;
    std::string hostname;
    MeshPort::Options options;
    options.refresh_interval = std::chrono::hours(1);
    port = std::make_unique<MeshPort>(backend([&](const std::string& name) -> std::optional<lnsdk::MeshPortCertificate> {
        ++requests;
        std::lock_guard lock(hostname_mutex);
        hostname = name;
        return wildcard(21);
    }), options);
    number = free_port();
    ASSERT_EQ(port->start(number, ""), MeshPortStartResult::Ok);
    port->refresh_now();
    EXPECT_GE(requests.load(), 1);
    {
        std::lock_guard lock(hostname_mutex);
        EXPECT_EQ(hostname, "My Laptop");
    }
    EXPECT_EQ(port->status()["tls"]["state"], "active");
    const int before = requests.load();
    port->refresh_now();
    EXPECT_EQ(requests.load(), before) << "a valid certificate is not requested again";
}

TEST_F(MeshPortTest, SingleOwner) {
    start();
    MeshPort second(backend());
    EXPECT_EQ(second.start(number, ""), MeshPortStartResult::PortInUse);
    EXPECT_EQ(port->start(static_cast<uint16_t>(number + 1), ""), MeshPortStartResult::AlreadyRunning);
    EXPECT_EQ(port->start(number, "http://127.0.0.1:1"), MeshPortStartResult::Ok) << "same port only updates the URL";

    TestServer other;
    other.start();
    MeshPort third(backend());
    EXPECT_EQ(third.start(static_cast<uint16_t>(other.port), ""), MeshPortStartResult::PortInUse);
    EXPECT_EQ(third.start(free_port(), "http://example.com:80"), MeshPortStartResult::InvalidArgument);
}

TEST_F(MeshPortTest, StopClearsTheSelectionAndAbortsStreams) {
    start();
    ASSERT_EQ(port->set_selection("gpu", "peer-key"), 0);
    port->stop();
    auto status = port->status();
    EXPECT_EQ(status["running"], false);
    EXPECT_TRUE(status["selection"]["target"].is_null());
    EXPECT_EQ(status["selection"]["peer_key_set"], false);
    EXPECT_EQ(port->set_selection("auto", ""), 409);
    ASSERT_EQ(port->start(number, ""), MeshPortStartResult::Ok) << "the port can be bound again";
}

TEST_F(MeshPortTest, RemovedPeerClosesItsEgress) {
    start();
    ASSERT_EQ(port->set_selection("gpu", ""), 0);
    httplib::Client client("127.0.0.1", number);
    ASSERT_TRUE(chat(client, "PeerModel"));
    {
        std::lock_guard lock(members_mutex);
        members.erase(members.begin() + 1);
    }
    port->refresh_now();
    EXPECT_EQ(closed_egress.load(), 1);
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

struct Client {
    ln_client_t* c = ln_create("localhost", 9);
    ~Client() { if (c) ln_destroy(c); }
};

json status_of(ln_client_t* client) {
    char* out = nullptr;
    EXPECT_EQ(ln_mesh_port_status(client, &out), LN_OK);
    auto parsed = json::parse(out ? out : "null", nullptr, false);
    ln_free(out);
    return parsed;
}

TEST(MeshPortCApi, ArgumentsAndLifecycle) {
    EXPECT_EQ(ln_mesh_port_start(nullptr, 0, nullptr), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_mesh_port_stop(nullptr), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_mesh_port_set_selection(nullptr, "auto", nullptr), LN_ERR_NULL_ARG);
    char* out = nullptr;
    EXPECT_EQ(ln_mesh_port_status(nullptr, &out), LN_ERR_NULL_ARG);

    Client client;
    ASSERT_NE(client.c, nullptr);
    EXPECT_EQ(ln_mesh_port_status(client.c, nullptr), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_mesh_port_set_selection(client.c, "auto", nullptr), LN_ERR_REJECTED);
    EXPECT_EQ(ln_mesh_port_stop(client.c), LN_OK);
    EXPECT_EQ(status_of(client.c)["running"], false);

    const auto number = free_port();
    EXPECT_EQ(ln_mesh_port_start(client.c, number, "http://198.51.100.1:80"), LN_ERR_REJECTED);
    ASSERT_EQ(ln_mesh_port_start(client.c, number, nullptr), LN_OK);
    auto status = status_of(client.c);
    EXPECT_EQ(status["running"], true);
    EXPECT_EQ(status["port"], number);
    EXPECT_EQ(ln_mesh_port_set_selection(client.c, "auto", "key"), LN_OK);
    EXPECT_EQ(ln_mesh_port_set_selection(client.c, "local", nullptr), LN_ERR_REJECTED);
    EXPECT_EQ(ln_mesh_port_set_selection(client.c, "no-such-node", nullptr), LN_ERR_NOT_FOUND);
    EXPECT_EQ(status_of(client.c)["selection"]["target"], "auto");

    Client other;
    EXPECT_EQ(ln_mesh_port_start(other.c, number, nullptr), LN_ERR_PORT_IN_USE);
    EXPECT_EQ(ln_mesh_port_stop(client.c), LN_OK);
    EXPECT_EQ(ln_mesh_port_start(other.c, number, nullptr), LN_OK) << "the port is free after stop";
}

}  // namespace
