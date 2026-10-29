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
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <set>
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
    const auto sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    socklen_t length = sizeof(address);
    uint16_t port = 0;
    if (::bind(sock, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 &&
        ::getsockname(sock, reinterpret_cast<sockaddr*>(&address), &length) == 0) {
        port = ntohs(address.sin_port);
    }
    httplib::detail::close_socket(sock);
    return port;
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

/// The peer's /slow response: six 8-byte chunks, 200 ms apart.
constexpr size_t kSlowChunks = 6;
constexpr size_t kSlowChunkSize = 8;
const std::string kSlowBody = "data: 0\ndata: 1\ndata: 2\ndata: 3\ndata: 4\ndata: 5\n";

/// A GET that runs on its own thread and reports when the first chunk arrives.
struct Stream {
    std::thread thread;
    std::mutex mutex;
    std::condition_variable changed;
    bool first{false};
    bool ok{false};
    std::string body;

    template <typename HttpClient>
    void begin(HttpClient& client, const std::string& path) {
        thread = std::thread([this, &client, path] {
            auto result = client.Get(path, [this](const char* data, size_t size) {
                std::lock_guard lock(mutex);
                body.append(data, size);
                first = true;
                changed.notify_all();
                return true;
            });
            std::lock_guard lock(mutex);
            ok = result && result->status == 200;
        });
    }
    bool wait_first(std::chrono::milliseconds limit) {
        std::unique_lock lock(mutex);
        return changed.wait_for(lock, limit, [this] { return first; });
    }
    void finish() {
        if (thread.joinable()) thread.join();
    }
    ~Stream() { finish(); }
};

bool wait_for_tls_state(MeshPort& port, const std::string& state, std::chrono::milliseconds limit) {
    const auto deadline = std::chrono::steady_clock::now() + limit;
    while (port.status()["tls"]["state"] != state) {
        if (std::chrono::steady_clock::now() > deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return true;
}

/// A peer lemond reached through mesh egress, and a local service. `slow` and
/// `guarded` are further peers that a test starts when it needs them.
class MeshPortTest : public ::testing::Test {
protected:
    TestServer peer;
    TestServer local;
    TestServer slow;
    TestServer guarded;
    std::mutex seen_mutex;
    std::string peer_authorization;
    std::string peer_model;
    std::string local_authorization;
    std::atomic<int> closed_egress{0};
    std::atomic<int> peer_model_listings{0};
    std::unique_ptr<MeshPort> port;
    uint16_t number = 0;
    std::mutex members_mutex;
    std::vector<MeshPortMember> members = group_members();
    MeshPort::Options options = [] {
        MeshPort::Options o;
        o.refresh_interval = std::chrono::hours(1);
        return o;
    }();

    void SetUp() override {
        peer.server.Get("/api/v1/health", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(R"({"status":"ok","all_models_loaded":[{"model_name":"PeerModel","is_busy":false}]})",
                            "application/json");
        });
        peer.server.Get("/api/v1/models", [this](const httplib::Request&, httplib::Response& res) {
            ++peer_model_listings;
            res.set_content(R"({"object":"list","data":[{"id":"PeerModel"},{"id":"Shared"}]})", "application/json");
        });
        peer.server.Get("/created", [](const httplib::Request&, httplib::Response& res) {
            res.status = 201;
            res.set_content("made", "application/x-mesh-test");
        });
        peer.server.Get("/slow", [](const httplib::Request&, httplib::Response& res) {
            res.set_chunked_content_provider("text/event-stream", [](size_t offset, httplib::DataSink& sink) {
                const auto index = offset / kSlowChunkSize;
                if (index >= kSlowChunks) {
                    sink.done();
                    return true;
                }
                if (index > 0) std::this_thread::sleep_for(std::chrono::milliseconds(200));
                const auto chunk = kSlowBody.substr(index * kSlowChunkSize, kSlowChunkSize);
                sink.write(chunk.data(), chunk.size());
                return true;
            });
        });
        const auto delayed = [](const char* body) {
            return [body](const httplib::Request&, httplib::Response& res) {
                std::this_thread::sleep_for(std::chrono::milliseconds(2500));
                res.set_content(body, "application/json");
            };
        };
        slow.server.Get("/api/v1/health", delayed(R"({"status":"ok","all_models_loaded":[]})"));
        slow.server.Get("/api/v1/models", delayed(R"({"object":"list","data":[{"id":"SlowModel"}]})"));
        const auto keyed = [](const char* body) {
            return [body](const httplib::Request& req, httplib::Response& res) {
                if (req.get_header_value("Authorization") != "Bearer right-key") {
                    res.status = 401;
                    res.set_content(R"({"error":"invalid API key"})", "application/json");
                    return;
                }
                res.set_content(body, "application/json");
            };
        };
        guarded.server.Get("/api/v1/health", keyed(R"({"status":"ok","all_models_loaded":[{"model_name":"Guarded","is_busy":false}]})"));
        guarded.server.Get("/api/v1/models", keyed(R"({"object":"list","data":[{"id":"Guarded"}]})"));
        guarded.server.Post("/api/v1/chat/completions", keyed(R"({"served_by":"guarded"})"));
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
        const auto slow_port = static_cast<uint16_t>(slow.port);
        const auto guarded_port = static_cast<uint16_t>(guarded.port);
        b.open_egress = [=](const std::string& ip, uint16_t vport) -> uint16_t {
            if (vport != lnsdk::kMeshPortPeerServicePort) return 0;
            if (ip == "10.64.0.3") return peer_port;
            if (ip == "10.64.0.8") return slow_port;
            if (ip == "10.64.0.9") return guarded_port;
            return 0;
        };
        b.close_egress = [this](const std::string&, uint16_t) { ++closed_egress; };
        b.ensure_certificate = std::move(cert);
        return b;
    }

    /// Adds a Tier 3 member at `ip` that a started extra server answers for.
    void add_member(const std::string& node_id, const std::string& name, const std::string& ip) {
        std::lock_guard lock(members_mutex);
        members.push_back({node_id, name, ip + "/32", true, true, true, 5.0});
    }

    void start(bool with_local = true) {
        port = std::make_unique<MeshPort>(backend(), options);
        number = free_port();
        const auto url = with_local ? "http://127.0.0.1:" + std::to_string(local.port) : std::string();
        ASSERT_EQ(port->start(number, url), MeshPortStartResult::Ok);
        port->refresh_now();
    }

    template <typename HttpClient>
    httplib::Result chat(HttpClient& client, const std::string& model, bool stream = false,
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

TEST(MeshPortRules, AmbiguousNamesRouteToNoDeviceAndGetNodeIdUrls) {
    auto members = group_members();
    members.push_back({"work1", "Work PC", "10.64.0.8/32", true, true, true, 3.0});
    members.push_back({"work2", "work-pc", "10.64.0.9/32", true, true, true, 4.0});
    const auto host = [&](const std::string& h) { return rules::host_target(h, "", kDomain, members, "self"); };
    const auto ambiguous = host("work-pc.team.lo.example");
    EXPECT_EQ(ambiguous.first, 409);
    EXPECT_NE(ambiguous.second.find("work1"), std::string::npos);
    EXPECT_NE(ambiguous.second.find("work2"), std::string::npos);
    EXPECT_EQ(host("work1.team.lo.example"), std::make_pair(0, std::string("work1")));
    EXPECT_EQ(host("work2.team.lo.example"), std::make_pair(0, std::string("work2")));
    EXPECT_EQ(host("gpu-tower.team.lo.example"), std::make_pair(0, std::string("gpu")))
        << "a unique name still routes";

    const auto urls = rules::device_urls(members, "self", kDomain, 13306, true);
    ASSERT_EQ(urls.size(), 5u);
    EXPECT_EQ(urls[3]["url"], "https://work1.team.lo.example:13306") << "a colliding name gets its node id";
    EXPECT_EQ(urls[4]["url"], "https://work2.team.lo.example:13306");
    EXPECT_EQ(urls[1]["url"], "https://gpu-tower.team.lo.example:13306");
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
    const std::vector<std::string> local = {"Small", "org/Small", "GPU tower/Both"};
    const auto route = [&](const std::string& model) { return rules::auto_route(model, members, "self", local, peers); };
    EXPECT_EQ(route("GPU tower/Big").target, "gpu");
    EXPECT_EQ(route("GPU tower/Big").model, "Big");
    EXPECT_EQ(route("fast/Big").target, "fast");
    EXPECT_EQ(route("My Laptop/Small").target, "local");
    EXPECT_EQ(route("My Laptop/Small").model, "Small");
    EXPECT_EQ(route("Sleeper/Big").status, 409);
    EXPECT_EQ(route("Locked box/Secret").status, 409);
    EXPECT_EQ(route("Small").target, "local");
    EXPECT_EQ(route("org/Small").target, "local") << "a local ID with '/' is not a device name";
    EXPECT_EQ(route("org/Small").model, "org/Small") << "the local ID is sent unchanged";
    EXPECT_EQ(route("GPU tower/Both").target, "local") << "an exact local ID wins over a device prefix";
    EXPECT_EQ(route("GPU tower/Both").model, "GPU tower/Both");
    EXPECT_EQ(route("Big").target, "gpu") << "an idle loaded peer beats a busy one";
    EXPECT_EQ(route("Both").target, "fast") << "among idle loaded peers the lowest latency wins";
    EXPECT_EQ(route("Spare").target, "gpu") << "a peer that lists the model is the last choice";
    EXPECT_EQ(route("Secret").status, 404) << "a peer without connect permission is never chosen";
    EXPECT_EQ(route("").target, "local");

    auto refused = peers;
    refused[0].models_status = 401;
    const auto spare = rules::auto_route("Spare", members, "self", local, refused);
    EXPECT_EQ(spare.status, 404) << "a peer that refused the peer key offers nothing";
    EXPECT_EQ(spare.refused, std::vector<std::string>{"GPU tower"});
    EXPECT_NE(spare.error.find("GPU tower"), std::string::npos) << spare.error;
    EXPECT_EQ(rules::auto_route("Big", members, "self", local, refused).target, "fast")
        << "a busy peer that accepts the key beats an idle one that refused it";
    EXPECT_EQ(rules::auto_route("GPU tower/Big", members, "self", local, refused).target, "gpu")
        << "an explicit device name is still honored; the peer answers 401 itself";

    const auto merged = rules::merge_models({{"object", "list"}, {"data", json::array({{{"id", "Small"}}})}},
                                            {peers[0], peers[1]});
    ASSERT_EQ(merged["data"].size(), 6u);
    EXPECT_EQ(merged["data"][1]["id"], "GPU tower/Big");
    EXPECT_EQ(merged["data"][4]["id"], "Fast box/Big");
}

// Every model a device lists appears in the merged listing with a loaded flag
// from its health all_models_loaded, so a client can badge loaded models.
TEST(MeshPortRules, MergedModelsCarryALoadedFlag) {
    lnsdk::MeshPortPeerModels gpu{"gpu", "GPU tower", 20,
                                  json::array({{{"model_name", "Big"}, {"is_busy", true}}, "junk", {{"other", 1}}}),
                                  {"Big", "Spare"}};
    lnsdk::MeshPortPeerModels quiet{"fast", "Fast box", 2, json(), {"Idle"}};  // health gave no list
    const auto merged = rules::merge_models({{"object", "list"}, {"data", json::array({{{"id", "Small"}}})}},
                                            {gpu, quiet});
    ASSERT_EQ(merged["data"].size(), 4u);
    EXPECT_FALSE(merged["data"][0].contains("loaded")) << "local entries pass through unchanged";
    EXPECT_EQ(merged["data"][1]["id"], "GPU tower/Big");
    EXPECT_EQ(merged["data"][1]["loaded"], true);
    EXPECT_EQ(merged["data"][2]["id"], "GPU tower/Spare");
    EXPECT_EQ(merged["data"][2]["loaded"], false);
    EXPECT_EQ(merged["data"][3]["loaded"], false);
    EXPECT_EQ(rules::loaded_model_names(gpu), (std::set<std::string>{"Big"}));
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
    EXPECT_EQ(ids[1]["loaded"], true);
    EXPECT_EQ(ids[2]["id"], "GPU tower/Shared");
    EXPECT_EQ(ids[2]["loaded"], false);
    // The status counts what that probe found; it sends no request itself.
    const int listings = peer_model_listings.load();
    bool found = false;
    const auto status = port->status();
    for (const auto& device : status["devices"]) {
        if (device["node_id"] != "gpu") continue;
        found = true;
        EXPECT_EQ(device["models_count"], 2);
        EXPECT_EQ(device["loaded_count"], 1);
    }
    EXPECT_TRUE(found);
    EXPECT_EQ(peer_model_listings.load(), listings);
}

TEST_F(MeshPortTest, AutoRouterSkipsDevicesThatRefuseTheKey) {
    guarded.start();
    add_member("guarded", "Guarded box", "10.64.0.9");
    start();
    ASSERT_EQ(port->set_selection("auto", "wrong-key"), 0);
    httplib::Client client("127.0.0.1", number);
    auto refused = chat(client, "Guarded");
    ASSERT_TRUE(refused);
    EXPECT_EQ(refused->status, 404) << "a device that answers 401 to the peer key is never chosen";
    EXPECT_NE(refused->body.find("Guarded box"), std::string::npos) << refused->body;
    auto listing = client.Get("/api/v1/models");
    ASSERT_TRUE(listing);
    for (const auto& model : json::parse(listing->body)["data"]) {
        EXPECT_NE(model["id"], "Guarded box/Guarded") << "a refused device lists no models";
    }
    auto still_peer = chat(client, "PeerModel");
    ASSERT_TRUE(still_peer);
    EXPECT_EQ(json::parse(still_peer->body)["served_by"], "peer");

    ASSERT_EQ(port->set_selection("auto", "right-key"), 0);
    auto served = chat(client, "Guarded");
    ASSERT_TRUE(served);
    EXPECT_EQ(served->status, 200);
    EXPECT_EQ(json::parse(served->body)["served_by"], "guarded") << "a new key probes the device again";
}

TEST_F(MeshPortTest, PeerProbesRunConcurrently) {
    slow.start();
    add_member("slow", "Slow box", "10.64.0.8");
    options.peer_probe_deadline = std::chrono::seconds(1);
    start();
    ASSERT_EQ(port->set_selection("auto", ""), 0);
    httplib::Client client("127.0.0.1", number);
    client.set_read_timeout(10, 0);
    const auto timed = [&] {
        const auto began = std::chrono::steady_clock::now();
        auto listing = client.Get("/api/v1/models");
        const auto took = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - began);
        return std::make_pair(std::move(listing), took);
    };
    auto [listing, took] = timed();
    ASSERT_TRUE(listing);
    EXPECT_EQ(listing->status, 200);
    const auto ids = json::parse(listing->body)["data"];
    ASSERT_EQ(ids.size(), 3u) << listing->body;
    EXPECT_EQ(ids[1]["id"], "GPU tower/PeerModel") << "the fast peer is listed";
    EXPECT_LT(took.count(), 2000) << "a slow peer does not delay the listing past the deadline";
    EXPECT_EQ(peer_model_listings.load(), 1);

    auto [again, took_again] = timed();
    ASSERT_TRUE(again);
    EXPECT_EQ(json::parse(again->body)["data"].size(), 3u);
    EXPECT_LT(took_again.count(), 500) << "a repeated listing is served from the cache";
    EXPECT_EQ(peer_model_listings.load(), 1) << "the peer is not probed again within the interval";
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

    auto gpu = secure("gpu-tower.team.lo.example");
    gpu->set_read_timeout(10, 0);
    Stream stream;
    stream.begin(*gpu, "/slow");
    ASSERT_TRUE(stream.wait_first(std::chrono::seconds(3)));
    ASSERT_TRUE(port->install_certificate(wildcard(12)));
    EXPECT_EQ(port->status()["tls"]["state"], "active");
    EXPECT_EQ(serial_seen(), 12) << "a renewed certificate applies to new connections";
    stream.finish();
    EXPECT_TRUE(stream.ok) << "a stream that spans the renewal is not reset";
    EXPECT_EQ(stream.body, kSlowBody);
}

TEST_F(MeshPortTest, TlsActivationWaitsForOpenStreams) {
    start();
    ASSERT_EQ(port->set_selection("gpu", ""), 0);
    httplib::Client plain("127.0.0.1", number);
    plain.set_read_timeout(10, 0);
    Stream stream;
    stream.begin(plain, "/slow");
    ASSERT_TRUE(stream.wait_first(std::chrono::seconds(3)));

    ASSERT_TRUE(port->install_certificate(wildcard(41)));
    auto status = port->status();
    EXPECT_EQ(status["tls"]["state"], "activating") << "the switch waits for the open stream";
    EXPECT_EQ(status["scheme"], "http");
    EXPECT_EQ(status["tls"]["domain"], "*.team.lo.example");
    httplib::Client second("127.0.0.1", number);
    auto served = second.Get("/created");
    ASSERT_TRUE(served);
    EXPECT_EQ(served->status, 201) << "the plain listener keeps serving while it drains";

    stream.finish();
    EXPECT_TRUE(stream.ok) << "the stream that was open at install time completes";
    EXPECT_EQ(stream.body, kSlowBody);
    ASSERT_TRUE(wait_for_tls_state(*port, "active", std::chrono::seconds(5)))
        << "the switch runs once the last plain request finishes";
    status = port->status();
    EXPECT_EQ(status["scheme"], "https");
    EXPECT_EQ(status["local_domain"], kDomain);
    auto gpu = secure("gpu-tower.team.lo.example");
    auto created = gpu->Get("/created");
    ASSERT_TRUE(created);
    EXPECT_EQ(created->status, 201);
    httplib::Client late("127.0.0.1", number);
    EXPECT_FALSE(late.Get("/created")) << "plain HTTP stops after the switch";
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

TEST_F(MeshPortTest, ProvisionsTheCertificateOncePerStart) {
    std::atomic<int> requests{0};
    std::mutex dir_mutex;
    std::string seen_dir;
    MeshPort::Options options;
    options.refresh_interval = std::chrono::hours(1);
    port = std::make_unique<MeshPort>(backend([&](const std::string& dir) -> std::optional<lnsdk::MeshPortCertificate> {
        ++requests;
        std::lock_guard lock(dir_mutex);
        seen_dir = dir;
        return wildcard(21);
    }), options);
    number = free_port();
    ASSERT_EQ(port->start(number, ""), MeshPortStartResult::Ok);
    port->refresh_now();
    EXPECT_EQ(requests.load(), 0) << "no certificate directory, no request";
    EXPECT_EQ(port->status()["tls"]["error"], "No certificate directory is set");
    port->set_certificate_dir("/certs/group");
    port->refresh_now();
    EXPECT_EQ(requests.load(), 1);
    {
        std::lock_guard lock(dir_mutex);
        EXPECT_EQ(seen_dir, "/certs/group");
    }
    EXPECT_EQ(port->status()["tls"]["state"], "active");
    port->refresh_now();
    EXPECT_EQ(requests.load(), 1) << "the SDK renewer, not the port, schedules later requests";
}

TEST_F(MeshPortTest, RenewalEventReloadsTheCertificate) {
    start();
    const auto dir = std::filesystem::temp_directory_path() / ("mesh-port-test-" + std::to_string(number));
    std::filesystem::create_directories(dir);
    const auto write = [&](const lnsdk::MeshPortCertificate& cert) {
        std::ofstream(dir / "fullchain.pem", std::ios::binary) << cert.fullchain_pem;
        std::ofstream(dir / "privkey.pem", std::ios::binary) << cert.privkey_pem;
    };
    const auto fullchain = (dir / "fullchain.pem").string();
    const auto key = (dir / "privkey.pem").string();
    port->set_certificate_dir(dir.string());
    write(wildcard(31));
    port->certificate_renewed("laptop", "*.team.lo.example", fullchain, key);
    EXPECT_EQ(port->status()["scheme"], "http") << "events for another target are ignored";
    port->certificate_renewed("*", "*.team.lo.example", "/elsewhere/fullchain.pem", "/elsewhere/privkey.pem");
    EXPECT_EQ(port->status()["scheme"], "http") << "events for another directory are ignored";
    port->certificate_renewed("*", "*.team.lo.example", fullchain, key);
    EXPECT_EQ(port->status()["scheme"], "https");
    EXPECT_EQ(port->status()["tls"]["state"], "active");
    EXPECT_GT(port->status()["tls"]["expires_at"].get<uint64_t>(), 0u);
    std::filesystem::remove_all(dir);
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

// The status shows what each device's SDK answers at /.nexus/catalog, read on
// the refresh thread, so an app can show "lemonade 2026.46.0" or "unknown
// app" without sending a request, and the catalog this device registered.
TEST_F(MeshPortTest, StatusListsEachDevicesCatalogAndTheLocalOne) {
    peer.server.Get("/.nexus/catalog", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(R"({"version":2,"app":{"name":"lemonade","version":"2026.46.0"},)"
                        R"("families":[{"name":"inference","routes":[]},{"name":"management","routes":[]}]})",
                        "application/json");
    });
    const json local_catalog = {{"version", 1}, {"app", {{"name", "local-app"}, {"version", "0.1"}}},
                                {"families", json::array()}};
    auto b = backend();
    b.local_catalog = [local_catalog] { return local_catalog; };
    port = std::make_unique<MeshPort>(std::move(b), options);
    number = free_port();
    ASSERT_EQ(port->start(number, ""), MeshPortStartResult::Ok);
    port->refresh_now();

    const auto status = port->status();
    EXPECT_EQ(status["catalog"], local_catalog);
    std::map<std::string, json> devices;
    for (const auto& device : status["devices"]) devices[device["node_id"]] = device;
    ASSERT_TRUE(devices.count("gpu"));
    EXPECT_EQ(devices["gpu"]["app"]["name"], "lemonade");
    EXPECT_EQ(devices["gpu"]["app"]["version"], "2026.46.0");
    EXPECT_EQ(devices["gpu"]["families"], json::array({"inference", "management"}));
    EXPECT_EQ(devices["gpu"]["catalog_status"], 200);
    // The fast box has no mesh path in this fixture: an unknown app.
    ASSERT_TRUE(devices.count("fast"));
    EXPECT_EQ(devices["fast"]["app"]["name"], "");
    EXPECT_EQ(devices["fast"]["families"], json::array());
    EXPECT_EQ(devices["fast"]["catalog_status"], 0);

    // The model probe carries the cached catalog too.
    ASSERT_EQ(port->set_selection("auto", ""), 0);
    httplib::Client client("127.0.0.1", number);
    const auto listing = client.Get("/api/v1/models");
    ASSERT_TRUE(listing);
    EXPECT_EQ(listing->status, 200);
}

// A device whose service has no catalog answers 404 for /.nexus/catalog from
// the service itself; the status reports that status and no app.
TEST_F(MeshPortTest, ADeviceWithoutACatalogIsAnUnknownApp) {
    start();
    const auto status = port->status();
    EXPECT_EQ(status["catalog"], json::object()) << "no local catalog without a backend function";
    for (const auto& device : status["devices"]) {
        if (device["node_id"] != "gpu") continue;
        EXPECT_EQ(device["catalog_status"], 404);
        EXPECT_EQ(device["app"]["name"], "");
        EXPECT_EQ(device["app"]["version"], "");
    }
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

// A bridge carries connections over the mesh path that was current when they
// opened. A new relay allocation for the device closes it, so the next request
// opens a fresh one; an unchanged path keeps it.
TEST_F(MeshPortTest, ARelayChangeClosesTheEgress) {
    start();
    ASSERT_EQ(port->set_selection("gpu", ""), 0);
    httplib::Client client("127.0.0.1", number);
    const auto set_relay = [&](const std::string& relay) {
        std::lock_guard lock(members_mutex);
        members[1].relay_endpoint = relay;
    };
    ASSERT_TRUE(chat(client, "PeerModel"));
    set_relay("198.51.100.7:9103");
    port->refresh_now();
    EXPECT_EQ(closed_egress.load(), 1) << "moving onto a relay closes the bridge";
    ASSERT_TRUE(chat(client, "PeerModel"));
    port->refresh_now();
    EXPECT_EQ(closed_egress.load(), 1) << "the same relay keeps the bridge";
    set_relay("203.0.113.9:9103");
    port->refresh_now();
    EXPECT_EQ(closed_egress.load(), 2) << "a new relay allocation closes the bridge";
}

// A request whose bridge answers nothing at once gets a new bridge and is sent
// once more before it is answered.
TEST_F(MeshPortTest, ADeadBridgeIsReplacedOnceBeforeTheAnswer) {
    std::atomic<int> opened{0};
    const auto dead = free_port();  // nothing listens there: the bridge is gone
    auto b = backend();
    const auto peer_port = static_cast<uint16_t>(peer.port);
    b.open_egress = [&, dead, peer_port](const std::string& ip, uint16_t) -> uint16_t {
        if (ip != "10.64.0.3") return 0;
        return opened++ == 0 || closed_egress.load() == 0 ? dead : peer_port;
    };
    port = std::make_unique<MeshPort>(std::move(b), options);
    number = free_port();
    ASSERT_EQ(port->start(number, ""), MeshPortStartResult::Ok);
    port->refresh_now();
    closed_egress = 0;
    opened = 0;
    ASSERT_EQ(port->set_selection("gpu", ""), 0);
    httplib::Client client("127.0.0.1", number);
    auto served = chat(client, "PeerModel");
    ASSERT_TRUE(served);
    EXPECT_EQ(served->status, 200);
    EXPECT_EQ(json::parse(served->body)["served_by"], "peer");
    EXPECT_EQ(closed_egress.load(), 1);

    // A bridge that stays dead is replaced only once, then answered with 502.
    port->stop();
    auto always_dead = backend();
    always_dead.open_egress = [dead](const std::string&, uint16_t) -> uint16_t { return dead; };
    port = std::make_unique<MeshPort>(std::move(always_dead), options);
    ASSERT_EQ(port->start(number, ""), MeshPortStartResult::Ok);
    port->refresh_now();
    closed_egress = 0;
    ASSERT_EQ(port->set_selection("gpu", ""), 0);
    auto failed = chat(client, "PeerModel");
    ASSERT_TRUE(failed);
    EXPECT_EQ(failed->status, 502);
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
    EXPECT_EQ(ln_mesh_port_set_cert_dir(nullptr, "/tmp"), LN_ERR_NULL_ARG);
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
