// Permission-based routing of an exposed service: catalog validation, the
// route policy, the ingress front end over the in-process mesh (a peer
// reaches the service through BoringtunMesh egress and ingress, as in
// test_mesh_ingress), the refusal callback, and the C ABI.

#include <LemonadeNexusSDK/BoringtunMesh.hpp>
#include <LemonadeNexusSDK/ServiceIngress.hpp>
#include <LemonadeNexusSDK/lemonade_nexus.h>

#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace {

using json = nlohmann::json;
using lnsdk::IngressDeniedEvent;
using lnsdk::MeshPeer;
using lnsdk::ServiceIngress;
namespace policy = lnsdk::service_ingress;

constexpr uint16_t kVport = 13305;

json sample_catalog() {
    return json{
        {"version", 3},
        {"app", {{"name", "lemonade"}, {"version", "2026.46.0"}}},
        {"families", json::array({
            {{"name", "inference"},
             {"routes", json::array({
                 {{"methods", json::array({"POST"})}, {"path", "/api/v1/chat/completions"}},
                 {{"methods", json::array({"GET"})}, {"prefix", "/api/v1/models"}},
             })}},
            {{"name", "management"},
             {"routes", json::array({
                 {{"methods", json::array({"GET"})}, {"path", "/api/v1/system-info"}},
                 {{"methods", json::array({"POST", "delete"})}, {"prefix", "/api/v1/load"}},
                 {{"methods", json::array({"GET"})}, {"path", "/stream"}},
             })}},
        })},
    };
}

lnsdk::ServiceCatalog parsed_sample() {
    auto parsed = policy::parse_catalog(sample_catalog());
    EXPECT_TRUE(parsed.ok) << parsed.error;
    return parsed.value;
}

std::string reason(const json& catalog) {
    const auto parsed = policy::parse_catalog(catalog);
    return parsed.ok ? std::string("accepted") : parsed.error;
}

}  // namespace

// ---------------------------------------------------------------------------
// Catalog validation
// ---------------------------------------------------------------------------

TEST(ServiceCatalog, AcceptsTheSampleAndKeepsItAsGiven) {
    const auto catalog = parsed_sample();
    EXPECT_EQ(catalog.version, 3u);
    EXPECT_EQ(catalog.app_name, "lemonade");
    EXPECT_EQ(catalog.app_version, "2026.46.0");
    ASSERT_EQ(catalog.families.size(), 2u);
    EXPECT_EQ(catalog.families[0].name, "inference");
    ASSERT_EQ(catalog.families[0].routes.size(), 2u);
    EXPECT_EQ(catalog.families[0].routes[0].path, "/api/v1/chat/completions");
    EXPECT_EQ(catalog.families[0].routes[1].prefix, "/api/v1/models");
    EXPECT_EQ(catalog.families[1].routes[1].methods, (std::vector<std::string>{"POST", "DELETE"}))
        << "method tokens are upper-cased";
    EXPECT_EQ(catalog.source, sample_catalog());

    // A catalog without an app and without families is valid: it registers nothing.
    const auto minimal = policy::parse_catalog(json{{"version", 0}, {"families", json::array()}});
    EXPECT_TRUE(minimal.ok) << minimal.error;
    EXPECT_EQ(minimal.value.app_name, "");
}

TEST(ServiceCatalog, FamilyNamesFollowTheRule) {
    for (const char* name : {"inference", "a", "0", "svc_1.x-y", "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0"}) {
        EXPECT_TRUE(policy::valid_family_name(name)) << name;
    }
    for (const char* name : {"", "Inference", "-x", "_x", ".x", "a b", "a/b", "svc:x",
                             "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01"}) {
        EXPECT_FALSE(policy::valid_family_name(name)) << name;
    }
    auto catalog = sample_catalog();
    catalog["families"][0]["name"] = "Inference";
    EXPECT_NE(reason(catalog).find("not [a-z0-9]"), std::string::npos) << reason(catalog);
    catalog["families"][0]["name"] = 7;
    EXPECT_NE(reason(catalog).find("needs a name"), std::string::npos);
}

TEST(ServiceCatalog, VersionIsARequiredUnsignedInteger) {
    auto catalog = sample_catalog();
    catalog.erase("version");
    EXPECT_NE(reason(catalog).find("version"), std::string::npos);
    catalog["version"] = -1;
    EXPECT_NE(reason(catalog).find("version"), std::string::npos);
    catalog["version"] = 1.5;
    EXPECT_NE(reason(catalog).find("version"), std::string::npos);
    catalog["version"] = "3";
    EXPECT_NE(reason(catalog).find("version"), std::string::npos);
    catalog["version"] = 3;
    EXPECT_EQ(reason(catalog), "accepted");
}

TEST(ServiceCatalog, DuplicateRoutesAndFamiliesAreRefused) {
    auto catalog = sample_catalog();
    // The same method and path in another family.
    catalog["families"][1]["routes"].push_back({{"methods", json::array({"post"})}, {"path", "/api/v1/chat/completions"}});
    EXPECT_NE(reason(catalog).find("listed twice"), std::string::npos) << reason(catalog);

    catalog = sample_catalog();
    catalog["families"][1]["name"] = "inference";
    EXPECT_NE(reason(catalog).find("listed twice"), std::string::npos);

    // The same value as a prefix and as a path are two routes.
    catalog = sample_catalog();
    catalog["families"][1]["routes"].push_back({{"methods", json::array({"GET"})}, {"path", "/api/v1/models"}});
    EXPECT_EQ(reason(catalog), "accepted");
    // Another method on the same path is another route.
    catalog = sample_catalog();
    catalog["families"][1]["routes"].push_back({{"methods", json::array({"PUT"})}, {"path", "/api/v1/chat/completions"}});
    EXPECT_EQ(reason(catalog), "accepted");
}

TEST(ServiceCatalog, MalformedRoutesAreRefused) {
    EXPECT_NE(reason(json::array()).find("object"), std::string::npos);
    EXPECT_NE(reason(json{{"version", 1}}).find("families"), std::string::npos);
    EXPECT_NE(reason(json{{"version", 1}, {"families", 3}}).find("families"), std::string::npos);
    EXPECT_NE(reason(json{{"version", 1}, {"app", "lemonade"}, {"families", json::array()}}).find("app"),
              std::string::npos);

    const auto with_route = [](json route) {
        return json{{"version", 1}, {"families", json::array({{{"name", "f"}, {"routes", json::array({std::move(route)})}}})}};
    };
    EXPECT_NE(reason(with_route({{"path", "/x"}})).find("methods"), std::string::npos);
    EXPECT_NE(reason(with_route({{"methods", json::array()}, {"path", "/x"}})).find("methods"), std::string::npos);
    EXPECT_NE(reason(with_route({{"methods", json::array({"G E T"})}, {"path", "/x"}})).find("method token"),
              std::string::npos);
    EXPECT_NE(reason(with_route({{"methods", json::array({"GET"})}})).find("exactly one"), std::string::npos);
    EXPECT_NE(reason(with_route({{"methods", json::array({"GET"})}, {"path", "/x"}, {"prefix", "/y"}})).find("exactly one"),
              std::string::npos);
    EXPECT_NE(reason(with_route({{"methods", json::array({"GET"})}, {"path", "x"}})).find("invalid path"),
              std::string::npos);
    EXPECT_NE(reason(with_route({{"methods", json::array({"GET"})}, {"prefix", "/x?y"}})).find("invalid prefix"),
              std::string::npos);
    EXPECT_NE(reason(with_route({{"methods", json::array({"GET"})}, {"path", "/x y"}})).find("invalid path"),
              std::string::npos);
    EXPECT_NE(reason(with_route("route")).find("object"), std::string::npos);
    EXPECT_EQ(reason(with_route({{"methods", json::array({"GET"})}, {"prefix", "/"}})), "accepted");
}

TEST(ServiceCatalog, RegistrationReplacesTheCatalogAndRoundTrips) {
    ServiceIngress ingress([] { return std::vector<MeshPeer>{}; });
    EXPECT_EQ(ingress.catalog(kVport), json::object());

    auto first = sample_catalog();
    ASSERT_TRUE(ingress.set_catalog(kVport, first).ok);
    EXPECT_EQ(ingress.catalog(kVport), first);
    EXPECT_EQ(ingress.catalog(8080), json::object()) << "another port has no catalog";

    auto second = sample_catalog();
    second["version"] = 4;
    second["families"].erase(1);
    ASSERT_TRUE(ingress.set_catalog(kVport, second).ok);
    EXPECT_EQ(ingress.catalog(kVport), second) << "a new catalog replaces the previous one";

    auto broken = sample_catalog();
    broken.erase("version");
    const auto refused = ingress.set_catalog(kVport, broken);
    EXPECT_FALSE(refused.ok);
    EXPECT_EQ(refused.http_status, 400);
    EXPECT_EQ(ingress.catalog(kVport), second) << "a refused catalog leaves the registered one in place";
    EXPECT_FALSE(ingress.set_catalog(0, first).ok);

    // Without a catalog the port bridges raw bytes; with one, only a tcp target works.
    const auto raw = ingress.bridge_target(8080, "unix:/run/x.sock");
    EXPECT_TRUE(raw.ok);
    EXPECT_FALSE(raw.front_end);
    EXPECT_EQ(raw.target, "unix:/run/x.sock");
    EXPECT_FALSE(ingress.bridge_target(kVport, "unix:/run/x.sock").ok);
    EXPECT_FALSE(ingress.bridge_target(kVport, "tcp:127.0.0.1:0").ok);
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

TEST(IngressPolicy, AdminAllowsEveryRegisteredRoute) {
    const auto catalog = parsed_sample();
    const std::vector<std::string> admin{"read", "admin"};
    for (const auto& [method, path] : std::vector<std::pair<std::string, std::string>>{
             {"POST", "/api/v1/chat/completions"}, {"GET", "/api/v1/models"}, {"GET", "/api/v1/system-info"},
             {"DELETE", "/api/v1/load/x"}}) {
        const auto decision = policy::evaluate(catalog, admin, method, path);
        EXPECT_EQ(decision.verdict, policy::IngressVerdict::Allowed) << method << " " << path;
        EXPECT_FALSE(decision.family.empty());
    }
    // admin does not register routes: an unknown path stays unregistered.
    EXPECT_EQ(policy::evaluate(catalog, admin, "GET", "/nope").verdict, policy::IngressVerdict::Unregistered);
}

TEST(IngressPolicy, AFamilyPermissionAllowsItsRoutesOnly) {
    const auto catalog = parsed_sample();
    const std::vector<std::string> inference{"connect_private", "svc:inference"};
    auto decision = policy::evaluate(catalog, inference, "POST", "/api/v1/chat/completions");
    EXPECT_EQ(decision.verdict, policy::IngressVerdict::Allowed);
    EXPECT_EQ(decision.family, "inference");
    EXPECT_EQ(decision.required, "svc:inference");

    decision = policy::evaluate(catalog, inference, "GET", "/api/v1/system-info");
    EXPECT_EQ(decision.verdict, policy::IngressVerdict::Denied);
    EXPECT_EQ(decision.family, "management");
    EXPECT_EQ(decision.required, "svc:management");

    // Permissions are exact tokens: no prefix or case folding.
    EXPECT_EQ(policy::evaluate(catalog, {"svc:inferences"}, "POST", "/api/v1/chat/completions").verdict,
              policy::IngressVerdict::Denied);
    EXPECT_EQ(policy::evaluate(catalog, {"Admin"}, "POST", "/api/v1/chat/completions").verdict,
              policy::IngressVerdict::Denied);
}

TEST(IngressPolicy, APrefixMatchesItselfAndThePathsBelowIt) {
    const auto catalog = parsed_sample();
    const std::vector<std::string> inference{"svc:inference"};
    EXPECT_EQ(policy::evaluate(catalog, inference, "GET", "/api/v1/models").verdict, policy::IngressVerdict::Allowed);
    EXPECT_EQ(policy::evaluate(catalog, inference, "GET", "/api/v1/models/").verdict, policy::IngressVerdict::Allowed);
    EXPECT_EQ(policy::evaluate(catalog, inference, "GET", "/api/v1/models/llama/info").verdict,
              policy::IngressVerdict::Allowed);
    EXPECT_EQ(policy::evaluate(catalog, inference, "GET", "/api/v1/modelsecret").verdict,
              policy::IngressVerdict::Unregistered)
        << "a prefix is a path segment boundary, not a string prefix";
    // A "/" prefix covers everything.
    lnsdk::ServiceCatalog all = policy::parse_catalog(json{{"version", 1}, {"families", json::array({
        {{"name", "all"}, {"routes", json::array({{{"methods", json::array({"GET"})}, {"prefix", "/"}}})}}})}}).value;
    EXPECT_EQ(policy::evaluate(all, {"svc:all"}, "GET", "/anything/at/all").verdict, policy::IngressVerdict::Allowed);
}

TEST(IngressPolicy, MethodMismatchAndUnknownPathsAreUnregistered) {
    const auto catalog = parsed_sample();
    const std::vector<std::string> admin{"admin"};
    auto decision = policy::evaluate(catalog, admin, "DELETE", "/api/v1/chat/completions");
    EXPECT_EQ(decision.verdict, policy::IngressVerdict::Unregistered);
    EXPECT_EQ(decision.family, "");
    EXPECT_EQ(decision.required, "");
    EXPECT_EQ(policy::evaluate(catalog, admin, "GET", "/api/v1/chat").verdict, policy::IngressVerdict::Unregistered);
    EXPECT_EQ(policy::evaluate(catalog, admin, "GET", "/api/v1/chat/completions/extra").verdict,
              policy::IngressVerdict::Unregistered)
        << "an exact path does not cover paths below it";
    // Methods compare case-insensitively; the listed ones were upper-cased.
    EXPECT_EQ(policy::evaluate(catalog, admin, "delete", "/api/v1/load/x").verdict, policy::IngressVerdict::Allowed);
}

TEST(IngressPolicy, EmptyPermissionsAreDeniedOnARegisteredRoute) {
    const auto catalog = parsed_sample();
    const auto decision = policy::evaluate(catalog, {}, "POST", "/api/v1/chat/completions");
    EXPECT_EQ(decision.verdict, policy::IngressVerdict::Denied);
    EXPECT_EQ(decision.required, "svc:inference");
    const auto body = policy::refusal_body(catalog, "nexus_permission_denied", "no", decision);
    EXPECT_EQ(body["code"], "nexus_permission_denied");
    EXPECT_EQ(body["family"], "inference");
    EXPECT_EQ(body["required"], "svc:inference");
    EXPECT_EQ(body["catalog_version"], 3);
    EXPECT_EQ(body["app"]["name"], "lemonade");
    EXPECT_EQ(body["app"]["version"], "2026.46.0");
}

TEST(IngressPolicy, TheFirstMatchingRouteInCatalogOrderWins) {
    const auto catalog = policy::parse_catalog(json{{"version", 1}, {"families", json::array({
        {{"name", "wide"}, {"routes", json::array({{{"methods", json::array({"GET"})}, {"prefix", "/x"}}})}},
        {{"name", "narrow"}, {"routes", json::array({{{"methods", json::array({"GET"})}, {"path", "/x/y"}}})}},
    })}}).value;
    EXPECT_EQ(policy::evaluate(catalog, {"svc:narrow"}, "GET", "/x/y").family, "wide");
    EXPECT_EQ(policy::evaluate(catalog, {"svc:narrow"}, "GET", "/x/y").verdict, policy::IngressVerdict::Denied);
    EXPECT_EQ(policy::evaluate(catalog, {"svc:wide"}, "GET", "/x/y").verdict, policy::IngressVerdict::Allowed);
}

// ---------------------------------------------------------------------------
// Front end over the mesh
// ---------------------------------------------------------------------------

namespace {

/// Device B exposes a local HTTP service with a catalog; device A reaches it
/// through the mesh. Both dataplanes and the netstacks are in-process; the
/// only real sockets are loopback TCP and the two mesh UDP sockets.
class ServiceIngressMeshTest : public ::testing::Test {
protected:
    httplib::Server service;
    std::thread service_thread;
    int service_port = 0;
    std::mutex seen_mutex;
    std::vector<std::pair<std::string, httplib::Headers>> seen;  // (path, headers) the service received

    std::mutex peers_mutex;
    std::vector<MeshPeer> peers;
    ServiceIngress ingress{[this] {
        std::lock_guard lock(peers_mutex);
        return peers;
    }};

    std::mutex events_mutex;
    std::condition_variable events_changed;
    std::vector<IngressDeniedEvent> events;

    lnsdk::BoringtunMesh b;  // the service device
    lnsdk::BoringtunMesh a;  // the peer
    std::pair<std::string, std::string> a_keys;
    std::pair<std::string, std::string> b_keys;
    uint16_t front_end_port = 0;

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        const auto record = [this](const httplib::Request& req) {
            std::lock_guard lock(seen_mutex);
            seen.emplace_back(req.path, req.headers);
        };
        service.Post("/api/v1/chat/completions", [=](const httplib::Request& req, httplib::Response& res) {
            record(req);
            res.set_content(json{{"served", true}, {"body", req.body}}.dump(), "application/json");
        });
        service.Get("/api/v1/models", [=](const httplib::Request& req, httplib::Response& res) {
            record(req);
            res.set_content(R"({"object":"list","data":[{"id":"M"}]})", "application/json");
        });
        service.Get("/api/v1/system-info", [=](const httplib::Request& req, httplib::Response& res) {
            record(req);
            res.set_content(R"({"system":"info"})", "application/json");
        });
        service.Get(".*", [=](const httplib::Request& req, httplib::Response& res) {
            record(req);
            if (req.path == "/stream") {
                res.set_chunked_content_provider("text/event-stream", [](size_t offset, httplib::DataSink& sink) {
                    if (offset >= 3 * 8) {
                        sink.done();
                        return true;
                    }
                    if (offset > 0) std::this_thread::sleep_for(150ms);
                    const std::string chunk = "data: " + std::to_string(offset / 8) + "\n";
                    sink.write(chunk.data(), chunk.size());
                    return true;
                });
                return;
            }
            res.status = 404;
            res.set_content("service 404", "text/plain");
        });
        service_port = service.bind_to_any_port("127.0.0.1");
        ASSERT_GT(service_port, 0);
        service_thread = std::thread([this] { service.listen_after_bind(); });
        service.wait_until_ready();

        ingress.set_denied_callback([this](const IngressDeniedEvent& event) {
            std::lock_guard lock(events_mutex);
            events.push_back(event);
            events_changed.notify_all();
        });

        a_keys = lnsdk::BoringtunMesh::generate_keypair();
        b_keys = lnsdk::BoringtunMesh::generate_keypair();
        lnsdk::BoringtunConfig bcfg;
        bcfg.private_key = b_keys.first;
        bcfg.public_key = b_keys.second;
        bcfg.tunnel_ip = "10.64.0.2/32";
        bcfg.allowed_ips = {"10.64.0.0/10"};
        ASSERT_TRUE(b.start(bcfg));
        b.set_ingress_source_handler([this](uint16_t vport, uint16_t bridge_port, const std::string& src_ip,
                                            uint16_t src_port, bool opened) {
            if (opened) ingress.connection_opened(vport, bridge_port, src_ip, src_port);
            else ingress.connection_closed(vport, bridge_port);
        });

        lnsdk::BoringtunConfig acfg;
        acfg.private_key = a_keys.first;
        acfg.public_key = a_keys.second;
        acfg.tunnel_ip = "10.64.0.3/32";
        acfg.allowed_ips = {"10.64.0.0/10"};
        acfg.server_public_key = b_keys.second;
        acfg.server_endpoint = "127.0.0.1:" + std::to_string(b.bound_port());
        ASSERT_TRUE(a.start(acfg));

        MeshPeer a_entry;
        a_entry.node_id = "peer-a";
        a_entry.mesh_pubkey = a_keys.second;
        a_entry.tunnel_ip = "10.64.0.3/32";
        a_entry.endpoint = "127.0.0.1:" + std::to_string(a.bound_port());
        ASSERT_TRUE(b.sync_peers({a_entry}).ok);
        list_peer({"read"});
    }

    void TearDown() override {
        a.stop();
        b.stop();
        ingress.stop();
        service.stop();
        if (service_thread.joinable()) service_thread.join();
    }

    /// Lists device A in B's peer list with `permissions`.
    void list_peer(std::vector<std::string> permissions, const std::string& tunnel_ip = "10.64.0.3/32") {
        MeshPeer entry;
        entry.node_id = "peer-a";
        entry.mesh_pubkey = a_keys.second;
        entry.tunnel_ip = tunnel_ip;
        entry.permissions = std::move(permissions);
        std::lock_guard lock(peers_mutex);
        peers = {entry};
    }

    /// Registers the sample catalog and exposes the service through the front end.
    void expose() {
        ASSERT_TRUE(ingress.set_catalog(kVport, sample_catalog()).ok);
        const auto bridge = ingress.bridge_target(kVport, "tcp:127.0.0.1:" + std::to_string(service_port));
        ASSERT_TRUE(bridge.ok) << bridge.error;
        ASSERT_TRUE(bridge.front_end);
        ASSERT_EQ(bridge.target.rfind("tcp:127.0.0.1:", 0), 0u) << bridge.target;
        front_end_port = static_cast<uint16_t>(std::stoi(bridge.target.substr(std::string("tcp:127.0.0.1:").size())));
        ASSERT_TRUE(b.tcp_ingress(kVport, bridge.target, true));
    }

    /// An HTTP client on A's egress to B's service port. The first request
    /// waits for the mesh handshake.
    std::unique_ptr<httplib::Client> client_from_a() {
        const uint16_t egress = a.tcp_egress("10.64.0.2", kVport);
        EXPECT_NE(egress, 0);
        auto client = std::make_unique<httplib::Client>("127.0.0.1", egress);
        client->set_connection_timeout(10, 0);
        client->set_read_timeout(10, 0);
        return client;
    }

    template <typename Send>
    httplib::Result until_answered(Send&& send) {
        httplib::Result res;
        const auto deadline = std::chrono::steady_clock::now() + 15s;
        do {
            res = send();
            if (res) break;
            std::this_thread::sleep_for(200ms);
        } while (std::chrono::steady_clock::now() < deadline);
        return res;
    }

    std::vector<IngressDeniedEvent> wait_events(size_t count, std::chrono::milliseconds limit = 5s) {
        std::unique_lock lock(events_mutex);
        events_changed.wait_for(lock, limit, [&] { return events.size() >= count; });
        return events;
    }

    std::vector<std::pair<std::string, httplib::Headers>> requests_seen() {
        std::lock_guard lock(seen_mutex);
        return seen;
    }
};

std::string header(const httplib::Headers& headers, const char* name) {
    const auto it = headers.find(name);
    return it == headers.end() ? std::string() : it->second;
}

}  // namespace

TEST_F(ServiceIngressMeshTest, AnAllowedRequestReachesTheServiceWithTheTrustedHeaders) {
    expose();
    list_peer({"read", "svc:inference"});
    auto client = client_from_a();
    const httplib::Headers forged{
        {"X-Nexus-Peer-Node", "forged"}, {"x-nexus-family", "management"},
        {"X-Nexus-Peer-Permissions", "admin"}, {"Authorization", "Bearer peer-key"}, {"X-Request-Id", "r1"}};
    const auto res = until_answered([&] {
        return client->Post("/api/v1/chat/completions?x=1", forged, R"({"model":"M"})", "application/json");
    });
    ASSERT_TRUE(res) << "no answer through the mesh";
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(json::parse(res->body)["body"], R"({"model":"M"})") << "the body passes through";

    const auto requests = requests_seen();
    ASSERT_EQ(requests.size(), 1u);
    EXPECT_EQ(requests[0].first, "/api/v1/chat/completions");
    const auto& headers = requests[0].second;
    EXPECT_EQ(header(headers, "X-Nexus-Peer-Node"), "peer-a");
    EXPECT_EQ(header(headers, "X-Nexus-Peer-Key"), a_keys.second) << "the peer's key, from the peer list";
    EXPECT_EQ(header(headers, "X-Nexus-Peer-Permissions"), "read,svc:inference");
    EXPECT_EQ(header(headers, "X-Nexus-Family"), "inference");
    EXPECT_EQ(header(headers, "X-Nexus-Catalog-Version"), "3");
    EXPECT_EQ(headers.count("X-Nexus-Peer-Node"), 1u) << "the client's copy is removed";
    EXPECT_EQ(headers.count("X-Nexus-Family"), 1u);
    EXPECT_EQ(headers.count("X-Nexus-Peer-Permissions"), 1u);
    EXPECT_EQ(header(headers, "Authorization"), "Bearer peer-key") << "the service applies its own API key policy";
    EXPECT_EQ(header(headers, "X-Request-Id"), "r1") << "other headers pass through";
    EXPECT_TRUE(wait_events(1, 300ms).empty()) << "an allowed request is not reported";
}

TEST_F(ServiceIngressMeshTest, ADeniedPeerGetsTheRefusalBodyAndOneEvent) {
    expose();
    list_peer({"svc:inference"});
    auto client = client_from_a();
    const auto res = until_answered([&] { return client->Get("/api/v1/system-info"); });
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 403);
    EXPECT_EQ(res->get_header_value("Content-Type"), "application/json");
    const auto body = json::parse(res->body);
    EXPECT_EQ(body["code"], "nexus_permission_denied");
    EXPECT_EQ(body["family"], "management");
    EXPECT_EQ(body["required"], "svc:management");
    EXPECT_EQ(body["catalog_version"], 3);
    EXPECT_EQ(body["app"]["name"], "lemonade");
    EXPECT_EQ(body["app"]["version"], "2026.46.0");
    EXPECT_FALSE(body["error"].get<std::string>().empty());
    EXPECT_TRUE(requests_seen().empty()) << "a refused request never reaches the service";

    const auto events = wait_events(1);
    ASSERT_EQ(events.size(), 1u);
    const auto& event = events[0];
    EXPECT_EQ(event.kind, "denied");
    EXPECT_EQ(event.vport, kVport);
    EXPECT_EQ(event.peer_node_id, "peer-a");
    EXPECT_EQ(event.peer_key, a_keys.second);
    EXPECT_EQ(event.peer_tunnel_ip, "10.64.0.3");
    EXPECT_EQ(event.method, "GET");
    EXPECT_EQ(event.path, "/api/v1/system-info");
    EXPECT_EQ(event.family, "management");
    EXPECT_EQ(event.required, "svc:management");
    EXPECT_EQ(event.catalog_version, 3u);
    EXPECT_GT(event.time, 0);
    const json as_json = event;
    for (const char* field : {"kind", "vport", "peer_node_id", "peer_key", "peer_tunnel_ip", "method", "path",
                              "family", "required", "catalog_version", "time"}) {
        EXPECT_TRUE(as_json.contains(field)) << field;
    }
}

TEST_F(ServiceIngressMeshTest, AnUnregisteredPathIsRefusedAndReported) {
    expose();
    list_peer({"admin"});
    auto client = client_from_a();
    const auto res = until_answered([&] { return client->Post("/api/v1/secret", "{\"never\":\"logged\"}", "application/json"); });
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 403);
    const auto body = json::parse(res->body);
    EXPECT_EQ(body["code"], "nexus_route_unregistered");
    EXPECT_EQ(body["family"], "");
    EXPECT_EQ(body["required"], "");
    EXPECT_TRUE(requests_seen().empty());
    const auto events = wait_events(1);
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0].kind, "unregistered");
    EXPECT_EQ(events[0].path, "/api/v1/secret");
    EXPECT_EQ(events[0].method, "POST");
    EXPECT_EQ(events[0].family, "");
    EXPECT_EQ(json(events[0]).dump().find("logged"), std::string::npos) << "the event carries no body";
}

TEST_F(ServiceIngressMeshTest, TheCatalogIsAnsweredBySdkForAnyAttributedPeer) {
    expose();
    list_peer({});
    auto client = client_from_a();
    const auto res = until_answered([&] { return client->Get("/.nexus/catalog"); });
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(res->get_header_value("Content-Type"), "application/json");
    EXPECT_EQ(json::parse(res->body), sample_catalog());
    EXPECT_TRUE(requests_seen().empty()) << "the SDK answers it, not the service";
    EXPECT_TRUE(wait_events(1, 300ms).empty());
    // Only GET: a POST to the path is an ordinary, unregistered request.
    const auto posted = client->Post("/.nexus/catalog", "{}", "application/json");
    ASSERT_TRUE(posted);
    EXPECT_EQ(posted->status, 403);
    EXPECT_EQ(json::parse(posted->body)["code"], "nexus_route_unregistered");
}

TEST_F(ServiceIngressMeshTest, AStreamingResponsePassesThroughAsItArrives) {
    expose();
    list_peer({"admin"});
    auto client = client_from_a();
    // Wait for the mesh path first, so the timing below measures the stream only.
    ASSERT_TRUE(until_answered([&] { return client->Get("/api/v1/models"); }));

    std::mutex mutex;
    std::condition_variable changed;
    std::string body;
    std::chrono::steady_clock::time_point first_chunk{};
    std::string content_type;
    const auto began = std::chrono::steady_clock::now();
    auto res = client->Get("/stream",
        [&](const httplib::Response& response) {
            content_type = response.get_header_value("Content-Type");
            return true;
        },
        [&](const char* data, size_t size) {
            std::lock_guard lock(mutex);
            if (body.empty()) first_chunk = std::chrono::steady_clock::now();
            body.append(data, size);
            changed.notify_all();
            return true;
        });
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(content_type, "text/event-stream");
    EXPECT_EQ(body, "data: 0\ndata: 1\ndata: 2\n");
    const auto finished = std::chrono::steady_clock::now();
    EXPECT_LT(first_chunk - began, finished - began - 150ms)
        << "the first chunk arrived before the service finished the stream";
}

TEST_F(ServiceIngressMeshTest, AConnectionNoListedPeerAccountsForIsUnattributed) {
    expose();
    {
        std::lock_guard lock(peers_mutex);
        peers.clear();
    }
    auto client = client_from_a();
    const auto res = until_answered([&] { return client->Get("/api/v1/models"); });
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 403);
    const auto body = json::parse(res->body);
    EXPECT_EQ(body["code"], "nexus_peer_unattributed");
    EXPECT_EQ(body["catalog_version"], 3);
    EXPECT_TRUE(requests_seen().empty());
    auto events = wait_events(1);
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0].kind, "unattributed");
    EXPECT_EQ(events[0].peer_node_id, "");
    EXPECT_EQ(events[0].peer_key, "");
    EXPECT_EQ(events[0].peer_tunnel_ip, "10.64.0.3") << "the source address is still reported";

    // A peer listed under another address does not match either, and two
    // peers on the same address are ambiguous: both fail closed.
    list_peer({"admin"}, "10.64.0.9/32");
    auto other = until_answered([&] { return client->Get("/api/v1/models"); });
    ASSERT_TRUE(other);
    EXPECT_EQ(json::parse(other->body)["code"], "nexus_peer_unattributed");
    {
        std::lock_guard lock(peers_mutex);
        MeshPeer entry;
        entry.node_id = "peer-a";
        entry.tunnel_ip = "10.64.0.3/32";
        entry.permissions = {"admin"};
        MeshPeer twin = entry;
        twin.node_id = "peer-twin";
        peers = {entry, twin};
    }
    other = client->Get("/api/v1/models");
    ASSERT_TRUE(other);
    EXPECT_EQ(json::parse(other->body)["code"], "nexus_peer_unattributed");
    EXPECT_EQ(wait_events(3).size(), 3u);
}

TEST_F(ServiceIngressMeshTest, ALocalClientOfTheFrontEndPortIsUnattributed) {
    expose();
    list_peer({"admin"});
    // Nothing on this machine but the netstack's bridges is attributed, so a
    // process that finds the front end's loopback port gets nothing.
    httplib::Client direct("127.0.0.1", front_end_port);
    const auto res = direct.Get("/api/v1/models");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 403);
    EXPECT_EQ(json::parse(res->body)["code"], "nexus_peer_unattributed");
    EXPECT_TRUE(requests_seen().empty());
    const auto events = wait_events(1);
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0].kind, "unattributed");
    EXPECT_EQ(events[0].peer_tunnel_ip, "");
}

TEST_F(ServiceIngressMeshTest, ClearingTheCallbackWaitsForARunningCallback) {
    expose();
    list_peer({});
    std::mutex gate_mutex;
    std::condition_variable gate;
    bool entered = false;
    bool release = false;
    ingress.set_denied_callback([&](const IngressDeniedEvent&) {
        std::unique_lock lock(gate_mutex);
        entered = true;
        gate.notify_all();
        gate.wait(lock, [&] { return release; });
    });
    auto client = client_from_a();
    std::thread request([&] { (void)until_answered([&] { return client->Get("/api/v1/models"); }); });
    {
        std::unique_lock lock(gate_mutex);
        ASSERT_TRUE(gate.wait_for(lock, 15s, [&] { return entered; })) << "the refusal did not reach the callback";
    }
    std::atomic<bool> cleared{false};
    std::thread clearer([&] {
        ingress.set_denied_callback({});
        cleared = true;
    });
    std::this_thread::sleep_for(200ms);
    EXPECT_FALSE(cleared.load()) << "the setter returns only when the running callback has returned";
    {
        std::lock_guard lock(gate_mutex);
        release = true;
    }
    gate.notify_all();
    clearer.join();
    EXPECT_TRUE(cleared.load());
    request.join();
    // The cleared callback never runs again.
    entered = false;
    const auto res = client->Get("/api/v1/models");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 403);
    std::this_thread::sleep_for(100ms);
    EXPECT_FALSE(entered);
}

// ---------------------------------------------------------------------------
// C ABI
// ---------------------------------------------------------------------------

namespace {

struct Client {
    ln_client_t* c = ln_create("localhost", 9);
    ~Client() { if (c) ln_destroy(c); }
};

void count_refusal(char* event_json, void* user) {
    ln_free(event_json);
    ++*static_cast<int*>(user);
}

}  // namespace

TEST(SdkCapiServiceIngress, NullArgumentsAreRefused) {
    char* out = nullptr;
    const auto catalog = sample_catalog().dump();
    EXPECT_EQ(ln_mesh_service_set_catalog(nullptr, kVport, catalog.c_str()), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_mesh_service_catalog(nullptr, kVport, &out), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_set_ingress_denied_callback(nullptr, count_refusal, nullptr), LN_ERR_NULL_ARG);
    Client client;
    ASSERT_NE(client.c, nullptr);
    EXPECT_EQ(ln_mesh_service_set_catalog(client.c, kVport, nullptr), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_mesh_service_catalog(client.c, kVport, nullptr), LN_ERR_NULL_ARG);
    EXPECT_EQ(out, nullptr);
}

TEST(SdkCapiServiceIngress, CatalogsAreValidatedStoredAndReadBack) {
    Client client;
    ASSERT_NE(client.c, nullptr);
    char* out = nullptr;
    ASSERT_EQ(ln_mesh_service_catalog(client.c, kVport, &out), LN_OK);
    ASSERT_NE(out, nullptr);
    EXPECT_EQ(std::string(out), "{}");
    ln_free(out);

    EXPECT_EQ(ln_mesh_service_set_catalog(client.c, kVport, "not json"), LN_ERR_REJECTED);
    EXPECT_EQ(ln_mesh_service_set_catalog(client.c, kVport, R"({"families":[]})"), LN_ERR_REJECTED) << "no version";
    EXPECT_EQ(ln_mesh_service_set_catalog(client.c, kVport,
                  R"({"version":1,"families":[{"name":"Bad Name","routes":[]}]})"), LN_ERR_REJECTED);
    EXPECT_EQ(ln_mesh_service_set_catalog(client.c, 0, R"({"version":1,"families":[]})"), LN_ERR_REJECTED);
    const std::string huge = std::string(lnsdk::service_ingress::kCatalogTextLimit + 1, ' ');
    EXPECT_EQ(ln_mesh_service_set_catalog(client.c, kVport, huge.c_str()), LN_ERR_REJECTED);

    const auto catalog = sample_catalog().dump();
    // Works before a join: the catalog waits for the exposure.
    ASSERT_EQ(ln_mesh_service_set_catalog(client.c, kVport, catalog.c_str()), LN_OK);
    ASSERT_EQ(ln_mesh_service_catalog(client.c, kVport, &out), LN_OK);
    ASSERT_NE(out, nullptr);
    EXPECT_EQ(json::parse(out), sample_catalog());
    ln_free(out);
    out = nullptr;
    ASSERT_EQ(ln_mesh_service_catalog(client.c, 8080, &out), LN_OK);
    EXPECT_EQ(std::string(out), "{}");
    ln_free(out);

    // Without a mesh the exposure is refused as before; the catalog stays.
    EXPECT_EQ(ln_mesh_expose_service(client.c, kVport, "tcp:127.0.0.1:1"), LN_ERR_CONNECT);
    ASSERT_EQ(ln_mesh_service_catalog(client.c, kVport, &out), LN_OK);
    EXPECT_EQ(json::parse(out)["version"], 3);
    ln_free(out);
}

TEST(SdkCapiServiceIngress, TheRefusalCallbackIsSetAndCleared) {
    int calls = 0;
    Client client;
    ASSERT_NE(client.c, nullptr);
    EXPECT_EQ(ln_set_ingress_denied_callback(client.c, count_refusal, &calls), LN_OK);
    EXPECT_EQ(ln_set_ingress_denied_callback(client.c, nullptr, nullptr), LN_OK);
    EXPECT_EQ(ln_set_ingress_denied_callback(client.c, count_refusal, &calls), LN_OK);
    ASSERT_EQ(ln_mesh_service_set_catalog(client.c, kVport, sample_catalog().dump().c_str()), LN_OK);
    EXPECT_EQ(calls, 0) << "no front end runs before an exposure, so nothing is refused";
}
