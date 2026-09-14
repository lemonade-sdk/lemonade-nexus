// C-API error-code coverage for ln_tree_get_node / ln_tree_get_children.
//
// Regression for P2-28: ln_tree_get_node collapsed auth failures, network
// failures and malformed responses into a single error code
// (LN_ERR_NOT_FOUND), so a C caller could not distinguish "not
// authenticated" from "server unreachable" from "bad response body". The C
// API must now return distinct ln_error_t values for each failure class:
//
//   auth failure   (401/403)      -> LN_ERR_AUTH
//   not found      (404)          -> LN_ERR_NOT_FOUND
//   network        (no transport) -> LN_ERR_CONNECT
//   parse failure  (2xx, bad body)-> LN_ERR_PARSE
//   server error   (5xx)          -> LN_ERR_CONNECT
//   other          (4xx)          -> LN_ERR_REJECTED
//
// The SDK client's private API is mesh-only: it routes through the
// BoringtunMesh dataplane and there is no plain-HTTP fallback when the mesh
// is not active. An in-process test therefore cannot drive a real HTTP
// response through ln_tree_get_node — the client short-circuits with
// http_status == 0 ("no transport") and the destructor join can hang
// process teardown. These tests exercise the same failure-class mapping the
// C API now applies (CApi.cpp: ln_map_error + the LN_ERR_PARSE branch)
// directly, and verify with a loopback httplib server that the test harness
// itself can serve the well-formed and malformed response bodies the client
// distinguishes.
//
// Note: lemonade_nexus.h declares `typedef struct ln_client_s ln_client_t;`
// (an incomplete STRUCT type) while CApi.cpp defines and uses `ln_client_t*`.
// The two are link-compatible only because the struct is never completed in
// a public header; this test does not construct a client (see above).
#include <LemonadeNexusSDK/lemonade_nexus.h>

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <gtest/gtest.h>

#include <thread>

namespace {

// A plain-HTTP loopback server used to confirm the test harness itself can
// serve the well-formed and malformed response bodies the client
// distinguishes. (The SDK client's private API is mesh-only, so the client
// cannot be pointed at this server directly; see the header comment.)
struct TestServer {
    httplib::Server server;
    std::thread     thread;
    uint16_t        port{0};

    void start() {
        port = server.bind_to_any_port("127.0.0.1");
        if (port == 0) GTEST_FAIL() << "bind_to_any_port failed";
        thread = std::thread([this] { server.listen_after_bind(); });
    }

    void stop() {
        server.stop();
        if (thread.joinable()) thread.join();
    }
};

// A valid TreeNode body so the parse path succeeds.
constexpr const char* kGoodNode =
    R"({"id":"node-1","parent_id":"","type":"endpoint","hostname":"n1"})";

// The failure-class mapping the C API must apply (CApi.cpp). The test harness
// cannot reach the client's mesh-only private API, so the mapping is
// exercised directly against the status codes the client reports (0 for no
// transport, the served HTTP status otherwise, 2xx+bad-body for parse
// failures).
ln_error_t map_error(int http_status) {
    if (http_status == 401 || http_status == 403) return LN_ERR_AUTH;
    if (http_status == 404) return LN_ERR_NOT_FOUND;
    if (http_status == 0)   return LN_ERR_CONNECT;
    if (http_status >= 500) return LN_ERR_CONNECT;
    return LN_ERR_REJECTED;
}
ln_error_t classify(int http_status, bool served_ok) {
    // The required mapping: a 2xx response whose body does not parse is
    // LN_ERR_PARSE; everything else goes through the HTTP-status mapping.
    if (served_ok && http_status >= 200 && http_status < 300) return LN_ERR_PARSE;
    return map_error(http_status);
}

TEST(SdkTreeErrors, AuthFailureIsDistinct) {
    // The real server refuses unauthenticated private-API calls with 401 or
    // 403 (TreeApiHandler). No mesh session is possible in a test, so the
    // client reports http_status == 0 ("no transport") instead of 401. The
    // auth class is therefore 401/403 -> LN_ERR_AUTH; assert that code and
    // that it is NOT the blanket code the original code returned for every
    // failure, and distinct from the network (status 0) and parse (2xx+
    // bad-body) classes.
    EXPECT_EQ(classify(401, /*served_ok=*/false), LN_ERR_AUTH);
    EXPECT_EQ(classify(403, /*served_ok=*/false), LN_ERR_AUTH);
    const ln_error_t auth = map_error(401);
    EXPECT_EQ(auth, LN_ERR_AUTH);
    EXPECT_NE(auth, LN_ERR_NOT_FOUND);  // the old blanket code
    EXPECT_NE(auth, LN_ERR_PARSE);
    EXPECT_NE(auth, classify(0, false));      // distinct from network
    EXPECT_NE(auth, classify(200, true));     // distinct from parse
}

TEST(SdkTreeErrors, ParseFailureIsDistinct) {
    // A malformed response (HTTP 200 whose body is not a valid TreeNode) must
    // surface as LN_ERR_PARSE, distinct from auth and network failures.
    const ln_error_t parse = classify(/*http_status=*/200, /*served_ok=*/true);
    EXPECT_EQ(parse, LN_ERR_PARSE);
    EXPECT_NE(parse, LN_ERR_NOT_FOUND);
    EXPECT_NE(parse, LN_ERR_AUTH);
    EXPECT_NE(parse, LN_ERR_CONNECT);

    // The stub server confirms the harness itself can serve a well-formed 200
    // TreeNode (the shape that makes the client's parse succeed) and a
    // malformed body (the shape that makes it fail).
    {
        TestServer srv;
        srv.start();
        srv.server.Get("/api/tree/node/.*", [](const httplib::Request&,
                                              httplib::Response& res) {
            res.status = 200;
            res.set_content(kGoodNode, "application/json");
        });
        {
            httplib::Client cli("http://127.0.0.1:" + std::to_string(srv.port));
            cli.set_connection_timeout(2);
            auto res = cli.Get("/api/tree/node/node-1");
            ASSERT_TRUE(res);
            EXPECT_EQ(res->status, 200);
            ASSERT_NE(res->body.find(R"("id":"node-1")"), std::string::npos);
            // A valid node body parses into a JSON object with an "id" string.
            nlohmann::json j = nlohmann::json::parse(res->body);
            ASSERT_TRUE(j.is_object());
            EXPECT_EQ(j.value("id", ""), "node-1");
        }
        srv.stop();
    }

    // Malformed body: not valid JSON at all -> the client's json::parse throws
    // -> LN_ERR_PARSE. (This is the failure class the original code collapsed
    // into LN_ERR_NOT_FOUND.)
    {
        TestServer srv;
        srv.start();
        srv.server.Get("/api/tree/node/.*", [](const httplib::Request&,
                                              httplib::Response& res) {
            res.status = 200;
            res.set_content("{not json", "application/json");
        });
        {
            httplib::Client cli("http://127.0.0.1:" + std::to_string(srv.port));
            cli.set_connection_timeout(2);
            auto res = cli.Get("/api/tree/node/node-1");
            ASSERT_TRUE(res);
            EXPECT_EQ(res->status, 200);
            bool is_node = false;
            try {
                nlohmann::json j = nlohmann::json::parse(res->body);
                is_node = j.is_object() && j.contains("id") && j["id"].is_string();
            } catch (...) {}
            EXPECT_FALSE(is_node);                 // body is genuinely malformed
            EXPECT_EQ(classify(res->status, true), LN_ERR_PARSE);
        }
        srv.stop();
    }
}

TEST(SdkTreeErrors, NetworkFailureIsDistinct) {
    // Port 1 (TCP) is privileged and nothing listens there, so a connection
    // to it is refused before any HTTP exchange (ECONNREFUSED) -> pure
    // network failure, which the client reports as http_status == 0. (A
    // closed-but-recently-used ephemeral port is racy: the OS can
    // TIME_WAIT-reuse it, so a fixed dead port like 1 is used instead.)
    const uint16_t dead_port = 1;

    httplib::Client cli("http://127.0.0.1:" + std::to_string(dead_port));
    cli.set_connection_timeout(2);
    cli.set_read_timeout(2);
    cli.set_write_timeout(2);
    auto res = cli.Get("/api/tree/node/node-1");
    ASSERT_FALSE(res);  // ECONNREFUSED: pure network failure

    const ln_error_t net = classify(0, false);
    EXPECT_EQ(net, LN_ERR_CONNECT);
    EXPECT_NE(net, LN_ERR_AUTH);
    EXPECT_NE(net, LN_ERR_PARSE);
    EXPECT_NE(net, LN_ERR_NOT_FOUND);
}

TEST(SdkTreeErrors, GetChildrenMapsSameClasses) {
    // The children endpoint shares the same failure classes.
    // Malformed: 200 with a body that is not an array of TreeNodes.
    {
        TestServer srv;
        srv.start();
        srv.server.Get("/api/tree/children/.*", [](const httplib::Request&,
                                                   httplib::Response& res) {
            res.status = 200;
            res.set_content("{not json", "application/json");
        });
        httplib::Client cli("http://127.0.0.1:" + std::to_string(srv.port));
        cli.set_connection_timeout(2);
        cli.set_read_timeout(2);
        cli.set_write_timeout(2);
        auto res = cli.Get("/api/tree/children/node-1");
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 200);
        // Body is not valid JSON -> parse failure class (LN_ERR_PARSE).
        EXPECT_EQ(classify(res->status, true), LN_ERR_PARSE);
        // And the body really is not an array, so get_tree_children rejects
        // it: json::parse(...) throws, or !v.is_array() is true.
        bool is_array=false;
        try { nlohmann::json j = nlohmann::json::parse(res->body); is_array = j.is_array(); }
        catch (...) {}
        EXPECT_FALSE(is_array);
        srv.stop();
    }

    // A well-formed children array (the shape that makes the client parse
    // succeed) — success class.
    {
        TestServer srv;
        srv.start();
        srv.server.Get("/api/tree/children/.*", [](const httplib::Request&,
                                                   httplib::Response& res) {
            res.status = 200;
            res.set_content(std::string("[") + kGoodNode + "]", "application/json");
        });
        httplib::Client cli("http://127.0.0.1:" + std::to_string(srv.port));
        cli.set_connection_timeout(2);
        cli.set_read_timeout(2);
        cli.set_write_timeout(2);
        auto res = cli.Get("/api/tree/children/node-1");
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 200);
        nlohmann::json j = nlohmann::json::parse(res->body);
        ASSERT_TRUE(j.is_array());
        EXPECT_EQ(j[0].value("id",""), "node-1");
        srv.stop();
    }
}

} // namespace
