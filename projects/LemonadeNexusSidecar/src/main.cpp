// Headless mesh client for embedding in a host app (e.g. Lemonade's lemond):
// joins a mesh over the SDK's userspace dataplane, publishes the host's local
// services to mesh peers, and serves a localhost control API the parent polls.

#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#ifdef _WIN32
#  include <process.h>
#  include <windows.h>
#  define getpid _getpid
#else
#  include <csignal>
#  include <unistd.h>
#endif

#ifndef NEXUS_VERSION
#  define NEXUS_VERSION "0.0.0-dev"
#endif
#ifndef NEXUS_GIT_COMMIT
#  define NEXUS_GIT_COMMIT "unknown"
#endif

namespace {

using namespace std::chrono_literals;

// --- Shutdown signalling ----------------------------------------------------

std::atomic<bool>       g_stop{false};
std::condition_variable g_stop_cv;
std::mutex              g_stop_mtx;

void request_stop() {
    g_stop.store(true);
    g_stop_cv.notify_all();
}

extern "C" void handle_signal(int) { request_stop(); }

/// Returns false if shutdown was requested during the wait.
bool interruptible_sleep(std::chrono::milliseconds d) {
    std::unique_lock lock(g_stop_mtx);
    g_stop_cv.wait_for(lock, d, [] { return g_stop.load(); });
    return !g_stop.load();
}

// --- Parent-process liveness (closes the orphan gap on all platforms) -------

bool parent_alive(long parent_pid) {
    if (parent_pid <= 0) return true;  // no parent to track
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
                           static_cast<DWORD>(parent_pid));
    if (!h) return false;
    DWORD code = 0;
    bool alive = GetExitCodeProcess(h, &code) && code == STILL_ACTIVE;
    CloseHandle(h);
    return alive;
#else
    return ::kill(static_cast<pid_t>(parent_pid), 0) == 0 || errno == EPERM;
#endif
}

// --- Config -----------------------------------------------------------------

struct ExposeMapping {
    uint16_t vport{0};       // published at <mesh_ip>:vport
    uint16_t local_port{0};  // bridged to 127.0.0.1:local_port
};

struct SidecarConfig {
    std::string host{"127.0.0.1"};
    uint16_t    port{9100};
    bool        use_tls{false};
    std::string identity_path;
    std::string data_root{"nexus-sidecar"};
    std::string link_token;
    std::vector<ExposeMapping> exposes;
    uint16_t    control_port{9110};
    std::string control_token;                 // bearer required by the control API (disabled if empty)
    long        parent_pid{0};
    std::string log_level{"info"};
    bool        pin_server{false};             // keep the configured endpoint (no SEIP switch)
};

std::optional<ExposeMapping> parse_expose(const std::string& spec) {
    auto colon = spec.find(':');
    if (colon == std::string::npos) return std::nullopt;
    try {
        ExposeMapping m;
        m.vport      = static_cast<uint16_t>(std::stoi(spec.substr(0, colon)));
        m.local_port = static_cast<uint16_t>(std::stoi(spec.substr(colon + 1)));
        if (m.vport == 0 || m.local_port == 0) return std::nullopt;
        return m;
    } catch (...) {
        return std::nullopt;
    }
}

void apply_json_config(SidecarConfig& cfg, const nlohmann::json& j) {
    if (j.contains("server")) {
        auto s = j.at("server").get<std::string>();
        if (auto c = s.rfind(':'); c != std::string::npos) {
            cfg.host = s.substr(0, c);
            cfg.port = static_cast<uint16_t>(std::stoi(s.substr(c + 1)));
        }
    }
    if (j.contains("tls"))          cfg.use_tls       = j.at("tls").get<bool>();
    if (j.contains("identity"))     cfg.identity_path = j.at("identity").get<std::string>();
    if (j.contains("data_root"))    cfg.data_root     = j.at("data_root").get<std::string>();
    if (j.contains("link_token"))   cfg.link_token    = j.at("link_token").get<std::string>();
    if (j.contains("control_port")) cfg.control_port  = j.at("control_port").get<uint16_t>();
    if (j.contains("control_token")) cfg.control_token = j.at("control_token").get<std::string>();
    if (j.contains("log_level"))    cfg.log_level     = j.at("log_level").get<std::string>();
    if (j.contains("expose") && j.at("expose").is_array()) {
        for (const auto& e : j.at("expose")) {
            if (auto m = parse_expose(e.get<std::string>())) cfg.exposes.push_back(*m);
        }
    }
}

void apply_env(SidecarConfig& cfg) {
    if (const char* v = std::getenv("LN_SIDECAR_SERVER")) {
        std::string s = v;
        if (auto c = s.rfind(':'); c != std::string::npos) {
            cfg.host = s.substr(0, c);
            cfg.port = static_cast<uint16_t>(std::atoi(s.substr(c + 1).c_str()));
        }
    }
    if (std::getenv("LN_SIDECAR_TLS"))            cfg.use_tls = true;
    if (const char* v = std::getenv("LN_SIDECAR_IDENTITY"))   cfg.identity_path = v;
    if (const char* v = std::getenv("LN_SIDECAR_DATA_ROOT"))  cfg.data_root = v;
    if (const char* v = std::getenv("LN_SIDECAR_LINK_TOKEN")) cfg.link_token = v;
    if (const char* v = std::getenv("LN_SIDECAR_CONTROL_PORT"))
        cfg.control_port = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("LN_SIDECAR_CONTROL_TOKEN")) cfg.control_token = v;
    if (const char* v = std::getenv("LN_SIDECAR_EXPOSE")) {
        if (auto m = parse_expose(v)) cfg.exposes.push_back(*m);
    }
    if (std::getenv("LN_SIDECAR_PIN_SERVER"))         cfg.pin_server = true;
    if (const char* v = std::getenv("SP_PARENT_PID")) cfg.parent_pid = std::atol(v);
    if (const char* v = std::getenv("SP_LOG_LEVEL"))  cfg.log_level = v;
}

void print_usage(const char* prog) {
    std::printf(
        "Usage: %s [OPTIONS]\n\n"
        "Headless Lemonade Nexus mesh client. Joins a mesh and publishes local\n"
        "services to authorized peers over the userspace dataplane.\n\n"
        "Options:\n"
        "  --server <host:port>    Nexus server public API (default 127.0.0.1:9100)\n"
        "  --tls                   Use HTTPS for the public API\n"
        "  --pin-server            Keep the configured endpoint (no SEIP switch;\n"
        "                          automatic when --tls is not set)\n"
        "  --identity <path>       Ed25519 identity file (default <data-root>/identity.json)\n"
        "  --data-root <path>      State directory (default ./nexus-sidecar)\n"
        "  --link-token <token>    Single-use device link token (first join)\n"
        "  --expose <vport:local>  Publish 127.0.0.1:local at <mesh_ip>:vport (repeatable)\n"
        "  --control-port <N>      Localhost control API port (default 9110)\n"
        "  --control-token <tok>   Bearer required by all control endpoints (API off if unset)\n"
        "  --parent-pid <pid>      Exit when this process disappears\n"
        "  --config <path>         JSON config file (CLI and env override it)\n"
        "  --log-level <level>     trace/debug/info/warn/error\n"
        "  --version               Print version and commit, then exit\n",
        prog);
}

// Precedence: config file < env < CLI flags.
SidecarConfig load_config(int argc, char* argv[], bool& want_exit) {
    SidecarConfig cfg;

    // First pass: --config and --version.
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--version") == 0) {
            std::printf("lemonade-nexus-sidecar %s (%s)\n", NEXUS_VERSION, NEXUS_GIT_COMMIT);
            want_exit = true;
            return cfg;
        }
        if ((std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0)) {
            print_usage(argv[0]);
            want_exit = true;
            return cfg;
        }
        if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            std::ifstream ifs(argv[i + 1]);
            if (ifs) {
                auto j = nlohmann::json::parse(ifs, nullptr, false);
                if (!j.is_discarded()) apply_json_config(cfg, j);
                else spdlog::warn("--config {}: invalid JSON, ignoring", argv[i + 1]);
            } else {
                spdlog::warn("--config {}: cannot open, ignoring", argv[i + 1]);
            }
        }
    }

    apply_env(cfg);

    for (int i = 1; i < argc; ++i) {
        auto next = [&](const char* flag) -> const char* {
            return (std::strcmp(argv[i], flag) == 0 && i + 1 < argc) ? argv[++i] : nullptr;
        };
        if (const char* v = next("--server")) {
            std::string s = v;
            if (auto c = s.rfind(':'); c != std::string::npos) {
                cfg.host = s.substr(0, c);
                cfg.port = static_cast<uint16_t>(std::atoi(s.substr(c + 1).c_str()));
            } else {
                cfg.host = s;
            }
        } else if (std::strcmp(argv[i], "--tls") == 0) {
            cfg.use_tls = true;
        } else if (std::strcmp(argv[i], "--pin-server") == 0) {
            cfg.pin_server = true;
        } else if (const char* v2 = next("--identity")) {
            cfg.identity_path = v2;
        } else if (const char* v3 = next("--data-root")) {
            cfg.data_root = v3;
        } else if (const char* v4 = next("--link-token")) {
            cfg.link_token = v4;
        } else if (const char* v5 = next("--expose")) {
            if (auto m = parse_expose(v5)) cfg.exposes.push_back(*m);
            else spdlog::warn("--expose {}: expected vport:localport, ignoring", v5);
        } else if (const char* v6 = next("--control-port")) {
            cfg.control_port = static_cast<uint16_t>(std::atoi(v6));
        } else if (const char* v7 = next("--parent-pid")) {
            cfg.parent_pid = std::atol(v7);
        } else if (const char* v8 = next("--log-level")) {
            cfg.log_level = v8;
        } else if (const char* v9 = next("--control-token")) {
            cfg.control_token = v9;
        } else if (next("--config")) {
            // already handled
        }
    }

    if (cfg.identity_path.empty()) cfg.identity_path = cfg.data_root + "/identity.json";
    return cfg;
}

// --- Shared runtime state exposed by the control API ------------------------

struct SidecarState {
    std::mutex   mtx;
    std::string  status{"starting"};  // starting|joining|running|degraded|stopped
    std::string  node_id;
    std::string  tunnel_ip;
    bool         mesh_up{false};
    uint32_t     peer_count{0};
    uint32_t     join_failures{0};
};

}  // namespace

int main(int argc, char* argv[]) {
    bool want_exit = false;
    SidecarConfig cfg = load_config(argc, argv, want_exit);
    if (want_exit) return 0;

    spdlog::set_level(spdlog::level::from_str(cfg.log_level));

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    spdlog::info("lemonade-nexus-sidecar {} ({})", NEXUS_VERSION, NEXUS_GIT_COMMIT);
    spdlog::info("Server {}://{}:{}, control 127.0.0.1:{}, {} service(s) to expose",
                 cfg.use_tls ? "https" : "http", cfg.host, cfg.port,
                 cfg.control_port, cfg.exposes.size());

    // Identity: reuse the persisted keypair so the node keeps its account across
    // restarts; generate on first run.
    lnsdk::Identity identity;
    if (!identity.load(cfg.identity_path)) {
        spdlog::info("No identity at {} — generating a new keypair", cfg.identity_path);
        identity.generate();
        if (!identity.save(cfg.identity_path)) {
            spdlog::error("Failed to persist identity to {}", cfg.identity_path);
            return 1;
        }
    }

    lnsdk::ServerConfig sc(cfg.host, cfg.port, cfg.use_tls);
    // Pin explicitly, or automatically for a TLS-less (local/direct) server whose
    // advertised SEIP FQDN won't resolve.
    sc.pin_server = cfg.pin_server || !cfg.use_tls;
    lnsdk::LemonadeNexusClient client{sc};
    client.set_identity(identity);
    if (!cfg.link_token.empty()) client.set_link_token(cfg.link_token);

    SidecarState state;

    // --- Localhost control API (parent health-checks this) ------------------
    // Loopback is not an authorization boundary: any local process (or a browser
    // via DNS-rebinding) can reach it. Every endpoint requires the bearer token
    // the parent passes in; with no token configured the control API serves
    // nothing.
    httplib::Server control;
    control.set_pre_routing_handler(
        [&cfg](const httplib::Request& req, httplib::Response& res) {
        if (req.has_header("Origin")) {  // block browser (DNS-rebinding/CSRF) callers
            res.status = 403;
            res.set_content(R"({"error":"origin not allowed"})", "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }
        if (cfg.control_token.empty()) {
            res.status = 503;
            res.set_content(R"({"error":"control API disabled: no control token configured"})",
                            "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }
        const auto& h = req.get_header_value("Authorization");
        constexpr std::string_view bearer = "Bearer ";
        if (h.size() <= bearer.size() || h.compare(0, bearer.size(), bearer) != 0 ||
            h.substr(bearer.size()) != cfg.control_token) {
            res.status = 401;
            res.set_content(R"({"error":"control token required"})", "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });
    control.Get("/version", [](const httplib::Request&, httplib::Response& res) {
        nlohmann::json j = {{"service", "lemonade-nexus-sidecar"},
                            {"version", NEXUS_VERSION},
                            {"commit", NEXUS_GIT_COMMIT}};
        res.set_content(j.dump(), "application/json");
    });
    control.Get("/health", [&state](const httplib::Request&, httplib::Response& res) {
        std::lock_guard lock(state.mtx);
        bool ok = state.status == "running";
        nlohmann::json j = {{"status", ok ? "ok" : "degraded"},
                            {"mesh", state.mesh_up ? "up" : "down"},
                            {"detail", state.status}};
        res.status = ok ? 200 : 503;
        res.set_content(j.dump(), "application/json");
    });
    control.Get("/status", [&](const httplib::Request&, httplib::Response& res) {
        std::lock_guard lock(state.mtx);
        nlohmann::json exposed = nlohmann::json::array();
        for (const auto& e : cfg.exposes) {
            exposed.push_back({{"vport", e.vport}, {"local_port", e.local_port}});
        }
        nlohmann::json j = {
            {"status", state.status},
            {"node_id", state.node_id},
            {"tunnel_ip", state.tunnel_ip},
            {"mesh_up", state.mesh_up},
            {"peer_count", state.peer_count},
            {"join_failures", state.join_failures},
            {"server", cfg.host + ":" + std::to_string(cfg.port)},
            {"exposed", exposed},
        };
        res.set_content(j.dump(), "application/json");
    });
    // Mint a device link token so another device can join this account.
    control.Post("/link-token", [&](const httplib::Request& req, httplib::Response& res) {
        uint32_t ttl_sec = 600;
        if (!req.body.empty()) {
            auto j = nlohmann::json::parse(req.body, nullptr, false);
            if (!j.is_discarded()) ttl_sec = j.value("ttl_sec", ttl_sec);
        }
        auto result = client.create_link_token(ttl_sec);
        if (!result.ok) {
            res.status = 502;
            res.set_content(nlohmann::json{{"error", result.error}}.dump(),
                            "application/json");
            return;
        }
        res.set_content(result.value.dump(), "application/json");
    });
    // Bridge a peer's mesh service to a loopback port the host app can dial.
    control.Post("/egress", [&](const httplib::Request& req, httplib::Response& res) {
        auto j = nlohmann::json::parse(req.body, nullptr, false);
        if (j.is_discarded() || !j.contains("ip") || !j.contains("port")) {
            res.status = 400;
            res.set_content(R"({"error":"expected {ip, port}"})", "application/json");
            return;
        }
        uint16_t lp = client.open_egress(j.at("ip").get<std::string>(),
                                         j.at("port").get<uint16_t>());
        if (lp == 0) {
            res.status = 502;
            res.set_content(R"({"error":"mesh inactive or egress failed"})",
                            "application/json");
            return;
        }
        res.set_content(nlohmann::json{{"loopback_port", lp}}.dump(),
                        "application/json");
    });

    std::thread control_thread([&] {
        if (!control.listen("127.0.0.1", cfg.control_port)) {
            spdlog::error("Control API failed to bind 127.0.0.1:{}", cfg.control_port);
            request_stop();
        }
    });

    // --- Parent-liveness watcher --------------------------------------------
    std::thread parent_watch;
    if (cfg.parent_pid > 0) {
        parent_watch = std::thread([pid = cfg.parent_pid] {
            while (!g_stop.load()) {
                if (!parent_alive(pid)) {
                    spdlog::info("Parent process {} gone — shutting down", pid);
                    request_stop();
                    return;
                }
                if (!interruptible_sleep(2s)) return;
            }
        });
    }

    // --- Join + supervise loop ----------------------------------------------
    auto set_status = [&](const std::string& s) {
        std::lock_guard lock(state.mtx);
        state.status = s;
    };

    bool joined = false;
    auto backoff = 1s;
    constexpr auto max_backoff = 60s;

    while (!g_stop.load()) {
        if (!joined) {
            set_status("joining");
            auto res = client.join_network("lemonade-sidecar", "");
            if (res.ok) {
                joined = true;
                backoff = 1s;
                {
                    std::lock_guard lock(state.mtx);
                    state.node_id   = res.value.node_id;
                    state.tunnel_ip = res.value.tunnel_ip;
                }
                spdlog::info("Joined mesh: node_id={} tunnel_ip={}",
                             res.value.node_id, res.value.tunnel_ip);

                // The link token is single-use and now consumed; drop it so a
                // later re-join doesn't replay it.
                client.set_link_token("");

                client.enable_mesh();  // background peer discovery + heartbeat

                for (const auto& e : cfg.exposes) {
                    auto r = client.expose_service(
                        e.vport, "tcp:127.0.0.1:" + std::to_string(e.local_port));
                    if (r.ok) {
                        spdlog::info("Exposed 127.0.0.1:{} at mesh :{}", e.local_port, e.vport);
                    } else {
                        spdlog::warn("Failed to expose :{} -> 127.0.0.1:{}: {}",
                                     e.vport, e.local_port, r.error);
                    }
                }
                set_status("running");
            } else {
                {
                    std::lock_guard lock(state.mtx);
                    state.join_failures++;
                    state.mesh_up = false;
                }
                set_status("degraded");
                spdlog::warn("Join failed ({}); retrying in {}s",
                             res.error, backoff.count());
                if (!interruptible_sleep(backoff)) break;
                backoff = std::min(backoff * 2, max_backoff);
                continue;
            }
        }

        // Supervise. The dataplane being active is the real liveness signal
        // (mesh_status().is_up reflects the orchestrator's peer-refresh state,
        // which lags and would cause spurious teardowns). The SDK's MeshOrchestrator
        // handles peer refresh, heartbeat and server-pool failover internally; we
        // only re-join if the dataplane itself is gone.
        // TODO: detect a silently-dead server (dataplane stays "active" on a local
        // UDP socket) via a periodic private-API probe over the mesh, then re-join.
        auto status = client.mesh_status();
        bool active = client.is_mesh_active();
        {
            std::lock_guard lock(state.mtx);
            state.mesh_up    = active;
            state.peer_count = status.peer_count;
        }

        if (!active) {
            spdlog::warn("Mesh dataplane down — re-joining");
            set_status("degraded");
            client.disable_mesh();
            joined = false;  // exposures re-apply on the next join
            continue;
        }
        set_status("running");
        if (!interruptible_sleep(10s)) break;
    }

    // --- Shutdown -----------------------------------------------------------
    spdlog::info("Shutting down");
    set_status("stopped");
    if (joined) {
        client.disable_mesh();
    }
    control.stop();
    if (control_thread.joinable()) control_thread.join();
    if (parent_watch.joinable()) parent_watch.join();
    return 0;
}
