#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>

#include <spdlog/spdlog.h>

#include <cstdlib>
#include <cstring>
#include <iostream>

static void print_usage(const char* prog) {
    std::cout << "Usage: " << prog
              << " [--host HOST] [--port PORT] [--tls]"
              << " [--user USER] [--pass PASS]"
              << " [--identity PATH]"
              << "\n\n"
              << "Lemonade Nexus SDK — example CLI driver.\n"
              << "Demonstrates: health → auth → list relays → cert status.\n";
}

int main(int argc, char* argv[]) {
    std::string host     = "127.0.0.1";
    uint16_t    port     = 9100;
    bool        use_tls  = false;
    std::string username;
    std::string password;
    std::string identity_path;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            host = argv[++i];
        } else if (std::strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--tls") == 0) {
            use_tls = true;
        } else if (std::strcmp(argv[i], "--user") == 0 && i + 1 < argc) {
            username = argv[++i];
        } else if (std::strcmp(argv[i], "--pass") == 0 && i + 1 < argc) {
            password = argv[++i];
        } else if (std::strcmp(argv[i], "--identity") == 0 && i + 1 < argc) {
            identity_path = argv[++i];
        } else if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        }
    }

    // Log level
    const char* log_env = std::getenv("SP_LOG_LEVEL");
    if (log_env) {
        spdlog::set_level(spdlog::level::from_str(log_env));
    } else {
        spdlog::set_level(spdlog::level::info);
    }

    // Create client
    lnsdk::ServerConfig config(host, port, use_tls);

    lnsdk::LemonadeNexusClient client{config};

    // Load or generate identity
    lnsdk::Identity identity;
    if (!identity_path.empty()) {
        if (!identity.load(identity_path)) {
            spdlog::info("Identity file not found, generating new keypair...");
            identity.generate();
            (void)identity.save(identity_path);
        }
    } else {
        identity.generate();
    }
    client.set_identity(identity);

    std::cout << "Lemonade Nexus SDK Client\n"
              << "  Server: " << (use_tls ? "https://" : "http://")
              << host << ":" << port << "\n"
              << "  Pubkey: " << identity.pubkey_string() << "\n\n";

    // --- Health check ---
    std::cout << "=== Health Check ===\n";
    auto health = client.check_health();
    if (health) {
        std::cout << "  Status:  " << health.value.status << "\n"
                  << "  Service: " << health.value.service << "\n";
    } else {
        std::cout << "  FAILED: " << health.error << "\n";
    }
    std::cout << "\n";

    // --- Authentication ---
    if (!username.empty() && !password.empty()) {
        std::cout << "=== Authentication ===\n";
        auto auth = client.authenticate(username, password);
        if (auth) {
            std::cout << "  Authenticated: true\n"
                      << "  User ID: " << auth.value.user_id << "\n"
                      << "  Token:   " << auth.value.session_token.substr(0, 20) << "...\n";
        } else {
            std::cout << "  FAILED: " << auth.error << "\n";
        }
        std::cout << "\n";
    }

    // --- List relays ---
    std::cout << "=== Relay List ===\n";
    auto relays = client.list_relays();
    if (relays) {
        std::cout << "  Found " << relays.value.size() << " relay(s)\n";
        for (const auto& r : relays.value) {
            std::cout << "    - " << r.relay_id
                      << " [" << r.endpoint << "]"
                      << " region=" << r.region
                      << " score=" << r.reputation_score << "\n";
        }
    } else {
        std::cout << "  FAILED: " << relays.error << "\n";
    }
    std::cout << "\n";

    // --- Certificate status ---
    std::cout << "=== Certificate Status (lemonade-nexus.local) ===\n";
    auto cert = client.get_cert_status("lemonade-nexus.local");
    if (cert) {
        std::cout << "  Domain:   " << cert.value.domain << "\n"
                  << "  Has cert: " << (cert.value.has_cert ? "yes" : "no") << "\n"
                  << "  Expires:  " << cert.value.expires_at << "\n";
    } else {
        std::cout << "  FAILED: " << cert.error << "\n";
    }
    std::cout << "\n";

    std::cout << "Done.\n";
    return 0;
}
