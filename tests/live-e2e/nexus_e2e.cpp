// nexus-e2e: a headless test client that runs the live end-to-end scenario
// against the production fleet through the public SDK C ABI
// (lemonade_nexus.h). See docs/Live-E2E.md for the scenario, the accounts it
// uses, and what it proves.
//
// This is a test tool. It is built only with BUILD_TESTING and is never
// packaged. CTest runs only its offline self-test.
//
// Secret handling: invite codes, identity files, and session tokens are never
// printed. An invite travels between CI jobs only inside a bundle that is
// sealed to the member account's Ed25519 key and bound to the CI run id.

#include <LemonadeNexusSDK/lemonade_nexus.h>

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sodium.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace {

using json = nlohmann::json;
using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

constexpr const char* kDefaultDomain = "lemonade-nexus.io";
constexpr const char* kDefaultRegion = "us-west";
constexpr uint16_t    kDefaultApiPort = 9100;
constexpr uint16_t    kDefaultVport = 18080;
constexpr uint32_t    kDefaultInviteTtlSec = 3600;  // the server's maximum
constexpr int64_t     kHandshakeFreshSec = 180;     // RelayFallback::Timing default
constexpr std::size_t kDataBytes = 64 * 1024;
constexpr const char* kBundleAd = "lemonade-nexus/live-e2e/invite-bundle/v1";

/// owner-serve stops waiting when the member does not call within this time
/// of the start, or goes silent for this long before it asks for removal, so
/// a failed member job does not hold the owner runner until --timeout.
constexpr auto kFirstContactLimit = std::chrono::seconds(900);
constexpr auto kIdleLimit = std::chrono::seconds(1200);

/// Permissions of the CI invite: membership and connect, nothing more.
constexpr const char* kInvitePermissions = R"(["read","connect_private"])";

std::atomic<bool> g_stop{false};

extern "C" void on_signal(int) { g_stop.store(true); }

// ---------------------------------------------------------------------------
// Logging. Messages never contain invite codes, tokens, or private keys.
// ---------------------------------------------------------------------------

void log_line(const char* level, const std::string& msg) {
    std::time_t now = std::time(nullptr);
    char stamp[32];
    std::strftime(stamp, sizeof stamp, "%H:%M:%S", std::gmtime(&now));
    std::fprintf(stderr, "%s [nexus-e2e] %s %s\n", stamp, level, msg.c_str());
    std::fflush(stderr);
}
void info(const std::string& m) { log_line("INFO", m); }
void warn(const std::string& m) { log_line("WARN", m); }
void fail_log(const std::string& m) { log_line("FAIL", m); }

/// A GitHub Actions annotation, printed only when running in Actions.
void annotate(const char* kind, const std::string& msg) {
    if (std::getenv("GITHUB_ACTIONS")) std::printf("::%s::%s\n", kind, msg.c_str());
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Owns a string returned by the SDK and releases it with ln_free.
struct SdkString {
    char* p = nullptr;
    SdkString() = default;
    explicit SdkString(char* s) : p(s) {}
    SdkString(const SdkString&) = delete;
    SdkString& operator=(const SdkString&) = delete;
    ~SdkString() { reset(); }
    void reset() {
        if (p) ln_free(p);
        p = nullptr;
    }
    /// Zero the contents first (for secret-bearing strings).
    void wipe() {
        if (p) sodium_memzero(p, std::strlen(p));
        reset();
    }
    char** out() {
        reset();
        return &p;
    }
    [[nodiscard]] std::string str() const { return p ? std::string(p) : std::string{}; }
    [[nodiscard]] json parsed() const {
        if (!p) return json::object();
        auto j = json::parse(p, nullptr, false);
        return j.is_discarded() ? json::object() : j;
    }
};

std::string b64_encode(const unsigned char* data, std::size_t len) {
    std::string out(sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL), '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_ORIGINAL);
    out.resize(std::strlen(out.c_str()));
    return out;
}

/// Decode base64 in any of the spellings in use: the SDK writes URL-safe
/// base64 without padding, and the server and libsodium tools write the
/// standard alphabet with padding.
std::optional<std::vector<unsigned char>> b64_decode(const std::string& text) {
    for (const int variant :
         {sodium_base64_VARIANT_ORIGINAL, sodium_base64_VARIANT_ORIGINAL_NO_PADDING,
          sodium_base64_VARIANT_URLSAFE, sodium_base64_VARIANT_URLSAFE_NO_PADDING}) {
        std::vector<unsigned char> out(text.size());
        std::size_t len = 0;
        if (sodium_base642bin(out.data(), out.size(), text.c_str(), text.size(), nullptr, &len,
                              nullptr, variant) == 0) {
            out.resize(len);
            return out;
        }
    }
    return std::nullopt;
}

/// Key bytes of a principal ("ed25519:<b64>" or bare base64), so two
/// spellings of one key compare equal. Empty for malformed input.
std::string canonical_key(const std::string& principal) {
    std::string b64 = principal;
    if (b64.rfind("ed25519:", 0) == 0) b64 = b64.substr(8);
    auto bytes = b64_decode(b64);
    if (!bytes || bytes->size() != 32) return {};
    return std::string(bytes->begin(), bytes->end());
}

std::string strip_prefix_len(const std::string& cidr) {
    auto slash = cidr.find('/');
    return slash == std::string::npos ? cidr : cidr.substr(0, slash);
}

int64_t unix_now() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

/// Sleep in short slices so a signal ends the wait. False when stopping.
bool nap(std::chrono::milliseconds d) {
    auto until = Clock::now() + d;
    while (Clock::now() < until) {
        if (g_stop.load()) return false;
        std::this_thread::sleep_for(std::min<std::chrono::milliseconds>(
            200ms, std::chrono::duration_cast<std::chrono::milliseconds>(until - Clock::now())));
    }
    return !g_stop.load();
}

/// Poll `check` every `every` until it returns true or `limit` passes.
bool wait_until(std::chrono::seconds limit, std::chrono::milliseconds every,
                const std::function<bool()>& check) {
    auto deadline = Clock::now() + limit;
    while (Clock::now() < deadline) {
        if (check()) return true;
        if (!nap(every)) return false;
    }
    return check();
}

bool write_private_file(const std::string& path, const std::string& text) {
    // Create with 0600 so the content is never readable by other users.
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;
    (void)::fchmod(fd, 0600);
    std::size_t done = 0;
    while (done < text.size()) {
        auto n = ::write(fd, text.data() + done, text.size() - done);
        if (n <= 0) {
            ::close(fd);
            return false;
        }
        done += static_cast<std::size_t>(n);
    }
    return ::close(fd) == 0;
}

std::optional<std::string> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::string trim(std::string s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    std::size_t i = 0;
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    return s.substr(i);
}

// ---------------------------------------------------------------------------
// Command line
// ---------------------------------------------------------------------------

struct Endpoint {
    std::string host;
    uint16_t    port = kDefaultApiPort;
};

std::optional<Endpoint> parse_endpoint(const std::string& text) {
    if (text.empty()) return std::nullopt;
    Endpoint ep;
    auto colon = text.rfind(':');
    if (colon == std::string::npos) {
        ep.host = text;
    } else {
        ep.host = text.substr(0, colon);
        const auto port_text = text.substr(colon + 1);
        if (port_text.empty() || port_text.size() > 5 ||
            !std::all_of(port_text.begin(), port_text.end(), ::isdigit)) {
            return std::nullopt;
        }
        const auto port = std::stoul(port_text);
        if (port == 0 || port > 65535) return std::nullopt;
        ep.port = static_cast<uint16_t>(port);
    }
    if (ep.host.empty()) return std::nullopt;
    for (char c : ep.host) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-') {
            return std::nullopt;
        }
    }
    return ep;
}

struct Options {
    std::string command;
    std::string identity;          // identity file to use
    std::string identity_out;      // setup-account: file to create
    std::string role;              // setup-account: owner | member
    std::string domain = kDefaultDomain;
    std::string region = kDefaultRegion;
    std::vector<Endpoint> seeds;   // replaces DNS discovery when set
    std::string expect_genesis_key;
    std::string member_pubkey;     // owner side: the member account's key
    std::string owner_pubkey;      // member cleanup: limit to this owner's groups
    std::string run_id;
    std::string bundle_out;
    std::string bundle;            // path of the sealed bundle
    std::string summary;           // Markdown summary file to append to
    uint16_t    vport = kDefaultVport;
    uint32_t    ttl_sec = kDefaultInviteTtlSec;
    uint32_t    timeout_sec = 2400;
    bool        force = false;
};

const std::map<std::string, std::set<std::string>>& command_options() {
    static const std::map<std::string, std::set<std::string>> table = {
        {"self-test", {}},
        {"discover", {"--domain", "--region", "--seed", "--expect-genesis-key"}},
        {"setup-account",
         {"--identity-out", "--role", "--domain", "--region", "--seed",
          "--expect-genesis-key", "--force"}},
        {"owner-invite",
         {"--identity", "--member-pubkey", "--run-id", "--bundle-out", "--ttl", "--vport",
          "--domain", "--region", "--seed", "--expect-genesis-key", "--summary"}},
        {"owner-serve",
         {"--identity", "--member-pubkey", "--run-id", "--vport", "--timeout", "--domain",
          "--region", "--seed", "--expect-genesis-key", "--summary"}},
        {"member",
         {"--identity", "--bundle", "--run-id", "--domain", "--region", "--seed",
          "--expect-genesis-key", "--summary"}},
        {"cleanup-owner",
         {"--identity", "--domain", "--region", "--seed", "--expect-genesis-key", "--summary"}},
        {"cleanup-member",
         {"--identity", "--owner-pubkey", "--domain", "--region", "--seed",
          "--expect-genesis-key", "--summary"}},
    };
    return table;
}

const std::set<std::string>& flag_options() {
    static const std::set<std::string> flags = {"--force"};
    return flags;
}

void print_usage() {
    std::printf(
        "Usage: nexus-e2e <command> [options]\n"
        "\n"
        "Live end-to-end test client for Lemonade Nexus (docs/Live-E2E.md).\n"
        "\n"
        "Commands:\n"
        "  self-test        Offline checks (argument parsing, bundle sealing, path rules)\n"
        "  discover         DNS discovery and Genesis key discovery only\n"
        "  setup-account    One time: create a persistent account (--role owner|member)\n"
        "  owner-invite     Owner: mint two invites and write a sealed bundle\n"
        "  owner-serve      Owner: serve the test service and control API over the mesh\n"
        "  member           Member: run join, direct, relay, leave, and removal checks\n"
        "  cleanup-owner    Owner: remove every other member entry from the CI group\n"
        "  cleanup-member   Member: leave every group entered through an invite\n"
        "\n"
        "Common options:\n"
        "  --identity PATH            Identity file ({public_key, private_key})\n"
        "  --domain NAME              DNS base domain (default %s)\n"
        "  --region CODE              SEIP region for discovery (default %s)\n"
        "  --seed HOST[:PORT]         Use this server instead of DNS discovery (repeatable)\n"
        "  --expect-genesis-key B64   Fail when the discovered Genesis key differs\n"
        "  --summary PATH             Append a Markdown result table to PATH\n"
        "\n"
        "Command options:\n"
        "  --identity-out PATH        setup-account: identity file to create (mode 0600)\n"
        "  --role owner|member        setup-account: account role to check\n"
        "  --force                    setup-account: replace an existing identity file\n"
        "  --member-pubkey KEY        owner-*: the member account's ed25519 public key\n"
        "  --owner-pubkey KEY         cleanup-member: leave only this owner's groups\n"
        "  --run-id ID                CI run id that binds the bundle and the service\n"
        "  --bundle-out PATH          owner-invite: sealed bundle file to write (mode 0600)\n"
        "  --bundle PATH              member: sealed bundle file to read\n"
        "  --ttl SEC                  owner-invite: invite lifetime (1..3600, default %u)\n"
        "  --vport PORT               mesh port of the test service (default %u)\n"
        "  --timeout SEC              owner-serve: total serve time (default 2400)\n"
        "\n"
        "Invite codes, tokens, and keys are never printed.\n",
        kDefaultDomain, kDefaultRegion, kDefaultInviteTtlSec, kDefaultVport);
}

bool parse_u32(const std::string& text, uint32_t lo, uint32_t hi, uint32_t& out) {
    if (text.empty() || text.size() > 10 || !std::all_of(text.begin(), text.end(), ::isdigit)) {
        return false;
    }
    const auto v = std::stoull(text);
    if (v < lo || v > hi) return false;
    out = static_cast<uint32_t>(v);
    return true;
}

bool valid_run_id(const std::string& id) {
    if (id.empty() || id.size() > 64) return false;
    return std::all_of(id.begin(), id.end(), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.';
    });
}

/// Parse argv into Options. Returns an error message, or nullopt on success.
std::optional<std::string> parse_args(const std::vector<std::string>& args, Options& o) {
    if (args.empty()) return std::string{"missing command"};
    o.command = args[0];
    const auto& table = command_options();
    const auto allowed = table.find(o.command);
    if (allowed == table.end()) return "unknown command '" + o.command + "'";

    for (std::size_t i = 1; i < args.size(); ++i) {
        const auto& name = args[i];
        if (!allowed->second.contains(name)) {
            return "option '" + name + "' is not valid for '" + o.command + "'";
        }
        if (flag_options().contains(name)) {
            if (name == "--force") o.force = true;
            continue;
        }
        if (i + 1 >= args.size()) return "option '" + name + "' needs a value";
        const auto& value = args[++i];
        if (name == "--identity") o.identity = value;
        else if (name == "--identity-out") o.identity_out = value;
        else if (name == "--role") o.role = value;
        else if (name == "--domain") o.domain = value;
        else if (name == "--region") o.region = value;
        else if (name == "--expect-genesis-key") o.expect_genesis_key = value;
        else if (name == "--member-pubkey") o.member_pubkey = value;
        else if (name == "--owner-pubkey") o.owner_pubkey = value;
        else if (name == "--run-id") o.run_id = value;
        else if (name == "--bundle-out") o.bundle_out = value;
        else if (name == "--bundle") o.bundle = value;
        else if (name == "--summary") o.summary = value;
        else if (name == "--seed") {
            auto ep = parse_endpoint(value);
            if (!ep) return "invalid --seed '" + value + "'";
            o.seeds.push_back(*ep);
        } else if (name == "--ttl") {
            if (!parse_u32(value, 1, 3600, o.ttl_sec)) return std::string{"--ttl must be 1..3600"};
        } else if (name == "--vport") {
            uint32_t v = 0;
            if (!parse_u32(value, 1, 65535, v)) return std::string{"--vport must be 1..65535"};
            o.vport = static_cast<uint16_t>(v);
        } else if (name == "--timeout") {
            if (!parse_u32(value, 60, 86400, o.timeout_sec)) {
                return std::string{"--timeout must be 60..86400"};
            }
        }
    }

    // Per-command requirements.
    const auto need = [&](const std::string& value,
                          const char* what) -> std::optional<std::string> {
        if (value.empty()) return std::string(what) + " is required for '" + o.command + "'";
        return std::nullopt;
    };
    std::optional<std::string> err;
    if (o.command == "setup-account") {
        if ((err = need(o.identity_out, "--identity-out"))) return err;
        if (o.role != "owner" && o.role != "member") {
            return std::string{"--role must be owner or member"};
        }
    }
    if (o.command == "owner-invite" || o.command == "owner-serve" || o.command == "member" ||
        o.command == "cleanup-owner" || o.command == "cleanup-member") {
        if ((err = need(o.identity, "--identity"))) return err;
    }
    if (o.command == "owner-invite" || o.command == "owner-serve") {
        if ((err = need(o.member_pubkey, "--member-pubkey"))) return err;
        if (canonical_key(o.member_pubkey).empty()) {
            return std::string{"--member-pubkey is not an ed25519 key"};
        }
    }
    if (o.command == "owner-invite") {
        if ((err = need(o.bundle_out, "--bundle-out"))) return err;
    }
    if (o.command == "member") {
        if ((err = need(o.bundle, "--bundle"))) return err;
    }
    if (o.command == "owner-invite" || o.command == "owner-serve" || o.command == "member") {
        if ((err = need(o.run_id, "--run-id"))) return err;
        if (!valid_run_id(o.run_id)) {
            return std::string{"--run-id may use only [A-Za-z0-9._-], at most 64"};
        }
    }
    if (!o.owner_pubkey.empty() && canonical_key(o.owner_pubkey).empty()) {
        return std::string{"--owner-pubkey is not an ed25519 key"};
    }
    for (char c : o.domain) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '.' && c != '-') {
            return std::string{"invalid --domain"};
        }
    }
    for (char c : o.region) {
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-') {
            return std::string{"invalid --region"};
        }
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Results and the Markdown summary
// ---------------------------------------------------------------------------

enum class Outcome { Pass, Fail, Skipped };

struct Check {
    std::string name;
    Outcome     outcome;
    std::string detail;
};

struct Report {
    std::string        title;
    std::vector<Check> checks;

    void add(const std::string& name, Outcome o, const std::string& detail) {
        checks.push_back({name, o, detail});
        const char* tag = o == Outcome::Pass ? "PASS" : o == Outcome::Fail ? "FAIL" : "SKIP";
        log_line(tag, name + ": " + detail);
        if (o == Outcome::Fail) annotate("error", name + ": " + detail);
        if (o == Outcome::Skipped) annotate("warning", name + ": " + detail);
    }
    [[nodiscard]] bool failed() const {
        return std::any_of(checks.begin(), checks.end(),
                           [](const Check& c) { return c.outcome == Outcome::Fail; });
    }
    void write_summary(const std::string& path) const {
        if (path.empty()) return;
        std::ofstream out(path, std::ios::app);
        if (!out) return;
        out << "### " << title << "\n\n| Check | Result | Detail |\n|---|---|---|\n";
        for (const auto& c : checks) {
            const char* r = c.outcome == Outcome::Pass ? "pass"
                            : c.outcome == Outcome::Fail ? "**fail**" : "skipped";
            std::string d = c.detail;
            std::replace(d.begin(), d.end(), '|', '/');
            out << "| " << c.name << " | " << r << " | " << d << " |\n";
        }
        out << "\n";
    }
};

// ---------------------------------------------------------------------------
// Invite bundle: the two invite codes, sealed to the member account.
//
// A fresh 32-byte key K is sealed to the member's Ed25519 key with the SDK's
// group-key envelope (ln_group_key_wrap: a libsodium sealed box). K encrypts
// the payload with XChaCha20-Poly1305; the associated data binds the bundle
// to its format version, recipient, and CI run id, so a bundle from another
// run, or for another account, does not open.
// ---------------------------------------------------------------------------

std::string bundle_ad(const std::string& recipient, const std::string& run_id) {
    std::string ad = kBundleAd;
    ad.push_back('\0');
    ad += canonical_key(recipient);
    ad.push_back('\0');
    ad += run_id;
    return ad;
}

std::optional<std::string> seal_bundle(const json& payload, const std::string& recipient,
                                       const std::string& run_id) {
    if (canonical_key(recipient).empty()) return std::nullopt;
    SdkString key_b64(ln_group_key_generate());
    if (!key_b64.p) return std::nullopt;
    SdkString envelope(ln_group_key_wrap(recipient.c_str(), key_b64.p));
    auto key = b64_decode(key_b64.str());
    key_b64.wipe();
    if (!envelope.p || !key || key->size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
        if (key) sodium_memzero(key->data(), key->size());
        return std::nullopt;
    }

    std::string plain = payload.dump();
    std::vector<unsigned char> nonce(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    const auto ad = bundle_ad(recipient, run_id);
    std::vector<unsigned char> cipher(plain.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    unsigned long long cipher_len = 0;
    crypto_aead_xchacha20poly1305_ietf_encrypt(
        cipher.data(), &cipher_len, reinterpret_cast<const unsigned char*>(plain.data()),
        plain.size(), reinterpret_cast<const unsigned char*>(ad.data()), ad.size(), nullptr,
        nonce.data(), key->data());
    sodium_memzero(plain.data(), plain.size());
    sodium_memzero(key->data(), key->size());
    cipher.resize(cipher_len);

    json bundle = {
        {"v", 1},
        {"recipient", recipient},
        {"envelope", envelope.parsed()},
        {"nonce", b64_encode(nonce.data(), nonce.size())},
        {"ciphertext", b64_encode(cipher.data(), cipher.size())},
    };
    const auto text = bundle.dump();
    // One base64 line: safe to pass as a GitHub job output.
    return b64_encode(reinterpret_cast<const unsigned char*>(text.data()), text.size());
}

std::optional<json> open_bundle(const std::string& sealed, const ln_identity_t* identity,
                                const std::string& run_id, std::string& error) {
    auto outer = b64_decode(trim(sealed));
    if (!outer) {
        error = "the bundle is not base64";
        return std::nullopt;
    }
    auto bundle = json::parse(outer->begin(), outer->end(), nullptr, false);
    if (bundle.is_discarded() || !bundle.is_object() || bundle.value("v", 0) != 1 ||
        !bundle.contains("envelope") || !bundle["envelope"].is_object()) {
        error = "the bundle format is not version 1";
        return std::nullopt;
    }
    SdkString own(ln_identity_pubkey(identity));
    const auto recipient = bundle.value("recipient", std::string{});
    if (canonical_key(recipient).empty() || canonical_key(recipient) != canonical_key(own.str())) {
        error = "the bundle is sealed to another account";
        return std::nullopt;
    }
    SdkString key_b64(ln_group_key_unwrap(identity, bundle["envelope"].dump().c_str()));
    if (!key_b64.p) {
        error = "the bundle key does not open with this identity";
        return std::nullopt;
    }
    auto key = b64_decode(key_b64.str());
    key_b64.wipe();
    auto nonce = b64_decode(bundle.value("nonce", std::string{}));
    auto cipher = b64_decode(bundle.value("ciphertext", std::string{}));
    if (!key || key->size() != crypto_aead_xchacha20poly1305_ietf_KEYBYTES || !nonce ||
        nonce->size() != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES || !cipher ||
        cipher->size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        if (key) sodium_memzero(key->data(), key->size());
        error = "the bundle fields are malformed";
        return std::nullopt;
    }
    const auto ad = bundle_ad(recipient, run_id);
    std::string plain(cipher->size() - crypto_aead_xchacha20poly1305_ietf_ABYTES, '\0');
    unsigned long long plain_len = 0;
    const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
        reinterpret_cast<unsigned char*>(plain.data()), &plain_len, nullptr, cipher->data(),
        cipher->size(), reinterpret_cast<const unsigned char*>(ad.data()), ad.size(),
        nonce->data(), key->data());
    sodium_memzero(key->data(), key->size());
    if (rc != 0) {
        error = "the bundle does not authenticate (another run, or modified)";
        return std::nullopt;
    }
    plain.resize(plain_len);
    auto payload = json::parse(plain, nullptr, false);
    sodium_memzero(plain.data(), plain.size());
    if (payload.is_discarded() || !payload.is_object()) {
        error = "the bundle payload is not JSON";
        return std::nullopt;
    }
    return payload;
}

// ---------------------------------------------------------------------------
// Path classification of one mesh peer
// ---------------------------------------------------------------------------

/// One peer's dataplane state from ln_mesh_status.
struct PeerPath {
    bool        found = false;
    std::string endpoint;
    std::string relay_endpoint;
    int64_t     last_handshake = 0;
    uint64_t    rx = 0;
    uint64_t    tx = 0;
};

enum class PathKind { Direct, Relay, Unproven };

const char* path_name(PathKind k) {
    switch (k) {
        case PathKind::Direct: return "direct";
        case PathKind::Relay: return "relay";
        default: return "unproven";
    }
}

/// Counters grew between two samples. A peer that was re-added starts again
/// from zero, so a smaller value that is not zero also counts as traffic.
bool counter_moved(uint64_t before, uint64_t after) {
    return after > before || (after < before && after > 0);
}

/// Which path carried traffic to the peer between `before` and `after`.
/// Direct and Relay need a fresh handshake with the peer itself and traffic
/// in both directions on that peer, so traffic that the Tier 1 server
/// forwarded (no peer handshake) stays Unproven.
PathKind classify_path(const PeerPath& before, const PeerPath& after, int64_t now) {
    if (!after.found) return PathKind::Unproven;
    const bool fresh = after.last_handshake > 0 && now - after.last_handshake < kHandshakeFreshSec;
    const bool moved = counter_moved(before.rx, after.rx) && counter_moved(before.tx, after.tx);
    if (!fresh || !moved) return PathKind::Unproven;
    if (!after.relay_endpoint.empty()) return PathKind::Relay;
    if (!after.endpoint.empty()) return PathKind::Direct;
    return PathKind::Unproven;
}

/// The data body served for a run: deterministic, so the member can check it.
std::string data_body(const std::string& run_id) {
    std::string out;
    out.reserve(kDataBytes);
    const std::string unit = "lemonade-nexus-live-e2e:" + run_id + ";";
    while (out.size() < kDataBytes) out += unit;
    out.resize(kDataBytes);
    return out;
}

// ---------------------------------------------------------------------------
// Discovery: the region's SEIP A records, then each server's certificate name
// (the same steps as the client app's DNS discovery). The certificate name is
// only a candidate: ln_discover_genesis_key then requires verified HTTPS to
// that name and agreement of at least three servers in the DNS domain.
// ---------------------------------------------------------------------------

std::vector<std::string> resolve_ipv4_all(const std::string& name) {
    std::vector<std::string> out;
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(name.c_str(), nullptr, &hints, &res) != 0) return out;
    for (auto* p = res; p; p = p->ai_next) {
        char buf[INET_ADDRSTRLEN] = {};
        auto* sin = reinterpret_cast<sockaddr_in*>(p->ai_addr);
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof buf)) {
            if (std::find(out.begin(), out.end(), buf) == out.end()) out.emplace_back(buf);
        }
    }
    freeaddrinfo(res);
    return out;
}

int connect_with_timeout(const std::string& ip, uint16_t port, int timeout_ms) {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip.c_str(), &addr.sin_addr) != 1) return -1;
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr);
    if (rc != 0 && errno == EINPROGRESS) {
        pollfd pfd{fd, POLLOUT, 0};
        rc = ::poll(&pfd, 1, timeout_ms) == 1 ? 0 : -1;
        int soerr = 0;
        socklen_t len = sizeof soerr;
        if (rc == 0 && (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len) != 0 || soerr != 0)) {
            rc = -1;
        }
    }
    if (rc != 0) {
        ::close(fd);
        return -1;
    }
    ::fcntl(fd, F_SETFL, flags);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    return fd;
}

/// The subject common name of the server's leaf certificate, or "".
std::string certificate_name(const std::string& ip, uint16_t port) {
    int fd = connect_with_timeout(ip, port, 5000);
    if (fd < 0) return {};
    std::string name;
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL* ssl = ctx ? SSL_new(ctx) : nullptr;
    if (ssl) {
        // No verification here: the name is a candidate, and the SDK verifies
        // HTTPS to it before it trusts anything the server says.
        SSL_set_verify(ssl, SSL_VERIFY_NONE, nullptr);
        SSL_set_fd(ssl, fd);
        if (SSL_connect(ssl) == 1) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
            X509* cert = SSL_get1_peer_certificate(ssl);
#else
            X509* cert = SSL_get_peer_certificate(ssl);
#endif
            if (cert) {
                char buf[256] = {};
                if (X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, buf,
                                              sizeof buf) > 0) {
                    name = buf;
                }
                X509_free(cert);
            }
            SSL_shutdown(ssl);
        }
        SSL_free(ssl);
    }
    if (ctx) SSL_CTX_free(ctx);
    ::close(fd);
    return name;
}

bool name_in_domain(const std::string& name, const std::string& domain) {
    if (name.size() <= domain.size() + 1) return false;
    if (name.compare(name.size() - domain.size(), domain.size(), domain) != 0) return false;
    if (name[name.size() - domain.size() - 1] != '.') return false;
    return parse_endpoint(name).has_value() && name.find('*') == std::string::npos;
}

std::vector<Endpoint> discover_seeds(const Options& o, Report& report) {
    if (!o.seeds.empty()) {
        report.add("discovery", Outcome::Pass,
                   std::to_string(o.seeds.size()) + " seed server(s) from --seed");
        return o.seeds;
    }
    const auto region_name = o.region + ".seip." + o.domain;
    const auto ips = resolve_ipv4_all(region_name);
    std::vector<Endpoint> seeds;
    for (const auto& ip : ips) {
        auto name = certificate_name(ip, kDefaultApiPort);
        if (name_in_domain(name, o.domain)) {
            if (std::none_of(seeds.begin(), seeds.end(),
                             [&](const Endpoint& e) { return e.host == name; })) {
                seeds.push_back({name, kDefaultApiPort});
            }
        } else {
            warn("server " + ip + " gave no certificate name in " + o.domain);
        }
    }
    std::string names;
    for (const auto& s : seeds) names += (names.empty() ? "" : ", ") + s.host;
    if (seeds.empty()) {
        report.add("discovery", Outcome::Fail,
                   "no server found from " + region_name + " (" + std::to_string(ips.size()) +
                       " address(es))");
    } else {
        report.add("discovery", Outcome::Pass,
                   std::to_string(seeds.size()) + " server(s) from " + region_name + ": " + names);
    }
    return seeds;
}

// ---------------------------------------------------------------------------
// A connected SDK session
// ---------------------------------------------------------------------------

struct Session {
    ln_client_t*   client = nullptr;
    ln_identity_t* identity = nullptr;
    std::string    pubkey;      // "ed25519:<b64>"
    std::string    node_id;
    std::string    tunnel_ip;
    std::string    genesis_key;

    Session() = default;
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    ~Session() {
        if (client) ln_destroy(client);  // stops the mesh and the mesh port
        if (identity) ln_identity_destroy(identity);
    }
};

json mesh_config(bool prefer_direct) {
    return {{"peer_refresh_interval_sec", 10u},
            {"heartbeat_interval_sec", 5u},
            {"stun_refresh_interval_sec", 30u},
            {"prefer_direct", prefer_direct},
            {"auto_connect", true}};
}

bool set_mesh_mode(Session& s, bool prefer_direct) {
    return ln_mesh_enable_config(s.client, mesh_config(prefer_direct).dump().c_str()) == LN_OK;
}

/// Create the client, discover and pin the Genesis key, and verify Tier 1.
bool open_client(const Options& o, Session& s, Report& report) {
    const auto seeds = discover_seeds(o, report);
    if (seeds.empty()) return false;

    s.client = ln_create_tls(seeds.front().host.c_str(), seeds.front().port);
    if (!s.client) {
        report.add("client", Outcome::Fail, "ln_create_tls returned NULL");
        return false;
    }
    json hosts = json::array();
    for (const auto& e : seeds) hosts.push_back({{"host", e.host}, {"port", e.port}});
    SdkString out;
    const auto rc = ln_discover_genesis_key(s.client, hosts.dump().c_str(), out.out());
    const auto found = out.parsed();
    if (rc != LN_OK) {
        report.add("genesis key", Outcome::Fail,
                   "ln_discover_genesis_key " + std::to_string(rc) + ": " +
                       found.value("error", std::string{"no detail"}));
        return false;
    }
    s.genesis_key = found.value("genesis_pubkey", std::string{});
    const auto agreeing = found.contains("hosts") && found["hosts"].is_array()
                              ? found["hosts"].size() : 0;
    if (!o.expect_genesis_key.empty() && s.genesis_key != o.expect_genesis_key) {
        report.add("genesis key", Outcome::Fail,
                   "discovered key " + s.genesis_key + " differs from --expect-genesis-key");
        return false;
    }
    report.add("genesis key", Outcome::Pass,
               "pinned " + s.genesis_key + " (network " +
                   found.value("network_id", std::string{"?"}).substr(0, 16) + ", " +
                   std::to_string(agreeing) + " agreeing servers)");

    SdkString t1;
    const auto t1rc = ln_tier1_refresh(s.client, t1.out());
    const auto membership = t1.parsed();
    if (t1rc != LN_OK) {
        report.add("tier 1", Outcome::Fail,
                   "ln_tier1_refresh " + std::to_string(t1rc) + ": " +
                       membership.value("error", std::string{"no detail"}));
        return false;
    }
    std::string servers;
    if (membership.contains("servers") && membership["servers"].is_array()) {
        for (const auto& srv : membership["servers"]) {
            servers += (servers.empty() ? "" : ", ") + srv.value("host", std::string{"?"});
        }
    }
    report.add("tier 1", Outcome::Pass,
               "epoch " + std::to_string(membership.value("epoch", uint64_t{0})) + ": " + servers);
    return true;
}

/// Wait until a private-API call over the mesh answers.
bool wait_private_api(Session& s, std::chrono::seconds limit) {
    return wait_until(limit, 2s, [&] {
        SdkString out;
        return ln_memberships_list(s.client, out.out()) == LN_OK;
    });
}

/// Join with the session's identity (a returning device keeps its node) and
/// bring up the mesh. `link_token` is used only by setup-account.
bool join_and_mesh(Session& s, Report& report, const std::string& link_token = {}) {
    SdkString pub(ln_identity_pubkey(s.identity));
    s.pubkey = pub.str();
    ln_set_identity(s.client, s.identity);
    if (!link_token.empty()) ln_set_link_token(s.client, link_token.c_str());

    json joined;
    ln_error_t rc = LN_ERR_INTERNAL;
    for (int attempt = 0; attempt < 4 && !g_stop.load(); ++attempt) {
        SdkString out;
        rc = ln_join_network(s.client, "", "", out.out());
        joined = out.parsed();
        if (rc == LN_OK) break;
        warn("join attempt " + std::to_string(attempt + 1) + " failed: " +
             joined.value("error", std::string{"no detail"}));
        if (!link_token.empty()) break;  // never retry a single-use code blindly
        nap(std::chrono::seconds(5 * (attempt + 1)));
    }
    if (rc != LN_OK) {
        report.add("join", Outcome::Fail,
                   "ln_join_network " + std::to_string(rc) + ": " +
                       joined.value("error", std::string{"no detail"}));
        return false;
    }
    s.node_id = joined.value("node_id", std::string{});
    s.tunnel_ip = joined.value("tunnel_ip", std::string{});
    if (s.node_id.empty() || s.tunnel_ip.empty()) {
        report.add("join", Outcome::Fail, "the join returned no node id or tunnel address");
        return false;
    }
    report.add("join", Outcome::Pass, "node " + s.node_id + ", tunnel " + s.tunnel_ip);

    if (!set_mesh_mode(s, true) || !ln_mesh_is_active(s.client)) {
        report.add("mesh", Outcome::Fail, "the mesh dataplane did not start");
        return false;
    }
    if (!wait_private_api(s, 180s)) {
        report.add("mesh", Outcome::Fail, "the private API did not answer over the mesh in 180 s");
        return false;
    }
    report.add("mesh", Outcome::Pass, "private API reachable over the mesh");
    return true;
}

bool load_identity(const Options& o, Session& s, Report& report) {
    s.identity = ln_identity_load(o.identity.c_str());
    if (!s.identity) {
        report.add("identity", Outcome::Fail, "cannot load the identity file");
        return false;
    }
    return true;
}

bool connect_session(const Options& o, Session& s, Report& report) {
    return load_identity(o, s, report) && open_client(o, s, report) && join_and_mesh(s, report);
}

json memberships(Session& s, ln_error_t* rc_out = nullptr) {
    SdkString out;
    const auto rc = ln_memberships_list(s.client, out.out());
    if (rc_out) *rc_out = rc;
    auto j = out.parsed();
    if (!j.contains("memberships") || !j["memberships"].is_array()) return json::array();
    return j["memberships"];
}

std::optional<json> membership_of(Session& s, const std::string& group_id) {
    for (const auto& m : memberships(s)) {
        if (m.value("node_id", std::string{}) == group_id) return m;
    }
    return std::nullopt;
}

bool has_permission(const json& entry, const std::string& perm) {
    if (!entry.contains("permissions") || !entry["permissions"].is_array()) return false;
    for (const auto& p : entry["permissions"]) {
        if (p.is_string() && p.get<std::string>() == perm) return true;
    }
    return false;
}

/// The group that holds this device: its endpoint's parent.
std::string home_group(Session& s) {
    SdkString out;
    if (ln_tree_get_node(s.client, s.node_id.c_str(), out.out()) != LN_OK) return {};
    return out.parsed().value("parent_id", std::string{});
}

json mesh_peers(Session& s) {
    SdkString out;
    if (ln_mesh_peers(s.client, out.out()) != LN_OK) return json::array();
    auto j = out.parsed();
    return j.is_array() ? j : json::array();
}

std::optional<json> find_peer(Session& s, const std::string& node_id) {
    for (const auto& p : mesh_peers(s)) {
        if (p.value("node_id", std::string{}) == node_id) return p;
    }
    return std::nullopt;
}

PeerPath peer_path(Session& s, const std::string& mesh_pubkey) {
    PeerPath path;
    SdkString out;
    if (ln_mesh_status(s.client, out.out()) != LN_OK) return path;
    const auto status = out.parsed();
    if (!status.contains("peers") || !status["peers"].is_array()) return path;
    for (const auto& p : status["peers"]) {
        if (p.value("mesh_pubkey", std::string{}) != mesh_pubkey) continue;
        path.found = true;
        path.endpoint = p.value("endpoint", std::string{});
        path.relay_endpoint = p.value("relay_endpoint", std::string{});
        path.last_handshake = p.value("last_handshake", int64_t{0});
        path.rx = p.value("rx_bytes", uint64_t{0});
        path.tx = p.value("tx_bytes", uint64_t{0});
        break;
    }
    return path;
}

// ---------------------------------------------------------------------------
// HTTP over the mesh (member side)
// ---------------------------------------------------------------------------

struct FetchResult {
    bool        ok = false;
    int         status = 0;
    std::string body;
    std::string error;
};

FetchResult mesh_request(Session& s, const std::string& peer_ip, uint16_t vport,
                         const std::string& method, const std::string& path,
                         std::chrono::seconds timeout, bool fresh_bridge = false) {
    FetchResult r;
    if (fresh_bridge) ln_mesh_close_egress(s.client, peer_ip.c_str(), vport);
    uint16_t local = 0;
    if (ln_mesh_open_egress(s.client, peer_ip.c_str(), vport, &local) != LN_OK || local == 0) {
        r.error = "no egress bridge";
        return r;
    }
    httplib::Client cli("127.0.0.1", local);
    cli.set_connection_timeout(timeout);
    cli.set_read_timeout(timeout);
    cli.set_write_timeout(timeout);
    auto res = method == "POST" ? cli.Post(path, std::string{}, "text/plain") : cli.Get(path);
    if (!res) {
        r.error = httplib::to_string(res.error());
        return r;
    }
    r.status = res->status;
    r.body = res->body;
    r.ok = res->status == 200;
    if (!r.ok) r.error = "HTTP " + std::to_string(res->status);
    return r;
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

int finish(const Options& o, const Report& report) {
    report.write_summary(o.summary);
    return report.failed() ? 1 : 0;
}

int cmd_discover(const Options& o) {
    Report report{"Discovery", {}};
    Session s;
    open_client(o, s, report);
    return finish(o, report);
}

int cmd_setup_account(const Options& o) {
    Report report{"Setup account (" + o.role + ")", {}};
    struct stat st{};
    if (::stat(o.identity_out.c_str(), &st) == 0 && !o.force) {
        report.add("identity", Outcome::Fail,
                   o.identity_out + " exists; pass --force to replace it");
        return finish(o, report);
    }
    Session s;
    s.identity = ln_identity_generate();
    if (!s.identity || ln_identity_save(s.identity, o.identity_out.c_str()) != LN_OK) {
        report.add("identity", Outcome::Fail, "cannot create " + o.identity_out);
        return finish(o, report);
    }
    report.add("identity", Outcome::Pass, "wrote " + o.identity_out + " (mode 0600)");

    // An optional invite code: the account then joins the inviter's group. It
    // is read from the environment so that it is not in the process arguments.
    std::string code;
    if (const char* env = std::getenv("NEXUS_E2E_INVITE_CODE")) code = trim(env);

    if (!open_client(o, s, report) || !join_and_mesh(s, report, code)) {
        sodium_memzero(code.data(), code.size());
        return finish(o, report);
    }
    sodium_memzero(code.data(), code.size());

    const auto group = home_group(s);
    const auto entry = group.empty() ? std::nullopt : membership_of(s, group);
    const bool admin = entry && has_permission(*entry, "admin");
    if (o.role == "owner" && !admin) {
        report.add("ci group", Outcome::Fail,
                   "this account does not administer its group " + group +
                       "; the owner account needs its own top-level group (see docs/Live-E2E.md)");
    } else {
        report.add("ci group", Outcome::Pass,
                   "home group " + group + (admin ? " (admin)" : " (member)"));
    }
    // Public values only: the key, node, and group. The private key stays in
    // the identity file.
    std::printf("role=%s\npublic_key=%s\nnode_id=%s\ngroup_id=%s\ngenesis_key=%s\n",
                o.role.c_str(), s.pubkey.c_str(), s.node_id.c_str(), group.c_str(),
                s.genesis_key.c_str());
    return finish(o, report);
}

int cmd_owner_invite(const Options& o) {
    Report report{"Owner: create invites", {}};
    Session s;
    if (!connect_session(o, s, report)) return finish(o, report);

    const auto group = home_group(s);
    const auto entry = group.empty() ? std::nullopt : membership_of(s, group);
    if (!entry || !has_permission(*entry, "admin")) {
        report.add("ci group", Outcome::Fail,
                   "the owner account does not administer its group '" + group + "'");
        return finish(o, report);
    }
    report.add("ci group", Outcome::Pass, group);

    // Two invites: the first proves join and leave, the second proves removal.
    json invites = json::array();
    uint64_t expires = 0;
    for (int i = 0; i < 2; ++i) {
        SdkString out;
        const auto rc = ln_invite_create(s.client, group.c_str(), kInvitePermissions, o.ttl_sec,
                                         out.out());
        auto j = out.parsed();
        const auto code = j.value("link_token", std::string{});
        if (rc != LN_OK || code.empty() || j.value("group_node_id", std::string{}) != group) {
            report.add("invite", Outcome::Fail,
                       "ln_invite_create " + std::to_string(rc) + ": " +
                           j.value("error", std::string{"no code returned"}));
            out.wipe();
            return finish(o, report);
        }
        expires = j.value("expires_at", uint64_t{0});
        invites.push_back(code);
        out.wipe();
    }
    report.add("invite", Outcome::Pass,
               "2 single-use invites into " + group + ", expire at unix " +
                   std::to_string(expires) + " (codes are not printed)");

    const json payload = {{"group_id", group},
                          {"owner_node_id", s.node_id},
                          {"owner_pubkey", s.pubkey},
                          {"vport", o.vport},
                          {"invites", invites}};
    auto sealed = seal_bundle(payload, o.member_pubkey, o.run_id);
    for (auto& code : invites) {
        auto& str = code.get_ref<std::string&>();
        sodium_memzero(str.data(), str.size());
    }
    if (!sealed || !write_private_file(o.bundle_out, *sealed + "\n")) {
        report.add("bundle", Outcome::Fail, "cannot seal or write the bundle");
        return finish(o, report);
    }
    report.add("bundle", Outcome::Pass,
               "sealed to the member key and run " + o.run_id + ", written to " + o.bundle_out);
    return finish(o, report);
}

int cmd_owner_serve(const Options& o) {
    Report report{"Owner: serve over the mesh", {}};
    Session s;
    if (!connect_session(o, s, report)) return finish(o, report);
    const auto group = home_group(s);
    if (group.empty()) {
        report.add("ci group", Outcome::Fail, "cannot read the owner's group");
        return finish(o, report);
    }

    std::mutex mtx;
    std::optional<Clock::time_point> last_contact;  // any request from the member
    std::string member_node;         // learned from the member's hello
    bool seen_member = false;        // the member was in this device's peer list
    std::optional<bool> mode_request;
    bool removal_requested = false;
    std::string removal_result;
    const std::string body = data_body(o.run_id);

    httplib::Server srv;
    srv.Get("/e2e/hello", [&](const httplib::Request& req, httplib::Response& res) {
        const auto node = req.get_param_value("member_node");
        {
            std::lock_guard lock(mtx);
            last_contact = Clock::now();
        }
        ln_mesh_refresh(s.client);
        bool sees = false;
        if (!node.empty()) {
            // The peer list follows the refresh within a moment.
            for (int i = 0; i < 6 && !sees; ++i) {
                sees = find_peer(s, node).has_value();
                if (!sees) std::this_thread::sleep_for(500ms);
            }
        }
        {
            std::lock_guard lock(mtx);
            if (!node.empty()) member_node = node;
            if (sees) seen_member = true;
        }
        res.set_content(json{{"run_id", o.run_id},
                             {"owner_node_id", s.node_id},
                             {"sees_member", sees}}.dump(),
                        "application/json");
    });
    srv.Get("/e2e/data", [&](const httplib::Request&, httplib::Response& res) {
        {
            std::lock_guard lock(mtx);
            last_contact = Clock::now();
        }
        res.set_content(body, "application/octet-stream");
    });
    srv.Post("/e2e/mode", [&](const httplib::Request& req, httplib::Response& res) {
        const auto v = req.get_param_value("prefer_direct");
        if (v != "0" && v != "1") {
            res.status = 400;
            return;
        }
        {
            std::lock_guard lock(mtx);
            last_contact = Clock::now();
            mode_request = (v == "1");
        }
        // Applied by the main loop after this answer leaves.
        res.set_content(R"({"ok":true})", "application/json");
    });
    srv.Post("/e2e/remove", [&](const httplib::Request&, httplib::Response& res) {
        // The removed key is fixed by configuration, never taken from the request.
        SdkString out;
        const auto rc = ln_remove_group_member(s.client, group.c_str(),
                                               o.member_pubkey.c_str(), out.out());
        const auto j = out.parsed();
        {
            std::lock_guard lock(mtx);
            last_contact = Clock::now();
            removal_requested = true;
            removal_result = rc == LN_OK ? "ok"
                                         : "ln_remove_group_member " + std::to_string(rc) + ": " +
                                               j.value("error", std::string{"no detail"});
        }
        res.set_content(json{{"ok", rc == LN_OK}, {"rc", rc}}.dump(), "application/json");
    });

    const int port = srv.bind_to_any_port("127.0.0.1");
    if (port <= 0) {
        report.add("service", Outcome::Fail, "cannot bind the local test service");
        return finish(o, report);
    }
    std::thread server_thread([&] { srv.listen_after_bind(); });
    const auto target = "tcp:127.0.0.1:" + std::to_string(port);
    if (ln_mesh_expose_service(s.client, o.vport, target.c_str()) != LN_OK) {
        report.add("service", Outcome::Fail, "ln_mesh_expose_service refused the exposure");
        srv.stop();
        server_thread.join();
        return finish(o, report);
    }
    report.add("service", Outcome::Pass,
               s.tunnel_ip + ":" + std::to_string(o.vport) + " exposed over the mesh");

    const auto started = Clock::now();
    const auto deadline = started + std::chrono::seconds(o.timeout_sec);
    std::optional<Clock::time_point> removed_at;
    bool member_gone = false;
    std::string stop_reason = "the serve time ended";
    while (!g_stop.load()) {
        const auto now = Clock::now();
        if (now >= deadline) break;
        std::optional<bool> mode;
        bool removal = false;
        std::string node;
        std::optional<Clock::time_point> contact;
        {
            std::lock_guard lock(mtx);
            std::swap(mode, mode_request);
            removal = removal_requested;
            node = member_node;
            contact = last_contact;
        }
        if (!contact && now - started > kFirstContactLimit) {
            stop_reason = "the member did not call within 900 s";
            break;
        }
        if (contact && !removal && now - *contact > kIdleLimit) {
            stop_reason = "the member was silent for 1200 s";
            break;
        }
        if (mode) {
            nap(500ms);  // let the answer reach the member first
            info(std::string("switching the mesh to prefer_direct=") + (*mode ? "true" : "false"));
            if (!set_mesh_mode(s, *mode)) warn("ln_mesh_enable_config failed");
        }
        if (removal) {
            if (!removed_at) removed_at = Clock::now();
            ln_mesh_refresh(s.client);
            if (!node.empty() && !find_peer(s, node)) {
                member_gone = true;
                break;
            }
            if (Clock::now() - *removed_at > 180s) break;
        }
        nap(1s);
    }
    srv.stop();
    server_thread.join();

    std::lock_guard lock(mtx);
    report.add("member seen", seen_member ? Outcome::Pass : Outcome::Fail,
               seen_member ? "the member " + member_node + " was in the owner's peer list"
                           : "the member never appeared in the owner's peer list");
    if (!removal_requested) {
        report.add("removal", Outcome::Fail,
                   "the member never asked for its removal (" + stop_reason + ")");
    } else if (removal_result != "ok") {
        report.add("removal", Outcome::Fail, removal_result);
    } else {
        report.add("removal", member_gone ? Outcome::Pass : Outcome::Fail,
                   member_gone ? "member entry removed; the member left the owner's peer list"
                               : "member entry removed, but it stayed in the peer list for 180 s");
    }
    return finish(o, report);
}

/// Member-side scenario state.
struct MemberRun {
    const Options& o;
    Session&       s;
    Report&        report;
    std::string    group_id;
    std::string    owner_node_id;
    std::string    owner_ip;
    std::string    owner_mesh_key;
    uint16_t       vport = kDefaultVport;

    MemberRun(const Options& opts, Session& session, Report& rep)
        : o(opts), s(session), report(rep) {}

    bool accept(const std::string& code, const std::string& label) {
        SdkString out;
        const auto rc = ln_invite_accept(s.client, code.c_str(), out.out());
        const auto j = out.parsed();
        if (rc != LN_OK) {
            std::string why = j.value("error", std::string{"no detail"});
            if (rc == LN_ERR_AUTH) {
                why += ". Invites are stored only on the Tier 1 server that minted them; the "
                       "owner and member may have used different servers";
            }
            report.add(label, Outcome::Fail, "ln_invite_accept " + std::to_string(rc) + ": " + why);
            return false;
        }
        const auto status = j.value("status", std::string{});
        const bool listed = wait_until(120s, 2s, [&] {
            auto m = membership_of(s, group_id);
            return m && m->value("role", std::string{}) == "member";
        });
        report.add(label, listed ? Outcome::Pass : Outcome::Fail,
                   listed ? "member of " + group_id + " (answer: " + status + ")"
                          : "accepted (" + status + ") but not listed as a member in 120 s");
        return listed;
    }

    bool wait_owner_peer(const std::string& label) {
        const bool found = wait_until(240s, 2s, [&] {
            ln_mesh_refresh(s.client);
            auto p = find_peer(s, owner_node_id);
            if (!p) return false;
            owner_ip = strip_prefix_len(p->value("tunnel_ip", std::string{}));
            owner_mesh_key = p->value("mesh_pubkey", std::string{});
            return !owner_ip.empty() && !owner_mesh_key.empty();
        });
        report.add(label, found ? Outcome::Pass : Outcome::Fail,
                   found ? "owner " + owner_node_id + " listed at " + owner_ip
                         : "the owner did not appear in the member's peer list in 240 s");
        return found;
    }

    /// The owner answers and lists this device as its peer.
    bool hello(const std::string& label, std::chrono::seconds limit) {
        std::string last;
        const bool ok = wait_until(limit, 3s, [&] {
            auto r = mesh_request(s, owner_ip, vport, "GET",
                                  "/e2e/hello?member_node=" + s.node_id, 10s);
            if (!r.ok) {
                last = r.error;
                return false;
            }
            auto j = json::parse(r.body, nullptr, false);
            if (j.is_discarded() || j.value("run_id", std::string{}) != o.run_id ||
                j.value("owner_node_id", std::string{}) != owner_node_id) {
                last = "the service answered for another run or device";
                return false;
            }
            if (!j.value("sees_member", false)) {
                last = "the owner does not list this device yet";
                return false;
            }
            return true;
        });
        report.add(label, ok ? Outcome::Pass : Outcome::Fail,
                   ok ? "owner service answered and lists this device as a peer"
                      : "no valid answer in " + std::to_string(limit.count()) + " s (" + last +
                            ")");
        return ok;
    }

    /// Fetch the data body once and classify the path that carried it.
    PathKind fetch_and_classify(std::string& note) {
        const auto before = peer_path(s, owner_mesh_key);
        auto r = mesh_request(s, owner_ip, vport, "GET", "/e2e/data", 15s);
        if (!r.ok) {
            note = "fetch failed: " + r.error;
            return PathKind::Unproven;
        }
        if (r.body != data_body(o.run_id)) {
            note = "the data body did not match";
            return PathKind::Unproven;
        }
        const auto after = peer_path(s, owner_mesh_key);
        const auto kind = classify_path(before, after, unix_now());
        note = "fetched " + std::to_string(r.body.size()) + " bytes; endpoint '" + after.endpoint +
               "', relay '" + after.relay_endpoint + "', handshake age " +
               (after.last_handshake > 0 ? std::to_string(unix_now() - after.last_handshake) + " s"
                                         : std::string{"none"});
        return kind;
    }

    void direct_path() {
        std::string note;
        PathKind last = PathKind::Unproven;
        const bool ok = wait_until(150s, 5s, [&] {
            last = fetch_and_classify(note);
            return last == PathKind::Direct;
        });
        if (ok) {
            report.add("direct path", Outcome::Pass, note);
        } else {
            // Hole punching can be impossible between two runners (for example
            // behind endpoint-dependent NAT). Record it; the relay check still runs.
            report.add("direct path", Outcome::Skipped,
                       std::string("no direct path in 150 s on this runner pair (last path: ") +
                           path_name(last) + "; " + note + ")");
        }
    }

    bool relay_path() {
        auto r = mesh_request(s, owner_ip, vport, "POST", "/e2e/mode?prefer_direct=0", 10s);
        if (!r.ok) {
            report.add("relay path", Outcome::Fail,
                       "the owner did not accept relay mode: " + r.error);
            return false;
        }
        if (!set_mesh_mode(s, false)) {
            report.add("relay path", Outcome::Fail, "ln_mesh_enable_config refused relay mode");
            return false;
        }
        std::string note;
        PathKind last = PathKind::Unproven;
        const bool ok = wait_until(240s, 5s, [&] {
            ln_mesh_refresh(s.client);
            auto p = find_peer(s, owner_node_id);
            if (p) owner_mesh_key = p->value("mesh_pubkey", owner_mesh_key);
            last = fetch_and_classify(note);
            return last == PathKind::Relay;
        });
        report.add("relay path", ok ? Outcome::Pass : Outcome::Fail,
                   ok ? note
                      : std::string("no relayed fetch in 240 s (last path: ") + path_name(last) +
                            "; " + note + ")");
        return ok;
    }

    /// After leave or removal: no membership, no peer, and no reachable service.
    bool assert_cut_off(const std::string& label) {
        const bool no_membership = wait_until(180s, 3s, [&] {
            ln_error_t rc = LN_OK;
            const auto list = memberships(s, &rc);
            if (rc != LN_OK) return false;
            return std::none_of(list.begin(), list.end(), [&](const json& m) {
                return m.value("node_id", std::string{}) == group_id;
            });
        });
        const bool no_peer = wait_until(180s, 3s, [&] {
            ln_mesh_refresh(s.client);
            return !find_peer(s, owner_node_id).has_value();
        });
        int failures = 0;
        std::string last;
        const bool unreachable = wait_until(180s, 3s, [&] {
            auto r = mesh_request(s, owner_ip, vport, "GET", "/e2e/data", 5s, true);
            if (r.ok) {
                failures = 0;
                last = "the service still answered";
                return false;
            }
            last = r.error;
            return ++failures >= 3;  // three refusals in a row
        });
        const bool ok = no_membership && no_peer && unreachable;
        std::string detail = std::string("membership gone: ") + (no_membership ? "yes" : "no") +
                             ", owner peer gone: " + (no_peer ? "yes" : "no") +
                             ", service unreachable: " + (unreachable ? "yes" : "no");
        if (!unreachable) detail += " (" + last + ")";
        report.add(label, ok ? Outcome::Pass : Outcome::Fail, detail);
        return ok;
    }
};

int cmd_member(const Options& o) {
    Report report{"Member: join, paths, leave, removal", {}};
    Session s;
    if (!load_identity(o, s, report)) return finish(o, report);

    const auto sealed = read_file(o.bundle);
    if (!sealed) {
        report.add("bundle", Outcome::Fail, "cannot read " + o.bundle);
        return finish(o, report);
    }
    std::string why;
    auto payload = open_bundle(*sealed, s.identity, o.run_id, why);
    if (!payload) {
        report.add("bundle", Outcome::Fail, why);
        return finish(o, report);
    }
    std::vector<std::string> codes;
    if ((*payload).contains("invites") && (*payload)["invites"].is_array()) {
        for (auto& c : (*payload)["invites"]) {
            if (c.is_string()) codes.push_back(c.get<std::string>());
            if (c.is_string()) {
                auto& str = c.get_ref<std::string&>();
                sodium_memzero(str.data(), str.size());
            }
        }
    }
    MemberRun run{o, s, report};
    run.group_id = payload->value("group_id", std::string{});
    run.owner_node_id = payload->value("owner_node_id", std::string{});
    run.vport = static_cast<uint16_t>(payload->value("vport", uint32_t{kDefaultVport}));
    if (codes.size() != 2 || run.group_id.empty() || run.owner_node_id.empty()) {
        report.add("bundle", Outcome::Fail, "the bundle payload is incomplete");
        return finish(o, report);
    }
    report.add("bundle", Outcome::Pass,
               "opened for run " + o.run_id + ": group " + run.group_id + ", owner " +
                   run.owner_node_id);

    const auto wipe_codes = [&] {
        for (auto& c : codes) sodium_memzero(c.data(), c.size());
    };
    if (!open_client(o, s, report) || !join_and_mesh(s, report)) {
        wipe_codes();
        return finish(o, report);
    }

    // A failed earlier run can leave this account in the group.
    if (auto stale = membership_of(s, run.group_id);
        stale && stale->value("role", std::string{}) == "member") {
        SdkString out;
        const auto rc = ln_membership_leave(s.client, run.group_id.c_str(), out.out());
        report.add("stale membership", rc == LN_OK ? Outcome::Pass : Outcome::Fail,
                   rc == LN_OK ? "left a membership from an earlier run"
                               : "cannot leave an earlier membership: " +
                                     out.parsed().value("error", std::string{"no detail"}));
        if (rc != LN_OK || !run.assert_cut_off("stale membership cleared")) {
            wipe_codes();
            return finish(o, report);
        }
    }

    bool ok = run.accept(codes[0], "accept invite 1") &&
              run.wait_owner_peer("owner peer listed") &&
              run.hello("both list each other", 600s);
    if (ok) {
        run.direct_path();
        ok = run.relay_path();
    }
    if (ok) {
        SdkString out;
        const auto rc = ln_membership_leave(s.client, run.group_id.c_str(), out.out());
        if (rc != LN_OK) {
            report.add("leave", Outcome::Fail,
                       "ln_membership_leave " + std::to_string(rc) + ": " +
                           out.parsed().value("error", std::string{"no detail"}));
            ok = false;
        } else {
            ok = run.assert_cut_off("leave");
        }
    }
    if (ok) {
        ok = run.accept(codes[1], "accept invite 2") &&
             run.wait_owner_peer("owner peer listed again") &&
             run.hello("both list each other again", 300s);
    }
    wipe_codes();
    if (ok) {
        auto r = mesh_request(s, run.owner_ip, run.vport, "POST", "/e2e/remove", 30s);
        auto j = json::parse(r.body, nullptr, false);
        if (r.ok && (j.is_discarded() || !j.value("ok", false))) {
            report.add("removal", Outcome::Fail, "the owner refused to remove the membership");
        } else {
            // The answer can be lost when the removal cuts the path first;
            // the cut-off checks decide the result either way.
            if (!r.ok) warn("no answer to the removal request (" + r.error + ")");
            run.assert_cut_off("removal");
        }
    }
    return finish(o, report);
}

int cmd_cleanup_owner(const Options& o) {
    Report report{"Cleanup: owner", {}};
    Session s;
    if (!connect_session(o, s, report)) return finish(o, report);
    const auto group = home_group(s);
    if (group.empty()) {
        report.add("ci group", Outcome::Fail, "cannot read the owner's group");
        return finish(o, report);
    }
    SdkString out;
    if (ln_get_group_members(s.client, group.c_str(), out.out()) != LN_OK) {
        report.add("members", Outcome::Fail, "cannot read the members of " + group);
        return finish(o, report);
    }
    const auto own = canonical_key(s.pubkey);
    int removed = 0;
    int failed = 0;
    for (const auto& m : out.parsed()) {
        const auto key = m.value("management_pubkey", std::string{});
        if (key.empty() || canonical_key(key) == own) continue;
        SdkString res;
        if (ln_remove_group_member(s.client, group.c_str(), key.c_str(), res.out()) == LN_OK) {
            ++removed;
            info("removed member entry " + key + " from " + group);
        } else {
            ++failed;
            warn("cannot remove member entry " + key + ": " +
                 res.parsed().value("error", std::string{"no detail"}));
        }
    }
    // Devices that joined into the CI group are reported, not deleted: the
    // scenario never places one there, so any such device needs a person.
    SdkString children;
    int foreign = 0;
    if (ln_tree_get_children(s.client, group.c_str(), children.out()) == LN_OK) {
        for (const auto& c : children.parsed()) {
            if (c.value("type", std::string{}) == "endpoint" &&
                canonical_key(c.value("mgmt_pubkey", std::string{})) != own) {
                ++foreign;
                warn("device " + c.value("id", std::string{"?"}) +
                     " in the CI group is not the owner's; remove it by hand if it is stale");
            }
        }
    }
    report.add("member entries", failed == 0 ? Outcome::Pass : Outcome::Fail,
               std::to_string(removed) + " removed, " + std::to_string(failed) + " failed, " +
                   std::to_string(foreign) + " other device(s) reported");
    return finish(o, report);
}

int cmd_cleanup_member(const Options& o) {
    Report report{"Cleanup: member", {}};
    Session s;
    if (!connect_session(o, s, report)) return finish(o, report);
    const auto owner = canonical_key(o.owner_pubkey);
    int left = 0;
    int failed = 0;
    for (const auto& m : memberships(s)) {
        if (m.value("role", std::string{}) != "member") continue;
        if (!owner.empty() && canonical_key(m.value("owner_pubkey", std::string{})) != owner) {
            continue;
        }
        const auto group = m.value("node_id", std::string{});
        SdkString out;
        if (ln_membership_leave(s.client, group.c_str(), out.out()) == LN_OK) {
            ++left;
            info("left " + group);
        } else {
            ++failed;
            warn("cannot leave " + group + ": " +
                 out.parsed().value("error", std::string{"no detail"}));
        }
    }
    report.add("memberships", failed == 0 ? Outcome::Pass : Outcome::Fail,
               std::to_string(left) + " left, " + std::to_string(failed) + " failed");
    return finish(o, report);
}

// ---------------------------------------------------------------------------
// Offline self-test
// ---------------------------------------------------------------------------

int cmd_self_test() {
    int failures = 0;
    const auto expect = [&](bool cond, const std::string& what) {
        if (!cond) {
            ++failures;
            fail_log(what);
        }
    };

    // Argument parsing.
    {
        Options o;
        expect(parse_args({}, o).has_value(), "an empty command line is refused");
        expect(parse_args({"bogus"}, o).has_value(), "an unknown command is refused");
        Options a;
        expect(!parse_args({"discover", "--seed", "a.example.io:9100", "--seed", "b.example.io"}, a)
                    .has_value() && a.seeds.size() == 2 && a.seeds[1].port == kDefaultApiPort,
               "seeds parse with and without a port");
        Options b;
        expect(parse_args({"discover", "--seed", "bad host"}, b).has_value(),
               "a seed with a space is refused");
        Options c;
        expect(parse_args({"discover", "--seed", "a.io:0"}, c).has_value(), "port 0 is refused");
        Options d;
        expect(parse_args({"discover", "--identity", "x"}, d).has_value(),
               "an option of another command is refused");
        Options e;
        expect(parse_args({"member", "--identity", "i", "--bundle"}, e).has_value(),
               "a missing option value is refused");
        Options f;
        expect(parse_args({"member", "--identity", "i", "--bundle", "b"}, f).has_value(),
               "member needs --run-id");
        Options g;
        expect(parse_args({"member", "--identity", "i", "--bundle", "b", "--run-id", "1 2"}, g)
                   .has_value(),
               "a run id with a space is refused");
        Options h;
        expect(parse_args({"owner-invite", "--identity", "i", "--member-pubkey", "nope",
                           "--run-id", "1", "--bundle-out", "x"}, h).has_value(),
               "a malformed member key is refused");
        Options k;
        expect(parse_args({"owner-invite", "--identity", "i", "--member-pubkey",
                           "ed25519:" + std::string(43, 'A') + "=", "--run-id", "42-1",
                           "--bundle-out", "x", "--ttl", "3601"}, k).has_value(),
               "a TTL above the server maximum is refused");
        Options m;
        expect(!parse_args({"setup-account", "--identity-out", "x", "--role", "owner",
                            "--force"}, m).has_value() && m.force,
               "setup-account accepts --force");
        Options n;
        expect(parse_args({"setup-account", "--identity-out", "x", "--role", "admin"}, n)
                   .has_value(),
               "an unknown role is refused");
    }

    // Domain matching for discovered certificate names.
    expect(name_in_domain("sn01.us-west.seip.lemonade-nexus.io", "lemonade-nexus.io"),
           "a SEIP name is inside the domain");
    expect(!name_in_domain("lemonade-nexus.io", "lemonade-nexus.io"), "the apex is not a server");
    expect(!name_in_domain("evil-lemonade-nexus.io", "lemonade-nexus.io"),
           "a suffix without a dot is outside the domain");
    expect(!name_in_domain("*.lemonade-nexus.io", "lemonade-nexus.io"), "a wildcard is refused");

    // Bundle sealing with throwaway identities (never saved).
    {
        ln_identity_t* member = ln_identity_generate();
        ln_identity_t* other = ln_identity_generate();
        SdkString member_pub(ln_identity_pubkey(member));
        const json payload = {{"group_id", "customer-x"}, {"invites", {"code-1", "code-2"}}};
        auto sealed = seal_bundle(payload, member_pub.str(), "run-1");
        expect(sealed.has_value(), "a bundle seals");
        if (sealed) {
            expect(sealed->find("code-1") == std::string::npos, "the bundle hides the codes");
            std::string err;
            auto opened = open_bundle(*sealed, member, "run-1", err);
            expect(opened && *opened == payload, "the recipient opens the bundle");
            expect(!open_bundle(*sealed, other, "run-1", err), "another identity cannot open it");
            expect(!open_bundle(*sealed, member, "run-2", err), "another run id cannot open it");
            // Flip one ciphertext byte.
            auto outer = b64_decode(*sealed);
            auto bundle = json::parse(outer->begin(), outer->end());
            auto cipher = *b64_decode(bundle["ciphertext"].get<std::string>());
            cipher[0] ^= 0x01;
            bundle["ciphertext"] = b64_encode(cipher.data(), cipher.size());
            const auto text = bundle.dump();
            const auto tampered =
                b64_encode(reinterpret_cast<const unsigned char*>(text.data()), text.size());
            expect(!open_bundle(tampered, member, "run-1", err), "a modified bundle is refused");
            expect(!open_bundle("not base64 !", member, "run-1", err), "garbage is refused");
        }
        expect(!seal_bundle(payload, "ed25519:short", "run-1"), "a malformed recipient is refused");
        ln_identity_destroy(member);
        ln_identity_destroy(other);
    }

    // Path classification.
    {
        const int64_t now = 1'000'000;
        PeerPath before{true, "203.0.113.5:51940", "", now - 10, 100, 100};
        PeerPath direct{true, "203.0.113.5:51940", "", now - 5, 70000, 900};
        expect(classify_path(before, direct, now) == PathKind::Direct, "fresh direct traffic");
        PeerPath relay{true, "", "198.51.100.9:9103", now - 5, 70000, 900};
        expect(classify_path(before, relay, now) == PathKind::Relay, "fresh relayed traffic");
        PeerPath stale = direct;
        stale.last_handshake = now - kHandshakeFreshSec;
        expect(classify_path(before, stale, now) == PathKind::Unproven, "a stale handshake");
        PeerPath idle{true, "203.0.113.5:51940", "", now - 5, 100, 100};
        expect(classify_path(before, idle, now) == PathKind::Unproven,
               "no traffic on the peer (server forwarded)");
        PeerPath reset{true, "203.0.113.5:51940", "", now - 5, 40, 30};
        expect(classify_path(before, reset, now) == PathKind::Direct,
               "counters that restarted after a re-add");
        expect(classify_path(before, PeerPath{}, now) == PathKind::Unproven, "a missing peer");
    }

    expect(data_body("r").size() == kDataBytes && data_body("r") == data_body("r") &&
               data_body("r") != data_body("s"),
           "the data body is deterministic per run");
    expect(!canonical_key("ed25519:" + std::string(43, 'A')).empty() &&
               canonical_key("ed25519:" + std::string(43, 'A')) ==
                   canonical_key(std::string(43, 'A') + "="),
           "prefixed, unpadded, and padded spellings are one principal");
    expect(canonical_key("ed25519:AAAA").empty(), "a short key is not a principal");

    if (failures == 0) info("self-test passed");
    return failures == 0 ? 0 : 1;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        std::fprintf(stderr, "libsodium failed to initialize\n");
        return 1;
    }
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.empty() || args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
        print_usage();
        return args.empty() ? 2 : 0;
    }
    Options o;
    if (auto err = parse_args(args, o)) {
        std::fprintf(stderr, "nexus-e2e: %s (see --help)\n", err->c_str());
        return 2;
    }
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);

    if (o.command == "self-test") return cmd_self_test();
    if (o.command == "discover") return cmd_discover(o);
    if (o.command == "setup-account") return cmd_setup_account(o);
    if (o.command == "owner-invite") return cmd_owner_invite(o);
    if (o.command == "owner-serve") return cmd_owner_serve(o);
    if (o.command == "member") return cmd_member(o);
    if (o.command == "cleanup-owner") return cmd_cleanup_owner(o);
    if (o.command == "cleanup-member") return cmd_cleanup_member(o);
    return 2;
}
