#include <LemonadeNexus/Network/DdnsService.hpp>

#include <LemonadeNexus/Gossip/ServerCertificate.hpp>

#include <httplib.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstring>
#include <regex>

namespace nexus::network {

using json = nlohmann::json;
namespace chrono = std::chrono;

// ---------------------------------------------------------------------------
// DdnsConfig serialization
// ---------------------------------------------------------------------------

void to_json(json& j, const DdnsConfig& c) {
    j = json{
        {"provider",             c.provider},
        {"domain",               c.domain},
        {"ddns_password",        c.ddns_password},
        {"update_interval_sec",  c.update_interval_sec},
        {"enabled",              c.enabled},
    };
}

void from_json(const json& j, DdnsConfig& c) {
    if (j.contains("provider"))            j.at("provider").get_to(c.provider);
    if (j.contains("domain"))              j.at("domain").get_to(c.domain);
    if (j.contains("ddns_password"))       j.at("ddns_password").get_to(c.ddns_password);
    if (j.contains("update_interval_sec")) j.at("update_interval_sec").get_to(c.update_interval_sec);
    if (j.contains("enabled"))             j.at("enabled").get_to(c.enabled);
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

DdnsService::DdnsService(asio::io_context& io,
                           crypto::SodiumCryptoService& crypto,
                           storage::FileStorageService& storage,
                           core::BinaryAttestationService& attestation,
                           gossip::GossipService& gossip)
    : io_(io)
    , update_timer_(io)
    , crypto_(crypto)
    , storage_(storage)
    , attestation_(attestation)
    , gossip_(gossip)
{
}

// ---------------------------------------------------------------------------
// IService lifecycle
// ---------------------------------------------------------------------------

void DdnsService::on_start() {
    // Try to load encrypted credentials from disk
    if (load_encrypted_credentials()) {
        spdlog::info("[{}] loaded encrypted DDNS credentials from disk", name());
        has_credentials_ = true;
    }

    if (has_credentials_ && config_.enabled && !our_hostname_.empty()) {
        // Do an initial update, then start the periodic timer
        update_now();
        start_update_timer();
    }

    spdlog::info("[{}] started (credentials={}, hostname={}, domain={})",
                  name(),
                  has_credentials_ ? "yes" : "no",
                  our_hostname_.empty() ? "(none)" : our_hostname_,
                  config_.domain.empty() ? "(none)" : config_.domain);
}

void DdnsService::on_stop() {
    update_timer_.cancel();
    timer_running_ = false;
    spdlog::info("[{}] stopped", name());
}

// ---------------------------------------------------------------------------
// Credential management
// ---------------------------------------------------------------------------

void DdnsService::set_credentials(const DdnsConfig& config) {
    std::lock_guard lock(mutex_);
    config_ = config;
    has_credentials_ = true;

    save_encrypted_credentials();

    if (config_.enabled && !our_hostname_.empty() && !timer_running_) {
        start_update_timer();
    }

    spdlog::info("[{}] DDNS credentials set (domain={}, interval={}s)",
                  name(), config_.domain, config_.update_interval_sec);
}

void DdnsService::set_hostname(const std::string& hostname) {
    std::lock_guard lock(mutex_);
    our_hostname_ = hostname;
    spdlog::info("[{}] hostname set to '{}'", name(), hostname);
}

bool DdnsService::has_credentials() const {
    std::lock_guard lock(mutex_);
    return has_credentials_;
}

std::string DdnsService::last_ip() const {
    std::lock_guard lock(mutex_);
    return last_known_ip_;
}

// ---------------------------------------------------------------------------
// Credential distribution: requester side
// ---------------------------------------------------------------------------

bool DdnsService::request_credentials(const std::string& root_http_endpoint,
                                        const crypto::Ed25519PrivateKey& our_privkey,
                                        const std::string& our_cert_json) {
    spdlog::info("[{}] requesting DDNS credentials from {}", name(), root_http_endpoint);

    // Build the request
    json request;
    request["server_certificate"] = our_cert_json;
    request["binary_hash"] = attestation_.self_hash();

    // Sign the request to prove we own the private key
    auto request_str = request.dump();
    auto request_bytes = std::vector<uint8_t>(request_str.begin(), request_str.end());
    auto sig = crypto_.ed25519_sign(our_privkey, request_bytes);
    request["signature"] = crypto::to_base64(sig);

    // Derive our X25519 public key for DH (so root can encrypt to us)
    auto our_x_pub = crypto::SodiumCryptoService::ed25519_pk_to_x25519(
        [&]() {
            // Extract pubkey from the first 32 bytes embedded in the 64-byte privkey
            crypto::Ed25519PublicKey pk{};
            std::memcpy(pk.data(), our_privkey.data() + 32, 32);
            return pk;
        }());
    request["x25519_pubkey"] = crypto::to_base64(our_x_pub);

    // Parse endpoint
    auto colon_pos = root_http_endpoint.rfind(':');
    if (colon_pos == std::string::npos) {
        spdlog::error("[{}] invalid root endpoint: {}", name(), root_http_endpoint);
        return false;
    }
    auto host = root_http_endpoint.substr(0, colon_pos);
    auto port_str = root_http_endpoint.substr(colon_pos + 1);
    auto port = std::atoi(port_str.c_str());

    // POST to root server
    httplib::Client client(host, port);
    client.set_connection_timeout(10);
    client.set_read_timeout(10);

    auto result = client.Post("/api/credentials/request",
                               request.dump(),
                               "application/json");

    if (!result || result->status != 200) {
        int status = result ? result->status : 0;
        spdlog::error("[{}] credential request failed (status={})", name(), status);
        return false;
    }

    // Parse response
    try {
        auto response = json::parse(result->body);

        if (!response.value("success", false)) {
            spdlog::error("[{}] credential request denied: {}",
                           name(), response.value("error", "unknown"));
            return false;
        }

        // Decrypt the credentials using X25519 DH
        auto root_x_pub_bytes = crypto::from_base64(
            response.value("x25519_pubkey", ""));
        if (root_x_pub_bytes.size() != crypto::kX25519PublicKeySize) {
            spdlog::error("[{}] invalid root X25519 pubkey in response", name());
            return false;
        }

        crypto::X25519PublicKey root_x_pub{};
        std::memcpy(root_x_pub.data(), root_x_pub_bytes.data(), crypto::kX25519PublicKeySize);

        // Our X25519 private key (derived from Ed25519)
        auto our_x_priv = crypto::SodiumCryptoService::ed25519_sk_to_x25519(our_privkey);

        // DH shared secret
        auto shared_secret = crypto_.x25519_dh(our_x_priv, root_x_pub);

        // Derive AES-256-GCM key from shared secret
        const std::string info_str = "lemonade-nexus-ddns-credentials";
        auto aes_key_bytes = crypto_.hkdf_sha256(
            shared_secret,
            std::span<const uint8_t>{}, // no salt
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size()),
            crypto::kAesGcmKeySize);

        crypto::AesGcmKey aes_key{};
        std::memcpy(aes_key.data(), aes_key_bytes.data(), crypto::kAesGcmKeySize);

        // Decrypt the credentials
        auto ciphertext_bytes = crypto::from_base64(
            response.value("encrypted_credentials", ""));
        auto nonce_bytes = crypto::from_base64(
            response.value("nonce", ""));

        if (nonce_bytes.size() != crypto::kAesGcmNonceSize) {
            spdlog::error("[{}] invalid nonce in credential response", name());
            return false;
        }

        crypto::AesGcmCiphertext ct;
        ct.ciphertext = std::move(ciphertext_bytes);
        ct.nonce = std::move(nonce_bytes);

        const std::string aad_str = "ddns-credential-transfer";
        auto plaintext = crypto_.aes_gcm_decrypt(
            aes_key, ct,
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(aad_str.data()), aad_str.size()));

        if (!plaintext) {
            spdlog::error("[{}] failed to decrypt DDNS credentials", name());
            return false;
        }

        // Parse decrypted credentials
        auto creds_str = std::string(plaintext->begin(), plaintext->end());
        auto creds = json::parse(creds_str);
        config_ = creds.get<DdnsConfig>();
        has_credentials_ = true;

        save_encrypted_credentials();

        spdlog::info("[{}] received and stored DDNS credentials (domain={})",
                      name(), config_.domain);

        // Start updating if enabled
        if (config_.enabled && !our_hostname_.empty() && !timer_running_) {
            update_now();
            start_update_timer();
        }

        return true;

    } catch (const std::exception& e) {
        spdlog::error("[{}] failed to parse credential response: {}", name(), e.what());
        return false;
    }
}

// ---------------------------------------------------------------------------
// Credential distribution: root server side
// ---------------------------------------------------------------------------

void DdnsService::set_trust_policy(core::TrustPolicyService* policy) {
    trust_policy_ = policy;
}

std::optional<std::string> DdnsService::handle_credential_request(
    const nlohmann::json& request,
    const crypto::Ed25519PrivateKey& root_privkey,
    const crypto::Ed25519PublicKey& root_pubkey) {

    // Zero-trust: if trust policy is active, verify the requesting server is Tier 1
    if (trust_policy_) {
        // Extract server pubkey from the certificate to check trust tier
        auto cert_json_str = request.value("server_certificate", "");
        if (!cert_json_str.empty()) {
            try {
                auto cert_j = json::parse(cert_json_str);
                auto server_pk = cert_j.value("server_pubkey", "");
                if (!server_pk.empty() &&
                    !trust_policy_->authorize(server_pk, core::TrustOperation::CredentialRequest)) {
                    spdlog::warn("[{}] credential request denied: server {} not authorized (requires Tier 1)",
                                  name(), server_pk.substr(0, 12) + "...");
                    return std::nullopt;
                }
            } catch (...) {
                // Will be caught by the certificate parsing below
            }
        }
    }

    // 1. Parse and verify the server certificate
    auto cert_json_str = request.value("server_certificate", "");
    if (cert_json_str.empty()) {
        spdlog::warn("[{}] credential request missing server_certificate", name());
        return std::nullopt;
    }

    gossip::ServerCertificate cert;
    try {
        auto cert_j = json::parse(cert_json_str);
        cert = cert_j.get<gossip::ServerCertificate>();
    } catch (...) {
        spdlog::warn("[{}] credential request has invalid server_certificate JSON", name());
        return std::nullopt;
    }

    // Verify cert was signed by root
    auto issuer_bytes = crypto::from_base64(cert.issuer_pubkey);
    if (issuer_bytes.size() != crypto::kEd25519PublicKeySize) {
        spdlog::warn("[{}] credential request: cert has invalid issuer pubkey", name());
        return std::nullopt;
    }
    crypto::Ed25519PublicKey issuer_pk{};
    std::memcpy(issuer_pk.data(), issuer_bytes.data(), crypto::kEd25519PublicKeySize);
    if (issuer_pk != root_pubkey) {
        spdlog::warn("[{}] credential request: cert not signed by our root key", name());
        return std::nullopt;
    }

    // Verify the certificate signature
    auto canonical = gossip::canonical_cert_json(cert);
    auto canonical_bytes = std::vector<uint8_t>(canonical.begin(), canonical.end());
    auto sig_bytes = crypto::from_base64(cert.signature);
    if (sig_bytes.size() != crypto::kEd25519SignatureSize) {
        spdlog::warn("[{}] credential request: cert has invalid signature size", name());
        return std::nullopt;
    }
    crypto::Ed25519Signature cert_sig{};
    std::memcpy(cert_sig.data(), sig_bytes.data(), crypto::kEd25519SignatureSize);

    if (!crypto_.ed25519_verify(root_pubkey, canonical_bytes, cert_sig)) {
        spdlog::warn("[{}] credential request: cert signature verification failed", name());
        return std::nullopt;
    }

    // Check cert expiry
    if (cert.expires_at != 0) {
        auto now = static_cast<uint64_t>(chrono::duration_cast<chrono::seconds>(
            chrono::system_clock::now().time_since_epoch()).count());
        if (now > cert.expires_at) {
            spdlog::warn("[{}] credential request: cert has expired", name());
            return std::nullopt;
        }
    }

    // 2. Verify the request signature (proves ownership of the server's private key)
    auto server_pk_bytes = crypto::from_base64(cert.server_pubkey);
    if (server_pk_bytes.size() != crypto::kEd25519PublicKeySize) {
        spdlog::warn("[{}] credential request: invalid server pubkey size", name());
        return std::nullopt;
    }
    crypto::Ed25519PublicKey server_pk{};
    std::memcpy(server_pk.data(), server_pk_bytes.data(), crypto::kEd25519PublicKeySize);

    // Reconstruct the signed portion (request without the signature field)
    json signed_portion;
    signed_portion["server_certificate"] = request.value("server_certificate", "");
    signed_portion["binary_hash"] = request.value("binary_hash", "");
    auto signed_str = signed_portion.dump();
    auto signed_bytes = std::vector<uint8_t>(signed_str.begin(), signed_str.end());

    auto req_sig_bytes = crypto::from_base64(request.value("signature", ""));
    if (req_sig_bytes.size() != crypto::kEd25519SignatureSize) {
        spdlog::warn("[{}] credential request: invalid request signature size", name());
        return std::nullopt;
    }
    crypto::Ed25519Signature req_sig{};
    std::memcpy(req_sig.data(), req_sig_bytes.data(), crypto::kEd25519SignatureSize);

    if (!crypto_.ed25519_verify(server_pk, signed_bytes, req_sig)) {
        spdlog::warn("[{}] credential request: request signature verification failed", name());
        return std::nullopt;
    }

    // 3. Verify binary attestation
    auto binary_hash = request.value("binary_hash", "");
    if (binary_hash.empty()) {
        spdlog::warn("[{}] credential request: missing binary_hash", name());
        return std::nullopt;
    }

    if (attestation_.has_signing_pubkey() && !attestation_.is_approved_binary(binary_hash)) {
        spdlog::warn("[{}] credential request denied: binary hash '{}' not in approved manifests",
                      name(), binary_hash.substr(0, 16) + "...");
        return std::nullopt;
    }

    // 4. All checks passed — encrypt and return credentials
    spdlog::info("[{}] credential request approved for server '{}' (binary: {}...)",
                  name(), cert.server_id, binary_hash.substr(0, 16));

    // Get the requester's X25519 public key
    auto requester_x_pub_bytes = crypto::from_base64(
        request.value("x25519_pubkey", ""));
    if (requester_x_pub_bytes.size() != crypto::kX25519PublicKeySize) {
        spdlog::warn("[{}] credential request: invalid X25519 pubkey", name());
        return std::nullopt;
    }
    crypto::X25519PublicKey requester_x_pub{};
    std::memcpy(requester_x_pub.data(), requester_x_pub_bytes.data(),
                crypto::kX25519PublicKeySize);

    // Convert our Ed25519 key to X25519 for DH
    crypto::Ed25519PublicKey our_ed_pub{};
    std::memcpy(our_ed_pub.data(), root_privkey.data() + 32, 32);
    auto our_x_pub = crypto::SodiumCryptoService::ed25519_pk_to_x25519(our_ed_pub);
    auto our_x_priv = crypto::SodiumCryptoService::ed25519_sk_to_x25519(root_privkey);

    // DH shared secret
    auto shared_secret = crypto_.x25519_dh(our_x_priv, requester_x_pub);

    // Derive AES key
    const std::string info_str = "lemonade-nexus-ddns-credentials";
    auto aes_key_bytes = crypto_.hkdf_sha256(
        shared_secret,
        std::span<const uint8_t>{}, // no salt
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size()),
        crypto::kAesGcmKeySize);

    crypto::AesGcmKey aes_key{};
    std::memcpy(aes_key.data(), aes_key_bytes.data(), crypto::kAesGcmKeySize);

    // Encrypt the DDNS credentials
    json creds_json = config_;
    auto creds_str = creds_json.dump();
    auto creds_bytes = std::vector<uint8_t>(creds_str.begin(), creds_str.end());

    const std::string aad_str = "ddns-credential-transfer";
    auto ct = crypto_.aes_gcm_encrypt(
        aes_key, creds_bytes,
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(aad_str.data()), aad_str.size()));

    // Build response
    json response;
    response["success"] = true;
    response["encrypted_credentials"] = crypto::to_base64(ct.ciphertext);
    response["nonce"] = crypto::to_base64(ct.nonce);
    response["x25519_pubkey"] = crypto::to_base64(our_x_pub);

    return response.dump();
}

// ---------------------------------------------------------------------------
// DDNS update logic
// ---------------------------------------------------------------------------

bool DdnsService::update_now() {
    std::string hostname;
    std::string domain;
    std::string password;
    {
        std::lock_guard lock(mutex_);
        if (!has_credentials_ || !config_.enabled) {
            spdlog::debug("[{}] update_now called but not ready", name());
            return false;
        }
        hostname = our_hostname_;
        domain = config_.domain;
        password = config_.ddns_password;
    }

    if (hostname.empty() || domain.empty()) {
        spdlog::warn("[{}] cannot update: hostname or domain not set", name());
        return false;
    }

    auto ip = detect_public_ip();
    if (ip.empty()) {
        spdlog::warn("[{}] could not detect public IP", name());
        return false;
    }

    {
        std::lock_guard lock(mutex_);
        if (ip == last_known_ip_) {
            spdlog::debug("[{}] IP unchanged ({}), skipping update", name(), ip);
            return true;
        }
    }

    spdlog::info("[{}] public IP changed: {} -> {}", name(), last_known_ip_, ip);

    bool success = do_namecheap_update(hostname, ip);
    if (success) {
        std::lock_guard lock(mutex_);
        last_known_ip_ = ip;
        spdlog::info("[{}] DDNS updated: {}.{} -> {}", name(), hostname, domain, ip);
    }

    return success;
}

bool DdnsService::do_namecheap_update(const std::string& host, const std::string& ip) {
    std::string domain;
    std::string password;
    {
        std::lock_guard lock(mutex_);
        domain = config_.domain;
        password = config_.ddns_password;
    }

    // Validate inputs to prevent injection
    // Host: alphanumeric + hyphens only
    static const std::regex host_pattern("^[a-zA-Z0-9][a-zA-Z0-9-]*$");
    if (!std::regex_match(host, host_pattern)) {
        spdlog::error("[{}] invalid hostname: {}", name(), host);
        return false;
    }

    // Domain: standard domain format
    static const std::regex domain_pattern("^[a-zA-Z0-9][a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
    if (!std::regex_match(domain, domain_pattern)) {
        spdlog::error("[{}] invalid domain: {}", name(), domain);
        return false;
    }

    // IP: standard IPv4
    static const std::regex ip_pattern("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
    if (!std::regex_match(ip, ip_pattern)) {
        spdlog::error("[{}] invalid IP address: {}", name(), ip);
        return false;
    }

    // Build the Namecheap DDNS URL
    std::string path = "/update?host=" + host +
                       "&domain=" + domain +
                       "&password=" + password +
                       "&ip=" + ip;

    httplib::SSLClient client("dynamicdns.park-your-domain.com", 443);
    client.set_connection_timeout(15);
    client.set_read_timeout(15);
    client.enable_server_certificate_verification(true);

    auto result = client.Get(path);

    if (!result) {
        spdlog::error("[{}] Namecheap DDNS API request failed (network error)", name());
        return false;
    }

    if (result->status != 200) {
        spdlog::error("[{}] Namecheap DDNS API returned status {}", name(), result->status);
        return false;
    }

    // Parse the XML response (simple check for <ErrCount>0</ErrCount>)
    const auto& body = result->body;
    if (body.find("<ErrCount>0</ErrCount>") != std::string::npos) {
        spdlog::info("[{}] Namecheap DDNS update successful for {}.{}", name(), host, domain);
        return true;
    }

    // Extract error if present
    auto err_start = body.find("<Err1>");
    auto err_end = body.find("</Err1>");
    if (err_start != std::string::npos && err_end != std::string::npos) {
        auto err = body.substr(err_start + 6, err_end - err_start - 6);
        spdlog::error("[{}] Namecheap DDNS error: {}", name(), err);
    } else {
        spdlog::error("[{}] Namecheap DDNS update failed (response: {})",
                       name(), body.substr(0, 200));
    }

    return false;
}

// ---------------------------------------------------------------------------
// Public IP detection (consensus-based)
// ---------------------------------------------------------------------------

std::string DdnsService::detect_public_ip() {
    // Query multiple services and take the most common result
    struct IpService {
        std::string host;
        std::string path;
    };

    static const std::vector<IpService> services = {
        {"api.ipify.org",     "/"},
        {"ifconfig.me",       "/ip"},
        {"icanhazip.com",     "/"},
        {"checkip.amazonaws.com", "/"},
    };

    std::map<std::string, int> votes;
    static const std::regex ip_pattern("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");

    for (const auto& svc : services) {
        auto ip = query_ip_service(svc.host, svc.path);
        // Trim whitespace
        while (!ip.empty() && (ip.back() == '\n' || ip.back() == '\r' || ip.back() == ' ')) {
            ip.pop_back();
        }
        while (!ip.empty() && (ip.front() == '\n' || ip.front() == '\r' || ip.front() == ' ')) {
            ip.erase(ip.begin());
        }

        if (!ip.empty() && std::regex_match(ip, ip_pattern)) {
            votes[ip]++;
        }
    }

    if (votes.empty()) {
        return {};
    }

    // Return the IP with the most votes
    std::string best_ip;
    int best_count = 0;
    for (const auto& [ip, count] : votes) {
        if (count > best_count) {
            best_count = count;
            best_ip = ip;
        }
    }

    return best_ip;
}

std::string DdnsService::query_ip_service(const std::string& host, const std::string& path) {
    try {
        httplib::SSLClient client(host, 443);
        client.set_connection_timeout(5);
        client.set_read_timeout(5);
        client.enable_server_certificate_verification(true);

        auto result = client.Get(path);
        if (result && result->status == 200) {
            return result->body;
        }
    } catch (const std::exception& e) {
        spdlog::debug("[{}] IP service {} failed: {}", name(), host, e.what());
    }
    return {};
}

// ---------------------------------------------------------------------------
// Update timer
// ---------------------------------------------------------------------------

void DdnsService::start_update_timer() {
    uint32_t interval;
    {
        std::lock_guard lock(mutex_);
        interval = config_.update_interval_sec;
        if (interval == 0) interval = 300;
        timer_running_ = true;
    }

    update_timer_.expires_after(chrono::seconds(interval));
    update_timer_.async_wait([this](const asio::error_code& ec) {
        if (!ec) {
            on_update_tick();
            start_update_timer();
        }
    });
}

void DdnsService::on_update_tick() {
    update_now();
}

// ---------------------------------------------------------------------------
// Encrypted credential storage
// ---------------------------------------------------------------------------

bool DdnsService::save_encrypted_credentials() {
    // Encrypt the DDNS config using a key derived from our server's identity
    // We use HKDF with the server's gossip Ed25519 pubkey as input keying material
    // and a fixed info string to derive a deterministic encryption key.
    // This way only this server instance can decrypt (needs same keypair).

    // Read our gossip keypair
    auto kp_env = storage_.read_file("identity", "keypair.json");
    if (!kp_env) {
        spdlog::warn("[{}] cannot save encrypted credentials: no identity keypair", name());
        return false;
    }

    try {
        auto kp_j = json::parse(kp_env->data);
        auto priv_bytes = crypto::from_base64(kp_j.value("private_key", ""));
        if (priv_bytes.size() != crypto::kEd25519PrivateKeySize) {
            spdlog::warn("[{}] invalid identity keypair", name());
            return false;
        }

        // Derive encryption key from private key via HKDF
        const std::string salt_str = "lemonade-nexus-ddns-at-rest";
        const std::string info_str = "ddns-credentials-encryption";
        auto aes_key_bytes = crypto_.hkdf_sha256(
            std::span<const uint8_t>(priv_bytes),
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(salt_str.data()), salt_str.size()),
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size()),
            crypto::kAesGcmKeySize);

        crypto::AesGcmKey aes_key{};
        std::memcpy(aes_key.data(), aes_key_bytes.data(), crypto::kAesGcmKeySize);

        // Encrypt
        json creds = config_;
        auto plaintext_str = creds.dump();
        auto plaintext = std::vector<uint8_t>(plaintext_str.begin(), plaintext_str.end());

        const std::string aad_str = "ddns-at-rest";
        auto ct = crypto_.aes_gcm_encrypt(
            aes_key, plaintext,
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(aad_str.data()), aad_str.size()));

        // Store as signed envelope
        json stored;
        stored["ciphertext"] = crypto::to_base64(ct.ciphertext);
        stored["nonce"] = crypto::to_base64(ct.nonce);

        storage::SignedEnvelope env;
        env.type = "ddns_credentials_encrypted";
        env.data = stored.dump();
        env.timestamp = static_cast<uint64_t>(chrono::duration_cast<chrono::seconds>(
            chrono::system_clock::now().time_since_epoch()).count());

        return storage_.write_file("identity", "ddns_credentials.enc", env);

    } catch (const std::exception& e) {
        spdlog::error("[{}] failed to save encrypted credentials: {}", name(), e.what());
        return false;
    }
}

bool DdnsService::load_encrypted_credentials() {
    auto env = storage_.read_file("identity", "ddns_credentials.enc");
    if (!env) {
        return false;
    }

    // Read our identity keypair
    auto kp_env = storage_.read_file("identity", "keypair.json");
    if (!kp_env) {
        return false;
    }

    try {
        auto kp_j = json::parse(kp_env->data);
        auto priv_bytes = crypto::from_base64(kp_j.value("private_key", ""));
        if (priv_bytes.size() != crypto::kEd25519PrivateKeySize) {
            return false;
        }

        // Re-derive the encryption key
        const std::string salt_str = "lemonade-nexus-ddns-at-rest";
        const std::string info_str = "ddns-credentials-encryption";
        auto aes_key_bytes = crypto_.hkdf_sha256(
            std::span<const uint8_t>(priv_bytes),
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(salt_str.data()), salt_str.size()),
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size()),
            crypto::kAesGcmKeySize);

        crypto::AesGcmKey aes_key{};
        std::memcpy(aes_key.data(), aes_key_bytes.data(), crypto::kAesGcmKeySize);

        // Parse stored envelope
        auto stored = json::parse(env->data);
        auto ct_bytes = crypto::from_base64(stored.value("ciphertext", ""));
        auto nonce_bytes = crypto::from_base64(stored.value("nonce", ""));
        if (nonce_bytes.size() != crypto::kAesGcmNonceSize) {
            return false;
        }

        crypto::AesGcmCiphertext ct;
        ct.ciphertext = std::move(ct_bytes);
        ct.nonce = std::move(nonce_bytes);

        const std::string aad_str = "ddns-at-rest";
        auto plaintext = crypto_.aes_gcm_decrypt(
            aes_key, ct,
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(aad_str.data()), aad_str.size()));

        if (!plaintext) {
            spdlog::warn("[{}] failed to decrypt stored DDNS credentials", name());
            return false;
        }

        auto creds_str = std::string(plaintext->begin(), plaintext->end());
        config_ = json::parse(creds_str).get<DdnsConfig>();
        return true;

    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to load encrypted credentials: {}", name(), e.what());
        return false;
    }
}

} // namespace nexus::network
