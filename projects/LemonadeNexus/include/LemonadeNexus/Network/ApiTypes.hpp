#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

namespace nexus::network {

// ============================================================================
// Common
// ============================================================================

/// Generic error response returned on validation or processing failures.
struct ErrorResponse {
    std::string error;
    std::string message;   // optional detail
    std::string detail;    // optional extended detail
    std::string region;    // optional (used by relay region validation)
    std::string hint;      // optional (used by relay region validation)
};

inline void to_json(nlohmann::json& j, const ErrorResponse& r) {
    j = nlohmann::json{{"error", r.error}};
    if (!r.message.empty()) j["message"] = r.message;
    if (!r.detail.empty())  j["detail"]  = r.detail;
    if (!r.region.empty())  j["region"]  = r.region;
    if (!r.hint.empty())    j["hint"]    = r.hint;
}

inline void from_json(const nlohmann::json& j, ErrorResponse& r) {
    r.error   = j.value("error", "");
    r.message = j.value("message", "");
    r.detail  = j.value("detail", "");
    r.region  = j.value("region", "");
    r.hint    = j.value("hint", "");
}

// ============================================================================
// Health — GET /api/health
// ============================================================================

struct HealthResponse {
    std::string status{"ok"};
    std::string service{"lemonade-nexus"};
    std::string rp_id;
    std::string dns_base_domain;
};

inline void to_json(nlohmann::json& j, const HealthResponse& r) {
    j = nlohmann::json{{"status", r.status}, {"service", r.service}};
    if (!r.rp_id.empty()) {
        j["rp_id"] = r.rp_id;
    }
    if (!r.dns_base_domain.empty()) {
        j["dns_base_domain"] = r.dns_base_domain;
    }
}

inline void from_json(const nlohmann::json& j, HealthResponse& r) {
    r.status          = j.value("status", "ok");
    r.service         = j.value("service", "lemonade-nexus");
    r.dns_base_domain = j.value("dns_base_domain", "");
}

// ============================================================================
// Auth — POST /api/auth, POST /api/auth/register
// ============================================================================

struct AuthResponse {
    bool        authenticated{false};
    std::string user_id;
    std::string session_token;
    std::string error;
};

inline void to_json(nlohmann::json& j, const AuthResponse& r) {
    j = nlohmann::json{
        {"authenticated", r.authenticated},
        {"user_id",       r.user_id},
        {"session_token", r.session_token},
        {"error",         r.error},
    };
}

inline void from_json(const nlohmann::json& j, AuthResponse& r) {
    r.authenticated = j.value("authenticated", false);
    r.user_id       = j.value("user_id", "");
    r.session_token = j.value("session_token", "");
    r.error         = j.value("error", "");
}

// ============================================================================
// Tree — POST /api/tree/delta
// ============================================================================

struct DeltaResponse {
    bool        success{false};
    std::string error;
};

inline void to_json(nlohmann::json& j, const DeltaResponse& r) {
    j = nlohmann::json{{"success", r.success}};
    if (!r.error.empty()) j["error"] = r.error;
}

inline void from_json(const nlohmann::json& j, DeltaResponse& r) {
    r.success = j.value("success", false);
    r.error   = j.value("error", "");
}

// ============================================================================
// IPAM — POST /api/ipam/allocate
// ============================================================================

struct IpamAllocateRequest {
    std::string node_id;
    std::string block_type{"tunnel"};
    uint8_t     prefix_len{30};
};

inline void to_json(nlohmann::json& j, const IpamAllocateRequest& r) {
    j = nlohmann::json{
        {"node_id",    r.node_id},
        {"block_type", r.block_type},
        {"prefix_len", r.prefix_len},
    };
}

inline void from_json(const nlohmann::json& j, IpamAllocateRequest& r) {
    r.node_id    = j.value("node_id", "");
    r.block_type = j.value("block_type", "tunnel");
    r.prefix_len = static_cast<uint8_t>(j.value("prefix_len", 30));
}

struct IpamAllocateResponse {
    bool        success{false};
    std::string network;
    std::string node_id;
};

inline void to_json(nlohmann::json& j, const IpamAllocateResponse& r) {
    j = nlohmann::json{
        {"success", r.success},
        {"network", r.network},
        {"node_id", r.node_id},
    };
}

inline void from_json(const nlohmann::json& j, IpamAllocateResponse& r) {
    r.success = j.value("success", false);
    r.network = j.value("network", "");
    r.node_id = j.value("node_id", "");
}

// ============================================================================
// Relay — GET /api/relay/list
// ============================================================================

struct RelayInfoEntry {
    std::string relay_id;
    std::string endpoint;
    std::string region;
    float       reputation_score{0.0f};
    bool        supports_stun{true};
    bool        supports_relay{true};
    std::optional<int> distance_km;
};

inline void to_json(nlohmann::json& j, const RelayInfoEntry& r) {
    j = nlohmann::json{
        {"relay_id",         r.relay_id},
        {"endpoint",         r.endpoint},
        {"region",           r.region},
        {"reputation_score", r.reputation_score},
        {"supports_stun",    r.supports_stun},
        {"supports_relay",   r.supports_relay},
    };
    if (r.distance_km) j["distance_km"] = *r.distance_km;
}

inline void from_json(const nlohmann::json& j, RelayInfoEntry& r) {
    r.relay_id         = j.value("relay_id", "");
    r.endpoint         = j.value("endpoint", "");
    r.region           = j.value("region", "");
    r.reputation_score = j.value("reputation_score", 0.0f);
    r.supports_stun    = j.value("supports_stun", true);
    r.supports_relay   = j.value("supports_relay", true);
    if (j.contains("distance_km")) r.distance_km = j["distance_km"].get<int>();
}

// GET /api/relay/nearest
struct RelayNearestResponse {
    std::string                client_region;
    std::vector<RelayInfoEntry> relays;
};

inline void to_json(nlohmann::json& j, const RelayNearestResponse& r) {
    j = nlohmann::json{
        {"client_region", r.client_region},
        {"relays",        r.relays},
    };
}

inline void from_json(const nlohmann::json& j, RelayNearestResponse& r) {
    r.client_region = j.value("client_region", "");
    r.relays        = j.value("relays", std::vector<RelayInfoEntry>{});
}

// ============================================================================
// Relay — POST /api/relay/ticket
// ============================================================================

struct RelayTicketRequest {
    std::string peer_id;
    std::string relay_id;
};

inline void to_json(nlohmann::json& j, const RelayTicketRequest& r) {
    j = nlohmann::json{{"peer_id", r.peer_id}, {"relay_id", r.relay_id}};
}

inline void from_json(const nlohmann::json& j, RelayTicketRequest& r) {
    r.peer_id  = j.value("peer_id", "");
    r.relay_id = j.value("relay_id", "");
}

struct RelayTicketResponse {
    std::string peer_id;
    std::string relay_id;
    std::string session_nonce;
    uint64_t    issued_at{0};
    uint64_t    expires_at{0};
    std::string signature;
};

inline void to_json(nlohmann::json& j, const RelayTicketResponse& r) {
    j = nlohmann::json{
        {"peer_id",       r.peer_id},
        {"relay_id",      r.relay_id},
        {"session_nonce", r.session_nonce},
        {"issued_at",     r.issued_at},
        {"expires_at",    r.expires_at},
        {"signature",     r.signature},
    };
}

inline void from_json(const nlohmann::json& j, RelayTicketResponse& r) {
    r.peer_id       = j.value("peer_id", "");
    r.relay_id      = j.value("relay_id", "");
    r.session_nonce = j.value("session_nonce", "");
    r.issued_at     = j.value("issued_at", uint64_t{0});
    r.expires_at    = j.value("expires_at", uint64_t{0});
    r.signature     = j.value("signature", "");
}

// ============================================================================
// Relay — POST /api/relay/register
// ============================================================================

struct RelayRegisterRequest {
    std::string relay_id;
    std::string endpoint;
    std::string region;
    std::string hostname;
};

inline void to_json(nlohmann::json& j, const RelayRegisterRequest& r) {
    j = nlohmann::json{
        {"relay_id", r.relay_id},
        {"endpoint", r.endpoint},
        {"region",   r.region},
        {"hostname", r.hostname},
    };
}

inline void from_json(const nlohmann::json& j, RelayRegisterRequest& r) {
    r.relay_id = j.value("relay_id", "");
    r.endpoint = j.value("endpoint", "");
    r.region   = j.value("region", "");
    r.hostname = j.value("hostname", "");
}

struct RelayRegisterResponse {
    bool                     success{false};
    std::string              relay_id;
    std::string              region;
    std::vector<std::string> dns_names;
};

inline void to_json(nlohmann::json& j, const RelayRegisterResponse& r) {
    j = nlohmann::json{
        {"success",   r.success},
        {"relay_id",  r.relay_id},
        {"region",    r.region},
        {"dns_names", r.dns_names},
    };
}

inline void from_json(const nlohmann::json& j, RelayRegisterResponse& r) {
    r.success   = j.value("success", false);
    r.relay_id  = j.value("relay_id", "");
    r.region    = j.value("region", "");
    r.dns_names = j.value("dns_names", std::vector<std::string>{});
}

// ============================================================================
// Server discovery — GET /api/servers
// ============================================================================

struct ServerEntry {
    std::string endpoint;
    std::string fqdn;        // cert FQDN for verified HTTPS ("" if unknown)
    std::string pubkey;
    uint16_t    http_port{0};
    uint64_t    last_seen{0};
    bool        healthy{true};
};

inline void to_json(nlohmann::json& j, const ServerEntry& r) {
    j = nlohmann::json{
        {"endpoint",  r.endpoint},
        {"http_port", r.http_port},
        {"healthy",   r.healthy},
    };
    if (!r.fqdn.empty())   j["fqdn"]      = r.fqdn;
    if (!r.pubkey.empty()) j["pubkey"]    = r.pubkey;
    if (r.last_seen > 0)  j["last_seen"] = r.last_seen;
}

inline void from_json(const nlohmann::json& j, ServerEntry& r) {
    r.endpoint  = j.value("endpoint", "");
    r.fqdn      = j.value("fqdn", "");
    r.pubkey    = j.value("pubkey", "");
    r.http_port = j.value("http_port", uint16_t{0});
    r.last_seen = j.value("last_seen", uint64_t{0});
    r.healthy   = j.value("healthy", true);
}

// ============================================================================
// Certificates — GET /api/certs/:domain
// ============================================================================

struct CertStatusResponse {
    std::string domain;
    bool        has_cert{false};
    uint64_t    expires_at{0};
};

inline void to_json(nlohmann::json& j, const CertStatusResponse& r) {
    j = nlohmann::json{
        {"domain",     r.domain},
        {"has_cert",   r.has_cert},
        {"expires_at", r.expires_at},
    };
}

inline void from_json(const nlohmann::json& j, CertStatusResponse& r) {
    r.domain     = j.value("domain", "");
    r.has_cert   = j.value("has_cert", false);
    r.expires_at = j.value("expires_at", uint64_t{0});
}

// ============================================================================
// Certificates — POST /api/certs/issue
// ============================================================================

struct CertIssueRequest {
    std::string hostname;
    std::string client_pubkey;
};

inline void to_json(nlohmann::json& j, const CertIssueRequest& r) {
    j = nlohmann::json{
        {"hostname",      r.hostname},
        {"client_pubkey", r.client_pubkey},
    };
}

inline void from_json(const nlohmann::json& j, CertIssueRequest& r) {
    r.hostname      = j.value("hostname", "");
    r.client_pubkey = j.value("client_pubkey", "");
}

struct CertIssueResponse {
    std::string domain;
    std::string fullchain_pem;
    std::string encrypted_privkey;
    /// Crypto format version of encrypted_privkey; see EncryptedBlob.
    unsigned    crypto_version{nexus::crypto::kEncryptedBlobVersion};
    std::string nonce;
    std::string ephemeral_pubkey;
    uint64_t    expires_at{0};
};

inline void to_json(nlohmann::json& j, const CertIssueResponse& r) {
    j = nlohmann::json{
        {"domain",            r.domain},
        {"fullchain_pem",     r.fullchain_pem},
        {"encrypted_privkey", r.encrypted_privkey},
        {"crypto_version",    r.crypto_version},
        {"nonce",             r.nonce},
        {"ephemeral_pubkey",  r.ephemeral_pubkey},
        {"expires_at",        r.expires_at},
    };
}

inline void from_json(const nlohmann::json& j, CertIssueResponse& r) {
    r.domain            = j.value("domain", "");
    r.fullchain_pem     = j.value("fullchain_pem", "");
    r.encrypted_privkey = j.value("encrypted_privkey", "");
    r.crypto_version    = j.value("crypto_version", 0u);
    r.nonce             = j.value("nonce", "");
    r.ephemeral_pubkey  = j.value("ephemeral_pubkey", "");
    r.expires_at        = j.value("expires_at", uint64_t{0});
}

// ============================================================================
// DDNS — GET /api/ddns/status
// ============================================================================

struct DdnsStatusResponse {
    bool        has_credentials{false};
    std::string last_ip;
    std::string binary_hash;
    bool        binary_approved{false};
};

inline void to_json(nlohmann::json& j, const DdnsStatusResponse& r) {
    j = nlohmann::json{
        {"has_credentials", r.has_credentials},
        {"last_ip",         r.last_ip},
        {"binary_hash",     r.binary_hash},
        {"binary_approved", r.binary_approved},
    };
}

inline void from_json(const nlohmann::json& j, DdnsStatusResponse& r) {
    r.has_credentials = j.value("has_credentials", false);
    r.last_ip         = j.value("last_ip", "");
    r.binary_hash     = j.value("binary_hash", "");
    r.binary_approved = j.value("binary_approved", false);
}

// ============================================================================
// DDNS — POST /api/ddns/update
// ============================================================================

struct DdnsUpdateResponse {
    bool        success{false};
    std::string ip;
};

inline void to_json(nlohmann::json& j, const DdnsUpdateResponse& r) {
    j = nlohmann::json{{"success", r.success}, {"ip", r.ip}};
}

inline void from_json(const nlohmann::json& j, DdnsUpdateResponse& r) {
    r.success = j.value("success", false);
    r.ip      = j.value("ip", "");
}

// ============================================================================
// Binary attestation — GET /api/attestation/manifests
// ============================================================================

struct ManifestEntry {
    std::string version;
    std::string platform;
    std::string binary_sha256;
    uint64_t    timestamp{0};
};

inline void to_json(nlohmann::json& j, const ManifestEntry& r) {
    j = nlohmann::json{
        {"version",       r.version},
        {"platform",      r.platform},
        {"binary_sha256", r.binary_sha256},
        {"timestamp",     r.timestamp},
    };
}

inline void from_json(const nlohmann::json& j, ManifestEntry& r) {
    r.version       = j.value("version", "");
    r.platform      = j.value("platform", "");
    r.binary_sha256 = j.value("binary_sha256", "");
    r.timestamp     = j.value("timestamp", uint64_t{0});
}

struct AttestationManifestsResponse {
    std::string                self_hash;
    bool                       self_approved{false};
    std::vector<ManifestEntry> manifests;
    std::string                github_url;
    std::string                minimum_version;
    uint32_t                   manifest_fetch_interval_sec{0};
};

inline void to_json(nlohmann::json& j, const AttestationManifestsResponse& r) {
    j = nlohmann::json{
        {"self_hash",                   r.self_hash},
        {"self_approved",               r.self_approved},
        {"manifests",                   r.manifests},
        {"github_url",                  r.github_url},
        {"minimum_version",            r.minimum_version},
        {"manifest_fetch_interval_sec", r.manifest_fetch_interval_sec},
    };
}

inline void from_json(const nlohmann::json& j, AttestationManifestsResponse& r) {
    r.self_hash                   = j.value("self_hash", "");
    r.self_approved               = j.value("self_approved", false);
    r.manifests                   = j.value("manifests", std::vector<ManifestEntry>{});
    r.github_url                  = j.value("github_url", "");
    r.minimum_version             = j.value("minimum_version", "");
    r.manifest_fetch_interval_sec = j.value("manifest_fetch_interval_sec", uint32_t{0});
}

// ============================================================================
// Binary attestation — POST /api/attestation/fetch
// ============================================================================

struct AttestationFetchResponse {
    bool     success{true};
    uint32_t new_manifests{0};
    size_t   total_manifests{0};
};

inline void to_json(nlohmann::json& j, const AttestationFetchResponse& r) {
    j = nlohmann::json{
        {"success",         r.success},
        {"new_manifests",   r.new_manifests},
        {"total_manifests", r.total_manifests},
    };
}

inline void from_json(const nlohmann::json& j, AttestationFetchResponse& r) {
    r.success         = j.value("success", true);
    r.new_manifests   = j.value("new_manifests", uint32_t{0});
    r.total_manifests = j.value("total_manifests", size_t{0});
}

// ============================================================================
// Credential request — POST /api/credentials/request
// (request body is opaque JSON handled by DdnsService)
// (success response is opaque JSON from DdnsService)
// ============================================================================

struct CredentialErrorResponse {
    bool        success{false};
    std::string error;
};

inline void to_json(nlohmann::json& j, const CredentialErrorResponse& r) {
    j = nlohmann::json{{"success", r.success}, {"error", r.error}};
}

inline void from_json(const nlohmann::json& j, CredentialErrorResponse& r) {
    r.success = j.value("success", false);
    r.error   = j.value("error", "");
}

} // namespace nexus::network
