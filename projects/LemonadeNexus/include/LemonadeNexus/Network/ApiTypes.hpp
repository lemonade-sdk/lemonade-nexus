#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

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
};

inline void to_json(nlohmann::json& j, const HealthResponse& r) {
    j = nlohmann::json{{"status", r.status}, {"service", r.service}};
}

inline void from_json(const nlohmann::json& j, HealthResponse& r) {
    r.status  = j.value("status", "ok");
    r.service = j.value("service", "lemonade-nexus");
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
    if (!r.pubkey.empty()) j["pubkey"]    = r.pubkey;
    if (r.last_seen > 0)  j["last_seen"] = r.last_seen;
}

inline void from_json(const nlohmann::json& j, ServerEntry& r) {
    r.endpoint  = j.value("endpoint", "");
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
    std::string nonce;
    std::string ephemeral_pubkey;
    uint64_t    expires_at{0};
};

inline void to_json(nlohmann::json& j, const CertIssueResponse& r) {
    j = nlohmann::json{
        {"domain",            r.domain},
        {"fullchain_pem",     r.fullchain_pem},
        {"encrypted_privkey", r.encrypted_privkey},
        {"nonce",             r.nonce},
        {"ephemeral_pubkey",  r.ephemeral_pubkey},
        {"expires_at",        r.expires_at},
    };
}

inline void from_json(const nlohmann::json& j, CertIssueResponse& r) {
    r.domain            = j.value("domain", "");
    r.fullchain_pem     = j.value("fullchain_pem", "");
    r.encrypted_privkey = j.value("encrypted_privkey", "");
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
// Trust — GET /api/trust/status
// ============================================================================

struct TrustPeerEntry {
    std::string pubkey;
    uint8_t     tier{0};
    std::string tier_name;
    std::string platform;
    uint64_t    last_verified{0};
    std::string binary_hash;
    uint32_t    failed_verifications{0};
};

inline void to_json(nlohmann::json& j, const TrustPeerEntry& r) {
    j = nlohmann::json{
        {"pubkey",                r.pubkey},
        {"tier",                  r.tier},
        {"tier_name",             r.tier_name},
        {"platform",              r.platform},
        {"last_verified",         r.last_verified},
        {"binary_hash",           r.binary_hash},
        {"failed_verifications",  r.failed_verifications},
    };
}

inline void from_json(const nlohmann::json& j, TrustPeerEntry& r) {
    r.pubkey                = j.value("pubkey", "");
    r.tier                  = j.value("tier", uint8_t{0});
    r.tier_name             = j.value("tier_name", "");
    r.platform              = j.value("platform", "");
    r.last_verified         = j.value("last_verified", uint64_t{0});
    r.binary_hash           = j.value("binary_hash", "");
    r.failed_verifications  = j.value("failed_verifications", uint32_t{0});
}

struct TrustStatusResponse {
    std::string                our_tier;
    std::string                our_platform;
    bool                       require_tee{false};
    std::string                binary_hash;
    size_t                     peer_count{0};
    std::vector<TrustPeerEntry> peers;
};

inline void to_json(nlohmann::json& j, const TrustStatusResponse& r) {
    j = nlohmann::json{
        {"our_tier",     r.our_tier},
        {"our_platform", r.our_platform},
        {"require_tee",  r.require_tee},
        {"binary_hash",  r.binary_hash},
        {"peer_count",   r.peer_count},
        {"peers",        r.peers},
    };
}

inline void from_json(const nlohmann::json& j, TrustStatusResponse& r) {
    r.our_tier     = j.value("our_tier", "");
    r.our_platform = j.value("our_platform", "");
    r.require_tee  = j.value("require_tee", false);
    r.binary_hash  = j.value("binary_hash", "");
    r.peer_count   = j.value("peer_count", size_t{0});
    r.peers        = j.value("peers", std::vector<TrustPeerEntry>{});
}

// ============================================================================
// Trust — GET /api/trust/peer/:pubkey
// ============================================================================

struct TrustPeerDetailResponse {
    std::string pubkey;
    uint8_t     tier{0};
    std::string tier_name;
    std::string platform;
    uint64_t    last_verified{0};
    std::string attestation_hash;
    std::string binary_hash;
    uint32_t    failed_verifications{0};
};

inline void to_json(nlohmann::json& j, const TrustPeerDetailResponse& r) {
    j = nlohmann::json{
        {"pubkey",                r.pubkey},
        {"tier",                  r.tier},
        {"tier_name",             r.tier_name},
        {"platform",              r.platform},
        {"last_verified",         r.last_verified},
        {"attestation_hash",      r.attestation_hash},
        {"binary_hash",           r.binary_hash},
        {"failed_verifications",  r.failed_verifications},
    };
}

inline void from_json(const nlohmann::json& j, TrustPeerDetailResponse& r) {
    r.pubkey                = j.value("pubkey", "");
    r.tier                  = j.value("tier", uint8_t{0});
    r.tier_name             = j.value("tier_name", "");
    r.platform              = j.value("platform", "");
    r.last_verified         = j.value("last_verified", uint64_t{0});
    r.attestation_hash      = j.value("attestation_hash", "");
    r.binary_hash           = j.value("binary_hash", "");
    r.failed_verifications  = j.value("failed_verifications", uint32_t{0});
}

// ============================================================================
// Enrollment — GET /api/enrollment/status
// ============================================================================

struct EnrollmentVoteEntry {
    std::string voter_pubkey;
    bool        approve{false};
    std::string reason;
    uint64_t    timestamp{0};
    std::string signature;   // only present in detail view
};

inline void to_json(nlohmann::json& j, const EnrollmentVoteEntry& r) {
    j = nlohmann::json{
        {"voter_pubkey", r.voter_pubkey},
        {"approve",      r.approve},
        {"reason",       r.reason},
        {"timestamp",    r.timestamp},
    };
    if (!r.signature.empty()) j["signature"] = r.signature;
}

inline void from_json(const nlohmann::json& j, EnrollmentVoteEntry& r) {
    r.voter_pubkey = j.value("voter_pubkey", "");
    r.approve      = j.value("approve", false);
    r.reason       = j.value("reason", "");
    r.timestamp    = j.value("timestamp", uint64_t{0});
    r.signature    = j.value("signature", "");
}

struct EnrollmentEntry {
    std::string request_id;
    std::string candidate_pubkey;
    std::string candidate_server_id;
    std::string sponsor_pubkey;
    std::string certificate_json;   // only present in detail view
    uint8_t     state{0};
    std::string state_name;
    uint64_t    created_at{0};
    uint64_t    timeout_at{0};
    uint32_t    retries{0};
    size_t      vote_count{0};      // only present in list view
    std::vector<EnrollmentVoteEntry> votes;
};

inline void to_json(nlohmann::json& j, const EnrollmentEntry& r) {
    j = nlohmann::json{
        {"request_id",            r.request_id},
        {"candidate_pubkey",      r.candidate_pubkey},
        {"candidate_server_id",   r.candidate_server_id},
        {"sponsor_pubkey",        r.sponsor_pubkey},
        {"state",                 r.state},
        {"state_name",            r.state_name},
        {"created_at",            r.created_at},
        {"timeout_at",            r.timeout_at},
        {"retries",               r.retries},
        {"votes",                 r.votes},
    };
    if (!r.certificate_json.empty()) j["certificate_json"] = r.certificate_json;
    if (r.vote_count > 0) j["vote_count"] = r.vote_count;
}

inline void from_json(const nlohmann::json& j, EnrollmentEntry& r) {
    r.request_id            = j.value("request_id", "");
    r.candidate_pubkey      = j.value("candidate_pubkey", "");
    r.candidate_server_id   = j.value("candidate_server_id", "");
    r.sponsor_pubkey        = j.value("sponsor_pubkey", "");
    r.certificate_json      = j.value("certificate_json", "");
    r.state                 = j.value("state", uint8_t{0});
    r.state_name            = j.value("state_name", "");
    r.created_at            = j.value("created_at", uint64_t{0});
    r.timeout_at            = j.value("timeout_at", uint64_t{0});
    r.retries               = j.value("retries", uint32_t{0});
    r.vote_count            = j.value("vote_count", size_t{0});
    r.votes                 = j.value("votes", std::vector<EnrollmentVoteEntry>{});
}

struct EnrollmentStatusResponse {
    bool                          enabled{false};
    float                         quorum_ratio{0.0f};
    uint32_t                      vote_timeout_sec{0};
    size_t                        pending_count{0};
    std::vector<EnrollmentEntry>  enrollments;
};

inline void to_json(nlohmann::json& j, const EnrollmentStatusResponse& r) {
    j = nlohmann::json{
        {"enabled",          r.enabled},
        {"quorum_ratio",     r.quorum_ratio},
        {"vote_timeout_sec", r.vote_timeout_sec},
        {"pending_count",    r.pending_count},
        {"enrollments",      r.enrollments},
    };
}

inline void from_json(const nlohmann::json& j, EnrollmentStatusResponse& r) {
    r.enabled          = j.value("enabled", false);
    r.quorum_ratio     = j.value("quorum_ratio", 0.0f);
    r.vote_timeout_sec = j.value("vote_timeout_sec", uint32_t{0});
    r.pending_count    = j.value("pending_count", size_t{0});
    r.enrollments      = j.value("enrollments", std::vector<EnrollmentEntry>{});
}

// ============================================================================
// Governance — GET /api/governance/proposals
// ============================================================================

struct GovernanceVoteEntry {
    std::string voter_pubkey;
    bool        approve{false};
    std::string reason;
    uint64_t    timestamp{0};
};

inline void to_json(nlohmann::json& j, const GovernanceVoteEntry& r) {
    j = nlohmann::json{
        {"voter_pubkey", r.voter_pubkey},
        {"approve",      r.approve},
        {"reason",       r.reason},
        {"timestamp",    r.timestamp},
    };
}

inline void from_json(const nlohmann::json& j, GovernanceVoteEntry& r) {
    r.voter_pubkey = j.value("voter_pubkey", "");
    r.approve      = j.value("approve", false);
    r.reason       = j.value("reason", "");
    r.timestamp    = j.value("timestamp", uint64_t{0});
}

struct GovernanceProposalEntry {
    std::string proposal_id;
    std::string proposer_pubkey;
    uint8_t     parameter{0};
    std::string new_value;
    std::string old_value;
    std::string rationale;
    uint64_t    created_at{0};
    uint64_t    expires_at{0};
    uint8_t     state{0};
    std::string state_name;
    std::vector<GovernanceVoteEntry> votes;
};

inline void to_json(nlohmann::json& j, const GovernanceProposalEntry& r) {
    j = nlohmann::json{
        {"proposal_id",     r.proposal_id},
        {"proposer_pubkey", r.proposer_pubkey},
        {"parameter",       r.parameter},
        {"new_value",       r.new_value},
        {"old_value",       r.old_value},
        {"rationale",       r.rationale},
        {"created_at",      r.created_at},
        {"expires_at",      r.expires_at},
        {"state",           r.state},
        {"state_name",      r.state_name},
        {"votes",           r.votes},
    };
}

inline void from_json(const nlohmann::json& j, GovernanceProposalEntry& r) {
    r.proposal_id     = j.value("proposal_id", "");
    r.proposer_pubkey = j.value("proposer_pubkey", "");
    r.parameter       = j.value("parameter", uint8_t{0});
    r.new_value       = j.value("new_value", "");
    r.old_value       = j.value("old_value", "");
    r.rationale       = j.value("rationale", "");
    r.created_at      = j.value("created_at", uint64_t{0});
    r.expires_at      = j.value("expires_at", uint64_t{0});
    r.state           = j.value("state", uint8_t{0});
    r.state_name      = j.value("state_name", "");
    r.votes           = j.value("votes", std::vector<GovernanceVoteEntry>{});
}

// ============================================================================
// Governance — POST /api/governance/propose
// ============================================================================

struct GovernanceProposeRequest {
    uint8_t     parameter{0};
    std::string new_value;
    std::string rationale;
};

inline void to_json(nlohmann::json& j, const GovernanceProposeRequest& r) {
    j = nlohmann::json{
        {"parameter", r.parameter},
        {"new_value", r.new_value},
        {"rationale", r.rationale},
    };
}

inline void from_json(const nlohmann::json& j, GovernanceProposeRequest& r) {
    r.parameter = j.value("parameter", uint8_t{0});
    r.new_value = j.value("new_value", "");
    r.rationale = j.value("rationale", "");
}

struct GovernanceProposeResponse {
    std::string proposal_id;
    std::string status;
};

inline void to_json(nlohmann::json& j, const GovernanceProposeResponse& r) {
    j = nlohmann::json{
        {"proposal_id", r.proposal_id},
        {"status",      r.status},
    };
}

inline void from_json(const nlohmann::json& j, GovernanceProposeResponse& r) {
    r.proposal_id = j.value("proposal_id", "");
    r.status      = j.value("status", "");
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
