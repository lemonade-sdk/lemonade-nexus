#include <LemonadeNexusSDK/Types.hpp>

#include <stdexcept>

namespace lnsdk {

using json = nlohmann::json;

// --- NodeType <-> string ---

std::string node_type_to_string(NodeType type) {
    switch (type) {
        case NodeType::Root:     return "root";
        case NodeType::Customer: return "customer";
        case NodeType::Endpoint: return "endpoint";
        case NodeType::Relay:    return "relay";
    }
    throw std::invalid_argument("Unknown NodeType value: " +
                                 std::to_string(static_cast<uint8_t>(type)));
}

NodeType string_to_node_type(std::string_view s) {
    if (s == "root")     return NodeType::Root;
    if (s == "customer") return NodeType::Customer;
    if (s == "endpoint") return NodeType::Endpoint;
    if (s == "relay")    return NodeType::Relay;
    throw std::invalid_argument("Unknown NodeType string: " + std::string(s));
}

// --- Assignment ---

void to_json(json& j, const Assignment& a) {
    j = json{
        {"management_pubkey", a.management_pubkey},
        {"permissions",       a.permissions},
    };
}

void from_json(const json& j, Assignment& a) {
    j.at("management_pubkey").get_to(a.management_pubkey);
    j.at("permissions").get_to(a.permissions);
}

// --- TreeNode ---
// Field names and ordering identical to server's TreeTypes.cpp

void to_json(json& j, const TreeNode& n) {
    j = json{
        {"id",                       n.id},
        {"parent_id",                n.parent_id},
        {"type",                     node_type_to_string(n.type)},
        {"tunnel_ip",                n.tunnel_ip},
        {"private_subnet",           n.private_subnet},
        {"private_shared_addresses", n.private_shared_addresses},
        {"shared_domain",            n.shared_domain},
        {"mgmt_pubkey",              n.mgmt_pubkey},
        {"wrapped_mgmt_privkey",     n.wrapped_mgmt_privkey},
        {"wg_pubkey",                n.wg_pubkey},
        {"assignments",              n.assignments},
        {"signature",                n.signature},
        {"listen_endpoint",          n.listen_endpoint},
        {"region",                   n.region},
        {"capacity_mbps",            n.capacity_mbps},
        {"reputation_score",         n.reputation_score},
        {"expires_at",               n.expires_at},
    };
}

void from_json(const json& j, TreeNode& n) {
    n.id                       = j.value("id", "");
    n.parent_id                = j.value("parent_id", "");
    if (j.contains("type") && j["type"].is_string()) {
        n.type = string_to_node_type(j["type"].get<std::string>());
    }
    n.tunnel_ip                = j.value("tunnel_ip", "");
    n.private_subnet           = j.value("private_subnet", "");
    n.private_shared_addresses = j.value("private_shared_addresses", "");
    n.shared_domain            = j.value("shared_domain", "");
    n.mgmt_pubkey              = j.value("mgmt_pubkey", "");
    n.wrapped_mgmt_privkey     = j.value("wrapped_mgmt_privkey", "");
    n.wg_pubkey                = j.value("wg_pubkey", "");
    if (j.contains("assignments") && j["assignments"].is_array()) {
        j["assignments"].get_to(n.assignments);
    }
    n.signature                = j.value("signature", "");
    n.listen_endpoint          = j.value("listen_endpoint", "");
    n.region                   = j.value("region", "");
    n.capacity_mbps            = j.value("capacity_mbps", uint32_t{0});
    n.reputation_score         = j.value("reputation_score", 0.0f);
    n.expires_at               = j.value("expires_at", uint64_t{0});
}

// --- TreeDelta ---

void to_json(json& j, const TreeDelta& d) {
    j = json{
        {"operation",      d.operation},
        {"target_node_id", d.target_node_id},
        {"node_data",      d.node_data},
        {"signer_pubkey",  d.signer_pubkey},
        {"signature",      d.signature},
        {"timestamp",      d.timestamp},
    };
}

void from_json(const json& j, TreeDelta& d) {
    j.at("operation").get_to(d.operation);
    j.at("target_node_id").get_to(d.target_node_id);
    j.at("node_data").get_to(d.node_data);
    d.signer_pubkey = j.value("signer_pubkey", "");
    d.signature     = j.value("signature", "");
    d.timestamp     = j.value("timestamp", uint64_t{0});
}

// --- Canonical JSON for signing ---
// Mirrors server's canonical_delta_json() exactly:
// sorted keys (nlohmann::json default), excludes "signature" field.

std::string canonical_delta_json(const TreeDelta& delta) {
    json j;
    j["node_data"]      = delta.node_data;
    j["operation"]      = delta.operation;
    j["signer_pubkey"]  = delta.signer_pubkey;
    j["target_node_id"] = delta.target_node_id;
    j["timestamp"]      = delta.timestamp;
    // "signature" intentionally excluded for canonical form
    return j.dump();
}

// --- StatsResponse ---
void from_json(const json& j, StatsResponse& s) {
    s.service             = j.value("service", "");
    s.peer_count          = j.value("peer_count", uint32_t{0});
    s.private_api_enabled = j.value("private_api_enabled", false);
}

// --- ServerEntry ---
void from_json(const json& j, ServerEntry& s) {
    s.endpoint  = j.value("endpoint", "");
    s.pubkey    = j.value("pubkey", "");
    s.http_port = j.value("http_port", uint16_t{0});
    s.last_seen = j.value("last_seen", uint64_t{0});
    s.healthy   = j.value("healthy", false);
}

// --- TrustPeerInfo ---
void from_json(const json& j, TrustPeerInfo& p) {
    p.pubkey               = j.value("pubkey", "");
    p.tier                 = j.value("tier", uint8_t{0});
    p.tier_name            = j.value("tier_name", "");
    p.platform             = j.value("platform", "");
    p.last_verified        = j.value("last_verified", uint64_t{0});
    p.attestation_hash     = j.value("attestation_hash", "");
    p.binary_hash          = j.value("binary_hash", "");
    p.failed_verifications = j.value("failed_verifications", uint32_t{0});
}

// --- TrustStatus ---
void from_json(const json& j, TrustStatus& s) {
    s.our_tier    = j.value("our_tier", "");
    s.our_platform = j.value("our_platform", "");
    s.require_tee = j.value("require_tee", false);
    s.binary_hash = j.value("binary_hash", "");
    s.peer_count  = j.value("peer_count", std::size_t{0});
    if (j.contains("peers") && j["peers"].is_array()) {
        s.peers = j["peers"].get<std::vector<TrustPeerInfo>>();
    }
}

// --- DdnsStatus ---
void from_json(const json& j, DdnsStatus& s) {
    s.has_credentials = j.value("has_credentials", false);
    s.last_ip         = j.value("last_ip", "");
    s.binary_hash     = j.value("binary_hash", "");
    s.binary_approved = j.value("binary_approved", false);
}

// --- EnrollmentVote ---
void from_json(const json& j, EnrollmentVote& v) {
    v.voter_pubkey = j.value("voter_pubkey", "");
    v.approve      = j.value("approve", false);
    v.reason       = j.value("reason", "");
    v.timestamp    = j.value("timestamp", uint64_t{0});
}

// --- EnrollmentEntry ---
void from_json(const json& j, EnrollmentEntry& e) {
    e.request_id           = j.value("request_id", "");
    e.candidate_pubkey     = j.value("candidate_pubkey", "");
    e.candidate_server_id  = j.value("candidate_server_id", "");
    e.sponsor_pubkey       = j.value("sponsor_pubkey", "");
    e.state                = j.value("state", uint8_t{0});
    e.state_name           = j.value("state_name", "");
    e.created_at           = j.value("created_at", uint64_t{0});
    e.timeout_at           = j.value("timeout_at", uint64_t{0});
    e.retries              = j.value("retries", uint32_t{0});
    if (j.contains("votes") && j["votes"].is_array()) {
        e.votes = j["votes"].get<std::vector<EnrollmentVote>>();
    }
}

// --- EnrollmentStatus ---
void from_json(const json& j, EnrollmentStatus& s) {
    s.enabled          = j.value("enabled", false);
    s.quorum_ratio     = j.value("quorum_ratio", 0.0f);
    s.vote_timeout_sec = j.value("vote_timeout_sec", uint32_t{0});
    s.pending_count    = j.value("pending_count", std::size_t{0});
    if (j.contains("enrollments") && j["enrollments"].is_array()) {
        s.enrollments = j["enrollments"].get<std::vector<EnrollmentEntry>>();
    }
}

// --- GovernanceVote ---
void from_json(const json& j, GovernanceVote& v) {
    v.voter_pubkey = j.value("voter_pubkey", "");
    v.approve      = j.value("approve", false);
    v.reason       = j.value("reason", "");
    v.timestamp    = j.value("timestamp", uint64_t{0});
}

// --- GovernanceProposal ---
void from_json(const json& j, GovernanceProposal& p) {
    p.proposal_id    = j.value("proposal_id", "");
    p.proposer_pubkey = j.value("proposer_pubkey", "");
    p.parameter      = j.value("parameter", uint8_t{0});
    p.new_value      = j.value("new_value", "");
    p.old_value      = j.value("old_value", "");
    p.rationale      = j.value("rationale", "");
    p.created_at     = j.value("created_at", uint64_t{0});
    p.expires_at     = j.value("expires_at", uint64_t{0});
    p.state          = j.value("state", uint8_t{0});
    p.state_name     = j.value("state_name", "");
    if (j.contains("votes") && j["votes"].is_array()) {
        p.votes = j["votes"].get<std::vector<GovernanceVote>>();
    }
}

// --- AttestationManifest ---
void from_json(const json& j, AttestationManifest& m) {
    m.version       = j.value("version", "");
    m.platform      = j.value("platform", "");
    m.binary_sha256 = j.value("binary_sha256", "");
    m.timestamp     = j.value("timestamp", uint64_t{0});
}

// --- AttestationManifests ---
void from_json(const json& j, AttestationManifests& a) {
    a.self_hash      = j.value("self_hash", "");
    a.self_approved  = j.value("self_approved", false);
    a.github_url     = j.value("github_url", "");
    a.minimum_version = j.value("minimum_version", "");
    a.manifest_fetch_interval_sec = j.value("manifest_fetch_interval_sec", uint32_t{0});
    if (j.contains("manifests") && j["manifests"].is_array()) {
        a.manifests = j["manifests"].get<std::vector<AttestationManifest>>();
    }
}

} // namespace lnsdk
