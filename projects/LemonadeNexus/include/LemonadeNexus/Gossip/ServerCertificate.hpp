#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>

namespace nexus::gossip {

/// Signed certificate proving a server is authorized to participate in gossip.
/// Issued by the root management key holder (admin).
struct ServerCertificate {
    std::string server_pubkey;   // base64 Ed25519 public key of the server
    std::string server_id;       // human-readable identifier (e.g. "us-east-1")
    std::string endpoint_hint;   // initial "host:port" (may change)
    uint64_t    issued_at{0};    // Unix timestamp
    uint64_t    expires_at{0};   // Unix timestamp (0 = no expiry)
    std::string issuer_pubkey;   // base64 Ed25519 public key of signer (root key)
    std::string signature;       // base64 Ed25519 signature by issuer
};

/// Canonical JSON for signing (excludes signature field).
[[nodiscard]] std::string canonical_cert_json(const ServerCertificate& cert);

void to_json(nlohmann::json& j, const ServerCertificate& c);
void from_json(const nlohmann::json& j, ServerCertificate& c);

} // namespace nexus::gossip
