#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace nexus::routing {

enum class DataPath { DirectP2P, Relay };

/// A transport candidate (ip:port) for hole punching. `verified` means the
/// coordinator witnessed it as return-routable; unverified candidates must not
/// be advertised to a peer once the data plane exists (see M5).
struct Candidate {
    std::string endpoint;     // "ip:port"
    bool        verified{false};
};

/// An endpoint's live control association. Endpoint-initiated: the endpoint
/// registers and refreshes it, and polls for pending connection requests
/// (no server->NAT push).
struct EndpointControlSession {
    std::string node_id;
    std::string endpoint_identifier;
    std::string wg_pubkey;     // Noise static (X25519, base64)
    std::string mgmt_pubkey;   // Ed25519 identity (for the M3.5 IdentityBinding)
    Candidate   reflexive;     // server-witnessed reflexive address
    uint64_t    last_seen{0};
    std::vector<std::string> pending_connection_ids;
};

enum class SessionPhase {
    Requested,        // client asked; endpoint not yet ready
    EndpointReady,    // endpoint signalled readiness
    ClientNotified,   // directive handed to the client
    Failed,
};

/// One in-flight client<->endpoint setup, owned by the coordinator.
struct PendingSession {
    std::string connection_id;

    std::string client_node_id;
    std::string client_pubkey;
    std::string client_wg_pub;
    std::vector<Candidate> client_candidates;

    std::string endpoint_node_id;
    std::string endpoint_identifier;
    std::string endpoint_wg_pub;
    std::string endpoint_mgmt_pubkey;
    std::vector<Candidate> endpoint_candidates;

    std::array<uint8_t, 16> conn_nonce{};
    DataPath     data_path{DataPath::DirectP2P};
    std::string  relay_endpoint;   // set when DataPath::Relay (M3.5 allocates)
    SessionPhase phase{SessionPhase::Requested};
    uint64_t     created_at{0};
    uint64_t     expires_at{0};
};

} // namespace nexus::routing
