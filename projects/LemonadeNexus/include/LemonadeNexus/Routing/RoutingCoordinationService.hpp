#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Routing/RoutingTypes.hpp>

#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace nexus::crypto { class SodiumCryptoService; }
namespace nexus::gossip { class GossipService; }

namespace nexus::routing {

/// Inputs handed in by the API layer (which has already authenticated the
/// caller and, for connection requests, run the authorization chokepoint).

struct EndpointRegistration {
    std::string node_id;
    std::string endpoint_identifier;
    std::string wg_pubkey;
    std::string mgmt_pubkey;
    std::string stun_endpoint;   // self-reported reflexive address
    std::string source_ip;       // observed TCP source (for return-routability)
};

struct ConnectionRequestInput {
    std::string client_node_id;
    std::string client_pubkey;
    std::string client_wg_pub;
    std::string target_node_id;
    std::string target_identifier;
    std::array<uint8_t, 16> conn_nonce{};
    std::vector<std::string> candidates;
    std::string source_ip;
};

struct EndpointReadyInput {
    std::string connection_id;
    std::string endpoint_node_id;
    std::string endpoint_wg_pub;
    std::vector<std::string> candidates;
    std::string source_ip;
};

struct RequestResult {
    bool        ok{false};
    std::string connection_id;
    std::string error;
    int         status{200};
};

struct ClientDirective {
    std::string connection_id;
    std::string endpoint_identifier;
    std::string endpoint_wg_pub;
    std::string endpoint_mgmt_pubkey;
    std::vector<Candidate> endpoint_candidates;
    std::array<uint8_t, 16> conn_nonce{};
    DataPath    data_path{DataPath::DirectP2P};
    std::string relay_endpoint;
    uint64_t    punch_at{0};
};

struct SessionView {
    std::string  connection_id;
    SessionPhase phase{SessionPhase::Requested};
    DataPath     data_path{DataPath::DirectP2P};
    uint64_t     created_at{0};
    uint64_t     expires_at{0};
};

/// Coordinates routing-layer connection setup: holds the in-flight session and
/// endpoint-control state, enforces per-client caps, and mints connection ids.
/// All authorization is done by the caller (RoutingApiHandler) via the tree
/// chokepoint; this service is identity/authz-agnostic state management.
class RoutingCoordinationService : public core::IService<RoutingCoordinationService> {
    friend class core::IService<RoutingCoordinationService>;

public:
    RoutingCoordinationService(crypto::SodiumCryptoService& crypto,
                               gossip::GossipService& gossip);

    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() {
        return "RoutingCoordinationService";
    }

    /// Routed E2E is unavailable unless a root-of-trust pubkey is configured.
    /// When disabled, every routing request fails closed (the API returns 503).
    [[nodiscard]] bool enabled() const { return enabled_; }

    /// Record/refresh an endpoint's control association.
    void register_endpoint(const EndpointRegistration& reg);

    /// Create an in-flight session for an already-authorized target. Enforces
    /// per-client and global caps before allocating any state.
    [[nodiscard]] RequestResult create_request(const ConnectionRequestInput& in);

    /// Endpoint signals readiness for a pending connection. Returns false (and
    /// sets `err`) if the connection is unknown or the endpoint does not match.
    [[nodiscard]] bool endpoint_ready(const EndpointReadyInput& in, std::string& err);

    /// Build the client connect directive. Only the named client may call.
    [[nodiscard]] std::optional<ClientDirective> build_client_directive(
            const std::string& connection_id, const std::string& caller_node_id);

    /// Session state, visible only to the two named participants.
    [[nodiscard]] std::optional<SessionView> get_session(
            const std::string& connection_id, const std::string& caller_node_id) const;

    /// Drain and return the pending connection ids an endpoint must act on.
    [[nodiscard]] std::vector<std::string> take_pending_for_endpoint(
            const std::string& endpoint_node_id);

    // Caps (bounds coordinator state per authenticated client).
    static constexpr std::size_t kMaxPendingPerClient = 64;
    static constexpr std::size_t kMaxTotalSessions    = 4096;
    static constexpr uint64_t    kSetupTtlSeconds     = 30;

private:
    void reap_expired_locked(uint64_t now);
    [[nodiscard]] std::string mint_connection_id();

    crypto::SodiumCryptoService& crypto_;
    gossip::GossipService&       gossip_;
    bool                         enabled_{false};

    mutable std::mutex mutex_;
    std::unordered_map<std::string, PendingSession>         sessions_;   // connection_id ->
    std::unordered_map<std::string, EndpointControlSession> endpoints_;  // node_id ->
    std::unordered_map<std::string, std::size_t>            pending_per_client_;
};

} // namespace nexus::routing
