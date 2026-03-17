#pragma once

#include <LemonadeNexusSDK/Error.hpp>
#include <LemonadeNexusSDK/Identity.hpp>
#include <LemonadeNexusSDK/LatencyMonitor.hpp>
#include <LemonadeNexusSDK/Types.hpp>
#include <LemonadeNexusSDK/WireGuardTunnel.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace lnsdk {

/// Standalone C++ client for the Lemonade-Nexus server.
///
/// Uses PIMPL to hide httplib and internal state from the public API.
/// Thread-safe for concurrent calls from multiple threads.
class LemonadeNexusClient {
public:
    explicit LemonadeNexusClient(const ServerConfig& config);
    ~LemonadeNexusClient();

    // Non-copyable, movable
    LemonadeNexusClient(const LemonadeNexusClient&) = delete;
    LemonadeNexusClient& operator=(const LemonadeNexusClient&) = delete;
    LemonadeNexusClient(LemonadeNexusClient&&) noexcept;
    LemonadeNexusClient& operator=(LemonadeNexusClient&&) noexcept;

    // -----------------------------------------------------------------
    // Identity management
    // -----------------------------------------------------------------

    /// Set the client identity (Ed25519 keypair) used for delta signing.
    void set_identity(const Identity& identity);

    /// Get the current identity (may be invalid if not set).
    /// Returns by value to avoid data races with concurrent set_identity().
    [[nodiscard]] Identity identity() const;

    // -----------------------------------------------------------------
    // Health
    // -----------------------------------------------------------------

    /// GET /api/health
    [[nodiscard]] Result<HealthStatus> check_health();

    // -----------------------------------------------------------------
    // Authentication
    // -----------------------------------------------------------------

    /// POST /api/auth — Ed25519 identity authentication (primary method).
    /// Performs two-phase challenge-response using the client's Ed25519 keypair.
    /// Requires a valid identity (call set_identity() first).
    /// Auto-registers new pubkeys on first use.
    [[nodiscard]] Result<AuthResponse> authenticate_ed25519();

    /// POST /api/auth/register/ed25519 — register Ed25519 pubkey with explicit user_id.
    /// If user_id is empty, server derives one from the pubkey hash.
    [[nodiscard]] Result<AuthResponse> register_ed25519(const std::string& user_id = "");

    /// POST /api/auth — password authentication (deprecated, stub on server).
    [[nodiscard]] Result<AuthResponse> authenticate(const std::string& username,
                                                     const std::string& password);

    /// POST /api/auth — passkey/FIDO2 authentication (backup method).
    [[nodiscard]] Result<AuthResponse> authenticate_passkey(const nlohmann::json& passkey_data);

    /// POST /api/auth — token-link authentication.
    [[nodiscard]] Result<AuthResponse> authenticate_token(const std::string& token);

    /// POST /api/auth — passkey registration flow (legacy).
    [[nodiscard]] Result<AuthResponse> register_passkey(const PasskeyRegistration& reg);

    /// POST /api/auth/register — register a passkey credential.
    [[nodiscard]] Result<AuthResponse> register_passkey_credential(const std::string& user_id,
                                                                     const PasskeyCredential& cred);

    // -----------------------------------------------------------------
    // Tree operations
    // -----------------------------------------------------------------

    /// GET /api/tree/node/{id}
    [[nodiscard]] Result<TreeNode> get_tree_node(const std::string& node_id);

    /// POST /api/tree/delta — submit a raw (signed) delta.
    [[nodiscard]] Result<DeltaResult> submit_delta(const TreeDelta& delta);

    /// Convenience: create_node delta under parent_id.
    [[nodiscard]] Result<DeltaResult> create_child_node(const std::string& parent_id,
                                                         const TreeNode& child);

    /// Convenience: update_node delta.
    [[nodiscard]] Result<DeltaResult> update_node(const std::string& node_id,
                                                    const nlohmann::json& updates);

    /// Convenience: delete_node delta.
    [[nodiscard]] Result<DeltaResult> delete_node(const std::string& node_id);

    /// GET /api/tree/children/{parent_id}
    [[nodiscard]] Result<std::vector<TreeNode>> get_children(const std::string& parent_id);

    // -----------------------------------------------------------------
    // IPAM
    // -----------------------------------------------------------------

    /// POST /api/ipam/allocate
    [[nodiscard]] Result<AllocationResponse> allocate_ip(const AllocationRequest& req);

    /// Convenience: allocate a tunnel IP for node_id.
    [[nodiscard]] Result<AllocationResponse> allocate_tunnel_ip(const std::string& node_id);

    // -----------------------------------------------------------------
    // Relay
    // -----------------------------------------------------------------

    /// GET /api/relay/list
    [[nodiscard]] Result<std::vector<RelayNodeInfo>> list_relays();

    /// POST /api/relay/ticket
    [[nodiscard]] Result<RelayTicket> request_relay_ticket(const std::string& peer_id,
                                                            const std::string& relay_id);

    /// POST /api/relay/register
    [[nodiscard]] Result<RelayRegisterResult> register_relay(const RelayRegistration& reg);

    // -----------------------------------------------------------------
    // Certificates
    // -----------------------------------------------------------------

    /// GET /api/certs/{domain} — check if a certificate exists.
    [[nodiscard]] Result<CertStatus> get_cert_status(const std::string& domain);

    /// POST /api/certs/issue — request a TLS certificate for this client.
    /// Server obtains the cert via ACME and returns it encrypted with our key.
    /// @param hostname The client hostname (e.g. "my-laptop")
    /// @return Encrypted certificate bundle (call decrypt_certificate to use)
    [[nodiscard]] Result<IssuedCertBundle> request_certificate(const std::string& hostname);

    /// Decrypt an issued certificate bundle using our Ed25519 identity.
    /// Performs X25519 DH with the server's ephemeral pubkey, derives AES-256-GCM
    /// key via HKDF, and decrypts the private key.
    /// @param bundle The encrypted bundle from request_certificate()
    /// @return Decrypted certificate (fullchain PEM + private key PEM)
    [[nodiscard]] Result<DecryptedCert> decrypt_certificate(const IssuedCertBundle& bundle);

    // -----------------------------------------------------------------
    // High-level composite operations
    // -----------------------------------------------------------------

    /// Authenticate → create endpoint node → allocate tunnel IP.
    [[nodiscard]] Result<JoinResult> join_network(const std::string& username,
                                                    const std::string& password);

    /// Submit delete_node delta for the current node.
    [[nodiscard]] StatusResult leave_network();

    // -----------------------------------------------------------------
    // Group membership management
    // -----------------------------------------------------------------

    /// Add a member to a group node's assignments.
    [[nodiscard]] Result<DeltaResult> add_group_member(const std::string& node_id,
                                                         const GroupMember& member);

    /// Remove a member from a group node's assignments by pubkey.
    [[nodiscard]] Result<DeltaResult> remove_group_member(const std::string& node_id,
                                                            const std::string& pubkey);

    /// Get the members (assignments) of a group node.
    [[nodiscard]] Result<std::vector<GroupMember>> get_group_members(const std::string& node_id);

    /// Join an existing group: create endpoint child under parent_node_id + allocate tunnel IP.
    [[nodiscard]] Result<GroupJoinResult> join_group(const std::string& parent_node_id);

    // -----------------------------------------------------------------
    // Server discovery & health
    // -----------------------------------------------------------------

    /// Fetch /api/servers to discover additional servers in the pool.
    void discover_servers();

    /// Check health of all servers in the pool and update their status.
    void refresh_health();

    // -----------------------------------------------------------------
    // Stats & server listing
    // -----------------------------------------------------------------

    /// GET /api/stats
    [[nodiscard]] Result<StatsResponse> get_stats();

    /// GET /api/servers
    [[nodiscard]] Result<std::vector<ServerEntry>> get_servers();

    // -----------------------------------------------------------------
    // Trust & attestation queries
    // -----------------------------------------------------------------

    /// GET /api/trust/status
    [[nodiscard]] Result<TrustStatus> get_trust_status();

    /// GET /api/trust/peer/{pubkey}
    [[nodiscard]] Result<TrustPeerInfo> get_trust_peer(const std::string& pubkey);

    // -----------------------------------------------------------------
    // DDNS status
    // -----------------------------------------------------------------

    /// GET /api/ddns/status
    [[nodiscard]] Result<DdnsStatus> get_ddns_status();

    // -----------------------------------------------------------------
    // Enrollment
    // -----------------------------------------------------------------

    /// GET /api/enrollment/status
    [[nodiscard]] Result<EnrollmentStatus> get_enrollment_status();

    // -----------------------------------------------------------------
    // Governance
    // -----------------------------------------------------------------

    /// GET /api/governance/proposals
    [[nodiscard]] Result<std::vector<GovernanceProposal>> get_governance_proposals();

    /// POST /api/governance/propose
    [[nodiscard]] Result<ProposalResult> submit_governance_proposal(
        uint8_t parameter, const std::string& new_value, const std::string& rationale);

    // -----------------------------------------------------------------
    // Attestation manifests
    // -----------------------------------------------------------------

    /// GET /api/attestation/manifests
    [[nodiscard]] Result<AttestationManifests> get_attestation_manifests();

    // -----------------------------------------------------------------
    // Latency-based auto-switching
    // -----------------------------------------------------------------

    /// Enable automatic server switching based on latency monitoring.
    void enable_auto_switching(const LatencyConfig& config = {});

    /// Disable automatic server switching and stop the background monitor.
    void disable_auto_switching();

    /// Get the smoothed RTT (ms) to the current server. Returns 0.0 if monitoring is off.
    [[nodiscard]] double current_latency_ms() const;

    /// Get latency stats for all monitored servers.
    [[nodiscard]] std::vector<ServerLatency> server_latencies() const;

    // -----------------------------------------------------------------
    // WireGuard tunnel management
    // -----------------------------------------------------------------

    /// Get current WireGuard tunnel status.
    [[nodiscard]] TunnelStatus tunnel_status() const;

    /// Check if the WireGuard tunnel is currently active.
    [[nodiscard]] bool is_tunnel_active() const;

    /// Get the WireGuard configuration string (wg-quick format).
    /// Useful on mobile platforms where the app manages the VPN lifecycle.
    [[nodiscard]] std::string get_wireguard_config() const;

    /// Get the WireGuard configuration as JSON (matching ln_tunnel_up format).
    [[nodiscard]] std::string get_wireguard_config_json() const;

    /// Manually bring up the WireGuard tunnel with the given config.
    [[nodiscard]] StatusResult tunnel_up(const WireGuardConfig& config);

    /// Tear down the WireGuard tunnel.
    [[nodiscard]] StatusResult tunnel_down();

    // -----------------------------------------------------------------
    // Mesh P2P networking
    // -----------------------------------------------------------------

    /// Enable mesh networking. Starts background peer discovery, NAT traversal,
    /// and tunnel synchronization. Requires an active tunnel and node_id.
    void enable_mesh(const MeshConfig& config = {});

    /// Disable mesh networking and remove all mesh peers from the tunnel.
    void disable_mesh();

    /// Get mesh tunnel status including all peers with live stats.
    [[nodiscard]] MeshTunnelStatus mesh_status() const;

    /// Get the current list of known mesh peers.
    [[nodiscard]] std::vector<MeshPeer> get_mesh_peers() const;

    /// Force an immediate peer refresh (fetch from server + sync tunnel).
    void refresh_mesh_peers();

    /// Callback type for mesh state changes.
    using MeshStateCallback = std::function<void(const MeshTunnelStatus&)>;

    /// Set a callback to be notified on mesh state changes.
    void set_mesh_callback(MeshStateCallback cb);

    /// Fetch mesh peers from the server for a given node_id.
    /// Used internally by MeshOrchestrator; also available for direct use.
    [[nodiscard]] Result<std::vector<MeshPeer>> fetch_mesh_peers(const std::string& node_id);

    /// Send a heartbeat to the server reporting our current endpoint.
    [[nodiscard]] StatusResult mesh_heartbeat(const std::string& node_id,
                                               const std::string& endpoint);

    // -----------------------------------------------------------------
    // Session state
    // -----------------------------------------------------------------

    /// Set the session token obtained from authentication.
    void set_session_token(const std::string& token);

    /// Get the current session token.
    /// Returns by value to avoid data races with concurrent set_session_token().
    [[nodiscard]] std::string session_token() const;

    /// Get the assigned node ID (set after join_network or set manually).
    /// Returns by value to avoid data races with concurrent set_node_id().
    [[nodiscard]] std::string node_id() const;

    /// Set the node ID manually.
    void set_node_id(const std::string& id);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace lnsdk
