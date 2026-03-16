#pragma once

#include <LemonadeNexus/ACL/ACLService.hpp>
#include <LemonadeNexus/Core/GovernanceService.hpp>
#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Core/RootKeyChain.hpp>
#include <LemonadeNexus/Core/TrustPolicy.hpp>
#include <LemonadeNexus/Gossip/IGossipProvider.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <asio.hpp>

#include <array>
#include <atomic>
#include <mutex>
#include <optional>
#include <random>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace nexus::network { class DnsService; }

namespace nexus::gossip {

/// Gossip-based state synchronization service.
///
/// Runs a UDP socket on the gossip port (default 9102). Every 5 seconds, picks a
/// random known peer and sends a Digest containing our latest delta sequence and
/// tree hash. On receiving a peer's Digest, compares sequences and either requests
/// or sends deltas as needed. All messages are signed with our Ed25519 key.
///
/// Peers are loaded from and saved to identity/peers.json via FileStorageService.
class GossipService : public core::IService<GossipService>,
                       public IGossipProvider<GossipService> {
    friend class core::IService<GossipService>;
    friend class IGossipProvider<GossipService>;

public:
    GossipService(asio::io_context& io, uint16_t port,
                   storage::FileStorageService& storage,
                   crypto::SodiumCryptoService& crypto);

    /// Set the root management pubkey for certificate verification.
    void set_root_pubkey(const crypto::Ed25519PublicKey& pk);

    /// Set the TrustPolicyService for zero-trust enforcement.
    /// Must be called before start() for trust features to be active.
    void set_trust_policy(core::TrustPolicyService* policy);

    /// Set the RootKeyChainService for key rotation and Shamir share distribution.
    void set_root_key_chain(core::RootKeyChainService* chain);

    /// Set the GovernanceService for democratic parameter changes.
    void set_governance(core::GovernanceService* governance);

    /// Set the IPAM service for tunnel IP allocation during ServerHello exchange.
    void set_ipam(ipam::IPAMService* ipam);

    /// Get the tunnel IP assigned to this server (empty if not yet assigned).
    [[nodiscard]] std::string our_tunnel_ip() const;

    /// Access the Ed25519 keypair (needed by TrustPolicy for token generation).
    [[nodiscard]] const crypto::Ed25519Keypair& keypair() const { return keypair_; }

    // IService
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "GossipService"; }

    // IGossipProvider
    void do_add_peer(std::string_view endpoint, std::string_view pubkey);
    void do_remove_peer(std::string_view pubkey);
    void do_send_digest(const GossipPeer& peer);
    void do_handle_digest(const GossipPeer& peer, uint64_t their_seq,
                           const std::array<uint8_t, 32>& their_hash);
    void do_send_deltas(const GossipPeer& peer, uint64_t from_seq);
    void do_handle_deltas(const GossipPeer& peer, const nlohmann::json& deltas_json);
    [[nodiscard]] std::vector<GossipPeer> do_get_peers() const;

private:
    // UDP async receive loop
    void start_receive();
    void handle_receive(std::size_t bytes_received);

    // Gossip timer: fires every 5 seconds to pick a random peer and send digest
    void start_gossip_timer();
    void on_gossip_tick();

    // Peer persistence
    void load_peers();
    void save_peers();

    // Packet construction and sending
    void send_packet(const asio::ip::udp::endpoint& target,
                      GossipMsgType msg_type,
                      const std::vector<uint8_t>& payload);

    // Message handlers by type
    void handle_digest_message(const asio::ip::udp::endpoint& sender,
                                const uint8_t* payload, std::size_t payload_len);
    void handle_delta_request(const asio::ip::udp::endpoint& sender,
                               const uint8_t* payload, std::size_t payload_len);
    void handle_delta_response(const asio::ip::udp::endpoint& sender,
                                const uint8_t* payload, std::size_t payload_len);
    void handle_anti_entropy(const asio::ip::udp::endpoint& sender,
                              const uint8_t* payload, std::size_t payload_len);
    void handle_peer_exchange(const asio::ip::udp::endpoint& sender,
                               const uint8_t* payload, std::size_t payload_len);

    // Parse "ip:port" into a UDP endpoint
    [[nodiscard]] static std::optional<asio::ip::udp::endpoint>
    parse_endpoint(std::string_view endpoint_str);

    // Find a peer by sender endpoint address
    [[nodiscard]] std::optional<GossipPeer>
    find_peer_by_endpoint(const asio::ip::udp::endpoint& ep) const;

    // Verify an incoming packet's Ed25519 signature
    [[nodiscard]] bool verify_packet_signature(const uint8_t* data, std::size_t total_len) const;

    // Pick up to N random peers for PeerExchange
    [[nodiscard]] std::vector<GossipPeer> random_peers(std::size_t count) const;

    // ServerHello handler
    void handle_server_hello(const asio::ip::udp::endpoint& sender,
                              const uint8_t* payload, std::size_t payload_len);

    // TEE challenge/response handlers (mutual verification)
    void handle_tee_challenge(const asio::ip::udp::endpoint& sender,
                               const uint8_t* payload, std::size_t payload_len);
    void handle_tee_response(const asio::ip::udp::endpoint& sender,
                              const uint8_t* payload, std::size_t payload_len);

    /// Send a TEE challenge to a peer to verify their Tier 1 status.
    void send_tee_challenge(const asio::ip::udp::endpoint& target,
                             const std::string& peer_pubkey);

    // Enrollment quorum handlers
    void handle_enrollment_vote_request(const asio::ip::udp::endpoint& sender,
                                         const uint8_t* payload, std::size_t payload_len);
    void handle_enrollment_vote(const asio::ip::udp::endpoint& sender,
                                 const uint8_t* payload, std::size_t payload_len);

    /// Broadcast an enrollment vote request to all known Tier1 peers.
    void broadcast_enrollment_vote_request(const EnrollmentBallot& ballot);

    /// Cast our vote for an enrollment and broadcast it.
    void cast_enrollment_vote(const std::string& request_id,
                               const std::string& candidate_pubkey,
                               bool approve, const std::string& reason);

    /// Check if quorum is met for a pending enrollment.
    void check_enrollment_quorum(const std::string& request_id);

    /// Expire timed-out enrollment ballots.
    void expire_enrollment_ballots();

    /// Zero-trust gate: verify an incoming message's attestation token.
    /// Returns the sender's pubkey if authorized, empty string if denied.
    [[nodiscard]] std::string verify_message_trust(
        const uint8_t* payload, std::size_t payload_len,
        core::TrustOperation required_op);

    // Root key rotation handlers
    void handle_root_key_rotation(const asio::ip::udp::endpoint& sender,
                                   const uint8_t* payload, std::size_t payload_len);
    void handle_shamir_share_offer(const asio::ip::udp::endpoint& sender,
                                    const uint8_t* payload, std::size_t payload_len);
    void handle_shamir_share_submit(const asio::ip::udp::endpoint& sender,
                                     const uint8_t* payload, std::size_t payload_len);
    void handle_peer_health_report(const asio::ip::udp::endpoint& sender,
                                    const uint8_t* payload, std::size_t payload_len);

    /// Broadcast root key rotation to all peers.
    void broadcast_root_key_rotation(const core::RootKeyEntry& entry);

    /// Distribute Shamir shares to all eligible Tier1 peers (encrypted per-peer).
    void distribute_shamir_shares();

    /// Broadcast our peer health observations to peers.
    void broadcast_peer_health();

    /// Record gossip tick for peer health tracking.
    void record_peer_health_tick();

    // Governance handlers
    void handle_governance_proposal(const asio::ip::udp::endpoint& sender,
                                     const uint8_t* payload, std::size_t payload_len);
    void handle_governance_vote(const asio::ip::udp::endpoint& sender,
                                 const uint8_t* payload, std::size_t payload_len);

    /// Broadcast a governance message to all known peers.
    void broadcast_governance_message(GossipMsgType type, const std::vector<uint8_t>& payload);

    // ACL delta handler
    void handle_acl_delta(const asio::ip::udp::endpoint& sender,
                           const uint8_t* payload, std::size_t payload_len);

    // DNS record sync handler
    void handle_dns_record_sync(const asio::ip::udp::endpoint& sender,
                                 const uint8_t* payload, std::size_t payload_len);

    // Verify a server certificate against the root pubkey
    [[nodiscard]] bool verify_server_certificate(const ServerCertificate& cert) const;

    // Check if a server pubkey has been revoked
    [[nodiscard]] bool is_revoked(const std::string& server_pubkey) const;

    // Load the server certificate and root pubkey
    void load_server_certificate();

    // Members
    asio::ip::udp::socket    socket_;
    asio::ip::udp::endpoint  remote_endpoint_;
    asio::steady_timer       gossip_timer_;
    std::array<uint8_t, 65536> recv_buffer_{};

    storage::FileStorageService& storage_;
    crypto::SodiumCryptoService& crypto_;
    crypto::Ed25519Keypair       keypair_;

    mutable std::mutex      peers_mutex_;
    std::vector<GossipPeer> peers_;
    uint16_t                port_;

    mutable std::mutex      rng_mutex_;
    mutable std::mt19937    rng_{std::random_device{}()};

    // Server enrollment
    std::optional<ServerCertificate> our_certificate_;
    crypto::Ed25519PublicKey         root_pubkey_{};
    bool                             has_root_pubkey_{false};
    std::vector<std::string>         revoked_pubkeys_;

    // Zero-trust enforcement (nullptr = trust checks disabled)
    core::TrustPolicyService*        trust_policy_{nullptr};

    // Root key chain (nullptr = rotation disabled)
    core::RootKeyChainService*       root_key_chain_{nullptr};

    // Democratic governance (nullptr = governance disabled)
    core::GovernanceService*         governance_{nullptr};
    std::atomic<uint64_t>            last_known_generation_{0};

    // IPAM for tunnel IP allocation during ServerHello exchange
    ipam::IPAMService*               ipam_{nullptr};
    std::string                      our_tunnel_ip_;  // assigned by peer or self

    // Shamir reconstruction: collect submitted shares from peers
    std::mutex                              reconstruction_mutex_;
    std::vector<std::string>                reconstruction_shares_;
    uint8_t                                 reconstruction_threshold_{0};

    // Distributed ACL sync (nullptr = ACL sync disabled)
    acl::ACLService*                 acl_{nullptr};

    // Distributed DNS record sync (nullptr = DNS sync disabled)
    network::DnsService*             dns_{nullptr};

    // Quorum-based enrollment
    bool     enrollment_quorum_enabled_{false};
    float    enrollment_quorum_ratio_{0.5f};
    uint32_t enrollment_vote_timeout_sec_{60};
    uint32_t enrollment_max_retries_{3};
    std::unordered_map<std::string, EnrollmentBallot> pending_enrollments_;

public:
    /// Set the ACL service for distributed permission sync.
    void set_acl(acl::ACLService* acl);

    /// Broadcast an ACL delta to all known peers (called by ACLService callback).
    void broadcast_acl_delta(const acl::AclDelta& delta);

    /// Set the DNS service for distributed DNS record sync.
    void set_dns(network::DnsService* dns);

    /// Broadcast a DNS record delta to all known peers.
    void broadcast_dns_record_delta(const DnsRecordDelta& delta);

    /// Configure enrollment quorum parameters.
    void set_enrollment_config(bool enabled, float ratio,
                                uint32_t timeout_sec, uint32_t max_retries);

    /// Get pending enrollment ballots (for status API).
    [[nodiscard]] std::vector<EnrollmentBallot> pending_enrollments() const;
};

} // namespace nexus::gossip
