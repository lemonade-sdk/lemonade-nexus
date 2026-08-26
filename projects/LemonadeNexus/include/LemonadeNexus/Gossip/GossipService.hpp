#pragma once

#include <LemonadeNexus/ACL/ACLService.hpp>
#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Gossip/IGossipProvider.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Security/Transport/SecurityTransport.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <asio.hpp>

#include <array>
#include <chrono>
#include <mutex>
#include <optional>
#include <random>
#include <functional>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace nexus::network { class DnsService; }
namespace nexus::boringtun { class BoringtunService; }

namespace nexus::gossip {

struct MisbehaviorProof;  // Gossip/MisbehaviorDetector.hpp

/// Gossip-based state synchronization service.
///
/// Runs a UDP socket on the gossip port (default 9102). Every 5 seconds, picks a
/// random known peer and sends a Digest containing our latest delta sequence and
/// tree hash. On receiving a peer's Digest, compares sequences and either requests
/// or sends deltas as needed. All messages are signed with our Ed25519 key.
///
/// Peers are loaded from and saved to identity/peers.json via FileStorageService.
class GossipService : public core::IService<GossipService>,
                       public IGossipProvider<GossipService>,
                       public security::ISecurityTransport {
    friend class core::IService<GossipService>;
    friend class IGossipProvider<GossipService>;
    // Test seam: private state sits behind packet-signature verification and a
    // bound socket, neither of which a unit test can drive. Reaching it via a
    // friend keeps the production surface unchanged.
    friend struct GossipBallotTestAccess;

public:
    GossipService(asio::io_context& io, uint16_t port,
                   storage::FileStorageService& storage,
                   crypto::SodiumCryptoService& crypto);

    /// Set the root management pubkey for certificate verification.
    void set_root_pubkey(const crypto::Ed25519PublicKey& pk);

    /// True once a root-of-trust pubkey has been configured.
    [[nodiscard]] bool has_root_pubkey() const { return has_root_pubkey_; }

    /// The configured root pubkey (only valid when has_root_pubkey()).
    [[nodiscard]] const crypto::Ed25519PublicKey& root_pubkey() const { return root_pubkey_; }

    /// Strict identity-binding verification for the routed E2E trust path.
    /// Unlike verify_server_certificate, this HARD-FAILS when no root pubkey is
    /// configured (no fail-open): a node that cannot anchor the root of trust
    /// cannot accept any binding.
    [[nodiscard]] bool verify_identity_binding(const ServerCertificate& cert) const;

    /// Set the IPAM service for tunnel IP allocation during ServerHello exchange.
    void set_ipam(ipam::IPAMService* ipam);

    /// Set the boringtun service for backbone peer provisioning.
    void set_boringtun(boringtun::BoringtunService* wg);

    /// Get the tunnel IP assigned to this server (empty if not yet assigned).
    [[nodiscard]] std::string our_tunnel_ip() const;

    /// Our own server_id from the installed certificate (nullopt if unenrolled).
    /// Used by admission to stop a candidate claiming the root's own identity.
    [[nodiscard]] std::optional<std::string> our_server_id() const {
        return our_certificate_ ? std::optional<std::string>(our_certificate_->server_id)
                                : std::nullopt;
    }

    /// Set our backbone IP for inclusion in ServerHello messages.
    void set_our_backbone_ip(const std::string& ip) { our_backbone_ip_ = ip; }

    /// Get our backbone IP.
    [[nodiscard]] std::string our_backbone_ip() const { return our_backbone_ip_; }

    /// Set our WG pubkey for inclusion in ServerHello messages.
    void set_our_wg_pubkey(const std::string& pubkey) { our_wg_pubkey_ = pubkey; }

    /// Set the "ip:port" this server is reachable at, carried in ServerHello so
    /// peers share it instead of the UDP source they happen to observe. Call
    /// before start().
    void set_our_advertised_endpoint(const std::string& ep) { our_advertised_endpoint_ = ep; }

    /// Broadcast a backbone IPAM allocation delta to all peers.
    void broadcast_backbone_ipam_delta(const ipam::BackboneAllocationDelta& delta);

    /// Set the cloud region code for this server (e.g. "us-east-1").
    void set_our_region(const std::string& region);

    /// Set the DNS base domain for NS slot FQDN construction (default: "lemonade-nexus.io").
    void set_dns_base_domain(const std::string& domain);

    /// Attempt to claim the lowest available NS slot (ns1-ns9) via gossip.
    void try_claim_ns_slot(const std::string& our_public_ip);

    /// Returns our claimed NS slot number (1-9), or nullopt if we don't hold one.
    [[nodiscard]] std::optional<uint8_t> our_ns_slot() const;

    /// Returns all currently claimed NS slots (for status reporting).
    [[nodiscard]] std::vector<NsSlotClaimData> get_ns_slots() const;

    /// Try to add a gossip peer as a mesh backbone peer.
    void try_add_backbone_wg_peer(const GossipPeer& peer);

    /// Access this server's Ed25519 identity keypair.
    [[nodiscard]] const crypto::Ed25519Keypair& keypair() const { return keypair_; }

    // ISecurityTransport. Gossip is transport only for the security protocol:
    // the packet signature authenticates the sender, the byte bound applies,
    // and the bytes go to the sink unparsed. Nothing here decides security
    // truth and nothing here relays an envelope.

    /// Receiver for inbound security envelopes. Runs on the io thread during
    /// packet dispatch; the span is valid only for the call. Call before start().
    void set_security_sink(security::SecuritySink sink);

    /// Reports the peer whose certificate just verified in handle_server_hello
    /// (the peer's raw Ed25519 identity key). Transport reports contact; it
    /// decides nothing. Runs on the io thread, outside peers_mutex_.
    void set_peer_certified_callback(std::function<void(const security::NodeId&)> cb);

    [[nodiscard]] bool send_to(const security::NodeId& peer,
                               std::span<const uint8_t> envelope) override;
    std::size_t broadcast(std::span<const uint8_t> envelope) override;

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
                                const std::string& sender_pubkey,
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

    // Security envelope: sender_pubkey is the signature-verified packet signer.
    void handle_security_envelope(const uint8_t* sender_pubkey,
                                  const uint8_t* payload, std::size_t len);

    // Endpoint of the peer whose canonical base64 key equals `b64`. Takes
    // peers_mutex_ internally.
    [[nodiscard]] bool find_peer_endpoint_by_pubkey(std::string_view b64,
                                                    asio::ip::udp::endpoint& out) const;

    // Pick up to N random peers for PeerExchange
    [[nodiscard]] std::vector<GossipPeer> random_peers(std::size_t count) const;

    // ServerHello handler. signer_pubkey is the packet's cryptographically
    // authenticated sender key (proven by verify_packet_signature) — used to
    // enforce proof-of-possession of the certificate identity.
    void handle_server_hello(const asio::ip::udp::endpoint& sender,
                              const uint8_t* payload, std::size_t payload_len,
                              const std::string& signer_pubkey);

    // ACL delta handler
    void handle_acl_delta(const asio::ip::udp::endpoint& sender,
                           const std::string& sender_pubkey,
                           const uint8_t* payload, std::size_t payload_len);

    // DNS record sync handler
    void handle_dns_record_sync(const asio::ip::udp::endpoint& sender,
                                 const std::string& sender_pubkey,
                                 const uint8_t* payload, std::size_t payload_len);

    // Backbone IPAM sync handler
    void handle_backbone_ipam_sync(const asio::ip::udp::endpoint& sender,
                                    const std::string& sender_pubkey,
                                    const uint8_t* payload, std::size_t payload_len);

    // NS slot claim handler
    void handle_ns_slot_claim(const asio::ip::udp::endpoint& sender,
                               const uint8_t* payload, std::size_t payload_len);

    /// Broadcast an NS slot claim to all known peers.
    void broadcast_ns_slot_claim(const NsSlotClaimData& claim);

    /// Register an NS slot claim in the local DNS service (if available).
    void register_ns_slot_in_dns(const NsSlotClaimData& claim);

    // Verify a server certificate against the root pubkey
    [[nodiscard]] bool verify_server_certificate(const ServerCertificate& cert) const;

    // Shared cert checks (issuer == root, expiry, revocation, signature).
    // Assumes a root pubkey is configured; the root-presence policy differs
    // between verify_server_certificate (fail-open) and verify_identity_binding
    // (hard-fail), so it is handled by the callers.
    [[nodiscard]] bool verify_cert_core(const ServerCertificate& cert) const;

    // Check if a server pubkey has been revoked
    [[nodiscard]] bool is_revoked(const std::string& server_pubkey) const;

    // --- Misbehavior detection (equivocation proofs) ---

    /// Handle an inbound MisbehaviorProofBroadcast: verify the proof is dispositive
    /// (both statements signed by the accused + genuine conflict), and if so ban the
    /// accused and re-broadcast (epidemic spread, verify-before-forward).
    void handle_misbehavior_proof(const asio::ip::udp::endpoint& sender,
                                  const uint8_t* payload, std::size_t payload_len);

    /// Gossip a verified proof to all peers (except an optional origin we got it from).
    void broadcast_misbehavior_proof(const MisbehaviorProof& proof,
                                     const std::string& exclude_endpoint = {});

    /// Durably ban a convicted pubkey: add to the revocation list (persisted), drop
    /// its peer entry, and persist the proof as evidence. Idempotent. `pubkey`
    /// may carry an "ed25519:"
    /// prefix; it is normalized to the certificate/revocation form.
    void apply_ban(const std::string& pubkey, const MisbehaviorProof& proof);

    /// Persist the current revocation list to identity/revoked_servers.json.
    void save_revoked_servers() const;

    /// Tier-2 transport membership gate — NEVER fails open: false when no root
    /// pubkey is configured. True only if `pubkey` is a known, non-revoked peer
    /// whose stored certificate belongs to it and verifies against the configured
    /// root via verify_cert_core (real issuer==root check + Ed25519 verify).
    [[nodiscard]] bool peer_certificate_is_root_signed(const std::string& pubkey) const;

    /// Same check for callers that already hold peers_mutex_.
    [[nodiscard]] bool peer_certificate_is_root_signed_locked(const std::string& pubkey) const;

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

    // Equivocation detection: last signed tree-delta we've seen per conflict identity
    // (signer ‖ target_node_id ‖ sequence) → the delta's JSON. A second, differing
    // statement at the same identity is provable equivocation. Bounded to avoid
    // unbounded growth; on overflow we clear (losing only detection memory, never
    // correctness — a re-sent conflicting pair is re-detected).
    mutable std::mutex               seen_statements_mutex_;
    std::unordered_map<std::string, std::string> seen_statements_;
    static constexpr std::size_t     kMaxSeenStatements = 50000;

    // Misbehavior proofs we've already processed (proof_id) — dedupe re-broadcasts.
    std::unordered_map<std::string, uint64_t> known_proofs_;

    // IPAM for tunnel IP allocation during ServerHello exchange
    ipam::IPAMService*               ipam_{nullptr};
    boringtun::BoringtunService*     boringtun_{nullptr};
    std::string                      our_tunnel_ip_;     // assigned by peer or self
    std::string                      our_backbone_ip_;   // 172.16.0.X backbone
    std::string                      our_wg_pubkey_;     // base64 X25519
    std::string                      our_advertised_endpoint_;  // "ip:port" we are reachable at

    // Democratic NS slot claiming (ns1-ns9 bootstrap nameservers)
    std::string                      our_region_;
    std::string                      dns_base_domain_{"lemonade-nexus.io"};
    std::array<NsSlotClaimData, 9>   ns_slots_{};       // slot 0 = ns1, slot 8 = ns9
    std::optional<uint8_t>           our_ns_slot_;
    uint8_t                          preferred_ns_slot_{0};  // 0 = auto (lowest free)

    // Distributed ACL sync (nullptr = ACL sync disabled)
    acl::ACLService*                 acl_{nullptr};

    // Distributed DNS record sync (nullptr = DNS sync disabled)
    network::DnsService*             dns_{nullptr};

    // Security transport: inbound sink and the oversize-drop log throttle
    // (both touched only from handle_receive on the io thread).
    security::SecuritySink                security_sink_;
    std::function<void(const security::NodeId&)> peer_certified_cb_;
    std::chrono::steady_clock::time_point security_drop_warn_at_{};
    uint64_t                              security_drops_since_warn_{0};

public:
    /// Set the ACL service for distributed permission sync.
    void set_acl(acl::ACLService* acl);

    /// Broadcast an ACL delta to all known peers (called by ACLService callback).
    void broadcast_acl_delta(const acl::AclDelta& delta);

    /// Set the DNS service for distributed DNS record sync.
    void set_dns(network::DnsService* dns);

    /// Broadcast a DNS record delta to all known peers.
    void broadcast_dns_record_delta(const DnsRecordDelta& delta);

    /// Pin the NS slot this server claims (1-9); 0 = auto (lowest free). Set
    /// when the operator's ns<N> identity matches registrar glue for that name.
    void set_preferred_ns_slot(uint8_t slot);

    /// Add a server pubkey to the revocation set and persist it. Idempotent.
    /// The single runtime writer of revoked_servers.json — callers such as the
    /// admission supersede path must route through here, never write the file.
    void add_revoked_server(const std::string& server_pubkey);
};

} // namespace nexus::gossip
