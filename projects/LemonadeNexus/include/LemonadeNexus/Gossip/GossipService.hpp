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
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <functional>
#include <set>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace nexus::network { class DnsService; }
namespace nexus::boringtun { class BoringtunService; }
namespace nexus::tree { class PermissionTreeService; }

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
                       public IGossipProvider<GossipService>,
                       public security::ISecurityTransport {
    friend class core::IService<GossipService>;
    friend class IGossipProvider<GossipService>;
    // Test seam: private state sits behind packet-signature verification and a
    // bound socket, neither of which a unit test can drive. Reaching it via a
    // friend keeps the production surface unchanged.
    friend struct GossipBallotTestAccess;

public:
    // --- Delta record transfer bounds ---
    // One page of a delta transfer; the pool holds retained author-signed
    // records (transfer state, never authoritative tree/ACL state).
    static constexpr std::size_t   kPageMaxRecords         = 100;
    static constexpr std::size_t   kPageMaxPayloadBytes    = 60000;
    static constexpr std::size_t   kPoolMaxRecords         = 10000;
    static constexpr std::uint64_t kPoolMaxBytes           = 64ull * 1024 * 1024;
    static constexpr std::uint64_t kMaxRetainedRecordBytes = 50000;
    static constexpr std::size_t   kOutstandingGlobal      = 64;
    static constexpr std::uint64_t kRequestTimeoutMs       = 10000;
    static constexpr std::size_t   kStallBudget            = 5;
    static constexpr std::uint64_t kBackoffMs              = 30000;
    static constexpr std::size_t   kPeerLogCap             = 512;

    GossipService(asio::io_context& io, uint16_t port,
                   storage::FileStorageService& storage,
                   crypto::SodiumCryptoService& crypto);

    /// Set the root management pubkey for certificate verification.
    void set_root_pubkey(const crypto::Ed25519PublicKey& pk);

    /// The Nexus network this node belongs to, as hex. Certificate validation
    /// requires it and rejects a certificate for any other network — the gate
    /// never fails open, so with no network configured no certificate is valid.
    void set_network_id(const std::string& network_hex);

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
    void set_boringtun(boringtun::BoringtunService* dataplane);

    /// Set the permission tree used to evaluate received records' existing
    /// operation-derived permissions. Null means no permission context is
    /// available (acceptance refuses as ContextMissing, never as authorized).
    void set_tree(tree::PermissionTreeService* tree) { tree_ = tree; }

    /// Retention entry point for locally applied deltas (wired by the host).
    /// Record transfer only: never mutates the tree. Returns false when the
    /// pool refused the record (full, unavailable, or write failure).
    [[nodiscard]] bool retain_local_delta(
            const storage::FileStorageService::RetainedDelta& rec);

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

    /// Set our mesh public key for inclusion in ServerHello messages.
    void set_our_mesh_pubkey(const std::string& pubkey) { our_mesh_pubkey_ = pubkey; }

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
    void try_add_backbone_mesh_peer(const GossipPeer& peer);

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

    /// Whether this peer holds a root-signed transport certificate. One of the
    /// Tier 1 prerequisites, and the transport is where the root signature was
    /// already verified. Reports an answer; it grants nothing.
    [[nodiscard]] bool peer_is_root_certified(const security::NodeId& peer) const;

    // IService
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "GossipService"; }

    // IGossipProvider
    void do_add_peer(std::string_view endpoint, std::string_view pubkey);
    void do_remove_peer(std::string_view pubkey);
    void do_send_digest(const GossipPeer& peer);
    void do_handle_digest(const GossipPeer& peer, uint64_t their_pos,
                           const std::string& their_generation);
    [[nodiscard]] std::vector<GossipPeer> do_get_peers() const;

    /// Number of tracked peers (peers_mutex_ taken internally).
    [[nodiscard]] std::size_t peer_count() const;

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

    // Message handlers by type. signer_pubkey is the packet-authenticated
    // sender (proven by verify_packet_signature); it is the transport
    // identity for gating and binding.
    void handle_digest_message(const asio::ip::udp::endpoint& sender,
                                const uint8_t* payload, std::size_t payload_len,
                                const std::string& signer_pubkey);
    void handle_delta_request(const asio::ip::udp::endpoint& sender,
                               const uint8_t* payload, std::size_t payload_len,
                               const std::string& signer_pubkey);
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

    // The tracked peer with this authenticated pubkey, if any (peers_mutex_
    // taken internally).
    [[nodiscard]] std::optional<GossipPeer> find_peer_by_pubkey(std::string_view b64) const;

    // --- Delta record transfer (under transfer_mutex_ unless noted) ---

    /// Per-peer log tracking. `cursor` is the contiguous prefix of the
    /// peer's pool this node has processed; `backoff_until_ms` persists
    /// across generation changes — a new log is not a retry reset.
    struct PeerLogState {
        std::string generation;
        uint64_t    cursor{0};
        uint64_t    stall{0};
        uint64_t    backoff_until_ms{0};
        uint64_t    last_digest_ms{0};
    };
    struct OutstandingRequest {
        uint64_t    nonce{0};
        uint64_t    from_pos{0};
        std::string generation;
        uint64_t    deadline_ms{0};
    };

    /// Result of retaining a record. Retained/Duplicate publish acceptance;
    /// every other value leaves pool state exactly as it was.
    enum class PoolRetain {
        Retained, Duplicate,
        RefusedCapacity, RefusedCollision, RefusedOversize,
        RefusedUnavailable, FailedWrite, RefusedMalformed
    };

    /// Outcome of admitting one received record (verify + authorize + retain).
    enum class Admission {
        Accepted, Duplicate, RefusedFinal, RefusedRetryable
    };

    /// Reconstruct the pool index from retained files within the bounds.
    /// Any record that fails re-verification is excluded (file preserved);
    /// any condition that prevents a COMPLETE reconstruction (bounds
    /// exceeded, unreadable record, inconsistent generation/position
    /// metadata) marks the pool unavailable for transfer and new retention.
    void reconstruct_transfer_pool();

    /// Retain an already-verified record (identity recomputed from content).
    /// Acceptance is published only after a successful durable write.
    [[nodiscard]] PoolRetain retain_verified_record(
            const storage::FileStorageService::RetainedDelta& rec,
            uint64_t& out_position);

    /// Admission pipeline for a received record: author signature, existing
    /// operation-derived permission (no author certificate required), then
    /// retention. RefusedRetryable covers missing permission context and
    /// all retention refusals; RefusedFinal covers statement defects.
    [[nodiscard]] Admission admit_received_record(const nlohmann::json& record);

    /// Request the next page from a peer, subject to the outstanding rules
    /// (one per peer, global cap, generation-bound). No-op when not allowed.
    void maybe_request_from(const std::string& peer_pubkey,
                            std::string_view endpoint, uint64_t from_pos);

    /// Retention entry point implementation (publishes through the storage
    /// pool; called for locally applied deltas).
    void retain_local_delta_locked(const storage::FileStorageService::RetainedDelta& rec);

    /// Highest position in the pool index (0 when empty). Caller holds
    /// transfer_mutex_.
    [[nodiscard]] uint64_t pool_latest_position_locked() const;

    /// Random 16-byte hex generation. Caller holds transfer_mutex_.
    std::string make_pool_generation_locked();

    /// Evict only idle peer-log entries (no outstanding request, no active
    /// backoff). Eviction must not provide a retry bypass. Caller holds
    /// transfer_mutex_.
    void evict_idle_peer_logs_locked(uint64_t now);

    [[nodiscard]] std::size_t peer_log_cap() const {
        return test_peer_log_cap_ ? test_peer_log_cap_ : kPeerLogCap;
    }
    [[nodiscard]] std::size_t effective_pool_max_records() const {
        return test_pool_max_records_ ? test_pool_max_records_ : kPoolMaxRecords;
    }
    [[nodiscard]] std::uint64_t effective_pool_max_bytes() const {
        return test_pool_max_bytes_ ? test_pool_max_bytes_ : kPoolMaxBytes;
    }

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

    // --- Misbehavior proofs (retired path) ---
    //
    // The sequence-based tree equivocation path is retired: transport
    // positions do not establish equivocation, and no ban is ever issued
    // from a received record. Wire value 0x15 remains reserved; received
    // proofs are logged and dropped.
    void handle_misbehavior_proof(const asio::ip::udp::endpoint& sender,
                                  const uint8_t* /*payload*/, std::size_t /*payload_len*/);

    /// Persist the current revocation list to identity/revoked_servers.json.
    void save_revoked_servers() const;

    /// Tier-2 transport membership gate — NEVER fails open: false when no root
    /// pubkey is configured. True only if `pubkey` is a known, non-revoked peer
    /// whose stored certificate belongs to it and verifies against the configured
    /// root via verify_cert_core (real issuer==root check + Ed25519 verify).
    [[nodiscard]] bool peer_certificate_is_root_signed(const std::string& pubkey) const;

    /// The origin-signed half of a gossiped delta: the named author signed
    /// exactly `canonical`, and the root enrolled that author. The packet
    /// signature only ever names the forwarder.
    [[nodiscard]] bool delta_origin_verified(const std::string& canonical,
                                             const std::string& signer_pubkey_b64,
                                             const std::string& signature_b64) const;

    /// Stores a certificate relayed through peer exchange, but only after the
    /// same full verification a direct hello gets, and never over one already
    /// held. This is how a delta's author can be certified without being a
    /// direct peer.
    void adopt_relayed_certificate(const std::string& pubkey_b64,
                                   const std::string& certificate_json);

    /// Same check for callers that already hold peers_mutex_.
    [[nodiscard]] bool peer_certificate_is_root_signed_locked(const std::string& pubkey) const;

    /// The server_id in a peer's root-verified certificate, or empty when the
    /// peer is unknown, uncertified, or revoked. Ordinary per-server resource
    /// ownership (SEIP DNS records) is keyed on this.
    [[nodiscard]] std::string certified_server_id(const std::string& pubkey) const;

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
    std::string                      expected_network_id_;
    bool                             has_root_pubkey_{false};
    std::vector<std::string>         revoked_pubkeys_;
    /// Tier 1 membership per finalized state; unset denies tier1 labels.
    std::function<bool(const std::string&)> tier1_membership_;

    // --- Shared mesh state (tunnel IP + NS slots) ---
    // One lock for the mutable mesh-contact state written on the io thread
    // and read from the main thread and the status API. Never held together
    // with peers_mutex_ or transfer_mutex_; external calls (DNS, packet
    // send) run outside it.
    mutable std::mutex mesh_state_mutex_;

    // --- Delta transfer pool state (under transfer_mutex_) ---
    mutable std::mutex                transfer_mutex_;
    std::unordered_map<std::string, PeerLogState>       peer_logs_;
    std::unordered_map<std::string, OutstandingRequest> outstanding_;
    // Pool index. position_index: pool position -> record hash; the hash
    // maps are the reverse index and the verified/excluded identifier sets.
    std::map<uint64_t, std::string>          pool_position_index_;
    std::unordered_map<std::string, uint64_t> pool_hash_to_position_;
    std::unordered_set<std::string>          pool_verified_;
    std::unordered_set<std::string>          pool_excluded_;
    std::uint64_t                            pool_verified_bytes_{0};
    std::uint64_t                            pool_excluded_bytes_{0};
    std::uint64_t                            pool_next_position_{1};
    std::string                              pool_generation_;
    bool                                    pool_available_{false};
    bool                                    pool_reconstructed_{false};
    // Set when a pool write reached the uncertain outcome (rename done,
    // directory sync failed): further retention is refused and the position
    // is never handed out again. Only startup reconstruction — which
    // re-verifies content and identifier — may reconcile the state.
    bool                                    pool_has_uncertain_write_{false};

    // Test seam: non-aborted receive errors that reached the error branch.
    std::uint64_t test_receive_error_count_{0};

    // Test seams (friend GossipBallotTestAccess): zero selects production.
    std::size_t   test_peer_log_cap_{0};
    std::size_t   test_pool_max_records_{0};
    std::uint64_t test_pool_max_bytes_{0};
    bool          test_fail_next_pool_write_{false};

    // Observation/mutation seams used by the transfer tests. The deadline
    // seam models the request timeout elapsing while a response is in
    // flight; the uncertain-write observation reports the quarantine flag.
    void test_set_outstanding_deadline(std::string_view peer_pubkey,
                                       std::uint64_t deadline_ms);
    // Models the request deadline elapsing: frees the peer's outstanding
    // slot so a new request may be issued.
    void test_drop_outstanding(std::string_view peer_pubkey) {
        std::lock_guard lock(transfer_mutex_);
        outstanding_.erase(std::string(peer_pubkey));
    }
    [[nodiscard]] bool test_pool_has_uncertain_write() const;

    // IPAM for tunnel IP allocation during ServerHello exchange
    ipam::IPAMService*               ipam_{nullptr};
    boringtun::BoringtunService*     boringtun_{nullptr};
    std::string                      our_tunnel_ip_;     // assigned by peer or self
    std::string                      our_backbone_ip_;   // 172.16.0.X backbone
    std::string                      our_mesh_pubkey_;   // base64 X25519
    std::string                      our_advertised_endpoint_;  // "ip:port" we are reachable at

    // Democratic NS slot claiming (ns1-ns9 bootstrap nameservers)
    std::string                      our_region_;
    std::string                      dns_base_domain_{"lemonade-nexus.io"};
    std::array<NsSlotClaimData, 9>   ns_slots_{};       // slot 0 = ns1, slot 8 = ns9
    std::optional<uint8_t>           our_ns_slot_;
    uint8_t                          preferred_ns_slot_{0};  // 0 = auto (lowest free)

    // Permission tree for evaluating received records' existing permissions
    // (nullptr = no permission context; acceptance refuses as ContextMissing).
    tree::PermissionTreeService*     tree_{nullptr};

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
    // Inbound security envelopes refused because the packet signer is not a
    // root-certified peer. Touched only from handle_receive on the io thread.
    uint64_t                              security_envelope_drops_{0};

public:
    /// Set the ACL service for distributed permission sync.
    void set_acl(acl::ACLService* acl);

    /// Broadcast an ACL delta to all known peers (called by ACLService callback).
    void broadcast_acl_delta(const acl::AclDelta& delta);

    /// Set the DNS service for distributed DNS record sync.
    void set_dns(network::DnsService* dns);

    /// Answers whether a server pubkey (base64) is a CURRENT Tier 1 member
    /// per finalized mesh state. Gates tier1-labelled DNS records: the label
    /// asserts finalized membership, not enrollment. Unset denies.
    void set_tier1_membership_source(std::function<bool(const std::string&)> source) {
        tier1_membership_ = std::move(source);
    }

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
