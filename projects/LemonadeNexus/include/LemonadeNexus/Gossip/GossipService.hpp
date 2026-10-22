#pragma once

#include <LemonadeNexus/ACL/ACLService.hpp>
#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Gossip/IGossipProvider.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Security/Transport/SecurityTransport.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Sync/EntryChunks.hpp>
#include <LemonadeNexus/Sync/OriginReplica.hpp>

#include <asio.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <memory>
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

namespace nexus::network { class DnsService; class VirtualNetService; }
namespace nexus::boringtun { class BoringtunService; }
namespace nexus::tree { class PermissionTreeService; }

namespace nexus::gossip {

/// nlohmann serialization for GossipPeer, shared by load_peers() and
/// save_peers(). The field set and names mirror the peers.json schema
/// exactly; from_json applies the same defaults the schema has always
/// allowed (missing field -> struct default).
void to_json(nlohmann::json& j, const GossipPeer& p);
void from_json(const nlohmann::json& j, GossipPeer& p);

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

    /// Set this server's backbone allocation (bare IPv4, no prefix) and the
    /// IPAM node id it is held under. The claim is announced directly to each
    /// certified peer, signed by and naming this gossip identity, after every
    /// accepted ServerHello and every 300 s. Peers add the backbone mesh peer
    /// once they hold both the claim and our mesh public key.
    void set_our_backbone_claim(const std::string& server_node_id,
                                const std::string& backbone_ip);

    /// Get our backbone IP.
    [[nodiscard]] std::string our_backbone_ip() const;

    /// Set our mesh public key (base64 X25519). Carried only in backbone claims
    /// this server sends directly, so a relaying peer cannot substitute it.
    void set_our_mesh_pubkey(const std::string& pubkey);

    /// Attach the in-process virtual netstack. Once our backbone IP is also
    /// set, gossip binds virtual UDP <backbone_ip>:<gossip port> and carries
    /// over the encrypted backbone: permission tree sync (Digest,
    /// DeltaRequest, DeltaResponse; retired in tree ops mode) with every
    /// certified peer, catch-up sync (SyncDigest, SyncRequest, catch-up
    /// DnsRecordSync, TreeLogSync) and AccountEnvelopeSync. Without a backbone
    /// path to a peer, no tree
    /// records move to or from it. Tier 1 servers serve catch-up to every
    /// certified server; Tier 2 servers catch up from Tier 1 and never feed
    /// records back. The netstack must outlive this service's start.
    void set_virtual_net(network::VirtualNetService* vnet);

    /// DNS catch-up state: whether this server is Tier 1, its per-origin
    /// summaries, and each certified peer's tier, backbone readiness and sync
    /// status (known for peers whose digests reach this server: Tier 1 peers
    /// on every server, and every peer on a Tier 1 server).
    [[nodiscard]] nlohmann::json dns_sync_status() const;

    /// Account envelope replication state, in the same shape as
    /// dns_sync_status().
    [[nodiscard]] nlohmann::json account_sync_status() const;

    /// Tree log replication state, in the same shape as dns_sync_status().
    [[nodiscard]] nlohmann::json tree_sync_status() const;

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

    /// Attempt to claim an NS slot (ns1-ns9) via gossip: the pinned slot when
    /// one is configured, otherwise the lowest free slot. The claim is
    /// deferred (and retried on the gossip tick) until slot state has been
    /// synced from the mesh, so a restarting node never claims from a stale
    /// or empty table. Pinned slot held by someone else, or no free slot:
    /// stays pending and retries each tick.
    void try_claim_ns_slot(const std::string& our_public_ip);

    /// Release an NS slot this node holds: broadcasts a signed release (the
    /// claim message with an empty server_ip) and removes the ns<N> A record
    /// from the DNS zone. No-op unless the slot is currently held by this
    /// node. Used by opt-out (dns_ns_hostname: "none").
    void release_ns_slot(uint8_t slot);

    /// Opt out of NS slot claiming (dns_ns_hostname: "none"). Cancels any
    /// pending claim, and a slot this node holds is released on the next
    /// gossip tick (or immediately if it is already held). Call before start().
    void set_ns_opt_out(bool opt_out);

    /// Returns our claimed NS slot number (1-9), or nullopt if we don't hold one.
    [[nodiscard]] std::optional<uint8_t> our_ns_slot() const;

    /// Returns all currently claimed NS slots (for status reporting).
    [[nodiscard]] std::vector<NsSlotClaimData> get_ns_slots() const;

    /// Try to add a gossip peer as a mesh backbone peer.
    void try_add_backbone_mesh_peer(const GossipPeer& peer);

    /// Access this server's Ed25519 identity keypair.
    [[nodiscard]] const crypto::Ed25519Keypair& keypair() const { return keypair_; }

    /// Use this identity instead of reading identity/keypair.json at start.
    /// The server sets it from the boot set (Core/BootSet.hpp), which owns the
    /// key's storage and its sealed copy. Call before start().
    void set_identity(const crypto::Ed25519Keypair& keypair) {
        keypair_ = keypair;
        identity_preset_ = true;
    }

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
    void arm_receive();
    void handle_receive(std::size_t bytes_received);

    // Gossip timer: fires every 5 seconds to pick a random peer and send digest
    void start_gossip_timer();
    void on_gossip_tick();

    // Peer persistence
    void load_peers();
    void save_peers();

    // NS slot state persistence (identity/ns_slots.json, same envelope
    // pattern as peers.json). Load never opens the sync gate.
    void load_ns_slots();
    void save_ns_slots();

    // Initial ServerHello announcement to all known peers (startup only;
    // runs before the async loops start).
    void send_startup_server_hello();

    // Packet construction and sending
    void send_packet(const asio::ip::udp::endpoint& target,
                      GossipMsgType msg_type,
                      const std::vector<uint8_t>& payload);

    /// Path a datagram arrived on. Backbone datagrams were decrypted by the
    /// mesh dataplane from a peer's mesh key. Tree sync, account envelopes and
    /// catch-up sync are accepted only on the backbone; other types only on
    /// the public socket, except DnsRecordSync, which uses both.
    enum class Via { Public, Backbone };

    // Message handlers by type. signer_pubkey is the packet-authenticated
    // sender (proven by verify_packet_signature); it is the transport
    // identity for gating and binding. Tree sync (digest, request,
    // response) requires Via::Backbone from the signer's backbone address.
    void handle_digest_message(const asio::ip::udp::endpoint& sender,
                                const uint8_t* payload, std::size_t payload_len,
                                const std::string& signer_pubkey, Via via);
    void handle_delta_request(const asio::ip::udp::endpoint& sender,
                               const uint8_t* payload, std::size_t payload_len,
                               const std::string& signer_pubkey, Via via);
    void handle_delta_response(const asio::ip::udp::endpoint& sender,
                                const std::string& sender_pubkey,
                                const uint8_t* payload, std::size_t payload_len, Via via);
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

    /// Request the next page from a peer over the backbone, subject to the
    /// outstanding rules (one per peer, global cap, generation-bound). No-op
    /// when not allowed or when the peer has no ready backbone path.
    void maybe_request_from(const std::string& peer_pubkey, uint64_t from_pos);

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

    /// Header, size and signature checks, then dispatch. Shared by the public
    /// socket and the backbone transport so both run identical verification.
    void process_datagram(const uint8_t* data, std::size_t len,
                          const asio::ip::udp::endpoint& from, Via via);

    // DNS record sync handler
    void handle_dns_record_sync(const asio::ip::udp::endpoint& sender,
                                 const std::string& sender_pubkey,
                                 const uint8_t* payload, std::size_t payload_len,
                                 Via via = Via::Public);

    // Catch-up sync (backbone only, Tier 1 to Tier 1)
    void handle_sync_digest(const asio::ip::udp::endpoint& sender,
                            const std::string& sender_pubkey,
                            const uint8_t* payload, std::size_t payload_len, Via via);
    void handle_sync_request(const asio::ip::udp::endpoint& sender,
                             const std::string& sender_pubkey,
                             const uint8_t* payload, std::size_t payload_len, Via via);
    /// Serve a tree stream catch-up request: committed log entries after
    /// `since`, in height order, read from the log and sent as chunks.
    void serve_tree_entries(const GossipPeer& peer, uint64_t since);
    /// One chunk of a committed tree log entry (TreeLogSync). Accepted only on
    /// the backbone from a certified Tier 1 peer; the assembled entry goes to
    /// the tree entry sink, which verifies it.
    void handle_tree_log_sync(const asio::ip::udp::endpoint& sender,
                              const std::string& sender_pubkey,
                              const uint8_t* payload, std::size_t payload_len, Via via);

    /// Sends the digest of every sync stream (DNS, account envelopes, and the
    /// tree log when enabled), paged to fit, over the backbone. Tier 1 sends to every certified peer with a
    /// backbone path; Tier 2 sends to Tier 1 peers only, as status. No-op
    /// until the backbone transport is bound.
    void send_sync_digests();

    /// Certified peers with a ready backbone path. With `tier1_only`, only
    /// current Tier 1 members.
    [[nodiscard]] std::vector<GossipPeer> backbone_targets(bool tier1_only) const;

    /// True when the peer is certified and has a backbone address, a known
    /// mesh key and, with a dataplane attached, a dataplane peer entry.
    /// The _locked form requires peers_mutex_.
    [[nodiscard]] bool backbone_path_ready(const GossipPeer& p) const;
    [[nodiscard]] bool backbone_path_ready_locked(const GossipPeer& p) const;

    /// Replica and entry message type of a named sync stream; nullptr for an
    /// unknown stream.
    [[nodiscard]] sync::OriginReplica* replica_for_stream(std::string_view stream) const;
    [[nodiscard]] GossipMsgType entry_type_for_stream(std::string_view stream) const;

    /// Sync status of one stream's replica, shared by the status endpoints.
    [[nodiscard]] nlohmann::json sync_status(const sync::OriginReplica* replica) const;

    // Account envelope replication (backbone only)
    void handle_account_envelope_sync(const asio::ip::udp::endpoint& sender,
                                      const std::string& sender_pubkey,
                                      const uint8_t* payload, std::size_t payload_len, Via via);
    /// Origin signature and origin certification of a record, or a reason it
    /// fails. Shared by network ingress and restore from disk.
    [[nodiscard]] std::optional<std::string> account_envelope_origin_error(
        const AccountEnvelopeRecord& record) const;
    /// Hand an origin-verified record to the account store and the replica.
    /// Returns true when the store accepted it (not stale, authorized).
    bool apply_account_envelope(const AccountEnvelopeRecord& record);
    void save_account_replica();
    void load_account_replica();

    /// Sign and persist a replica snapshot as <category>/replica.json.
    bool save_replica_file(const sync::OriginReplica& replica, const std::string& category,
                           const std::string& type);

    /// Common gate for catch-up messages: arrived on the backbone, from the
    /// sender's own backbone IP, sender certified. Tier rules are per message.
    [[nodiscard]] bool backbone_sender_verified(const asio::ip::udp::endpoint& sender,
                                                const std::string& sender_pubkey, Via via,
                                                std::string_view what);
    void deny_sync(const asio::ip::udp::endpoint& sender, const std::string& sender_pubkey,
                   std::string_view what, std::string_view reason);

    /// Why a DNS delta's author may not make this change (origin signature,
    /// tier1 label, SEIP ownership), or nullopt when it may. Shared by
    /// network ingress and restore from disk.
    [[nodiscard]] std::optional<std::string> dns_delta_authorship_error(
        const DnsRecordDelta& delta) const;

    /// Apply an authorized delta to the zone and the replica. Returns true
    /// when it changed the zone (not stale, not a duplicate).
    bool apply_dns_delta(const DnsRecordDelta& delta);

    /// Persist the replica (dns/replica.json) when it changed since the last
    /// save. Restore it once both the identity and the peer table (on_start)
    /// and the DNS service (set_dns) are present; entries are re-verified.
    void save_dns_replica();
    void load_dns_replica();

    [[nodiscard]] bool self_is_tier1() const;
    [[nodiscard]] bool is_tier1(const std::string& pubkey_b64) const;

    // Backbone transport and claims
    void start_backbone_transport();
    [[nodiscard]] std::vector<uint8_t> build_signed_packet(GossipMsgType msg_type,
                                                           const std::vector<uint8_t>& payload) const;
    /// Signed packet over virtual UDP from our backbone address and gossip
    /// port to `dst_ip:dst_port`. False when the backbone is not bound or the
    /// packet does not fit one datagram.
    bool send_backbone_to(const std::string& dst_ip, uint16_t dst_port, GossipMsgType msg_type,
                          const std::vector<uint8_t>& payload);
    bool send_backbone_packet(const GossipPeer& peer, GossipMsgType msg_type,
                              const std::vector<uint8_t>& payload);
    /// Our backbone claim with our mesh key, sent directly to `target`, or to
    /// every certified peer when `target` is empty.
    void announce_backbone_claim(const std::optional<asio::ip::udp::endpoint>& target);

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

    /// Register every held NS slot in the local DNS service. Runs after the
    /// load at start and again when the DNS service or base domain is set, so
    /// either startup order works. Slots loaded from disk at start
    /// are otherwise never registered: the holder's re-broadcast carries the
    /// same timestamp and is refused as a stale renewal.
    void register_known_ns_slots();

    /// Sign an NS slot claim in place. Unpinned claims sign the legacy
    /// 5-field preimage (wire-identical to v0.9.3); pinned claims sign the
    /// 6-field preimage that includes "pinned".
    void sign_ns_claim(NsSlotClaimData& claim);

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

    /// Whether this node's own loaded certificate is valid under the rules
    /// applied to peers: root key present, key not revoked, certificate bound
    /// to our gossip key and root-verified. The peers table never lists this
    /// node, so this answers for it. Takes peers_mutex_.
    [[nodiscard]] bool own_certificate_valid() const;

    /// The Ed25519 signature check of delta_origin_verified, without the
    /// enrollment lookup.
    [[nodiscard]] bool author_signature_valid(const std::string& canonical,
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
    bool                         identity_preset_{false};

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
    std::unordered_set<std::string>  revoked_pubkeys_;
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
    std::unordered_set<std::string>          pool_temp_hashes_;
    std::uint64_t                            pool_verified_bytes_{0};
    std::uint64_t                            pool_excluded_bytes_{0};
    std::uint64_t                            pool_temp_bytes_{0};
    std::size_t                              pool_entry_count_{0};
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
    // Test seam: number of async receive operations armed.
    std::uint64_t test_receive_arm_count_{0};
    // Test seam: largest serialized delta page emitted (bytes, envelope
    // included).
    std::uint64_t test_max_page_bytes_{0};
    // Test seam: NS slot claim messages broadcast (every claim/release send
    // goes through broadcast_ns_slot_claim).
    std::uint64_t test_ns_claim_broadcast_count_{0};
    // Test seam: NS slot claim messages received (every NsSlotClaim ingress
    // increments this, before any validation).
    std::uint64_t test_ns_claim_received_count_{0};

    // v0.9.6: denial-log rate limit for NS slot ingress. A looping or hostile
    // sender must not be able to fill the journal: each denial key is logged
    // at most once per 60 s. The map is bounded by pruning expired entries
    // when it grows.
    std::mutex denial_log_mutex_;
    std::map<std::string, std::chrono::steady_clock::time_point> denial_log_last_;
    bool denial_log_allowed(const std::string& key,
                            std::chrono::steady_clock::time_point now);

    // Send-failure observability (tracked #9, gossip half): failures are
    // counted per destination; the first per destination warns immediately,
    // repeats within 60 s are counted and summarized on the next warn.
    // Touched only on the failure path; bounded by pruning quiet entries.
    struct SendFailState {
        std::chrono::steady_clock::time_point last_log{};
        std::uint64_t suppressed{0};
    };
    std::mutex send_fail_mutex_;
    std::unordered_map<std::string, SendFailState> send_fail_;
    // Suppressed-since-last-warn count when a warn is due; nullopt when the
    // failure is only counted.
    [[nodiscard]] std::optional<std::uint64_t> send_fail_log_due(
        const std::string& dest, std::chrono::steady_clock::time_point now);
    void note_send_failure(const std::string& dest, const std::string& error);

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
    // Backbone identity, under mesh_state_mutex_.
    std::string                      our_backbone_ip_;   // 172.16.0.X backbone
    std::string                      our_backbone_node_id_;
    uint64_t                         our_backbone_claim_ts_{0};
    std::string                      our_mesh_pubkey_;   // base64 X25519
    std::string                      our_advertised_endpoint_;  // "ip:port" we are reachable at

    // Backbone transport. vnet_ is set once before the io loop runs; the
    // rest is touched only on the io thread except where noted.
    network::VirtualNetService*      vnet_{nullptr};
    std::atomic<bool>                backbone_bound_{false};
    // Cleared in on_stop so datagrams already posted from the netstack thread
    // are dropped instead of reaching a stopped service.
    std::shared_ptr<std::atomic<bool>> backbone_alive_ =
        std::make_shared<std::atomic<bool>>(true);
    // "<mesh_pubkey>|<backbone_ip>" pairs already handed to the dataplane
    // (under peers_mutex_).
    std::set<std::string>            backbone_peers_added_;
    std::chrono::steady_clock::time_point last_backbone_announce_{};

    // DNS catch-up replica (created in on_start, once the identity is known).
    std::unique_ptr<sync::OriginReplica> dns_replica_;
    uint64_t                              sync_digest_round_{0};
    uint64_t                              dns_replica_saved_version_{0};
    bool                                  dns_replica_loaded_{false};
    std::chrono::steady_clock::time_point last_dns_sync_digest_{};
    std::chrono::steady_clock::time_point last_dns_replica_save_{};

    // Account envelope replica and the store it feeds.
    std::unique_ptr<sync::OriginReplica>  account_replica_;

    // Tree log stream (enable_tree_stream). The replica indexes committed
    // heights only; entry bytes stay in the tree log and are read on demand.
    std::unique_ptr<sync::OriginReplica>  tree_replica_;
    std::function<std::optional<std::vector<uint8_t>>(uint64_t)> tree_entry_source_;
    std::function<void(std::vector<uint8_t>)> tree_entry_sink_;
    std::unique_ptr<sync::EntryAssembler> tree_assembler_;
    // Ops mode: the record transfer pool (Digest, DeltaRequest,
    // DeltaResponse) no longer carries tree changes; tree replication does.
    std::atomic<bool>                     tree_transfer_retired_{false};
    uint64_t                              account_replica_saved_version_{0};
    bool                                  account_replica_loaded_{false};
    std::function<bool(const AccountEnvelopeRecord&)> account_envelope_sink_;
    std::chrono::steady_clock::time_point last_tombstone_prune_{};
    // Last SyncRequest served per "<stream>|<peer>", for rate limiting (io
    // thread only).
    std::unordered_map<std::string, std::chrono::steady_clock::time_point> sync_request_served_;

    // Democratic NS slot claiming (ns1-ns9 bootstrap nameservers)
    std::string                      our_region_;
    std::string                      dns_base_domain_{"lemonade-nexus.io"};
    std::array<NsSlotClaimData, 9>   ns_slots_{};       // slot 0 = ns1, slot 8 = ns9
    std::optional<uint8_t>           our_ns_slot_;
    uint8_t                          preferred_ns_slot_{0};  // 0 = auto (lowest free)
    // True once slot state is known exchanged with the mesh (first accepted
    // peer ServerHello or first applied slot claim). Claims before that are
    // made from a stale/empty table and are deferred until this is set.
    bool                             ns_state_synced_{false};
    // A claim was requested but deferred (unsynced) or lost (displaced by a
    // pinned claim); the gossip tick re-attempts while this stays set.
    bool                             ns_claim_pending_{false};
    // The public IP used for (re-)claiming; remembered so the tick can
    // retry without a new call site.
    std::string                      ns_claim_ip_;
    // Opt-out (dns_ns_hostname: "none"): never claim; release a held slot.
    bool                             ns_opt_out_{false};
    // One-shot startup claim refresh (v0.9.5): once the sync gate has
    // opened, the first gossip tick re-broadcasts every stored claim so
    // restarting/empty nodes re-learn slot state the mesh already holds.
    // Set once per process life; never reset.
    bool                             ns_refresh_sent_{false};

    // PeerExchange initiator (v0.9.4 fix 4): at most one request per 60 s of
    // internal cadence (last_peer_exchange_tick_); peer_exchange_last_ holds
    // the last request time per peer pubkey for the 300 s per-peer cooldown.
    // Both are guarded by peers_mutex_.
    std::chrono::steady_clock::time_point last_peer_exchange_tick_{};
    std::unordered_map<std::string, std::chrono::steady_clock::time_point>
        peer_exchange_last_;

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

    /// Set the store that receives replicated account envelopes. The sink
    /// re-checks the uploading device's authority against the local tree and
    /// returns true only when it stored the envelope. It runs on the io
    /// thread. Restores the persisted replica once start() has also run.
    void set_account_envelope_sink(std::function<bool(const AccountEnvelopeRecord&)> sink);

    /// Enable the "tree" sync stream (design A7). `source` returns the encoded
    /// committed entry at a height, or nullopt when the log does not hold it;
    /// it must be thread-safe. `sink` receives each assembled entry from a
    /// Tier 1 peer on the io thread and must verify it before any use: the
    /// stream only carries bytes, consensus evidence decides. Call before the
    /// io context runs.
    void enable_tree_stream(std::function<std::optional<std::vector<uint8_t>>(uint64_t)> source,
                            std::function<void(std::vector<uint8_t>)> sink);

    /// Record that the local tree log holds `height`, so digests offer it.
    /// Heights are offered in order from 1. Thread-safe.
    void offer_tree_height(uint64_t height);

    /// Stop the record transfer pool for tree changes (ops mode): no transfer
    /// digest is sent, and Digest, DeltaRequest, and DeltaResponse are
    /// dropped. Call before the io context runs.
    void retire_tree_transfer() { tree_transfer_retired_.store(true); }

    /// Replicate an envelope this server just stored for an authenticated
    /// device. Fills in the origin fields, signs the record, and sends it over
    /// the backbone to every certified peer. Only a Tier 1 server replicates;
    /// a Tier 2 server keeps the envelope local. Thread-safe: the send runs on
    /// the io thread.
    void broadcast_account_envelope(AccountEnvelopeRecord record);

    /// Pin the NS slot this server claims (1-9); 0 = auto (lowest free). Set
    /// when the operator's ns<N> identity matches registrar glue for that name.
    void set_preferred_ns_slot(uint8_t slot);

    /// Add a server pubkey to the revocation set and persist it. Idempotent.
    /// The single runtime writer of revoked_servers.json — callers such as the
    /// admission supersede path must route through here, never write the file.
    void add_revoked_server(const std::string& server_pubkey);
};

} // namespace nexus::gossip
