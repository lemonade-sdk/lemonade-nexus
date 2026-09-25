#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Network/DnsService.hpp>
#include <LemonadeNexus/Boringtun/BoringtunService.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>
#include <optional>
#include <unordered_set>

namespace nexus::gossip {

using json = nlohmann::json;
using asio::ip::udp;
namespace chrono = std::chrono;

namespace {

std::uint64_t steady_ms() {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

// Strip an optional "ed25519:" prefix to the bare base64 certificate form
// used by the revocation list.
std::string normalize_pubkey(std::string_view pk) {
    return pk.starts_with("ed25519:") ? std::string(pk.substr(8)) : std::string(pk);
}

// The retained record's canonical statement (the signed content). The
// supplied record_hash is never trusted; identity is recomputed from the
// parsed fields at every boundary.
nlohmann::json retained_record_node_data(const storage::FileStorageService::RetainedDelta& rec) {
    return nlohmann::json::parse(rec.data, nullptr, false);
}

/// The record as a typed delta. The json-to-TreeNode conversion THROWS on
/// shape mismatch (missing fields, wrong types, unknown node type); the
/// conversion is contained here so no caller in the receive path can be
/// taken down by hostile node_data. nullopt means the content is not a
/// well-formed node shape and must be treated as malformed.
std::optional<tree::TreeDelta> retained_record_to_delta(
    const storage::FileStorageService::RetainedDelta& rec) {
    if (rec.operation.empty() || rec.target_node_id.empty() ||
        rec.signer_pubkey.empty() || rec.signature.empty()) {
        return std::nullopt;
    }
    const auto nd = retained_record_node_data(rec);
    if (nd.is_discarded() || !nd.is_object()) return std::nullopt;
    tree::TreeDelta td;
    try {
        td.operation      = rec.operation;
        td.target_node_id = rec.target_node_id;
        td.node_data      = nd;
        td.signer_pubkey  = rec.signer_pubkey;
        td.signature      = rec.signature;
        td.timestamp      = rec.timestamp;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    return td;
}

bool retained_record_is_malformed(const storage::FileStorageService::RetainedDelta& rec) {
    return !retained_record_to_delta(rec).has_value();
}

std::optional<std::string> retained_record_hash(
    const storage::FileStorageService::RetainedDelta& rec,
    crypto::SodiumCryptoService& crypto) {
    auto td = retained_record_to_delta(rec);
    if (!td) return std::nullopt;
    const auto canonical = tree::canonical_delta_json(*td);
    const auto msg = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
    return crypto::to_hex(crypto.sha256(msg));
}

bool retained_record_signature_ok(const storage::FileStorageService::RetainedDelta& rec,
                                   crypto::SodiumCryptoService& crypto) {
    if (!rec.signer_pubkey.starts_with("ed25519:")) return false;
    auto td = retained_record_to_delta(rec);
    if (!td) return false;
    const auto canonical = tree::canonical_delta_json(*td);
    const auto msg = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
    const auto pk  = crypto::from_base64(rec.signer_pubkey.substr(8));
    const auto sig = crypto::from_base64(rec.signature);
    if (pk.size() != crypto::kEd25519PublicKeySize ||
        sig.size() != crypto::kEd25519SignatureSize) {
        return false;
    }
    crypto::Ed25519PublicKey pub{};
    crypto::Ed25519Signature s{};
    std::memcpy(pub.data(), pk.data(), pk.size());
    std::memcpy(s.data(), sig.data(), sig.size());
    return crypto.ed25519_verify(pub, msg, s);
}

// Strict unsigned-integer field read: nlohmann's value() THROWS type_error
// when the key exists with a different type; reject instead.
bool u64_field(const nlohmann::json& j, const char* key, std::uint64_t& out) {
    if (!j.contains(key) || !j[key].is_number_unsigned()) return false;
    out = j[key].get<std::uint64_t>();
    return true;
}

// Record identifiers are 64 lowercase hex characters. Only such identifiers
// can occupy a pool position; other names are storage but not a position
// threat.
bool is_record_identifier(std::string_view name) {
    if (name.size() != 64) return false;
    for (char c : name) {
        const bool hexdigit = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hexdigit) return false;
    }
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

GossipService::GossipService(asio::io_context& io, uint16_t port,
                               storage::FileStorageService& storage,
                               crypto::SodiumCryptoService& crypto)
    : socket_{io, udp::endpoint{udp::v4(), port}}
    , gossip_timer_{io}
    , storage_{storage}
    , crypto_{crypto}
    , port_{port}
{
    // A security envelope can approach the datagram limit. The default
    // socket buffers on some platforms (macOS: 9 KiB send) reject such a
    // datagram at the kernel, so both buffers are raised to the packet size.
    asio::error_code ec;
    socket_.set_option(asio::socket_base::send_buffer_size(2 * 65536), ec);
    socket_.set_option(asio::socket_base::receive_buffer_size(4 * 65536), ec);
}

void GossipService::set_root_pubkey(const crypto::Ed25519PublicKey& pk) {
    root_pubkey_ = pk;
    has_root_pubkey_ = true;
}

void GossipService::set_network_id(const std::string& network_hex) {
    expected_network_id_ = network_hex;
}

// ---------------------------------------------------------------------------
// IService lifecycle
// ---------------------------------------------------------------------------

void GossipService::on_start() {
    // Generate or load our identity keypair
    // Check if identity/keypair.json exists in storage
    auto envelope = storage_.read_file("identity", "keypair.json");
    if (envelope) {
        try {
            auto j = json::parse(envelope->data);
            auto pub_bytes = crypto::from_base64(j.value("public_key", ""));
            auto priv_bytes = crypto::from_base64(j.value("private_key", ""));

            if (pub_bytes.size() == crypto::kEd25519PublicKeySize &&
                priv_bytes.size() == crypto::kEd25519PrivateKeySize) {
                std::memcpy(keypair_.public_key.data(), pub_bytes.data(),
                            crypto::kEd25519PublicKeySize);
                std::memcpy(keypair_.private_key.data(), priv_bytes.data(),
                            crypto::kEd25519PrivateKeySize);
                spdlog::info("[{}] loaded identity keypair", name());
            } else {
                spdlog::warn("[{}] stored keypair has wrong size, regenerating", name());
                keypair_ = crypto_.ed25519_keygen();
            }
        } catch (const std::exception& e) {
            spdlog::warn("[{}] failed to parse keypair: {}, regenerating", name(), e.what());
            keypair_ = crypto_.ed25519_keygen();
        }
    } else {
        keypair_ = crypto_.ed25519_keygen();
        spdlog::info("[{}] generated new Ed25519 identity", name());

        // Persist the keypair
        storage::SignedEnvelope kp_env;
        kp_env.type = "identity_keypair";
        json kp_json;
        kp_json["public_key"] = crypto::to_base64(keypair_.public_key);
        kp_json["private_key"] = crypto::to_base64(keypair_.private_key);
        kp_env.data = kp_json.dump();
        kp_env.signer_pubkey = "ed25519:" + crypto::to_base64(keypair_.public_key);
        kp_env.timestamp = static_cast<uint64_t>(
            chrono::system_clock::to_time_t(chrono::system_clock::now()));
        (void)storage_.write_file("identity", "keypair.json", kp_env);
    }

    // Load server certificate and root pubkey
    load_server_certificate();

    // Load known peers
    load_peers();

    // Reconstruct the transfer pool index before any transfer state can move
    // (bounded; pool files are preserved on any failure).
    reconstruct_transfer_pool();

    // Send ServerHello to all known peers on startup (before starting async loops).
    // If we need a tunnel IP, include the request flag so a peer allocates one for us.
    {
        std::vector<std::string> endpoints;
        bool have_cert = false;
        {
            std::lock_guard lock(peers_mutex_);
            spdlog::info("[{}] listening on UDP port {} (pubkey: {}, peers: {})",
                          name(), port_,
                          crypto::to_base64(keypair_.public_key),
                          peers_.size());
            if (our_certificate_ && !peers_.empty()) {
                have_cert = true;
                for (const auto& p : peers_) endpoints.push_back(p.endpoint);
            }
        }
        if (have_cert) {
            json hello = *our_certificate_;
            bool need_tunnel_ip = false;
            {
                std::lock_guard lock(mesh_state_mutex_);
                need_tunnel_ip = ipam_ && our_tunnel_ip_.empty();
                // Check if IPAM already has our allocation
                if (need_tunnel_ip) {
                    auto existing = ipam_->get_allocation(our_certificate_->server_id);
                    if (existing && existing->tunnel) {
                        auto ip = existing->tunnel->base_network;
                        if (auto slash = ip.find('/'); slash != std::string::npos)
                            ip = ip.substr(0, slash);
                        our_tunnel_ip_ = ip;
                        need_tunnel_ip = false;
                    }
                }
                if (need_tunnel_ip) {
                    hello["request_tunnel_ip"] = true;
                }
                if (!our_region_.empty()) {
                    hello["region"] = our_region_;
                }
                if (!our_advertised_endpoint_.empty()) {
                    hello["advertised_endpoint"] = our_advertised_endpoint_;
                }
            }
            auto payload_str = hello.dump();
            std::vector<uint8_t> payload_bytes(payload_str.begin(), payload_str.end());

            for (const auto& ep : endpoints) {
                auto target = parse_endpoint(ep);
                if (target) {
                    send_packet(*target, GossipMsgType::ServerHello, payload_bytes);
                }
            }
            spdlog::info("[{}] sent ServerHello to {} peers (request_tunnel_ip: {})",
                          name(), endpoints.size(), need_tunnel_ip);
        }
    }

    // Start async receive loop and gossip timer after initial ServerHello
    start_receive();
    start_gossip_timer();
}

void GossipService::on_stop() {
    spdlog::info("[{}] stopping...", name());

    gossip_timer_.cancel();

    asio::error_code ec;
    socket_.close(ec);
    if (ec) {
        spdlog::warn("[{}] socket close error: {}", name(), ec.message());
    }

    save_peers();
    spdlog::info("[{}] stopped", name());
}

// ---------------------------------------------------------------------------
// IGossipProvider implementation
// ---------------------------------------------------------------------------

void GossipService::do_add_peer(std::string_view endpoint, std::string_view pubkey) {
    // Never add ourselves as a peer (e.g. peer-exchange echoing our own identity).
    if (!pubkey.empty() && pubkey == crypto::to_base64(keypair_.public_key)) {
        spdlog::debug("[{}] refusing to add self as peer ({})", name(), endpoint);
        return;
    }

    std::lock_guard lock(peers_mutex_);

    // Check if peer already exists
    auto it = std::find_if(peers_.begin(), peers_.end(),
        [&](const GossipPeer& p) { return p.pubkey == pubkey; });

    if (it != peers_.end()) {
        it->endpoint = std::string(endpoint);
        it->last_seen = static_cast<uint64_t>(
            chrono::system_clock::to_time_t(chrono::system_clock::now()));
        spdlog::debug("[{}] updated peer {} at {}", name(), pubkey, endpoint);
    } else {
        // Peer exchange accepts entries from unauthenticated senders, so the
        // table has to be bounded or a stranger can grow it without limit.
        // Certified peers are the mesh and are never refused; uncertified ones
        // share a cap. Refusing an unknown entry costs nothing: a real peer
        // re-announces, and a certified one takes the branch above.
        if (peers_.size() >= kMaxTrackedPeers &&
            !peer_certificate_is_root_signed_locked(std::string(pubkey))) {
            spdlog::debug("[{}] refusing peer {} — the peer table is at its cap of {}",
                           name(), pubkey, kMaxTrackedPeers);
            return;
        }
        GossipPeer peer;
        peer.pubkey = std::string(pubkey);
        peer.endpoint = std::string(endpoint);
        peer.last_seen = static_cast<uint64_t>(
            chrono::system_clock::to_time_t(chrono::system_clock::now()));
        peer.reputation = 1.0f;
        peers_.push_back(std::move(peer));
        spdlog::info("[{}] added peer {} at {}", name(), pubkey, endpoint);
    }
}

void GossipService::do_remove_peer(std::string_view pubkey) {
    std::lock_guard lock(peers_mutex_);
    auto it = std::remove_if(peers_.begin(), peers_.end(),
        [&](const GossipPeer& p) { return p.pubkey == pubkey; });

    if (it != peers_.end()) {
        peers_.erase(it, peers_.end());
        spdlog::info("[{}] removed peer {}", name(), pubkey);
    }
}

void GossipService::do_send_digest(const GossipPeer& peer) {
    auto target = parse_endpoint(peer.endpoint);
    if (!target) {
        spdlog::warn("[{}] invalid peer endpoint: {}", name(), peer.endpoint);
        return;
    }

    std::string generation;
    std::uint64_t latest_pos = 0;
    {
        std::lock_guard lock(transfer_mutex_);
        generation = pool_generation_;
        latest_pos = pool_latest_position_locked();
    }

    // Build digest JSON payload. The digest carries this node's transfer-pool
    // position and log generation — node-local values that never bind any
    // record.
    json digest;
    digest["latest_pos"] = latest_pos;
    digest["log_generation"] = generation;
    digest["peer_count"] = static_cast<std::uint32_t>(peer_count());
    digest["timestamp"] = static_cast<std::uint64_t>(
        chrono::system_clock::to_time_t(chrono::system_clock::now()));

    auto payload_str = digest.dump();
    std::vector<uint8_t> payload(payload_str.begin(), payload_str.end());

    send_packet(*target, GossipMsgType::Digest, payload);
    spdlog::debug("[{}] sent digest to {} (pos={}, generation={})",
                   name(), peer.endpoint, latest_pos, generation.substr(0, 8));
}

void GossipService::do_handle_digest(const GossipPeer& peer, uint64_t their_pos,
                                       const std::string& their_generation) {
    // Identity is the authenticated packet signer (passed through as
    // peer.pubkey by the handler), not the NAT-able endpoint.
    if (peer.pubkey.empty()) return;

    uint64_t from_pos = 0;
    {
        std::lock_guard lock(transfer_mutex_);
        const auto now = steady_ms();

        // Cap the per-peer log before allocating state for a new identity.
        if (!peer_logs_.count(peer.pubkey) && peer_logs_.size() >= peer_log_cap()) {
            evict_idle_peer_logs_locked(now);
            if (peer_logs_.size() >= peer_log_cap()) {
                spdlog::debug("[{}] no transfer state for digest from {} — peer log "
                              "cap reached", name(), peer.pubkey);
                return;
            }
        }

        auto& st = peer_logs_[peer.pubkey];
        st.last_digest_ms = now;

        if (!their_generation.empty() && st.generation != their_generation) {
            // New log generation: positions from the old log mean nothing.
            // Invalidate the outstanding request and reset the cursor. The
            // stall budget and backoff persist — a new log is not a retry
            // reset.
            st.generation = their_generation;
            st.cursor = 0;
            outstanding_.erase(peer.pubkey);
        }

        if (their_generation.empty()) return;  // reports no generation: nothing to request
        if (st.backoff_until_ms > now) return; // exhausted budget: repeated digests do not reset it
        if (their_pos <= st.cursor) return;    // caught up

        from_pos = st.cursor;
    }

    spdlog::debug("[{}] digest from {} (their_pos={}, generation={})",
                   name(), peer.endpoint, their_pos, their_generation.substr(0, 8));
    maybe_request_from(peer.pubkey, peer.endpoint, from_pos);
}

// ---------------------------------------------------------------------------
// Delta record transfer: pool index, retention, admission, requests
// ---------------------------------------------------------------------------

std::uint64_t GossipService::pool_latest_position_locked() const {
    return pool_position_index_.empty()
               ? 0
               : pool_position_index_.rbegin()->first;
}

std::string GossipService::make_pool_generation_locked() {
    std::array<uint8_t, 16> buf{};
    crypto_.random_bytes(std::span<uint8_t>(buf));
    return crypto::to_hex(std::span<const uint8_t>(buf));
}

void GossipService::reconstruct_transfer_pool() {
    std::lock_guard lock(transfer_mutex_);

    // Rebuild from scratch: the index is always re-derived from the pool
    // files, never merged with a previous reconstruction. This is the only
    // path that may clear an uncertain-write quarantine — verified content
    // is re-indexed at its own position; anything else makes the pool
    // unavailable.
    pool_has_uncertain_write_ = false;
    pool_position_index_.clear();
    pool_hash_to_position_.clear();
    pool_verified_.clear();
    pool_excluded_.clear();
    pool_verified_bytes_ = 0;
    pool_excluded_bytes_ = 0;
    pool_next_position_ = 1;
    pool_available_ = false;
    pool_reconstructed_ = false;

    const auto unavailable = [this](std::string_view why) {
        pool_available_ = false;
        pool_reconstructed_ = true;
        // An unavailable pool exposes no transfer view: the index is cleared
        // (the files are preserved on disk and re-derived by a later
        // reconstruction). Nothing is served, reported, or retained.
        pool_position_index_.clear();
        pool_hash_to_position_.clear();
        pool_verified_.clear();
        pool_verified_bytes_ = 0;
        pool_excluded_.clear();
        pool_excluded_bytes_ = 0;
        pool_next_position_ = 1;
        spdlog::critical("[{}] transfer pool unavailable: {} — pool files are "
                         "preserved; transfer and new retention are refused",
                         name(), why);
    };

    const auto max_records = effective_pool_max_records();
    const auto max_bytes = effective_pool_max_bytes();

    // Enforce the bounds before reading any record content.
    const auto entries = storage_.list_pool_entries();
    std::uint64_t total_bytes = 0;
    for (const auto& e : entries) {
        if (e.size_bytes > max_bytes) { total_bytes = max_bytes + 1; break; }
        total_bytes += e.size_bytes;
    }
    if (entries.size() > max_records) {
        unavailable("pool entry count " + std::to_string(entries.size()) +
                    " exceeds the bound " + std::to_string(max_records));
        return;
    }
    if (total_bytes > max_bytes) {
        unavailable("pool byte total " + std::to_string(total_bytes) +
                    " exceeds the bound " + std::to_string(max_bytes));
        return;
    }

    // Generation metadata must be consistent with the records. Unreadable
    // metadata is not absent: it must not be replaced over unreadable state.
    const bool has_record_file =
        std::any_of(entries.begin(), entries.end(),
                    [](const auto& e) { return !e.temporary; });
    storage::FileStorageService::PoolMetaRead meta_state{};
    if (auto meta = storage_.read_pool_generation(meta_state)) {
        pool_generation_ = *meta;
    } else {
        if (meta_state == storage::FileStorageService::PoolMetaRead::IoError) {
            unavailable("generation metadata exists but cannot be read");
            return;
        }
        if (has_record_file) {
            unavailable("records exist without generation metadata");
            return;
        }
        pool_generation_ = make_pool_generation_locked();
        if (!storage_.write_pool_generation(pool_generation_)) {
            unavailable("cannot persist pool generation");
            return;
        }
    }

    // An excluded RECORD identifier means the position it occupied cannot be
    // reconstructed: the log can no longer be proven complete, and a new
    // record might be assigned that position. Unavailable, not shortened.
    bool position_unreconstructable = false;
    const auto exclude = [this, &position_unreconstructable](
        const storage::FileStorageService::PoolEntry& e) {
        pool_excluded_.insert(e.hash);
        pool_excluded_bytes_ += e.size_bytes;
        if (is_record_identifier(e.hash)) position_unreconstructable = true;
    };

    for (const auto& e : entries) {
        if (e.temporary) {
            // In-flight or orphaned temp files count as storage; they are
            // never indexed.
            pool_excluded_bytes_ += e.size_bytes;
            spdlog::warn("[{}] ignoring stale pool temp file {} ({} bytes)",
                         name(), e.hash, e.size_bytes);
            continue;
        }

        storage::FileStorageService::PoolRead result;
        auto text = storage_.read_pool_record(e.hash, kMaxRetainedRecordBytes, result);
        if (result == storage::FileStorageService::PoolRead::Oversized) {
            exclude(e);
            spdlog::critical("[{}] pool record {} exceeds the per-record bound "
                             "({} bytes); excluded from the index, file preserved",
                             name(), e.hash, e.size_bytes);
            continue;
        }
        if (!text.has_value()) {
            if (result == storage::FileStorageService::PoolRead::IoError) {
                unavailable("pool record " + e.hash + " exists but cannot be read");
                return;
            }
            continue;  // absent: skipped, the identifier stays free
        }

        auto rec = storage::FileStorageService::RetainedDelta::from_json(*text);
        if (!rec.has_value()) {
            exclude(e);
            spdlog::critical("[{}] pool record {} is not valid retained content; "
                             "excluded from the index, file preserved", name(), e.hash);
            continue;
        }

        // Re-verify the author signature and recompute the identifier from
        // the canonical content. The stored hash field is never trusted.
        const auto computed = retained_record_hash(*rec, crypto_);
        const bool sig_ok = retained_record_signature_ok(*rec, crypto_);
        if (!computed || *computed != e.hash || !sig_ok) {
            exclude(e);
            spdlog::critical("[{}] pool record {} {} — excluded from the index, "
                             "file preserved", name(), e.hash,
                             !computed ? "content is not a well-formed statement"
                             : *computed != e.hash
                                 ? "content does not match its identifier"
                                 : "author signature does not verify");
            continue;
        }

        if (rec->position == 0 || rec->position > max_records ||
            pool_position_index_.count(rec->position)) {
            unavailable("inconsistent pool position metadata at record " + e.hash);
            return;
        }

        pool_position_index_[rec->position] = e.hash;
        pool_hash_to_position_[e.hash] = rec->position;
        pool_verified_.insert(e.hash);
        pool_verified_bytes_ += e.size_bytes;
        pool_next_position_ = std::max(pool_next_position_, rec->position + 1);
    }

    if (position_unreconstructable) {
        unavailable("an excluded record identifier cannot have its position "
                    "reconstructed; positions beyond the verified prefix cannot "
                    "be proven free");
        return;
    }

    pool_available_ = true;
    pool_reconstructed_ = true;
    spdlog::info("[{}] transfer pool reconstructed: {} verified record(s) "
                 "({} bytes), {} excluded identifier(s), latest position {}",
                 name(), pool_position_index_.size(), pool_verified_bytes_,
                 pool_excluded_.size(), pool_latest_position_locked());
}

GossipService::PoolRetain GossipService::retain_verified_record(
        const storage::FileStorageService::RetainedDelta& rec, uint64_t& out_position) {
    std::lock_guard lock(transfer_mutex_);
    if (!pool_reconstructed_) return PoolRetain::RefusedUnavailable;
    if (retained_record_is_malformed(rec)) return PoolRetain::RefusedMalformed;

    // An uncertain write quarantines the pool: the bytes may be on disk,
    // so the position must not be handed out again and the storage must not
    // be ignored. Only the startup reconstruction reconciles the state.
    if (pool_has_uncertain_write_) return PoolRetain::RefusedUnavailable;

    const auto max_records = effective_pool_max_records();
    const auto max_bytes = effective_pool_max_bytes();

    // Identity is recomputed from the content; the supplied hash is never
    // trusted.
    const auto hash = retained_record_hash(rec, crypto_);
    if (!hash) return PoolRetain::RefusedMalformed;

    if (auto it = pool_hash_to_position_.find(*hash);
        it != pool_hash_to_position_.end()) {
        out_position = it->second;
        return PoolRetain::Duplicate;
    }
    if (!pool_available_) return PoolRetain::RefusedUnavailable;
    if (pool_position_index_.size() + 1 > max_records) return PoolRetain::RefusedCapacity;

    // A stored file we could not verify still occupies its identifier:
    // overwriting it would destroy evidence and could resurrect a colliding
    // record. Refuse while it exists.
    if (storage_.pool_record_exists(*hash)) return PoolRetain::RefusedCollision;

    const auto position = pool_next_position_;
    storage::FileStorageService::RetainedDelta stored = rec;
    stored.position = position;
    stored.record_hash = *hash;
    const auto text = stored.to_json();
    if (text.size() > kMaxRetainedRecordBytes) return PoolRetain::RefusedOversize;
    // Capacity accounting includes the excluded evidence bytes: corruption
    // does not create free capacity.
    if (pool_verified_bytes_ + pool_excluded_bytes_ + text.size() > max_bytes) {
        return PoolRetain::RefusedCapacity;
    }
    if (test_fail_next_pool_write_) {
        test_fail_next_pool_write_ = false;
        return PoolRetain::FailedWrite;
    }
    const auto write_result = storage_.write_pool_record(*hash, text);
    if (write_result == storage::FileStorageService::PoolWrite::Uncertain) {
        // The rename may have left the record on disk. The position is
        // burned — never handed out again — and the pool is quarantined:
        // no further retention until the startup reconstruction verifies
        // the content (and re-indexes it) or finds it unreadable (and marks
        // the pool unavailable). Neither the position nor the bytes are
        // ignored.
        pool_next_position_ = position + 1;
        pool_has_uncertain_write_ = true;
        pool_available_ = false;
        spdlog::critical("[{}] pool write at position {} is uncertain (rename "
                         "done, directory sync failed); position burned and pool "
                         "quarantined until a restart reconciles the state",
                         name(), position);
        return PoolRetain::FailedWrite;
    }
    if (write_result != storage::FileStorageService::PoolWrite::Ok) {
        return PoolRetain::FailedWrite;
    }

    // Acceptance is published only after the durable write succeeded.
    pool_position_index_[position] = *hash;
    pool_hash_to_position_[*hash] = position;
    pool_verified_.insert(*hash);
    pool_verified_bytes_ += text.size();
    pool_next_position_ = position + 1;
    out_position = position;
    return PoolRetain::Retained;
}

bool GossipService::retain_local_delta(
        const storage::FileStorageService::RetainedDelta& rec) {
    uint64_t position = 0;
    const auto result = retain_verified_record(rec, position);
    if (result == PoolRetain::Retained) {
        spdlog::debug("[{}] retained local delta for {} on '{}' (position {})",
                      name(), rec.operation, rec.target_node_id, position);
        return true;
    }
    if (result == PoolRetain::Duplicate) return true;
    spdlog::warn("[{}] local delta retention refused for {} on '{}' (pool full, "
                 "unavailable, or write failed); the applied mutation is unaffected",
                 name(), rec.operation, rec.target_node_id);
    return false;
}

void GossipService::test_set_outstanding_deadline(std::string_view peer_pubkey,
                                                  std::uint64_t deadline_ms) {
    std::lock_guard lock(transfer_mutex_);
    auto it = outstanding_.find(std::string(peer_pubkey));
    if (it != outstanding_.end()) it->second.deadline_ms = deadline_ms;
}

bool GossipService::test_pool_has_uncertain_write() const {
    std::lock_guard lock(transfer_mutex_);
    return pool_has_uncertain_write_;
}

GossipService::Admission GossipService::admit_received_record(const nlohmann::json& r) {
    try {
    // 1. Statement fields. Transport positions are not part of the statement
    //    and never bind it.
    if (!r.is_object() ||
        !r.contains("operation") || !r["operation"].is_string() ||
        !r.contains("target_node_id") || !r["target_node_id"].is_string() ||
        !r.contains("node_data") || !r["node_data"].is_object() ||
        !r.contains("signer_pubkey") || !r["signer_pubkey"].is_string() ||
        !r.contains("signature") || !r["signature"].is_string() ||
        !r.contains("timestamp") || !r["timestamp"].is_number_unsigned()) {
        spdlog::warn("[{}] received record with malformed statement fields — "
                     "refused (final)", name());
        return Admission::RefusedFinal;
    }

    storage::FileStorageService::RetainedDelta rec;
    rec.operation      = r["operation"].get<std::string>();
    rec.target_node_id = r["target_node_id"].get<std::string>();
    rec.data           = r["node_data"].dump();
    rec.signer_pubkey  = r["signer_pubkey"].get<std::string>();
    rec.signature      = r["signature"].get<std::string>();
    rec.timestamp      = r["timestamp"].get<std::uint64_t>();

    // 2. The original author's signature over the canonical statement.
    if (!retained_record_signature_ok(rec, crypto_)) {
        spdlog::warn("[{}] received record for {} on '{}' has an invalid author "
                     "signature — refused (final)",
                     name(), rec.operation, rec.target_node_id);
        return Admission::RefusedFinal;
    }

    // 3. Existing operation-derived permissions. Only a statement no
    //    operation could ever name is final: an UNKNOWN operation is
    //    permanently invalid. A known operation that lacks the required
    //    permission in the CURRENT tree is not necessarily permanently
    //    invalid — like a missing context it is retryable, and the same
    //    signed statement is admitted once the context allows it.
    if (tree_) {
        if (tree_->required_permission_for(rec.operation) == acl::Permission::None) {
            spdlog::warn("[{}] received record for unknown operation '{}' — "
                         "refused (final)", name(), rec.operation);
            return Admission::RefusedFinal;
        }
        const auto authz = tree_->authorize_delta_statement(
            rec.operation, rec.target_node_id,
            retained_record_node_data(rec), rec.signer_pubkey);
        if (authz == tree::PermissionTreeService::DeltaAuthorization::ContextMissing) {
            spdlog::debug("[{}] received record for {} on '{}': permission context "
                          "missing — refused (retryable)",
                          name(), rec.operation, rec.target_node_id);
            return Admission::RefusedRetryable;
        }
        if (authz == tree::PermissionTreeService::DeltaAuthorization::Denied) {
            spdlog::debug("[{}] received record for {} on '{}' lacks the required "
                          "permission in the current tree — refused (retryable)",
                          name(), rec.operation, rec.target_node_id);
            return Admission::RefusedRetryable;
        }
    } else {
        // No tree wired: no permission context exists to evaluate.
        spdlog::debug("[{}] received record for {} on '{}': no permission context "
                      "— refused (retryable)", name(), rec.operation, rec.target_node_id);
        return Admission::RefusedRetryable;
    }

    // 4. Retain. Every retention refusal is retryable: capacity, collision,
    //    oversize, unavailability, and write failure are transfer
    //    conditions, not statement defects.
    uint64_t position = 0;
    const auto rr = retain_verified_record(rec, position);
    switch (rr) {
        case PoolRetain::Retained:
            spdlog::debug("[{}] retained received record for {} on '{}' (position {})",
                          name(), rec.operation, rec.target_node_id, position);
            return Admission::Accepted;
        case PoolRetain::Duplicate:
            return Admission::Duplicate;
        default:
            return Admission::RefusedRetryable;
    }
    } catch (const std::exception& e) {
        // Hostile content must not escape the admission boundary: any
        // conversion or allocation failure is a transfer stall, not a crash
        // and not a final verdict on the statement.
        spdlog::error("[{}] received record failed to process: {} — refused "
                      "(retryable)", name(), e.what());
        return Admission::RefusedRetryable;
    }
}

void GossipService::maybe_request_from(const std::string& peer_pubkey,
                                        std::string_view endpoint, uint64_t from_pos) {
    if (peer_pubkey.empty()) return;
    auto target = parse_endpoint(endpoint);
    if (!target) return;

    bool will_send = false;
    std::uint64_t nonce = 0;
    {
        std::lock_guard lock(transfer_mutex_);
        const auto now = steady_ms();

        // Expired requests free their slot.
        for (auto it = outstanding_.begin(); it != outstanding_.end();) {
            if (it->second.deadline_ms < now) it = outstanding_.erase(it);
            else ++it;
        }

        if (outstanding_.count(peer_pubkey)) return;
        if (outstanding_.size() >= kOutstandingGlobal) {
            spdlog::debug("[{}] delta request to {} refused — outstanding cap ({}) "
                          "reached", name(), peer_pubkey, kOutstandingGlobal);
            return;
        }
        auto st = peer_logs_.find(peer_pubkey);
        if (st == peer_logs_.end()) return;  // a request binds to a known generation

        std::array<uint8_t, 8> nb{};
        crypto_.random_bytes(std::span<uint8_t>(nb));
        std::memcpy(&nonce, nb.data(), 8);
        if (nonce == 0) nonce = 1;
        outstanding_[peer_pubkey] = OutstandingRequest{
            nonce, from_pos, st->second.generation, now + kRequestTimeoutMs};
        will_send = true;
    }
    if (!will_send) return;

    json request;
    request["nonce"] = nonce;
    request["from_pos"] = from_pos;
    auto s = request.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());
    send_packet(*target, GossipMsgType::DeltaRequest, payload);
    spdlog::debug("[{}] delta request to {} (nonce={}, from_pos={})",
                   name(), peer_pubkey, nonce, from_pos);
}

void GossipService::evict_idle_peer_logs_locked(std::uint64_t now) {
    // Only entries with no outstanding request and no active backoff may be
    // evicted: eviction must not provide a retry bypass.
    while (peer_logs_.size() >= peer_log_cap()) {
        std::string stalest;
        std::uint64_t stalest_seen = ~std::uint64_t{0};
        for (const auto& [pk, st] : peer_logs_) {
            if (outstanding_.count(pk)) continue;
            if (st.backoff_until_ms > now) continue;
            if (st.last_digest_ms < stalest_seen) {
                stalest_seen = st.last_digest_ms;
                stalest = pk;
            }
        }
        if (stalest.empty()) break;  // nothing removable: refuse new state instead
        peer_logs_.erase(stalest);
    }
}

std::size_t GossipService::peer_count() const {
    std::lock_guard lock(peers_mutex_);
    return peers_.size();
}

std::optional<GossipPeer> GossipService::find_peer_by_pubkey(std::string_view b64) const {
    std::lock_guard lock(peers_mutex_);
    for (const auto& p : peers_) {
        if (p.pubkey == b64) return p;
    }
    return std::nullopt;
}

std::vector<GossipPeer> GossipService::do_get_peers() const {
    std::lock_guard lock(peers_mutex_);
    return peers_;
}

// ---------------------------------------------------------------------------
// UDP async receive
// ---------------------------------------------------------------------------

void GossipService::start_receive() {
    // Never arm on a closed socket: the completion would fail instantly and
    // the error path below would rearm forever. A stopped service simply
    // stops receiving; the same object is not restarted (tests and callers
    // construct a fresh service over the retained storage).
    if (!socket_.is_open()) return;
    socket_.async_receive_from(
        asio::buffer(recv_buffer_), remote_endpoint_,
        [this](const asio::error_code& ec, std::size_t bytes) {
            if (!ec) {
                handle_receive(bytes);
                start_receive();
            } else if (ec != asio::error::operation_aborted &&
                       ec != asio::error::bad_descriptor &&
                       ec != asio::error::not_socket) {
                // Terminal descriptor errors must not rearm: the descriptor
                // will not recover by retrying.
                ++test_receive_error_count_;
                spdlog::error("[{}] UDP receive error: {}", name(), ec.message());
                start_receive();
            }
        });
}

void GossipService::handle_receive(std::size_t bytes_received) {
    // Minimum packet: header + signature (no payload)
    if (bytes_received < kGossipHeaderSize) {
        spdlog::debug("[{}] packet too small ({} bytes) from {}:{}",
                       name(), bytes_received,
                       remote_endpoint_.address().to_string(),
                       remote_endpoint_.port());
        return;
    }

    const auto* data = recv_buffer_.data();

    // Parse header
    GossipPacketHeader header;
    std::memcpy(&header, data, kGossipHeaderSize);

    // Validate magic and version
    if (header.magic != kGossipMagic) {
        spdlog::debug("[{}] invalid magic 0x{:04X} from {}:{}",
                       name(), header.magic,
                       remote_endpoint_.address().to_string(),
                       remote_endpoint_.port());
        return;
    }

    if (header.version != kGossipVersion) {
        spdlog::debug("[{}] unsupported version {} from {}:{}",
                       name(), header.version,
                       remote_endpoint_.address().to_string(),
                       remote_endpoint_.port());
        return;
    }

    // Validate total packet size: header + payload + signature
    const std::size_t expected_size = kGossipHeaderSize +
                                       header.payload_length +
                                       kGossipSignatureSize;
    if (bytes_received < expected_size) {
        spdlog::debug("[{}] truncated packet ({} < {} expected) from {}:{}",
                       name(), bytes_received, expected_size,
                       remote_endpoint_.address().to_string(),
                       remote_endpoint_.port());
        return;
    }

    // Verify packet signature
    if (!verify_packet_signature(data, expected_size)) {
        spdlog::warn("[{}] invalid packet signature from {}:{}",
                      name(), remote_endpoint_.address().to_string(),
                      remote_endpoint_.port());
        return;
    }

    // Update peer last_seen
    const auto sender_pubkey_b64 = crypto::to_base64(
        std::span<const uint8_t>{header.sender_pubkey, 32});
    {
        std::lock_guard lock(peers_mutex_);
        auto it = std::find_if(peers_.begin(), peers_.end(),
            [&](const GossipPeer& p) { return p.pubkey == sender_pubkey_b64; });
        if (it != peers_.end()) {
            it->last_seen = static_cast<uint64_t>(
                chrono::system_clock::to_time_t(chrono::system_clock::now()));
        }
    }

    const auto* payload = data + kGossipHeaderSize;
    const auto payload_len = header.payload_length;

    // Dispatch by message type
    switch (header.msg_type) {
        case GossipMsgType::Digest:
            handle_digest_message(remote_endpoint_, payload, payload_len,
                                  sender_pubkey_b64);
            break;
        case GossipMsgType::DeltaRequest:
            handle_delta_request(remote_endpoint_, payload, payload_len,
                                 sender_pubkey_b64);
            break;
        case GossipMsgType::DeltaResponse:
            handle_delta_response(remote_endpoint_, sender_pubkey_b64, payload, payload_len);
            break;
        case GossipMsgType::AntiEntropy:
            handle_anti_entropy(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::PeerExchange:
            handle_peer_exchange(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::ServerHello:
            handle_server_hello(remote_endpoint_, payload, payload_len,
                                sender_pubkey_b64);
            break;
        case GossipMsgType::AclDelta:
            handle_acl_delta(remote_endpoint_, sender_pubkey_b64, payload, payload_len);
            break;
        case GossipMsgType::DnsRecordSync:
            handle_dns_record_sync(remote_endpoint_, sender_pubkey_b64, payload, payload_len);
            break;
        case GossipMsgType::BackboneIpamSync:
            handle_backbone_ipam_sync(remote_endpoint_, sender_pubkey_b64, payload, payload_len);
            break;
        case GossipMsgType::NsSlotClaim:
            handle_ns_slot_claim(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::MisbehaviorProofBroadcast:
            handle_misbehavior_proof(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::SecurityEnvelope:
            handle_security_envelope(header.sender_pubkey, payload, payload_len);
            break;
        default:
            spdlog::warn("[{}] unknown message type 0x{:02X} from {}:{}",
                          name(), static_cast<uint8_t>(header.msg_type),
                          remote_endpoint_.address().to_string(),
                          remote_endpoint_.port());
            break;
    }
}

// ---------------------------------------------------------------------------
// Message handlers
// ---------------------------------------------------------------------------

void GossipService::handle_digest_message(const asio::ip::udp::endpoint& sender,
                                            const uint8_t* payload,
                                            std::size_t payload_len,
                                            const std::string& signer_pubkey) {
    // Transport authorization before any transfer state is allocated: an
    // uncertified digest allocates nothing and triggers no request.
    if (!peer_certificate_is_root_signed(signer_pubkey)) {
        spdlog::warn("[{}] DENIED digest from {}:{} — sender is not a "
                      "cert-verified enrolled peer", name(),
                      sender.address().to_string(), sender.port());
        return;
    }

    try {
        auto j = json::parse(std::string_view{
            reinterpret_cast<const char*>(payload), payload_len});

        const auto their_pos = j.value("latest_pos", std::uint64_t{0});
        const auto their_generation = j.value("log_generation", std::string{});

        // Identity is the authenticated packet signer, not the NAT-able
        // endpoint.
        GossipPeer peer;
        if (auto peer_opt = find_peer_by_pubkey(signer_pubkey)) {
            peer = *peer_opt;
        } else {
            peer.pubkey = signer_pubkey;
            peer.endpoint = sender.address().to_string() + ":"
                                + std::to_string(sender.port());
            peer.last_seen = static_cast<std::uint64_t>(
                chrono::system_clock::to_time_t(chrono::system_clock::now()));
        }

        do_handle_digest(peer, their_pos, their_generation);

    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse digest from {}:{}: {}",
                      name(), sender.address().to_string(), sender.port(), e.what());
    }
}

void GossipService::handle_delta_request(const asio::ip::udp::endpoint& sender,
                                           const uint8_t* payload,
                                           std::size_t payload_len,
                                           const std::string& signer_pubkey) {
    // Data-returning path: same transport gate as digest and response.
    if (!peer_certificate_is_root_signed(signer_pubkey)) {
        spdlog::warn("[{}] DENIED delta request from {}:{} — sender is not a "
                      "cert-verified enrolled peer", name(),
                      sender.address().to_string(), sender.port());
        return;
    }

    std::uint64_t nonce = 0, from_pos = 0;
    try {
        auto j = json::parse(std::string_view{
            reinterpret_cast<const char*>(payload), payload_len});
        nonce = j.value("nonce", std::uint64_t{0});
        from_pos = j.value("from_pos", std::uint64_t{0});
    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse delta request from {}:{}: {}",
                      name(), sender.address().to_string(), sender.port(), e.what());
        return;
    }

    spdlog::debug("[{}] delta request from {} (nonce={}, from_pos={})",
                   name(), signer_pubkey, nonce, from_pos);

    json records = json::array();
    bool page_failed = false;
    std::string generation;
    std::uint64_t latest_pos = 0;
    {
        std::lock_guard lock(transfer_mutex_);
        generation = pool_generation_;
        latest_pos = pool_latest_position_locked();

        if (pool_available_) {
            std::size_t running = 2;  // "records":[] overhead grows as we append
            auto it = pool_position_index_.upper_bound(from_pos);
            for (; it != pool_position_index_.end(); ++it) {
                if (records.size() >= kPageMaxRecords) break;
                const auto position = it->first;
                const auto& hash = it->second;

                // The per-record bound is checked before any read; the page
                // byte bound before appending.
                storage::FileStorageService::PoolRead result;
                auto text = storage_.read_pool_record(hash, kMaxRetainedRecordBytes, result);
                if (!text.has_value() ||
                    result == storage::FileStorageService::PoolRead::Oversized) {
                    // A retained record we cannot serve is a bounded transfer
                    // failure: the page stops here and positions beyond it are
                    // not served over it.
                    page_failed = true;
                    spdlog::error("[{}] pool record at position {} (hash {}) cannot "
                                  "be served; page incomplete", name(), position, hash);
                    break;
                }
                auto stored = json::parse(*text, nullptr, false);
                if (stored.is_discarded()) {
                    page_failed = true;
                    spdlog::error("[{}] pool record at position {} (hash {}) is not "
                                  "valid JSON; page incomplete", name(), position, hash);
                    break;
                }
                // The file may have changed since reconstruction: the
                // content must still match the indexed identifier, carry the
                // indexed position, and verify under the author signature.
                // Corruption at serve time is a bounded page failure, never
                // a served record.
                auto served = storage::FileStorageService::RetainedDelta::from_json(*text);
                const auto served_hash = served ? retained_record_hash(*served, crypto_)
                                                : std::nullopt;
                if (!served || served->position != position ||
                    !served_hash || *served_hash != hash ||
                    !retained_record_signature_ok(*served, crypto_)) {
                    page_failed = true;
                    spdlog::error("[{}] pool record at position {} (hash {}) no "
                                  "longer verifies against its identifier; page "
                                  "incomplete", name(), position, hash);
                    break;
                }
                json r;
                r["position"]       = stored["position"];
                r["record_hash"]    = stored["record_hash"];
                r["operation"]      = stored["operation"];
                r["target_node_id"] = stored["target_node_id"];
                r["node_data"]      = stored["node_data"];
                r["signer_pubkey"]  = stored["signer_pubkey"];
                r["signature"]      = stored["signature"];
                r["timestamp"]      = stored["timestamp"];
                const auto rsize = r.dump().size();
                if (!records.empty() && running + rsize + 1 > kPageMaxPayloadBytes) break;
                records.push_back(std::move(r));
                running += rsize + 1;
            }
        }
    }

    json response;
    response["nonce"] = nonce;
    response["from_pos"] = from_pos;
    response["generation"] = generation;
    response["latest_pos"] = latest_pos;
    response["complete"] = !page_failed;
    response["records"] = std::move(records);

    auto payload_str = response.dump();
    if (payload_str.size() > 65000) {
        // Should not happen: the page is bounded to kPageMaxPayloadBytes.
        spdlog::error("[{}] delta response to {} exceeds the packet cap "
                      "({} bytes); not sent", name(), signer_pubkey, payload_str.size());
        return;
    }
    std::vector<uint8_t> pkt(payload_str.begin(), payload_str.end());
    send_packet(sender, GossipMsgType::DeltaResponse, pkt);
    spdlog::debug("[{}] delta page served to {} (from_pos={}, latest_pos={}, failed={})",
                   name(), signer_pubkey, from_pos, latest_pos, page_failed);
}

void GossipService::handle_delta_response(const asio::ip::udp::endpoint& sender,
                                            const std::string& sender_pubkey,
                                            const uint8_t* payload,
                                            std::size_t payload_len) {
    // Fail-closed gate, no tokens: state-mutating gossip ingress requires the
    // packet signer to be an enrolled peer with a root-signed certificate.
    // Gossip is Tier-2 transport and never decides Tier 1 — that authority
    // lives in the security plane (SecurityEnvelope → SecurityRouter).
    if (!peer_certificate_is_root_signed(sender_pubkey)) {
        spdlog::warn("[{}] DENIED delta response from {}:{} — sender is not a "
                      "cert-verified enrolled peer", name(),
                      sender.address().to_string(), sender.port());
        return;
    }

    try {
        // The receive side enforces the page bounds itself: a hostile or
        // buggy peer must not be able to make us allocate or parse beyond
        // them.
        if (payload_len > kPageMaxPayloadBytes) {
            spdlog::warn("[{}] delta response from {} exceeds the payload bound "
                          "({} > {} bytes) — dropped",
                          name(), sender_pubkey, payload_len, kPageMaxPayloadBytes);
            return;
        }

        json j = json::parse(std::string_view{
            reinterpret_cast<const char*>(payload), payload_len});
        if (!j.is_object()) {
            spdlog::warn("[{}] delta response from {} is not an object — dropped",
                          name(), sender_pubkey);
            return;
        }

        // The complete envelope is validated, with strict typed reads, before
        // any transfer state is touched and before the outstanding request
        // can be consumed. value() would throw on a mistyped present field;
        // u64_field refuses instead.
        std::uint64_t nonce = 0, from_pos = 0, latest_pos = 0;
        if (!u64_field(j, "nonce", nonce) ||
            !u64_field(j, "from_pos", from_pos) ||
            !u64_field(j, "latest_pos", latest_pos)) {
            spdlog::warn("[{}] delta response from {} has malformed envelope "
                          "fields — dropped", name(), sender_pubkey);
            return;
        }
        std::string generation;
        if (j.contains("generation")) {
            if (!j["generation"].is_string() ||
                j["generation"].get<std::string>().size() > 128) {
                spdlog::warn("[{}] delta response from {} has a malformed "
                              "generation field — dropped", name(), sender_pubkey);
                return;
            }
            generation = j["generation"].get<std::string>();
        }
        bool complete = true;
        if (j.contains("complete")) {
            if (!j["complete"].is_boolean()) {
                spdlog::warn("[{}] delta response from {} has a malformed complete "
                              "field — dropped", name(), sender_pubkey);
                return;
            }
            complete = j["complete"].get<bool>();
        }
        if (!j.contains("records") || !j["records"].is_array()) {
            spdlog::warn("[{}] delta response from {} has no records array — dropped",
                          name(), sender_pubkey);
            return;
        }
        const auto& records = j["records"];
        if (records.size() > kPageMaxRecords) {
            spdlog::warn("[{}] delta response from {} carries more than {} records "
                          "— dropped", name(), sender_pubkey, kPageMaxRecords);
            return;
        }

        // Bind the response to the outstanding request: the authenticated
        // peer, the nonce, the requested generation, and the requested
        // position. A late response after a generation reset is dropped, not
        // merged; an EXPIRED request is dropped with its slot freed and
        // changes nothing — retained records, cursors, nothing.
        bool bound = false;
        {
            std::lock_guard lock(transfer_mutex_);
            auto it = outstanding_.find(sender_pubkey);
            if (it == outstanding_.end()) {
                spdlog::warn("[{}] unsolicited delta response from {} — no outstanding "
                              "request; dropped", name(), sender_pubkey);
                return;
            }
            const auto& req = it->second;
            if (req.deadline_ms < steady_ms()) {
                outstanding_.erase(it);
                spdlog::warn("[{}] delta response from {} arrived after the request "
                              "deadline — dropped", name(), sender_pubkey);
                return;
            }
            bound = (nonce == req.nonce && from_pos == req.from_pos &&
                     generation == req.generation);
            if (!bound) {
                // A stale answer does not consume the real request: the
                // in-flight answer can still bind to the outstanding slot.
                spdlog::warn("[{}] stale delta response from {} (nonce/generation/"
                              "position mismatch); dropped", name(), sender_pubkey);
            } else {
                outstanding_.erase(it);
            }
        }
        if (!bound) return;

        // Admit each record. The cursor advances only over the contiguous
        // accepted prefix: final refusals and duplicates advance it, retryable
        // refusals stop it, and a gap is a bounded transfer failure that never
        // advances past the missing record.
        bool contiguous = true;
        std::uint64_t cursor_after = from_pos;
        std::uint64_t expected = from_pos;
        for (const auto& r : records) {
            if (!r.is_object()) { contiguous = false; break; }
            std::uint64_t pos = 0;
            if (!u64_field(r, "position", pos)) {
                spdlog::warn("[{}] delta response from {} has a record with a "
                              "malformed position — page not advanced further",
                              name(), sender_pubkey);
                contiguous = false;
                break;
            }
            if (pos <= expected) {
            spdlog::warn("[{}] non-increasing position {} in page from {} — page "
                          "inconsistent; not advancing further",
                          name(), pos, sender_pubkey);
            contiguous = false;
            break;
        }
        if (pos != expected + 1) {
            spdlog::warn("[{}] gap in page from {} at position {} (expected {}) — "
                          "transfer failure; not advancing past it",
                          name(), sender_pubkey, pos, expected + 1);
            contiguous = false;
            break;
        }
            expected = pos;
            const auto admission = admit_received_record(r);
            if (admission == Admission::Accepted || admission == Admission::Duplicate ||
                admission == Admission::RefusedFinal) {
                cursor_after = expected;
                continue;
            }
            contiguous = false;  // RefusedRetryable: stall, do not advance
            break;
        }

    // Publish the cursor under the generation binding.
    bool advanced = false;
    bool caught_up = false;
    std::uint64_t cursor_now = from_pos;
    {
        std::lock_guard lock(transfer_mutex_);
        auto it = peer_logs_.find(sender_pubkey);
        if (it == peer_logs_.end() || it->second.generation != generation) {
            // Late response after a generation reset (or unknown peer): no
            // cursor may move.
            return;
        }
        auto& st = it->second;
        if (contiguous && cursor_after > st.cursor) {
            st.cursor = cursor_after;
            advanced = true;
        }
        cursor_now = st.cursor;
        if (advanced) {
            st.stall = 0;
        } else {
            st.stall += 1;
            if (st.stall >= kStallBudget) {
                st.stall = 0;
                st.backoff_until_ms = steady_ms() + kBackoffMs;
                spdlog::warn("[{}] delta transfer from {} stalled ({} consecutive "
                              "pages without progress); backing off {} ms",
                              name(), sender_pubkey, kStallBudget, kBackoffMs);
            }
        }
        caught_up = st.cursor >= latest_pos;
    }

    // Continue the session: only when we advanced, the page was clean, and
    // the sender has more to give.
    if (advanced && complete && contiguous && !caught_up) {
        std::string ep;
        std::uint64_t next_cursor = 0;
        bool in_backoff = false;
        {
            std::lock_guard lock(transfer_mutex_);
            auto it = peer_logs_.find(sender_pubkey);
            if (it != peer_logs_.end()) {
                in_backoff = it->second.backoff_until_ms > steady_ms();
                next_cursor = it->second.cursor;
            }
        }
        if (auto peer_opt = find_peer_by_pubkey(sender_pubkey)) {
            ep = peer_opt->endpoint;
        } else {
            ep = sender.address().to_string() + ":" + std::to_string(sender.port());
        }
        if (!in_backoff) maybe_request_from(sender_pubkey, ep, next_cursor);
    }

        spdlog::info("[{}] delta page from {}: {} record(s), cursor now {} (latest {})",
                       name(), sender_pubkey, records.size(), cursor_now, latest_pos);
    } catch (const std::exception& e) {
        // Malformed input must not escape the receive callback: a throw out
        // of an asio completion handler terminates the process. Whatever
        // was safely retained before the failure stays retained; the rest of
        // the page is dropped.
        spdlog::error("[{}] delta response from {} failed to process: {} — the "
                      "rest of the page is dropped", name(), sender_pubkey, e.what());
    }
}

void GossipService::handle_anti_entropy(const asio::ip::udp::endpoint& sender,
                                          const uint8_t* /*payload*/,
                                          std::size_t /*payload_len*/) {
    // Anti-entropy: full state comparison — placeholder for future implementation
    spdlog::debug("[{}] anti-entropy request from {}:{} (not yet implemented)",
                   name(), sender.address().to_string(), sender.port());
}

void GossipService::handle_peer_exchange(const asio::ip::udp::endpoint& sender,
                                           const uint8_t* payload,
                                           std::size_t payload_len) {
    try {
        auto j = json::parse(std::string_view{
            reinterpret_cast<const char*>(payload), payload_len});

        if (!j.contains("peers") || !j["peers"].is_array()) {
            return;
        }

        // Check if this is a response (don't respond to responses to prevent infinite loop)
        const bool is_response = j.value("is_response", false);

        std::size_t added = 0;
        for (const auto& p : j["peers"]) {
            auto pk = p.value("pubkey", "");
            auto ep = p.value("endpoint", "");
            if (pk.empty() || ep.empty()) continue;

            // Don't add ourselves
            if (pk == crypto::to_base64(keypair_.public_key)) continue;

            // Check if we already know this peer
            bool known = false;
            {
                std::lock_guard lock(peers_mutex_);
                known = std::any_of(peers_.begin(), peers_.end(),
                    [&](const GossipPeer& existing) { return existing.pubkey == pk; });
            }

            if (!known) {
                do_add_peer(ep, pk);
                ++added;
            }

            // A relayed certificate is candidate data: it counts only after
            // the same full verification a direct hello gets. Adopting it
            // here is what lets a delta's AUTHOR be certified even when the
            // author is not a direct peer of this node.
            adopt_relayed_certificate(pk, p.value("certificate_json", ""));
        }

        if (added > 0) {
            spdlog::info("[{}] peer exchange from {}:{}: added {} new peers",
                          name(), sender.address().to_string(), sender.port(), added);
        }

        // Only respond if this was an initial request (not a response)
        if (!is_response) {
            auto our_peers = random_peers(10);
            json response;
            json peers_array = json::array();
            for (const auto& p : our_peers) {
                json peer_j;
                peer_j["pubkey"]           = p.pubkey;
                // Only relay an advertised endpoint we confirmed against the
                // peer's real UDP source; an unconfirmed advertisement is
                // attacker-controlled and would steer third parties at an
                // arbitrary address (reflection). Fall back to the observed
                // source otherwise.
                peer_j["endpoint"]         = (p.advertised_confirmed &&
                                              !p.advertised_endpoint.empty())
                                                 ? p.advertised_endpoint
                                                 : p.endpoint;
                peer_j["http_port"]        = p.http_port;
                peer_j["certificate_json"] = p.certificate_json;
                peers_array.push_back(std::move(peer_j));
            }
            response["peers"] = std::move(peers_array);
            response["is_response"] = true;

            auto payload_str = response.dump();
            std::vector<uint8_t> payload_bytes(payload_str.begin(), payload_str.end());
            send_packet(sender, GossipMsgType::PeerExchange, payload_bytes);
        }

    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse peer exchange from {}:{}: {}",
                      name(), sender.address().to_string(), sender.port(), e.what());
    }
}

// ---------------------------------------------------------------------------
// Gossip timer
// ---------------------------------------------------------------------------

void GossipService::start_gossip_timer() {
    gossip_timer_.expires_after(chrono::seconds(5));
    gossip_timer_.async_wait([this](const asio::error_code& ec) {
        if (!ec) {
            on_gossip_tick();
            start_gossip_timer();
        }
        // If ec == operation_aborted, timer was cancelled (shutdown)
    });
}

void GossipService::on_gossip_tick() {
    // Re-introduce ourselves (ServerHello) to any peer we haven't handshaked with
    // yet — e.g. seeds added after startup by background DNS discovery, or peers
    // that were unreachable during the initial hello. Once a peer responds its
    // certificate_json is populated and we stop. Self-seeds are dropped by the
    // identity guard in handle_server_hello.
    if (our_certificate_) {
        std::vector<std::string> pending;
        {
            std::lock_guard lock(peers_mutex_);
            for (const auto& p : peers_) {
                if (p.certificate_json.empty()) pending.push_back(p.endpoint);
            }
        }
        if (!pending.empty()) {
            json hello = *our_certificate_;
            {
                std::lock_guard lock(mesh_state_mutex_);
                if (ipam_ && our_tunnel_ip_.empty()) hello["request_tunnel_ip"] = true;
                if (!our_region_.empty()) hello["region"] = our_region_;
                if (!our_advertised_endpoint_.empty())
                    hello["advertised_endpoint"] = our_advertised_endpoint_;
            }
            auto hello_str = hello.dump();
            std::vector<uint8_t> hello_bytes(hello_str.begin(), hello_str.end());
            for (const auto& ep : pending) {
                if (auto target = parse_endpoint(ep)) {
                    send_packet(*target, GossipMsgType::ServerHello, hello_bytes);
                }
            }
        }
    }

    GossipPeer chosen;

    {
        std::lock_guard lock(peers_mutex_);

        if (peers_.empty()) {
            return;
        }

        // Pick a random peer
        std::uniform_int_distribution<std::size_t> dist(0, peers_.size() - 1);
        {
            std::lock_guard rng_lock(rng_mutex_);
            chosen = peers_[dist(rng_)];
        }
    }

    // Send digest outside of the lock to avoid holding it during I/O
    do_send_digest(chosen);
}

// ---------------------------------------------------------------------------
// Packet construction and sending
// ---------------------------------------------------------------------------

void GossipService::send_packet(const asio::ip::udp::endpoint& target,
                                  GossipMsgType msg_type,
                                  const std::vector<uint8_t>& payload) {
    // Build packet: header + payload + signature
    GossipPacketHeader header{};
    header.magic = kGossipMagic;
    header.version = kGossipVersion;
    header.msg_type = msg_type;
    std::memcpy(header.sender_pubkey, keypair_.public_key.data(),
                crypto::kEd25519PublicKeySize);
    if (payload.size() > 65000) {
        spdlog::error("[{}] payload too large ({} bytes) for gossip packet", name(), payload.size());
        return;
    }
    header.payload_length = static_cast<uint16_t>(payload.size());

    // Assemble unsigned packet (header + payload)
    std::vector<uint8_t> packet(kGossipHeaderSize + payload.size() + kGossipSignatureSize);
    std::memcpy(packet.data(), &header, kGossipHeaderSize);

    if (!payload.empty()) {
        std::memcpy(packet.data() + kGossipHeaderSize, payload.data(), payload.size());
    }

    // Sign header + payload
    auto message_span = std::span<const uint8_t>{
        packet.data(), kGossipHeaderSize + payload.size()};
    auto signature = crypto_.ed25519_sign(keypair_.private_key, message_span);

    // Append signature
    std::memcpy(packet.data() + kGossipHeaderSize + payload.size(),
                signature.data(), kGossipSignatureSize);

    // Send asynchronously
    auto send_buf = std::make_shared<std::vector<uint8_t>>(std::move(packet));
    socket_.async_send_to(
        asio::buffer(*send_buf), target,
        [send_buf, this, target](const asio::error_code& ec, std::size_t /*bytes*/) {
            if (ec) {
                spdlog::warn("[{}] failed to send to {}:{}: {}",
                              name(), target.address().to_string(),
                              target.port(), ec.message());
            }
        });
}

// ---------------------------------------------------------------------------
// Peer persistence
// ---------------------------------------------------------------------------

void GossipService::load_peers() {
    std::lock_guard lock(peers_mutex_);
    // Do NOT clear: seed peers added (with empty pubkey) before start() must
    // survive so the startup ServerHello reaches them. Merge by endpoint.
    std::unordered_set<std::string> known_endpoints;
    for (const auto& p : peers_) known_endpoints.insert(p.endpoint);

    auto envelope = storage_.read_file("identity", "peers.json");
    if (!envelope) {
        spdlog::info("[{}] no peers.json found ({} seed peer(s) present)",
                     name(), peers_.size());
        return;
    }

    try {
        auto j = json::parse(envelope->data);
        if (!j.contains("peers") || !j["peers"].is_array()) {
            spdlog::warn("[{}] peers.json has invalid format", name());
            return;
        }

        for (const auto& p : j["peers"]) {
            GossipPeer peer;
            peer.pubkey              = p.value("pubkey", "");
            peer.endpoint            = p.value("endpoint", "");
            peer.advertised_endpoint = p.value("advertised_endpoint", "");
            peer.http_port           = p.value("http_port", uint16_t{9100});
            peer.last_seen           = p.value("last_seen", uint64_t{0});
            peer.reputation          = p.value("reputation", 1.0f);
            peer.certificate_json    = p.value("certificate_json", "");

            if (!peer.pubkey.empty() && !peer.endpoint.empty() &&
                known_endpoints.insert(peer.endpoint).second) {
                peers_.push_back(std::move(peer));
            }
        }

        spdlog::info("[{}] {} peer(s) after loading storage", name(), peers_.size());

    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse peers.json: {}", name(), e.what());
    }
}

void GossipService::save_peers() {
    std::lock_guard lock(peers_mutex_);

    json j;
    json peers_array = json::array();
    for (const auto& p : peers_) {
        json peer_j;
        peer_j["pubkey"]              = p.pubkey;
        peer_j["endpoint"]            = p.endpoint;
        peer_j["advertised_endpoint"] = p.advertised_endpoint;
        peer_j["http_port"]           = p.http_port;
        peer_j["last_seen"]           = p.last_seen;
        peer_j["reputation"]          = p.reputation;
        peer_j["certificate_json"]    = p.certificate_json;
        peers_array.push_back(std::move(peer_j));
    }
    j["peers"] = std::move(peers_array);

    storage::SignedEnvelope envelope;
    envelope.type = "peer_list";
    envelope.data = j.dump();
    envelope.signer_pubkey = "ed25519:" + crypto::to_base64(keypair_.public_key);
    envelope.timestamp = static_cast<uint64_t>(
        chrono::system_clock::to_time_t(chrono::system_clock::now()));

    // Sign the peer list data
    auto data_bytes = std::vector<uint8_t>(envelope.data.begin(), envelope.data.end());
    auto sig = crypto_.ed25519_sign(keypair_.private_key, data_bytes);
    envelope.signature = crypto::to_base64(sig);

    if (storage_.write_file("identity", "peers.json", envelope)) {
        spdlog::debug("[{}] saved {} peers to storage", name(), peers_.size());
    } else {
        spdlog::warn("[{}] failed to save peers to storage", name());
    }
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

std::optional<asio::ip::udp::endpoint>
GossipService::parse_endpoint(std::string_view endpoint_str) {
    // Expected format: "ip:port"
    const auto colon = endpoint_str.rfind(':');
    if (colon == std::string_view::npos) {
        return std::nullopt;
    }

    const auto address_str = endpoint_str.substr(0, colon);
    const auto port_str    = endpoint_str.substr(colon + 1);

    try {
        auto address = asio::ip::make_address(std::string(address_str));
        const auto port = static_cast<uint16_t>(std::stoul(std::string(port_str)));
        return udp::endpoint{address, port};
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<GossipPeer>
GossipService::find_peer_by_endpoint(const asio::ip::udp::endpoint& ep) const {
    const auto endpoint_str = ep.address().to_string() + ":" + std::to_string(ep.port());

    std::lock_guard lock(peers_mutex_);
    auto it = std::find_if(peers_.begin(), peers_.end(),
        [&](const GossipPeer& p) { return p.endpoint == endpoint_str; });

    if (it != peers_.end()) {
        return *it;
    }
    return std::nullopt;
}

bool GossipService::verify_packet_signature(const uint8_t* data,
                                              std::size_t total_len) const {
    if (total_len < kGossipHeaderSize + kGossipSignatureSize) {
        return false;
    }

    // Extract sender's public key from header
    const auto* header = reinterpret_cast<const GossipPacketHeader*>(data);
    crypto::Ed25519PublicKey sender_pk{};
    std::memcpy(sender_pk.data(), header->sender_pubkey, crypto::kEd25519PublicKeySize);

    // The signed message is header + payload (everything except the trailing signature)
    const auto message_len = total_len - kGossipSignatureSize;
    auto message = std::span<const uint8_t>{data, message_len};

    // Extract the signature (last 64 bytes)
    crypto::Ed25519Signature sig{};
    std::memcpy(sig.data(), data + message_len, kGossipSignatureSize);

    return crypto_.ed25519_verify(sender_pk, message, sig);
}

std::vector<GossipPeer> GossipService::random_peers(std::size_t count) const {
    std::lock_guard lock(peers_mutex_);

    if (peers_.size() <= count) {
        return peers_;
    }

    // Fisher-Yates partial shuffle to pick `count` random peers
    std::vector<GossipPeer> result = peers_;
    {
        std::lock_guard rng_lock(rng_mutex_);
        for (std::size_t i = 0; i < count; ++i) {
            std::uniform_int_distribution<std::size_t> dist(i, result.size() - 1);
            std::swap(result[i], result[dist(rng_)]);
        }
    }
    result.resize(count);
    return result;
}

// ---------------------------------------------------------------------------
// Server certificate verification
// ---------------------------------------------------------------------------

void GossipService::load_server_certificate() {
    // Load our server certificate
    auto cert_env = storage_.read_file("identity", "server_cert.json");
    if (cert_env) {
        try {
            auto j = json::parse(cert_env->data);
            auto cert = j.get<ServerCertificate>();
            std::string server_id = cert.server_id;
            {
                std::lock_guard lock(peers_mutex_);
                our_certificate_ = std::move(cert);
            }
            spdlog::info("[{}] loaded server certificate (id: {})",
                          name(), server_id);
        } catch (const std::exception& e) {
            spdlog::warn("[{}] failed to parse server certificate: {}", name(), e.what());
        }
        // A certificate written before platform_class/expected_measurement/
        // approved_binary_hash joined the canonical form still PARSES (from_json is
        // all `if (contains)`) and then fails verify_cert_core on the signature.
        // Say so here, or it gets debugged as a root-key mismatch.
        std::lock_guard lock(peers_mutex_);
        if (our_certificate_ && our_certificate_->platform_class.empty() &&
            !our_certificate_->tpm_ak_pubkey.empty()) {
            spdlog::warn("[{}] our certificate predates the platform_class schema — its "
                          "signature will not verify against the current canonical form. "
                          "Re-enroll: --enroll-server <own gossip pubkey> <server-id> "
                          "--enroll-platform-class <class> --enroll-measurement <hex>", name());
        }
    } else {
        spdlog::warn("[{}] no server certificate found — gossip peer verification will be limited", name());
    }

    // Load revoked servers list
    auto revoked_env = storage_.read_file("identity", "revoked_servers.json");
    if (revoked_env) {
        try {
            auto j = json::parse(revoked_env->data);
            if (j.is_array()) {
                for (const auto& pk : j) {
                    if (pk.is_string()) revoked_pubkeys_.push_back(pk.get<std::string>());
                }
            }
            spdlog::info("[{}] loaded {} revoked server pubkeys", name(), revoked_pubkeys_.size());
        } catch (...) {}
    }
}

bool GossipService::verify_server_certificate(const ServerCertificate& cert) const {
    // NO fail-open, matching verify_identity_binding below: without a root pubkey
    // there is nothing to anchor trust to, so every certificate is rejected.
    if (!has_root_pubkey_) {
        spdlog::warn("[{}] certificate rejected: no root pubkey configured, nothing to "
                      "anchor trust to", name());
        return false;
    }
    return verify_cert_core(cert);
}

bool GossipService::verify_identity_binding(const ServerCertificate& cert) const {
    // Routed-flow trust anchor: NO fail-open. A node that cannot anchor the root
    // of trust must reject every binding — otherwise a malicious coordinator
    // could substitute a Noise static and MITM the E2E session.
    if (!has_root_pubkey_) {
        spdlog::warn("[{}] identity-binding rejected: no root pubkey configured", name());
        return false;
    }
    return verify_cert_core(cert);
}

bool GossipService::verify_cert_core(const ServerCertificate& cert) const {
    // The certificate must name THIS network. Two deployments sharing a root
    // key by accident are still two networks, and a certificate with no
    // network at all validates nowhere — there is no unbound acceptance path.
    if (expected_network_id_.empty() || cert.network_id != expected_network_id_) {
        spdlog::warn("[{}] certificate network binding rejected for {}", name(),
                     cert.server_id);
        return false;
    }

    // Check issuer matches our root pubkey
    auto issuer_bytes = crypto::from_base64(cert.issuer_pubkey);
    if (issuer_bytes.size() != crypto::kEd25519PublicKeySize) {
        spdlog::warn("[{}] certificate has invalid issuer pubkey size", name());
        return false;
    }
    crypto::Ed25519PublicKey issuer_pk{};
    std::memcpy(issuer_pk.data(), issuer_bytes.data(), crypto::kEd25519PublicKeySize);
    if (issuer_pk != root_pubkey_) {
        spdlog::warn("[{}] certificate issuer does not match root pubkey", name());
        return false;
    }

    // Check expiry
    if (cert.expires_at != 0) {
        auto now = static_cast<uint64_t>(
            chrono::system_clock::to_time_t(chrono::system_clock::now()));
        if (now > cert.expires_at) {
            spdlog::warn("[{}] certificate for {} has expired", name(), cert.server_id);
            return false;
        }
    }

    // Check revocation
    if (is_revoked(cert.server_pubkey)) {
        spdlog::warn("[{}] certificate for {} has been revoked", name(), cert.server_id);
        return false;
    }

    // Verify Ed25519 signature
    auto canonical = canonical_cert_json(cert);
    auto canonical_bytes = std::vector<uint8_t>(canonical.begin(), canonical.end());
    auto sig_bytes = crypto::from_base64(cert.signature);
    if (sig_bytes.size() != crypto::kEd25519SignatureSize) {
        spdlog::warn("[{}] certificate has invalid signature size", name());
        return false;
    }
    crypto::Ed25519Signature sig{};
    std::memcpy(sig.data(), sig_bytes.data(), crypto::kEd25519SignatureSize);

    if (!crypto_.ed25519_verify(root_pubkey_, canonical_bytes, sig)) {
        spdlog::warn("[{}] certificate signature verification failed for {}", name(), cert.server_id);
        return false;
    }

    return true;
}

bool GossipService::is_revoked(const std::string& server_pubkey) const {
    return std::find(revoked_pubkeys_.begin(), revoked_pubkeys_.end(),
                     server_pubkey) != revoked_pubkeys_.end();
}

// ---------------------------------------------------------------------------
void GossipService::save_revoked_servers() const {
    json arr = json::array();
    for (const auto& pk : revoked_pubkeys_) arr.push_back(pk);

    storage::SignedEnvelope env;
    env.type = "revocation_list";
    env.data = arr.dump();
    env.timestamp = static_cast<uint64_t>(chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count());
    (void)storage_.write_file("identity", "revoked_servers.json", env);
}

void GossipService::add_revoked_server(const std::string& server_pubkey) {
    const std::string pk = normalize_pubkey(server_pubkey);
    if (pk.empty() || is_revoked(pk)) return;  // idempotent
    revoked_pubkeys_.push_back(pk);
    save_revoked_servers();
    spdlog::warn("[{}] revoked superseded server pubkey {}", name(), pk);
}

void GossipService::handle_misbehavior_proof(const asio::ip::udp::endpoint& sender,
                                             const uint8_t* /*payload*/,
                                             std::size_t /*payload_len*/) {
    // The sequence-based tree equivocation path is retired: transport
    // positions do not establish equivocation, and no ban is ever issued
    // from a received record. Wire value 0x15 remains reserved.
    spdlog::debug("[{}] misbehavior proof from {}:{} — the sequence-based tree "
                  "proof path is retired; not processed", name(),
                  sender.address().to_string(), sender.port());
}

bool GossipService::peer_certificate_is_root_signed(const std::string& pubkey) const {
    // Tier-2 transport membership gate -- NEVER fail-open: with no root pubkey
    // configured there is no anchor, so the answer is false. Requires a stored
    // certificate that (a) belongs to this pubkey, (b) is not revoked, and
    // (c) verifies against the configured root via verify_cert_core (real
    // issuer==root check + Ed25519 signature verify).
    std::lock_guard lock(peers_mutex_);
    return peer_certificate_is_root_signed_locked(pubkey);
}

bool GossipService::peer_certificate_is_root_signed_locked(const std::string& pubkey) const {
    // Callers already hold peers_mutex_.
    if (!has_root_pubkey_) return false;
    if (pubkey.empty() || is_revoked(pubkey)) return false;

    std::string cert_json;
    {
        auto it = std::find_if(peers_.begin(), peers_.end(),
            [&](const GossipPeer& p) { return p.pubkey == pubkey; });
        if (it == peers_.end() || it->certificate_json.empty()) return false;
        cert_json = it->certificate_json;
    }

    try {
        auto cert = json::parse(cert_json).get<ServerCertificate>();
        if (cert.server_pubkey != pubkey) return false;
        return verify_cert_core(cert);   // root-anchored; no fail-open
    } catch (...) {
        return false;
    }
}

std::string GossipService::certified_server_id(const std::string& pubkey) const {
    std::lock_guard lock(peers_mutex_);
    if (!has_root_pubkey_ || pubkey.empty() || is_revoked(pubkey)) return {};
    const auto it = std::find_if(peers_.begin(), peers_.end(),
        [&](const GossipPeer& p) { return p.pubkey == pubkey; });
    if (it == peers_.end() || it->certificate_json.empty()) return {};
    try {
        auto cert = json::parse(it->certificate_json).get<ServerCertificate>();
        if (cert.server_pubkey != pubkey || !verify_cert_core(cert)) return {};
        return cert.server_id;
    } catch (...) {
        return {};
    }
}

void GossipService::handle_server_hello(const asio::ip::udp::endpoint& sender,
                                          const uint8_t* payload,
                                          std::size_t payload_len,
                                          const std::string& signer_pubkey) {
    try {
        auto j = json::parse(std::string_view{
            reinterpret_cast<const char*>(payload), payload_len});

        ServerCertificate cert = j.get<ServerCertificate>();

        if (!verify_server_certificate(cert)) {
            spdlog::warn("[{}] rejected ServerHello from {}:{} — invalid certificate",
                          name(), sender.address().to_string(), sender.port());
            return;
        }

        // Proof of possession: the certificate is public, so a valid root
        // signature alone does not prove the presenter holds cert.server_pubkey's
        // private key. The packet signer is cryptographically authenticated
        // (verify_packet_signature in handle_receive), so require it to match the
        // cert identity before we bind that identity to this endpoint — otherwise
        // anyone replaying a public cert could hijack a peer's endpoint mapping.
        if (cert.server_pubkey != signer_pubkey) {
            spdlog::warn("[{}] rejected ServerHello from {}:{} — cert pubkey does not "
                          "match packet signer (proof-of-possession failed)",
                          name(), sender.address().to_string(), sender.port());
            return;
        }

        // Add or update peer with verified certificate
        auto pk = cert.server_pubkey;
        auto ep = sender.address().to_string() + ":" + std::to_string(sender.port());

        // Never peer with ourselves. A lone/genesis server can discover its own
        // tier/region DNS record and seed itself; when our own ServerHello hairpins
        // back (or peer-exchange echoes us), drop the self-referential entry and stop.
        if (pk == crypto::to_base64(keypair_.public_key)) {
            std::lock_guard lock(peers_mutex_);
            auto before = peers_.size();
            peers_.erase(std::remove_if(peers_.begin(), peers_.end(),
                [&](const GossipPeer& p) { return p.endpoint == ep || p.pubkey == pk; }),
                peers_.end());
            if (peers_.size() != before) {
                spdlog::info("[{}] dropped self-referential peer at {} (own identity)",
                              name(), ep);
            } else {
                spdlog::debug("[{}] ignored ServerHello from self ({})", name(), ep);
            }
            return;
        }

        {
            std::lock_guard lock(peers_mutex_);
            auto it = std::find_if(peers_.begin(), peers_.end(),
                [&](const GossipPeer& p) { return p.pubkey == pk; });
            if (it == peers_.end()) {
                // A seed peer is added by endpoint with an empty pubkey. Upgrade
                // it in place on first hello — appending a second entry would
                // leave a certless duplicate that the re-introduce loop hellos
                // at every tick, forever.
                it = std::find_if(peers_.begin(), peers_.end(),
                    [&](const GossipPeer& p) { return p.pubkey.empty() && p.endpoint == ep; });
                if (it != peers_.end()) it->pubkey = pk;
            }

            const auto advertised = j.value("advertised_endpoint", std::string{});
            // Cross-check the advertised endpoint against the UDP source we
            // actually observed. Only a match is "source-confirmed" and safe to
            // relay to third parties / seed; an unconfirmed advertisement is
            // attacker-controlled (it is not covered by the signed certificate).
            const bool advertised_confirmed = !advertised.empty() && advertised == ep;
            if (it != peers_.end()) {
                it->certificate_json = j.dump();
                it->region = j.value("region", "");
                if (!advertised.empty()) {
                    it->advertised_endpoint  = advertised;
                    it->advertised_confirmed = advertised_confirmed;
                }
                it->last_seen = static_cast<uint64_t>(
                    chrono::system_clock::to_time_t(chrono::system_clock::now()));
            } else {
                GossipPeer peer;
                peer.pubkey             = pk;
                peer.endpoint           = ep;
                peer.advertised_endpoint = advertised;
                peer.advertised_confirmed = advertised_confirmed;
                peer.region             = j.value("region", "");
                peer.http_port          = 9100; // will be updated via peer exchange
                peer.last_seen          = static_cast<uint64_t>(
                    chrono::system_clock::to_time_t(chrono::system_clock::now()));
                peer.reputation         = 1.0f;
                peer.certificate_json   = j.dump();
                peers_.push_back(std::move(peer));
            }

            // Heal duplicates persisted before this fix: once this endpoint has
            // an identified entry, any certless twin is redundant.
            std::erase_if(peers_, [&](const GossipPeer& p) {
                return p.pubkey.empty() && p.endpoint == ep;
            });
        }

        spdlog::info("[{}] accepted ServerHello from {} ({})",
                      name(), cert.server_id, ep);

        // If peer requested a tunnel IP and we have IPAM, allocate one
        if (j.value("request_tunnel_ip", false) && ipam_ && !cert.server_id.empty()) {
            auto alloc = ipam_->allocate_tunnel_ip(cert.server_id);
            if (!alloc.base_network.empty()) {
                // Strip /32 suffix for the IP
                auto assigned_ip = alloc.base_network;
                if (auto slash = assigned_ip.find('/'); slash != std::string::npos) {
                    assigned_ip = assigned_ip.substr(0, slash);
                }
                spdlog::info("[{}] allocated tunnel IP {} for joining server '{}'",
                              name(), assigned_ip, cert.server_id);

                // Send assignment in our response
                if (our_certificate_ && !j.value("is_response", false)) {
                    json response = *our_certificate_;
                    response["is_response"] = true;
                    response["assigned_tunnel_ip"] = assigned_ip;
                    if (!our_advertised_endpoint_.empty())
                        response["advertised_endpoint"] = our_advertised_endpoint_;
                    auto payload_str = response.dump();
                    std::vector<uint8_t> payload_bytes(payload_str.begin(), payload_str.end());
                    send_packet(sender, GossipMsgType::ServerHello, payload_bytes);
                }
            }
        }
        // Respond with our own certificate (no IP request)
        else if (our_certificate_ && !j.value("is_response", false)) {
            json response = *our_certificate_;
            response["is_response"] = true;
            if (!our_advertised_endpoint_.empty())
                response["advertised_endpoint"] = our_advertised_endpoint_;
            auto payload_str = response.dump();
            std::vector<uint8_t> payload_bytes(payload_str.begin(), payload_str.end());
            send_packet(sender, GossipMsgType::ServerHello, payload_bytes);
        }

        // If this is a response containing our assigned tunnel IP, store it
        if (j.value("is_response", false) && j.contains("assigned_tunnel_ip")) {
            {
                std::lock_guard lock(mesh_state_mutex_);
                our_tunnel_ip_ = j["assigned_tunnel_ip"].get<std::string>();
            }
            std::string ip;
            {
                std::lock_guard lock(mesh_state_mutex_);
                ip = our_tunnel_ip_;
            }
            spdlog::info("[{}] received tunnel IP assignment: {}", name(), ip);
        }

        // The certificate verified and the packet signer proved possession of
        // pk. Report the contact; the security layer decides what follows.
        if (peer_certified_cb_) {
            auto pk_bytes = crypto::from_base64(pk);
            if (pk_bytes.size() == crypto::kEd25519PublicKeySize) {
                security::NodeId peer_id{};
                std::memcpy(peer_id.bytes.data(), pk_bytes.data(), pk_bytes.size());
                peer_certified_cb_(peer_id);
            }
        }
    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse ServerHello from {}:{}: {}",
                      name(), sender.address().to_string(), sender.port(), e.what());
    }
}


// ---------------------------------------------------------------------------
// Service wiring
// ---------------------------------------------------------------------------

void GossipService::set_preferred_ns_slot(uint8_t slot) {
    std::lock_guard lock(mesh_state_mutex_);
    preferred_ns_slot_ = slot > 9 ? 0 : slot;
}

void GossipService::set_ipam(ipam::IPAMService* ipam) {
    ipam_ = ipam;
}

void GossipService::set_boringtun(boringtun::BoringtunService* dataplane) {
    boringtun_ = dataplane;
}

std::string GossipService::our_tunnel_ip() const {
    std::lock_guard lock(mesh_state_mutex_);
    return our_tunnel_ip_;
}

void GossipService::try_add_backbone_mesh_peer(const GossipPeer& peer) {
    if (!boringtun_ || peer.mesh_pubkey.empty() || peer.backbone_ip.empty()) return;

    // Build the backbone endpoint from the peer's public address and mesh UDP port.
    std::string mesh_endpoint;
    auto colon = peer.endpoint.rfind(':');
    if (colon != std::string::npos) {
        // Extract the IP from the gossip endpoint "ip:9102" and use port 51940
        mesh_endpoint = peer.endpoint.substr(0, colon) + ":51940";
    }

    if (boringtun_->add_peer(peer.mesh_pubkey, peer.backbone_ip + "/32", mesh_endpoint)) {
        spdlog::info("[{}] added backbone mesh peer {} ({}) endpoint={}",
                      name(), peer.backbone_ip, peer.pubkey.substr(0, 12), mesh_endpoint);
    }
}

namespace {

// The origin-signed preimage of each delta family: data fields only, sorted
// keys, signer and signature excluded — the shape ACL and the NS claims
// already use.
std::string dns_delta_canonical(const DnsRecordDelta& d) {
    json j;
    j["delta_id"]    = d.delta_id;
    j["fqdn"]        = d.fqdn;
    j["operation"]   = d.operation;
    j["record_type"] = d.record_type;
    j["timestamp"]   = d.timestamp;
    j["ttl"]         = d.ttl;
    j["value"]       = d.value;
    return j.dump();
}

std::string ipam_delta_canonical(const ipam::BackboneAllocationDelta& d) {
    json j;
    j["backbone_ip"]    = d.backbone_ip;
    j["delta_id"]       = d.delta_id;
    j["operation"]      = d.operation;
    j["server_node_id"] = d.server_node_id;
    j["server_pubkey"]  = d.server_pubkey;
    j["timestamp"]      = d.timestamp;
    return j.dump();
}

}  // namespace

void GossipService::adopt_relayed_certificate(const std::string& pubkey_b64,
                                              const std::string& certificate_json) {
    if (pubkey_b64.empty() || certificate_json.empty()) {
        return;
    }
    {
        std::lock_guard lock(peers_mutex_);
        const auto it = std::find_if(peers_.begin(), peers_.end(),
                                     [&](const GossipPeer& p) { return p.pubkey == pubkey_b64; });
        if (it == peers_.end() || !it->certificate_json.empty()) {
            return;  // Unknown peer, or a certificate is already held.
        }
    }
    try {
        const ServerCertificate cert = json::parse(certificate_json).get<ServerCertificate>();
        if (cert.server_pubkey != pubkey_b64 || !verify_cert_core(cert)) {
            return;
        }
    } catch (...) {
        return;
    }
    bool stored = false;
    {
        std::lock_guard lock(peers_mutex_);
        const auto it = std::find_if(peers_.begin(), peers_.end(), [&](const GossipPeer& p) {
            return p.pubkey == pubkey_b64;
        });
        if (it != peers_.end() && it->certificate_json.empty()) {
            it->certificate_json = certificate_json;
            stored = true;
        }
    }
    // Outside the lock: save_peers takes peers_mutex_ itself.
    if (stored) {
        save_peers();
    }
}

bool GossipService::delta_origin_verified(const std::string& canonical,
                                          const std::string& signer_pubkey_b64,
                                          const std::string& signature_b64) const {
    // The packet signature named the FORWARDER; this names the AUTHOR. A
    // delta applies only when the author signed exactly these fields AND the
    // root enrolled the author — a self-minted key authors nothing the mesh
    // accepts, no matter who relays it.
    if (signer_pubkey_b64.empty() || signature_b64.empty()) {
        return false;
    }
    try {
        const auto pk  = crypto::from_base64(signer_pubkey_b64);
        const auto sig = crypto::from_base64(signature_b64);
        if (pk.size() != crypto::kEd25519PublicKeySize ||
            sig.size() != crypto::kEd25519SignatureSize) {
            return false;
        }
        crypto::Ed25519PublicKey pubkey{};
        crypto::Ed25519Signature signature{};
        std::memcpy(pubkey.data(), pk.data(), pk.size());
        std::memcpy(signature.data(), sig.data(), sig.size());
        if (!crypto_.ed25519_verify(
                pubkey,
                std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(canonical.data()),
                                         canonical.size()),
                signature)) {
            return false;
        }
    } catch (...) {
        return false;
    }
    return peer_certificate_is_root_signed(signer_pubkey_b64);
}

void GossipService::broadcast_backbone_ipam_delta(const ipam::BackboneAllocationDelta& delta) {
    // The origin signs what it asserts; forwarding never re-signs. A server
    // may only assert its own allocation, so the signer IS the subject.
    ipam::BackboneAllocationDelta signed_delta = delta;
    signed_delta.signer_pubkey = crypto::to_base64(keypair_.public_key);
    const std::string canonical = ipam_delta_canonical(signed_delta);
    const auto sig = crypto_.ed25519_sign(
        keypair_.private_key,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(canonical.data()),
                                 canonical.size()));
    signed_delta.signature = crypto::to_base64(sig);

    json j;
    j["delta_id"]        = signed_delta.delta_id;
    j["operation"]       = signed_delta.operation;
    j["server_node_id"]  = signed_delta.server_node_id;
    j["server_pubkey"]   = signed_delta.server_pubkey;
    j["backbone_ip"]     = signed_delta.backbone_ip;
    j["timestamp"]       = signed_delta.timestamp;
    j["signer_pubkey"]   = signed_delta.signer_pubkey;
    j["signature"]       = signed_delta.signature;

    auto packed = json::to_msgpack(j);
    std::vector<uint8_t> payload(packed.begin(), packed.end());

    std::lock_guard lock(peers_mutex_);
    for (const auto& peer : peers_) {
        auto ep = parse_endpoint(peer.endpoint);
        if (ep) {
            send_packet(*ep, GossipMsgType::BackboneIpamSync, payload);
        }
    }
}

void GossipService::handle_backbone_ipam_sync(
    const asio::ip::udp::endpoint& sender,
    const std::string& sender_pubkey,
    const uint8_t* payload, std::size_t payload_len) {
    if (!ipam_) return;

    // Cert-gated ingress; rule in handle_delta_response.
    if (!peer_certificate_is_root_signed(sender_pubkey)) {
        spdlog::warn("[{}] DENIED backbone IPAM delta from {}:{} — sender is not a "
                      "cert-verified enrolled peer", name(),
                      sender.address().to_string(), sender.port());
        return;
    }

    try {
        auto j = json::from_msgpack(payload, payload + payload_len);

        ipam::BackboneAllocationDelta delta;
        delta.delta_id       = j.value("delta_id", "");
        delta.operation      = j.value("operation", "");
        delta.server_node_id = j.value("server_node_id", "");
        delta.server_pubkey  = j.value("server_pubkey", "");
        delta.backbone_ip    = j.value("backbone_ip", "");
        delta.timestamp      = j.value("timestamp", uint64_t{0});
        delta.signer_pubkey  = j.value("signer_pubkey", "");
        delta.signature      = j.value("signature", "");

        if (delta.delta_id.empty() || delta.server_node_id.empty()) {
            return;
        }

        // A backbone claim is a statement about the claimant's OWN address:
        // the author must be the named server, must have signed these exact
        // fields, and must be root-enrolled. Third parties evict nobody.
        if (delta.signer_pubkey != delta.server_pubkey ||
            !delta_origin_verified(ipam_delta_canonical(delta), delta.signer_pubkey,
                                   delta.signature)) {
            spdlog::warn("[{}] DENIED backbone IPAM delta from {}:{} — origin is not "
                          "the certified subject of its own claim", name(),
                          sender.address().to_string(), sender.port());
            return;
        }

        if (ipam_->apply_remote_backbone_allocation(delta)) {
            // New allocation — forward to all peers except sender
            std::vector<uint8_t> fwd_payload(payload, payload + payload_len);
            std::lock_guard lock(peers_mutex_);
            for (const auto& peer : peers_) {
                auto ep = parse_endpoint(peer.endpoint);
                if (ep && *ep != sender) {
                    send_packet(*ep, GossipMsgType::BackboneIpamSync, fwd_payload);
                }
            }

            // If allocate operation, try to add it as a mesh peer.
            if (delta.operation == "allocate") {
                // Find the peer in our list and update backbone_ip
                for (auto& peer : peers_) {
                    if (peer.pubkey == delta.server_pubkey) {
                        peer.backbone_ip = delta.backbone_ip;
                        // Strip CIDR prefix for the stored IP
                        auto slash = peer.backbone_ip.find('/');
                        if (slash != std::string::npos) {
                            peer.backbone_ip = peer.backbone_ip.substr(0, slash);
                        }
                        try_add_backbone_mesh_peer(peer);
                        break;
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse backbone IPAM delta from {}:{}: {}",
                      name(), sender.address().to_string(), sender.port(), e.what());
    }
}

// ---------------------------------------------------------------------------
// Distributed ACL sync
// ---------------------------------------------------------------------------

void GossipService::set_acl(acl::ACLService* acl) {
    acl_ = acl;
}

void GossipService::broadcast_acl_delta(const acl::AclDelta& delta) {
    json j;
    j["delta_id"]    = delta.delta_id;
    j["operation"]   = delta.operation;
    j["user_id"]     = delta.user_id;
    j["resource"]    = delta.resource;
    j["permissions"] = delta.permissions;
    j["timestamp"]   = delta.timestamp;
    j["signer_pubkey"] = delta.signer_pubkey;
    j["signature"]   = delta.signature;

    auto packed = json::to_msgpack(j);
    std::vector<uint8_t> payload(packed.begin(), packed.end());

    std::lock_guard lock(peers_mutex_);
    for (const auto& peer : peers_) {
        auto ep = parse_endpoint(peer.endpoint);
        if (ep) {
            send_packet(*ep, GossipMsgType::AclDelta, payload);
        }
    }
}

void GossipService::handle_acl_delta(const asio::ip::udp::endpoint& sender,
                                      const std::string& sender_pubkey,
                                      const uint8_t* payload, std::size_t payload_len) {
    if (!acl_) return;

    // Cert-gated ingress; rule in handle_delta_response.
    if (!peer_certificate_is_root_signed(sender_pubkey)) {
        spdlog::warn("[{}] DENIED ACL delta from {}:{} — sender is not a "
                      "cert-verified enrolled peer", name(),
                      sender.address().to_string(), sender.port());
        return;
    }

    try {
        auto j = json::from_msgpack(payload, payload + payload_len);

        acl::AclDelta delta;
        delta.delta_id     = j.value("delta_id", "");
        delta.operation    = j.value("operation", "");
        delta.user_id      = j.value("user_id", "");
        delta.resource     = j.value("resource", "");
        delta.permissions  = j.value("permissions", uint32_t{0});
        delta.timestamp    = j.value("timestamp", uint64_t{0});
        delta.signer_pubkey = j.value("signer_pubkey", "");
        delta.signature    = j.value("signature", "");

        if (delta.delta_id.empty() || delta.user_id.empty()) {
            spdlog::warn("[{}] received invalid ACL delta from {}:{}",
                          name(), sender.address().to_string(), sender.port());
            return;
        }

        // The service verifies the signature against the named author below;
        // the author itself must also be a root-enrolled server. A key minted
        // for the occasion self-signs a valid delta and still writes nothing.
        if (!peer_certificate_is_root_signed(delta.signer_pubkey)) {
            spdlog::warn("[{}] DENIED ACL delta from {}:{} — the delta's author is "
                          "not a cert-verified enrolled peer", name(),
                          sender.address().to_string(), sender.port());
            return;
        }

        // apply_remote_delta verifies signature and deduplicates
        if (acl_->apply_remote_delta(delta)) {
            // New delta — forward to all peers except sender (epidemic spread)
            std::vector<uint8_t> fwd_payload(payload, payload + payload_len);
            std::lock_guard lock(peers_mutex_);
            for (const auto& peer : peers_) {
                auto ep = parse_endpoint(peer.endpoint);
                if (ep && *ep != sender) {
                    send_packet(*ep, GossipMsgType::AclDelta, fwd_payload);
                }
            }
        }
    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse ACL delta from {}:{}: {}",
                      name(), sender.address().to_string(), sender.port(), e.what());
    }
}

// ---------------------------------------------------------------------------
// Distributed DNS record sync
// ---------------------------------------------------------------------------

void GossipService::set_dns(network::DnsService* dns) {
    dns_ = dns;
}

void GossipService::broadcast_dns_record_delta(const DnsRecordDelta& delta) {
    // The origin signs what it asserts; forwarding never re-signs.
    DnsRecordDelta signed_delta = delta;
    signed_delta.signer_pubkey = crypto::to_base64(keypair_.public_key);
    const std::string canonical = dns_delta_canonical(signed_delta);
    const auto sig = crypto_.ed25519_sign(
        keypair_.private_key,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(canonical.data()),
                                 canonical.size()));
    signed_delta.signature = crypto::to_base64(sig);

    json j;
    j["delta_id"]      = signed_delta.delta_id;
    j["operation"]     = signed_delta.operation;
    j["fqdn"]          = signed_delta.fqdn;
    j["record_type"]   = signed_delta.record_type;
    j["value"]         = signed_delta.value;
    j["ttl"]           = signed_delta.ttl;
    j["timestamp"]     = signed_delta.timestamp;
    j["signer_pubkey"] = signed_delta.signer_pubkey;
    j["signature"]     = signed_delta.signature;

    auto packed = json::to_msgpack(j);
    std::vector<uint8_t> payload(packed.begin(), packed.end());

    std::lock_guard lock(peers_mutex_);
    for (const auto& peer : peers_) {
        auto ep = parse_endpoint(peer.endpoint);
        if (ep) {
            send_packet(*ep, GossipMsgType::DnsRecordSync, payload);
        }
    }
}

void GossipService::handle_dns_record_sync(const asio::ip::udp::endpoint& sender,
                                             const std::string& sender_pubkey,
                                             const uint8_t* payload, std::size_t payload_len) {
    if (!dns_) return;

    // Cert-gated ingress; rule in handle_delta_response.
    if (!peer_certificate_is_root_signed(sender_pubkey)) {
        spdlog::warn("[{}] DENIED DNS record delta from {}:{} — sender is not a "
                      "cert-verified enrolled peer", name(),
                      sender.address().to_string(), sender.port());
        return;
    }

    try {
        auto j = json::from_msgpack(payload, payload + payload_len);

        DnsRecordDelta delta;
        delta.delta_id      = j.value("delta_id", "");
        delta.operation     = j.value("operation", "");
        delta.fqdn          = j.value("fqdn", "");
        delta.record_type   = j.value("record_type", "");
        delta.value         = j.value("value", "");
        delta.ttl           = j.value("ttl", uint32_t{60});
        delta.timestamp     = j.value("timestamp", uint64_t{0});
        delta.signer_pubkey = j.value("signer_pubkey", "");
        delta.signature     = j.value("signature", "");

        if (delta.delta_id.empty() || delta.fqdn.empty()) {
            spdlog::warn("[{}] received invalid DNS record delta from {}:{}",
                          name(), sender.address().to_string(), sender.port());
            return;
        }

        // Zone writes are authored, not relayed into existence: the origin
        // signed exactly these fields and is a root-enrolled server, or the
        // record does not change.
        if (!delta_origin_verified(dns_delta_canonical(delta), delta.signer_pubkey,
                                   delta.signature)) {
            spdlog::warn("[{}] DENIED DNS record delta from {}:{} — origin signature "
                          "or enrollment failed", name(),
                          sender.address().to_string(), sender.port());
            return;
        }

        // A tier1 label asserts finalized membership, not enrollment. Only a
        // CURRENT Tier 1 member may author one, judged against finalized mesh
        // state; with no membership source configured, nothing qualifies.
        std::string fqdn_lower = delta.fqdn;
        std::transform(fqdn_lower.begin(), fqdn_lower.end(), fqdn_lower.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        if (fqdn_lower.find(".tier1.") != std::string::npos &&
            (!tier1_membership_ || !tier1_membership_(delta.signer_pubkey))) {
            spdlog::warn("[{}] DENIED tier1-labelled DNS record from {}:{} — author is "
                          "not a current Tier 1 member", name(),
                          sender.address().to_string(), sender.port());
            return;
        }

        // A per-server SEIP record is an ORDINARY resource owned by exactly
        // one server: the FQDN embeds that server's id. An enrolled author may
        // write only its own — never another node's address record. The real
        // names are "<id>.<region>.seip.<base>", "<id>.tier<N>.<region>.seip"
        // and "private.<id>.<region>.seip"; the owner id is the FIRST label,
        // after dropping a leading "private." qualifier.
        if (fqdn_lower.find(".seip.") != std::string::npos) {
            std::string_view head(fqdn_lower);
            if (head.substr(0, 8) == "private.") {
                head.remove_prefix(8);
            }
            const auto dot = head.find('.');
            const std::string owner_id(dot == std::string_view::npos ? head
                                                                     : head.substr(0, dot));
            if (!owner_id.empty() && owner_id != certified_server_id(delta.signer_pubkey)) {
                spdlog::warn("[{}] DENIED SEIP DNS record from {}:{} — author does not "
                              "own the server id '{}'", name(),
                              sender.address().to_string(), sender.port(), owner_id);
                return;
            }
        }

        // Convert to DnsZoneRecord for DnsService
        network::DnsZoneRecord zone_rec;
        zone_rec.fqdn        = delta.fqdn;
        zone_rec.record_type = delta.record_type;
        zone_rec.value       = delta.value;
        zone_rec.ttl         = delta.ttl;
        zone_rec.timestamp   = delta.timestamp;

        // apply_remote_delta deduplicates and applies timestamp ordering
        if (dns_->apply_remote_delta(delta.delta_id, delta.operation, zone_rec)) {
            spdlog::debug("[{}] applied DNS delta {} {} {} from {}:{}",
                           name(), delta.operation, delta.record_type,
                           delta.fqdn, sender.address().to_string(), sender.port());

            // New delta — forward to all peers except sender (epidemic spread)
            std::vector<uint8_t> fwd_payload(payload, payload + payload_len);
            std::lock_guard lock(peers_mutex_);
            for (const auto& peer : peers_) {
                auto ep = parse_endpoint(peer.endpoint);
                if (ep && *ep != sender) {
                    send_packet(*ep, GossipMsgType::DnsRecordSync, fwd_payload);
                }
            }
        }
    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse DNS record delta from {}:{}: {}",
                      name(), sender.address().to_string(), sender.port(), e.what());
    }
}

// ---------------------------------------------------------------------------
// Democratic NS slot claiming (ns1-ns9 bootstrap nameservers)
// ---------------------------------------------------------------------------

void GossipService::set_our_region(const std::string& region) {
    our_region_ = region;
}

void GossipService::set_dns_base_domain(const std::string& domain) {
    dns_base_domain_ = domain;
}

std::optional<uint8_t> GossipService::our_ns_slot() const {
    std::lock_guard lock(mesh_state_mutex_);
    return our_ns_slot_;
}

std::vector<NsSlotClaimData> GossipService::get_ns_slots() const {
    std::lock_guard lock(mesh_state_mutex_);
    std::vector<NsSlotClaimData> result;
    for (const auto& s : ns_slots_) {
        if (s.slot > 0) result.push_back(s);
    }
    return result;
}

void GossipService::try_claim_ns_slot(const std::string& our_public_ip) {
    NsSlotClaimData claim;
    bool claimed = false;
    {
        std::lock_guard lock(mesh_state_mutex_);

        // Don't claim if we already hold a slot
        if (our_ns_slot_.has_value()) {
            spdlog::debug("[{}] already hold NS slot ns{}, skipping claim",
                           name(), *our_ns_slot_);
            return;
        }

        // Pinned: claim exactly that slot or none — the registrar's glue points
        // ns<pin> at us, so holding any other slot advertises a nameserver the
        // registry contradicts. Otherwise take the lowest available slot (1-9).
        uint8_t chosen_slot = 0;
        if (preferred_ns_slot_ != 0) {
            const auto& s = ns_slots_[preferred_ns_slot_ - 1];
            if (s.slot == 0 || s.server_pubkey.empty()) {
                chosen_slot = preferred_ns_slot_;
            } else {
                spdlog::warn("[{}] pinned NS slot ns{} is held by {}; not claiming a slot",
                              name(), preferred_ns_slot_, s.server_pubkey.substr(0, 12));
                return;
            }
        } else {
            for (uint8_t i = 0; i < 9; ++i) {
                if (ns_slots_[i].slot == 0 || ns_slots_[i].server_pubkey.empty()) {
                    chosen_slot = i + 1; // slots are 1-based
                    break;
                }
            }
        }

        if (chosen_slot == 0) {
            spdlog::warn("[{}] all 9 NS slots are claimed, cannot claim a slot", name());
            return;
        }

        auto our_pubkey_b64 = crypto::to_base64(keypair_.public_key);
        auto now = static_cast<uint64_t>(
            chrono::system_clock::to_time_t(chrono::system_clock::now()));

        claim.slot          = chosen_slot;
        claim.server_pubkey = our_pubkey_b64;
        claim.server_ip     = our_public_ip;
        claim.region        = our_region_;
        claim.timestamp     = now;

        // Sign: canonical JSON of the claim fields (excluding signature)
        json sign_payload;
        sign_payload["slot"]          = claim.slot;
        sign_payload["server_pubkey"] = claim.server_pubkey;
        sign_payload["server_ip"]     = claim.server_ip;
        sign_payload["region"]        = claim.region;
        sign_payload["timestamp"]     = claim.timestamp;

        auto sign_data = sign_payload.dump();
        std::span<const uint8_t> sign_bytes(
            reinterpret_cast<const uint8_t*>(sign_data.data()), sign_data.size());
        auto sig = crypto_.ed25519_sign(keypair_.private_key, sign_bytes);
        claim.signature = crypto::to_base64(sig);

        // Store locally
        ns_slots_[chosen_slot - 1] = claim;
        our_ns_slot_ = chosen_slot;
        claimed = true;

        spdlog::info("[{}] claimed NS slot ns{} (ip={}, region={})",
                      name(), chosen_slot, our_public_ip, our_region_);
    }
    if (!claimed) return;

    // Register in DNS and broadcast outside the mesh lock (external calls)
    register_ns_slot_in_dns(claim);
    broadcast_ns_slot_claim(claim);
}

void GossipService::broadcast_ns_slot_claim(const NsSlotClaimData& claim) {
    json j;
    j["slot"]          = claim.slot;
    j["server_pubkey"] = claim.server_pubkey;
    j["server_ip"]     = claim.server_ip;
    j["region"]        = claim.region;
    j["timestamp"]     = claim.timestamp;
    j["signature"]     = claim.signature;

    auto packed = json::to_msgpack(j);
    std::vector<uint8_t> payload(packed.begin(), packed.end());

    std::vector<asio::ip::udp::endpoint> targets;
    {
        std::lock_guard lock(peers_mutex_);
        for (const auto& peer : peers_) {
            if (auto ep = parse_endpoint(peer.endpoint)) targets.push_back(*ep);
        }
    }
    for (const auto& ep : targets) {
        send_packet(ep, GossipMsgType::NsSlotClaim, payload);
    }
}

void GossipService::handle_ns_slot_claim(const asio::ip::udp::endpoint& sender,
                                           const uint8_t* payload,
                                           std::size_t payload_len) {
    try {
        auto j = json::from_msgpack(payload, payload + payload_len);

        NsSlotClaimData claim;
        claim.slot          = j.value("slot", uint8_t{0});
        claim.server_pubkey = j.value("server_pubkey", "");
        claim.server_ip     = j.value("server_ip", "");
        claim.region        = j.value("region", "");
        claim.timestamp     = j.value("timestamp", uint64_t{0});
        claim.signature     = j.value("signature", "");

        // Validate basic fields
        if (claim.slot < 1 || claim.slot > 9) {
            spdlog::warn("[{}] received NS slot claim with invalid slot {} from {}:{}",
                          name(), claim.slot, sender.address().to_string(), sender.port());
            return;
        }
        if (claim.server_pubkey.empty()) {
            spdlog::warn("[{}] received NS slot claim with empty pubkey from {}:{}",
                          name(), sender.address().to_string(), sender.port());
            return;
        }

        // NS slots decide which hosts the registry advertises as nameservers,
        // so a claim is state-mutating ingress. Claims travel epidemically, so
        // the gate binds to the CLAIMANT, not the forwarding sender: the claim
        // signature proves the claimant wrote these fields, and the claimant's
        // stored certificate proves the root enrolled it. No cert, no slot.
        {
            json sign_payload;
            sign_payload["slot"]          = claim.slot;
            sign_payload["server_pubkey"] = claim.server_pubkey;
            sign_payload["server_ip"]     = claim.server_ip;
            sign_payload["region"]        = claim.region;
            sign_payload["timestamp"]     = claim.timestamp;
            const auto sign_data = sign_payload.dump();

            bool sig_ok = false;
            try {
                const auto pk  = crypto::from_base64(claim.server_pubkey);
                const auto sig = crypto::from_base64(claim.signature);
                if (pk.size() == crypto::kEd25519PublicKeySize &&
                    sig.size() == crypto::kEd25519SignatureSize) {
                    crypto::Ed25519PublicKey pubkey{};
                    crypto::Ed25519Signature signature{};
                    std::memcpy(pubkey.data(), pk.data(), pk.size());
                    std::memcpy(signature.data(), sig.data(), sig.size());
                    sig_ok = crypto_.ed25519_verify(
                        pubkey,
                        std::span<const uint8_t>(
                            reinterpret_cast<const uint8_t*>(sign_data.data()),
                            sign_data.size()),
                        signature);
                }
            } catch (...) {}
            if (!sig_ok) {
                spdlog::warn("[{}] DENIED NS slot claim for ns{} from {}:{} — claim "
                              "signature does not verify against the claimant key",
                              name(), claim.slot, sender.address().to_string(),
                              sender.port());
                return;
            }
        }
        if (!peer_certificate_is_root_signed(claim.server_pubkey)) {
            spdlog::warn("[{}] DENIED NS slot claim for ns{} from {}:{} — claimant is "
                          "not a cert-verified enrolled peer", name(), claim.slot,
                          sender.address().to_string(), sender.port());
            return;
        }

        NsSlotClaimData accepted_claim;
        NsSlotClaimData reclaim_claim;
        bool reclaimed = false;
        bool accepted = false;
        {
            std::lock_guard lock(mesh_state_mutex_);

            auto& existing = ns_slots_[claim.slot - 1];
            bool is_new = false;

            if (existing.slot == 0 || existing.server_pubkey.empty()) {
                // Slot is unclaimed — accept
                is_new = true;
            } else if (claim.timestamp > existing.timestamp) {
                // LWW: newer timestamp wins
                is_new = true;
            } else if (claim.timestamp == existing.timestamp &&
                       claim.server_pubkey > existing.server_pubkey) {
                // Tiebreak: higher pubkey wins (lexicographic)
                is_new = true;
            }

            if (!is_new) {
                spdlog::debug("[{}] rejected NS slot claim for ns{} from {} (existing claim is newer or wins tiebreak)",
                               name(), claim.slot, claim.server_pubkey);
                return;
            }

            // Check if our own slot is being overwritten
            bool our_slot_stolen = false;
            std::string our_old_ip;
            auto our_pubkey_b64 = crypto::to_base64(keypair_.public_key);
            if (existing.server_pubkey == our_pubkey_b64 &&
                claim.server_pubkey != our_pubkey_b64 &&
                our_ns_slot_.has_value() && *our_ns_slot_ == claim.slot) {
                our_slot_stolen = true;
                our_old_ip = existing.server_ip; // save before overwrite
            }

            // Accept the claim
            existing = claim;
            accepted_claim = claim;
            accepted = true;

            spdlog::info("[{}] accepted NS slot claim: ns{} -> {} (ip={}, region={})",
                          name(), claim.slot, claim.server_pubkey, claim.server_ip, claim.region);

            // If our slot was stolen, try to re-claim a different one
            if (our_slot_stolen) {
                our_ns_slot_.reset();
                spdlog::warn("[{}] our NS slot ns{} was overwritten by {}, will try to re-claim",
                              name(), claim.slot, claim.server_pubkey);
                // Find a new free slot. Pinned: only the pinned slot is ever ours —
                // if someone else now holds it, stand down instead of advertising a
                // slot whose registry glue does not point at us.
                uint8_t new_slot = 0;
                if (preferred_ns_slot_ != 0) {
                    const auto& s = ns_slots_[preferred_ns_slot_ - 1];
                    if (s.slot == 0 || s.server_pubkey.empty()) new_slot = preferred_ns_slot_;
                } else {
                    for (uint8_t i = 0; i < 9; ++i) {
                        if (ns_slots_[i].slot == 0 || ns_slots_[i].server_pubkey.empty()) {
                            new_slot = i + 1;
                            break;
                        }
                    }
                }
                if (new_slot > 0) {
                    auto now = static_cast<uint64_t>(
                        chrono::system_clock::to_time_t(chrono::system_clock::now()));

                    NsSlotClaimData reclaim;
                    reclaim.slot          = new_slot;
                    reclaim.server_pubkey = our_pubkey_b64;
                    reclaim.server_ip     = our_old_ip; // recovered before overwrite
                    reclaim.region        = our_region_;
                    reclaim.timestamp = now;

                    json sign_payload;
                    sign_payload["slot"]          = reclaim.slot;
                    sign_payload["server_pubkey"] = reclaim.server_pubkey;
                    sign_payload["server_ip"]     = reclaim.server_ip;
                    sign_payload["region"]        = reclaim.region;
                    sign_payload["timestamp"]     = reclaim.timestamp;

                    auto sign_data = sign_payload.dump();
                    std::span<const uint8_t> sign_bytes(
                        reinterpret_cast<const uint8_t*>(sign_data.data()), sign_data.size());
                    auto sig = crypto_.ed25519_sign(keypair_.private_key, sign_bytes);
                    reclaim.signature = crypto::to_base64(sig);

                    ns_slots_[new_slot - 1] = reclaim;
                    our_ns_slot_ = new_slot;
                    reclaim_claim = reclaim;
                    reclaimed = true;

                    spdlog::info("[{}] re-claimed NS slot ns{} after losing ns{}",
                                  name(), new_slot, claim.slot);
                } else {
                    spdlog::warn("[{}] all NS slots taken after losing ns{}, no slot available",
                                  name(), claim.slot);
                }
            }
        }
        if (!accepted) return;

        // Register in DNS and forward outside the mesh lock (external calls)
        register_ns_slot_in_dns(accepted_claim);

        {
            std::vector<asio::ip::udp::endpoint> targets;
            std::lock_guard lock(peers_mutex_);
            for (const auto& peer : peers_) {
                auto ep = parse_endpoint(peer.endpoint);
                if (ep && *ep != sender) targets.push_back(*ep);
            }
            std::vector<uint8_t> fwd_payload(payload, payload + payload_len);
            for (const auto& ep : targets) {
                send_packet(ep, GossipMsgType::NsSlotClaim, fwd_payload);
            }
        }

        if (reclaimed) {
            register_ns_slot_in_dns(reclaim_claim);
            broadcast_ns_slot_claim(reclaim_claim);
        }
    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse NS slot claim from {}:{}: {}",
                      name(), sender.address().to_string(), sender.port(), e.what());
    }
}

void GossipService::register_ns_slot_in_dns(const NsSlotClaimData& claim) {
    if (!dns_) return;

    std::string ns_fqdn = "ns" + std::to_string(claim.slot) + "." + dns_base_domain_;
    dns_->add_nameserver(ns_fqdn, claim.server_ip);
    spdlog::debug("[{}] registered DNS NS record: {} -> {}",
                   name(), ns_fqdn, claim.server_ip);
}

// ---------------------------------------------------------------------------
// Security transport (ISecurityTransport)
// ---------------------------------------------------------------------------
//
// The packet signature is the only authentication applied here. No trust-tier
// check, no parse, no forward: the security layer binds the envelope to the
// signer and decides every fan-out, so gossip cannot amplify a hostile message.

void GossipService::set_security_sink(security::SecuritySink sink) {
    security_sink_ = std::move(sink);
}

void GossipService::set_peer_certified_callback(
    std::function<void(const security::NodeId&)> cb) {
    peer_certified_cb_ = std::move(cb);
}

bool GossipService::find_peer_endpoint_by_pubkey(std::string_view b64,
                                                 asio::ip::udp::endpoint& out) const {
    std::lock_guard lock(peers_mutex_);
    for (const auto& p : peers_) {
        // Canonical compare: the same key has several base64 spellings.
        if (crypto::canonical_key_b64(p.pubkey) != b64) continue;
        auto ep = parse_endpoint(p.endpoint);
        if (!ep) return false;
        out = *ep;
        return true;
    }
    return false;
}

void GossipService::handle_security_envelope(const uint8_t* sender_pubkey,
                                             const uint8_t* payload, std::size_t len) {
    // Fail-closed membership gate, mirroring every other state-mutating
    // gossip ingress path: once the mesh is formed (some peer holds a
    // root-signed certificate), a packet that reaches the Tier 1 security
    // plane must have been signed by one of them. A stranger can otherwise
    // reach the router line rate with bytes it signed itself, and the
    // outbound refusal is hollow if the inbound one is not.
    //
    // The exemption is per-kind, not a category. Each exempt kind names a
    // sender this node's certificate table may not hold yet, and each is
    // authorized somewhere that protocol state decides: transport enrollment
    // authorizes the peer; attestation evaluates Tier 1 eligibility. It is
    // the reverse of the old assumption that attestation certifies anyone.
    //   AttestationChallenge — the pinned anchor issues the founding
    //     challenges before its certificate has converged into a peer's
    //     table; the router admits the anchor pre-quorum and current members
    //     once an epoch is active, then applies the production budget.
    //   AttestationEvidence — the subject was certified before it was ever
    //     challenged; an envelope that names no live challenge this node
    //     issued is refused before any verification work.
    //   DkgTranscriptAttest / GenesisEligibilityAttest — sent by the founding
    //     set, anchor included; GenesisService accepts only a signature as a
    //     founder over the founding transcript, and a stranger holds none of
    //     those keys.
    // A ParticipationChallenge is NOT exempt: only current members, all of
    // them certified, ever issue one, and never before an epoch is active.
    // While no peer is certified (mesh not yet formed) the gate is inert for
    // everyone, and ServerHello/PeerExchange is still the only way
    // certificates enter.
    const auto sender_b64 =
        crypto::to_base64(std::span<const uint8_t>{sender_pubkey, 32});

    // Decode just enough to learn the kind. A malformed envelope falls
    // through to the size check and the sink's own decode, which rejects it;
    // we do not gate on a kind we cannot read.
    const auto decoded =
        security::decode_security_message(std::span<const uint8_t>{payload, len});
    const bool is_exempt_kind = std::holds_alternative<security::SecurityMessage>(decoded) &&
        (std::get<security::SecurityMessage>(decoded).kind ==
             security::SecurityMessageKind::AttestationChallenge ||
         std::get<security::SecurityMessage>(decoded).kind ==
             security::SecurityMessageKind::AttestationEvidence ||
         std::get<security::SecurityMessage>(decoded).kind ==
             security::SecurityMessageKind::DkgTranscriptAttest ||
         std::get<security::SecurityMessage>(decoded).kind ==
             security::SecurityMessageKind::GenesisEligibilityAttest);

    if (!is_exempt_kind) {
        bool any_certified = false;
        {
            std::lock_guard lock(peers_mutex_);
            any_certified = has_root_pubkey_ &&
                            std::any_of(peers_.begin(), peers_.end(),
                                        [&](const GossipPeer& p) {
                                            return !p.certificate_json.empty();
                                        });
            if (any_certified && !peer_certificate_is_root_signed_locked(sender_b64)) {
                ++security_envelope_drops_;
                ++security_drops_since_warn_;
                const auto now = chrono::steady_clock::now();
                if (now - security_drop_warn_at_ >= chrono::seconds(10)) {
                    spdlog::warn(
                        "[{}] dropped {} security envelope(s) from uncertified sender "
                        "{}:{}, latest {} bytes", name(), security_drops_since_warn_,
                        remote_endpoint_.address().to_string(), remote_endpoint_.port(), len);
                    security_drop_warn_at_ = now;
                    security_drops_since_warn_ = 0;
                }
                return;
            }
        }
    }

    if (len > security::constants::kMaxSecurityMessageBytes) {
        // A peer can repeat this at line rate; keep the log from becoming the
        // amplifier.
        ++security_drops_since_warn_;
        const auto now = chrono::steady_clock::now();
        if (now - security_drop_warn_at_ >= chrono::seconds(10)) {
            spdlog::warn("[{}] dropped {} oversized security envelope(s), latest {} bytes from {}:{}",
                          name(), security_drops_since_warn_, len,
                          remote_endpoint_.address().to_string(), remote_endpoint_.port());
            security_drop_warn_at_ = now;
            security_drops_since_warn_ = 0;
        }
        return;
    }

    if (!security_sink_) {
        spdlog::debug("[{}] security envelope dropped: no sink", name());
        return;
    }

    security::NodeId sender{};
    std::memcpy(sender.bytes.data(), sender_pubkey, sender.bytes.size());
    security_sink_(sender, std::span<const uint8_t>{payload, len});
}

bool GossipService::peer_is_root_certified(const security::NodeId& peer) const {
    return peer_certificate_is_root_signed(crypto::to_base64(peer.bytes));
}

bool GossipService::send_to(const security::NodeId& peer,
                            std::span<const uint8_t> envelope) {
    if (envelope.size() > security::constants::kMaxSecurityMessageBytes) return false;
    if (peer.bytes == keypair_.public_key) return false;

    asio::ip::udp::endpoint target;
    if (!find_peer_endpoint_by_pubkey(crypto::to_base64(peer.bytes), target)) return false;

    send_packet(target, GossipMsgType::SecurityEnvelope,
                std::vector<uint8_t>(envelope.begin(), envelope.end()));
    return true;
}

std::size_t GossipService::broadcast(std::span<const uint8_t> envelope) {
    if (envelope.size() > security::constants::kMaxSecurityMessageBytes) return 0;

    // Snapshot under the lock, send with it released (send_packet is not to be
    // called under peers_mutex_).
    std::vector<asio::ip::udp::endpoint> targets;
    {
        const auto our_b64 = crypto::to_base64(keypair_.public_key);
        std::lock_guard lock(peers_mutex_);
        targets.reserve(peers_.size());
        for (const auto& p : peers_) {
            if (crypto::canonical_key_b64(p.pubkey) == our_b64) continue;
            if (auto ep = parse_endpoint(p.endpoint)) targets.push_back(*ep);
        }
    }

    const std::vector<uint8_t> payload(envelope.begin(), envelope.end());
    for (const auto& ep : targets) {
        send_packet(ep, GossipMsgType::SecurityEnvelope, payload);
    }
    return targets.size();
}

} // namespace nexus::gossip
