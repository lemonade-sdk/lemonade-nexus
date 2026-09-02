#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Gossip/MisbehaviorDetector.hpp>
#include <LemonadeNexus/Network/DnsService.hpp>
#include <LemonadeNexus/Boringtun/BoringtunService.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

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

    // Send ServerHello to all known peers on startup (before starting async loops).
    // If we need a tunnel IP, include the request flag so a peer allocates one for us.
    {
        std::lock_guard lock(peers_mutex_);

        spdlog::info("[{}] listening on UDP port {} (pubkey: {}, peers: {})",
                      name(), port_,
                      crypto::to_base64(keypair_.public_key),
                      peers_.size());

        if (our_certificate_ && !peers_.empty()) {
            bool need_tunnel_ip = ipam_ && our_tunnel_ip_.empty();
            // Check if IPAM already has our allocation
            if (need_tunnel_ip && our_certificate_) {
                auto existing = ipam_->get_allocation(our_certificate_->server_id);
                if (existing && existing->tunnel) {
                    auto ip = existing->tunnel->base_network;
                    if (auto slash = ip.find('/'); slash != std::string::npos)
                        ip = ip.substr(0, slash);
                    our_tunnel_ip_ = ip;
                    need_tunnel_ip = false;
                }
            }

            json hello = *our_certificate_;
            if (need_tunnel_ip) {
                hello["request_tunnel_ip"] = true;
            }
            if (!our_region_.empty()) {
                hello["region"] = our_region_;
            }
            if (!our_advertised_endpoint_.empty()) {
                hello["advertised_endpoint"] = our_advertised_endpoint_;
            }
            auto payload_str = hello.dump();
            std::vector<uint8_t> payload_bytes(payload_str.begin(), payload_str.end());

            for (const auto& peer : peers_) {
                auto target = parse_endpoint(peer.endpoint);
                if (target) {
                    send_packet(*target, GossipMsgType::ServerHello, payload_bytes);
                }
            }
            spdlog::info("[{}] sent ServerHello to {} peers (request_tunnel_ip: {})",
                          name(), peers_.size(), need_tunnel_ip);
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

    const auto our_seq = storage_.latest_delta_seq();

    // Build digest JSON payload
    json digest;
    digest["latest_seq"] = our_seq;
    digest["peer_count"] = static_cast<uint32_t>(peers_.size());
    digest["timestamp"] = static_cast<uint64_t>(
        chrono::system_clock::to_time_t(chrono::system_clock::now()));

    // Compute tree hash: SHA-256 of all delta sequences concatenated
    // For now, hash the latest sequence number as a simple tree hash
    std::vector<uint8_t> seq_bytes(sizeof(our_seq));
    std::memcpy(seq_bytes.data(), &our_seq, sizeof(our_seq));
    auto hash = crypto_.sha256(seq_bytes);
    digest["tree_hash"] = crypto::to_base64(hash);

    auto payload_str = digest.dump();
    std::vector<uint8_t> payload(payload_str.begin(), payload_str.end());

    send_packet(*target, GossipMsgType::Digest, payload);
    spdlog::debug("[{}] sent digest to {} (seq={})", name(), peer.endpoint, our_seq);
}

void GossipService::do_handle_digest(const GossipPeer& peer, uint64_t their_seq,
                                       const std::array<uint8_t, 32>& their_hash) {
    const auto our_seq = storage_.latest_delta_seq();

    spdlog::debug("[{}] received digest from {} (their_seq={}, our_seq={})",
                   name(), peer.endpoint, their_seq, our_seq);

    if (their_seq > our_seq) {
        // They have deltas we don't — request them
        auto target = parse_endpoint(peer.endpoint);
        if (!target) return;

        json request;
        request["from_seq"] = our_seq;

        auto payload_str = request.dump();
        std::vector<uint8_t> payload(payload_str.begin(), payload_str.end());
        send_packet(*target, GossipMsgType::DeltaRequest, payload);

        spdlog::debug("[{}] requesting deltas from {} since seq {}",
                       name(), peer.endpoint, our_seq);

    } else if (our_seq > their_seq) {
        // We have deltas they don't — send them proactively
        do_send_deltas(peer, their_seq);
    } else {
        // Same sequence — compare tree hashes
        std::vector<uint8_t> seq_bytes(sizeof(our_seq));
        std::memcpy(seq_bytes.data(), &our_seq, sizeof(our_seq));
        auto our_hash = crypto_.sha256(seq_bytes);

        if (our_hash != their_hash) {
            spdlog::warn("[{}] sequence match but tree hash mismatch with {} — "
                          "anti-entropy needed", name(), peer.endpoint);
            // Could trigger AntiEntropy here in a future iteration
        }
    }
}

void GossipService::do_send_deltas(const GossipPeer& peer, uint64_t from_seq) {
    auto target = parse_endpoint(peer.endpoint);
    if (!target) return;

    auto deltas = storage_.read_deltas_since(from_seq);
    if (deltas.empty()) {
        spdlog::debug("[{}] no deltas to send to {} since seq {}",
                       name(), peer.endpoint, from_seq);
        return;
    }

    json response;
    json deltas_array = json::array();

    for (const auto& delta : deltas) {
        json d;
        d["sequence"]            = delta.sequence;
        d["operation"]           = delta.operation;
        d["target_node_id"]      = delta.target_node_id;
        d["data"]                = json::parse(delta.data, nullptr, false);
        d["signer_pubkey"]       = delta.signer_pubkey;
        d["required_permission"] = delta.required_permission;
        d["signature"]           = delta.signature;
        d["timestamp"]           = delta.timestamp;
        deltas_array.push_back(std::move(d));
    }

    response["deltas"] = std::move(deltas_array);
    response["from_seq"] = from_seq;

    auto payload_str = response.dump();
    std::vector<uint8_t> payload(payload_str.begin(), payload_str.end());
    send_packet(*target, GossipMsgType::DeltaResponse, payload);

    spdlog::debug("[{}] sent {} deltas to {} (from_seq={})",
                   name(), deltas.size(), peer.endpoint, from_seq);
}

void GossipService::do_handle_deltas(const GossipPeer& peer,
                                       const nlohmann::json& deltas_json) {
    if (!deltas_json.contains("deltas") || !deltas_json["deltas"].is_array()) {
        spdlog::warn("[{}] invalid deltas payload from {}", name(), peer.endpoint);
        return;
    }

    std::size_t applied = 0;
    std::size_t rejected = 0;

    for (const auto& d : deltas_json["deltas"]) {
        storage::SignedDelta delta;
        delta.sequence            = d.value("sequence", uint64_t{0});
        delta.operation           = d.value("operation", "");
        delta.target_node_id      = d.value("target_node_id", "");
        delta.signer_pubkey       = d.value("signer_pubkey", "");
        delta.required_permission = d.value("required_permission", "");
        delta.signature           = d.value("signature", "");
        delta.timestamp           = d.value("timestamp", uint64_t{0});

        if (d.contains("data")) {
            delta.data = d["data"].dump();
        }

        // Reject unsigned deltas — all deltas MUST be signed
        if (delta.signer_pubkey.empty() || delta.signature.empty()) {
            spdlog::warn("[{}] delta seq {} from {} is unsigned, rejecting",
                          name(), delta.sequence, peer.endpoint);
            ++rejected;
            continue;
        }

        // Validate the delta's Ed25519 signature
        {
            try {
                // Extract the raw public key from "ed25519:base64..." format
                std::string_view pk_str = delta.signer_pubkey;
                if (pk_str.starts_with("ed25519:")) {
                    pk_str.remove_prefix(8);
                }
                auto pk_bytes = crypto::from_base64(pk_str);
                auto sig_bytes = crypto::from_base64(delta.signature);

                if (pk_bytes.size() == crypto::kEd25519PublicKeySize &&
                    sig_bytes.size() == crypto::kEd25519SignatureSize) {

                    crypto::Ed25519PublicKey pub{};
                    crypto::Ed25519Signature sig{};
                    std::memcpy(pub.data(), pk_bytes.data(), crypto::kEd25519PublicKeySize);
                    std::memcpy(sig.data(), sig_bytes.data(), crypto::kEd25519SignatureSize);

                    // Verify signature over the FULL delta (not just data)
                    // to prevent replay with modified operation/target
                    std::string canonical =
                        delta.operation + "\n" +
                        delta.target_node_id + "\n" +
                        std::to_string(delta.sequence) + "\n" +
                        delta.required_permission + "\n" +
                        std::to_string(delta.timestamp) + "\n" +
                        delta.data;
                    auto canonical_bytes = std::vector<uint8_t>(
                        canonical.begin(), canonical.end());
                    if (!crypto_.ed25519_verify(pub, canonical_bytes, sig)) {
                        spdlog::warn("[{}] delta seq {} from {} has invalid signature, skipping",
                                      name(), delta.sequence, peer.endpoint);
                        ++rejected;
                        continue;
                    }
                } else {
                    spdlog::warn("[{}] delta seq {} has malformed key/sig, skipping",
                                  name(), delta.sequence);
                    ++rejected;
                    continue;
                }
            } catch (const std::exception& e) {
                spdlog::warn("[{}] delta sig verification failed: {}", name(), e.what());
                ++rejected;
                continue;
            }
        }

        // Equivocation detection (signature already verified above): if this signer
        // previously signed a DIFFERENT statement at the same (target_node_id,
        // sequence), that is non-repudiable proof it equivocated. Mint a proof, ban
        // the signer, gossip the proof, and refuse to apply the conflicting delta.
        {
            std::string id = normalize_pubkey(delta.signer_pubkey) + "\x1f" +
                             delta.target_node_id + "\x1f" + std::to_string(delta.sequence);
            std::string current = d.dump();
            std::string prev;
            {
                std::lock_guard lk(seen_statements_mutex_);
                auto it = seen_statements_.find(id);
                if (it != seen_statements_.end()) {
                    prev = it->second;
                } else if (seen_statements_.size() >= kMaxSeenStatements) {
                    seen_statements_.clear();  // bounded; only loses detection memory
                }
                seen_statements_[id] = current;
            }
            if (!prev.empty() && prev != current) {
                try {
                    auto prev_json = json::parse(prev);
                    auto now = static_cast<uint64_t>(chrono::duration_cast<chrono::seconds>(
                        chrono::system_clock::now().time_since_epoch()).count());
                    auto proof = make_tree_delta_equivocation_proof(
                        prev_json, d, crypto::to_base64(keypair_.public_key), now, crypto_);
                    if (proof) {
                        spdlog::warn("[{}] EQUIVOCATION: peer {} signed two conflicting deltas "
                                      "at {}/seq {} — banning", name(), proof->accused_pubkey,
                                      delta.target_node_id, delta.sequence);
                        apply_ban(proof->accused_pubkey, *proof);
                        broadcast_misbehavior_proof(*proof);
                        ++rejected;
                        continue;
                    }
                } catch (const std::exception& e) {
                    spdlog::debug("[{}] equivocation check parse error: {}", name(), e.what());
                }
            }
        }

        // Apply the delta via storage
        auto seq = storage_.append_delta(delta);
        if (seq > 0) {
            ++applied;
        } else {
            spdlog::warn("[{}] failed to apply delta seq {} from {}",
                          name(), delta.sequence, peer.endpoint);
            ++rejected;
        }
    }

    spdlog::info("[{}] received deltas from {}: {} applied, {} rejected",
                  name(), peer.endpoint, applied, rejected);
}

std::vector<GossipPeer> GossipService::do_get_peers() const {
    std::lock_guard lock(peers_mutex_);
    return peers_;
}

// ---------------------------------------------------------------------------
// UDP async receive
// ---------------------------------------------------------------------------

void GossipService::start_receive() {
    socket_.async_receive_from(
        asio::buffer(recv_buffer_), remote_endpoint_,
        [this](const asio::error_code& ec, std::size_t bytes) {
            if (!ec) {
                handle_receive(bytes);
                start_receive();
            } else if (ec != asio::error::operation_aborted) {
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
            handle_digest_message(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::DeltaRequest:
            handle_delta_request(remote_endpoint_, payload, payload_len);
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
                                            std::size_t payload_len) {
    try {
        auto j = json::parse(std::string_view{
            reinterpret_cast<const char*>(payload), payload_len});

        const auto their_seq = j.value("latest_seq", uint64_t{0});
        std::array<uint8_t, 32> their_hash{};

        if (j.contains("tree_hash")) {
            auto hash_bytes = crypto::from_base64(j["tree_hash"].get<std::string>());
            if (hash_bytes.size() == 32) {
                std::memcpy(their_hash.data(), hash_bytes.data(), 32);
            }
        }

        // Find or create peer entry
        const auto endpoint_str = sender.address().to_string() + ":"
                                   + std::to_string(sender.port());
        auto peer_opt = find_peer_by_endpoint(sender);
        GossipPeer peer;
        if (peer_opt) {
            peer = *peer_opt;
        } else {
            peer.endpoint = endpoint_str;
            peer.last_seen = static_cast<uint64_t>(
                chrono::system_clock::to_time_t(chrono::system_clock::now()));
        }

        do_handle_digest(peer, their_seq, their_hash);

    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse digest from {}:{}: {}",
                      name(), sender.address().to_string(), sender.port(), e.what());
    }
}

void GossipService::handle_delta_request(const asio::ip::udp::endpoint& sender,
                                           const uint8_t* payload,
                                           std::size_t payload_len) {
    try {
        auto j = json::parse(std::string_view{
            reinterpret_cast<const char*>(payload), payload_len});

        const auto from_seq = j.value("from_seq", uint64_t{0});

        const auto endpoint_str = sender.address().to_string() + ":"
                                   + std::to_string(sender.port());
        auto peer_opt = find_peer_by_endpoint(sender);
        GossipPeer peer;
        if (peer_opt) {
            peer = *peer_opt;
        } else {
            peer.endpoint = endpoint_str;
        }

        spdlog::debug("[{}] delta request from {} (from_seq={})",
                       name(), endpoint_str, from_seq);

        do_send_deltas(peer, from_seq);

    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse delta request from {}:{}: {}",
                      name(), sender.address().to_string(), sender.port(), e.what());
    }
}

void GossipService::handle_delta_response(const asio::ip::udp::endpoint& sender,
                                            const std::string& sender_pubkey,
                                            const uint8_t* payload,
                                            std::size_t payload_len) {
    // Fail-closed gate, no tokens: state-mutating gossip ingress (delta apply,
    // ACL/DNS/IPAM sync) requires the packet signer to be an enrolled peer with
    // a root-signed certificate. Gossip is Tier-2 transport and never decides
    // Tier 1 — that authority lives in the security plane (SecurityEnvelope →
    // SecurityRouter).
    if (!peer_certificate_is_root_signed(sender_pubkey)) {
        spdlog::warn("[{}] DENIED delta response from {}:{} — sender is not a "
                      "cert-verified enrolled peer", name(),
                      sender.address().to_string(), sender.port());
        return;
    }

    try {
        auto j = json::parse(std::string_view{
            reinterpret_cast<const char*>(payload), payload_len});

        const auto endpoint_str = sender.address().to_string() + ":"
                                   + std::to_string(sender.port());
        auto peer_opt = find_peer_by_endpoint(sender);
        GossipPeer peer;
        if (peer_opt) {
            peer = *peer_opt;
        } else {
            peer.endpoint = endpoint_str;
        }

        do_handle_deltas(peer, j);

    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse delta response from {}:{}: {}",
                      name(), sender.address().to_string(), sender.port(), e.what());
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
            if (ipam_ && our_tunnel_ip_.empty()) hello["request_tunnel_ip"] = true;
            if (!our_region_.empty()) hello["region"] = our_region_;
            if (!our_advertised_endpoint_.empty())
                hello["advertised_endpoint"] = our_advertised_endpoint_;
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
// Misbehavior detection — equivocation proofs (dispositive auto-ban)
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

void GossipService::apply_ban(const std::string& pubkey, const MisbehaviorProof& proof) {
    const std::string pk = normalize_pubkey(pubkey);
    if (pk.empty() || is_revoked(pk)) return;  // idempotent

    // 1. Durable revocation — is_revoked now rejects all of this peer's certs, tokens
    //    and messages, across restarts (revoked_servers.json is reloaded on start).
    revoked_pubkeys_.push_back(pk);
    save_revoked_servers();

    // 2. Persist the proof as durable, independently-verifiable evidence.
    {
        storage::SignedEnvelope env;
        env.type = "misbehavior_proof";
        json pj = proof;
        env.data = pj.dump();
        env.timestamp = proof.observed_at;
        (void)storage_.write_file("misbehavior_proofs", proof.proof_id + ".json", env);
    }

    // 3. Drop the peer entry.
    do_remove_peer(pk);

    spdlog::warn("[{}] BANNED peer {} (proof {})", name(), pk, proof.proof_id);
}

void GossipService::broadcast_misbehavior_proof(const MisbehaviorProof& proof,
                                                const std::string& exclude_endpoint) {
    json j = proof;
    auto s = j.dump();
    std::vector<uint8_t> payload(s.begin(), s.end());

    std::lock_guard lock(peers_mutex_);
    for (const auto& peer : peers_) {
        if (!exclude_endpoint.empty() && peer.endpoint == exclude_endpoint) continue;
        if (auto ep = parse_endpoint(peer.endpoint)) {
            send_packet(*ep, GossipMsgType::MisbehaviorProofBroadcast, payload);
        }
    }
}

void GossipService::handle_misbehavior_proof(const asio::ip::udp::endpoint& sender,
                                             const uint8_t* payload, std::size_t payload_len) {
    MisbehaviorProof proof;
    try {
        proof = json::parse(std::string_view(reinterpret_cast<const char*>(payload), payload_len))
                    .get<MisbehaviorProof>();
    } catch (const std::exception& e) {
        spdlog::debug("[{}] malformed misbehavior proof from {}: {}",
                      name(), sender.address().to_string(), e.what());
        return;
    }

    // Dedupe: we may receive the same proof from many peers (epidemic spread).
    if (known_proofs_.count(proof.proof_id)) return;

    // DISPOSITIVE verification — trust ONLY the accused's own signatures, never the
    // reporter. A malicious relayer cannot forge this; an invalid proof dies here and
    // is never forwarded (verify-before-forward), so bad proofs cannot spread.
    if (!verify_misbehavior_proof(proof, crypto_)) {
        spdlog::warn("[{}] rejecting INVALID misbehavior proof {} from {}",
                      name(), proof.proof_id, sender.address().to_string());
        return;
    }

    known_proofs_[proof.proof_id] = static_cast<uint64_t>(chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count());

    spdlog::warn("[{}] verified misbehavior proof {} against {} — banning and re-gossiping",
                  name(), proof.proof_id, proof.accused_pubkey);
    apply_ban(proof.accused_pubkey, proof);

    // Re-broadcast to everyone except the peer we received it from (epidemic spread;
    // every honest node independently verifies, so convergence is guaranteed).
    std::string from = sender.address().to_string() + ":" + std::to_string(sender.port());
    broadcast_misbehavior_proof(proof, from);
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
            std::lock_guard lock(peers_mutex_);
            our_tunnel_ip_ = j["assigned_tunnel_ip"].get<std::string>();
            spdlog::info("[{}] received tunnel IP assignment: {}", name(), our_tunnel_ip_);
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
    std::lock_guard lock(peers_mutex_);
    preferred_ns_slot_ = slot > 9 ? 0 : slot;
}

void GossipService::set_ipam(ipam::IPAMService* ipam) {
    ipam_ = ipam;
}

void GossipService::set_boringtun(boringtun::BoringtunService* wg) {
    boringtun_ = wg;
}

std::string GossipService::our_tunnel_ip() const {
    std::lock_guard lock(peers_mutex_);
    return our_tunnel_ip_;
}

void GossipService::try_add_backbone_wg_peer(const GossipPeer& peer) {
    if (!boringtun_ || peer.wg_pubkey.empty() || peer.backbone_ip.empty()) return;

    // Build the backbone endpoint: use the peer's public endpoint IP + WG port (51940)
    std::string wg_endpoint;
    auto colon = peer.endpoint.rfind(':');
    if (colon != std::string::npos) {
        // Extract the IP from the gossip endpoint "ip:9102" and use port 51940
        wg_endpoint = peer.endpoint.substr(0, colon) + ":51940";
    }

    if (boringtun_->add_peer(peer.wg_pubkey, peer.backbone_ip + "/32", wg_endpoint)) {
        spdlog::info("[{}] added backbone WG peer {} ({}) endpoint={}",
                      name(), peer.backbone_ip, peer.pubkey.substr(0, 12), wg_endpoint);
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

            // If allocate operation, try to add as WG peer
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
                        try_add_backbone_wg_peer(peer);
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
    return our_ns_slot_;
}

std::vector<NsSlotClaimData> GossipService::get_ns_slots() const {
    std::lock_guard lock(peers_mutex_);
    std::vector<NsSlotClaimData> result;
    for (const auto& s : ns_slots_) {
        if (s.slot > 0) result.push_back(s);
    }
    return result;
}

void GossipService::try_claim_ns_slot(const std::string& our_public_ip) {
    std::lock_guard lock(peers_mutex_);

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

    NsSlotClaimData claim;
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

    spdlog::info("[{}] claimed NS slot ns{} (ip={}, region={})",
                  name(), chosen_slot, our_public_ip, our_region_);

    // Register in DNS
    register_ns_slot_in_dns(claim);

    // Broadcast to all peers
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

    // peers_mutex_ must already be held by callers, or we acquire it here
    // For broadcast from handle_ns_slot_claim we already hold the lock,
    // but for try_claim_ns_slot we also hold it. Use the peers_ directly.
    for (const auto& peer : peers_) {
        auto ep = parse_endpoint(peer.endpoint);
        if (ep) {
            send_packet(*ep, GossipMsgType::NsSlotClaim, payload);
        }
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

        std::lock_guard lock(peers_mutex_);

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

        spdlog::info("[{}] accepted NS slot claim: ns{} -> {} (ip={}, region={})",
                      name(), claim.slot, claim.server_pubkey, claim.server_ip, claim.region);

        // Register in DNS
        register_ns_slot_in_dns(claim);

        // Forward to all peers except sender (epidemic gossip)
        std::vector<uint8_t> fwd_payload(payload, payload + payload_len);
        for (const auto& peer : peers_) {
            auto ep = parse_endpoint(peer.endpoint);
            if (ep && *ep != sender) {
                send_packet(*ep, GossipMsgType::NsSlotClaim, fwd_payload);
            }
        }

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

                spdlog::info("[{}] re-claimed NS slot ns{} after losing ns{}",
                              name(), new_slot, claim.slot);

                register_ns_slot_in_dns(reclaim);
                broadcast_ns_slot_claim(reclaim);
            } else {
                spdlog::warn("[{}] all NS slots taken after losing ns{}, no slot available",
                              name(), claim.slot);
            }
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
