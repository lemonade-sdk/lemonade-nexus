#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Network/DnsService.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <memory>

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
}

void GossipService::set_root_pubkey(const crypto::Ed25519PublicKey& pk) {
    root_pubkey_ = pk;
    has_root_pubkey_ = true;
}

void GossipService::set_trust_policy(core::TrustPolicyService* policy) {
    trust_policy_ = policy;
    if (policy) {
        spdlog::info("[{}] zero-trust enforcement enabled (our tier: {})",
                      name(), policy->our_tier() == core::TrustTier::Tier1 ? "Tier1" : "Tier2");
    }
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

    // Zero-trust: attach our attestation token so the receiver can verify us
    if (trust_policy_ && trust_policy_->our_tier() == core::TrustTier::Tier1) {
        auto token = trust_policy_->generate_attestation_token(keypair_);
        json token_j = token;
        digest["attestation_token"] = std::move(token_j);
    }

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

    // Zero-trust: attach our attestation token
    if (trust_policy_ && trust_policy_->our_tier() == core::TrustTier::Tier1) {
        auto token = trust_policy_->generate_attestation_token(keypair_);
        json token_j = token;
        response["attestation_token"] = std::move(token_j);
    }

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
            handle_delta_response(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::AntiEntropy:
            handle_anti_entropy(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::PeerExchange:
            handle_peer_exchange(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::ServerHello:
            handle_server_hello(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::TeeChallenge:
            handle_tee_challenge(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::TeeResponse:
            handle_tee_response(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::EnrollmentVoteRequest:
            handle_enrollment_vote_request(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::EnrollmentVote:
            handle_enrollment_vote(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::RootKeyRotation:
            handle_root_key_rotation(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::ShamirShareOffer:
            handle_shamir_share_offer(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::ShamirShareSubmit:
            handle_shamir_share_submit(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::PeerHealthReport:
            handle_peer_health_report(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::GovernanceProposal:
            handle_governance_proposal(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::GovernanceVote:
            handle_governance_vote(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::AclDelta:
            handle_acl_delta(remote_endpoint_, payload, payload_len);
            break;
        case GossipMsgType::DnsRecordSync:
            handle_dns_record_sync(remote_endpoint_, payload, payload_len);
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
        // Zero-trust: verify attestation token before processing
        auto sender_pk = verify_message_trust(payload, payload_len,
                                               core::TrustOperation::GossipDigest);
        if (trust_policy_ && sender_pk.empty()) {
            spdlog::warn("[{}] DENIED digest from {}:{} — failed trust verification",
                          name(), sender.address().to_string(), sender.port());
            return;
        }

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
        // Zero-trust: verify attestation token
        auto sender_pk = verify_message_trust(payload, payload_len,
                                               core::TrustOperation::GossipDigest);
        if (trust_policy_ && sender_pk.empty()) {
            spdlog::warn("[{}] DENIED delta request from {}:{} — failed trust verification",
                          name(), sender.address().to_string(), sender.port());
            return;
        }

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
                                            const uint8_t* payload,
                                            std::size_t payload_len) {
    try {
        // Zero-trust: verify attestation token
        auto sender_pk = verify_message_trust(payload, payload_len,
                                               core::TrustOperation::GossipDigest);
        if (trust_policy_ && sender_pk.empty()) {
            spdlog::warn("[{}] DENIED delta response from {}:{} — failed trust verification",
                          name(), sender.address().to_string(), sender.port());
            return;
        }

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
        // Zero-trust: verify attestation token for peer exchange
        auto sender_pk = verify_message_trust(payload, payload_len,
                                               core::TrustOperation::GossipPeerExchange);
        if (trust_policy_ && sender_pk.empty()) {
            spdlog::warn("[{}] DENIED peer exchange from {}:{} — failed trust verification",
                          name(), sender.address().to_string(), sender.port());
            return;
        }

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
                peer_j["endpoint"]         = p.endpoint;
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
    // Zero-trust: expire stale peer trust states every tick
    if (trust_policy_) {
        trust_policy_->expire_stale_peers(core::TrustPolicyService::kTrustExpirationSec);
    }

    // Expire timed-out enrollment ballots
    if (enrollment_quorum_enabled_) {
        expire_enrollment_ballots();
    }

    // Governance: expire proposals and update Tier1 peer count
    if (governance_) {
        governance_->expire_proposals();
        uint32_t tier1_count = 0;
        {
            std::lock_guard lock(peers_mutex_);
            for (const auto& p : peers_) {
                if (p.trust_tier == core::TrustTier::Tier1) ++tier1_count;
            }
        }
        governance_->set_tier1_peer_count(tier1_count);
    }

    // Record peer health observations and check for root key rotation
    if (root_key_chain_) {
        record_peer_health_tick();

        // Check if root key was rotated — redistribute shares if so
        auto current_chain = root_key_chain_->chain();
        if (!current_chain.empty() && current_chain.back().generation > last_known_generation_) {
            last_known_generation_ = current_chain.back().generation;
            broadcast_root_key_rotation(current_chain.back());
            distribute_shamir_shares();
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
        chosen = peers_[dist(rng_)];
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
    peers_.clear();

    auto envelope = storage_.read_file("identity", "peers.json");
    if (!envelope) {
        spdlog::info("[{}] no peers.json found, starting with empty peer list", name());
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
            peer.pubkey           = p.value("pubkey", "");
            peer.endpoint         = p.value("endpoint", "");
            peer.http_port        = p.value("http_port", uint16_t{9100});
            peer.last_seen        = p.value("last_seen", uint64_t{0});
            peer.reputation       = p.value("reputation", 1.0f);
            peer.certificate_json = p.value("certificate_json", "");

            if (!peer.pubkey.empty() && !peer.endpoint.empty()) {
                peers_.push_back(std::move(peer));
            }
        }

        spdlog::info("[{}] loaded {} peers from storage", name(), peers_.size());

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
        peer_j["pubkey"]           = p.pubkey;
        peer_j["endpoint"]         = p.endpoint;
        peer_j["http_port"]        = p.http_port;
        peer_j["last_seen"]        = p.last_seen;
        peer_j["reputation"]       = p.reputation;
        peer_j["certificate_json"] = p.certificate_json;
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
    for (std::size_t i = 0; i < count; ++i) {
        std::uniform_int_distribution<std::size_t> dist(i, result.size() - 1);
        std::swap(result[i], result[dist(rng_)]);
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
            our_certificate_ = j.get<ServerCertificate>();
            spdlog::info("[{}] loaded server certificate (id: {})",
                          name(), our_certificate_->server_id);
        } catch (const std::exception& e) {
            spdlog::warn("[{}] failed to parse server certificate: {}", name(), e.what());
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
    if (!has_root_pubkey_) {
        // No root pubkey configured — skip certificate verification
        return true;
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

void GossipService::handle_server_hello(const asio::ip::udp::endpoint& sender,
                                          const uint8_t* payload,
                                          std::size_t payload_len) {
    try {
        auto j = json::parse(std::string_view{
            reinterpret_cast<const char*>(payload), payload_len});

        ServerCertificate cert = j.get<ServerCertificate>();

        if (!verify_server_certificate(cert)) {
            spdlog::warn("[{}] rejected ServerHello from {}:{} — invalid certificate",
                          name(), sender.address().to_string(), sender.port());
            return;
        }

        // Add or update peer with verified certificate
        auto pk = cert.server_pubkey;
        auto ep = sender.address().to_string() + ":" + std::to_string(sender.port());

        {
            std::lock_guard lock(peers_mutex_);
            auto it = std::find_if(peers_.begin(), peers_.end(),
                [&](const GossipPeer& p) { return p.pubkey == pk; });

            if (it != peers_.end()) {
                it->certificate_json = j.dump();
                it->last_seen = static_cast<uint64_t>(
                    chrono::system_clock::to_time_t(chrono::system_clock::now()));
            } else {
                GossipPeer peer;
                peer.pubkey           = pk;
                peer.endpoint         = ep;
                peer.http_port        = 9100; // will be updated via peer exchange
                peer.last_seen        = static_cast<uint64_t>(
                    chrono::system_clock::to_time_t(chrono::system_clock::now()));
                peer.reputation       = 1.0f;
                peer.certificate_json = j.dump();
                peers_.push_back(std::move(peer));
            }
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

        // After accepting a ServerHello, initiate TEE challenge for mutual verification
        if (trust_policy_) {
            // Set peer as Tier 2 (certificate-verified) initially
            trust_policy_->set_peer_tier2(pk);
            // Send TEE challenge to upgrade them to Tier 1
            send_tee_challenge(sender, pk);
        }

        // If quorum enrollment is enabled, start a vote before full admission
        if (enrollment_quorum_enabled_ && !j.value("is_response", false)) {
            // Check if we already have a pending enrollment for this pubkey
            std::lock_guard lock(peers_mutex_);
            bool already_pending = false;
            for (const auto& [rid, ballot] : pending_enrollments_) {
                if (ballot.candidate_pubkey == pk &&
                    ballot.state == EnrollmentBallot::State::Collecting) {
                    already_pending = true;
                    break;
                }
            }

            if (!already_pending) {
                // Generate a unique request ID
                std::array<uint8_t, 16> request_id_bytes{};
                crypto_.random_bytes(std::span<uint8_t>(request_id_bytes));
                auto request_id = crypto::to_hex(std::span<const uint8_t>(request_id_bytes));

                auto now = static_cast<uint64_t>(
                    chrono::system_clock::to_time_t(chrono::system_clock::now()));

                EnrollmentBallot ballot;
                ballot.request_id         = request_id;
                ballot.candidate_pubkey   = pk;
                ballot.candidate_server_id = cert.server_id;
                ballot.certificate_json   = j.dump();
                ballot.sponsor_pubkey     = crypto::to_base64(keypair_.public_key);
                ballot.created_at         = now;
                ballot.timeout_at         = now + enrollment_vote_timeout_sec_;

                pending_enrollments_[request_id] = ballot;

                spdlog::info("[{}] enrollment quorum started for '{}' (request: {})",
                              name(), cert.server_id, request_id.substr(0, 12));

                // Broadcast vote request to all peers
                broadcast_enrollment_vote_request(ballot);

                // We auto-vote approve since we verified the certificate
                cast_enrollment_vote(request_id, pk, true, "certificate_valid");
            }
        }
    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse ServerHello from {}:{}: {}",
                      name(), sender.address().to_string(), sender.port(), e.what());
    }
}

// ---------------------------------------------------------------------------
// Zero-trust: verify attestation token in incoming message payload
// ---------------------------------------------------------------------------

std::string GossipService::verify_message_trust(
    const uint8_t* payload, std::size_t payload_len,
    core::TrustOperation required_op) {

    if (!trust_policy_) {
        // Trust enforcement disabled — allow everything
        return "unverified";
    }

    try {
        auto j = json::parse(std::string_view{
            reinterpret_cast<const char*>(payload), payload_len});

        if (!j.contains("attestation_token")) {
            spdlog::debug("[{}] message missing attestation_token", name());
            return {};
        }

        auto token = j["attestation_token"].get<core::AttestationToken>();

        // Verify and update trust state through TrustPolicy
        auto tier = trust_policy_->verify_and_update(token.server_pubkey, token);

        // Check if the resulting tier allows the requested operation
        if (!core::is_operation_allowed(tier, required_op)) {
            spdlog::debug("[{}] peer {} has tier {} — insufficient for operation {}",
                           name(), token.server_pubkey.substr(0, 12) + "...",
                           static_cast<uint8_t>(tier),
                           static_cast<uint8_t>(required_op));
            return {};
        }

        return token.server_pubkey;

    } catch (const std::exception& e) {
        spdlog::debug("[{}] failed to parse attestation_token: {}", name(), e.what());
        return {};
    }
}

// ---------------------------------------------------------------------------
// TEE challenge/response — mutual verification
// ---------------------------------------------------------------------------

void GossipService::send_tee_challenge(const asio::ip::udp::endpoint& target,
                                        const std::string& peer_pubkey) {
    if (!trust_policy_) return;

    auto nonce = trust_policy_->challenge_peer(peer_pubkey);

    json challenge;
    challenge["nonce"] = crypto::to_base64(nonce);
    challenge["challenger_pubkey"] = crypto::to_base64(keypair_.public_key);

    auto payload_str = challenge.dump();
    std::vector<uint8_t> payload(payload_str.begin(), payload_str.end());

    send_packet(target, GossipMsgType::TeeChallenge, payload);
    spdlog::debug("[{}] sent TEE challenge to {}:{}", name(),
                   target.address().to_string(), target.port());
}

void GossipService::handle_tee_challenge(const asio::ip::udp::endpoint& sender,
                                          const uint8_t* payload,
                                          std::size_t payload_len) {
    if (!trust_policy_) return;

    try {
        auto j = json::parse(std::string_view{
            reinterpret_cast<const char*>(payload), payload_len});

        auto nonce_b64 = j.value("nonce", "");
        if (nonce_b64.empty()) return;

        auto nonce_bytes = crypto::from_base64(nonce_b64);
        if (nonce_bytes.size() != 32) return;

        std::array<uint8_t, 32> nonce{};
        std::memcpy(nonce.data(), nonce_bytes.data(), 32);

        // Generate our TEE attestation report bound to this nonce
        auto& tee = trust_policy_->tee_attestation_service();
        auto report = tee.generate_report(nonce);

        // Sign the report
        auto canonical = core::canonical_attestation_json(report);
        auto canonical_bytes = std::vector<uint8_t>(canonical.begin(), canonical.end());
        auto sig = crypto_.ed25519_sign(keypair_.private_key, canonical_bytes);
        report.signature = crypto::to_base64(sig);
        report.server_pubkey = crypto::to_base64(keypair_.public_key);

        // Send TEE response
        json response = report;
        auto payload_str = response.dump();
        std::vector<uint8_t> response_payload(payload_str.begin(), payload_str.end());

        send_packet(sender, GossipMsgType::TeeResponse, response_payload);
        spdlog::debug("[{}] sent TEE response to {}:{}", name(),
                       sender.address().to_string(), sender.port());

        // Also challenge them back (mutual verification)
        auto challenger_pk = j.value("challenger_pubkey", "");
        if (!challenger_pk.empty()) {
            send_tee_challenge(sender, challenger_pk);
        }

    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to handle TEE challenge from {}:{}: {}",
                      name(), sender.address().to_string(), sender.port(), e.what());
    }
}

void GossipService::handle_tee_response(const asio::ip::udp::endpoint& sender,
                                         const uint8_t* payload,
                                         std::size_t payload_len) {
    if (!trust_policy_) return;

    try {
        auto j = json::parse(std::string_view{
            reinterpret_cast<const char*>(payload), payload_len});

        auto report = j.get<core::TeeAttestationReport>();

        bool accepted = trust_policy_->handle_challenge_response(
            report.server_pubkey, report);

        if (accepted) {
            spdlog::info("[{}] peer {}:{} (pk: {}...) promoted to Tier1 via TEE challenge",
                          name(), sender.address().to_string(), sender.port(),
                          report.server_pubkey.substr(0, 12));

            // Update peer trust_tier in our peer list
            std::lock_guard lock(peers_mutex_);
            auto it = std::find_if(peers_.begin(), peers_.end(),
                [&](const GossipPeer& p) { return p.pubkey == report.server_pubkey; });
            if (it != peers_.end()) {
                it->trust_tier = core::TrustTier::Tier1;
            }
        } else {
            spdlog::warn("[{}] TEE challenge response from {}:{} failed verification",
                          name(), sender.address().to_string(), sender.port());
        }

    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to handle TEE response from {}:{}: {}",
                      name(), sender.address().to_string(), sender.port(), e.what());
    }
}

// ---------------------------------------------------------------------------
// Enrollment quorum
// ---------------------------------------------------------------------------

void GossipService::set_enrollment_config(bool enabled, float ratio,
                                            uint32_t timeout_sec, uint32_t max_retries) {
    std::lock_guard lock(peers_mutex_);
    enrollment_quorum_enabled_ = enabled;
    enrollment_quorum_ratio_   = std::clamp(ratio, 0.0f, 1.0f);
    enrollment_vote_timeout_sec_ = timeout_sec > 0 ? timeout_sec : 60;
    enrollment_max_retries_    = max_retries;

    if (enabled) {
        spdlog::info("[{}] enrollment quorum enabled (ratio={:.0f}%, timeout={}s, retries={})",
                      name(), ratio * 100.0f, timeout_sec, max_retries);
    }
}

std::vector<EnrollmentBallot> GossipService::pending_enrollments() const {
    std::lock_guard lock(peers_mutex_);
    std::vector<EnrollmentBallot> result;
    for (const auto& [id, ballot] : pending_enrollments_) {
        result.push_back(ballot);
    }
    return result;
}

void GossipService::broadcast_enrollment_vote_request(const EnrollmentBallot& ballot) {
    json request = {
        {"request_id",         ballot.request_id},
        {"candidate_pubkey",   ballot.candidate_pubkey},
        {"candidate_server_id", ballot.candidate_server_id},
        {"certificate",        json::parse(ballot.certificate_json)},
        {"sponsor_pubkey",     ballot.sponsor_pubkey},
        {"timestamp",          ballot.created_at},
    };

    // Attach our attestation token if we're Tier1
    if (trust_policy_ && trust_policy_->our_tier() == core::TrustTier::Tier1) {
        auto token = trust_policy_->generate_attestation_token(keypair_);
        request["attestation_token"] = token;
    }

    auto payload_str = request.dump();
    std::vector<uint8_t> payload_bytes(payload_str.begin(), payload_str.end());

    // Send to all known peers
    std::lock_guard lock(peers_mutex_);
    for (const auto& peer : peers_) {
        auto ep = parse_endpoint(peer.endpoint);
        if (ep) {
            send_packet(*ep, GossipMsgType::EnrollmentVoteRequest, payload_bytes);
        }
    }
}

void GossipService::cast_enrollment_vote(const std::string& request_id,
                                           const std::string& candidate_pubkey,
                                           bool approve, const std::string& reason) {
    auto now = static_cast<uint64_t>(
        chrono::system_clock::to_time_t(chrono::system_clock::now()));

    // Build canonical vote JSON for signing (sorted keys, excludes signature)
    json canonical_vote = {
        {"approve",          approve},
        {"candidate_pubkey", candidate_pubkey},
        {"reason",           reason},
        {"request_id",       request_id},
        {"timestamp",        now},
        {"voter_pubkey",     crypto::to_base64(keypair_.public_key)},
    };
    auto canonical_str = canonical_vote.dump();
    auto canonical_bytes = std::vector<uint8_t>(canonical_str.begin(), canonical_str.end());
    auto sig = crypto_.ed25519_sign(keypair_.private_key, canonical_bytes);

    EnrollmentVoteData vote;
    vote.request_id       = request_id;
    vote.candidate_pubkey = candidate_pubkey;
    vote.voter_pubkey     = crypto::to_base64(keypair_.public_key);
    vote.approve          = approve;
    vote.reason           = reason;
    vote.timestamp        = now;
    vote.signature        = crypto::to_base64(sig);

    // Add to our own ballot
    {
        std::lock_guard lock(peers_mutex_);
        auto it = pending_enrollments_.find(request_id);
        if (it != pending_enrollments_.end()) {
            it->second.votes.push_back(vote);
        }
    }

    // Broadcast the vote
    json vote_json = {
        {"request_id",       vote.request_id},
        {"candidate_pubkey", vote.candidate_pubkey},
        {"voter_pubkey",     vote.voter_pubkey},
        {"approve",          vote.approve},
        {"reason",           vote.reason},
        {"timestamp",        vote.timestamp},
        {"signature",        vote.signature},
    };
    auto payload_str = vote_json.dump();
    std::vector<uint8_t> payload_bytes(payload_str.begin(), payload_str.end());

    std::lock_guard lock(peers_mutex_);
    for (const auto& peer : peers_) {
        auto ep = parse_endpoint(peer.endpoint);
        if (ep) {
            send_packet(*ep, GossipMsgType::EnrollmentVote, payload_bytes);
        }
    }
}

void GossipService::handle_enrollment_vote_request(
    const asio::ip::udp::endpoint& sender,
    const uint8_t* payload, std::size_t payload_len)
{
    try {
        auto j = json::parse(std::string_view{
            reinterpret_cast<const char*>(payload), payload_len});

        auto request_id       = j.value("request_id", "");
        auto candidate_pubkey = j.value("candidate_pubkey", "");
        auto sponsor_pubkey   = j.value("sponsor_pubkey", "");

        if (request_id.empty() || candidate_pubkey.empty()) return;

        // Check if we already have this request
        {
            std::lock_guard lock(peers_mutex_);
            if (pending_enrollments_.contains(request_id)) return; // already seen
        }

        // Verify the sponsor's attestation token if trust is enabled
        if (trust_policy_) {
            if (j.contains("attestation_token")) {
                auto token = j["attestation_token"].get<core::AttestationToken>();
                auto tier = trust_policy_->verify_and_update(sponsor_pubkey, token);
                if (tier == core::TrustTier::Untrusted) {
                    spdlog::warn("[{}] enrollment vote request from untrusted sponsor {}",
                                  name(), sponsor_pubkey.substr(0, 12));
                    return;
                }
            }
        }

        // Independently verify the candidate's certificate
        bool cert_valid = false;
        std::string server_id;
        if (j.contains("certificate")) {
            try {
                ServerCertificate cert = j["certificate"].get<ServerCertificate>();
                cert_valid = verify_server_certificate(cert);
                server_id = cert.server_id;
            } catch (...) {}
        }

        // Store the ballot locally
        auto now = static_cast<uint64_t>(
            chrono::system_clock::to_time_t(chrono::system_clock::now()));

        {
            std::lock_guard lock(peers_mutex_);
            EnrollmentBallot ballot;
            ballot.request_id          = request_id;
            ballot.candidate_pubkey    = candidate_pubkey;
            ballot.candidate_server_id = server_id;
            ballot.certificate_json    = j.contains("certificate") ? j["certificate"].dump() : "";
            ballot.sponsor_pubkey      = sponsor_pubkey;
            ballot.created_at          = now;
            ballot.timeout_at          = now + enrollment_vote_timeout_sec_;
            pending_enrollments_[request_id] = ballot;
        }

        // Cast our vote
        cast_enrollment_vote(request_id, candidate_pubkey,
                              cert_valid, cert_valid ? "certificate_valid" : "cert_invalid");

        spdlog::info("[{}] received enrollment vote request for '{}' — voted {}",
                      name(), server_id.empty() ? candidate_pubkey.substr(0, 12) : server_id,
                      cert_valid ? "approve" : "reject");

    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse enrollment vote request: {}", name(), e.what());
    }
}

void GossipService::handle_enrollment_vote(
    const asio::ip::udp::endpoint& sender,
    const uint8_t* payload, std::size_t payload_len)
{
    try {
        auto j = json::parse(std::string_view{
            reinterpret_cast<const char*>(payload), payload_len});

        auto request_id       = j.value("request_id", "");
        auto candidate_pubkey = j.value("candidate_pubkey", "");
        auto voter_pubkey     = j.value("voter_pubkey", "");
        auto approve          = j.value("approve", false);
        auto reason           = j.value("reason", "");
        auto timestamp        = j.value("timestamp", uint64_t{0});
        auto signature        = j.value("signature", "");

        if (request_id.empty() || voter_pubkey.empty()) return;

        // Verify the vote signature
        json canonical_vote = {
            {"approve",          approve},
            {"candidate_pubkey", candidate_pubkey},
            {"reason",           reason},
            {"request_id",       request_id},
            {"timestamp",        timestamp},
            {"voter_pubkey",     voter_pubkey},
        };
        auto canonical_str = canonical_vote.dump();
        auto canonical_bytes = std::vector<uint8_t>(canonical_str.begin(), canonical_str.end());

        auto sig_bytes = crypto::from_base64(signature);
        auto pk_bytes = crypto::from_base64(voter_pubkey);
        if (sig_bytes.size() != crypto::kEd25519SignatureSize ||
            pk_bytes.size() != crypto::kEd25519PublicKeySize) {
            spdlog::warn("[{}] enrollment vote has invalid signature/pubkey size", name());
            return;
        }

        crypto::Ed25519PublicKey pk{};
        crypto::Ed25519Signature sig{};
        std::memcpy(pk.data(), pk_bytes.data(), pk_bytes.size());
        std::memcpy(sig.data(), sig_bytes.data(), sig_bytes.size());

        if (!crypto_.ed25519_verify(pk, canonical_bytes, sig)) {
            spdlog::warn("[{}] enrollment vote signature verification failed for voter {}",
                          name(), voter_pubkey.substr(0, 12));
            return;
        }

        // Only accept votes from Tier1 peers (if trust is enabled)
        if (trust_policy_) {
            auto tier = trust_policy_->peer_tier(voter_pubkey);
            if (tier != core::TrustTier::Tier1 && tier != core::TrustTier::Tier2) {
                spdlog::debug("[{}] ignoring vote from untrusted peer {}", name(), voter_pubkey.substr(0, 12));
                return;
            }
        }

        // Add vote to ballot
        {
            std::lock_guard lock(peers_mutex_);
            auto it = pending_enrollments_.find(request_id);
            if (it == pending_enrollments_.end()) return;
            if (it->second.state != EnrollmentBallot::State::Collecting) return;

            // Check for duplicate voter
            for (const auto& v : it->second.votes) {
                if (v.voter_pubkey == voter_pubkey) return; // already voted
            }

            EnrollmentVoteData vote;
            vote.request_id       = request_id;
            vote.candidate_pubkey = candidate_pubkey;
            vote.voter_pubkey     = voter_pubkey;
            vote.approve          = approve;
            vote.reason           = reason;
            vote.timestamp        = timestamp;
            vote.signature        = signature;
            it->second.votes.push_back(vote);
        }

        // Check quorum
        check_enrollment_quorum(request_id);

    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse enrollment vote: {}", name(), e.what());
    }
}

void GossipService::check_enrollment_quorum(const std::string& request_id) {
    std::lock_guard lock(peers_mutex_);
    auto it = pending_enrollments_.find(request_id);
    if (it == pending_enrollments_.end()) return;
    if (it->second.state != EnrollmentBallot::State::Collecting) return;

    auto& ballot = it->second;

    // Count Tier1 peers for quorum calculation
    uint32_t tier1_count = 0;
    if (trust_policy_) {
        auto states = trust_policy_->all_peer_states();
        for (const auto& s : states) {
            if (s.tier == core::TrustTier::Tier1) ++tier1_count;
        }
    } else {
        tier1_count = static_cast<uint32_t>(peers_.size());
    }

    // Genesis case: no peers = auto-approve
    if (tier1_count == 0) {
        ballot.state = EnrollmentBallot::State::Approved;
        spdlog::info("[{}] enrollment approved for '{}' (genesis — no peers)",
                      name(), ballot.candidate_server_id);
        return;
    }

    // Count approval votes
    uint32_t approve_count = 0;
    uint32_t reject_count = 0;
    for (const auto& v : ballot.votes) {
        if (v.approve) ++approve_count;
        else ++reject_count;
    }

    uint32_t needed = std::max(1u, static_cast<uint32_t>(
        std::ceil(static_cast<float>(tier1_count) * enrollment_quorum_ratio_)));

    if (approve_count >= needed) {
        ballot.state = EnrollmentBallot::State::Approved;
        spdlog::info("[{}] enrollment APPROVED for '{}' ({}/{} votes, needed {})",
                      name(), ballot.candidate_server_id,
                      approve_count, ballot.votes.size(), needed);
    } else if (reject_count > tier1_count - needed) {
        // Impossible to reach quorum even if all remaining vote approve
        ballot.state = EnrollmentBallot::State::Rejected;
        spdlog::warn("[{}] enrollment REJECTED for '{}' ({} rejections)",
                      name(), ballot.candidate_server_id, reject_count);
    }
}

void GossipService::expire_enrollment_ballots() {
    auto now = static_cast<uint64_t>(
        chrono::system_clock::to_time_t(chrono::system_clock::now()));

    std::lock_guard lock(peers_mutex_);
    for (auto& [id, ballot] : pending_enrollments_) {
        if (ballot.state != EnrollmentBallot::State::Collecting) continue;
        if (now < ballot.timeout_at) continue;

        if (ballot.retries < enrollment_max_retries_) {
            // Retry: extend timeout, re-broadcast
            ballot.retries++;
            ballot.timeout_at = now + enrollment_vote_timeout_sec_;
            spdlog::info("[{}] enrollment vote timeout for '{}', retry {}/{}",
                          name(), ballot.candidate_server_id,
                          ballot.retries, enrollment_max_retries_);
            // Re-broadcast will happen on next gossip tick
        } else {
            ballot.state = EnrollmentBallot::State::TimedOut;
            spdlog::warn("[{}] enrollment TIMED OUT for '{}' after {} retries",
                          name(), ballot.candidate_server_id, enrollment_max_retries_);
        }
    }
}

// ---------------------------------------------------------------------------
// Root Key Chain integration
// ---------------------------------------------------------------------------

void GossipService::set_root_key_chain(core::RootKeyChainService* chain) {
    root_key_chain_ = chain;
    if (chain) {
        auto current_chain = chain->chain();
        if (!current_chain.empty()) {
            last_known_generation_ = current_chain.back().generation;
        }
    }
}

void GossipService::set_governance(core::GovernanceService* governance) {
    governance_ = governance;
    if (governance) {
        // Wire the broadcast callback so GovernanceService can send gossip messages
        governance->set_broadcast_fn(
            [this](GossipMsgType type, const std::vector<uint8_t>& payload) {
                broadcast_governance_message(type, payload);
            });
        governance->set_keypair(keypair_);
        spdlog::info("[{}] democratic governance enabled", name());
    }
}

void GossipService::set_ipam(ipam::IPAMService* ipam) {
    ipam_ = ipam;
}

std::string GossipService::our_tunnel_ip() const {
    std::lock_guard lock(peers_mutex_);
    return our_tunnel_ip_;
}

// ---------------------------------------------------------------------------
// Peer health tracking — called every gossip tick
// ---------------------------------------------------------------------------

void GossipService::record_peer_health_tick() {
    if (!root_key_chain_) return;

    std::lock_guard lock(peers_mutex_);
    auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    for (const auto& peer : peers_) {
        // Peer "responded" if last_seen within the last 30 seconds (2x gossip interval)
        bool responded = (now - peer.last_seen) < 30;
        root_key_chain_->record_peer_check(peer.pubkey, responded);
    }
}

// ---------------------------------------------------------------------------
// Root key rotation handler
// ---------------------------------------------------------------------------

void GossipService::handle_root_key_rotation(const asio::ip::udp::endpoint& sender,
                                               const uint8_t* payload, std::size_t payload_len) {
    if (!root_key_chain_) return;

    // Only Tier1 peers can propagate rotations
    auto sender_peer = find_peer_by_endpoint(sender);
    if (!sender_peer || sender_peer->trust_tier != core::TrustTier::Tier1) {
        spdlog::warn("[{}] root key rotation from non-Tier1 peer, ignoring", name());
        return;
    }

    try {
        std::string json_str(reinterpret_cast<const char*>(payload), payload_len);
        auto j = nlohmann::json::parse(json_str);

        core::RootKeyEntry entry;
        entry.pubkey_hex = j.at("pubkey_hex").get<std::string>();
        entry.activated_at = j.at("activated_at").get<uint64_t>();
        entry.expires_at = j.value("expires_at", uint64_t{0});
        entry.generation = j.at("generation").get<uint32_t>();
        entry.signed_by_hex = j.at("signed_by_hex").get<std::string>();
        entry.endorsement_sig = j.at("endorsement_sig").get<std::string>();

        if (root_key_chain_->accept_rotation(entry)) {
            spdlog::info("[{}] accepted root key rotation to generation {} from {}",
                         name(), entry.generation, sender_peer->pubkey.substr(0, 12));
            last_known_generation_ = entry.generation;

            // Forward to all other peers
            broadcast_root_key_rotation(entry);
        }
    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse root key rotation: {}", name(), e.what());
    }
}

void GossipService::broadcast_root_key_rotation(const core::RootKeyEntry& entry) {
    nlohmann::json j = entry;
    auto json_str = j.dump();
    std::vector<uint8_t> payload(json_str.begin(), json_str.end());

    std::lock_guard lock(peers_mutex_);
    for (const auto& peer : peers_) {
        auto ep = parse_endpoint(peer.endpoint);
        if (ep) {
            send_packet(*ep, GossipMsgType::RootKeyRotation, payload);
        }
    }
}

// ---------------------------------------------------------------------------
// Shamir share distribution — encrypted per-peer via X25519
// ---------------------------------------------------------------------------

void GossipService::distribute_shamir_shares() {
    if (!root_key_chain_ || !root_key_chain_->has_root_private_key()) return;

    auto eligible = root_key_chain_->eligible_tier1_peers();
    if (eligible.size() < 2) {
        spdlog::info("[{}] not enough eligible Tier1 peers for Shamir split (have {})",
                     name(), eligible.size());
        return;
    }

    auto count = static_cast<uint8_t>(std::min<std::size_t>(eligible.size(), 255));
    auto shares = root_key_chain_->generate_shamir_shares(count);
    if (shares.empty()) return;

    auto threshold = root_key_chain_->compute_threshold(count);
    auto generation = root_key_chain_->chain().back().generation;

    spdlog::info("[{}] distributing {} Shamir shares (K={}) for generation {}",
                 name(), shares.size(), threshold, generation);

    std::lock_guard lock(peers_mutex_);
    std::size_t share_idx = 0;

    for (const auto& eligible_pubkey : eligible) {
        if (share_idx >= shares.size()) break;

        // Find the peer to get their endpoint
        for (const auto& peer : peers_) {
            if (peer.pubkey == eligible_pubkey) {
                auto ep = parse_endpoint(peer.endpoint);
                if (!ep) break;

                // Build share offer: encrypted share + metadata
                // The share is encrypted with X25519 DH between us and the recipient
                auto recipient_pk_bytes = crypto::from_base64(peer.pubkey);
                if (recipient_pk_bytes.size() != crypto::kEd25519PublicKeySize) break;

                crypto::Ed25519PublicKey recipient_ed_pk{};
                std::memcpy(recipient_ed_pk.data(), recipient_pk_bytes.data(),
                           recipient_pk_bytes.size());

                // Convert Ed25519 keys to X25519 for DH
                auto recipient_x_pk = crypto_.ed25519_pk_to_x25519(recipient_ed_pk);
                auto our_x_sk = crypto_.ed25519_sk_to_x25519(keypair_.private_key);
                auto shared_secret = crypto_.x25519_dh(our_x_sk, recipient_x_pk);

                // Derive encryption key from shared secret
                const std::string shamir_info = "shamir-share";
                auto enc_key = crypto_.hkdf_sha256(shared_secret, {},
                    std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(shamir_info.data()), shamir_info.size()), 32);
                crypto::AesGcmKey aes_key{};
                std::memcpy(aes_key.data(), enc_key.data(),
                           std::min(enc_key.size(), aes_key.size()));

                // Encrypt the share
                auto share_bytes = std::vector<uint8_t>(
                    shares[share_idx].begin(), shares[share_idx].end());
                auto encrypted = crypto_.aes_gcm_encrypt(aes_key, share_bytes, {});

                nlohmann::json offer = {
                    {"generation", generation},
                    {"threshold", threshold},
                    {"total_shares", count},
                    {"recipient_pubkey", peer.pubkey},
                    {"nonce", crypto::to_base64(encrypted.nonce)},
                    {"encrypted_share", crypto::to_base64(encrypted.ciphertext)},
                };

                auto offer_str = offer.dump();
                std::vector<uint8_t> payload(offer_str.begin(), offer_str.end());
                send_packet(*ep, GossipMsgType::ShamirShareOffer, payload);

                share_idx++;
                break;
            }
        }
    }

    spdlog::info("[{}] distributed {} Shamir shares to eligible Tier1 peers", name(), share_idx);
}

void GossipService::handle_shamir_share_offer(const asio::ip::udp::endpoint& sender,
                                                const uint8_t* payload, std::size_t payload_len) {
    if (!root_key_chain_) return;

    auto sender_peer = find_peer_by_endpoint(sender);
    if (!sender_peer || sender_peer->trust_tier != core::TrustTier::Tier1) {
        spdlog::warn("[{}] Shamir share offer from non-Tier1 peer, ignoring", name());
        return;
    }

    try {
        std::string json_str(reinterpret_cast<const char*>(payload), payload_len);
        auto j = nlohmann::json::parse(json_str);

        auto generation = j.at("generation").get<uint32_t>();
        auto recipient = j.at("recipient_pubkey").get<std::string>();

        // Verify this share is for us
        auto our_pubkey = crypto::to_base64(keypair_.public_key);
        if (recipient != our_pubkey) {
            spdlog::debug("[{}] Shamir share offer not for us, ignoring", name());
            return;
        }

        // Decrypt the share using X25519 DH
        auto sender_pk_bytes = crypto::from_base64(sender_peer->pubkey);
        crypto::Ed25519PublicKey sender_ed_pk{};
        std::memcpy(sender_ed_pk.data(), sender_pk_bytes.data(),
                   std::min(sender_pk_bytes.size(), sender_ed_pk.size()));

        auto sender_x_pk = crypto_.ed25519_pk_to_x25519(sender_ed_pk);
        auto our_x_sk = crypto_.ed25519_sk_to_x25519(keypair_.private_key);
        auto shared_secret = crypto_.x25519_dh(our_x_sk, sender_x_pk);

        const std::string shamir_info = "shamir-share";
        auto enc_key = crypto_.hkdf_sha256(shared_secret, {},
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(shamir_info.data()), shamir_info.size()), 32);
        crypto::AesGcmKey aes_key{};
        std::memcpy(aes_key.data(), enc_key.data(),
                   std::min(enc_key.size(), aes_key.size()));

        crypto::AesGcmCiphertext ct;
        ct.ciphertext = crypto::from_base64(j.at("encrypted_share").get<std::string>());
        ct.nonce = crypto::from_base64(j.at("nonce").get<std::string>());

        auto decrypted = crypto_.aes_gcm_decrypt(aes_key, ct, {});
        if (!decrypted) {
            spdlog::warn("[{}] failed to decrypt Shamir share from {}", name(),
                         sender_peer->pubkey.substr(0, 12));
            return;
        }

        std::string share_string(decrypted->begin(), decrypted->end());
        root_key_chain_->store_received_share(share_string, generation);

        spdlog::info("[{}] stored Shamir share for generation {} from {}",
                     name(), generation, sender_peer->pubkey.substr(0, 12));

    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to process Shamir share offer: {}", name(), e.what());
    }
}

// ---------------------------------------------------------------------------
// Shamir share submission — peers submit shares for reconstruction
// ---------------------------------------------------------------------------

void GossipService::handle_shamir_share_submit(const asio::ip::udp::endpoint& sender,
                                                 const uint8_t* payload, std::size_t payload_len) {
    if (!root_key_chain_) return;

    auto sender_peer = find_peer_by_endpoint(sender);
    if (!sender_peer || sender_peer->trust_tier != core::TrustTier::Tier1) {
        spdlog::warn("[{}] Shamir share submit from non-Tier1 peer, ignoring", name());
        return;
    }

    // Check uptime eligibility
    auto health = root_key_chain_->peer_health(sender_peer->pubkey);
    if (!health.qualifies_for_tier1()) {
        spdlog::warn("[{}] Shamir share submit from peer with insufficient uptime ({:.1f}%), ignoring",
                     name(), health.uptime_ratio * 100.0f);
        return;
    }

    try {
        std::string json_str(reinterpret_cast<const char*>(payload), payload_len);
        auto j = nlohmann::json::parse(json_str);

        auto generation = j.at("generation").get<uint32_t>();
        auto threshold = j.at("threshold").get<uint8_t>();
        auto share_string = j.at("share").get<std::string>();

        std::lock_guard lock(reconstruction_mutex_);
        reconstruction_threshold_ = threshold;
        reconstruction_shares_.push_back(share_string);

        spdlog::info("[{}] received Shamir share submission ({}/{}) for generation {}",
                     name(), reconstruction_shares_.size(), threshold, generation);

        // Try reconstruction if we have enough shares
        if (reconstruction_shares_.size() >= threshold) {
            spdlog::info("[{}] attempting root key reconstruction with {} shares",
                         name(), reconstruction_shares_.size());

            if (root_key_chain_->reconstruct_from_shares(reconstruction_shares_, threshold)) {
                spdlog::info("[{}] ROOT KEY RECONSTRUCTED — this node can now perform enrollments",
                             name());
                reconstruction_shares_.clear();
            } else {
                spdlog::error("[{}] root key reconstruction FAILED", name());
            }
        }
    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to process Shamir share submit: {}", name(), e.what());
    }
}

// ---------------------------------------------------------------------------
// Peer health report gossip — Tier1 peers share health observations
// ---------------------------------------------------------------------------

void GossipService::handle_peer_health_report(const asio::ip::udp::endpoint& sender,
                                                const uint8_t* payload, std::size_t payload_len) {
    if (!root_key_chain_) return;

    auto sender_peer = find_peer_by_endpoint(sender);
    if (!sender_peer || sender_peer->trust_tier != core::TrustTier::Tier1) {
        return; // Only Tier1 peers can report health
    }

    try {
        std::string json_str(reinterpret_cast<const char*>(payload), payload_len);
        auto j = nlohmann::json::parse(json_str);

        if (!j.contains("peers") || !j["peers"].is_array()) return;

        for (const auto& entry : j["peers"]) {
            auto pubkey = entry.at("pubkey").get<std::string>();
            auto uptime = entry.at("uptime_ratio").get<float>();
            auto total = entry.at("total_checks").get<uint64_t>();

            // Only incorporate reports from peers with significant data
            if (total < 50) continue;

            // Record as a single check result weighted by the reporter's observation
            bool healthy = uptime >= core::PeerHealthRecord::kMinTier1Uptime;
            root_key_chain_->record_peer_check(pubkey, healthy);
        }
    } catch (const std::exception& e) {
        spdlog::debug("[{}] failed to parse peer health report: {}", name(), e.what());
    }
}

void GossipService::broadcast_peer_health() {
    if (!root_key_chain_) return;

    auto all_health = root_key_chain_->all_peer_health();
    if (all_health.empty()) return;

    nlohmann::json peers_arr = nlohmann::json::array();
    for (const auto& h : all_health) {
        if (h.total_checks < 10) continue; // only share meaningful data
        peers_arr.push_back({
            {"pubkey", h.pubkey},
            {"uptime_ratio", h.uptime_ratio},
            {"total_checks", h.total_checks},
            {"last_check", h.last_check},
        });
    }

    if (peers_arr.empty()) return;

    nlohmann::json report = {{"peers", peers_arr}};
    auto report_str = report.dump();
    std::vector<uint8_t> payload(report_str.begin(), report_str.end());

    std::lock_guard lock(peers_mutex_);
    for (const auto& peer : peers_) {
        if (peer.trust_tier == core::TrustTier::Tier1) {
            auto ep = parse_endpoint(peer.endpoint);
            if (ep) {
                send_packet(*ep, GossipMsgType::PeerHealthReport, payload);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Democratic governance gossip handlers
// ---------------------------------------------------------------------------

void GossipService::handle_governance_proposal(const asio::ip::udp::endpoint& sender,
                                                 const uint8_t* payload, std::size_t payload_len) {
    if (!governance_) return;

    try {
        auto j = json::from_msgpack(payload, payload + payload_len);

        GovernanceProposalData proposal;
        proposal.proposal_id     = j.value("proposal_id", "");
        proposal.proposer_pubkey = j.value("proposer_pubkey", "");
        proposal.parameter       = static_cast<GovernableParam>(j.value("parameter", 0));
        proposal.new_value       = j.value("new_value", "");
        proposal.old_value       = j.value("old_value", "");
        proposal.rationale       = j.value("rationale", "");
        proposal.created_at      = j.value("created_at", uint64_t{0});
        proposal.expires_at      = j.value("expires_at", uint64_t{0});
        proposal.signature       = j.value("signature", "");

        if (governance_->handle_proposal(proposal)) {
            // Forward to all peers (epidemic spread)
            std::vector<uint8_t> fwd_payload(payload, payload + payload_len);
            std::lock_guard lock(peers_mutex_);
            for (const auto& peer : peers_) {
                auto ep = parse_endpoint(peer.endpoint);
                if (ep && *ep != sender) {
                    send_packet(*ep, GossipMsgType::GovernanceProposal, fwd_payload);
                }
            }
        }
    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse governance proposal: {}", name(), e.what());
    }
}

void GossipService::handle_governance_vote(const asio::ip::udp::endpoint& sender,
                                             const uint8_t* payload, std::size_t payload_len) {
    if (!governance_) return;

    try {
        auto j = json::from_msgpack(payload, payload + payload_len);

        GovernanceVoteData vote;
        vote.proposal_id  = j.value("proposal_id", "");
        vote.voter_pubkey = j.value("voter_pubkey", "");
        vote.approve      = j.value("approve", false);
        vote.reason       = j.value("reason", "");
        vote.timestamp    = j.value("timestamp", uint64_t{0});
        vote.signature    = j.value("signature", "");

        if (governance_->handle_vote(vote)) {
            // Forward to all peers
            std::vector<uint8_t> fwd_payload(payload, payload + payload_len);
            std::lock_guard lock(peers_mutex_);
            for (const auto& peer : peers_) {
                auto ep = parse_endpoint(peer.endpoint);
                if (ep && *ep != sender) {
                    send_packet(*ep, GossipMsgType::GovernanceVote, fwd_payload);
                }
            }
        }
    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse governance vote: {}", name(), e.what());
    }
}

void GossipService::broadcast_governance_message(GossipMsgType type,
                                                   const std::vector<uint8_t>& payload) {
    std::lock_guard lock(peers_mutex_);
    for (const auto& peer : peers_) {
        auto ep = parse_endpoint(peer.endpoint);
        if (ep) {
            send_packet(*ep, type, payload);
        }
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
                                      const uint8_t* payload, std::size_t payload_len) {
    if (!acl_) return;

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
    json j;
    j["delta_id"]      = delta.delta_id;
    j["operation"]     = delta.operation;
    j["fqdn"]          = delta.fqdn;
    j["record_type"]   = delta.record_type;
    j["value"]         = delta.value;
    j["ttl"]           = delta.ttl;
    j["timestamp"]     = delta.timestamp;
    j["signer_pubkey"] = delta.signer_pubkey;
    j["signature"]     = delta.signature;

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
                                             const uint8_t* payload, std::size_t payload_len) {
    if (!dns_) return;

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

} // namespace nexus::gossip
