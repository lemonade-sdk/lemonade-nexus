#include <LemonadeNexus/Routing/RoutingCoordinationService.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>

#include <spdlog/spdlog.h>

#include <cctype>
#include <chrono>
#include <span>
#include <utility>

namespace nexus::routing {
namespace {

uint64_t now_seconds() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

bool is_wellformed_endpoint(const std::string& ep) {
    if (ep.empty() || ep.size() > 259) return false;
    auto pos = ep.rfind(':');
    if (pos == std::string::npos || pos == 0 || pos + 1 >= ep.size()) return false;
    for (std::size_t i = pos + 1; i < ep.size(); ++i) {
        if (!std::isdigit(static_cast<unsigned char>(ep[i]))) return false;
    }
    return true;
}

std::string host_of(const std::string& ep) {
    auto pos = ep.rfind(':');
    std::string host = (pos == std::string::npos) ? ep : ep.substr(0, pos);
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    return host;
}

// Self-reported candidates are kept only if well-formed; `verified` is set when
// the advertised host matches the observed control-connection source. M5 will
// replace this with a STUN-witnessed / echo round-trip on the UDP path and stop
// advertising unverified candidates to a peer.
std::vector<Candidate> make_candidates(const std::vector<std::string>& eps,
                                       const std::string& source_ip) {
    std::vector<Candidate> out;
    for (const auto& e : eps) {
        if (!is_wellformed_endpoint(e)) continue;
        out.push_back(Candidate{e, host_of(e) == source_ip});
    }
    return out;
}

} // namespace

RoutingCoordinationService::RoutingCoordinationService(crypto::SodiumCryptoService& crypto,
                                                       gossip::GossipService& gossip)
    : crypto_(crypto), gossip_(gossip) {}

void RoutingCoordinationService::on_start() {
    enabled_ = gossip_.has_root_pubkey();
    if (!enabled_) {
        spdlog::error("[{}] no root-of-trust pubkey configured — routed E2E DISABLED; "
                      "all /api/routing requests fail closed", name());
    } else {
        spdlog::info("[{}] started (routed E2E enabled)", name());
    }
}

void RoutingCoordinationService::on_stop() {
    std::lock_guard lock(mutex_);
    sessions_.clear();
    endpoints_.clear();
    pending_per_client_.clear();
    spdlog::info("[{}] stopped", name());
}

std::string RoutingCoordinationService::mint_connection_id() {
    std::array<uint8_t, 16> raw{};
    crypto_.random_bytes(std::span<uint8_t>(raw));
    return crypto::to_hex(std::span<const uint8_t>(raw));
}

void RoutingCoordinationService::reap_expired_locked(uint64_t now) {
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        if (it->second.expires_at != 0 && now >= it->second.expires_at) {
            auto pit = pending_per_client_.find(it->second.client_node_id);
            if (pit != pending_per_client_.end() && pit->second > 0) {
                if (--pit->second == 0) pending_per_client_.erase(pit);
            }
            it = sessions_.erase(it);
        } else {
            ++it;
        }
    }
}

void RoutingCoordinationService::register_endpoint(const EndpointRegistration& reg) {
    std::lock_guard lock(mutex_);
    auto& e = endpoints_[reg.node_id];
    e.node_id             = reg.node_id;
    e.endpoint_identifier = reg.endpoint_identifier;
    e.wg_pubkey           = reg.wg_pubkey;
    e.mgmt_pubkey         = reg.mgmt_pubkey;
    if (is_wellformed_endpoint(reg.stun_endpoint)) {
        e.reflexive = Candidate{reg.stun_endpoint,
                                host_of(reg.stun_endpoint) == reg.source_ip};
    }
    e.last_seen = now_seconds();
}

RequestResult RoutingCoordinationService::create_request(const ConnectionRequestInput& in) {
    if (!enabled_) return {false, "", "routing unavailable: no root of trust", 503};

    std::lock_guard lock(mutex_);
    const uint64_t now = now_seconds();
    reap_expired_locked(now);

    if (sessions_.size() >= kMaxTotalSessions) {
        return {false, "", "coordinator at capacity", 429};
    }
    auto& count = pending_per_client_[in.client_node_id];
    if (count >= kMaxPendingPerClient) {
        return {false, "", "too many in-flight connections", 429};
    }

    PendingSession s;
    s.connection_id       = mint_connection_id();
    s.client_node_id      = in.client_node_id;
    s.client_pubkey       = in.client_pubkey;
    s.client_wg_pub       = in.client_wg_pub;
    s.client_candidates   = make_candidates(in.candidates, in.source_ip);
    s.endpoint_node_id    = in.target_node_id;
    s.endpoint_identifier = in.target_identifier;
    s.conn_nonce          = in.conn_nonce;
    s.phase               = SessionPhase::Requested;
    s.created_at          = now;
    s.expires_at          = now + kSetupTtlSeconds;

    // Pre-fill the endpoint's identity hints if it already registered (the
    // endpoint discovers the request by polling, regardless of timing).
    if (auto eit = endpoints_.find(in.target_node_id); eit != endpoints_.end()) {
        s.endpoint_wg_pub      = eit->second.wg_pubkey;
        s.endpoint_mgmt_pubkey = eit->second.mgmt_pubkey;
    }

    const std::string cid = s.connection_id;
    ++count;
    sessions_[cid] = std::move(s);
    return {true, cid, "", 202};
}

bool RoutingCoordinationService::endpoint_ready(const EndpointReadyInput& in,
                                                std::string& err) {
    if (!enabled_) { err = "routing unavailable: no root of trust"; return false; }

    std::lock_guard lock(mutex_);
    reap_expired_locked(now_seconds());

    auto it = sessions_.find(in.connection_id);
    if (it == sessions_.end()) { err = "unknown connection"; return false; }
    auto& s = it->second;
    if (s.endpoint_node_id != in.endpoint_node_id) { err = "endpoint mismatch"; return false; }

    if (!in.endpoint_wg_pub.empty()) s.endpoint_wg_pub = in.endpoint_wg_pub;
    s.endpoint_candidates = make_candidates(in.candidates, in.source_ip);

    // Path selection: direct when both sides offered a candidate, else relay.
    // M3.5 lazily allocates the relay session + signs the ticket for the relay
    // path; until then relay_endpoint stays empty.
    const bool both_have = !s.client_candidates.empty() && !s.endpoint_candidates.empty();
    s.data_path = both_have ? DataPath::DirectP2P : DataPath::Relay;
    s.phase = SessionPhase::EndpointReady;
    return true;
}

std::optional<ClientDirective> RoutingCoordinationService::build_client_directive(
        const std::string& connection_id, const std::string& caller_node_id) {
    std::lock_guard lock(mutex_);
    reap_expired_locked(now_seconds());

    auto it = sessions_.find(connection_id);
    if (it == sessions_.end()) return std::nullopt;
    auto& s = it->second;
    if (s.client_node_id != caller_node_id) return std::nullopt;   // only the client
    if (s.phase != SessionPhase::EndpointReady &&
        s.phase != SessionPhase::ClientNotified) {
        return std::nullopt;                                       // endpoint not ready
    }

    ClientDirective d;
    d.connection_id        = s.connection_id;
    d.client_node_id       = s.client_node_id;
    d.endpoint_node_id     = s.endpoint_node_id;
    d.endpoint_identifier  = s.endpoint_identifier;
    d.endpoint_wg_pub      = s.endpoint_wg_pub;
    d.endpoint_mgmt_pubkey = s.endpoint_mgmt_pubkey;
    d.endpoint_candidates  = s.endpoint_candidates;
    d.conn_nonce           = s.conn_nonce;
    d.data_path            = s.data_path;
    d.relay_endpoint       = s.relay_endpoint;
    d.punch_at             = now_seconds() + 1;
    s.phase = SessionPhase::ClientNotified;
    return d;
}

std::optional<SessionView> RoutingCoordinationService::get_session(
        const std::string& connection_id, const std::string& caller_node_id) const {
    std::lock_guard lock(mutex_);
    auto it = sessions_.find(connection_id);
    if (it == sessions_.end()) return std::nullopt;
    const auto& s = it->second;
    if (s.client_node_id != caller_node_id && s.endpoint_node_id != caller_node_id) {
        return std::nullopt;                                       // not a participant
    }
    return SessionView{s.connection_id, s.phase, s.data_path, s.created_at, s.expires_at};
}

std::vector<std::string> RoutingCoordinationService::take_pending_for_endpoint(
        const std::string& endpoint_node_id) {
    std::lock_guard lock(mutex_);
    const uint64_t now = now_seconds();
    reap_expired_locked(now);

    // Scan for still-pending requests targeting this endpoint, independent of
    // when the endpoint registered. Idempotent — phase stays Requested until
    // the endpoint acknowledges via /endpoint/ready.
    std::vector<std::string> out;
    for (const auto& [cid, s] : sessions_) {
        if (s.endpoint_node_id == endpoint_node_id &&
            s.phase == SessionPhase::Requested) {
            out.push_back(cid);
        }
    }
    if (auto it = endpoints_.find(endpoint_node_id); it != endpoints_.end()) {
        it->second.last_seen = now;
    }
    return out;
}

} // namespace nexus::routing
