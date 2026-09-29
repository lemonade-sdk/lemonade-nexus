#include <LemonadeNexus/Network/DnsService.hpp>
#include <LemonadeNexus/Network/SeipNaming.hpp>
#include <LemonadeNexus/Relay/GeoRegion.hpp>

#include <spdlog/spdlog.h>

#include <ares.h>
#include <ares_dns_record.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <set>
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include <chrono>
#include <cstring>
#include <deque>
#include <memory>
#include <random>
#include <sstream>

namespace nexus::network {

using asio::ip::udp;

namespace {

/// ASCII-lowercase a string (same per-character std::tolower semantics the
/// file used to apply inline).
std::string to_lower(std::string_view in) {
    std::string out(in);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
}

[[nodiscard]] bool ends_with(std::string_view s, std::string_view suffix) {
    return s.size() >= suffix.size() &&
           s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

[[nodiscard]] bool starts_with(std::string_view s, std::string_view prefix) {
    return s.size() >= prefix.size() &&
           s.compare(0, prefix.size(), prefix) == 0;
}

/// s with a trailing suffix removed; empty when s does not end with suffix.
[[nodiscard]] std::string_view strip_suffix(std::string_view s, std::string_view suffix) {
    return ends_with(s, suffix) ? std::string_view(s.data(), s.size() - suffix.size())
                                : std::string_view{};
}

/// Unix time in seconds (zone record timestamps).
[[nodiscard]] uint64_t now_seconds() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

/// RAII owner for a c-ares DNS record so the response builders cannot leak
/// a created record on a failure path.
class DnsRecordGuard {
public:
    explicit DnsRecordGuard(ares_dns_record_t* rec) : rec_(rec) {}
    ~DnsRecordGuard() { if (rec_) ares_dns_record_destroy(rec_); }
    DnsRecordGuard(const DnsRecordGuard&) = delete;
    DnsRecordGuard& operator=(const DnsRecordGuard&) = delete;

    ares_dns_record_t* get() const { return rec_; }

private:
    ares_dns_record_t* rec_;
};

}  // namespace

DnsService::DnsService(asio::io_context& io,
                         uint16_t port,
                         tree::PermissionTreeService& tree,
                         std::string base_domain)
    : socket_(io, udp::endpoint{udp::v4(), port})
    , tree_(tree)
    , base_domain_(std::move(base_domain))
{
    while (!base_domain_.empty() && base_domain_.front() == '.') {
        base_domain_.erase(base_domain_.begin());
    }
    // base_domain_ is immutable after construction (no setter), so the
    // lowercase copy can be cached for the lifetime of the service.
    base_domain_lower_ = to_lower(base_domain_);
    soa_email_ = "admin." + base_domain_;
}

DnsService::~DnsService() { on_stop(); }

void DnsService::on_start() {
    const uint16_t port = socket_.local_endpoint().port();
    start_receive();

    tcp_handler_ = std::make_shared<TcpQueryHandler>(
        [this, state = async_state_](const uint8_t* data, std::size_t bytes, const ResponseSink& reply) {
            std::lock_guard lock(state->mutex);
            if (state->stopped) return;
            handle_query(data, bytes, reply);
        });

    try {
        acceptor_.emplace(static_cast<asio::io_context&>(socket_.get_executor().context()),
                          asio::ip::tcp::endpoint{asio::ip::tcp::v4(), port});
        acceptor_->listen();
        start_accept();
        spdlog::info("[{}] listening on UDP and TCP port {} (zone: {})", name(), port,
                     base_domain_);
    } catch (const std::exception& e) {
        acceptor_.reset();
        spdlog::error("[{}] TCP listener on port {} failed: {} — UDP only, which is not "
                      "sufficient for an authoritative server", name(), port, e.what());
    }
}

uint16_t DnsService::local_port() const {
    asio::error_code ec;
    const auto ep = socket_.local_endpoint(ec);
    return ec ? 0 : ep.port();
}

void DnsService::on_stop() {
    // Wait for callbacks using the authority before destruction.
    std::lock_guard lock(async_state_->mutex);
    if (async_state_->stopped) return;
    async_state_->stopped = true;
    tcp_handler_.reset();
    for (const auto& session : async_state_->sessions) session.stop();
    async_state_->sessions.clear();

    asio::error_code ec;
    if (acceptor_) {
        acceptor_->close(ec);
        acceptor_.reset();
    }
    socket_.close(ec);
    spdlog::info("[{}] stopped", name());
}

void DnsService::start_receive() {
    socket_.async_receive_from(
        asio::buffer(async_state_->recv_buffer), async_state_->remote_endpoint,
        [this, state = async_state_](const asio::error_code& ec, std::size_t bytes) {
            std::lock_guard lock(state->mutex);
            if (state->stopped) return;
            if (!ec) {
                // The next receive overwrites the shared endpoint before send completion.
                const udp::endpoint peer = state->remote_endpoint;
                handle_query(state->recv_buffer.data(), bytes,
                             [this, peer](std::vector<uint8_t> resp) {
                                 auto buf =
                                     std::make_shared<std::vector<uint8_t>>(std::move(resp));
                                 socket_.async_send_to(
                                     asio::buffer(*buf), peer,
                                     [buf](const asio::error_code&, std::size_t) {});
                             });
                start_receive();
            } else if (ec != asio::error::operation_aborted) {
                spdlog::error("[{}] UDP receive error: {}", name(), ec.message());
            }
        });
}

namespace {

class DnsTcpSession : public std::enable_shared_from_this<DnsTcpSession> {
public:
    using Handler = std::function<void(const uint8_t*, std::size_t,
                                       const std::function<void(std::vector<uint8_t>)>&)>;

    DnsTcpSession(asio::ip::tcp::socket socket, std::weak_ptr<Handler> handler,
                  std::shared_ptr<std::atomic<int>> sessions)
        : strand_(socket.get_executor())
        , socket_(std::move(socket))
        , timer_(strand_)
        , handler_(std::move(handler))
        , sessions_(std::move(sessions)) {}

    ~DnsTcpSession() { sessions_->fetch_sub(1); }

    void start() {
        asio::dispatch(strand_, [self = shared_from_this()] {
            self->arm_idle_timer();
            self->read_length();
        });
    }

    void stop() {
        asio::dispatch(strand_, [self = shared_from_this()] { self->close(); });
    }

private:
    void close() {
        if (closed_) return;
        closed_ = true;
        asio::error_code ec;
        socket_.close(ec);
        timer_.cancel();
    }

    void arm_idle_timer() {
        if (closed_) return;
        timer_.expires_after(std::chrono::seconds(kDnsTcpIdleTimeoutSeconds));
        auto self = shared_from_this();
        timer_.async_wait(asio::bind_executor(strand_, [self](const asio::error_code& ec) {
            if (!ec && self->timer_.expiry() <= std::chrono::steady_clock::now()) self->close();
        }));
    }

    // Asio skips the condition on a full buffer; final handlers refresh too.
    auto refresh_on_progress() {
        return [self = shared_from_this()](const asio::error_code& ec, std::size_t bytes) {
            if (!ec && bytes != 0) self->arm_idle_timer();
            return asio::transfer_all()(ec, bytes);
        };
    }

    void read_length() {
        if (closed_) return;
        auto self = shared_from_this();
        asio::async_read(
            socket_, asio::buffer(length_prefix_), refresh_on_progress(),
            asio::bind_executor(strand_, [self](const asio::error_code& ec, std::size_t) {
                if (ec || self->closed_) { self->close(); return; }
                self->arm_idle_timer();
                const std::size_t declared =
                    (static_cast<std::size_t>(self->length_prefix_[0]) << 8) |
                    static_cast<std::size_t>(self->length_prefix_[1]);
                if (declared < kDnsMinMessageBytes || declared > kDnsTcpMaxMessageBytes) {
                    self->close();
                    return;
                }
                self->read_message(declared);
            }));
    }

    void read_message(std::size_t declared) {
        message_.assign(declared, 0);
        auto self = shared_from_this();
        asio::async_read(
            socket_, asio::buffer(message_), refresh_on_progress(),
            asio::bind_executor(strand_,
                                [self, declared](const asio::error_code& ec, std::size_t got) {
                                    if (ec || self->closed_ || got != declared) { self->close(); return; }
                                    self->arm_idle_timer();
                                    self->answer();
                                }));
    }

    void answer() {
        const auto handler = handler_.lock();
        if (!handler) { close(); return; }

        auto self = shared_from_this();
        bool replied = false;
        (*handler)(message_.data(), message_.size(),
                   [self, &replied](std::vector<uint8_t> resp) {
                       if (replied || resp.empty()) return;
                       replied = true;
                       self->enqueue_reply(std::move(resp));
                   });
        if (!replied) { close(); return; }

        if (write_queue_.size() >= kDnsTcpMaxQueuedResponses) {
            reads_paused_ = true;
            return;
        }
        read_length();
    }

    void enqueue_reply(std::vector<uint8_t> resp) {
        if (resp.size() > kDnsTcpMaxMessageBytes) { close(); return; }
        auto out = std::make_shared<std::vector<uint8_t>>();
        out->reserve(2 + resp.size());
        out->push_back(static_cast<uint8_t>((resp.size() >> 8) & 0xFF));
        out->push_back(static_cast<uint8_t>(resp.size() & 0xFF));
        out->insert(out->end(), resp.begin(), resp.end());
        write_queue_.push_back(std::move(out));
        if (!write_in_flight_) write_next();
    }

    // One write in flight preserves DNS frame boundaries (RFC 7766).
    void write_next() {
        if (closed_) return;
        if (write_queue_.empty()) { write_in_flight_ = false; return; }
        write_in_flight_ = true;
        auto out = write_queue_.front();
        auto self = shared_from_this();
        asio::async_write(
            socket_, asio::buffer(*out), refresh_on_progress(),
            asio::bind_executor(strand_, [self, out](const asio::error_code& ec, std::size_t) {
                self->write_queue_.pop_front();
                self->write_in_flight_ = false;
                if (ec || self->closed_) { self->close(); return; }
                self->arm_idle_timer();
                self->write_next();
                if (self->reads_paused_ &&
                    self->write_queue_.size() < kDnsTcpMaxQueuedResponses) {
                    self->reads_paused_ = false;
                    self->read_length();
                }
            }));
    }

    asio::strand<asio::any_io_executor> strand_;
    asio::ip::tcp::socket    socket_;
    asio::steady_timer       timer_;
    std::weak_ptr<Handler>   handler_;
    std::shared_ptr<std::atomic<int>> sessions_;
    std::array<uint8_t, 2>   length_prefix_{};
    std::vector<uint8_t>     message_;
    std::deque<std::shared_ptr<std::vector<uint8_t>>> write_queue_;
    bool                     write_in_flight_{false};
    bool                     reads_paused_{false};
    bool                     closed_{false};
};

}  // namespace

void DnsService::start_accept() {
    if (!acceptor_ || !tcp_handler_) return;
    acceptor_->async_accept([this, state = async_state_](const asio::error_code& ec, asio::ip::tcp::socket socket) {
        std::lock_guard lock(state->mutex);
        if (state->stopped) return;
        if (ec) {
            if (ec != asio::error::operation_aborted) {
                spdlog::error("[{}] TCP accept error: {}", name(), ec.message());
                start_accept();
            }
            return;
        }
        if (tcp_sessions_->load() >= kDnsTcpMaxSessions) {
            asio::error_code ignored;
            socket.close(ignored);
            spdlog::warn("[{}] TCP session limit ({}) reached; dropping connection", name(),
                         kDnsTcpMaxSessions);
        } else {
            tcp_sessions_->fetch_add(1);
            auto session = std::make_shared<DnsTcpSession>(std::move(socket),
                                            std::weak_ptr<TcpQueryHandler>(tcp_handler_),
                                            tcp_sessions_);
            std::erase_if(state->sessions, [](const auto& entry) { return entry.lifetime.expired(); });
            state->sessions.push_back({session, [weak = std::weak_ptr(session)] {
                if (auto live = weak.lock()) live->stop();
            }});
            session->start();
        }
        start_accept();
    });
}

namespace {

/// The "<tierlabel>.<region>" prefix of a tier wildcard name
/// ("tier<N>.<region>.seip.<base_domain>"), or empty when the name is not a
/// well-formed tier query: the tier label must be "tier" plus one or more
/// digits and the region must be a single DNS label. Shared by the tier A
/// and tier TXT aggregation branches so both apply identical validation.
std::string tier_wildcard_prefix(const std::string& query_lower,
                                 const std::string& base_lower) {
    const std::string seip_suffix = ".seip." + base_lower;
    if (query_lower.size() <= seip_suffix.size() ||
        !ends_with(query_lower, seip_suffix)) {
        return {};
    }
    const std::string prefix = std::string(strip_suffix(query_lower, seip_suffix));
    const auto dot = prefix.find('.');
    if (dot == std::string::npos || dot <= 4 ||
        prefix.find('.', dot + 1) != std::string::npos ||
        prefix.rfind("tier", 0) != 0) {
        return {};
    }
    for (std::size_t i = 4; i < dot; ++i) {
        if (!std::isdigit(static_cast<unsigned char>(prefix[i]))) return {};
    }
    return prefix;
}

}  // namespace

namespace {

/// Parse a received DNS packet exactly once. Returns false — meaning: send no
/// response — when the packet is too short, unparseable, is a response rather
/// than a query, has no question, or has no qname (the same conditions
/// handle_query used to check inline, in the same order).
bool parse_dns_query(const uint8_t* data, std::size_t bytes, ParsedQuery& out) {
    if (bytes < kDnsMinMessageBytes) return false; // Too short for DNS header

    // Parse the query using c-ares
    ares_dns_record_t* dnsrec = nullptr;
    ares_status_t status = ares_dns_parse(data, bytes, 0, &dnsrec);
    if (status != ARES_SUCCESS || !dnsrec) {
        return false;
    }
    DnsRecordGuard guard(dnsrec);

    // Only handle standard queries
    if (ares_dns_record_get_flags(dnsrec) & ARES_FLAG_QR) {
        return false; // Not a query
    }

    // Get the first question
    if (ares_dns_record_query_cnt(dnsrec) == 0) {
        return false;
    }

    const char* qname_ptr = nullptr;
    ares_dns_rec_type_t qtype = ARES_REC_TYPE_A;
    ares_dns_class_t qclass = ARES_CLASS_IN;
    ares_dns_record_query_get(dnsrec, 0, &qname_ptr, &qtype, &qclass);

    if (!qname_ptr) {
        return false;
    }

    out.qname = qname_ptr;

    // Normalize query: lowercase + strip trailing dot
    out.qname_lower = to_lower(qname_ptr);
    if (!out.qname_lower.empty() && out.qname_lower.back() == '.') {
        out.qname_lower.pop_back();
    }

    out.qtype = qtype;
    out.qclass = qclass;
    out.id = ares_dns_record_get_id(dnsrec);
    return true;
}

}  // namespace

void DnsService::handle_query(const uint8_t* data, std::size_t bytes,
                              const ResponseSink& send_response) {
    ParsedQuery q;
    if (!parse_dns_query(data, bytes, q)) return;

    // Branch dispatch order is a wire contract — do not reorder. Each branch
    // consumes its qtype/qclass combination and never falls through:
    //   1. SOA (IN)   — apex SOA, else NXDOMAIN
    //   2. NS  (IN)   — apex NS, else NXDOMAIN
    //   3. TXT (IN)   — dynamic TXT → _config TXT → tier+region wildcard TXT
    //                    → NXDOMAIN
    //   4. A   (IN)   — zone apex → tier+region wildcard multi-A → region
    //                    wildcard multi-A → dynamic A → tree resolve → NXDOMAIN
    //   5. anything else → NXDOMAIN
    if (q.qtype == ARES_REC_TYPE_SOA && q.qclass == ARES_CLASS_IN) {
        answer_soa_query(q, send_response);
        return;
    }

    if (q.qtype == ARES_REC_TYPE_NS && q.qclass == ARES_CLASS_IN) {
        answer_ns_query(q, send_response);
        return;
    }

    if (q.qtype == ARES_REC_TYPE_TXT && q.qclass == ARES_CLASS_IN) {
        answer_txt_query(q, send_response);
        return;
    }

    if (q.qtype == ARES_REC_TYPE_A && q.qclass == ARES_CLASS_IN) {
        answer_a_query(q, send_response);
        return;
    }

    // --- Unsupported query type ---
    send_response(build_nxdomain(q));
}

void DnsService::answer_soa_query(const ParsedQuery& q, const ResponseSink& send) {
    if (q.qname_lower == base_domain_lower_) {
        auto resp = build_soa_response(q);
        if (!resp.empty()) {
            spdlog::debug("[{}] SOA {} -> serial {}", name(), q.qname, soa_serial_.load());
            send(std::move(resp));
            return;
        }
    }
    send(build_nxdomain(q));
}

void DnsService::answer_ns_query(const ParsedQuery& q, const ResponseSink& send) {
    if (q.qname_lower == base_domain_lower_) {
        auto resp = build_ns_response(q);
        if (!resp.empty()) {
            spdlog::debug("[{}] NS {} -> nameservers", name(), q.qname);
            send(std::move(resp));
            return;
        }
    }
    send(build_nxdomain(q));
}

void DnsService::answer_txt_query(const ParsedQuery& q, const ResponseSink& send) {
    // 1. Check dynamic TXT records (ACME challenges, etc.)
    auto dyn_txt = lookup_dynamic_txt(q.qname_lower);
    if (dyn_txt) {
        spdlog::debug("[{}] TXT {} -> {} (dynamic)", name(), q.qname, *dyn_txt);
        send(build_txt_response(q, *dyn_txt, 60));
        return;
    }

    // 2. Check _config. subdomain (per-server port config, gossip-synced)
    const std::string suffix = "." + base_domain_lower_;
    if (q.qname_lower.size() > suffix.size() &&
        ends_with(q.qname_lower, suffix)) {
        std::string prefix = std::string(strip_suffix(q.qname_lower, suffix));
        if (starts_with(prefix, "_config.")) {
            std::string hostname = prefix.substr(8); // strip "_config."
            auto txt = resolve_config_txt(hostname);
            if (txt) {
                spdlog::debug("[{}] TXT {} -> {}", name(), q.qname, *txt);
                send(build_txt_response(q, *txt, 300));
                return;
            }
        }
    }

    // 3. Tier+region wildcard TXT: tier<N>.<region>.seip.<base_domain> ->
    // "v=sp1 host=<id>.<region>.seip.<base_domain> ..." listing every
    // member's SEIP FQDN. Members are the servers that published
    // per-server tier A records (<id>.tier<N>.<region>.seip.<base>);
    // each member FQDN is the record key with the tier label stripped.
    // Onboarding probes those FQDNs because the ACME certificate covers
    // them — the tier name is never covered, so probing it would fail
    // hostname verification.
    if (auto prefix = tier_wildcard_prefix(q.qname_lower, base_domain_lower_);
        !prefix.empty()) {
        const std::string match_suffix =
            "." + prefix + ".seip." + base_domain_lower_;  // ".tier<N>.<region>.seip.<base>"
        // ".<region>.seip.<base>" — everything after "<tierlabel>.". The tier
        // label ends at prefix.find('.') (the dot before the region label),
        // so skip 1 (leading dot) + label length = dot + 1 characters.
        const std::string fqdn_suffix = match_suffix.substr(prefix.find('.') + 1);
        std::set<std::string> members;
        for (const auto& id : scan_a_prefixes(match_suffix)) {
            members.insert(id + fqdn_suffix);
        }
        if (!members.empty()) {
            std::string txt = "v=sp1";
            for (const auto& member : members) txt += " host=" + member;
            spdlog::debug("[{}] TXT {} -> {} tier member(s)",
                           name(), q.qname, members.size());
            send(build_txt_response(q, txt, 300));
            return;
        }
        // No servers for this tier+region — fall through to NXDOMAIN.
    }

    spdlog::debug("[{}] TXT {} -> NXDOMAIN", name(), q.qname);
    send(build_nxdomain(q));
}

void DnsService::answer_a_query(const ParsedQuery& q, const ResponseSink& send) {
    // 0. Zone apex: return our own IP so getaddrinfo(base_domain) works
    if (q.qname_lower == base_domain_lower_ && !our_ns_ip_.empty()) {
        spdlog::debug("[{}] {} -> {} (zone apex)", name(), q.qname, our_ns_ip_);
        send(build_response(q, our_ns_ip_, 300));
        return;
    }

    // 0b. Tier+region wildcard: tier<N>.<region>.seip.<base_domain> -> multi-A.
    // Aggregates per-server records <id>.tier<N>.<region>.seip.<base_domain> so a
    // bootstrapping node can resolve all servers of a given tier in a region.
    // More specific than the plain region wildcard below, so checked first.
    if (auto prefix = tier_wildcard_prefix(q.qname_lower, base_domain_lower_);
        !prefix.empty()) {
        std::string match_suffix = "." + q.qname_lower;  // ".tier<N>.<region>.seip.<base>"
        std::set<std::string> ipset = scan_a_values(match_suffix);
        if (!ipset.empty()) {
            std::vector<std::string> ips(ipset.begin(), ipset.end());
            spdlog::debug("[{}] {} -> {} tier A records",
                           name(), q.qname, ips.size());
            send(build_multi_a_response(q, ips, 300));
            return;
        }
        // No servers for this tier+region — fall through to NXDOMAIN.
    }

    // 1. SEIP region-wildcard: <region>.seip.<base_domain> -> multi-A response
    {
        std::string seip_suffix = ".seip." + base_domain_lower_;
        if (q.qname_lower.size() > seip_suffix.size() &&
            ends_with(q.qname_lower, seip_suffix)) {
            std::string region_part = std::string(strip_suffix(q.qname_lower, seip_suffix));
            // Only match if region_part has no dots (i.e. it's just "<region>", not "<id>.<region>")
            if (region_part.find('.') == std::string::npos) {
                // Collect all A records for servers in this region. This also picks up
                // per-server tier records (<id>.tier<N>.<region>.seip.<base>), so dedupe
                // by IP to avoid a server appearing twice (plain SEIP + tier record).
                std::string match_suffix = "." + region_part + ".seip." + base_domain_lower_;
                std::set<std::string> ipset = scan_a_values(match_suffix);
                if (!ipset.empty()) {
                    std::vector<std::string> ips(ipset.begin(), ipset.end());
                    spdlog::debug("[{}] {} -> {} SEIP A records (region {})",
                                   name(), q.qname, ips.size(), region_part);
                    send(build_multi_a_response(q, ips, 300));
                    return;
                }
                // No servers in this region — fall through to NXDOMAIN
            }
        }
    }

    // 2. Check dynamic A records (NS glue records, etc.)
    auto dyn_a = lookup_dynamic_a(q.qname_lower);
    if (dyn_a) {
        spdlog::debug("[{}] {} -> {} (dynamic)", name(), q.qname, *dyn_a);
        send(build_response(q, *dyn_a, 60));
        return;
    }

    // 3. Tree-based resolution
    auto record = do_resolve(q.qname);
    if (record) {
        spdlog::debug("[{}] {} -> {}", name(), q.qname, record->ipv4_address);
        send(build_response(q, record->ipv4_address, record->ttl));
        return;
    }

    spdlog::debug("[{}] {} -> NXDOMAIN", name(), q.qname);
    send(build_nxdomain(q));
}

std::set<std::string> DnsService::scan_a_values(std::string_view suffix) const {
    std::set<std::string> values;
    std::lock_guard<std::mutex> lock(zone_mutex_);
    for (const auto& [key, rec] : zone_records_) {
        if (!starts_with(key, "A:") || key.size() <= 2 + suffix.size() ||
            !ends_with(key, suffix)) {
            continue;
        }
        values.insert(rec.value);
    }
    return values;
}

std::set<std::string> DnsService::scan_a_prefixes(std::string_view suffix) const {
    std::set<std::string> prefixes;
    std::lock_guard<std::mutex> lock(zone_mutex_);
    for (const auto& [key, rec] : zone_records_) {
        if (!starts_with(key, "A:") || key.size() <= 2 + suffix.size() ||
            !ends_with(key, suffix)) {
            continue;
        }
        prefixes.insert(key.substr(2, key.size() - (2 + suffix.size())));
    }
    return prefixes;
}

// ---------------------------------------------------------------------------
// IDnsProvider: resolve a hostname against the tree
// ---------------------------------------------------------------------------

std::optional<DnsRecord> DnsService::do_resolve(const std::string& fqdn) {
    // Lowercase the input
    std::string query = to_lower(fqdn);

    // Strip trailing dot
    if (!query.empty() && query.back() == '.') {
        query.pop_back();
    }

    // Check if query ends with .<base_domain>
    std::string suffix = "." + base_domain_lower_;
    if (query.size() <= suffix.size() || !ends_with(query, suffix)) {
        return std::nullopt; // Not in our zone
    }

    // Strip the base domain suffix
    // e.g. "my-laptop.ep.lemonade-nexus.io" -> "my-laptop.ep"
    std::string prefix = std::string(strip_suffix(query, suffix));

    // Check for SEIP subdomain: <id>.<region>.seip
    // This handles: server1.us-west.seip.lemonade-nexus.io -> specific server A record
    {
        const std::string seip_tag = ".seip";
        if (prefix.size() > seip_tag.size() && ends_with(prefix, seip_tag)) {
            // prefix is "<id>.<region>.seip" or "<region>.seip"

            // Look up the specific dynamic A record
            std::string a_fqdn = query; // full fqdn
            auto dyn_a = lookup_dynamic_a(a_fqdn);
            if (dyn_a) {
                DnsRecord rec;
                rec.name = fqdn;
                rec.ipv4_address = *dyn_a;
                rec.ttl = 300;
                return rec;
            }
            return std::nullopt;
        }
    }

    // Check for "relays" subdomain: <hostname>.[region.]relays
    // This handles: relay1.us-ca.relays.lemonade-nexus.io
    //               relay1.relays.lemonade-nexus.io
    {
        const std::string relays_tag = ".relays";
        if (prefix.size() > relays_tag.size() && ends_with(prefix, relays_tag)) {
            std::string relay_prefix = std::string(strip_suffix(prefix, relays_tag));
            auto result = resolve_relay_subdomain(relay_prefix);
            if (result) {
                result->name = fqdn;
            }
            return result;
        }
    }

    // Split prefix by dots
    std::vector<std::string> parts;
    std::istringstream iss(prefix);
    std::string part;
    while (std::getline(iss, part, '.')) {
        if (!part.empty()) parts.push_back(part);
    }

    if (parts.empty()) return std::nullopt;

    std::string hostname;
    std::optional<tree::NodeType> type_filter;

    if (parts.size() >= 2) {
        // Last part might be a type qualifier
        type_filter = type_qualifier_to_node_type(parts.back());
        if (type_filter) {
            hostname = parts[0];
            for (std::size_t i = 1; i + 1 < parts.size(); ++i) {
                hostname += "." + parts[i];
            }
        } else {
            hostname = prefix;
        }
    } else {
        hostname = parts[0];
    }

    hostname = to_lower(hostname);

    // Search types in priority order
    auto search_types = std::vector<tree::NodeType>{
        tree::NodeType::Endpoint,
        tree::NodeType::Root,
        tree::NodeType::Customer,
        tree::NodeType::Relay,
    };

    if (type_filter) {
        search_types = {*type_filter};
    }

    for (auto node_type : search_types) {
        auto nodes = tree_.get_nodes_by_type(node_type);
        for (const auto& node : nodes) {
            std::string node_hostname = to_lower(node.hostname);

            if (node_hostname == hostname && !node.tunnel_ip.empty()) {
                std::string ip = strip_cidr(node.tunnel_ip);
                if (!ip.empty()) {
                    DnsRecord rec;
                    rec.name = fqdn;
                    rec.ipv4_address = ip;
                    rec.ttl = 60;
                    return rec;
                }
            }
        }
    }

    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Relay subdomain resolution
// ---------------------------------------------------------------------------

std::optional<DnsRecord> DnsService::resolve_relay_subdomain(
    const std::string& prefix) {

    // prefix is everything before ".relays"
    // e.g. "relay1.us-ca" or "relay1"
    std::vector<std::string> parts;
    std::istringstream iss(prefix);
    std::string part;
    while (std::getline(iss, part, '.')) {
        if (!part.empty()) parts.push_back(part);
    }

    if (parts.empty()) return std::nullopt;

    std::string hostname;
    std::string region_filter;

    if (parts.size() >= 2) {
        // Check if last part is a valid region code
        if (relay::GeoRegion::is_valid_region(parts.back())) {
            region_filter = parts.back();
            hostname = parts[0];
            for (std::size_t i = 1; i + 1 < parts.size(); ++i) {
                hostname += "." + parts[i];
            }
        } else {
            // Treat entire prefix as hostname
            hostname = prefix;
        }
    } else {
        hostname = parts[0];
    }

    hostname = to_lower(hostname);
    region_filter = to_lower(region_filter);

    // Search only relay nodes
    auto nodes = tree_.get_nodes_by_type(tree::NodeType::Relay);
    for (const auto& node : nodes) {
        std::string node_hostname = to_lower(node.hostname);

        if (node_hostname != hostname) continue;
        if (node.tunnel_ip.empty()) continue;

        // If region filter is specified, check the node's region
        if (!region_filter.empty()) {
            std::string node_region = to_lower(node.region);
            if (node_region != region_filter) continue;
        }

        std::string ip = strip_cidr(node.tunnel_ip);
        if (!ip.empty()) {
            DnsRecord rec;
            rec.ipv4_address = ip;
            rec.ttl = 60;
            return rec;
        }
    }

    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Type qualifier mapping
// ---------------------------------------------------------------------------

std::optional<tree::NodeType> DnsService::type_qualifier_to_node_type(
    std::string_view qualifier) {
    if (qualifier == "ep" || qualifier == "endpoint") return tree::NodeType::Endpoint;
    if (qualifier == "capi" || qualifier == "client")  return tree::NodeType::Endpoint;
    if (qualifier == "srv" || qualifier == "server")   return tree::NodeType::Root;
    if (qualifier == "relay")                           return tree::NodeType::Relay;
    if (qualifier == "cust" || qualifier == "customer") return tree::NodeType::Customer;
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// Port config for TXT records
// ---------------------------------------------------------------------------

void DnsService::set_port_config(const PortConfig& config) {
    port_config_ = config;
    has_port_config_ = true;
}

void DnsService::publish_port_config(const std::string& server_id, const std::string& server_fqdn) {
    if (!has_port_config_ || server_id.empty()) return;

    std::string fqdn = "_config." + server_id + "." + base_domain_;
    // "v=sp1" TXT body is shared with build_port_config_txt(); an empty
    // server_fqdn omits the trailing " host=..." field.
    std::string txt = build_port_config_txt(port_config_.region, server_fqdn,
                                            port_config_.connected_clients);

    // Publish as a dynamic TXT record — gossip callback broadcasts to peers
    set_record(fqdn, "TXT", txt, 300);
    spdlog::info("[{}] published _config record: {} -> {}", name(), fqdn, txt);
}

std::optional<std::string> DnsService::resolve_config_txt(
    const std::string& hostname) {

    // Check for SEIP _config queries: <id>.<region>.seip
    // These are stored as dynamic TXT records, not in the permission tree.
    {
        std::string host_lower_check = to_lower(hostname);

        // If the hostname ends with ".seip", look up the dynamic TXT record
        const std::string seip_tag = ".seip";
        if (host_lower_check.size() > seip_tag.size() &&
            ends_with(host_lower_check, seip_tag)) {
            // "_config.<id>.<region>.seip.<base>": host_lower_check is one
            // opaque "<id>.<region>.seip" string that cannot be split into
            // (id, region) without assuming a single-label id, so the
            // "_config." + hostname + "." + base concatenation is kept.
            std::string txt_fqdn =
                to_lower("_config." + host_lower_check + "." + base_domain_);
            return lookup_dynamic_txt(txt_fqdn);
        }
    }

    if (!has_port_config_) return std::nullopt;

    // Verify the hostname exists in the tree (any node type)
    std::string host_lower = to_lower(hostname);

    // Check for a type qualifier (e.g. config_.my-laptop.ep)
    std::vector<std::string> parts;
    std::istringstream iss(host_lower);
    std::string part;
    while (std::getline(iss, part, '.')) {
        if (!part.empty()) parts.push_back(part);
    }

    if (parts.empty()) return std::nullopt;

    std::string search_hostname;
    std::optional<tree::NodeType> type_filter;

    if (parts.size() >= 2) {
        type_filter = type_qualifier_to_node_type(parts.back());
        if (type_filter) {
            search_hostname = parts[0];
            for (std::size_t i = 1; i + 1 < parts.size(); ++i) {
                search_hostname += "." + parts[i];
            }
        } else {
            search_hostname = host_lower;
        }
    } else {
        search_hostname = parts[0];
    }

    // Search for matching node
    auto search_types = std::vector<tree::NodeType>{
        tree::NodeType::Endpoint,
        tree::NodeType::Root,
        tree::NodeType::Customer,
        tree::NodeType::Relay,
    };

    if (type_filter) {
        search_types = {*type_filter};
    }

    for (auto node_type : search_types) {
        auto nodes = tree_.get_nodes_by_type(node_type);
        for (const auto& node : nodes) {
            std::string node_hostname = to_lower(node.hostname);

            if (node_hostname == search_hostname && !node.tunnel_ip.empty()) {
                // Build TXT record with all port info for peer discovery
                return build_port_config_txt(port_config_.region, "",
                                             port_config_.connected_clients);
            }
        }
    }

    return std::nullopt;
}

// ---------------------------------------------------------------------------
// DNS response building (using c-ares)
// ---------------------------------------------------------------------------

std::vector<uint8_t> DnsService::build_response(
    const ParsedQuery& q, const std::string& ipv4_addr, uint32_t ttl) {

    // Parse the IPv4 address
    struct in_addr addr{};
    if (inet_pton(AF_INET, ipv4_addr.c_str(), &addr) != 1) {
        return build_nxdomain(q);
    }

    // Create response record
    ares_dns_record_t* response = nullptr;
    unsigned short flags = ARES_FLAG_QR | ARES_FLAG_AA;
    ares_status_t status = ares_dns_record_create(
        &response, q.id, flags, ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
    if (status != ARES_SUCCESS || !response) return {};
    DnsRecordGuard response_guard(response);

    // Add the question section
    ares_dns_record_query_add(response, q.qname.c_str(),
                               ARES_REC_TYPE_A, ARES_CLASS_IN);

    // Add the answer A record
    ares_dns_rr_t* rr = nullptr;
    status = ares_dns_record_rr_add(&rr, response, ARES_SECTION_ANSWER,
                                     q.qname.c_str(), ARES_REC_TYPE_A,
                                     ARES_CLASS_IN, ttl);
    if (status == ARES_SUCCESS && rr) {
        ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &addr);
    }

    // Serialize to wire format
    unsigned char* buf = nullptr;
    size_t buf_len = 0;
    status = ares_dns_write(response, &buf, &buf_len);

    if (status != ARES_SUCCESS || !buf) return {};

    std::vector<uint8_t> result(buf, buf + buf_len);
    ares_free_string(buf);
    return result;
}

std::vector<uint8_t> DnsService::build_txt_response(
    const ParsedQuery& q, const std::string& txt_data, uint32_t ttl) {

    // Create response record
    ares_dns_record_t* response = nullptr;
    unsigned short flags = ARES_FLAG_QR | ARES_FLAG_AA;
    ares_status_t status = ares_dns_record_create(
        &response, q.id, flags, ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
    if (status != ARES_SUCCESS || !response) return {};
    DnsRecordGuard response_guard(response);

    // Add the question section (echo back TXT type)
    ares_dns_record_query_add(response, q.qname.c_str(),
                               ARES_REC_TYPE_TXT, ARES_CLASS_IN);

    // Add the answer TXT record
    ares_dns_rr_t* rr = nullptr;
    status = ares_dns_record_rr_add(&rr, response, ARES_SECTION_ANSWER,
                                     q.qname.c_str(), ARES_REC_TYPE_TXT,
                                     ARES_CLASS_IN, ttl);
    if (status == ARES_SUCCESS && rr) {
        ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA,
                              reinterpret_cast<const unsigned char*>(txt_data.data()),
                              txt_data.size());
    }

    // Serialize to wire format
    unsigned char* buf = nullptr;
    size_t buf_len = 0;
    status = ares_dns_write(response, &buf, &buf_len);

    if (status != ARES_SUCCESS || !buf) return {};

    std::vector<uint8_t> result(buf, buf + buf_len);
    ares_free_string(buf);
    return result;
}

std::vector<uint8_t> DnsService::build_nxdomain(const ParsedQuery& q) {

    // Create NXDOMAIN response
    ares_dns_record_t* response = nullptr;
    unsigned short flags = ARES_FLAG_QR | ARES_FLAG_AA;
    ares_status_t status = ares_dns_record_create(
        &response, q.id, flags, ARES_OPCODE_QUERY, ARES_RCODE_NXDOMAIN);
    if (status != ARES_SUCCESS || !response) return {};
    DnsRecordGuard response_guard(response);

    // Echo the question
    if (!q.qname.empty()) {
        ares_dns_record_query_add(response, q.qname.c_str(), q.qtype, q.qclass);
    }

    // Serialize
    unsigned char* buf = nullptr;
    size_t buf_len = 0;
    status = ares_dns_write(response, &buf, &buf_len);

    if (status != ARES_SUCCESS || !buf) return {};

    std::vector<uint8_t> result(buf, buf + buf_len);
    ares_free_string(buf);
    return result;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

std::string DnsService::strip_cidr(const std::string& addr) {
    auto slash = addr.find('/');
    if (slash == std::string::npos) return addr;
    return addr.substr(0, slash);
}

// ---------------------------------------------------------------------------
// Dynamic record management
// ---------------------------------------------------------------------------

bool DnsService::set_record(const std::string& fqdn, const std::string& record_type,
                             const std::string& value, uint32_t ttl) {
    std::string fqdn_lower = to_lower(fqdn);

    std::string key = record_type + ":" + fqdn_lower;
    auto now = now_seconds();

    DnsZoneRecord rec;
    rec.fqdn = fqdn_lower;
    rec.record_type = record_type;
    rec.value = value;
    rec.ttl = ttl;
    rec.timestamp = now;

    {
        std::lock_guard<std::mutex> lock(zone_mutex_);
        zone_records_[key] = rec;
    }

    bump_serial();
    spdlog::info("[{}] set dynamic {} {} -> {} (TTL {})",
                  name(), record_type, fqdn_lower, value, ttl);

    // Notify gossip layer to broadcast this change
    if (record_callback_) {
        auto delta_id = generate_delta_id();
        record_callback_(delta_id, "set", rec);
    }

    return true;
}

bool DnsService::remove_record(const std::string& fqdn, const std::string& record_type) {
    std::string fqdn_lower = to_lower(fqdn);

    std::string key = record_type + ":" + fqdn_lower;
    DnsZoneRecord removed;

    {
        std::lock_guard<std::mutex> lock(zone_mutex_);
        auto it = zone_records_.find(key);
        if (it == zone_records_.end()) {
            return false;
        }
        removed = it->second;
        zone_records_.erase(it);
    }

    bump_serial();
    spdlog::info("[{}] removed dynamic {} {}", name(), record_type, fqdn_lower);

    // Notify gossip layer
    if (record_callback_) {
        auto delta_id = generate_delta_id();
        record_callback_(delta_id, "remove", removed);
    }

    return true;
}

bool DnsService::apply_remote_delta(const std::string& delta_id,
                                      const std::string& operation,
                                      const DnsZoneRecord& record) {
    std::lock_guard<std::mutex> lock(zone_mutex_);

    // Deduplication check
    if (seen_delta_ids_.count(delta_id)) {
        return false;
    }
    seen_delta_ids_.insert(delta_id);

    // Cap seen IDs to prevent unbounded growth (evict oldest half)
    if (seen_delta_ids_.size() > 100000) {
        auto it = seen_delta_ids_.begin();
        for (std::size_t i = 0; i < seen_delta_ids_.size() / 2 && it != seen_delta_ids_.end(); ++i) {
            it = seen_delta_ids_.erase(it);
        }
    }

    std::string fqdn_lower = to_lower(record.fqdn);
    std::string key = record.record_type + ":" + fqdn_lower;

    if (operation == "set") {
        // Only apply if timestamp is newer than existing
        auto it = zone_records_.find(key);
        if (it != zone_records_.end() && it->second.timestamp >= record.timestamp) {
            return false; // Stale update
        }
        zone_records_[key] = record;
        zone_records_[key].fqdn = fqdn_lower;
        spdlog::debug("[{}] applied remote delta: {} {} {} -> {}",
                       name(), operation, record.record_type, fqdn_lower, record.value);
    } else if (operation == "remove") {
        zone_records_.erase(key);
        spdlog::debug("[{}] applied remote delta: {} {} {}",
                       name(), operation, record.record_type, fqdn_lower);
    } else {
        spdlog::warn("[{}] unknown delta operation: {}", name(), operation);
        return false;
    }

    soa_serial_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

void DnsService::set_record_callback(DnsRecordCallback cb) {
    std::lock_guard<std::mutex> lock(zone_mutex_);
    record_callback_ = std::move(cb);
}

// ---------------------------------------------------------------------------
// Nameserver management
// ---------------------------------------------------------------------------

void DnsService::add_nameserver(const std::string& hostname, const std::string& ip) {
    std::lock_guard<std::mutex> lock(zone_mutex_);

    // Update existing or insert
    for (auto& ns : nameservers_) {
        if (ns.hostname == hostname) {
            ns.ip = ip;
            spdlog::info("[{}] updated nameserver {} -> {}", name(), hostname, ip);
            return;
        }
    }

    nameservers_.push_back({hostname, ip});

    // Also add glue A record
    DnsZoneRecord rec;
    rec.fqdn = hostname;
    rec.record_type = "A";
    rec.value = ip;
    rec.ttl = 3600;
    rec.timestamp = now_seconds();
    zone_records_["A:" + hostname] = rec;

    spdlog::info("[{}] added nameserver {} -> {}", name(), hostname, ip);
}

void DnsService::remove_nameserver(const std::string& hostname) {
    std::lock_guard<std::mutex> lock(zone_mutex_);

    auto it = std::remove_if(nameservers_.begin(), nameservers_.end(),
        [&](const Nameserver& ns) { return ns.hostname == hostname; });

    if (it != nameservers_.end()) {
        nameservers_.erase(it, nameservers_.end());
        zone_records_.erase("A:" + hostname);
        spdlog::info("[{}] removed nameserver {}", name(), hostname);
    }
}

void DnsService::set_our_nameserver(const std::string& hostname, const std::string& ip) {
    std::lock_guard<std::mutex> lock(zone_mutex_);
    our_ns_hostname_ = hostname;
    our_ns_ip_ = ip;
    spdlog::info("[{}] our nameserver: {} ({})", name(), hostname, ip);
}

// ---------------------------------------------------------------------------
// SOA configuration
// ---------------------------------------------------------------------------

void DnsService::set_soa_email(const std::string& email) {
    soa_email_ = email;
}

uint32_t DnsService::soa_serial() const {
    return soa_serial_.load(std::memory_order_relaxed);
}

void DnsService::bump_serial() {
    soa_serial_.fetch_add(1, std::memory_order_relaxed);
}

std::string DnsService::generate_delta_id() const {
    auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    thread_local std::mt19937_64 rng(std::random_device{}());
    uint64_t rand_val = rng();

    std::ostringstream oss;
    oss << std::hex << now << "-" << rand_val;
    return oss.str();
}

// ---------------------------------------------------------------------------
// Dynamic record lookup
// ---------------------------------------------------------------------------

std::optional<std::string> DnsService::lookup_dynamic_txt(const std::string& fqdn) {
    std::lock_guard<std::mutex> lock(zone_mutex_);
    auto it = zone_records_.find("TXT:" + fqdn);
    if (it != zone_records_.end()) {
        return it->second.value;
    }
    return std::nullopt;
}

std::optional<std::string> DnsService::lookup_dynamic_a(const std::string& fqdn) {
    std::lock_guard<std::mutex> lock(zone_mutex_);
    auto it = zone_records_.find("A:" + fqdn);
    if (it != zone_records_.end()) {
        return it->second.value;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------
// NS response building
// ---------------------------------------------------------------------------

std::vector<uint8_t> DnsService::build_ns_response(const ParsedQuery& q) {

    std::lock_guard<std::mutex> lock(zone_mutex_);

    if (nameservers_.empty()) {
        return {}; // No NS records to serve
    }

    // Create response
    ares_dns_record_t* response = nullptr;
    unsigned short rflags = ARES_FLAG_QR | ARES_FLAG_AA;
    ares_status_t st = ares_dns_record_create(
        &response, q.id, rflags, ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
    if (st != ARES_SUCCESS || !response) return {};
    DnsRecordGuard response_guard(response);

    // Echo the question
    ares_dns_record_query_add(response, q.qname.c_str(), ARES_REC_TYPE_NS, ARES_CLASS_IN);

    // Add NS records in answer section
    for (const auto& ns : nameservers_) {
        ares_dns_rr_t* rr = nullptr;
        st = ares_dns_record_rr_add(&rr, response, ARES_SECTION_ANSWER,
                                     q.qname.c_str(), ARES_REC_TYPE_NS,
                                     ARES_CLASS_IN, 3600);
        if (st == ARES_SUCCESS && rr) {
            ares_dns_rr_set_str(rr, ARES_RR_NS_NSDNAME, ns.hostname.c_str());
        }
    }

    // Add glue A records in additional section
    for (const auto& ns : nameservers_) {
        if (ns.ip.empty()) continue;
        struct in_addr addr{};
        if (inet_pton(AF_INET, ns.ip.c_str(), &addr) != 1) continue;

        ares_dns_rr_t* rr = nullptr;
        st = ares_dns_record_rr_add(&rr, response, ARES_SECTION_ADDITIONAL,
                                     ns.hostname.c_str(), ARES_REC_TYPE_A,
                                     ARES_CLASS_IN, 3600);
        if (st == ARES_SUCCESS && rr) {
            ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &addr);
        }
    }

    // Serialize
    unsigned char* buf = nullptr;
    size_t buf_len = 0;
    st = ares_dns_write(response, &buf, &buf_len);

    if (st != ARES_SUCCESS || !buf) return {};

    std::vector<uint8_t> result(buf, buf + buf_len);
    ares_free_string(buf);
    return result;
}

// ---------------------------------------------------------------------------
// SOA response building
// ---------------------------------------------------------------------------

std::vector<uint8_t> DnsService::build_soa_response(const ParsedQuery& q) {
    // Determine MNAME (primary NS)
    std::string mname;
    {
        std::lock_guard<std::mutex> lock(zone_mutex_);
        mname = our_ns_hostname_;
        if (mname.empty() && !nameservers_.empty()) {
            mname = nameservers_.front().hostname;
        }
    }
    if (mname.empty()) {
        mname = "ns1." + base_domain_;
    }

    // Create response
    ares_dns_record_t* response = nullptr;
    unsigned short rflags = ARES_FLAG_QR | ARES_FLAG_AA;
    ares_status_t st = ares_dns_record_create(
        &response, q.id, rflags, ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
    if (st != ARES_SUCCESS || !response) return {};
    DnsRecordGuard response_guard(response);

    // Echo the question
    ares_dns_record_query_add(response, q.qname.c_str(), ARES_REC_TYPE_SOA, ARES_CLASS_IN);

    // Add SOA record
    ares_dns_rr_t* rr = nullptr;
    st = ares_dns_record_rr_add(&rr, response, ARES_SECTION_ANSWER,
                                 q.qname.c_str(), ARES_REC_TYPE_SOA,
                                 ARES_CLASS_IN, 3600);
    if (st == ARES_SUCCESS && rr) {
        ares_dns_rr_set_str(rr, ARES_RR_SOA_MNAME, mname.c_str());
        ares_dns_rr_set_str(rr, ARES_RR_SOA_RNAME, soa_email_.c_str());
        ares_dns_rr_set_u32(rr, ARES_RR_SOA_SERIAL, soa_serial_.load());
        ares_dns_rr_set_u32(rr, ARES_RR_SOA_REFRESH, 3600);
        ares_dns_rr_set_u32(rr, ARES_RR_SOA_RETRY, 900);
        ares_dns_rr_set_u32(rr, ARES_RR_SOA_EXPIRE, 604800);
        ares_dns_rr_set_u32(rr, ARES_RR_SOA_MINIMUM, 60);
    }

    // Serialize
    unsigned char* buf = nullptr;
    size_t buf_len = 0;
    st = ares_dns_write(response, &buf, &buf_len);

    if (st != ARES_SUCCESS || !buf) return {};

    std::vector<uint8_t> result(buf, buf + buf_len);
    ares_free_string(buf);
    return result;
}

// ---------------------------------------------------------------------------
// SEIP DNS record hierarchy
// ---------------------------------------------------------------------------

void DnsService::set_server_region(const std::string& region) {
    server_region_ = region;
    port_config_.region = region;
}

void DnsService::publish_seip_records(const std::string& server_id,
                                       const std::string& region,
                                       const std::string& public_ip) {
    // Cache IDs for update_load() re-publishing
    seip_server_id_ = server_id;
    server_region_ = region;
    port_config_.region = region;

    // Normalize components
    std::string id_lower = to_lower(server_id);
    std::string region_lower = to_lower(region);

    // 1. A record: <server_id>.<region>.seip.<base_domain> -> public_ip
    const std::string server_fqdn =
        seip::seipFqdn(id_lower, region_lower, base_domain_lower_);
    set_record(server_fqdn, "A", public_ip, 300);

    // 2. _config TXT: _config.<server_id>.<region>.seip.<base_domain> -> full port config
    seip_server_fqdn_ = server_fqdn;

    std::string txt = build_port_config_txt(region_lower, server_fqdn,
                                            port_config_.connected_clients);

    std::string txt_fqdn =
        seip::configFqdn(id_lower, region_lower, base_domain_lower_);
    set_record(txt_fqdn, "TXT", txt, 300);

    spdlog::info("[{}] published SEIP records: {}.{}.seip.{}",
                  name(), server_id, region, base_domain_);
}

void DnsService::publish_tier_record(const std::string& server_id,
                                      const std::string& region,
                                      int tier,
                                      const std::string& public_ip) {
    if (server_id.empty() || region.empty() || public_ip.empty() || tier < 1) return;

    std::string id_lower = to_lower(server_id);
    std::string region_lower = to_lower(region);

    // <id>.tier<N>.<region>.seip.<base> -> public_ip
    // The tier+region wildcard (tier<N>.<region>.seip.<base>) aggregates these into
    // a multi-A answer used by DNS seed discovery.
    std::string a_fqdn =
        seip::memberTierFqdn(id_lower, tier, region_lower, base_domain_lower_);
    set_record(a_fqdn, "A", public_ip, 300);

    spdlog::info("[{}] published tier record: tier{}.{}.seip.{} -> {}",
                  name(), tier, region, base_domain_, public_ip);
}

void DnsService::update_load(uint32_t connected_client_count) {
    // Only re-publish if the count actually changed (avoid gossip spam)
    if (port_config_.connected_clients == connected_client_count) {
        return;
    }

    port_config_.connected_clients = connected_client_count;

    // Re-publish the SEIP _config TXT record with updated load
    if (seip_server_id_.empty() || server_region_.empty()) {
        return; // SEIP records haven't been published yet
    }

    std::string id_lower = to_lower(seip_server_id_);
    std::string region_lower = to_lower(server_region_);

    std::string server_fqdn = seip_server_fqdn_;
    if (server_fqdn.empty()) {
        server_fqdn = seip::seipFqdn(id_lower, region_lower, base_domain_lower_);
    }

    std::string txt = build_port_config_txt(region_lower, server_fqdn,
                                            port_config_.connected_clients);

    std::string txt_fqdn =
        seip::configFqdn(id_lower, region_lower, base_domain_lower_);
    set_record(txt_fqdn, "TXT", txt, 300);

    spdlog::debug("[{}] updated SEIP load: {} -> {} clients",
                   name(), txt_fqdn, connected_client_count);
}

// ---------------------------------------------------------------------------
// Port config TXT body (shared by all "v=sp1" builders)
// ---------------------------------------------------------------------------

std::string DnsService::build_port_config_txt(const std::string& region,
                                               std::string_view host,
                                               uint32_t load) const {
    std::string txt = "v=sp1"
                      " http=" + std::to_string(port_config_.http_port) +
                      " udp=" + std::to_string(port_config_.udp_port) +
                      " gossip=" + std::to_string(port_config_.gossip_port) +
                      " stun=" + std::to_string(port_config_.stun_port) +
                      " relay=" + std::to_string(port_config_.relay_port) +
                      " dns=" + std::to_string(port_config_.public_dns_port) +
                      " private_http=" + std::to_string(port_config_.private_http_port) +
                      " region=" + region +
                      " load=" + std::to_string(load);
    if (!host.empty()) {
        txt += " host=" + std::string(host);
    }
    return txt;
}

// ---------------------------------------------------------------------------
// Multi-A response building (for SEIP region wildcards)
// ---------------------------------------------------------------------------

std::vector<uint8_t> DnsService::build_multi_a_response(
    const ParsedQuery& q,
    const std::vector<std::string>& ips,
    uint32_t ttl) {

    // Create response record
    ares_dns_record_t* response = nullptr;
    unsigned short flags = ARES_FLAG_QR | ARES_FLAG_AA;
    ares_status_t status = ares_dns_record_create(
        &response, q.id, flags, ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
    if (status != ARES_SUCCESS || !response) return {};
    DnsRecordGuard response_guard(response);

    // Add the question section
    ares_dns_record_query_add(response, q.qname.c_str(),
                               ARES_REC_TYPE_A, ARES_CLASS_IN);

    // Add multiple A records — cap at 5 to stay within 512-byte UDP limit
    std::size_t count = std::min(ips.size(), static_cast<std::size_t>(5));
    for (std::size_t i = 0; i < count; ++i) {
        struct in_addr addr{};
        if (inet_pton(AF_INET, ips[i].c_str(), &addr) != 1) {
            continue; // Skip invalid IPs
        }

        ares_dns_rr_t* rr = nullptr;
        status = ares_dns_record_rr_add(&rr, response, ARES_SECTION_ANSWER,
                                         q.qname.c_str(), ARES_REC_TYPE_A,
                                         ARES_CLASS_IN, ttl);
        if (status == ARES_SUCCESS && rr) {
            ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &addr);
        }
    }

    // Serialize to wire format
    unsigned char* buf = nullptr;
    size_t buf_len = 0;
    status = ares_dns_write(response, &buf, &buf_len);

    if (status != ARES_SUCCESS || !buf) return {};

    std::vector<uint8_t> result(buf, buf + buf_len);
    ares_free_string(buf);
    return result;
}

} // namespace nexus::network
