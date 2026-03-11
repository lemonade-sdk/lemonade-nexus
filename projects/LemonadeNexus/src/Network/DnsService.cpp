#include <LemonadeNexus/Network/DnsService.hpp>
#include <LemonadeNexus/Relay/GeoRegion.hpp>

#include <spdlog/spdlog.h>

#include <ares.h>
#include <ares_dns_record.h>

#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <memory>
#include <random>
#include <sstream>

namespace nexus::network {

using asio::ip::udp;

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

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
    soa_email_ = "admin." + base_domain_;
}

// ---------------------------------------------------------------------------
// IService lifecycle
// ---------------------------------------------------------------------------

void DnsService::on_start() {
    spdlog::info("[{}] listening on UDP port {} (zone: {})",
                  name(), socket_.local_endpoint().port(), base_domain_);
    start_receive();
}

void DnsService::on_stop() {
    asio::error_code ec;
    socket_.close(ec);
    spdlog::info("[{}] stopped", name());
}

// ---------------------------------------------------------------------------
// Async receive loop
// ---------------------------------------------------------------------------

void DnsService::start_receive() {
    socket_.async_receive_from(
        asio::buffer(recv_buffer_), remote_endpoint_,
        [this](const asio::error_code& ec, std::size_t bytes) {
            if (!ec) {
                handle_query(bytes);
                start_receive();
            } else if (ec != asio::error::operation_aborted) {
                spdlog::error("[{}] UDP receive error: {}", name(), ec.message());
            }
        });
}

void DnsService::handle_query(std::size_t bytes) {
    if (bytes < 12) return; // Too short for DNS header

    const auto* data = recv_buffer_.data();

    // Parse the query using c-ares
    ares_dns_record_t* dnsrec = nullptr;
    ares_status_t status = ares_dns_parse(data, bytes, 0, &dnsrec);
    if (status != ARES_SUCCESS || !dnsrec) {
        return;
    }

    // Only handle standard queries
    unsigned short flags = ares_dns_record_get_flags(dnsrec);
    if (flags & ARES_FLAG_QR) {
        ares_dns_record_destroy(dnsrec);
        return; // Not a query
    }

    // Get the first question
    if (ares_dns_record_query_cnt(dnsrec) == 0) {
        ares_dns_record_destroy(dnsrec);
        return;
    }

    const char* qname_ptr = nullptr;
    ares_dns_rec_type_t qtype = ARES_REC_TYPE_A;
    ares_dns_class_t qclass = ARES_CLASS_IN;
    ares_dns_record_query_get(dnsrec, 0, &qname_ptr, &qtype, &qclass);

    if (!qname_ptr) {
        ares_dns_record_destroy(dnsrec);
        return;
    }

    std::string qname = qname_ptr;
    ares_dns_record_destroy(dnsrec);

    // Normalize query: lowercase + strip trailing dot
    std::string query_lower = qname;
    std::transform(query_lower.begin(), query_lower.end(), query_lower.begin(),
        [](unsigned char c) { return std::tolower(c); });
    if (!query_lower.empty() && query_lower.back() == '.') {
        query_lower.pop_back();
    }

    std::string base_lower = base_domain_;
    std::transform(base_lower.begin(), base_lower.end(), base_lower.begin(),
        [](unsigned char c) { return std::tolower(c); });

    auto send_response = [&](std::vector<uint8_t> resp) {
        auto buf = std::make_shared<std::vector<uint8_t>>(std::move(resp));
        socket_.async_send_to(asio::buffer(*buf), remote_endpoint_,
            [buf](const asio::error_code&, std::size_t) {});
    };

    // --- SOA queries ---
    if (qtype == ARES_REC_TYPE_SOA && qclass == ARES_CLASS_IN) {
        if (query_lower == base_lower) {
            auto resp = build_soa_response(data, bytes, qname);
            if (!resp.empty()) {
                spdlog::debug("[{}] SOA {} -> serial {}", name(), qname, soa_serial_.load());
                send_response(std::move(resp));
                return;
            }
        }
        send_response(build_nxdomain(data, bytes));
        return;
    }

    // --- NS queries ---
    if (qtype == ARES_REC_TYPE_NS && qclass == ARES_CLASS_IN) {
        if (query_lower == base_lower) {
            auto resp = build_ns_response(data, bytes, qname);
            if (!resp.empty()) {
                spdlog::debug("[{}] NS {} -> nameservers", name(), qname);
                send_response(std::move(resp));
                return;
            }
        }
        send_response(build_nxdomain(data, bytes));
        return;
    }

    // --- TXT queries ---
    if (qtype == ARES_REC_TYPE_TXT && qclass == ARES_CLASS_IN) {
        // 1. Check dynamic TXT records (ACME challenges, etc.)
        auto dyn_txt = lookup_dynamic_txt(query_lower);
        if (dyn_txt) {
            spdlog::debug("[{}] TXT {} -> {} (dynamic)", name(), qname, *dyn_txt);
            send_response(build_txt_response(data, bytes, qname, *dyn_txt, 60));
            return;
        }

        // 2. Check config_ subdomain
        std::string suffix = "." + base_lower;
        if (query_lower.size() > suffix.size() &&
            query_lower.compare(query_lower.size() - suffix.size(), suffix.size(), suffix) == 0) {
            std::string prefix = query_lower.substr(0, query_lower.size() - suffix.size());
            if (prefix.starts_with("config_.")) {
                std::string hostname = prefix.substr(8); // strip "config_."
                auto txt = resolve_config_txt(hostname);
                if (txt) {
                    spdlog::debug("[{}] TXT {} -> {}", name(), qname, *txt);
                    send_response(build_txt_response(data, bytes, qname, *txt, 300));
                    return;
                }
            }
        }

        spdlog::debug("[{}] TXT {} -> NXDOMAIN", name(), qname);
        send_response(build_nxdomain(data, bytes));
        return;
    }

    // --- A record queries ---
    if (qtype == ARES_REC_TYPE_A && qclass == ARES_CLASS_IN) {
        // 1. Check dynamic A records (NS glue records, etc.)
        auto dyn_a = lookup_dynamic_a(query_lower);
        if (dyn_a) {
            spdlog::debug("[{}] {} -> {} (dynamic)", name(), qname, *dyn_a);
            send_response(build_response(data, bytes, qname, *dyn_a, 60));
            return;
        }

        // 2. Tree-based resolution
        auto record = do_resolve(qname);
        if (record) {
            spdlog::debug("[{}] {} -> {}", name(), qname, record->ipv4_address);
            send_response(build_response(data, bytes, qname, record->ipv4_address, record->ttl));
            return;
        }

        spdlog::debug("[{}] {} -> NXDOMAIN", name(), qname);
        send_response(build_nxdomain(data, bytes));
        return;
    }

    // --- Unsupported query type ---
    send_response(build_nxdomain(data, bytes));
}

// ---------------------------------------------------------------------------
// IDnsProvider: resolve a hostname against the tree
// ---------------------------------------------------------------------------

std::optional<DnsRecord> DnsService::do_resolve(const std::string& fqdn) {
    // Lowercase the input
    std::string query = fqdn;
    std::transform(query.begin(), query.end(), query.begin(),
        [](unsigned char c) { return std::tolower(c); });

    // Strip trailing dot
    if (!query.empty() && query.back() == '.') {
        query.pop_back();
    }

    // Lowercase the base domain for comparison
    std::string base = base_domain_;
    std::transform(base.begin(), base.end(), base.begin(),
        [](unsigned char c) { return std::tolower(c); });

    // Check if query ends with .<base_domain>
    std::string suffix = "." + base;
    if (query.size() <= suffix.size() ||
        query.compare(query.size() - suffix.size(), suffix.size(), suffix) != 0) {
        return std::nullopt; // Not in our zone
    }

    // Strip the base domain suffix
    // e.g. "my-laptop.ep.lemonade-nexus.io" -> "my-laptop.ep"
    std::string prefix = query.substr(0, query.size() - suffix.size());

    // Check for "relays" subdomain: <hostname>.[region.]relays
    // This handles: relay1.us-ca.relays.lemonade-nexus.io
    //               relay1.relays.lemonade-nexus.io
    {
        const std::string relays_tag = ".relays";
        if (prefix.size() > relays_tag.size() &&
            prefix.compare(prefix.size() - relays_tag.size(), relays_tag.size(), relays_tag) == 0) {
            std::string relay_prefix = prefix.substr(0, prefix.size() - relays_tag.size());
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

    std::transform(hostname.begin(), hostname.end(), hostname.begin(),
        [](unsigned char c) { return std::tolower(c); });

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
            std::string node_hostname = node.hostname;
            std::transform(node_hostname.begin(), node_hostname.end(),
                           node_hostname.begin(),
                           [](unsigned char c) { return std::tolower(c); });

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

    std::transform(hostname.begin(), hostname.end(), hostname.begin(),
        [](unsigned char c) { return std::tolower(c); });
    std::transform(region_filter.begin(), region_filter.end(), region_filter.begin(),
        [](unsigned char c) { return std::tolower(c); });

    // Search only relay nodes
    auto nodes = tree_.get_nodes_by_type(tree::NodeType::Relay);
    for (const auto& node : nodes) {
        std::string node_hostname = node.hostname;
        std::transform(node_hostname.begin(), node_hostname.end(),
                       node_hostname.begin(),
                       [](unsigned char c) { return std::tolower(c); });

        if (node_hostname != hostname) continue;
        if (node.tunnel_ip.empty()) continue;

        // If region filter is specified, check the node's region
        if (!region_filter.empty()) {
            std::string node_region = node.region;
            std::transform(node_region.begin(), node_region.end(),
                           node_region.begin(),
                           [](unsigned char c) { return std::tolower(c); });
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

std::optional<std::string> DnsService::resolve_config_txt(
    const std::string& hostname) {

    if (!has_port_config_) return std::nullopt;

    // Verify the hostname exists in the tree (any node type)
    std::string host_lower = hostname;
    std::transform(host_lower.begin(), host_lower.end(), host_lower.begin(),
        [](unsigned char c) { return std::tolower(c); });

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
            std::string node_hostname = node.hostname;
            std::transform(node_hostname.begin(), node_hostname.end(),
                           node_hostname.begin(),
                           [](unsigned char c) { return std::tolower(c); });

            if (node_hostname == search_hostname && !node.tunnel_ip.empty()) {
                // Build TXT record: "v=sp1 http=9100 udp=9101 gossip=9102 stun=3478 relay=51820 dns=5353"
                return "v=sp1"
                       " http=" + std::to_string(port_config_.http_port) +
                       " udp=" + std::to_string(port_config_.udp_port) +
                       " gossip=" + std::to_string(port_config_.gossip_port) +
                       " stun=" + std::to_string(port_config_.stun_port) +
                       " relay=" + std::to_string(port_config_.relay_port) +
                       " dns=" + std::to_string(port_config_.dns_port);
            }
        }
    }

    return std::nullopt;
}

// ---------------------------------------------------------------------------
// DNS response building (using c-ares)
// ---------------------------------------------------------------------------

std::vector<uint8_t> DnsService::build_response(
    const unsigned char* query_data, std::size_t query_len,
    const std::string& qname, const std::string& ipv4_addr, uint32_t ttl) {

    // Parse the IPv4 address
    struct in_addr addr{};
    if (inet_pton(AF_INET, ipv4_addr.c_str(), &addr) != 1) {
        return build_nxdomain(query_data, query_len);
    }

    // Parse original query to extract the ID
    ares_dns_record_t* query_rec = nullptr;
    if (ares_dns_parse(query_data, query_len, 0, &query_rec) != ARES_SUCCESS) {
        return {};
    }
    unsigned short id = ares_dns_record_get_id(query_rec);
    ares_dns_record_destroy(query_rec);

    // Create response record
    ares_dns_record_t* response = nullptr;
    unsigned short flags = ARES_FLAG_QR | ARES_FLAG_AA;
    ares_status_t status = ares_dns_record_create(
        &response, id, flags, ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
    if (status != ARES_SUCCESS || !response) return {};

    // Add the question section
    ares_dns_record_query_add(response, qname.c_str(),
                               ARES_REC_TYPE_A, ARES_CLASS_IN);

    // Add the answer A record
    ares_dns_rr_t* rr = nullptr;
    status = ares_dns_record_rr_add(&rr, response, ARES_SECTION_ANSWER,
                                     qname.c_str(), ARES_REC_TYPE_A,
                                     ARES_CLASS_IN, ttl);
    if (status == ARES_SUCCESS && rr) {
        ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &addr);
    }

    // Serialize to wire format
    unsigned char* buf = nullptr;
    size_t buf_len = 0;
    status = ares_dns_write(response, &buf, &buf_len);
    ares_dns_record_destroy(response);

    if (status != ARES_SUCCESS || !buf) return {};

    std::vector<uint8_t> result(buf, buf + buf_len);
    ares_free_string(buf);
    return result;
}

std::vector<uint8_t> DnsService::build_txt_response(
    const unsigned char* query_data, std::size_t query_len,
    const std::string& qname, const std::string& txt_data, uint32_t ttl) {

    // Parse original query to extract the ID
    ares_dns_record_t* query_rec = nullptr;
    if (ares_dns_parse(query_data, query_len, 0, &query_rec) != ARES_SUCCESS) {
        return {};
    }
    unsigned short id = ares_dns_record_get_id(query_rec);
    ares_dns_record_destroy(query_rec);

    // Create response record
    ares_dns_record_t* response = nullptr;
    unsigned short flags = ARES_FLAG_QR | ARES_FLAG_AA;
    ares_status_t status = ares_dns_record_create(
        &response, id, flags, ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
    if (status != ARES_SUCCESS || !response) return {};

    // Add the question section (echo back TXT type)
    ares_dns_record_query_add(response, qname.c_str(),
                               ARES_REC_TYPE_TXT, ARES_CLASS_IN);

    // Add the answer TXT record
    ares_dns_rr_t* rr = nullptr;
    status = ares_dns_record_rr_add(&rr, response, ARES_SECTION_ANSWER,
                                     qname.c_str(), ARES_REC_TYPE_TXT,
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
    ares_dns_record_destroy(response);

    if (status != ARES_SUCCESS || !buf) return {};

    std::vector<uint8_t> result(buf, buf + buf_len);
    ares_free_string(buf);
    return result;
}

std::vector<uint8_t> DnsService::build_nxdomain(
    const unsigned char* query_data, std::size_t query_len) {

    // Parse original query
    ares_dns_record_t* query_rec = nullptr;
    if (ares_dns_parse(query_data, query_len, 0, &query_rec) != ARES_SUCCESS) {
        return {};
    }

    unsigned short id = ares_dns_record_get_id(query_rec);

    // Get original question info
    const char* qname = nullptr;
    ares_dns_rec_type_t qtype = ARES_REC_TYPE_A;
    ares_dns_class_t qclass = ARES_CLASS_IN;
    if (ares_dns_record_query_cnt(query_rec) > 0) {
        ares_dns_record_query_get(query_rec, 0, &qname, &qtype, &qclass);
    }

    std::string qname_str = qname ? qname : "";
    ares_dns_record_destroy(query_rec);

    // Create NXDOMAIN response
    ares_dns_record_t* response = nullptr;
    unsigned short flags = ARES_FLAG_QR | ARES_FLAG_AA;
    ares_status_t status = ares_dns_record_create(
        &response, id, flags, ARES_OPCODE_QUERY, ARES_RCODE_NXDOMAIN);
    if (status != ARES_SUCCESS || !response) return {};

    // Echo the question
    if (!qname_str.empty()) {
        ares_dns_record_query_add(response, qname_str.c_str(), qtype, qclass);
    }

    // Serialize
    unsigned char* buf = nullptr;
    size_t buf_len = 0;
    status = ares_dns_write(response, &buf, &buf_len);
    ares_dns_record_destroy(response);

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
    std::string fqdn_lower = fqdn;
    std::transform(fqdn_lower.begin(), fqdn_lower.end(), fqdn_lower.begin(),
        [](unsigned char c) { return std::tolower(c); });

    std::string key = record_type + ":" + fqdn_lower;
    auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

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
    std::string fqdn_lower = fqdn;
    std::transform(fqdn_lower.begin(), fqdn_lower.end(), fqdn_lower.begin(),
        [](unsigned char c) { return std::tolower(c); });

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

    std::string fqdn_lower = record.fqdn;
    std::transform(fqdn_lower.begin(), fqdn_lower.end(), fqdn_lower.begin(),
        [](unsigned char c) { return std::tolower(c); });
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
    rec.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
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

std::vector<uint8_t> DnsService::build_ns_response(
    const unsigned char* query_data, std::size_t query_len,
    const std::string& qname) {

    std::lock_guard<std::mutex> lock(zone_mutex_);

    if (nameservers_.empty()) {
        return {}; // No NS records to serve
    }

    // Parse query ID
    ares_dns_record_t* query_rec = nullptr;
    if (ares_dns_parse(query_data, query_len, 0, &query_rec) != ARES_SUCCESS) {
        return {};
    }
    unsigned short id = ares_dns_record_get_id(query_rec);
    ares_dns_record_destroy(query_rec);

    // Create response
    ares_dns_record_t* response = nullptr;
    unsigned short rflags = ARES_FLAG_QR | ARES_FLAG_AA;
    ares_status_t st = ares_dns_record_create(
        &response, id, rflags, ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
    if (st != ARES_SUCCESS || !response) return {};

    // Echo the question
    ares_dns_record_query_add(response, qname.c_str(), ARES_REC_TYPE_NS, ARES_CLASS_IN);

    // Add NS records in answer section
    for (const auto& ns : nameservers_) {
        ares_dns_rr_t* rr = nullptr;
        st = ares_dns_record_rr_add(&rr, response, ARES_SECTION_ANSWER,
                                     qname.c_str(), ARES_REC_TYPE_NS,
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
    ares_dns_record_destroy(response);

    if (st != ARES_SUCCESS || !buf) return {};

    std::vector<uint8_t> result(buf, buf + buf_len);
    ares_free_string(buf);
    return result;
}

// ---------------------------------------------------------------------------
// SOA response building
// ---------------------------------------------------------------------------

std::vector<uint8_t> DnsService::build_soa_response(
    const unsigned char* query_data, std::size_t query_len,
    const std::string& qname) {

    // Parse query ID
    ares_dns_record_t* query_rec = nullptr;
    if (ares_dns_parse(query_data, query_len, 0, &query_rec) != ARES_SUCCESS) {
        return {};
    }
    unsigned short id = ares_dns_record_get_id(query_rec);
    ares_dns_record_destroy(query_rec);

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
        &response, id, rflags, ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
    if (st != ARES_SUCCESS || !response) return {};

    // Echo the question
    ares_dns_record_query_add(response, qname.c_str(), ARES_REC_TYPE_SOA, ARES_CLASS_IN);

    // Add SOA record
    ares_dns_rr_t* rr = nullptr;
    st = ares_dns_record_rr_add(&rr, response, ARES_SECTION_ANSWER,
                                 qname.c_str(), ARES_REC_TYPE_SOA,
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
    ares_dns_record_destroy(response);

    if (st != ARES_SUCCESS || !buf) return {};

    std::vector<uint8_t> result(buf, buf + buf_len);
    ares_free_string(buf);
    return result;
}

} // namespace nexus::network
