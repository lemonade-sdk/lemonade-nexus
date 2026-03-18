#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Network/IDnsProvider.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include <asio.hpp>
#include <ares.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace nexus::network {

/// A dynamic DNS zone record (gossip-synced across Tier 1 peers).
struct DnsZoneRecord {
    std::string fqdn;             // fully qualified domain name
    std::string record_type;      // "A", "TXT", "NS", "AAAA", "CNAME"
    std::string value;            // record value
    uint32_t    ttl{60};
    uint64_t    timestamp{0};     // last update time
};

/// Callback type: called when a local DNS record mutation needs gossip broadcast.
using DnsRecordCallback = std::function<void(const std::string& delta_id,
                                              const std::string& operation,
                                              const DnsZoneRecord& record)>;

/// Authoritative DNS server for the mesh domain.
///
/// Runs on UDP port 53 (configurable). Serves:
///   - SOA record for the zone
///   - NS records pointing to all Tier 1 nameservers
///   - A records from permission tree nodes + dynamic records
///   - TXT records for ACME challenges + config subdomains
///   - Dynamic records synced via gossip across all Tier 1 peers
///
/// Uses c-ares (MIT) for DNS packet parsing and building.
///
/// Hostname format:
///   <hostname>.ep.<base_domain>                -> Endpoint's tunnel IP
///   <hostname>.capi.<base_domain>              -> Client API endpoint's tunnel IP
///   <hostname>.srv.<base_domain>               -> Root node's tunnel IP
///   <hostname>.relay.<base_domain>             -> Relay node's tunnel IP
///   <hostname>.<base_domain>                   -> Any node matching the hostname
///   <hostname>.<region>.relays.<base_domain>   -> Relay in specific region
///   <hostname>.relays.<base_domain>            -> Relay by hostname (any region)
///   _config.<hostname>.<base_domain>            -> TXT record with port config
///   _acme-challenge.<domain>                   -> ACME DNS-01 TXT challenge
class DnsService : public core::IService<DnsService>,
                    public IDnsProvider<DnsService> {
    friend class core::IService<DnsService>;
    friend class IDnsProvider<DnsService>;

public:
    /// @param io          Shared ASIO io_context
    /// @param port        UDP port to listen on (default 53)
    /// @param tree        Permission tree service for node lookups
    /// @param base_domain The DNS zone suffix (e.g. "lemonade-nexus.io")
    DnsService(asio::io_context& io,
               uint16_t port,
               tree::PermissionTreeService& tree,
               std::string base_domain = "lemonade-nexus.io");

    // IService
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "DnsService"; }

    // IDnsProvider
    [[nodiscard]] std::optional<DnsRecord> do_resolve(const std::string& fqdn);

    // -----------------------------------------------------------------
    // Dynamic record management (gossip-synced)
    // -----------------------------------------------------------------

    /// Set a dynamic DNS record. Broadcasts via gossip callback.
    /// Used by AcmeService for _acme-challenge TXT records, and for
    /// adding NS/A records for Tier 1 nameservers.
    bool set_record(const std::string& fqdn, const std::string& record_type,
                    const std::string& value, uint32_t ttl = 60);

    /// Remove a dynamic DNS record. Broadcasts via gossip callback.
    bool remove_record(const std::string& fqdn, const std::string& record_type);

    /// Apply a remote DNS record delta received via gossip. Returns true if
    /// applied (new), false if already seen (duplicate).
    bool apply_remote_delta(const std::string& delta_id,
                            const std::string& operation,
                            const DnsZoneRecord& record);

    /// Register a callback invoked when local DNS mutations need gossip broadcast.
    void set_record_callback(DnsRecordCallback cb);

    // -----------------------------------------------------------------
    // Nameserver management (Tier 1 peers as NS records)
    // -----------------------------------------------------------------

    /// Add a nameserver (Tier 1 peer) to the NS record set.
    /// @param hostname  e.g. "ns1.domain.com"
    /// @param ip        e.g. "1.2.3.4"
    void add_nameserver(const std::string& hostname, const std::string& ip);

    /// Remove a nameserver.
    void remove_nameserver(const std::string& hostname);

    /// Set our own server's hostname and IP for the SOA MNAME field.
    void set_our_nameserver(const std::string& hostname, const std::string& ip);

    // -----------------------------------------------------------------
    // SOA configuration
    // -----------------------------------------------------------------

    /// Set the SOA admin email (default: "admin.<base_domain>").
    void set_soa_email(const std::string& email);

    /// Get the current SOA serial number.
    [[nodiscard]] uint32_t soa_serial() const;

    // -----------------------------------------------------------------
    // Utilities (public for testing)
    // -----------------------------------------------------------------

    /// Strip CIDR prefix length if present (e.g. "10.64.0.1/32" -> "10.64.0.1").
    [[nodiscard]] static std::string strip_cidr(const std::string& addr);

    /// Map a type qualifier string to a NodeType.
    [[nodiscard]] static std::optional<tree::NodeType> type_qualifier_to_node_type(
        std::string_view qualifier);

    /// Resolve a relay hostname under the "relays" subdomain.
    [[nodiscard]] std::optional<DnsRecord> resolve_relay_subdomain(
        const std::string& prefix);

    /// Port configuration for TXT record publishing.
    struct PortConfig {
        uint16_t http_port{9100};
        uint16_t udp_port{51940};
        uint16_t wg_port{51820};
        uint16_t gossip_port{9102};
        uint16_t stun_port{3478};
        uint16_t relay_port{9103};
        uint16_t dns_port{53};
        uint16_t private_http_port{9101};
    };

    /// Set the port configuration to publish via TXT records.
    void set_port_config(const PortConfig& config);

    /// Publish this server's port config as a dynamic TXT record
    /// (_config.<server_id>.<base_domain>), gossip-synced to all peers.
    /// Must be called after set_port_config() and set_record_callback().
    void publish_port_config(const std::string& server_id, const std::string& server_fqdn = "");

    /// Resolve a _config. subdomain query, returning TXT record data.
    [[nodiscard]] std::optional<std::string> resolve_config_txt(
        const std::string& hostname);

private:
    void start_receive();
    void handle_query(std::size_t bytes);

    // --- Response builders ---
    [[nodiscard]] std::vector<uint8_t> build_response(
        const unsigned char* query_data, std::size_t query_len,
        const std::string& qname, const std::string& ipv4_addr, uint32_t ttl);

    [[nodiscard]] std::vector<uint8_t> build_txt_response(
        const unsigned char* query_data, std::size_t query_len,
        const std::string& qname, const std::string& txt_data, uint32_t ttl);

    [[nodiscard]] std::vector<uint8_t> build_ns_response(
        const unsigned char* query_data, std::size_t query_len,
        const std::string& qname);

    [[nodiscard]] std::vector<uint8_t> build_soa_response(
        const unsigned char* query_data, std::size_t query_len,
        const std::string& qname);

    [[nodiscard]] std::vector<uint8_t> build_nxdomain(
        const unsigned char* query_data, std::size_t query_len);

    // --- Dynamic record lookup ---
    [[nodiscard]] std::optional<std::string> lookup_dynamic_txt(const std::string& fqdn);
    [[nodiscard]] std::optional<std::string> lookup_dynamic_a(const std::string& fqdn);

    // --- Delta deduplication ---
    [[nodiscard]] std::string generate_delta_id() const;

    // --- Increment SOA serial ---
    void bump_serial();

    asio::ip::udp::socket   socket_;
    asio::ip::udp::endpoint remote_endpoint_;
    std::array<uint8_t, 512> recv_buffer_{};

    tree::PermissionTreeService& tree_;
    std::string                  base_domain_;
    PortConfig                   port_config_;
    bool                         has_port_config_{false};

    // Dynamic zone records: key = "TYPE:fqdn" (e.g. "TXT:_acme-challenge.example.com")
    mutable std::mutex                                  zone_mutex_;
    std::unordered_map<std::string, DnsZoneRecord>      zone_records_;
    std::unordered_set<std::string>                     seen_delta_ids_;
    DnsRecordCallback                                   record_callback_;

    // Nameservers (Tier 1 peers)
    struct Nameserver {
        std::string hostname;   // e.g. "ns1.domain.com"
        std::string ip;         // e.g. "1.2.3.4"
    };
    std::vector<Nameserver>  nameservers_;
    std::string              our_ns_hostname_;
    std::string              our_ns_ip_;

    // SOA state
    std::string              soa_email_;          // e.g. "admin.domain.com"
    std::atomic<uint32_t>    soa_serial_{1};      // auto-incremented on zone changes
};

} // namespace nexus::network
