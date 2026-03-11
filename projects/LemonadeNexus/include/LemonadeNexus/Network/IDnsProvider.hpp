#pragma once

#include <concepts>
#include <cstdint>
#include <optional>
#include <string>

namespace nexus::network {

/// A resolved DNS record.
struct DnsRecord {
    std::string name;          ///< The queried hostname
    std::string ipv4_address;  ///< Resolved IPv4 address (dotted-decimal)
    uint32_t    ttl{60};       ///< Time-to-live in seconds
};

/// CRTP base for DNS resolution.
/// Derived must implement:
///   std::optional<DnsRecord> do_resolve(const std::string& fqdn)
template <typename Derived>
class IDnsProvider {
public:
    [[nodiscard]] std::optional<DnsRecord> resolve(const std::string& fqdn) {
        return self().do_resolve(fqdn);
    }

protected:
    ~IDnsProvider() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

template <typename T>
concept DnsProviderType = requires(T t, const std::string& s) {
    { t.do_resolve(s) } -> std::same_as<std::optional<DnsRecord>>;
};

} // namespace nexus::network
