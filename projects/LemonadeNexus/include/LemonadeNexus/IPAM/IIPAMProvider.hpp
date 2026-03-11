#pragma once

#include <LemonadeNexus/IPAM/IPAMTypes.hpp>

#include <concepts>
#include <cstdint>
#include <optional>
#include <string_view>

namespace nexus::ipam {

/// CRTP base for IPAM providers.
/// Derived must implement:
///   Allocation do_allocate_tunnel_ip(std::string_view node_id)
///   Allocation do_allocate_private_subnet(std::string_view node_id, uint8_t prefix_len)
///   Allocation do_allocate_shared_block(std::string_view node_id, uint8_t prefix_len)
///   Allocation do_expand_allocation(std::string_view node_id, BlockType, uint8_t new_prefix_len)
///   bool do_release(std::string_view node_id, BlockType)
///   std::optional<AllocationSet> do_get_allocation(std::string_view node_id)
///   bool do_check_conflict(std::string_view network_cidr)
template <typename Derived>
class IIPAMProvider {
public:
    [[nodiscard]] Allocation allocate_tunnel_ip(std::string_view node_id) {
        return self().do_allocate_tunnel_ip(node_id);
    }

    [[nodiscard]] Allocation allocate_private_subnet(std::string_view node_id,
                                                      uint8_t prefix_len = 30) {
        return self().do_allocate_private_subnet(node_id, prefix_len);
    }

    [[nodiscard]] Allocation allocate_shared_block(std::string_view node_id,
                                                     uint8_t prefix_len = 30) {
        return self().do_allocate_shared_block(node_id, prefix_len);
    }

    [[nodiscard]] Allocation expand_allocation(std::string_view node_id,
                                                BlockType block_type,
                                                uint8_t new_prefix_len) {
        return self().do_expand_allocation(node_id, block_type, new_prefix_len);
    }

    [[nodiscard]] bool release(std::string_view node_id, BlockType block_type) {
        return self().do_release(node_id, block_type);
    }

    [[nodiscard]] std::optional<AllocationSet> get_allocation(std::string_view node_id) const {
        return self().do_get_allocation(node_id);
    }

    [[nodiscard]] bool check_conflict(std::string_view network_cidr) const {
        return self().do_check_conflict(network_cidr);
    }

protected:
    ~IIPAMProvider() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

/// Concept constraining a valid IIPAMProvider implementation.
template <typename T>
concept IPAMProviderType = requires(T t, const T ct,
                                     std::string_view sv,
                                     BlockType bt,
                                     uint8_t prefix) {
    { t.do_allocate_tunnel_ip(sv) } -> std::same_as<Allocation>;
    { t.do_allocate_private_subnet(sv, prefix) } -> std::same_as<Allocation>;
    { t.do_allocate_shared_block(sv, prefix) } -> std::same_as<Allocation>;
    { t.do_expand_allocation(sv, bt, prefix) } -> std::same_as<Allocation>;
    { t.do_release(sv, bt) } -> std::same_as<bool>;
    { ct.do_get_allocation(sv) } -> std::same_as<std::optional<AllocationSet>>;
    { ct.do_check_conflict(sv) } -> std::same_as<bool>;
};

} // namespace nexus::ipam
