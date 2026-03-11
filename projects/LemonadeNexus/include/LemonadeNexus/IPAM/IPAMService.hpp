#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/IPAM/IIPAMProvider.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace nexus::ipam {

/// File-backed IPAM service.
/// Loads allocations from data/ipam/allocations.json on start,
/// performs sequential allocation within each block range,
/// enforces root key holder as signer, and persists on each allocation.
class IPAMService : public core::IService<IPAMService>,
                     public IIPAMProvider<IPAMService> {
    friend class core::IService<IPAMService>;
    friend class IIPAMProvider<IPAMService>;

public:
    explicit IPAMService(storage::FileStorageService& storage);

    // IService
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "IPAMService"; }

    // IIPAMProvider
    [[nodiscard]] Allocation do_allocate_tunnel_ip(std::string_view node_id);
    [[nodiscard]] Allocation do_allocate_private_subnet(std::string_view node_id,
                                                         uint8_t prefix_len);
    [[nodiscard]] Allocation do_allocate_shared_block(std::string_view node_id,
                                                       uint8_t prefix_len);
    [[nodiscard]] Allocation do_expand_allocation(std::string_view node_id,
                                                   BlockType block_type,
                                                   uint8_t new_prefix_len);
    [[nodiscard]] bool do_release(std::string_view node_id, BlockType block_type);
    [[nodiscard]] std::optional<AllocationSet> do_get_allocation(std::string_view node_id) const;
    [[nodiscard]] bool do_check_conflict(std::string_view network_cidr) const;

private:
    /// Persist current allocations to storage.
    void save_allocations();

    /// Load allocations from storage.
    void load_allocations();

    /// Allocate the next sequential IP/subnet within the given block range.
    [[nodiscard]] std::string next_address(BlockType type, uint8_t prefix_len);

    /// Parse a CIDR string into (ip_u32, prefix_len).
    [[nodiscard]] static std::pair<uint32_t, uint8_t> parse_cidr(std::string_view cidr);

    /// Format a uint32_t IP + prefix length to CIDR string.
    [[nodiscard]] static std::string format_cidr(uint32_t ip, uint8_t prefix_len);

    /// Convert dotted-quad to uint32_t (network byte order value).
    [[nodiscard]] static uint32_t ip_to_u32(std::string_view ip);

    /// Convert uint32_t to dotted-quad string.
    [[nodiscard]] static std::string u32_to_ip(uint32_t ip);

    /// Check whether two CIDR ranges overlap.
    [[nodiscard]] static bool cidrs_overlap(uint32_t a_ip, uint8_t a_prefix,
                                             uint32_t b_ip, uint8_t b_prefix);

    storage::FileStorageService& storage_;
    mutable std::mutex           mutex_;

    /// All current allocations, keyed by customer_node_id.
    std::unordered_map<std::string, AllocationSet> allocations_;

    /// Cursor trackers for sequential allocation within each block.
    uint32_t next_tunnel_ip_{0};   // next offset within 10.64.0.0/10
    uint32_t next_private_ip_{0};  // next offset within 10.128.0.0/9
    uint32_t next_shared_ip_{0};   // next offset within 172.20.0.0/14
};

} // namespace nexus::ipam
