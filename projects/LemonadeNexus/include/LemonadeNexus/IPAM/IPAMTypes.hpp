#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace nexus::ipam {

/// The category of address block being allocated.
enum class BlockType : uint8_t {
    Tunnel,   // 10.64.0.0/10,  per-customer /32
    Private,  // 10.128.0.0/9,  default /30, expandable
    Shared,   // 172.20.0.0/14, default /30, expandable
};

/// A single IPAM allocation record.
struct Allocation {
    BlockType   block_type;
    std::string base_network;      // CIDR notation, e.g. "10.64.4.210/32"
    std::string customer_node_id;
    uint64_t    allocated_at{0};   // Unix timestamp
    std::string signer_pubkey;     // who allocated (must be root key holder)
    std::string signature;
};

/// The complete set of allocations for a single customer node.
struct AllocationSet {
    std::optional<Allocation> tunnel;
    std::optional<Allocation> private_subnet;
    std::optional<Allocation> shared_block;
};

// IP ranges from specification:
//   Tunnel:  10.64.0.0/10,  per-customer /32
//   Private: 10.128.0.0/9,  default /30, expandable
//   Shared:  172.20.0.0/14, default /30, expandable

} // namespace nexus::ipam
