#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace nexus::ipam {

/// The category of address block being allocated.
enum class BlockType : uint8_t {
    Tunnel,    // 10.64.0.0/10,   per-client /32
    Private,   // 10.128.0.0/9,   default /30, expandable
    Shared,    // 172.20.0.0/14,  default /30, expandable
    Backbone,  // 172.16.0.0/22,  per-server /32 (server mesh backbone)
};

/// A single IPAM allocation record.
struct Allocation {
    BlockType   block_type;
    std::string base_network;      // CIDR notation, e.g. "10.64.4.210/32"
    std::string customer_node_id;
    uint64_t    allocated_at{0};   // Unix timestamp
    uint64_t    last_seen{0};      // Last time the owner was observed alive (backbone only)
    std::string signer_pubkey;     // who allocated (must be root key holder)
    std::string signature;
};

/// The complete set of allocations for a single customer node.
struct AllocationSet {
    std::optional<Allocation> tunnel;
    std::optional<Allocation> private_subnet;
    std::optional<Allocation> shared_block;
    std::optional<Allocation> backbone;
};

/// A gossip delta for backbone IP allocation sync.
struct BackboneAllocationDelta {
    std::string delta_id;           // UUID for dedup
    std::string operation;          // "allocate" or "release"
    std::string server_node_id;
    std::string server_pubkey;      // Ed25519 pubkey (base64) — used for tiebreak
    std::string backbone_ip;        // "172.16.0.X/32"
    uint64_t    timestamp{0};
    std::string signer_pubkey;
    std::string signature;
};

// IP ranges from specification:
//   Tunnel:   10.64.0.0/10,   per-client /32
//   Private:  10.128.0.0/9,   default /30, expandable
//   Shared:   172.20.0.0/14,  default /30, expandable
//   Backbone: 172.16.0.0/22,  per-server /32 (server mesh)

} // namespace nexus::ipam
