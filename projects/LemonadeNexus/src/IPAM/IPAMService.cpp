#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <stdexcept>

namespace nexus::ipam {

namespace {

using json = nlohmann::json;

// Block range definitions
constexpr uint32_t kTunnelBase  = (10u << 24) | (64u << 16);          // 10.64.0.0
constexpr uint32_t kTunnelMask  = 0xFFC00000u;                        // /10
constexpr uint32_t kTunnelSize  = ~kTunnelMask + 1;                   // 4,194,304 addresses

constexpr uint32_t kPrivateBase = (10u << 24) | (128u << 16);         // 10.128.0.0
constexpr uint32_t kPrivateMask = 0xFF800000u;                        // /9
constexpr uint32_t kPrivateSize = ~kPrivateMask + 1;                  // 8,388,608 addresses

constexpr uint32_t kSharedBase    = (172u << 24) | (20u << 16);         // 172.20.0.0
constexpr uint32_t kSharedMask    = 0xFFFC0000u;                        // /14
constexpr uint32_t kSharedSize    = ~kSharedMask + 1;                   // 262,144 addresses

constexpr uint32_t kBackboneBase  = (172u << 24) | (16u << 16);         // 172.16.0.0
constexpr uint32_t kBackboneMask  = 0xFFFFFC00u;                        // /22
constexpr uint32_t kBackboneSize  = ~kBackboneMask + 1;                 // 1,024 addresses

/// Return the current Unix timestamp.
uint64_t now_unix() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

/// Stringify a BlockType for JSON serialization.
std::string block_type_to_string(BlockType bt) {
    switch (bt) {
        case BlockType::Tunnel:   return "tunnel";
        case BlockType::Private:  return "private";
        case BlockType::Shared:   return "shared";
        case BlockType::Backbone: return "backbone";
    }
    return "unknown";
}

/// Parse a BlockType from its string representation.
BlockType string_to_block_type(std::string_view s) {
    if (s == "tunnel")   return BlockType::Tunnel;
    if (s == "private")  return BlockType::Private;
    if (s == "shared")   return BlockType::Shared;
    if (s == "backbone") return BlockType::Backbone;
    throw std::invalid_argument(std::string("Unknown BlockType: ") + std::string(s));
}

json allocation_to_json(const Allocation& a) {
    json j;
    j["block_type"]        = block_type_to_string(a.block_type);
    j["base_network"]      = a.base_network;
    j["customer_node_id"]  = a.customer_node_id;
    j["allocated_at"]      = a.allocated_at;
    j["last_seen"]         = a.last_seen;
    j["signer_pubkey"]     = a.signer_pubkey;
    j["signature"]         = a.signature;
    return j;
}

Allocation json_to_allocation(const json& j) {
    Allocation a;
    a.block_type        = string_to_block_type(j.value("block_type", "tunnel"));
    a.base_network      = j.value("base_network", "");
    a.customer_node_id  = j.value("customer_node_id", "");
    a.allocated_at      = j.value("allocated_at", uint64_t{0});
    a.last_seen         = j.value("last_seen", uint64_t{0});
    a.signer_pubkey     = j.value("signer_pubkey", "");
    a.signature         = j.value("signature", "");
    return a;
}

} // anonymous namespace

// --- Construction ---

IPAMService::IPAMService(storage::FileStorageService& storage)
    : storage_(storage) {}

// --- IService lifecycle ---

void IPAMService::on_start() {
    load_allocations();
    spdlog::info("[{}] started ({} customer allocations loaded)",
                  name(), allocations_.size());
}

void IPAMService::on_stop() {
    spdlog::info("[{}] stopped", name());
}

// --- IIPAMProvider implementation ---

Allocation IPAMService::do_allocate_tunnel_ip(std::string_view node_id) {
    std::lock_guard lock(mutex_);

    // Check for existing tunnel allocation — DHCP-style lease renewal
    auto it = allocations_.find(std::string(node_id));
    if (it != allocations_.end() && it->second.tunnel) {
        it->second.tunnel->last_seen = now_unix();
        spdlog::info("[{}] node '{}' reclaimed tunnel {}", name(), node_id,
                      it->second.tunnel->base_network);
        return *it->second.tunnel;
    }

    auto cidr = next_address(BlockType::Tunnel, 32);

    Allocation alloc;
    alloc.block_type       = BlockType::Tunnel;
    alloc.base_network     = cidr;
    alloc.customer_node_id = std::string(node_id);
    alloc.allocated_at     = now_unix();
    alloc.last_seen        = now_unix();

    allocations_[std::string(node_id)].tunnel = alloc;
    save_allocations();

    spdlog::info("[{}] allocated tunnel {} to node '{}'", name(), cidr, node_id);
    return alloc;
}

Allocation IPAMService::do_allocate_private_subnet(std::string_view node_id,
                                                     uint8_t prefix_len) {
    std::lock_guard lock(mutex_);

    auto it = allocations_.find(std::string(node_id));
    if (it != allocations_.end() && it->second.private_subnet) {
        spdlog::warn("[{}] node '{}' already has a private allocation", name(), node_id);
        return *it->second.private_subnet;
    }

    auto cidr = next_address(BlockType::Private, prefix_len);

    Allocation alloc;
    alloc.block_type       = BlockType::Private;
    alloc.base_network     = cidr;
    alloc.customer_node_id = std::string(node_id);
    alloc.allocated_at     = now_unix();

    allocations_[std::string(node_id)].private_subnet = alloc;
    save_allocations();

    spdlog::info("[{}] allocated private {} to node '{}'", name(), cidr, node_id);
    return alloc;
}

Allocation IPAMService::do_allocate_shared_block(std::string_view node_id,
                                                   uint8_t prefix_len) {
    std::lock_guard lock(mutex_);

    auto it = allocations_.find(std::string(node_id));
    if (it != allocations_.end() && it->second.shared_block) {
        spdlog::warn("[{}] node '{}' already has a shared allocation", name(), node_id);
        return *it->second.shared_block;
    }

    auto cidr = next_address(BlockType::Shared, prefix_len);

    Allocation alloc;
    alloc.block_type       = BlockType::Shared;
    alloc.base_network     = cidr;
    alloc.customer_node_id = std::string(node_id);
    alloc.allocated_at     = now_unix();

    allocations_[std::string(node_id)].shared_block = alloc;
    save_allocations();

    spdlog::info("[{}] allocated shared {} to node '{}'", name(), cidr, node_id);
    return alloc;
}

Allocation IPAMService::do_expand_allocation(std::string_view node_id,
                                               BlockType block_type,
                                               uint8_t new_prefix_len) {
    std::lock_guard lock(mutex_);

    auto it = allocations_.find(std::string(node_id));
    if (it == allocations_.end()) {
        throw std::runtime_error("No allocations found for node: " + std::string(node_id));
    }

    std::optional<Allocation>* target = nullptr;
    switch (block_type) {
        case BlockType::Tunnel:
            throw std::runtime_error("Tunnel allocations are always /32 and cannot be expanded");
        case BlockType::Backbone:
            throw std::runtime_error("Backbone allocations are always /32 and cannot be expanded");
        case BlockType::Private:
            target = &it->second.private_subnet;
            break;
        case BlockType::Shared:
            target = &it->second.shared_block;
            break;
    }

    if (!target || !*target) {
        throw std::runtime_error("No existing allocation of the requested type for node: "
                                 + std::string(node_id));
    }

    auto [old_ip, old_prefix] = parse_cidr((*target)->base_network);
    if (new_prefix_len >= old_prefix) {
        throw std::runtime_error("New prefix length must be shorter (larger block) than current");
    }

    // Re-anchor the allocation at the same base address with the new prefix length
    (*target)->base_network = format_cidr(old_ip, new_prefix_len);
    (*target)->allocated_at = now_unix();

    save_allocations();

    spdlog::info("[{}] expanded {} allocation for '{}' to /{}",
                  name(), block_type_to_string(block_type), node_id, new_prefix_len);
    return **target;
}

bool IPAMService::do_release(std::string_view node_id, BlockType block_type) {
    std::lock_guard lock(mutex_);

    auto it = allocations_.find(std::string(node_id));
    if (it == allocations_.end()) {
        return false;
    }

    bool released = false;
    switch (block_type) {
        case BlockType::Tunnel:
            released = it->second.tunnel.has_value();
            it->second.tunnel.reset();
            break;
        case BlockType::Private:
            released = it->second.private_subnet.has_value();
            it->second.private_subnet.reset();
            break;
        case BlockType::Shared:
            released = it->second.shared_block.has_value();
            it->second.shared_block.reset();
            break;
        case BlockType::Backbone:
            released = it->second.backbone.has_value();
            it->second.backbone.reset();
            break;
    }

    // Remove the node entry entirely if all allocations are released
    if (!it->second.tunnel && !it->second.private_subnet &&
        !it->second.shared_block && !it->second.backbone) {
        allocations_.erase(it);
    }

    if (released) {
        save_allocations();
        spdlog::info("[{}] released {} allocation for '{}'",
                      name(), block_type_to_string(block_type), node_id);
    }
    return released;
}

std::optional<AllocationSet> IPAMService::do_get_allocation(std::string_view node_id) const {
    std::lock_guard lock(mutex_);

    auto it = allocations_.find(std::string(node_id));
    if (it == allocations_.end()) {
        return std::nullopt;
    }
    return it->second;
}

bool IPAMService::do_check_conflict(std::string_view network_cidr) const {
    std::lock_guard lock(mutex_);

    auto [check_ip, check_prefix] = parse_cidr(network_cidr);

    for (const auto& [node_id, aset] : allocations_) {
        auto check_alloc = [&](const std::optional<Allocation>& alloc) -> bool {
            if (!alloc) return false;
            auto [alloc_ip, alloc_prefix] = parse_cidr(alloc->base_network);
            return cidrs_overlap(check_ip, check_prefix, alloc_ip, alloc_prefix);
        };

        if (check_alloc(aset.tunnel) ||
            check_alloc(aset.private_subnet) ||
            check_alloc(aset.shared_block) ||
            check_alloc(aset.backbone)) {
            return true;
        }
    }
    return false;
}

// --- Persistence ---

void IPAMService::save_allocations() {
    json j = json::array();

    for (const auto& [node_id, aset] : allocations_) {
        if (aset.tunnel)         j.push_back(allocation_to_json(*aset.tunnel));
        if (aset.private_subnet) j.push_back(allocation_to_json(*aset.private_subnet));
        if (aset.shared_block)   j.push_back(allocation_to_json(*aset.shared_block));
        if (aset.backbone)       j.push_back(allocation_to_json(*aset.backbone));
    }

    storage::SignedEnvelope envelope;
    envelope.version = 1;
    envelope.type    = "ipam";
    envelope.data    = j.dump();
    envelope.timestamp = now_unix();

    if (!storage_.write_file("ipam", "allocations.json", envelope)) {
        spdlog::error("[{}] failed to persist allocations", name());
    }
}

void IPAMService::load_allocations() {
    auto envelope = storage_.read_file("ipam", "allocations.json");
    if (!envelope) {
        spdlog::debug("[{}] no existing allocations file found", name());
        return;
    }

    auto j = json::parse(envelope->data, nullptr, false);
    if (j.is_discarded() || !j.is_array()) {
        spdlog::warn("[{}] allocations file is malformed", name());
        return;
    }

    for (const auto& entry : j) {
        auto alloc = json_to_allocation(entry);
        auto& aset = allocations_[alloc.customer_node_id];

        switch (alloc.block_type) {
            case BlockType::Tunnel:
                aset.tunnel = alloc;
                break;
            case BlockType::Private:
                aset.private_subnet = alloc;
                break;
            case BlockType::Shared:
                aset.shared_block = alloc;
                break;
            case BlockType::Backbone:
                aset.backbone = alloc;
                break;
        }
    }

    // Rebuild cursor positions by scanning existing allocations
    for (const auto& [node_id, aset] : allocations_) {
        if (aset.tunnel) {
            auto [ip, prefix] = parse_cidr(aset.tunnel->base_network);
            uint32_t offset = ip - kTunnelBase + 1;
            // Never go below 10 — .0-.9 reserved for system use
            if (offset > next_tunnel_ip_) next_tunnel_ip_ = std::max(offset, uint32_t{10});
        }
        if (aset.private_subnet) {
            auto [ip, prefix] = parse_cidr(aset.private_subnet->base_network);
            uint32_t stride = 1u << (32 - prefix);
            uint32_t offset = ip - kPrivateBase + stride;
            if (offset > next_private_ip_) next_private_ip_ = offset;
        }
        if (aset.shared_block) {
            auto [ip, prefix] = parse_cidr(aset.shared_block->base_network);
            uint32_t stride = 1u << (32 - prefix);
            uint32_t offset = ip - kSharedBase + stride;
            if (offset > next_shared_ip_) next_shared_ip_ = offset;
        }
        if (aset.backbone) {
            auto [ip, prefix] = parse_cidr(aset.backbone->base_network);
            uint32_t offset = ip - kBackboneBase + 1;
            if (offset > next_backbone_ip_) next_backbone_ip_ = std::max(offset, uint32_t{10});
        }
    }
}

// --- IP math helpers ---

std::string IPAMService::next_address(BlockType type, uint8_t prefix_len) {
    uint32_t base   = 0;
    uint32_t size   = 0;
    uint32_t* cursor = nullptr;

    switch (type) {
        case BlockType::Tunnel:
            base   = kTunnelBase;
            size   = kTunnelSize;
            cursor = &next_tunnel_ip_;
            break;
        case BlockType::Private:
            base   = kPrivateBase;
            size   = kPrivateSize;
            cursor = &next_private_ip_;
            break;
        case BlockType::Shared:
            base   = kSharedBase;
            size   = kSharedSize;
            cursor = &next_shared_ip_;
            break;
        case BlockType::Backbone:
            base   = kBackboneBase;
            size   = kBackboneSize;
            cursor = &next_backbone_ip_;
            break;
    }

    // Stride is the number of addresses covered by one allocation
    uint32_t stride = 1u << (32 - prefix_len);

    // Align cursor to stride boundary
    if (*cursor % stride != 0) {
        *cursor = ((*cursor / stride) + 1) * stride;
    }

    if (*cursor + stride > size) {
        throw std::runtime_error("IPAM: no more addresses available in "
                                 + block_type_to_string(type) + " block");
    }

    uint32_t ip = base + *cursor;
    *cursor += stride;

    return format_cidr(ip, prefix_len);
}

std::pair<uint32_t, uint8_t> IPAMService::parse_cidr(std::string_view cidr) {
    auto slash = cidr.find('/');
    if (slash == std::string_view::npos) {
        throw std::invalid_argument("Invalid CIDR: " + std::string(cidr));
    }
    uint32_t ip = ip_to_u32(cidr.substr(0, slash));
    auto prefix = static_cast<uint8_t>(std::stoi(std::string(cidr.substr(slash + 1))));
    return {ip, prefix};
}

std::string IPAMService::format_cidr(uint32_t ip, uint8_t prefix_len) {
    return u32_to_ip(ip) + "/" + std::to_string(prefix_len);
}

uint32_t IPAMService::ip_to_u32(std::string_view ip) {
    uint32_t result = 0;
    uint32_t octet  = 0;
    int shift       = 24;

    for (char c : ip) {
        if (c == '.') {
            result |= (octet << shift);
            shift -= 8;
            octet = 0;
        } else {
            octet = octet * 10 + static_cast<uint32_t>(c - '0');
        }
    }
    result |= (octet << shift);
    return result;
}

std::string IPAMService::u32_to_ip(uint32_t ip) {
    return std::to_string((ip >> 24) & 0xFF) + "." +
           std::to_string((ip >> 16) & 0xFF) + "." +
           std::to_string((ip >>  8) & 0xFF) + "." +
           std::to_string( ip        & 0xFF);
}

bool IPAMService::cidrs_overlap(uint32_t a_ip, uint8_t a_prefix,
                                  uint32_t b_ip, uint8_t b_prefix) {
    // Use the shorter prefix (larger block) for comparison
    uint8_t min_prefix = std::min(a_prefix, b_prefix);
    uint32_t mask = min_prefix == 0 ? 0 : (~0u << (32 - min_prefix));
    return (a_ip & mask) == (b_ip & mask);
}

// --- DHCP-style tunnel lease management ---

uint64_t IPAMService::tunnel_lease_timeout_sec() const {
    std::lock_guard lock(mutex_);

    // Count tunnel allocations
    uint32_t tunnel_count = 0;
    for (const auto& [nid, aset] : allocations_) {
        if (aset.tunnel) ++tunnel_count;
    }

    // Usable addresses: kTunnelSize - 10 (reserved .0-.9)
    constexpr uint32_t usable = kTunnelSize - 10;
    if (usable == 0) return 0;

    // Percent full (0-100)
    double pct_full = (static_cast<double>(tunnel_count) / usable) * 100.0;

    // Scale from 50%: below 50% = full 7 days, above 50% scales linearly to 0
    // Formula: lease_hours = 168 / 100 * (100 - PERCENT_FULL_SCALED_FROM_HALF)
    // where PERCENT_FULL_SCALED_FROM_HALF = max(0, (pct_full - 50) * 2)
    double scaled = std::max(0.0, (pct_full - 50.0) * 2.0);
    double lease_hours = 168.0 / 100.0 * (100.0 - scaled);
    lease_hours = std::max(0.0, lease_hours);

    return static_cast<uint64_t>(lease_hours * 3600.0);
}

uint32_t IPAMService::sweep_expired_tunnel_leases() {
    std::lock_guard lock(mutex_);

    auto timeout = tunnel_lease_timeout_sec();
    if (timeout == 0) return 0;

    auto now = now_unix();
    uint32_t released = 0;
    std::vector<std::string> to_release;

    for (const auto& [nid, aset] : allocations_) {
        if (!aset.tunnel) continue;
        if (aset.tunnel->last_seen > 0 &&
            (now - aset.tunnel->last_seen) > timeout) {
            to_release.push_back(nid);
        }
    }

    for (const auto& nid : to_release) {
        auto it = allocations_.find(nid);
        if (it == allocations_.end()) continue;

        spdlog::info("[{}] lease expired for '{}' (tunnel {}), releasing",
                      name(), nid, it->second.tunnel->base_network);
        it->second.tunnel.reset();

        if (!it->second.tunnel && !it->second.private_subnet &&
            !it->second.shared_block && !it->second.backbone) {
            allocations_.erase(it);
        }
        ++released;
    }

    if (released > 0) {
        save_allocations();
        spdlog::info("[{}] swept {} expired tunnel leases (timeout={}h)",
                      name(), released, timeout / 3600);
    }
    return released;
}

void IPAMService::update_tunnel_last_seen(std::string_view node_id) {
    std::lock_guard lock(mutex_);
    auto it = allocations_.find(std::string(node_id));
    if (it != allocations_.end() && it->second.tunnel) {
        it->second.tunnel->last_seen = now_unix();
    }
}

// --- Backbone (server mesh 172.16.0.0/22) ---

Allocation IPAMService::allocate_backbone_ip(std::string_view server_node_id,
                                              std::string_view ed25519_pubkey_b64) {
    std::lock_guard lock(mutex_);

    // Return existing allocation if present
    auto it = allocations_.find(std::string(server_node_id));
    if (it != allocations_.end() && it->second.backbone) {
        return *it->second.backbone;
    }

    // Derive preferred offset from pubkey hash: SHA-256 → first 4 bytes → mod usable range
    // Usable offsets: 10..1023 (first 10 reserved, /22 = 1024 total)
    constexpr uint32_t kUsableStart = 10;
    constexpr uint32_t kUsableCount = kBackboneSize - kUsableStart;

    uint32_t preferred_offset = kUsableStart;
    if (ed25519_pubkey_b64.size() >= 4) {
        uint32_t hash_val = 0;
        for (size_t i = 0; i < std::min(ed25519_pubkey_b64.size(), size_t{16}); ++i) {
            hash_val = hash_val * 31 + static_cast<uint8_t>(ed25519_pubkey_b64[i]);
        }
        preferred_offset = (hash_val % kUsableCount) + kUsableStart;
    }

    // Linear probe from preferred offset to find a free slot
    uint32_t offset = preferred_offset;
    for (uint32_t tries = 0; tries < kUsableCount; ++tries) {
        uint32_t ip = kBackboneBase + offset;
        auto cidr = format_cidr(ip, 32);

        // Check if any existing allocation uses this IP
        bool taken = false;
        for (const auto& [nid, aset] : allocations_) {
            if (aset.backbone && aset.backbone->base_network == cidr) {
                taken = true;
                break;
            }
        }

        if (!taken) {
            Allocation alloc;
            alloc.block_type       = BlockType::Backbone;
            alloc.base_network     = cidr;
            alloc.customer_node_id = std::string(server_node_id);
            alloc.allocated_at     = now_unix();
            alloc.last_seen        = now_unix();

            allocations_[std::string(server_node_id)].backbone = alloc;

            // Advance cursor past this allocation
            if (offset + 1 > next_backbone_ip_) {
                next_backbone_ip_ = offset + 1;
            }

            save_allocations();
            spdlog::info("[{}] allocated backbone {} to server '{}'",
                          name(), cidr, server_node_id);
            return alloc;
        }

        // Wrap around within usable range
        offset = ((offset - kUsableStart + 1) % kUsableCount) + kUsableStart;
    }

    throw std::runtime_error("IPAM: backbone range exhausted (172.16.0.0/22)");
}

bool IPAMService::apply_remote_backbone_allocation(const BackboneAllocationDelta& delta) {
    std::lock_guard lock(mutex_);

    // Dedup check
    if (seen_backbone_deltas_.count(delta.delta_id)) {
        return false;
    }
    // Cap dedup set to prevent unbounded growth
    if (seen_backbone_deltas_.size() > 100000) {
        seen_backbone_deltas_.clear();
    }
    seen_backbone_deltas_.insert(delta.delta_id);

    if (delta.operation == "release") {
        auto it = allocations_.find(delta.server_node_id);
        if (it != allocations_.end() && it->second.backbone) {
            spdlog::info("[{}] remote release backbone {} from '{}'",
                          name(), it->second.backbone->base_network, delta.server_node_id);
            it->second.backbone.reset();
            if (!it->second.tunnel && !it->second.private_subnet &&
                !it->second.shared_block && !it->second.backbone) {
                allocations_.erase(it);
            }
            save_allocations();
            return true;
        }
        return false;
    }

    // operation == "allocate"
    // Check for conflict: does another server already hold this IP?
    for (auto& [nid, aset] : allocations_) {
        if (nid == delta.server_node_id) continue;
        if (!aset.backbone) continue;
        if (aset.backbone->base_network != delta.backbone_ip) continue;

        // Conflict! Higher pubkey wins (lexicographic comparison)
        if (delta.server_pubkey > aset.backbone->signer_pubkey) {
            // Incoming wins — evict the existing holder
            spdlog::warn("[{}] backbone conflict on {} — '{}' evicts '{}' (higher pubkey)",
                          name(), delta.backbone_ip, delta.server_node_id, nid);
            aset.backbone.reset();
        } else {
            // Existing holder wins — reject incoming
            spdlog::warn("[{}] backbone conflict on {} — '{}' rejected (lower pubkey than '{}')",
                          name(), delta.backbone_ip, delta.server_node_id, nid);
            return true;  // Still forward so other peers learn about the claim
        }
    }

    // Apply the allocation
    Allocation alloc;
    alloc.block_type       = BlockType::Backbone;
    alloc.base_network     = delta.backbone_ip;
    alloc.customer_node_id = delta.server_node_id;
    alloc.allocated_at     = delta.timestamp;
    alloc.last_seen        = now_unix();
    alloc.signer_pubkey    = delta.server_pubkey;

    allocations_[delta.server_node_id].backbone = alloc;

    // Advance cursor past this allocation
    auto [ip, prefix] = parse_cidr(delta.backbone_ip);
    uint32_t offset = ip - kBackboneBase + 1;
    if (offset > next_backbone_ip_) {
        next_backbone_ip_ = std::max(offset, uint32_t{10});
    }

    save_allocations();
    spdlog::info("[{}] applied remote backbone {} for '{}'",
                  name(), delta.backbone_ip, delta.server_node_id);
    return true;
}

std::vector<Allocation> IPAMService::get_backbone_allocations() const {
    std::lock_guard lock(mutex_);
    std::vector<Allocation> result;
    for (const auto& [nid, aset] : allocations_) {
        if (aset.backbone) {
            result.push_back(*aset.backbone);
        }
    }
    return result;
}

void IPAMService::update_backbone_last_seen(std::string_view server_node_id,
                                              uint64_t timestamp) {
    std::lock_guard lock(mutex_);
    auto it = allocations_.find(std::string(server_node_id));
    if (it != allocations_.end() && it->second.backbone) {
        it->second.backbone->last_seen = timestamp;
    }
}

std::vector<std::string> IPAMService::collect_stale_backbone(
    uint64_t stale_threshold_sec) const {
    std::lock_guard lock(mutex_);
    auto now = now_unix();
    std::vector<std::string> stale;
    for (const auto& [nid, aset] : allocations_) {
        if (!aset.backbone) continue;
        if (aset.backbone->last_seen > 0 &&
            (now - aset.backbone->last_seen) > stale_threshold_sec) {
            stale.push_back(nid);
        }
    }
    return stale;
}

} // namespace nexus::ipam
