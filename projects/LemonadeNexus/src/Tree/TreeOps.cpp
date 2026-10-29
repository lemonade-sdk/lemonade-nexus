#include <LemonadeNexus/Tree/TreeOps.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Routing/IdentifierDerivation.hpp>
#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Tree/DeviceLabel.hpp>

#include <algorithm>
#include <bit>
#include <charconv>
#include <cstring>
#include <map>
#include <unordered_set>

namespace nexus::tree {

namespace {

constexpr std::string_view kEd25519Prefix = "ed25519:";

// --- Canonical field encoding ----------------------------------------------

void add_bool(security::CanonicalEncoder& enc, bool value) {
    enc.add_u16(value ? 1 : 0);
}

void add_strings(security::CanonicalEncoder& enc, const std::vector<std::string>& values) {
    enc.add_u32(static_cast<uint32_t>(values.size()));
    for (const auto& v : values) enc.add_string(v);
}

void add_node(security::CanonicalEncoder& enc, const TreeNode& n) {
    enc.add_string(n.id);
    enc.add_string(n.parent_id);
    enc.add_string(node_type_to_string(n.type));
    enc.add_string(n.hostname);
    enc.add_string(n.tunnel_ip);
    enc.add_string(n.private_subnet);
    enc.add_string(n.private_shared_addresses);
    enc.add_string(n.shared_domain);
    enc.add_string(n.mgmt_pubkey);
    enc.add_string(n.wrapped_mgmt_privkey);
    enc.add_string(n.mesh_pubkey);
    enc.add_string(n.endpoint_identifier);
    enc.add_string(n.cpu_id);
    enc.add_string(n.net_mac);
    add_bool(enc, n.is_inference);
    enc.add_u32(static_cast<uint32_t>(n.assignments.size()));
    for (const auto& a : n.assignments) {
        enc.add_string(a.management_pubkey);
        add_strings(enc, a.permissions);
    }
    enc.add_string(n.signature);
    enc.add_string(n.listen_endpoint);
    enc.add_string(n.region);
    enc.add_u32(n.capacity_mbps);
    // The IEEE-754 bit pattern, so the encoding never depends on float formatting.
    enc.add_u32(std::bit_cast<uint32_t>(n.reputation_score));
    enc.add_u64(n.expires_at);
    enc.add_u64(n.version);
}

void add_delta(security::CanonicalEncoder& enc, const TreeDelta& d) {
    enc.add_string(d.operation);
    enc.add_string(d.target_node_id);
    add_node(enc, d.node_data);
    enc.add_string(d.signer_pubkey);
    enc.add_string(d.signature);
    enc.add_u64(d.timestamp);
}

void add_join(security::CanonicalEncoder& enc, const JoinStatement& j) {
    enc.add_string(j.device_pubkey);
    enc.add_string(j.challenge);
    enc.add_string(j.challenge_signature);
    add_bool(enc, j.hostname_present);
    enc.add_string(j.hostname);
    add_bool(enc, j.mesh_pubkey_present);
    enc.add_string(j.mesh_pubkey);
    enc.add_string(j.cpu_id);
    enc.add_string(j.net_mac);
    enc.add_string(j.region);
    add_bool(enc, j.is_inference);
    enc.add_string(j.link_group_id);
    enc.add_string(j.link_owner_pubkey);
}

void add_link_event(security::CanonicalEncoder& enc, const auth::LinkTokenEvent& e) {
    enc.add_u16(static_cast<uint16_t>(e.kind));
    enc.add_string(e.token_hash);
    enc.add_u32(e.generation);
    enc.add_string(e.network_id);
    enc.add_u64(e.expires_at);
    enc.add_string(e.group_node_id);
    add_strings(enc, e.permissions);
    enc.add_string(e.owner_user_id);
    enc.add_string(e.owner_pubkey);
    enc.add_u64(e.created_at);
    enc.add_u64(e.timestamp);
    enc.add_string(e.origin_pubkey);
    enc.add_u64(e.origin_seq);
    enc.add_string(e.signature);
}

/// The op kinds and sources that may carry the link extension.
bool link_extension_allowed(const TreeOp& op) {
    return (op.kind == TreeOpKind::Join && op.body.source == TreeOpSource::Device) ||
           (op.kind == TreeOpKind::AcceptInvite && op.body.source == TreeOpSource::Session);
}

/// The kind/source pairs an op may use.
bool source_allowed(TreeOpKind kind, TreeOpSource source) {
    switch (kind) {
        case TreeOpKind::CreateNode:
        case TreeOpKind::UpdateFields:
        case TreeOpKind::DeleteNode:
            return source == TreeOpSource::Session || source == TreeOpSource::Delta;
        case TreeOpKind::SetAssignment:
        case TreeOpKind::EstablishRoot:
        case TreeOpKind::SetEndpoint:
        case TreeOpKind::AcceptInvite:
        case TreeOpKind::MoveNode:
        case TreeOpKind::DeleteAccount:
            return source == TreeOpSource::Session;
        case TreeOpKind::Join:
            return source == TreeOpSource::Device;
    }
    return false;
}

bool kind_known(TreeOpKind kind) {
    switch (kind) {
        case TreeOpKind::CreateNode:
        case TreeOpKind::UpdateFields:
        case TreeOpKind::SetAssignment:
        case TreeOpKind::DeleteNode:
        case TreeOpKind::Join:
        case TreeOpKind::EstablishRoot:
        case TreeOpKind::SetEndpoint:
        case TreeOpKind::AcceptInvite:
        case TreeOpKind::MoveNode:
        case TreeOpKind::DeleteAccount:
            return true;
    }
    return false;
}

/// "host:port", "a.b.c.d:port", or "[v6]:port" characters only, bounded like
/// the heartbeat route's check (253-character host, ":" and a 5-digit port).
/// Empty clears the endpoint. The API applies the stricter pattern check
/// first; this keeps a replica from storing arbitrary bytes.
bool endpoint_text_valid(std::string_view endpoint) {
    if (endpoint.empty()) return true;
    if (endpoint.size() > 253 + 6) return false;
    const auto colon = endpoint.rfind(':');
    if (colon == std::string_view::npos || colon == 0 || colon + 1 >= endpoint.size()) {
        return false;
    }
    for (char c : endpoint) {
        const bool allowed = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                             (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':' ||
                             c == '[' || c == ']';
        if (!allowed) return false;
    }
    unsigned port = 0;
    const auto digits = endpoint.substr(colon + 1);
    if (digits.size() > 5) return false;
    auto [ptr, ec] = std::from_chars(digits.data(), digits.data() + digits.size(), port);
    return ec == std::errc{} && ptr == digits.data() + digits.size() && port >= 1 &&
           port <= 65535;
}

// --- Key and signature parsing ----------------------------------------------

std::optional<std::vector<uint8_t>> decode_b64(std::string_view s) {
    try {
        return crypto::from_base64(s);
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<crypto::Ed25519PublicKey> parse_ed25519_key(std::string_view key) {
    if (!key.starts_with(kEd25519Prefix)) return std::nullopt;
    const auto bytes = decode_b64(key.substr(kEd25519Prefix.size()));
    if (!bytes || bytes->size() != crypto::kEd25519PublicKeySize) return std::nullopt;
    crypto::Ed25519PublicKey out{};
    std::copy_n(bytes->begin(), crypto::kEd25519PublicKeySize, out.begin());
    return out;
}

std::optional<crypto::Ed25519Signature> parse_signature(std::string_view sig_b64) {
    const auto bytes = decode_b64(sig_b64);
    if (!bytes || bytes->size() != crypto::kEd25519SignatureSize) return std::nullopt;
    crypto::Ed25519Signature out{};
    std::copy_n(bytes->begin(), crypto::kEd25519SignatureSize, out.begin());
    return out;
}

std::vector<uint8_t> signing_message(const crypto::Hash256& op_id) {
    security::CanonicalEncoder enc(kTreeOpSignatureDomain);
    enc.add_bytes(op_id);
    return enc.bytes();
}

/// The same verification do_apply_delta performs on a signed delta.
bool delta_signature_valid(crypto::SodiumCryptoService& crypto, const TreeDelta& delta) {
    const auto pubkey = parse_ed25519_key(delta.signer_pubkey);
    const auto sig = parse_signature(delta.signature);
    if (!pubkey || !sig) return false;
    const auto canonical = canonical_delta_json(delta);
    return crypto.ed25519_verify(
        *pubkey,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(canonical.data()),
                                 canonical.size()),
        *sig);
}

constexpr uint32_t kTunnelBase = (10u << 24) | (64u << 16);  // 10.64.0.0
constexpr uint32_t kTunnelMask = 0xFFC00000u;                // /10

/// The offset inside 10.64.0.0/10 of a "a.b.c.d/32" address, or nullopt when
/// the text is not such an address.
std::optional<uint32_t> tunnel_offset(std::string_view cidr) {
    if (!cidr.ends_with("/32")) return std::nullopt;
    const auto addr = cidr.substr(0, cidr.size() - 3);
    uint32_t value = 0;
    std::size_t pos = 0;
    for (int octet = 0; octet < 4; ++octet) {
        if (octet > 0) {
            if (pos >= addr.size() || addr[pos] != '.') return std::nullopt;
            ++pos;
        }
        unsigned part = 0;
        const auto* begin = addr.data() + pos;
        const auto* end = addr.data() + addr.size();
        auto [ptr, ec] = std::from_chars(begin, end, part);
        if (ec != std::errc{} || ptr == begin || part > 255 || (ptr - begin) > 3) {
            return std::nullopt;
        }
        pos += static_cast<std::size_t>(ptr - begin);
        value = (value << 8) | part;
    }
    if (pos != addr.size() || (value & kTunnelMask) != kTunnelBase) return std::nullopt;
    return value - kTunnelBase;
}

std::string tunnel_address_text(uint32_t offset) {
    const uint32_t v = kTunnelBase + offset;
    return std::to_string(v >> 24) + "." + std::to_string((v >> 16) & 0xFF) + "." +
           std::to_string((v >> 8) & 0xFF) + "." + std::to_string(v & 0xFF) + "/32";
}

/// First offset in the tree range not in `used`, probing upward from the
/// node id's derived start and wrapping. Empty when the range is full.
std::string first_free_tunnel_address(const std::unordered_set<uint32_t>& used,
                                      std::string_view node_id) {
    constexpr uint64_t span = uint64_t{kTreeTunnelLastOffset} - kTreeTunnelFirstOffset + 1;
    security::CanonicalEncoder enc(kTreeTunnelDomain);
    enc.add_string(node_id);
    const auto digest = enc.digest();
    uint64_t seed = 0;
    for (int i = 0; i < 8; ++i) seed |= uint64_t{digest[static_cast<std::size_t>(i)]} << (8 * i);
    const uint64_t start = seed % span;
    for (uint64_t step = 0; step < span; ++step) {
        const auto offset = static_cast<uint32_t>(kTreeTunnelFirstOffset + (start + step) % span);
        if (!used.contains(offset)) return tunnel_address_text(offset);
    }
    return {};
}

TreeOpVerdict refuse(TreeOpRefusal refusal, std::string reason) {
    return TreeOpVerdict{refusal, std::move(reason)};
}

// --- Plan overlay -----------------------------------------------------------

/// Copy-on-write view over a node map. Collects the writes and removals of one
/// op so a refused plan changes nothing, and so each node gets one version
/// increment per op however often the op touches it.
class Overlay {
public:
    explicit Overlay(const TreeState::NodeMap& base) : base_(base) {}

    [[nodiscard]] const TreeNode* find(const std::string& id) const {
        if (auto it = changes_.find(id); it != changes_.end()) {
            return it->second ? &*it->second : nullptr;
        }
        auto it = base_.find(id);
        return it == base_.end() ? nullptr : &it->second;
    }

    /// Writable copy of an existing node. Precondition: find(id) != nullptr.
    TreeNode& edit(const std::string& id) {
        auto it = changes_.find(id);
        if (it == changes_.end()) {
            it = changes_.emplace(id, base_.at(id)).first;
        }
        return *it->second;
    }

    void put(TreeNode node) {
        const auto id = node.id;
        changes_[id] = std::move(node);
    }

    void erase(const std::string& id) { changes_[id] = std::nullopt; }

    /// Visit every live node once (overlay first, then unchanged base nodes).
    template <typename Fn>
    void for_each(Fn&& fn) const {
        for (const auto& [id, node] : changes_) {
            if (node) fn(*node);
        }
        for (const auto& [id, node] : base_) {
            if (!changes_.contains(id)) fn(node);
        }
    }

    [[nodiscard]] bool mesh_taken(const std::string& mesh, const std::string& own_id) const {
        if (mesh.empty()) return false;
        bool taken = false;
        for_each([&](const TreeNode& n) {
            if (n.id != own_id && n.mesh_pubkey == mesh) taken = true;
        });
        return taken;
    }

    [[nodiscard]] bool identifier_taken(const std::string& identifier,
                                        const std::string& own_id) const {
        if (identifier.empty()) return false;
        bool taken = false;
        for_each([&](const TreeNode& n) {
            if (n.id != own_id && n.endpoint_identifier == identifier) taken = true;
        });
        return taken;
    }

    /// Why the device `own_id` under `parent_id` may not take the name
    /// `hostname` (rules::device_name_refusal); nullopt when the name is
    /// free. The conflicting device with the lowest id names the refusal, so
    /// every replica gives the same reason.
    [[nodiscard]] std::optional<std::string> device_name_refusal(
            const std::string& parent_id, const std::string& hostname,
            const std::string& own_id) const {
        const auto label = device_label(hostname);
        const TreeNode* conflict = nullptr;
        for_each([&](const TreeNode& n) {
            if (rules::device_label_collides(n, parent_id, label, own_id) &&
                (!conflict || n.id < conflict->id)) {
                conflict = &n;
            }
        });
        return rules::device_name_refusal(hostname, conflict);
    }

    /// The tunnel address a join assigns to `node_id` against this view.
    [[nodiscard]] std::string free_tunnel_address(std::string_view node_id) const {
        std::unordered_set<uint32_t> used;
        for_each([&](const TreeNode& n) {
            if (const auto offset = tunnel_offset(n.tunnel_ip)) used.insert(*offset);
        });
        return first_free_tunnel_address(used, node_id);
    }

    /// Ids of the live children of `parent_id`, sorted, so callers never depend
    /// on hash-map iteration order.
    [[nodiscard]] std::vector<std::string> child_ids(const std::string& parent_id) const {
        std::vector<std::string> ids;
        for_each([&](const TreeNode& n) {
            if (n.parent_id == parent_id) ids.push_back(n.id);
        });
        std::sort(ids.begin(), ids.end());
        return ids;
    }

    /// Writes (with versions) and removals, sorted by node id.
    [[nodiscard]] TreeOpEffect effect() const {
        TreeOpEffect out;
        for (const auto& [id, node] : changes_) {
            auto base_it = base_.find(id);
            if (node) {
                TreeNode written = *node;
                written.id = id;
                written.version = (base_it == base_.end() ? 0 : base_it->second.version) + 1;
                out.writes.push_back(std::move(written));
            } else if (base_it != base_.end()) {
                out.removals.push_back(id);
            }
        }
        return out;
    }

private:
    const TreeState::NodeMap& base_;
    std::map<std::string, std::optional<TreeNode>> changes_;
};

/// grant_assignment's rule: add the entry unless one with exactly this key
/// spelling already exists. Returns true when the node changed.
bool grant_once(TreeNode& node, const Assignment& grant) {
    for (const auto& a : node.assignments) {
        if (a.management_pubkey == grant.management_pubkey) return false;
    }
    node.assignments.push_back(grant);
    return true;
}

TreeOpVerdict plan_join(const TreeOp& op, Overlay& overlay) {
    const auto& js = op.body.join;
    const std::string& node_id = op.target;
    const std::string& norm = js.device_pubkey;

    if (!overlay.find("root")) {
        return refuse(TreeOpRefusal::NotFound, "application root not established");
    }
    const TreeNode* existing = overlay.find(node_id);
    const bool endpoint_exists = existing != nullptr;

    std::string customer_id;
    if (endpoint_exists) {
        // Returning device: keep its placement.
        customer_id = existing->parent_id;
    } else if (!js.link_group_id.empty()) {
        customer_id = js.link_group_id;
        if (!overlay.find(customer_id)) {
            return refuse(TreeOpRefusal::Conflict, "link token group no longer exists");
        }
    } else {
        customer_id = "customer-" + node_id;
        if (!overlay.find(customer_id)) {
            TreeNode customer;
            customer.id          = customer_id;
            customer.parent_id   = "root";
            customer.type        = NodeType::Customer;
            customer.hostname    = js.hostname_present ? js.hostname
                                                       : "group-" + node_id.substr(0, 8);
            customer.mgmt_pubkey = norm;
            customer.assignments = {{
                .management_pubkey = norm,
                .permissions = {"read", "write", "add_child", "delete_node", "edit_node",
                                "admin"},
            }};
            overlay.put(std::move(customer));
        }
    }

    // The group creator administers the group; groups created before that
    // rule gain admin on the owner's next join.
    if (const TreeNode* group = overlay.find(customer_id);
        group && group->type == NodeType::Customer &&
        canonical_principal(group->mgmt_pubkey) == canonical_principal(norm)) {
        bool needs_admin = false;
        for (const auto& a : group->assignments) {
            if (canonical_principal(a.management_pubkey) != canonical_principal(norm)) continue;
            if (std::find(a.permissions.begin(), a.permissions.end(), "admin") ==
                a.permissions.end()) {
                needs_admin = true;
            }
        }
        if (needs_admin) {
            auto& upgraded = overlay.edit(customer_id);
            for (auto& a : upgraded.assignments) {
                if (canonical_principal(a.management_pubkey) != canonical_principal(norm)) {
                    continue;
                }
                if (std::find(a.permissions.begin(), a.permissions.end(), "admin") ==
                    a.permissions.end()) {
                    a.permissions.push_back("admin");
                }
            }
        }
    }

    if (!endpoint_exists) {
        TreeNode endpoint;
        endpoint.id          = node_id;
        endpoint.parent_id   = customer_id;
        endpoint.type        = NodeType::Endpoint;
        endpoint.hostname    = js.hostname_present ? js.hostname
                                                   : "endpoint-" + node_id.substr(0, 8);
        endpoint.mgmt_pubkey = norm;
        const bool linked = !js.link_group_id.empty();
        if (linked) {
            endpoint.assignments = {
                {.management_pubkey = norm, .permissions = {"read", "write", "edit_node"}},
                {.management_pubkey = js.link_owner_pubkey,
                 .permissions = {"read", "write", "add_child", "delete_node", "edit_node"}},
            };
        } else {
            endpoint.assignments = {{
                .management_pubkey = norm,
                .permissions = {"read", "write", "add_child", "delete_node", "edit_node"},
            }};
        }
        endpoint.mesh_pubkey = js.mesh_pubkey_present ? js.mesh_pubkey : std::string{};
        endpoint.endpoint_identifier = routing::derive_endpoint_identifier(
            node_id, js.region, js.cpu_id, js.net_mac, js.is_inference);
        endpoint.cpu_id       = js.cpu_id;
        endpoint.net_mac      = js.net_mac;
        endpoint.region       = js.region;
        endpoint.is_inference = js.is_inference;
        endpoint.tunnel_ip    = overlay.free_tunnel_address(node_id);
        if (endpoint.tunnel_ip.empty()) {
            return refuse(TreeOpRefusal::Conflict, "tunnel address pool exhausted");
        }

        if (!overlay.find(customer_id) ||
            overlay.identifier_taken(endpoint.endpoint_identifier, node_id) ||
            overlay.mesh_taken(endpoint.mesh_pubkey, node_id)) {
            return refuse(TreeOpRefusal::Conflict, "endpoint identifier conflict");
        }
        if (auto r = overlay.device_name_refusal(customer_id, endpoint.hostname, node_id)) {
            return refuse(TreeOpRefusal::Conflict, *r);
        }
        overlay.put(endpoint);

        if (linked) {
            // Pairwise grants so devices in the group can list and dial each
            // other. Sorted sibling order keeps the assignment lists identical
            // on every machine.
            for (const auto& sibling_id : overlay.child_ids(customer_id)) {
                if (sibling_id == node_id) continue;
                const TreeNode* sibling = overlay.find(sibling_id);
                if (sibling->type != NodeType::Endpoint) continue;
                const std::string sibling_mgmt = sibling->mgmt_pubkey;
                if (op.body.link_extension) {
                    // The sibling's key may already hold an entry on the new
                    // device (the group owner's always does); complete it.
                    if (!sibling_mgmt.empty()) {
                        (void)rules::grant_link_peer_access(overlay.edit(node_id),
                                                            sibling_mgmt);
                    }
                    if (rules::link_peer_access_missing(*sibling, norm)) {
                        (void)rules::grant_link_peer_access(overlay.edit(sibling_id), norm);
                    }
                    continue;
                }
                // Ops from an earlier release: a key that already holds an
                // entry gains nothing.
                if (!sibling_mgmt.empty()) {
                    grant_once(overlay.edit(node_id),
                               {.management_pubkey = sibling_mgmt,
                                .permissions = {"read", "connect_private"}});
                }
                const Assignment back{.management_pubkey = norm,
                                      .permissions = {"read", "connect_private"}};
                const bool has_back = std::any_of(
                    sibling->assignments.begin(), sibling->assignments.end(),
                    [&](const Assignment& a) {
                        return a.management_pubkey == back.management_pubkey;
                    });
                if (!has_back) grant_once(overlay.edit(sibling_id), back);
            }
            const Assignment group_read{.management_pubkey = norm, .permissions = {"read"}};
            const TreeNode* group = overlay.find(customer_id);
            const bool has_read = std::any_of(
                group->assignments.begin(), group->assignments.end(),
                [&](const Assignment& a) {
                    return a.management_pubkey == group_read.management_pubkey;
                });
            if (!has_read) grant_once(overlay.edit(customer_id), group_read);
        }
        return {};
    }

    // Returning device: it keeps its tunnel address (a node stored without one
    // gets a derived address) and records a rotated mesh key. Best effort: a
    // mesh key another node holds leaves the key
    // unchanged (the API layer refuses such claims first).
    std::string new_ip = existing->tunnel_ip;
    if (new_ip.empty()) {
        new_ip = overlay.free_tunnel_address(node_id);
        if (new_ip.empty()) {
            return refuse(TreeOpRefusal::Conflict, "tunnel address pool exhausted");
        }
    }
    std::string new_mesh = js.mesh_pubkey_present ? js.mesh_pubkey : existing->mesh_pubkey;
    if (overlay.mesh_taken(new_mesh, node_id)) new_mesh = existing->mesh_pubkey;
    if (existing->tunnel_ip != new_ip || existing->mesh_pubkey != new_mesh) {
        auto& updated = overlay.edit(node_id);
        updated.tunnel_ip = new_ip;
        updated.mesh_pubkey = new_mesh;
    }
    return {};
}

/// Move the target under body.new_parent_id. The node keeps its id, its
/// addresses, and its own assignments. Its parent signature no longer covers
/// the new record, so the move clears it. A device key that owns no other
/// node loses the entries its old group and old sibling devices held for it
/// (the link-join grants), as a delete would remove them. A move adds no
/// grant: access in the new group comes from the new group's rules.
TreeOpVerdict plan_move(const TreeOp& op, Overlay& overlay) {
    const std::string& id = op.target;
    const TreeNode* moving = overlay.find(id);
    if (!moving) return refuse(TreeOpRefusal::NotFound, "node not found");
    if (!overlay.find(op.body.new_parent_id)) {
        return refuse(TreeOpRefusal::NotFound, "new parent not found");
    }
    const std::string old_parent = moving->parent_id;
    const std::string key_canon = canonical_principal(moving->mgmt_pubkey);
    const bool is_device = moving->type == NodeType::Endpoint;
    {
        auto& moved = overlay.edit(id);
        moved.parent_id = op.body.new_parent_id;
        moved.signature.clear();
    }
    if (!is_device || key_canon.empty()) return {};

    bool key_owns_other = false;
    overlay.for_each([&](const TreeNode& n) {
        if (n.id != id && canonical_principal(n.mgmt_pubkey) == key_canon) key_owns_other = true;
    });
    if (key_owns_other) return {};

    std::vector<std::string> scope = overlay.child_ids(old_parent);
    if (!old_parent.empty()) scope.push_back(old_parent);
    std::sort(scope.begin(), scope.end());
    for (const auto& sid : scope) {
        if (sid == id) continue;
        const TreeNode* n = overlay.find(sid);
        if (!n) continue;
        const bool names_key =
            std::any_of(n->assignments.begin(), n->assignments.end(), [&](const Assignment& a) {
                return canonical_principal(a.management_pubkey) == key_canon;
            });
        if (!names_key) continue;
        std::erase_if(overlay.edit(sid).assignments, [&](const Assignment& a) {
            return canonical_principal(a.management_pubkey) == key_canon;
        });
    }
    return {};
}

/// Remove the principal's account scope (rules::account_scope) and the
/// assignments that name its swept keys on every surviving node except a Root
/// node. Each changed node is edited once, in node id order.
void plan_delete_account(const TreeOp& op, const TreeState::NodeMap& nodes, Overlay& overlay) {
    const auto scope = rules::account_scope(nodes, op.principal);
    for (const auto& id : scope.removed) overlay.erase(id);
    if (scope.swept_keys.empty()) return;

    std::vector<std::string> ids;
    ids.reserve(nodes.size());
    for (const auto& [id, node] : nodes) ids.push_back(id);
    std::sort(ids.begin(), ids.end());
    auto swept = [&](const Assignment& a) {
        return std::binary_search(scope.swept_keys.begin(), scope.swept_keys.end(),
                                  canonical_principal(a.management_pubkey));
    };
    for (const auto& id : ids) {
        const TreeNode* n = overlay.find(id);
        if (!n || n->type == NodeType::Root || n->parent_id.empty()) continue;
        if (std::none_of(n->assignments.begin(), n->assignments.end(), swept)) continue;
        std::erase_if(overlay.edit(id).assignments, swept);
    }
}

/// The op verdict for a refused assignment, invite, or move rule.
TreeOpVerdict ruling_verdict(const rules::AssignmentRuling& ruling) {
    switch (ruling.refusal) {
        case rules::AssignmentRefusal::NotFound:
            return refuse(TreeOpRefusal::NotFound, ruling.reason);
        case rules::AssignmentRefusal::Forbidden:
            return refuse(TreeOpRefusal::Forbidden, ruling.reason);
        case rules::AssignmentRefusal::Invalid:
            return refuse(TreeOpRefusal::Invalid, ruling.reason);
        case rules::AssignmentRefusal::Conflict:
            return refuse(TreeOpRefusal::Conflict, ruling.reason);
    }
    return refuse(TreeOpRefusal::Invalid, ruling.reason);
}

}  // namespace

// --- TreeState / CommittedOpIds ---------------------------------------------

const TreeNode* TreeState::find(std::string_view id) const {
    auto it = nodes_.find(std::string(id));
    return it == nodes_.end() ? nullptr : &it->second;
}

bool CommittedOpIds::contains(const std::string& id) const { return ids_.contains(id); }

void CommittedOpIds::insert(const std::string& id, uint64_t signed_at) {
    ids_[id] = signed_at;
}

void CommittedOpIds::prune_signed_before(uint64_t cutoff) {
    std::erase_if(ids_, [cutoff](const auto& kv) { return kv.second < cutoff; });
}

std::vector<std::pair<std::string, uint64_t>> CommittedOpIds::sorted() const {
    std::vector<std::pair<std::string, uint64_t>> out(ids_.begin(), ids_.end());
    std::sort(out.begin(), out.end());
    return out;
}

// --- Encoding, ids, signing --------------------------------------------------

namespace {

security::CanonicalEncoder op_encoder(const TreeOp& op) {
    security::CanonicalEncoder enc(kTreeOpDomain);
    enc.add_u32(op.version);
    enc.add_bytes(op.network_id);
    enc.add_u16(static_cast<uint16_t>(op.kind));
    enc.add_string(op.target);
    enc.add_u64(op.base_version);
    enc.add_u64(op.signed_at);
    enc.add_bytes(op.nonce);
    enc.add_string(op.principal);
    enc.add_string(op.author);
    enc.add_u16(static_cast<uint16_t>(op.body.source));
    switch (op.body.source) {
        case TreeOpSource::Delta:
            add_delta(enc, op.body.delta);
            break;
        case TreeOpSource::Device:
            add_join(enc, op.body.join);
            break;
        case TreeOpSource::Session:
            if (op.kind == TreeOpKind::CreateNode || op.kind == TreeOpKind::UpdateFields) {
                add_node(enc, op.body.node);
            } else if (op.kind == TreeOpKind::SetAssignment) {
                enc.add_string(op.body.assignment_principal);
                add_strings(enc, op.body.assignment_permissions);
            } else if (op.kind == TreeOpKind::SetEndpoint) {
                enc.add_string(op.body.listen_endpoint);
            } else if (op.kind == TreeOpKind::AcceptInvite) {
                enc.add_string(op.body.inviter);
                add_strings(enc, op.body.invite_permissions);
            } else if (op.kind == TreeOpKind::MoveNode) {
                enc.add_string(op.body.new_parent_id);
            }
            break;
    }
    // Appended only when set, so an op without it keeps the encoding (and op
    // id) an earlier release computes.
    if (op.body.link_extension) {
        enc.add_string(kTreeOpLinkExtensionTag);
        add_bool(enc, op.body.invite_grant.has_value());
        if (op.body.invite_grant) add_link_event(enc, *op.body.invite_grant);
    }
    return enc;
}

}  // namespace

void record_committed(CommittedOpIds& committed, const TreeOp& op) {
    committed.insert(op_id_hex(op), op.signed_at);
    if (const auto statement = statement_id_hex(op)) committed.insert(*statement, op.signed_at);
    // Kept until the invite expires: an id is pruned once its time is older
    // than the freshness window, and no block time past the expiry accepts
    // the grant.
    if (const auto redemption = redemption_id_hex(op)) {
        committed.insert(*redemption, op.body.invite_grant->expires_at);
    }
}

std::optional<std::string> redemption_id_hex(const TreeOp& op) {
    if (!op.body.invite_grant) return std::nullopt;
    security::CanonicalEncoder enc(kTreeOpRedemptionDomain);
    enc.add_string(op.body.invite_grant->token_hash);
    const auto d = enc.digest();
    return crypto::to_hex(std::span<const uint8_t>(d.data(), d.size()));
}

std::vector<uint8_t> encode_tree_op(const TreeOp& op) {
    return op_encoder(op).bytes();
}

crypto::Hash256 compute_op_id(const TreeOp& op) {
    return op_encoder(op).digest();
}

std::string op_id_hex(const TreeOp& op) {
    return crypto::to_hex(std::span<const uint8_t>(op.op_id.data(), op.op_id.size()));
}

std::optional<std::string> statement_id_hex(const TreeOp& op) {
    security::CanonicalEncoder enc(kTreeOpStatementDomain);
    switch (op.body.source) {
        case TreeOpSource::Session:
            return std::nullopt;
        case TreeOpSource::Delta:
            enc.add_string("delta");
            enc.add_string(canonical_delta_json(op.body.delta));
            break;
        case TreeOpSource::Device: {
            enc.add_string("join");
            const auto key = parse_ed25519_key(op.body.join.device_pubkey);
            const auto challenge = decode_b64(op.body.join.challenge);
            if (key) {
                enc.add_bytes(*key);
            } else {
                enc.add_string(op.body.join.device_pubkey);
            }
            if (challenge) {
                enc.add_bytes(*challenge);
            } else {
                enc.add_string(op.body.join.challenge);
            }
            break;
        }
    }
    const auto d = enc.digest();
    return crypto::to_hex(std::span<const uint8_t>(d.data(), d.size()));
}

void sign_tree_op(crypto::SodiumCryptoService& crypto, TreeOp& op,
                  const crypto::Ed25519Keypair& key) {
    op.author = std::string(kEd25519Prefix) +
                crypto::to_base64(std::span<const uint8_t>(key.public_key.data(),
                                                           key.public_key.size()));
    op.op_id = compute_op_id(op);
    const auto msg = signing_message(op.op_id);
    const auto sig = crypto.ed25519_sign(key.private_key, std::span<const uint8_t>(msg));
    op.signature = crypto::to_base64(std::span<const uint8_t>(sig.data(), sig.size()));
}

std::string derive_join_node_id(crypto::SodiumCryptoService& crypto,
                                std::string_view device_pubkey) {
    const auto key = parse_ed25519_key(device_pubkey);
    if (!key) return {};
    const auto hash = crypto.sha256(std::span<const uint8_t>(key->data(), key->size()));
    return crypto::to_hex(std::span<const uint8_t>(hash.data(), hash.size())).substr(0, 32);
}

// --- Validation -------------------------------------------------------------

namespace {

/// The invite grant an op carries: a mint signed by a trusted submitter for
/// this network, unexpired at the block time, and bound to the op's target,
/// inviter, and permissions.
TreeOpVerdict invite_grant_verdict(crypto::SodiumCryptoService& crypto, const TreeOp& op,
                                   const auth::LinkTokenEvent& grant, const TreeState& state,
                                   uint64_t block_time_sec) {
    using R = TreeOpRefusal;
    if (grant.kind != auth::LinkTokenEventKind::Mint || auth::link_token_event_shape_error(grant)) {
        return refuse(R::BadStatement, "invite grant is malformed");
    }
    // Identity is not authority: the grant only shows that a Tier 1 server
    // issued the invite. The inviter's current tree authority still decides
    // (plan_join placement and rules::invite_acceptance_refusal).
    const auto origin = canonical_principal(std::string(kEd25519Prefix) + grant.origin_pubkey);
    const auto& trusted = state.policy().trusted_submitters;
    if (origin.empty() || std::none_of(trusted.begin(), trusted.end(), [&](const std::string& t) {
            return canonical_principal(t) == origin;
        })) {
        return refuse(R::BadStatement, "invite grant origin is not a trusted submitter");
    }
    if (!auth::link_token_event_signature_valid(crypto, grant)) {
        return refuse(R::BadStatement, "invite grant signature does not verify");
    }
    if (grant.network_id !=
        crypto::to_hex(std::span<const uint8_t>(op.network_id.data(), op.network_id.size()))) {
        return refuse(R::WrongNetwork, "invite grant is bound to another network");
    }
    if (block_time_sec >= grant.expires_at) return refuse(R::Stale, "invite expired");
    if (grant.created_at > block_time_sec + kTreeOpMaxFutureSec) {
        return refuse(R::Stale, "invite issued after the block time");
    }
    if (op.kind == TreeOpKind::Join) {
        const auto& js = op.body.join;
        if (js.link_group_id != grant.group_node_id ||
            js.link_owner_pubkey != grant.owner_pubkey) {
            return refuse(R::BadStatement, "join differs from the invite grant");
        }
    } else if (op.target != grant.group_node_id || op.body.inviter != grant.owner_pubkey ||
               op.body.invite_permissions != grant.permissions) {
        return refuse(R::BadStatement, "invite acceptance differs from the invite grant");
    }
    return {};
}

}  // namespace

TreeOpVerdict validate_op(crypto::SodiumCryptoService& crypto, const TreeOp& op,
                          const TreeState& state, uint64_t block_time_sec,
                          const CommittedOpIds& committed) {
    using R = TreeOpRefusal;

    // 1. Format.
    if (op.version != kTreeOpVersion) return refuse(R::Malformed, "unsupported op version");
    if (!kind_known(op.kind)) return refuse(R::Malformed, "unknown op kind");
    if (!source_allowed(op.kind, op.body.source)) {
        return refuse(R::Malformed, "op source does not fit the op kind");
    }
    if (op.target.empty()) return refuse(R::Malformed, "op target is empty");
    if (op.principal.empty()) return refuse(R::Malformed, "op principal is empty");
    if (op.body.link_extension && !link_extension_allowed(op)) {
        return refuse(R::Malformed, "only a join or an invite acceptance has a link extension");
    }
    if (op.body.invite_grant && !op.body.link_extension) {
        return refuse(R::Malformed, "an invite grant needs the link extension");
    }

    // 2. Network binding.
    if (op.network_id != state.policy().network_id) {
        return refuse(R::WrongNetwork, "op is bound to another network");
    }

    // 3. Size, then op id.
    const auto encoded = encode_tree_op(op);
    if (encoded.size() > kMaxTreeOpEncodedBytes) return refuse(R::Oversize, "op too large");
    if (compute_op_id(op) != op.op_id) return refuse(R::BadOpId, "op id does not match");

    // 4. Submitter and signature. Identity is not authority: a trusted
    //    submitter signature only proves which server submitted the op; the
    //    principal's tree permissions still decide below.
    const auto author_canon = canonical_principal(op.author);
    const auto& trusted = state.policy().trusted_submitters;
    if (author_canon.empty() ||
        std::none_of(trusted.begin(), trusted.end(), [&](const std::string& t) {
            return canonical_principal(t) == author_canon;
        })) {
        return refuse(R::UntrustedSubmitter, "op author is not a trusted submitter");
    }
    {
        const auto author_key = parse_ed25519_key(op.author);
        const auto sig = parse_signature(op.signature);
        const auto msg = signing_message(op.op_id);
        if (!author_key || !sig ||
            !crypto.ed25519_verify(*author_key, std::span<const uint8_t>(msg), *sig)) {
            return refuse(R::BadSignature, "op signature does not verify");
        }
    }

    // 5. Freshness against the block time, never the local clock.
    if (op.signed_at == 0) return refuse(R::Stale, "op has no signed time");
    if (op.signed_at + kTreeOpMaxAgeSec < block_time_sec) {
        return refuse(R::Stale, "op is older than the freshness window");
    }
    if (op.signed_at > block_time_sec + kTreeOpMaxFutureSec) {
        return refuse(R::Stale, "op is newer than the freshness window");
    }

    // 6. Replay against the committed set.
    if (committed.contains(op_id_hex(op))) return refuse(R::Replayed, "op already committed");
    const auto statement = statement_id_hex(op);
    if (statement && committed.contains(*statement)) {
        return refuse(R::Replayed, "wrapped statement already committed");
    }
    if (const auto redemption = redemption_id_hex(op);
        redemption && committed.contains(*redemption)) {
        return refuse(R::Replayed, "invite already redeemed");
    }

    // 7. The wrapped statement, and the op fields it fixes.
    const auto& body = op.body;
    switch (body.source) {
        case TreeOpSource::Delta: {
            const auto& d = body.delta;
            const auto required = rules::required_permission_for(d.operation);
            const bool kind_matches =
                (op.kind == TreeOpKind::CreateNode && d.operation == "create_node") ||
                (op.kind == TreeOpKind::DeleteNode && d.operation == "delete_node") ||
                (op.kind == TreeOpKind::UpdateFields && required == acl::Permission::EditNode);
            if (!kind_matches) return refuse(R::BadStatement, "delta operation does not fit the op");
            const auto& expected_target =
                op.kind == TreeOpKind::CreateNode ? d.node_data.id : d.target_node_id;
            if (op.target != expected_target) {
                return refuse(R::BadStatement, "op target differs from the delta");
            }
            if (op.principal != d.signer_pubkey) {
                return refuse(R::BadStatement, "op principal differs from the delta signer");
            }
            if (op.signed_at != d.timestamp) {
                return refuse(R::BadStatement, "op signed time differs from the delta");
            }
            if (!delta_signature_valid(crypto, d)) {
                return refuse(R::BadStatement, "delta signature does not verify");
            }
            break;
        }
        case TreeOpSource::Device: {
            const auto& js = body.join;
            if (op.principal != js.device_pubkey) {
                return refuse(R::BadStatement, "op principal differs from the device key");
            }
            const auto key = parse_ed25519_key(js.device_pubkey);
            const auto challenge = decode_b64(js.challenge);
            const auto sig = parse_signature(js.challenge_signature);
            if (!key || !challenge || challenge->empty() || !sig ||
                !crypto.ed25519_verify(*key, std::span<const uint8_t>(*challenge), *sig)) {
                return refuse(R::BadStatement, "join challenge signature does not verify");
            }
            if (op.target != derive_join_node_id(crypto, js.device_pubkey)) {
                return refuse(R::BadStatement, "join target is not the device's node id");
            }
            break;
        }
        case TreeOpSource::Session:
            if ((op.kind == TreeOpKind::CreateNode || op.kind == TreeOpKind::UpdateFields) &&
                body.node.id != op.target) {
                return refuse(R::Malformed, "node record id differs from the op target");
            }
            if (op.kind == TreeOpKind::EstablishRoot && op.target != "root") {
                return refuse(R::Malformed, "the root op must target \"root\"");
            }
            if (op.kind == TreeOpKind::SetEndpoint && !endpoint_text_valid(body.listen_endpoint)) {
                return refuse(R::Malformed, "listen endpoint is not host:port");
            }
            // An account op names exactly the principal's own account, so no
            // principal deletes another account.
            if (op.kind == TreeOpKind::DeleteAccount &&
                op.target != derive_join_node_id(crypto, op.principal)) {
                return refuse(R::Malformed, "account id differs from the principal's account");
            }
            break;
    }

    if (body.invite_grant) {
        if (auto v = invite_grant_verdict(crypto, op, *body.invite_grant, state, block_time_sec);
            !v.ok()) {
            return v;
        }
    }

    // 8. Target existence and base_version.
    const TreeNode* target = state.find(op.target);
    if (op.kind == TreeOpKind::CreateNode || op.kind == TreeOpKind::EstablishRoot) {
        if (target) return refuse(R::AlreadyExists, "node already exists");
        if (op.base_version != 0) return refuse(R::StaleBaseVersion, "create must use base version 0");
    } else if (op.kind == TreeOpKind::DeleteAccount) {
        // The target is an account id, not one node: the op covers every
        // node in the account scope at the block that applies it.
        if (op.base_version != 0) {
            return refuse(R::Malformed, "an account op uses base version 0");
        }
    } else if (op.kind == TreeOpKind::Join) {
        const uint64_t current = target ? target->version : 0;
        if (op.base_version != current) {
            return refuse(R::StaleBaseVersion, "the node changed; reload and retry");
        }
    } else {
        if (!target) return refuse(R::NotFound, "node not found");
        if (op.base_version != target->version) {
            return refuse(R::StaleBaseVersion, "the node changed; reload and retry");
        }
    }

    // 9. Permission and content rules shared with the delta and assignment paths.
    const auto& nodes = state.nodes();
    auto content_delta = [&](std::string_view operation, const TreeNode& data) {
        if (body.source == TreeOpSource::Delta) return body.delta;
        TreeDelta d;
        d.operation = std::string(operation);
        d.target_node_id = op.target;
        d.node_data = data;
        d.signer_pubkey = op.principal;
        return d;
    };
    switch (op.kind) {
        case TreeOpKind::CreateNode: {
            const TreeNode& data =
                body.source == TreeOpSource::Delta ? body.delta.node_data : body.node;
            const TreeNode* parent = state.find(data.parent_id);
            if (!parent) return refuse(R::NotFound, "parent not found");
            if (!rules::signer_has_permission(*parent, op.principal, acl::Permission::AddChild)) {
                return refuse(R::Forbidden, "no add_child permission on parent");
            }
            if (auto r = rules::delta_content_refusal(nodes, content_delta("create_node", data))) {
                return refuse(R::ContentRefused, *r);
            }
            break;
        }
        case TreeOpKind::UpdateFields: {
            const TreeNode& data =
                body.source == TreeOpSource::Delta ? body.delta.node_data : body.node;
            if (!rules::signer_has_permission(*target, op.principal, acl::Permission::EditNode)) {
                return refuse(R::Forbidden, "no edit_node permission");
            }
            if (auto r = rules::delta_content_refusal(nodes, content_delta("update_node", data))) {
                return refuse(R::ContentRefused, *r);
            }
            break;
        }
        case TreeOpKind::DeleteNode: {
            // A group admin removes the group's devices through the API, and
            // a device removes its own node (it leaves the network). A
            // signed delta keeps the stricter delta rule: delete_node on the
            // node itself.
            const bool session_op = body.source != TreeOpSource::Delta;
            const bool admin_removal =
                session_op && rules::admin_anchor(nodes, op.target, op.principal);
            const bool own_device_removal =
                session_op && rules::removes_own_device(nodes, op.target, op.principal,
                                                        derive_join_node_id(crypto, op.principal));
            if (!admin_removal && !own_device_removal &&
                !rules::signer_has_permission(*target, op.principal,
                                              acl::Permission::DeleteNode)) {
                return refuse(R::Forbidden, "no delete_node permission");
            }
            if (auto r = rules::delta_content_refusal(nodes,
                                                      content_delta("delete_node", TreeNode{}))) {
                return refuse(R::ContentRefused, *r);
            }
            break;
        }
        case TreeOpKind::SetAssignment: {
            if (auto ruling = rules::assignment_change_refusal(
                    nodes, op.target, op.principal, body.assignment_principal,
                    body.assignment_permissions)) {
                return ruling_verdict(*ruling);
            }
            break;
        }
        case TreeOpKind::AcceptInvite: {
            // The submitter consumed the link token. Every replica still
            // checks, against the committed tree, that the inviter may grant
            // these permissions on the target now.
            if (auto ruling = rules::invite_acceptance_refusal(
                    nodes, op.target, op.principal, body.inviter, body.invite_permissions)) {
                return ruling_verdict(*ruling);
            }
            break;
        }
        case TreeOpKind::MoveNode: {
            if (auto ruling = rules::move_refusal(nodes, op.target, body.new_parent_id,
                                                  op.principal)) {
                return ruling_verdict(*ruling);
            }
            break;
        }
        case TreeOpKind::DeleteAccount:
            // Self-removal: the principal removes the nodes it owns, what lies
            // beneath them, and its own entries. The scope never holds a Root
            // node, and the sweep never edits one.
            break;
        case TreeOpKind::Join:
            // A join is authorized by the verified device statement and the
            // submitter (registration is open; a link token places the
            // device in the inviter's group), not by a tree permission.
            // plan_op checks placement.
            break;
        case TreeOpKind::EstablishRoot: {
            // Only the configured root management key, never a key the
            // submitter chooses. Every replica checks the same policy key.
            const auto& root_key = state.policy().root_key;
            if (root_key.empty() || canonical_principal(op.principal).empty() ||
                canonical_principal(op.principal) != canonical_principal(root_key) ||
                !parse_ed25519_key(op.principal)) {
                return refuse(R::Forbidden, "principal is not the configured root key");
            }
            break;
        }
        case TreeOpKind::SetEndpoint:
            // The heartbeat route's ownership rule, in a form every replica
            // can check: the principal is the node's own management key.
            if (target->mgmt_pubkey.empty() ||
                canonical_principal(target->mgmt_pubkey) != canonical_principal(op.principal)) {
                return refuse(R::Forbidden, "only the node's own key sets its endpoint");
            }
            break;
    }

    // 10. The op must apply against this state.
    TreeOpEffect effect;
    return plan_op(op, nodes, effect);
}

// --- Planning ---------------------------------------------------------------

TreeOpVerdict plan_op(const TreeOp& op, const TreeState::NodeMap& nodes,
                      TreeOpEffect& effect) {
    using R = TreeOpRefusal;
    Overlay overlay(nodes);
    const auto& body = op.body;
    const std::string& id = op.target;

    switch (op.kind) {
        case TreeOpKind::CreateNode: {
            TreeNode node = body.source == TreeOpSource::Delta ? body.delta.node_data : body.node;
            node.id = id;
            if (overlay.find(id)) return refuse(R::AlreadyExists, "node already exists");
            if (node.parent_id.empty() || !overlay.find(node.parent_id)) {
                return refuse(R::NotFound, "parent not found");
            }
            if (overlay.identifier_taken(node.endpoint_identifier, id)) {
                return refuse(R::Conflict, "endpoint identifier already bound to another node");
            }
            if (overlay.mesh_taken(node.mesh_pubkey, id)) {
                return refuse(R::Conflict, "mesh public key already bound to another node");
            }
            if (node.type == NodeType::Endpoint) {
                if (auto r = overlay.device_name_refusal(node.parent_id, node.hostname, id)) {
                    return refuse(R::Conflict, *r);
                }
            }
            overlay.put(std::move(node));
            break;
        }
        case TreeOpKind::UpdateFields: {
            const TreeNode* before = overlay.find(id);
            if (!before) return refuse(R::NotFound, "node not found");
            TreeNode node = body.source == TreeOpSource::Delta ? body.delta.node_data : body.node;
            node.id = id;
            if (overlay.mesh_taken(node.mesh_pubkey, id)) {
                return refuse(R::Conflict, "mesh public key already bound to another node");
            }
            // A device rename to a new label follows the device-name rule. A
            // name that keeps its label, and a collision that already exists
            // in the tree, are left as they are.
            if (before->type == NodeType::Endpoint &&
                device_label(node.hostname) != device_label(before->hostname)) {
                if (auto r = overlay.device_name_refusal(before->parent_id, node.hostname, id)) {
                    return refuse(R::Conflict, *r);
                }
            }
            overlay.put(std::move(node));
            break;
        }
        case TreeOpKind::SetAssignment: {
            if (!overlay.find(id)) return refuse(R::NotFound, "node not found");
            rules::replace_assignment(overlay.edit(id).assignments, body.assignment_principal,
                                      body.assignment_permissions);
            break;
        }
        case TreeOpKind::DeleteNode: {
            const TreeNode* doomed = overlay.find(id);
            if (!doomed) return refuse(R::NotFound, "node not found");
            const std::string deleted_mgmt = doomed->mgmt_pubkey;
            const std::string parent_id = doomed->parent_id;
            overlay.erase(id);
            // Sweep the link-join grants that named the deleted device's key
            // from its siblings and its group, so no dangling ACL remains.
            // Never strip a node the key owns (an owner's own devices share
            // the owner key).
            if (!deleted_mgmt.empty()) {
                std::vector<std::string> scope = overlay.child_ids(parent_id);
                if (!parent_id.empty()) scope.push_back(parent_id);
                std::sort(scope.begin(), scope.end());
                for (const auto& sid : scope) {
                    const TreeNode* n = overlay.find(sid);
                    if (!n || n->mgmt_pubkey == deleted_mgmt) continue;
                    const bool names_key = std::any_of(
                        n->assignments.begin(), n->assignments.end(),
                        [&](const Assignment& a) { return a.management_pubkey == deleted_mgmt; });
                    if (!names_key) continue;
                    std::erase_if(overlay.edit(sid).assignments, [&](const Assignment& a) {
                        return a.management_pubkey == deleted_mgmt;
                    });
                }
            }
            break;
        }
        case TreeOpKind::Join: {
            if (auto v = plan_join(op, overlay); !v.ok()) return v;
            break;
        }
        case TreeOpKind::EstablishRoot: {
            if (overlay.find(id)) return refuse(R::AlreadyExists, "node already exists");
            overlay.put(make_root_node(op.principal));
            break;
        }
        case TreeOpKind::SetEndpoint: {
            if (!overlay.find(id)) return refuse(R::NotFound, "node not found");
            overlay.edit(id).listen_endpoint = body.listen_endpoint;
            break;
        }
        case TreeOpKind::AcceptInvite: {
            if (!overlay.find(id)) return refuse(R::NotFound, "node not found");
            rules::replace_assignment(overlay.edit(id).assignments, op.principal,
                                      body.invite_permissions);
            break;
        }
        case TreeOpKind::MoveNode: {
            if (auto v = plan_move(op, overlay); !v.ok()) return v;
            break;
        }
        case TreeOpKind::DeleteAccount:
            plan_delete_account(op, nodes, overlay);
            break;
    }

    effect = overlay.effect();
    return {};
}

void apply_effect(TreeState::NodeMap& nodes, const TreeOpEffect& effect) {
    for (const auto& node : effect.writes) nodes[node.id] = node;
    for (const auto& id : effect.removals) nodes.erase(id);
}

TreeNode make_root_node(const std::string& root_key) {
    TreeNode root;
    root.id          = "root";
    root.parent_id   = "";
    root.type        = NodeType::Root;
    root.hostname    = "root";
    root.mgmt_pubkey = root_key;
    root.assignments = {{.management_pubkey = root_key,
                         .permissions = {"read", "write", "add_child", "delete_node",
                                         "edit_node", "admin"}}};
    return root;
}

std::string derive_tunnel_address(const TreeState::NodeMap& nodes, std::string_view node_id) {
    std::unordered_set<uint32_t> used;
    for (const auto& [id, node] : nodes) {
        if (const auto offset = tunnel_offset(node.tunnel_ip)) used.insert(*offset);
    }
    return first_free_tunnel_address(used, node_id);
}

std::optional<crypto::Ed25519Signature> tree_op_signature_bytes(const TreeOp& op) {
    return parse_signature(op.signature);
}

// --- Canonical decoding -------------------------------------------------------

namespace {

/// Reads the CanonicalEncoder layout back: each field is a little-endian u32
/// length and that many bytes. Every read checks bounds; a failed read leaves
/// the reader failed, and the caller discards the result.
class CanonicalReader {
public:
    explicit CanonicalReader(std::span<const uint8_t> bytes) : bytes_(bytes) {}

    bool field(std::span<const uint8_t>& out) {
        if (failed_ || bytes_.size() - pos_ < 4) return fail();
        uint32_t n = 0;
        for (int i = 0; i < 4; ++i) n |= uint32_t{bytes_[pos_ + static_cast<std::size_t>(i)]} << (8 * i);
        pos_ += 4;
        if (bytes_.size() - pos_ < n) return fail();
        out = bytes_.subspan(pos_, n);
        pos_ += n;
        return true;
    }

    bool string(std::string& out) {
        std::span<const uint8_t> f;
        if (!field(f)) return false;
        out.assign(reinterpret_cast<const char*>(f.data()), f.size());
        return true;
    }

    bool expect(std::string_view literal) {
        std::string s;
        return string(s) && (s == literal || fail());
    }

    template <typename T>
    bool uint(T& out) {
        std::span<const uint8_t> f;
        if (!field(f) || f.size() != sizeof(T)) return fail();
        uint64_t v = 0;
        for (std::size_t i = 0; i < sizeof(T); ++i) v |= uint64_t{f[i]} << (8 * i);
        out = static_cast<T>(v);
        return true;
    }

    bool boolean(bool& out) {
        uint16_t v = 0;
        if (!uint(v) || v > 1) return fail();
        out = v == 1;
        return true;
    }

    template <std::size_t N>
    bool fixed(std::array<uint8_t, N>& out) {
        std::span<const uint8_t> f;
        if (!field(f) || f.size() != N) return fail();
        std::memcpy(out.data(), f.data(), N);
        return true;
    }

    /// A u32 element count that cannot exceed the bytes left (each element
    /// takes at least one 4-byte length prefix), so a hostile count never
    /// drives a large allocation.
    bool count(uint32_t& out) {
        if (!uint(out)) return false;
        return out <= (bytes_.size() - pos_) / 4 || fail();
    }

    bool strings(std::vector<std::string>& out) {
        uint32_t n = 0;
        if (!count(n)) return false;
        out.resize(n);
        for (auto& s : out) {
            if (!string(s)) return false;
        }
        return true;
    }

    [[nodiscard]] bool done() const { return !failed_ && pos_ == bytes_.size(); }

private:
    bool fail() {
        failed_ = true;
        return false;
    }

    std::span<const uint8_t> bytes_;
    std::size_t pos_ = 0;
    bool failed_ = false;
};

bool read_node(CanonicalReader& r, TreeNode& n) {
    std::string type;
    uint32_t assignments = 0;
    if (!(r.string(n.id) && r.string(n.parent_id) && r.string(type) && r.string(n.hostname) &&
          r.string(n.tunnel_ip) && r.string(n.private_subnet) &&
          r.string(n.private_shared_addresses) && r.string(n.shared_domain) &&
          r.string(n.mgmt_pubkey) && r.string(n.wrapped_mgmt_privkey) &&
          r.string(n.mesh_pubkey) && r.string(n.endpoint_identifier) && r.string(n.cpu_id) &&
          r.string(n.net_mac) && r.boolean(n.is_inference) && r.count(assignments))) {
        return false;
    }
    // string_to_node_type throws on an unknown name; decoding never throws.
    if (type == "root") {
        n.type = NodeType::Root;
    } else if (type == "customer") {
        n.type = NodeType::Customer;
    } else if (type == "endpoint") {
        n.type = NodeType::Endpoint;
    } else if (type == "relay") {
        n.type = NodeType::Relay;
    } else {
        return false;
    }
    n.assignments.resize(assignments);
    for (auto& a : n.assignments) {
        if (!(r.string(a.management_pubkey) && r.strings(a.permissions))) return false;
    }
    uint32_t score_bits = 0;
    if (!(r.string(n.signature) && r.string(n.listen_endpoint) && r.string(n.region) &&
          r.uint(n.capacity_mbps) && r.uint(score_bits))) {
        return false;
    }
    n.reputation_score = std::bit_cast<float>(score_bits);
    return r.uint(n.expires_at) && r.uint(n.version);
}

bool read_delta(CanonicalReader& r, TreeDelta& d) {
    return r.string(d.operation) && r.string(d.target_node_id) && read_node(r, d.node_data) &&
           r.string(d.signer_pubkey) && r.string(d.signature) && r.uint(d.timestamp);
}

bool read_link_event(CanonicalReader& r, auth::LinkTokenEvent& e) {
    uint16_t kind = 0;
    if (!(r.uint(kind) && r.string(e.token_hash) && r.uint(e.generation) &&
          r.string(e.network_id) && r.uint(e.expires_at) && r.string(e.group_node_id) &&
          r.strings(e.permissions) && r.string(e.owner_user_id) && r.string(e.owner_pubkey) &&
          r.uint(e.created_at) && r.uint(e.timestamp) && r.string(e.origin_pubkey) &&
          r.uint(e.origin_seq) && r.string(e.signature))) {
        return false;
    }
    if (kind > 0xFF) return false;
    e.kind = static_cast<auth::LinkTokenEventKind>(kind);
    return true;
}

bool read_join(CanonicalReader& r, JoinStatement& j) {
    return r.string(j.device_pubkey) && r.string(j.challenge) &&
           r.string(j.challenge_signature) && r.boolean(j.hostname_present) &&
           r.string(j.hostname) && r.boolean(j.mesh_pubkey_present) && r.string(j.mesh_pubkey) &&
           r.string(j.cpu_id) && r.string(j.net_mac) && r.string(j.region) &&
           r.boolean(j.is_inference) && r.string(j.link_group_id) &&
           r.string(j.link_owner_pubkey);
}

}  // namespace

std::optional<TreeOp> decode_tree_op(std::span<const uint8_t> encoding,
                                     const crypto::Ed25519Signature& signature) {
    if (encoding.size() > kMaxTreeOpEncodedBytes) return std::nullopt;
    CanonicalReader r(encoding);
    TreeOp op;
    uint16_t kind = 0;
    uint16_t source = 0;
    if (!(r.expect(kTreeOpDomain) && r.uint(op.version) && r.fixed(op.network_id) &&
          r.uint(kind) && r.string(op.target) && r.uint(op.base_version) &&
          r.uint(op.signed_at) && r.fixed(op.nonce) && r.string(op.principal) &&
          r.string(op.author) && r.uint(source))) {
        return std::nullopt;
    }
    op.kind = static_cast<TreeOpKind>(kind);
    op.body.source = static_cast<TreeOpSource>(source);
    if (!kind_known(op.kind) || !source_allowed(op.kind, op.body.source)) return std::nullopt;
    bool ok = true;
    switch (op.body.source) {
        case TreeOpSource::Delta:
            ok = read_delta(r, op.body.delta);
            break;
        case TreeOpSource::Device:
            ok = read_join(r, op.body.join);
            break;
        case TreeOpSource::Session:
            if (op.kind == TreeOpKind::CreateNode || op.kind == TreeOpKind::UpdateFields) {
                ok = read_node(r, op.body.node);
            } else if (op.kind == TreeOpKind::SetAssignment) {
                ok = r.string(op.body.assignment_principal) &&
                     r.strings(op.body.assignment_permissions);
            } else if (op.kind == TreeOpKind::SetEndpoint) {
                ok = r.string(op.body.listen_endpoint);
            } else if (op.kind == TreeOpKind::AcceptInvite) {
                ok = r.string(op.body.inviter) && r.strings(op.body.invite_permissions);
            } else if (op.kind == TreeOpKind::MoveNode) {
                ok = r.string(op.body.new_parent_id);
            }
            break;
    }
    if (ok && !r.done() && link_extension_allowed(op)) {
        bool has_grant = false;
        ok = r.expect(kTreeOpLinkExtensionTag) && r.boolean(has_grant);
        op.body.link_extension = ok;
        if (ok && has_grant) {
            auth::LinkTokenEvent grant;
            ok = read_link_event(r, grant);
            if (ok) op.body.invite_grant = std::move(grant);
        }
    }
    if (!ok || !r.done()) return std::nullopt;
    // The layout above mirrors op_encoder; the exact re-encoding check makes
    // the two impossible to drift apart silently.
    if (encode_tree_op(op) != std::vector<uint8_t>(encoding.begin(), encoding.end())) {
        return std::nullopt;
    }
    op.op_id = compute_op_id(op);
    op.signature = crypto::to_base64(std::span<const uint8_t>(signature.data(), signature.size()));
    return op;
}

std::vector<uint8_t> encode_tree_node(const TreeNode& node) {
    security::CanonicalEncoder enc(kTreeNodeDomain);
    add_node(enc, node);
    return enc.bytes();
}

std::optional<TreeNode> decode_tree_node(std::span<const uint8_t> encoding) {
    CanonicalReader r(encoding);
    TreeNode node;
    if (!r.expect(kTreeNodeDomain) || !read_node(r, node) || !r.done()) return std::nullopt;
    if (encode_tree_node(node) != std::vector<uint8_t>(encoding.begin(), encoding.end())) {
        return std::nullopt;
    }
    return node;
}

security::Digest compute_tree_digest(const TreeState::NodeMap& nodes) {
    std::vector<std::pair<const std::string*, const TreeNode*>> ordered;
    ordered.reserve(nodes.size());
    for (const auto& [id, node] : nodes) ordered.emplace_back(&id, &node);
    std::sort(ordered.begin(), ordered.end(),
              [](const auto& a, const auto& b) { return *a.first < *b.first; });
    security::CanonicalEncoder enc(kTreeDigestDomain);
    enc.add_u64(ordered.size());
    for (const auto& [id, node] : ordered) {
        // The map key is the node identity, so it is part of the digest even
        // when a record's own id field disagrees with it.
        enc.add_string(*id);
        enc.add_bytes(encode_tree_node(*node));
    }
    return enc.digest();
}

}  // namespace nexus::tree
