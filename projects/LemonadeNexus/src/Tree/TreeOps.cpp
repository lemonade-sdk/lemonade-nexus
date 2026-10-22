#include <LemonadeNexus/Tree/TreeOps.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Routing/IdentifierDerivation.hpp>
#include <LemonadeNexus/Security/CanonicalEncoding.hpp>

#include <algorithm>
#include <bit>
#include <charconv>
#include <map>

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
    enc.add_string(j.tunnel_ip);
}

/// The kind/source pairs an op may use.
bool source_allowed(TreeOpKind kind, TreeOpSource source) {
    switch (kind) {
        case TreeOpKind::CreateNode:
        case TreeOpKind::UpdateFields:
        case TreeOpKind::DeleteNode:
            return source == TreeOpSource::Session || source == TreeOpSource::Delta;
        case TreeOpKind::SetAssignment:
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
            return true;
    }
    return false;
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

/// "a.b.c.d/32" inside the tunnel pool 10.64.0.0/10.
bool tunnel_address_valid(std::string_view cidr) {
    if (!cidr.ends_with("/32")) return false;
    const auto addr = cidr.substr(0, cidr.size() - 3);
    uint32_t value = 0;
    std::size_t pos = 0;
    for (int octet = 0; octet < 4; ++octet) {
        if (octet > 0) {
            if (pos >= addr.size() || addr[pos] != '.') return false;
            ++pos;
        }
        unsigned part = 0;
        const auto* begin = addr.data() + pos;
        const auto* end = addr.data() + addr.size();
        auto [ptr, ec] = std::from_chars(begin, end, part);
        if (ec != std::errc{} || ptr == begin || part > 255 || (ptr - begin) > 3) return false;
        pos += static_cast<std::size_t>(ptr - begin);
        value = (value << 8) | part;
    }
    if (pos != addr.size()) return false;
    constexpr uint32_t kTunnelBase = (10u << 24) | (64u << 16);
    constexpr uint32_t kTunnelMask = 0xFFC00000u;
    return (value & kTunnelMask) == kTunnelBase;
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
        endpoint.tunnel_ip    = js.tunnel_ip;

        if (!overlay.find(customer_id) ||
            overlay.identifier_taken(endpoint.endpoint_identifier, node_id) ||
            overlay.mesh_taken(endpoint.mesh_pubkey, node_id)) {
            return refuse(TreeOpRefusal::Conflict, "endpoint identifier conflict");
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

    // Returning device: record the new tunnel address and a rotated mesh key.
    // Best effort, like the direct path: a mesh key another node holds leaves
    // the node unchanged (the API layer refuses such claims first).
    if (!js.tunnel_ip.empty()) {
        const std::string new_mesh = js.mesh_pubkey_present ? js.mesh_pubkey
                                                            : existing->mesh_pubkey;
        if ((existing->tunnel_ip != js.tunnel_ip || existing->mesh_pubkey != new_mesh) &&
            !overlay.mesh_taken(new_mesh, node_id)) {
            auto& updated = overlay.edit(node_id);
            updated.tunnel_ip = js.tunnel_ip;
            updated.mesh_pubkey = new_mesh;
        }
    }
    return {};
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
            }
            break;
    }
    return enc;
}

}  // namespace

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
            if (!js.tunnel_ip.empty() && !tunnel_address_valid(js.tunnel_ip)) {
                return refuse(R::Malformed, "join tunnel address is not a tunnel-pool /32");
            }
            break;
        }
        case TreeOpSource::Session:
            if ((op.kind == TreeOpKind::CreateNode || op.kind == TreeOpKind::UpdateFields) &&
                body.node.id != op.target) {
                return refuse(R::Malformed, "node record id differs from the op target");
            }
            break;
    }

    // 8. Target existence and base_version.
    const TreeNode* target = state.find(op.target);
    if (op.kind == TreeOpKind::CreateNode) {
        if (target) return refuse(R::AlreadyExists, "node already exists");
        if (op.base_version != 0) return refuse(R::StaleBaseVersion, "create must use base version 0");
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
            if (!rules::signer_has_permission(*target, op.principal,
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
                switch (ruling->refusal) {
                    case rules::AssignmentRefusal::NotFound:
                        return refuse(R::NotFound, ruling->reason);
                    case rules::AssignmentRefusal::Forbidden:
                        return refuse(R::Forbidden, ruling->reason);
                    case rules::AssignmentRefusal::Invalid:
                        return refuse(R::Invalid, ruling->reason);
                }
            }
            break;
        }
        case TreeOpKind::Join:
            // A join is authorized by the verified device statement and the
            // submitter's admission policy (open registration or a link
            // token), not by a tree permission. plan_op checks placement.
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
            overlay.put(std::move(node));
            break;
        }
        case TreeOpKind::UpdateFields: {
            if (!overlay.find(id)) return refuse(R::NotFound, "node not found");
            TreeNode node = body.source == TreeOpSource::Delta ? body.delta.node_data : body.node;
            node.id = id;
            if (overlay.mesh_taken(node.mesh_pubkey, id)) {
                return refuse(R::Conflict, "mesh public key already bound to another node");
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
    }

    effect = overlay.effect();
    return {};
}

}  // namespace nexus::tree
