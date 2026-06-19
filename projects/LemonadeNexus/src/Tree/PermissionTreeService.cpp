#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include <LemonadeNexus/Routing/IdentifierDerivation.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <unordered_set>

namespace nexus::tree {

using json = nlohmann::json;

PermissionTreeService::PermissionTreeService(storage::FileStorageService& storage,
                                               crypto::SodiumCryptoService& crypto)
    : storage_(storage)
    , crypto_(crypto) {}

// --- IService ---

void PermissionTreeService::on_start() {
    std::lock_guard lock(mutex_);

    // Load all persisted nodes into the in-memory cache
    const auto node_ids = storage_.list_nodes();
    for (const auto& node_id : node_ids) {
        auto envelope = storage_.read_node(node_id);
        if (!envelope) {
            spdlog::warn("[{}] failed to read node '{}' from storage, skipping",
                          name(), node_id);
            continue;
        }

        auto parsed = json::parse(envelope->data, nullptr, false);
        if (parsed.is_discarded()) {
            spdlog::warn("[{}] node '{}' has invalid JSON data, skipping",
                          name(), node_id);
            continue;
        }

        try {
            auto node = parsed.get<TreeNode>();
            nodes_[node.id] = std::move(node);
        } catch (const std::exception& e) {
            spdlog::warn("[{}] failed to deserialize node '{}': {}",
                          name(), node_id, e.what());
        }
    }

    // Build the endpoint-identifier reverse index from the loaded nodes.
    identifier_index_.clear();
    for (const auto& [id, node] : nodes_) {
        if (!node.endpoint_identifier.empty()) {
            identifier_index_[node.endpoint_identifier] = id;
        }
    }

    spdlog::info("[{}] loaded {} nodes from storage ({} with endpoint identifiers)",
                  name(), nodes_.size(), identifier_index_.size());
}

void PermissionTreeService::on_stop() {
    spdlog::info("[{}] stopped", name());
}

// --- Join bootstrap (bypasses delta permission checks) ---

bool PermissionTreeService::bootstrap_root(const TreeNode& root_node) {
    std::lock_guard lock(mutex_);

    if (nodes_.contains("root")) {
        spdlog::info("[{}] root node already exists, skipping bootstrap", name());
        return false;
    }

    nodes_[root_node.id] = root_node;
    if (!persist_node(root_node)) {
        spdlog::error("[{}] failed to persist bootstrap root node", name());
        nodes_.erase(root_node.id);
        return false;
    }

    spdlog::info("[{}] bootstrapped root node with pubkey '{}'",
                  name(), root_node.mgmt_pubkey);
    return true;
}

bool PermissionTreeService::insert_join_node(const TreeNode& node) {
    std::lock_guard lock(mutex_);

    if (node.id.empty()) {
        spdlog::error("[{}] insert_join_node: empty node id", name());
        return false;
    }

    if (nodes_.contains(node.id)) {
        // Idempotent: node already exists from a previous join
        spdlog::info("[{}] insert_join_node: node '{}' already exists, skipping",
                      name(), node.id);
        return true;
    }

    if (!node.parent_id.empty() && !nodes_.contains(node.parent_id)) {
        spdlog::error("[{}] insert_join_node: parent '{}' not found for node '{}'",
                       name(), node.parent_id, node.id);
        return false;
    }

    // Reject a colliding identifier owned by a different node; the incumbent
    // keeps it (no rename), which removes the order-dependent squatting vector.
    if (!node.endpoint_identifier.empty()) {
        auto ix = identifier_index_.find(node.endpoint_identifier);
        if (ix != identifier_index_.end() && ix->second != node.id) {
            spdlog::error("[{}] insert_join_node: endpoint_identifier '{}' already "
                          "bound to node '{}' — rejecting colliding node '{}'",
                          name(), node.endpoint_identifier, ix->second, node.id);
            return false;
        }
    }

    nodes_[node.id] = node;
    if (!persist_node(node)) {
        spdlog::error("[{}] failed to persist join node '{}'", name(), node.id);
        nodes_.erase(node.id);
        return false;
    }

    if (!node.endpoint_identifier.empty()) {
        identifier_index_[node.endpoint_identifier] = node.id;
    }

    spdlog::info("[{}] inserted join node '{}' (type={}, parent={})",
                  name(), node.id,
                  node_type_to_string(node.type), node.parent_id);
    return true;
}

bool PermissionTreeService::update_node_direct(const std::string& node_id,
                                                const TreeNode& updated) {
    std::lock_guard lock(mutex_);

    auto it = nodes_.find(node_id);
    if (it == nodes_.end()) {
        spdlog::error("[{}] update_node_direct: node '{}' not found", name(), node_id);
        return false;
    }

    const std::string old_identifier = it->second.endpoint_identifier;

    it->second = updated;
    it->second.id = node_id; // Preserve original ID
    if (!persist_node(it->second)) {
        spdlog::error("[{}] update_node_direct: failed to persist '{}'", name(), node_id);
        return false;
    }

    // Keep the reverse index in sync if the identifier changed.
    if (old_identifier != it->second.endpoint_identifier) {
        if (!old_identifier.empty()) identifier_index_.erase(old_identifier);
        if (!it->second.endpoint_identifier.empty()) {
            identifier_index_[it->second.endpoint_identifier] = node_id;
        }
    }

    spdlog::info("[{}] updated node '{}' directly", name(), node_id);
    return true;
}

bool PermissionTreeService::update_node_endpoint(const std::string& node_id,
                                                  const std::string& new_endpoint) {
    std::lock_guard lock(mutex_);

    auto it = nodes_.find(node_id);
    if (it == nodes_.end()) {
        spdlog::error("[{}] update_node_endpoint: node '{}' not found", name(), node_id);
        return false;
    }

    it->second.listen_endpoint = new_endpoint;
    if (!persist_node(it->second)) {
        spdlog::error("[{}] update_node_endpoint: failed to persist '{}'", name(), node_id);
        return false;
    }

    spdlog::debug("[{}] updated endpoint for node '{}' to '{}'",
                   name(), node_id, new_endpoint);
    return true;
}

bool PermissionTreeService::delete_node_direct(const std::string& node_id) {
    std::lock_guard lock(mutex_);

    auto it = nodes_.find(node_id);
    if (it == nodes_.end()) {
        spdlog::error("[{}] delete_node_direct: node '{}' not found", name(), node_id);
        return false;
    }

    if (!it->second.endpoint_identifier.empty()) {
        identifier_index_.erase(it->second.endpoint_identifier);
    }
    nodes_.erase(it);
    if (!remove_node(node_id)) {
        spdlog::warn("[{}] delete_node_direct: storage delete failed for '{}'", name(), node_id);
    }

    spdlog::info("[{}] deleted node '{}' directly", name(), node_id);
    return true;
}

bool PermissionTreeService::grant_assignment(const std::string& node_id,
                                              const Assignment& assignment) {
    std::lock_guard lock(mutex_);

    auto it = nodes_.find(node_id);
    if (it == nodes_.end()) {
        spdlog::warn("[{}] grant_assignment: node '{}' not found", name(), node_id);
        return false;
    }

    // Idempotent: skip if pubkey already has an assignment
    for (const auto& a : it->second.assignments) {
        if (a.management_pubkey == assignment.management_pubkey) {
            spdlog::debug("[{}] grant_assignment: pubkey already assigned on '{}'",
                           name(), node_id);
            return true;
        }
    }

    it->second.assignments.push_back(assignment);
    if (!persist_node(it->second)) {
        spdlog::error("[{}] grant_assignment: failed to persist node '{}'",
                       name(), node_id);
        it->second.assignments.pop_back();
        return false;
    }

    spdlog::info("[{}] granted assignment on '{}' to pubkey '{}'",
                  name(), node_id, assignment.management_pubkey.substr(0, 24));
    return true;
}

// --- ITreeProvider ---

bool PermissionTreeService::do_apply_delta(const TreeDelta& delta) {
    std::lock_guard lock(mutex_);

    // 1. Determine required permission for the operation
    acl::Permission required = acl::Permission::None;
    if (delta.operation == "create_node") {
        required = acl::Permission::AddChild;
    } else if (delta.operation == "update_node" || delta.operation == "allocate_ip" ||
               delta.operation == "register_relay" || delta.operation == "update_assignment") {
        required = acl::Permission::EditNode;
    } else if (delta.operation == "delete_node") {
        required = acl::Permission::DeleteNode;
    } else {
        spdlog::error("[{}] unknown delta operation '{}'", name(), delta.operation);
        return false;
    }

    // 2. For create_node, check permission on the parent; otherwise on the target
    const auto& check_node_id = (delta.operation == "create_node")
                                    ? delta.node_data.parent_id
                                    : delta.target_node_id;

    auto check_it = nodes_.find(check_node_id);
    if (check_it == nodes_.end()) {
        spdlog::error("[{}] permission check target node '{}' not found",
                       name(), check_node_id);
        return false;
    }

    // Verify signer has the required permission via assignments
    bool has_perm = false;
    for (const auto& assignment : check_it->second.assignments) {
        if (assignment.management_pubkey == delta.signer_pubkey) {
            for (const auto& perm_str : assignment.permissions) {
                if (acl::has_permission(string_to_permission(perm_str), required)) {
                    has_perm = true;
                    break;
                }
            }
            break;
        }
    }

    if (!has_perm) {
        spdlog::warn("[{}] signer '{}' lacks permission for '{}' on node '{}'",
                      name(), delta.signer_pubkey, delta.operation, check_node_id);
        return false;
    }

    // 3. Verify Ed25519 signature over canonical delta JSON
    const auto canonical = canonical_delta_json(delta);
    const auto msg_bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());

    // Extract raw public key from "ed25519:base64..." format
    const std::string_view pubkey_str = delta.signer_pubkey;
    constexpr std::string_view prefix = "ed25519:";
    if (!pubkey_str.starts_with(prefix)) {
        spdlog::error("[{}] signer_pubkey has invalid format: '{}'",
                       name(), delta.signer_pubkey);
        return false;
    }
    const auto pubkey_b64 = pubkey_str.substr(prefix.size());
    const auto pubkey_bytes = crypto::from_base64(pubkey_b64);
    if (pubkey_bytes.size() != crypto::kEd25519PublicKeySize) {
        spdlog::error("[{}] signer_pubkey has invalid key size: {}",
                       name(), pubkey_bytes.size());
        return false;
    }

    crypto::Ed25519PublicKey pubkey{};
    std::copy_n(pubkey_bytes.begin(), crypto::kEd25519PublicKeySize, pubkey.begin());

    const auto sig_bytes = crypto::from_base64(delta.signature);
    if (sig_bytes.size() != crypto::kEd25519SignatureSize) {
        spdlog::error("[{}] delta signature has invalid size: {}", name(), sig_bytes.size());
        return false;
    }

    crypto::Ed25519Signature sig{};
    std::copy_n(sig_bytes.begin(), crypto::kEd25519SignatureSize, sig.begin());

    if (!crypto_.ed25519_verify(pubkey, msg_bytes, sig)) {
        spdlog::warn("[{}] delta signature verification failed for operation '{}' on '{}'",
                      name(), delta.operation, delta.target_node_id);
        return false;
    }

    // 3b. Timestamp freshness: reject deltas with missing, stale, or future timestamps
    {
        auto now_sec = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());

        if (delta.timestamp == 0) {
            spdlog::warn("[{}] rejecting delta with zero timestamp for '{}' on '{}'",
                          name(), delta.operation, delta.target_node_id);
            return false;
        }
        constexpr uint64_t kMaxAgeSec    = 300;  // 5 minutes
        constexpr uint64_t kMaxFutureSec = 60;   // 1 minute

        if (delta.timestamp + kMaxAgeSec < now_sec) {
            spdlog::warn("[{}] rejecting stale delta (ts={}, now={}) for '{}' on '{}'",
                          name(), delta.timestamp, now_sec, delta.operation, delta.target_node_id);
            return false;
        }
        if (delta.timestamp > now_sec + kMaxFutureSec) {
            spdlog::warn("[{}] rejecting future delta (ts={}, now={}) for '{}' on '{}'",
                          name(), delta.timestamp, now_sec, delta.operation, delta.target_node_id);
            return false;
        }
    }

    // 3c. Replay protection: reject duplicate deltas based on canonical hash
    {
        const auto delta_hash = crypto_.sha256(msg_bytes);
        std::string hash_hex;
        hash_hex.reserve(64);
        for (auto b : delta_hash) {
            char buf[3];
            std::snprintf(buf, sizeof(buf), "%02x", b);
            hash_hex.append(buf);
        }

        auto now_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());

        if (recent_deltas_.contains(hash_hex)) {
            spdlog::warn("[{}] rejecting replayed delta for '{}' on '{}'",
                          name(), delta.operation, delta.target_node_id);
            return false;
        }
        recent_deltas_[hash_hex] = now_ms;
        evict_replay_cache();
    }

    // 4. Apply the operation
    if (delta.operation == "create_node") {
        if (nodes_.contains(delta.node_data.id)) {
            spdlog::error("[{}] cannot create node '{}': already exists",
                           name(), delta.node_data.id);
            return false;
        }
        nodes_[delta.node_data.id] = delta.node_data;
        if (!persist_node(delta.node_data)) {
            spdlog::error("[{}] failed to persist new node '{}'",
                           name(), delta.node_data.id);
            nodes_.erase(delta.node_data.id);
            return false;
        }
    } else if (delta.operation == "update_node" || delta.operation == "allocate_ip" ||
               delta.operation == "register_relay" || delta.operation == "update_assignment") {
        auto it = nodes_.find(delta.target_node_id);
        if (it == nodes_.end()) {
            spdlog::error("[{}] cannot update node '{}': not found",
                           name(), delta.target_node_id);
            return false;
        }
        it->second = delta.node_data;
        if (!persist_node(it->second)) {
            spdlog::error("[{}] failed to persist updated node '{}'",
                           name(), delta.target_node_id);
            return false;
        }
    } else if (delta.operation == "delete_node") {
        auto it = nodes_.find(delta.target_node_id);
        if (it == nodes_.end()) {
            spdlog::error("[{}] cannot delete node '{}': not found",
                           name(), delta.target_node_id);
            return false;
        }
        nodes_.erase(it);
        if (!remove_node(delta.target_node_id)) {
            spdlog::warn("[{}] node '{}' removed from cache but storage delete failed",
                          name(), delta.target_node_id);
        }
    }

    // 5. Append delta to the storage log
    storage::SignedDelta signed_delta;
    signed_delta.operation      = delta.operation;
    signed_delta.target_node_id = delta.target_node_id;
    signed_delta.data           = json(delta.node_data).dump();
    signed_delta.signer_pubkey  = delta.signer_pubkey;
    signed_delta.signature      = delta.signature;
    signed_delta.timestamp      = delta.timestamp;

    const auto seq = storage_.append_delta(signed_delta);
    if (seq == 0) {
        spdlog::warn("[{}] failed to append delta to log (operation '{}' on '{}')",
                      name(), delta.operation, delta.target_node_id);
    }

    spdlog::info("[{}] applied delta: {} on '{}' (seq {})",
                  name(), delta.operation, delta.target_node_id, seq);
    return true;
}

std::optional<TreeNode> PermissionTreeService::do_get_node(std::string_view node_id) const {
    std::lock_guard lock(mutex_);
    auto it = nodes_.find(std::string(node_id));
    if (it != nodes_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::string PermissionTreeService::derive_endpoint_identifier(const TreeNode& node) const {
    // Pure: derive purely from the node's own stable inputs.
    return routing::derive_endpoint_identifier(node.id, node.region, node.cpu_id,
                                                node.net_mac, node.is_inference);
}

bool PermissionTreeService::validate_identifier_binding(const TreeNode& node) const {
    if (node.endpoint_identifier.empty()) {
        return false;
    }
    return node.endpoint_identifier == derive_endpoint_identifier(node);
}

std::optional<TreeNode> PermissionTreeService::resolve_by_identifier(
        std::string_view identifier) const {
    std::lock_guard lock(mutex_);
    auto ix = identifier_index_.find(std::string(identifier));
    if (ix == identifier_index_.end()) {
        return std::nullopt;
    }
    auto it = nodes_.find(ix->second);
    if (it == nodes_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<TreeNode> PermissionTreeService::collect_subtree(std::string_view root_parent_id,
                                                             std::size_t max_depth,
                                                             std::size_t max_nodes) const {
    std::lock_guard lock(mutex_);
    std::vector<TreeNode> result;

    // Build a parent_id -> children adjacency once, so the BFS is linear.
    std::unordered_map<std::string, std::vector<const TreeNode*>> children_of;
    for (const auto& [id, node] : nodes_) {
        children_of[node.parent_id].push_back(&node);
    }

    // Independent cycle guard; seed with the root so a loop can't re-expand it.
    std::unordered_set<std::string> visited;
    visited.insert(std::string(root_parent_id));

    std::vector<std::string> frontier{std::string(root_parent_id)};
    std::size_t depth = 0;
    while (!frontier.empty() && depth < max_depth) {
        std::vector<std::string> next;
        for (const auto& pid : frontier) {
            auto it = children_of.find(pid);
            if (it == children_of.end()) continue;
            for (const TreeNode* child : it->second) {
                if (!visited.insert(child->id).second) continue; // cycle/dup guard
                result.push_back(*child);
                if (result.size() >= max_nodes) {
                    spdlog::warn("[{}] collect_subtree hit max_nodes={} under '{}' -- truncating",
                                 name(), max_nodes, std::string(root_parent_id));
                    return result;
                }
                next.push_back(child->id);
            }
        }
        frontier = std::move(next);
        ++depth;
    }
    if (depth >= max_depth && !frontier.empty()) {
        spdlog::warn("[{}] collect_subtree hit max_depth={} under '{}' -- truncating",
                     name(), max_depth, std::string(root_parent_id));
    }
    return result;
}

bool PermissionTreeService::is_descendant_of(std::string_view node_id,
                                              std::string_view ancestor_id) const {
    std::lock_guard lock(mutex_);
    if (node_id == ancestor_id) return false; // a node is not its own descendant

    std::unordered_set<std::string> visited;
    std::string current(node_id);
    while (true) {
        if (!visited.insert(current).second) return false; // cycle
        auto it = nodes_.find(current);
        if (it == nodes_.end()) return false;
        const std::string& parent = it->second.parent_id;
        if (parent.empty()) return false;          // reached root, no match
        if (parent == ancestor_id) return true;
        current = parent;
    }
}

std::optional<TreeNode> PermissionTreeService::resolve_authorized(
        std::string_view caller_pubkey,
        std::string_view caller_node_id,
        std::string_view identifier) const {
    // Composes individually-locked methods; must NOT be called while holding mutex_.
    auto target = resolve_by_identifier(identifier);
    if (!target) return std::nullopt;
    if (!validate_identifier_binding(*target)) return std::nullopt;

    auto caller = do_get_node(caller_node_id);
    if (!caller) return std::nullopt;
    if (caller->parent_id.empty()) return std::nullopt;   // root owns no group
    if (target->id == caller_node_id) return std::nullopt; // no self-connect

    // Scope: target must be within the caller's parent-group subtree.
    if (!is_descendant_of(target->id, caller->parent_id)) return std::nullopt;

    // Per-node ACL — permissions are not inherited.
    if (!do_check_permission(caller_pubkey, target->id, acl::Permission::ConnectPrivate) &&
        !do_check_permission(caller_pubkey, target->id, acl::Permission::ConnectShared)) {
        return std::nullopt;
    }
    return target;
}

std::vector<TreeNode> PermissionTreeService::do_get_children(std::string_view parent_id) const {
    std::lock_guard lock(mutex_);
    std::vector<TreeNode> children;
    const std::string pid(parent_id);
    for (const auto& [id, node] : nodes_) {
        if (node.parent_id == pid) {
            children.push_back(node);
        }
    }
    return children;
}

bool PermissionTreeService::do_validate_signature_chain(std::string_view node_id) const {
    std::lock_guard lock(mutex_);

    std::string current_id(node_id);

    // Cycle guard: a corrupt/malicious parent_id can form a loop (self-parent or
    // A->B->A). Without this, the walk spins forever holding mutex_, wedging every
    // other tree operation. Reject any chain that revisits a node or exceeds the
    // node count (a valid chain visits each node at most once on the way to root).
    std::unordered_set<std::string> visited;

    while (true) {
        if (!visited.insert(current_id).second) {
            spdlog::error("[{}] signature chain has a cycle at node '{}' -- rejecting",
                           name(), current_id);
            return false;
        }

        auto it = nodes_.find(current_id);
        if (it == nodes_.end()) {
            spdlog::error("[{}] signature chain broken: node '{}' not found",
                           name(), current_id);
            return false;
        }
        const auto& node = it->second;

        // Root node is self-signed; verify against its own mgmt_pubkey
        if (node.type == NodeType::Root) {
            const auto canonical = canonical_node_json(node);
            const auto msg = std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());

            constexpr std::string_view pfx = "ed25519:";
            if (!node.mgmt_pubkey.starts_with(pfx)) return false;
            const auto pk_bytes = crypto::from_base64(
                std::string_view(node.mgmt_pubkey).substr(pfx.size()));
            if (pk_bytes.size() != crypto::kEd25519PublicKeySize) return false;

            crypto::Ed25519PublicKey pk{};
            std::copy_n(pk_bytes.begin(), crypto::kEd25519PublicKeySize, pk.begin());

            const auto sig_bytes = crypto::from_base64(node.signature);
            if (sig_bytes.size() != crypto::kEd25519SignatureSize) return false;

            crypto::Ed25519Signature sig{};
            std::copy_n(sig_bytes.begin(), crypto::kEd25519SignatureSize, sig.begin());

            if (!crypto_.ed25519_verify(pk, msg, sig)) {
                spdlog::error("[{}] root node '{}' self-signature invalid",
                               name(), node.id);
                return false;
            }
            return true; // chain verified up to root
        }

        // Non-root: verify signature against parent's mgmt_pubkey
        auto parent_it = nodes_.find(node.parent_id);
        if (parent_it == nodes_.end()) {
            spdlog::error("[{}] signature chain broken: parent '{}' of node '{}' not found",
                           name(), node.parent_id, current_id);
            return false;
        }
        const auto& parent = parent_it->second;

        const auto canonical = canonical_node_json(node);
        const auto msg = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());

        constexpr std::string_view pfx = "ed25519:";
        if (!parent.mgmt_pubkey.starts_with(pfx)) return false;
        const auto pk_bytes = crypto::from_base64(
            std::string_view(parent.mgmt_pubkey).substr(pfx.size()));
        if (pk_bytes.size() != crypto::kEd25519PublicKeySize) return false;

        crypto::Ed25519PublicKey pk{};
        std::copy_n(pk_bytes.begin(), crypto::kEd25519PublicKeySize, pk.begin());

        const auto sig_bytes = crypto::from_base64(node.signature);
        if (sig_bytes.size() != crypto::kEd25519SignatureSize) return false;

        crypto::Ed25519Signature sig{};
        std::copy_n(sig_bytes.begin(), crypto::kEd25519SignatureSize, sig.begin());

        if (!crypto_.ed25519_verify(pk, msg, sig)) {
            spdlog::error("[{}] node '{}' signature invalid (signed by parent '{}')",
                           name(), node.id, parent.id);
            return false;
        }

        // Walk up to the parent
        current_id = node.parent_id;
    }
}

bool PermissionTreeService::do_check_permission(std::string_view signer_pubkey,
                                                  std::string_view node_id,
                                                  acl::Permission perm) const {
    std::lock_guard lock(mutex_);

    auto it = nodes_.find(std::string(node_id));
    if (it == nodes_.end()) {
        return false;
    }

    for (const auto& assignment : it->second.assignments) {
        if (assignment.management_pubkey == signer_pubkey) {
            for (const auto& perm_str : assignment.permissions) {
                if (acl::has_permission(string_to_permission(perm_str), perm)) {
                    return true;
                }
            }
            return false; // signer found but lacks the required permission
        }
    }
    return false; // signer not found in assignments
}

crypto::Hash256 PermissionTreeService::do_get_tree_hash() const {
    std::lock_guard lock(mutex_);

    // Collect all node IDs and sort them for deterministic ordering
    std::vector<std::string> ids;
    ids.reserve(nodes_.size());
    for (const auto& [id, node] : nodes_) {
        ids.push_back(id);
    }
    std::sort(ids.begin(), ids.end());

    // SHA-256 each node's canonical JSON, then SHA-256 the concatenation of all hashes
    std::vector<uint8_t> concatenated;
    concatenated.reserve(ids.size() * crypto::kHash256Size);

    for (const auto& id : ids) {
        const auto& node = nodes_.at(id);
        const auto canonical = canonical_node_json(node);
        const auto data = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
        const auto hash = crypto_.sha256(data);
        concatenated.insert(concatenated.end(), hash.begin(), hash.end());
    }

    return crypto_.sha256(std::span<const uint8_t>(concatenated));
}

std::vector<TreeNode> PermissionTreeService::do_get_nodes_by_type(NodeType type) const {
    std::lock_guard lock(mutex_);
    std::vector<TreeNode> result;
    for (const auto& [id, node] : nodes_) {
        if (node.type == type) {
            result.push_back(node);
        }
    }
    return result;
}

// --- Private helpers ---

bool PermissionTreeService::persist_node(const TreeNode& node) {
    storage::SignedEnvelope envelope;
    envelope.version       = 1;
    envelope.type          = "tree_node";
    envelope.data          = json(node).dump();
    envelope.signer_pubkey = node.mgmt_pubkey;
    envelope.signature     = node.signature;
    envelope.timestamp     = 0;
    return storage_.write_node(node.id, envelope);
}

bool PermissionTreeService::remove_node(std::string_view node_id) {
    return storage_.delete_node(node_id);
}

void PermissionTreeService::evict_replay_cache() {
    constexpr uint64_t kEvictAfterMs = 600000; // 10 minutes
    auto now_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());

    for (auto it = recent_deltas_.begin(); it != recent_deltas_.end(); ) {
        if (now_ms - it->second > kEvictAfterMs) {
            it = recent_deltas_.erase(it);
        } else {
            ++it;
        }
    }
}

acl::Permission PermissionTreeService::string_to_permission(std::string_view perm_str) {
    if (perm_str == "read")            return acl::Permission::Read;
    if (perm_str == "write")           return acl::Permission::Write;
    if (perm_str == "add_child")       return acl::Permission::AddChild;
    if (perm_str == "edit_node")       return acl::Permission::EditNode;
    if (perm_str == "delete_node")     return acl::Permission::DeleteNode;
    if (perm_str == "expand_subnet")   return acl::Permission::ExpandSubnet;
    if (perm_str == "connect_private") return acl::Permission::ConnectPrivate;
    if (perm_str == "connect_shared")  return acl::Permission::ConnectShared;
    if (perm_str == "relay_forward")   return acl::Permission::RelayForward;
    if (perm_str == "stun_respond")    return acl::Permission::StunRespond;
    if (perm_str == "relay_register")  return acl::Permission::RelayRegister;
    if (perm_str == "allocate_ip")     return acl::Permission::AllocateIP;
    if (perm_str == "admin")           return acl::Permission::Admin;
    return acl::Permission::None;
}

} // namespace nexus::tree
