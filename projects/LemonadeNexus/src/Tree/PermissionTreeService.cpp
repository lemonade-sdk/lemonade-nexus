#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>

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

    spdlog::info("[{}] loaded {} nodes from storage", name(), nodes_.size());
}

void PermissionTreeService::on_stop() {
    spdlog::info("[{}] stopped", name());
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

    while (true) {
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
