#include <LemonadeNexus/Account/AccountDataStore.hpp>

#include <LemonadeNexus/ACL/Permission.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

namespace nexus::account {
namespace {
Result error(int status, const char* message) { return {status, {{"error", message}}}; }
}

bool AccountDataStore::avatar_authorized(const AccountAvatarRecord& r) const {
    const auto group = tree_.get_node(r.group_id);
    return group && group->type == tree::NodeType::Customer &&
           is_member_device(r.group_id, "ed25519:" + r.author_pubkey) &&
           can_write(r.author_pubkey, r.group_id) && verify_avatar(r, crypto_);
}

std::optional<AccountAvatarRecord> AccountDataStore::read_avatar(const std::string& group) const {
    std::optional<AccountAvatarRecord> current;
    const auto category = "avatar-ref-" + hex_sha256(group);
    for (const auto& id : storage_.list_files(category)) {
        const auto env = storage_.read_file(category, id + ".json");
        if (!env) continue;
        const auto record = avatar_from_wire(nlohmann::json::parse(env->data, nullptr, false));
        if (!record || record->group_id != group || !avatar_authorized(*record)) continue;
        if (!current || avatar_newer(*record, *current)) current = record;
    }
    return current;
}

Result AccountDataStore::get_avatar(const std::string& caller_node,
                                   const std::string& caller_pubkey) const {
    const auto group = group_of(caller_node);
    const auto node = tree_.get_node(caller_node);
    const auto owner = group ? tree_.get_node(*group) : std::nullopt;
    if (!group || !node || node->type != tree::NodeType::Endpoint ||
        !owner || owner->type != tree::NodeType::Customer ||
        tree::canonical_principal(node->mgmt_pubkey) !=
            tree::canonical_principal(with_ed25519_prefix(caller_pubkey)) ||
        !can_read(caller_pubkey, *group)) return error(404, "not found");
    std::lock_guard lock(avatar_mutex_);
    const auto record = read_avatar(*group);
    nlohmann::json devices = nlohmann::json::array();
    for (const auto& device : tree_.get_children(*group)) {
        const auto key = tree::canonical_principal(device.mgmt_pubkey);
        if (device.type != tree::NodeType::Endpoint || !can_read(key, *group)) continue;
        const auto connects = [&](const std::string& principal, const std::string& target) {
            const auto normalized = with_ed25519_prefix(principal);
            return tree_.check_permission(normalized, target, acl::Permission::ConnectPrivate) ||
                   tree_.check_permission(normalized, target, acl::Permission::ConnectShared);
        };
        devices.push_back({{"node_id", device.id}, {"pubkey", key},
            {"can_fetch_from_me", connects(key, caller_node)},
            {"can_serve_me", connects(caller_pubkey, device.id)}});
    }
    return {200, {{"protocol", "nexus.account_avatar.ref.v2"}, {"group_id", *group},
                   {"revision", record ? record->revision : 0},
                   {"record", record ? avatar_wire(*record) : nlohmann::json()},
                   {"devices", std::move(devices)},
                   {"can_write", can_write(caller_pubkey, *group)}}};
}

bool AccountDataStore::write_avatar(const AccountAvatarRecord& record) {
    const auto category = "avatar-ref-" + hex_sha256(record.group_id);
    const auto filename = principal_hash(record.author_pubkey) + ".json";
    if (const auto previous = storage_.read_file(category, filename)) {
        const auto old = avatar_from_wire(nlohmann::json::parse(previous->data, nullptr, false));
        if (old && verify_avatar(*old, crypto_) && !avatar_newer(record, *old)) {
            return avatar_canonical(record) == avatar_canonical(*old);
        }
    }
    storage::SignedEnvelope env;
    env.type = "account_avatar";
    env.data = avatar_wire(record).dump();
    env.signer_pubkey = "ed25519:" + record.author_pubkey;
    env.signature = record.signature;
    env.timestamp = record.revision;
    return storage_.write_file_atomic(category, filename, env);
}

Result AccountDataStore::put_avatar(const std::string& caller_node,
                                   const std::string& caller_pubkey,
                                   const nlohmann::json& body, std::size_t body_size) {
    if (body_size > kMaxAvatarRecordBytes) return error(413, "profile image too large");
    const auto record = avatar_from_wire(body);
    if (!record) return error(400, "invalid profile image record");
    const auto group = group_of(caller_node);
    const auto node = tree_.get_node(caller_node);
    if (!group || !node || node->type != tree::NodeType::Endpoint || *group != record->group_id ||
        tree::canonical_principal(with_ed25519_prefix(caller_pubkey)) != "ed25519:" + record->author_pubkey ||
        tree::canonical_principal(node->mgmt_pubkey) != "ed25519:" + record->author_pubkey ||
        !can_read(caller_pubkey, *group) || !can_write(caller_pubkey, *group)) return error(404, "not found");
    if (!avatar_authorized(*record)) return error(400, "invalid profile image reference or signature");
    {
        std::lock_guard lock(avatar_mutex_);
        const auto current = read_avatar(*group);
        if (current && record->revision <= current->revision) return error(409, "profile image changed; refresh and try again");
        if (!write_avatar(*record)) return error(500, "profile image write failed");
    }
    if (avatar_publisher_) avatar_publisher_(*record);
    return get_avatar(caller_node, caller_pubkey);
}

void AccountDataStore::set_avatar_publisher(std::function<void(AccountAvatarRecord)> publisher) {
    avatar_publisher_ = std::move(publisher);
}

bool AccountDataStore::apply_replicated_avatar(const AccountAvatarRecord& record) {
    if (!avatar_authorized(record)) return false;
    std::lock_guard lock(avatar_mutex_);
    return write_avatar(record);
}

} // namespace nexus::account
