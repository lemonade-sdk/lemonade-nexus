#include <LemonadeNexus/Account/AccountDataStore.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/ACL/Permission.hpp>

#include <array>
#include <ctime>
#include <span>

namespace nexus::account {

namespace {
Result err(int status, std::string msg) {
    return Result{status, nlohmann::json{{"error", std::move(msg)}}};
}
// Uniform "you don't own this / it isn't here" reply — never distinguishes
// missing from forbidden, so non-members can't probe for existence.
Result not_found() { return err(404, "not found"); }
} // namespace

bool is_hex_id(std::string_view s) {
    if (s.empty() || s.size() > 64) return false;
    for (char c : s) {
        const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hex) return false;
    }
    return true;
}

std::string with_ed25519_prefix(const std::string& pk) {
    constexpr std::string_view prefix = "ed25519:";
    return pk.starts_with(prefix) ? pk : std::string(prefix) + pk;
}

AccountDataStore::AccountDataStore(crypto::SodiumCryptoService& crypto,
                                   tree::PermissionTreeService& tree,
                                   storage::FileStorageService& storage)
    : crypto_(crypto), tree_(tree), storage_(storage) {}

std::string AccountDataStore::hex_sha256(const std::string& s) const {
    auto h = crypto_.sha256(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()), s.size()));
    return crypto::to_hex(std::span<const uint8_t>(h.data(), h.size()));
}

std::string AccountDataStore::chat_category(const std::string& group) const {
    return "chat-" + hex_sha256(group);
}

std::string AccountDataStore::keyenv_category(const std::string& group) const {
    return "keyenv-" + hex_sha256(group);
}

std::string AccountDataStore::principal_hash(const std::string& pubkey) const {
    return hex_sha256(tree::canonical_principal(with_ed25519_prefix(pubkey)));
}

std::optional<std::string> AccountDataStore::group_of(const std::string& caller_node) const {
    auto node = tree_.get_node(caller_node);
    if (!node || node->parent_id.empty()) return std::nullopt;
    return node->parent_id;
}

bool AccountDataStore::can_read(const std::string& caller_pubkey, const std::string& group) const {
    return tree_.check_permission(with_ed25519_prefix(caller_pubkey), group,
                                  acl::Permission::Read);
}

bool AccountDataStore::can_write(const std::string& caller_pubkey, const std::string& group) const {
    return tree_.check_permission(with_ed25519_prefix(caller_pubkey), group,
                                  acl::Permission::Write);
}

// --- Chat blobs ---

Result AccountDataStore::create_chat(const std::string& caller_node,
                                     const std::string& caller_pubkey,
                                     const nlohmann::json& blob, std::size_t body_size) {
    auto group = group_of(caller_node);
    if (!group) return err(403, "no account group");
    if (!can_write(caller_pubkey, *group)) return not_found();
    if (body_size > kMaxBlobBytes) return err(413, "blob too large");

    std::array<uint8_t, 16> rid{};
    crypto_.random_bytes(std::span<uint8_t>(rid));
    auto chat_id = crypto::to_hex(std::span<const uint8_t>(rid.data(), rid.size()));

    storage::SignedEnvelope env;
    env.type          = "chat_blob";
    env.data          = blob.dump();
    env.signer_pubkey = with_ed25519_prefix(caller_pubkey);
    env.signature     = blob.value("signature", std::string{});
    env.timestamp     = static_cast<uint64_t>(std::time(nullptr));

    if (!storage_.write_file(chat_category(*group), chat_id + ".json", env))
        return err(500, "write failed");
    return Result{201, {{"chat_id", chat_id}, {"updated_at", env.timestamp}}};
}

Result AccountDataStore::list_chats(const std::string& caller_node,
                                    const std::string& caller_pubkey) const {
    auto group = group_of(caller_node);
    if (!group) return err(403, "no account group");
    if (!can_read(caller_pubkey, *group)) return not_found();

    const auto category = chat_category(*group);
    nlohmann::json chats = nlohmann::json::array();
    for (const auto& id : storage_.list_files(category)) {
        auto env = storage_.read_file(category, id + ".json");
        if (!env) continue;
        chats.push_back({{"chat_id", id},
                         {"updated_at", env->timestamp},
                         {"size", static_cast<uint64_t>(env->data.size())}});
    }
    return Result{200, {{"chats", std::move(chats)}}};
}

Result AccountDataStore::get_chat(const std::string& caller_node,
                                  const std::string& caller_pubkey,
                                  const std::string& chat_id) const {
    auto group = group_of(caller_node);
    if (!group) return err(403, "no account group");
    if (!can_read(caller_pubkey, *group)) return not_found();
    if (!is_hex_id(chat_id)) return not_found();

    auto env = storage_.read_file(chat_category(*group), chat_id + ".json");
    if (!env) return not_found();

    nlohmann::json out = nlohmann::json::parse(env->data, nullptr, false);
    if (out.is_discarded()) out = nlohmann::json::object();
    out["chat_id"]    = chat_id;
    out["updated_at"] = env->timestamp;
    return Result{200, std::move(out)};
}

Result AccountDataStore::update_chat(const std::string& caller_node,
                                     const std::string& caller_pubkey,
                                     const std::string& chat_id,
                                     const nlohmann::json& blob, std::size_t body_size) {
    auto group = group_of(caller_node);
    if (!group) return err(403, "no account group");
    if (!can_write(caller_pubkey, *group)) return not_found();
    if (!is_hex_id(chat_id)) return not_found();
    if (body_size > kMaxBlobBytes) return err(413, "blob too large");

    const auto category = chat_category(*group);
    if (!storage_.read_file(category, chat_id + ".json")) return not_found();  // update != create

    storage::SignedEnvelope env;
    env.type          = "chat_blob";
    env.data          = blob.dump();
    env.signer_pubkey = with_ed25519_prefix(caller_pubkey);
    env.signature     = blob.value("signature", std::string{});
    env.timestamp     = static_cast<uint64_t>(std::time(nullptr));
    if (!storage_.write_file(category, chat_id + ".json", env))
        return err(500, "write failed");
    return Result{200, {{"chat_id", chat_id}, {"updated_at", env.timestamp}}};
}

Result AccountDataStore::delete_chat(const std::string& caller_node,
                                     const std::string& caller_pubkey,
                                     const std::string& chat_id) {
    auto group = group_of(caller_node);
    if (!group) return err(403, "no account group");
    if (!can_write(caller_pubkey, *group)) return not_found();
    if (!is_hex_id(chat_id)) return not_found();

    if (!storage_.delete_file(chat_category(*group), chat_id + ".json")) return not_found();
    return Result{200, {{"success", true}}};
}

// --- Group-key envelopes ---

Result AccountDataStore::put_envelope(const std::string& caller_node,
                                      const std::string& caller_pubkey,
                                      const nlohmann::json& body, std::size_t body_size) {
    auto group = group_of(caller_node);
    if (!group) return err(403, "no account group");
    if (!can_write(caller_pubkey, *group)) return not_found();
    if (body_size > kMaxBlobBytes) return err(413, "envelope too large");

    auto target = body.value("target_pubkey", std::string{});
    if (target.empty()) return err(400, "missing target_pubkey");

    // The target must be an Endpoint device under the SAME Customer group, so a
    // member cannot provision the group key to a non-member.
    const auto target_principal = tree::canonical_principal(with_ed25519_prefix(target));
    bool is_member = false;
    for (const auto& child : tree_.get_children(*group)) {
        if (child.type == tree::NodeType::Endpoint &&
            tree::canonical_principal(with_ed25519_prefix(child.mgmt_pubkey)) == target_principal) {
            is_member = true;
            break;
        }
    }
    if (!is_member) return not_found();

    nlohmann::json data = {
        {"recipient_pubkey", target_principal},
        {"key_id",           body.value("key_id", std::string{})},
        {"ephemeral_pubkey", body.value("ephemeral_pubkey", std::string{})},
        {"wrapped_key",      body.value("wrapped_key", std::string{})},
        {"created_by",       with_ed25519_prefix(caller_pubkey)},
    };
    storage::SignedEnvelope env;
    env.type          = "group_key_envelope";
    env.data          = data.dump();
    env.signer_pubkey = with_ed25519_prefix(caller_pubkey);
    env.signature     = body.value("signature", std::string{});
    env.timestamp     = static_cast<uint64_t>(std::time(nullptr));

    if (!storage_.write_file(keyenv_category(*group), principal_hash(target) + ".json", env))
        return err(500, "write failed");
    return Result{200, {{"success", true}, {"recipient", target_principal}}};
}

Result AccountDataStore::get_envelope(const std::string& caller_node,
                                      const std::string& caller_pubkey) const {
    auto group = group_of(caller_node);
    if (!group) return err(403, "no account group");
    if (!can_read(caller_pubkey, *group)) return not_found();

    auto env = storage_.read_file(keyenv_category(*group),
                                  principal_hash(caller_pubkey) + ".json");
    if (!env) return not_found();
    nlohmann::json out = nlohmann::json::parse(env->data, nullptr, false);
    if (out.is_discarded()) out = nlohmann::json::object();
    return Result{200, std::move(out)};
}

Result AccountDataStore::pending_envelopes(const std::string& caller_node,
                                           const std::string& caller_pubkey) const {
    auto group = group_of(caller_node);
    if (!group) return err(403, "no account group");
    if (!can_read(caller_pubkey, *group)) return not_found();

    const auto category = keyenv_category(*group);
    nlohmann::json pending = nlohmann::json::array();
    for (const auto& child : tree_.get_children(*group)) {
        if (child.type != tree::NodeType::Endpoint) continue;
        if (storage_.read_file(category, principal_hash(child.mgmt_pubkey) + ".json")) continue;
        pending.push_back({{"node_id", child.id}, {"pubkey", child.mgmt_pubkey}});
    }
    return Result{200, {{"pending", std::move(pending)}}};
}

} // namespace nexus::account
