#include <LemonadeNexus/Core/TreeMigrationControl.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Tree/TreeMerge.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <exception>

namespace nexus::core {

namespace {

using json = nlohmann::json;

json refuse(std::string error) { return json{{"ok", false}, {"error", std::move(error)}}; }

/// The canonical spelling of an "ed25519:<base64>" principal, or empty.
std::string canonical(const std::string& principal) {
    constexpr std::string_view prefix = "ed25519:";
    if (!std::string_view(principal).starts_with(prefix)) return {};
    std::vector<uint8_t> bytes;
    try {
        bytes = crypto::from_base64(principal.substr(prefix.size()));
    } catch (const std::exception&) {
        return {};
    }
    if (bytes.size() != crypto::kEd25519PublicKeySize) return {};
    return std::string(prefix) + crypto::to_base64(bytes);
}

/// The exports and block time of a build or sign request.
struct BuildRequest {
    std::vector<json> exports;
    uint64_t block_time_ms = 0;
};

std::optional<BuildRequest> parse_build(const json& request, const TreeMigrationHooks& hooks,
                                        std::string& error) {
    const auto exports = request.find("exports");
    if (exports == request.end() || !exports->is_array() || exports->empty()) {
        error = "exports must be a non-empty array";
        return std::nullopt;
    }
    if (exports->size() > kMaxTreeMigrationExports) {
        error = "too many exports";
        return std::nullopt;
    }
    BuildRequest out;
    out.exports.assign(exports->begin(), exports->end());
    const auto time = request.find("block_time_ms");
    if (time == request.end()) {
        out.block_time_ms = hooks.wall_clock_ms();
    } else if (time->is_number_unsigned() && time->get<uint64_t>() > 0) {
        out.block_time_ms = time->get<uint64_t>();
    } else {
        error = "block_time_ms must be a positive integer";
        return std::nullopt;
    }
    return out;
}

tree::SignedMergeInput merge_input(const TreeMigrationFacts& facts, uint64_t block_time_ms) {
    tree::SignedMergeInput input;
    input.network_id = facts.network_id;
    input.root_key = facts.root_key;
    input.root_signer = facts.signer;
    for (const auto& member : facts.members) input.members.push_back(member.signer);
    input.block_time_ms = block_time_ms;
    return input;
}

json build_reply(const tree::SignedMergeBuild& build) {
    json reply = {{"ok", build.entry.has_value()}, {"report", build.report}};
    if (!build.entry) {
        reply["error"] = "the merge has conflicts; see report.conflicts";
    } else {
        reply["preimage"] = build.preimage;
    }
    return reply;
}

json handle(const json& request, const TreeMigrationHooks& hooks) {
    const auto op = request.value("op", "");
    const auto facts = hooks.facts();

    if (op == "tree_merge_context") {
        json members = json::array();
        for (const auto& m : facts.members) {
            members.push_back(json{{"signer", m.signer},
                                   {"address", m.address},
                                   {"http_port", m.http_port},
                                   {"server_id", m.server_id}});
        }
        return json{{"ok", true},
                    {"network_id", crypto::to_hex(facts.network_id)},
                    {"root_key", facts.root_key},
                    {"holds_root_key", facts.holds_root_key},
                    {"signer", facts.signer},
                    {"membership_known", facts.membership_known},
                    {"members", std::move(members)}};
    }

    // Every other step uses the root management key or names the root
    // server's export, so only its holder serves it.
    if (!facts.holds_root_key) {
        return refuse("this server does not hold the root management key; run the migration "
                      "on the root server");
    }
    if (facts.root_key.empty()) return refuse("no root management key is configured");

    if (op == "tree_merge_request") {
        if (!facts.membership_known) return refuse("Tier 1 membership is not known yet");
        const auto target = canonical(request.value("target", ""));
        const bool member = !target.empty() &&
            std::any_of(facts.members.begin(), facts.members.end(),
                        [&](const TreeMigrationMember& m) { return canonical(m.signer) == target; });
        if (!member) return refuse("target is not a current Tier 1 member");
        const auto nonce = hooks.random_nonce_hex();
        const auto text =
            tree::tree_export_request(facts.network_id, target, hooks.wall_clock_ms(), nonce);
        const auto signature = hooks.sign_with_root_key(
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
        if (!signature) return refuse("the root management key is not available");
        return json{{"ok", true},
                    {"body", json{{"request", text},
                                  {"signature", crypto::to_base64(*signature)}}}};
    }

    if (op == "tree_merge_export_backup") {
        const auto it = request.find("data_root");
        if (it == request.end() || !it->is_string() || it->get<std::string>().empty()) {
            return refuse("data_root must name a directory");
        }
        const std::filesystem::path data_root(it->get<std::string>());
        if (!data_root.is_absolute()) return refuse("data_root must be an absolute path");
        std::string error;
        auto exported = hooks.export_backup(data_root, error);
        if (!exported) return refuse(error.empty() ? "the backup does not export" : error);
        return json{{"ok", true}, {"export", std::move(*exported)}};
    }

    if (op == "tree_merge_build" || op == "tree_merge_sign") {
        if (!facts.membership_known) return refuse("Tier 1 membership is not known yet");
        std::string error;
        const auto parsed = parse_build(request, hooks, error);
        if (!parsed) return refuse(error);
        const auto build = tree::build_signed_merge(*hooks.crypto, parsed->exports,
                                                    merge_input(facts, parsed->block_time_ms));
        if (!build.refusal.empty()) return refuse(build.refusal);
        if (op == "tree_merge_build" || !build.entry) return build_reply(build);

        const auto expected = request.find("tree_digest");
        if (expected == request.end() || !expected->is_string()) {
            return refuse("tree_digest from the reviewed dry run is required");
        }
        if (expected->get<std::string>() != crypto::to_base64(build.entry->tree_digest)) {
            return refuse("the merged tree differs from the reviewed dry run; run the dry run "
                          "again and review it");
        }
        const auto signature = hooks.sign_with_root_key(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(build.preimage.data()), build.preimage.size()));
        if (!signature) return refuse("the root management key is not available");
        const auto signed_entry = tree::attach_merge_signature(*build.entry, *signature);
        if (const auto refusal = tree::verify_merge_signature(*hooks.crypto, signed_entry,
                                                              facts.network_id, facts.root_key)) {
            return refuse("the signed commit does not verify: " + *refusal);
        }
        spdlog::warn("[tree-merge] signed the tree merge commit: {} nodes, state root {}",
                     build.result.nodes.size(), crypto::to_base64(signed_entry.state_root));
        return json{{"ok", true},
                    {"commit", tree::tree_log_entry_to_json(signed_entry)},
                    {"node_count", build.result.nodes.size()},
                    {"tree_digest", crypto::to_base64(signed_entry.tree_digest)},
                    {"state_root", crypto::to_base64(signed_entry.state_root)}};
    }

    return refuse("unknown op");
}

}  // namespace

std::pair<int, json> TreeMergeExportEndpoint::answer(const json& body) {
    if (!source_.awaiting_merge || !source_.awaiting_merge()) {
        return {409, {{"error", "this server is not awaiting the tree merge commit"}}};
    }
    std::string refusal;
    const auto now = source_.wall_clock_ms();
    const auto request = tree::verify_tree_export_request(*source_.crypto, body, source_.network_id,
                                                          source_.root_key, source_.self, now,
                                                          refusal);
    if (!request) return {403, {{"error", refusal}}};
    {
        std::lock_guard lock(mutex_);
        if (!nonces_.admit(request->nonce, request->issued_ms, now)) {
            return {409, {{"error", "this export request was already served"}}};
        }
    }
    const auto exported = source_.collect();
    spdlog::warn("[tree-merge] exported {} pre-merge tree nodes for the tree merge",
                 exported.nodes.size());
    return {200, tree::sign_tree_export(*source_.crypto, tree::tree_export_to_json(exported),
                                        source_.network_id, *source_.keypair)};
}

json handle_tree_migration_request(const json& request, const TreeMigrationHooks& hooks) {
    if (!hooks.crypto || !hooks.facts || !hooks.sign_with_root_key || !hooks.export_backup ||
        !hooks.wall_clock_ms || !hooks.random_nonce_hex) {
        return refuse("the tree merge is not available on this server");
    }
    try {
        return handle(request, hooks);
    } catch (const std::exception& e) {
        return refuse(std::string("the request failed: ") + e.what());
    }
}

}  // namespace nexus::core
