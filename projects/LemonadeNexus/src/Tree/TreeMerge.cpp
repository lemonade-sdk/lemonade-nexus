#include <LemonadeNexus/Tree/TreeMerge.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Tree/TreeOps.hpp>

#include <algorithm>
#include <tuple>

namespace nexus::tree {

using json = nlohmann::json;

namespace {

void put_u32(std::vector<uint8_t>& out, uint32_t value) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((value >> (8 * i)) & 0xFF));
}

bool get_u32(std::span<const uint8_t> in, std::size_t& at, uint32_t& value) {
    if (in.size() - at < 4) return false;
    value = 0;
    for (int i = 0; i < 4; ++i) value |= static_cast<uint32_t>(in[at + i]) << (8 * i);
    at += 4;
    return true;
}

std::string b64(std::span<const uint8_t> bytes) { return crypto::to_base64(bytes); }

/// Raw key bytes of an "ed25519:<base64>" principal, or nullopt.
std::optional<crypto::Ed25519PublicKey> principal_key(std::string_view principal) {
    constexpr std::string_view prefix = "ed25519:";
    if (!principal.starts_with(prefix)) return std::nullopt;
    std::vector<uint8_t> bytes;
    try {
        bytes = crypto::from_base64(principal.substr(prefix.size()));
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (bytes.size() != crypto::kEd25519PublicKeySize) return std::nullopt;
    crypto::Ed25519PublicKey key{};
    std::copy(bytes.begin(), bytes.end(), key.begin());
    return key;
}

std::vector<std::string> sorted_ids(const rules::NodeMap& nodes) {
    std::vector<std::string> ids;
    ids.reserve(nodes.size());
    for (const auto& [id, node] : nodes) ids.push_back(id);
    std::sort(ids.begin(), ids.end());
    return ids;
}

}  // namespace

std::optional<std::vector<uint8_t>> encode_merge_body(const rules::NodeMap& nodes) {
    if (nodes.size() > kMaxTreeMergeNodes) return std::nullopt;
    std::vector<uint8_t> out;
    put_u32(out, static_cast<uint32_t>(nodes.size()));
    for (const auto& id : sorted_ids(nodes)) {
        const auto encoded = encode_tree_node(nodes.at(id));
        put_u32(out, static_cast<uint32_t>(encoded.size()));
        out.insert(out.end(), encoded.begin(), encoded.end());
        if (out.size() > kMaxTreeMergeBodyBytes) return std::nullopt;
    }
    return out;
}

std::optional<rules::NodeMap> decode_merge_body(std::span<const uint8_t> body) {
    if (body.size() > kMaxTreeMergeBodyBytes) return std::nullopt;
    std::size_t at = 0;
    uint32_t count = 0;
    if (!get_u32(body, at, count) || count > kMaxTreeMergeNodes) return std::nullopt;
    rules::NodeMap nodes;
    std::string previous_id;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t length = 0;
        if (!get_u32(body, at, length) || length > body.size() - at) return std::nullopt;
        const auto bytes = body.subspan(at, length);
        at += length;
        auto node = decode_tree_node(bytes);
        if (!node || node->id.empty()) return std::nullopt;
        // Ids strictly increase, so the encoding of a set is unique.
        if (i > 0 && node->id <= previous_id) return std::nullopt;
        const auto reencoded = encode_tree_node(*node);
        if (!std::equal(reencoded.begin(), reencoded.end(), bytes.begin(), bytes.end())) {
            return std::nullopt;
        }
        previous_id = node->id;
        nodes.emplace(node->id, std::move(*node));
    }
    if (at != body.size()) return std::nullopt;
    return nodes;
}

security::Digest merge_body_digest(std::span<const uint8_t> body) {
    security::CanonicalEncoder enc(kTreeMergeBodyDomain);
    enc.add_bytes(body);
    return enc.digest();
}

std::string merge_preimage(const TreeLogEntry& entry, const security::NetworkId& network_id,
                           std::size_t node_count) {
    // nlohmann::json objects keep keys sorted, so dump() is canonical.
    const json doc{{"type", std::string(kTreeMergePreimageType)},
                   {"network_id", crypto::to_hex(network_id)},
                   {"height", entry.height},
                   {"block_time_ms", entry.block_time_ms},
                   {"previous_root", b64(entry.previous_root)},
                   {"merge_digest", b64(entry.ops_digest)},
                   {"tree_digest", b64(entry.tree_digest)},
                   {"state_root", b64(entry.state_root)},
                   {"node_count", node_count}};
    return doc.dump();
}

std::optional<TreeLogEntry> build_merge_entry(const rules::NodeMap& nodes, uint64_t block_time_ms,
                                              const security::NetworkId& network_id,
                                              const std::string& root_key) {
    auto body = encode_merge_body(nodes);
    if (!body) return std::nullopt;
    TreeLogEntry entry;
    entry.kind = TreeLogEntryKind::Merge;
    entry.height = 1;
    entry.block_time_ms = block_time_ms;
    entry.ops_digest = merge_body_digest(*body);
    entry.batch = std::move(*body);
    entry.previous_root = empty_base_root();
    TreeChainState after;
    after.nodes = nodes;
    entry.tree_digest = compute_tree_digest(after.nodes);
    entry.state_root = chain_state_root(entry.previous_root, entry.ops_digest, after);
    entry.commit = json{{"kind", "merge"},
                        {"network_id", crypto::to_hex(network_id)},
                        {"signer", root_key},
                        {"node_count", nodes.size()},
                        {"signature", ""}};
    return entry;
}

TreeLogEntry attach_merge_signature(TreeLogEntry entry, const crypto::Ed25519Signature& signature) {
    entry.commit["signature"] = b64(signature);
    return entry;
}

std::optional<std::string> verify_merge_signature(crypto::SodiumCryptoService& crypto,
                                                  const TreeLogEntry& entry,
                                                  const security::NetworkId& network_id,
                                                  const std::string& root_key) {
    if (entry.kind != TreeLogEntryKind::Merge) return "not a merge entry";
    if (entry.height != 1) return "a merge entry is valid only at height 1";
    const auto configured = principal_key(root_key);
    if (!configured) return "no root management key is configured";
    const json& c = entry.commit;
    if (!c.is_object() || c.value("kind", "") != "merge" || !c.contains("network_id") ||
        !c["network_id"].is_string() || !c.contains("signer") || !c["signer"].is_string() ||
        !c.contains("signature") || !c["signature"].is_string() || !c.contains("node_count") ||
        !c["node_count"].is_number_unsigned()) {
        return "the merge commit record is malformed";
    }
    if (c["network_id"].get<std::string>() != crypto::to_hex(network_id)) {
        return "the merge commit names another network";
    }
    const auto signer = principal_key(c["signer"].get<std::string>());
    if (!signer || *signer != *configured) {
        return "the merge commit is not signed by the configured root management key";
    }
    std::vector<uint8_t> signature;
    try {
        signature = crypto::from_base64(c["signature"].get<std::string>());
    } catch (const std::exception&) {
        return "the merge signature is not base64";
    }
    if (signature.size() != crypto::kEd25519SignatureSize) {
        return "the merge signature is not 64 bytes";
    }
    const auto nodes = decode_merge_body(entry.batch);
    if (!nodes) return "the merge body does not decode";
    if (nodes->size() != c["node_count"].get<uint64_t>()) {
        return "the merge body does not hold the signed node count";
    }
    crypto::Ed25519Signature sig{};
    std::copy(signature.begin(), signature.end(), sig.begin());
    const auto preimage = merge_preimage(entry, network_id, nodes->size());
    const std::span<const uint8_t> message(reinterpret_cast<const uint8_t*>(preimage.data()),
                                           preimage.size());
    if (!crypto.ed25519_verify(*configured, message, sig)) {
        return "the merge signature does not verify";
    }
    return std::nullopt;
}

// --- Exports -------------------------------------------------------------------

json tree_export_to_json(const TreeExport& exported) {
    std::vector<const TreeNode*> ordered;
    for (const auto& node : exported.nodes) ordered.push_back(&node);
    std::sort(ordered.begin(), ordered.end(),
              [](const TreeNode* a, const TreeNode* b) { return a->id < b->id; });
    json nodes = json::array();
    for (const auto* node : ordered) nodes.push_back(b64(encode_tree_node(*node)));
    return json{{"type", std::string(kTreeExportType)},
                {"format", 1},
                {"server", exported.server},
                {"root_server", exported.root_server},
                {"nodes", std::move(nodes)},
                {"joined_here", exported.joined_here},
                {"created_here", exported.created_here}};
}

std::optional<TreeExport> tree_export_from_json(const json& doc) {
    if (!doc.is_object() || doc.value("type", "") != kTreeExportType ||
        !doc.contains("format") || !doc["format"].is_number_integer() || doc["format"] != 1 ||
        !doc.contains("server") ||
        !doc["server"].is_string() || doc["server"].get<std::string>().empty() ||
        !doc.contains("root_server") || !doc["root_server"].is_boolean() ||
        !doc.contains("nodes") || !doc["nodes"].is_array() ||
        doc["nodes"].size() > kMaxTreeMergeNodes) {
        return std::nullopt;
    }
    TreeExport out;
    out.server = doc["server"].get<std::string>();
    out.root_server = doc["root_server"].get<bool>();
    std::set<std::string> seen;
    for (const auto& item : doc["nodes"]) {
        if (!item.is_string()) return std::nullopt;
        std::vector<uint8_t> bytes;
        try {
            bytes = crypto::from_base64(item.get<std::string>());
        } catch (const std::exception&) {
            return std::nullopt;
        }
        auto node = decode_tree_node(bytes);
        if (!node || node->id.empty() || !seen.insert(node->id).second) return std::nullopt;
        out.nodes.push_back(std::move(*node));
    }
    for (const char* key : {"joined_here", "created_here"}) {
        if (!doc.contains(key) || !doc[key].is_array()) return std::nullopt;
        auto& target = std::string_view(key) == "joined_here" ? out.joined_here : out.created_here;
        for (const auto& id : doc[key]) {
            if (!id.is_string()) return std::nullopt;
            target.insert(id.get<std::string>());
        }
    }
    return out;
}

// --- The merge rule --------------------------------------------------------------

namespace {

struct Copy {
    const TreeExport* from;
    const TreeNode* node;
};

void add_conflict(MergeResult& out, std::string id, std::string kind, std::string detail,
                  std::vector<std::string> servers) {
    std::sort(servers.begin(), servers.end());
    servers.erase(std::unique(servers.begin(), servers.end()), servers.end());
    out.conflicts.push_back({std::move(id), std::move(kind), std::move(detail), std::move(servers)});
}

std::vector<std::string> servers_of(const std::vector<Copy>& copies) {
    std::vector<std::string> out;
    for (const auto& c : copies) out.push_back(c.from->server);
    return out;
}

/// Flags every value shared by two or more merged nodes.
void check_unique(MergeResult& out, const char* kind, const char* what,
                  std::string TreeNode::*field, const std::vector<std::string>& ids,
                  const std::map<std::string, std::string>& source) {
    std::map<std::string, std::vector<std::string>> holders;
    for (const auto& id : ids) {
        const auto& value = out.nodes.at(id).*field;
        if (!value.empty()) holders[value].push_back(id);
    }
    for (const auto& [value, holding] : holders) {
        if (holding.size() < 2) continue;
        std::vector<std::string> servers;
        for (const auto& id : holding) servers.push_back(source.at(id));
        std::string list;
        for (const auto& id : holding) list += (list.empty() ? "" : ", ") + id;
        for (const auto& id : holding) {
            add_conflict(out, id, kind,
                         std::string(what) + " " + value + " is held by " + list, servers);
        }
    }
}

}  // namespace

MergeResult merge_tree_exports(const std::vector<TreeExport>& exports,
                               const std::map<std::string, std::string>& resolutions) {
    MergeResult out;
    std::map<std::string, const TreeExport*> by_server;
    const TreeExport* root_server = nullptr;
    std::size_t root_servers = 0;
    for (const auto& e : exports) {
        if (!by_server.emplace(e.server, &e).second) {
            add_conflict(out, "", "bad_exports", "server label " + e.server + " repeats",
                         {e.server});
        }
        if (e.root_server) {
            root_server = &e;
            ++root_servers;
        }
    }
    if (root_servers != 1) {
        add_conflict(out, "root", "bad_exports",
                     "exactly one export must be marked as the root server; found " +
                         std::to_string(root_servers),
                     {});
        root_server = nullptr;
    }

    // Every copy of every node, in server order so the result does not depend
    // on the order of `exports`.
    std::map<std::string, std::vector<Copy>> copies;
    for (const auto& [server, e] : by_server) {
        for (const auto& node : e->nodes) copies[node.id].push_back({e, &node});
    }

    std::map<std::string, std::string> source;  // node id -> server it came from
    const auto take = [&](const Copy& c, const std::string& rule) {
        out.nodes[c.node->id] = *c.node;
        source[c.node->id] = c.from->server;
        out.decisions.push_back(c.node->id + ": " + rule + " from " + c.from->server);
    };

    for (const auto& [id, held] : copies) {
        if (const auto r = resolutions.find(id); r != resolutions.end()) {
            if (r->second == "drop") {
                out.decisions.push_back(id + ": dropped by resolution");
                continue;
            }
            const auto pick = std::find_if(held.begin(), held.end(), [&](const Copy& c) {
                return c.from->server == r->second;
            });
            if (pick == held.end()) {
                add_conflict(out, id, "bad_resolution",
                             "resolution names server " + r->second + ", which does not hold it",
                             servers_of(held));
            } else {
                take(*pick, "resolution");
            }
            continue;
        }
        if (id == "root") {
            if (root_server == nullptr) continue;  // reported as bad_exports
            const auto pick = std::find_if(held.begin(), held.end(), [&](const Copy& c) {
                return c.from == root_server;
            });
            if (pick == held.end()) {
                add_conflict(out, id, "root_missing",
                             "the root server's export holds no root", servers_of(held));
            } else {
                take(*pick, "root server");
            }
            continue;
        }
        const auto first = encode_tree_node(*held.front().node);
        const bool identical = std::all_of(held.begin(), held.end(), [&](const Copy& c) {
            return encode_tree_node(*c.node) == first;
        });
        if (identical) {
            take(held.front(), held.size() == 1 ? "single copy" : "identical copies");
            continue;
        }
        std::vector<const Copy*> evidence;
        const char* rule = nullptr;
        const NodeType type = held.front().node->type;
        const bool same_type = std::all_of(held.begin(), held.end(), [&](const Copy& c) {
            return c.node->type == type;
        });
        if (same_type && type == NodeType::Endpoint) {
            rule = "joined server";
            for (const auto& c : held) {
                if (c.from->joined_here.contains(id)) evidence.push_back(&c);
            }
        } else if (same_type && type == NodeType::Customer) {
            rule = "creator's record";
            for (const auto& c : held) {
                if (c.from->created_here.contains(id)) evidence.push_back(&c);
            }
        }
        if (rule != nullptr && evidence.size() == 1) {
            take(*evidence.front(), rule);
            continue;
        }
        add_conflict(out, id, "divergent",
                     rule == nullptr
                         ? "copies differ and no rule decides this node type"
                         : std::string("copies differ and ") + std::to_string(evidence.size()) +
                               " servers hold the " + rule + " evidence",
                     servers_of(held));
    }
    for (const auto& [id, server] : resolutions) {
        if (!copies.contains(id)) {
            add_conflict(out, id, "bad_resolution", "no export holds this node", {server});
        }
    }

    // Structure of the merged tree.
    const auto ids = sorted_ids(out.nodes);
    for (const auto& id : ids) {
        const auto& node = out.nodes.at(id);
        if (id == "root") continue;
        if (node.parent_id.empty() || !out.nodes.contains(node.parent_id)) {
            add_conflict(out, id, "orphan",
                         "parent '" + node.parent_id + "' is not in the merged tree",
                         {source.at(id)});
        }
    }
    check_unique(out, "duplicate_identifier", "endpoint identifier",
                 &TreeNode::endpoint_identifier, ids, source);
    check_unique(out, "duplicate_mesh_key", "mesh key", &TreeNode::mesh_pubkey, ids, source);
    check_unique(out, "duplicate_tunnel_address", "tunnel address", &TreeNode::tunnel_ip, ids,
                 source);

    std::sort(out.conflicts.begin(), out.conflicts.end(), [](const auto& a, const auto& b) {
        return std::tie(a.node_id, a.kind, a.detail) < std::tie(b.node_id, b.kind, b.detail);
    });
    std::sort(out.decisions.begin(), out.decisions.end());
    return out;
}

json merge_conflicts_to_json(const std::vector<MergeConflict>& conflicts) {
    json out = json::array();
    for (const auto& c : conflicts) {
        out.push_back(json{{"node_id", c.node_id},
                           {"kind", c.kind},
                           {"detail", c.detail},
                           {"servers", c.servers}});
    }
    return out;
}

}  // namespace nexus::tree
