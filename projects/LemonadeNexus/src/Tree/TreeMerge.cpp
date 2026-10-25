#include <LemonadeNexus/Tree/TreeMerge.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/TreeOps.hpp>

#include <algorithm>
#include <array>
#include <set>
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

// --- Collecting and signing exports ----------------------------------------------

TreeExport collect_tree_export(std::string server, bool root_server, const rules::NodeMap& nodes,
                               const ipam::IPAMService& ipam,
                               const storage::FileStorageService& storage) {
    TreeExport exported;
    exported.server = std::move(server);
    exported.root_server = root_server;
    for (const auto& [id, node] : nodes) {
        if (node.type == NodeType::Endpoint && !node.tunnel_ip.empty()) {
            const auto allocation = ipam.get_allocation(id);
            if (allocation && allocation->tunnel &&
                allocation->tunnel->base_network == node.tunnel_ip) {
                exported.joined_here.insert(id);
            }
        }
        exported.nodes.push_back(node);
    }
    for (const auto& delta : storage.read_deltas_since(0)) {
        if (delta.operation == "create_node") exported.created_here.insert(delta.target_node_id);
    }
    return exported;
}

namespace {

std::vector<uint8_t> export_signature_message(const json& unsigned_doc) {
    const std::string text =
        std::string(kTreeExportSignatureDomain) + "\n" + unsigned_doc.dump();
    return std::vector<uint8_t>(text.begin(), text.end());
}

std::string principal_of(const crypto::Ed25519PublicKey& key) {
    return "ed25519:" + b64(std::span<const uint8_t>(key.data(), key.size()));
}

std::optional<crypto::Ed25519Signature> signature_from_b64(const std::string& text) {
    std::vector<uint8_t> raw;
    try {
        raw = crypto::from_base64(text);
    } catch (const std::exception&) {
        return std::nullopt;
    }
    if (raw.size() != crypto::kEd25519SignatureSize) return std::nullopt;
    crypto::Ed25519Signature sig{};
    std::copy(raw.begin(), raw.end(), sig.begin());
    return sig;
}

bool is_lower_hex(std::string_view text) {
    return std::all_of(text.begin(), text.end(),
                       [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

}  // namespace

json sign_tree_export(crypto::SodiumCryptoService& crypto, json doc,
                      const security::NetworkId& network_id,
                      const crypto::Ed25519Keypair& keypair) {
    doc.erase("signature");
    doc["network_id"] = crypto::to_hex(network_id);
    doc["signer"] = principal_of(keypair.public_key);
    const auto message = export_signature_message(doc);
    doc["signature"] = b64(crypto.ed25519_sign(keypair.private_key, message));
    return doc;
}

std::optional<std::string> verify_tree_export(crypto::SodiumCryptoService& crypto,
                                              const json& doc,
                                              const security::NetworkId& network_id,
                                              std::string& signer) {
    if (!doc.is_object() || !doc.contains("signature") || !doc["signature"].is_string() ||
        !doc.contains("signer") || !doc["signer"].is_string() || !doc.contains("network_id") ||
        !doc["network_id"].is_string()) {
        return "the export is not signed";
    }
    if (doc["network_id"].get<std::string>() != crypto::to_hex(network_id)) {
        return "the export names another network";
    }
    const auto key = principal_key(doc["signer"].get<std::string>());
    if (!key) return "the export signer is not an Ed25519 key";
    const auto sig = signature_from_b64(doc["signature"].get<std::string>());
    if (!sig) return "the export signature is not 64 bytes of base64";
    json unsigned_doc = doc;
    unsigned_doc.erase("signature");
    if (!crypto.ed25519_verify(*key, export_signature_message(unsigned_doc), *sig)) {
        return "the export signature does not verify";
    }
    signer = principal_of(*key);
    return std::nullopt;
}

std::string tree_export_request(const security::NetworkId& network_id, const std::string& target,
                                uint64_t issued_ms, const std::string& nonce_hex) {
    // nlohmann::json objects keep keys sorted, so dump() is canonical.
    return json{{"type", std::string(kTreeExportRequestType)},
                {"network_id", crypto::to_hex(network_id)},
                {"target", target},
                {"issued_ms", issued_ms},
                {"nonce", nonce_hex}}
        .dump();
}

std::optional<TreeExportRequest> verify_tree_export_request(
    crypto::SodiumCryptoService& crypto, const json& body, const security::NetworkId& network_id,
    const std::string& root_key, const std::string& self, uint64_t now_ms,
    std::string& refusal) {
    const auto refuse = [&](std::string reason) -> std::optional<TreeExportRequest> {
        refusal = std::move(reason);
        return std::nullopt;
    };
    const auto configured = principal_key(root_key);
    if (!configured) return refuse("no root management key is configured");
    if (!body.is_object() || !body.contains("request") || !body["request"].is_string() ||
        !body.contains("signature") || !body["signature"].is_string()) {
        return refuse("the body needs request and signature strings");
    }
    const auto& text = body["request"].get_ref<const std::string&>();
    if (text.size() > 1024) return refuse("the request is too large");
    const json request = json::parse(text, nullptr, false);
    if (request.is_discarded() || !request.is_object() || request.dump() != text ||
        request.size() != 5 || request.value("type", "") != kTreeExportRequestType ||
        !request.contains("issued_ms") || !request["issued_ms"].is_number_unsigned() ||
        !request.contains("nonce") || !request["nonce"].is_string() ||
        !request.contains("target") || !request["target"].is_string() ||
        !request.contains("network_id") || !request["network_id"].is_string()) {
        return refuse("the request is not a canonical tree export request");
    }
    if (request["network_id"].get<std::string>() != crypto::to_hex(network_id)) {
        return refuse("the request names another network");
    }
    const auto target = principal_key(request["target"].get<std::string>());
    const auto mine = principal_key(self);
    if (!target || !mine || *target != *mine) return refuse("the request names another server");
    const auto nonce = request["nonce"].get<std::string>();
    if (nonce.size() != 32 || !is_lower_hex(nonce)) {
        return refuse("the request nonce is not 32 lowercase hex digits");
    }
    const auto issued = request["issued_ms"].get<uint64_t>();
    if (issued > now_ms + kTreeExportRequestWindowMs ||
        issued + kTreeExportRequestWindowMs < now_ms) {
        return refuse("the request is outside the request window of this server's clock");
    }
    const auto sig = signature_from_b64(body["signature"].get<std::string>());
    if (!sig) return refuse("the signature is not 64 bytes of base64");
    const std::span<const uint8_t> message(reinterpret_cast<const uint8_t*>(text.data()),
                                           text.size());
    if (!crypto.ed25519_verify(*configured, message, *sig)) {
        return refuse("the request is not signed by the configured root management key");
    }
    return TreeExportRequest{nonce, issued};
}

bool TreeExportNonces::admit(const std::string& nonce, uint64_t issued_ms, uint64_t now_ms) {
    std::erase_if(seen_, [&](const auto& kv) {
        return kv.second + 2 * kTreeExportRequestWindowMs < now_ms;
    });
    if (seen_.contains(nonce) || seen_.size() >= kMax) return false;
    seen_.emplace(nonce, issued_ms);
    return true;
}

// --- The merge rule --------------------------------------------------------------

namespace {

struct Copy {
    const TreeExport* from;
    const TreeNode* node;
    std::vector<uint8_t> encoding;
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
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return out;
}

/// Rule 6: the copy to take among `candidates` (pointers into `all`).
const Copy* tie_break(const std::vector<const Copy*>& candidates, const std::vector<Copy>& all,
                      const TreeExport* root_server) {
    const auto holders = [&](const Copy* c) {
        return std::count_if(all.begin(), all.end(),
                             [&](const Copy& other) { return other.encoding == c->encoding; });
    };
    const Copy* best = nullptr;
    for (const Copy* c : candidates) {
        if (best == nullptr) {
            best = c;
            continue;
        }
        const auto key = [&](const Copy* x) {
            return std::make_tuple(x->node->version, holders(x), x->from == root_server);
        };
        const auto a = key(c);
        const auto b = key(best);
        if (a > b || (a == b && c->encoding < best->encoding)) best = c;
    }
    return best;
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
        for (const auto& node : e->nodes) {
            copies[node.id].push_back({e, &node, encode_tree_node(node)});
        }
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
        if (id == "root" && root_server != nullptr) {
            const auto pick = std::find_if(held.begin(), held.end(), [&](const Copy& c) {
                return c.from == root_server;
            });
            if (pick != held.end()) {
                take(*pick, "root server");
                continue;
            }
        }
        const bool identical = std::all_of(held.begin(), held.end(), [&](const Copy& c) {
            return c.encoding == held.front().encoding;
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
        std::vector<const Copy*> candidates = evidence;
        if (candidates.size() < 2) {
            candidates.clear();
            for (const auto& c : held) candidates.push_back(&c);
        }
        const Copy* pick = tie_break(candidates, held, root_server);
        std::string others;
        for (const auto& server : servers_of(held)) {
            if (server != pick->from->server) others += (others.empty() ? "" : ",") + server;
        }
        take(*pick, std::string("tie-break over ") + std::to_string(candidates.size()) +
                        " differing copies (also held by " + others + ")");
    }
    for (const auto& [id, server] : resolutions) {
        if (!copies.contains(id)) {
            add_conflict(out, id, "bad_resolution", "no export holds this node", {server});
        }
    }
    if (!out.nodes.contains("root")) {
        add_conflict(out, "root", "root_missing", "no export holds a root", {});
    }

    const auto holders_of = [&](const std::string& id) {
        const auto it = copies.find(id);
        return it == copies.end() ? std::vector<std::string>{} : servers_of(it->second);
    };
    const auto drop = [&](const std::string& id, std::string reason, std::string detail) {
        out.nodes.erase(id);
        out.dropped.push_back({id, std::move(reason), std::move(detail), holders_of(id)});
    };

    // Rule 7: shared identifiers. Rank: the root, a recorded join, the most
    // holders, the smallest id.
    const auto joined_somewhere = [&](const std::string& id) {
        return std::any_of(exports.begin(), exports.end(),
                           [&](const TreeExport& e) { return e.joined_here.contains(id); });
    };
    const auto keeps_before = [&](const std::string& a, const std::string& b) {
        const auto key = [&](const std::string& id) {
            return std::make_tuple(id == "root", joined_somewhere(id), holders_of(id).size());
        };
        const auto ka = key(a);
        const auto kb = key(b);
        if (ka != kb) return ka > kb;
        return a < b;
    };
    const std::array<std::tuple<const char*, const char*, std::string TreeNode::*>, 3> fields = {{
        {"duplicate_identifier", "endpoint identifier", &TreeNode::endpoint_identifier},
        {"duplicate_mesh_key", "mesh key", &TreeNode::mesh_pubkey},
        {"duplicate_tunnel_address", "tunnel address", &TreeNode::tunnel_ip},
    }};
    for (const auto& [reason, what, field] : fields) {
        std::map<std::string, std::vector<std::string>> holding;
        for (const auto& [id, node] : out.nodes) {
            const auto& value = node.*field;
            if (!value.empty()) holding[value].push_back(id);
        }
        for (auto& [value, ids] : holding) {
            if (ids.size() < 2) continue;
            std::sort(ids.begin(), ids.end(), keeps_before);
            for (std::size_t i = 1; i < ids.size(); ++i) {
                drop(ids[i], reason, std::string(what) + " " + value + " is kept by " + ids[0]);
            }
        }
    }

    // Rule 8: everything that does not reach the root.
    if (out.nodes.contains("root")) {
        std::map<std::string, std::vector<std::string>> children;
        for (const auto& [id, node] : out.nodes) {
            if (id != "root") children[node.parent_id].push_back(id);
        }
        std::set<std::string> reached{"root"};
        std::vector<std::string> frontier{"root"};
        while (!frontier.empty()) {
            const auto id = frontier.back();
            frontier.pop_back();
            for (const auto& child : children[id]) {
                if (reached.insert(child).second) frontier.push_back(child);
            }
        }
        std::vector<std::string> unreached;
        for (const auto& [id, node] : out.nodes) {
            if (!reached.contains(id)) unreached.push_back(id);
        }
        const auto selected = out.nodes;
        for (const auto& id : unreached) {
            const auto& parent = selected.at(id).parent_id;
            if (parent.empty() || !selected.contains(parent)) {
                drop(id, "orphan", "parent '" + parent + "' is not in the merged tree");
            } else {
                drop(id, "unreachable", "parent '" + parent + "' does not reach the root");
            }
        }
    }

    std::sort(out.conflicts.begin(), out.conflicts.end(), [](const auto& a, const auto& b) {
        return std::tie(a.node_id, a.kind, a.detail) < std::tie(b.node_id, b.kind, b.detail);
    });
    std::sort(out.dropped.begin(), out.dropped.end(), [](const auto& a, const auto& b) {
        return std::tie(a.node_id, a.reason) < std::tie(b.node_id, b.reason);
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

json merge_report(const std::vector<TreeExport>& exports, const MergeResult& result) {
    json dropped = json::array();
    for (const auto& d : result.dropped) {
        dropped.push_back(json{{"node_id", d.node_id},
                               {"reason", d.reason},
                               {"detail", d.detail},
                               {"servers", d.servers}});
    }
    json servers = json::object();
    for (const auto& e : exports) {
        std::vector<std::string> added;
        std::vector<std::string> removed;
        std::vector<std::string> changed;
        std::map<std::string, const TreeNode*> mine;
        for (const auto& node : e.nodes) mine.emplace(node.id, &node);
        for (const auto& [id, node] : result.nodes) {
            const auto it = mine.find(id);
            if (it == mine.end()) {
                added.push_back(id);
            } else if (encode_tree_node(*it->second) != encode_tree_node(node)) {
                changed.push_back(id);
            }
        }
        for (const auto& [id, node] : mine) {
            if (!result.nodes.contains(id)) removed.push_back(id);
        }
        std::sort(added.begin(), added.end());
        std::sort(changed.begin(), changed.end());
        servers[e.server] = json{{"nodes", e.nodes.size()},
                                 {"root_server", e.root_server},
                                 {"added", added},
                                 {"removed", removed},
                                 {"changed", changed}};
    }
    return json{{"node_count", result.nodes.size()},
                {"decisions", result.decisions},
                {"dropped", std::move(dropped)},
                {"conflicts", merge_conflicts_to_json(result.conflicts)},
                {"servers", std::move(servers)}};
}

// --- The supported migration -------------------------------------------------------

SignedMergeBuild build_signed_merge(crypto::SodiumCryptoService& crypto,
                                    const std::vector<json>& docs,
                                    const SignedMergeInput& input) {
    SignedMergeBuild out;
    const auto refuse = [&](std::string reason) {
        out = SignedMergeBuild{};
        out.refusal = std::move(reason);
        return out;
    };
    const auto root_signer = principal_key(input.root_signer);
    if (!root_signer) return refuse("the root signer is not an Ed25519 key");
    // Compare principals by key bytes: spellings of one key differ.
    std::map<std::string, bool> required;  // canonical principal -> seen
    required.emplace(principal_of(*root_signer), false);
    for (const auto& member : input.members) {
        const auto key = principal_key(member);
        if (!key) return refuse("a Tier 1 member is not an Ed25519 key");
        required.emplace(principal_of(*key), false);
    }
    json signers = json::object();
    for (const auto& doc : docs) {
        std::string signer;
        if (const auto refusal = verify_tree_export(crypto, doc, input.network_id, signer)) {
            return refuse(*refusal);
        }
        const auto slot = required.find(signer);
        if (slot == required.end()) {
            return refuse("an export is signed by " + signer +
                          ", which is neither a Tier 1 member nor the root server");
        }
        if (slot->second) return refuse("two exports are signed by " + signer);
        slot->second = true;
        auto parsed = tree_export_from_json(doc);
        if (!parsed) return refuse("the export signed by " + signer + " is malformed");
        if (parsed->root_server != (signer == principal_of(*root_signer))) {
            return refuse("only the root server's export is marked as the root server export");
        }
        if (signers.contains(parsed->server)) {
            return refuse("server label " + parsed->server + " repeats");
        }
        signers[parsed->server] = signer;
        out.exports.push_back(std::move(*parsed));
    }
    for (const auto& [signer, seen] : required) {
        if (!seen) {
            return refuse("no export from " + signer +
                          "; every Tier 1 member and the root server must contribute one");
        }
    }

    out.result = merge_tree_exports(out.exports, {});
    out.report = merge_report(out.exports, out.result);
    out.report["signers"] = std::move(signers);
    if (!out.result.conflicts.empty()) return out;
    out.entry = build_merge_entry(out.result.nodes, input.block_time_ms, input.network_id,
                                  input.root_key);
    if (!out.entry) {
        out.report["conflicts"].push_back(json{{"node_id", ""},
                                               {"kind", "too_large"},
                                               {"detail", "the merged tree exceeds the merge body "
                                                          "limits"},
                                               {"servers", json::array()}});
        return out;
    }
    out.preimage = merge_preimage(*out.entry, input.network_id, out.result.nodes.size());
    out.report["tree_digest"] = b64(out.entry->tree_digest);
    out.report["state_root"] = b64(out.entry->state_root);
    out.report["block_time_ms"] = out.entry->block_time_ms;
    return out;
}

}  // namespace nexus::tree
