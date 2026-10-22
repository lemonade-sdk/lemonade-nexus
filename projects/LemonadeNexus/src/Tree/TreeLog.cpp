#include <LemonadeNexus/Tree/TreeLog.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Consensus/BlockPayload.hpp>
#include <LemonadeNexus/Security/Consensus/HotStuffState.hpp>
#include <LemonadeNexus/Security/DurableWrite.hpp>
#include <LemonadeNexus/Tree/TreeMerge.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <charconv>
#include <fstream>
#include <set>
#include <sstream>
#include <system_error>

namespace nexus::tree {

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

constexpr std::string_view kSnapshotPrefix = "snapshot-";
constexpr std::string_view kAppliedFile = "applied.json";

std::string b64(std::span<const uint8_t> bytes) { return crypto::to_base64(bytes); }

std::optional<std::vector<uint8_t>> unb64(const json& value) {
    if (!value.is_string()) return std::nullopt;
    try {
        return crypto::from_base64(value.get<std::string>());
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

bool read_digest(const json& doc, const char* key, security::Digest& out) {
    const auto it = doc.find(key);
    if (it == doc.end()) return false;
    const auto bytes = unb64(*it);
    if (!bytes || bytes->size() != out.size()) return false;
    std::copy(bytes->begin(), bytes->end(), out.begin());
    return true;
}

bool read_u64(const json& doc, const char* key, uint64_t& out) {
    const auto it = doc.find(key);
    if (it == doc.end() || !it->is_number_unsigned()) return false;
    out = it->get<uint64_t>();
    return true;
}

std::optional<json> read_json_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    std::ostringstream text;
    text << in.rdbuf();
    auto doc = json::parse(text.str(), nullptr, false);
    if (doc.is_discarded() || !doc.is_object()) return std::nullopt;
    return doc;
}

bool format_ok(const json& doc) {
    uint64_t format = 0;
    return read_u64(doc, "format", format) && format == kTreeLogFormatVersion;
}

/// Height in "<height>.json" or "snapshot-<height>.json"; nullopt otherwise.
std::optional<uint64_t> height_of(std::string_view stem) {
    if (stem.empty()) return std::nullopt;
    uint64_t value = 0;
    auto [ptr, ec] = std::from_chars(stem.data(), stem.data() + stem.size(), value);
    if (ec != std::errc{} || ptr != stem.data() + stem.size()) return std::nullopt;
    // One spelling per height: no leading zeros.
    if (stem.size() > 1 && stem.front() == '0') return std::nullopt;
    return value;
}

security::Digest batch_digest(const std::vector<uint8_t>& batch) {
    security::BlockPayload payload;
    payload.kind = security::BlockPayloadKind::TreeBatch;
    payload.body = batch;
    return security::block_payload_digest(payload);
}

}  // namespace

json tree_log_entry_to_json(const TreeLogEntry& entry) {
    return json{{"format", kTreeLogFormatVersion},
                {"kind", entry.kind == TreeLogEntryKind::Merge ? "merge" : "batch"},
                {"height", entry.height},
                {"block_time_ms", entry.block_time_ms},
                {"batch", b64(entry.batch)},
                {"ops_digest", b64(entry.ops_digest)},
                {"previous_root", b64(entry.previous_root)},
                {"tree_digest", b64(entry.tree_digest)},
                {"state_root", b64(entry.state_root)},
                {"commit", entry.commit}};
}

std::optional<TreeLogEntry> tree_log_entry_from_json(const json& doc) {
    if (!doc.is_object() || !format_ok(doc)) return std::nullopt;
    TreeLogEntry entry;
    const auto kind = doc.find("kind");
    if (kind == doc.end() || !kind->is_string()) return std::nullopt;
    if (*kind == "batch") {
        entry.kind = TreeLogEntryKind::Batch;
    } else if (*kind == "merge") {
        entry.kind = TreeLogEntryKind::Merge;
    } else {
        return std::nullopt;
    }
    const auto batch = doc.contains("batch") ? unb64(doc["batch"]) : std::nullopt;
    if (!batch || !read_u64(doc, "height", entry.height) ||
        !read_u64(doc, "block_time_ms", entry.block_time_ms) ||
        !read_digest(doc, "ops_digest", entry.ops_digest) ||
        !read_digest(doc, "previous_root", entry.previous_root) ||
        !read_digest(doc, "tree_digest", entry.tree_digest) ||
        !read_digest(doc, "state_root", entry.state_root) || !doc.contains("commit") ||
        !doc["commit"].is_object()) {
        return std::nullopt;
    }
    entry.batch = *batch;
    entry.commit = doc["commit"];
    return entry;
}

security::Digest empty_base_root() {
    return base_state_root(compute_tree_digest(rules::NodeMap{}));
}

TreeBlockResult replay_entry(TreeChainState& state, const TreeLogEntry& entry) {
    TreeBlockResult out;
    const auto refuse = [&out](std::string reason) {
        out.verdict = {TreeOpRefusal::Malformed, std::move(reason)};
        out.effects.clear();
        return out;
    };
    if (entry.previous_root != state.root) {
        return refuse("the entry does not chain to the previous state root");
    }
    if (entry.kind == TreeLogEntryKind::Merge) {
        // One-shot: the merge commit replaces the empty base at height 1 and
        // nothing else.
        if (entry.height != 1 || state.root != empty_base_root() || !state.nodes.empty() ||
            state.committed.size() != 0 || state.last_block_time_ms != 0) {
            return refuse("a merge entry is valid only at height 1 on top of the empty base");
        }
        if (merge_body_digest(entry.batch) != entry.ops_digest) {
            return refuse("the merge body does not match its digest");
        }
        auto nodes = decode_merge_body(entry.batch);
        if (!nodes) return refuse("the merge body does not decode");
        if (entry.block_time_ms == 0) return refuse("the merge entry has no block time");
        TreeChainState next;
        next.nodes = std::move(*nodes);
        next.last_block_time_ms = entry.block_time_ms;
        out.tree_digest = compute_tree_digest(next.nodes);
        out.root = chain_state_root(state.root, entry.ops_digest, next);
        if (out.tree_digest != entry.tree_digest || out.root != entry.state_root) {
            return refuse("the merge entry does not produce its recorded roots");
        }
        next.root = out.root;
        state = std::move(next);
        return out;
    }

    if (batch_digest(entry.batch) != entry.ops_digest) {
        return refuse("the batch does not match its ops digest");
    }
    const auto batch = decode_tree_batch(entry.batch);
    if (!batch) return refuse("the batch is malformed");
    // The certified header, when recorded, must state the same block: its
    // time, ops digest, and roots. This binds the block time, which the state
    // root does not cover, to a quorum-certified record.
    if (const auto it = entry.commit.find("proposal"); it != entry.commit.end()) {
        const auto header = security::proposal_from_json(*it);
        if (!header || header->timestamp_hint != entry.block_time_ms ||
            header->transitions_digest != entry.ops_digest ||
            header->previous_state_root != entry.previous_root ||
            header->proposed_state_root != entry.state_root) {
            return refuse("the entry contradicts its certified header");
        }
    }
    TreeChainState next = state;
    out = apply_certified_batch(next, *batch, entry.block_time_ms, entry.ops_digest);
    if (!out.verdict.ok()) return out;
    if (out.tree_digest != entry.tree_digest || out.root != entry.state_root) {
        return refuse("the entry does not replay to its recorded state");
    }
    state = std::move(next);
    return out;
}

TreeLog::TreeLog(fs::path directory) : directory_(std::move(directory)) {}

fs::path TreeLog::entry_path(uint64_t height) const {
    return directory_ / (std::to_string(height) + ".json");
}

fs::path TreeLog::snapshot_path(uint64_t height) const {
    return directory_ / (std::string(kSnapshotPrefix) + std::to_string(height) + ".json");
}

bool TreeLog::write_snapshot(uint64_t height, const TreeChainState& state) const {
    std::vector<std::pair<std::string, const TreeNode*>> ordered;
    for (const auto& [id, node] : state.nodes) ordered.emplace_back(id, &node);
    std::sort(ordered.begin(), ordered.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    json nodes = json::array();
    for (const auto& [id, node] : ordered) {
        nodes.push_back(json{{"id", id}, {"node", b64(encode_tree_node(*node))}});
    }
    json committed = json::array();
    for (const auto& [id, signed_at] : state.committed.sorted()) {
        committed.push_back(json::array({id, signed_at}));
    }
    const json doc{{"format", kTreeLogFormatVersion},
                   {"height", height},
                   {"block_time_ms", state.last_block_time_ms},
                   {"tree_digest", b64(compute_tree_digest(state.nodes))},
                   {"root", b64(state.root)},
                   {"nodes", std::move(nodes)},
                   {"committed", std::move(committed)}};
    return security::write_durable(snapshot_path(height), doc.dump());
}

std::optional<TreeChainState> TreeLog::read_snapshot(uint64_t height) const {
    const auto doc = read_json_file(snapshot_path(height));
    uint64_t stored_height = 0;
    if (!doc || !format_ok(*doc) || !read_u64(*doc, "height", stored_height) ||
        stored_height != height) {
        return std::nullopt;
    }
    TreeChainState state;
    security::Digest tree_digest{};
    if (!read_u64(*doc, "block_time_ms", state.last_block_time_ms) ||
        !read_digest(*doc, "tree_digest", tree_digest) || !read_digest(*doc, "root", state.root) ||
        !doc->contains("nodes") || !(*doc)["nodes"].is_array() || !doc->contains("committed") ||
        !(*doc)["committed"].is_array()) {
        return std::nullopt;
    }
    for (const auto& item : (*doc)["nodes"]) {
        if (!item.is_object() || !item.contains("id") || !item["id"].is_string() ||
            !item.contains("node")) {
            return std::nullopt;
        }
        const auto bytes = unb64(item["node"]);
        if (!bytes) return std::nullopt;
        auto node = decode_tree_node(*bytes);
        const auto id = item["id"].get<std::string>();
        if (!node || node->id != id || state.nodes.contains(id)) return std::nullopt;
        state.nodes.emplace(id, std::move(*node));
    }
    for (const auto& item : (*doc)["committed"]) {
        if (!item.is_array() || item.size() != 2 || !item[0].is_string() ||
            !item[1].is_number_unsigned()) {
            return std::nullopt;
        }
        state.committed.insert(item[0].get<std::string>(), item[1].get<uint64_t>());
    }
    // The snapshot's own digest must describe the nodes it holds; the root
    // is checked against the next entry's previous root, or is the head.
    if (compute_tree_digest(state.nodes) != tree_digest) return std::nullopt;
    if (height == 0 && state.root != base_state_root(tree_digest)) return std::nullopt;
    return state;
}

TreeLog::OpenResult TreeLog::open(const rules::NodeMap& base_nodes) {
    std::error_code ec;
    fs::create_directories(directory_, ec);
    if (ec) {
        spdlog::error("[TreeLog] cannot create {}: {}", directory_.string(), ec.message());
        return OpenResult::Corrupt;
    }

    std::set<uint64_t> entries;
    std::set<uint64_t> snapshots;
    for (const auto& item : fs::directory_iterator(directory_, ec)) {
        if (!item.is_regular_file() || item.path().extension() != ".json") continue;
        const std::string stem = item.path().stem().string();
        if (stem.starts_with(kSnapshotPrefix)) {
            if (auto h = height_of(std::string_view(stem).substr(kSnapshotPrefix.size()))) {
                snapshots.insert(*h);
            }
        } else if (auto h = height_of(stem)) {
            entries.insert(*h);
        }
    }
    if (ec) {
        spdlog::error("[TreeLog] cannot list {}: {}", directory_.string(), ec.message());
        return OpenResult::Corrupt;
    }

    if (entries.empty() && snapshots.empty()) {
        // A new log starts from the tree as it is now. Every replica must
        // start from the same tree for their roots to agree.
        state_ = TreeChainState{};
        state_.nodes = base_nodes;
        state_.root = base_state_root(compute_tree_digest(state_.nodes));
        height_ = 0;
        if (!write_snapshot(0, state_) || !mark_applied(0)) {
            spdlog::error("[TreeLog] cannot write the base snapshot in {}", directory_.string());
            return OpenResult::Corrupt;
        }
        spdlog::info("[TreeLog] started a new tree log from {} nodes", state_.nodes.size());
        return OpenResult::Ok;
    }

    // The newest snapshot that loads. Entries must continue it without a gap.
    std::optional<TreeChainState> base;
    uint64_t base_height = 0;
    for (auto it = snapshots.rbegin(); it != snapshots.rend(); ++it) {
        base = read_snapshot(*it);
        if (base && *it > 0) {
            // Cross-check against the entry the snapshot follows: the same
            // tree digest, root, and block time, and a root recomputed from
            // the snapshot's own nodes and committed ids, or the snapshot is
            // not used.
            const auto entry = read_entry(*it);
            if (!entry || entry->state_root != base->root ||
                entry->tree_digest != compute_tree_digest(base->nodes) ||
                entry->block_time_ms != base->last_block_time_ms ||
                chain_state_root(entry->previous_root, entry->ops_digest, *base) !=
                    base->root) {
                base.reset();
            }
        }
        if (base) {
            base_height = *it;
            break;
        }
        spdlog::warn("[TreeLog] snapshot at height {} does not load; trying an older one", *it);
    }
    if (!base) {
        spdlog::error("[TreeLog] no usable snapshot in {}", directory_.string());
        return OpenResult::Corrupt;
    }
    state_ = std::move(*base);
    height_ = base_height;

    const uint64_t last = entries.empty() ? 0 : *entries.rbegin();
    for (uint64_t h = base_height + 1; h <= last; ++h) {
        if (!entries.contains(h)) {
            spdlog::error("[TreeLog] entry {} is missing below entry {}", h, last);
            return OpenResult::Corrupt;
        }
        const auto entry = read_entry(h);
        if (!entry || entry->height != h) {
            spdlog::error("[TreeLog] entry {} is unreadable or has another format", h);
            return OpenResult::Corrupt;
        }
        const auto result = replay_entry(state_, *entry);
        if (!result.verdict.ok()) {
            spdlog::error("[TreeLog] entry {}: {}", h, result.verdict.reason);
            return OpenResult::Corrupt;
        }
        height_ = h;
    }

    applied_height_ = 0;
    if (const auto applied = read_json_file(directory_ / kAppliedFile)) {
        uint64_t value = 0;
        if (format_ok(*applied) && read_u64(*applied, "height", value)) applied_height_ = value;
    }
    spdlog::info("[TreeLog] opened at height {} (snapshot {}, applied {})", height_, base_height,
                 applied_height_);
    return OpenResult::Ok;
}

bool TreeLog::append(const TreeLogEntry& entry, TreeChainState next) {
    if (entry.height != height_ + 1 || entry.previous_root != state_.root ||
        next.root != entry.state_root ||
        (entry.kind == TreeLogEntryKind::Merge && entry.height != 1)) {
        return false;
    }
    if (!security::write_durable(entry_path(entry.height), tree_log_entry_to_json(entry).dump())) {
        spdlog::error("[TreeLog] cannot write entry {}", entry.height);
        return false;
    }
    if (entry.height % kTreeLogSnapshotInterval == 0 && !write_snapshot(entry.height, next)) {
        // The entry is durable; replay still reaches this state from the
        // previous snapshot, so a failed snapshot costs replay time only.
        spdlog::warn("[TreeLog] cannot write the snapshot at height {}", entry.height);
    }
    state_ = std::move(next);
    height_ = entry.height;
    return true;
}

bool TreeLog::mark_applied(uint64_t height) {
    const json doc{{"format", kTreeLogFormatVersion}, {"height", height}};
    if (!security::write_durable(directory_ / kAppliedFile, doc.dump())) return false;
    applied_height_ = height;
    return true;
}

std::optional<TreeLogEntry> TreeLog::read_entry(uint64_t height) const {
    const auto doc = read_json_file(entry_path(height));
    if (!doc) return std::nullopt;
    return tree_log_entry_from_json(*doc);
}

}  // namespace nexus::tree
