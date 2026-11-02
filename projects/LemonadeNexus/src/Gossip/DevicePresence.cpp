#include <LemonadeNexus/Gossip/DevicePresence.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>

namespace nexus::gossip {

namespace {

using json = nlohmann::json;

bool online_at(uint64_t seen, uint64_t now) {
    return seen > 0 && seen + kDevicePresenceOnlineSec > now;
}

// msgpack bytes of the outer map with an array header for up to
// kPresenceSyncMaxEntries entries: fixmap, the "entries" key, array16.
constexpr std::size_t kPayloadOverheadBytes = 1 + 8 + 3;
// msgpack bytes of one entry besides the node id characters: fixmap, the
// "node_id" key, a str8 header, the "seen" key, and a uint64.
constexpr std::size_t kEntryOverheadBytes = 1 + 8 + 2 + 5 + 9;

}  // namespace

bool presence_node_id_valid(std::string_view node_id) {
    if (node_id.empty() || node_id.size() > kDevicePresenceMaxNodeIdBytes) return false;
    return std::all_of(node_id.begin(), node_id.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '_' || c == '-';
    });
}

std::vector<std::vector<uint8_t>> encode_presence_sync(const std::vector<PresenceEntry>& entries) {
    std::vector<std::vector<uint8_t>> out;
    json page = json::array();
    std::size_t page_bytes = kPayloadOverheadBytes;
    const auto flush = [&] {
        if (page.empty()) return;
        out.push_back(json::to_msgpack(json{{"entries", std::move(page)}}));
        page = json::array();
        page_bytes = kPayloadOverheadBytes;
    };
    for (const auto& e : entries) {
        if (e.seen == 0 || !presence_node_id_valid(e.node_id)) continue;
        const auto bytes = kEntryOverheadBytes + e.node_id.size();
        if (page.size() >= kPresenceSyncMaxEntries ||
            page_bytes + bytes > kPresenceSyncMaxPayloadBytes) {
            flush();
        }
        page.push_back({{"node_id", e.node_id}, {"seen", e.seen}});
        page_bytes += bytes;
    }
    flush();
    return out;
}

std::optional<std::vector<PresenceEntry>> decode_presence_sync(std::span<const uint8_t> payload) {
    if (payload.empty() || payload.size() > kPresenceSyncMaxPayloadBytes) return std::nullopt;
    const auto doc = json::from_msgpack(payload.begin(), payload.end(), true, false);
    if (doc.is_discarded() || !doc.is_object()) return std::nullopt;
    const auto list = doc.find("entries");
    if (list == doc.end() || !list->is_array() || list->empty() ||
        list->size() > kPresenceSyncMaxEntries) {
        return std::nullopt;
    }
    std::vector<PresenceEntry> out;
    out.reserve(list->size());
    for (const auto& e : *list) {
        if (!e.is_object()) return std::nullopt;
        const auto id = e.find("node_id");
        const auto seen = e.find("seen");
        if (id == e.end() || !id->is_string() || seen == e.end() ||
            !seen->is_number_unsigned()) {
            return std::nullopt;
        }
        const auto& node_id = id->get_ref<const std::string&>();
        const auto time = seen->get<uint64_t>();
        if (!presence_node_id_valid(node_id) || time == 0) return std::nullopt;
        out.push_back({node_id, time});
    }
    return out;
}

DevicePresence::Entry* DevicePresence::find_or_add_locked(const std::string& node_id,
                                                          uint64_t now) {
    if (const auto it = entries_.find(node_id); it != entries_.end()) return &it->second;
    if (entries_.size() >= kDevicePresenceMaxEntries) {
        std::erase_if(entries_, [now](const auto& item) {
            return now >= item.second.seen && now - item.second.seen >= kDevicePresenceRetentionSec;
        });
        if (entries_.size() >= kDevicePresenceMaxEntries) return nullptr;
    }
    return &entries_[node_id];
}

DevicePresence::LocalResult DevicePresence::record_local(const std::string& node_id,
                                                         uint64_t now) {
    LocalResult result;
    if (now == 0 || !presence_node_id_valid(node_id)) return result;
    {
        std::lock_guard lock(mtx_);
        auto* entry = find_or_add_locked(node_id, now);
        if (!entry) return result;
        result.accepted = true;
        result.became_online = !online_at(entry->seen, now);
        result.locally_new = !online_at(entry->local_seen, now);
        entry->seen = std::max(entry->seen, now);
        entry->local_seen = std::max(entry->local_seen, now);
        entry->online = true;
    }
    if (result.became_online) notify_changed();
    return result;
}

DevicePresence::MergeResult DevicePresence::merge_remote(const std::vector<PresenceEntry>& entries,
                                                         uint64_t now) {
    MergeResult result;
    {
        std::lock_guard lock(mtx_);
        for (const auto& e : entries) {
            if (!presence_node_id_valid(e.node_id) || e.seen == 0) continue;
            if (e.seen > now + kDevicePresenceMaxSkewSec) {
                ++result.ahead;
                continue;
            }
            const auto seen = std::min(e.seen, now);
            if (now - seen >= kDevicePresenceRetentionSec) continue;
            auto* entry = find_or_add_locked(e.node_id, now);
            if (!entry || seen <= entry->seen) continue;
            ++result.merged;
            if (!online_at(entry->seen, now) && online_at(seen, now)) result.became_online = true;
            entry->seen = seen;
            if (online_at(seen, now)) entry->online = true;
        }
    }
    if (result.became_online) notify_changed();
    return result;
}

DevicePresence::Status DevicePresence::status(const std::string& node_id, uint64_t now) const {
    std::lock_guard lock(mtx_);
    const auto it = entries_.find(node_id);
    if (it == entries_.end()) return {};
    return {online_at(it->second.seen, now), it->second.seen};
}

std::vector<PresenceEntry> DevicePresence::local_online(uint64_t now) const {
    std::vector<PresenceEntry> out;
    {
        std::lock_guard lock(mtx_);
        for (const auto& [id, entry] : entries_) {
            if (online_at(entry.local_seen, now)) out.push_back({id, entry.local_seen});
        }
    }
    std::sort(out.begin(), out.end(),
              [](const PresenceEntry& a, const PresenceEntry& b) { return a.node_id < b.node_id; });
    return out;
}

DevicePresence::Sweep DevicePresence::sweep(uint64_t now) {
    Sweep result;
    std::lock_guard lock(mtx_);
    for (auto it = entries_.begin(); it != entries_.end();) {
        auto& entry = it->second;
        const bool online = online_at(entry.seen, now);
        if (entry.online && !online) result.went_offline = true;
        entry.online = online;
        if (online) {
            const auto expiry = entry.seen + kDevicePresenceOnlineSec;
            if (result.next_expiry == 0 || expiry < result.next_expiry) result.next_expiry = expiry;
        }
        if (now >= entry.seen && now - entry.seen >= kDevicePresenceRetentionSec) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
    return result;
}

void DevicePresence::set_changed_hook(std::function<void()> hook) {
    std::lock_guard lock(hook_mtx_);
    hook_ = std::move(hook);
}

void DevicePresence::notify_changed() {
    // The hook runs under hook_mtx_, so set_changed_hook waits for a running
    // call and the hook's owner can clear it before it is destroyed.
    std::lock_guard lock(hook_mtx_);
    if (hook_) hook_();
}

std::size_t DevicePresence::size() const {
    std::lock_guard lock(mtx_);
    return entries_.size();
}

}  // namespace nexus::gossip
