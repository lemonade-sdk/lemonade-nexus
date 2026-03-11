#include <LemonadeNexus/Relay/RelayDiscoveryService.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>

namespace nexus::relay {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

RelayDiscoveryService::RelayDiscoveryService(storage::FileStorageService& storage)
    : storage_(storage)
{
}

// ---------------------------------------------------------------------------
// IService
// ---------------------------------------------------------------------------

void RelayDiscoveryService::on_start() {
    spdlog::info("[{}] starting -- loading relay list from storage", name());
    do_refresh_relay_list();
}

void RelayDiscoveryService::on_stop() {
    spdlog::info("[{}] stopped", name());
}

// ---------------------------------------------------------------------------
// IRelayDiscovery -- discover_relays
// ---------------------------------------------------------------------------

std::vector<RelayNodeInfo> RelayDiscoveryService::do_discover_relays(
        const RelaySelectionCriteria& criteria) const {
    std::lock_guard lock(mutex_);

    std::vector<RelayNodeInfo> results;
    results.reserve(known_relays_.size());

    for (const auto& node : known_relays_) {
        // Apply filters
        if (!criteria.preferred_region.empty() && node.region != criteria.preferred_region) {
            continue;
        }
        if (node.reputation_score < criteria.min_reputation) {
            continue;
        }
        if (node.capacity_mbps < criteria.min_capacity_mbps) {
            continue;
        }
        if (node.estimated_latency_ms > static_cast<float>(criteria.max_latency_ms)) {
            continue;
        }
        if (!node.supports_relay) {
            continue;
        }
        results.push_back(node);
    }

    // Sort by reputation (descending), then by latency (ascending)
    std::sort(results.begin(), results.end(),
              [](const RelayNodeInfo& a, const RelayNodeInfo& b) {
                  if (a.reputation_score != b.reputation_score) {
                      return a.reputation_score > b.reputation_score;
                  }
                  return a.estimated_latency_ms < b.estimated_latency_ms;
              });

    // Limit to max_results
    if (results.size() > criteria.max_results) {
        results.resize(criteria.max_results);
    }

    return results;
}

// ---------------------------------------------------------------------------
// IRelayDiscovery -- select_best_relay
// ---------------------------------------------------------------------------

std::optional<RelayNodeInfo> RelayDiscoveryService::do_select_best_relay(
        const RelaySelectionCriteria& criteria) const {
    auto candidates = do_discover_relays(criteria);
    if (candidates.empty()) {
        return std::nullopt;
    }
    return candidates.front();
}

// ---------------------------------------------------------------------------
// IRelayDiscovery -- report_relay_quality
// ---------------------------------------------------------------------------

void RelayDiscoveryService::do_report_relay_quality(const RelayQualityReport& report) {
    reputation_.record_quality_report(report);

    // Update the cached reputation score for this relay
    float new_score = reputation_.get_score(report.relay_id);

    std::lock_guard lock(mutex_);
    for (auto& node : known_relays_) {
        if (node.relay_id == report.relay_id) {
            node.reputation_score = new_score;
            spdlog::debug("[{}] updated reputation for relay {} -> {:.3f}",
                          name(), report.relay_id, new_score);
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// IRelayDiscovery -- is_relay_trusted
// ---------------------------------------------------------------------------

bool RelayDiscoveryService::do_is_relay_trusted(std::string_view relay_id) const {
    std::lock_guard lock(mutex_);
    return trusted_relay_ids_.contains(std::string(relay_id));
}

// ---------------------------------------------------------------------------
// IRelayDiscovery -- get_stun_servers
// ---------------------------------------------------------------------------

std::vector<std::string> RelayDiscoveryService::do_get_stun_servers() const {
    std::lock_guard lock(mutex_);

    std::vector<std::string> servers;
    for (const auto& node : known_relays_) {
        if (node.supports_stun && !node.endpoint.empty()) {
            servers.push_back(node.endpoint);
        }
    }
    return servers;
}

// ---------------------------------------------------------------------------
// IRelayDiscovery -- refresh_relay_list
// ---------------------------------------------------------------------------

void RelayDiscoveryService::do_refresh_relay_list() {
    // Read all relay node files from the "relay" category in storage
    auto nodes = storage_.list_nodes();

    std::vector<RelayNodeInfo> relays;
    std::unordered_set<std::string> trusted;

    for (const auto& node_id : nodes) {
        auto envelope = storage_.read_file("relay", node_id);
        if (!envelope) {
            continue;
        }

        auto info = parse_relay_node(envelope->data);
        if (!info) {
            spdlog::warn("[{}] failed to parse relay node: {}", name(), node_id);
            continue;
        }

        // Look up reputation score from the engine
        float score = reputation_.get_score(info->relay_id);
        if (score > 0.0f) {
            info->reputation_score = score;
        }

        // Any relay present in signed storage is considered trusted
        trusted.insert(info->relay_id);
        relays.push_back(std::move(*info));
    }

    {
        std::lock_guard lock(mutex_);
        known_relays_ = std::move(relays);
        trusted_relay_ids_ = std::move(trusted);
    }

    spdlog::info("[{}] loaded {} relay nodes ({} trusted)",
                 name(), known_relays_.size(), trusted_relay_ids_.size());
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

std::optional<RelayNodeInfo> RelayDiscoveryService::parse_relay_node(
        const std::string& json_data) {
    try {
        auto j = nlohmann::json::parse(json_data);

        RelayNodeInfo info;
        info.relay_id         = j.value("relay_id", "");
        info.public_key       = j.value("public_key", "");
        info.endpoint         = j.value("endpoint", "");
        info.region           = j.value("region", "");
        info.hostname         = j.value("hostname", "");
        info.capacity_mbps    = j.value("capacity_mbps", 0u);
        info.reputation_score = j.value("reputation_score", 0.5f);
        info.estimated_latency_ms = j.value("estimated_latency_ms", 0.0f);
        info.supports_stun    = j.value("supports_stun", true);
        info.supports_relay   = j.value("supports_relay", true);
        info.is_central       = j.value("is_central", false);

        if (info.relay_id.empty() || info.endpoint.empty()) {
            return std::nullopt;
        }

        return info;
    } catch (const nlohmann::json::exception& e) {
        spdlog::warn("Failed to parse relay node JSON: {}", e.what());
        return std::nullopt;
    }
}

} // namespace nexus::relay
