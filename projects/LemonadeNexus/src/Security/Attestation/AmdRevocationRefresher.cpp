#include <LemonadeNexus/Security/Attestation/AmdRevocationRefresher.hpp>

#include <LemonadeNexus/Security/SnpVerify.hpp>

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <ctime>
#include <exception>
#include <limits>
#include <optional>
#include <utility>

namespace nexus::security {

namespace {

/// ISO 8601 UTC for log lines; "none" for the zero that means "no time".
std::string utc_string(int64_t unix_seconds) {
    if (unix_seconds <= 0) return "none";
    const time_t when = static_cast<time_t>(unix_seconds);
    struct tm t{};
#if defined(_WIN32)
    if (gmtime_s(&t, &when) != 0) return std::to_string(unix_seconds);
#else
    if (gmtime_r(&when, &t) == nullptr) return std::to_string(unix_seconds);
#endif
    char buf[32];
    if (std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &t) == 0) {
        return std::to_string(unix_seconds);
    }
    return buf;
}

/// How a cached list stands at `now`, for the one log line an attempt writes.
std::string cached_standing(const std::optional<AmdCrlInspection>& cached, int64_t now_unix) {
    if (!cached.has_value()) return "nothing is cached";
    if (!cached->ok) return "the cached list is unusable (" + cached->failure + ")";
    if (cached->next_update_unix <= now_unix) {
        return "the cached list expired at " + utc_string(cached->next_update_unix) +
               "; new attestation fails closed until a fetch succeeds";
    }
    const int64_t left = cached->next_update_unix - now_unix;
    return "the cached list is valid until " + utc_string(cached->next_update_unix) + " (" +
           std::to_string(left / 3600) + " h left)";
}

}  // namespace

AmdCrlFetchResult fetch_amd_crl_https(const std::string& url) {
    AmdCrlFetchResult out;
    constexpr std::string_view kScheme = "https://";
    if (url.rfind(kScheme, 0) != 0) {
        out.error = "not an https URL";
        return out;
    }
    const auto path_start = url.find('/', kScheme.size());
    if (path_start == std::string::npos) {
        out.error = "URL has no path";
        return out;
    }
    const std::string host = url.substr(kScheme.size(), path_start - kScheme.size());
    try {
        // The same client shape as the VCEK fetch in PlatformProbe: verified
        // TLS, short timeouts, KDS redirects followed.
        httplib::SSLClient client(host, 443);
        client.set_connection_timeout(10);
        client.set_read_timeout(30);
        client.set_follow_location(true);
        client.enable_server_certificate_verification(true);
        auto res = client.Get(url.substr(path_start));
        if (!res) {
            out.error = httplib::to_string(res.error());
            return out;
        }
        out.status = res->status;
        out.body = std::move(res->body);
    } catch (const std::exception& e) {
        out.error = e.what();
    }
    return out;
}

std::string_view amd_crl_refresh_outcome_name(AmdCrlRefreshOutcome outcome) {
    switch (outcome) {
        case AmdCrlRefreshOutcome::NotDue: return "not_due";
        case AmdCrlRefreshOutcome::Skipped: return "skipped";
        case AmdCrlRefreshOutcome::Refreshed: return "refreshed";
        case AmdCrlRefreshOutcome::Unchanged: return "unchanged";
        case AmdCrlRefreshOutcome::FetchFailed: return "fetch_failed";
        case AmdCrlRefreshOutcome::Unparsable: return "unparsable";
        case AmdCrlRefreshOutcome::SignatureInvalid: return "signature_invalid";
        case AmdCrlRefreshOutcome::OlderThanCached: return "older_than_cached";
        case AmdCrlRefreshOutcome::StoreFailed: return "store_failed";
    }
    return "unknown";
}

AmdRevocationRefresher::AmdRevocationRefresher(AmdRevocationRefresherConfig config)
    : config_(std::move(config)), cache_(config_.directory) {
    if (config_.products.empty()) {
        for (const auto product : pinned_amd_products()) {
            products_.emplace_back(product);
        }
    } else {
        products_ = config_.products;
    }
    if (config_.backoff_base_seconds <= 0) config_.backoff_base_seconds = 1;
    if (config_.backoff_max_seconds < config_.backoff_base_seconds) {
        config_.backoff_max_seconds = config_.backoff_base_seconds;
    }
    if (config_.check_interval_seconds <= 0) config_.check_interval_seconds = 1;
}

int64_t AmdRevocationRefresher::backoff_seconds(uint32_t failures, int64_t base_seconds,
                                                int64_t max_seconds) {
    if (failures == 0) return 0;
    int64_t delay = base_seconds;
    for (uint32_t i = 1; i < failures && delay < max_seconds; ++i) delay *= 2;
    return std::min(delay, max_seconds);
}

bool AmdRevocationRefresher::due(int64_t now_unix) const {
    std::lock_guard lock(mutex_);
    return std::any_of(products_.begin(), products_.end(), [&](const std::string& product) {
        const auto it = states_.find(product);
        return it == states_.end() || it->second.next_attempt_unix <= now_unix;
    });
}

AmdRevocationRefresher::ProductState AmdRevocationRefresher::state(
    std::string_view product) const {
    std::lock_guard lock(mutex_);
    const auto it = states_.find(product);
    return it == states_.end() ? ProductState{} : it->second;
}

void AmdRevocationRefresher::record(std::string_view product, int64_t now_unix, bool failed) {
    std::lock_guard lock(mutex_);
    auto& entry = states_[std::string(product)];
    if (failed) {
        if (entry.failures < 32) ++entry.failures;
        entry.next_attempt_unix =
            now_unix + backoff_seconds(entry.failures, config_.backoff_base_seconds,
                                       config_.backoff_max_seconds);
    } else {
        entry.failures = 0;
        entry.next_attempt_unix = now_unix + config_.check_interval_seconds;
    }
}

void AmdRevocationRefresher::skip(std::string_view product) {
    std::lock_guard lock(mutex_);
    auto& entry = states_[std::string(product)];
    entry.failures = 0;
    // Nothing can ever check a list for this product, so there is no attempt
    // to schedule.
    entry.next_attempt_unix = std::numeric_limits<int64_t>::max();
}

void AmdRevocationRefresher::tick(int64_t now_unix) {
    std::vector<std::string> due_now;
    {
        std::lock_guard lock(mutex_);
        for (const auto& product : products_) {
            const auto it = states_.find(product);
            if (it == states_.end() || it->second.next_attempt_unix <= now_unix) {
                due_now.push_back(product);
            }
        }
    }
    for (const auto& product : due_now) {
        (void)refresh(product, now_unix);
    }
}

AmdCrlRefreshOutcome AmdRevocationRefresher::refresh(std::string_view product,
                                                     int64_t now_unix) {
    if (pinned_amd_chain(product).empty()) {
        skip(product);
        spdlog::debug("[revocation] {}: no compiled-in AMD chain, no CRL to keep current",
                      product);
        return AmdCrlRefreshOutcome::Skipped;
    }

    std::optional<AmdCrlInspection> cached;
    if (const auto on_disk = cache_.load(product)) {
        cached = inspect_amd_crl(product, on_disk->bytes);
    }
    const bool cached_is_good = cached.has_value() && cached->ok;
    const bool due_for_refresh =
        !cached_is_good ||
        cached->next_update_unix <= now_unix + config_.refresh_window_seconds;
    if (!due_for_refresh) {
        record(product, now_unix, false);
        return AmdCrlRefreshOutcome::NotDue;
    }

    // One warning per attempt, naming the reason and what the node is left
    // with. Each failure also backs off, so a KDS outage is not a request storm.
    const auto failed = [&](AmdCrlRefreshOutcome outcome, const std::string& reason) {
        record(product, now_unix, true);
        const auto next = state(product);
        spdlog::warn("[revocation] {}: CRL refresh failed ({}): {}; {}; next attempt at {}",
                     product, amd_crl_refresh_outcome_name(outcome), reason,
                     cached_standing(cached, now_unix), utc_string(next.next_attempt_unix));
        return outcome;
    };

    if (!config_.fetch) {
        return failed(AmdCrlRefreshOutcome::FetchFailed, "no fetch configured");
    }
    const std::string url = amd_crl_kds_url(product);
    AmdCrlFetchResult fetched;
    try {
        fetched = config_.fetch(url);
    } catch (const std::exception& e) {
        fetched = {};
        fetched.error = e.what();
    }
    if (fetched.status != 200 || fetched.body.empty()) {
        std::string reason = "KDS " + url;
        if (fetched.status != 0) {
            reason += " answered HTTP " + std::to_string(fetched.status);
            if (fetched.body.empty()) reason += " with an empty body";
        } else {
            reason += " gave no response";
        }
        if (!fetched.error.empty()) reason += " (" + fetched.error + ")";
        return failed(AmdCrlRefreshOutcome::FetchFailed, reason);
    }

    const AmdCrlInspection candidate = inspect_amd_crl(product, fetched.body);
    if (!candidate.ok) {
        return failed(candidate.parsed ? AmdCrlRefreshOutcome::SignatureInvalid
                                       : AmdCrlRefreshOutcome::Unparsable,
                      candidate.failure);
    }
    if (cached_is_good) {
        // thisUpdate must not go backwards: a list older than the one on disk
        // could predate a revocation the cached one already names.
        if (candidate.this_update_unix < cached->this_update_unix) {
            return failed(AmdCrlRefreshOutcome::OlderThanCached,
                          "KDS served a list from " + utc_string(candidate.this_update_unix) +
                              ", older than the cached " +
                              utc_string(cached->this_update_unix));
        }
        if (candidate.this_update_unix == cached->this_update_unix &&
            candidate.next_update_unix == cached->next_update_unix) {
            // KDS has not published a newer list yet. Not a failure of this
            // node, but the cached list is still running out, so say so.
            record(product, now_unix, false);
            spdlog::info("[revocation] {}: KDS still serves the cached CRL; {}", product,
                         cached_standing(cached, now_unix));
            return AmdCrlRefreshOutcome::Unchanged;
        }
    }
    if (!cache_.store(product, fetched.body, now_unix)) {
        return failed(AmdCrlRefreshOutcome::StoreFailed,
                      "could not write " + cache_.directory().string());
    }
    record(product, now_unix, false);
    spdlog::info("[revocation] {}: CRL refreshed from KDS; thisUpdate {}, nextUpdate {}, {} "
                 "revoked serial(s)",
                 product, utc_string(candidate.this_update_unix),
                 utc_string(candidate.next_update_unix), candidate.revoked_count);
    return AmdCrlRefreshOutcome::Refreshed;
}

}  // namespace nexus::security
