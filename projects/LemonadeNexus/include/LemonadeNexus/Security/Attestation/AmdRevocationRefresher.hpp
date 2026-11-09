#pragma once

// Keeps the AmdRevocationCache current from AMD KDS.
//
// The verifier reads the cache and refuses a list past its signed nextUpdate.
// Without a refresh every list on disk expires, and from that moment every new
// Tier 1 attestation on the node fails closed: no storage unlock after a
// restart, no rollout. This object fetches a product's list before that
// happens. It changes nothing about what the verifier accepts: a fetched list
// reaches disk only when it passes inspect_amd_crl under the compiled-in chain
// and is not older than the cached one, and any failure keeps the cached file.
//
// Scheduling is the caller's. The object is a clock-driven state machine with
// an injected fetch, so tests drive it without a network.
#include <LemonadeNexus/Security/Attestation/AmdRevocationCache.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::security {

/// One HTTP answer from KDS. `status` 0 means no response; `error` says why.
struct AmdCrlFetchResult {
    int status{0};
    std::string body;
    std::string error;
};

/// Fetches one URL. Blocking; may take the full connection and read timeouts.
using AmdCrlFetch = std::function<AmdCrlFetchResult(const std::string& url)>;

/// The production fetch: HTTPS with certificate verification and the same
/// timeouts the VCEK fetch uses. Never throws.
[[nodiscard]] AmdCrlFetchResult fetch_amd_crl_https(const std::string& url);

struct AmdRevocationRefresherConfig {
    /// The cache directory (AmdRevocationCache).
    std::filesystem::path directory;
    /// Required. The refresher does no network I/O of its own.
    AmdCrlFetch fetch;
    /// Products to keep current. Empty means pinned_amd_products(). A product
    /// without compiled-in material is skipped: nothing could check its list.
    std::vector<std::string> products;
    /// A cached list whose nextUpdate is this close, or past, is refreshed.
    int64_t refresh_window_seconds{7 * 24 * 3600};
    /// How often a product is re-examined after a successful attempt or while
    /// its list is not due. Bounds the KDS request rate when all is well.
    int64_t check_interval_seconds{3600};
    /// Retry pacing after a failed attempt: base doubles per failure, capped.
    int64_t backoff_base_seconds{5 * 60};
    int64_t backoff_max_seconds{6 * 3600};
};

enum class AmdCrlRefreshOutcome : uint8_t {
    /// The cached list is good and not near its nextUpdate; nothing fetched.
    NotDue,
    /// No compiled-in chain for the product; never fetched.
    Skipped,
    /// A newer list passed inspection and is now on disk.
    Refreshed,
    /// KDS still serves the cached list; nothing changed.
    Unchanged,
    FetchFailed,
    Unparsable,
    SignatureInvalid,
    OlderThanCached,
    StoreFailed,
};

[[nodiscard]] std::string_view amd_crl_refresh_outcome_name(AmdCrlRefreshOutcome outcome);

class AmdRevocationRefresher {
public:
    explicit AmdRevocationRefresher(AmdRevocationRefresherConfig config);

    /// True when some product's next attempt is at or before `now_unix`. In
    /// memory only; safe to call on every tick from any thread.
    [[nodiscard]] bool due(int64_t now_unix) const;

    /// One attempt for every due product. Blocking while the fetch runs; the
    /// state lock is not held during the fetch, so due() stays responsive.
    void tick(int64_t now_unix);

    /// One attempt for one product, whatever the schedule says. Records the
    /// outcome, so the next due() follows from it.
    AmdCrlRefreshOutcome refresh(std::string_view product, int64_t now_unix);

    struct ProductState {
        uint32_t failures{0};
        /// Unix seconds of the next permitted attempt; 0 means now.
        int64_t next_attempt_unix{0};
    };
    [[nodiscard]] ProductState state(std::string_view product) const;

    /// Seconds to wait after `failures` consecutive failures: `base` doubling
    /// per failure, never above `max`, zero for no failures.
    [[nodiscard]] static int64_t backoff_seconds(uint32_t failures, int64_t base_seconds,
                                                 int64_t max_seconds);

    [[nodiscard]] const AmdRevocationCache& cache() const { return cache_; }
    [[nodiscard]] const std::vector<std::string>& products() const { return products_; }

private:
    void record(std::string_view product, int64_t now_unix, bool failed);
    void skip(std::string_view product);

    AmdRevocationRefresherConfig config_;
    AmdRevocationCache cache_;
    std::vector<std::string> products_;
    mutable std::mutex mutex_;
    std::map<std::string, ProductState, std::less<>> states_;
};

}  // namespace nexus::security
