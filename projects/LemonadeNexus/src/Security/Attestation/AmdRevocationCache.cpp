#include <LemonadeNexus/Security/Attestation/AmdRevocationCache.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <fstream>
#include <iterator>
#include <system_error>
#include <utility>

namespace nexus::security {

namespace {

/// The product name becomes a filename, so it must not be able to name any
/// other path. Only the compiled-in products are ever accepted, which makes
/// this a whitelist rather than an escaping problem.
[[nodiscard]] std::string crl_file_name(std::string_view product) {
    return std::string(product) + ".crl";
}

}  // namespace

bool is_pinned_amd_product(std::string_view product) {
    const auto products = pinned_amd_products();
    return std::find(products.begin(), products.end(), product) != products.end();
}

AmdRevocationCache::AmdRevocationCache(std::filesystem::path directory)
    : directory_(std::move(directory)) {}

std::filesystem::path AmdRevocationCache::path_for(std::string_view product) const {
    return directory_ / crl_file_name(product);
}

bool AmdRevocationCache::store(std::string_view product, std::string_view crl_bytes,
                               int64_t now_unix) {
    // A product with no compiled-in root has no chain to verify a CRL against,
    // so caching one would store bytes nothing could ever check.
    if (!is_pinned_amd_product(product)) {
        spdlog::warn("[revocation] refusing to cache a CRL for unknown product {}", product);
        return false;
    }
    if (crl_bytes.empty()) {
        return false;
    }

    std::error_code ec;
    std::filesystem::create_directories(directory_, ec);
    if (ec) {
        spdlog::warn("[revocation] cannot create {}: {}", directory_.string(), ec.message());
        return false;
    }

    // Write beside the target and rename, so a crash mid-write cannot leave a
    // truncated CRL that the verifier would read as malformed.
    const std::filesystem::path target = path_for(product);
    const std::filesystem::path temporary = target.string() + ".new";
    {
        std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
        if (!out) {
            return false;
        }
        out.write(crl_bytes.data(), static_cast<std::streamsize>(crl_bytes.size()));
        if (!out) {
            return false;
        }
    }
    std::filesystem::rename(temporary, target, ec);
    if (ec) {
        std::filesystem::remove(temporary, ec);
        return false;
    }

    std::ofstream stamp(target.string() + ".stored", std::ios::trunc);
    if (stamp) {
        stamp << now_unix;
    }
    return true;
}

std::optional<CachedCrl> AmdRevocationCache::load(std::string_view product) const {
    if (!is_pinned_amd_product(product)) {
        return std::nullopt;
    }
    const std::filesystem::path target = path_for(product);
    std::ifstream in(target, std::ios::binary);
    if (!in) {
        return std::nullopt;
    }
    CachedCrl cached;
    cached.product = product;
    cached.bytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    if (cached.bytes.empty()) {
        return std::nullopt;
    }
    if (std::ifstream stamp(target.string() + ".stored"); stamp) {
        stamp >> cached.stored_unix;
    }
    return cached;
}

AmdRevocationState AmdRevocationCache::state_for(std::string_view product,
                                                 int64_t now_unix) const {
    AmdRevocationState state;
    state.now_unix = now_unix;
    if (auto cached = load(product)) {
        state.crls.push_back(std::move(cached->bytes));
    }
    // An empty list is the honest answer. The verifier refuses on it rather
    // than treating an absent list as an empty one.
    return state;
}

AmdRevocationState AmdRevocationCache::state(int64_t now_unix) const {
    // A mesh spans silicon generations, and a verifier does not know which one
    // a peer runs until it resolves that peer's chain. Hand over everything;
    // the verifier picks the list that belongs to the chain in hand.
    AmdRevocationState state;
    state.now_unix = now_unix;
    for (const auto product : pinned_amd_products()) {
        if (auto cached = load(product)) {
            state.crls.push_back(std::move(cached->bytes));
        }
    }
    return state;
}

AmdRevocationSource AmdRevocationCache::source(std::function<int64_t()> clock) const {
    // The cache is captured by value: the source outlives this call, and a
    // dangling reference here would silently become "no revocation data".
    AmdRevocationCache copy = *this;
    return [copy, clock = std::move(clock)] {
        return copy.state(clock ? clock() : 0);
    };
}

}  // namespace nexus::security
