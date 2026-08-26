#pragma once

// The cached AMD revocation state, and where it comes from.
//
// Two jobs live here, and they are kept apart on purpose:
//
//   storage   — which bytes are on disk for which product, and how stale they
//               are. No cryptography. No trust decision.
//   validation — verify_snp_revocation() in SnpVerify. Signature under the
//               compiled AMD chain, validity window, revoked serials.
//
// The cache never decides whether a CRL is good. It hands over what it holds,
// and the verifier decides. That split is what keeps a fetch failure from
// looking like a cryptographic result, and it is why a stale file cannot
// quietly become an accepted one: the validity window inside the CRL is what
// expires it, not any policy this class applies.
//
// The verifier reaches no network. Refreshing is the operator's job, and a
// refresh that fails leaves the last good bytes in place until the CRL's own
// nextUpdate passes. New Tier 1 attestation then fails closed. An already
// frozen epoch is untouched: membership is decided once, at selection.
//
// Architecture reference: Security Architecture Final Draft 1.1, section 11.

#include <LemonadeNexus/Security/SnpVerify.hpp>

#include <cstdint>
#include <functional>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace nexus::security {

/// One product's cached CRL bytes plus when they were stored.
struct CachedCrl {
    std::string product;
    /// PEM or DER, exactly as fetched. Never reformatted: reformatting would
    /// mean parsing, and parsing belongs to the verifier.
    std::string bytes;
    /// When these bytes were written, in seconds since the epoch. Diagnostic
    /// only — freshness is decided by the CRL's own nextUpdate, which is
    /// signed, unlike a filesystem timestamp.
    int64_t stored_unix{0};
};

/// A file-backed cache of AMD CRLs, one file per product.
///
/// Reads never fail loudly: an absent, unreadable or empty file yields no
/// revocation state, and no revocation state fails new attestation closed.
class AmdRevocationCache {
public:
    /// `directory` is created on first store. It holds operational data, not
    /// security rules, so it is an ordinary path and carries no trust.
    explicit AmdRevocationCache(std::filesystem::path directory);

    /// Replaces the cached CRL for one product.
    ///
    /// The bytes are NOT validated here. A caller that stores garbage has
    /// stored garbage the verifier will refuse; it has not weakened anything.
    /// Returns false only on an I/O failure.
    [[nodiscard]] bool store(std::string_view product, std::string_view crl_bytes,
                            int64_t now_unix);

    /// The cached CRL for one product, or nullopt when nothing is cached.
    [[nodiscard]] std::optional<CachedCrl> load(std::string_view product) const;

    /// The revocation state to hand a verifier for `product` at `now_unix`.
    ///
    /// An empty `crl` is the honest answer when nothing is cached: the verifier
    /// then refuses rather than skipping the check. `now_unix` is passed
    /// through, not read from a clock here, so verification stays a pure
    /// function of its inputs.
    [[nodiscard]] AmdRevocationState state_for(std::string_view product,
                                               int64_t now_unix) const;

    /// Every cached list, for a verifier that does not yet know which silicon
    /// generation the peer it is examining runs on.
    [[nodiscard]] AmdRevocationState state(int64_t now_unix) const;

    /// A revocation source over the whole cache. `clock` supplies wall-clock
    /// seconds; it is injected so verification stays a pure function of its
    /// inputs and tests stay deterministic.
    [[nodiscard]] AmdRevocationSource source(std::function<int64_t()> clock) const;

    [[nodiscard]] const std::filesystem::path& directory() const { return directory_; }

private:
    [[nodiscard]] std::filesystem::path path_for(std::string_view product) const;

    std::filesystem::path directory_;
};

/// True when `product` is one this binary carries root material for. A CRL for
/// any other product has no chain to verify against, so it is refused before it
/// is read from disk.
[[nodiscard]] bool is_pinned_amd_product(std::string_view product);

}  // namespace nexus::security
