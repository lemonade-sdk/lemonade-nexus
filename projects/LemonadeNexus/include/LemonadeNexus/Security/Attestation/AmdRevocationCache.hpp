#pragma once

// A file-backed cache of AMD CRLs, one file per product.
//
// Storage only. The cache never decides whether a list is good — it hands over
// what it holds and verify_snp_revocation checks the signature, the validity
// window and the serials. Keeping the two apart is what stops a fetch failure
// from reading as a cryptographic result, and stops a stale file from quietly
// becoming an accepted one.
#include <LemonadeNexus/Security/SnpVerify.hpp>

#include <cstdint>
#include <functional>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace nexus::security {

struct CachedCrl {
    std::string product;
    /// PEM or DER, exactly as fetched. Reformatting would mean parsing, and
    /// parsing belongs to the verifier.
    std::string bytes;
    /// Diagnostic only. Freshness comes from the CRL's signed nextUpdate, not
    /// from a filesystem timestamp.
    int64_t stored_unix{0};
};

class AmdRevocationCache {
public:
    explicit AmdRevocationCache(std::filesystem::path directory);

    /// Replaces the cached CRL for one product. The bytes are not validated
    /// here; garbage stored is garbage the verifier refuses. False on I/O
    /// failure or an unpinned product.
    [[nodiscard]] bool store(std::string_view product, std::string_view crl_bytes,
                            int64_t now_unix);

    /// Nullopt when nothing is cached, which the verifier treats as a refusal
    /// rather than as an empty list.
    [[nodiscard]] std::optional<CachedCrl> load(std::string_view product) const;

    [[nodiscard]] AmdRevocationState state_for(std::string_view product,
                                               int64_t now_unix) const;

    /// Every cached list, for a verifier that does not yet know which silicon
    /// generation the peer it is examining runs on.
    [[nodiscard]] AmdRevocationState state(int64_t now_unix) const;

    /// `clock` is injected so verification stays a pure function of its inputs.
    [[nodiscard]] AmdRevocationSource source(std::function<int64_t()> clock) const;

    [[nodiscard]] const std::filesystem::path& directory() const { return directory_; }

private:
    [[nodiscard]] std::filesystem::path path_for(std::string_view product) const;

    std::filesystem::path directory_;
};

/// A CRL for a product with no compiled-in root has no chain to verify against,
/// so it is refused before it reaches disk.
[[nodiscard]] bool is_pinned_amd_product(std::string_view product);

}  // namespace nexus::security
