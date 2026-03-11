#pragma once

#include <LemonadeNexus/Core/TrustTypes.hpp>

#include <array>
#include <concepts>

namespace nexus::core {

/// CRTP interface for TEE (Trusted Execution Environment) attestation providers.
///
/// Derived must implement:
///   - TeeAttestationReport do_generate_report(const std::array<uint8_t, 32>& nonce)
///   - bool do_verify_report(const TeeAttestationReport& report,
///                           const std::array<uint8_t, 32>& expected_nonce)
///   - bool do_platform_available() const
///   - TeePlatform do_detected_platform() const
template <typename Derived>
class ITeeAttestationProvider {
public:
    /// Generate a TEE attestation report bound to the given challenge nonce.
    /// The report proves that our binary is running inside a genuine TEE.
    [[nodiscard]] TeeAttestationReport generate_report(
            const std::array<uint8_t, 32>& nonce) {
        return self().do_generate_report(nonce);
    }

    /// Verify a remote server's TEE attestation report.
    /// Checks: platform-specific quote validity, nonce binding, timestamp freshness.
    [[nodiscard]] bool verify_report(
            const TeeAttestationReport& report,
            const std::array<uint8_t, 32>& expected_nonce) {
        return self().do_verify_report(report, expected_nonce);
    }

    /// Check if any TEE hardware is available on this machine.
    [[nodiscard]] bool platform_available() const {
        return self().do_platform_available();
    }

    /// Get which TEE platform was detected (or None).
    [[nodiscard]] TeePlatform detected_platform() const {
        return self().do_detected_platform();
    }

protected:
    ~ITeeAttestationProvider() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

/// Concept constraining a valid TEE attestation provider.
template <typename T>
concept TeeAttestationProviderType = requires(T t, const T ct,
                                               const std::array<uint8_t, 32>& nonce,
                                               const TeeAttestationReport& report) {
    { t.do_generate_report(nonce) } -> std::same_as<TeeAttestationReport>;
    { t.do_verify_report(report, nonce) } -> std::same_as<bool>;
    { ct.do_platform_available() } -> std::same_as<bool>;
    { ct.do_detected_platform() } -> std::same_as<TeePlatform>;
};

} // namespace nexus::core
