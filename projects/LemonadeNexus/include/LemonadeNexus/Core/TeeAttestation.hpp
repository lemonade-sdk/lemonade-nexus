#pragma once

#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Core/ITeeAttestationProvider.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <mutex>
#include <optional>
#include <string>

namespace nexus::core {

/// TEE Attestation Service — detects and uses hardware TEE capabilities.
///
/// Supports three TEE platforms:
///   - Intel SGX/TDX: via DCAP library or /dev/tdx-guest (works in Docker with device passthrough)
///   - AMD SEV-SNP: via /dev/sev-guest ioctl (works in Docker inside SEV-SNP VM)
///   - Apple Secure Enclave: via Security.framework (macOS bare-metal only)
///
/// At startup, probes for available TEE hardware. If none found, reports
/// TeePlatform::None and the server operates as Tier 2.
///
/// Docker compatibility:
///   Intel SGX: docker run --device=/dev/sgx_enclave --device=/dev/sgx_provision
///   AMD SEV-SNP: runs automatically inside confidential VM, /dev/sev-guest mapped
///   Apple: not available in Docker (macOS Docker runs Linux VMs)
class TeeAttestationService : public IService<TeeAttestationService>,
                                public ITeeAttestationProvider<TeeAttestationService> {
    friend class IService<TeeAttestationService>;
    friend class ITeeAttestationProvider<TeeAttestationService>;

public:
    TeeAttestationService(crypto::SodiumCryptoService& crypto,
                           storage::FileStorageService& storage,
                           BinaryAttestationService& binary_attestation);

    /// Get our cached attestation report (generated at startup or on demand).
    [[nodiscard]] std::optional<TeeAttestationReport> cached_report() const;

    /// Generate a fresh AttestationToken for inclusion in gossip messages.
    /// The token is a lightweight, signed proof of TEE status.
    [[nodiscard]] AttestationToken generate_token(
        const crypto::Ed25519Keypair& keypair);

    /// Verify an AttestationToken from a remote server.
    /// Zero-trust: called on EVERY incoming sensitive gossip message.
    [[nodiscard]] bool verify_token(const AttestationToken& token) const;

    /// Force override the detected platform (for testing or config).
    void set_platform_override(const std::string& platform_str);

private:
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "TeeAttestationService"; }

    // ITeeAttestationProvider
    [[nodiscard]] TeeAttestationReport do_generate_report(const std::array<uint8_t, 32>& nonce);
    [[nodiscard]] bool do_verify_report(const TeeAttestationReport& report,
                                         const std::array<uint8_t, 32>& expected_nonce);
    [[nodiscard]] bool do_platform_available() const;
    [[nodiscard]] TeePlatform do_detected_platform() const;

    /// Platform detection (called at startup)
    TeePlatform detect_tee_platform();

    // Platform-specific attestation backends
    [[nodiscard]] TeeAttestationReport generate_sgx_report(const std::array<uint8_t, 32>& nonce);
    [[nodiscard]] TeeAttestationReport generate_tdx_report(const std::array<uint8_t, 32>& nonce);
    [[nodiscard]] TeeAttestationReport generate_sev_snp_report(const std::array<uint8_t, 32>& nonce);
    [[nodiscard]] TeeAttestationReport generate_apple_se_report(const std::array<uint8_t, 32>& nonce);

    [[nodiscard]] bool verify_sgx_report(const TeeAttestationReport& report) const;
    [[nodiscard]] bool verify_tdx_report(const TeeAttestationReport& report) const;
    [[nodiscard]] bool verify_sev_snp_report(const TeeAttestationReport& report) const;
    [[nodiscard]] bool verify_apple_se_report(const TeeAttestationReport& report) const;

    crypto::SodiumCryptoService& crypto_;
    storage::FileStorageService& storage_;
    BinaryAttestationService& binary_attestation_;

    TeePlatform detected_platform_{TeePlatform::None};
    std::optional<TeeAttestationReport> cached_report_;
    std::string report_hash_;  // hex SHA-256 of cached_report_ canonical JSON
    mutable std::mutex mutex_;
};

} // namespace nexus::core
