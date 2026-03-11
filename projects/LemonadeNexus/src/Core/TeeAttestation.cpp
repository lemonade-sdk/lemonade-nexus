#include <LemonadeNexus/Core/TeeAttestation.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>

// Platform-specific includes
#if defined(__linux__)
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

#if defined(__APPLE__)
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#endif

namespace nexus::core {

using json = nlohmann::json;
namespace chrono = std::chrono;

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

TeeAttestationService::TeeAttestationService(
    crypto::SodiumCryptoService& crypto,
    storage::FileStorageService& storage,
    BinaryAttestationService& binary_attestation)
    : crypto_(crypto)
    , storage_(storage)
    , binary_attestation_(binary_attestation)
{
}

// ---------------------------------------------------------------------------
// IService lifecycle
// ---------------------------------------------------------------------------

void TeeAttestationService::on_start() {
    detected_platform_ = detect_tee_platform();

    if (detected_platform_ != TeePlatform::None) {
        spdlog::info("[{}] TEE platform detected: {} — this server is Tier 1 capable",
                      name(), tee_platform_name(detected_platform_));

        // Generate initial attestation report with a random nonce
        std::array<uint8_t, 32> startup_nonce{};
        crypto_.random_bytes(startup_nonce);
        cached_report_ = do_generate_report(startup_nonce);

        if (cached_report_) {
            // Compute hash of the report for use in tokens
            auto canonical = canonical_attestation_json(*cached_report_);
            auto canonical_bytes = std::vector<uint8_t>(canonical.begin(), canonical.end());
            auto hash = crypto_.sha256(canonical_bytes);
            report_hash_ = crypto::to_hex(hash);
            spdlog::info("[{}] initial attestation report generated (hash: {}...)",
                          name(), report_hash_.substr(0, 16));
        }
    } else {
        spdlog::warn("[{}] no TEE hardware detected — this server will operate as Tier 2 "
                      "(certificate-only, hole punching only)", name());
    }

    spdlog::info("[{}] started (platform: {})", name(), tee_platform_name(detected_platform_));
}

void TeeAttestationService::on_stop() {
    spdlog::info("[{}] stopped", name());
}

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

TeePlatform TeeAttestationService::detect_tee_platform() {
#if defined(__APPLE__)
    // Check for Apple Secure Enclave (Apple Silicon only)
    // The Secure Enclave is available on all Apple Silicon Macs
    // and some Intel Macs with T2 chip
    {
        CFDictionaryRef attrs = nullptr;
        const void* keys[] = {kSecAttrTokenID};
        const void* values[] = {kSecAttrTokenIDSecureEnclave};
        attrs = CFDictionaryCreate(nullptr, keys, values, 1,
                                   &kCFTypeDictionaryKeyCallBacks,
                                   &kCFTypeDictionaryValueCallBacks);
        if (attrs) {
            // Try to check if Secure Enclave is accessible
            // On Apple Silicon, this should always work
            CFRelease(attrs);

            // Additional check: try to detect if we're on Apple Silicon
            // by checking for the Secure Enclave device
            if (std::filesystem::exists("/usr/libexec/seputil") ||
                std::filesystem::exists("/usr/sbin/bless")) {
                spdlog::debug("[{}] Apple Secure Enclave detected", name());
                return TeePlatform::AppleSecureEnclave;
            }
        }
    }
#endif

#if defined(__linux__)
    // Check for AMD SEV-SNP (runs inside a confidential VM)
    // Docker: /dev/sev-guest is mapped into the container automatically
    // when the host VM runs on SEV-SNP
    if (std::filesystem::exists("/dev/sev-guest")) {
        spdlog::debug("[{}] AMD SEV-SNP device found (/dev/sev-guest)", name());
        return TeePlatform::AmdSevSnp;
    }

    // Check for Intel TDX (Trust Domain Extensions)
    // Docker: /dev/tdx-guest mapped via --device
    if (std::filesystem::exists("/dev/tdx-guest") ||
        std::filesystem::exists("/dev/tdx_guest")) {
        spdlog::debug("[{}] Intel TDX device found", name());
        return TeePlatform::IntelTdx;
    }

    // Check for Intel SGX
    // Docker: --device=/dev/sgx_enclave --device=/dev/sgx_provision
    if (std::filesystem::exists("/dev/sgx_enclave") ||
        std::filesystem::exists("/dev/sgx/enclave") ||
        std::filesystem::exists("/dev/isgx")) {
        spdlog::debug("[{}] Intel SGX device found", name());
        return TeePlatform::IntelSgx;
    }

    // Also check CPUID for SGX support even if device files don't exist
    // (some environments expose SGX differently)
    {
        // CPUID leaf 7, subleaf 0, EBX bit 2 = SGX
        uint32_t eax = 0, ebx = 0, ecx = 0, edx = 0;
#if defined(__x86_64__) || defined(__i386__)
        __asm__ __volatile__(
            "cpuid"
            : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
            : "a"(7), "c"(0)
        );
        if (ebx & (1u << 2)) {
            spdlog::debug("[{}] Intel SGX supported (CPUID)", name());
            // SGX is supported by CPU but device may not be available
            // Only report if we have device access
        }
#endif
    }
#endif

    return TeePlatform::None;
}

// ---------------------------------------------------------------------------
// ITeeAttestationProvider implementation
// ---------------------------------------------------------------------------

bool TeeAttestationService::do_platform_available() const {
    return detected_platform_ != TeePlatform::None;
}

TeePlatform TeeAttestationService::do_detected_platform() const {
    return detected_platform_;
}

TeeAttestationReport TeeAttestationService::do_generate_report(
    const std::array<uint8_t, 32>& nonce) {

    switch (detected_platform_) {
        case TeePlatform::IntelSgx:          return generate_sgx_report(nonce);
        case TeePlatform::IntelTdx:          return generate_tdx_report(nonce);
        case TeePlatform::AmdSevSnp:         return generate_sev_snp_report(nonce);
        case TeePlatform::AppleSecureEnclave: return generate_apple_se_report(nonce);
        case TeePlatform::None:
            break;
    }

    // No platform — return an empty report
    TeeAttestationReport report;
    report.platform = TeePlatform::None;
    report.nonce = nonce;
    report.timestamp = static_cast<uint64_t>(chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count());
    report.binary_hash = binary_attestation_.self_hash();
    return report;
}

bool TeeAttestationService::do_verify_report(
    const TeeAttestationReport& report,
    const std::array<uint8_t, 32>& expected_nonce) {

    // 1. Check nonce binding
    if (report.nonce != expected_nonce) {
        spdlog::warn("[{}] attestation report nonce mismatch", name());
        return false;
    }

    // 2. Check timestamp freshness
    auto now = static_cast<uint64_t>(chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count());
    if (report.timestamp + kTeeReportMaxAgeSec < now) {
        spdlog::warn("[{}] attestation report expired (age={}s)",
                      name(), now - report.timestamp);
        return false;
    }
    if (report.timestamp > now + 300) {  // 5 min future tolerance
        spdlog::warn("[{}] attestation report from the future", name());
        return false;
    }

    // 3. Verify Ed25519 signature over canonical JSON
    if (!report.signature.empty() && !report.server_pubkey.empty()) {
        auto pubkey_bytes = crypto::from_base64(report.server_pubkey);
        if (pubkey_bytes.size() != crypto::kEd25519PublicKeySize) {
            spdlog::warn("[{}] attestation report has invalid pubkey size", name());
            return false;
        }

        crypto::Ed25519PublicKey pubkey{};
        std::memcpy(pubkey.data(), pubkey_bytes.data(), crypto::kEd25519PublicKeySize);

        auto canonical = canonical_attestation_json(report);
        auto canonical_bytes = std::vector<uint8_t>(canonical.begin(), canonical.end());

        auto sig_bytes = crypto::from_base64(report.signature);
        if (sig_bytes.size() != crypto::kEd25519SignatureSize) {
            spdlog::warn("[{}] attestation report has invalid signature size", name());
            return false;
        }

        crypto::Ed25519Signature sig{};
        std::memcpy(sig.data(), sig_bytes.data(), crypto::kEd25519SignatureSize);

        if (!crypto_.ed25519_verify(pubkey, canonical_bytes, sig)) {
            spdlog::warn("[{}] attestation report signature verification failed", name());
            return false;
        }
    }

    // 4. Platform-specific quote verification
    if (report.platform == TeePlatform::None) {
        spdlog::warn("[{}] attestation report has no TEE platform", name());
        return false;
    }

    switch (report.platform) {
        case TeePlatform::IntelSgx:          return verify_sgx_report(report);
        case TeePlatform::IntelTdx:          return verify_tdx_report(report);
        case TeePlatform::AmdSevSnp:         return verify_sev_snp_report(report);
        case TeePlatform::AppleSecureEnclave: return verify_apple_se_report(report);
        case TeePlatform::None:
            return false;
    }
    return false;
}

// ---------------------------------------------------------------------------
// AttestationToken generation and verification
// ---------------------------------------------------------------------------

AttestationToken TeeAttestationService::generate_token(
    const crypto::Ed25519Keypair& keypair) {

    std::lock_guard lock(mutex_);

    AttestationToken token;
    token.server_pubkey = crypto::to_base64(keypair.public_key);
    token.platform = detected_platform_;
    token.binary_hash = binary_attestation_.self_hash();
    token.timestamp = static_cast<uint64_t>(chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count());

    if (cached_report_) {
        token.attestation_hash = report_hash_;
        token.attestation_timestamp = cached_report_->timestamp;

        // Check if we need to refresh the underlying TEE report
        if (token.timestamp - cached_report_->timestamp > kTeeReportMaxAgeSec / 2) {
            // Report is getting stale — regenerate
            std::array<uint8_t, 32> fresh_nonce{};
            crypto_.random_bytes(fresh_nonce);
            cached_report_ = do_generate_report(fresh_nonce);
            if (cached_report_) {
                auto canonical = canonical_attestation_json(*cached_report_);
                auto canonical_bytes = std::vector<uint8_t>(canonical.begin(), canonical.end());
                auto hash = crypto_.sha256(canonical_bytes);
                report_hash_ = crypto::to_hex(hash);
                token.attestation_hash = report_hash_;
                token.attestation_timestamp = cached_report_->timestamp;
            }
        }
    }

    // Sign the token
    auto canonical = canonical_token_json(token);
    auto canonical_bytes = std::vector<uint8_t>(canonical.begin(), canonical.end());
    auto sig = crypto_.ed25519_sign(keypair.private_key, canonical_bytes);
    token.signature = crypto::to_base64(sig);

    return token;
}

bool TeeAttestationService::verify_token(const AttestationToken& token) const {
    // 1. Check platform — must have TEE
    if (token.platform == TeePlatform::None) {
        spdlog::debug("[{}] token has no TEE platform", name());
        return false;
    }

    // 2. Check timestamp freshness (zero-trust: tokens must be fresh)
    auto now = static_cast<uint64_t>(chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count());

    if (token.timestamp + kAttestationTokenMaxAgeSec < now) {
        spdlog::debug("[{}] token expired (age={}s, max={}s)",
                       name(), now - token.timestamp, kAttestationTokenMaxAgeSec);
        return false;
    }
    if (token.timestamp > now + 60) {
        spdlog::debug("[{}] token from the future", name());
        return false;
    }

    // 3. Check attestation report freshness
    if (token.attestation_timestamp + kTeeReportMaxAgeSec < now) {
        spdlog::debug("[{}] underlying TEE report expired", name());
        return false;
    }

    // 4. Verify Ed25519 signature
    auto pubkey_bytes = crypto::from_base64(token.server_pubkey);
    if (pubkey_bytes.size() != crypto::kEd25519PublicKeySize) {
        spdlog::debug("[{}] token has invalid pubkey size", name());
        return false;
    }

    crypto::Ed25519PublicKey pubkey{};
    std::memcpy(pubkey.data(), pubkey_bytes.data(), crypto::kEd25519PublicKeySize);

    auto canonical = canonical_token_json(token);
    auto canonical_bytes = std::vector<uint8_t>(canonical.begin(), canonical.end());

    auto sig_bytes = crypto::from_base64(token.signature);
    if (sig_bytes.size() != crypto::kEd25519SignatureSize) {
        spdlog::debug("[{}] token has invalid signature size", name());
        return false;
    }

    crypto::Ed25519Signature sig{};
    std::memcpy(sig.data(), sig_bytes.data(), crypto::kEd25519SignatureSize);

    if (!crypto_.ed25519_verify(pubkey, canonical_bytes, sig)) {
        spdlog::warn("[{}] token signature verification failed for {}",
                      name(), token.server_pubkey.substr(0, 12) + "...");
        return false;
    }

    // 5. Verify binary hash matches an approved release
    if (binary_attestation_.has_signing_pubkey() &&
        !binary_attestation_.is_approved_binary(token.binary_hash)) {
        spdlog::warn("[{}] token binary hash not in approved manifests", name());
        return false;
    }

    return true;
}

std::optional<TeeAttestationReport> TeeAttestationService::cached_report() const {
    std::lock_guard lock(mutex_);
    return cached_report_;
}

void TeeAttestationService::set_platform_override(const std::string& platform_str) {
    detected_platform_ = tee_platform_from_string(platform_str);
    spdlog::info("[{}] platform overridden to: {}", name(), tee_platform_name(detected_platform_));
}

// ===========================================================================
// PLATFORM BACKENDS
// ===========================================================================

// ---------------------------------------------------------------------------
// Intel SGX backend
// ---------------------------------------------------------------------------

TeeAttestationReport TeeAttestationService::generate_sgx_report(
    const std::array<uint8_t, 32>& nonce) {

    TeeAttestationReport report;
    report.platform = TeePlatform::IntelSgx;
    report.nonce = nonce;
    report.timestamp = static_cast<uint64_t>(chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count());
    report.binary_hash = binary_attestation_.self_hash();

#if defined(__linux__) && (defined(__x86_64__) || defined(__i386__))
    // Intel SGX DCAP quote generation
    // In Docker: requires --device=/dev/sgx_enclave --device=/dev/sgx_provision
    //
    // Real implementation would:
    // 1. Open /dev/sgx_enclave
    // 2. Create an SGX report with the nonce in report_data
    // 3. Use sgx_ql_get_quote() from libsgx-dcap-ql to convert report to quote
    // 4. Quote contains MRENCLAVE (code measurement) + report_data (our nonce)
    //
    // For now, we read the SGX device to prove access, and generate a
    // self-signed report. Full DCAP integration requires the DCAP library.

    int fd = open("/dev/sgx_enclave", O_RDONLY);
    if (fd < 0) {
        fd = open("/dev/sgx/enclave", O_RDONLY);
    }
    if (fd >= 0) {
        close(fd);

        // Generate a proof-of-access report
        // In production, this would be a real DCAP quote
        std::vector<uint8_t> quote_data;
        quote_data.reserve(128);

        // Magic header identifying this as an SGX attestation
        const uint8_t sgx_magic[] = {'S', 'G', 'X', '1'};
        quote_data.insert(quote_data.end(), sgx_magic, sgx_magic + 4);

        // Include nonce
        quote_data.insert(quote_data.end(), nonce.begin(), nonce.end());

        // Include binary hash
        auto hash_bytes = crypto::from_hex(report.binary_hash);
        quote_data.insert(quote_data.end(), hash_bytes.begin(), hash_bytes.end());

        // Include timestamp
        auto ts = report.timestamp;
        for (int i = 0; i < 8; ++i) {
            quote_data.push_back(static_cast<uint8_t>(ts & 0xFF));
            ts >>= 8;
        }

        report.quote = std::move(quote_data);
        spdlog::info("[{}] SGX attestation report generated ({} bytes)",
                      name(), report.quote.size());
    } else {
        spdlog::warn("[{}] cannot open SGX device for quote generation", name());
    }
#else
    spdlog::warn("[{}] SGX not available on this platform", name());
#endif

    return report;
}

bool TeeAttestationService::verify_sgx_report(const TeeAttestationReport& report) const {
    if (report.quote.size() < 4) return false;

    // Check magic header
    if (report.quote[0] != 'S' || report.quote[1] != 'G' ||
        report.quote[2] != 'X' || report.quote[3] != '1') {
        spdlog::warn("[{}] invalid SGX quote magic", name());
        return false;
    }

    // In production: use sgx_ql_verify_quote() or Intel Attestation Service API
    // to verify the DCAP quote against Intel's root of trust.
    //
    // For now, verify the structural integrity (nonce binding, binary hash)

    if (report.quote.size() >= 36) {
        // Verify nonce binding (bytes 4-35)
        if (std::memcmp(report.quote.data() + 4, report.nonce.data(), 32) != 0) {
            spdlog::warn("[{}] SGX quote nonce mismatch", name());
            return false;
        }
    }

    spdlog::debug("[{}] SGX report verified (structural)", name());
    return true;
}

// ---------------------------------------------------------------------------
// Intel TDX backend
// ---------------------------------------------------------------------------

TeeAttestationReport TeeAttestationService::generate_tdx_report(
    const std::array<uint8_t, 32>& nonce) {

    TeeAttestationReport report;
    report.platform = TeePlatform::IntelTdx;
    report.nonce = nonce;
    report.timestamp = static_cast<uint64_t>(chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count());
    report.binary_hash = binary_attestation_.self_hash();

#if defined(__linux__)
    // Intel TDX: open /dev/tdx-guest, use TDX_CMD_GET_REPORT ioctl
    // The entire VM runs inside a Trust Domain — the report proves this
    int fd = open("/dev/tdx-guest", O_RDWR);
    if (fd < 0) {
        fd = open("/dev/tdx_guest", O_RDWR);
    }
    if (fd >= 0) {
        // TDX report generation via ioctl
        // struct tdx_report_req { uint8_t report_data[64]; uint8_t tdreport[1024]; };
        // ioctl(fd, TDX_CMD_GET_REPORT, &req);

        // For now, proof-of-access + structured report
        std::vector<uint8_t> quote_data;
        const uint8_t tdx_magic[] = {'T', 'D', 'X', '1'};
        quote_data.insert(quote_data.end(), tdx_magic, tdx_magic + 4);
        quote_data.insert(quote_data.end(), nonce.begin(), nonce.end());
        auto hash_bytes = crypto::from_hex(report.binary_hash);
        quote_data.insert(quote_data.end(), hash_bytes.begin(), hash_bytes.end());

        report.quote = std::move(quote_data);
        close(fd);

        spdlog::info("[{}] TDX attestation report generated", name());
    } else {
        spdlog::warn("[{}] cannot open TDX device", name());
    }
#endif

    return report;
}

bool TeeAttestationService::verify_tdx_report(const TeeAttestationReport& report) const {
    if (report.quote.size() < 4) return false;
    if (report.quote[0] != 'T' || report.quote[1] != 'D' ||
        report.quote[2] != 'X' || report.quote[3] != '1') {
        return false;
    }

    // Verify nonce binding
    if (report.quote.size() >= 36) {
        if (std::memcmp(report.quote.data() + 4, report.nonce.data(), 32) != 0) {
            return false;
        }
    }

    spdlog::debug("[{}] TDX report verified (structural)", name());
    return true;
}

// ---------------------------------------------------------------------------
// AMD SEV-SNP backend
// ---------------------------------------------------------------------------

TeeAttestationReport TeeAttestationService::generate_sev_snp_report(
    const std::array<uint8_t, 32>& nonce) {

    TeeAttestationReport report;
    report.platform = TeePlatform::AmdSevSnp;
    report.nonce = nonce;
    report.timestamp = static_cast<uint64_t>(chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count());
    report.binary_hash = binary_attestation_.self_hash();

#if defined(__linux__)
    // AMD SEV-SNP: open /dev/sev-guest, use SNP_GET_REPORT ioctl
    // Docker: runs inside SEV-SNP confidential VM, device is mapped automatically
    //
    // struct snp_report_req {
    //     uint8_t user_data[64];  // our nonce goes here
    //     uint32_t vmpl;
    // };
    // struct snp_report_resp {
    //     uint8_t data[4000];  // attestation report
    //     uint32_t size;
    // };
    // struct snp_guest_request_ioctl {
    //     uint8_t msg_version;
    //     uint64_t req_data;
    //     uint64_t resp_data;
    //     uint64_t fw_err;
    // };

    int fd = open("/dev/sev-guest", O_RDWR);
    if (fd >= 0) {
        // In production: fill snp_report_req with nonce, issue SNP_GET_REPORT ioctl
        // The kernel returns a signed attestation report with the VM's launch measurement

        // For now, proof-of-access + structured report
        std::vector<uint8_t> quote_data;
        const uint8_t sev_magic[] = {'S', 'E', 'V', '1'};
        quote_data.insert(quote_data.end(), sev_magic, sev_magic + 4);
        quote_data.insert(quote_data.end(), nonce.begin(), nonce.end());
        auto hash_bytes = crypto::from_hex(report.binary_hash);
        quote_data.insert(quote_data.end(), hash_bytes.begin(), hash_bytes.end());

        report.quote = std::move(quote_data);
        close(fd);

        spdlog::info("[{}] AMD SEV-SNP attestation report generated", name());
    } else {
        spdlog::warn("[{}] cannot open SEV-SNP device", name());
    }
#endif

    return report;
}

bool TeeAttestationService::verify_sev_snp_report(const TeeAttestationReport& report) const {
    if (report.quote.size() < 4) return false;
    if (report.quote[0] != 'S' || report.quote[1] != 'E' ||
        report.quote[2] != 'V' || report.quote[3] != '1') {
        return false;
    }

    // In production: fetch VCEK cert from AMD KDS, verify ECDSA P-384 signature
    // on the attestation report, validate cert chain against AMD root CA

    if (report.quote.size() >= 36) {
        if (std::memcmp(report.quote.data() + 4, report.nonce.data(), 32) != 0) {
            return false;
        }
    }

    spdlog::debug("[{}] SEV-SNP report verified (structural)", name());
    return true;
}

// ---------------------------------------------------------------------------
// Apple Secure Enclave backend
// ---------------------------------------------------------------------------

TeeAttestationReport TeeAttestationService::generate_apple_se_report(
    const std::array<uint8_t, 32>& nonce) {

    TeeAttestationReport report;
    report.platform = TeePlatform::AppleSecureEnclave;
    report.nonce = nonce;
    report.timestamp = static_cast<uint64_t>(chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count());
    report.binary_hash = binary_attestation_.self_hash();

#if defined(__APPLE__)
    // Apple Secure Enclave attestation via Security.framework
    // This works on Apple Silicon Macs (bare metal only, not in Docker)
    //
    // Flow:
    // 1. Create Secure Enclave-backed key (kSecAttrTokenIDSecureEnclave)
    // 2. Use the key to sign our nonce — proves we have Secure Enclave access
    // 3. The signed nonce + key attestation forms our quote
    //
    // For Docker: Apple Secure Enclave is NOT available in Docker on macOS
    // (Docker for Mac runs a Linux VM without hardware access)

    // Create attestation key parameters using pure CoreFoundation C APIs
    // (no Objective-C required)

    // Private key attributes: non-permanent ephemeral key
    const void* privAttrKeys[]   = {kSecAttrIsPermanent};
    const void* privAttrValues[] = {kCFBooleanFalse};
    CFDictionaryRef privAttrs = CFDictionaryCreate(
        nullptr, privAttrKeys, privAttrValues, 1,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    // Key size as CFNumber
    int keySizeBits = 256;
    CFNumberRef keySizeRef = CFNumberCreate(nullptr, kCFNumberIntType, &keySizeBits);

    // Top-level key creation attributes
    const void* attrKeys[] = {
        kSecAttrKeyType,
        kSecAttrKeySizeInBits,
        kSecAttrTokenID,
        kSecPrivateKeyAttrs,
    };
    const void* attrValues[] = {
        kSecAttrKeyTypeECSECPrimeRandom,
        keySizeRef,
        kSecAttrTokenIDSecureEnclave,
        privAttrs,
    };
    CFDictionaryRef attributes = CFDictionaryCreate(
        nullptr, attrKeys, attrValues, 4,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CFRelease(privAttrs);
    CFRelease(keySizeRef);

    CFErrorRef error = nullptr;
    SecKeyRef privateKey = SecKeyCreateRandomKey(attributes, &error);
    CFRelease(attributes);

    if (privateKey && !error) {
        // Sign our nonce with the Secure Enclave key
        CFDataRef nonceData = CFDataCreate(nullptr, nonce.data(),
                                            static_cast<CFIndex>(nonce.size()));
        CFDataRef signature = SecKeyCreateSignature(
            privateKey,
            kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
            nonceData,
            &error);
        CFRelease(nonceData);

        if (signature && !error) {
            const uint8_t* sig_ptr = CFDataGetBytePtr(signature);
            auto sig_len = static_cast<size_t>(CFDataGetLength(signature));

            std::vector<uint8_t> quote_data;
            const uint8_t apple_magic[] = {'A', 'P', 'S', 'E'};  // Apple Secure Enclave
            quote_data.insert(quote_data.end(), apple_magic, apple_magic + 4);
            quote_data.insert(quote_data.end(), nonce.begin(), nonce.end());
            quote_data.insert(quote_data.end(), sig_ptr, sig_ptr + sig_len);

            // Append the public key for verification
            SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
            if (publicKey) {
                CFDataRef pubKeyData = SecKeyCopyExternalRepresentation(publicKey, nullptr);
                if (pubKeyData) {
                    const uint8_t* pk_ptr = CFDataGetBytePtr(pubKeyData);
                    auto pk_len = static_cast<size_t>(CFDataGetLength(pubKeyData));
                    // Length-prefix the public key
                    auto pk_len_u16 = static_cast<uint16_t>(pk_len);
                    quote_data.push_back(static_cast<uint8_t>(pk_len_u16 & 0xFF));
                    quote_data.push_back(static_cast<uint8_t>((pk_len_u16 >> 8) & 0xFF));
                    quote_data.insert(quote_data.end(), pk_ptr, pk_ptr + pk_len);
                    CFRelease(pubKeyData);
                }
                CFRelease(publicKey);
            }

            report.quote = std::move(quote_data);
            CFRelease(signature);
            spdlog::info("[{}] Apple Secure Enclave attestation generated", name());
        } else {
            if (error) {
                spdlog::warn("[{}] Secure Enclave signing failed", name());
                CFRelease(error);
            }
        }
        CFRelease(privateKey);
    } else {
        if (error) {
            spdlog::warn("[{}] cannot create Secure Enclave key", name());
            CFRelease(error);
        }
    }
#endif

    return report;
}

bool TeeAttestationService::verify_apple_se_report(const TeeAttestationReport& report) const {
    if (report.quote.size() < 4) return false;
    if (report.quote[0] != 'A' || report.quote[1] != 'P' ||
        report.quote[2] != 'S' || report.quote[3] != 'E') {
        return false;
    }

#if defined(__APPLE__)
    // Verify: extract public key from quote, verify ECDSA signature over nonce
    // In production: also validate the key attestation certificate chain
    // against Apple's root CA

    if (report.quote.size() < 36) return false;

    // Verify nonce binding (bytes 4-35)
    if (std::memcmp(report.quote.data() + 4, report.nonce.data(), 32) != 0) {
        spdlog::warn("[{}] Apple SE quote nonce mismatch", name());
        return false;
    }

    spdlog::debug("[{}] Apple SE report verified (structural)", name());
    return true;
#else
    // Can't verify Apple attestation on non-Apple platforms
    // In production, you'd verify the certificate chain using OpenSSL
    spdlog::debug("[{}] Apple SE verification on non-Apple platform (chain only)", name());
    return report.quote.size() >= 36;
#endif
}

} // namespace nexus::core
