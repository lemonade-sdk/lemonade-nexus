#include <LemonadeNexus/Security/EvidenceSnpSvsmVtpm.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/EvidenceBinding.hpp>
#include <LemonadeNexus/Security/MeasurementIma.hpp>
#include <LemonadeNexus/Security/SnpReport.hpp>
#include <LemonadeNexus/Security/TpmQuote.hpp>

#include "AttestationDetail.hpp"

#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <iterator>
#include <limits>
#include <utility>

namespace nexus::security {

using json = nlohmann::json;

namespace {

inline constexpr uint16_t kTpmAlgRsa = 0x0001;
inline constexpr uint16_t kTpmAlgAes = 0x0006;
inline constexpr uint16_t kTpmAlgNull = 0x0010;
inline constexpr uint16_t kTpmAlgCfb = 0x0043;

inline constexpr uint32_t kTpmaFixedTpm = 1u << 1;
inline constexpr uint32_t kTpmaFixedParent = 1u << 4;
inline constexpr uint32_t kTpmaSensitiveDataOrigin = 1u << 5;
inline constexpr uint32_t kTpmaUserWithAuth = 1u << 6;
inline constexpr uint32_t kTpmaAdminWithPolicy = 1u << 7;
inline constexpr uint32_t kTpmaRestricted = 1u << 16;
inline constexpr uint32_t kTpmaDecrypt = 1u << 17;
inline constexpr uint32_t kTpmaSignEncrypt = 1u << 18;

class BeReader {
public:
    explicit BeReader(std::span<const uint8_t> bytes) : bytes_(bytes) {}
    bool u16(uint16_t& out) {
        if (left() < 2) return false;
        out = static_cast<uint16_t>((bytes_[at_] << 8) | bytes_[at_ + 1]);
        at_ += 2;
        return true;
    }
    bool u32(uint32_t& out) {
        if (left() < 4) return false;
        out = (static_cast<uint32_t>(bytes_[at_]) << 24) |
              (static_cast<uint32_t>(bytes_[at_ + 1]) << 16) |
              (static_cast<uint32_t>(bytes_[at_ + 2]) << 8) |
              static_cast<uint32_t>(bytes_[at_ + 3]);
        at_ += 4;
        return true;
    }
    bool blob(std::vector<uint8_t>& out) {
        uint16_t size = 0;
        if (!u16(size) || size > left()) return false;
        out.assign(bytes_.begin() + static_cast<long>(at_),
                   bytes_.begin() + static_cast<long>(at_ + size));
        at_ += size;
        return true;
    }
    [[nodiscard]] std::size_t left() const { return bytes_.size() - at_; }
private:
    std::span<const uint8_t> bytes_;
    std::size_t at_{0};
};

using detail::b64;
using detail::unb64;
using detail::exact_keys;

bool sha(const EVP_MD* md, std::span<const uint8_t> first,
         std::span<const uint8_t> second, std::span<uint8_t> out) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return false;
    unsigned size = 0;
    const bool ok = EVP_DigestInit_ex(ctx, md, nullptr) == 1 &&
                    EVP_DigestUpdate(ctx, first.data(), first.size()) == 1 &&
                    EVP_DigestUpdate(ctx, second.data(), second.size()) == 1 &&
                    EVP_DigestFinal_ex(ctx, out.data(), &size) == 1 && size == out.size();
    EVP_MD_CTX_free(ctx);
    return ok;
}

SvsmEvidenceVerdict deny_svsm(SvsmEvidenceVerdict verdict,
                              SvsmEvidenceFailure failure, std::string why) {
    verdict.ok = false;
    verdict.svsm_failure = failure;
    verdict.failure = std::move(why);
    return verdict;
}

bool matches_hex(std::span<const uint8_t> bytes, const std::string& expected) {
    return !expected.empty() && hex_of(bytes) == expected;
}

// RSA exponent as big-endian bytes with leading zeros trimmed.
std::vector<uint8_t> exponent_be(uint32_t exponent) {
    std::vector<uint8_t> bytes{
        static_cast<uint8_t>(exponent >> 24), static_cast<uint8_t>(exponent >> 16),
        static_cast<uint8_t>(exponent >> 8), static_cast<uint8_t>(exponent)};
    bytes.erase(bytes.begin(), std::find_if(bytes.begin(), bytes.end(),
                                            [](uint8_t byte) { return byte != 0; }));
    return bytes;
}

}  // namespace

std::optional<TpmRsaPublic> parse_tpmt_public_rsa(std::span<const uint8_t> bytes) {
    BeReader reader(bytes);
    TpmRsaPublic out;
    if (!reader.u16(out.type) || out.type != kTpmAlgRsa ||
        !reader.u16(out.name_alg) || out.name_alg != kTpmAlgSha256 ||
        !reader.u32(out.object_attributes) || !reader.blob(out.auth_policy) ||
        !reader.u16(out.symmetric_alg)) {
        return std::nullopt;
    }
    if (out.symmetric_alg != kTpmAlgNull) {
        if (out.symmetric_alg != kTpmAlgAes || !reader.u16(out.symmetric_key_bits) ||
            !reader.u16(out.symmetric_mode) || out.symmetric_key_bits == 0 ||
            out.symmetric_mode == kTpmAlgNull) {
            return std::nullopt;
        }
    }
    if (!reader.u16(out.scheme)) return std::nullopt;
    if (out.scheme != kTpmAlgNull) {
        if ((out.scheme != kTpmAlgRsassa && out.scheme != kTpmAlgRsapss) ||
            !reader.u16(out.scheme_hash) || out.scheme_hash != kTpmAlgSha256) {
            return std::nullopt;
        }
    }
    if (!reader.u16(out.key_bits) || !reader.u32(out.exponent) ||
        !reader.blob(out.modulus) || reader.left() != 0 ||
        out.key_bits != out.modulus.size() * 8 || out.key_bits < 2048) {
        return std::nullopt;
    }
    if (out.exponent == 0) out.exponent = 65537;
    if (out.exponent < 3 || (out.exponent & 1) == 0) return std::nullopt;

    std::array<uint8_t, 32> digest{};
    unsigned digest_len = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), digest.data(), &digest_len,
                   EVP_sha256(), nullptr) != 1 || digest_len != digest.size()) {
        return std::nullopt;
    }
    out.name = {static_cast<uint8_t>(out.name_alg >> 8),
                static_cast<uint8_t>(out.name_alg & 0xff)};
    out.name.insert(out.name.end(), digest.begin(), digest.end());

    out.spki_b64 = rsa_spki_b64(out.modulus, exponent_be(out.exponent));
    if (out.spki_b64.empty()) return std::nullopt;
    return out;
}

bool is_svsm_vtpm_ek(const TpmRsaPublic& public_area) {
    static constexpr std::array<uint8_t, 32> kTcgEkPolicyASha256{
        0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8,
        0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
        0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64,
        0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
    };
    constexpr uint32_t required = kTpmaFixedTpm | kTpmaFixedParent |
                                  kTpmaSensitiveDataOrigin | kTpmaAdminWithPolicy |
                                  kTpmaRestricted | kTpmaDecrypt;
    constexpr uint32_t forbidden = kTpmaUserWithAuth | kTpmaSignEncrypt;
    return (public_area.object_attributes & required) == required &&
           (public_area.object_attributes & forbidden) == 0 &&
           public_area.symmetric_alg == kTpmAlgAes &&
           public_area.symmetric_key_bits == 128 &&
           public_area.symmetric_mode == kTpmAlgCfb &&
           public_area.scheme == kTpmAlgNull && public_area.key_bits == 2048 &&
           std::ranges::equal(public_area.auth_policy, kTcgEkPolicyASha256);
}

bool is_nexus_quote_ak(const TpmRsaPublic& public_area) {
    constexpr uint32_t required = kTpmaFixedTpm | kTpmaFixedParent |
                                  kTpmaSensitiveDataOrigin | kTpmaUserWithAuth |
                                  kTpmaRestricted | kTpmaSignEncrypt;
    constexpr uint32_t forbidden = kTpmaAdminWithPolicy | kTpmaDecrypt;
    return (public_area.object_attributes & required) == required &&
           (public_area.object_attributes & forbidden) == 0 &&
           public_area.symmetric_alg == kTpmAlgNull &&
           public_area.scheme == kTpmAlgRsassa &&
           public_area.scheme_hash == kTpmAlgSha256 && public_area.key_bits == 2048;
}

Digest ak_ek_binding_digest(std::span<const uint8_t> ek_name,
                            std::span<const uint8_t> ak_name) {
    CanonicalEncoder encoder("LEMONADE-NEXUS-SVSM-AK-EK-ACTIVATION-V1");
    encoder.add_bytes(ek_name);
    encoder.add_bytes(ak_name);
    return encoder.digest();
}

std::array<uint8_t, 64> svsm_report_nonce(const Digest& challenge_digest) {
    static constexpr std::string_view domain =
        "LEMONADE-NEXUS-SVSM-REPORT-NONCE-V1";
    std::array<uint8_t, 64> nonce{};
    (void)sha(EVP_sha512(),
              {reinterpret_cast<const uint8_t*>(domain.data()), domain.size()},
              challenge_digest, nonce);
    return nonce;
}

Digest svsm_enrollment_challenge_digest(
    std::span<const uint8_t> admission_nonce,
    std::span<const uint8_t> candidate_identity) {
    CanonicalEncoder encoder("LEMONADE-NEXUS-SVSM-AK-ENROLLMENT-CHALLENGE-V1");
    encoder.add_bytes(admission_nonce);
    encoder.add_bytes(candidate_identity);
    encoder.add_u32(kSvsmAttestationProtocolVersion);
    encoder.add_string(kSvsmVtpmServiceGuid);
    encoder.add_u32(kSvsmVtpmManifestVersion);
    return encoder.digest();
}

std::string encode_snp_svsm_vtpm_evidence(const SnpSvsmVtpmEvidence& ev) {
    json j;
    j["profile"] = "snp-svsm-vtpm";
    j["protocol_version"] = ev.protocol_version;
    j["service_provider"] = ev.service_provider;
    j["service_guid"] = ev.service_guid;
    j["service_manifest_version"] = ev.service_manifest_version;
    j["svsm_report"] = b64(ev.svsm_report);
    j["guest_report"] = b64(ev.guest_report);
    j["vcek_der"] = b64(ev.vcek_der);
    j["amd_chain_pem"] = ev.amd_chain_pem;
    j["ek_manifest"] = b64(ev.ek_manifest);
    j["certificate_blob"] = b64(ev.certificate_blob);
    j["ak_public"] = b64(ev.ak_public);
    j["tpms_attest"] = b64(ev.tpms_attest);
    j["tpm_signature"] = b64(ev.tpm_signature);
    j["pcr_values"] = b64(ev.pcr_values);
    j["ima_binary_log"] = b64(ev.ima_binary_log);
    j["binary_path"] = ev.binary_path;
    j["binary_sha256"] = ev.binary_sha256;
    j["ima_unavailable"] = ev.ima_unavailable;
    j["runtime_no_new_privs"] = ev.runtime_no_new_privs;
    j["runtime_seccomp_mode"] = ev.runtime_seccomp_mode;
    return j.dump();
}

std::optional<SnpSvsmVtpmEvidence> decode_snp_svsm_vtpm_evidence(std::string_view text) {
    const json j = json::parse(text, nullptr, false);
    if (!exact_keys(j, {"profile", "protocol_version", "service_provider",
                        "service_guid", "service_manifest_version", "svsm_report",
                        "guest_report", "vcek_der", "amd_chain_pem", "ek_manifest",
                        "certificate_blob", "ak_public", "tpms_attest",
                        "tpm_signature", "pcr_values", "ima_binary_log",
                        "binary_path", "binary_sha256", "ima_unavailable",
                        "runtime_no_new_privs", "runtime_seccomp_mode"}) ||
        j.value("profile", "") != "snp-svsm-vtpm") {
        return std::nullopt;
    }
    try {
        SnpSvsmVtpmEvidence ev;
        ev.protocol_version = j.at("protocol_version").get<uint32_t>();
        ev.service_provider = j.at("service_provider").get<std::string>();
        ev.service_guid = j.at("service_guid").get<std::string>();
        ev.service_manifest_version = j.at("service_manifest_version").get<uint32_t>();
        ev.svsm_report = unb64(j.at("svsm_report"));
        ev.guest_report = unb64(j.at("guest_report"));
        ev.vcek_der = unb64(j.at("vcek_der"));
        ev.amd_chain_pem = j.at("amd_chain_pem").get<std::string>();
        ev.ek_manifest = unb64(j.at("ek_manifest"));
        ev.certificate_blob = unb64(j.at("certificate_blob"));
        ev.ak_public = unb64(j.at("ak_public"));
        ev.tpms_attest = unb64(j.at("tpms_attest"));
        ev.tpm_signature = unb64(j.at("tpm_signature"));
        ev.pcr_values = unb64(j.at("pcr_values"));
        ev.ima_binary_log = unb64(j.at("ima_binary_log"));
        ev.binary_path = j.at("binary_path").get<std::string>();
        ev.binary_sha256 = j.at("binary_sha256").get<std::string>();
        ev.ima_unavailable = j.at("ima_unavailable").get<std::string>();
        ev.runtime_no_new_privs = j.at("runtime_no_new_privs").get<std::string>();
        ev.runtime_seccomp_mode = j.at("runtime_seccomp_mode").get<std::string>();
        return ev;
    } catch (...) {
        return std::nullopt;
    }
}

SvsmAkEnrollmentIdentity verify_svsm_ak_enrollment_identity(
    const SnpSvsmVtpmEvidence& ev, const Digest& enrollment_challenge_digest,
    const SvsmAkEnrollmentRequirements& req) {
    SvsmAkEnrollmentIdentity identity;
    const auto refuse = [&identity](std::string failure) {
        identity.ok = false;
        identity.failure = std::move(failure);
        return identity;
    };
    if (ev.protocol_version != kSvsmAttestationProtocolVersion ||
        ev.service_provider != "svsm" || ev.service_guid != kSvsmVtpmServiceGuid ||
        ev.service_manifest_version != kSvsmVtpmManifestVersion) {
        return refuse("the SVSM service identity or protocol version is wrong");
    }
    const auto service = parse_snp_report(ev.svsm_report);
    if (!service) return refuse("the SVSM enrollment report is malformed");
    const auto signature = verify_snp_signature(*service, ev.vcek_der, ev.amd_chain_pem);
    if (!signature.ok) {
        return refuse("AMD signature check failed for SVSM enrollment report: " +
                      signature.failure);
    }
    if (req.require_revocation_check) {
        const auto revocation = verify_snp_revocation(ev.vcek_der, ev.amd_chain_pem,
                                                       req.revocation);
        if (!revocation.ok) {
            return refuse("AMD revocation check failed: " + revocation.failure);
        }
    }
    SnpPolicyRequirements policy = req.policy;
    policy.vmpl_policy = VmplPolicy::RequireVmpl0;
    if (const auto checked = verify_snp_policy(*service, policy); !checked.ok) {
        return refuse("platform policy check failed for SVSM enrollment report: " +
                      checked.failure);
    }
    const auto nonce = svsm_report_nonce(enrollment_challenge_digest);
    std::array<uint8_t, 64> expected_report_data{};
    if (!sha(EVP_sha512(), nonce, ev.ek_manifest, expected_report_data) ||
        service->report_data != expected_report_data) {
        return refuse("SVSM enrollment REPORT_DATA does not bind its challenge and EK manifest");
    }
    const auto ek = parse_tpmt_public_rsa(ev.ek_manifest);
    const auto ak = parse_tpmt_public_rsa(ev.ak_public);
    if (!ek || !ak || !is_svsm_vtpm_ek(*ek) || !is_nexus_quote_ak(*ak)) {
        return refuse("the enrollment EK manifest or AK has the wrong TPM object role");
    }
    identity.measurement_hex = service->measurement_hex();
    identity.chip_id_hex = service->chip_id_hex();
    identity.ek_name = ek->name;
    identity.ak_name = ak->name;
    identity.ak_spki_b64 = ak->spki_b64;
    identity.ok = true;
    return identity;
}

SvsmEvidenceVerdict verify_snp_svsm_vtpm_evidence(
    const SnpSvsmVtpmEvidence& ev, const Digest& challenge_digest,
    std::span<const uint8_t> identity_pubkey, const SvsmEvidenceRequirements& req) {
    SvsmEvidenceVerdict verdict;
    const auto fail = [&verdict](SvsmEvidenceFailure failure, std::string why) {
        return deny_svsm(std::move(verdict), failure, std::move(why));
    };
    if (ev.protocol_version != kSvsmAttestationProtocolVersion ||
        ev.service_provider != "svsm" || ev.service_guid != kSvsmVtpmServiceGuid ||
        ev.service_manifest_version != kSvsmVtpmManifestVersion) {
        return fail(SvsmEvidenceFailure::Protocol,
                    "the SVSM service identity or protocol version is wrong");
    }

    const auto service = parse_snp_report(ev.svsm_report);
    if (!service) return fail(SvsmEvidenceFailure::ServiceReportMalformed,
                              "the SVSM SNP report is malformed");
    const auto guest = parse_snp_report(ev.guest_report);
    if (!guest) return fail(SvsmEvidenceFailure::GuestReportMalformed,
                            "the guest SNP report is malformed");
    verdict.measurement_hex = service->measurement_hex();
    verdict.chip_id_hex = service->chip_id_hex();
    verdict.tcb = service->reported_tcb.to_string();
    verdict.report_summary = snp_report_summary(*service) + "; guest=" +
                             snp_report_summary(*guest);

    const auto check_signature = req.signature_verifier
        ? req.signature_verifier
        : [](const SnpReport& report, std::span<const uint8_t> vcek,
             std::string_view chain) { return verify_snp_signature(report, vcek, chain); };
    const auto service_sig = check_signature(*service, ev.vcek_der, ev.amd_chain_pem);
    if (!service_sig.ok) {
        return fail(SvsmEvidenceFailure::ServiceSignatureInvalid,
                    "AMD signature check failed for SVSM report: " + service_sig.failure);
    }
    const auto guest_sig = check_signature(*guest, ev.vcek_der, ev.amd_chain_pem);
    if (!guest_sig.ok) {
        return fail(SvsmEvidenceFailure::GuestSignatureInvalid,
                    "AMD signature check failed for guest report: " + guest_sig.failure);
    }
    verdict.snp_signature_valid = true;
    if (req.require_revocation_check) {
        const auto revocation = verify_snp_revocation(ev.vcek_der, ev.amd_chain_pem,
                                                       req.revocation);
        if (!revocation.ok) {
            return fail(SvsmEvidenceFailure::RevocationInvalid,
                        "AMD revocation check failed: " + revocation.failure);
        }
        verdict.endorsement_not_revoked = true;
    }

    if (service->vmpl != 0) return fail(SvsmEvidenceFailure::ServiceVmplInvalid,
                                        "the SVSM report is not VMPL0");
    if (req.policy.require_debug_disabled && service->policy.debug)
        return fail(SvsmEvidenceFailure::ServiceDebugEnabled,
                    "the SVSM report enables DEBUG");
    if (req.policy.require_no_migration_agent && service->policy.migrate_ma)
        return fail(SvsmEvidenceFailure::ServiceMigrationEnabled,
                    "the SVSM report enables a migration agent");
    if (!service->reported_tcb.at_least(req.policy.min_tcb))
        return fail(SvsmEvidenceFailure::ServiceTcbTooOld,
                    "the SVSM report TCB is below the release floor");
    // Empty pin is for paired signed test fixtures only; readiness() requires
    // a release measurement pin in production.
    if (!req.expected_measurement_hex.empty() &&
        !matches_hex(service->measurement, req.expected_measurement_hex))
        return fail(SvsmEvidenceFailure::ServiceMeasurementInvalid,
                    "the SVSM launch measurement is not release-approved");

    if (guest->vmpl == 0) return fail(SvsmEvidenceFailure::GuestVmplInvalid,
                                      "the guest report does not prove a VMPL0 SVSM below Linux");
    if (req.policy.require_debug_disabled && guest->policy.debug)
        return fail(SvsmEvidenceFailure::GuestDebugEnabled,
                    "the guest report enables DEBUG");
    if (req.policy.require_no_migration_agent && guest->policy.migrate_ma)
        return fail(SvsmEvidenceFailure::GuestMigrationEnabled,
                    "the guest report enables a migration agent");
    if (!guest->reported_tcb.at_least(req.policy.min_tcb))
        return fail(SvsmEvidenceFailure::GuestTcbTooOld,
                    "the guest report TCB is below the release floor");
    if (!req.expected_measurement_hex.empty() &&
        !matches_hex(guest->measurement, req.expected_measurement_hex))
        return fail(SvsmEvidenceFailure::GuestMeasurementInvalid,
                    "the guest launch measurement is not release-approved");
    if (service->chip_id != guest->chip_id)
        return fail(SvsmEvidenceFailure::PairChipMismatch,
                    "SVSM and guest reports do not name the same chip");
    if (service->measurement != guest->measurement)
        return fail(SvsmEvidenceFailure::PairMeasurementMismatch,
                    "SVSM and guest reports do not name the same launch measurement");
    verdict.snp_policy_valid = true;
    verdict.tcb_valid = service->reported_tcb.at_least(req.policy.min_tcb) &&
                        guest->reported_tcb.at_least(req.policy.min_tcb);

    const auto nonce = svsm_report_nonce(challenge_digest);
    std::array<uint8_t, 64> expected_service_data{};
    if (!sha(EVP_sha512(), nonce, ev.ek_manifest, expected_service_data) ||
        service->report_data != expected_service_data) {
        return fail(SvsmEvidenceFailure::ServiceReportDataInvalid,
                    "SVSM REPORT_DATA is not SHA-512(nonce || exact EK manifest)");
    }
    if (!std::equal(guest->report_data.begin(), guest->report_data.end(), nonce.begin())) {
        return fail(SvsmEvidenceFailure::GuestNonceInvalid,
                    "guest REPORT_DATA is not the derived challenge nonce");
    }

    const auto ek = parse_tpmt_public_rsa(ev.ek_manifest);
    const auto ak = parse_tpmt_public_rsa(ev.ak_public);
    if (!ek || !ak || !is_svsm_vtpm_ek(*ek) || !is_nexus_quote_ak(*ak)) {
        return fail(SvsmEvidenceFailure::ServiceManifestInvalid,
                    "the EK manifest or AK is not the required TPM object role");
    }
    verdict.ak_spki_b64 = ak->spki_b64;
    if (!matches_hex(ek->name, req.expected_ek_name_hex) ||
        !matches_hex(ak->name, req.expected_ak_name_hex) ||
        req.expected_ak_spki_b64.empty() || ak->spki_b64 != req.expected_ak_spki_b64) {
        return fail(!matches_hex(ek->name, req.expected_ek_name_hex)
                        ? SvsmEvidenceFailure::EkMismatch
                        : SvsmEvidenceFailure::AkMismatch,
                    "the EK or AK does not match enrollment state");
    }
    const Digest binding = ak_ek_binding_digest(ek->name, ak->name);
    if (req.expected_ak_ek_binding == Digest{} || binding != req.expected_ak_ek_binding) {
        return fail(SvsmEvidenceFailure::ActivationReceiptInvalid,
                    "the AK has no matching MakeCredential/ActivateCredential enrollment receipt");
    }
    verdict.ak_bound_to_report = true;

    const auto quote = parse_tpm_quote(ev.tpms_attest);
    if (!quote) return fail(SvsmEvidenceFailure::QuoteMalformed,
                            "the quote is not a well-formed TPM2 attestation");
    std::string quote_failure;
    if (!verify_quote_signature_rsa(ev.tpms_attest, ev.tpm_signature, ak->modulus,
                                    exponent_be(ak->exponent), &quote_failure)) {
        return fail(SvsmEvidenceFailure::QuoteSignatureInvalid,
                    "the quote is not signed by the enrolled AK: " + quote_failure);
    }

    std::vector<uint8_t> binary_measurement;
    try { binary_measurement = crypto::from_hex(ev.binary_sha256); } catch (...) {}
    if (binary_measurement.size() != 32) {
        return fail(SvsmEvidenceFailure::BinaryMeasurementInvalid,
                    "the claimed binary measurement is not SHA-256 hex");
    }
    const auto quote_binding = evidence_binding(challenge_digest, identity_pubkey,
                                                binary_measurement);
    if (quote->extra_data.size() != quote_binding.size() ||
        !std::equal(quote->extra_data.begin(), quote->extra_data.end(), quote_binding.begin())) {
        return fail(SvsmEvidenceFailure::QuoteNonceInvalid,
                    "the quote is not bound to this challenge, identity and binary measurement");
    }
    verdict.quote_bound_to_challenge = true;
    const auto quote_hash = tpmt_signature_hash_alg(ev.tpm_signature);
    if (!quote_hash || !quote_pcr_digest_matches(*quote, ev.pcr_values, *quote_hash)) {
        return fail(SvsmEvidenceFailure::QuotePcrDigestInvalid,
                    "the supplied PCR values are not the ones the quote signed");
    }
    verdict.quote_verified = true;

    if (req.expected_pcrs.empty()) {
        return fail(SvsmEvidenceFailure::BootPcrInvalid,
                    "the boot measurement has no verifier-owned PCR pins");
    }
    for (const auto& [index, expected_hex] : req.expected_pcrs) {
        const auto value = quote_pcr_value(*quote, kTpmAlgSha256, index, ev.pcr_values);
        std::vector<uint8_t> expected;
        try { expected = crypto::from_hex(expected_hex); } catch (...) {}
        if (!value || expected.size() != 32 || *value != expected) {
            return fail(SvsmEvidenceFailure::BootPcrInvalid,
                        "the boot measurement does not match PCR " + std::to_string(index));
        }
    }
    verdict.boot_state_valid = true;

    const auto log = parse_ima_binary(ev.ima_binary_log);
    if (!log || (req.ima_mode == ImaEvidenceMode::Full && log->entries.empty()))
        return fail(SvsmEvidenceFailure::ImaMalformed,
                    "the binary IMA measurement log is malformed or empty");
    if (std::any_of(log->entries.begin(), log->entries.end(),
                    [](const ImaBinaryEntry& entry) { return entry.violation; })) {
        return fail(SvsmEvidenceFailure::ImaViolation,
                    "the binary IMA log contains a violation marker");
    }
    const auto pcr10 = quote_pcr_value(*quote, kTpmAlgSha256, kImaPcr, ev.pcr_values);
    std::optional<ImaBinaryReplayState> replay;
    if (req.ima_mode == ImaEvidenceMode::Full) {
        std::array<uint8_t, 32> zero{};
        replay = replay_ima_binary_from(*log, 0, zero);
    } else {
        if (!req.checkpoint || !attestation_checkpoint_valid(*req.checkpoint))
            return fail(SvsmEvidenceFailure::ImaCheckpointInvalid,
                        "the Resume request has no valid verifier checkpoint");
        std::vector<ImaBinaryPathState> prior;
        prior.reserve(req.checkpoint->required_paths.size());
        for (const auto& path : req.checkpoint->required_paths)
            prior.push_back({path.path, path.sha256});
        replay = replay_ima_binary_from(*log, req.checkpoint->event_count,
                                        req.checkpoint->pcr10, prior);
    }
    if (!pcr10 || !replay || replay->pcr10 != *pcr10)
        return fail(SvsmEvidenceFailure::ImaPcr10Mismatch,
                    "the binary IMA material does not replay to SHA-256 PCR 10");
    verdict.ima_state = *replay;
    if (ev.binary_path != req.evidence_collector_path ||
        std::find(req.approved_paths.begin(), req.approved_paths.end(), ev.binary_path) ==
            req.approved_paths.end()) {
        return fail(SvsmEvidenceFailure::BinaryMeasurementInvalid,
                    "the evidence collector path is not approved");
    }
    const auto collector = std::find_if(replay->paths.begin(), replay->paths.end(),
                                        [&ev](const auto& p) { return p.path == ev.binary_path; });
    if (collector == replay->paths.end() || collector->sha256 != ev.binary_sha256)
        return fail(SvsmEvidenceFailure::BinaryMeasurementInvalid,
                    "the claimed binary measurement is not the kernel's last path measurement");
    verdict.binary_path = ev.binary_path;
    verdict.binary_sha256 = ev.binary_sha256;
    verdict.ima_anchored = true;
    verdict.binary_measured = true;

    if ((req.require_no_new_privs && ev.runtime_no_new_privs != "1") ||
        (req.require_seccomp && ev.runtime_seccomp_mode != "2")) {
        return fail(SvsmEvidenceFailure::RuntimeProfileInvalid,
                    "the runtime profile is wrong");
    }
    verdict.runtime_profile_valid = true;
    verdict.svsm_failure = SvsmEvidenceFailure::None;
    verdict.ok = true;
    return verdict;
}

}  // namespace nexus::security
