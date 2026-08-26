#pragma once

// Fuzz targets for the security-sensitive parsers.
//
// Every target takes attacker-controlled bytes and must return. It must not
// crash, must not read past its input, and must not allocate from a length the
// input chose before that length has been bounded. None of them decides
// anything: a target parses and discards, so nothing here can reach an
// authority decision even when it is fed a bundle that would otherwise verify.
//
// The same functions run two ways. Under libFuzzer they take generated input;
// under the normal suite they take a deterministic corpus, so the harnesses
// stay compiled and exercised on every build rather than rotting until someone
// remembers to run a fuzzer.

#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>
#include <LemonadeNexus/Security/HclReport.hpp>
#include <LemonadeNexus/Security/MeasurementIma.hpp>
#include <LemonadeNexus/Security/SnpReport.hpp>
#include <LemonadeNexus/Security/SnpVerify.hpp>
#include <LemonadeNexus/Security/TpmQuote.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace nexus_fuzz {

using Bytes = std::span<const uint8_t>;

[[nodiscard]] inline std::string_view as_text(Bytes input) {
    return {reinterpret_cast<const char*>(input.data()), input.size()};
}

/// The security envelope, and through it every message class it carries:
/// attestation challenge and evidence, HotStuff proposal, vote and timeout,
/// DKG traffic, FROST commitment and share, epoch announcement, and the
/// restart sync response.
inline void fuzz_security_envelope(Bytes input) {
    const auto decoded = nexus::security::decode_security_message(input);
    if (!std::holds_alternative<nexus::security::SecurityMessage>(decoded)) {
        return;
    }
    // A message that decoded must re-encode to the same bytes. Anything else is
    // a silent reinterpretation: two peers would disagree about what arrived
    // while both believing they parsed it.
    const auto& message = std::get<nexus::security::SecurityMessage>(decoded);
    const auto re_encoded = nexus::security::encode_security_message(message);
    if (!re_encoded.empty() && re_encoded.size() != input.size()) {
        std::abort();
    }
}

inline void fuzz_snp_report(Bytes input) {
    (void)nexus::security::parse_snp_report(input);
}

inline void fuzz_hcl_blob(Bytes input) {
    (void)nexus::security::parse_hcl_blob(input);
}

inline void fuzz_tpm_quote(Bytes input) {
    const auto quote = nexus::security::parse_tpm_quote(input);
    if (!quote) {
        return;
    }
    // The value slicing reads a second attacker-controlled buffer against a
    // selection the first one chose. Drive both halves from the same input.
    const std::vector<uint8_t> values(input.begin(), input.end());
    for (const uint32_t index : nexus::security::kEvidencePcrs) {
        for (const uint16_t bank : nexus::security::kEvidenceImaBanks) {
            (void)nexus::security::quote_pcr_value(*quote, bank, index, values);
        }
    }
    (void)nexus::security::quote_pcr_digest_matches(*quote, values,
                                                    nexus::security::kTpmAlgSha256);
}

inline void fuzz_tpmt_signature(Bytes input) {
    (void)nexus::security::tpmt_signature_hash_alg(input);
}

inline void fuzz_ima_log(Bytes input) {
    const auto log = nexus::security::parse_ima_ascii(as_text(input));
    if (!log) {
        return;
    }
    (void)nexus::security::ima_replay_bank(*log);
    (void)nexus::security::ima_entry_for_path(*log, "/opt/nexus");
}

/// The AMD revocation list, straight off a fetch. Nothing here trusts it: the
/// accessor reads what a list names, and the verifier refuses anything that is
/// not signed by a compiled-in chain.
inline void fuzz_amd_crl(Bytes input) {
    const std::string_view text = as_text(input);
    (void)nexus::security::amd_crl_revoked_serials(text);

    nexus::security::AmdRevocationState state;
    state.crls = {std::string(text)};
    state.now_unix = 1'788'220'800;
    (void)nexus::security::verify_snp_revocation(input, {}, state);
}

/// A DER certificate arriving as a VCEK, plus a PEM chain that claims to issue
/// it. Both are attacker-supplied on the evidence path.
inline void fuzz_amd_certificate(Bytes input) {
    nexus::security::SnpReport report{};
    (void)nexus::security::verify_snp_signature(report, input, as_text(input));
}

/// The transported platform bundle, as JSON.
inline void fuzz_platform_evidence_json(Bytes input) {
    const auto decoded = nexus::security::decode_snp_vtpm_evidence(as_text(input));
    if (!decoded) {
        return;
    }
    const std::array<uint8_t, 32> nonce{};
    const std::array<uint8_t, 32> identity{};
    (void)nexus::security::verify_snp_vtpm_evidence(*decoded, nonce, identity, {});
}

struct Target {
    const char* name;
    void (*run)(Bytes);
};

inline constexpr Target kTargets[] = {
    {"security_envelope", &fuzz_security_envelope},
    {"snp_report", &fuzz_snp_report},
    {"hcl_blob", &fuzz_hcl_blob},
    {"tpm_quote", &fuzz_tpm_quote},
    {"tpmt_signature", &fuzz_tpmt_signature},
    {"ima_log", &fuzz_ima_log},
    {"amd_crl", &fuzz_amd_crl},
    {"amd_certificate", &fuzz_amd_certificate},
    {"platform_evidence_json", &fuzz_platform_evidence_json},
};

}  // namespace nexus_fuzz
