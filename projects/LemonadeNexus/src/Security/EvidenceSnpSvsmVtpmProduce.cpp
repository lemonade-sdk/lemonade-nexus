#include <LemonadeNexus/Security/EvidenceSnpSvsmVtpm.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/EvidenceBinding.hpp>
#include <LemonadeNexus/Security/MeasurementIma.hpp>
#include <LemonadeNexus/Security/PlatformProbe.hpp>
#include <LemonadeNexus/Security/TpmQuote.hpp>

#include "AttestationDetail.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <fstream>
#include <iterator>

#if defined(__linux__) && defined(LEMONADE_HAVE_TPM_FAPI)
#include "TpmEsysDetail.hpp"

#include <fcntl.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>
#endif

namespace nexus::security {

namespace {

using detail::set_failure;

}  // namespace

#if defined(__linux__) && defined(LEMONADE_HAVE_TPM_FAPI)

namespace {

std::vector<uint8_t> read_dynamic_file(const std::filesystem::path& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return {};
    std::vector<uint8_t> out;
    std::array<uint8_t, 4096> chunk{};
    for (;;) {
        const ssize_t got = ::read(fd, chunk.data(), chunk.size());
        if (got < 0) {
            out.clear();
            break;
        }
        if (got == 0) break;
        out.insert(out.end(), chunk.begin(), chunk.begin() + got);
    }
    ::close(fd);
    return out;
}

bool write_dynamic_file(const std::filesystem::path& path, std::span<const uint8_t> bytes) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
    if (fd < 0) return false;
    std::size_t at = 0;
    while (at != bytes.size()) {
        const ssize_t wrote = ::write(fd, bytes.data() + at, bytes.size() - at);
        if (wrote <= 0) {
            ::close(fd);
            return false;
        }
        at += static_cast<std::size_t>(wrote);
    }
    return ::close(fd) == 0;
}

using detail::EsysSession;
using detail::create_primary;
using detail::nexus_ak_template;

TPML_PCR_SELECTION svsm_pcr_selection() {
    TPML_PCR_SELECTION selection{};
    selection.count = 1;
    selection.pcrSelections[0].hash = TPM2_ALG_SHA256;
    selection.pcrSelections[0].sizeofSelect = 3;
    for (uint32_t pcr : kSvsmEvidencePcrs) {
        selection.pcrSelections[0].pcrSelect[pcr / 8] |=
            static_cast<uint8_t>(1u << (pcr % 8));
    }
    return selection;
}

bool serialize_signature(const TPMT_SIGNATURE& signature, std::vector<uint8_t>& out) {
    const TPMS_SIGNATURE_RSA* rsa = nullptr;
    if (signature.sigAlg == TPM2_ALG_RSASSA) rsa = &signature.signature.rsassa;
    if (signature.sigAlg == TPM2_ALG_RSAPSS) rsa = &signature.signature.rsapss;
    if (!rsa) return false;
    auto put_u16 = [&out](uint16_t value) {
        out.push_back(static_cast<uint8_t>(value >> 8));
        out.push_back(static_cast<uint8_t>(value));
    };
    put_u16(signature.sigAlg);
    put_u16(rsa->hash);
    put_u16(rsa->sig.size);
    out.insert(out.end(), rsa->sig.buffer, rsa->sig.buffer + rsa->sig.size);
    return true;
}

bool read_pcr_values(ESYS_CONTEXT* esys, std::vector<uint8_t>& out) {
    TPML_PCR_SELECTION selection = svsm_pcr_selection();
    UINT32 counter = 0;
    TPML_PCR_SELECTION* returned = nullptr;
    TPML_DIGEST* values = nullptr;
    const TSS2_RC rc = Esys_PCR_Read(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                     &selection, &counter, &returned, &values);
    if (rc != TSS2_RC_SUCCESS || !returned || !values || returned->count != 1 ||
        values->count != std::size(kSvsmEvidencePcrs)) {
        if (returned) Esys_Free(returned);
        if (values) Esys_Free(values);
        return false;
    }
    out.clear();
    for (UINT32 i = 0; i < values->count; ++i) {
        if (values->digests[i].size != 32) {
            Esys_Free(returned);
            Esys_Free(values);
            out.clear();
            return false;
        }
        out.insert(out.end(), values->digests[i].buffer,
                   values->digests[i].buffer + values->digests[i].size);
    }
    Esys_Free(returned);
    Esys_Free(values);
    return true;
}

bool quote_once(ESYS_CONTEXT* esys, ESYS_TR ak, std::span<const uint8_t> binding,
                std::vector<uint8_t>& attest, std::vector<uint8_t>& signature,
                std::vector<uint8_t>& pcr_values) {
    TPM2B_DATA qualifying{};
    if (binding.size() > sizeof(qualifying.buffer)) return false;
    qualifying.size = static_cast<UINT16>(binding.size());
    std::memcpy(qualifying.buffer, binding.data(), binding.size());
    TPMT_SIG_SCHEME scheme{};
    scheme.scheme = TPM2_ALG_RSASSA;
    scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;
    const TPML_PCR_SELECTION selection = svsm_pcr_selection();
    TPM2B_ATTEST* quoted = nullptr;
    TPMT_SIGNATURE* signed_quote = nullptr;
    const TSS2_RC rc = Esys_Quote(esys, ak, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                  &qualifying, &scheme, &selection, &quoted, &signed_quote);
    if (rc != TSS2_RC_SUCCESS || !quoted || !signed_quote) {
        if (quoted) Esys_Free(quoted);
        if (signed_quote) Esys_Free(signed_quote);
        return false;
    }
    attest.assign(quoted->attestationData,
                  quoted->attestationData + quoted->size);
    signature.clear();
    const bool signature_ok = serialize_signature(*signed_quote, signature);
    Esys_Free(quoted);
    Esys_Free(signed_quote);
    if (!signature_ok || !read_pcr_values(esys, pcr_values)) return false;
    const auto parsed = parse_tpm_quote(attest);
    const auto hash = tpmt_signature_hash_alg(signature);
    return parsed && hash && quote_pcr_digest_matches(*parsed, pcr_values, *hash);
}

void collect_runtime_state(SnpSvsmVtpmEvidence& evidence) {
    const int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    if (nnp >= 0) evidence.runtime_no_new_privs = nnp ? "1" : "0";
    std::ifstream status("/proc/self/status");
    const std::string text{std::istreambuf_iterator<char>(status),
                           std::istreambuf_iterator<char>()};
    const auto at = text.find("Seccomp:");
    if (at != std::string::npos) {
        const auto first = text.find_first_of("0123456789", at + 8);
        const auto last = text.find_first_not_of("0123456789", first);
        if (first != std::string::npos) evidence.runtime_seccomp_mode = text.substr(first, last - first);
    }
}

}  // namespace

std::optional<SnpSvsmVtpmEvidence> produce_snp_svsm_vtpm_evidence(
    const SnpSvsmEvidenceProduceConfig& config, const Digest& challenge_digest,
    std::string* failure) {
    SnpSvsmVtpmEvidence evidence;
    const auto nonce = svsm_report_nonce(challenge_digest);
    const auto service_inblob = config.service_report_object / "inblob";
    const auto guest_inblob = config.guest_report_object / "inblob";
    if (!write_dynamic_file(service_inblob, nonce) || !write_dynamic_file(guest_inblob, nonce)) {
        set_failure(failure, "dedicated TSM report objects are absent or not writable");
        return std::nullopt;
    }
    evidence.svsm_report = read_dynamic_file(config.service_report_object / "outblob");
    evidence.ek_manifest = read_dynamic_file(config.service_report_object / "manifestblob");
    evidence.certificate_blob = read_dynamic_file(config.service_report_object / "auxblob");
    evidence.guest_report = read_dynamic_file(config.guest_report_object / "outblob");
    if (evidence.svsm_report.empty() || evidence.ek_manifest.empty() ||
        evidence.guest_report.empty()) {
        set_failure(failure, "the TSM interface returned an incomplete SVSM/guest evidence pair");
        return std::nullopt;
    }
    const auto report = parse_snp_report(evidence.svsm_report);
    if (!report) {
        set_failure(failure, "the TSM SVSM report is malformed");
        return std::nullopt;
    }
    const auto endorsement = discover_amd_endorsement(config.cache_dir, *report,
                                                       config.allow_network);
    if (endorsement.empty()) {
        set_failure(failure, "no AMD endorsement verifies the SVSM report");
        return std::nullopt;
    }
    evidence.vcek_der = endorsement.vcek_der;
    // amd_chain_pem stays empty: an empty chain selects the compiled-in
    // ASK/ARK (SnpVerify.hpp).

    evidence.binary_path = running_executable_path();
    const auto before = read_ima_binary_log();
    const auto parsed_before = parse_ima_binary(before);
    const auto measured = parsed_before ? ima_binary_entry_for_path(*parsed_before,
                                                                    evidence.binary_path)
                                        : std::nullopt;
    if (!measured || measured->violation || measured->file_hash_algo != "sha256") {
        evidence.ima_unavailable = "binary IMA carries no clean SHA-256 measurement of '" +
                                   evidence.binary_path + "'";
        set_failure(failure, evidence.ima_unavailable);
        return std::nullopt;
    }
    evidence.binary_sha256 = measured->file_hash_hex;
    std::vector<uint8_t> binary_digest;
    try { binary_digest = crypto::from_hex(evidence.binary_sha256); } catch (...) {}
    if (binary_digest.size() != 32) {
        set_failure(failure, "the IMA binary digest is not SHA-256");
        return std::nullopt;
    }

    EsysSession session;
    ESYS_TR ak = ESYS_TR_NONE;
    if (!session.ok() || !create_primary(session.esys, ESYS_TR_RH_OWNER,
                                         nexus_ak_template(), ak, evidence.ak_public)) {
        set_failure(failure, "the protected vTPM could not create its deterministic primary AK");
        return std::nullopt;
    }
    const auto binding = evidence_binding(challenge_digest, config.identity_pubkey,
                                          binary_digest);
    bool quoted = false;
    for (unsigned attempt = 0; attempt != 3 && !quoted; ++attempt) {
        quoted = quote_once(session.esys, ak, binding, evidence.tpms_attest,
                            evidence.tpm_signature, evidence.pcr_values);
    }
    (void)Esys_FlushContext(session.esys, ak);
    if (!quoted) {
        set_failure(failure, "PCRs moved during all three quote/read attempts");
        return std::nullopt;
    }

    const auto quote = parse_tpm_quote(evidence.tpms_attest);
    const auto quoted_pcr10 = quote ? quote_pcr_value(*quote, kTpmAlgSha256, kImaPcr,
                                                       evidence.pcr_values)
                                    : std::nullopt;
    const auto after = read_ima_binary_log();
    const auto prefix = quoted_pcr10 ? ima_binary_truncate_to_pcr(
                                          after, kImaPcr, kTpmAlgSha256, *quoted_pcr10)
                                     : std::nullopt;
    if (!prefix) {
        set_failure(failure, "the binary IMA log has no unique prefix for quoted SHA-256 PCR10");
        return std::nullopt;
    }
    evidence.ima_binary_log = *prefix;
    collect_runtime_state(evidence);
    return evidence;
}

#else

std::optional<SnpSvsmVtpmEvidence> produce_snp_svsm_vtpm_evidence(
    const SnpSvsmEvidenceProduceConfig&, const Digest&, std::string* failure) {
    set_failure(failure, "SVSM evidence production needs Linux and the TPM ESYS stack");
    return std::nullopt;
}

#endif

}  // namespace nexus::security
