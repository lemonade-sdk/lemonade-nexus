#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/EvidenceBinding.hpp>
#include <LemonadeNexus/Security/HclReport.hpp>
#include <LemonadeNexus/Security/PlatformProbe.hpp>
#include <LemonadeNexus/Security/TpmQuote.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>

#if defined(__linux__) && defined(LEMONADE_HAVE_TPM_FAPI)
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#include <openssl/evp.h>
#include <sys/prctl.h>
#endif

namespace nexus::security {

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

std::string b64(std::span<const uint8_t> bytes) {
    return bytes.empty() ? std::string{} : crypto::to_base64(bytes);
}

std::vector<uint8_t> unb64(const std::string& s) {
    if (s.empty()) return {};
    try {
        return crypto::from_base64(s);
    } catch (...) {
        return {};
    }
}

EvidenceVerdict deny(EvidenceVerdict v, std::string why) {
    v.ok = false;
    v.failure = std::move(why);
    return v;
}

bool set_fail(std::string* out, std::string why) {
    if (out) *out = std::move(why);
    return false;
}

}  // namespace

// ---------------------------------------------------------------------------
// Wire form
// ---------------------------------------------------------------------------

std::string encode_snp_vtpm_evidence(const SnpVtpmEvidence& ev) {
    json j;
    j["profile"]       = "snp-vtpm";
    j["hcl_blob"]      = b64(ev.hcl_blob);
    j["vcek_der"]      = b64(ev.vcek_der);
    j["amd_chain_pem"] = ev.amd_chain_pem;
    j["tpms_attest"]   = b64(ev.tpms_attest);
    j["tpm_signature"] = b64(ev.tpm_signature);
    j["pcr_values"]    = b64(ev.pcr_values);
    j["ima_log"]       = ev.ima_log;
    j["binary_path"]   = ev.binary_path;
    j["binary_sha256"] = ev.binary_sha256;
    j["ima_unavailable"] = ev.ima_unavailable;
    j["ima_policy_sha256"]     = ev.ima_policy_sha256;
    j["runtime_no_new_privs"]  = ev.runtime_no_new_privs;
    j["runtime_seccomp_mode"]  = ev.runtime_seccomp_mode;
    return j.dump();
}

std::optional<SnpVtpmEvidence> decode_snp_vtpm_evidence(std::string_view text) {
    if (text.empty()) return std::nullopt;
    try {
        const auto j = json::parse(text);
        if (j.value("profile", "") != "snp-vtpm") return std::nullopt;

        SnpVtpmEvidence ev;
        ev.hcl_blob      = unb64(j.value("hcl_blob", ""));
        ev.vcek_der      = unb64(j.value("vcek_der", ""));
        ev.amd_chain_pem = j.value("amd_chain_pem", "");
        ev.tpms_attest   = unb64(j.value("tpms_attest", ""));
        ev.tpm_signature = unb64(j.value("tpm_signature", ""));
        ev.pcr_values    = unb64(j.value("pcr_values", ""));
        ev.ima_log       = j.value("ima_log", "");
        ev.binary_path   = j.value("binary_path", "");
        ev.binary_sha256 = j.value("binary_sha256", "");
        ev.ima_unavailable = j.value("ima_unavailable", "");
        ev.ima_policy_sha256    = j.value("ima_policy_sha256", "");
        ev.runtime_no_new_privs = j.value("runtime_no_new_privs", "");
        ev.runtime_seccomp_mode = j.value("runtime_seccomp_mode", "");
        return ev;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

// ---------------------------------------------------------------------------
// Prover — Linux + a TPM stack only
// ---------------------------------------------------------------------------

#if defined(__linux__) && defined(LEMONADE_HAVE_TPM_FAPI)

namespace {

/// securityfs and procfs report size 0, so read to EOF rather than seeking.
std::string read_text_file(const char* path) {
    std::ifstream f(path);
    if (!f) return {};
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

std::vector<uint8_t> sha256_bytes(std::span<const uint8_t> data) {
    std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
    unsigned len = 0;
    if (EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha256(), nullptr) != 1) {
        return {};
    }
    out.resize(len);
    return out;
}

/// RAII for the ESYS context + TCTI.
struct EsysSession {
    TSS2_TCTI_CONTEXT* tcti{nullptr};
    ESYS_CONTEXT*      esys{nullptr};
    bool               ok{false};

    EsysSession() {
        if (Tss2_TctiLdr_Initialize(nullptr, &tcti) != TSS2_RC_SUCCESS || !tcti) return;
        if (Esys_Initialize(&esys, tcti, nullptr) != TSS2_RC_SUCCESS || !esys) return;
        Esys_Startup(esys, TPM2_SU_CLEAR);  // idempotent
        ok = true;
    }
    ~EsysSession() {
        if (esys) Esys_Finalize(&esys);
        if (tcti) Tss2_TctiLdr_Finalize(&tcti);
    }
    EsysSession(const EsysSession&) = delete;
    EsysSession& operator=(const EsysSession&) = delete;
};

TPML_PCR_SELECTION evidence_pcr_selection() {
    TPML_PCR_SELECTION sel{};
    sel.count = 2;
    sel.pcrSelections[0].hash = TPM2_ALG_SHA256;
    sel.pcrSelections[0].sizeofSelect = 3;  // 24 PCRs
    for (uint32_t pcr : kEvidencePcrs) {
        sel.pcrSelections[0].pcrSelect[pcr / 8] |= static_cast<uint8_t>(1u << (pcr % 8));
    }
    // PCR 10 in the SHA-1 bank too — the kernel decides which bank the IMA log
    // replays against, so the prover supplies both and lets the verifier demand
    // the one that matches.
    sel.pcrSelections[1].hash = TPM2_ALG_SHA1;
    sel.pcrSelections[1].sizeofSelect = 3;
    sel.pcrSelections[1].pcrSelect[kImaPcr / 8] |= static_cast<uint8_t>(1u << (kImaPcr % 8));
    return sel;
}

/// Does this persistent object carry exactly the RSA public key AMD signed over?
bool matches_hcl_ak(const TPM2B_PUBLIC& pub, const HclAkPub& want) {
    if (pub.publicArea.type != TPM2_ALG_RSA) return false;
    const auto& n = pub.publicArea.unique.rsa;
    if (n.size != want.modulus.size()) return false;
    if (std::memcmp(n.buffer, want.modulus.data(), n.size) != 0) return false;

    // exponent 0 means the TPM default, 65537.
    uint32_t e = pub.publicArea.parameters.rsaDetail.exponent;
    if (e == 0) e = 65537;
    uint64_t want_e = 0;
    if (want.exponent.size() > 8) return false;
    for (uint8_t byte : want.exponent) want_e = (want_e << 8) | byte;
    return want_e == e;
}

/// Locate the vTPM key AMD vouched for. The conventional Azure handle is tried
/// first, then every persistent handle is checked — finding the AK by matching
/// HCLAkPub is what actually matters, the handle number is a convenience.
ESYS_TR find_hcl_ak(ESYS_CONTEXT* esys, const HclAkPub& want) {
    auto try_handle = [&](TPM2_HANDLE h) -> ESYS_TR {
        ESYS_TR tr = ESYS_TR_NONE;
        if (Esys_TR_FromTPMPublic(esys, h, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &tr) !=
            TSS2_RC_SUCCESS) {
            return ESYS_TR_NONE;
        }
        TPM2B_PUBLIC* pub = nullptr;
        const TSS2_RC rc = Esys_ReadPublic(esys, tr, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                            &pub, nullptr, nullptr);
        bool hit = false;
        if (rc == TSS2_RC_SUCCESS && pub) hit = matches_hcl_ak(*pub, want);
        if (pub) Esys_Free(pub);
        if (hit) return tr;
        Esys_TR_Close(esys, &tr);
        return ESYS_TR_NONE;
    };

    // Azure's HCL parks the AK here.
    if (ESYS_TR tr = try_handle(TPM2_PERSISTENT_FIRST + 3); tr != ESYS_TR_NONE) return tr;

    TPMI_YES_NO more = TPM2_NO;
    TPMS_CAPABILITY_DATA* cap = nullptr;
    if (Esys_GetCapability(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, TPM2_CAP_HANDLES,
                            TPM2_PERSISTENT_FIRST, TPM2_MAX_CAP_HANDLES, &more,
                            &cap) != TSS2_RC_SUCCESS || !cap) {
        if (cap) Esys_Free(cap);
        return ESYS_TR_NONE;
    }
    ESYS_TR found = ESYS_TR_NONE;
    for (UINT32 i = 0; i < cap->data.handles.count && found == ESYS_TR_NONE; ++i) {
        const TPM2_HANDLE h = cap->data.handles.handle[i];
        if (h == TPM2_PERSISTENT_FIRST + 3) continue;  // already tried
        found = try_handle(h);
    }
    Esys_Free(cap);
    return found;
}

/// Serialize a TPMT_SIGNATURE into the wire form the verifier parses:
/// u16 sigAlg, u16 hashAlg, u16 size, bytes.
bool serialize_signature(const TPMT_SIGNATURE& sig, std::vector<uint8_t>& out) {
    auto put_u16 = [&out](uint16_t v) {
        out.push_back(static_cast<uint8_t>(v >> 8));
        out.push_back(static_cast<uint8_t>(v & 0xFF));
    };
    // rsassa and rsapss are both TPMS_SIGNATURE_RSA, so the union member choice
    // below is only about naming.
    const TPMS_SIGNATURE_RSA* rsa = nullptr;
    if (sig.sigAlg == TPM2_ALG_RSASSA)      rsa = &sig.signature.rsassa;
    else if (sig.sigAlg == TPM2_ALG_RSAPSS) rsa = &sig.signature.rsapss;
    else return false;

    put_u16(sig.sigAlg);
    put_u16(rsa->hash);
    put_u16(rsa->sig.size);
    out.insert(out.end(), rsa->sig.buffer, rsa->sig.buffer + rsa->sig.size);
    return true;
}

/// Quote under `ak`. Empty-auth first; if the TPM refuses authorization, retry
/// under the standard endorsement-hierarchy policy that AK objects usually carry.
TSS2_RC quote_under_ak(ESYS_CONTEXT* esys, ESYS_TR ak, const TPM2B_DATA& qualifying,
                       const TPML_PCR_SELECTION& sel, TPM2B_ATTEST** quoted,
                       TPMT_SIGNATURE** signature) {
    TPMT_SIG_SCHEME scheme{};
    scheme.scheme = TPM2_ALG_NULL;  // use the key's own scheme

    TSS2_RC rc = Esys_Quote(esys, ak, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             &qualifying, &scheme, &sel, quoted, signature);
    if (rc == TSS2_RC_SUCCESS) return rc;

    spdlog::debug("[evidence] plain-auth quote failed (0x{:x}); retrying under an "
                  "endorsement policy session", rc);

    TPMT_SYM_DEF sym{};
    sym.algorithm = TPM2_ALG_NULL;
    ESYS_TR session = ESYS_TR_NONE;
    if (Esys_StartAuthSession(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               ESYS_TR_NONE, nullptr, TPM2_SE_POLICY, &sym, TPM2_ALG_SHA256,
                               &session) != TSS2_RC_SUCCESS) {
        return rc;
    }
    TPM2B_TIMEOUT* timeout = nullptr;
    TPMT_TK_AUTH*  ticket = nullptr;
    TSS2_RC prc = Esys_PolicySecret(esys, ESYS_TR_RH_ENDORSEMENT, session, ESYS_TR_PASSWORD,
                                     ESYS_TR_NONE, ESYS_TR_NONE, nullptr, nullptr, nullptr, 0,
                                     &timeout, &ticket);
    if (timeout) Esys_Free(timeout);
    if (ticket) Esys_Free(ticket);
    if (prc == TSS2_RC_SUCCESS) {
        rc = Esys_Quote(esys, ak, session, ESYS_TR_NONE, ESYS_TR_NONE, &qualifying, &scheme,
                         &sel, quoted, signature);
    }
    Esys_FlushContext(esys, session);
    return rc;
}

/// Read every quoted PCR, in the order the quote's selection implies.
bool read_pcr_values(ESYS_CONTEXT* esys, std::vector<uint8_t>& out) {
    // Esys_PCR_Read returns at most 8 digests per call and reports what it read,
    // so loop over the remainder rather than assuming one call covers it.
    TPML_PCR_SELECTION remaining = evidence_pcr_selection();
    for (int round = 0; round < 8; ++round) {
        bool any = false;
        for (UINT32 s = 0; s < remaining.count && !any; ++s) {
            for (uint8_t b : remaining.pcrSelections[s].pcrSelect) {
                if (b != 0) { any = true; break; }
            }
        }
        if (!any) return true;

        UINT32 counter = 0;
        TPML_PCR_SELECTION* got = nullptr;
        TPML_DIGEST* values = nullptr;
        if (Esys_PCR_Read(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &remaining, &counter,
                           &got, &values) != TSS2_RC_SUCCESS || !got || !values) {
            if (got) Esys_Free(got);
            if (values) Esys_Free(values);
            return false;
        }
        for (UINT32 i = 0; i < values->count; ++i) {
            out.insert(out.end(), values->digests[i].buffer,
                       values->digests[i].buffer + values->digests[i].size);
        }
        // Clear what was actually returned and go round again for the rest.
        for (UINT32 s = 0; s < got->count && s < remaining.count; ++s) {
            for (UINT32 b = 0; b < got->pcrSelections[s].sizeofSelect &&
                               b < remaining.pcrSelections[s].sizeofSelect; ++b) {
                remaining.pcrSelections[s].pcrSelect[b] &=
                    static_cast<uint8_t>(~got->pcrSelections[s].pcrSelect[b]);
            }
        }
        const bool progressed = values->count > 0;
        Esys_Free(got);
        Esys_Free(values);
        if (!progressed) return false;
    }
    return false;
}

}  // namespace

std::optional<SnpVtpmEvidence> produce_snp_vtpm_evidence(const EvidenceProduceConfig& cfg,
                                                          std::span<const uint8_t> nonce,
                                                          std::string* failure) {
    SnpVtpmEvidence ev;

    // 1. The AMD-signed platform blob, and the key inside it AMD vouched for.
    if (!cfg.hcl_blob_override.empty()) {
        std::ifstream f(cfg.hcl_blob_override, std::ios::binary);
        ev.hcl_blob.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
    } else {
        ev.hcl_blob = read_hcl_nv_blob();
    }
    if (ev.hcl_blob.empty()) {
        set_fail(failure, "no platform evidence source: vTPM NV index 0x01400001 is absent or "
                          "unreadable, and no /dev/sev-guest backend is implemented yet");
        return std::nullopt;
    }
    auto hcl = parse_hcl_blob(ev.hcl_blob);
    if (!hcl) {
        set_fail(failure, "the attestation blob is malformed or inconsistent");
        return std::nullopt;
    }

    // 2. The AMD certificate material a peer needs to check it.
    ev.vcek_der = fetch_vcek(cfg.cache_dir, hcl->snp, cfg.product, cfg.allow_network);
    if (ev.vcek_der.empty()) {
        set_fail(failure, "no VCEK for this chip and TCB (AMD KDS unreachable and nothing cached)");
        return std::nullopt;
    }
    // The ASK and ARK are compiled in, so they are deliberately NOT put in the
    // bundle: 4.6 KB of a 65 KB gossip budget to deliver material the verifier
    // refuses to trust from the wire anyway.
    if (pinned_amd_chain(cfg.product).empty()) {
        set_fail(failure, "no compiled-in AMD certificate chain for product '" + cfg.product + "'");
        return std::nullopt;
    }

    // 3. The kernel's measurement of the running binary — not our own hash of it.
    //
    // A missing measurement does NOT abort here. The two requirements are separate
    // — secure memory (the AMD-anchored quote) and secure binary (IMA) — and
    // collapsing them means an operator with a working platform and an
    // unconfigured IMA policy sees the same opaque failure as one with neither.
    // The evidence goes out carrying no binary hash and the VERIFIER refuses it;
    // ev.ima_unavailable says why, for diagnostics only.
    ev.ima_log     = read_ima_ascii_log();
    ev.binary_path = running_executable_path();

    // The IMA policy the kernel is enforcing. Most builds leave
    // CONFIG_IMA_READ_POLICY off, so this is usually unreadable — the field
    // then stays empty and a verifier that pins a policy digest refuses the
    // bundle. Absent evidence is failed evidence.
    if (auto policy = read_text_file("/sys/kernel/security/ima/policy"); !policy.empty()) {
        const auto digest = sha256_bytes(
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(policy.data()),
                                     policy.size()));
        if (!digest.empty()) ev.ima_policy_sha256 = crypto::to_hex(digest);
    }

    // Runtime state of this process. Self-reported: see the caveat on the
    // fields themselves.
    {
        const int nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
        if (nnp >= 0) ev.runtime_no_new_privs = nnp ? "1" : "0";

        const auto status = read_text_file("/proc/self/status");
        const auto at = status.find("Seccomp:");
        if (at != std::string::npos) {
            const auto line_end = status.find('\n', at);
            const auto value = status.substr(at + 8, line_end - at - 8);
            const auto first = value.find_first_of("0123456789");
            if (first != std::string::npos) {
                const auto last = value.find_first_not_of("0123456789", first);
                ev.runtime_seccomp_mode = value.substr(first, last - first);
            }
        }
    }
    if (ev.ima_log.empty()) {
        std::error_code ec;
        const bool present =
            fs::exists("/sys/kernel/security/ima/ascii_runtime_measurements", ec);
        ev.ima_unavailable = present
            ? "the IMA measurement log exists but could not be read — it is root-only, so this "
              "process must run as root to measure its own binary"
            : "IMA is not enabled: /sys/kernel/security/ima/ascii_runtime_measurements is "
              "absent, so the running binary has no measurement the kernel will vouch for";
    } else if (auto log = parse_ima_ascii(ev.ima_log); !log) {
        ev.ima_unavailable = "the IMA measurement log did not parse";
    } else if (auto entry = ima_entry_for_path(*log, ev.binary_path); !entry) {
        ev.ima_unavailable = "the IMA log carries no measurement of '" + ev.binary_path +
                             "' — the active policy is not measuring executables (boot the "
                             "guest with ima_policy=tcb)";
    } else if (entry->file_hash_algo != "sha256" || entry->file_hash_hex.empty()) {
        ev.ima_unavailable = "IMA measured '" + ev.binary_path + "' with '" +
                             entry->file_hash_algo + "', not sha256 (boot with ima_hash=sha256)";
    } else {
        ev.binary_sha256 = entry->file_hash_hex;
    }
    if (!ev.ima_unavailable.empty()) {
        spdlog::warn("[evidence] no binary measurement: {}", ev.ima_unavailable);
    }

    std::vector<uint8_t> measurement;
    if (!ev.binary_sha256.empty()) {
        try {
            measurement = crypto::from_hex(ev.binary_sha256);
        } catch (...) {
            set_fail(failure, "the IMA measurement for our binary is not hex");
            return std::nullopt;
        }
    }

    // 4. The hop that closes the chain: quote under HCLAkPub itself, so the
    //    signature traces back through REPORT_DATA to something AMD signed.
    EsysSession sess;
    if (!sess.ok) {
        set_fail(failure, "no usable TPM: could not bring up an ESYS context");
        return std::nullopt;
    }
    ESYS_TR ak = find_hcl_ak(sess.esys, hcl->ak);
    if (ak == ESYS_TR_NONE) {
        set_fail(failure, "the key AMD vouched for (HCLAkPub) is not present in this vTPM as a "
                          "persistent object — nothing can chain a quote to the SNP report");
        return std::nullopt;
    }

    // 32 bytes, not 64: the Azure vTPM rejects a wider qualifyingData outright
    // (TPM2_RC_SIZE), so the binding is sized to what the hardware accepts.
    const auto binding = evidence_binding(nonce, cfg.identity_pubkey, measurement);
    TPM2B_DATA qualifying{};
    static_assert(kEvidenceBindingSize <= sizeof(qualifying.buffer),
                  "the evidence binding must fit a TPM2B_DATA");
    qualifying.size = static_cast<UINT16>(kEvidenceBindingSize);
    std::memcpy(qualifying.buffer, binding.data(), kEvidenceBindingSize);

    const TPML_PCR_SELECTION sel = evidence_pcr_selection();
    TPM2B_ATTEST*   quoted = nullptr;
    TPMT_SIGNATURE* sig = nullptr;
    const TSS2_RC rc = quote_under_ak(sess.esys, ak, qualifying, sel, &quoted, &sig);

    bool ok = false;
    if (rc == TSS2_RC_SUCCESS && quoted && sig) {
        ev.tpms_attest.assign(quoted->attestationData, quoted->attestationData + quoted->size);
        ok = serialize_signature(*sig, ev.tpm_signature);
        if (!ok) {
            set_fail(failure, "the vTPM signed the quote with a scheme we cannot transport "
                              "(expected RSASSA or RSAPSS under HCLAkPub)");
        }
    } else {
        char buf[96];
        std::snprintf(buf, sizeof(buf), "TPM2_Quote under HCLAkPub failed (0x%x)",
                      static_cast<unsigned>(rc));
        set_fail(failure, buf);
    }
    if (quoted) Esys_Free(quoted);
    if (sig) Esys_Free(sig);

    if (ok && !read_pcr_values(sess.esys, ev.pcr_values)) {
        set_fail(failure, "could not read back the quoted PCR values");
        ok = false;
    }

    Esys_TR_Close(sess.esys, &ak);
    if (!ok) return std::nullopt;
    return ev;
}

#else  // no TPM stack on this build

std::optional<SnpVtpmEvidence> produce_snp_vtpm_evidence(const EvidenceProduceConfig&,
                                                          std::span<const uint8_t>,
                                                          std::string* failure) {
    set_fail(failure, "this build has no TPM stack, so it cannot produce platform evidence "
                      "(verification of a peer's evidence still works)");
    return std::nullopt;
}

#endif  // __linux__ && LEMONADE_HAVE_TPM_FAPI

// ---------------------------------------------------------------------------
// Verifier — pure OpenSSL, every platform
// ---------------------------------------------------------------------------

EvidenceVerdict verify_snp_vtpm_evidence(const SnpVtpmEvidence& ev,
                                          std::span<const uint8_t> nonce,
                                          std::span<const uint8_t> identity_pubkey,
                                          const EvidenceRequirements& req) {
    EvidenceVerdict v;

    // --- link 1: the blob parses and binds its own runtime data ---------------
    auto hcl = parse_hcl_blob(ev.hcl_blob);
    if (!hcl) return deny(std::move(v), "the attestation blob is malformed or inconsistent");

    v.measurement_hex = hcl->snp.measurement_hex();
    v.chip_id_hex     = hcl->snp.chip_id_hex();
    v.tcb             = hcl->snp.reported_tcb.to_string();
    v.report_summary  = snp_report_summary(hcl->snp);
    v.ak_spki_b64     = rsa_spki_b64(hcl->ak.modulus, hcl->ak.exponent);

    // --- link 2: AMD signed it, and the chain roots in the compiled-in ARK ----
    if (auto sig = verify_snp_signature(hcl->snp, ev.vcek_der, ev.amd_chain_pem); !sig.ok) {
        return deny(std::move(v), "AMD signature check failed: " + sig.failure);
    }
    v.snp_signature_valid = true;

    // --- revocation: AMD's signature is not enough if AMD withdrew it --------
    // Gated, because the startup self-probe and first enrollment run before any
    // CRL is cached. Tier 1 sets the flag, and then absent or expired
    // revocation data fails closed rather than being skipped.
    if (req.require_revocation_check) {
        if (auto rev = verify_snp_revocation(ev.vcek_der, ev.amd_chain_pem, req.revocation);
            !rev.ok) {
            return deny(std::move(v), "AMD revocation check failed: " + rev.failure);
        }
        v.endorsement_not_revoked = true;
    }

    // parse_hcl_blob already refused unless sha256(runtime data) equals the
    // signed REPORT_DATA, so AMD has vouched for which vTPM key belongs to this
    // launch. That is the whole vTPM binding: without it a quote proves only
    // that some TPM somewhere signed something.
    v.ak_bound_to_report = !v.ak_spki_b64.empty();

    // --- guest policy: where "pause the VM and dump memory" is ruled out ------
    SnpPolicyRequirements policy = req.policy;
    if (!req.expected_measurement_hex.empty()) {
        policy.expected_measurement_hex = req.expected_measurement_hex;
    }
    if (auto pol = verify_snp_policy(hcl->snp, policy); !pol.ok) {
        return deny(std::move(v), "platform policy check failed: " + pol.failure);
    }
    v.snp_policy_valid = true;
    v.tcb_valid = hcl->snp.reported_tcb.at_least(policy.min_tcb);

    // --- the enrolled vTPM, when one was pinned ------------------------------
    if (!req.expected_ak_spki_b64.empty()) {
        if (v.ak_spki_b64.empty() || v.ak_spki_b64 != req.expected_ak_spki_b64) {
            return deny(std::move(v), "the platform binding key does not match the one pinned "
                                       "at enrollment (different vTPM, or the AK was rotated)");
        }
    }

    // --- link 3: a quote signed by the key AMD vouched for -------------------
    auto quote = parse_tpm_quote(ev.tpms_attest);
    if (!quote) return deny(std::move(v), "the quote is not a well-formed TPM2 attestation");

    std::string why;
    if (!verify_quote_signature_rsa(ev.tpms_attest, ev.tpm_signature, hcl->ak.modulus,
                                    hcl->ak.exponent, &why)) {
        return deny(std::move(v), "the quote is not signed by HCLAkPub: " + why);
    }

    // --- link 4: the quote is about US, NOW, running THIS build --------------
    std::vector<uint8_t> measurement;
    if (!ev.binary_sha256.empty()) {
        try {
            measurement = crypto::from_hex(ev.binary_sha256);
        } catch (...) {
            return deny(std::move(v), "the claimed binary measurement is not hex");
        }
    }
    const auto expected = evidence_binding(nonce, identity_pubkey, measurement);
    if (quote->extra_data.size() != expected.size() ||
        std::memcmp(quote->extra_data.data(), expected.data(), expected.size()) != 0) {
        return deny(std::move(v), "the quote is not bound to this challenge, identity and "
                                   "binary measurement");
    }

    v.quote_bound_to_challenge = true;

    const auto hash_alg = tpmt_signature_hash_alg(ev.tpm_signature);
    if (!hash_alg) return deny(std::move(v), "the quote signature has no readable hash algorithm");
    if (!quote_pcr_digest_matches(*quote, ev.pcr_values, *hash_alg)) {
        return deny(std::move(v), "the supplied PCR values are not the ones the quote signed");
    }

    // Everything above is "secure memory": AMD vouches for this platform, its
    // policy rules out a hypervisor reading guest state, and it just answered our
    // challenge live. The binary is a separate question.
    v.quote_verified = true;

    // --- boot state: the quoted PCRs must be the pinned ones -----------------
    // The quote covers these values, so unlike the runtime fields below they are
    // hardware facts. An unpinned list checks nothing, so it leaves the link
    // false and Tier 1 eligibility fails closed on it.
    if (!req.expected_pcrs.empty()) {
        for (const auto& [index, want_hex] : req.expected_pcrs) {
            const uint16_t bank = *hash_alg;
            auto quoted = quote_pcr_value(*quote, bank, index, ev.pcr_values);
            if (!quoted) {
                return deny(std::move(v), "the boot measurement is incomplete: the quote does "
                                           "not cover PCR " + std::to_string(index));
            }
            std::vector<uint8_t> want;
            try { want = crypto::from_hex(want_hex); } catch (...) {}
            if (want.empty() || want != *quoted) {
                return deny(std::move(v), "the boot measurement does not match the approved "
                                           "value for PCR " + std::to_string(index));
            }
        }
        v.boot_state_valid = true;
    }

    // --- the binary measurement, anchored in a PCR ---------------------------
    if (req.require_ima) {
        if (ev.binary_sha256.empty()) {
            return deny(std::move(v),
                        "the platform is verified but its binary is not measured" +
                        (ev.ima_unavailable.empty() ? std::string{}
                                                    : ": " + ev.ima_unavailable));
        }
        auto log = parse_ima_ascii(ev.ima_log);
        if (!log) return deny(std::move(v), "the IMA measurement log did not parse");
        if (log->entries.empty()) {
            return deny(std::move(v), "the IMA measurement log is empty");
        }

        const uint16_t bank = ima_replay_bank(*log);
        if (bank == 0) {
            return deny(std::move(v), "the IMA log's template digest width matches no PCR bank");
        }
        v.ima_replayed_in_sha1_bank = bank == kTpmAlgSha1;

        auto quoted_pcr10 = quote_pcr_value(*quote, bank, kImaPcr, ev.pcr_values);
        if (!quoted_pcr10) {
            return deny(std::move(v), "the quote does not cover PCR 10 in the bank this IMA log "
                                       "replays into, so the log is unanchored");
        }
        const auto replayed = replay_ima_pcr(*log, kImaPcr, bank);
        if (replayed.empty() || replayed != *quoted_pcr10) {
            return deny(std::move(v), "the IMA log does not replay to the quoted PCR 10 — the "
                                       "log has been edited or truncated");
        }
        auto entry = ima_entry_for_path(*log, ev.binary_path);
        if (!entry) {
            return deny(std::move(v), "the IMA log carries no measurement of '" +
                                           ev.binary_path + "'");
        }
        if (entry->file_hash_algo != "sha256" || entry->file_hash_hex != ev.binary_sha256) {
            return deny(std::move(v), "the claimed binary measurement is not what the kernel "
                                       "recorded for that path");
        }
        v.binary_sha256 = entry->file_hash_hex;
        v.ima_anchored = true;
        v.binary_measured = true;
    } else {
        v.binary_sha256 = ev.binary_sha256;
    }

    // --- the IMA policy the kernel is enforcing ------------------------------
    // A log that replays correctly proves the entries are real. It does not
    // prove the policy measured everything it should have, which is what this
    // pins.
    if (!req.expected_ima_policy_sha256.empty()) {
        if (ev.ima_policy_sha256.empty()) {
            return deny(std::move(v), "the IMA policy digest is absent, so the measuring policy "
                                       "cannot be checked against the approved one");
        }
        if (ev.ima_policy_sha256 != req.expected_ima_policy_sha256) {
            return deny(std::move(v), "the IMA policy digest is not the approved one");
        }
    }

    // --- runtime profile -----------------------------------------------------
    // Self-reported, and only meaningful because the binary reporting it is
    // IMA-measured and on the approved list. See SnpVtpmEvidence.
    if (req.require_no_new_privs || req.require_seccomp) {
        if (req.require_no_new_privs && ev.runtime_no_new_privs != "1") {
            return deny(std::move(v), "the runtime profile is wrong: no_new_privs is not set");
        }
        if (req.require_seccomp &&
            (ev.runtime_seccomp_mode.empty() || ev.runtime_seccomp_mode == "0")) {
            return deny(std::move(v), "the runtime profile is wrong: seccomp is not active");
        }
        v.runtime_profile_valid = true;
    }

    v.ok = true;
    return v;
}

}  // namespace nexus::security
