// TPM 2.0 backend for TeeAttestationService.
//
//   * GENERATION (prover) uses the ESYS API and only compiles where a TPM stack
//     is linked (Linux + LEMONADE_HAVE_TPM_FAPI). The AK is a *deterministic*
//     ECC P-256 restricted primary signing key in the owner hierarchy, so its
//     public key is stable across reboots and can be pinned at enrollment.
//
//   * VERIFICATION is pure OpenSSL and compiles on EVERY platform — a macOS /
//     Tier-2 / no-TPM node can still verify a Tier-1 peer's quote. It parses the
//     raw TPMS_ATTEST + TPMT_SIGNATURE wire bytes by hand (no tss2 dependency)
//     and checks the signature against the AK pinned in the peer's certificate.
//
// See docs/TEE-Attestation-Hardening-Plan.md §§3-4.

#include <LemonadeNexus/Core/TeeAttestation.hpp>
#include <LemonadeNexus/Core/TeeAttestationTpm.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <spdlog/spdlog.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/x509.h>  // d2i_PUBKEY / i2d_PUBKEY

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#ifdef LEMONADE_HAVE_TPM_FAPI
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>
#endif

namespace nexus::core {

namespace {

namespace chrono = std::chrono;

uint64_t now_sec() {
    return static_cast<uint64_t>(chrono::duration_cast<chrono::seconds>(
        chrono::system_clock::now().time_since_epoch()).count());
}

// TPM wire constants the *verifier* needs. Defined locally so verify_tpm_report
// compiles on platforms with no tss2 headers (macOS / Tier-2 verify-only nodes).
// Values match TPM 2.0 (tss2_tpm2_types.h) — checked against the vendored 4.1.3.
constexpr uint32_t kTpmGeneratedValue = 0xff544347u;  // TPM2_GENERATED_VALUE
constexpr uint16_t kTpmStAttestQuote  = 0x8018u;      // TPM2_ST_ATTEST_QUOTE
constexpr uint16_t kTpmAlgEcdsa       = 0x0018u;      // TPM2_ALG_ECDSA
constexpr uint16_t kTpmAlgSha256      = 0x000Bu;      // TPM2_ALG_SHA256

// --- big-endian wire reader (no tss2 dependency — used on the verifier) -------
struct Reader {
    const uint8_t* p;
    size_t n;
    size_t off{0};
    [[nodiscard]] bool need(size_t k) const { return off + k <= n; }
    bool u16(uint16_t& v) {
        if (!need(2)) return false;
        v = static_cast<uint16_t>((p[off] << 8) | p[off + 1]);
        off += 2;
        return true;
    }
    bool u32(uint32_t& v) {
        if (!need(4)) return false;
        v = (uint32_t(p[off]) << 24) | (uint32_t(p[off + 1]) << 16) |
            (uint32_t(p[off + 2]) << 8) | uint32_t(p[off + 3]);
        off += 4;
        return true;
    }
    bool skip(size_t k) {
        if (!need(k)) return false;
        off += k;
        return true;
    }
    // Reads a TPM2B (uint16 size-prefixed blob), returning a view into the buffer.
    bool blob(const uint8_t*& out, uint16_t& len) {
        if (!u16(len)) return false;
        if (!need(len)) return false;
        out = p + off;
        off += len;
        return true;
    }
};

[[maybe_unused]] void put_u16(std::vector<uint8_t>& v, uint16_t x) {
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x & 0xFF));
}

// Load an EVP_PKEY (EC) from base64 DER SubjectPublicKeyInfo.
EVP_PKEY* evp_from_spki_b64(const std::string& b64) {
    if (b64.empty()) return nullptr;
    std::vector<uint8_t> der;
    try {
        der = crypto::from_base64(b64);
    } catch (...) {
        return nullptr;
    }
    if (der.empty()) return nullptr;
    const unsigned char* p = der.data();
    return d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size()));
}

// Verify an ECDSA(SHA-256) signature (raw r||s as TPM2B params) over `msg` using
// the given EC public key — exactly what a TPM Quote signature is.
bool ecdsa_sha256_verify(EVP_PKEY* pkey,
                         const uint8_t* r, size_t r_len,
                         const uint8_t* s, size_t s_len,
                         const uint8_t* msg, size_t msg_len) {
    if (!pkey || r_len == 0 || s_len == 0) return false;

    bool ok = false;
    ECDSA_SIG* sig = ECDSA_SIG_new();
    BIGNUM* bnr = BN_bin2bn(r, static_cast<int>(r_len), nullptr);
    BIGNUM* bns = BN_bin2bn(s, static_cast<int>(s_len), nullptr);
    unsigned char* der = nullptr;
    EVP_MD_CTX* ctx = nullptr;

    if (!sig || !bnr || !bns) goto done;
    if (ECDSA_SIG_set0(sig, bnr, bns) != 1) goto done;  // takes ownership of bnr/bns
    bnr = nullptr;
    bns = nullptr;

    {
        int der_len = i2d_ECDSA_SIG(sig, &der);
        if (der_len <= 0) goto done;

        ctx = EVP_MD_CTX_new();
        if (!ctx) goto done;
        if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) goto done;
        ok = (EVP_DigestVerify(ctx, der, static_cast<size_t>(der_len), msg, msg_len) == 1);
    }

done:
    if (der) OPENSSL_free(der);
    if (ctx) EVP_MD_CTX_free(ctx);
    if (bnr) BN_free(bnr);
    if (bns) BN_free(bns);
    if (sig) ECDSA_SIG_free(sig);
    return ok;
}

#ifdef LEMONADE_HAVE_TPM_FAPI

// ---------------------------------------------------------------------------
// ESYS prover helpers (Linux only)
// ---------------------------------------------------------------------------

// Template for the deterministic AK: ECC P-256, restricted signing, fixed so the
// owner-hierarchy primary regenerates the same key (and thus the same pub) every
// time — this is what makes enrollment-time pinning (Model A) work.
TPM2B_PUBLIC ak_template() {
    TPM2B_PUBLIC t{};
    t.size = 0;
    TPMT_PUBLIC& pub = t.publicArea;
    pub.type = TPM2_ALG_ECC;
    pub.nameAlg = TPM2_ALG_SHA256;
    pub.objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                           TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
                           TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT;
    pub.authPolicy.size = 0;
    pub.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
    pub.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
    pub.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
    pub.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    pub.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    pub.unique.ecc.x.size = 0;
    pub.unique.ecc.y.size = 0;
    return t;
}

// Build the base64 DER SPKI for an AK from its TPM public ECC point.
std::string ak_spki_b64(const TPM2B_PUBLIC& outPublic) {
    const TPMS_ECC_POINT& pt = outPublic.publicArea.unique.ecc;
    if (pt.x.size != 32 || pt.y.size != 32) return {};

    unsigned char raw[65];
    raw[0] = 0x04;
    std::memcpy(raw + 1, pt.x.buffer, 32);
    std::memcpy(raw + 33, pt.y.buffer, 32);

    std::string out;
    OSSL_PARAM_BLD* bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM* params = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    EVP_PKEY* pkey = nullptr;
    unsigned char* der = nullptr;

    if (!bld) goto done;
    OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0);
    OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, raw, sizeof(raw));
    params = OSSL_PARAM_BLD_to_param(bld);
    if (!params) goto done;

    ctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    if (!ctx || EVP_PKEY_fromdata_init(ctx) != 1) goto done;
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1 || !pkey) goto done;

    {
        int der_len = i2d_PUBKEY(pkey, &der);
        if (der_len > 0) {
            out = crypto::to_base64(std::span<const uint8_t>(der, static_cast<size_t>(der_len)));
        }
    }

done:
    if (der) OPENSSL_free(der);
    if (pkey) EVP_PKEY_free(pkey);
    if (ctx) EVP_PKEY_CTX_free(ctx);
    if (params) OSSL_PARAM_free(params);
    if (bld) OSSL_PARAM_BLD_free(bld);
    return out;
}

// PCR selection: SHA-256 bank, PCRs 0,1,7,23.
TPML_PCR_SELECTION pcr_selection() {
    TPML_PCR_SELECTION sel{};
    sel.count = 1;
    sel.pcrSelections[0].hash = TPM2_ALG_SHA256;
    sel.pcrSelections[0].sizeofSelect = 3;  // 24 PCRs
    auto set_bit = [&](int pcr) {
        sel.pcrSelections[0].pcrSelect[pcr / 8] |= static_cast<uint8_t>(1u << (pcr % 8));
    };
    set_bit(0);
    set_bit(1);
    set_bit(7);
    set_bit(23);
    return sel;
}

// RAII for the ESYS context + TCTI.
struct EsysSession {
    TSS2_TCTI_CONTEXT* tcti{nullptr};
    ESYS_CONTEXT* esys{nullptr};
    bool ok{false};

    EsysSession() {
        if (Tss2_TctiLdr_Initialize(nullptr, &tcti) != TSS2_RC_SUCCESS || !tcti) {
            spdlog::warn("[tpm] Tss2_TctiLdr_Initialize failed (no TCTI / TPM device?)");
            return;
        }
        if (Esys_Initialize(&esys, tcti, nullptr) != TSS2_RC_SUCCESS || !esys) {
            spdlog::warn("[tpm] Esys_Initialize failed");
            return;
        }
        // Startup is idempotent; ignore "already started" — only a hard failure matters.
        Esys_Startup(esys, TPM2_SU_CLEAR);
        ok = true;
    }
    ~EsysSession() {
        if (esys) Esys_Finalize(&esys);
        if (tcti) Tss2_TctiLdr_Finalize(&tcti);
    }
    EsysSession(const EsysSession&) = delete;
    EsysSession& operator=(const EsysSession&) = delete;
};

// Provision the deterministic AK; returns its ESYS handle (caller flushes) and
// fills `spki` with the base64 DER SPKI. Returns ESYS_TR_NONE on failure.
ESYS_TR provision_ak(ESYS_CONTEXT* esys, std::string& spki) {
    TPM2B_SENSITIVE_CREATE inSensitive{};
    TPM2B_DATA outsideInfo{};
    TPML_PCR_SELECTION creationPCR{};
    TPM2B_PUBLIC inPublic = ak_template();

    ESYS_TR ak = ESYS_TR_NONE;
    TPM2B_PUBLIC* outPublic = nullptr;
    TSS2_RC rc = Esys_CreatePrimary(
        esys, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &inSensitive, &inPublic, &outsideInfo, &creationPCR,
        &ak, &outPublic, nullptr, nullptr, nullptr);
    if (rc != TSS2_RC_SUCCESS) {
        spdlog::warn("[tpm] Esys_CreatePrimary(AK) failed: 0x{:x}", rc);
        return ESYS_TR_NONE;
    }
    spki = ak_spki_b64(*outPublic);
    Esys_Free(outPublic);
    return ak;
}

#endif // LEMONADE_HAVE_TPM_FAPI

} // namespace

// ===========================================================================
// Generation (prover) — TeePlatform::Tpm2
// ===========================================================================

TeeAttestationReport TeeAttestationService::generate_tpm_report(
    const std::array<uint8_t, 32>& nonce) {

    TeeAttestationReport report;
    report.platform = TeePlatform::Tpm2;
    report.nonce = nonce;
    report.timestamp = now_sec();
    report.binary_hash = binary_attestation_.self_hash();

#ifdef LEMONADE_HAVE_TPM_FAPI
    // qualifyingData = SHA256(nonce ‖ server_pubkey ‖ binary_hash). The hardware
    // signature over the quote therefore covers the challenge, our identity, and
    // the running binary simultaneously.
    std::vector<uint8_t> qd_input(nonce.begin(), nonce.end());
    if (!identity_pubkey_b64_.empty()) {
        try {
            auto pk = crypto::from_base64(identity_pubkey_b64_);
            qd_input.insert(qd_input.end(), pk.begin(), pk.end());
        } catch (...) {}
    }
    std::vector<uint8_t> bin_meas;
    if (!report.binary_hash.empty()) {
        try {
            bin_meas = crypto::from_hex(report.binary_hash);
        } catch (...) {}
    }
    qd_input.insert(qd_input.end(), bin_meas.begin(), bin_meas.end());
    auto qd = crypto_.sha256(qd_input);  // std::array<uint8_t,32>

    EsysSession sess;
    if (!sess.ok) return report;  // platform=Tpm2 but no evidence → verifier rejects

    std::string ak_spki;
    ESYS_TR ak = provision_ak(sess.esys, ak_spki);
    if (ak == ESYS_TR_NONE) return report;
    report.ak_pubkey = ak_spki;  // hint only; the verifier uses the cert-pinned AK

    // Reflect the binary measurement into application PCR 23 (reset then extend so
    // it is measured, not merely self-declared). Reset may be denied by locality
    // policy — best-effort; the cryptographic binding is via qualifyingData.
    if (bin_meas.size() == 32) {
        Esys_PCR_Reset(sess.esys, ESYS_TR_PCR23, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
        TPML_DIGEST_VALUES digests{};
        digests.count = 1;
        digests.digests[0].hashAlg = TPM2_ALG_SHA256;
        std::memcpy(digests.digests[0].digest.sha256, bin_meas.data(), 32);
        Esys_PCR_Extend(sess.esys, ESYS_TR_PCR23, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                        ESYS_TR_NONE, &digests);
    }

    // Quote.
    TPM2B_DATA qualifying{};
    qualifying.size = 32;
    std::memcpy(qualifying.buffer, qd.data(), 32);
    TPMT_SIG_SCHEME scheme{};
    scheme.scheme = TPM2_ALG_NULL;  // use the AK's own scheme (ECDSA-SHA256)
    TPML_PCR_SELECTION pcrSel = pcr_selection();

    TPM2B_ATTEST* quoted = nullptr;
    TPMT_SIGNATURE* sig = nullptr;
    TSS2_RC rc = Esys_Quote(sess.esys, ak, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &qualifying, &scheme, &pcrSel, &quoted, &sig);
    if (rc == TSS2_RC_SUCCESS && quoted && sig) {
        report.tpms_attest.assign(quoted->attestationData,
                                  quoted->attestationData + quoted->size);

        // Serialize the ECDSA signature in TPMT_SIGNATURE wire form so the OpenSSL
        // verifier can parse it without any tss2 dependency.
        const TPMS_SIGNATURE_ECDSA& e = sig->signature.ecdsa;
        put_u16(report.tpm_signature, sig->sigAlg);
        put_u16(report.tpm_signature, e.hash);
        put_u16(report.tpm_signature, e.signatureR.size);
        report.tpm_signature.insert(report.tpm_signature.end(),
                                    e.signatureR.buffer, e.signatureR.buffer + e.signatureR.size);
        put_u16(report.tpm_signature, e.signatureS.size);
        report.tpm_signature.insert(report.tpm_signature.end(),
                                    e.signatureS.buffer, e.signatureS.buffer + e.signatureS.size);
        spdlog::debug("[tpm] quote generated ({} attest bytes, {} sig bytes)",
                      report.tpms_attest.size(), report.tpm_signature.size());
    } else {
        spdlog::warn("[tpm] Esys_Quote failed: 0x{:x}", rc);
    }
    if (quoted) Esys_Free(quoted);
    if (sig) Esys_Free(sig);

    // Read the selected PCRs so a verifier can recompute the quote's pcrDigest.
    {
        TPML_PCR_SELECTION pcrIn = pcr_selection();
        UINT32 updateCounter = 0;
        TPML_PCR_SELECTION* pcrOut = nullptr;
        TPML_DIGEST* pcrVals = nullptr;
        if (Esys_PCR_Read(sess.esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                          &pcrIn, &updateCounter, &pcrOut, &pcrVals) == TSS2_RC_SUCCESS &&
            pcrVals) {
            for (UINT32 i = 0; i < pcrVals->count; ++i) {
                report.pcr_values.insert(report.pcr_values.end(),
                                         pcrVals->digests[i].buffer,
                                         pcrVals->digests[i].buffer + pcrVals->digests[i].size);
            }
        }
        if (pcrOut) Esys_Free(pcrOut);
        if (pcrVals) Esys_Free(pcrVals);
    }

    Esys_FlushContext(sess.esys, ak);
#else
    spdlog::warn("[{}] TPM report requested but no TPM stack is linked on this build", name());
#endif

    return report;
}

// ===========================================================================
// Verification — pure OpenSSL, runs on every platform
// ===========================================================================

bool TeeAttestationService::verify_tpm_report(
    const TeeAttestationReport& report,
    const std::array<uint8_t, 32>& expected_nonce,
    const std::string& trusted_ak_pubkey) const {

    if (trusted_ak_pubkey.empty()) {
        spdlog::warn("[{}] TPM verify: no cert-pinned AK supplied — refusing (the report's "
                      "own ak_pubkey is never trusted)", name());
        return false;
    }
    if (report.tpms_attest.empty() || report.tpm_signature.empty()) {
        spdlog::warn("[{}] TPM verify: missing tpms_attest or tpm_signature", name());
        return false;
    }

    // 1. Recompute the qualifyingData this quote MUST be bound to.
    std::vector<uint8_t> qd_input(expected_nonce.begin(), expected_nonce.end());
    if (!report.server_pubkey.empty()) {
        try {
            auto pk = crypto::from_base64(report.server_pubkey);
            qd_input.insert(qd_input.end(), pk.begin(), pk.end());
        } catch (...) {
            return false;
        }
    }
    if (!report.binary_hash.empty()) {
        try {
            auto bin = crypto::from_hex(report.binary_hash);
            qd_input.insert(qd_input.end(), bin.begin(), bin.end());
        } catch (...) {
            return false;
        }
    }
    auto qd = crypto_.sha256(qd_input);

    // 2. Parse TPMS_ATTEST and enforce magic / type / extraData == qualifyingData.
    //    This is the anti-injection core: the binding is checked against the bytes
    //    the TPM hardware actually signed, not against attacker-supplied siblings.
    Reader ar{report.tpms_attest.data(), report.tpms_attest.size()};
    uint32_t magic = 0;
    uint16_t type = 0;
    if (!ar.u32(magic) || magic != kTpmGeneratedValue) {
        spdlog::warn("[{}] TPM verify: bad TPMS_ATTEST magic", name());
        return false;
    }
    if (!ar.u16(type) || type != kTpmStAttestQuote) {
        spdlog::warn("[{}] TPM verify: TPMS_ATTEST is not a quote (type=0x{:x})", name(), type);
        return false;
    }
    const uint8_t* qsigner = nullptr;
    uint16_t qsigner_len = 0;
    if (!ar.blob(qsigner, qsigner_len)) {  // qualifiedSigner (TPM2B_NAME)
        spdlog::warn("[{}] TPM verify: truncated qualifiedSigner", name());
        return false;
    }
    const uint8_t* extra = nullptr;
    uint16_t extra_len = 0;
    if (!ar.blob(extra, extra_len)) {  // extraData (TPM2B_DATA) — our qualifyingData
        spdlog::warn("[{}] TPM verify: truncated extraData", name());
        return false;
    }
    if (extra_len != qd.size() || std::memcmp(extra, qd.data(), qd.size()) != 0) {
        spdlog::warn("[{}] TPM verify: extraData != qualifyingData (nonce/identity/binary "
                      "binding failed)", name());
        return false;
    }

    // 3. Verify the hardware signature over the WHOLE TPMS_ATTEST using the
    //    CERT-PINNED AK. Parse the TPMT_SIGNATURE wire bytes (sigAlg, hash, r, s).
    Reader sr{report.tpm_signature.data(), report.tpm_signature.size()};
    uint16_t sigAlg = 0, hashAlg = 0;
    const uint8_t* r = nullptr;
    const uint8_t* s = nullptr;
    uint16_t r_len = 0, s_len = 0;
    if (!sr.u16(sigAlg) || !sr.u16(hashAlg) || !sr.blob(r, r_len) || !sr.blob(s, s_len)) {
        spdlog::warn("[{}] TPM verify: malformed TPMT_SIGNATURE", name());
        return false;
    }
    if (sigAlg != kTpmAlgEcdsa || hashAlg != kTpmAlgSha256) {
        spdlog::warn("[{}] TPM verify: unsupported signature scheme (alg=0x{:x} hash=0x{:x})",
                      name(), sigAlg, hashAlg);
        return false;
    }

    EVP_PKEY* ak = evp_from_spki_b64(trusted_ak_pubkey);
    if (!ak) {
        spdlog::warn("[{}] TPM verify: cert-pinned AK pubkey did not parse", name());
        return false;
    }
    bool sig_ok = ecdsa_sha256_verify(ak, r, r_len, s, s_len,
                                      report.tpms_attest.data(), report.tpms_attest.size());
    EVP_PKEY_free(ak);
    if (!sig_ok) {
        spdlog::warn("[{}] TPM verify: quote signature does not verify against the pinned AK",
                      name());
        return false;
    }

    // 4. Bind the reported PCR values to the signed quote: pcrDigest inside the
    //    quote MUST equal SHA-256 of the concatenated PCR values we were given.
    //    (Which specific PCR values constitute an approved boot is a deployment
    //    policy — advisory for now; see hardening plan open question 3.)
    if (!report.pcr_values.empty()) {
        // Walk past clockInfo (17) + firmwareVersion (8) to TPMS_QUOTE_INFO.
        if (ar.skip(17 + 8)) {
            uint32_t sel_count = 0;
            bool parsed = ar.u32(sel_count);
            for (uint32_t i = 0; parsed && i < sel_count; ++i) {
                uint16_t hash = 0;
                if (!ar.u16(hash) || !ar.need(1)) { parsed = false; break; }
                uint8_t sz = ar.p[ar.off];
                ar.off += 1;
                if (!ar.skip(sz)) { parsed = false; break; }
            }
            const uint8_t* pcrdig = nullptr;
            uint16_t pcrdig_len = 0;
            if (parsed && ar.blob(pcrdig, pcrdig_len)) {
                auto recomputed = crypto_.sha256(report.pcr_values);
                if (pcrdig_len != recomputed.size() ||
                    std::memcmp(pcrdig, recomputed.data(), recomputed.size()) != 0) {
                    spdlog::warn("[{}] TPM verify: pcrDigest does not match supplied PCR values",
                                  name());
                    return false;
                }
            }
        }
    }

    // 5. The running binary must be an approved release — UNCONDITIONAL.
    if (!binary_attestation_.is_approved_binary(report.binary_hash)) {
        spdlog::warn("[{}] TPM verify: binary hash not in approved manifests", name());
        return false;
    }

    spdlog::debug("[{}] TPM report verified against cert-pinned AK", name());
    return true;
}

} // namespace nexus::core

// ===========================================================================
// Enrollment helpers (free functions) — Linux + LEMONADE_HAVE_TPM_FAPI only
// ===========================================================================

namespace nexus::core::tpm {

#ifdef LEMONADE_HAVE_TPM_FAPI

bool tpm_available() {
    EsysSession sess;
    return sess.ok;
}

std::optional<std::string> export_ak_pubkey_b64() {
    EsysSession sess;
    if (!sess.ok) return std::nullopt;
    std::string spki;
    ESYS_TR ak = provision_ak(sess.esys, spki);
    if (ak == ESYS_TR_NONE) return std::nullopt;
    Esys_FlushContext(sess.esys, ak);
    if (spki.empty()) return std::nullopt;
    return spki;
}

#else  // no TPM stack on this build (macOS / Windows)

bool tpm_available() { return false; }
std::optional<std::string> export_ak_pubkey_b64() { return std::nullopt; }

#endif

} // namespace nexus::core::tpm
