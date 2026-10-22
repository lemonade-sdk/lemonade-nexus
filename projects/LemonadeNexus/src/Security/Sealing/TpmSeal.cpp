#include <LemonadeNexus/Security/Sealing/TpmSeal.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <sodium.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <memory>

#if defined(__linux__) && defined(LEMONADE_HAVE_TPM_FAPI)
#include "../TpmEsysDetail.hpp"

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_rc.h>
#endif

namespace nexus::security {

std::string_view tpm_seal_error_name(TpmSealError error) {
    switch (error) {
        case TpmSealError::None:           return "none";
        case TpmSealError::Unavailable:    return "unavailable";
        case TpmSealError::PolicyMismatch: return "policy_mismatch";
        case TpmSealError::Corrupt:        return "corrupt";
        case TpmSealError::TpmFailure:     return "tpm_failure";
    }
    return "unknown";
}

namespace {

void fail(TpmSealStatus& status, TpmSealError error, std::string detail) {
    status.error = error;
    status.detail = std::move(detail);
}

}  // namespace

#if defined(__linux__) && defined(LEMONADE_HAVE_TPM_FAPI)

namespace {

using detail::EsysSession;

struct EsysFree {
    void operator()(void* pointer) const {
        if (pointer) Esys_Free(pointer);
    }
};
template <typename T>
using EsysPtr = std::unique_ptr<T, EsysFree>;

/// Flushes a transient object or session when the scope ends, on every path.
class Flush {
public:
    explicit Flush(ESYS_CONTEXT* esys) : esys_(esys) {}
    ~Flush() {
        if (handle != ESYS_TR_NONE) (void)Esys_FlushContext(esys_, handle);
    }
    Flush(const Flush&) = delete;
    Flush& operator=(const Flush&) = delete;

    ESYS_TR handle{ESYS_TR_NONE};

private:
    ESYS_CONTEXT* esys_;
};

std::string rc_text(TSS2_RC rc) {
    char code[16];
    std::snprintf(code, sizeof(code), "0x%x", static_cast<unsigned>(rc));
    return std::string(Tss2_RC_Decode(rc)) + " (rc=" + code + ")";
}

/// TPM_RC_POLICY_FAIL, ignoring the session-number bits of a format-one code.
bool is_policy_failure(TSS2_RC rc) {
    if ((rc & TSS2_RC_LAYER_MASK) != TSS2_TPM_RC_LAYER || (rc & TPM2_RC_FMT1) == 0) return false;
    return (rc & 0xBFu) == (TPM2_RC_POLICY_FAIL & 0xBFu);
}

TPML_PCR_SELECTION boot_selection() {
    TPML_PCR_SELECTION selection{};
    selection.count = 1;
    selection.pcrSelections[0].hash = TPM2_ALG_SHA256;
    selection.pcrSelections[0].sizeofSelect = 3;
    for (const uint32_t pcr : kSvsmBootPcrs) {
        selection.pcrSelections[0].pcrSelect[pcr / 8] |= static_cast<uint8_t>(1u << (pcr % 8));
    }
    return selection;
}

bool read_boot_pcrs(ESYS_CONTEXT* esys, BootPcrValues& out, std::string& why) {
    TPML_PCR_SELECTION selection = boot_selection();
    UINT32 counter = 0;
    TPML_PCR_SELECTION* returned_raw = nullptr;
    TPML_DIGEST* values_raw = nullptr;
    const TSS2_RC rc = Esys_PCR_Read(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                     &selection, &counter, &returned_raw, &values_raw);
    EsysPtr<TPML_PCR_SELECTION> returned(returned_raw);
    EsysPtr<TPML_DIGEST> values(values_raw);
    if (rc != TSS2_RC_SUCCESS || !values || values->count != kSealPcrCount) {
        why = "TPM2_PCR_Read of SHA-256 PCR 8 and 9 failed" +
              (rc != TSS2_RC_SUCCESS ? ": " + rc_text(rc) : std::string{});
        return false;
    }
    for (std::size_t i = 0; i < kSealPcrCount; ++i) {
        if (values->digests[i].size != out[i].size()) {
            why = "the TPM returned a PCR value that is not SHA-256 sized";
            return false;
        }
        std::memcpy(out[i].data(), values->digests[i].buffer, out[i].size());
    }
    return true;
}

TPM2B_PUBLIC seal_parent_template() {
    TPM2B_PUBLIC input{};
    auto& area = input.publicArea;
    area.type = TPM2_ALG_ECC;
    area.nameAlg = TPM2_ALG_SHA256;
    area.objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                            TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
                            TPMA_OBJECT_NODA | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT;
    area.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
    area.parameters.eccDetail.symmetric.keyBits.aes = 128;
    area.parameters.eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;
    area.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
    area.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    area.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    // The unique field feeds the primary-key derivation, so this tag gives the
    // seal parent its own key, distinct from a default SRK and from the AK.
    area.unique.ecc.x.size = static_cast<UINT16>(kSealParentUnique.size());
    std::memcpy(area.unique.ecc.x.buffer, kSealParentUnique.data(), kSealParentUnique.size());
    area.unique.ecc.y.size = 0;
    return input;
}

bool create_seal_parent(ESYS_CONTEXT* esys, ESYS_TR& parent, std::string& why) {
    TPM2B_SENSITIVE_CREATE sensitive{};
    TPM2B_PUBLIC input = seal_parent_template();
    TPM2B_DATA outside{};
    TPML_PCR_SELECTION creation_pcr{};
    TPM2B_PUBLIC* out_public = nullptr;
    TPM2B_CREATION_DATA* creation = nullptr;
    TPM2B_DIGEST* creation_hash = nullptr;
    TPMT_TK_CREATION* ticket = nullptr;
    const TSS2_RC rc = Esys_CreatePrimary(esys, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                                          ESYS_TR_NONE, &sensitive, &input, &outside,
                                          &creation_pcr, &parent, &out_public, &creation,
                                          &creation_hash, &ticket);
    EsysPtr<TPM2B_PUBLIC> free_public(out_public);
    EsysPtr<TPM2B_CREATION_DATA> free_creation(creation);
    EsysPtr<TPM2B_DIGEST> free_hash(creation_hash);
    EsysPtr<TPMT_TK_CREATION> free_ticket(ticket);
    if (rc != TSS2_RC_SUCCESS) {
        why = "TPM2_CreatePrimary for the seal parent failed: " + rc_text(rc);
        return false;
    }
    return true;
}

/// A session salted to the seal parent, so command or response parameters
/// that carry the key are encrypted between this process and the TPM.
bool start_salted_session(ESYS_CONTEXT* esys, ESYS_TR parent, TPM2_SE type,
                          TPMA_SESSION attributes, ESYS_TR& session, std::string& why) {
    TPMT_SYM_DEF symmetric{};
    symmetric.algorithm = TPM2_ALG_AES;
    symmetric.keyBits.aes = 128;
    symmetric.mode.aes = TPM2_ALG_CFB;
    TSS2_RC rc = Esys_StartAuthSession(esys, parent, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                       ESYS_TR_NONE, nullptr, type, &symmetric, TPM2_ALG_SHA256,
                                       &session);
    if (rc != TSS2_RC_SUCCESS) {
        why = "TPM2_StartAuthSession failed: " + rc_text(rc);
        return false;
    }
    rc = Esys_TRSess_SetAttributes(esys, session, attributes, 0xFF);
    if (rc != TSS2_RC_SUCCESS) {
        why = "setting session attributes failed: " + rc_text(rc);
        return false;
    }
    return true;
}

/// No USERWITHAUTH: the user role is reachable only through the PCR policy.
/// ADMINWITHPOLICY: admin actions (ObjectChangeAuth) also need the policy.
constexpr TPMA_OBJECT kSealedObjectAttributes =
    TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_ADMINWITHPOLICY |
    TPMA_OBJECT_NODA;

TPM2B_PUBLIC sealed_object_template(const Digest& policy) {
    TPM2B_PUBLIC input{};
    auto& area = input.publicArea;
    area.type = TPM2_ALG_KEYEDHASH;
    area.nameAlg = TPM2_ALG_SHA256;
    area.objectAttributes = kSealedObjectAttributes;
    area.authPolicy.size = static_cast<UINT16>(policy.size());
    std::memcpy(area.authPolicy.buffer, policy.data(), policy.size());
    area.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_NULL;
    area.unique.keyedHash.size = 0;
    return input;
}

/// The public area must be exactly what a seal to `pcr_digest` produces.
bool public_area_matches(const TPMT_PUBLIC& area, const Digest& pcr_digest) {
    const Digest policy = boot_pcr_policy_digest(pcr_digest);
    return area.type == TPM2_ALG_KEYEDHASH && area.nameAlg == TPM2_ALG_SHA256 &&
           area.objectAttributes == kSealedObjectAttributes &&
           area.parameters.keyedHashDetail.scheme.scheme == TPM2_ALG_NULL &&
           area.authPolicy.size == policy.size() &&
           std::equal(policy.begin(), policy.end(), area.authPolicy.buffer);
}

template <typename T, typename Marshal>
bool marshal(const T& value, std::vector<uint8_t>& out, Marshal function) {
    std::vector<uint8_t> buffer(4096);
    std::size_t offset = 0;
    if (function(&value, buffer.data(), buffer.size(), &offset) != TSS2_RC_SUCCESS) return false;
    buffer.resize(offset);
    out = std::move(buffer);
    return true;
}

template <typename T, typename Unmarshal>
bool unmarshal_exact(std::span<const uint8_t> wire, T& out, Unmarshal function) {
    std::size_t offset = 0;
    return function(wire.data(), wire.size(), &offset, &out) == TSS2_RC_SUCCESS &&
           offset == wire.size();
}

}  // namespace

std::optional<SealedKey> tpm_seal_key(const std::optional<BootPcrValues>& target,
                                      TpmSealStatus& status, const char* tcti_config) {
    status = {};
    EsysSession session{tcti_config};
    if (!session.ok()) {
        fail(status, TpmSealError::Unavailable, "no TPM answers at the configured TCTI");
        return std::nullopt;
    }
    std::string why;
    BootPcrValues values{};
    if (target) {
        values = *target;
    } else if (!read_boot_pcrs(session.esys, values, why)) {
        fail(status, TpmSealError::TpmFailure, why);
        return std::nullopt;
    }

    SealedKey sealed;
    sealed.object.pcr_digest = boot_pcr_digest(values);

    Flush parent{session.esys};
    if (!create_seal_parent(session.esys, parent.handle, why)) {
        fail(status, TpmSealError::TpmFailure, why);
        return std::nullopt;
    }
    Flush encrypt{session.esys};
    if (!start_salted_session(session.esys, parent.handle, TPM2_SE_HMAC,
                              TPMA_SESSION_DECRYPT | TPMA_SESSION_CONTINUESESSION,
                              encrypt.handle, why)) {
        fail(status, TpmSealError::TpmFailure, why);
        return std::nullopt;
    }

    sealed.key = crypto::SecureBuffer(kSealKeyBytes);
    randombytes_buf(sealed.key.data(), sealed.key.size());

    TPM2B_SENSITIVE_CREATE sensitive{};
    sensitive.sensitive.data.size = static_cast<UINT16>(sealed.key.size());
    std::memcpy(sensitive.sensitive.data.buffer, sealed.key.data(), sealed.key.size());
    const TPM2B_PUBLIC input =
        sealed_object_template(boot_pcr_policy_digest(sealed.object.pcr_digest));
    TPM2B_DATA outside{};
    TPML_PCR_SELECTION creation_pcr{};
    TPM2B_PRIVATE* out_private = nullptr;
    TPM2B_PUBLIC* out_public = nullptr;
    TPM2B_CREATION_DATA* creation = nullptr;
    TPM2B_DIGEST* creation_hash = nullptr;
    TPMT_TK_CREATION* ticket = nullptr;
    const TSS2_RC rc = Esys_Create(session.esys, parent.handle, ESYS_TR_PASSWORD, encrypt.handle,
                                   ESYS_TR_NONE, &sensitive, &input, &outside, &creation_pcr,
                                   &out_private, &out_public, &creation, &creation_hash, &ticket);
    sodium_memzero(&sensitive, sizeof(sensitive));
    EsysPtr<TPM2B_PRIVATE> free_private(out_private);
    EsysPtr<TPM2B_PUBLIC> free_public(out_public);
    EsysPtr<TPM2B_CREATION_DATA> free_creation(creation);
    EsysPtr<TPM2B_DIGEST> free_hash(creation_hash);
    EsysPtr<TPMT_TK_CREATION> free_ticket(ticket);
    if (rc != TSS2_RC_SUCCESS || !out_private || !out_public) {
        fail(status, TpmSealError::TpmFailure,
             "TPM2_Create of the sealed object failed: " + rc_text(rc));
        return std::nullopt;
    }
    if (!public_area_matches(out_public->publicArea, sealed.object.pcr_digest) ||
        !marshal(*out_public, sealed.object.tpm_public, Tss2_MU_TPM2B_PUBLIC_Marshal) ||
        !marshal(*out_private, sealed.object.tpm_private, Tss2_MU_TPM2B_PRIVATE_Marshal) ||
        sealed.object.tpm_public.size() > kMaxTpmObjectBytes ||
        sealed.object.tpm_private.size() > kMaxTpmObjectBytes) {
        fail(status, TpmSealError::TpmFailure,
             "the TPM returned a sealed object that does not match the request");
        return std::nullopt;
    }
    return sealed;
}

std::optional<crypto::SecureBuffer> tpm_unseal_key(const SealedKeyObject& object,
                                                   TpmSealStatus& status,
                                                   const char* tcti_config) {
    status = {};
    TPM2B_PUBLIC in_public{};
    TPM2B_PRIVATE in_private{};
    if (object.tpm_public.size() > kMaxTpmObjectBytes ||
        object.tpm_private.size() > kMaxTpmObjectBytes ||
        !unmarshal_exact(object.tpm_public, in_public, Tss2_MU_TPM2B_PUBLIC_Unmarshal) ||
        !unmarshal_exact(object.tpm_private, in_private, Tss2_MU_TPM2B_PRIVATE_Unmarshal) ||
        !public_area_matches(in_public.publicArea, object.pcr_digest)) {
        fail(status, TpmSealError::Corrupt,
             "the sealed object does not carry the policy its PCR digest names");
        return std::nullopt;
    }

    EsysSession session{tcti_config};
    if (!session.ok()) {
        fail(status, TpmSealError::Unavailable, "no TPM answers at the configured TCTI");
        return std::nullopt;
    }
    std::string why;
    BootPcrValues current{};
    if (!read_boot_pcrs(session.esys, current, why)) {
        fail(status, TpmSealError::TpmFailure, why);
        return std::nullopt;
    }
    if (boot_pcr_digest(current) != object.pcr_digest) {
        fail(status, TpmSealError::PolicyMismatch,
             "PCR 8/9 differ from the values this object is sealed to");
        return std::nullopt;
    }

    Flush parent{session.esys};
    if (!create_seal_parent(session.esys, parent.handle, why)) {
        fail(status, TpmSealError::TpmFailure, why);
        return std::nullopt;
    }
    Flush item{session.esys};
    TSS2_RC rc = Esys_Load(session.esys, parent.handle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                           ESYS_TR_NONE, &in_private, &in_public, &item.handle);
    if (rc != TSS2_RC_SUCCESS) {
        // An integrity failure here is a damaged object, an object from another
        // TPM, or a TPM whose owner seed changed since the seal.
        fail(status, TpmSealError::Corrupt,
             "the TPM refused to load the sealed object: " + rc_text(rc));
        return std::nullopt;
    }
    Flush policy{session.esys};
    if (!start_salted_session(session.esys, parent.handle, TPM2_SE_POLICY,
                              TPMA_SESSION_ENCRYPT | TPMA_SESSION_CONTINUESESSION,
                              policy.handle, why)) {
        fail(status, TpmSealError::TpmFailure, why);
        return std::nullopt;
    }
    // An empty pcrDigest makes the TPM use its own current PCR values.
    TPM2B_DIGEST pcr_digest{};
    const TPML_PCR_SELECTION selection = boot_selection();
    rc = Esys_PolicyPCR(session.esys, policy.handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        &pcr_digest, &selection);
    if (rc != TSS2_RC_SUCCESS) {
        fail(status, TpmSealError::TpmFailure, "TPM2_PolicyPCR failed: " + rc_text(rc));
        return std::nullopt;
    }
    TPM2B_SENSITIVE_DATA* out_raw = nullptr;
    rc = Esys_Unseal(session.esys, item.handle, policy.handle, ESYS_TR_NONE, ESYS_TR_NONE,
                     &out_raw);
    EsysPtr<TPM2B_SENSITIVE_DATA> out(out_raw);
    if (rc != TSS2_RC_SUCCESS || !out) {
        if (is_policy_failure(rc)) {
            fail(status, TpmSealError::PolicyMismatch,
                 "the TPM refused the PCR policy: " + rc_text(rc));
        } else {
            fail(status, TpmSealError::TpmFailure, "TPM2_Unseal failed: " + rc_text(rc));
        }
        return std::nullopt;
    }
    const bool key_ok = out->size == kSealKeyBytes;
    crypto::SecureBuffer key(std::span<const uint8_t>(out->buffer, key_ok ? out->size : 0));
    sodium_memzero(out->buffer, sizeof(out->buffer));
    if (!key_ok) {
        fail(status, TpmSealError::Corrupt, "the sealed object holds a key of the wrong size");
        return std::nullopt;
    }
    return key;
}

#else

std::optional<SealedKey> tpm_seal_key(const std::optional<BootPcrValues>&, TpmSealStatus& status,
                                      const char*) {
    fail(status, TpmSealError::Unavailable, "sealing needs Linux and the TPM ESYS stack");
    return std::nullopt;
}

std::optional<crypto::SecureBuffer> tpm_unseal_key(const SealedKeyObject&, TpmSealStatus& status,
                                                   const char*) {
    fail(status, TpmSealError::Unavailable, "unsealing needs Linux and the TPM ESYS stack");
    return std::nullopt;
}

#endif

}  // namespace nexus::security
