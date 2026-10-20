#pragma once

// Internal ESYS helpers shared by the SVSM evidence producer and AK
// enrollment. Not part of the public include tree.

#if defined(__linux__) && defined(LEMONADE_HAVE_TPM_FAPI)

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

#include <array>
#include <cstring>
#include <vector>

namespace nexus::security::detail {

struct EsysSession {
    TSS2_TCTI_CONTEXT* tcti{nullptr};
    ESYS_CONTEXT* esys{nullptr};

    explicit EsysSession(const char* tcti_config = nullptr) {
        if (Tss2_TctiLdr_Initialize(tcti_config, &tcti) != TSS2_RC_SUCCESS || !tcti) return;
        if (Esys_Initialize(&esys, tcti, nullptr) != TSS2_RC_SUCCESS || !esys) return;
        (void)Esys_Startup(esys, TPM2_SU_CLEAR);
    }
    ~EsysSession() {
        if (esys) Esys_Finalize(&esys);
        if (tcti) Tss2_TctiLdr_Finalize(&tcti);
    }
    [[nodiscard]] bool ok() const { return esys != nullptr; }
};

/// The owner-hierarchy restricted RSA-2048/SHA-256 signing AK template. The
/// producer creates the AK from it and enrollment must recreate the same
/// public area byte-for-byte, so both sides share this one builder.
inline TPM2B_PUBLIC nexus_ak_template() {
    TPM2B_PUBLIC input{};
    input.publicArea.type = TPM2_ALG_RSA;
    input.publicArea.nameAlg = TPM2_ALG_SHA256;
    input.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
        TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
        TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_RESTRICTED;
    input.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_NULL;
    input.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_RSASSA;
    input.publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg = TPM2_ALG_SHA256;
    input.publicArea.parameters.rsaDetail.keyBits = 2048;
    input.publicArea.parameters.rsaDetail.exponent = 0;
    return input;
}

inline bool marshal_public(const TPMT_PUBLIC& public_area, std::vector<uint8_t>& out) {
    std::array<uint8_t, 1024> buffer{};
    std::size_t offset = 0;
    if (Tss2_MU_TPMT_PUBLIC_Marshal(&public_area, buffer.data(), buffer.size(),
                                    &offset) != TSS2_RC_SUCCESS) {
        return false;
    }
    out.assign(buffer.begin(), buffer.begin() + static_cast<long>(offset));
    return true;
}

inline bool create_primary(ESYS_CONTEXT* esys, ESYS_TR hierarchy, TPM2B_PUBLIC input,
                           ESYS_TR& handle, std::vector<uint8_t>& public_wire) {
    // The TCG default RSA EK template uses a 256-byte all-zero unique input
    // whose LENGTH feeds the primary-key derivation, so a zero size derives a
    // different primary.  The owner-hierarchy AK template uses an empty one.
    if (hierarchy == ESYS_TR_RH_ENDORSEMENT) {
        input.publicArea.unique.rsa.size = input.publicArea.parameters.rsaDetail.keyBits / 8;
        std::memset(input.publicArea.unique.rsa.buffer, 0,
                    input.publicArea.unique.rsa.size);
    } else {
        input.publicArea.unique.rsa.size = 0;
    }
    TPM2B_SENSITIVE_CREATE sensitive{};
    TPM2B_DATA outside{};
    TPML_PCR_SELECTION creation_pcr{};
    TPM2B_PUBLIC* output = nullptr;
    TPM2B_CREATION_DATA* creation = nullptr;
    TPM2B_DIGEST* creation_hash = nullptr;
    TPMT_TK_CREATION* ticket = nullptr;
    const TSS2_RC rc = Esys_CreatePrimary(
        esys, hierarchy, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
        &sensitive, &input, &outside, &creation_pcr, &handle, &output, &creation,
        &creation_hash, &ticket);
    const bool ok = rc == TSS2_RC_SUCCESS && output &&
                    marshal_public(output->publicArea, public_wire);
    if (output) Esys_Free(output);
    if (creation) Esys_Free(creation);
    if (creation_hash) Esys_Free(creation_hash);
    if (ticket) Esys_Free(ticket);
    return ok;
}

}  // namespace nexus::security::detail

#endif  // __linux__ && LEMONADE_HAVE_TPM_FAPI
