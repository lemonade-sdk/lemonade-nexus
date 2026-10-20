#include <LemonadeNexus/Security/Attestation/SvsmAkEnrollment.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/CanonicalEncoding.hpp>

#include "../AttestationDetail.hpp"

#include <nlohmann/json.hpp>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <memory>

#if defined(__linux__) && defined(LEMONADE_HAVE_TPM_FAPI)
#include "../TpmEsysDetail.hpp"

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>
#endif

namespace nexus::security {

SvsmAkActivationExchange::SvsmAkActivationExchange(
    SvsmAkActivationChallenge challenge, SvsmAkActivationOfferMessage offer)
    : challenge_(std::move(challenge)), offer_(std::move(offer)) {}

std::optional<Digest> SvsmAkActivationExchange::complete(
    const SvsmAkActivationResponseMessage& response) {
    if (consumed_ || response.network_id != offer_.network_id ||
        response.subject_node != offer_.subject_node ||
        response.incarnation != offer_.incarnation || response.epoch != offer_.epoch ||
        response.profile_id != offer_.profile_id ||
        response.profile_ruleset != offer_.profile_ruleset ||
        response.observer != offer_.observer ||
        response.activation_context != offer_.activation.enrollment_context ||
        crypto_sign_verify_detached(response.identity_signature.data(),
                                    svsm_ak_activation_response_digest(response).data(),
                                    kDigestSize, offer_.subject_key.data()) != 0) {
        return std::nullopt;
    }
    const auto receipt = complete_svsm_ak_activation(challenge_, response.activated_secret);
    if (!receipt) return std::nullopt;
    consumed_ = true;
    return receipt;
}

namespace {

template <typename T>
using Ptr = std::unique_ptr<T, void (*)(T*)>;

void put_u16(std::vector<uint8_t>& out, std::size_t value) {
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

void put_u32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>(value >> 24));
    out.push_back(static_cast<uint8_t>(value >> 16));
    out.push_back(static_cast<uint8_t>(value >> 8));
    out.push_back(static_cast<uint8_t>(value));
}

using detail::set_failure;

std::vector<uint8_t> hmac_sha256(std::span<const uint8_t> key,
                                 std::span<const uint8_t> data) {
    std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
    unsigned size = 0;
    if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(),
              data.size(), out.data(), &size)) {
        return {};
    }
    out.resize(size);
    return out;
}

std::vector<uint8_t> kdfa_sha256(std::span<const uint8_t> key, std::string_view label,
                                 std::span<const uint8_t> context_u,
                                 std::span<const uint8_t> context_v, uint32_t bits) {
    std::vector<uint8_t> output;
    const std::size_t bytes = (bits + 7) / 8;
    for (uint32_t counter = 1; output.size() < bytes; ++counter) {
        std::vector<uint8_t> input;
        put_u32(input, counter);
        input.insert(input.end(), label.begin(), label.end());
        input.push_back(0);
        input.insert(input.end(), context_u.begin(), context_u.end());
        input.insert(input.end(), context_v.begin(), context_v.end());
        put_u32(input, bits);
        auto block = hmac_sha256(key, input);
        if (block.empty()) return {};
        output.insert(output.end(), block.begin(), block.end());
    }
    output.resize(bytes);
    if ((bits & 7u) != 0) output.front() &= static_cast<uint8_t>(0xffu >> (8u - (bits & 7u)));
    return output;
}

Ptr<EVP_PKEY> public_key(const TpmRsaPublic& ek) {
    std::vector<uint8_t> der;
    try { der = crypto::from_base64(ek.spki_b64); } catch (...) { return {nullptr, EVP_PKEY_free}; }
    const unsigned char* at = der.data();
    return {d2i_PUBKEY(nullptr, &at, static_cast<long>(der.size())), EVP_PKEY_free};
}

std::vector<uint8_t> rsa_oaep_seed(EVP_PKEY* key, std::span<const uint8_t> seed) {
    Ptr<EVP_PKEY_CTX> ctx{EVP_PKEY_CTX_new(key, nullptr), EVP_PKEY_CTX_free};
    if (!ctx || EVP_PKEY_encrypt_init(ctx.get()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_padding(ctx.get(), RSA_PKCS1_OAEP_PADDING) <= 0 ||
        EVP_PKEY_CTX_set_rsa_oaep_md(ctx.get(), EVP_sha256()) <= 0 ||
        EVP_PKEY_CTX_set_rsa_mgf1_md(ctx.get(), EVP_sha256()) <= 0) {
        return {};
    }
    static constexpr char kIdentity[] = "IDENTITY";
    auto* label = static_cast<unsigned char*>(OPENSSL_malloc(sizeof(kIdentity)));
    if (!label) return {};
    std::memcpy(label, kIdentity, sizeof(kIdentity));
    if (EVP_PKEY_CTX_set0_rsa_oaep_label(ctx.get(), label, sizeof(kIdentity)) <= 0) {
        OPENSSL_free(label);
        return {};
    }
    std::size_t size = 0;
    if (EVP_PKEY_encrypt(ctx.get(), nullptr, &size, seed.data(), seed.size()) <= 0) return {};
    std::vector<uint8_t> out(size);
    if (EVP_PKEY_encrypt(ctx.get(), out.data(), &size, seed.data(), seed.size()) <= 0) return {};
    out.resize(size);
    return out;
}

std::vector<uint8_t> aes_cfb(std::span<const uint8_t> key,
                             std::span<const uint8_t> plaintext) {
    if (key.size() != 16) return {};
    std::array<uint8_t, 16> iv{};
    Ptr<EVP_CIPHER_CTX> ctx{EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free};
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_cfb(), nullptr, key.data(),
                                  iv.data()) != 1) {
        return {};
    }
    std::vector<uint8_t> out(plaintext.size() + 16);
    int first = 0;
    int last = 0;
    if (EVP_EncryptUpdate(ctx.get(), out.data(), &first, plaintext.data(),
                          static_cast<int>(plaintext.size())) != 1 ||
        EVP_EncryptFinal_ex(ctx.get(), out.data() + first, &last) != 1) {
        return {};
    }
    out.resize(static_cast<std::size_t>(first + last));
    return out;
}

}  // namespace

Digest svsm_ak_activation_context(
    const Digest& enrollment_challenge_digest,
    const SvsmAkActivationChallenge& challenge) {
    CanonicalEncoder encoder("LEMONADE-NEXUS-SVSM-AK-ACTIVATION-CONTEXT-V1");
    encoder.add_bytes(enrollment_challenge_digest);
    encoder.add_bytes(challenge.ek_name);
    encoder.add_bytes(challenge.ak_name);
    encoder.add_bytes(challenge.credential_blob);
    encoder.add_bytes(challenge.encrypted_secret);
    return encoder.digest();
}

Digest svsm_ak_activation_offer_context(const SvsmAkActivationOfferMessage& offer) {
    CanonicalEncoder encoder("LEMONADE-NEXUS-SVSM-AK-ACTIVATION-OFFER-V1");
    encoder.add_bytes(offer.network_id);
    encoder.add_bytes(offer.subject_node.bytes);
    encoder.add_bytes(offer.subject_key);
    encoder.add_u64(offer.incarnation.underlying());
    encoder.add_u64(offer.epoch.underlying());
    encoder.add_u16(static_cast<uint16_t>(offer.profile_id));
    encoder.add_u16(offer.profile_ruleset);
    encoder.add_bytes(offer.observer.bytes);
    encoder.add_bytes(offer.enrollment_challenge_digest);
    encoder.add_bytes(offer.verifier_nonce);
    encoder.add_bytes(offer.ek_public);
    encoder.add_bytes(offer.ak_public);
    encoder.add_bytes(offer.ek_name);
    encoder.add_bytes(offer.ak_name);
    encoder.add_bytes(offer.ak_spki_digest);
    encoder.add_bytes(offer.activation.credential_blob);
    encoder.add_bytes(offer.activation.encrypted_secret);
    return encoder.digest();
}

Digest svsm_ak_activation_response_digest(
    const SvsmAkActivationResponseMessage& response) {
    CanonicalEncoder encoder("LEMONADE-NEXUS-SVSM-AK-ACTIVATION-RESPONSE-V1");
    encoder.add_bytes(response.network_id);
    encoder.add_bytes(response.subject_node.bytes);
    encoder.add_u64(response.incarnation.underlying());
    encoder.add_u64(response.epoch.underlying());
    encoder.add_u16(static_cast<uint16_t>(response.profile_id));
    encoder.add_u16(response.profile_ruleset);
    encoder.add_bytes(response.observer.bytes);
    encoder.add_bytes(response.activation_context);
    encoder.add_bytes(response.activated_secret);
    return encoder.digest();
}

SvsmAkActivationOffer svsm_ak_activation_offer(
    const Digest& enrollment_challenge_digest,
    const SvsmAkActivationChallenge& challenge) {
    SvsmAkActivationOffer offer;
    offer.enrollment_context =
        svsm_ak_activation_context(enrollment_challenge_digest, challenge);
    offer.credential_blob = challenge.credential_blob;
    offer.encrypted_secret = challenge.encrypted_secret;
    return offer;
}

namespace {

using detail::exact_keys;

std::optional<Digest> decode_context(const nlohmann::json& value) {
    if (!value.is_string()) return std::nullopt;
    try {
        const auto bytes = crypto::from_hex(value.get<std::string>());
        if (bytes.size() != kDigestSize) return std::nullopt;
        Digest digest{};
        std::copy(bytes.begin(), bytes.end(), digest.begin());
        return digest;
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::vector<uint8_t>> decode_nonempty_b64(const nlohmann::json& value,
                                                        std::size_t maximum) {
    if (!value.is_string()) return std::nullopt;
    try {
        auto decoded = crypto::from_base64(value.get<std::string>());
        if (decoded.empty() || decoded.size() > maximum) return std::nullopt;
        return decoded;
    } catch (...) {
        return std::nullopt;
    }
}

}  // namespace

std::string encode_svsm_ak_activation_offer(const SvsmAkActivationOffer& offer) {
    nlohmann::json json;
    json["version"] = offer.version;
    json["type"] = "svsm-ak-activation-offer";
    json["enrollment_context"] = crypto::to_hex(offer.enrollment_context);
    json["credential_blob"] = crypto::to_base64(offer.credential_blob);
    json["encrypted_secret"] = crypto::to_base64(offer.encrypted_secret);
    return json.dump();
}

std::optional<SvsmAkActivationOffer> decode_svsm_ak_activation_offer(
    std::string_view wire) {
    if (wire.empty() || wire.size() > kMaxSvsmAkActivationWireBytes) return std::nullopt;
    const auto json = nlohmann::json::parse(wire, nullptr, false);
    if (!exact_keys(json, {"version", "type", "enrollment_context", "credential_blob",
                           "encrypted_secret"}) ||
        !json["version"].is_number_unsigned() ||
        json["version"].get<uint32_t>() != kSvsmAkActivationWireVersion ||
        !json["type"].is_string() ||
        json["type"].get<std::string>() != "svsm-ak-activation-offer") {
        return std::nullopt;
    }
    const auto context = decode_context(json["enrollment_context"]);
    const auto credential = decode_nonempty_b64(json["credential_blob"], 4096);
    const auto secret = decode_nonempty_b64(json["encrypted_secret"], 4096);
    if (!context || !credential || !secret) return std::nullopt;
    return SvsmAkActivationOffer{kSvsmAkActivationWireVersion, *context,
                                 *credential, *secret};
}

std::string encode_svsm_ak_activation_response(
    const SvsmAkActivationResponse& response) {
    nlohmann::json json;
    json["version"] = response.version;
    json["type"] = "svsm-ak-activation-response";
    json["enrollment_context"] = crypto::to_hex(response.enrollment_context);
    json["activated_secret"] = crypto::to_base64(response.activated_secret);
    return json.dump();
}

std::optional<SvsmAkActivationResponse> decode_svsm_ak_activation_response(
    std::string_view wire) {
    if (wire.empty() || wire.size() > kMaxSvsmAkActivationWireBytes) return std::nullopt;
    const auto json = nlohmann::json::parse(wire, nullptr, false);
    if (!exact_keys(json, {"version", "type", "enrollment_context", "activated_secret"}) ||
        !json["version"].is_number_unsigned() ||
        json["version"].get<uint32_t>() != kSvsmAkActivationWireVersion ||
        !json["type"].is_string() ||
        json["type"].get<std::string>() != "svsm-ak-activation-response") {
        return std::nullopt;
    }
    const auto context = decode_context(json["enrollment_context"]);
    const auto secret = decode_nonempty_b64(json["activated_secret"], 64);
    if (!context || !secret) return std::nullopt;
    return SvsmAkActivationResponse{kSvsmAkActivationWireVersion, *context, *secret};
}

std::optional<SvsmAkActivationChallenge> make_svsm_ak_activation_challenge(
    std::span<const uint8_t> ek_tpmt_public, std::span<const uint8_t> ak_tpmt_public,
    std::string* failure) {
    const auto ek = parse_tpmt_public_rsa(ek_tpmt_public);
    const auto ak = parse_tpmt_public_rsa(ak_tpmt_public);
    if (!ek || !ak || !is_svsm_vtpm_ek(*ek) || !is_nexus_quote_ak(*ak)) {
        set_failure(failure, "EK or AK public area has the wrong TPM object role");
        return std::nullopt;
    }
    auto ek_key = public_key(*ek);
    if (!ek_key) {
        set_failure(failure, "EK public key could not be loaded");
        return std::nullopt;
    }

    std::array<uint8_t, 32> seed{};
    SvsmAkActivationChallenge challenge;
    challenge.expected_secret.resize(32);
    if (RAND_bytes(seed.data(), seed.size()) != 1 ||
        RAND_bytes(challenge.expected_secret.data(), challenge.expected_secret.size()) != 1) {
        set_failure(failure, "cryptographic random generation failed");
        return std::nullopt;
    }
    auto encrypted_seed = rsa_oaep_seed(ek_key.get(), seed);
    if (encrypted_seed.empty()) {
        set_failure(failure, "RSA-OAEP encryption under the EK failed");
        return std::nullopt;
    }

    const auto storage_key = kdfa_sha256(seed, "STORAGE", ak->name, {}, 128);
    std::vector<uint8_t> credential_2b;
    put_u16(credential_2b, challenge.expected_secret.size());
    credential_2b.insert(credential_2b.end(), challenge.expected_secret.begin(),
                         challenge.expected_secret.end());
    const auto encrypted_identity = aes_cfb(storage_key, credential_2b);
    const auto integrity_key = kdfa_sha256(seed, "INTEGRITY", {}, {}, 256);
    std::vector<uint8_t> integrity_input = encrypted_identity;
    integrity_input.insert(integrity_input.end(), ak->name.begin(), ak->name.end());
    const auto integrity = hmac_sha256(integrity_key, integrity_input);
    if (storage_key.empty() || encrypted_identity.empty() || integrity.size() != 32) {
        set_failure(failure, "TPM MakeCredential key derivation failed");
        return std::nullopt;
    }

    std::vector<uint8_t> id_object_body;
    put_u16(id_object_body, integrity.size());
    id_object_body.insert(id_object_body.end(), integrity.begin(), integrity.end());
    // TPM2B_ID_OBJECT.credential is the marshalled integrity TPM2B followed
    // directly by encIdentity.  encIdentity already encrypts the marshalled
    // TPM2B_DIGEST credential, so it has no additional size prefix here.
    id_object_body.insert(id_object_body.end(), encrypted_identity.begin(),
                          encrypted_identity.end());
    put_u16(challenge.credential_blob, id_object_body.size());
    challenge.credential_blob.insert(challenge.credential_blob.end(), id_object_body.begin(),
                                     id_object_body.end());
    put_u16(challenge.encrypted_secret, encrypted_seed.size());
    challenge.encrypted_secret.insert(challenge.encrypted_secret.end(), encrypted_seed.begin(),
                                      encrypted_seed.end());
    challenge.ek_name = ek->name;
    challenge.ak_name = ak->name;
    return challenge;
}

std::optional<Digest> complete_svsm_ak_activation(
    const SvsmAkActivationChallenge& challenge, std::span<const uint8_t> activated_secret) {
    if (challenge.expected_secret.empty() ||
        activated_secret.size() != challenge.expected_secret.size() ||
        CRYPTO_memcmp(activated_secret.data(), challenge.expected_secret.data(),
                      activated_secret.size()) != 0 || challenge.ek_name.empty() ||
        challenge.ak_name.empty()) {
        return std::nullopt;
    }
    return ak_ek_binding_digest(challenge.ek_name, challenge.ak_name);
}

std::optional<Digest> complete_svsm_ak_activation(
    const Digest& enrollment_challenge_digest,
    const SvsmAkActivationChallenge& challenge,
    const SvsmAkActivationResponse& response) {
    if (response.version != kSvsmAkActivationWireVersion ||
        response.enrollment_context !=
            svsm_ak_activation_context(enrollment_challenge_digest, challenge)) {
        return std::nullopt;
    }
    return complete_svsm_ak_activation(challenge, response.activated_secret);
}

#if defined(__linux__) && defined(LEMONADE_HAVE_TPM_FAPI)

namespace {

using detail::EsysSession;
using detail::create_primary;

template <typename T, typename Unmarshal>
bool unmarshal_exact(std::span<const uint8_t> wire, T& out, Unmarshal unmarshal) {
    std::size_t offset = 0;
    return unmarshal(wire.data(), wire.size(), &offset, &out) == TSS2_RC_SUCCESS &&
           offset == wire.size();
}

ESYS_TR endorsement_policy_session(ESYS_CONTEXT* esys) {
    TPMT_SYM_DEF symmetric{};
    symmetric.algorithm = TPM2_ALG_NULL;
    ESYS_TR session = ESYS_TR_NONE;
    if (Esys_StartAuthSession(esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, nullptr, TPM2_SE_POLICY,
                              &symmetric, TPM2_ALG_SHA256, &session) != TSS2_RC_SUCCESS) {
        return ESYS_TR_NONE;
    }
    TPM2B_NONCE nonce_tpm{};
    TPM2B_DIGEST cp_hash{};
    TPM2B_NONCE policy_ref{};
    TPM2B_TIMEOUT* timeout = nullptr;
    TPMT_TK_AUTH* ticket = nullptr;
    const TSS2_RC rc = Esys_PolicySecret(
        esys, ESYS_TR_RH_ENDORSEMENT, session, ESYS_TR_PASSWORD, ESYS_TR_NONE,
        ESYS_TR_NONE, &nonce_tpm, &cp_hash, &policy_ref, 0, &timeout, &ticket);
    if (timeout) Esys_Free(timeout);
    if (ticket) Esys_Free(ticket);
    if (rc != TSS2_RC_SUCCESS) {
        (void)Esys_FlushContext(esys, session);
        return ESYS_TR_NONE;
    }
    return session;
}

bool exact_bytes(const std::vector<uint8_t>& actual, std::span<const uint8_t> expected) {
    return actual.size() == expected.size() &&
           std::equal(actual.begin(), actual.end(), expected.begin());
}

std::string public_mismatch(std::string_view key,
                            const std::vector<uint8_t>& actual,
                            std::span<const uint8_t> expected) {
    const auto common = std::min(actual.size(), expected.size());
    std::size_t first = 0;
    while (first != common && actual[first] == expected[first]) ++first;
    return "the recreated " + std::string(key) +
           " public area differs from enrollment (expected=" +
           std::to_string(expected.size()) + " bytes, actual=" +
           std::to_string(actual.size()) + " bytes, first_difference=" +
           std::to_string(first) + ")";
}

}  // namespace

std::optional<std::vector<uint8_t>> activate_svsm_ak_credential(
    std::span<const uint8_t> ek_tpmt_public, std::span<const uint8_t> ak_tpmt_public,
    std::span<const uint8_t> credential_blob, std::span<const uint8_t> encrypted_secret,
    std::string* failure, const char* tcti_config) {
    const auto parsed_ek = parse_tpmt_public_rsa(ek_tpmt_public);
    const auto parsed_ak = parse_tpmt_public_rsa(ak_tpmt_public);
    if (!parsed_ek || !parsed_ak || !is_svsm_vtpm_ek(*parsed_ek) ||
        !is_nexus_quote_ak(*parsed_ak)) {
        set_failure(failure, "activation keys have the wrong TPM object role");
        return std::nullopt;
    }

    TPM2B_PUBLIC ek_input{};
    TPM2B_PUBLIC ak_input{};
    TPM2B_ID_OBJECT credential{};
    TPM2B_ENCRYPTED_SECRET secret{};
    if (!unmarshal_exact(ek_tpmt_public, ek_input.publicArea,
                         Tss2_MU_TPMT_PUBLIC_Unmarshal) ||
        !unmarshal_exact(ak_tpmt_public, ak_input.publicArea,
                         Tss2_MU_TPMT_PUBLIC_Unmarshal) ||
        !unmarshal_exact(credential_blob, credential, Tss2_MU_TPM2B_ID_OBJECT_Unmarshal) ||
        !unmarshal_exact(encrypted_secret, secret,
                         Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal)) {
        set_failure(failure, "credential activation material is not exact TPM wire format");
        return std::nullopt;
    }

    EsysSession session{tcti_config};
    if (!session.esys) {
        set_failure(failure, "the protected vTPM is unavailable");
        return std::nullopt;
    }
    ESYS_TR ek = ESYS_TR_NONE;
    ESYS_TR ak = ESYS_TR_NONE;
    ESYS_TR policy = ESYS_TR_NONE;
    std::vector<uint8_t> created_ek;
    std::vector<uint8_t> created_ak;
    TPM2B_DIGEST* activated = nullptr;
    bool ok = true;
    std::string detail;
    if (!create_primary(session.esys, ESYS_TR_RH_ENDORSEMENT, ek_input, ek,
                        created_ek)) {
        ok = false;
        detail = "TPM2_CreatePrimary could not recreate the enrollment EK";
    } else if (!exact_bytes(created_ek, ek_tpmt_public)) {
        ok = false;
        detail = public_mismatch("EK", created_ek, ek_tpmt_public);
    } else if (!create_primary(session.esys, ESYS_TR_RH_OWNER, ak_input, ak,
                               created_ak)) {
        ok = false;
        detail = "TPM2_CreatePrimary could not recreate the proposed AK";
    } else if (!exact_bytes(created_ak, ak_tpmt_public)) {
        ok = false;
        detail = public_mismatch("AK", created_ak, ak_tpmt_public);
    }
    if (ok) {
        policy = endorsement_policy_session(session.esys);
        if (policy == ESYS_TR_NONE) {
            ok = false;
            detail = "the endorsement hierarchy could not authorize the EK policy";
        } else {
            const TSS2_RC rc = Esys_ActivateCredential(
                session.esys, ak, ek, ESYS_TR_PASSWORD, policy, ESYS_TR_NONE,
                &credential, &secret, &activated);
            ok = rc == TSS2_RC_SUCCESS && activated;
            if (!ok) {
                detail = "TPM2_ActivateCredential rejected the verifier credential (rc=" +
                         std::to_string(rc) + ")";
            }
        }
    }
    std::vector<uint8_t> result;
    if (ok) result.assign(activated->buffer, activated->buffer + activated->size);
    if (activated) Esys_Free(activated);
    if (policy != ESYS_TR_NONE) (void)Esys_FlushContext(session.esys, policy);
    if (ak != ESYS_TR_NONE) (void)Esys_FlushContext(session.esys, ak);
    if (ek != ESYS_TR_NONE) (void)Esys_FlushContext(session.esys, ek);
    if (!ok) {
        set_failure(failure, std::move(detail));
        return std::nullopt;
    }
    return result;
}

#else

std::optional<std::vector<uint8_t>> activate_svsm_ak_credential(
    std::span<const uint8_t>, std::span<const uint8_t>, std::span<const uint8_t>,
    std::span<const uint8_t>, std::string* failure, const char*) {
    set_failure(failure, "SVSM credential activation needs Linux and the TPM ESYS stack");
    return std::nullopt;
}

#endif

}  // namespace nexus::security
