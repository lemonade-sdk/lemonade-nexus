#pragma once

#include <LemonadeNexus/Security/EvidenceSnpSvsmVtpm.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationProfileId.hpp>

#include <optional>
#include <cstddef>
#include <span>
#include <string>
#include <vector>

namespace nexus::security {

inline constexpr uint32_t kSvsmAkActivationWireVersion = 1;
inline constexpr std::size_t kMaxSvsmAkActivationWireBytes = 16 * 1024;

/// Verifier-side state for the one extra enrollment round.  Only
/// credential_blob and encrypted_secret are sent to the candidate;
/// expected_secret remains with the verifier and is short-lived.
struct SvsmAkActivationChallenge {
    std::vector<uint8_t> credential_blob;   ///< TPM2B_ID_OBJECT wire bytes
    std::vector<uint8_t> encrypted_secret;  ///< TPM2B_ENCRYPTED_SECRET wire bytes
    std::vector<uint8_t> expected_secret;   ///< verifier-only random credential
    std::vector<uint8_t> ek_name;
    std::vector<uint8_t> ak_name;
};

/// Wire form of the offer: public/ciphertext values only; expected_secret
/// never leaves the verifier.
struct SvsmAkActivationOffer {
    uint32_t version{kSvsmAkActivationWireVersion};
    Digest enrollment_context{};
    std::vector<uint8_t> credential_blob;
    std::vector<uint8_t> encrypted_secret;
};

/// Candidate response after TPM2_ActivateCredential.  enrollment_context
/// prevents responses from being swapped across concurrent admissions.
struct SvsmAkActivationResponse {
    uint32_t version{kSvsmAkActivationWireVersion};
    Digest enrollment_context{};
    std::vector<uint8_t> activated_secret;
};

/// Mesh-routed offer, bound to one Nexus network, observer, subject identity,
/// incarnation, profile and exact attested EK/AK pair.
struct SvsmAkActivationOfferMessage {
    NetworkId network_id{};
    NodeId subject_node{};
    crypto::Ed25519PublicKey subject_key{};
    IncarnationId incarnation{};
    EpochId epoch{};
    AttestationProfileId profile_id{AttestationProfileId::Unknown};
    AttestationProfileRuleset profile_ruleset{};
    NodeId observer{};
    Digest enrollment_challenge_digest{};
    Nonce verifier_nonce{};
    std::vector<uint8_t> ek_public;
    std::vector<uint8_t> ak_public;
    std::vector<uint8_t> ek_name;
    std::vector<uint8_t> ak_name;
    Digest ak_spki_digest{};
    SvsmAkActivationOffer activation;
};

struct SvsmAkActivationResponseMessage {
    NetworkId network_id{};
    NodeId subject_node{};
    IncarnationId incarnation{};
    EpochId epoch{};
    AttestationProfileId profile_id{AttestationProfileId::Unknown};
    AttestationProfileRuleset profile_ruleset{};
    NodeId observer{};
    Digest activation_context{};
    std::vector<uint8_t> activated_secret;
    crypto::Ed25519Signature identity_signature{};
};

/// One-shot verifier-owned exchange.  Invalid answers do not consume the live
/// offer (a stranger cannot cancel enrollment); the first valid answer does,
/// so a replay fails even before the caller removes its outer map entry.
class SvsmAkActivationExchange {
public:
    SvsmAkActivationExchange(SvsmAkActivationChallenge challenge,
                             SvsmAkActivationOfferMessage offer);

    [[nodiscard]] const SvsmAkActivationOfferMessage& offer() const { return offer_; }
    [[nodiscard]] bool consumed() const { return consumed_; }
    [[nodiscard]] std::optional<Digest> complete(
        const SvsmAkActivationResponseMessage& response);

private:
    SvsmAkActivationChallenge challenge_;
    SvsmAkActivationOfferMessage offer_;
    bool consumed_{false};
};

[[nodiscard]] Digest svsm_ak_activation_offer_context(
    const SvsmAkActivationOfferMessage& offer);
[[nodiscard]] Digest svsm_ak_activation_response_digest(
    const SvsmAkActivationResponseMessage& response);

[[nodiscard]] Digest svsm_ak_activation_context(
    const Digest& enrollment_challenge_digest,
    const SvsmAkActivationChallenge& challenge);
[[nodiscard]] SvsmAkActivationOffer svsm_ak_activation_offer(
    const Digest& enrollment_challenge_digest,
    const SvsmAkActivationChallenge& challenge);
[[nodiscard]] std::string encode_svsm_ak_activation_offer(
    const SvsmAkActivationOffer& offer);
[[nodiscard]] std::optional<SvsmAkActivationOffer> decode_svsm_ak_activation_offer(
    std::string_view wire);
[[nodiscard]] std::string encode_svsm_ak_activation_response(
    const SvsmAkActivationResponse& response);
[[nodiscard]] std::optional<SvsmAkActivationResponse> decode_svsm_ak_activation_response(
    std::string_view wire);

/// TPM 2.0 MakeCredential for an RSA/SHA-256 EK and an AK Name.  The output is
/// directly consumable by TPM2_ActivateCredential after unmarshalling the two
/// outer TPM2B values.  No private TPM material enters this function.
[[nodiscard]] std::optional<SvsmAkActivationChallenge> make_svsm_ak_activation_challenge(
    std::span<const uint8_t> ek_tpmt_public,
    std::span<const uint8_t> ak_tpmt_public,
    std::string* failure = nullptr);

/// Constant-time verification of the ActivateCredential plaintext.  Success
/// returns the receipt digest that may be persisted in the node profile.
[[nodiscard]] std::optional<Digest> complete_svsm_ak_activation(
    const SvsmAkActivationChallenge& challenge,
    std::span<const uint8_t> activated_secret);

[[nodiscard]] std::optional<Digest> complete_svsm_ak_activation(
    const Digest& enrollment_challenge_digest,
    const SvsmAkActivationChallenge& challenge,
    const SvsmAkActivationResponse& response);

/// Candidate side: recreates the deterministic EK and AK primaries inside the
/// protected vTPM, requires exact public-area matches against the attested
/// manifest and proposed AK, then runs TPM2_ActivateCredential.  No persistent
/// handle is created.  `tcti_config` is the TCTI loader config; nullptr uses
/// the stack default (the packaged unit allows /dev/tpmrm0, not raw /dev/tpm0).
/// Empty on non-Linux/non-TPM builds or on any TPM/policy/key mismatch.
[[nodiscard]] std::optional<std::vector<uint8_t>> activate_svsm_ak_credential(
    std::span<const uint8_t> ek_tpmt_public,
    std::span<const uint8_t> ak_tpmt_public,
    std::span<const uint8_t> credential_blob,
    std::span<const uint8_t> encrypted_secret,
    std::string* failure = nullptr,
    const char* tcti_config = nullptr);

}  // namespace nexus::security
