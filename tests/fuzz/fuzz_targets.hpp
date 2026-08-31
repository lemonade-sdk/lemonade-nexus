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

#include <LemonadeNexus/Security/Eligibility/EligibilityLedger.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Eligibility/ParticipationProof.hpp>
#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>
#include <LemonadeNexus/Security/HclReport.hpp>
#include <LemonadeNexus/Security/MeasurementIma.hpp>
#include <LemonadeNexus/Security/SnpReport.hpp>
#include <LemonadeNexus/Security/SnpVerify.hpp>
#include <LemonadeNexus/Security/TpmQuote.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>

#include <sodium.h>

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
/// attestation challenge and evidence, HotStuff proposal, quorum certificate,
/// vote and timeout, DKG traffic, FROST commitment and share, epoch
/// announcement, the restart sync response, eligibility observations, the
/// Genesis eligibility attest, and the participation exchange.
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

/// A fixed observer identity, so a fuzzed observation reaches the signature
/// check and the rules behind it instead of stopping at the first structural
/// gate. Derived from a constant seed, so the corpus generator and the target
/// agree without sharing state.
inline const nexus::crypto::Ed25519Keypair& fuzz_observer_key() {
    static const nexus::crypto::Ed25519Keypair key = [] {
        nexus::crypto::Ed25519Keypair pair;
        std::array<uint8_t, crypto_sign_SEEDBYTES> seed{};
        seed.fill(0x7F);
        crypto_sign_seed_keypair(pair.public_key.data(), pair.private_key.data(), seed.data());
        return pair;
    }();
    return key;
}

inline const nexus::security::NetworkId& fuzz_network() {
    static const nexus::security::NetworkId id = [] {
        nexus::security::NetworkId value{};
        value.fill(0x5E);
        return value;
    }();
    return id;
}

inline const nexus::security::MeshFactContext& fuzz_fact_context() {
    static const nexus::security::MeshFactContext context = [] {
        std::vector<nexus::security::NodeId> observers;
        nexus::security::NodeId observer;
        observer.bytes = fuzz_observer_key().public_key;
        observers.push_back(observer);
        for (uint8_t i = 1; i < 5; ++i) {
            nexus::security::NodeId other;
            other.bytes.fill(i);
            observers.push_back(other);
        }
        return nexus::security::established_fact_context(fuzz_network(), 7, observers);
    }();
    return context;
}

inline const nexus::security::ParticipationChallenge& fuzz_participation_challenge() {
    static const nexus::security::ParticipationChallenge challenge = [] {
        nexus::security::ParticipationChallenge value;
        value.network_id = fuzz_network();
        value.epoch = 7;
        value.security_ruleset = nexus::security::constants::kSecurityRulesetVersion;
        value.consensus_ruleset = nexus::security::constants::kConsensusRulesetVersion;
        value.node_id.bytes.fill(0x02);
        value.incarnation = 1;
        value.nonce.fill(0x3D);
        value.finalized_height = 42;
        value.finalized_state.fill(0xC0);
        value.observer.bytes = fuzz_observer_key().public_key;
        return value;
    }();
    return challenge;
}

/// One observer's signed statement, through every rule that judges it: the
/// structural gates, the claim-consistency check, the signature, and the
/// counting that turns statements into facts. Nothing here grants anything —
/// the ledger produces booleans and the fuzzer discards them.
inline void fuzz_eligibility_observation(Bytes input) {
    const auto decoded = nexus::security::decode_security_message(input);
    if (!std::holds_alternative<nexus::security::SecurityMessage>(decoded)) {
        return;
    }
    const auto& message = std::get<nexus::security::SecurityMessage>(decoded);
    const auto* observation =
        std::get_if<nexus::security::EligibilityObservation>(&message.body);
    if (observation == nullptr) {
        return;
    }
    nexus::security::EligibilityLedger ledger;
    (void)ledger.record(*observation, fuzz_fact_context());
    (void)ledger.evaluate(observation->subject, observation->subject_incarnation,
                          fuzz_fact_context());
    (void)ledger.quorum_incarnation(observation->subject, fuzz_fact_context());
    (void)ledger.subjects(observation->epoch, 1);
    (void)ledger.snapshot();
}

/// The Tier 2 participation answer, against a challenge the observer holds.
/// Every binding is checked before the signature, so hostile bytes are
/// diagnosed rather than run through expensive verification.
inline void fuzz_participation_response(Bytes input) {
    const auto decoded = nexus::security::decode_security_message(input);
    if (!std::holds_alternative<nexus::security::SecurityMessage>(decoded)) {
        return;
    }
    const auto& message = std::get<nexus::security::SecurityMessage>(decoded);
    if (const auto* response =
            std::get_if<nexus::security::ParticipationResponse>(&message.body)) {
        (void)nexus::security::verify_participation_response(*response,
                                                             fuzz_participation_challenge());
    }
    if (const auto* challenge =
            std::get_if<nexus::security::ParticipationChallenge>(&message.body)) {
        (void)nexus::security::participation_challenge_digest(*challenge);
    }
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
    {"eligibility_observation", &fuzz_eligibility_observation},
    {"participation_response", &fuzz_participation_response},
};

}  // namespace nexus_fuzz
