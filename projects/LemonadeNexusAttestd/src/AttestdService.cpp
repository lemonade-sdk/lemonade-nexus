#include <LemonadeNexusAttestd/AttestdService.hpp>

#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexusAttestd/AttestdCodec.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <utility>

namespace nexus::attestd {

namespace constants = nexus::security::constants;

AttestdService::AttestdService(AttestdConfig config) : config_(std::move(config)) {}

// Nothing to wipe: this daemon holds no secret.
AttestdService::~AttestdService() = default;

bool AttestdService::platform_available() {
#if defined(__linux__) && defined(LEMONADE_HAVE_TPM_FAPI)
    return true;
#else
    return false;
#endif
}

Refusal AttestdService::answer(const security::AttestationChallenge& challenge,
                               PlatformEvidenceBundle& out, std::string* detail) {
    // Everything decidable without touching hardware, first. A refused challenge
    // must never reach the TPM: a quote is expensive, and a hostile caller
    // driving quotes is the cheapest denial of service against this daemon.
    if (const Refusal r = check_challenge(challenge); r != Refusal::None) {
        return r;
    }

    // Computed here, never accepted over the socket: this digest becomes the
    // quote nonce.
    out.challenge_digest = security::challenge_digest(challenge);

    if (!platform_available()) {
        if (detail) {
            *detail = "this build has no snp-vtpm prover (needs Linux and LEMONADE_HAVE_TPM_FAPI)";
        }
        return Refusal::PlatformUnavailable;
    }

    // The quote nonce is the challenge digest the daemon just computed — never a
    // value that arrived over the socket (architecture 9). produce_snp_vtpm_evidence
    // derives qualifyingData from it with evidence_binding(); derive_quote_binding()
    // in AttestdGate.hpp restates that value for anyone who needs to check it.
    security::EvidenceProduceConfig produce;
    produce.cache_dir = config_.cache_dir;
    produce.allow_network = config_.allow_network;
    // The identity the binding covers is the PUBLIC key the challenge names.
    // evidence_binding takes a public key, so the daemon needs no secret — which
    // is exactly why it can hold none.
    produce.identity_pubkey.assign(challenge.node_key.begin(), challenge.node_key.end());
    // hcl_blob_override is deliberately left empty. It is an offline-testing seam
    // in the prover, and a daemon that exposed it would let a caller substitute
    // the platform half of the chain.

    std::string why;
    auto bundle = security::produce_snp_vtpm_evidence(produce, out.challenge_digest, &why);
    if (!bundle) {
        if (detail) *detail = why;
        return Refusal::EvidenceUnavailable;
    }

    // A bundle no peer can carry is worse than no bundle: it fails late, at the
    // far end, as an unexplained drop.
    if (const auto encoded = security::encode_snp_vtpm_evidence(*bundle);
        encoded.size() > constants::kMaxPlatformEvidenceWireBytes) {
        if (detail) {
            *detail = "evidence is " + std::to_string(encoded.size()) + " bytes, over the " +
                      std::to_string(constants::kMaxPlatformEvidenceWireBytes) + " byte bound";
        }
        return Refusal::EvidenceOversized;
    }

    out.platform = std::move(*bundle);
    return Refusal::None;
}

std::string AttestdService::handle_request(std::string_view request) {
    const auto challenge = decode_challenge(request);
    if (!challenge) {
        spdlog::warn("[attestd] refused: {}", refusal_name(Refusal::MalformedRequest));
        return encode_refusal(Refusal::MalformedRequest);
    }

    PlatformEvidenceBundle bundle;
    std::string detail;
    const Refusal refusal = answer(*challenge, bundle, &detail);
    if (refusal != Refusal::None) {
        spdlog::warn("[attestd] refused epoch={} purpose={} incarnation={}: {}{}{}",
                     challenge->epoch, static_cast<uint16_t>(challenge->purpose),
                     challenge->incarnation, refusal_name(refusal),
                     detail.empty() ? "" : " — ", detail);
        return encode_refusal(refusal, detail);
    }

    spdlog::info("[attestd] answered epoch={} purpose={} incarnation={} challenge={} binary={}",
                 challenge->epoch, static_cast<uint16_t>(challenge->purpose),
                 challenge->incarnation, crypto::to_hex(bundle.challenge_digest),
                 bundle.platform.binary_sha256.empty() ? "unmeasured"
                                                       : bundle.platform.binary_sha256);
    return encode_bundle(bundle);
}

}  // namespace nexus::attestd
