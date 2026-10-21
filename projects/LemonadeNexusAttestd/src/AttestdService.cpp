#include <LemonadeNexusAttestd/AttestdService.hpp>

#include <LemonadeNexus/Security/Attestation/SvsmAkEnrollment.hpp>
#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>
#include <LemonadeNexus/Security/EvidenceSnpSvsmVtpm.hpp>
#include <LemonadeNexus/Security/HclReport.hpp>
#include <LemonadeNexus/Security/MeasurementIma.hpp>
#include <LemonadeNexusAttestd/AttestdCodec.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <optional>
#include <type_traits>
#include <utility>

namespace nexus::attestd {

namespace {

/// #12/#48e cache key: the chip/TCB the verified endorsement covers. Falls back
/// to a plain validated-once marker when the report cannot be re-parsed.
std::string endorsement_cache_key(const security::PlatformEvidence& platform) {
    const auto report = std::visit(
        [](const auto& evidence) -> std::optional<security::SnpReport> {
            if constexpr (std::is_same_v<std::decay_t<decltype(evidence)>,
                                         security::SnpSvsmVtpmEvidence>) {
                return security::parse_snp_report(evidence.svsm_report);
            } else {
                std::optional<security::SnpReport> snp;
                if (const auto hcl = security::parse_hcl_blob(evidence.hcl_blob)) snp = hcl->snp;
                return snp;
            }
        },
        platform);
    return report ? report->chip_id_hex() + "/" + report->reported_tcb.to_string()
                  : std::string{"validated"};
}

}  // namespace

std::string_view tsm_heal_hint(std::string_view detail) {
    // The prover's exact failure string for absent TSM objects (#49).
    return detail.find("dedicated TSM report objects") != std::string_view::npos
               ? std::string_view{" (heal: systemctl restart nexus-attestd-tsm-setup.service)"}
               : std::string_view{};
}

bool endorsement_discovery_failed(std::string_view detail) {
    // Both producers' discovery failures start "no AMD endorsement ...".
    return detail.find("no AMD endorsement") != std::string_view::npos;
}

AttestdService::AttestdService(AttestdConfig config) : config_(std::move(config)) {}

// The one secret this daemon ever holds is the transient activation secret;
// handle_request wipes it once the result frame is emitted.
AttestdService::~AttestdService() = default;

bool AttestdService::platform_available() {
#if defined(__linux__) && defined(LEMONADE_HAVE_TPM_FAPI)
    return true;
#else
    return false;
#endif
}

Refusal AttestdService::answer_activation(const SvsmAkActivationRequest& request,
                                          std::vector<uint8_t>& activated_secret,
                                          std::string* detail) {
#if defined(__linux__) && defined(LEMONADE_HAVE_TPM_FAPI)
    // The unit's DeviceAllow grants /dev/tpmrm0 only; the TSS default
    // device:/dev/tpm0 would be refused.
    static constexpr const char* kTctiConfig = "device:/dev/tpmrm0";
    auto secret = security::activate_svsm_ak_credential(
        request.ek_public, request.ak_public, request.credential_blob,
        request.encrypted_secret, detail, kTctiConfig);
    if (!secret) {
        // ActivationUnavailable is reserved for builds with no TPM stack.
        if (detail && detail->empty()) *detail = "the TPM path refused the activation";
        return Refusal::ActivationFailed;
    }
    activated_secret = std::move(*secret);
    // Wipe the moved-from intermediate in case the move degenerated to a copy.
    if (!secret->empty()) sodium_memzero(secret->data(), secret->size());
    return Refusal::None;
#else
    (void)request;
    (void)activated_secret;
    if (detail) *detail = "this build has no TPM stack";
    return Refusal::ActivationUnavailable;
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
    //
    // The identity the binding covers is the PUBLIC key the challenge names.
    // evidence_binding takes a public key, so the daemon needs no secret — which
    // is exactly why it can hold none.
    const std::vector<uint8_t> identity_pubkey(challenge.node_key.begin(),
                                               challenge.node_key.end());

    std::string why;
    auto produce_bundle = [&](bool allow_network) -> Refusal {
        why.clear();
        if (challenge.profile_id == security::AttestationProfileId::SnpSvsmVtpm) {
            security::SnpSvsmEvidenceProduceConfig svsm;
            svsm.cache_dir = config_.cache_dir;
            svsm.allow_network = allow_network;
            svsm.identity_pubkey = identity_pubkey;
            svsm.service_report_object = config_.svsm_report_object;
            svsm.guest_report_object = config_.guest_report_object;
            auto bundle = security::produce_snp_svsm_vtpm_evidence(
                svsm, out.challenge_digest, &why);
            if (!bundle) return Refusal::EvidenceUnavailable;
            if (challenge.purpose == security::AttestationPurpose::PlatformEnrollment) {
                bundle->ima_binary_log.clear();
            } else if (challenge.ima_mode == security::ImaEvidenceMode::Resume) {
                const auto parsed = security::parse_ima_binary(bundle->ima_binary_log);
                if (!parsed || challenge.ima_prior_event_count > parsed->entries.size()) {
                    why = "the verifier checkpoint is not present in this IMA log";
                    return Refusal::EvidenceUnavailable;
                }
                security::ImaBinaryLog prefix;
                prefix.entries.assign(parsed->entries.begin(), parsed->entries.begin() +
                    static_cast<std::ptrdiff_t>(challenge.ima_prior_event_count));
                std::array<uint8_t, 32> zero{};
                const auto replay = security::replay_ima_binary_from(prefix, 0, zero);
                if (!replay || !std::ranges::equal(replay->pcr10,
                                                    challenge.ima_prior_pcr10)) {
                    why = "the verifier checkpoint PCR is not this boot's prefix";
                    return Refusal::EvidenceUnavailable;
                }
                for (const auto& expected : challenge.ima_checkpoint_paths) {
                    const auto found = std::find_if(replay->paths.begin(), replay->paths.end(),
                        [&expected](const auto& path) { return path.path == expected.path; });
                    if (found == replay->paths.end() || found->sha256 != expected.sha256) {
                        why = "the verifier checkpoint path state is stale";
                        return Refusal::EvidenceUnavailable;
                    }
                }
                auto suffix = security::ima_binary_suffix_after_checkpoint(
                    bundle->ima_binary_log, challenge.ima_prior_event_count,
                    challenge.ima_prior_pcr10);
                if (!suffix) return Refusal::EvidenceUnavailable;
                bundle->ima_binary_log = std::move(*suffix);
            }
            out.platform = security::PlatformEvidence{std::move(*bundle)};
        } else {
            security::EvidenceProduceConfig produce;
            produce.cache_dir = config_.cache_dir;
            produce.allow_network = allow_network;
            produce.identity_pubkey = identity_pubkey;
            // hcl_blob_override is deliberately left empty. It is an offline-testing seam
            // in the prover, and a daemon that exposed it would let a caller substitute
            // the platform half of the chain.
            auto bundle = security::produce_snp_vtpm_evidence(produce, out.challenge_digest, &why);
            if (!bundle) return Refusal::EvidenceUnavailable;
            out.platform = security::PlatformEvidence{std::move(*bundle)};
        }
        return Refusal::None;
    };

    // #12/#48e: one verified KDS resolve per chip/TCB per daemon lifetime. While
    // the cached key stands the prover runs with networking off — the disk cache
    // already holds that verified VCEK — so KDS sees no per-request probes. When
    // the offline resolve fails (chip/TCB moved past the cache) the cached key is
    // dropped and the produce retried once on the existing probing path. The
    // endorsement itself still verifies against the pinned chain on every produce.
    const bool kds_suppressed = config_.allow_network && !endorsed_chip_tcb_.empty();
    Refusal produced = produce_bundle(config_.allow_network && !kds_suppressed);
    if (produced == Refusal::EvidenceUnavailable && kds_suppressed &&
        endorsement_discovery_failed(why)) {
        spdlog::info("[attestd] cached endorsement {} no longer resolves offline; re-probing AMD KDS",
                     endorsed_chip_tcb_);
        endorsed_chip_tcb_.clear();
        produced = produce_bundle(true);
    }
    if (produced != Refusal::None) {
        if (detail) *detail = why;
        return produced;
    }
    // Cache only what verified: the resolve inside the prover accepted this VCEK
    // against this report under the pinned AMD chain.
    endorsed_chip_tcb_ = endorsement_cache_key(out.platform);

    // Bounded by what this operation can carry LOCALLY, never by the mesh's
    // kMaxPlatformEvidenceWireBytes — that is a decision for the process that
    // gossips, and enforcing it here withheld correct answers from local callers.
    if (const auto encoded = security::encode_platform_evidence(out.platform);
        encoded.size() > kMaxLocalFrameBytes * kMaxLocalChunks) {
        if (detail) {
            *detail = "evidence is " + std::to_string(encoded.size()) + " bytes, over the " +
                      std::to_string(kMaxLocalFrameBytes * kMaxLocalChunks) +
                      " byte local stream bound";
        }
        return Refusal::EvidenceOversized;
    }

    return Refusal::None;
}

void AttestdService::handle_request(std::string_view request, const FrameSink& sink) {
    const auto challenge = decode_challenge(request);
    if (!challenge) {
        const auto activation = decode_activation_request(request);
        if (activation) {
            std::vector<uint8_t> secret;
            std::string detail;
            const Refusal refusal = answer_activation(*activation, secret, &detail);
            if (refusal != Refusal::None) {
                spdlog::warn("[attestd] refused activation: {}{}{}",
                             refusal_name(refusal), detail.empty() ? "" : " — ", detail);
                (void)emit_refusal(refusal, sink, detail);
                return;
            }
            // The raw secret IS the enrollment proof — log a correlator only.
            std::array<uint8_t, crypto_hash_sha256_BYTES> correlator{};
            crypto_hash_sha256(correlator.data(), secret.data(), secret.size());
            spdlog::info("[attestd] activated SVSM AK credential secret_sha256={}",
                         crypto::to_hex(correlator).substr(0, 16));
            (void)emit_activation_result(secret, sink);
            // The secret leaves this process only in that frame; wipe our copy.
            if (!secret.empty()) sodium_memzero(secret.data(), secret.size());
            return;
        }
        spdlog::warn("[attestd] refused: {}", refusal_name(Refusal::MalformedRequest));
        (void)emit_refusal(Refusal::MalformedRequest, sink);
        return;
    }

    PlatformEvidenceBundle bundle;
    std::string detail;
    const Refusal refusal = answer(*challenge, bundle, &detail);
    if (refusal != Refusal::None) {
        // #49: the appended hint names the setup unit when the TSM objects are
        // missing; the grep-able "[attestd] refused ..." prefix stays unchanged.
        spdlog::warn("[attestd] refused epoch={} purpose={} incarnation={}: {}{}{}{}",
                     challenge->epoch.underlying(), static_cast<uint16_t>(challenge->purpose),
                     challenge->incarnation.underlying(), refusal_name(refusal),
                     detail.empty() ? "" : " — ", detail, tsm_heal_hint(detail));
        (void)emit_refusal(refusal, sink, detail);
        return;
    }

    spdlog::info("[attestd] answered epoch={} purpose={} incarnation={} challenge={} binary={}",
                 challenge->epoch.underlying(), static_cast<uint16_t>(challenge->purpose),
                 challenge->incarnation.underlying(), crypto::to_hex(bundle.challenge_digest),
                 std::visit([](const auto& evidence) {
                     return evidence.binary_sha256.empty() ? std::string{"unmeasured"}
                                                           : evidence.binary_sha256;
                 }, bundle.platform));
    if (!emit_bundle(bundle, sink)) {
        // Caller gone, or the bundle needs more frames than one operation allows.
        spdlog::warn("[attestd] response stream ended early for epoch={} incarnation={}",
                     challenge->epoch.underlying(), challenge->incarnation.underlying());
    }
}

}  // namespace nexus::attestd
