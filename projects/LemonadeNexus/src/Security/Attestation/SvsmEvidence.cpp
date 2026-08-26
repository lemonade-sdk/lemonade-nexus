#include <LemonadeNexus/Security/Attestation/SvsmEvidence.hpp>

#include <algorithm>
#include <utility>

namespace nexus::security {

namespace {

constexpr SvsmEvidencePart kParts[] = {
    SvsmEvidencePart::SnpReport,
    SvsmEvidencePart::SvsmAttestationResponse,
    SvsmEvidencePart::ServiceManifest,
    SvsmEvidencePart::Certificates,
    SvsmEvidencePart::VtpmIdentity,
    SvsmEvidencePart::TpmQuote,
    SvsmEvidencePart::PcrValues,
    SvsmEvidencePart::ImaLog,
};

}  // namespace

std::string_view svsm_evidence_part_name(SvsmEvidencePart part) {
    switch (part) {
        case SvsmEvidencePart::SnpReport:               return "snp-report";
        case SvsmEvidencePart::SvsmAttestationResponse: return "svsm-attestation-response";
        case SvsmEvidencePart::ServiceManifest:         return "service-manifest";
        case SvsmEvidencePart::Certificates:            return "certificates";
        case SvsmEvidencePart::VtpmIdentity:            return "vtpm-identity";
        case SvsmEvidencePart::TpmQuote:                return "tpm-quote";
        case SvsmEvidencePart::PcrValues:               return "pcr-values";
        case SvsmEvidencePart::ImaLog:                  return "ima-log";
    }
    return "unknown-part";
}

std::span<const SvsmEvidencePart> svsm_evidence_parts() { return kParts; }

void SvsmEvidence::set(SvsmEvidencePart part, std::vector<uint8_t> bytes) {
    parts_[part] = std::move(bytes);
}

std::optional<std::span<const uint8_t>> SvsmEvidence::get(SvsmEvidencePart part) const {
    const auto it = parts_.find(part);
    if (it == parts_.end()) {
        return std::nullopt;
    }
    return std::span<const uint8_t>(it->second);
}

bool SvsmEvidence::has(SvsmEvidencePart part) const { return parts_.contains(part); }

std::size_t SvsmEvidence::total_bytes() const {
    std::size_t total = 0;
    for (const auto& [part, bytes] : parts_) {
        total += bytes.size();
    }
    return total;
}

std::vector<SvsmEvidencePart> SvsmEvidence::missing() const {
    std::vector<SvsmEvidencePart> absent;
    for (const auto part : kParts) {
        if (!parts_.contains(part)) {
            absent.push_back(part);
        }
    }
    return absent;
}

}  // namespace nexus::security
