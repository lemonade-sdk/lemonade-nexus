#pragma once

#include <LemonadeNexus/Security/EvidenceSnpSvsmVtpm.hpp>
#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace nexus::security {

inline constexpr uint32_t kPlatformEvidenceWireVersion = 1;

using PlatformEvidence = std::variant<SnpVtpmEvidence, SnpSvsmVtpmEvidence>;

[[nodiscard]] inline SnpVtpmEvidence& azure_evidence(PlatformEvidence& evidence) {
    return std::get<SnpVtpmEvidence>(evidence);
}
[[nodiscard]] inline const SnpVtpmEvidence& azure_evidence(const PlatformEvidence& evidence) {
    return std::get<SnpVtpmEvidence>(evidence);
}
[[nodiscard]] inline SnpSvsmVtpmEvidence& svsm_evidence(PlatformEvidence& evidence) {
    return std::get<SnpSvsmVtpmEvidence>(evidence);
}
[[nodiscard]] inline const SnpSvsmVtpmEvidence& svsm_evidence(
    const PlatformEvidence& evidence) {
    return std::get<SnpSvsmVtpmEvidence>(evidence);
}
[[nodiscard]] inline bool platform_evidence_empty(const PlatformEvidence& evidence) {
    return std::visit([](const auto& value) { return value.empty(); }, evidence);
}

enum class PlatformEvidenceType : uint16_t {
    AzureSnpVtpm = 1,
    SnpSvsmVtpm = 2,
};

[[nodiscard]] PlatformEvidenceType platform_evidence_type(const PlatformEvidence& evidence);
[[nodiscard]] std::string_view platform_evidence_type_name(PlatformEvidenceType type);

/// Closed, explicitly tagged platform envelope.  Payload is the exact
/// canonical profile-specific JSON string; the tag is checked before decoding.
[[nodiscard]] std::string encode_platform_evidence(const PlatformEvidence& evidence);
[[nodiscard]] std::optional<PlatformEvidence> decode_platform_evidence(std::string_view json);
[[nodiscard]] std::size_t platform_evidence_size(const PlatformEvidence& evidence);

}  // namespace nexus::security
