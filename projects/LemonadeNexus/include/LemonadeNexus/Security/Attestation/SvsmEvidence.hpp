#pragma once

// A capture from an SVSM host, as named opaque parts.
//
// Every part is bytes and nothing here knows what is inside one. That is the
// whole point: naming a field before the live protocol has been read is how an
// assumed format becomes a verification rule nobody checked. The part names
// come from what an SVSM capture is expected to contain, not from a schema.
//
// This exists so real .40 evidence can be added without redesigning the way it
// arrives. Parsing waits for the evidence.

#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace nexus::security {

enum class SvsmEvidencePart : uint16_t {
    SnpReport,
    SvsmAttestationResponse,
    ServiceManifest,
    Certificates,
    VtpmIdentity,
    TpmQuote,
    PcrValues,
    ImaLog,
};

[[nodiscard]] std::string_view svsm_evidence_part_name(SvsmEvidencePart part);

/// Every part a capture may carry, in declaration order.
[[nodiscard]] std::span<const SvsmEvidencePart> svsm_evidence_parts();

class SvsmEvidence {
public:
    /// Replaces one part. A capture may be incomplete: a host that supplies
    /// nothing for a part is telling us the live protocol does not produce it,
    /// which is exactly what the capture is meant to reveal.
    void set(SvsmEvidencePart part, std::vector<uint8_t> bytes);

    [[nodiscard]] std::optional<std::span<const uint8_t>> get(SvsmEvidencePart part) const;
    [[nodiscard]] bool has(SvsmEvidencePart part) const;
    [[nodiscard]] std::size_t total_bytes() const;
    [[nodiscard]] bool empty() const { return parts_.empty(); }

    /// Which listed parts this capture does not carry. Diagnostic: an absent
    /// part is a fact about the host, never a reason to accept anything.
    [[nodiscard]] std::vector<SvsmEvidencePart> missing() const;

private:
    std::map<SvsmEvidencePart, std::vector<uint8_t>> parts_;
};

}  // namespace nexus::security
