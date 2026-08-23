#pragma once

// Deterministic Tier 1 eligibility.
//
// Every field of Tier1EvidenceState defaults to false: evidence that was never
// collected is failed evidence. There is no override, no score, and no vote —
// the same input always gives the same result, on every correct verifier.

#include <cstdint>
#include <vector>

namespace nexus::security {

enum class Tier1Prerequisite : uint16_t {
    NodeIdentity,
    Certificate,
    ConfidentialCompute,
    Vtpm,
    AttestationFreshness,
    BootState,
    NexusBinary,
    RuntimeMeasurements,
    RuntimeSecurityProfile,
    Uptime,
    MeshHealth,
    Incarnation,
    Epoch,
};

struct Tier1EvidenceState {
    bool node_identity_valid = false;
    bool certificate_valid = false;

    bool snp_valid = false;
    bool vtpm_valid = false;
    bool quote_fresh = false;

    bool boot_state_valid = false;
    bool binary_valid = false;
    bool ima_valid = false;
    bool runtime_profile_valid = false;

    bool uptime_valid = false;
    bool mesh_health_valid = false;

    bool incarnation_current = false;
    bool epoch_current = false;
};

enum class Tier1Eligibility {
    Eligible,
    Ineligible,
};

class Tier1EligibilityPolicy {
public:
    [[nodiscard]] static Tier1Eligibility evaluate(const Tier1EvidenceState& state);

    /// Every prerequisite the state fails, in declaration order. Diagnostic
    /// output only — eligibility is the conjunction, never a subset.
    [[nodiscard]] static std::vector<Tier1Prerequisite> failed_prerequisites(
        const Tier1EvidenceState& state);
};

}  // namespace nexus::security
