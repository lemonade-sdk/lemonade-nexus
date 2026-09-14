#include <LemonadeNexus/Security/Attestation/AttestationProfileId.hpp>

namespace nexus::security {

std::string_view attestation_profile_id_name(AttestationProfileId id) {
    switch (id) {
        case AttestationProfileId::Unknown:       return "unknown";
        case AttestationProfileId::AzureSnpVtpm:  return "snp-hcl-vtpm";
        case AttestationProfileId::SnpSvsmVtpm:   return "snp-svsm-vtpm";
        case AttestationProfileId::SnpDirectBoot: return "snp-direct-boot";
        case AttestationProfileId::Tdx:           return "tdx";
    }
    return "unnamed";
}

bool is_known_attestation_profile_id(AttestationProfileId id) {
    switch (id) {
        case AttestationProfileId::AzureSnpVtpm:
        case AttestationProfileId::SnpSvsmVtpm:
        case AttestationProfileId::SnpDirectBoot:
        case AttestationProfileId::Tdx:
            return true;
        case AttestationProfileId::Unknown:
            return false;
    }
    return false;
}

}  // namespace nexus::security
