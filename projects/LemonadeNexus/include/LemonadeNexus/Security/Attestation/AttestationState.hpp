#pragma once

// Verifier-owned state for SVSM attestation.
//
// These records are deliberately separate from the eligibility ledger and
// from release-global LinuxAttestationProfile.  An EK/AK relationship and an
// IMA replay position are facts one observer established about one node; they
// are never compiled release policy and never become quorum authority.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationProfileId.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>
#include <variant>
#include <vector>

namespace nexus::security {

inline constexpr uint32_t kAttestationCheckpointFormatVersion = 1;
inline constexpr uint32_t kSvsmActivationRecordFormatVersion = 1;

struct ImaCheckpointPath {
    std::string path;
    std::string sha256;

    auto operator<=>(const ImaCheckpointPath&) const = default;
};

struct AttestationCheckpoint {
    uint32_t format_version{kAttestationCheckpointFormatVersion};
    NetworkId network_id{};
    NodeId node_id{};
    IncarnationId incarnation{};
    AttestationProfileId profile_id{AttestationProfileId::Unknown};
    AttestationProfileRuleset profile_ruleset{};
    Digest policy_digest{};
    std::array<uint8_t, 48> launch_measurement{};
    std::vector<uint8_t> ek_name;
    std::vector<uint8_t> ak_name;
    uint16_t ima_bank{};
    uint64_t event_count{};
    Digest pcr10{};
    std::vector<ImaCheckpointPath> required_paths;
    Digest previous_evidence_digest{};
    Digest checkpoint_digest{};
};

/// Canonical verifier-generated identity of every security-relevant field.
[[nodiscard]] Digest attestation_checkpoint_digest(const AttestationCheckpoint& checkpoint);
[[nodiscard]] bool attestation_checkpoint_valid(const AttestationCheckpoint& checkpoint);

struct SvsmAkActivationRecord {
    uint32_t format_version{kSvsmActivationRecordFormatVersion};
    NetworkId network_id{};
    NodeId node_id{};
    crypto::Ed25519PublicKey node_key{};
    IncarnationId incarnation{};
    AttestationProfileId profile_id{AttestationProfileId::Unknown};
    AttestationProfileRuleset profile_ruleset{};
    std::vector<uint8_t> ek_name;
    std::vector<uint8_t> ak_name;
    std::string ak_spki_b64;
    Digest ak_spki_digest{};
    Digest activation_receipt{};
    Digest enrollment_evidence_digest{};
    Digest record_digest{};
};

[[nodiscard]] Digest svsm_activation_record_digest(const SvsmAkActivationRecord& record);
[[nodiscard]] bool svsm_activation_record_valid(const SvsmAkActivationRecord& record);

enum class AttestationStateLoadFailure : uint8_t {
    Absent,
    Corrupt,
};

using CheckpointLoadResult =
    std::variant<AttestationCheckpoint, AttestationStateLoadFailure>;
using ActivationLoadResult =
    std::variant<SvsmAkActivationRecord, AttestationStateLoadFailure>;

class AttestationCheckpointStore {
public:
    explicit AttestationCheckpointStore(std::filesystem::path directory = {});

    [[nodiscard]] CheckpointLoadResult load(const NetworkId& network_id,
                                            const NodeId& node_id,
                                            IncarnationId incarnation,
                                            AttestationProfileId profile_id) const;
    [[nodiscard]] bool store(AttestationCheckpoint checkpoint);
    [[nodiscard]] const std::filesystem::path& directory() const { return directory_; }

private:
    std::filesystem::path directory_;
};

class SvsmActivationStore {
public:
    explicit SvsmActivationStore(std::filesystem::path directory = {});

    [[nodiscard]] ActivationLoadResult load(const NetworkId& network_id,
                                            const NodeId& node_id,
                                            IncarnationId incarnation,
                                            AttestationProfileId profile_id) const;
    [[nodiscard]] bool store(SvsmAkActivationRecord record);
    /// Drops one record. A subject whose vTPM AK rotated (any reboot) can only
    /// re-enroll once the record pinning the old AK is gone.
    bool remove(const NetworkId& network_id, const NodeId& node_id, IncarnationId incarnation,
                AttestationProfileId profile_id);
    [[nodiscard]] const std::filesystem::path& directory() const { return directory_; }

private:
    std::filesystem::path directory_;
};

}  // namespace nexus::security
