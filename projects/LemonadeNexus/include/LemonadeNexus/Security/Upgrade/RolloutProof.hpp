#pragma once

// A self-verifying proof of the finalized rollout state (Design-Auto-Update,
// release guard).
//
// The release workflow must not publish release N+1 while the rollout of
// release N is open: each approval lists only one previous release, so the
// servers still on N-1 would drop out of attestation. The proof lets a
// verifier with no network trust decide that from Tier 1 finalized state:
//
//   base     the Genesis-signed bootstrap certificate and the epoch-1 vote-key
//            listing it commits to (an AuthorityChainPage message);
//   links    every finalized epoch handoff with its commit proof, in order
//            (EpochHandoffProof messages);
//   records  the UpgradeProgress records since the latest Start, each with
//            the commit proof that finalized it (Upgrade RecordProof
//            messages).
//
// The proof names the Genesis public key as candidate data. A verifier pins
// only the network id: the network id is derived from the Genesis key and the
// compiled rulesets, so only the true Genesis key matches it.
//
// Verification derives everything from the Genesis public key: the epoch
// authority chain (AuthorityChain.hpp), then each record's commit proof under
// the vote keys and quorum of the epoch that finalized it, then the record
// rules (check_upgrade_record) with that epoch's Tier 1 members as witnesses.
// Any server may serve the proof; it supplies bytes, never trust.
//
// Freshness: a proof shows a state that was finalized, not the newest state.
// Completion of a release is final (a rollout never reopens), so a stale proof
// can only fail to show completion; it cannot show a completion that did not
// happen.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Security/Upgrade/UpgradeProgress.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::security {

inline constexpr uint32_t kRolloutProofFormatVersion = 1;
/// Largest proof document accepted, checked before parsing.
inline constexpr std::size_t kMaxRolloutProofBytes = 8 * 1024 * 1024;

/// Each byte vector is one encoded SecurityMessage (encode_security_message).
struct RolloutProof {
    /// Candidate data; checked against the pinned network id.
    crypto::Ed25519PublicKey genesis_public_key{};
    std::vector<uint8_t> base;
    std::vector<std::vector<uint8_t>> links;
    std::vector<std::vector<uint8_t>> records;
};

/// {"format_version":1,"genesis_public_key":"<base64>","base":"<hex>",
///  "links":["<hex>"],"records":["<hex>"]}
[[nodiscard]] std::string rollout_proof_json(const RolloutProof& proof);
[[nodiscard]] std::optional<RolloutProof> parse_rollout_proof(std::string_view json_text,
                                                              std::string& error);

/// What a verified proof shows.
struct VerifiedRollout {
    /// The rollout state the records build; inactive when the proof carries
    /// no records.
    UpgradeChainState state;
    /// The newest epoch the authority chain reaches.
    EpochId epoch{};
};

/// Verifies the proof for the pinned `network_id`. nullopt with `error` set on
/// any failure: a Genesis key that does not derive `network_id`, a bad
/// encoding, a broken authority chain, a record whose commit proof does not
/// verify, or a record that does not extend the rollout from its Start.
[[nodiscard]] std::optional<VerifiedRollout> verify_rollout_proof(const RolloutProof& proof,
                                                                  const NetworkId& network_id,
                                                                  std::string& error);

/// The release guard: true only when the proof shows the rollout of
/// `release_number` complete and not halted. `reason` says why not.
[[nodiscard]] bool rollout_complete(const VerifiedRollout& rollout, uint64_t release_number,
                                    std::string& reason);

}  // namespace nexus::security
