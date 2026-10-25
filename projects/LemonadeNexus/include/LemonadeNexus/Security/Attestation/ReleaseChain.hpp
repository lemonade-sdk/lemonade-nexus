#pragma once

// The accepted release approvals of one server (Design-Auto-Update Phase 0.1
// and Phase 2).
//
// One durable record beside the epoch state pins the release signer and keeps
// the newest accepted approval and the highest accepted release number. A
// newer approval replaces the held one only when all of these hold:
//   - it verifies under the Genesis delegation, the compiled protocol
//     identity, and the TCB floor;
//   - it names this network;
//   - its release signer is the pinned signer;
//   - its release number is strictly greater than the highest accepted one.
// Nothing lowers the number, so an older approval can never return (no
// downgrade, no replay after restart).
//
// The pin comes from the founding approval. A Genesis-signed bootstrap
// certificate commits the digest of the approval the network was founded
// under; bind_commitment accepts that commitment when the founding approval
// it names carries the pinned signer and this network. The certificate thus
// binds the release signer and the network, not one approval digest, and a
// release update needs no Genesis action (Genesis stays one-shot).
//
// Rollback: the record is integrity-checked by verification on every load,
// and a party that can write the security directory can still replace or
// delete it. Finalized consensus state is the anchor against that. Every
// rollout starts with a finalized UpgradeProgress Start record, which a Tier 1
// quorum votes for only when each voter accepted that exact approval. The
// newest finalized Start release is therefore a network floor: every honest
// server accepted at least that release. The upgrade service raises the floor
// (raise_floor) from the records it holds at start and from every finalized
// Start record it learns, on Tier 1 by commit and on every server, Tier 2
// included, by verified record proofs from Tier 1. While the highest accepted
// number is below the floor, current() is empty: this server attests no peer
// and votes for no upgrade record with the rolled-back approval. A peer
// pushes the newer approval when the statuses differ, and adopting it clears
// the condition. The floor lives in memory and is rebuilt from finalized
// state at every start, so it has no file of its own to roll back.
//
// Limits: before a rollout starts, the floor lags the newest adopted approval;
// load() folds in the packaged approval, so the accepted number never falls
// below the running release. A server whose upgrade records were also deleted
// learns the floor from a Tier 1 peer within one record-sync interval. The
// storage vault and the sealed store do not close the gap: the vault does not
// detect a whole-file rollback and is locked when the driver starts, and a
// sealed blob is bound to PCR 8/9, not to a counter. nexus-attestd has no TPM
// NV counter operation. Release-key rotation is not supported; it would need
// its own consensus-finalized transition.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseApproval.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace nexus::security {

inline constexpr uint32_t kReleaseChainFormatVersion = 1;
/// The record, under the chain directory (data_root/security/release).
inline constexpr std::string_view kReleaseChainFile = "release-chain.json";
/// Migration input for a network founded under an earlier approval (for
/// example a format-2 approval): that approval, copied here before the first
/// start on a release chain build. Read only while the commitment is unbound,
/// and accepted only when its digest equals the certificate's commitment. The
/// bootstrap procedure (Design-Auto-Update Phase 6) founds the network fresh on
/// the bootstrap approval and does not use it.
inline constexpr std::string_view kFoundingApprovalFile = "release-founding-approval.json";
/// Largest approval bundle accepted from a peer or the updater, checked before
/// parsing.
inline constexpr std::size_t kMaxReleaseApprovalBytes = 32 * 1024;

enum class ReleaseOfferResult : uint8_t {
    /// A newer approval was verified, persisted, and is now current.
    Adopted = 1,
    /// The offer is the approval already held.
    Current = 2,
    /// The release number is not greater than the highest accepted number.
    Stale = 3,
    /// Verified, but signed by a release key other than the pinned one.
    WrongSigner = 4,
    /// Parse, signature, network, protocol identity, TCB floor, or form check
    /// failed.
    Invalid = 5,
    /// Larger than kMaxReleaseApprovalBytes; not parsed.
    Oversize = 6,
    /// No pinned signer, a corrupt record, or the record write failed.
    Unavailable = 7,
};

[[nodiscard]] std::string_view release_offer_result_name(ReleaseOfferResult result);

/// The durable record. Not a trust anchor on its own: load() re-verifies the
/// stored approval under the Genesis key on every start.
struct ReleaseChainRecord {
    uint32_t format_version{kReleaseChainFormatVersion};
    std::string network_id_hex;
    /// The pinned release signer (canonical base64 Ed25519).
    std::string release_signing_pubkey_b64;
    /// Digest of the verified approval that established the pin. For a
    /// network founded on this release line it is the founding approval, so
    /// the commitment binds even after newer approvals were adopted.
    Digest pin_approval_digest{};
    /// The founding approval digest the bootstrap certificate commits, once
    /// bound; all-zero before.
    Digest founding_approval_digest{};
    uint64_t highest_release_number{};
    /// The newest accepted bundle (release_approval_bundle_json form).
    std::string approval_bundle_json;
};

/// Not thread-safe; the owner serializes calls (the security io thread).
class ReleaseChain {
public:
    ReleaseChain(std::filesystem::path directory, crypto::Ed25519PublicKey genesis_public_key,
                 NetworkId network_id);

    /// Loads the record and folds in the installed (packaged) approval, which
    /// the caller has already verified. Without a record, the installed
    /// approval pins the signer and becomes current. With a record, the
    /// installed approval is offered like any other: a newer one is adopted,
    /// an older one is ignored and the stored newer one stays current.
    /// Returns false when the record exists but is corrupt or names another
    /// network; the chain then refuses every offer and every commitment.
    [[nodiscard]] bool load(const std::optional<ReleaseApprovalBundleV1>& installed);

    /// False after a failed load: fail closed.
    [[nodiscard]] bool healthy() const { return healthy_; }
    /// True once a release signer is pinned.
    [[nodiscard]] bool pinned() const { return record_.has_value(); }

    /// The newest accepted approval, or nullopt when none verifies under this
    /// build's compiled protocol identity and TCB floor, or when it is below
    /// the finalized release floor (below_floor).
    [[nodiscard]] const std::optional<ReleaseApprovalBundleV1>& current() const;
    /// Digest of current(); all-zero when current() is empty.
    [[nodiscard]] Digest current_digest() const;

    /// Raises the finalized release floor: the release number of a finalized
    /// UpgradeProgress Start record. The floor never falls. Returns true when
    /// the call raised it. In memory only; the owner raises it again from
    /// finalized state after every start.
    bool raise_floor(uint64_t finalized_release_number);
    [[nodiscard]] uint64_t floor() const { return floor_; }
    /// True when the highest accepted release number is below the finalized
    /// floor, for example after the record was rolled back or on a server
    /// installed from an older package. current() is then empty until a
    /// newer approval is adopted.
    [[nodiscard]] bool below_floor() const;
    [[nodiscard]] uint64_t highest_release_number() const {
        return record_ ? record_->highest_release_number : 0;
    }
    [[nodiscard]] const std::optional<ReleaseChainRecord>& record() const { return record_; }

    /// Offers an approval bundle as received bytes (a peer, the updater). The
    /// size is checked before parsing.
    [[nodiscard]] ReleaseOfferResult offer_json(std::string_view json_text);
    [[nodiscard]] ReleaseOfferResult offer(const ReleaseApprovalBundleV1& bundle);

    /// Accepts a stored bootstrap certificate's release commitment at restart.
    /// Bound before: true only for the same digest. Unbound: the digest must
    /// name the approval that established the pin, or the approval in the
    /// migration file, which must verify under
    /// the Genesis delegation for this network and carry the pinned signer;
    /// the binding is then persisted. Anything else returns false.
    [[nodiscard]] bool bind_commitment(const Digest& committed_approval_digest);

    [[nodiscard]] const std::filesystem::path& directory() const { return directory_; }

private:
    [[nodiscard]] bool persist(const ReleaseChainRecord& record);
    [[nodiscard]] std::optional<ReleaseApprovalBundleV1> founding_from_file(
        const Digest& committed) const;

    std::filesystem::path directory_;
    crypto::Ed25519PublicKey genesis_public_key_{};
    NetworkId network_id_{};
    bool healthy_ = true;
    uint64_t floor_ = 0;
    std::optional<ReleaseChainRecord> record_;
    std::optional<ReleaseApprovalBundleV1> current_;
};

}  // namespace nexus::security
