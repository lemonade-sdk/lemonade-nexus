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
// Limits: the record is integrity-checked by verification on every load, not
// rollback-protected. A party that can write the security directory can
// replace or delete it. The damage is bounded: load() folds in the packaged
// approval, which is part of the measured release, so the accepted number
// never falls below the running release; and a peer whose status shows a
// higher accepted release pushes its approval within one offer window. The
// storage vault and the sealed store do not close this gap: the vault does not
// detect a whole-file rollback and is locked when the driver starts, and a
// sealed blob is bound to PCR 8/9, not to a counter, so an older blob still
// unseals. Closing it needs a monotonic counter (no TPM NV operation exists in
// nexus-attestd) or a check against finalized state at start. Release-key
// rotation is not supported; it would need its own consensus-finalized
// transition.

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
/// One-time migration input (Design-Auto-Update Phase 6): the approval an
/// existing network was founded under, copied here before the first
/// auto-update release starts. Read only while the commitment is unbound, and
/// accepted only when its digest equals the certificate's commitment.
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
    /// build's compiled protocol identity and TCB floor.
    [[nodiscard]] const std::optional<ReleaseApprovalBundleV1>& current() const {
        return current_;
    }
    [[nodiscard]] Digest current_digest() const;
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
    std::optional<ReleaseChainRecord> record_;
    std::optional<ReleaseApprovalBundleV1> current_;
};

}  // namespace nexus::security
