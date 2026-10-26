#pragma once

// The threshold storage key on one server (design Part B, Phase 5).
//
// One service per server, on the security io thread. It is unconditional: the
// threshold storage key and the holder duties run on every server. It owns
// four jobs:
//
// 1. Holder records in consensus (B4, B5, B5a). Two block payload handlers
//    (StorageHolderPlan, StorageKeyRotation) propose and check the storage
//    records. A replica votes for a selection only when its own derivation
//    from finalized inputs gives identical bytes, and for a final plan only
//    when it completes the pending selection with every holder's signature
//    over the same plan bytes. Records reach servers outside Tier 1 as
//    StoragePlanProof messages that carry the commit proof; each server
//    verifies the proof against the committing epoch's vote keys. A live
//    record whose commit produced no proof is still kept on disk, so that a
//    restart does not fall back to an older plan, but it is served to nobody.
//    A member rebuilds its proof from the certified chain that the peers'
//    consensus still serves, verifies it, and then serves the record.
// 2. Key sessions (B5, B5a, Part C). Each selected holder runs the first key
//    generation, a share refresh, or a rotation for the finalized selection
//    over the security transport: round 1 broadcast, round 2 sealed to each
//    recipient with the session bound inside the seal, then a signed
//    confirmation of the plan it derived. Early round-2 packages are held and
//    the holder's own packages are re-sent (RoundRelay.hpp) until the final
//    plan commits.
// 3. Unlock, holder side (B7). A holder answers a StorageUnlockRequest only for
//    the current plan (or the retiring plan while it is live), only for an R
//    that the requester's latest finalized wrap claim names, only after a
//    passing StorageUnlock attestation of the requester bound to that request,
//    and only within the budgets. The partial is sealed to the requester with
//    the request digest bound inside the seal.
// 4. The data key (DataKeyService): the requester side of unlock, the wrap
//    claims, and the rewrap after a rotation.
//
// The stored records are bound to the epoch chain: records.json names the
// Genesis certificate digest of the chain that finalized them. Records from
// another chain (for example after a re-found) are refused, and the service
// stays inert. When the files are encrypted under the data key, lost or
// foreign storage state stops the server (halt_reason()) instead of starting
// fresh: a fresh start would prune the holder's shares and create a new data
// key, and the encrypted files would never open again. For the same reason a
// share that the stored records do not name (for example a share of a plan
// whose record was never written) is kept until the chain names its plan:
// stale records must not destroy a live share.
//
// The storage key is its own key role. Nothing here signs for the network,
// votes, or grants Tier 1 authority; the identity key signs only the holder's
// own confirmation statement.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/StorageThreshold.hpp>
#include <LemonadeNexus/Security/Authority/RoundRelay.hpp>
#include <LemonadeNexus/Security/Consensus/BlockPayload.hpp>
#include <LemonadeNexus/Security/Eligibility/EligibilityService.hpp>
#include <LemonadeNexus/Security/Storage/DataKeyService.hpp>
#include <LemonadeNexus/Security/Storage/StorageRecords.hpp>
#include <LemonadeNexus/Security/Storage/StorageShareStore.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>

namespace nexus::crypto {
class SodiumCryptoService;
}

namespace nexus::security {

class HotStuffService;
class PairwiseSealer;
class SecurityDriver;
class SecurityRouter;
class SecurityRuntime;

struct StorageKeyServiceConfig {
    NodeId self{};
    /// The gossip identity keypair. Signs this holder's confirmations and is
    /// the requester identity the holders attest.
    crypto::Ed25519Keypair identity{};
    NetworkId network_id{};
    /// <data>/security/storage: records.json and data-key.json.
    std::filesystem::path directory;
    /// Unix time in milliseconds: the proposer's block time and the voter's
    /// block-time bound, as for tree batches (design A4). Block time, never
    /// this clock, decides rotation and session timeouts.
    std::function<uint64_t()> wall_clock_ms;
    /// True when this server's files are encrypted under the data key (the
    /// vault records `encrypted`). Empty means no vault: never encrypted.
    std::function<bool()> files_encrypted;
};

/// Why the service refused an inbound storage message. Counted for tests and
/// diagnostics; a refusal never changes state.
enum class StorageDrop : uint16_t {
    Malformed,
    UnknownSession,
    NotAHolder,
    WrongRound,
    Equivocation,
    BadSignature,
    ProofInvalid,
    UnknownPlan,
    EpochMismatch,
    Replay,
    PendingBusy,
    BudgetExceeded,
    AttestationFailed,
    InvalidPartial,
    NoShare,
    /// The request's R is not in the requester's latest finalized wrap claim
    /// for the plan's S, for example an R that belongs to another server.
    UnclaimedWrap,
    /// A wrap claim that does not pass check_storage_wrap_claim().
    ClaimInvalid,
};

class StorageKeyService {
public:
    /// Not owning: every reference must outlive the service.
    StorageKeyService(StorageKeyServiceConfig config, SecurityDriver& driver,
                      SecurityRouter& router, SecurityRuntime& runtime, PairwiseSealer& sealer,
                      IStorageShareStore& shares, crypto::SodiumCryptoService& crypto);
    ~StorageKeyService();

    StorageKeyService(const StorageKeyService&) = delete;
    StorageKeyService& operator=(const StorageKeyService&) = delete;

    /// Registers the payload handlers, the message and verdict sinks, and the
    /// eligibility callback with the driver. Call before the driver starts.
    void attach();

    /// Loads durable records and the holder's shares. False when either is
    /// corrupt: the service then stays inert (no vote, no partial, no
    /// session). Lost storage state is never a fresh start. Also false, with
    /// halt_reason() set, when the files are encrypted and records.json or
    /// data-key.json is missing, or records.json holds no finalized plan.
    /// No share is pruned before the records are bound to the epoch chain.
    [[nodiscard]] bool start(uint64_t now_ms);
    [[nodiscard]] bool healthy() const { return healthy_; }

    /// Why this server must not run with its storage state, or empty: the
    /// files are encrypted and the state that unlocks them is missing, or the
    /// stored records belong to another epoch chain. The text names the files
    /// to restore or move aside. Thread-safe.
    [[nodiscard]] std::string halt_reason() const;

    /// True once the records are bound to this node's verified epoch chain
    /// (its Genesis certificate digest). io thread.
    [[nodiscard]] bool chain_bound() const { return chain_bound_; }

    /// Liveness work on the io thread: re-sends, record sync, grace expiry,
    /// pending-unlock expiry, and the data key. `now_ms` is the steady clock
    /// of the security tick.
    void tick(uint64_t now_ms);

    /// The router's StorageUnlock challenge gate: true only while this node's
    /// data key has a live unlock request to `holder` bound to `context` (an
    /// all-zero context matches any live request to that holder).
    [[nodiscard]] bool expects_unlock_challenge(const NodeId& holder,
                                                const Digest& context) const;

    // --- Inbound (driver sinks) ---
    void on_message(const SecurityMessage& message);
    void on_verdict(const AttestationVerdict& verdict);
    void on_eligibility_finalized(const FinalizedEligibility& finalized, const Tier1Set& pool);
    /// A checked sync reply (SecurityDriver::set_storage_chain_sink). A
    /// three-chain in it over the block of a live record that this node holds
    /// without its proof becomes that proof once it verifies under the vote
    /// keys and quorum of its epoch. Also advances this node's own search for
    /// such a proof. The reply is candidate data; nothing else in it counts.
    void on_certified_chain(const SyncResponse& response, const NodeId& from);

    // --- Payload handling (through the two registered adapters) ---
    [[nodiscard]] std::optional<ProposedPayload> propose(const HotStuffService& consensus,
                                                         BlockPayloadKind kind);
    [[nodiscard]] bool validate(const HotStuffService& consensus, const Proposal& proposal,
                                const BlockPayload& payload);
    void on_committed(const CommittedPayload& committed);

    // --- Reads ---
    [[nodiscard]] const StorageChainState& chain() const { return chain_; }
    [[nodiscard]] DataKeyService& data_keys() { return *data_keys_; }
    [[nodiscard]] const DataKeyService& data_keys() const { return *data_keys_; }
    /// True when this node holds the record `record_digest` with a commit
    /// proof, which is what it serves to other servers.
    [[nodiscard]] bool holds_proof(const Digest& record_digest) const {
        return proofs_.contains(record_digest);
    }
    /// True when this holder keeps a share for the final plan `plan_digest`.
    [[nodiscard]] bool holds_share(const Digest& plan_digest) const;
    /// True while the current plan's retiring plan still unwraps.
    [[nodiscard]] bool retiring_live() const;
    /// The epoch this server treats as current: its epoch state, else its
    /// verified authority. Zero before either exists.
    [[nodiscard]] EpochId current_epoch() const;
    [[nodiscard]] uint64_t drops(StorageDrop reason) const;
    /// Partials this holder produced.
    [[nodiscard]] uint64_t partials_sent() const { return partials_sent_; }
    /// The eligibility facts of the latest finalized boundary, when held.
    [[nodiscard]] const std::optional<StorageEligibleSnapshot>& snapshot() const {
        return snapshot_;
    }

    // --- For DataKeyService ---
    [[nodiscard]] const StorageKeyServiceConfig& config() const { return config_; }
    [[nodiscard]] crypto::SodiumCryptoService& crypto() { return crypto_; }
    [[nodiscard]] PairwiseSealer& sealer() { return sealer_; }
    /// True when `plan_digest` names the current plan and that record was
    /// verified by this process (a commit or a verified proof), not only
    /// read from disk. Only such a plan's S receives a new wrap.
    [[nodiscard]] bool current_verified() const { return current_verified_; }
    /// The files_encrypted() input; false without one.
    [[nodiscard]] bool files_encrypted() const;
    void send_unlock_request(const NodeId& holder, const StorageUnlockRequestMsg& request);
    /// Sends this server's signed wrap claim to every Tier 1 member (and to
    /// its own pool when it is one). Idempotent; the caller re-sends until
    /// the claim is finalized.
    void submit_wrap_claim(const StorageWrapClaim& claim);
    /// This holder's own partial for a request, without attestation: the
    /// requester is this process. nullopt without a share for the plan.
    [[nodiscard]] std::optional<crypto::StoragePartial> own_partial(
        const StorageFinalPlan& plan, const Digest& plan_digest,
        const StorageUnlockRequestMsg& request) const;
    [[nodiscard]] static crypto::StorageUnlockContext unlock_context(
        const NetworkId& network_id, const StorageUnlockRequestMsg& request);

private:
    class PayloadAdapter;
    struct Session;
    struct PendingUnlock {
        StorageUnlockRequestMsg request;
        Digest request_digest{};
        Digest context{};
        uint64_t expires_ms = 0;
    };
    struct AuthorityKeys {
        std::size_t quorum = 0;
        std::map<NodeId, crypto::Ed25519PublicKey> vote_keys;
    };
    /// A search of a peer's certified chain for the block that finalized a
    /// live record held without its proof.
    struct ProofSearch {
        Digest record{};
        NodeId peer{};
        /// Exclusive lower bound: the block of the nearest earlier record
        /// proved in this epoch, or zero.
        uint64_t lower = 0;
        /// The height the outstanding page request names (SyncRequest).
        uint64_t after = 0;
        uint64_t sent_ms = 0;
        /// The next page, sent on the next tick so that a search stays far
        /// below the peer's message budget.
        std::optional<uint64_t> next_after;
    };

    // Records.
    void apply_record(const StorageRecord& record, std::optional<StoragePlanProofMsg> proof,
                      bool verified);
    void on_plan_proof(const StoragePlanProofMsg& proof);
    /// True when the commit proof verifies for the record under the vote keys
    /// and quorum of its committing epoch, and a final plan names that epoch.
    [[nodiscard]] bool proof_verifies(const StorageRecord& record,
                                      const StoragePlanProofMsg& message);
    /// True while `digest` names a live record: the pending, current, or
    /// retiring plan, or a batch that carries a latest claim.
    [[nodiscard]] bool live_record(const Digest& digest, const StorageRecord& record) const;
    /// Drops the proofs and the unproven records of records that are no
    /// longer live.
    void keep_live_records();
    /// The lowest-sequence live record held without its proof.
    [[nodiscard]] std::optional<std::pair<Digest, StorageRecord>> first_unproven() const;
    /// The heights (exclusive) between which the block of the unproven
    /// `record` lies in the current epoch; nullopt when it cannot lie in it.
    [[nodiscard]] std::optional<std::pair<uint64_t, uint64_t>> search_bounds(
        const StorageRecord& record) const;
    void search_proof(const NodeId& peer);
    void request_page(uint64_t after);
    void on_plan_request(const StoragePlanRequestMsg& request, const NodeId& from);
    void send_live_records(const NodeId& to, uint64_t after_sequence);
    void broadcast_proof(const Digest& record_digest);
    void persist_records();
    [[nodiscard]] bool load_records();
    void bind_chain();
    void halt(std::string reason);
    [[nodiscard]] bool live_batch(const StorageRecord& record) const;
    void on_wrap_claim(const StorageWrapClaimMsg& claim);
    [[nodiscard]] std::vector<NodeId> tier1_members() const;
    void capture_authority();
    void sync_records(uint64_t now_ms);
    [[nodiscard]] bool uncommitted_storage_ancestor(const HotStuffService& consensus,
                                                    const Digest& from) const;
    [[nodiscard]] std::set<NodeId> silent_holders() const;
    [[nodiscard]] const StorageEligibleSnapshot* derivation_snapshot() const;

    // Sessions.
    void open_session();
    void start_round1(Session& session);
    void on_package(const StorageKeyPackageMsg& package);
    void maybe_round2(Session& session);
    void maybe_finish(Session& session);
    void on_confirm(Session& session, const StorageKeyPackageMsg& package,
                    const StorageHolder& sender);
    void resend(uint64_t now_ms);
    void send_round2(const Session& session);
    void broadcast_package(const StorageKeyPackageMsg& package);
    [[nodiscard]] std::optional<std::pair<std::vector<uint8_t>,
                                          std::map<NodeId, crypto::Ed25519Signature>>>
    complete_confirmations() const;

    // Shares.
    void adopt_session_share(const Digest& session_id, const Digest& plan_digest);
    void prune_shares();
    [[nodiscard]] bool persist_shares();
    [[nodiscard]] bool load_shares();
    [[nodiscard]] const crypto::StorageKeyShare* share_for(const Digest& plan_digest) const;

    // Unlock, holder side.
    void on_unlock_request(const StorageUnlockRequestMsg& request);
    void on_unlock_partial(const StorageUnlockPartialMsg& partial);
    [[nodiscard]] const StorageFinalPlan* live_plan(const Digest& plan_digest) const;

    void drop(StorageDrop reason);

    StorageKeyServiceConfig config_;
    SecurityDriver& driver_;
    SecurityRouter& router_;
    SecurityRuntime& runtime_;
    PairwiseSealer& sealer_;
    IStorageShareStore& share_store_;
    crypto::SodiumCryptoService& crypto_;

    std::unique_ptr<PayloadAdapter> plan_handler_;
    std::unique_ptr<PayloadAdapter> rotation_handler_;
    std::unique_ptr<DataKeyService> data_keys_;

    bool healthy_ = false;
    uint64_t now_ms_ = 0;

    StorageChainState chain_;
    bool current_verified_ = false;
    /// Commit proofs of the live records (pending, current, retiring).
    std::map<Digest, StoragePlanProofMsg> proofs_;
    std::optional<StorageEligibleSnapshot> snapshot_;
    std::map<EpochId, AuthorityKeys> authorities_;
    ResendCadence record_sync_{30'000};
    std::size_t sync_cursor_ = 0;

    std::unique_ptr<Session> session_;

    /// Live shares by final-plan digest, plus a finished session's share
    /// under the session digest until its final plan commits.
    std::map<Digest, crypto::StorageKeyShare> shares_;

    /// Verified wrap claims waiting for a batch, by node (Tier 1 only).
    std::map<NodeId, StorageWrapClaim> claim_pool_;

    /// Epoch-chain binding of the records (see the file comment).
    bool records_file_present_ = false;
    std::optional<Digest> stored_chain_;
    std::optional<Digest> chain_identity_;
    bool chain_bound_ = false;
    /// A record applied past a gap in the sequence: the next record request
    /// asks for every live record again.
    bool record_gap_ = false;
    /// Live records applied from a commit that produced no commit proof, by
    /// record digest. Kept on disk; never served until a verified proof
    /// replaces the entry.
    std::map<Digest, StorageRecord> unproven_;
    std::optional<ProofSearch> proof_search_;
    /// Shares loaded at start for a plan that the stored records do not name.
    /// Each stays until the chain names its plan; the normal pruning rules
    /// apply from then on.
    std::set<Digest> unplaced_shares_;
    mutable std::mutex halt_mutex_;
    std::string halt_reason_;

    std::map<NodeId, PendingUnlock> pending_unlocks_;
    std::map<std::pair<EpochId, NodeId>, uint32_t> unlock_counts_;
    std::set<Digest> seen_requests_;
    EpochId seen_epoch_{};
    uint64_t partials_sent_ = 0;

    std::map<StorageDrop, uint64_t> drops_;
};

}  // namespace nexus::security
