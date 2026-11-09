#pragma once

// This server's data key (DEK), wrapped to the storage public key S (design
// B2, B7, B9, B10). The API Phase 7 uses to encrypt the server's files.
//
// - First use: when a verified current plan exists and no wrapped key is on
//   disk, the service creates a random 32-byte DEK, wraps it to S with
//   StorageThreshold::wrap_data_key, and writes the wrapped key to
//   <directory>/data-key.json. It then runs one unlock through the holders to
//   prove the wrapped key opens (unlock_verified()); Phase 7 deletes no
//   plaintext before that proof (B10). It never creates a DEK while the files
//   are encrypted: a lost data-key.json is restored, not replaced.
// - Wrap claims (B5a, B7): the service keeps a signed claim of its wrapped
//   keys (S and R) finalized in the storage chain: the committed wrap, and the
//   staged wrap while one exists. Holders serve s_i*R only for an R the
//   requester's latest finalized claim names, so no unlock round trip starts
//   before that claim is finalized.
// - Startup: the DEK is not on disk in the clear. The service sends a
//   StorageUnlockRequest to every holder of the plan whose S the wrapped key
//   names, collects t verified partials, and unwraps the DEK into guarded
//   memory. With fewer it retries with backoff and stays locked: nothing that
//   needs the DEK may run (fail closed). An attempt waits at least as long as
//   a holder may still answer its request (kStorageUnlockPendingMs), and the
//   partials of a timed-out request stay usable for that window: a holder
//   charges a served partial against this server's per-epoch budget when it
//   sends it, so none is wasted. No new request goes out while a holder may
//   still hold the previous one pending.
// - Rotation: when the current plan's S differs from the S the wrapped key
//   names and the DEK is in memory, rewrap() stages the DEK wrapped to the new
//   S in data-key.next.json, claims it, and proves through the new plan's
//   holders that it unwraps. Only then does it replace data-key.json (the
//   switch point) and claim the new wrap alone, which is this server's
//   acknowledgement of the rotation. A server that restarted before the swap
//   unlocks under the retiring plan and stages again. The retiring plan stays
//   live until every server's claim moved off its S, up to a hard cap; after
//   the cap a key wrapped to the retired S cannot unlock (state Retired).
//
// - Replacement (B5a, monthly DEK rotation): begin_replacement() creates a new
//   DEK, wraps it to the current S, and stores it in data-key.next.json beside
//   the current wrapped key; once claimed, an unlock round trip proves it
//   unwraps. Only commit_replacement() makes it current. A next file found at
//   startup was never committed and is removed.
//
// StorageVault (Phase 7) encrypts the server's files under this key.

#include <LemonadeNexus/Crypto/SecureBuffer.hpp>
#include <LemonadeNexus/Crypto/StorageThreshold.hpp>
#include <LemonadeNexus/Security/Storage/StorageRecords.hpp>
#include <LemonadeNexus/Security/Storage/StorageVault.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace nexus::security {

class StorageKeyService;

enum class DataKeyState : uint8_t {
    /// No finalized storage key exists yet, or this server has not verified
    /// its plan in this run.
    NoStorageKey,
    /// A wrapped DEK exists and the DEK is not in memory. Unlock is running
    /// or waiting for its next attempt.
    Locked,
    /// The DEK is in memory.
    Unlocked,
    /// The wrapped DEK names the retiring S after the retiring plan ended:
    /// every server claimed a rewrap, or the hard cap passed. It cannot
    /// unlock.
    Retired,
};

class DataKeyService final : public DataKeySource {
public:
    /// Not owning: `service` must outlive this object.
    explicit DataKeyService(StorageKeyService& service);

    /// Thread-safe.
    [[nodiscard]] DataKeyState state() const;

    /// A copy of the DEK in guarded memory, or nullopt unless Unlocked.
    /// Thread-safe. The caller keeps the copy no longer than it needs it.
    [[nodiscard]] std::optional<crypto::SecureBuffer> data_key() const override;

    /// True once an unlock through the holders reproduced the in-memory DEK
    /// from the stored wrapped key (B10 step 2). Thread-safe.
    [[nodiscard]] bool unlock_verified() const override;

    /// Clears unlock_verified() and starts a new unlock round trip through the
    /// holders on the next tick. io thread.
    void request_verification() override;

    /// See the replacement rules above. io thread, except the two reads.
    bool begin_replacement() override;
    [[nodiscard]] std::optional<crypto::SecureBuffer> replacement_key() const override;
    [[nodiscard]] bool replacement_verified() const override;
    bool commit_replacement() override;
    void abort_replacement() override;

    /// The S the stored wrapped DEK names, or nullopt when none is stored.
    /// Thread-safe.
    [[nodiscard]] std::optional<StoragePointBytes> wrapped_to() const;

    /// Stages the in-memory DEK wrapped to the current S in
    /// data-key.next.json. The stored wrapped key is replaced only after an
    /// unlock through the current plan's holders reproduces the DEK from the
    /// staged wrap. False when the DEK is not in memory, the current plan is
    /// not verified in this run, the stored key already names the current S,
    /// or the write fails. io thread.
    bool rewrap();

    /// The S the staged wrap (data-key.next.json) names, or nullopt when none
    /// is staged. Thread-safe.
    [[nodiscard]] std::optional<StoragePointBytes> staged_to() const;

    /// Called on the io thread on every state change.
    void set_state_callback(std::function<void(DataKeyState)> callback);

    /// Liveness work: creation, unlock attempts and their backoff, and the
    /// rewrap after a rotation. io thread.
    void tick(uint64_t now_ms);

    /// The storage chain changed (a record applied). io thread.
    void on_chain_changed();

    /// One holder's partial for the live attempt. io thread.
    void on_partial(const StorageUnlockPartialMsg& partial);

    /// The router gate (see StorageKeyService::expects_unlock_challenge).
    [[nodiscard]] bool expects_challenge(const NodeId& holder, const Digest& context) const;

    /// Requests sent in total (tests and diagnostics).
    [[nodiscard]] uint64_t attempts() const { return attempts_; }
    /// Partials that arrived after their attempt timed out and still counted
    /// toward that request (tests and diagnostics).
    [[nodiscard]] uint64_t late_partials() const { return late_partials_; }
    /// Partials for a request this service no longer holds: not live, not
    /// kept after its timeout, and not answered within the last holder
    /// pending window. Each one spent a served partial at its holder for
    /// nothing (tests and diagnostics).
    [[nodiscard]] uint64_t stray_partials() const { return stray_partials_; }

    /// The digest of the live attempt's request, or nullopt. A timed-out
    /// request kept for late partials is not live.
    [[nodiscard]] std::optional<Digest> live_request() const;

private:
    struct WrappedKeyFile {
        crypto::StorageWrappedDataKey wrapped;
    };
    enum class Target : uint8_t { Current, Replacement };
    struct Attempt {
        Target target = Target::Current;
        crypto::StorageWrappedDataKey wrapped;
        Digest plan_digest{};
        StorageFinalPlan plan;
        StorageUnlockRequestMsg request;
        Digest request_digest{};
        Digest context{};
        std::set<NodeId> asked;
        crypto::StoragePeerBytesMap partials;
        uint64_t started_ms = 0;
        bool verify_only = false;
        /// Set when the attempt timed out: the request stays usable for late
        /// partials until this time (io thread steady clock).
        uint64_t keep_until_ms = 0;
    };

    void set_state(DataKeyState next);
    void create(uint64_t now_ms);
    [[nodiscard]] bool commit_staged();
    void discard_staged();
    void maintain_claim(uint64_t now_ms);
    [[nodiscard]] bool claimed(const crypto::StorageWrappedDataKey& wrapped) const;
    void start_attempt(const StorageFinalPlan& plan, const Digest& plan_digest, bool verify_only,
                       uint64_t now_ms, Target target = Target::Current);
    void finish_attempt();
    /// Unwraps with the attempt's t partials and applies the result. `live`
    /// is false for a request that had already timed out; its failure then
    /// leaves the live attempt and the backoff alone.
    void complete_attempt(Attempt attempt, bool live);
    /// Drops the live attempt and the kept timed-out ones that `which`
    /// selects: the question they asked no longer stands.
    void forget_attempts(const std::function<bool(const Attempt&)>& which);
    void note_stray_partial(const NodeId& holder);
    void fail_attempt();
    [[nodiscard]] bool store(const crypto::StorageWrappedDataKey& wrapped);
    [[nodiscard]] static std::string encode_wrapped(const crypto::StorageWrappedDataKey& wrapped);
    [[nodiscard]] static std::optional<crypto::StorageWrappedDataKey> decode_wrapped(
        const std::string& text);
    [[nodiscard]] bool load();
    [[nodiscard]] std::vector<uint8_t> server_id() const;

    StorageKeyService& service_;
    std::filesystem::path path_;
    std::filesystem::path next_path_;

    mutable std::mutex mutex_;  // guards dek_, state_, verified_, wrapped_, next_*
    std::optional<crypto::SecureBuffer> dek_;
    DataKeyState state_ = DataKeyState::NoStorageKey;
    bool verified_ = false;
    std::optional<crypto::StorageWrappedDataKey> wrapped_;
    std::optional<crypto::SecureBuffer> next_dek_;
    std::optional<crypto::StorageWrappedDataKey> next_wrapped_;
    bool next_verified_ = false;
    /// The staged wrap holds the same DEK under a new S (a rewrap) and is
    /// committed as soon as it verifies; otherwise it is a replacement the
    /// vault commits.
    bool next_rewrap_ = false;

    /// The last claim this server signed and when it was last sent.
    std::optional<StorageWrapClaim> claim_;
    uint64_t claim_sent_ms_ = 0;
    bool create_refused_ = false;

    bool loaded_ = false;
    std::optional<Attempt> attempt_;
    /// Timed-out attempts whose request a holder may still answer, each
    /// until its keep_until_ms. Bounded by time: attempts start at least one
    /// attempt timeout apart and are kept for one holder pending window.
    std::vector<Attempt> late_attempts_;
    /// Requests answered with t partials, each until the time a holder may
    /// still send one more: the surplus partials of a finished round trip
    /// are expected, not stray.
    std::vector<std::pair<Digest, uint64_t>> answered_requests_;
    uint64_t next_attempt_ms_ = 0;
    /// No request before this time: a holder may still hold the previous
    /// request pending and would refuse a new one (PendingBusy).
    uint64_t holders_pending_until_ms_ = 0;
    uint64_t backoff_ms_ = 0;
    uint64_t now_ms_ = 0;
    uint64_t attempts_ = 0;
    uint64_t late_partials_ = 0;
    uint64_t stray_partials_ = 0;
    /// Rate limit of the stray-partial info line, as StorageKeyService::drop()
    /// limits its lines (one per kDropLogWindowMs, repeats counted).
    uint64_t stray_log_window_ms_ = 0;
    uint64_t stray_log_suppressed_ = 0;
    std::function<void(DataKeyState)> on_state_;
};

}  // namespace nexus::security
