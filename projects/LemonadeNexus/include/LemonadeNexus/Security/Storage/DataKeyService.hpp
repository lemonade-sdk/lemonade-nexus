#pragma once

// This server's data key (DEK), wrapped to the storage public key S (design
// B2, B7, B9, B10). The API Phase 7 uses to encrypt the server's files.
//
// - First use: when a verified current plan exists and no wrapped key is on
//   disk, the service creates a random 32-byte DEK, wraps it to S with
//   StorageThreshold::wrap_data_key, and writes the wrapped key to
//   <directory>/data-key.json. It then runs one unlock through the holders to
//   prove the wrapped key opens (unlock_verified()); Phase 7 deletes no
//   plaintext before that proof (B10).
// - Startup: the DEK is not on disk in the clear. The service sends a
//   StorageUnlockRequest to every holder of the plan whose S the wrapped key
//   names, collects t verified partials, and unwraps the DEK into guarded
//   memory. With fewer it retries with backoff and stays locked: nothing that
//   needs the DEK may run (fail closed).
// - Rotation: when the current plan's S differs from the S the wrapped key
//   names and the DEK is in memory, rewrap() wraps it to the new S. A server
//   that restarted inside the grace period first unlocks under the retiring
//   plan, then rewraps. After the grace period a key wrapped to the retired S
//   cannot unlock (state Retired).
//
// This phase encrypts no file; it only provides the key.

#include <LemonadeNexus/Crypto/SecureBuffer.hpp>
#include <LemonadeNexus/Crypto/StorageThreshold.hpp>
#include <LemonadeNexus/Security/Storage/StorageRecords.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <set>

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
    /// The wrapped DEK names an S whose grace period ended. It cannot unlock.
    Retired,
};

class DataKeyService {
public:
    /// Not owning: `service` must outlive this object.
    explicit DataKeyService(StorageKeyService& service);

    /// Thread-safe.
    [[nodiscard]] DataKeyState state() const;

    /// A copy of the DEK in guarded memory, or nullopt unless Unlocked.
    /// Thread-safe. The caller keeps the copy no longer than it needs it.
    [[nodiscard]] std::optional<crypto::SecureBuffer> data_key() const;

    /// True once an unlock through the holders reproduced the in-memory DEK
    /// from the stored wrapped key (B10 step 2). Thread-safe.
    [[nodiscard]] bool unlock_verified() const;

    /// The S the stored wrapped DEK names, or nullopt when none is stored.
    /// Thread-safe.
    [[nodiscard]] std::optional<StoragePointBytes> wrapped_to() const;

    /// Wraps the in-memory DEK to the current S and replaces the stored
    /// wrapped key. False when the DEK is not in memory, the current plan is
    /// not verified in this run, or the write fails. io thread.
    bool rewrap();

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

    /// The digest of the live attempt's request, or nullopt.
    [[nodiscard]] std::optional<Digest> live_request() const;

private:
    struct WrappedKeyFile {
        crypto::StorageWrappedDataKey wrapped;
    };
    struct Attempt {
        Digest plan_digest{};
        StorageFinalPlan plan;
        StorageUnlockRequestMsg request;
        Digest request_digest{};
        Digest context{};
        std::set<NodeId> asked;
        crypto::StoragePeerBytesMap partials;
        uint64_t started_ms = 0;
        bool verify_only = false;
    };

    void set_state(DataKeyState next);
    void create(uint64_t now_ms);
    void start_attempt(const StorageFinalPlan& plan, const Digest& plan_digest, bool verify_only,
                       uint64_t now_ms);
    void finish_attempt();
    void fail_attempt();
    [[nodiscard]] bool store(const crypto::StorageWrappedDataKey& wrapped);
    [[nodiscard]] bool load();
    [[nodiscard]] std::vector<uint8_t> server_id() const;

    StorageKeyService& service_;
    std::filesystem::path path_;

    mutable std::mutex mutex_;  // guards dek_, state_, verified_, wrapped_
    std::optional<crypto::SecureBuffer> dek_;
    DataKeyState state_ = DataKeyState::NoStorageKey;
    bool verified_ = false;
    std::optional<crypto::StorageWrappedDataKey> wrapped_;

    bool loaded_ = false;
    std::optional<Attempt> attempt_;
    uint64_t next_attempt_ms_ = 0;
    uint64_t backoff_ms_ = 0;
    uint64_t now_ms_ = 0;
    uint64_t attempts_ = 0;
    std::function<void(DataKeyState)> on_state_;
};

}  // namespace nexus::security
