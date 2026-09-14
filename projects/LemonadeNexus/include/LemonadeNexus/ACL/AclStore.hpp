#pragma once

// SQLite persistence for the ACL service.
//
// AclStore is the only component that touches the acl database: it owns the
// sqlite3 handle, opens it (WAL), creates the schema, and runs every
// prepare/bind/step/finalize. ACLService keeps all business logic — grant and
// revoke, delta production and signing, and the AEAD encryption of permission
// values — and talks to the store through this interface.
//
// Database: data/acl.db
// Tables:
//   acl(user_id, resource, perms_enc BLOB, last_modified INTEGER)
//   acl_seen_deltas(delta_id TEXT PRIMARY KEY)   — deduplication
//
// The store is single-connection and not thread-safe: ACLService serializes
// access with its own mutex, so a connection outlives no caller-held lock.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

struct sqlite3;  // forward-declare (C handle)

namespace nexus::acl {

class AclStore {
public:
    explicit AclStore(std::filesystem::path db_path);
    ~AclStore();

    AclStore(const AclStore&) = delete;
    AclStore& operator=(const AclStore&) = delete;

    /// Opens the database (creating parent directories), sets WAL journal
    /// mode, and creates the schema. Safe to call again after close().
    void open();

    /// Closes the database. Safe to call when not open.
    void close();

    /// True when the database is open and usable.
    [[nodiscard]] bool ready() const;

    /// Number of permission rows currently on disk (0 when not open).
    [[nodiscard]] int64_t count() const;

    /// The stored encrypted blob for a (user_id, resource) row, or nullopt
    /// when the row does not exist. The blob is opaque here — decryption
    /// lives in ACLService.
    [[nodiscard]] std::optional<std::vector<uint8_t>>
    load_perms(std::string_view user_id, std::string_view resource) const;

    /// Upserts an encrypted blob for a (user_id, resource) row.
    bool store_perms(std::string_view user_id, std::string_view resource,
                     std::span<const uint8_t> perms_enc, uint64_t last_modified);

    /// Deletes the (user_id, resource) row. A revoke that leaves no
    /// permissions removes the row rather than storing an empty blob.
    bool delete_perms(std::string_view user_id, std::string_view resource);

    /// Whether a gossip delta was already applied (deduplication).
    [[nodiscard]] bool is_delta_seen(std::string_view delta_id) const;

    /// Records a delta as applied. Idempotent.
    bool mark_delta_seen(std::string_view delta_id);

    [[nodiscard]] const std::filesystem::path& db_path() const { return db_path_; }

private:
    std::filesystem::path db_path_;
    sqlite3*              db_{nullptr};
};

} // namespace nexus::acl
