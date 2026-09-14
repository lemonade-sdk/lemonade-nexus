#include <LemonadeNexus/ACL/AclStore.hpp>

#include <spdlog/spdlog.h>
#include <sqlite3.h>

#include <cstring>

namespace nexus::acl {

static constexpr std::string_view kStoreName = "AclStore";

AclStore::AclStore(std::filesystem::path db_path)
    : db_path_{std::move(db_path)}
{
}

AclStore::~AclStore() {
    close();
}

void AclStore::open() {
    if (db_) return;

    auto parent = db_path_.parent_path();
    if (!parent.empty()) {
        std::filesystem::create_directories(parent);
    }

    int rc = sqlite3_open(db_path_.string().c_str(), &db_);
    if (rc != SQLITE_OK) {
        spdlog::error("[{}] failed to open database {}: {}",
                      kStoreName, db_path_.string(), sqlite3_errmsg(db_));
        sqlite3_close(db_);
        db_ = nullptr;
        return;
    }

    sqlite3_exec(db_, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);

    // ACL table with last_modified for conflict resolution
    const char* create_acl =
        "CREATE TABLE IF NOT EXISTS acl ("
        "  user_id TEXT NOT NULL,"
        "  resource TEXT NOT NULL,"
        "  perms_enc BLOB NOT NULL,"
        "  last_modified INTEGER NOT NULL DEFAULT 0,"
        "  PRIMARY KEY (user_id, resource)"
        ");";

    // Seen deltas for deduplication
    const char* create_seen =
        "CREATE TABLE IF NOT EXISTS acl_seen_deltas ("
        "  delta_id TEXT PRIMARY KEY"
        ");";

    char* err_msg = nullptr;
    rc = sqlite3_exec(db_, create_acl, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("[{}] failed to create acl table: {}", kStoreName, err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return;
    }
    rc = sqlite3_exec(db_, create_seen, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        spdlog::error("[{}] failed to create seen deltas table: {}", kStoreName, err_msg ? err_msg : "unknown");
        sqlite3_free(err_msg);
        return;
    }
}

void AclStore::close() {
    if (db_) {
        sqlite3_close(db_);
        db_ = nullptr;
    }
}

bool AclStore::ready() const {
    return db_ != nullptr;
}

int64_t AclStore::count() const {
    if (!db_) return 0;

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, "SELECT COUNT(*) FROM acl;", -1, &stmt, nullptr);
    int64_t result = 0;
    if (rc == SQLITE_OK && sqlite3_step(stmt) == SQLITE_ROW) {
        result = sqlite3_column_int64(stmt, 0);
    }
    sqlite3_finalize(stmt);
    return result;
}

std::optional<std::vector<uint8_t>> AclStore::load_perms(std::string_view user_id,
                                                         std::string_view resource) const {
    if (!db_) return std::nullopt;

    const char* sql = "SELECT perms_enc FROM acl WHERE user_id = ? AND resource = ?;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return std::nullopt;

    sqlite3_bind_text(stmt, 1, user_id.data(), static_cast<int>(user_id.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, resource.data(), static_cast<int>(resource.size()), SQLITE_STATIC);

    std::optional<std::vector<uint8_t>> result;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        auto blob_ptr = static_cast<const uint8_t*>(sqlite3_column_blob(stmt, 0));
        auto blob_len = sqlite3_column_bytes(stmt, 0);
        if (blob_ptr && blob_len > 0) {
            result = std::vector<uint8_t>(blob_ptr, blob_ptr + blob_len);
        }
    }
    sqlite3_finalize(stmt);
    return result;
}

bool AclStore::store_perms(std::string_view user_id, std::string_view resource,
                           std::span<const uint8_t> perms_enc, uint64_t last_modified) {
    if (!db_) return false;

    const char* sql =
        "INSERT INTO acl (user_id, resource, perms_enc, last_modified) VALUES (?, ?, ?, ?)"
        " ON CONFLICT(user_id, resource) DO UPDATE SET perms_enc = excluded.perms_enc,"
        " last_modified = excluded.last_modified;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, user_id.data(), static_cast<int>(user_id.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, resource.data(), static_cast<int>(resource.size()), SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 3, perms_enc.data(), static_cast<int>(perms_enc.size()), SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 4, static_cast<int64_t>(last_modified));

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool AclStore::delete_perms(std::string_view user_id, std::string_view resource) {
    if (!db_) return false;

    const char* sql = "DELETE FROM acl WHERE user_id = ? AND resource = ?;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, user_id.data(), static_cast<int>(user_id.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, resource.data(), static_cast<int>(resource.size()), SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool AclStore::is_delta_seen(std::string_view delta_id) const {
    if (!db_) return false;

    const char* sql = "SELECT 1 FROM acl_seen_deltas WHERE delta_id = ?;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, delta_id.data(), static_cast<int>(delta_id.size()), SQLITE_STATIC);
    bool seen = (sqlite3_step(stmt) == SQLITE_ROW);
    sqlite3_finalize(stmt);
    return seen;
}

bool AclStore::mark_delta_seen(std::string_view delta_id) {
    if (!db_) return false;

    const char* sql = "INSERT OR IGNORE INTO acl_seen_deltas (delta_id) VALUES (?);";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, delta_id.data(), static_cast<int>(delta_id.size()), SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

} // namespace nexus::acl
