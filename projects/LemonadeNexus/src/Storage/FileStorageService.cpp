#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <unistd.h>
#endif

namespace nexus::storage {

namespace fs = std::filesystem;
using json = nlohmann::json;

FileStorageService::FileStorageService(fs::path data_root)
    // Copy, do not move: members initialize in declaration order, so the
    // second initializer would otherwise use a moved-from path (unspecified
    // state — empty on libc++, which silently makes pool_dir_ CWD-relative).
    : data_root_(data_root)
    , pool_dir_(data_root / "tree" / "retained_deltas") {}

void FileStorageService::on_start() {
    do_ensure_directories();

    // Scan existing deltas to find next sequence number
    const auto deltas_dir = data_root_ / "tree" / "deltas";
    uint64_t max_seq = 0;
    if (fs::exists(deltas_dir)) {
        for (const auto& entry : fs::directory_iterator(deltas_dir)) {
            if (entry.path().extension() == ".json") {
                try {
                    const auto seq = std::stoull(entry.path().stem().string());
                    max_seq = std::max(max_seq, static_cast<uint64_t>(seq));
                } catch (...) {
                    // skip non-numeric filenames
                }
            }
        }
    }
    next_delta_seq_ = max_seq + 1;

    spdlog::info("[{}] initialized at '{}' (next delta seq: {})",
                  name(), data_root_.string(), next_delta_seq_);
}

void FileStorageService::on_stop() {
    spdlog::info("[{}] stopped", name());
}

// --- Tree nodes ---

bool FileStorageService::do_write_node(std::string_view node_id, const SignedEnvelope& envelope) {
    std::lock_guard lock(mutex_);
    try {
        const auto path = node_path(node_id);
        std::ofstream ofs(path, std::ios::trunc);
        if (!ofs) return false;
        ofs << envelope_to_json(envelope);
        return ofs.good();
    } catch (const std::exception& e) {
        spdlog::error("[{}] write_node '{}' failed: {}", name(), node_id, e.what());
        return false;
    }
}

std::optional<SignedEnvelope> FileStorageService::do_read_node(std::string_view node_id) const {
    std::lock_guard lock(mutex_);
    try {
        const auto path = node_path(node_id);
        if (!fs::exists(path)) return std::nullopt;

        std::ifstream ifs(path);
        if (!ifs) return std::nullopt;

        std::ostringstream ss;
        ss << ifs.rdbuf();
        return json_to_envelope(ss.str());
    } catch (const std::exception& e) {
        spdlog::error("[{}] read_node '{}' failed: {}", name(), node_id, e.what());
        return std::nullopt;
    }
}

bool FileStorageService::do_delete_node(std::string_view node_id) {
    std::lock_guard lock(mutex_);
    try {
        return fs::remove(node_path(node_id));
    } catch (const std::exception& e) {
        spdlog::error("[{}] delete_node '{}' failed: {}", name(), node_id, e.what());
        return false;
    }
}

std::vector<std::string> FileStorageService::do_list_nodes() const {
    std::lock_guard lock(mutex_);
    std::vector<std::string> nodes;
    const auto nodes_dir = data_root_ / "tree" / "nodes";
    if (!fs::exists(nodes_dir)) return nodes;

    for (const auto& entry : fs::directory_iterator(nodes_dir)) {
        if (entry.path().extension() == ".json") {
            nodes.push_back(entry.path().stem().string());
        }
    }
    std::sort(nodes.begin(), nodes.end());
    return nodes;
}

// --- Delta log ---

uint64_t FileStorageService::do_append_delta(const SignedDelta& delta) {
    std::lock_guard lock(mutex_);
    const auto seq = next_delta_seq_;
    SignedDelta stamped = delta;
    stamped.sequence = seq;

    try {
        const auto path = delta_path(seq);
        std::ofstream ofs(path, std::ios::trunc);
        if (!ofs) {
            spdlog::error("[{}] failed to write delta {}", name(), seq);
            return 0;
        }
        ofs << delta_to_json(stamped);
        if (!ofs.good()) {
            spdlog::error("[{}] delta {} write error", name(), seq);
            return 0;
        }
        // Only advance sequence after successful write
        ++next_delta_seq_;
        return seq;
    } catch (const std::exception& e) {
        spdlog::error("[{}] append_delta failed: {}", name(), e.what());
        return 0;
    }
}

std::optional<SignedDelta> FileStorageService::do_read_delta(uint64_t seq) const {
    std::lock_guard lock(mutex_);
    try {
        const auto path = delta_path(seq);
        if (!fs::exists(path)) return std::nullopt;

        std::ifstream ifs(path);
        if (!ifs) return std::nullopt;

        std::ostringstream ss;
        ss << ifs.rdbuf();
        return json_to_delta(ss.str());
    } catch (const std::exception& e) {
        spdlog::error("[{}] read_delta {} failed: {}", name(), seq, e.what());
        return std::nullopt;
    }
}

uint64_t FileStorageService::do_latest_delta_seq() const {
    std::lock_guard lock(mutex_);
    return next_delta_seq_ > 0 ? next_delta_seq_ - 1 : 0;
}

std::vector<SignedDelta> FileStorageService::do_read_deltas_since(uint64_t seq) const {
    std::lock_guard lock(mutex_);
    std::vector<SignedDelta> deltas;
    for (uint64_t s = seq + 1; s < next_delta_seq_; ++s) {
        const auto path = delta_path(s);
        if (!fs::exists(path)) continue;

        std::ifstream ifs(path);
        if (!ifs) continue;

        std::ostringstream ss;
        ss << ifs.rdbuf();
        auto d = json_to_delta(ss.str());
        if (d) {
            deltas.push_back(std::move(*d));
        }
    }
    return deltas;
}

// --- Generic file storage ---

bool FileStorageService::do_write_file(std::string_view category, std::string_view file_name,
                                         const SignedEnvelope& envelope) {
    std::lock_guard lock(mutex_);
    try {
        const auto path = file_path(category, file_name);
        fs::create_directories(path.parent_path());
        std::ofstream ofs(path, std::ios::trunc);
        if (!ofs) return false;
        ofs << envelope_to_json(envelope);
        return ofs.good();
    } catch (const std::exception& e) {
        spdlog::error("[{}] write_file '{}/{}' failed: {}", name(), category, file_name, e.what());
        return false;
    }
}

std::optional<SignedEnvelope> FileStorageService::do_read_file(std::string_view category,
                                                                std::string_view file_name) const {
    std::lock_guard lock(mutex_);
    try {
        const auto path = file_path(category, file_name);
        if (!fs::exists(path)) return std::nullopt;

        std::ifstream ifs(path);
        if (!ifs) return std::nullopt;

        std::ostringstream ss;
        ss << ifs.rdbuf();
        return json_to_envelope(ss.str());
    } catch (const std::exception& e) {
        spdlog::error("[{}] read_file '{}/{}' failed: {}", name(), category, file_name, e.what());
        return std::nullopt;
    }
}

bool FileStorageService::do_delete_file(std::string_view category, std::string_view file_name) {
    std::lock_guard lock(mutex_);
    try {
        return fs::remove(file_path(category, file_name));
    } catch (const std::exception& e) {
        spdlog::error("[{}] delete_file '{}/{}' failed: {}", name(), category, file_name, e.what());
        return false;
    }
}

std::vector<std::string> FileStorageService::do_list_files(std::string_view category) const {
    std::lock_guard lock(mutex_);
    std::vector<std::string> files;
    try {
        if (!is_safe_path_component(category)) {
            throw std::runtime_error("invalid category: path traversal rejected");
        }
        const auto dir = data_root_ / std::string(category);
        if (!fs::exists(dir)) return files;
        for (const auto& entry : fs::directory_iterator(dir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".json") {
                files.push_back(entry.path().stem().string());
            }
        }
        std::sort(files.begin(), files.end());
    } catch (const std::exception& e) {
        spdlog::error("[{}] list_files '{}' failed: {}", name(), category, e.what());
    }
    return files;
}

void FileStorageService::do_ensure_directories() {
    const std::array<fs::path, 7> dirs = {
        data_root_ / "tree" / "nodes",
        data_root_ / "tree" / "deltas",
        pool_dir_,
        data_root_ / "identity",
        data_root_ / "credentials",
        data_root_ / "ipam",
        data_root_ / "certs",
    };
    for (const auto& dir : dirs) {
        fs::create_directories(dir);
    }
}

// --- Path safety ---

bool FileStorageService::is_safe_path_component(std::string_view component) {
    if (component.empty()) return false;
    // Reject absolute paths, traversal, and null bytes
    if (component.find("..") != std::string_view::npos) return false;
    if (component.find('/') != std::string_view::npos) return false;
    if (component.find('\\') != std::string_view::npos) return false;
    if (component.find('\0') != std::string_view::npos) return false;
    return true;
}

// --- Path helpers ---

fs::path FileStorageService::node_path(std::string_view node_id) const {
    if (!is_safe_path_component(node_id)) {
        throw std::runtime_error("invalid node_id: path traversal rejected");
    }
    return data_root_ / "tree" / "nodes" / (std::string(node_id) + ".json");
}

fs::path FileStorageService::delta_path(uint64_t seq) const {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%06llu", static_cast<unsigned long long>(seq));
    return data_root_ / "tree" / "deltas" / (std::string(buf) + ".json");
}

fs::path FileStorageService::file_path(std::string_view category, std::string_view file_name) const {
    if (!is_safe_path_component(category)) {
        throw std::runtime_error("invalid category: path traversal rejected");
    }
    if (!is_safe_path_component(file_name)) {
        throw std::runtime_error("invalid file_name: path traversal rejected");
    }
    return data_root_ / std::string(category) / std::string(file_name);
}

fs::path FileStorageService::pool_record_path(std::string_view hash) const {
    // Record identifiers are hex SHA-256 digests. Anything else is refused:
    // the caller computes the identifier, but a path-shaped value must not
    // reach the filesystem through it.
    if (hash.size() != 64) return {};
    for (char c : hash) {
        const bool hexdigit = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!hexdigit) return {};
    }
    return pool_dir_ / (std::string(hash) + ".json");
}

// --- Delta transfer pool primitives ---

bool FileStorageService::synchronize_file(int fd) {
#ifdef _WIN32
    HANDLE handle = reinterpret_cast<HANDLE>(_get_osfhandle(fd));
    if (handle == INVALID_HANDLE_VALUE) return false;
    return FlushFileBuffers(handle) != FALSE;
#else
    return ::fsync(fd) == 0;
#endif
}

bool FileStorageService::synchronize_directory(const fs::path& path) {
#ifdef _WIN32
    // No directory sync primitive; the rename is the visibility boundary.
    (void)path;
    return true;
#else
    int dfd = ::open(path.c_str(), O_RDONLY | O_DIRECTORY);
    if (dfd < 0) return false;
    const int rc = ::fsync(dfd);
    ::close(dfd);
    return rc == 0;
#endif
}

FileStorageService::AtomicWrite FileStorageService::atomic_write_synced(
        const fs::path& path, const std::string& text, bool force_dirsync_fail) {
    fs::create_directories(path.parent_path());
    fs::path tmp = path;
    tmp += ".tmp";
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return AtomicWrite::Failed;
    bool ok = false;
    {
        const auto* p = text.data();
        std::size_t remaining = text.size();
        while (remaining > 0) {
#ifdef _WIN32
            const auto n = static_cast<std::size_t>(::WriteFile(
                reinterpret_cast<HANDLE>(_get_osfhandle(fd)), p, static_cast<DWORD>(remaining),
                nullptr, nullptr));
            if (n == 0) break;
            p += n; remaining -= n;
#else
            const auto n = ::write(fd, p, remaining);
            if (n <= 0) break;
            p += n; remaining -= static_cast<std::size_t>(n);
#endif
        }
        ok = remaining == 0;
    }
    if (ok) ok = synchronize_file(fd);
    ::close(fd);
    if (!ok) {
        std::error_code ec;
        fs::remove(tmp, ec);
        return AtomicWrite::Failed;
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) {
        fs::remove(tmp, ec);
        return AtomicWrite::Failed;
    }
    // The rename itself must be durable, not just the file content. A
    // failed directory sync after a successful rename is an UNCERTAIN
    // outcome: the destination exists, but its durability is not confirmed.
    if (force_dirsync_fail) return AtomicWrite::Uncertain;
    return synchronize_directory(path.parent_path()) ? AtomicWrite::Ok
                                                     : AtomicWrite::Uncertain;
}

// The generation metadata is small by construction; bound the read so a
// hostile or corrupted meta file cannot force an unbounded allocation.
namespace { constexpr std::uint64_t kPoolMetaMaxBytes = 4096; }

// Read at most max_bytes from path, enforcing the limit DURING the read.
// A size inspection alone is not sufficient: the file may grow between the
// inspection and the read, so the reader stops at the limit and reports
// any further data instead of allocating it. On success, out holds the
// complete file. On failure, oversize distinguishes "holds more than
// max_bytes" from an I/O error.
bool bounded_read_file(const fs::path& path, std::uint64_t max_bytes,
                       std::string& out, bool& oversize) {
    oversize = false;
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) return false;
    char buf[8192];
    std::uint64_t total = 0;
    for (;;) {
        const std::uint64_t room = total < max_bytes ? max_bytes - total : 0;
        const std::size_t want = room >= sizeof(buf)
                                     ? sizeof(buf)
                                     : static_cast<std::size_t>(room) + 1;
        ifs.read(buf, static_cast<std::streamsize>(want));
        const auto got = static_cast<std::uint64_t>(ifs.gcount());
        if (got > room) { oversize = true; return false; }
        total += got;
        out.append(buf, got);
        if (got < want) {
            // A short read ends the read at a clean EOF; anything else is
            // an I/O error.
            if (ifs.bad() || (got > 0 && !ifs.eof())) return false;
            return true;
        }
    }
}

enum class PathEntryKind { Absent, Regular, Other, IoError };

PathEntryKind path_entry_kind(const fs::path& path) {
    std::error_code ec;
    const auto status = fs::symlink_status(path, ec);
    if (ec) {
        return ec == std::errc::no_such_file_or_directory
                   ? PathEntryKind::Absent
                   : PathEntryKind::IoError;
    }
    if (status.type() == fs::file_type::not_found) return PathEntryKind::Absent;
    return fs::is_regular_file(status) ? PathEntryKind::Regular
                                       : PathEntryKind::Other;
}

std::optional<std::string> FileStorageService::read_pool_generation(PoolMetaRead& result) const {
    std::lock_guard lock(mutex_);
    const auto path = pool_dir_ / "_meta.json";
    const auto state = path_entry_kind(path);
    if (state == PathEntryKind::Absent) {
        result = PoolMetaRead::Absent;
        return std::nullopt;
    }
    if (state != PathEntryKind::Regular) {
        result = PoolMetaRead::IoError;
        return std::nullopt;
    }
    std::error_code size_ec;
    const auto size = fs::file_size(path, size_ec);
    if (size_ec) { result = PoolMetaRead::IoError; return std::nullopt; }
    if (static_cast<std::uint64_t>(size) > kPoolMetaMaxBytes) {
        result = PoolMetaRead::IoError;
        return std::nullopt;
    }
    // Bounded during the read: growth between the size inspection and the
    // read is an I/O error, not an unbounded allocation.
    bool oversize = false;
    std::string text;
    if (!bounded_read_file(path, kPoolMetaMaxBytes, text, oversize) || oversize) {
        result = PoolMetaRead::IoError;
        return std::nullopt;
    }
    auto j = json::parse(text, nullptr, false);
    if (j.is_discarded() || !j.is_object()) { result = PoolMetaRead::IoError; return std::nullopt; }
    if (!j.contains("generation") || !j["generation"].is_string()) {
        result = PoolMetaRead::IoError;
        return std::nullopt;
    }
    const auto gen = j["generation"].get<std::string>();
    if (gen.empty() || gen.size() > 128) { result = PoolMetaRead::IoError; return std::nullopt; }
    result = PoolMetaRead::Ok;
    return gen;
}

bool FileStorageService::write_pool_generation(const std::string& generation) {
    if (generation.empty() || generation.size() > 128) return false;
    std::lock_guard lock(mutex_);
    json meta;
    meta["generation"] = generation;
    // An uncertain meta write is not a confirmed persist: refuse rather
    // than claim a generation the pool may not actually carry.
    return atomic_write_synced(pool_dir_ / "_meta.json", meta.dump()) == AtomicWrite::Ok;
}

// The pool holds at most kPoolMaxRecords record files plus their temp
// siblings; the enumeration is bounded WHILE collecting, not after the
// vector is built, so a hostile or corrupted directory cannot force an
// unbounded allocation.
namespace { constexpr std::size_t kPoolMaxListEntries = 200000; }

FileStorageService::PoolList FileStorageService::list_pool_entries() const {
    std::lock_guard lock(mutex_);
    PoolList list;
    std::error_code ec;
    if (!fs::exists(pool_dir_, ec)) {
        if (ec) { list.error = true; return list; }
        return list;  // no pool directory: a complete, empty inventory
    }
    const auto cap = test_pool_list_cap_ ? test_pool_list_cap_ : kPoolMaxListEntries;
    fs::directory_iterator it(pool_dir_, ec);
    if (ec) { list.error = true; return list; }
    const fs::directory_iterator end;
    std::size_t scanned = 0;
    while (it != end) {
        if (scanned >= cap) { list.truncated = true; return list; }
        ++scanned;
        const auto& entry = *it;
        const auto filename = entry.path().filename().string();
        if (filename != "_meta.json") {
            PoolEntry pe;
            pe.hash = filename;
            if (filename.ends_with(".json.tmp")) {
                pe.hash.resize(pe.hash.size() - 9);
                pe.temporary = true;
            } else if (filename.ends_with(".json")) {
                pe.hash.resize(pe.hash.size() - 5);
                pe.record = true;
            }
            std::error_code status_ec;
            const auto status = entry.symlink_status(status_ec);
            if (status_ec || !fs::is_regular_file(status)) {
                list.error = true;
                return list;
            }
            std::error_code size_ec;
            const auto size = entry.file_size(size_ec);
            if (size_ec) { list.error = true; return list; }
            pe.size_bytes = static_cast<uint64_t>(size);
            list.entries.push_back(std::move(pe));
        }
        std::error_code step_ec;
        it.increment(step_ec);
        if (step_ec) { list.error = true; return list; }
    }
    return list;
}

std::optional<std::string> FileStorageService::read_pool_record(const std::string& hash,
                                                                uint64_t max_bytes,
                                                                PoolRead& result) const {
    std::lock_guard lock(mutex_);
    const auto path = pool_record_path(hash);
    if (path.empty()) { result = PoolRead::IoError; return std::nullopt; }
    if (test_remove_record_ == hash) {
        test_remove_record_.clear();
        std::error_code remove_ec;
        fs::remove(path, remove_ec);
        if (remove_ec) { result = PoolRead::IoError; return std::nullopt; }
    }
    const auto state = path_entry_kind(path);
    if (state == PathEntryKind::Absent) {
        result = PoolRead::Absent;
        return std::nullopt;
    }
    if (state != PathEntryKind::Regular) {
        result = PoolRead::IoError;
        return std::nullopt;
    }
    std::error_code size_ec;
    const auto size = fs::file_size(path, size_ec);
    if (size_ec) { result = PoolRead::IoError; return std::nullopt; }
    if (static_cast<uint64_t>(size) > max_bytes) {
        result = PoolRead::Oversized;
        return std::nullopt;  // not read at all
    }
    if (test_grow_record_ == hash) {
        // Test seam: a concurrent writer appends between the inspection and
        // the read. The bounded read must enforce the limit itself.
        test_grow_record_.clear();
        std::ofstream ofs(path, std::ios::binary | std::ios::app);
        ofs << std::string(test_grow_record_bytes_, 'x');
        test_grow_record_bytes_ = 0;
        if (!ofs) { result = PoolRead::IoError; return std::nullopt; }
    }
    // Bounded during the read: growth past the inspected size is not an
    // oversize file, the inspected state is no longer the state on disk.
    bool oversize = false;
    std::string text;
    if (!bounded_read_file(path, max_bytes, text, oversize)) {
        result = PoolRead::IoError;
        return std::nullopt;
    }
    result = PoolRead::Ok;
    return text;
}

FileStorageService::PoolWrite FileStorageService::write_pool_record(const std::string& hash,
                                                                    const std::string& text) {
    std::lock_guard lock(mutex_);
    const auto path = pool_record_path(hash);
    if (path.empty()) return PoolWrite::Failed;
    bool force_dirsync_fail = false;
    if (test_fail_next_pool_dirsync_ > 0) {
        test_fail_next_pool_dirsync_--;
        force_dirsync_fail = true;
    }
    const auto result = atomic_write_synced(path, text, force_dirsync_fail);
    return result == AtomicWrite::Ok     ? PoolWrite::Ok
         : result == AtomicWrite::Uncertain ? PoolWrite::Uncertain
                                            : PoolWrite::Failed;
}

void FileStorageService::test_arm_pool_dirsync_failure() {
    std::lock_guard lock(mutex_);
    test_fail_next_pool_dirsync_ = 1;
}

bool FileStorageService::sync_pool_directory() {
    std::lock_guard lock(mutex_);
    std::error_code ec;
    if (!fs::exists(pool_dir_, ec) || ec) return false;
    if (test_fail_next_pool_sync_ > 0) {
        test_fail_next_pool_sync_--;
        return false;
    }
    return synchronize_directory(pool_dir_);
}

void FileStorageService::test_arm_pool_sync_failure() {
    std::lock_guard lock(mutex_);
    test_fail_next_pool_sync_ = 1;
}

void FileStorageService::test_arm_pool_record_growth(const std::string& hash,
                                                     std::size_t bytes) {
    std::lock_guard lock(mutex_);
    test_grow_record_ = hash;
    test_grow_record_bytes_ = bytes;
}

void FileStorageService::test_arm_pool_record_state_failure(const std::string& hash) {
    std::lock_guard lock(mutex_);
    test_fail_record_state_ = hash;
}

void FileStorageService::test_arm_pool_record_disappearance(const std::string& hash) {
    std::lock_guard lock(mutex_);
    test_remove_record_ = hash;
}

void FileStorageService::test_set_pool_list_cap(std::size_t cap) {
    std::lock_guard lock(mutex_);
    test_pool_list_cap_ = cap;
}

FileStorageService::PoolFileState
FileStorageService::pool_record_state(const std::string& hash) const {
    std::lock_guard lock(mutex_);
    const auto path = pool_record_path(hash);
    if (path.empty()) return PoolFileState::IoError;
    if (test_fail_record_state_ == hash) {
        test_fail_record_state_.clear();
        return PoolFileState::IoError;
    }
    switch (path_entry_kind(path)) {
        case PathEntryKind::Absent:  return PoolFileState::Absent;
        case PathEntryKind::IoError: return PoolFileState::IoError;
        case PathEntryKind::Regular:
        case PathEntryKind::Other:   return PoolFileState::Present;
    }
    return PoolFileState::IoError;
}

// --- RetainedDelta serialization ---

std::string FileStorageService::RetainedDelta::to_json() const {
    json j;
    j["version"]        = 1;
    j["position"]       = position;
    j["record_hash"]    = record_hash;
    j["operation"]      = operation;
    j["target_node_id"] = target_node_id;
    j["node_data"]      = json::parse(data, nullptr, false);
    j["signer_pubkey"]  = signer_pubkey;
    j["signature"]      = signature;
    j["timestamp"]      = timestamp;
    return j.dump();
}

std::optional<FileStorageService::RetainedDelta> FileStorageService::RetainedDelta::from_json(
    std::string_view text) {
    auto j = json::parse(text, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return std::nullopt;
    if (!j.contains("operation") || !j["operation"].is_string() ||
        !j.contains("target_node_id") || !j["target_node_id"].is_string() ||
        !j.contains("node_data") || !j["node_data"].is_object() ||
        !j.contains("signer_pubkey") || !j["signer_pubkey"].is_string() ||
        !j.contains("signature") || !j["signature"].is_string() ||
        !j.contains("timestamp") || !j["timestamp"].is_number_unsigned() ||
        !j.contains("position") || !j["position"].is_number_unsigned() ||
        !j.contains("record_hash") || !j["record_hash"].is_string()) {
        return std::nullopt;
    }
    RetainedDelta r;
    r.position       = j["position"].get<uint64_t>();
    r.record_hash    = j["record_hash"].get<std::string>();
    r.operation      = j["operation"].get<std::string>();
    r.target_node_id = j["target_node_id"].get<std::string>();
    r.data           = j["node_data"].dump();
    r.signer_pubkey  = j["signer_pubkey"].get<std::string>();
    r.signature      = j["signature"].get<std::string>();
    r.timestamp      = j["timestamp"].get<uint64_t>();
    return r;
}

// --- JSON serialization ---

std::string FileStorageService::envelope_to_json(const SignedEnvelope& env) {
    json j;
    j["version"]       = env.version;
    j["type"]          = env.type;
    j["data"]          = json::parse(env.data, nullptr, false);
    j["signer_pubkey"] = env.signer_pubkey;
    j["signature"]     = env.signature;
    j["timestamp"]     = env.timestamp;
    return j.dump(2);
}

std::optional<SignedEnvelope> FileStorageService::json_to_envelope(std::string_view json_str) {
    auto j = json::parse(json_str, nullptr, false);
    if (j.is_discarded()) return std::nullopt;

    SignedEnvelope env;
    env.version       = j.value("version", 1u);
    env.type          = j.value("type", "");
    env.signer_pubkey = j.value("signer_pubkey", "");
    env.signature     = j.value("signature", "");
    env.timestamp     = j.value("timestamp", uint64_t{0});

    // Store data as JSON string
    if (j.contains("data")) {
        env.data = j["data"].dump();
    }
    return env;
}

std::string FileStorageService::delta_to_json(const SignedDelta& delta) {
    json j;
    j["version"]             = 1;
    j["type"]                = "delta";
    j["sequence"]            = delta.sequence;
    j["operation"]           = delta.operation;
    j["target_node_id"]      = delta.target_node_id;
    j["data"]                = json::parse(delta.data, nullptr, false);
    j["signer_pubkey"]       = delta.signer_pubkey;
    j["required_permission"] = delta.required_permission;
    j["signature"]           = delta.signature;
    j["timestamp"]           = delta.timestamp;
    return j.dump(2);
}

std::optional<SignedDelta> FileStorageService::json_to_delta(std::string_view json_str) {
    auto j = json::parse(json_str, nullptr, false);
    if (j.is_discarded()) return std::nullopt;

    SignedDelta delta;
    delta.sequence            = j.value("sequence", uint64_t{0});
    delta.operation           = j.value("operation", "");
    delta.target_node_id      = j.value("target_node_id", "");
    delta.signer_pubkey       = j.value("signer_pubkey", "");
    delta.required_permission = j.value("required_permission", "");
    delta.signature           = j.value("signature", "");
    delta.timestamp           = j.value("timestamp", uint64_t{0});

    if (j.contains("data")) {
        delta.data = j["data"].dump();
    }
    return delta;
}

} // namespace nexus::storage
