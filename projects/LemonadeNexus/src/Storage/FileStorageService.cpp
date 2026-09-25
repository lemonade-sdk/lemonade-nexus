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
    : data_root_(std::move(data_root))
    , pool_dir_(std::move(data_root) / "tree" / "retained_deltas") {}

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

bool FileStorageService::atomic_write_synced(const fs::path& path, const std::string& text) {
    fs::create_directories(path.parent_path());
    fs::path tmp = path;
    tmp += ".tmp";
    int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;
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
        return false;
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) {
        fs::remove(tmp, ec);
        return false;
    }
    // The rename itself must be durable, not just the file content.
    return synchronize_directory(path.parent_path());
}

std::optional<std::string> FileStorageService::read_pool_generation() const {
    std::lock_guard lock(mutex_);
    const auto path = pool_dir_ / "_meta.json";
    std::error_code ec;
    if (!fs::exists(path, ec) || ec) return std::nullopt;
    std::ifstream ifs(path);
    if (!ifs) return std::nullopt;
    std::ostringstream ss;
    ss << ifs.rdbuf();
    auto j = json::parse(ss.str(), nullptr, false);
    if (j.is_discarded() || !j.is_object()) return std::nullopt;
    if (!j.contains("generation") || !j["generation"].is_string()) return std::nullopt;
    const auto gen = j["generation"].get<std::string>();
    if (gen.empty() || gen.size() > 128) return std::nullopt;
    return gen;
}

bool FileStorageService::write_pool_generation(const std::string& generation) {
    if (generation.empty() || generation.size() > 128) return false;
    std::lock_guard lock(mutex_);
    json meta;
    meta["generation"] = generation;
    return atomic_write_synced(pool_dir_ / "_meta.json", meta.dump());
}

std::vector<FileStorageService::PoolEntry> FileStorageService::list_pool_entries() const {
    std::lock_guard lock(mutex_);
    std::vector<PoolEntry> entries;
    std::error_code ec;
    if (!fs::exists(pool_dir_, ec) || ec) return entries;
    for (const auto& entry : fs::directory_iterator(pool_dir_, ec)) {
        const auto ext = entry.path().extension().string();
        // Record files are <hash>.json; in-flight writes are <hash>.json.tmp.
        if (ext != ".json" && ext != ".tmp") continue;
        if (entry.path().filename() == "_meta.json") continue;
        PoolEntry pe;
        auto stem = entry.path().stem().string();
        pe.temporary = (ext == ".tmp");
        if (pe.temporary && stem.size() > 5 && stem.ends_with(".json")) {
            stem.resize(stem.size() - 5);
        }
        pe.hash = std::move(stem);
        std::error_code size_ec;
        const auto size = entry.file_size(size_ec);
        pe.size_bytes = size_ec ? 0 : static_cast<uint64_t>(size);
        entries.push_back(std::move(pe));
    }
    return entries;
}

std::optional<std::string> FileStorageService::read_pool_record(const std::string& hash,
                                                                uint64_t max_bytes,
                                                                PoolRead& result) const {
    std::lock_guard lock(mutex_);
    const auto path = pool_record_path(hash);
    if (path.empty()) { result = PoolRead::IoError; return std::nullopt; }
    std::error_code ec;
    if (!fs::exists(path, ec) || ec) { result = PoolRead::Absent; return std::nullopt; }
    std::error_code size_ec;
    const auto size = fs::file_size(path, size_ec);
    if (size_ec) { result = PoolRead::IoError; return std::nullopt; }
    if (static_cast<uint64_t>(size) > max_bytes) {
        result = PoolRead::Oversized;
        return std::nullopt;  // not read at all
    }
    std::ifstream ifs(path, std::ios::binary);
    if (!ifs) { result = PoolRead::IoError; return std::nullopt; }
    std::ostringstream ss;
    ss << ifs.rdbuf();
    if (!ifs) { result = PoolRead::IoError; return std::nullopt; }
    result = PoolRead::Ok;
    return ss.str();
}

bool FileStorageService::write_pool_record(const std::string& hash, const std::string& text) {
    std::lock_guard lock(mutex_);
    const auto path = pool_record_path(hash);
    if (path.empty()) return false;
    return atomic_write_synced(path, text);
}

bool FileStorageService::pool_record_exists(const std::string& hash) const {
    std::lock_guard lock(mutex_);
    const auto path = pool_record_path(hash);
    if (path.empty()) return false;
    std::error_code ec;
    return fs::exists(path, ec) && !ec;
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
