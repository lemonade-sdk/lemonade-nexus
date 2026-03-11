#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <fstream>
#include <sstream>

namespace nexus::storage {

namespace fs = std::filesystem;
using json = nlohmann::json;

FileStorageService::FileStorageService(fs::path data_root)
    : data_root_(std::move(data_root)) {}

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
                    max_seq = std::max(max_seq, seq);
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

void FileStorageService::do_ensure_directories() {
    const std::array<fs::path, 6> dirs = {
        data_root_ / "tree" / "nodes",
        data_root_ / "tree" / "deltas",
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
