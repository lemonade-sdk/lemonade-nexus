#include <LemonadeNexus/Security/Consensus/ConsensusStore.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <nlohmann/json.hpp>

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace nexus::security {

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

// Crash-atomic durable write, in this exact order: write "<final>.tmp" in the
// same directory, fsync the file descriptor, rename onto the final name, then
// fsync the DIRECTORY so the rename itself is durable. The write path is
// POSIX because ofstream cannot fsync.
//
// A vote may only leave this node after its safety state is on disk. A torn
// write that survives a crash would let the node vote twice.
[[nodiscard]] bool write_durable(const fs::path& final_path, std::string_view payload) {
    fs::path temp_path = final_path;
    temp_path += ".tmp";

    const int fd = ::open(temp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;

    std::size_t written = 0;
    while (written < payload.size()) {
        const ssize_t count =
            ::write(fd, payload.data() + written, payload.size() - written);
        if (count <= 0) {
            ::close(fd);
            return false;
        }
        written += static_cast<std::size_t>(count);
    }
    if (::fsync(fd) != 0) {
        ::close(fd);
        return false;
    }
    if (::close(fd) != 0) return false;

    std::error_code ec;
    fs::rename(temp_path, final_path, ec);
    if (ec) return false;

    const int dir_fd = ::open(final_path.parent_path().c_str(), O_RDONLY);
    if (dir_fd < 0) return false;
    const bool directory_synced = ::fsync(dir_fd) == 0;
    ::close(dir_fd);
    return directory_synced;
}

[[nodiscard]] std::optional<std::string> read_file(const fs::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return std::nullopt;
    std::string content((std::istreambuf_iterator<char>(stream)),
                        std::istreambuf_iterator<char>());
    if (stream.bad()) return std::nullopt;
    return content;
}

// Parses without exceptions; a discarded document means corrupt input.
[[nodiscard]] std::optional<json> parse_file(const fs::path& path) {
    const auto content = read_file(path);
    if (!content) return std::nullopt;
    json document = json::parse(*content, nullptr, false);
    if (document.is_discarded()) return std::nullopt;
    return document;
}

[[nodiscard]] bool read_u64(const json& object, const char* key, uint64_t& out) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_number_unsigned()) return false;
    out = it->get<uint64_t>();
    return true;
}

[[nodiscard]] bool read_digest(const json& object, const char* key, Digest& out) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_string()) return false;
    std::vector<uint8_t> decoded;
    try {
        decoded = crypto::from_base64(it->get<std::string>());
    } catch (...) {
        return false;
    }
    if (decoded.size() != out.size()) return false;
    std::copy(decoded.begin(), decoded.end(), out.begin());
    return true;
}

[[nodiscard]] json commit_to_json(const ConsensusCommit& commit) {
    return json{{"epoch", commit.epoch},
                {"height", commit.height},
                {"view", commit.view},
                {"proposal_digest", crypto::to_base64(commit.proposal_digest)},
                {"proposed_state_root", crypto::to_base64(commit.proposed_state_root)},
                {"qc_digest", crypto::to_base64(commit.qc_digest)}};
}

[[nodiscard]] std::optional<ConsensusCommit> commit_from_json(const json& document) {
    if (!document.is_object()) return std::nullopt;
    ConsensusCommit commit{};
    if (!read_u64(document, "epoch", commit.epoch)) return std::nullopt;
    if (!read_u64(document, "height", commit.height)) return std::nullopt;
    if (!read_u64(document, "view", commit.view)) return std::nullopt;
    if (!read_digest(document, "proposal_digest", commit.proposal_digest)) return std::nullopt;
    if (!read_digest(document, "proposed_state_root", commit.proposed_state_root)) {
        return std::nullopt;
    }
    if (!read_digest(document, "qc_digest", commit.qc_digest)) return std::nullopt;
    return commit;
}

}  // namespace

FileConsensusStore::FileConsensusStore(fs::path directory) : directory_(std::move(directory)) {
    fs::create_directories(directory_);
}

fs::path FileConsensusStore::safety_path(EpochId epoch) const {
    return directory_ / ("hotstuff-safety-" + std::to_string(epoch) + ".json");
}

fs::path FileConsensusStore::commit_path(EpochId epoch) const {
    return directory_ / ("hotstuff-commit-" + std::to_string(epoch) + ".json");
}

bool FileConsensusStore::store_before_vote(const HotStuffState& state) {
    // Monotonicity guard. The stored values may only stay or grow.
    const auto existing = load(state.epoch);
    if (const auto* result = std::get_if<LoadResult>(&existing)) {
        // Corrupt state is never overwritten as if it were fresh: it may hide
        // a vote this node already cast.
        if (*result == LoadResult::Corrupt) return false;
    } else {
        const auto& prior = std::get<HotStuffState>(existing);
        if (state.epoch != prior.epoch) return false;
        if (state.last_voted_view < prior.last_voted_view) return false;
        if (state.high_qc.view < prior.high_qc.view) return false;
        if (state.locked_qc.view < prior.locked_qc.view) return false;
    }
    return write_durable(safety_path(state.epoch), hotstuff_state_to_json(state).dump());
}

std::variant<HotStuffState, IConsensusStore::LoadResult> FileConsensusStore::load(
    EpochId epoch) const {
    const auto path = safety_path(epoch);

    std::error_code ec;
    const bool present = fs::exists(path, ec);
    // A stat failure is not proof of absence.
    if (ec) return LoadResult::Corrupt;
    if (!present) return LoadResult::Absent;

    // Only the final name is ever opened. A leftover "<final>.tmp" from an
    // interrupted write is simply ignored — the rename discipline means it
    // never held state this node relied on.
    const auto document = parse_file(path);
    if (!document) return LoadResult::Corrupt;
    auto state = hotstuff_state_from_json(*document);
    if (!state) return LoadResult::Corrupt;
    // A safety file that names another epoch is a misplaced or rolled disk.
    if (state->epoch != epoch) return LoadResult::Corrupt;
    return std::move(*state);
}

bool FileConsensusStore::store_commit(const ConsensusCommit& commit) {
    return write_durable(commit_path(commit.epoch), commit_to_json(commit).dump());
}

std::optional<ConsensusCommit> FileConsensusStore::latest_commit(EpochId epoch) const {
    const auto path = commit_path(epoch);
    std::error_code ec;
    if (!fs::exists(path, ec) || ec) return std::nullopt;
    const auto document = parse_file(path);
    if (!document) return std::nullopt;
    auto commit = commit_from_json(*document);
    if (!commit || commit->epoch != epoch) return std::nullopt;
    return commit;
}

}  // namespace nexus::security
