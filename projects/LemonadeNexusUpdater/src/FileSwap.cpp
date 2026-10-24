#include <LemonadeNexusUpdater/FileSwap.hpp>

#include <LemonadeNexusUpdater/ReleaseVerifier.hpp>

#include <LemonadeNexus/Security/DurableWrite.hpp>

#include <nlohmann/json.hpp>

#include <fstream>
#include <iterator>

#ifndef _WIN32
#  include <fcntl.h>
#  include <unistd.h>
#endif

namespace nexus::updater {

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

constexpr std::string_view kAbsentSuffix = ".absent";

const char* phase_name(SwapPhase p) {
    switch (p) {
        case SwapPhase::None:       return "none";
        case SwapPhase::BackedUp:   return "backed_up";
        case SwapPhase::Swapped:    return "swapped";
        case SwapPhase::RolledBack: return "rolled_back";
    }
    return "none";
}

std::optional<SwapPhase> phase_from(std::string_view s) {
    if (s == "backed_up") return SwapPhase::BackedUp;
    if (s == "swapped") return SwapPhase::Swapped;
    if (s == "rolled_back") return SwapPhase::RolledBack;
    if (s == "none") return SwapPhase::None;
    return std::nullopt;
}

fs::path backup_path(const SwapPlan& plan, const SwapFile& file) {
    return plan.backup_dir / file.target.filename();
}

fs::path absent_marker(const SwapPlan& plan, const SwapFile& file) {
    return plan.backup_dir / (file.target.filename().string() + std::string(kAbsentSuffix));
}

bool fsync_path(const fs::path& path) {
#ifndef _WIN32
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    const bool ok = ::fsync(fd) == 0;
    ::close(fd);
    return ok;
#else
    (void)path;
    return true;
#endif
}

}  // namespace

bool install_file_atomic(const fs::path& source, const fs::path& target, fs::perms mode,
                         std::string& error) {
    std::error_code ec;
    const fs::path tmp =
        target.parent_path() / ("." + target.filename().string() + ".nexus-updater-new");
    fs::remove(tmp, ec);
    if (!fs::copy_file(source, tmp, fs::copy_options::overwrite_existing, ec)) {
        error = "cannot copy " + source.string() + " to " + tmp.string() + ": " + ec.message();
        return false;
    }
    fs::permissions(tmp, mode, fs::perm_options::replace, ec);
    if (ec || !fsync_path(tmp)) {
        error = "cannot finish " + tmp.string();
        fs::remove(tmp, ec);
        return false;
    }
    if (!security::rename_durable(tmp, target)) {
        error = "cannot rename " + tmp.string() + " to " + target.string();
        fs::remove(tmp, ec);
        return false;
    }
    return true;
}

FileSwapper::FileSwapper(fs::path journal_path) : journal_path_(std::move(journal_path)) {}

bool FileSwapper::write_journal(SwapPhase phase, const SwapPlan& plan, std::string& error) {
    json files = json::array();
    for (const auto& f : plan.files) {
        files.push_back({{"target", f.target.string()},
                         {"staged", f.staged.string()},
                         {"sha256", f.sha256},
                         {"mode", static_cast<unsigned>(f.mode)}});
    }
    const json j = {{"phase", phase_name(phase)},
                    {"release_tag", plan.release_tag},
                    {"backup_dir", plan.backup_dir.string()},
                    {"files", std::move(files)}};
    std::error_code ec;
    fs::create_directories(journal_path_.parent_path(), ec);
    if (!security::write_durable(journal_path_, j.dump(2))) {
        error = "cannot write the swap journal " + journal_path_.string();
        return false;
    }
    return true;
}

std::optional<std::pair<SwapPhase, SwapPlan>> FileSwapper::load() const {
    std::ifstream in(journal_path_, std::ios::binary);
    if (!in) return std::nullopt;
    const std::string text{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    const json j = json::parse(text, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return std::nullopt;
    try {
        const auto phase = phase_from(j.at("phase").get<std::string>());
        if (!phase) return std::nullopt;
        SwapPlan plan;
        plan.release_tag = j.at("release_tag").get<std::string>();
        plan.backup_dir = j.at("backup_dir").get<std::string>();
        for (const auto& f : j.at("files")) {
            SwapFile file;
            file.target = f.at("target").get<std::string>();
            file.staged = f.at("staged").get<std::string>();
            file.sha256 = f.at("sha256").get<std::string>();
            file.mode = static_cast<fs::perms>(f.at("mode").get<unsigned>());
            plan.files.push_back(std::move(file));
        }
        return std::make_pair(*phase, std::move(plan));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

void FileSwapper::clear() {
    std::error_code ec;
    fs::remove(journal_path_, ec);
}

bool FileSwapper::swap_files(const SwapPlan& plan, std::string& error) {
    for (std::size_t i = 0; i < plan.files.size(); ++i) {
        const auto& f = plan.files[i];
        // Idempotent: a target that already holds the new bytes is done.
        if (sha256_file_hex(f.target.string()) == f.sha256) continue;
        if (sha256_file_hex(f.staged.string()) != f.sha256) {
            error = "the staged file " + f.staged.string() + " does not have the verified hash";
            return false;
        }
        if (before_rename && !before_rename(i)) {
            error = "the swap stopped before " + f.target.string();
            return false;
        }
        if (!install_file_atomic(f.staged, f.target, f.mode, error)) return false;
    }
    return true;
}

bool FileSwapper::apply(const SwapPlan& plan, std::string& error) {
    if (plan.files.empty()) {
        error = "the swap plan is empty";
        return false;
    }
    for (const auto& f : plan.files) {
        if (sha256_file_hex(f.staged.string()) != f.sha256) {
            error = "the staged file " + f.staged.string() + " does not have the verified hash";
            return false;
        }
    }
    std::error_code ec;
    fs::create_directories(plan.backup_dir, ec);
    fs::permissions(plan.backup_dir, fs::perms::owner_all, fs::perm_options::replace, ec);
    // Back up every target before any of them changes. A backup that already
    // exists is from an interrupted earlier attempt at this plan: keep it, it
    // holds the bytes from before that attempt.
    for (const auto& f : plan.files) {
        const auto backup = backup_path(plan, f);
        const auto marker = absent_marker(plan, f);
        if (fs::exists(backup, ec) || fs::exists(marker, ec)) continue;
        if (!fs::exists(f.target, ec)) {
            if (!security::write_durable(marker, "")) {
                error = "cannot record that " + f.target.string() + " was absent";
                return false;
            }
            continue;
        }
        if (!install_file_atomic(f.target, backup, fs::status(f.target, ec).permissions(),
                                 error)) {
            return false;
        }
    }
    if (!write_journal(SwapPhase::BackedUp, plan, error)) return false;
    if (!swap_files(plan, error)) return false;
    return write_journal(SwapPhase::Swapped, plan, error);
}

bool FileSwapper::resume(std::string& error) {
    const auto state = load();
    if (!state) return true;
    if (state->first != SwapPhase::BackedUp) return true;
    if (!swap_files(state->second, error)) return false;
    return write_journal(SwapPhase::Swapped, state->second, error);
}

bool FileSwapper::rollback(std::string& error) {
    const auto state = load();
    if (!state) {
        error = "there is no swap to roll back";
        return false;
    }
    const auto& plan = state->second;
    std::error_code ec;
    for (const auto& f : plan.files) {
        const auto backup = backup_path(plan, f);
        if (fs::exists(absent_marker(plan, f), ec)) {
            fs::remove(f.target, ec);
            continue;
        }
        if (!fs::exists(backup, ec)) {
            error = "the backup of " + f.target.string() + " is missing";
            return false;
        }
        if (!install_file_atomic(backup, f.target, fs::status(backup, ec).permissions(),
                                 error)) {
            return false;
        }
    }
    return write_journal(SwapPhase::RolledBack, plan, error);
}

}  // namespace nexus::updater
