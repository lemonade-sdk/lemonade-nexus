#include <LemonadeNexusUpdater/SystemdUnits.hpp>

#include <LemonadeNexusUpdater/FileSwap.hpp>

#include <fstream>
#include <iterator>
#include <optional>
#include <system_error>

namespace nexus::updater {

namespace fs = std::filesystem;

namespace {

std::optional<std::string> read_all(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    return std::string{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::string join(const std::vector<std::string>& argv) {
    std::string out;
    for (const auto& arg : argv) out += (out.empty() ? "" : " ") + arg;
    return out;
}

}  // namespace

UnitRefreshResult refresh_systemd_units(const fs::path& root, const CommandRunner& run) {
    UnitRefreshResult result;
    const fs::path directory = root / fs::path(kSystemdUnitDirectory).relative_path();
    std::error_code ec;
    fs::create_directories(directory, ec);
    if (ec) {
        result.error = "cannot create " + directory.string() + ": " + ec.message();
        return result;
    }
    constexpr auto kUnitMode = fs::perms::owner_read | fs::perms::owner_write |
                               fs::perms::group_read | fs::perms::others_read;
    for (const auto& unit : embedded_systemd_units()) {
        const fs::path target = directory / std::string(unit.name);
        const auto installed = read_all(target);
        if (installed && *installed == unit.content) continue;
        std::string error;
        if (!write_file_atomic(unit.content, target, kUnitMode, error)) {
            result.error = error;
            return result;
        }
        result.refreshed.push_back(std::string(unit.name) +
                                   (installed ? " (changed)" : " (missing)"));
    }
    if (result.refreshed.empty()) return result;

    // The manager must read the new files before anything acts on them. The
    // path unit is new on a server that never had this package version, so
    // it is enabled and started; the timer that runs this cycle is left as it
    // is and picks up its new file at the reload.
    const std::vector<std::vector<std::string>> commands{
        {"systemctl", "daemon-reload"},
        {"systemctl", "enable", "--now", std::string(kUpdaterPathUnit)}};
    for (const auto& argv : commands) {
        const auto outcome = run(argv);
        if (outcome.exit_code != 0) {
            result.error = join(argv) + " failed (" + std::to_string(outcome.exit_code) + ")" +
                           (outcome.output.empty() ? "" : ": " + outcome.output);
            return result;
        }
    }
    return result;
}

}  // namespace nexus::updater
