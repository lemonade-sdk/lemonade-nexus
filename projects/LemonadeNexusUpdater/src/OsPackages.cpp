#include <LemonadeNexusUpdater/OsPackages.hpp>

#include <algorithm>
#include <set>
#include <sstream>

namespace nexus::updater {
namespace {

bool valid_name(std::string_view s) {
    if (s.size() < 2 || s.size() > 128) return false;
    auto alnum = [](char c) { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'); };
    if (!alnum(s[0])) return false;
    return std::all_of(s.begin(), s.end(),
                       [&](char c) { return alnum(c) || c == '+' || c == '-' || c == '.'; });
}

bool valid_version(std::string_view s) {
    if (s.empty() || s.size() > 128 || !(s[0] >= '0' && s[0] <= '9')) return false;
    return std::all_of(s.begin(), s.end(), [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '.' || c == '+' || c == '~' || c == ':' || c == '-';
    });
}

std::vector<std::string_view> split_ws(std::string_view line) {
    std::vector<std::string_view> out;
    std::size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
        const auto start = i;
        while (i < line.size() && line[i] != ' ' && line[i] != '\t') ++i;
        if (i > start) out.push_back(line.substr(start, i - start));
    }
    return out;
}

std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) {
        s.remove_suffix(1);
    }
    return s;
}

std::vector<std::string_view> lines_of(std::string_view text) {
    std::vector<std::string_view> out;
    std::size_t start = 0;
    while (start <= text.size()) {
        const auto end = text.find('\n', start);
        out.push_back(text.substr(start, end == std::string_view::npos ? end : end - start));
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return out;
}

/// The single-quoted $menuentry_id_option argument of a menuentry/submenu line.
std::optional<std::string> entry_id(std::string_view line) {
    const auto key = line.find("$menuentry_id_option");
    if (key == std::string_view::npos) return std::nullopt;
    const auto open = line.find('\'', key);
    if (open == std::string_view::npos) return std::nullopt;
    const auto close = line.find('\'', open + 1);
    if (close == std::string_view::npos) return std::nullopt;
    return std::string(line.substr(open + 1, close - open - 1));
}

}  // namespace

std::optional<OsPackageLock> parse_os_package_lock(std::string_view text, std::string& error) {
    if (text.size() > kMaxOsLockBytes) {
        error = "the OS package lock is too large";
        return std::nullopt;
    }
    OsPackageLock lock;
    bool have_format = false;
    std::set<std::string> names;
    std::size_t number = 0;
    for (const auto raw : lines_of(text)) {
        ++number;
        const auto line = trim(raw);
        if (line.empty() || line.front() == '#') continue;
        const auto words = split_ws(line);
        const auto where = " (line " + std::to_string(number) + ")";
        if (words[0] == "format") {
            if (have_format || words.size() != 2 || words[1] != "1") {
                error = "the OS package lock has an unsupported format line" + where;
                return std::nullopt;
            }
            have_format = true;
            continue;
        }
        if (!have_format) {
            error = "the OS package lock must start with 'format 1'";
            return std::nullopt;
        }
        if (words[0] != "package" || words.size() != 4) {
            error = "the OS package lock has an invalid record" + where;
            return std::nullopt;
        }
        OsPackage p;
        p.name = std::string(words[1]);
        p.version = std::string(words[2]);
        if (words[3] == "boot") p.role = PackageRole::Boot;
        else if (words[3] == "library") p.role = PackageRole::Library;
        else if (words[3] == "system") p.role = PackageRole::System;
        else {
            error = "the OS package lock has an unknown role" + where;
            return std::nullopt;
        }
        if (!valid_name(p.name) || !valid_version(p.version)) {
            error = "the OS package lock has an invalid name or version" + where;
            return std::nullopt;
        }
        if (!names.insert(p.name).second) {
            error = "the OS package lock lists " + p.name + " twice";
            return std::nullopt;
        }
        lock.packages.push_back(std::move(p));
    }
    if (!have_format) {
        error = "the OS package lock must start with 'format 1'";
        return std::nullopt;
    }
    return lock;
}

OsPackagePlan plan_os_packages(const OsPackageLock& lock,
                               const std::map<std::string, std::string>& installed) {
    OsPackagePlan plan;
    for (const auto& p : lock.packages) {
        const auto it = installed.find(p.name);
        const std::string current = it == installed.end() ? std::string() : it->second;
        if (current == p.version) continue;
        plan.install.push_back(p);
        plan.previous.push_back({p.name, current, p.role});
        plan.boot_chain_changed |= p.role == PackageRole::Boot;
    }
    return plan;
}

std::vector<std::string> dpkg_query_argv(const OsPackageLock& lock) {
    std::vector<std::string> argv{"dpkg-query", "-W",
                                  "-f=${Package}\t${Version}\t${db:Status-Abbrev}\n"};
    for (const auto& p : lock.packages) argv.push_back(p.name);
    return argv;
}

std::map<std::string, std::string> parse_dpkg_query(std::string_view output) {
    std::map<std::string, std::string> out;
    for (const auto line : lines_of(output)) {
        const auto t1 = line.find('\t');
        if (t1 == std::string_view::npos) continue;
        const auto t2 = line.find('\t', t1 + 1);
        if (t2 == std::string_view::npos) continue;
        const auto name = line.substr(0, t1);
        // dpkg-query -W prints "name:arch" for multi-arch packages.
        const auto bare = name.substr(0, name.find(':'));
        const auto version = line.substr(t1 + 1, t2 - t1 - 1);
        const auto status = trim(line.substr(t2 + 1));
        if (status == "ii" && valid_name(bare) && valid_version(version)) {
            out[std::string(bare)] = std::string(version);
        }
    }
    return out;
}

std::vector<std::string> apt_install_argv(const std::vector<OsPackage>& packages) {
    if (packages.empty()) return {};
    std::vector<std::string> argv{"apt-get",
                                  "install",
                                  "-y",
                                  "--no-install-recommends",
                                  "--allow-downgrades",
                                  "-o",
                                  "Dpkg::Options::=--force-confold",
                                  "--"};
    for (const auto& p : packages) argv.push_back(p.name + "=" + p.version);
    return argv;
}

RebootDecision decide_reboot(bool lock_boot_changed, bool approval_pcrs_changed) {
    if (lock_boot_changed && approval_pcrs_changed) return {true, {}};
    if (!lock_boot_changed && !approval_pcrs_changed) return {false, {}};
    if (lock_boot_changed) {
        return {false,
                "the OS package lock changes the boot chain but the approval keeps the "
                "installed PCR 8/9 values"};
    }
    return {false,
            "the approval changes PCR 8/9 but the OS package lock changes no boot package"};
}

bool grub_default_is_saved(std::string_view etc_default_grub) {
    bool saved = false;
    for (const auto raw : lines_of(etc_default_grub)) {
        const auto line = trim(raw);
        if (line.rfind("GRUB_DEFAULT=", 0) != 0) continue;
        auto value = line.substr(std::string_view("GRUB_DEFAULT=").size());
        if (value.size() >= 2 && (value.front() == '"' || value.front() == '\'') &&
            value.back() == value.front()) {
            value = value.substr(1, value.size() - 2);
        }
        saved = value == "saved";  // the last assignment wins, as in the shell
    }
    return saved;
}

std::optional<std::string> grub_entry_for_kernel(std::string_view grub_cfg,
                                                 std::string_view kernel_release) {
    const std::string image = "/vmlinuz-" + std::string(kernel_release);
    std::optional<std::string> submenu;
    std::optional<std::string> entry;
    int depth = 0;
    int submenu_depth = -1;
    int entry_depth = -1;
    for (const auto raw : lines_of(grub_cfg)) {
        const auto line = trim(raw);
        if (line.rfind("submenu ", 0) == 0) {
            submenu = entry_id(line);
            submenu_depth = depth;
        } else if (line.rfind("menuentry ", 0) == 0) {
            entry = entry_id(line);
            entry_depth = depth;
        } else if (entry && line.rfind("linux", 0) == 0) {
            const auto words = split_ws(line);
            if (words.size() >= 2) {
                const auto path = words[1];
                const bool match =
                    path.size() >= image.size() &&
                    path.substr(path.size() - image.size()) == image;
                if (match) {
                    return submenu && submenu_depth >= 0 && entry_depth > submenu_depth
                               ? *submenu + ">" + *entry
                               : *entry;
                }
            }
        }
        depth += static_cast<int>(std::count(line.begin(), line.end(), '{'));
        depth -= static_cast<int>(std::count(line.begin(), line.end(), '}'));
        if (entry && depth <= entry_depth) {
            entry.reset();
            entry_depth = -1;
        }
        if (submenu && depth <= submenu_depth) {
            submenu.reset();
            submenu_depth = -1;
        }
    }
    return std::nullopt;
}

}  // namespace nexus::updater
