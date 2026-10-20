#include <LemonadeNexusAttestd/Tier1AuthorityProbe.hpp>

#include <array>
#include <charconv>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>

#ifdef __linux__
#  include <linux/openat2.h>
#  include <sys/syscall.h>
#endif

namespace nexus::attestd {
namespace {
namespace fs = std::filesystem;

constexpr std::array<std::string_view, 7> kRequiredFiles = {
    "/var/lib/lemonade-nexus/lemonade-nexus.json",
    "/etc/lemonade-nexus/lemonade-nexus.env",
    "/usr/lib/systemd/system/lemonade-nexus.service",
    "/usr/lib/systemd/system/nexus-attestd.service",
    "/etc/apparmor.d/nexus-tier1-authority-probe",
    "/etc/passwd",
    "/etc/group",
};

constexpr std::string_view kSocket = "/run/nexus-attestd/nexus-attestd.sock";
constexpr std::string_view kCompletion =
    "/usr/lib/lemonade-nexus/tier1-authority-probe.complete";
constexpr std::string_view kCompletionText = "nexus-tier1-authority-probe-v1\n";

constexpr std::array<std::string_view, 11> kOverrideRoots = {
    "/etc/systemd/system", "/etc/systemd/system.attached", "/run/systemd/system",
    "/run/systemd/system.attached", "/usr/local/lib/systemd/system",
    "/etc/systemd/system.control", "/run/systemd/system.control",
    "/run/systemd/transient", "/run/systemd/generator.early",
    "/run/systemd/generator", "/run/systemd/generator.late",
};
constexpr std::array<std::string_view, 3> kUnitNames = {
    "lemonade-nexus.service", "nexus-attestd.service",
    "nexus-attestd.socket",
};

fs::path physical(std::string_view logical, const fs::path& root) {
    const fs::path path(logical);
    return root.empty() ? path : root / path.relative_path();
}

bool no_symlink_components(const fs::path& path) {
    fs::path prefix;
    for (const auto& part : path) {
        prefix /= part;
        struct stat st {};
        if (::lstat(prefix.c_str(), &st) == 0) {
            if (S_ISLNK(st.st_mode)) return false;
        } else if (errno != ENOENT) {
            return false;
        }
    }
    return true;
}

int open_readonly_no_symlinks(const fs::path& path, bool directory = false) {
#ifdef __linux__
    struct open_how how {};
    how.flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | (directory ? O_DIRECTORY : 0);
    how.resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS;
    return static_cast<int>(::syscall(SYS_openat2, AT_FDCWD, path.c_str(), &how,
                                      sizeof(how)));
#else
    if (!no_symlink_components(path)) {
        errno = ELOOP;
        return -1;
    }
    return ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW |
                                 (directory ? O_DIRECTORY : 0));
#endif
}

bool read_required(std::string_view logical, const fs::path& root, uid_t owner,
                   dev_t root_device, std::string& contents, std::string& error) {
    const auto path = physical(logical, root);
    const int fd = open_readonly_no_symlinks(path);
    if (fd < 0) {
        error = "missing, symlinked, or unreadable authority file: " + std::string(logical);
        return false;
    }
    struct stat before {}, after {};
    if (::fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_uid != owner || (before.st_mode & 022) != 0 ||
        before.st_dev != root_device || before.st_nlink != 1) {
        error = "wrong owner, mode, type, link count, or filesystem: " +
                std::string(logical);
        ::close(fd);
        return false;
    }
    contents.clear();
    char buffer[8192];
    while (true) {
        const ssize_t n = ::read(fd, buffer, sizeof(buffer));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 || contents.size() + static_cast<std::size_t>(n) > 1024 * 1024) {
            error = "authority file read failed or exceeds 1 MiB: " + std::string(logical);
            ::close(fd);
            return false;
        }
        if (n == 0) break;
        contents.append(buffer, static_cast<std::size_t>(n));
    }
    const bool stable = ::fstat(fd, &after) == 0 && before.st_dev == after.st_dev &&
        before.st_ino == after.st_ino && before.st_size == after.st_size &&
        before.st_mtime == after.st_mtime && before.st_ctime == after.st_ctime;
    ::close(fd);
    if (!stable) {
        error = "authority file changed during read: " + std::string(logical);
        return false;
    }
    return true;
}

bool absent(const fs::path& path) {
    if (!no_symlink_components(path)) return false;
    struct stat st {};
    return ::lstat(path.c_str(), &st) != 0 && errno == ENOENT;
}

bool absent_or_empty_directory(const fs::path& path, uid_t owner, std::string& error) {
    if (absent(path)) return true;
    const int fd = open_readonly_no_symlinks(path, true);
    if (fd < 0) {
        error = "unexpected non-directory or symlinked service drop-in: " + path.string();
        return false;
    }
    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != owner ||
        (st.st_mode & 022) != 0) {
        error = "unsafe service drop-in directory: " + path.string();
        ::close(fd);
        return false;
    }
    DIR* dir = ::fdopendir(fd);
    if (!dir) {
        error = "cannot enumerate service drop-in directory: " + path.string();
        ::close(fd);
        return false;
    }
    bool empty = true;
    while (auto* entry = ::readdir(dir)) {
        if (std::strcmp(entry->d_name, ".") != 0 &&
            std::strcmp(entry->d_name, "..") != 0) {
            empty = false;
            break;
        }
    }
    ::closedir(dir);
    if (!empty) error = "unexpected privileged service drop-in: " + path.string();
    return empty;
}

bool named_id(std::string_view text, std::string_view name, std::size_t field,
              unsigned long& id) {
    std::size_t start = 0;
    while (start < text.size()) {
        const auto end = text.find('\n', start);
        const auto line = text.substr(start, end == std::string_view::npos
                                             ? text.size() - start : end - start);
        if (line.starts_with(name) && line.size() > name.size() &&
            line[name.size()] == ':') {
            std::size_t cursor = name.size() + 1;
            for (std::size_t i = 1; i < field; ++i) {
                const auto colon = line.find(':', cursor);
                if (colon == std::string_view::npos) return false;
                cursor = colon + 1;
            }
            const auto colon = line.find(':', cursor);
            const auto number = line.substr(cursor, colon == std::string_view::npos
                                                   ? line.size() - cursor : colon - cursor);
            const auto parsed = std::from_chars(number.data(), number.data() + number.size(), id);
            return parsed.ec == std::errc{} && parsed.ptr == number.data() + number.size();
        }
        if (end == std::string_view::npos) break;
        start = end + 1;
    }
    return false;
}

}  // namespace

Tier1AuthorityProbeResult run_tier1_authority_probe(const fs::path& test_root) {
    Tier1AuthorityProbeResult result;
    if (!test_root.empty() && !test_root.is_absolute()) {
        result.failure = "test root must be absolute";
        return result;
    }
    struct stat root_stat {};
    if (::stat((test_root.empty() ? fs::path("/") : test_root).c_str(), &root_stat) != 0) {
        result.failure = "authority filesystem root is unavailable";
        return result;
    }
    const uid_t owner = test_root.empty() ? 0 : ::geteuid();
    std::array<std::string, kRequiredFiles.size()> contents;
    for (std::size_t i = 0; i < kRequiredFiles.size(); ++i) {
        if (!read_required(kRequiredFiles[i], test_root, owner, root_stat.st_dev,
                           contents[i], result.failure)) return result;
        result.opened_paths.emplace_back(kRequiredFiles[i]);
    }

    for (auto root : kOverrideRoots) {
        for (auto unit : kUnitNames) {
            const auto unit_path = physical(std::string(root) + "/" + std::string(unit), test_root);
            if (!absent(unit_path)) {
                result.failure = "unexpected privileged unit override: " + unit_path.string();
                return result;
            }
            const auto dropin = physical(std::string(root) + "/" +
                                             std::string(unit) + ".d", test_root);
            if (!absent_or_empty_directory(dropin, owner, result.failure)) return result;
        }
    }
    if (!absent(physical("/usr/lib/systemd/system/nexus-attestd.socket", test_root))) {
        result.failure = "unexpected packaged attestd socket unit";
        return result;
    }
    for (auto unit : kUnitNames) {
        const auto dropin = physical(std::string("/usr/lib/systemd/system/") +
                                         std::string(unit) + ".d", test_root);
        if (!absent_or_empty_directory(dropin, owner, result.failure)) return result;
    }

    unsigned long expected_uid = 0, expected_gid = 0;
    if (!named_id(contents[5], "nexus-attestd", 2, expected_uid) ||
        !named_id(contents[6], "nexus", 2, expected_gid)) {
        result.failure = "attestd owner or nexus ACL group is missing";
        return result;
    }
    const auto socket_path = physical(kSocket, test_root);
    struct stat socket_stat {};
    if (!no_symlink_components(socket_path) ||
        ::lstat(socket_path.c_str(), &socket_stat) != 0 ||
        !S_ISSOCK(socket_stat.st_mode) ||
        (socket_stat.st_mode & 0777) != 0660 ||
        socket_stat.st_uid != expected_uid || socket_stat.st_gid != expected_gid) {
        result.failure = "attestd socket type, owner, group, or mode is wrong";
        return result;
    }

    std::string completion;
    if (!read_required(kCompletion, test_root, owner, root_stat.st_dev,
                       completion, result.failure)) return result;
    if (completion != kCompletionText) {
        result.failure = "authority probe completion artifact is not approved v1";
        return result;
    }
    result.opened_paths.emplace_back(kCompletion);
    result.ok = true;
    return result;
}

}  // namespace nexus::attestd
