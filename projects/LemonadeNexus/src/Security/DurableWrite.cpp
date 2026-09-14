#include <LemonadeNexus/Security/DurableWrite.hpp>

#include <cstddef>
#include <system_error>

#ifdef _WIN32
// NOMINMAX keeps windows.h from defining min/max macros; LEAN_AND_MEAN trims
// the header surface. Both before the include, or they do nothing.
#  define NOMINMAX
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#else
#  include <fcntl.h>
#  include <unistd.h>
#endif

namespace nexus::security {

namespace fs = std::filesystem;

bool write_durable(const fs::path& final_path, std::string_view payload) {
    fs::path temp_path = final_path;
    temp_path += ".tmp";

#ifdef _WIN32
    // CreateFileW takes the wide path directly; fs::path already stores wchar_t
    // on Windows, so there is no encoding conversion to get wrong.
    const HANDLE file = ::CreateFileW(temp_path.c_str(), GENERIC_WRITE, 0, nullptr,
                                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return false;

    std::size_t written = 0;
    while (written < payload.size()) {
        // One WriteFile can be short, and its count is a DWORD, so a large
        // payload is written in bounded chunks rather than truncated.
        const std::size_t remaining = payload.size() - written;
        const DWORD chunk = remaining > (1u << 20) ? DWORD{1u << 20}
                                                   : static_cast<DWORD>(remaining);
        DWORD produced = 0;
        if (::WriteFile(file, payload.data() + written, chunk, &produced, nullptr) == 0 ||
            produced == 0) {
            ::CloseHandle(file);
            ::DeleteFileW(temp_path.c_str());
            return false;
        }
        written += produced;
    }
    // The fsync equivalent: commit the file's data to the device.
    if (::FlushFileBuffers(file) == 0) {
        ::CloseHandle(file);
        ::DeleteFileW(temp_path.c_str());
        return false;
    }
    if (::CloseHandle(file) == 0) {
        ::DeleteFileW(temp_path.c_str());
        return false;
    }

    // Atomic replace.
    if (::MoveFileExW(temp_path.c_str(), final_path.c_str(),
                      MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) == 0) {
        ::DeleteFileW(temp_path.c_str());
        return false;
    }

    // MOVEFILE_WRITE_THROUGH is NOT sufficient on its own: its documented
    // guarantee covers a move performed as copy-and-delete, and a rename inside
    // one directory is always the metadata-only path, whose directory entry
    // NTFS commits lazily. Windows exposes no directory handle to flush, so
    // reopen the destination and flush it — that is what forces the rename to
    // disk, standing in for the parent-directory fsync on POSIX. Without it the
    // caller would be told a vote is durable while it is still only in the log.
    const HANDLE renamed =
        ::CreateFileW(final_path.c_str(), GENERIC_WRITE,
                      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (renamed == INVALID_HANDLE_VALUE) return false;
    const bool renamed_durable = ::FlushFileBuffers(renamed) != 0;
    ::CloseHandle(renamed);
    return renamed_durable;
#else
    const int fd = ::open(temp_path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return false;

    std::size_t written = 0;
    while (written < payload.size()) {
        const ssize_t count = ::write(fd, payload.data() + written, payload.size() - written);
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

    // The rename is only durable once the directory entry is flushed too.
    const int dir_fd = ::open(final_path.parent_path().c_str(), O_RDONLY);
    if (dir_fd < 0) return false;
    const bool directory_synced = ::fsync(dir_fd) == 0;
    ::close(dir_fd);
    return directory_synced;
#endif
}

}  // namespace nexus::security
