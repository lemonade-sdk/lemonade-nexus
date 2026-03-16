/// @file WireGuardWindowsBridge.cpp
/// Windows implementation of the WireGuard bridge using wireguard-nt.
///
/// Dynamically loads wireguard.dll via LoadLibrary/GetProcAddress and wraps
/// the kernel driver API in a simplified C interface.

#ifdef _WIN32

#include <LemonadeNexus/WireGuard/WireGuardWindowsBridge.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <in6addr.h>
#include <urlmon.h>      // URLDownloadToFileW
#include <wintrust.h>    // WinVerifyTrust
#include <softpub.h>     // WINTRUST_ACTION_GENERIC_VERIFY_V2
#include <shellapi.h>    // SHFileOperationW

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "shell32.lib")

#include <wireguard.h>  // wireguard-nt API header

#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// DLL function pointers
// ---------------------------------------------------------------------------

static HMODULE g_wg_dll = nullptr;

static WIREGUARD_CREATE_ADAPTER_FUNC*              WireGuardCreateAdapter;
static WIREGUARD_OPEN_ADAPTER_FUNC*                WireGuardOpenAdapter;
static WIREGUARD_CLOSE_ADAPTER_FUNC*               WireGuardCloseAdapter;
static WIREGUARD_GET_ADAPTER_LUID_FUNC*            WireGuardGetAdapterLUID;
static WIREGUARD_GET_RUNNING_DRIVER_VERSION_FUNC*  WireGuardGetRunningDriverVersion;
static WIREGUARD_DELETE_DRIVER_FUNC*               WireGuardDeleteDriver;
static WIREGUARD_SET_LOGGER_FUNC*                  WireGuardSetLogger;
static WIREGUARD_SET_ADAPTER_LOGGING_FUNC*         WireGuardSetAdapterLogging;
static WIREGUARD_GET_ADAPTER_STATE_FUNC*           WireGuardGetAdapterState;
static WIREGUARD_SET_ADAPTER_STATE_FUNC*           WireGuardSetAdapterState;
static WIREGUARD_GET_CONFIGURATION_FUNC*           WireGuardGetConfiguration;
static WIREGUARD_SET_CONFIGURATION_FUNC*           WireGuardSetConfiguration;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

namespace {

/// Convert UTF-8 to wide string.
std::wstring utf8_to_wide(const char* str) {
    if (!str || !*str) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, str, -1, nullptr, 0);
    if (len <= 0) return {};
    std::wstring result(len - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str, -1, result.data(), len);
    return result;
}

/// Decode a base64 WireGuard key (44 chars) into raw 32 bytes.
/// Minimal base64 decoder for WireGuard keys only.
bool base64_decode_key(const char* b64, BYTE out[WIREGUARD_KEY_LENGTH]) {
    if (!b64 || std::strlen(b64) != 44) return false;

    static const int8_t b64_table[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1, 0,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    };

    std::vector<BYTE> raw;
    raw.reserve(33);
    for (int i = 0; i < 44; i += 4) {
        int a = b64_table[(unsigned char)b64[i]];
        int b = b64_table[(unsigned char)b64[i+1]];
        int c = b64_table[(unsigned char)b64[i+2]];
        int d = b64_table[(unsigned char)b64[i+3]];
        if (a < 0 || b < 0) return false;

        raw.push_back(static_cast<BYTE>((a << 2) | (b >> 4)));
        if (b64[i+2] != '=') {
            if (c < 0) return false;
            raw.push_back(static_cast<BYTE>(((b & 0xF) << 4) | (c >> 2)));
        }
        if (b64[i+3] != '=') {
            if (d < 0) return false;
            raw.push_back(static_cast<BYTE>(((c & 0x3) << 6) | d));
        }
    }

    if (raw.size() < WIREGUARD_KEY_LENGTH) return false;
    std::memcpy(out, raw.data(), WIREGUARD_KEY_LENGTH);
    return true;
}

/// Encode raw 32 bytes as base64 (44 chars + null).
void base64_encode_key(const BYTE key[WIREGUARD_KEY_LENGTH], char out[45]) {
    static const char b64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    int j = 0;
    for (int i = 0; i < 32; i += 3) {
        int remaining = 32 - i;
        unsigned int triple = (key[i] << 16);
        if (remaining > 1) triple |= (key[i+1] << 8);
        if (remaining > 2) triple |= key[i+2];

        out[j++] = b64_chars[(triple >> 18) & 0x3F];
        out[j++] = b64_chars[(triple >> 12) & 0x3F];
        out[j++] = (remaining > 1) ? b64_chars[(triple >> 6) & 0x3F] : '=';
        out[j++] = (remaining > 2) ? b64_chars[triple & 0x3F] : '=';
    }
    out[j] = '\0';
}

/// Parse "ip:port" or "[ipv6]:port" into a SOCKADDR_INET.
bool parse_endpoint_win(const char* ep, SOCKADDR_INET& addr) {
    if (!ep || !*ep) return false;
    std::memset(&addr, 0, sizeof(addr));

    std::string ep_str(ep);

    // [IPv6]:port
    if (ep_str.front() == '[') {
        auto bracket = ep_str.find(']');
        if (bracket == std::string::npos) return false;
        auto colon = ep_str.find(':', bracket);
        if (colon == std::string::npos) return false;
        if (colon + 1 >= ep_str.size()) return false;

        auto ip = ep_str.substr(1, bracket - 1);
        USHORT port;
        try {
            port = static_cast<USHORT>(std::stoul(ep_str.substr(colon + 1)));
        } catch (...) {
            return false;
        }

        addr.si_family = AF_INET6;
        addr.Ipv6.sin6_port = htons(port);
        if (InetPtonA(AF_INET6, ip.c_str(), &addr.Ipv6.sin6_addr) != 1) return false;
        return true;
    }

    // IPv4:port
    auto colon = ep_str.rfind(':');
    if (colon == std::string::npos) return false;
    if (colon + 1 >= ep_str.size()) return false;

    auto ip = ep_str.substr(0, colon);
    USHORT port;
    try {
        port = static_cast<USHORT>(std::stoul(ep_str.substr(colon + 1)));
    } catch (...) {
        return false;
    }

    addr.si_family = AF_INET;
    addr.Ipv4.sin_port = htons(port);
    if (InetPtonA(AF_INET, ip.c_str(), &addr.Ipv4.sin_addr) != 1) return false;
    return true;
}

/// Format a SOCKADDR_INET as "ip:port".
std::string format_endpoint_win(const SOCKADDR_INET& addr) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (addr.si_family == AF_INET) {
        InetNtopA(AF_INET, &addr.Ipv4.sin_addr, buf, sizeof(buf));
        return std::string(buf) + ":" + std::to_string(ntohs(addr.Ipv4.sin_port));
    } else if (addr.si_family == AF_INET6) {
        InetNtopA(AF_INET6, &addr.Ipv6.sin6_addr, buf, sizeof(buf));
        return "[" + std::string(buf) + "]:" + std::to_string(ntohs(addr.Ipv6.sin6_port));
    }
    return {};
}

/// Parse a CIDR string into address family, address bytes, and prefix length.
bool parse_cidr_win(const char* cidr, ADDRESS_FAMILY& family, void* addr_out, BYTE& prefix) {
    std::string s(cidr);
    auto slash = s.find('/');
    if (slash == std::string::npos) return false;

    auto ip_str = s.substr(0, slash);
    prefix = static_cast<BYTE>(std::stoul(s.substr(slash + 1)));

    // Try IPv4
    IN_ADDR v4{};
    if (InetPtonA(AF_INET, ip_str.c_str(), &v4) == 1) {
        family = AF_INET;
        std::memcpy(addr_out, &v4, sizeof(v4));
        return true;
    }

    // Try IPv6
    IN6_ADDR v6{};
    if (InetPtonA(AF_INET6, ip_str.c_str(), &v6) == 1) {
        family = AF_INET6;
        std::memcpy(addr_out, &v6, sizeof(v6));
        return true;
    }

    return false;
}

} // anonymous namespace

// ---------------------------------------------------------------------------
// Auto-download support
// ---------------------------------------------------------------------------

namespace {

/// Version of wireguard-nt to download (must match cmake/libraries/wireguard-nt.cmake).
constexpr const wchar_t* WG_NT_DOWNLOAD_URL =
    L"https://download.wireguard.com/wireguard-nt/wireguard-nt-0.10.1.zip";

/// Target architecture subdirectory name inside the ZIP.
#if defined(_M_AMD64) || defined(_M_X64)
constexpr const wchar_t* WG_NT_ARCH = L"amd64";
#elif defined(_M_IX86)
constexpr const wchar_t* WG_NT_ARCH = L"x86";
#elif defined(_M_ARM64)
constexpr const wchar_t* WG_NT_ARCH = L"arm64";
#else
constexpr const wchar_t* WG_NT_ARCH = nullptr;
#endif

/// Get the directory containing the current executable.
bool get_exe_directory(wchar_t* dir, DWORD max_len) {
    DWORD len = GetModuleFileNameW(nullptr, dir, max_len);
    if (len == 0 || len >= max_len) return false;
    for (DWORD i = len; i > 0; --i) {
        if (dir[i - 1] == L'\\' || dir[i - 1] == L'/') {
            dir[i - 1] = L'\0';
            return true;
        }
    }
    return false;
}

/// Verify Authenticode code-signing signature on a file.
/// Returns true if the file has a valid signature from a trusted publisher.
bool verify_authenticode(const wchar_t* file_path) {
    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = file_path;

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trust_data{};
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_WHOLECHAIN;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_VERIFY;
    trust_data.dwProvFlags = WTD_SAFER_FLAG;

    LONG status = WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &action, &trust_data);

    trust_data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(reinterpret_cast<HWND>(INVALID_HANDLE_VALUE), &action, &trust_data);

    return status == ERROR_SUCCESS;
}

/// Recursively delete a directory and all its contents.
void remove_directory_recursive(const wchar_t* dir) {
    // SHFileOperation requires double-null-terminated string
    size_t len = wcslen(dir);
    std::vector<wchar_t> from(len + 2, L'\0');
    wcscpy_s(from.data(), len + 1, dir);

    SHFILEOPSTRUCTW op{};
    op.wFunc = FO_DELETE;
    op.pFrom = from.data();
    op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    SHFileOperationW(&op);
}

/// Search for wireguard.dll for the target architecture in an extracted directory tree.
/// Handles common ZIP layout variations:
///   base/bin/<arch>/wireguard.dll
///   base/<arch>/wireguard.dll
///   base/<subdir>/bin/<arch>/wireguard.dll
///   base/<subdir>/<arch>/wireguard.dll
bool find_dll_in_tree(const wchar_t* base_dir, const wchar_t* arch, wchar_t* out, DWORD max_len) {
    wchar_t candidate[MAX_PATH];

    // Try directly: base/bin/<arch>/wireguard.dll
    swprintf_s(candidate, MAX_PATH, L"%s\\bin\\%s\\wireguard.dll", base_dir, arch);
    if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES) {
        wcscpy_s(out, max_len, candidate);
        return true;
    }

    // Try directly: base/<arch>/wireguard.dll
    swprintf_s(candidate, MAX_PATH, L"%s\\%s\\wireguard.dll", base_dir, arch);
    if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES) {
        wcscpy_s(out, max_len, candidate);
        return true;
    }

    // Search one level of subdirectories (e.g., wireguard-nt-0.10.1/)
    wchar_t search[MAX_PATH];
    swprintf_s(search, MAX_PATH, L"%s\\*", base_dir);
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return false;

    bool found = false;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

        wchar_t subdir[MAX_PATH];
        swprintf_s(subdir, MAX_PATH, L"%s\\%s", base_dir, fd.cFileName);

        // subdir/bin/<arch>/wireguard.dll
        swprintf_s(candidate, MAX_PATH, L"%s\\bin\\%s\\wireguard.dll", subdir, arch);
        if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES) {
            wcscpy_s(out, max_len, candidate);
            found = true;
            break;
        }

        // subdir/<arch>/wireguard.dll
        swprintf_s(candidate, MAX_PATH, L"%s\\%s\\wireguard.dll", subdir, arch);
        if (GetFileAttributesW(candidate) != INVALID_FILE_ATTRIBUTES) {
            wcscpy_s(out, max_len, candidate);
            found = true;
            break;
        }
    } while (FindNextFileW(hFind, &fd));

    FindClose(hFind);
    return found;
}

} // anonymous namespace (auto-download helpers)

// ---------------------------------------------------------------------------
// Auto-download
// ---------------------------------------------------------------------------

int wg_nt_download_dll(void) {
    if (!WG_NT_ARCH) return -1;  // Unsupported architecture

    // 1. Get application directory
    wchar_t app_dir[MAX_PATH];
    if (!get_exe_directory(app_dir, MAX_PATH)) return -1;

    // 2. Check if wireguard.dll already exists
    wchar_t dll_dest[MAX_PATH];
    swprintf_s(dll_dest, MAX_PATH, L"%s\\wireguard.dll", app_dir);
    if (GetFileAttributesW(dll_dest) != INVALID_FILE_ATTRIBUTES) {
        return 0;  // Already present
    }

    // 3. Download ZIP to temp directory
    wchar_t temp_dir[MAX_PATH];
    GetTempPathW(MAX_PATH, temp_dir);

    wchar_t zip_path[MAX_PATH];
    swprintf_s(zip_path, MAX_PATH, L"%swireguard-nt-download.zip", temp_dir);

    HRESULT hr = URLDownloadToFileW(nullptr, WG_NT_DOWNLOAD_URL, zip_path, 0, nullptr);
    if (FAILED(hr)) return -1;

    // 4. Extract ZIP using tar (built into Windows 10 1803+)
    wchar_t extract_dir[MAX_PATH];
    swprintf_s(extract_dir, MAX_PATH, L"%swireguard-nt-extract", temp_dir);
    CreateDirectoryW(extract_dir, nullptr);

    wchar_t cmd[1024];
    swprintf_s(cmd, 1024, L"tar -xf \"%s\" -C \"%s\"", zip_path, extract_dir);

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};

    BOOL ok = CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE,
                             CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    DeleteFileW(zip_path);  // Done with ZIP regardless of outcome

    if (!ok) {
        remove_directory_recursive(extract_dir);
        return -1;
    }

    WaitForSingleObject(pi.hProcess, 60000);  // 60s timeout
    DWORD exit_code = 1;
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exit_code != 0) {
        remove_directory_recursive(extract_dir);
        return -1;
    }

    // 5. Find the architecture-specific DLL in the extracted tree
    wchar_t found_dll[MAX_PATH] = {};
    if (!find_dll_in_tree(extract_dir, WG_NT_ARCH, found_dll, MAX_PATH)) {
        remove_directory_recursive(extract_dir);
        return -1;
    }

    // 6. Verify Authenticode signature (ensures the DLL is signed by a trusted publisher)
    if (!verify_authenticode(found_dll)) {
        remove_directory_recursive(extract_dir);
        return -1;
    }

    // 7. Copy verified DLL to application directory
    BOOL copied = CopyFileW(found_dll, dll_dest, FALSE);
    remove_directory_recursive(extract_dir);

    return copied ? 0 : -1;
}

// ---------------------------------------------------------------------------
// DLL initialization
// ---------------------------------------------------------------------------

int wg_nt_init(void) {
    if (g_wg_dll) return 0;  // Already initialized

    g_wg_dll = LoadLibraryExW(L"wireguard.dll", nullptr,
        LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);

    // Auto-download from official WireGuard server if DLL not found
    if (!g_wg_dll) {
        if (wg_nt_download_dll() == 0) {
            g_wg_dll = LoadLibraryExW(L"wireguard.dll", nullptr,
                LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        }
        if (!g_wg_dll) return -1;
    }

#define RESOLVE(Name) \
    ((*(FARPROC*)&Name = GetProcAddress(g_wg_dll, #Name)) == nullptr)

    if (RESOLVE(WireGuardCreateAdapter) ||
        RESOLVE(WireGuardOpenAdapter) ||
        RESOLVE(WireGuardCloseAdapter) ||
        RESOLVE(WireGuardGetAdapterLUID) ||
        RESOLVE(WireGuardGetRunningDriverVersion) ||
        RESOLVE(WireGuardDeleteDriver) ||
        RESOLVE(WireGuardSetLogger) ||
        RESOLVE(WireGuardSetAdapterLogging) ||
        RESOLVE(WireGuardGetAdapterState) ||
        RESOLVE(WireGuardSetAdapterState) ||
        RESOLVE(WireGuardGetConfiguration) ||
        RESOLVE(WireGuardSetConfiguration))
    {
        FreeLibrary(g_wg_dll);
        g_wg_dll = nullptr;
        return -1;
    }
#undef RESOLVE

    return 0;
}

void wg_nt_deinit(void) {
    if (g_wg_dll) {
        FreeLibrary(g_wg_dll);
        g_wg_dll = nullptr;
    }
}

int wg_nt_is_initialized(void) {
    return g_wg_dll ? 1 : 0;
}

unsigned long wg_nt_get_driver_version(void) {
    if (!g_wg_dll) return 0;
    return WireGuardGetRunningDriverVersion();
}

// ---------------------------------------------------------------------------
// Adapter lifecycle
// ---------------------------------------------------------------------------

void* wg_nt_create_adapter(const char* name, const char* tunnel_type) {
    if (!g_wg_dll || !name) return nullptr;

    auto wname = utf8_to_wide(name);
    auto wtype = utf8_to_wide(tunnel_type ? tunnel_type : "WireGuard");

    return static_cast<void*>(
        WireGuardCreateAdapter(wname.c_str(), wtype.c_str(), nullptr));
}

void* wg_nt_open_adapter(const char* name) {
    if (!g_wg_dll || !name) return nullptr;

    auto wname = utf8_to_wide(name);
    return static_cast<void*>(WireGuardOpenAdapter(wname.c_str()));
}

void wg_nt_close_adapter(void* adapter) {
    if (!g_wg_dll || !adapter) return;
    WireGuardCloseAdapter(static_cast<WIREGUARD_ADAPTER_HANDLE>(adapter));
}

int wg_nt_set_adapter_state(void* adapter, int up) {
    if (!g_wg_dll || !adapter) return -1;

    auto state = up ? WIREGUARD_ADAPTER_STATE_UP : WIREGUARD_ADAPTER_STATE_DOWN;
    return WireGuardSetAdapterState(
        static_cast<WIREGUARD_ADAPTER_HANDLE>(adapter), state) ? 0 : -1;
}

// ---------------------------------------------------------------------------
// Interface configuration
// ---------------------------------------------------------------------------

int wg_nt_set_interface(void* adapter, const char* private_key, unsigned short listen_port) {
    if (!g_wg_dll || !adapter || !private_key) return -1;

    // Build a config with just the interface, no peers
    WIREGUARD_INTERFACE iface{};
    iface.Flags = static_cast<WIREGUARD_INTERFACE_FLAG>(
        WIREGUARD_INTERFACE_HAS_PRIVATE_KEY | WIREGUARD_INTERFACE_HAS_LISTEN_PORT);
    iface.ListenPort = listen_port;
    iface.PeersCount = 0;

    if (!base64_decode_key(private_key, iface.PrivateKey)) {
        return -1;
    }

    return WireGuardSetConfiguration(
        static_cast<WIREGUARD_ADAPTER_HANDLE>(adapter),
        &iface, sizeof(iface)) ? 0 : -1;
}

// ---------------------------------------------------------------------------
// Peer management
// ---------------------------------------------------------------------------

int wg_nt_add_peer(void* adapter, const char* pubkey, const char* allowed_ips,
                   const char* endpoint, unsigned short keepalive) {
    if (!g_wg_dll || !adapter || !pubkey) return -1;

    // Parse allowed IPs to count them
    std::vector<WIREGUARD_ALLOWED_IP> aips;
    if (allowed_ips && *allowed_ips) {
        std::istringstream stream(allowed_ips);
        std::string token;
        while (std::getline(stream, token, ',')) {
            auto start = token.find_first_not_of(" \t");
            auto end = token.find_last_not_of(" \t");
            if (start == std::string::npos) continue;
            auto trimmed = token.substr(start, end - start + 1);

            WIREGUARD_ALLOWED_IP aip{};
            ADDRESS_FAMILY family;
            union { IN_ADDR v4; IN6_ADDR v6; } addr{};

            if (parse_cidr_win(trimmed.c_str(), family, &addr, aip.Cidr)) {
                aip.AddressFamily = family;
                if (family == AF_INET) {
                    aip.Address.V4 = addr.v4;
                } else {
                    aip.Address.V6 = addr.v6;
                }
                aips.push_back(aip);
            }
        }
    }

    // Allocate contiguous buffer: WIREGUARD_INTERFACE + WIREGUARD_PEER + allowed_ips
    size_t total = sizeof(WIREGUARD_INTERFACE) + sizeof(WIREGUARD_PEER) +
                   aips.size() * sizeof(WIREGUARD_ALLOWED_IP);
    std::vector<BYTE> buf(total, 0);

    auto* iface = reinterpret_cast<WIREGUARD_INTERFACE*>(buf.data());
    auto* peer = reinterpret_cast<WIREGUARD_PEER*>(buf.data() + sizeof(WIREGUARD_INTERFACE));
    auto* aip_ptr = reinterpret_cast<WIREGUARD_ALLOWED_IP*>(
        buf.data() + sizeof(WIREGUARD_INTERFACE) + sizeof(WIREGUARD_PEER));

    // Interface: don't replace existing peers
    iface->Flags = static_cast<WIREGUARD_INTERFACE_FLAG>(0);
    iface->PeersCount = 1;

    // Peer
    peer->Flags = static_cast<WIREGUARD_PEER_FLAG>(
        WIREGUARD_PEER_HAS_PUBLIC_KEY | WIREGUARD_PEER_REPLACE_ALLOWED_IPS);
    if (!base64_decode_key(pubkey, peer->PublicKey)) return -1;

    if (endpoint && *endpoint) {
        if (parse_endpoint_win(endpoint, peer->Endpoint)) {
            peer->Flags = static_cast<WIREGUARD_PEER_FLAG>(
                peer->Flags | WIREGUARD_PEER_HAS_ENDPOINT);
        }
    }

    if (keepalive > 0) {
        peer->PersistentKeepalive = keepalive;
        peer->Flags = static_cast<WIREGUARD_PEER_FLAG>(
            peer->Flags | WIREGUARD_PEER_HAS_PERSISTENT_KEEPALIVE);
    }

    peer->AllowedIPsCount = static_cast<DWORD>(aips.size());

    // Copy allowed IPs
    for (size_t i = 0; i < aips.size(); ++i) {
        aip_ptr[i] = aips[i];
    }

    return WireGuardSetConfiguration(
        static_cast<WIREGUARD_ADAPTER_HANDLE>(adapter),
        iface, static_cast<DWORD>(total)) ? 0 : -1;
}

int wg_nt_remove_peer(void* adapter, const char* pubkey) {
    if (!g_wg_dll || !adapter || !pubkey) return -1;

    // Build config: interface + 1 peer with REMOVE flag
    struct {
        WIREGUARD_INTERFACE iface;
        WIREGUARD_PEER peer;
    } config{};

    config.iface.Flags = static_cast<WIREGUARD_INTERFACE_FLAG>(0);
    config.iface.PeersCount = 1;

    config.peer.Flags = static_cast<WIREGUARD_PEER_FLAG>(
        WIREGUARD_PEER_HAS_PUBLIC_KEY | WIREGUARD_PEER_REMOVE);
    if (!base64_decode_key(pubkey, config.peer.PublicKey)) return -1;
    config.peer.AllowedIPsCount = 0;

    return WireGuardSetConfiguration(
        static_cast<WIREGUARD_ADAPTER_HANDLE>(adapter),
        &config.iface, sizeof(config)) ? 0 : -1;
}

int wg_nt_get_peers(void* adapter, wg_nt_peer_info* peers, int max_peers) {
    if (!g_wg_dll || !adapter || !peers || max_peers <= 0) return -1;

    // Query configuration size first
    DWORD bytes = 0;
    WireGuardGetConfiguration(
        static_cast<WIREGUARD_ADAPTER_HANDLE>(adapter), nullptr, &bytes);
    if (bytes == 0) return 0;

    std::vector<BYTE> buf(bytes);
    auto* iface = reinterpret_cast<WIREGUARD_INTERFACE*>(buf.data());

    if (!WireGuardGetConfiguration(
            static_cast<WIREGUARD_ADAPTER_HANDLE>(adapter), iface, &bytes)) {
        return -1;
    }

    int count = 0;
    auto* ptr = reinterpret_cast<BYTE*>(iface + 1);

    for (DWORD i = 0; i < iface->PeersCount && count < max_peers; ++i) {
        auto* peer = reinterpret_cast<WIREGUARD_PEER*>(ptr);
        auto& info = peers[count];

        std::memset(&info, 0, sizeof(info));

        // Public key
        base64_encode_key(peer->PublicKey, info.public_key);

        // Endpoint
        auto ep = format_endpoint_win(peer->Endpoint);
        std::strncpy(info.endpoint, ep.c_str(), sizeof(info.endpoint) - 1);

        // Stats
        info.last_handshake = peer->LastHandshake;
        info.rx_bytes = peer->RxBytes;
        info.tx_bytes = peer->TxBytes;
        info.persistent_keepalive = peer->PersistentKeepalive;

        // Allowed IPs
        auto* aip_ptr = reinterpret_cast<WIREGUARD_ALLOWED_IP*>(peer + 1);
        std::string allowed;
        for (DWORD j = 0; j < peer->AllowedIPsCount; ++j) {
            char ip_buf[INET6_ADDRSTRLEN] = {};
            if (aip_ptr[j].AddressFamily == AF_INET) {
                InetNtopA(AF_INET, &aip_ptr[j].Address.V4, ip_buf, sizeof(ip_buf));
            } else if (aip_ptr[j].AddressFamily == AF_INET6) {
                InetNtopA(AF_INET6, &aip_ptr[j].Address.V6, ip_buf, sizeof(ip_buf));
            }
            if (!allowed.empty()) allowed += ", ";
            allowed += std::string(ip_buf) + "/" + std::to_string(aip_ptr[j].Cidr);
        }
        std::strncpy(info.allowed_ips, allowed.c_str(), sizeof(info.allowed_ips) - 1);

        ++count;

        // Advance past this peer and its allowed IPs
        ptr = reinterpret_cast<BYTE*>(aip_ptr + peer->AllowedIPsCount);
    }

    return count;
}

// ---------------------------------------------------------------------------
// Network helpers (Windows IP Helper API)
// ---------------------------------------------------------------------------

int wg_nt_set_address(void* adapter, const char* address) {
    if (!g_wg_dll || !adapter || !address) return -1;

    NET_LUID luid{};
    WireGuardGetAdapterLUID(static_cast<WIREGUARD_ADAPTER_HANDLE>(adapter), &luid);

    std::string addr_str(address);
    auto slash = addr_str.find('/');
    if (slash == std::string::npos) return -1;

    auto ip_str = addr_str.substr(0, slash);
    auto prefix = static_cast<BYTE>(std::stoul(addr_str.substr(slash + 1)));

    MIB_UNICASTIPADDRESS_ROW row{};
    InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = luid;
    row.OnLinkPrefixLength = prefix;
    row.DadState = IpDadStatePreferred;

    // Try IPv4
    IN_ADDR v4{};
    if (InetPtonA(AF_INET, ip_str.c_str(), &v4) == 1) {
        row.Address.si_family = AF_INET;
        row.Address.Ipv4.sin_addr = v4;
        return (CreateUnicastIpAddressEntry(&row) == NO_ERROR) ? 0 : -1;
    }

    // Try IPv6
    IN6_ADDR v6{};
    if (InetPtonA(AF_INET6, ip_str.c_str(), &v6) == 1) {
        row.Address.si_family = AF_INET6;
        row.Address.Ipv6.sin6_addr = v6;
        return (CreateUnicastIpAddressEntry(&row) == NO_ERROR) ? 0 : -1;
    }

    return -1;
}

int wg_nt_add_route(void* adapter, const char* destination) {
    if (!g_wg_dll || !adapter || !destination) return -1;

    NET_LUID luid{};
    WireGuardGetAdapterLUID(static_cast<WIREGUARD_ADAPTER_HANDLE>(adapter), &luid);

    ADDRESS_FAMILY family;
    BYTE prefix;
    union { IN_ADDR v4; IN6_ADDR v6; } addr{};

    if (!parse_cidr_win(destination, family, &addr, prefix)) return -1;

    MIB_IPFORWARD_ROW2 route{};
    InitializeIpForwardEntry(&route);
    route.InterfaceLuid = luid;
    route.DestinationPrefix.PrefixLength = prefix;
    route.DestinationPrefix.Prefix.si_family = family;
    route.Metric = 0;

    if (family == AF_INET) {
        route.DestinationPrefix.Prefix.Ipv4.sin_addr = addr.v4;
        route.NextHop.si_family = AF_INET;
    } else {
        route.DestinationPrefix.Prefix.Ipv6.sin6_addr = addr.v6;
        route.NextHop.si_family = AF_INET6;
    }

    return (CreateIpForwardEntry2(&route) == NO_ERROR) ? 0 : -1;
}

#endif // _WIN32
