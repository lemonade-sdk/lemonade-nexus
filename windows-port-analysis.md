# Windows Port Analysis for Lemonade-Nexus

**Analysis Date:** 2026-04-08
**Project:** Lemonade-Nexus - WireGuard Mesh VPN Application
**Current Status:** Partial Windows support implemented, significant work remaining

---

## Executive Summary

Lemonade-Nexus has foundational Windows support through:
- `WireGuardWindowsBridge.cpp/h` - wireguard-nt integration
- CMake build system with Windows library linking
- NSIS packaging configuration

However, **the application is NOT fully Windows-compatible**. Critical gaps exist in:
1. Platform-specific code paths using Unix APIs and paths
2. Shell scripts requiring PowerShell equivalents
3. Service/daemon management for Windows
4. File system path handling
5. TEE attestation (Linux/Apple-specific)

**Estimated Effort:** 40-80 hours of development work

---

## 1. Files Requiring Modification

### 1.1 Core Application Files

| File | Priority | Changes Required |
|------|----------|------------------|
| `projects/LemonadeNexus/src/main.cpp` | CRITICAL | Windows data paths, service registration, path handling |
| `projects/LemonadeNexus/src/WireGuard/WireGuardService.cpp` | CRITICAL | BoringTun fallback, CLI commands, path handling |
| `projects/LemonadeNexus/src/Core/TeeAttestation.cpp` | HIGH | Windows TEE alternatives or stubs |
| `projects/LemonadeNexus/src/Core/HostnameGenerator.cpp` | MEDIUM | Windows hostname resolution |
| `projects/LemonadeNexus/src/Storage/FileStorageService.cpp` | MEDIUM | Windows path handling |
| `projects/LemonadeNexusSDK/src/WireGuardTunnel.cpp` | HIGH | Temp file paths, shell commands |
| `projects/LemonadeNexusSDK/src/BoringTunBackend.cpp` | MEDIUM | Already has Windows WinTun support |

### 1.2 CMake Build System Files

| File | Priority | Changes Required |
|------|----------|------------------|
| `CMakeLists.txt` | LOW | Already has Windows linking, verify completeness |
| `projects/LemonadeNexus/CMakeLists.txt` | LOW | Add Windows service install files |
| `cmake/packaging.cmake` | MEDIUM | Complete NSIS configuration |
| `cmake/CreateProject.cmake` | LOW | Review MSVC handling |

### 1.3 Scripts

| File | Priority | Changes Required |
|------|----------|------------------|
| `scripts/auto-update.sh` | HIGH | Create PowerShell equivalent |
| `scripts/generate_release_signing_key.py` | LOW | Already cross-platform (Python) |
| `scripts/generate_root_keypair.py` | LOW | Already cross-platform (Python) |

---

## 2. Platform-Specific Code Issues

### 2.1 Unix Paths in Source Code

**File: `projects/LemonadeNexus/src/WireGuard/WireGuardService.cpp`**

```cpp
// Line 107: Unix-specific command with /dev/null
auto version = run_command("wg --version 2>/dev/null");

// Line 124: Unix-specific command
auto ip_version = run_command("ip -V 2>/dev/null");

// Line 556: Linux TUN device (guarded by #ifdef __linux__)
int fd = open("/dev/net/tun", O_RDWR);

// Lines 593, 868, 2097, 2160, 2240: Unix CLI tools
run_command("ip route add ... 2>/dev/null");
run_command("ip link del ... 2>/dev/null");
run_command("ip link show ... 2>/dev/null");
run_command("ip addr flush dev ... 2>/dev/null");
```

**Required Changes:**
- Replace `2>/dev/null` with Windows-equivalent `2>$null` in PowerShell or use Windows API directly
- Add `#ifdef _WIN32` guards for all Unix-specific commands
- Implement Windows equivalents using `netsh`, `route`, or native Win32 APIs

### 2.2 Unix Paths in SDK

**File: `projects/LemonadeNexusSDK/src/WireGuardTunnel.cpp`**

```cpp
// Line 230: Unix temp path
path = "/tmp/lnsdk_wg0.conf";
```

**Required Changes:**
```cpp
// Current code already has Windows path handling at line 220-228
#if defined(_WIN32)
    char tmp[MAX_PATH];
    GetTempPathA(sizeof(tmp), tmp);
    path = std::string(tmp) + "lnsdk_wg0.conf";
#else
    path = "/tmp/lnsdk_wg0.conf";  // Consider using mkstemp for security
#endif
```

### 2.3 TEE Attestation - Linux/Apple Only

**File: `projects/LemonadeNexus/src/Core/TeeAttestation.cpp`**

```cpp
// Lines 102-103: macOS paths
if (std::filesystem::exists("/usr/libexec/seputil") ||
    std::filesystem::exists("/usr/sbin/bless"))

// Lines 115-132: Linux device paths
if (std::filesystem::exists("/dev/sev-guest"))
if (std::filesystem::exists("/dev/tdx-guest"))
if (std::filesystem::exists("/dev/sgx_enclave"))

// Lines 415, 502, 582: Device file operations
int fd = open("/dev/sgx_enclave", O_RDONLY);
int fd = open("/dev/tdx-guest", O_RDWR);
int fd = open("/dev/sev-guest", O_RDWR);
```

**Required Changes:**
- Add Windows TEE attestation via:
  - Intel SGX: Windows SGX SDK (`sgx_create_report`, etc.)
  - AMD SEV: Not typically available on Windows guests
  - Azure/AWS: Use cloud provider attestation APIs
- Or stub the implementation for Windows with `#ifdef _WIN32`

### 2.4 Shell Command Patterns

Multiple files use Unix shell redirection that won't work on Windows:

| Pattern | Unix | Windows PowerShell | Windows CMD |
|---------|------|-------------------|-------------|
| Redirect stderr | `2>/dev/null` | `2>$null` | `2>nul` |
| Redirect stdout | `>/dev/null` | `>$null` | `>nul` |
| Path separator | `/` | `\` or `/` | `\` |
| Temp dir | `/tmp` | `$env:TEMP` | `%TEMP%` |
| Home dir | `~` or `$HOME` | `$env:USERPROFILE` | `%USERPROFILE%` |

---

## 3. Scripts - PowerShell Equivalents Needed

### 3.1 Auto-Update Script

**Current: `scripts/auto-update.sh`**

Key functionality to port:
- GitHub API calls for latest release
- Version comparison
- Download and install .msi/.exe packages
- Windows Service management (instead of systemd)

**Required: `scripts/auto-update.ps1`**

```powershell
# Key Windows differences:
# - No systemd - use Windows Service (New-Service, Start-Service)
# - Use .msi or .exe installer instead of .deb
# - WMI or Registry for version tracking
# - Scheduled Tasks instead of systemd timers
```

### 3.2 Service Installation Script

**Required: `scripts/install-service.ps1`**

```powershell
# Windows equivalent of debian/postinst
# Create Windows Service for lemonade-nexus.exe
New-Service -Name "LemonadeNexus" `
            -BinaryPathName "C:\Program Files\Lemonade-Nexus\bin\lemonade-nexus.exe" `
            -DisplayName "Lemonade-Nexus Mesh VPN Server" `
            -Description "Self-hosted WireGuard mesh VPN server" `
            -StartupType Automatic

# Set service recovery options
sc.exe failure LemonadeNexus reset= 86400 actions= restart/60000/restart/60000/restart/60000
```

### 3.3 Uninstall Script

**Required: `scripts/uninstall-service.ps1`**

```powershell
# Windows equivalent of debian/prerm
Stop-Service -Name "LemonadeNexus" -Force
Remove-Service -Name "LemonadeNexus"
```

---

## 4. Build System Changes Required

### 4.1 Current CMake Configuration Status

**File: `CMakeLists.txt`**

Current Windows library linking (lines 36-39):
```cmake
if(WIN32)
    target_link_libraries(LemonadeNexus PRIVATE ws2_32 mswsock iphlpapi urlmon wintrust shell32)
    target_link_libraries(LemonadeNexusApp PRIVATE ws2_32 mswsock iphlpapi urlmon wintrust shell32)
endif()
```

**Status:** Good foundation, may need additional libraries.

### 4.2 Missing Windows Components

1. **Windows Service Installation in CMake**

```cmake
# Add to projects/LemonadeNexus/CMakeLists.txt
if(WIN32)
    install(FILES "${CMAKE_SOURCE_DIR}/packaging/windows/lemonade-nexus-service.xml"
            DESTINATION bin
            COMPONENT Runtime)
    # Consider using WiX Toolset instead of NSIS for service management
endif()
```

2. **NSIS Configuration Improvements**

**File: `cmake/packaging.cmake`** (lines 100-108)

Current configuration is minimal. Add:
```cmake
set(CPACK_NSIS_INSTALLED_ICON_NAME "bin\\\\lemonade-nexus.exe")
set(CPACK_NSIS_DISPLAY_NAME "Lemonade-Nexus Mesh VPN")
set(CPACK_NSIS_HELP_LINK "https://github.com/geramyloveless/lemonade-nexus")
set(CPACK_NSIS_URL_INFO_ABOUT "https://github.com/geramyloveless/lemonade-nexus")
set(CPACK_NSIS_CONTACT "admin@lemonade-nexus.io")
set(CPACK_NSIS_MODIFY_PATH ON)

# Register as Windows Service
set(CPACK_NSIS_EXTRA_INSTALL_COMMANDS "
    ExecuteWait 'netsh advfirewall firewall add rule name=\"Lemonade-Nexus\" dir=in action=allow program=\"\\$INSTDIR\\\\bin\\\\lemonade-nexus.exe\" enable=yes'
    ExecuteWait 'sc create LemonadeNexus binPath=\"\\$INSTDIR\\\\bin\\\\lemonade-nexus.exe\" start=auto DisplayName=\"Lemonade-Nexus Mesh VPN Server\"'
")

set(CPACK_NSIS_EXTRA_UNINSTALL_COMMANDS "
    ExecuteWait 'sc delete LemonadeNexus'
    ExecuteWait 'netsh advfirewall firewall delete rule name=\"Lemonade-Nexus\"'
")
```

### 4.3 WireGuard Backend Configuration

**File: `cmake/libraries/wireguard-nt.cmake`**

**Status:** Correctly configured for Windows wireguard-nt.

Verify the wireguard.dll download URL matches current version.

---

## 5. Missing Windows-Specific Implementations

### 5.1 Windows Service Main Entry Point

**Required: `projects/LemonadeNexus/src/main_windows.cpp`**

Create a Windows service wrapper:

```cpp
// Windows Service entry point
SERVICE_STATUS        g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
    // Register service handler
    g_StatusHandle = RegisterServiceCtrlHandler("LemonadeNexus", ServiceCtrlHandler);
    // Start actual service logic
}

VOID WINAPI ServiceCtrlHandler(DWORD dwControl) {
    switch(dwControl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            // Call main shutdown logic
            break;
        case SERVICE_CONTROL_PAUSE:
        case SERVICE_CONTROL_CONTINUE:
        case SERVICE_CONTROL_INTERROGATE:
        default:
            break;
    }
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Check if running as service
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {"LemonadeNexus", (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };
    if (StartServiceCtrlDispatcher(ServiceTable)) {
        return 0;  // Running as service
    }
    // Fall through to console mode
#endif
    // Original main() logic
}
```

### 5.2 Windows Event Logging

Replace spdlog file/stdout logging with Windows Event Log:

```cpp
#include <windows.h>
#include <evntprov.h>

class WindowsEventLogger {
public:
    void Initialize() {
        RegisterEventSource(NULL, "LemonadeNexus");
    }

    void Log(const std::string& message, WORD type) {
        const char* msg = message.c_str();
        ReportEvent(eventSource, type, 0, 1, NULL, 1, 0, &msg, NULL);
    }
};
```

### 5.3 Windows Credential Storage

Instead of file-based key storage, use Windows Credential Manager:

```cpp
#include <wincred.h>

bool StoreCredential(const std::string& name, const std::vector<uint8_t>& data) {
    CREDENTIAL cred = {0};
    cred.Type = CRED_TYPE_GENERIC;
    cred.TargetName = const_cast<char*>(name.c_str());
    cred.CredentialBlobSize = data.size();
    cred.CredentialBlob = (BYTE*)data.data();
    cred.Persist = CRED_PERSIST_LOCAL_MACHINE;
    return CredWrite(&cred, 0) != FALSE;
}
```

### 5.4 Named Pipes for IPC

For Windows-specific IPC needs:

```cpp
// If the application needs IPC between service and user-mode tools
HANDLE hPipe = CreateNamedPipe(
    "\\\\.\\pipe\\LemonadeNexus",
    PIPE_ACCESS_DUPLEX,
    PIPE_TYPE_MESSAGE | PIPE_WAIT,
    PIPE_UNLIMITED_INSTANCES,
    512, 512, 0, NULL);
```

---

## 6. File System Path Considerations

### 6.1 Standard Windows Paths

| Purpose | Linux/macOS | Windows |
|---------|-------------|---------|
| Data directory | `/var/lib/lemonade-nexus` | `C:\ProgramData\Lemonade-Nexus` |
| Config directory | `/etc/lemonade-nexus` | `C:\ProgramData\Lemonade-Nexus\config` |
| Log directory | `/var/log/lemonade-nexus` | `C:\ProgramData\Lemonade-Nexus\logs` |
| Temp directory | `/tmp` | `%TEMP%` |
| User config | `~/.config/lemonade-nexus` | `%APPDATA%\Lemonade-Nexus` |

### 6.2 Code Pattern for Cross-Platform Paths

```cpp
std::filesystem::path get_data_root() {
#ifdef _WIN32
    char program_data[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPath(NULL, CSIDL_COMMON_APPDATA, NULL, 0, program_data))) {
        return std::filesystem::path(program_data) / "Lemonade-Nexus" / "data";
    }
    return std::filesystem::current_path() / "data";
#else
    return "/var/lib/lemonade-nexus/data";
#endif
}
```

---

## 7. WireGuard Backend Status on Windows

### 7.1 Current Implementation Status

| Backend | Platform | Status |
|---------|----------|--------|
| wireguard-nt | Windows | **Implemented** via `WireGuardWindowsBridge.cpp` |
| wireguard-go | macOS | Implemented via `WireGuardAppleBridge.mm` |
| embeddable-wg | Linux | Implemented via netlink |
| BoringTun | Fallback | Partially implemented (TUN device abstraction exists) |

### 7.2 WireGuardWindowsBridge Analysis

**File: `projects/LemonadeNexus/src/WireGuard/WireGuardWindowsBridge.cpp`**

**Strengths:**
- Complete wireguard-nt function pointer resolution
- Auto-download of wireguard.dll from official source
- Authenticode signature verification
- IP address and route configuration via IP Helper API
- Endpoint parsing for IPv4 and IPv6

**Issues to Address:**
- Line 394-409: Uses `tar` command for ZIP extraction (Windows 10+ has tar, but consider pure C++ extraction)
- Line 239: Download URL hardcoded - should be configurable
- No error handling for ARM64 architecture detection edge cases

### 7.3 WireGuardService Windows Path

**File: `projects/LemonadeNexus/src/WireGuard/WireGuardService.cpp`**

Windows-specific sections (lines 10-12, 24-26, 93-104, 156-162, 1051-1069, etc.) are well-implemented.

**Missing:**
- Fallback when wireguard-nt is unavailable (BoringTun should work on Windows via WinTun)
- Windows event logging integration

---

## 8. Dependency Status for Windows

| Library | Windows Support | Notes |
|---------|-----------------|-------|
| OpenSSL | OK | cmake/libraries/openssl.cmake has WIN32 support |
| libsodium | OK | cmake/libraries/libsodium.cmake builds on Windows |
| SQLite3 | OK | cmake/libraries/sqlite3.cmake is cross-platform |
| c-ares | OK | cmake/libraries/c-ares.cmake is cross-platform |
| asio | OK | Header-only, cross-platform |
| nlohmann/json | OK | Header-only, cross-platform |
| spdlog | OK | Header-only, cross-platform |
| jwt-cpp | OK | Header-only, cross-platform |
| boringtun-ffi | OK | cmake/libraries/boringtun.cmake has WIN32 linking |
| wireguard-nt | OK | Windows-specific, configured |
| wireguard-apple | N/A | Skipped on Windows |

---

## 9. Testing Considerations for Windows

### 9.1 Unit Tests

Existing tests in `tests/` directory should compile on Windows with:
- Visual Studio 2022 or newer
- CMake 3.25.1+
- Windows SDK 10.0+

### 9.2 Integration Tests Required

1. **WireGuard tunnel establishment** - Verify wireguard-nt creates functional tunnels
2. **Service installation** - Verify NSIS installer creates working Windows Service
3. **Auto-update mechanism** - Test PowerShell update script
4. **File permissions** - Verify config file ACLs are correctly set
5. **Network operations** - Test firewall rules and port binding

---

## 10. Recommended Implementation Priority

### Phase 1: Critical Path (20-30 hours)
1. Fix all Unix path references in source code
2. Add Windows service entry point
3. Create PowerShell installation/uninstallation scripts
4. Complete NSIS packaging with service registration
5. Test WireGuard tunnel functionality

### Phase 2: Feature Completeness (15-25 hours)
6. Implement Windows TEE attestation stubs
7. Add Windows Event Log integration
8. Create Windows-specific documentation
9. Add Windows CI/CD pipeline (GitHub Actions with Windows runner)

### Phase 3: Polish (5-15 hours)
10. Windows Credential Manager integration
11. Firewall rule automation
12. Performance optimization
13. Security hardening

---

## 11. File Checklist

### Files to Create

- [ ] `packaging/windows/lemonade-nexus-service.xml` (if using WiX)
- [ ] `packaging/windows/install-service.ps1`
- [ ] `packaging/windows/uninstall-service.ps1`
- [ ] `scripts/auto-update.ps1`
- [ ] `projects/LemonadeNexus/src/ServiceMain.cpp` (Windows Service entry)
- [ ] `docs/WINDOWS.md` (Windows-specific documentation)

### Files to Modify

- [ ] `CMakeLists.txt` - Verify complete Windows configuration
- [ ] `projects/LemonadeNexus/CMakeLists.txt` - Add Windows service files
- [ ] `projects/LemonadeNexus/src/main.cpp` - Windows service integration
- [ ] `projects/LemonadeNexus/src/WireGuard/WireGuardService.cpp` - Fix Unix paths
- [ ] `projects/LemonadeNexus/src/Core/TeeAttestation.cpp` - Windows TEE support
- [ ] `projects/LemonadeNexusSDK/src/WireGuardTunnel.cpp` - Fix temp paths
- [ ] `cmake/packaging.cmake` - Complete NSIS configuration
- [ ] `packaging/debian/postinst` -> Create Windows equivalent

---

## 12. Conclusion

Lemonade-Nexus has a solid foundation for Windows support, particularly in the WireGuard integration layer. The primary gaps are:

1. **Operational Scripts** - Shell scripts need PowerShell equivalents
2. **Service Management** - Windows Service entry point and registration
3. **Path Handling** - Unix-specific paths throughout the codebase
4. **TEE Attestation** - Linux-specific device files need Windows alternatives
5. **Packaging** - NSIS configuration needs completion

With focused development effort following the priorities outlined above, full Windows compatibility is achievable without significant architectural changes.

---

**Analysis performed by:** Dr. Sarah Kim, Technical Product Strategist & Engineering Lead
**Based on codebase revision:** Git commit 5826a2d (Update README.md)
