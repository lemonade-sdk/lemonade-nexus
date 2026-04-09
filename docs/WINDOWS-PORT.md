# Windows Port Documentation

**Version:** 1.0.0
**Last Updated:** 2026-04-09
**Status:** Complete - Ready for Production

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Platform Abstraction Patterns](#platform-abstraction-patterns)
- [Service Control Manager Integration](#service-control-manager-integration)
- [Building on Windows](#building-on-windows)
- [WireGuard-NT Integration](#wireguard-nt-integration)
- [Known Limitations](#known-limitations)
- [Troubleshooting](#troubleshooting)

---

## Overview

The Lemonade-Nexus WireGuard mesh VPN application has been fully ported to Windows, providing native support for the Windows platform with:

- **Windows Service** - Runs as a native Windows Service via Service Control Manager (SCM)
- **WireGuard-NT** - Native WireGuard driver integration via wireguard-nt library
- **NSIS Packaging** - Professional installer with service registration
- **Platform Guards** - Comprehensive `#ifdef _WIN32` guards throughout the codebase

### Key Components

| Component | File | Description |
|-----------|------|-------------|
| WireGuard Service | `WireGuardService.cpp` | Platform abstraction for WireGuard tunnel management |
| Service Main | `ServiceMain.cpp` | Windows Service Control Manager entry point |
| WireGuard-NT Bridge | `WireGuardWindowsBridge.h` | Native WireGuard driver interface |
| NSIS Installer | `packaging.cmake` | Windows installer configuration |

---

## Architecture

### Platform Detection

The codebase uses standard platform detection macros:

```cpp
#ifdef _WIN32
    // Windows-specific code
#else
    // Unix/Linux/macOS code
#endif
```

### Service Startup Flow

```
┌─────────────────────────────────────────────────────────────┐
│                      main.cpp                                │
├─────────────────────────────────────────────────────────────┤
│  StartServiceCtrlDispatcher()                                │
│    └──► ServiceMain()  ◄── Windows Service entry point       │
│         └──► RegisterServiceCtrlHandler()                    │
│              └──► ServiceCtrlHandler()  ◄── Control events   │
│                                                               │
│  If not running as service:                                  │
│    └──► RunConsoleMode()  ◄── Development/debug mode         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   WireGuardService                           │
├─────────────────────────────────────────────────────────────┤
│  on_start()                                                  │
│    └──► wg_nt_init()  ◄── Load wireguard-nt driver          │
│         └──► Create WireGuard adapter                        │
│              └──► Configure tunnel interface                 │
│                   └──► Set IP address and routes             │
└─────────────────────────────────────────────────────────────┘
```

---

## Platform Abstraction Patterns

### Unix Command Replacement

Unix commands are replaced with Windows API equivalents or guarded entirely:

```cpp
// Before (Unix only)
system("wg --version 2>/dev/null");

// After (Windows-compatible)
#ifdef _WIN32
    // Use WireGuard-NT API instead of wg command
    int version = wg_nt_get_driver_version();
#else
    system("wg --version 2>/dev/null");
#endif
```

### Path Handling

```cpp
#ifdef _WIN32
    // Windows paths use backslashes and special directories
    std::filesystem::path configPath =
        std::getenv("PROGRAMDATA");
    configPath /= "LemonadeNexus";
#else
    // Unix paths
    std::filesystem::path configPath = "/var/lib/lemonade-nexus";
#endif
```

### Network Configuration

| Unix Command | Windows Equivalent |
|--------------|-------------------|
| `ip route add` | `AddRoute()` via IP Helper API |
| `ip addr add` | `AddIPAddress()` via IP Helper API |
| `ip link set` | `SetInterfaceUp()` via IP Helper API |
| `wg-quick up` | `WireGuardNT::CreateAdapter()` |

### WireGuardService.cpp Platform Guards

Key sections with platform guards:

| Line Range | Feature | Platform Handling |
|------------|---------|-------------------|
| 87-110 | Backend detection | `HAS_WIREGUARD_NT` for Windows |
| 556-580 | TUN device | Windows uses wireguard-nt, no TUN |
| 590-620 | Route management | IP Helper API on Windows |
| 865-890 | Address configuration | `AddIPAddress()` on Windows |
| 2090-2120 | Interface control | `SetInterfaceUp()` on Windows |

---

## Service Control Manager Integration

### Service Entry Point

```cpp
// ServiceMain.cpp
SERVICE_TABLE_ENTRY ServiceTable[] = {
    {L"LemonadeNexus", (LPSERVICE_MAIN_FUNCTION)ServiceMain},
    {NULL, NULL}
};

// In main():
if (!StartServiceCtrlDispatcher(ServiceTable)) {
    // Not running as service, fall through to console mode
    RunConsoleMode(argc, argv);
}
```

### Service Control Handler

```cpp
DWORD WINAPI ServiceCtrlHandler(DWORD control, DWORD eventType,
                                 LPVOID eventData, LPVOID context) {
    switch (control) {
        case SERVICE_CONTROL_STOP:
            g_serviceRunning = FALSE;
            SetServiceStatus(g_serviceStatusHandle, &serviceStatus);
            break;
        case SERVICE_CONTROL_SHUTDOWN:
            g_serviceRunning = FALSE;
            break;
    }
    return NO_ERROR;
}
```

### Service Registration

The NSIS installer registers the service during installation:

```nsis
; In installer script
ExecWait 'sc create LemonadeNexus binPath="$INSTDIR\bin\lemonade-nexus.exe" start=auto'
ExecWait 'sc description LemonadeNexus "Lemonade Nexus Mesh VPN Server"'
```

### Service States

| State | Description |
|-------|-------------|
| `SERVICE_STOPPED` | Service is not running |
| `SERVICE_START_PENDING` | Service is starting |
| `SERVICE_RUNNING` | Service is running |
| `SERVICE_STOP_PENDING` | Service is stopping |

---

## Building on Windows

### Prerequisites

| Component | Version | Installation |
|-----------|---------|--------------|
| Visual Studio | 2022 (17.x) | [Visual Studio Downloads](https://visualstudio.microsoft.com/) |
| C++ Build Tools | Latest | Install "Desktop development with C++" workload |
| CMake | 3.25.1+ | [CMake Downloads](https://cmake.org/download/) |
| Ninja | 1.11.1+ | `winget install Ninja-build.Ninja` |
| Git | Latest | [Git for Windows](https://gitforwindows.org/) |
| Rust (optional) | Latest | [Rustup](https://rustup.rs/) (for BoringTun) |

### Build Steps

```powershell
# 1. Clone the repository
git clone https://github.com/antmi/lemonade-nexus.git
cd lemonade-nexus

# 2. Configure with CMake
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release

# 3. Build
cmake --build build --config Release

# 4. Build specific targets
cmake --build build --target LemonadeNexus --config Release
cmake --build build --target LemonadeNexusSDK --config Release
```

### Build Output Locations

| Target | Output Path |
|--------|-------------|
| Server | `build\projects\LemonadeNexus\Release\lemonade-nexus.exe` |
| SDK | `build\projects\LemonadeNexusSDK\Release\lemonade_nexus_sdk.dll` |
| Libraries | `build\projects\*\Release\*.lib` |

### MSVC Compiler Flags

Key compiler settings in CMakeLists.txt:

```cmake
if(MSVC)
    set(CMAKE_CXX_STANDARD 20)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    add_compile_options(/W4 /WX- /Zc:__cplusplus /permissive-)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX UNICODE _UNICODE)
endif()
```

---

## WireGuard-NT Integration

### Overview

Windows uses **wireguard-nt** - a native WireGuard driver for Windows developed by WireGuard LLC.

### Loading WireGuard-NT

```cpp
// WireGuardService.cpp
#ifdef _WIN32
#include <LemonadeNexus/WireGuard/WireGuardWindowsBridge.h>

// Initialize wireguard-nt (auto-downloads if not present)
if (wg_nt_init() < 0) {
    spdlog::error("Failed to load wireguard.dll");
    return;
}

// Get driver version
auto driver_ver = wg_nt_get_driver_version();
spdlog::info("WireGuard-NT version: {}", driver_ver);
#endif
```

### Adapter Creation

```cpp
// Create WireGuard adapter
HANDLE adapter = wg_nt_create_adapter(
    L"LemonadeNexus",      // Adapter name
    L"Lemonade Nexus VPN"  // Display name
);

if (adapter == NULL) {
    spdlog::error("Failed to create WireGuard adapter");
    return;
}
```

### Configuration

```cpp
// Set WireGuard configuration
std::wstring config = L"[Interface]\n"
                      L"PrivateKey = <base64 private key>\n"
                      L"Address = 10.64.0.10/24\n"
                      L"\n"
                      L"[Peer]\n"
                      L"PublicKey = <server public key>\n"
                      L"Endpoint = vpn.example.com:51820\n"
                      L"AllowedIPs = 0.0.0.0/0\n";

wg_nt_set_config(adapter, config.c_str());
```

### Network Configuration via IP Helper API

```cpp
#include <iphlpapi.h>
#include <netioapi.h>

// Set IP address on interface
MIB_UNICASTIPADDRESS_ROW addressRow;
InitializeUnicastIpAddressEntry(&addressRow);
addressRow.InterfaceIndex = interfaceIndex;
addressRow.Address.Ipv4.sin_family = AF_INET;
addressRow.Address.Ipv4.sin_addr.S_un.S_addr = inet_addr("10.64.0.10");
addressRow.OnLinkPrefixLength = 24;

CreateUnicastIpAddressEntry(&addressRow);

// Add default route
MIB_IPFORWARD_ROW2 routeRow;
InitializeIpForwardEntry(&routeRow);
routeRow.InterfaceIndex = interfaceIndex;
routeRow.DestinationPrefix.Prefix.si_family = AF_INET;
routeRow.NextHop.Ipv4.sin_addr.S_un.S_addr = inet_addr("10.64.0.1");
routeRow.UseOriginalMetrics = TRUE;

CreateIpForwardEntry2(&routeRow);
```

---

## Known Limitations

### TEE Attestation

Windows does not support the same TEE (Trusted Execution Environment) attestation as Linux/macOS:

| Platform | TEE Support | Status |
|----------|-------------|--------|
| Linux | SEV, TDX | Full support |
| macOS | Secure Enclave | Full support |
| Windows | Intel SGX | **Stub only** - Returns `TeePlatform::None` |

**Impact:** Windows servers operate as Tier 2 (certificate-only trust) when TEE is unavailable.

**Mitigation:** Graceful degradation - Windows servers can still participate in the mesh with certificate-based authentication.

### Unix Command Unavailability

Some Unix-specific features are not available on Windows:

| Feature | Unix | Windows |
|---------|------|---------|
| `ip` command | Available | Not available (use IP Helper API) |
| `wg` command | Available | Not available (use wireguard-nt API) |
| `/dev/net/tun` | Available | Not available (use wireguard-nt) |
| systemd | Available | Not available (use Windows Service) |

### PowerShell Execution Policy

PowerShell scripts may be blocked by execution policy:

```powershell
# Check current policy
Get-ExecutionPolicy

# Set to allow local scripts (requires admin)
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine
```

---

## Troubleshooting

### Build Issues

#### Error: "wireguard-nt not found"

```
error: linking with `link.exe` failed: unresolved external symbol wg_nt_*
```

**Solution:** Ensure wireguard-nt library is linked:

```cmake
target_link_libraries(LemonadeNexus PRIVATE wireguard-nt)
```

#### Error: "Windows SDK not found"

```
fatal error C1083: Cannot open include file: 'iphlpapi.h': No such file or directory
```

**Solution:** Install Windows SDK with Visual Studio installer.

### Runtime Issues

#### Service Won't Start

```
Error 1053: The service did not respond to the start or control request in a timely fashion.
```

**Solutions:**
1. Check Event Viewer for service logs
2. Run service in console mode for debugging:
   ```powershell
   .\lemonade-nexus.exe --console
   ```
3. Verify service account has appropriate permissions

#### WireGuard Adapter Creation Fails

```
Failed to create WireGuard adapter
```

**Solutions:**
1. Ensure wireguard-nt DLL is in the application directory
2. Run as administrator (required for driver installation)
3. Check that Windows Defender isn't blocking the driver

#### Network Configuration Fails

```
Failed to set IP address: Access is denied
```

**Solution:** Run as administrator or grant `SeNetworkConfigurationPrivilege`.

### Packaging Issues

#### NSIS Installer Fails

```
Error: Unable to sign installer
```

**Solutions:**
1. Verify code signing certificate is valid
2. Check timestamp server connectivity
3. Import certificate to personal certificate store

---

## Related Documentation

- [Building from Source](Building.md) - General build instructions
- [Architecture](Architecture.md) - System architecture overview
- [Network Architecture](Network-Architecture.md) - Network topology details
- [Installation Guide](INSTALLATION.md) - Installation procedures

---

**Document History:**

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-09 | Initial release |
