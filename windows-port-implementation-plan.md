# Windows Port Implementation Plan

**Program:** Lemonade-Nexus Windows Port
**Program Manager:** Claude (AI PM)
**Analysis Reference:** `windows-port-analysis.md`
**Created:** 2026-04-08
**Target:** Full Windows Compatibility for WireGuard Mesh VPN Application

---

## Program Overview

### Objective
Transform Lemonade-Nexus from partial Windows support to full production-ready Windows compatibility, maintaining feature parity with Linux/macOS implementations.

### Scope
- **In Scope:** Core application, SDK, build system, packaging, service management, documentation
- **Out of Scope:** Feature additions beyond existing Linux/macOS functionality

### Success Criteria
1. Application builds successfully with MSVC on Windows 10/11
2. NSIS installer creates working Windows Service
3. WireGuard mesh VPN functionality operational
4. SDK works on Windows for client applications
5. Auto-update mechanism functional via PowerShell
6. All platform-specific tests pass

---

## Phase 1: Core Platform Abstraction (Critical Path)

**Duration:** 3-5 days
**Owner:** senior-developer
**Priority:** CRITICAL

### 1.1 Fix Unix Path References in Source Code

| Work Item | File | Effort | Status |
|-----------|------|--------|--------|
| 1.1.1 | `projects/LemonadeNexus/src/WireGuard/WireGuardService.cpp` | 4h | NOT STARTED |
| 1.1.2 | `projects/LemonadeNexusSDK/src/WireGuardTunnel.cpp` | 2h | NOT STARTED |
| 1.1.3 | `projects/LemonadeNexus/src/Core/HostnameGenerator.cpp` | 2h | NOT STARTED |
| 1.1.4 | `projects/LemonadeNexus/src/Storage/FileStorageService.cpp` | 2h | NOT STARTED |

**Deliverables:**
- All `2>/dev/null` patterns replaced with Windows equivalents
- All Unix paths replaced with cross-platform `std::filesystem` abstractions
- All Unix CLI commands (`ip`, `wg`) guarded or replaced

**Technical Approach:**
```cpp
// Pattern to apply throughout
#ifdef _WIN32
    // Windows implementation using IP Helper API, netsh, or native APIs
#else
    // Unix implementation using ip, wg commands
#endif
```

### 1.2 Implement Windows Service Entry Point

| Work Item | File | Effort | Status |
|-----------|------|--------|--------|
| 1.2.1 | Create `projects/LemonadeNexus/src/ServiceMain.cpp` | 4h | NOT STARTED |
| 1.2.2 | Modify `projects/LemonadeNexus/src/main.cpp` for service dispatch | 2h | NOT STARTED |
| 1.2.3 | Add Windows Event Log integration | 3h | NOT STARTED |

**Deliverables:**
- `ServiceMain.cpp` with `ServiceMain()` and `ServiceCtrlHandler()`
- Service can start/stop/pause via Windows SCM
- Fallback to console mode when not running as service

**Technical Approach:**
```cpp
// Service dispatch in main()
#ifdef _WIN32
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {"LemonadeNexus", (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };
    if (StartServiceCtrlDispatcher(ServiceTable)) {
        return 0;
    }
#endif
// Continue with console mode
```

### 1.3 Fix TEE Attestation for Windows

| Work Item | File | Effort | Status |
|-----------|------|--------|--------|
| 1.3.1 | Add Windows TEE stubs in `TeeAttestation.cpp` | 4h | NOT STARTED |
| 1.3.2 | Implement SGX attestation (optional) | 8h | NOT STARTED |

**Deliverables:**
- No compilation errors on Windows
- Graceful degradation if TEE not available

---

## Phase 2: Build System & Packaging

**Duration:** 2-3 days
**Owner:** senior-developer
**Priority:** HIGH

### 2.1 Complete NSIS Packaging Configuration

| Work Item | File | Effort | Status |
|-----------|------|--------|--------|
| 2.1.1 | Enhance `cmake/packaging.cmake` with NSIS extras | 3h | NOT STARTED |
| 2.1.2 | Create firewall rule installation | 2h | NOT STARTED |
| 2.1.3 | Create service registration in installer | 2h | NOT STARTED |

**Deliverables:**
- NSIS installer registers Windows Service
- Firewall rules created during installation
- Uninstaller cleans up service and rules

### 2.2 Create PowerShell Scripts

| Work Item | File | Effort | Status |
|-----------|------|--------|--------|
| 2.2.1 | Create `scripts/auto-update.ps1` | 6h | NOT STARTED |
| 2.2.2 | Create `scripts/install-service.ps1` | 3h | NOT STARTED |
| 2.2.3 | Create `scripts/uninstall-service.ps1` | 2h | NOT STARTED |

**Deliverables:**
- `auto-update.ps1`: GitHub release check, download, install, service restart
- `install-service.ps1`: Creates Windows Service with proper configuration
- `uninstall-service.ps1`: Stops and removes service

---

## Phase 3: SDK Windows Compatibility

**Duration:** 2-3 days
**Owner:** senior-developer
**Priority:** HIGH

### 3.1 Fix SDK Windows Issues

| Work Item | File | Effort | Status |
|-----------|------|--------|--------|
| 3.1.1 | Fix temp file paths in `WireGuardTunnel.cpp` | 2h | NOT STARTED |
| 3.1.2 | Verify `BoringTunBackend.cpp` WinTun support | 2h | NOT STARTED |
| 3.1.3 | Test SDK tunnel establishment on Windows | 4h | NOT STARTED |

**Deliverables:**
- SDK compiles without errors on Windows
- Tunnel creation functional via WinTun or wireguard-nt

---

## Phase 4: Testing & Quality Assurance

**Duration:** 3-5 days
**Owner:** testing-quality-specialist
**Priority:** HIGH

### 4.1 Build Verification

| Test Item | Platform | Status |
|-----------|----------|--------|
| CMake configuration | Windows 10/11, MSVC 2022 | NOT STARTED |
| Full build | x64 Release | NOT STARTED |
| Full build | x64 Debug | NOT STARTED |

### 4.2 Functional Testing

| Test Item | Description | Status |
|-----------|-------------|--------|
| Service installation | NSIS installer creates service | NOT STARTED |
| Service start/stop | SCM operations work correctly | NOT STARTED |
| WireGuard tunnel | Tunnel establishes successfully | NOT STARTED |
| Mesh connectivity | Multiple nodes can mesh | NOT STARTED |
| Auto-update | PowerShell script updates application | NOT STARTED |

### 4.3 Integration Testing

| Test Item | Description | Status |
|-----------|-------------|--------|
| SDK integration | External app can use SDK | NOT STARTED |
| Event logging | Events appear in Windows Event Log | NOT STARTED |
| Firewall rules | Rules created and functional | NOT STARTED |

---

## Phase 5: Documentation

**Duration:** 1-2 days
**Owner:** technical-writer-expert
**Priority:** MEDIUM

### 5.1 Create Windows Documentation

| Document | Description | Status |
|----------|-------------|--------|
| `docs/WINDOWS.md` | Windows-specific setup and usage | NOT STARTED |
| `docs/windows-service.md` | Service management guide | NOT STARTED |
| `docs/windows-sdk.md` | SDK usage on Windows | NOT STARTED |
| `README.md` updates | Add Windows build instructions | NOT STARTED |

---

## Risk Register

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| wireguard-nt API changes | High | Low | Pin to specific version, verify signature |
| MSVC compatibility issues | Medium | Medium | Early build testing, use standard C++ |
| Service permission issues | High | Medium | Test with admin/non-admin scenarios |
| TEE attestation gaps | Low | High | Implement graceful degradation |
| PowerShell execution policy | Medium | High | Document policy requirements |

---

## Dependencies

| Dependency | Owner | Status |
|------------|-------|--------|
| wireguard-nt binaries | External (WireGuard team) | Available |
| WinTun driver | External (WireGuard team) | Available |
| NSIS installer | Build system | Configured |
| Visual Studio 2022 | Development | Required |
| Windows SDK 10.0+ | Development | Required |

---

## Stakeholder Communication Plan

| Audience | Frequency | Channel | Content |
|----------|-----------|---------|---------|
| Development Team | Daily | Task comments | Progress, blockers |
| Technical Leadership | Phase completion | Summary report | Milestone status |
| End Users | Release | Release notes | Feature availability |

---

## Metrics & KPIs

| Metric | Target | Current |
|--------|--------|---------|
| Build success rate | 100% | TBD |
| Test pass rate | >95% | TBD |
| Critical bugs | 0 | TBD |
| Documentation coverage | 100% | 0% |

---

## Agent Handoff Points

1. **After Phase 1-3:** Handoff to `testing-quality-specialist`
2. **After Phase 4:** Handoff to `technical-writer-expert`
3. **After Phase 5:** Program closure and release

---

## Appendix: File Change Summary

### Files to Create (12)
1. `projects/LemonadeNexus/src/ServiceMain.cpp`
2. `scripts/auto-update.ps1`
3. `scripts/install-service.ps1`
4. `scripts/uninstall-service.ps1`
5. `packaging/windows/lemonade-nexus-service.xml`
6. `docs/WINDOWS.md`
7. `docs/windows-service.md`
8. `docs/windows-sdk.md`
9. `future-where-to-resume-left-off.md`

### Files to Modify (8)
1. `CMakeLists.txt`
2. `projects/LemonadeNexus/CMakeLists.txt`
3. `projects/LemonadeNexus/src/main.cpp`
4. `projects/LemonadeNexus/src/WireGuard/WireGuardService.cpp`
5. `projects/LemonadeNexus/src/Core/TeeAttestation.cpp`
6. `projects/LemonadeNexusSDK/src/WireGuardTunnel.cpp`
7. `cmake/packaging.cmake`
8. `README.md`

---

**Program Status:** INITIATED
**Next Action:** Begin Phase 1.1 - Fix Unix path references
