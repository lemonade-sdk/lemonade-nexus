# Windows Client Strategy: Flutter/Dart vs Raw C++

**Document Date:** 2026-04-08
**Purpose:** Technology selection for Windows client UI implementation

---

## Current Architecture Summary

### C SDK FFI Surface (`lemonade_nexus.h`)
- **40+ C functions** covering all API operations
- **Opaque handle API** (`ln_client_t`, `ln_identity_t`)
- **JSON-based data exchange** - all complex data returned as JSON strings
- **Memory management** via `ln_free()` - clean FFI semantics
- **Perfect for FFI bindings** from any language

### macOS Client Structure (Reference Implementation)
```
apps/LemonadeNexusMac/
├── Sources/LemonadeNexusMac/
│   ├── Views/           (~12 SwiftUI views)
│   │   ├── ContentView.swift
│   │   ├── LoginView.swift
│   │   ├── DashboardView.swift
│   │   ├── TunnelControlView.swift
│   │   ├── PeersListView.swift
│   │   ├── NetworkMonitorView.swift
│   │   ├── TreeBrowserView.swift
│   │   ├── ServersView.swift
│   │   ├── CertificatesView.swift
│   │   ├── SettingsView.swift
│   │   └── ...
│   ├── Services/        (SDK wrappers, tunnel management)
│   │   ├── NexusSDK.swift      ← C FFI wrapper
│   │   ├── TunnelManager.swift
│   │   ├── DnsDiscovery.swift
│   │   └── ...
│   └── Models/          (Swift structs for API data)
│       ├── APIModels.swift
│       └── AppState.swift
└── Packaging/
```

**Lines of UI Code (macOS):** ~3,500 lines across 12 view files + ~800 lines services

---

## Technology Options Analysis

### Option 1: Flutter/Dart (RECOMMENDED)

#### Upsides

| Category | Benefit |
|----------|---------|
| **Cross-Platform** | Single codebase for Windows, macOS, Linux - can REPLACE the SwiftUI macOS app |
| **FFI Support** | Dart FFI is mature and well-documented for C interop |
| **Development Speed** | Hot reload enables rapid UI iteration |
| **UI Quality** | Modern, polished widgets out of the box |
| **Maintainability** | One codebase to maintain, not three |
| **Future-Proof** | Google actively develops Flutter; Windows support is strong |
| **Package Ecosystem** | Rich pub.dev ecosystem for common UI needs |
| **Performance** | More than adequate for dashboard/monitoring UI |

#### Downsides

| Category | Impact | Mitigation |
|----------|--------|------------|
| **Runtime Size** | +15-25MB for Dart VM | Acceptable for VPN client (not embedded) |
| **Learning Curve** | Dart language | Easy for devs familiar with Java/C#/TS |
| **"Native" Feel** | Slightly different from WinUI | Flutter's Material/Cupertino themes are close |
| **FFI Marshalling** | JSON parsing overhead | Minimal impact for dashboard-style UI |
| **Build Complexity** | Need Flutter toolchain | Well-documented, CI/CD friendly |

#### FFI Binding Complexity

```dart
// Example Dart FFI binding for ln_create
typedef LnCreateNative = Pointer<Void> Function(Pointer<Utf8> host, Uint16 port);
typedef LnCreate = Pointer<Void> Function(Pointer<Utf8> host, int port);

final class LemonadeNexusSdk {
  final ffi.DynamicLibrary _lib;

  LemonadeNexusSdk(this._lib) {
    _create = _lib
        .lookup<ffi.NativeFunction<LnCreateNative>>('ln_create')
        .asFunction<LnCreate>();
  }

  late final LnCreate _create;

  LemonadeNexusClient create(String host, int port) {
    return LemonadeNexusClient(_create(host.toNativeUtf8(), port));
  }
}
```

**Estimated FFI Wrapper Code:** ~400-500 lines of Dart (one wrapper per C function)

---

### Option 2: Raw C++ (Qt or WinUI 3)

#### Upsides

| Category | Benefit |
|----------|---------|
| **Native Look** | 100% native Windows controls |
| **No Runtime** | No additional VM/runtime dependency |
| **Direct Integration** | C++ SDK can be used directly (no FFI) |
| **Performance** | Best for compute-heavy UI (not needed here) |

#### Downsides

| Category | Impact |
|----------|--------|
| **Windows-Only** | Requires separate macOS/Linux UI codebases |
| **Qt Licensing** | LGPL/commercial licensing complexity |
| **UI Development** | More verbose, slower iteration (no hot reload) |
| **Polish Effort** | More work to achieve modern appearance |
| **WinUI 3** | Still maturing, limited cross-platform |
| **Future Work** | If macOS app needs rewriting, duplicate effort |

#### Code Structure (Qt Example)

```cpp
// MainWindow.h
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
private slots:
    void onLoginButtonClicked();
    void onTunnelToggleButton();
    void refreshPeerList();
private:
    Ui::MainWindow *ui;
    LemonadeNexusClient* m_client;
};
```

**Estimated Code:** Similar LOC to macOS Swift (~4,000 lines) but Windows-only

---

### Option 3: C#/.NET (WPF or WinUI 3)

#### Upsides

| Category | Benefit |
|----------|---------|
| **Native Windows** | Deep Windows integration |
| **P/Invoke** | Mature FFI via P/Invoke |
| **Tooling** | Excellent Visual Studio support |
| **Ecosystem** | Large .NET ecosystem |

#### Downsides

| Category | Impact |
|----------|--------|
| **Windows-Only** | No code reuse for macOS/Linux |
| **Runtime** | .NET runtime required anyway (~50MB) |
| **Future** | Microsoft pushing MAUI (cross-platform) but immature |

---

## Recommendation: Flutter/Dart

### Why Flutter Wins

1. **Cross-Platform from Day 1**
   - Write once, deploy to Windows, macOS, Linux
   - Can replace the existing SwiftUI macOS app
   - Single team, single codebase

2. **Perfect FFI Match**
   - C SDK's JSON-based return types map cleanly to Dart
   - Opaque handles (`ln_client_t`) work as `Pointer<Void>`
   - Memory management is explicit (`ln_free`)

3. **Modern Development Experience**
   - Hot reload for instant UI feedback
   - Rich widget library
   - Strong IDE support (VS Code, IntelliJ)

4. **Strategic Alignment**
   - User expressed preference: "probably flutter / dart is best honestly"
   - Industry trend toward cross-platform UI
   - Reduces long-term maintenance burden

5. **Appropriate Performance**
   - Dashboard/monitoring UI is not performance-critical
   - Dart's JIT/AOT compilation is fast enough
   - WireGuard tunnel runs in C SDK, not UI layer

---

## Implementation Plan (Flutter/Dart)

### Phase 1: FFI Bindings (~40 hours)
1. Create Flutter project structure
2. Write Dart FFI wrappers for all ~40 C SDK functions
3. Create idiomatic Dart API layer on top of FFI

### Phase 2: Core UI (~60 hours)
1. App state management (Provider/Riverpod)
2. Login/Authentication views
3. Dashboard view
4. Tunnel control view
5. Peer list view

### Phase 3: Advanced UI (~40 hours)
1. Network monitor view
2. Tree browser view
3. Server list view
4. Certificate management view
5. Settings view

### Phase 4: Windows Integration (~20 hours)
1. Windows Service integration (start VPN on boot)
2. System tray integration
3. Windows-specific packaging (MSI/MSIX)
4. Code signing

### Phase 5: Polish & Testing (~20 hours)
1. Theme customization
2. Accessibility testing
3. Performance optimization
4. User testing

**Total Estimated Effort:** ~180 hours (4.5 weeks full-time)

---

## File Structure (Flutter)

```
apps/LemonadeNexus/
├── lib/
│   ├── main.dart                    # App entry point
│   ├── src/
│   │   ├── sdk/                     # FFI bindings
│   │   │   ├── lemonade_nexus_sdk.dart
│   │   │   ├── ffi_bindings.dart    # ~500 lines FFI wrappers
│   │   │   └── types.dart           # Dart model classes
│   │   ├── services/                # Business logic
│   │   │   ├── tunnel_service.dart
│   │   │   ├── auth_service.dart
│   │   │   └── dns_discovery.dart
│   │   ├── state/                   # State management
│   │   │   ├── app_state.dart
│   │   │   └── providers.dart
│   │   └── views/                   # UI screens
│   │       ├── login_view.dart
│   │       ├── dashboard_view.dart
│   │       ├── tunnel_control_view.dart
│   │       ├── peers_view.dart
│   │       ├── network_monitor_view.dart
│   │       ├── tree_browser_view.dart
│   │       ├── servers_view.dart
│   │       ├── certificates_view.dart
│   │       └── settings_view.dart
│   └── theme/
│       └── app_theme.dart
├── windows/
│   ├── runner/                      # Windows-specific runner
│   └── CMakeLists.txt
├── macos/
│   └── Runner/                      # macOS runner (replaces SwiftUI)
├── linux/
│   └── flutter/                     # Linux runner
├── c_ffi/
│   └── lemonade_nexus.h             # Symlink to SDK header
└── pubspec.yaml                     # Dependencies
```

---

## FFI Binding Examples

### Dart FFI for Core Functions

```dart
import 'dart:ffi';
import 'dart:ffi' as ffi;

typedef LnCreateNative = Pointer<Void> Function(Pointer<Utf8> host, Uint16 port);
typedef LnCreate = Pointer<Void> Function(Pointer<Utf8> host, int port);

typedef LnDestroyNative = Void Function(Pointer<Void> client);
typedef LnDestroy = void Function(Pointer<Void> client);

typedef LnHealthNative = Int32 Function(
    Pointer<Void> client, Pointer<Pointer<CChar>> outJson);
typedef LnHealth = int Function(
    Pointer<Void> client, Pointer<Pointer<CChar>> outJson);

class LemonadeNexusSdk {
  final ffi.DynamicLibrary _lib;

  late final LnCreate _create;
  late final LnDestroy _destroy;
  late final LnHealth _health;

  LemonadeNexusSdk(String libPath) : _lib = ffi.DynamicLibrary.open(libPath) {
    _create = _lib.lookup<ffi.NativeFunction<LnCreateNative>>('ln_create').asFunction();
    _destroy = _lib.lookup<ffi.NativeFunction<LnDestroyNative>>('ln_destroy').asFunction();
    _health = _lib.lookup<ffi.NativeFunction<LnHealthNative>>('ln_health').asFunction();
  }

  LemonadeNexusClient create(String host, int port) {
    final hostPtr = host.toNativeUtf8();
    final ptr = _create(hostPtr, port);
    calloc.free(hostPtr);
    return LemonadeNexusClient._(ptr, this);
  }

  void destroy(Pointer<Void> client) => _destroy(client);

  Map<String, dynamic> health(Pointer<Void> client) {
    final jsonPtr = calloc<Pointer<CChar>>();
    final result = _health(client, jsonPtr);
    if (result != 0) {
      throw LemonadeNexusException('Health check failed: $result');
    }
    final jsonString = jsonPtr.value.cast<Utf8>().toDartString();
    _lnFree(jsonPtr.value);
    calloc.free(jsonPtr);
    return jsonDecode(jsonString);
  }

  void _lnFree(Pointer<CChar> ptr) {
    // Call ln_free from the SDK
    _lib.lookup<ffi.NativeFunction<Void Function(Pointer<CChar>)>>('ln_free')(ptr);
  }
}
```

---

## macOS SwiftUI Replacement Strategy

The existing macOS app uses SwiftUI. Flutter can replace it entirely:

| SwiftUI Component | Flutter Equivalent |
|-------------------|-------------------|
| `NavigationView` | `NavigationDrawer` / `NavigationRail` |
| `List` | `ListView.builder` |
| `VStack`/`HStack` | `Column`/`Row` |
| `@EnvironmentObject` | `Provider.of<AppState>` |
| `@State`/`@Published` | `StateNotifier` / `ChangeNotifier` |
| `.task {}` | `WidgetsBinding.instance.addPostFrameCallback` |

**Migration Path:**
1. Build Flutter Windows app first
2. Test FFI bindings thoroughly
3. Port macOS app to Flutter (reuse 95%+ code)
4. Deprecate SwiftUI implementation

---

## Build & Distribution

### Windows Build

```bash
flutter build windows --release
# Output: build/windows/runner/Release/lemonade_nexus.exe
```

### Packaging Options

| Format | Tool | Notes |
|--------|------|-------|
| **MSIX** | `flutter pub run msix:create` | Modern Windows package, Store-compatible |
| **MSI** | WiX Toolset / Inno Setup | Traditional installer |
| **EXE** | NSIS | Same as server installer |

### Code Signing

```yaml
# GitHub Actions
- name: Sign Windows executable
  uses: signpath/github-action-sign-app@v1
  with:
    signpath-organization-id: '...'
    project-slug: 'lemonade-nexus'
```

---

## Development Environment Setup

### Prerequisites

```bash
# Install Flutter
flutter doctor -v

# Verify Windows toolchain
flutter config --enable-windows-desktop

# Install dependencies
flutter pub get
```

### C SDK Integration

```bash
# Build C SDK for Windows
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --target LemonadeNexusSDK

# Copy DLL to Flutter project
copy build\projects\LemonadeNexusSDK\Release\lemonade_nexus_sdk.dll apps\LemonadeNexus\windows\
```

---

## Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| FFI binding bugs | Medium | High | Comprehensive tests, type-safe wrappers |
| Flutter Windows maturity | Low | Medium | Test thoroughly, have fallback plan |
| Performance issues | Low | Low | Profile early, optimize hot paths |
| Team learning curve | Medium | Low | Allocate training time, pair programming |
| Dart runtime bugs | Low | Medium | Pin Flutter version, track stable channel |

---

## Conclusion

**Flutter/Dart is the recommended approach** because:

1. ✅ Perfect technical fit for C SDK FFI
2. ✅ Cross-platform code reuse (Windows + macOS + Linux)
3. ✅ Modern development experience
4. ✅ User preference aligned
5. ✅ Strategic long-term maintainability
6. ✅ Appropriate performance characteristics

**Next Step:** Create Flutter agent ecosystem to implement the Windows client.

---

**Author:** AI Assistant
**Review Date:** 2026-04-08
