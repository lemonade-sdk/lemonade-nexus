# Windows Integration Implementation

**Date:** 2026-04-08
**Status:** COMPLETE

## Overview

This document describes the Windows-specific native integration implemented for the Lemonade Nexus VPN Flutter client.

## Features Implemented

### 1. System Tray Integration

**Location:** `lib/src/windows/system_tray.dart`

The system tray provides:
- Tray icon showing connection status
- Context menu with:
  - Connect/Disconnect toggle
  - Open Dashboard
  - Settings
  - Exit
- Tooltip with current connection status
- Double-click to restore window

**Native Support:** `windows/runner/win32_window.cpp` and `windows/runner/win32_window.h`

The C++ implementation provides:
- `CreateSystemTray()` - Initialize tray icon
- `UpdateTrayIcon(tooltip)` - Update tooltip text
- `ShowContextMenu()` - Display context menu on right-click
- `RemoveSystemTray()` - Clean up on exit

### 2. Auto-Start on Login

**Location:** `lib/src/windows/auto_start.dart`

Three auto-start methods are supported:

#### Registry Run Key (Default)
- User-level (no elevation required)
- Location: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
- Most reliable for standard applications

#### Task Scheduler
- Requires elevation
- Runs with highest privileges
- More robust for VPN applications

#### Startup Folder
- User-level (no elevation required)
- Less reliable but compatible
- Creates a batch file as shortcut alternative

**Usage:**
```dart
final autoStart = WindowsAutoStart();
final result = await autoStart.enable();  // Auto-select best method
final result = await autoStart.enable(method: AutoStartMethod.registryRun);  // Specific
final result = await autoStart.disable();
final enabled = autoStart.isEnabled();
```

### 3. Windows Service Integration

**Location:** `lib/src/windows/windows_service.dart`

For enterprise deployments, the app can run as a Windows Service:

- **Service Control Manager (SCM) integration**
- **Service recovery configuration** - Auto-restart on failure
- **Start/Stop from app**
- **Event log integration** (via SCM)

**Usage:**
```dart
final service = WindowsServiceManager();
service.install();    // Install as service
service.start();      // Start service
service.stop();       // Stop service
service.uninstall();  // Remove service
service.isInstalled(); // Check installation
service.getState();   // Get current state
```

**Note:** Requires administrator privileges for installation.

### 4. Windows Path Management

**Location:** `lib/src/windows/windows_paths.dart`

Proper Windows file system paths:

| Method | Windows Path | Use Case |
|--------|-------------|----------|
| `getLocalAppDataDir()` | `%LOCALAPPDATA%\LemonadeNexus` | Cache, temp data |
| `getRoamingAppDataDir()` | `%APPDATA%\LemonadeNexus` | Roaming settings |
| `getProgramDataDir()` | `%PROGRAMDATA%\LemonadeNexus` | Shared data, logs |
| `getCacheDir()` | `%TEMP%\LemonadeNexus` | Temporary files |
| `getDocumentsDir()` | `%USERPROFILE%\Documents\LemonadeNexus` | User exports |
| `getConfigDir()` | `%APPDATA%\LemonadeNexus\config` | Configuration files |
| `getDataDir()` | `%LOCALAPPDATA%\LemonadeNexus\data` | App data |
| `getLogsDir()` | `%PROGRAMDATA%\LemonadeNexus\logs` | Log files |
| `getTunnelDir()` | `%LOCALAPPDATA%\LemonadeNexus\tunnel` | WireGuard configs |

### 5. Central Integration Service

**Location:** `lib/src/windows/windows_integration.dart`

Unified API for all Windows integrations:

```dart
final integration = WindowsIntegrationService(ref);
await integration.initialize();

// Auto-start
await integration.toggleAutoStart(true);
final isEnabled = integration.isAutoStartEnabled();

// System tray
await integration.toggleSystemTray(true);
integration.updateTrayConnectionState();

// Window close handling
if (!integration.handleWindowClose()) {
  // Minimize to tray instead of closing
}
```

## Settings UI

**Location:** `lib/src/views/settings_view.dart`

Windows-specific settings section added:

- **Start on login** - Toggle auto-start
- **Minimize to system tray** - Minimize to tray on window close
- **Run in background** - Continue VPN tunnel when window closed
- **Windows Service (Advanced)** - Install/Start/Stop/Uninstall service

## Dependencies Added

```yaml
dependencies:
  tray_manager: ^0.2.1      # System tray
  win32: ^5.0.0             # Windows API bindings
  win32_registry: ^1.1.0    # Registry access
  path_provider: ^2.1.0     # Windows paths
```

## File Structure

```
apps/LemonadeNexus/
├── lib/
│   ├── main.dart                          # Initialize Windows integration
│   ├── src/
│   │   ├── windows/
│   │   │   ├── system_tray.dart           # Tray service
│   │   │   ├── auto_start.dart            # Auto-start service
│   │   │   ├── windows_service.dart       # Windows service
│   │   │   ├── windows_paths.dart         # Path management
│   │   │   └── windows_integration.dart   # Central integration
│   │   └── views/
│   │       └── settings_view.dart         # Updated with Windows settings
│   └── theme/
│       └── app_theme.dart
├── windows/
│   └── runner/
│       ├── main.cpp                       # Initialize system tray
│       ├── win32_window.h                 # Tray declarations
│       └── win32_window.cpp               # Tray implementation
└── pubspec.yaml
```

## Usage in App

### Initialize Windows Integration

```dart
// In main.dart
void main() {
  runApp(
    ProviderScope(
      child: LemonadeNexusApp(),
    ),
  );
}

class _AppShellState extends ConsumerState<AppShell> {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(appNotifierProvider.notifier).initialize();
      // Initialize Windows integrations
      if (Platform.isWindows) {
        ref.read(windowsIntegrationProvider).initialize();
      }
    });
  }
}
```

### Update Tray on Connection Change

```dart
// In AppNotifier or connection state changes
void updateConnectionState() {
  // ... update connection state ...

  // Update system tray
  if (Platform.isWindows) {
    ref.read(windowsIntegrationProvider).updateTrayConnectionState();
  }
}
```

### Handle Window Close

```dart
// In window close handler
Future<bool> onWillPop() async {
  final integration = ref.read(windowsIntegrationProvider);

  if (!integration.handleWindowClose()) {
    // Minimize to tray instead
    await windowManager.hide();
    return false;
  }

  return true; // Actually close
}
```

## Testing

### Manual Testing Checklist

1. **System Tray**
   - [ ] Tray icon appears on app start
   - [ ] Tooltip shows connection status
   - [ ] Right-click shows context menu
   - [ ] Connect/Disconnect toggles work
   - [ ] Open Dashboard restores window
   - [ ] Exit closes application

2. **Auto-Start**
   - [ ] Toggle in settings enables/disables
   - [ ] Entry appears in Registry Run key
   - [ ] App starts on Windows login
   - [ ] Works without elevation

3. **Windows Service** (Advanced)
   - [ ] Install requires elevation
   - [ ] Service appears in Services MMC
   - [ ] Start/Stop work from app
   - [ ] Recovery configured (restart on failure)
   - [ ] Uninstall removes service

4. **Paths**
   - [ ] Config directory created in AppData
   - [ ] Logs directory created in ProgramData
   - [ ] Tunnel directory for WireGuard configs

## Troubleshooting

### System Tray Not Appearing

1. Check if `tray_manager` package is working
2. Verify icon file exists in assets
3. Check Windows notification area settings

### Auto-Start Not Working

1. Check Registry Run key: `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
2. Verify executable path is correct
3. Check if antivirus is blocking

### Service Installation Fails

1. Run app as administrator
2. Check Windows Event Log for errors
3. Verify Service Control Manager is running

## Future Enhancements

1. **Tray Icon Updates** - Dynamic icon based on connection status
2. **Toast Notifications** - Windows 10/11 toast for connection events
3. **Jump List** - Windows taskbar jump list integration
4. **Dark Mode Tray** - System-aware tray icon theme
5. **Update Detection** - Check for updates on startup

## Security Considerations

1. **Registry Access** - User-level only (HKCU), no system modifications
2. **Service Security** - Service runs with restricted privileges
3. **Path Security** - Proper ACLs on application directories
4. **Elevation** - UAC prompts for service operations only

## References

- [Windows System Tray Documentation](https://learn.microsoft.com/en-us/windows/win32/api/shellapi/ns-shellapi-notifyicondataw)
- [Windows Service Documentation](https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager)
- [Registry Run Key Documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/startup-run-registry-keys)
- [path_provider Package](https://pub.dev/packages/path_provider)
- [win32 Package](https://pub.dev/packages/win32)
