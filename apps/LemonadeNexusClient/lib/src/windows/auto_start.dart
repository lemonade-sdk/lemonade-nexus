/// @title Windows Auto-Start Integration
/// @description Auto-start service for Windows VPN client.
///
/// Provides:
/// - Registry Run key (user-level, non-elevated) via `package:win32_registry`
/// - Task Scheduler (elevated) via the `schtasks` command-line tool
/// - User preference toggle
/// - Handle both elevated and non-elevated modes
library;

import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:win32/win32.dart';
import 'package:win32_registry/win32_registry.dart';

/// HKCU subkey controlling per-user auto-start applications.
const _kRunSubKey = r'Software\Microsoft\Windows\CurrentVersion\Run';

/// Auto-start methods available on Windows
enum AutoStartMethod {
  /// Registry Run key (user-level, works without elevation)
  registryRun,

  /// Task Scheduler (requires elevation)
  taskScheduler,

  /// Startup folder (user-level, less reliable)
  startupFolder,
}

/// Auto-start configuration
class AutoStartConfig {
  /// Unique identifier for the auto-start entry
  final String appName;

  /// Display name for Task Scheduler
  final String displayName;

  /// Description for Task Scheduler
  final String description;

  /// Optional arguments to pass to the executable
  final List<String> arguments;

  /// Whether to run with elevated privileges
  final bool runElevated;

  const AutoStartConfig({
    this.appName = 'LemonadeNexus',
    this.displayName = 'Lemonade Nexus VPN',
    this.description = 'userspace mesh VPN Client',
    this.arguments = const ['--minimized'],
    this.runElevated = false,
  });
}

/// Result of auto-start operation
class AutoStartResult {
  final bool success;
  final String? message;
  final AutoStartMethod? method;

  const AutoStartResult({
    required this.success,
    this.message,
    this.method,
  });

  factory AutoStartResult.success(AutoStartMethod method, [String? message]) {
    return AutoStartResult(
      success: true,
      method: method,
      message: message ?? 'Auto-start enabled successfully',
    );
  }

  factory AutoStartResult.failure(String message) {
    return AutoStartResult(
      success: false,
      message: message,
    );
  }
}

/// Windows auto-start service
class WindowsAutoStart {
  final AutoStartConfig _config;

  WindowsAutoStart({AutoStartConfig? config})
      : _config = config ?? const AutoStartConfig();

  /// Check if auto-start is currently enabled
  bool isEnabled() {
    if (_isRegistryAutoStartEnabled()) {
      return true;
    }

    if (_isTaskSchedulerAutoStartEnabled()) {
      return true;
    }

    if (_isStartupFolderEnabled()) {
      return true;
    }

    return false;
  }

  /// Get the current auto-start method
  AutoStartMethod? getCurrentMethod() {
    if (_isRegistryAutoStartEnabled()) {
      return AutoStartMethod.registryRun;
    }
    if (_isTaskSchedulerAutoStartEnabled()) {
      return AutoStartMethod.taskScheduler;
    }
    if (_isStartupFolderEnabled()) {
      return AutoStartMethod.startupFolder;
    }
    return null;
  }

  /// Enable auto-start using the best available method
  Future<AutoStartResult> enable({AutoStartMethod? method}) async {
    if (method != null) {
      return _enableWithMethod(method);
    }

    AutoStartResult result;

    // Registry first (works without elevation)
    result = _enableRegistryAutoStart();
    if (result.success) return result;

    // Startup folder (also works without elevation)
    result = _enableStartupFolder();
    if (result.success) return result;

    // Task Scheduler requires elevation, try last
    result = await _enableTaskScheduler();
    return result;
  }

  Future<AutoStartResult> _enableWithMethod(AutoStartMethod method) async {
    switch (method) {
      case AutoStartMethod.registryRun:
        return _enableRegistryAutoStart();
      case AutoStartMethod.startupFolder:
        return _enableStartupFolder();
      case AutoStartMethod.taskScheduler:
        return _enableTaskScheduler();
    }
  }

  /// Disable all auto-start methods
  Future<AutoStartResult> disable() async {
    var anySuccess = false;
    String? lastMessage;

    final registryResult = _disableRegistryAutoStart();
    if (registryResult.success) anySuccess = true;
    lastMessage = registryResult.message;

    final taskResult = await _disableTaskScheduler();
    if (taskResult.success) anySuccess = true;
    lastMessage = taskResult.message;

    final folderResult = _disableStartupFolder();
    if (folderResult.success) anySuccess = true;
    lastMessage = folderResult.message;

    if (anySuccess) {
      return AutoStartResult.success(AutoStartMethod.registryRun, lastMessage);
    } else {
      return AutoStartResult.failure(
          lastMessage ?? 'Failed to disable auto-start');
    }
  }

  /// Check if the current process is running elevated.
  ///
  /// Calls `OpenProcessToken` -> `GetTokenInformation(TokenElevation)` via
  /// the bindings exposed by `package:win32`.
  static bool isElevated() {
    if (!Platform.isWindows) return false;

    final pToken = calloc<HANDLE>();
    Pointer<_TokenElevation>? pElevation;
    Pointer<DWORD>? pReturnLength;

    try {
      final ok = OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_QUERY,
        pToken,
      );
      if (ok == 0) {
        return false;
      }

      pElevation = calloc<_TokenElevation>();
      pReturnLength = calloc<DWORD>();

      final infoOk = GetTokenInformation(
        pToken.value,
        TokenElevation, // top-level constant exported by package:win32
        pElevation.cast(),
        sizeOf<_TokenElevation>(),
        pReturnLength,
      );
      if (infoOk == 0) {
        return false;
      }

      return pElevation.ref.TokenIsElevated != 0;
    } catch (_) {
      return false;
    } finally {
      if (pElevation != null) calloc.free(pElevation);
      if (pReturnLength != null) calloc.free(pReturnLength);
      if (pToken.value != 0) CloseHandle(pToken.value);
      calloc.free(pToken);
    }
  }

  // =========================================================================
  // Registry Run Key Implementation
  // =========================================================================

  bool _isRegistryAutoStartEnabled() {
    if (!Platform.isWindows) return false;
    RegistryKey? key;
    try {
      key = Registry.openPath(
        RegistryHive.currentUser,
        path: _kRunSubKey,
        desiredAccessRights: AccessRights.readOnly,
      );
      return key.getValueAsString(_config.appName) != null;
    } catch (_) {
      return false;
    } finally {
      key?.close();
    }
  }

  AutoStartResult _enableRegistryAutoStart() {
    if (!Platform.isWindows) {
      return AutoStartResult.failure('Registry auto-start requires Windows');
    }
    RegistryKey? key;
    try {
      key = Registry.openPath(
        RegistryHive.currentUser,
        path: _kRunSubKey,
        desiredAccessRights: AccessRights.writeOnly,
      );

      final exePath = Platform.resolvedExecutable;
      final cmdLine = _config.arguments.isEmpty
          ? exePath
          : '"$exePath" ${_config.arguments.join(' ')}';

      key.createValue(
        RegistryValue(_config.appName, RegistryValueType.string, cmdLine),
      );

      return AutoStartResult.success(AutoStartMethod.registryRun);
    } catch (e) {
      return AutoStartResult.failure('Registry error: $e');
    } finally {
      key?.close();
    }
  }

  AutoStartResult _disableRegistryAutoStart() {
    if (!Platform.isWindows) {
      return AutoStartResult.failure('Registry auto-start requires Windows');
    }
    RegistryKey? key;
    try {
      key = Registry.openPath(
        RegistryHive.currentUser,
        path: _kRunSubKey,
        desiredAccessRights: AccessRights.allAccess,
      );

      try {
        key.deleteValue(_config.appName);
      } on WindowsException catch (e) {
        // ERROR_FILE_NOT_FOUND surfaces as HRESULT 0x80070002 — treat as success.
        if (e.hr != HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)) {
          rethrow;
        }
      }

      return AutoStartResult.success(
        AutoStartMethod.registryRun,
        'Registry auto-start disabled',
      );
    } catch (e) {
      return AutoStartResult.failure('Registry error: $e');
    } finally {
      key?.close();
    }
  }

  // =========================================================================
  // Task Scheduler Implementation
  // =========================================================================

  bool _isTaskSchedulerAutoStartEnabled() {
    // Simplified check - full implementation would use ITaskService COM interface
    // For now, we check if the task exists by trying to run schtasks query
    try {
      final result = Process.runSync(
        'schtasks',
        ['/Query', '/TN', _config.appName],
        runInShell: true,
      );
      return result.exitCode == 0;
    } catch (e) {
      return false;
    }
  }

  Future<AutoStartResult> _enableTaskScheduler() async {
    try {
      if (!isElevated()) {
        return AutoStartResult.failure(
          'Task Scheduler requires elevated privileges',
        );
      }

      final exePath = Platform.resolvedExecutable;
      final cmdLine = _config.arguments.isEmpty
          ? exePath
          : '"$exePath" ${_config.arguments.join(' ')}';

      final result = await Process.run(
        'schtasks',
        [
          '/Create',
          '/TN', _config.appName,
          '/TR', cmdLine,
          '/SC', 'ONLOGON',
          '/RL', 'HIGHEST',
          '/F',
        ],
        runInShell: true,
      );

      if (result.exitCode == 0) {
        return AutoStartResult.success(AutoStartMethod.taskScheduler);
      } else {
        return AutoStartResult.failure(
          'Task Scheduler error: ${result.stderr}',
        );
      }
    } catch (e) {
      return AutoStartResult.failure('Task Scheduler error: $e');
    }
  }

  Future<AutoStartResult> _disableTaskScheduler() async {
    try {
      final result = await Process.run(
        'schtasks',
        ['/Delete', '/TN', _config.appName, '/F'],
        runInShell: true,
      );

      if (result.exitCode == 0) {
        return AutoStartResult.success(
          AutoStartMethod.taskScheduler,
          'Task Scheduler auto-start disabled',
        );
      } else {
        if (result.stderr.toString().contains('ERROR: The specified task')) {
          return AutoStartResult.success(
            AutoStartMethod.taskScheduler,
            'Task was not configured',
          );
        }
        return AutoStartResult.failure(
          'Task Scheduler error: ${result.stderr}',
        );
      }
    } catch (e) {
      return AutoStartResult.failure('Task Scheduler error: $e');
    }
  }

  // =========================================================================
  // Startup Folder Implementation
  // =========================================================================

  bool _isStartupFolderEnabled() {
    try {
      final shortcutPath = _getShortcutPath();
      if (shortcutPath == null) return false;
      final batPath = shortcutPath.replaceAll('.lnk', '.bat');
      return File(shortcutPath).existsSync() || File(batPath).existsSync();
    } catch (e) {
      return false;
    }
  }

  AutoStartResult _enableStartupFolder() {
    try {
      final shortcutPath = _getShortcutPath();
      if (shortcutPath == null) {
        return AutoStartResult.failure(
            'Could not resolve startup folder path');
      }
      final exePath = Platform.resolvedExecutable;

      // We can't create a true .lnk shortcut from Dart without COM, so emit
      // a small launcher batch file in the startup folder instead.
      final batchContent = '''
@echo off
start "" "$exePath" ${_config.arguments.join(' ')}
exit
''';

      final batchFile = File(shortcutPath.replaceAll('.lnk', '.bat'));
      batchFile.writeAsStringSync(batchContent);

      return AutoStartResult.success(AutoStartMethod.startupFolder);
    } catch (e) {
      return AutoStartResult.failure('Startup folder error: $e');
    }
  }

  AutoStartResult _disableStartupFolder() {
    try {
      final shortcutPath = _getShortcutPath();
      if (shortcutPath == null) {
        return AutoStartResult.failure(
            'Could not resolve startup folder path');
      }
      final batPath = shortcutPath.replaceAll('.lnk', '.bat');

      if (File(shortcutPath).existsSync()) {
        File(shortcutPath).deleteSync();
      }
      if (File(batPath).existsSync()) {
        File(batPath).deleteSync();
      }

      return AutoStartResult.success(
        AutoStartMethod.startupFolder,
        'Startup folder auto-start disabled',
      );
    } catch (e) {
      return AutoStartResult.failure('Startup folder error: $e');
    }
  }

  String? _getShortcutPath() {
    // Try FOLDERID_Startup first; fall back to APPDATA-relative path.
    final startupFolder = _knownFolderPath(FOLDERID_Startup);
    if (startupFolder != null) {
      return '$startupFolder\\${_config.appName}.lnk';
    }

    final appData = Platform.environment['APPDATA'];
    if (appData == null || appData.isEmpty) return null;
    final startupPath =
        '$appData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup';
    return '$startupPath\\${_config.appName}.lnk';
  }
}

/// Provider for Windows auto-start service
final autoStartProvider = Provider<WindowsAutoStart>((ref) {
  return WindowsAutoStart();
});

// =========================================================================
// FFI helpers — TOKEN_ELEVATION isn't exposed by `package:win32` 5.x, so we
// declare just the single-field struct we need locally.
// =========================================================================

/// `typedef struct _TOKEN_ELEVATION { DWORD TokenIsElevated; } TOKEN_ELEVATION;`
base class _TokenElevation extends Struct {
  @Uint32()
  // ignore: non_constant_identifier_names
  external int TokenIsElevated;
}

/// Resolves a Windows known folder using `SHGetKnownFolderPath`.
///
/// Returns `null` if the call fails or we're not running on Windows.
String? _knownFolderPath(String folderIdGuid) {
  if (!Platform.isWindows) return null;

  final pGuid = GUIDFromString(folderIdGuid);
  final ppPath = calloc<Pointer<Utf16>>();
  try {
    final hr = SHGetKnownFolderPath(pGuid, 0, 0, ppPath);
    if (hr != S_OK) {
      return null;
    }
    final result = ppPath.value.toDartString();
    CoTaskMemFree(ppPath.value);
    return result;
  } catch (_) {
    return null;
  } finally {
    calloc.free(pGuid);
    calloc.free(ppPath);
  }
}
