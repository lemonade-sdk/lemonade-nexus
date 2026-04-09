/// @title Windows Auto-Start Integration
/// @description Auto-start service for Windows VPN client.
///
/// Provides:
/// - Registry Run key approach (user-level, non-elevated)
/// - Task Scheduler approach (elevated, system-level)
/// - User preference toggle
/// - Handle both elevated and non-elevated modes

import 'dart:io';
import 'package:ffi/ffi.dart';
import 'package:win32/win32.dart';
import 'package:riverpod/riverpod.dart';

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
    this.description = 'WireGuard Mesh VPN Client',
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
    // Try registry first (most common)
    if (_isRegistryAutoStartEnabled()) {
      return true;
    }

    // Try Task Scheduler
    if (_isTaskSchedulerAutoStartEnabled()) {
      return true;
    }

    // Try startup folder
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
    // If a specific method is requested, use it
    if (method != null) {
      return _enableWithMethod(method);
    }

    // Otherwise, try methods in order of preference
    // Registry is preferred for non-elevated apps
    AutoStartResult result;

    // Try registry first (works without elevation)
    result = _enableRegistryAutoStart();
    if (result.success) return result;

    // Try startup folder (also works without elevation)
    result = _enableStartupFolder();
    if (result.success) return result;

    // Task Scheduler requires elevation, try last
    result = await _enableTaskScheduler();
    return result;
  }

  /// Disable all auto-start methods
  Future<AutoStartResult> disable() async {
    var anySuccess = false;
    String? lastMessage;

    // Disable registry
    final registryResult = _disableRegistryAutoStart();
    if (registryResult.success) anySuccess = true;
    lastMessage = registryResult.message;

    // Disable Task Scheduler
    final taskResult = await _disableTaskScheduler();
    if (taskResult.success) anySuccess = true;
    lastMessage = taskResult.message;

    // Disable startup folder
    final folderResult = _disableStartupFolder();
    if (folderResult.success) anySuccess = true;
    lastMessage = folderResult.message;

    if (anySuccess) {
      return AutoStartResult.success(AutoStartMethod.registryRun, lastMessage);
    } else {
      return AutoStartResult.failure(lastMessage ?? 'Failed to disable auto-start');
    }
  }

  /// Check if the current process is running elevated
  static bool isElevated() {
    final hToken = calloc<HANDLE>();
    try {
      final result = OpenProcessToken(
        GetCurrentProcess(),
        TOKEN_QUERY,
        hToken,
      );

      if (result == 0) {
        calloc.free(hToken);
        return false;
      }

      final tokenElevation = calloc<_TOKEN_ELEVATION>();
      try {
        final cbSize = sizeOf<_TOKEN_ELEVATION>();
        final pReturnLength = calloc<DWORD>();

        final getinfoResult = GetTokenInformation(
          hToken.value,
          TOKEN_INFORMATION_CLASS.TokenElevation,
          tokenElevation.cast(),
          cbSize,
          pReturnLength,
        );

        calloc.free(pReturnLength);

        if (getinfoResult == 0) {
          calloc.free(tokenElevation);
          calloc.free(hToken);
          return false;
        }

        final isElevated = tokenElevation.ref.TokenIsElevated != 0;
        calloc.free(tokenElevation);
        calloc.free(hToken);
        return isElevated;
      } finally {
        // Cleanup in case of early return
      }
    } catch (e) {
      return false;
    } finally {
      // Ensure cleanup
      try {
        CloseHandle(hToken.value);
        calloc.free(hToken);
      } catch (_) {}
    }
  }

  // =========================================================================
  // Registry Run Key Implementation
  // =========================================================================

  bool _isRegistryAutoStartEnabled() {
    try {
      final hKey = _openRegistryKey();
      if (hKey == 0) return false;

      final valuePointer = wsalloc(MAX_PATH);
      final dataSize = calloc<DWORD>();

      final result = RegQueryValueEx(
        hKey,
        _config.appName.toNativeUtf16(),
        nullptr,
        nullptr,
        valuePointer,
        dataSize,
      );

      final exists = result == ERROR_SUCCESS;

      RegCloseKey(hKey);
      calloc.free(dataSize);
      calloc.free(valuePointer);

      return exists;
    } catch (e) {
      return false;
    }
  }

  AutoStartResult _enableRegistryAutoStart() {
    try {
      final hKey = _openOrCreateRegistryKey();
      if (hKey == 0) {
        return AutoStartResult.failure('Failed to open registry key');
      }

      // Get the current executable path
      final exePath = Platform.resolvedExecutable;
      final exePathPtr = exePath.toNativeUtf16();

      // Build the command line (exe + optional arguments)
      final cmdLine = _config.arguments.isEmpty
          ? exePath
          : '"$exePath" ${_config.arguments.join(' ')}';
      final cmdLinePtr = cmdLine.toNativeUtf16();

      // Set the registry value
      final result = RegSetValueEx(
        hKey,
        _config.appName.toNativeUtf16(),
        0,
        REG_SZ,
        cmdLinePtr.cast(),
        (cmdLinePtr.length * 2) + 2, // Length in bytes including null terminator
      );

      RegCloseKey(hKey);
      calloc.free(exePathPtr);
      calloc.free(cmdLinePtr);

      if (result == ERROR_SUCCESS) {
        return AutoStartResult.success(AutoStartMethod.registryRun);
      } else {
        return AutoStartResult.failure('Failed to set registry value: $result');
      }
    } catch (e) {
      return AutoStartResult.failure('Registry error: $e');
    }
  }

  AutoStartResult _disableRegistryAutoStart() {
    try {
      final hKey = _openRegistryKey();
      if (hKey == 0) {
        return AutoStartResult.failure('Failed to open registry key');
      }

      final result = RegDeleteValue(
        hKey,
        _config.appName.toNativeUtf16(),
      );

      RegCloseKey(hKey);

      if (result == ERROR_SUCCESS || result == ERROR_FILE_NOT_FOUND) {
        return AutoStartResult.success(
          AutoStartMethod.registryRun,
          'Registry auto-start disabled',
        );
      } else {
        return AutoStartResult.failure('Failed to delete registry value: $result');
      }
    } catch (e) {
      return AutoStartResult.failure('Registry error: $e');
    }
  }

  int _openRegistryKey() {
    final phKey = calloc<HKEY>();

    final result = RegOpenKeyEx(
      HKEY_CURRENT_USER,
      r'Software\Microsoft\Windows\CurrentVersion\Run'.toNativeUtf16(),
      0,
      KEY_READ,
      phKey,
    );

    if (result == ERROR_SUCCESS) {
      final hKey = phKey.value;
      calloc.free(phKey);
      return hKey;
    }

    calloc.free(phKey);
    return 0;
  }

  int _openOrCreateRegistryKey() {
    final phKey = calloc<HKEY>();

    final result = RegCreateKeyEx(
      HKEY_CURRENT_USER,
      r'Software\Microsoft\Windows\CurrentVersion\Run'.toNativeUtf16(),
      0,
      nullptr,
      0,
      KEY_SET_VALUE,
      nullptr,
      phKey,
      nullptr,
    );

    if (result == ERROR_SUCCESS) {
      final hKey = phKey.value;
      calloc.free(phKey);
      return hKey;
    }

    calloc.free(phKey);
    return 0;
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
      // Check if elevated
      if (!isElevated()) {
        return AutoStartResult.failure(
          'Task Scheduler requires elevated privileges',
        );
      }

      final exePath = Platform.resolvedExecutable;
      final cmdLine = _config.arguments.isEmpty
          ? exePath
          : '"$exePath" ${_config.arguments.join(' ')}';

      // Create task using schtasks command
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
      if (!isElevated()) {
        // Try to delete anyway, might fail
      }

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
        // Task might not exist, which is fine
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
      return File(shortcutPath).existsSync();
    } catch (e) {
      return false;
    }
  }

  AutoStartResult _enableStartupFolder() {
    try {
      final shortcutPath = _getShortcutPath();
      final exePath = Platform.resolvedExecutable;

      // Create a simple batch file as a shortcut alternative
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

  String _getShortcutPath() {
    // Get the startup folder path
    final appData = Platform.environment['APPDATA'] ?? '';
    final startupPath = '$appData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup';

    return '$startupPath\\${_config.appName}.lnk';
  }
}

/// Provider for Windows auto-start service
final autoStartProvider = Provider<WindowsAutoStart>((ref) {
  return WindowsAutoStart();
});

// Extension removed - using direct toNativeUtf16() from package:ffi/ffi.dart
