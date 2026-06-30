/// @title Windows Path Helper
/// @description Proper Windows file system paths for VPN client.
///
/// Provides:
/// - AppData for user-specific data
/// - ProgramData for shared data
/// - Proper path handling with path_provider
/// - Windows-specific directory conventions
///
/// Uses `SHGetKnownFolderPath` from `package:win32` to resolve canonical
/// paths, falling back to environment variables / path_provider when the
/// shell call fails or we're running off-Windows.

import 'dart:ffi';
import 'dart:io';

import 'package:ffi/ffi.dart';
import 'package:path/path.dart' as path;
import 'package:path_provider/path_provider.dart';
import 'package:win32/win32.dart';

/// Windows-specific paths
class WindowsPaths {
  /// Application name for directory paths
  final String appName;

  WindowsPaths({this.appName = 'LemonadeNexus'});

  /// Get the user's AppData Local directory for this app
  /// Use for: cache, temporary data, user-specific settings
  Future<Directory> getLocalAppDataDir() async {
    final shellPath = _knownFolderPath(FOLDERID_LocalAppData);
    if (shellPath != null) {
      final dir = Directory(path.join(shellPath, appName));
      await dir.create(recursive: true);
      return dir;
    }

    // Fallback to path_provider's application support directory
    final dir = await getApplicationSupportDirectory();
    final appDir = Directory(path.join(dir.path, appName));
    await appDir.create(recursive: true);
    return appDir;
  }

  /// Get the user's AppData Roaming directory for this app
  /// Use for: settings that should roam with user profile
  Future<Directory> getRoamingAppDataDir() async {
    final shellPath = _knownFolderPath(FOLDERID_RoamingAppData);
    if (shellPath != null) {
      final dir = Directory(path.join(shellPath, appName));
      await dir.create(recursive: true);
      return dir;
    }

    // APPDATA points at the roaming directory on Windows
    final appData = Platform.environment['APPDATA'];
    if (appData != null) {
      final dir = Directory(path.join(appData, appName));
      await dir.create(recursive: true);
      return dir;
    }

    // Last resort: local app data
    return getLocalAppDataDir();
  }

  /// Get the ProgramData directory for shared data
  /// Use for: shared configuration, logs, data accessible to all users
  Future<Directory> getProgramDataDir() async {
    final shellPath = _knownFolderPath(FOLDERID_ProgramData);
    if (shellPath != null) {
      final dir = Directory(path.join(shellPath, appName));
      await dir.create(recursive: true);
      return dir;
    }

    final programData = Platform.environment['PROGRAMDATA'];
    if (programData != null) {
      final dir = Directory(path.join(programData, appName));
      await dir.create(recursive: true);
      return dir;
    }

    throw Exception('Unable to resolve ProgramData directory');
  }

  /// Get the cache directory
  Future<Directory> getCacheDir() async {
    final dir = await getTemporaryDirectory();
    final cacheDir = Directory(path.join(dir.path, appName));
    await cacheDir.create(recursive: true);
    return cacheDir;
  }

  /// Get the documents directory for user exports
  Future<Directory> getDocumentsDir() async {
    final shellPath = _knownFolderPath(FOLDERID_Documents);
    if (shellPath != null) {
      final dir = Directory(path.join(shellPath, appName));
      await dir.create(recursive: true);
      return dir;
    }

    final dir = await getApplicationDocumentsDirectory();
    final docsDir = Directory(path.join(dir.path, appName));
    await docsDir.create(recursive: true);
    return docsDir;
  }

  // =========================================================================
  // Specialized Paths for VPN Client
  // =========================================================================

  /// Get the configuration directory
  /// Stores: settings.json, identity keys, certificates
  Future<Directory> getConfigDir() async {
    final dir = await getRoamingAppDataDir();
    final configDir = Directory(path.join(dir.path, 'config'));
    await configDir.create(recursive: true);
    return configDir;
  }

  /// Get the data directory
  /// Stores: tunnel state, peer cache, connection history
  Future<Directory> getDataDir() async {
    final dir = await getLocalAppDataDir();
    final dataDir = Directory(path.join(dir.path, 'data'));
    await dataDir.create(recursive: true);
    return dataDir;
  }

  /// Get the logs directory
  /// Stores: application logs, crash reports
  Future<Directory> getLogsDir() async {
    // Logs go to ProgramData for easier access by support/admin
    final dir = await getProgramDataDir();
    final logsDir = Directory(path.join(dir.path, 'logs'));
    await logsDir.create(recursive: true);
    return logsDir;
  }

  /// Get the tunnel working directory
  /// Stores: mesh configuration files, socket files
  Future<Directory> getTunnelDir() async {
    final dir = await getDataDir();
    final tunnelDir = Directory(path.join(dir.path, 'tunnel'));
    await tunnelDir.create(recursive: true);
    return tunnelDir;
  }

  // =========================================================================
  // Path Utilities
  // =========================================================================

  /// Get the full path for a config file
  Future<String> getConfigPath(String filename) async {
    final dir = await getConfigDir();
    return path.join(dir.path, filename);
  }

  /// Get the full path for a data file
  Future<String> getDataPath(String filename) async {
    final dir = await getDataDir();
    return path.join(dir.path, filename);
  }

  /// Get the full path for a log file
  Future<String> getLogPath(String filename) async {
    final dir = await getLogsDir();
    return path.join(dir.path, filename);
  }

  /// Get the full path for a tunnel config file
  Future<String> getTunnelPath(String filename) async {
    final dir = await getTunnelDir();
    return path.join(dir.path, filename);
  }

  /// Ensure all required directories exist
  Future<void> createAllDirectories() async {
    await getLocalAppDataDir();
    await getRoamingAppDataDir();
    await getProgramDataDir();
    await getCacheDir();
    await getDocumentsDir();
    await getConfigDir();
    await getDataDir();
    await getLogsDir();
    await getTunnelDir();
  }

  /// Check if the app has write access to a directory
  static Future<bool> hasWriteAccess(Directory dir) async {
    try {
      final testFile = File(path.join(dir.path, '.write_test'));
      await testFile.writeAsString('test');
      await testFile.delete();
      return true;
    } catch (e) {
      return false;
    }
  }

  /// Get the Windows username
  static String getUsername() {
    return Platform.environment['USERNAME'] ?? 'unknown';
  }

  /// Get the Windows computer name
  static String getComputerName() {
    return Platform.environment['COMPUTERNAME'] ?? 'unknown';
  }

  /// Get the Windows version string
  ///
  /// We don't use `RtlGetVersion` here because Dart can't safely synthesize
  /// the `OSVERSIONINFOEXW` struct without a generator. `Platform.operatingSystemVersion`
  /// reflects the same kernel data Windows reports to the process.
  static Future<String> getWindowsVersion() async {
    return Platform.operatingSystemVersion;
  }

  /// Get the path to the current executable
  static String getExecutablePath() {
    return Platform.resolvedExecutable;
  }

  /// Get the directory containing the executable
  static String getExecutableDirectory() {
    return path.dirname(Platform.resolvedExecutable);
  }
}

/// Provider-style accessor for Windows paths
final windowsPathsProvider = WindowsPaths();

/// Resolves a Windows known folder using `SHGetKnownFolderPath`.
///
/// Returns the directory path on success, or `null` on failure (including
/// when this code is exercised outside of Windows by unit tests).
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
    // The shell allocates the returned string via CoTaskMemAlloc.
    CoTaskMemFree(ppPath.value);
    return result;
  } catch (_) {
    return null;
  } finally {
    calloc.free(pGuid);
    calloc.free(ppPath);
  }
}
