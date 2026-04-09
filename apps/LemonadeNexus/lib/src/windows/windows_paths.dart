/// @title Windows Path Helper
/// @description Proper Windows file system paths for VPN client.
///
/// Provides:
/// - AppData for user-specific data
/// - ProgramData for shared data
/// - Proper path handling with path_provider
/// - Windows-specific directory conventions

import 'dart:io';
import 'package:path/path.dart' as path;
import 'package:path_provider/path_provider.dart';
import 'package:win32/win32.dart';
import 'package:ffi/ffi.dart';

/// Windows-specific paths
class WindowsPaths {
  /// Application name for directory paths
  final String appName;

  WindowsPaths({this.appName = 'LemonadeNexus'});

  /// Get the user's AppData Local directory for this app
  /// Use for: cache, temporary data, user-specific settings
  Future<Directory> getLocalAppDataDir() async {
    // Use path_provider for standard locations
    final dir = await getApplicationSupportDirectory();
    final appDir = Directory(path.join(dir.path, appName));
    await appDir.create(recursive: true);
    return appDir;
  }

  /// Get the user's AppData Roaming directory for this app
  /// Use for: settings that should roam with user profile
  Future<Directory> getRoamingAppDataDir() async {
    // On Windows, APPDATA is the roaming directory
    final appData = Platform.environment['APPDATA'];
    if (appData != null) {
      final dir = Directory(path.join(appData, appName));
      await dir.create(recursive: true);
      return dir;
    }

    // Fallback to application support
    return getLocalAppDataDir();
  }

  /// Get the ProgramData directory for shared data
  /// Use for: shared configuration, logs, data accessible to all users
  Future<Directory> getProgramDataDir() async {
    // PROGRAMDATA environment variable points to C:\ProgramData
    final programData = Platform.environment['PROGRAMDATA'];
    if (programData != null) {
      final dir = Directory(path.join(programData, appName));
      await dir.create(recursive: true);
      return dir;
    }

    // Fallback - this shouldn't happen on Windows
    throw Exception('PROGRAMDATA environment variable not found');
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
  /// Stores: WireGuard configuration files, socket files
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
  static Future<String> getWindowsVersion() async {
    // Use RtlGetVersion for accurate Windows version
    final osVersionInfo = _OSVERSIONINFOEXW();
    osVersionInfo.dwOSVersionInfoSize = sizeOf<_OSVERSIONINFOEXW>();

    final ntdll = GetModuleHandle('ntdll.dll');
    if (ntdll != 0) {
      final rtlGetVersion = GetProcAddress(ntdll, 'RtlGetVersion');
      if (rtlGetVersion != 0) {
        final getVersion = rtlGetVersion
            .asFunction<int Function(Pointer<_OSVERSIONINFOEXW>)>();
        getVersion(osVersionInfo);

        return 'Windows ${osVersionInfo.dwMajorVersion}.${osVersionInfo.dwMinorVersion} '
            '(Build ${osVersionInfo.dwBuildNumber})';
      }
    }

    // Fallback to environment
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

/// OSVERSIONINFOEXW structure for Windows version detection
class _OSVERSIONINFOEXW extends Struct {
  @Uint32()
  external int dwOSVersionInfoSize;

  @Uint32()
  external int dwMajorVersion;

  @Uint32()
  external int dwMinorVersion;

  @Uint32()
  external int dwBuildNumber;

  @Uint32()
  external int dwPlatformId;

  @Array(128)
  external Array<Uint16> szCSDVersion;

  @Uint16()
  external int wServicePackMajor;

  @Uint16()
  external int wServicePackMinor;

  @Uint16()
  external int wSuiteMask;

  @Uint8()
  external int wProductType;

  @Uint8()
  external int wReserved;
}

/// Provider-style accessor for Windows paths
final windowsPathsProvider = WindowsPaths();
