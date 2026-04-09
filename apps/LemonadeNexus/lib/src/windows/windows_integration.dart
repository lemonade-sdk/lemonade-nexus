/// @title Windows Integration Service
/// @description Central service for Windows-specific integrations.
///
/// Combines:
/// - System tray
/// - Auto-start
/// - Windows service
/// - Path management
///
/// Provides a unified API for Windows integration features.

import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:riverpod/riverpod.dart';
import 'system_tray.dart';
import 'auto_start.dart';
import 'windows_service.dart';
import 'windows_paths.dart';
import '../state/providers.dart';
import '../state/app_state.dart';

/// Windows integration settings
class WindowsIntegrationSettings {
  /// Enable system tray integration
  final bool enableSystemTray;

  /// Enable auto-start on login
  final bool enableAutoStart;

  /// Auto-start method preference
  final AutoStartMethod? autoStartMethod;

  /// Enable Windows service mode
  final bool enableWindowsService;

  /// Run in background when window closed
  final bool runInBackground;

  /// Minimize to tray on window close
  final bool minimizeToTray;

  const WindowsIntegrationSettings({
    this.enableSystemTray = true,
    this.enableAutoStart = false,
    this.autoStartMethod,
    this.enableWindowsService = false,
    this.runInBackground = false,
    this.minimizeToTray = true,
  });

  WindowsIntegrationSettings copyWith({
    bool? enableSystemTray,
    bool? enableAutoStart,
    AutoStartMethod? autoStartMethod,
    bool? enableWindowsService,
    bool? runInBackground,
    bool? minimizeToTray,
  }) {
    return WindowsIntegrationSettings(
      enableSystemTray: enableSystemTray ?? this.enableSystemTray,
      enableAutoStart: enableAutoStart ?? this.enableAutoStart,
      autoStartMethod: autoStartMethod ?? this.autoStartMethod,
      enableWindowsService: enableWindowsService ?? this.enableWindowsService,
      runInBackground: runInBackground ?? this.runInBackground,
      minimizeToTray: minimizeToTray ?? this.minimizeToTray,
    );
  }

  /// Default settings for Windows
  static const defaults = WindowsIntegrationSettings();
}

/// Windows integration service
class WindowsIntegrationService {
  final Ref _ref;
  WindowsIntegrationSettings _settings;
  bool _isInitialized = false;

  WindowsIntegrationService(this._ref, {WindowsIntegrationSettings? settings})
      : _settings = settings ?? WindowsIntegrationSettings.defaults;

  /// Initialize all Windows integrations
  Future<void> initialize() async {
    if (_isInitialized) {
      return;
    }

    if (!Platform.isWindows) {
      debugPrint('[WindowsIntegration] Not running on Windows, skipping initialization');
      _isInitialized = true;
      return;
    }

    try {
      // Initialize paths
      await windowsPathsProvider.createAllDirectories();
      debugPrint('[WindowsIntegration] Paths initialized');

      // Initialize system tray if enabled
      if (_settings.enableSystemTray) {
        await _ref.read(systemTrayProvider).initialize();
        debugPrint('[WindowsIntegration] System tray initialized');
      }

      // Check auto-start status
      final autoStart = _ref.read(autoStartProvider);
      if (autoStart.isEnabled()) {
        _settings = _settings.copyWith(enableAutoStart: true);
        debugPrint('[WindowsIntegration] Auto-start is enabled');
      }

      _isInitialized = true;
      debugPrint('[WindowsIntegration] Fully initialized');
    } catch (e) {
      debugPrint('[WindowsIntegration] Initialization error: $e');
    }
  }

  /// Toggle auto-start
  Future<bool> toggleAutoStart(bool enabled) async {
    final autoStart = _ref.read(autoStartProvider);

    if (enabled) {
      final result = await autoStart.enable(method: _settings.autoStartMethod);
      if (result.success) {
        _settings = _settings.copyWith(enableAutoStart: true);
        return true;
      }
      debugPrint('[WindowsIntegration] Failed to enable auto-start: ${result.message}');
      return false;
    } else {
      final result = await autoStart.disable();
      if (result.success) {
        _settings = _settings.copyWith(enableAutoStart: false);
        return true;
      }
      debugPrint('[WindowsIntegration] Failed to disable auto-start: ${result.message}');
      return false;
    }
  }

  /// Check if auto-start is enabled
  bool isAutoStartEnabled() {
    final autoStart = _ref.read(autoStartProvider);
    return autoStart.isEnabled();
  }

  /// Get auto-start method
  AutoStartMethod? getAutoStartMethod() {
    final autoStart = _ref.read(autoStartProvider);
    return autoStart.getCurrentMethod();
  }

  /// Toggle system tray
  Future<bool> toggleSystemTray(bool enabled) async {
    if (enabled) {
      try {
        await _ref.read(systemTrayProvider).initialize();
        _settings = _settings.copyWith(enableSystemTray: true);
        return true;
      } catch (e) {
        debugPrint('[WindowsIntegration] Failed to enable system tray: $e');
        return false;
      }
    } else {
      _settings = _settings.copyWith(enableSystemTray: false);
      // Note: We don't actually remove the tray icon as it's managed by the app
      return true;
    }
  }

  /// Install Windows service
  Future<bool> installService() async {
    final service = _ref.read(windowsServiceProvider);
    final result = service.install();
    if (result.success) {
      _settings = _settings.copyWith(enableWindowsService: true);
      return true;
    }
    debugPrint('[WindowsIntegration] Failed to install service: ${result.message}');
    return false;
  }

  /// Uninstall Windows service
  Future<bool> uninstallService() async {
    final service = _ref.read(windowsServiceProvider);
    final result = service.uninstall();
    if (result.success) {
      _settings = _settings.copyWith(enableWindowsService: false);
      return true;
    }
    debugPrint('[WindowsIntegration] Failed to uninstall service: ${result.message}');
    return false;
  }

  /// Check if Windows service is installed
  bool isServiceInstalled() {
    final service = _ref.read(windowsServiceProvider);
    return service.isInstalled();
  }

  /// Start Windows service
  Future<bool> startService() async {
    final service = _ref.read(windowsServiceProvider);
    final result = service.start();
    return result.success;
  }

  /// Stop Windows service
  Future<bool> stopService() async {
    final service = _ref.read(windowsServiceProvider);
    final result = service.stop();
    return result.success;
  }

  /// Get service state
  ServiceState getServiceState() {
    final service = _ref.read(windowsServiceProvider);
    return service.getState();
  }

  /// Update system tray when connection state changes
  void updateTrayConnectionState() {
    if (_settings.enableSystemTray && _isInitialized) {
      try {
        _ref.read(systemTrayProvider).updateConnectionState();
      } catch (e) {
        // Tray may not be initialized
      }
    }
  }

  /// Handle window close event
  /// Returns true if should close, false if should minimize to tray
  bool handleWindowClose() {
    if (_settings.minimizeToTray && _settings.enableSystemTray) {
      // Instead of closing, minimize to tray
      return false;
    }
    return true;
  }

  /// Get current settings
  WindowsIntegrationSettings get settings => _settings;

  /// Dispose resources
  void dispose() {
    if (_isInitialized) {
      if (_settings.enableSystemTray) {
        try {
          _ref.read(systemTrayProvider).dispose();
        } catch (e) {
          // Ignore
        }
      }
      _ref.read(windowsServiceProvider).dispose();
      _isInitialized = false;
    }
  }
}

/// Provider for Windows integration service
final windowsIntegrationProvider = Provider<WindowsIntegrationService>((ref) {
  final service = WindowsIntegrationService(ref);

  ref.onDispose(() {
    service.dispose();
  });

  return service;
});

/// State notifier for Windows integration settings
class WindowsIntegrationNotifier extends StateNotifier<WindowsIntegrationSettings> {
  final WindowsIntegrationService _service;

  WindowsIntegrationNotifier(this._service) : super(WindowsIntegrationSettings.defaults);

  /// Toggle auto-start
  Future<bool> toggleAutoStart(bool enabled) {
    return _service.toggleAutoStart(enabled);
  }

  /// Toggle system tray
  Future<bool> toggleSystemTray(bool enabled) {
    return _service.toggleSystemTray(enabled);
  }

  /// Toggle minimize to tray
  void toggleMinimizeToTray(bool enabled) {
    state = state.copyWith(minimizeToTray: enabled);
  }

  /// Toggle run in background
  void toggleRunInBackground(bool enabled) {
    state = state.copyWith(runInBackground: enabled);
  }

  /// Install Windows service
  Future<bool> installService() {
    return _service.installService();
  }

  /// Uninstall Windows service
  Future<bool> uninstallService() {
    return _service.uninstallService();
  }

  /// Check if service is installed
  bool isServiceInstalled() {
    return _service.isServiceInstalled();
  }

  /// Check if auto-start is enabled
  bool get isAutoStartEnabled => _service.isAutoStartEnabled();
}

/// Provider for Windows integration settings notifier
final windowsIntegrationNotifierProvider =
    StateNotifierProvider<WindowsIntegrationNotifier, WindowsIntegrationSettings>((ref) {
  final service = ref.watch(windowsIntegrationProvider);
  return WindowsIntegrationNotifier(service);
});
