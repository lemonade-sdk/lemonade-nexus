/// @title Windows Tunnel Service
/// @description Windows-specific tunnel management with system integration.
///
/// Provides:
/// - Tunnel lifecycle management
/// - System tray integration
/// - Auto-connect on startup
/// - Background operation
library;

import 'dart:async';
import 'dart:io';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import 'windows_integration.dart';

/// Windows tunnel service configuration
class WindowsTunnelConfig {
  /// Auto-connect tunnel on app startup
  final bool autoConnect;

  /// Reconnect tunnel after disconnect
  final bool autoReconnect;

  /// Run tunnel in background
  final bool runInBackground;

  /// Show notifications
  final bool showNotifications;

  const WindowsTunnelConfig({
    this.autoConnect = false,
    this.autoReconnect = true,
    this.runInBackground = false,
    this.showNotifications = true,
  });
}

/// Windows tunnel service
class WindowsTunnelService {
  final Ref _ref;
  WindowsTunnelConfig _config;
  bool _isTunnelMonitoring = false;
  Timer? _monitorTimer;

  WindowsTunnelService(this._ref, {WindowsTunnelConfig? config})
      : _config = config ?? const WindowsTunnelConfig();

  /// Initialize tunnel service
  Future<void> initialize() async {
    if (!Platform.isWindows) {
      return;
    }

    // Check if auto-connect is enabled
    if (_config.autoConnect) {
      await _autoConnectTunnel();
    }

    // Start monitoring tunnel state
    _startTunnelMonitoring();
  }

  /// Auto-connect tunnel if previously connected
  Future<void> _autoConnectTunnel() async {
    debugPrint('[WindowsTunnel] Auto-connecting tunnel');

    final appState = _ref.read(appNotifierProvider);
    if (appState.isAuthenticated) {
      try {
        await _ref.read(appNotifierProvider.notifier).enableMesh();
      } catch (e) {
        debugPrint('[WindowsTunnel] Auto-connect failed: $e');
      }
    }
  }

  /// Poll tunnel status periodically and reflect it in the tray.
  void _startTunnelMonitoring() {
    if (_isTunnelMonitoring) return;
    _isTunnelMonitoring = true;
    _monitorTimer = Timer.periodic(const Duration(seconds: 5), (_) async {
      await _ref.read(appNotifierProvider.notifier).refreshMeshStatus();
      _ref.read(windowsIntegrationProvider).updateTrayConnectionState();
    });
  }

  /// Stop monitoring tunnel state
  void _stopTunnelMonitoring() {
    _monitorTimer?.cancel();
    _monitorTimer = null;
    _isTunnelMonitoring = false;
  }

  /// Connect tunnel with Windows integration
  Future<bool> connect() async {
    final notifier = _ref.read(appNotifierProvider.notifier);

    try {
      await notifier.enableMesh();

      // Update tray icon
      if (Platform.isWindows) {
        _ref.read(windowsIntegrationProvider).updateTrayConnectionState();
      }

      if (_config.showNotifications) {
        debugPrint('[WindowsTunnel] Tunnel connected');
      }

      return true;
    } catch (e) {
      debugPrint('[WindowsTunnel] Failed to connect: $e');
      return false;
    }
  }

  /// Disconnect tunnel with Windows integration
  Future<bool> disconnect() async {
    final notifier = _ref.read(appNotifierProvider.notifier);

    try {
      await notifier.disableMesh();

      // Update tray icon
      if (Platform.isWindows) {
        _ref.read(windowsIntegrationProvider).updateTrayConnectionState();
      }

      if (_config.showNotifications) {
        debugPrint('[WindowsTunnel] Tunnel disconnected');
      }

      return true;
    } catch (e) {
      debugPrint('[WindowsTunnel] Failed to disconnect: $e');
      return false;
    }
  }

  /// Toggle tunnel connection
  Future<bool> toggle() async {
    final appState = _ref.read(appNotifierProvider);
    if (appState.isMeshEnabled) {
      return await disconnect();
    } else {
      return await connect();
    }
  }

  /// Handle app exit - cleanup tunnel
  Future<void> onAppExit() async {
    debugPrint('[WindowsTunnel] Handling app exit');

    final appState = _ref.read(appNotifierProvider);
    if (appState.isMeshEnabled) {
      await disconnect();
    }

    _stopTunnelMonitoring();
  }

  /// Handle window close - minimize or exit
  bool handleWindowClose() {
    final integration = _ref.read(windowsIntegrationProvider);
    return integration.handleWindowClose();
  }

  /// Update configuration
  void updateConfig(WindowsTunnelConfig config) {
    _config = config;
  }

  /// Get current configuration
  WindowsTunnelConfig get config => _config;

  /// Dispose resources
  void dispose() {
    _stopTunnelMonitoring();
  }
}

/// Provider for Windows tunnel service
final windowsTunnelServiceProvider = Provider<WindowsTunnelService>((ref) {
  final service = WindowsTunnelService(ref);

  ref.onDispose(() {
    service.dispose();
  });

  return service;
});

/// Extension for tunnel service helpers
extension WindowsTunnelExtension on WidgetRef {
  /// Get Windows tunnel service
  WindowsTunnelService get windowsTunnel {
    return read(windowsTunnelServiceProvider);
  }

  /// Connect tunnel
  Future<bool> connectTunnel() {
    return read(windowsTunnelServiceProvider).connect();
  }

  /// Disconnect tunnel
  Future<bool> disconnectTunnel() {
    return read(windowsTunnelServiceProvider).disconnect();
  }

  /// Toggle tunnel
  Future<bool> toggleTunnel() {
    return read(windowsTunnelServiceProvider).toggle();
  }
}
