/// @title Windows System Tray Integration
/// @description System tray service for Windows VPN client.
///
/// Provides:
/// - Tray icon showing connection status
/// - Context menu (Connect, Disconnect, Settings, Exit)
/// - Click handlers for tunnel control
/// - Tooltip with current connection status

import 'dart:io';
import 'package:flutter/material.dart';
import 'package:tray_manager/tray_manager.dart';
import 'package:riverpod/riverpod.dart';
import '../state/providers.dart';
import '../state/app_state.dart';

/// System tray service for Windows
class WindowsSystemTray extends TrayListener {
  final Ref _ref;
  bool _isInitialized = false;

  /// Connection status colors for tray icon tooltip
  static const Map<ConnectionStatus, String> statusColors = {
    ConnectionStatus.disconnected: 'gray',
    ConnectionStatus.connecting: 'yellow',
    ConnectionStatus.connected: 'green',
    ConnectionStatus.error: 'red',
  };

  WindowsSystemTray(this._ref);

  /// Initialize system tray
  Future<void> initialize() async {
    if (_isInitialized) {
      return;
    }

    try {
      // Register this as the tray listener
      trayManager.addListener(this);

      // Set the tray icon
      await _setTrayIcon();

      // Set initial context menu
      await _updateContextMenu();

      // Set initial tooltip
      await _updateTooltip();

      _isInitialized = true;
      debugPrint('[SystemTray] Initialized');
    } catch (e) {
      debugPrint('[SystemTray] Failed to initialize: $e');
    }
  }

  /// Set the tray icon based on platform
  Future<void> _setTrayIcon() async {
    try {
      // Use the app icon for the tray
      // The icon should be in the assets folder
      if (Platform.isWindows) {
        // For Windows, we can use the executable icon or a custom ICO file
        await trayManager.setIcon(
          'assets/icons/tray_icon.ico',
          isTemplate: false,
        );
      }
    } catch (e) {
      // If custom icon fails, use default
      debugPrint('[SystemTray] Using default icon: $e');
      try {
        await trayManager.setIcon(
          'assets/icons/app_icon.png',
          isTemplate: false,
        );
      } catch (e2) {
        debugPrint('[SystemTray] Could not set icon: $e2');
      }
    }
  }

  /// Update the context menu based on current state
  Future<void> _updateContextMenu() async {
    final appState = _ref.read(appNotifierProvider);
    final isTunnelUp = appState.isTunnelUp;
    final isMeshEnabled = appState.isMeshEnabled;

    final menuItems = [
      MenuItem(
        key: 'connect',
        label: isTunnelUp ? 'Disconnect' : 'Connect',
      ),
      MenuItem.separator(),
      MenuItem(
        key: 'dashboard',
        label: 'Open Dashboard',
      ),
      MenuItem(
        key: 'settings',
        label: 'Settings',
      ),
      MenuItem.separator(),
      MenuItem(
        key: 'exit',
        label: 'Exit',
      ),
    ];

    await trayManager.setContextMenu(Menu(items: menuItems));
  }

  /// Update the tooltip with connection status
  Future<void> _updateTooltip() async {
    final appState = _ref.read(appNotifierProvider);
    String tooltipText = 'Lemonade Nexus VPN';

    if (appState.isConnected) {
      tooltipText += ' - Connected';
      if (appState.tunnelStatus?.tunnelIp != null) {
        tooltipText += ' (${appState.tunnelStatus!.tunnelIp})';
      }
    } else if (appState.connectionStatus == ConnectionStatus.connecting) {
      tooltipText += ' - Connecting...';
    } else {
      tooltipText += ' - Disconnected';
    }

    await trayManager.setToolTip(tooltipText);
  }

  /// Update tray when connection state changes
  void updateConnectionState() {
    if (!_isInitialized) return;

    // Update context menu (Connect/Disconnect toggle)
    _updateContextMenu();

    // Update tooltip
    _updateTooltip();
  }

  // =========================================================================
  // TrayListener Implementation
  // =========================================================================

  @override
  void onTrayIconMouseDown() async {
    debugPrint('[SystemTray] Icon clicked');
    // Left click - open/restore the main window
    await trayManager.showAppWindow();
  }

  @override
  void onTrayIconRightMouseDown() async {
    debugPrint('[SystemTray] Right click - showing menu');
    // Right click will show context menu automatically
  }

  @override
  void onTrayMenuItemClick(MenuItem menuItem) async {
    debugPrint('[SystemTray] Menu item clicked: ${menuItem.key}');

    final notifier = _ref.read(appNotifierProvider.notifier);

    switch (menuItem.key) {
      case 'connect':
        final appState = _ref.read(appNotifierProvider);
        if (appState.isTunnelUp) {
          await notifier.disconnectTunnel();
        } else {
          await notifier.connectTunnel();
        }
        // Update menu after toggle
        await Future.delayed(const Duration(milliseconds: 500));
        await _updateContextMenu();
        await _updateTooltip();
        break;

      case 'dashboard':
        await trayManager.showAppWindow();
        // Navigate to dashboard
        notifier.setSelectedSidebarItem(SidebarItem.dashboard);
        break;

      case 'settings':
        await trayManager.showAppWindow();
        // Navigate to settings
        notifier.setSelectedSidebarItem(SidebarItem.settings);
        break;

      case 'exit':
        await _handleExit();
        break;
    }
  }

  @override
  void onTrayIconRightMouseUp() {
    // Handle right mouse up if needed
  }

  @override
  void onTrayIconMouseMove() {
    // Handle mouse hover if needed
  }

  @override
  void onTrayIconSecondaryMouseUp() {
    // Handle secondary mouse up if needed
  }

  /// Handle exit action
  Future<void> _handleExit() async {
    debugPrint('[SystemTray] Exiting application');

    // Disconnect tunnel before exit
    final notifier = _ref.read(appNotifierProvider.notifier);
    if (await _ref.read(appNotifierProvider).isTunnelUp) {
      await notifier.disconnectTunnel();
    }

    // Close the application
    exit(0);
  }

  /// Dispose and cleanup
  void dispose() {
    if (_isInitialized) {
      trayManager.removeListener(this);
      _isInitialized = false;
      debugPrint('[SystemTray] Disposed');
    }
  }
}

/// Provider for Windows system tray service
final systemTrayProvider = Provider<WindowsSystemTray>((ref) {
  final tray = WindowsSystemTray(ref);

  ref.onDispose(() {
    tray.dispose();
  });

  return tray;
});

/// Extension to help with tray icon state updates
extension SystemTrayExtension on WidgetRef {
  /// Update system tray when app state changes
  void notifySystemTrayOfStateChange() {
    try {
      final tray = read(systemTrayProvider);
      tray.updateConnectionState();
    } catch (e) {
      // System tray may not be initialized
    }
  }
}
