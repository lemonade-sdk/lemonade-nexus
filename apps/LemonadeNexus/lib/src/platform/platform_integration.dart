/// Platform-specific desktop integration (tray/menu-bar, auto-start, lifecycle),
/// selected at runtime. Replaces the Windows-only init path in main.dart with a
/// platform-agnostic facade.
library;

import 'dart:io';

import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../windows/windows_integration.dart';

abstract class PlatformIntegration {
  Future<void> initialize();
  void updateTrayConnectionState();

  /// Returns true to allow the window to close, false to minimize to tray.
  bool handleWindowClose();

  void dispose();
}

PlatformIntegration createPlatformIntegration(Ref ref) {
  if (Platform.isWindows) return _WindowsPlatformIntegration(ref);
  if (Platform.isMacOS) return _MacosPlatformIntegration();
  return _DesktopPlatformIntegration();
}

class _WindowsPlatformIntegration implements PlatformIntegration {
  final Ref _ref;
  _WindowsPlatformIntegration(this._ref);

  WindowsIntegrationService get _svc => _ref.read(windowsIntegrationProvider);

  @override
  Future<void> initialize() => _svc.initialize();
  @override
  void updateTrayConnectionState() => _svc.updateTrayConnectionState();
  @override
  bool handleWindowClose() => _svc.handleWindowClose();
  @override
  void dispose() => _svc.dispose();
}

/// Minimal until the macOS menu-bar/tray integration lands (follow-up).
class _MacosPlatformIntegration implements PlatformIntegration {
  @override
  Future<void> initialize() async {}
  @override
  void updateTrayConnectionState() {}
  @override
  bool handleWindowClose() => true;
  @override
  void dispose() {}
}

class _DesktopPlatformIntegration implements PlatformIntegration {
  @override
  Future<void> initialize() async {}
  @override
  void updateTrayConnectionState() {}
  @override
  bool handleWindowClose() => true;
  @override
  void dispose() {}
}
