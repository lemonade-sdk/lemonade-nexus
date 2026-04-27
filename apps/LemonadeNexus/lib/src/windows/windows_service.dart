/// @title Windows Service Integration
/// @description Windows Service wrapper for background VPN operation.
///
/// Provides:
/// - Service Control Manager (SCM) integration
/// - Start/stop service from app
/// - Service recovery configuration
/// - Event log integration
///
/// Note: This is an advanced feature for enterprise deployments.
/// For most users, the system tray auto-start is sufficient.

import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';
import 'package:win32/win32.dart';
import 'package:riverpod/riverpod.dart';

/// Windows service configuration
class WindowsServiceConfig {
  /// Service name (used in SCM)
  final String serviceName;

  /// Display name shown in Services MMC snap-in
  final String displayName;

  /// Service description
  final String description;

  /// Service executable path
  final String executablePath;

  /// Optional arguments
  final List<String> arguments;

  /// Service start type
  final ServiceStartType startType;

  const WindowsServiceConfig({
    this.serviceName = 'LemonadeNexusService',
    this.displayName = 'Lemonade Nexus VPN Service',
    this.description = 'WireGuard Mesh VPN background service',
    String? executablePath,
    this.arguments = const ['--service'],
    this.startType = ServiceStartType.automatic,
  }) : executablePath = executablePath ?? Platform.resolvedExecutable;

  /// Get the full service command line
  String get serviceCommandLine {
    final args = [executablePath, ...arguments].join(' ');
    return '"$args"';
  }
}

/// Service start type
enum ServiceStartType {
  boot,
  system,
  automatic,
  manual,
  disabled,
}

/// Service state
enum ServiceState {
  unknown,
  stopped,
  startPending,
  stopPending,
  running,
  continuePending,
  pausePending,
  paused,
}

/// Service control result
class ServiceResult {
  final bool success;
  final String? message;
  final ServiceState? state;

  const ServiceResult({
    required this.success,
    this.message,
    this.state,
  });

  factory ServiceResult.success([String? message, ServiceState? state]) {
    return ServiceResult(
      success: true,
      message: message,
      state: state,
    );
  }

  factory ServiceResult.failure(String message) {
    return ServiceResult(
      success: false,
      message: message,
    );
  }
}

/// Windows Service Manager
class WindowsServiceManager {
  final WindowsServiceConfig _config;
  bool _isConnected = false;
  int _scManagerHandle = 0;

  WindowsServiceManager({WindowsServiceConfig? config})
      : _config = config ?? const WindowsServiceConfig();

  /// Connect to the Service Control Manager
  bool _connect() {
    if (_isConnected) return true;

    _scManagerHandle = OpenSCManager(
      nullptr,
      nullptr,
      SC_MANAGER_ALL_ACCESS,
    );

    _isConnected = _scManagerHandle != 0;
    return _isConnected;
  }

  /// Disconnect from the Service Control Manager
  void _disconnect() {
    if (_isConnected && _scManagerHandle != 0) {
      CloseServiceHandle(_scManagerHandle);
      _scManagerHandle = 0;
      _isConnected = false;
    }
  }

  /// Check if the service is installed
  bool isInstalled() {
    if (!_connect()) return false;

    try {
      final serviceHandle = OpenService(
        _scManagerHandle,
        _config.serviceName.toNativeUtf16(),
        SERVICE_QUERY_STATUS,
      );

      if (serviceHandle != 0) {
        CloseServiceHandle(serviceHandle);
        return true;
      }

      return false;
    } finally {
      _disconnect();
    }
  }

  /// Get the current service state
  ServiceState getState() {
    if (!_connect()) return ServiceState.unknown;

    try {
      final serviceHandle = OpenService(
        _scManagerHandle,
        _config.serviceName.toNativeUtf16(),
        SERVICE_QUERY_STATUS,
      );

      if (serviceHandle == 0) {
        return ServiceState.unknown;
      }

      final serviceStatus = calloc<_SERVICE_STATUS>();
      try {
        final result = QueryServiceStatus(
          serviceHandle,
          serviceStatus,
        );

        if (result == 0) {
          CloseServiceHandle(serviceHandle);
          return ServiceState.unknown;
        }

        final state = _mapServiceState(serviceStatus.ref.dwCurrentState);
        CloseServiceHandle(serviceHandle);
        return state;
      } finally {
        calloc.free(serviceStatus);
      }
    } finally {
      _disconnect();
    }
  }

  /// Install the Windows service
  ServiceResult install() {
    if (!_connect()) {
      return ServiceResult.failure('Failed to connect to Service Control Manager');
    }

    try {
      final serviceHandle = CreateService(
        _scManagerHandle,
        _config.serviceName.toNativeUtf16(),
        _config.displayName.toNativeUtf16(),
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        _mapStartType(_config.startType),
        SERVICE_ERROR_NORMAL,
        _config.serviceCommandLine.toNativeUtf16(),
        nullptr,
        nullptr,
        nullptr,
        nullptr, // No logon account
        nullptr, // No password
      );

      if (serviceHandle == 0) {
        final error = GetLastError();
        if (error == ERROR_SERVICE_EXISTS) {
          return ServiceResult.failure('Service already exists');
        }
        return ServiceResult.failure('Failed to create service: $error');
      }

      // Set service description
      _setDescription(serviceHandle);

      // Configure service recovery
      _configureRecovery(serviceHandle);

      CloseServiceHandle(serviceHandle);
      return ServiceResult.success('Service installed successfully');
    } finally {
      _disconnect();
    }
  }

  /// Uninstall the Windows service
  ServiceResult uninstall() {
    if (!_connect()) {
      return ServiceResult.failure('Failed to connect to Service Control Manager');
    }

    try {
      final serviceHandle = OpenService(
        _scManagerHandle,
        _config.serviceName.toNativeUtf16(),
        DELETE,
      );

      if (serviceHandle == 0) {
        final error = GetLastError();
        if (error == ERROR_SERVICE_DOES_NOT_EXIST) {
          return ServiceResult.success('Service was not installed');
        }
        return ServiceResult.failure('Failed to open service: $error');
      }

      // Stop the service first if running
      _stopService(serviceHandle);

      final result = DeleteService(serviceHandle);
      CloseServiceHandle(serviceHandle);

      if (result != 0) {
        return ServiceResult.success('Service uninstalled successfully');
      } else {
        return ServiceResult.failure('Failed to delete service: ${GetLastError()}');
      }
    } finally {
      _disconnect();
    }
  }

  /// Start the Windows service
  ServiceResult start() {
    if (!_connect()) {
      return ServiceResult.failure('Failed to connect to Service Control Manager');
    }

    try {
      final serviceHandle = OpenService(
        _scManagerHandle,
        _config.serviceName.toNativeUtf16(),
        SERVICE_START,
      );

      if (serviceHandle == 0) {
        return ServiceResult.failure('Failed to open service: ${GetLastError()}');
      }

      final result = StartService(
        serviceHandle,
        0,
        nullptr,
      );

      CloseServiceHandle(serviceHandle);

      if (result != 0) {
        return ServiceResult.success('Service started', ServiceState.startPending);
      } else {
        final error = GetLastError();
        if (error == ERROR_SERVICE_ALREADY_RUNNING) {
          return ServiceResult.success('Service is already running', ServiceState.running);
        }
        return ServiceResult.failure('Failed to start service: $error');
      }
    } finally {
      _disconnect();
    }
  }

  /// Stop the Windows service
  ServiceResult stop() {
    if (!_connect()) {
      return ServiceResult.failure('Failed to connect to Service Control Manager');
    }

    try {
      final serviceHandle = OpenService(
        _scManagerHandle,
        _config.serviceName.toNativeUtf16(),
        SERVICE_STOP | SERVICE_QUERY_STATUS,
      );

      if (serviceHandle == 0) {
        return ServiceResult.failure('Failed to open service: ${GetLastError()}');
      }

      final result = _stopService(serviceHandle);
      CloseServiceHandle(serviceHandle);
      return result;
    } finally {
      _disconnect();
    }
  }

  /// Stop the service (internal)
  ServiceResult _stopService(int serviceHandle) {
    final serviceStatus = calloc<_SERVICE_STATUS>();

    try {
      final result = ControlService(
        serviceHandle,
        SERVICE_CONTROL_STOP,
        serviceStatus,
      );

      if (result != 0) {
        return ServiceResult.success('Service stopped', ServiceState.stopPending);
      } else {
        final error = GetLastError();
        if (error == ERROR_SERVICE_NOT_ACTIVE) {
          return ServiceResult.success('Service was not running', ServiceState.stopped);
        }
        return ServiceResult.failure('Failed to stop service: $error');
      }
    } finally {
      calloc.free(serviceStatus);
    }
  }

  /// Set the service description
  void _setDescription(int serviceHandle) {
    final description = _SERVICE_DESCRIPTION(
      lpDescription: _config.description.toNativeUtf16(),
    );

    final descriptionPtr = calloc<_SERVICE_DESCRIPTION>()
      ..ref.lpDescription = description.lpDescription;

    ChangeServiceConfig2(
      serviceHandle,
      SERVICE_CONFIG_DESCRIPTION,
      descriptionPtr.cast(),
    );

    calloc.free(descriptionPtr);
  }

  /// Configure service recovery options
  void _configureRecovery(int serviceHandle) {
    // Configure recovery actions: restart on failure
    final actions = calloc<_SERVICE_FAILURE_ACTIONS>();
    final actionArray = calloc<_SC_ACTION>(count: 3);

    try {
      // First failure: restart after 1 minute
      actionArray[0].type = SC_ACTION_RESTART;
      actionArray[0].delay = 60000; // 1 minute

      // Second failure: restart after 1 minute
      actionArray[1].type = SC_ACTION_RESTART;
      actionArray[1].delay = 60000;

      // Subsequent failures: restart after 5 minutes
      actionArray[2].type = SC_ACTION_RESTART;
      actionArray[2].delay = 300000; // 5 minutes

      actions.ref.cActions = 3;
      actions.ref.lpsaActions = actionArray;
      actions.ref.dwResetPeriod = 86400; // Reset after 1 day
      actions.ref.lpRebootMsg = nullptr;
      actions.ref.lpCommand = nullptr;

      ChangeServiceConfig2(
        serviceHandle,
        SERVICE_CONFIG_FAILURE_ACTIONS,
        actions.cast(),
      );
    } finally {
      calloc.free(actionArray);
      calloc.free(actions);
    }
  }

  /// Map Windows service state to our enum
  ServiceState _mapServiceState(int dwState) {
    switch (dwState) {
      case SERVICE_STOPPED:
        return ServiceState.stopped;
      case SERVICE_START_PENDING:
        return ServiceState.startPending;
      case SERVICE_STOP_PENDING:
        return ServiceState.stopPending;
      case SERVICE_RUNNING:
        return ServiceState.running;
      case SERVICE_CONTINUE_PENDING:
        return ServiceState.continuePending;
      case SERVICE_PAUSE_PENDING:
        return ServiceState.pausePending;
      case SERVICE_PAUSED:
        return ServiceState.paused;
      default:
        return ServiceState.unknown;
    }
  }

  /// Map our start type to Windows constant
  int _mapStartType(ServiceStartType startType) {
    switch (startType) {
      case ServiceStartType.boot:
        return SERVICE_BOOT_START;
      case ServiceStartType.system:
        return SERVICE_SYSTEM_START;
      case ServiceStartType.automatic:
        return SERVICE_AUTO_START;
      case ServiceStartType.manual:
        return SERVICE_DEMAND_START;
      case ServiceStartType.disabled:
        return SERVICE_DISABLED;
    }
  }

  /// Dispose resources
  void dispose() {
    _disconnect();
  }
}

/// Provider for Windows service manager
final windowsServiceProvider = Provider<WindowsServiceManager>((ref) {
  final service = WindowsServiceManager();

  ref.onDispose(() {
    service.dispose();
  });

  return service;
});

/// Service installation check provider
final serviceInstalledProvider = Provider<bool>((ref) {
  final service = ref.watch(windowsServiceProvider);
  return service.isInstalled();
});

/// Service state provider
final serviceStateProvider = Provider<ServiceState>((ref) {
  final service = ref.watch(windowsServiceProvider);
  return service.getState();
});
