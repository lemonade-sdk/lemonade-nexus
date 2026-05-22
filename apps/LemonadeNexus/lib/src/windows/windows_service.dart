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
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:win32/win32.dart';

// ---------------------------------------------------------------------------
// CreateServiceW binding
//
// The win32 ^5.0 package does not expose CreateService directly, so we look
// it up ourselves from advapi32.dll. The signature mirrors the Win32 docs:
//
//   SC_HANDLE CreateServiceW(
//     SC_HANDLE hSCManager,
//     LPCWSTR   lpServiceName,
//     LPCWSTR   lpDisplayName,
//     DWORD     dwDesiredAccess,
//     DWORD     dwServiceType,
//     DWORD     dwStartType,
//     DWORD     dwErrorControl,
//     LPCWSTR   lpBinaryPathName,
//     LPCWSTR   lpLoadOrderGroup,
//     LPDWORD   lpdwTagId,
//     LPCWSTR   lpDependencies,
//     LPCWSTR   lpServiceStartName,
//     LPCWSTR   lpPassword
//   );
// ---------------------------------------------------------------------------

typedef _CreateServiceWNative =
    IntPtr Function(
      IntPtr hSCManager,
      Pointer<Utf16> lpServiceName,
      Pointer<Utf16> lpDisplayName,
      Uint32 dwDesiredAccess,
      Uint32 dwServiceType,
      Uint32 dwStartType,
      Uint32 dwErrorControl,
      Pointer<Utf16> lpBinaryPathName,
      Pointer<Utf16> lpLoadOrderGroup,
      Pointer<Uint32> lpdwTagId,
      Pointer<Utf16> lpDependencies,
      Pointer<Utf16> lpServiceStartName,
      Pointer<Utf16> lpPassword,
    );

typedef _CreateServiceWDart =
    int Function(
      int hSCManager,
      Pointer<Utf16> lpServiceName,
      Pointer<Utf16> lpDisplayName,
      int dwDesiredAccess,
      int dwServiceType,
      int dwStartType,
      int dwErrorControl,
      Pointer<Utf16> lpBinaryPathName,
      Pointer<Utf16> lpLoadOrderGroup,
      Pointer<Uint32> lpdwTagId,
      Pointer<Utf16> lpDependencies,
      Pointer<Utf16> lpServiceStartName,
      Pointer<Utf16> lpPassword,
    );

final DynamicLibrary _advapi32 = DynamicLibrary.open('advapi32.dll');

final _CreateServiceWDart _createServiceW = _advapi32
    .lookupFunction<_CreateServiceWNative, _CreateServiceWDart>(
      'CreateServiceW',
    );

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

  WindowsServiceConfig({
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
      : _config = config ?? WindowsServiceConfig();

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

    final namePtr = _config.serviceName.toNativeUtf16();
    try {
      final serviceHandle = OpenService(
        _scManagerHandle,
        namePtr,
        SERVICE_QUERY_STATUS,
      );

      if (serviceHandle != 0) {
        CloseServiceHandle(serviceHandle);
        return true;
      }

      return false;
    } finally {
      calloc.free(namePtr);
      _disconnect();
    }
  }

  /// Get the current service state
  ServiceState getState() {
    if (!_connect()) return ServiceState.unknown;

    final namePtr = _config.serviceName.toNativeUtf16();
    try {
      final serviceHandle = OpenService(
        _scManagerHandle,
        namePtr,
        SERVICE_QUERY_STATUS,
      );

      if (serviceHandle == 0) {
        return ServiceState.unknown;
      }

      final serviceStatus = calloc<SERVICE_STATUS>();
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
      calloc.free(namePtr);
      _disconnect();
    }
  }

  /// Install the Windows service
  ServiceResult install() {
    if (!_connect()) {
      return ServiceResult.failure(
        'Failed to connect to Service Control Manager',
      );
    }

    final namePtr = _config.serviceName.toNativeUtf16();
    final displayPtr = _config.displayName.toNativeUtf16();
    final cmdPtr = _config.serviceCommandLine.toNativeUtf16();
    try {
      final serviceHandle = _createServiceW(
        _scManagerHandle,
        namePtr,
        displayPtr,
        SERVICE_ALL_ACCESS,
        ENUM_SERVICE_TYPE.SERVICE_WIN32_OWN_PROCESS,
        _mapStartType(_config.startType),
        SERVICE_ERROR.SERVICE_ERROR_NORMAL,
        cmdPtr,
        nullptr, // lpLoadOrderGroup
        nullptr, // lpdwTagId
        nullptr, // lpDependencies
        nullptr, // lpServiceStartName (no logon account)
        nullptr, // lpPassword
      );

      if (serviceHandle == 0) {
        final error = GetLastError();
        if (error == WIN32_ERROR.ERROR_SERVICE_EXISTS) {
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
      calloc.free(namePtr);
      calloc.free(displayPtr);
      calloc.free(cmdPtr);
      _disconnect();
    }
  }

  /// Uninstall the Windows service
  ServiceResult uninstall() {
    if (!_connect()) {
      return ServiceResult.failure(
        'Failed to connect to Service Control Manager',
      );
    }

    final namePtr = _config.serviceName.toNativeUtf16();
    try {
      final serviceHandle = OpenService(
        _scManagerHandle,
        namePtr,
        DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS,
      );

      if (serviceHandle == 0) {
        final error = GetLastError();
        if (error == WIN32_ERROR.ERROR_SERVICE_DOES_NOT_EXIST) {
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
        return ServiceResult.failure(
          'Failed to delete service: ${GetLastError()}',
        );
      }
    } finally {
      calloc.free(namePtr);
      _disconnect();
    }
  }

  /// Start the Windows service
  ServiceResult start() {
    if (!_connect()) {
      return ServiceResult.failure(
        'Failed to connect to Service Control Manager',
      );
    }

    final namePtr = _config.serviceName.toNativeUtf16();
    try {
      final serviceHandle = OpenService(
        _scManagerHandle,
        namePtr,
        SERVICE_START,
      );

      if (serviceHandle == 0) {
        return ServiceResult.failure(
          'Failed to open service: ${GetLastError()}',
        );
      }

      final result = StartService(
        serviceHandle,
        0,
        nullptr,
      );

      CloseServiceHandle(serviceHandle);

      if (result != 0) {
        return ServiceResult.success(
          'Service started',
          ServiceState.startPending,
        );
      } else {
        final error = GetLastError();
        if (error == WIN32_ERROR.ERROR_SERVICE_ALREADY_RUNNING) {
          return ServiceResult.success(
            'Service is already running',
            ServiceState.running,
          );
        }
        return ServiceResult.failure('Failed to start service: $error');
      }
    } finally {
      calloc.free(namePtr);
      _disconnect();
    }
  }

  /// Stop the Windows service
  ServiceResult stop() {
    if (!_connect()) {
      return ServiceResult.failure(
        'Failed to connect to Service Control Manager',
      );
    }

    final namePtr = _config.serviceName.toNativeUtf16();
    try {
      final serviceHandle = OpenService(
        _scManagerHandle,
        namePtr,
        SERVICE_STOP | SERVICE_QUERY_STATUS,
      );

      if (serviceHandle == 0) {
        return ServiceResult.failure(
          'Failed to open service: ${GetLastError()}',
        );
      }

      final result = _stopService(serviceHandle);
      CloseServiceHandle(serviceHandle);
      return result;
    } finally {
      calloc.free(namePtr);
      _disconnect();
    }
  }

  /// Stop the service (internal)
  ServiceResult _stopService(int serviceHandle) {
    final serviceStatus = calloc<SERVICE_STATUS>();

    try {
      final result = ControlService(
        serviceHandle,
        SERVICE_CONTROL_STOP,
        serviceStatus,
      );

      if (result != 0) {
        return ServiceResult.success(
          'Service stopped',
          ServiceState.stopPending,
        );
      } else {
        final error = GetLastError();
        if (error == WIN32_ERROR.ERROR_SERVICE_NOT_ACTIVE) {
          return ServiceResult.success(
            'Service was not running',
            ServiceState.stopped,
          );
        }
        return ServiceResult.failure('Failed to stop service: $error');
      }
    } finally {
      calloc.free(serviceStatus);
    }
  }

  /// Set the service description
  void _setDescription(int serviceHandle) {
    final descPtr = calloc<SERVICE_DESCRIPTION>();
    final textPtr = _config.description.toNativeUtf16();
    try {
      descPtr.ref.lpDescription = textPtr;

      ChangeServiceConfig2(
        serviceHandle,
        SERVICE_CONFIG.SERVICE_CONFIG_DESCRIPTION,
        descPtr,
      );
    } finally {
      calloc.free(textPtr);
      calloc.free(descPtr);
    }
  }

  /// Configure service recovery options
  void _configureRecovery(int serviceHandle) {
    // Configure recovery actions: restart on failure
    final actions = calloc<SERVICE_FAILURE_ACTIONS>();
    final actionArray = calloc<SC_ACTION>(3);

    try {
      // First failure: restart after 1 minute
      actionArray[0].Type = SC_ACTION_TYPE.SC_ACTION_RESTART;
      actionArray[0].Delay = 60000; // 1 minute

      // Second failure: restart after 1 minute
      actionArray[1].Type = SC_ACTION_TYPE.SC_ACTION_RESTART;
      actionArray[1].Delay = 60000;

      // Subsequent failures: restart after 5 minutes
      actionArray[2].Type = SC_ACTION_TYPE.SC_ACTION_RESTART;
      actionArray[2].Delay = 300000; // 5 minutes

      actions.ref.cActions = 3;
      actions.ref.lpsaActions = actionArray;
      actions.ref.dwResetPeriod = 86400; // Reset after 1 day
      actions.ref.lpRebootMsg = nullptr;
      actions.ref.lpCommand = nullptr;

      ChangeServiceConfig2(
        serviceHandle,
        SERVICE_CONFIG.SERVICE_CONFIG_FAILURE_ACTIONS,
        actions,
      );
    } finally {
      calloc.free(actionArray);
      calloc.free(actions);
    }
  }

  /// Map Windows service state to our enum
  ServiceState _mapServiceState(int dwState) {
    switch (dwState) {
      case SERVICE_STATUS_CURRENT_STATE.SERVICE_STOPPED:
        return ServiceState.stopped;
      case SERVICE_STATUS_CURRENT_STATE.SERVICE_START_PENDING:
        return ServiceState.startPending;
      case SERVICE_STATUS_CURRENT_STATE.SERVICE_STOP_PENDING:
        return ServiceState.stopPending;
      case SERVICE_STATUS_CURRENT_STATE.SERVICE_RUNNING:
        return ServiceState.running;
      case SERVICE_STATUS_CURRENT_STATE.SERVICE_CONTINUE_PENDING:
        return ServiceState.continuePending;
      case SERVICE_STATUS_CURRENT_STATE.SERVICE_PAUSE_PENDING:
        return ServiceState.pausePending;
      case SERVICE_STATUS_CURRENT_STATE.SERVICE_PAUSED:
        return ServiceState.paused;
      default:
        return ServiceState.unknown;
    }
  }

  /// Map our start type to Windows constant
  int _mapStartType(ServiceStartType startType) {
    switch (startType) {
      case ServiceStartType.boot:
        return SERVICE_START_TYPE.SERVICE_BOOT_START;
      case ServiceStartType.system:
        return SERVICE_START_TYPE.SERVICE_SYSTEM_START;
      case ServiceStartType.automatic:
        return SERVICE_START_TYPE.SERVICE_AUTO_START;
      case ServiceStartType.manual:
        return SERVICE_START_TYPE.SERVICE_DEMAND_START;
      case ServiceStartType.disabled:
        return SERVICE_START_TYPE.SERVICE_DISABLED;
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
