# Template: Provider/StateNotifier Class

## Description
Standard template for creating Provider/StateNotifier classes for state management.

## Usage
Use this template when creating any new state provider.

## Template Structure

```dart
// lib/src/state/{name}_provider.dart
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../sdk/sdk_wrapper.dart';
import '../models/{name}_model.dart';

/// {@template {name}State}
/// State class for {description}.
/// {@endtemplate}
class {Name}State {
  final {DataType} data;
  final bool isLoading;
  final String? error;
  final DateTime? lastUpdated;

  const {Name}State({
    this.data = const [],
    this.isLoading = false,
    this.error,
    this.lastUpdated,
  });

  {Name}State copyWith({
    {DataType}? data,
    bool? isLoading,
    String? error,
    DateTime? lastUpdated,
  }) {
    return {Name}State(
      data: data ?? this.data,
      isLoading: isLoading ?? this.isLoading,
      error: error ?? this.error,
      lastUpdated: lastUpdated ?? this.lastUpdated,
    );
  }
}

/// {@template {name}Notifier}
/// StateNotifier for managing {description}.
/// {@endtemplate}
class {Name}Notifier extends StateNotifier<{Name}State> {
  final LemonadeNexusSdk _sdk;

  {Name}Notifier(this._sdk) : super(const {Name}State());

  /// Initialize and load initial data
  Future<void> initialize() async {
    state = state.copyWith(isLoading: true, error: null);
    try {
      // Load data
      state = state.copyWith(
        isLoading: false,
        lastUpdated: DateTime.now(),
      );
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
    }
  }

  /// Refresh data from SDK
  Future<void> refresh() async {
    state = state.copyWith(isLoading: true, error: null);
    try {
      // Fetch data
      state = state.copyWith(
        isLoading: false,
        lastUpdated: DateTime.now(),
      );
    } catch (e) {
      state = state.copyWith(
        isLoading: false,
        error: e.toString(),
      );
    }
  }

  /// Action method
  Future<void> {actionName}({parameters}) async {
    // Implementation
  }
}

/// Provider definition
final {name}Provider = StateNotifierProvider<{Name}Notifier, {Name}State>(
  (ref) {
    final sdk = ref.watch(sdkProvider);
    return {Name}Notifier(sdk);
  },
);
```

## Complete Example

```dart
// lib/src/state/tunnel_provider.dart
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../sdk/sdk_wrapper.dart';
import '../models/tunnel_model.dart';

/// {@template TunnelState}
/// State class for WireGuard tunnel status.
/// {@endtemplate}
class TunnelState {
  final TunnelStatus status;
  final String? tunnelIp;
  final String? serverEndpoint;
  final int rxBytes;
  final int txBytes;
  final double? latency;
  final bool isLoading;
  final String? error;

  const TunnelState({
    this.status = TunnelStatus.disconnected,
    this.tunnelIp,
    this.serverEndpoint,
    this.rxBytes = 0,
    this.txBytes = 0,
    this.latency,
    this.isLoading = false,
    this.error,
  });

  TunnelState copyWith({
    TunnelStatus? status,
    String? tunnelIp,
    String? serverEndpoint,
    int? rxBytes,
    int? txBytes,
    double? latency,
    bool? isLoading,
    String? error,
  }) {
    return TunnelState(
      status: status ?? this.status,
      tunnelIp: tunnelIp ?? this.tunnelIp,
      serverEndpoint: serverEndpoint ?? this.serverEndpoint,
      rxBytes: rxBytes ?? this.rxBytes,
      txBytes: txBytes ?? this.txBytes,
      latency: latency ?? this.latency,
      isLoading: isLoading ?? this.isLoading,
      error: error ?? this.error,
    );
  }

  bool get isConnected => status == TunnelStatus.connected;
  String get trafficSummary => '${_formatBytes(rxBytes)} ↓ / ${_formatBytes(txBytes)} ↑';

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
  }
}

enum TunnelStatus {
  disconnected,
  connecting,
  connected,
  disconnecting,
  error;

  String get displayString {
    switch (this) {
      case TunnelStatus.disconnected:
        return 'Disconnected';
      case TunnelStatus.connecting:
        return 'Connecting...';
      case TunnelStatus.connected:
        return 'Connected';
      case TunnelStatus.disconnecting:
        return 'Disconnecting...';
      case TunnelStatus.error:
        return 'Error';
    }
  }
}

/// {@template TunnelNotifier}
/// StateNotifier for managing WireGuard tunnel state.
/// {@endtemplate}
class TunnelNotifier extends StateNotifier<TunnelState> {
  final LemonadeNexusSdk _sdk;
  Timer? _statusPollTimer;

  TunnelNotifier(this._sdk) : super(const TunnelState());

  @override
  void dispose() {
    _statusPollTimer?.cancel();
    super.dispose();
  }

  /// Connect the tunnel
  Future<void> connect(String configJson) async {
    state = state.copyWith(
      status: TunnelStatus.connecting,
      isLoading: true,
      error: null,
    );

    try {
      final result = await _sdk.tunnel.up(configJson);
      if (result['success'] == true) {
        state = state.copyWith(
          status: TunnelStatus.connected,
          tunnelIp: result['tunnel_ip'],
          serverEndpoint: result['server_endpoint'],
        );
        _startStatusPolling();
      } else {
        throw Exception(result['error'] ?? 'Unknown error');
      }
    } catch (e) {
      state = state.copyWith(
        status: TunnelStatus.error,
        error: e.toString(),
      );
    } finally {
      state = state.copyWith(isLoading: false);
    }
  }

  /// Disconnect the tunnel
  Future<void> disconnect() async {
    state = state.copyWith(
      status: TunnelStatus.disconnecting,
      isLoading: true,
    );

    try {
      await _sdk.tunnel.down();
      state = state.copyWith(
        status: TunnelStatus.disconnected,
        tunnelIp: null,
        serverEndpoint: null,
      );
    } catch (e) {
      state = state.copyWith(
        status: TunnelStatus.error,
        error: e.toString(),
      );
    } finally {
      state = state.copyWith(isLoading: false);
      _stopStatusPolling();
    }
  }

  /// Refresh tunnel status
  Future<void> refreshStatus() async {
    try {
      final status = await _sdk.tunnel.getStatus();
      state = state.copyWith(
        status: _mapStatus(status['status']),
        tunnelIp: status['tunnel_ip'],
        serverEndpoint: status['server_endpoint'],
        rxBytes: status['rx_bytes'],
        txBytes: status['tx_bytes'],
        latency: status['latency_ms']?.toDouble(),
      );
    } catch (e) {
      state = state.copyWith(error: e.toString());
    }
  }

  void _startStatusPolling() {
    _statusPollTimer?.cancel();
    _statusPollTimer = Timer.periodic(
      const Duration(seconds: 5),
      (_) => refreshStatus(),
    );
  }

  void _stopStatusPolling() {
    _statusPollTimer?.cancel();
    _statusPollTimer = null;
  }

  TunnelStatus _mapStatus(String status) {
    switch (status.toLowerCase()) {
      case 'up':
        return TunnelStatus.connected;
      case 'down':
        return TunnelStatus.disconnected;
      default:
        return TunnelStatus.error;
    }
  }
}

/// Provider definition
final tunnelProvider = StateNotifierProvider<TunnelNotifier, TunnelState>(
  (ref) {
    final sdk = ref.watch(sdkProvider);
    return TunnelNotifier(sdk);
  },
);
```

## Related Templates
- Flutter View Component Template
- Service Class Template
- Model Class Template

## Notes
- Use StateNotifier for complex state
- Use ChangeNotifier for simpler cases
- Always implement dispose for cleanup
- Include copyWith for immutability
- Document state transitions
