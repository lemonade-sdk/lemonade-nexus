/// Provider for per-server admin HTTP clients.
///
/// Creates one [LemonadeApiClient] per selected server and auto-disposes it on change.

import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../api/lemonade_api_client.dart';
import '../../api/server_config.dart';

/// A server entry that can be selected for admin console access.
class AdminServer {
  final String id; // unique identifier (e.g., host:port from SDK)
  final String name;
  final String baseUrl; // e.g., http://192.168.1.100:13305
  final String? apiKey;
  final bool available;

  const AdminServer({
    required this.id,
    required this.name,
    required this.baseUrl,
    this.apiKey,
    required this.available,
  });

  factory AdminServer.fromSdk(Map<String, dynamic> sdkServer) {
    final host = sdkServer['host']?.toString() ?? 'unknown';
    final port = (sdkServer['port'] as num?)?.toInt() ?? 13305;
    final id = '$host:$port';
    return AdminServer(
      id: id,
      name: sdkServer['name']?.toString() ?? host,
      baseUrl: 'http://$host:$port',
      available: sdkServer['available'] as bool? ?? true,
    );
  }

  Map<String, dynamic> toJson() => {
        'id': id,
        'name': name,
        'baseUrl': baseUrl,
        'apiKey': apiKey,
        'available': available,
      };

  factory AdminServer.fromJson(Map<String, dynamic> json) => AdminServer(
        id: json['id'] as String? ?? '',
        name: json['name'] as String? ?? '',
        baseUrl: json['baseUrl'] as String? ?? '',
        apiKey: json['apiKey'] as String?,
        available: json['available'] as bool? ?? true,
      );
}

/// Provider that holds the list of admin-capable servers.
final adminServersProvider = StateNotifierProvider<AdminServersNotifier, List<AdminServer>>(
  (ref) => AdminServersNotifier(),
);

/// Provider that holds the currently selected admin server.
final selectedAdminServerProvider = StateNotifierProvider<SelectedAdminServerNotifier, AdminServer?>(
  (ref) => SelectedAdminServerNotifier(),
);

/// Provider that creates an HTTP client for the selected admin server.
final serverAdminProvider = Provider<LemonadeApiClient?>((ref) {
  final server = ref.watch(selectedAdminServerProvider);
  if (server == null) return null;
  final config = ServerConfig(name: server.name, baseUrl: server.baseUrl, apiKey: server.apiKey);
  final client = LemonadeApiClient(config);
  ref.onDispose(client.close);
  return client;
});

class AdminServersNotifier extends StateNotifier<List<AdminServer>> {
  AdminServersNotifier() : super([]);

  void setServers(List<AdminServer> servers) {
    state = servers;
  }

  /// Sync from SDK server list (auto-populates base URLs).
  void syncFromSdkServers(List<Map<String, dynamic>> sdkServers) {
    final existing = <String, AdminServer>{};
    for (final s in state) {
      existing[s.id] = s;
    }

    for (final sdk in sdkServers) {
      final host = sdk['host']?.toString() ?? 'unknown';
      final port = (sdk['port'] as num?)?.toInt() ?? 13305;
      final id = '$host:$port';

      if (existing.containsKey(id)) {
        // Update existing server's availability status
        final old = existing[id]!;
        existing[id] = AdminServer(
          id: id,
          name: old.name,
          baseUrl: old.baseUrl, // keep user-configured URL
          apiKey: old.apiKey,
          available: sdk['available'] as bool? ?? true,
        );
      } else {
        existing[id] = AdminServer(
          id: id,
          name: sdk['name']?.toString() ?? host,
          baseUrl: 'http://$host:$port',
          available: sdk['available'] as bool? ?? true,
        );
      }
    }

    state = existing.values.toList(growable: false);
  }
}

class SelectedAdminServerNotifier extends StateNotifier<AdminServer?> {
  SelectedAdminServerNotifier() : super(null);

  void selectServer(AdminServer? server) {
    state = server;
  }

  void selectById(String id) {
    final servers = state; // Note: need to watch adminServersProvider separately
  }
}
