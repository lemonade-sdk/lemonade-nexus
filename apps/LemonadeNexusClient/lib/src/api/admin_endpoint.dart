/// Lemonade admin / management endpoints.
library;

import 'dart:async';
import 'dart:convert';

import '../api/lemonade_api_client.dart';
import 'sse_parser.dart';

class AdminEndpoint {
  final LemonadeApiClient _client;
  AdminEndpoint(this._client);

  // ---------------------------------------------------------------------------
  // Health / liveness
  // ---------------------------------------------------------------------------

  /// `GET /v1/health` — server status, version, loaded models, max_models, websocket_port.
  Future<Map<String, dynamic>> health() {
    return _client.getJson(_client.apiUriFor('/health'));
  }

  /// `GET /live` — root-mounted lightweight liveness probe.
  Future<bool> live() async {
    try {
      final body = await _client.getJson(_client.rootUriFor('/live'));
      return body['status'] == 'ok';
    } catch (_) {
      return false;
    }
  }

  /// `GET /v1/stats` — performance stats from the last request.
  Future<Map<String, dynamic>> stats() {
    return _client.getJson(_client.apiUriFor('/stats'));
  }

  /// `GET /v1/system-info` — hardware enumeration + recipe / backend states.
  Future<Map<String, dynamic>> systemInfo() {
    return _client.getJson(_client.apiUriFor('/system-info'));
  }

  // ---------------------------------------------------------------------------
  // Model lifecycle
  // ---------------------------------------------------------------------------

  /// `POST /v1/load`.
  Future<Map<String, dynamic>> load({
    required String modelName,
    int? ctxSize,
    String? llamacppBackend,
    String? llamacppArgs,
  }) {
    final body = <String, dynamic>{'model_name': modelName};
    if (ctxSize != null) body['ctx_size'] = ctxSize;
    if (llamacppBackend != null) body['llamacpp_backend'] = llamacppBackend;
    if (llamacppArgs != null) body['llamacpp_args'] = llamacppArgs;
    return _client.postJson(
      _client.apiUriFor('/load'),
      body,
      timeout: const Duration(minutes: 10),
    );
  }

  /// `POST /v1/unload`. Pass [modelName] to unload a specific model, or omit to unload all.
  Future<Map<String, dynamic>> unload({String? modelName}) {
    final body = <String, dynamic>{};
    if (modelName != null) body['model_name'] = modelName;
    return _client.postJson(_client.apiUriFor('/unload'), body);
  }

  /// `POST /v1/delete` — remove a model from local storage.
  Future<Map<String, dynamic>> delete({required String modelName}) {
    return _client.postJson(
      _client.apiUriFor('/delete'),
      {'model_name': modelName},
    );
  }

  // ---------------------------------------------------------------------------
  // Pull (install)
  // ---------------------------------------------------------------------------

  /// `POST /v1/pull` (stream=false).
  Future<Map<String, dynamic>> pull({
    required String modelName,
    String? checkpoint,
    String? recipe,
    Duration? timeout,
  }) {
    final body = <String, dynamic>{
      'model_name': modelName,
      'stream': false,
      if (checkpoint != null) 'checkpoint': checkpoint,
      if (recipe != null) 'recipe': recipe,
    };
    return _client.postJson(
      _client.apiUriFor('/pull'),
      body,
      timeout: timeout ?? const Duration(minutes: 30),
    );
  }

  /// `POST /v1/pull` (stream=true) — install with progress events.
  Stream<PullEvent> pullStream({
    required String modelName,
    String? checkpoint,
    String? recipe,
  }) async* {
    final body = <String, dynamic>{
      'model_name': modelName,
      'stream': true,
      if (checkpoint != null) 'checkpoint': checkpoint,
      if (recipe != null) 'recipe': recipe,
    };
    final resp = await _client.streamSsePost(
      _client.apiUriFor('/pull'),
      body,
    );
    await for (final SseEvent ev in parseSseStream(resp.stream)) {
      final data = ev.data.trim();
      if (data.isEmpty) continue;
      Map<String, dynamic>? payload;
      try {
        final decoded = jsonDecode(data);
        if (decoded is Map<String, dynamic>) payload = decoded;
      } catch (_) {}
      if (payload == null) continue;

      switch (ev.event) {
        case 'progress':
          yield PullEvent.progress(
            file: payload['file'] as String?,
            bytesDownloaded: (payload['bytes_downloaded'] as num?)?.toInt(),
            bytesTotal: (payload['bytes_total'] as num?)?.toInt(),
            percent: (payload['percent'] as num?)?.toDouble(),
          );
        case 'complete':
          yield const PullComplete();
          return;
        case 'error':
          yield pullError(payload['error']?.toString() ?? 'Unknown error');
          return;
        default:
          break;
      }
    }
  }

  // ---------------------------------------------------------------------------
  // Backend lifecycle
  // ---------------------------------------------------------------------------

  /// `POST /v1/install`.
  Future<Map<String, dynamic>> install({
    required String recipe,
    required String backend,
    bool force = false,
  }) {
    return _client.postJson(
      _client.apiUriFor('/install'),
      {
        'recipe': recipe,
        'backend': backend,
        'stream': false,
        if (force) 'force': true,
      },
      timeout: const Duration(minutes: 30),
    );
  }

  /// `POST /v1/uninstall`.
  Future<Map<String, dynamic>> uninstall({
    required String recipe,
    required String backend,
  }) {
    return _client.postJson(
      _client.apiUriFor('/uninstall'),
      {'recipe': recipe, 'backend': backend},
    );
  }

  // ---------------------------------------------------------------------------
  // Models list
  // ---------------------------------------------------------------------------

  /// `GET /v1/models?show_all=true` — all models known to the server.
  Future<List<Map<String, dynamic>>> listModels() async {
    final uri = _client.apiUriFor('/models', query: {'show_all': 'true'});
    final body = await _client.getJson(uri);
    final raw = body['data'];
    if (raw is! List) return const [];
    return raw.whereType<Map<String, dynamic>>().toList();
  }

  /// `GET /v1/models` — only downloaded models.
  Future<List<Map<String, dynamic>>> listInstalledModels() async {
    final uri = _client.apiUriFor('/models');
    final body = await _client.getJson(uri);
    final raw = body['data'];
    if (raw is! List) return const [];
    return raw.whereType<Map<String, dynamic>>().toList();
  }
}

/// Streaming events from `POST /v1/pull` with `stream: true`.
sealed class PullEvent {
  const PullEvent();

  factory PullEvent.progress({
    String? file,
    int? bytesDownloaded,
    int? bytesTotal,
    double? percent,
  }) = PullProgress;

  factory PullEvent.complete() = PullComplete;
}

class PullError extends PullEvent {
  final String message;
  const PullError(this.message);
}

/// Factory to create a PullEvent.error (used outside the sealed class).
PullEvent pullError(String message) => PullError(message);

class PullProgress extends PullEvent {
  final String? file;
  final int? bytesDownloaded;
  final int? bytesTotal;
  final double? percent;

  const PullProgress({this.file, this.bytesDownloaded, this.bytesTotal, this.percent});
}

class PullComplete extends PullEvent {
  const PullComplete();
}
