/// @title Nexus Worker
/// @description Runs a [LemonadeNexusSdk] on a background isolate.
///
/// Most SDK calls block on the network (authentication, joining, Genesis key
/// discovery). On the UI isolate each one would freeze the app for the whole
/// round trip. A [NexusWorker] owns one [LemonadeNexusSdk] on its own isolate
/// and runs the closures given to [run] there, one at a time and in order, so
/// two calls never race on the same native client.
///
/// ```dart
/// final worker = await NexusWorker.spawn();
/// final health = await worker.run((sdk) => sdk.health());
/// await worker.close();
/// ```
library;

import 'dart:async';
import 'dart:isolate';

import 'lemonade_nexus_sdk.dart';

class NexusWorker {
  NexusWorker._(this._isolate, this._commands, this._responses);

  final Isolate _isolate;
  final SendPort _commands;
  final ReceivePort _responses;
  final Map<int, Completer<Object?>> _pending = {};
  int _nextId = 0;
  bool _closed = false;

  /// Starts the worker isolate and loads the native library there.
  /// [libraryPath] is passed to [LemonadeNexusSdk]; null uses the platform
  /// default. A library that fails to load fails each [run] call.
  static Future<NexusWorker> spawn({String? libraryPath}) async {
    final responses = ReceivePort();
    final isolate = await Isolate.spawn(
      _workerMain,
      (responses.sendPort, libraryPath),
      debugName: 'lemonade_nexus_sdk',
    );
    final ready = Completer<SendPort>();
    late final NexusWorker worker;
    responses.listen((message) {
      if (!ready.isCompleted) {
        ready.complete(message as SendPort);
        return;
      }
      worker._onResponse(message);
    });
    worker = NexusWorker._(isolate, await ready.future, responses);
    return worker;
  }

  /// Runs [task] with the worker's SDK on the worker isolate and returns its
  /// result. Tasks run in the order they were submitted.
  ///
  /// [task] and its result must be sendable between isolates. A closure is
  /// sent together with every variable of the scopes it was created in, so a
  /// closure written inside a method that also holds a widget, a provider ref
  /// or this worker is not sendable. Build tasks in a static or top-level
  /// function that takes only plain data (strings, numbers, lists, maps):
  ///
  /// ```dart
  /// static Future<Map<String, dynamic>> _invite(LemonadeNexusSdk sdk) =>
  ///     sdk.createLinkToken(ttlSec: 3600);
  /// await worker.run(_invite);
  /// ```
  Future<R> run<R>(FutureOr<R> Function(LemonadeNexusSdk sdk) task) async {
    if (_closed) throw StateError('NexusWorker is closed');
    final id = _nextId++;
    final completer = Completer<Object?>();
    _pending[id] = completer;
    try {
      _commands.send(_Job(id, _wrap(task)));
    } catch (_) {
      _pending.remove(id);
      rethrow;
    }
    return await completer.future as R;
  }

  // A separate function, so the job closure captures only [task].
  static Future<Object?> Function(LemonadeNexusSdk) _wrap<R>(
          FutureOr<R> Function(LemonadeNexusSdk sdk) task) =>
      (sdk) async => await task(sdk);

  /// Disposes the SDK (which stops the mesh and the mesh port) after the
  /// queued tasks finish, then ends the isolate.
  Future<void> close() async {
    if (_closed) return;
    _closed = true;
    final done = Completer<void>();
    final exit = ReceivePort();
    _isolate.addOnExitListener(exit.sendPort);
    exit.first.then((_) {
      exit.close();
      done.complete();
    });
    _commands.send(null);
    await done.future;
    _responses.close();
    for (final pending in _pending.values) {
      pending.completeError(StateError('NexusWorker closed'));
    }
    _pending.clear();
  }

  void _onResponse(Object? message) {
    final (id, ok, value, stack) = message as (int, bool, Object?, String?);
    final completer = _pending.remove(id);
    if (completer == null) return;
    if (ok) {
      completer.complete(value);
    } else {
      completer.completeError(
          value ?? StateError('Unknown error'), StackTrace.fromString(stack ?? ''));
    }
  }
}

class _Job {
  const _Job(this.id, this.task);
  final int id;
  final Future<Object?> Function(LemonadeNexusSdk sdk) task;
}

void _workerMain((SendPort, String?) args) {
  final (out, libraryPath) = args;
  final commands = ReceivePort();
  out.send(commands.sendPort);

  LemonadeNexusSdk? sdk;
  Object? loadError;
  try {
    sdk = LemonadeNexusSdk(libraryPath: libraryPath);
  } catch (e) {
    loadError = e;
  }

  // Each value or error is sent as is when it can cross the isolate boundary,
  // otherwise as its string form.
  void reply(int id, bool ok, Object? value, StackTrace? stack) {
    try {
      out.send((id, ok, value, stack?.toString()));
    } catch (_) {
      out.send((id, false, StateError('$value'), stack?.toString()));
    }
  }

  var queue = Future<void>.value();
  commands.listen((message) {
    if (message == null) {
      queue.whenComplete(() {
        sdk?.dispose();
        commands.close();
        Isolate.exit();
      });
      return;
    }
    final job = message as _Job;
    queue = queue.then((_) async {
      try {
        if (sdk == null) throw loadError!;
        reply(job.id, true, await job.task(sdk), null);
      } catch (e, st) {
        reply(job.id, false, e, st);
      }
    });
  });
}
