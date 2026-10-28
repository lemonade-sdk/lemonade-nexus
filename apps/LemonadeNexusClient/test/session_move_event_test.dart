// The session-move event as the SDK's callback delivers it. None of these
// tests needs the native SDK library.

import 'package:flutter_test/flutter_test.dart';
import 'package:nexus_client/src/sdk/sdk.dart';

void main() {
  group('SessionMoveEvent', () {
    test('parses a silent move', () {
      final event = SessionMoveEvent.fromJson({
        'from_node_id': 'AAAA',
        'from_host': 'a.example',
        'to_node_id': 'BBBB',
        'to_host': 'b.example',
        'epoch': 7,
        'silent': true,
        'error': '',
      });
      expect(event.fromNodeId, 'AAAA');
      expect(event.fromHost, 'a.example');
      expect(event.toNodeId, 'BBBB');
      expect(event.toHost, 'b.example');
      expect(event.epoch, 7);
      expect(event.silent, isTrue);
      expect(event.error, isEmpty);
      expect(SessionMoveEvent.fromJson(event.toJson()).toJson(), event.toJson());
    });

    test('a move that is not silent names no new server and says why', () {
      final event = SessionMoveEvent.fromJson({
        'from_node_id': 'AAAA',
        'from_host': 'a.example',
        'to_node_id': '',
        'to_host': '',
        'epoch': 8,
        'silent': false,
        'error': 'no identity for a silent re-authentication',
      });
      expect(event.silent, isFalse);
      expect(event.toNodeId, isEmpty);
      expect(event.toHost, isEmpty);
      expect(event.error, 'no identity for a silent re-authentication');
    });

    test('missing fields fail closed to an empty, not silent event', () {
      final event = SessionMoveEvent.fromJson(const {});
      expect(event.silent, isFalse);
      expect(event.epoch, 0);
      expect(event.fromNodeId, isEmpty);
      expect(event.toHost, isEmpty);
    });

    test('mesh status still reports needs_rejoin for a dropped session', () {
      final status = MeshStatus.fromJson({'is_up': true, 'needs_rejoin': true});
      expect(status.needsRejoin, isTrue);
      expect(MeshStatus.fromJson({'is_up': true}).needsRejoin, isFalse);
    });
  });
}
