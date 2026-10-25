// Widget tests for the mesh port panel: device URLs, copy, the selection
// control, and the TLS state. The panel takes a status value, so these tests
// do not need the native SDK library.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:nexus_client/src/sdk/mesh_port.dart';
import 'package:nexus_client/src/views/mesh_port_view.dart';

MeshPortStatus _status({String? selection, String tls = 'active', String error = ''}) {
  return MeshPortStatus.fromJson({
    'running': error.isEmpty,
    'port': 13306,
    'scheme': tls == 'active' ? 'https' : 'http',
    'local_service': false,
    'error': error,
    'selection': {'target': selection, 'peer_key_set': false},
    'tls': {'state': tls, 'domain': '*.g0123456789abcdef0123.lo.example', 'expires_at': 0, 'error': ''},
    'urls': [
      {
        'node_id': 'self',
        'device_name': 'My Laptop',
        'url': 'https://my-laptop.g0123456789abcdef0123.lo.example:13306',
        'self': true,
      },
      {
        'node_id': 'gpu',
        'device_name': 'GPU tower',
        'url': 'https://gpu-tower.g0123456789abcdef0123.lo.example:13306',
        'self': false,
      },
    ],
    'devices': [
      {'node_id': 'gpu', 'device_name': 'GPU tower', 'is_online': true},
      {'node_id': 'sleeper', 'device_name': 'Sleeper', 'is_online': false},
    ],
  });
}

Widget _host(Widget child) => MaterialApp(home: Scaffold(body: SingleChildScrollView(child: child)));

void main() {
  testWidgets('lists each reachable device URL and copies it', (tester) async {
    final copied = <String>[];
    await tester.pumpWidget(_host(MeshPortPanel(
      status: _status(),
      onSelect: (_) {},
      onCopy: (url) async => copied.add(url),
    )));

    expect(find.text('https://my-laptop.g0123456789abcdef0123.lo.example:13306'), findsOneWidget);
    expect(find.text('https://gpu-tower.g0123456789abcdef0123.lo.example:13306'), findsOneWidget);
    expect(find.text('This device'), findsOneWidget);
    expect(find.text('TLS active'), findsOneWidget);

    await tester.tap(find.byKey(const ValueKey('mesh-port-copy-gpu')));
    await tester.pump();
    expect(copied, ['https://gpu-tower.g0123456789abcdef0123.lo.example:13306']);
    expect(find.textContaining('Copied'), findsOneWidget);
  });

  testWidgets('selection control offers auto and each Tier 3 device', (tester) async {
    final selected = <String?>[];
    await tester.pumpWidget(_host(MeshPortPanel(
      status: _status(selection: 'gpu'),
      onSelect: selected.add,
    )));

    final dropdown = find.byKey(const ValueKey('mesh-port-selection'));
    expect(tester.widget<DropdownButton<String>>(dropdown).value, 'gpu');

    await tester.tap(dropdown);
    await tester.pumpAndSettle();
    expect(find.text('Auto').last, findsOneWidget);
    expect(find.text('Sleeper (offline)').last, findsOneWidget);
    expect(find.text('This device'), findsOneWidget, reason: 'no local service, so no local entry');
    await tester.tap(find.text('Auto').last);
    await tester.pumpAndSettle();
    expect(selected, ['auto']);

    await tester.tap(dropdown);
    await tester.pumpAndSettle();
    await tester.tap(find.text('None').last);
    await tester.pumpAndSettle();
    expect(selected, ['auto', null]);
  });

  testWidgets('shows plain HTTP while the certificate is pending', (tester) async {
    await tester.pumpWidget(_host(MeshPortPanel(status: _status(tls: 'waiting'), onSelect: (_) {})));
    expect(find.text('HTTP: waiting for certificate'), findsOneWidget);
  });

  testWidgets('shows a port conflict and offers a retry', (tester) async {
    var retried = 0;
    await tester.pumpWidget(_host(MeshPortPanel(
      status: const MeshPortStatus(error: 'Port 13306 is in use by another process, for example lemond'),
      onSelect: (_) {},
      onRetry: () => retried++,
    )));
    expect(find.textContaining('in use by another process'), findsOneWidget);
    expect(find.text('Mesh port is off'), findsOneWidget);
    final dropdown = find.byKey(const ValueKey('mesh-port-selection'));
    expect(tester.widget<DropdownButton<String>>(dropdown).onChanged, isNull);
    await tester.tap(find.text('Retry'));
    expect(retried, 1);
  });
}
