// Smoke test for the app root widget. Constructed (not pumped) so it does not
// require the native SDK library to be loaded in the test environment.

import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';

import 'package:lemonade_nexus/main.dart';

void main() {
  test('app root widget constructs', () {
    expect(const LemonadeNexusApp(), isA<Widget>());
  });
}
