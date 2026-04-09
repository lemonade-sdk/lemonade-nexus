# Template: Integration Test

## Description
Standard template for creating Flutter integration tests.

## Usage
Use this template for end-to-end flow testing.

## Template Structure

```dart
// test/integration/{flow_name}_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:lemonade_nexus/main.dart' as app;

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('{FlowName} Integration Test', () {
    testWidgets('{testDescription}', (WidgetTester tester) async {
      // Launch app
      app.main();
      await tester.pumpAndSettle();

      // Execute flow
      // ...

      // Verify result
      // ...
    });
  });
}
```

## Complete Example

```dart
// test/integration/auth_flow_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:lemonade_nexus/main.dart' as app;

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Authentication Flow', () {
    testWidgets('completes login and shows dashboard', (WidgetTester tester) async {
      // Start the app
      app.main();
      await tester.pumpAndSettle();

      // Verify we're on login screen
      expect(find.byType(LoginView), findsOneWidget);
      expect(find.text('Login'), findsOneWidget);

      // Enter credentials
      await tester.enterText(
        find.byKey(const Key('username_field')),
        'testuser',
      );
      await tester.enterText(
        find.byKey(const Key('password_field')),
        'TestPassword123!',
      );

      // Submit login
      await tester.tap(find.byKey(const Key('login_button')));
      await tester.pumpAndSettle();

      // Wait for authentication
      await tester.pump(const Duration(seconds: 2));
      await tester.pumpAndSettle();

      // Verify we're now on dashboard
      expect(find.byType(DashboardView), findsOneWidget);
      expect(find.text('Dashboard'), findsOneWidget);
    });

    testWidgets('shows error on invalid credentials', (WidgetTester tester) async {
      // Start the app
      app.main();
      await tester.pumpAndSettle();

      // Enter invalid credentials
      await tester.enterText(
        find.byKey(const Key('username_field')),
        'invaliduser',
      );
      await tester.enterText(
        find.byKey(const Key('password_field')),
        'wrongpassword',
      );

      // Submit login
      await tester.tap(find.byKey(const Key('login_button')));
      await tester.pumpAndSettle();

      // Wait for error
      await tester.pump(const Duration(seconds: 2));
      await tester.pumpAndSettle();

      // Verify error message
      expect(find.text('Invalid credentials'), findsOneWidget);
      expect(find.byType(LoginView), findsOneWidget); // Still on login
    });

    testWidgets('can logout and return to login', (WidgetTester tester) async {
      // Start the app and login (using mock)
      app.main();
      await tester.pumpAndSettle();

      // ... login steps ...

      // Navigate to settings
      await tester.tap(find.byIcon(Icons.settings));
      await tester.pumpAndSettle();

      // Tap logout
      await tester.tap(find.byKey(const Key('logout_button')));
      await tester.pumpAndSettle();

      // Verify returned to login
      expect(find.byType(LoginView), findsOneWidget);
    });
  });
}
```

## Tunnel Lifecycle Test

```dart
// test/integration/tunnel_lifecycle_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:lemonade_nexus/main.dart' as app;

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Tunnel Lifecycle', () {
    setUp(() async {
      // Login first
      app.main();
      final tester = WidgetTester(null); // Would need proper setup
      // ... login flow
    });

    testWidgets('connects and disconnects tunnel', (WidgetTester tester) async {
      // Navigate to tunnel control
      await tester.tap(find.byKey(const Key('tunnel_nav')));
      await tester.pumpAndSettle();

      // Verify disconnected state
      expect(find.text('Disconnected'), findsOneWidget);
      expect(find.text('Connect'), findsOneWidget);

      // Connect tunnel
      await tester.tap(find.byKey(const Key('connect_button')));
      await tester.pumpAndSettle();

      // Wait for connection
      await tester.pump(const Duration(seconds: 5));
      await tester.pumpAndSettle();

      // Verify connected state
      expect(find.text('Connected'), findsOneWidget);
      expect(find.text('Disconnect'), findsOneWidget);

      // Check tunnel IP displayed
      expect(find.byType(IpAddressText), findsOneWidget);

      // Disconnect tunnel
      await tester.tap(find.byKey(const Key('disconnect_button')));
      await tester.pumpAndSettle();

      // Verify disconnected
      expect(find.text('Disconnected'), findsOneWidget);
    });

    testWidgets('shows peer list after connection', (WidgetTester tester) async {
      // ... connect tunnel ...

      // Navigate to peers
      await tester.tap(find.byKey(const Key('peers_nav')));
      await tester.pumpAndSettle();

      // Wait for peer refresh
      await tester.pump(const Duration(seconds: 3));
      await tester.pumpAndSettle();

      // Verify peer list populated
      expect(find.byType(PeerListTile), findsWidgets);
    });
  });
}
```

## Running Integration Tests

```bash
# Run all integration tests
flutter test integration_test/

# Run specific test
flutter test integration_test/auth_flow_test.dart

# With coverage
flutter test --coverage integration_test/

# On Windows device
flutter test -d windows integration_test/
```

## Related Templates
- Unit Test Template
- Widget Test Template
- Mock Class Template

## Notes
- Integration tests run full app
- Slower than unit/widget tests
- Test complete user flows
- Require test backend/mock
- Use IntegrationTestWidgetsFlutterBinding
