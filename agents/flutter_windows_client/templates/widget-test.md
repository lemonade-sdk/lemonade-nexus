# Template: Widget Test

## Description
Standard template for creating Flutter widget tests.

## Usage
Use this template when testing any UI component.

## Template Structure

```dart
// test/widget/{widget_name}_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:lemonade_nexus/src/views/{view_name}_view.dart';
import 'package:lemonade_nexus/src/state/{state_provider}.dart';

void main() {
  group('{ViewName}View', () {
    late Mock{StateClass} mockState;

    setUp(() {
      mockState = Mock{StateClass}();
    });

    testWidgets('renders correctly', (WidgetTester tester) async {
      await tester.pumpWidget(
        MaterialApp(
          home: ChangeNotifierProvider<{StateClass}>.value(
            value: mockState,
            child: const {ViewName}View(),
          ),
        ),
      );

      expect(find.byType({ViewName}View), findsOneWidget);
    });

    testWidgets('displays expected content', (WidgetTester tester) async {
      // Test content
    });

    testWidgets('responds to user interaction', (WidgetTester tester) async {
      // Test interactions
    });
  });
}
```

## Complete Example

```dart
// test/widget/login_view_test.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:mockito/mockito.dart';
import 'package:mockito/annotations.dart';
import 'package:lemonade_nexus/src/views/login_view.dart';
import 'package:lemonade_nexus/src/state/auth_provider.dart';

@GenerateMocks([AuthState])
import 'login_view_test.mocks.dart';

void main() {
  group('LoginView', () {
    late MockAuthState mockAuthState;
    late MockAuthNotifier mockAuthNotifier;

    setUp(() {
      mockAuthState = MockAuthState();
      mockAuthNotifier = MockAuthNotifier();
    });

    testWidgets('displays login form', (WidgetTester tester) async {
      when(mockAuthState.status).thenReturn(AuthStatus.unauthenticated);
      when(mockAuthState.error).thenReturn(null);

      await tester.pumpWidget(
        MaterialApp(
          home: ChangeNotifierProvider<AuthState>.value(
            value: mockAuthState,
            child: ChangeNotifierProvider<AuthNotifier>.value(
              value: mockAuthNotifier,
              child: const LoginView(),
            ),
          ),
        ),
      );

      // Verify form elements
      expect(find.byType(TextFormField), findsNWidgets(2)); // username, password
      expect(find.text('Login'), findsOneWidget);
      expect(find.text('Password'), findsOneWidget);
    });

    testWidgets('shows error message when auth fails', (WidgetTester tester) async {
      when(mockAuthState.status).thenReturn(AuthStatus.error);
      when(mockAuthState.error).thenReturn('Invalid credentials');

      await tester.pumpWidget(
        MaterialApp(
          home: ChangeNotifierProvider<AuthState>.value(
            value: mockAuthState,
            child: const LoginView(),
          ),
        ),
      );

      expect(find.text('Invalid credentials'), findsOneWidget);
    });

    testWidgets('calls login on form submission', (WidgetTester tester) async {
      when(mockAuthState.status).thenReturn(AuthStatus.unauthenticated);
      when(mockAuthNotifier.login(any, any)).thenAnswer((_) async {});

      await tester.pumpWidget(
        MaterialApp(
          home: ChangeNotifierProvider<AuthState>.value(
            value: mockAuthState,
            child: ChangeNotifierProvider<AuthNotifier>.value(
              value: mockAuthNotifier,
              child: const LoginView(),
            ),
          ),
        ),
      );

      // Enter credentials
      await tester.enterText(
        find.byType(TextFormField).first,
        'testuser',
      );
      await tester.enterText(
        find.byType(TextFormField).last,
        'password123',
      );

      // Submit form
      await tester.tap(find.text('Login'));
      await tester.pump();

      // Verify login called
      verify(mockAuthNotifier.login('testuser', 'password123')).called(1);
    });

    testWidgets('shows loading indicator during authentication', (WidgetTester tester) async {
      when(mockAuthState.status).thenReturn(AuthStatus.authenticating);

      await tester.pumpWidget(
        MaterialApp(
          home: ChangeNotifierProvider<AuthState>.value(
            value: mockAuthState,
            child: const LoginView(),
          ),
        ),
      );

      expect(find.byType(CircularProgressIndicator), findsOneWidget);
    });
  });
}
```

## Mock Generation

```dart
// test/widget/login_view_test.mocks.dart (generated)
// Run: flutter pub run build_runner build --delete-conflicting-outputs
```

## Pump Extensions

```dart
// test/helpers/pump_helpers.dart
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';

extension PumpHelpers on WidgetTester {
  Future<void> pumpApp(Widget widget) async {
    await pumpWidget(
      MaterialApp(
        home: widget,
      ),
    );
  }

  Future<void> pumpAndSettle(Duration timeout = const Duration(seconds: 5)) async {
    await pump();
    await pumpAndSettle();
  }
}
```

## Related Templates
- Unit Test Template
- Integration Test Template
- Mock Class Template

## Notes
- Use mockito for mocking
- Generate mocks with build_runner
- Test all user interactions
- Verify state changes
- Test error states
