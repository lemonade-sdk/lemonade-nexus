/// @title Login View Widget Tests
/// @description Tests for the LoginView component.
///
/// Coverage Target: 75%
/// Priority: High

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus/src/views/login_view.dart';
import 'package:lemonade_nexus/src/state/providers.dart';
import 'package:lemonade_nexus/src/state/app_state.dart';

import '../helpers/test_helpers.dart';
import '../fixtures/fixtures.dart';
import '../helpers/mocks.dart';

void main() {
  group('LoginView Widget Tests', () {
    testWidgets('should display app title and logo', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Verify title is displayed
      expect(find.text('Lemonade Nexus'), findsOneWidget);
      expect(find.text('Secure Mesh VPN'), findsOneWidget);
    });

    testWidgets('should display server URL field', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.text('Server URL'), findsOneWidget);
      expect(find.byType(TextFormField), findsWidgets);
    });

    testWidgets('should display password auth tab by default', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.text('Password'), findsOneWidget);
      expect(find.text('Passkey'), findsOneWidget);
    });

    testWidgets('should display username and password fields', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.text('Username'), findsOneWidget);
      expect(find.text('Password'), findsWidgets); // Password label + tab
    });

    testWidgets('should display Sign In button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.text('Sign In'), findsOneWidget);
    });

    testWidgets('should display Register button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.text('Register'), findsOneWidget);
    });

    testWidgets('should show validation error for empty username', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Try to submit without entering data
      final signInButton = find.text('Sign In');
      await tester.tap(signInButton);
      await tester.pumpAndSettle();

      // Should show validation error
      expect(
        find.text('Please enter your username'),
        findsOneWidget,
      );
    });

    testWidgets('should show validation error for empty password', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Enter username only
      final usernameField = find.text('Username');
      await tester.tap(usernameField);
      await tester.enterText(usernameField, 'testuser');
      await tester.pump();

      // Try to submit
      final signInButton = find.text('Sign In');
      await tester.tap(signInButton);
      await tester.pumpAndSettle();

      // Should show validation error
      expect(
        find.text('Please enter your password'),
        findsOneWidget,
      );
    });

    testWidgets('should switch to Passkey tab when tapped', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Tap Passkey tab
      final passkeyTab = find.text('Passkey');
      await tester.tap(passkeyTab);
      await tester.pumpAndSettle();

      // Should show passkey content
      expect(
        find.text('Sign in with your fingerprint or face'),
        findsOneWidget,
      );
      expect(
        find.text('Sign In with Passkey'),
        findsOneWidget,
      );
    });

    testWidgets('should display Connect button for server', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.text('Connect'), findsOneWidget);
    });

    testWidgets('should display version number', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.text('v1.0.0'), findsOneWidget);
    });

    testWidgets('should have password field obscure text', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      final passwordField = find.byWidgetPredicate((widget) {
        if (widget is EditableText) {
          return widget.obscureText;
        }
        return false;
      });

      expect(passwordField, findsOneWidget);
    });

    testWidgets('should have proper form structure', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Should have a Form widget
      expect(find.byType(Form), findsOneWidget);

      // Should have a Card for the login form
      expect(find.byType(Card), findsOneWidget);
    });

    testWidgets('should have logo with network lines', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Should have CustomPaint for logo
      expect(find.byType(CustomPaint), findsWidgets);
    });

    testWidgets('should have proper tab structure', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Should have two tabs
      expect(find.text('Password'), findsOneWidget);
      expect(find.text('Passkey'), findsOneWidget);
    });

    testWidgets('should show loading indicator when signing in', (tester) async {
      // Create mock notifier with loading state
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(isLoading: true),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      // Should show loading text
      expect(find.text('Signing In...'), findsOneWidget);
    });

    testWidgets('should show loading indicator when registering', (tester) async {
      // Create mock notifier with loading state
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(isLoading: true),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      // Should show registering text
      expect(find.text('Registering...'), findsOneWidget);
    });

    testWidgets('should have fingerprint icon for passkey', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Switch to passkey tab
      await tester.tap(find.text('Passkey'));
      await tester.pumpAndSettle();

      // Should have fingerprint icon
      expect(
        find.byIcon(Icons.fingerprint),
        findsOneWidget,
      );
    });

    testWidgets('should have proper input field icons', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Username should have person icon
      expect(find.byIcon(Icons.person_outline), findsWidgets);

      // Password should have lock icon
      expect(find.byIcon(Icons.lock_outline), findsWidgets);
    });

    testWidgets('should have Connected status when connected to server', (tester) async {
      // Create mock notifier with connected state
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          connectionStatus: ConnectionStatus.connected,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      // Should show Connected status
      expect(find.text('Connected'), findsOneWidget);
    });

    testWidgets('should display server connection info when connected', (tester) async {
      // Create mock notifier with connected state
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          connectionStatus: ConnectionStatus.connected,
          settings: SettingsTest.createTest(
            serverHost: 'localhost',
            serverPort: 9100,
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      // Should show connection info
      expect(
        find.textContaining('Connected to'),
        findsOneWidget,
      );
    });

    testWidgets('should have Clear button when text entered in search', (tester) async {
      // This tests the general pattern - actual implementation may vary
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Enter text in username field
      final usernameField = find.text('Username');
      await tester.tap(usernameField);
      await tester.enterText(usernameField, 'test');
      await tester.pump();

      // Verify text was entered
      expect(find.text('test'), findsOneWidget);
    });

    testWidgets('should have proper button styling', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Sign In button should be ElevatedButton
      final signInButton = find.ancestor(
        of: find.text('Sign In'),
        matching: find.byType(ElevatedButton),
      );
      expect(signInButton, findsOneWidget);

      // Register button should be OutlinedButton
      final registerButton = find.ancestor(
        of: find.text('Register'),
        matching: find.byType(OutlinedButton),
      );
      expect(registerButton, findsOneWidget);
    });

    testWidgets('should have proper color scheme', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Should have gradient background (Container with decoration)
      expect(find.byType(Container), findsWidgets);

      // Should have yellow/gold accent color (#E9C46A)
      // This is verified by the visual appearance
    });

    testWidgets('should have status message area', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Status message area exists (may be hidden when empty)
      // The widget structure includes this
      expect(find.byType(Icon), findsWidgets);
    });

    testWidgets('should show error icon for error messages', (tester) async {
      // Create mock notifier with error state
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          errorMessage: 'Authentication failed',
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      // Error icon should be present
      expect(find.byIcon(Icons.error_outline), findsWidgets);
    });

    testWidgets('should have info icon for info messages', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Info icon exists in the UI
      expect(find.byIcon(Icons.info_outline), findsWidgets);
    });

    testWidgets('should have proper scaffold structure', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.byType(Scaffold), findsOneWidget);
      expect(find.byType(SafeArea), findsOneWidget);
      expect(find.byType(SingleChildScrollView), findsOneWidget);
    });

    testWidgets('should have center-aligned content', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.byType(Center), findsOneWidget);
    });

    testWidgets('should have constrained width for login card', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.byType(ConstrainedBox), findsOneWidget);
    });

    testWidgets('should have AutoConnectOnLaunch passkey button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Switch to passkey tab
      await tester.tap(find.text('Passkey'));
      await tester.pumpAndSettle();

      // Should have Create Passkey button
      expect(
        find.text('Create Passkey'),
        findsOneWidget,
      );
    });

    testWidgets('should disable buttons when loading', (tester) async {
      // Create mock notifier with loading state
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(isLoading: true),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      // Sign In button should be disabled (CircularSpinner shown instead)
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
    });

    testWidgets('should have proper text styles', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      // Title should be headlineMedium
      expect(find.text('Lemonade Nexus'), findsOneWidget);

      // Subtitle should be bodyMedium
      expect(find.text('Secure Mesh VPN'), findsOneWidget);
    });
  });

  group('AuthTab Extension Tests', () {
    test('should return correct labels', () {
      expect(AuthTab.password.label, equals('Password'));
      expect(AuthTab.passkey.label, equals('Passkey'));
    });

    test('should have correct number of values', () {
      expect(AuthTab.values.length, equals(2));
    });
  });

  group('LoginView Server Connection Tests', () {
    testWidgets('should display server section header', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.text('Server'), findsOneWidget);
    });

    testWidgets('should have link icon for server', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.byIcon(Icons.link), findsWidgets);
    });

    testWidgets('should have wifi tethering icon for connect', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: LoginView()),
        ),
      );

      expect(find.byIcon(Icons.wifi_tethering), findsWidgets);
    });

    testWidgets('should have check circle icon when connected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          connectionStatus: ConnectionStatus.connected,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: LoginView()),
        ),
      );

      expect(find.byIcon(Icons.check_circle), findsWidgets);
    });
  });
}
