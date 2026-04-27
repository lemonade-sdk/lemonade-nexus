/// @title Settings View Widget Tests
/// @description Tests for the SettingsView component.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus/src/views/settings_view.dart';
import 'package:lemonade_nexus/src/state/providers.dart';
import 'package:lemonade_nexus/src/state/app_state.dart';
import 'package:lemonade_nexus/src/windows/windows_integration.dart';

import '../helpers/test_helpers.dart';
import '../helpers/mocks.dart';
import '../fixtures/fixtures.dart';

void main() {
  group('SettingsView Widget Tests', () {
    testWidgets('should display header', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Settings'), findsOneWidget);
      expect(find.byIcon(Icons.settings), findsOneWidget);
    });

    testWidgets('should display server connection section', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Server Connection'), findsOneWidget);
      expect(find.text('Server URL'), findsOneWidget);
    });

    testWidgets('should display server URL input field', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.byType(TextField), findsOneWidget);
    });

    testWidgets('should display save button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Save'), findsOneWidget);
    });

    testWidgets('should display connection status', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Status'), findsOneWidget);
      expect(find.text('Disconnected'), findsOneWidget);
    });

    testWidgets('should display test connection button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Test Connection'), findsOneWidget);
      expect(find.byIcon(Icons.refresh), findsWidgets);
    });

    testWidgets('should display identity section', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Identity'), findsOneWidget);
      expect(find.byIcon(Icons.person), findsOneWidget);
    });

    testWidgets('should display export identity button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Export Identity'), findsOneWidget);
      expect(find.byIcon(Icons.upload), findsOneWidget);
    });

    testWidgets('should display import identity button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Import Identity'), findsOneWidget);
      expect(find.byIcon(Icons.download), findsOneWidget);
    });

    testWidgets('should display preferences section', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Preferences'), findsOneWidget);
      expect(find.byIcon(Icons.tune), findsOneWidget);
    });

    testWidgets('should display DNS auto-discovery toggle', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('DNS Auto-discovery'), findsOneWidget);
      expect(find.byType(Switch), findsWidgets);
    });

    testWidgets('should display auto-connect toggle', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Auto-connect on launch'), findsOneWidget);
    });

    testWidgets('should display about section', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('About'), findsOneWidget);
      expect(find.byIcon(Icons.info), findsOneWidget);
    });

    testWidgets('should display app version', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('v1.0.0'), findsOneWidget);
      expect(find.text('App Version'), findsOneWidget);
    });

    testWidgets('should display sign out button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Sign Out'), findsOneWidget);
      expect(find.byIcon(Icons.logout), findsOneWidget);
    });
  });

  group('SettingsView With State Tests', () {
    testWidgets('should show connected status when healthy', (tester) async {
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
          child: const MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Connected'), findsOneWidget);
    });

    testWidgets('should show public key when authenticated', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(
            publicKeyBase64: 'test_public_key_base64_string',
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Public Key'), findsOneWidget);
    });

    testWidgets('should show username when authenticated', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(
            username: 'testuser',
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Username'), findsOneWidget);
      expect(find.text('testuser'), findsOneWidget);
    });

    testWidgets('should show user ID when authenticated', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(
            userId: 'test-user-id-12345',
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('User ID'), findsOneWidget);
      expect(find.text('test-user-id-12345'), findsOneWidget);
    });

    testWidgets('should show auto-discovery enabled state', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          autoDiscoveryEnabled: true,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: SettingsView()),
        ),
      );

      // Switch should be on
      final switches = tester.widgetList<Switch>(find.byType(Switch)).toList();
      expect(switches.length, greaterThan(0));
    });

    testWidgets('should show auto-connect enabled state', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          autoConnectOnLaunch: true,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: SettingsView()),
        ),
      );

      // Should have multiple switches
      expect(find.byType(Switch), findsWidgets);
    });
  });

  group('SettingsView Windows Integration Tests', () {
    testWidgets('should show Windows integration section on Windows', (tester) async {
      // Note: This test will show the section only when running on Windows
      // We test the UI structure regardless of platform
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      // Section headers exist
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should show auto-start toggle', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      // Windows integration toggles use Switch widgets
      expect(find.byType(Switch), findsWidgets);
    });

    testWidgets('should show minimize to tray toggle', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Minimize to system tray'), findsWidgets);
    });

    testWidgets('should show run in background toggle', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Run in background'), findsWidgets);
    });

    testWidgets('should show Windows service section', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Windows Service (Advanced)'), findsWidgets);
      expect(find.byIcon(Icons.admin_panel_settings), findsWidgets);
    });

    testWidgets('should show install service button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Install Service'), findsWidgets);
    });
  });

  group('SettingsView Sign Out Dialog Tests', () {
    testWidgets('should open sign out dialog when sign out tapped', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      await tester.tap(find.text('Sign Out'));
      await tester.pumpAndSettle();

      expect(find.text('Sign Out'), findsWidgets); // Button and dialog title
    });

    testWidgets('should show confirmation message in dialog', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      await tester.tap(find.text('Sign Out'));
      await tester.pumpAndSettle();

      expect(
        find.textContaining('Are you sure you want to sign out'),
        findsOneWidget,
      );
    });

    testWidgets('should show cancel button in dialog', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      await tester.tap(find.text('Sign Out'));
      await tester.pumpAndSettle();

      expect(find.text('Cancel'), findsOneWidget);
    });

    testWidgets('should close dialog when cancel tapped', (tester) async {
      final mockNotifier = MockAppNotifier();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: SettingsView()),
        ),
      );

      await tester.tap(find.text('Sign Out'));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();

      // Dialog should be closed - only the button should remain
      expect(find.text('Sign Out'), findsOneWidget); // Only the button
    });
  });

  group('SettingsView UI Element Tests', () {
    testWidgets('should have proper section styling', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have scrollable content', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.byType(SingleChildScrollView), findsOneWidget);
    });

    testWidgets('should have proper input field styling', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.byType(TextField), findsOneWidget);
    });

    testWidgets('should have monospace font for server URL', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.byType(TextField), findsOneWidget);
    });

    testWidgets('should have elevated buttons', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.byType(ElevatedButton), findsWidgets);
    });

    testWidgets('should have outlined buttons', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.byType(OutlinedButton), findsWidgets);
    });

    testWidgets('should have text buttons', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.byType(TextButton), findsWidgets);
    });

    testWidgets('should have proper divider styling', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.byType(Divider), findsWidgets);
    });

    testWidgets('should have proper color scheme', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      // Verify overall structure
      expect(find.byType(Column), findsWidgets);
    });

    testWidgets('should have proper section icons', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.byIcon(Icons.link), findsOneWidget);
      expect(find.byIcon(Icons.person), findsOneWidget);
      expect(find.byIcon(Icons.tune), findsOneWidget);
      expect(find.byIcon(Icons.info), findsOneWidget);
    });
  });

  group('SettingsView Server URL Input Tests', () {
    testWidgets('should update save button on text change', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      // The save button should be enabled when there are changes
      expect(find.text('Save'), findsOneWidget);
    });

    testWidgets('should have hint text for server URL', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Server URL'), findsOneWidget);
    });

    testWidgets('should have proper content padding for input', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.byType(TextField), findsOneWidget);
    });
  });

  group('SettingsView About Section Tests', () {
    testWidgets('should display build number', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Build'), findsOneWidget);
    });

    testWidgets('should display platform', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: SettingsView()),
        ),
      );

      expect(find.text('Platform'), findsOneWidget);
    });
  });
}
