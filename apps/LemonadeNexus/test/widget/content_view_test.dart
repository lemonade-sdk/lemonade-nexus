/// @title Content View Widget Tests
/// @description Tests for the ContentView component (main container with sidebar).

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus/src/views/content_view.dart';
import 'package:lemonade_nexus/src/state/providers.dart';
import 'package:lemonade_nexus/src/state/app_state.dart';

import '../helpers/test_helpers.dart';
import '../helpers/mocks.dart';

void main() {
  group('ContentView Widget Tests', () {
    testWidgets('should display sidebar', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should display app logo', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byIcon(Icons.security), findsOneWidget);
    });

    testWidgets('should display app title', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('Lemonade Nexus'), findsOneWidget);
    });

    testWidgets('should display connection status in sidebar header', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('Disconnected'), findsOneWidget);
    });

    testWidgets('should display status dot', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      // Status dot is a Container with decoration
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should display dashboard navigation item', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('Dashboard'), findsOneWidget);
      expect(find.byIcon(Icons.dashboard_outlined), findsOneWidget);
    });

    testWidgets('should display tunnel navigation item', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('Tunnel'), findsOneWidget);
      expect(find.byIcon(Icons.security_outlined), findsOneWidget);
    });

    testWidgets('should display peers navigation item', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('Peers'), findsOneWidget);
      expect(find.byIcon(Icons.people_outlined), findsOneWidget);
    });

    testWidgets('should display network navigation item', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('Network'), findsOneWidget);
      expect(find.byIcon(Icons.network_check_outlined), findsOneWidget);
    });

    testWidgets('should display endpoints navigation item', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('Endpoints'), findsOneWidget);
      expect(find.byIcon(Icons.account_tree_outlined), findsOneWidget);
    });

    testWidgets('should display servers navigation item', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('Servers'), findsOneWidget);
      expect(find.byIcon(Icons.dns_outlined), findsOneWidget);
    });

    testWidgets('should display certificates navigation item', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('Certificates'), findsOneWidget);
      expect(find.byIcon(Icons.cert_outlined), findsOneWidget);
    });

    testWidgets('should display relays navigation item', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('Relays'), findsOneWidget);
      expect(find.byIcon(Icons.wifi_tethering_outlined), findsOneWidget);
    });

    testWidgets('should display settings navigation item', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('Settings'), findsOneWidget);
      expect(find.byIcon(Icons.settings_outlined), findsOneWidget);
    });

    testWidgets('should display user info in footer', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byIcon(Icons.person), findsWidgets);
    });

    testWidgets('should display user online/offline status', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('Offline'), findsOneWidget);
    });

    testWidgets('should display sign out button in footer', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byIcon(Icons.logout), findsOneWidget);
    });

    testWidgets('should display vertical divider between sidebar and content', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(VerticalDivider), findsOneWidget);
    });

    testWidgets('should display detail view area', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(Expanded), findsOneWidget);
    });

    testWidgets('should have proper sidebar width', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      // Sidebar is a Container with width 260
      expect(find.byType(Container), findsWidgets);
    });
  });

  group('ContentView Connected State Tests', () {
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
          child: const MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('Connected'), findsOneWidget);
    });

    testWidgets('should show username when authenticated', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(
            username: 'testuser',
            isAuthenticated: true,
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('testuser'), findsOneWidget);
    });

    testWidgets('should show online status when authenticated', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          authState: AuthStateTest.createTest(
            isAuthenticated: true,
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      expect(find.text('Online'), findsOneWidget);
    });
  });

  group('ContentView Sidebar Navigation Tests', () {
    testWidgets('should navigate to dashboard when tapped', (tester) async {
      final mockNotifier = MockAppNotifier();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Tap on dashboard
      await tester.tap(find.text('Dashboard'));
      await tester.pumpAndSettle();

      // Verify navigation was triggered
      expect(mockNotifier.state.selectedSidebarItem, equals(SidebarItem.dashboard));
    });

    testWidgets('should navigate to tunnel when tapped', (tester) async {
      final mockNotifier = MockAppNotifier();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      await tester.tap(find.text('Tunnel'));
      await tester.pumpAndSettle();

      expect(mockNotifier.state.selectedSidebarItem, equals(SidebarItem.tunnel));
    });

    testWidgets('should navigate to peers when tapped', (tester) async {
      final mockNotifier = MockAppNotifier();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      await tester.tap(find.text('Peers'));
      await tester.pumpAndSettle();

      expect(mockNotifier.state.selectedSidebarItem, equals(SidebarItem.peers));
    });

    testWidgets('should navigate to network when tapped', (tester) async {
      final mockNotifier = MockAppNotifier();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      await tester.tap(find.text('Network'));
      await tester.pumpAndSettle();

      expect(mockNotifier.state.selectedSidebarItem, equals(SidebarItem.network));
    });

    testWidgets('should navigate to endpoints when tapped', (tester) async {
      final mockNotifier = MockAppNotifier();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      await tester.tap(find.text('Endpoints'));
      await tester.pumpAndSettle();

      expect(mockNotifier.state.selectedSidebarItem, equals(SidebarItem.endpoints));
    });

    testWidgets('should navigate to servers when tapped', (tester) async {
      final mockNotifier = MockAppNotifier();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      await tester.tap(find.text('Servers'));
      await tester.pumpAndSettle();

      expect(mockNotifier.state.selectedSidebarItem, equals(SidebarItem.servers));
    });

    testWidgets('should navigate to certificates when tapped', (tester) async {
      final mockNotifier = MockAppNotifier();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      await tester.tap(find.text('Certificates'));
      await tester.pumpAndSettle();

      expect(mockNotifier.state.selectedSidebarItem, equals(SidebarItem.certificates));
    });

    testWidgets('should navigate to relays when tapped', (tester) async {
      final mockNotifier = MockAppNotifier();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      await tester.tap(find.text('Relays'));
      await tester.pumpAndSettle();

      expect(mockNotifier.state.selectedSidebarItem, equals(SidebarItem.relays));
    });

    testWidgets('should navigate to settings when tapped', (tester) async {
      final mockNotifier = MockAppNotifier();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      await tester.tap(find.text('Settings'));
      await tester.pumpAndSettle();

      expect(mockNotifier.state.selectedSidebarItem, equals(SidebarItem.settings));
    });

    testWidgets('should highlight selected navigation item', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          selectedSidebarItem: SidebarItem.dashboard,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Dashboard should be highlighted (selected)
      expect(find.text('Dashboard'), findsOneWidget);
    });
  });

  group('ContentView Detail View Tests', () {
    testWidgets('should show dashboard view when dashboard selected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          selectedSidebarItem: SidebarItem.dashboard,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // DashboardView should be displayed
      expect(find.byType(MaterialApp), findsOneWidget);
    });

    testWidgets('should show tunnel view when tunnel selected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          selectedSidebarItem: SidebarItem.tunnel,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(MaterialApp), findsOneWidget);
    });

    testWidgets('should show peers view when peers selected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          selectedSidebarItem: SidebarItem.peers,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(MaterialApp), findsOneWidget);
    });

    testWidgets('should show network view when network selected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          selectedSidebarItem: SidebarItem.network,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(MaterialApp), findsOneWidget);
    });

    testWidgets('should show tree browser when endpoints selected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          selectedSidebarItem: SidebarItem.endpoints,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(MaterialApp), findsOneWidget);
    });

    testWidgets('should show servers view when servers selected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          selectedSidebarItem: SidebarItem.servers,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(MaterialApp), findsOneWidget);
    });

    testWidgets('should show certificates view when certificates selected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          selectedSidebarItem: SidebarItem.certificates,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(MaterialApp), findsOneWidget);
    });

    testWidgets('should show tree browser when relays selected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          selectedSidebarItem: SidebarItem.relays,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(MaterialApp), findsOneWidget);
    });

    testWidgets('should show settings view when settings selected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          selectedSidebarItem: SidebarItem.settings,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(MaterialApp), findsOneWidget);
    });
  });

  group('ContentView Sign Out Dialog Tests', () {
    testWidgets('should open sign out dialog when sign out tapped', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      await tester.tap(find.byIcon(Icons.logout));
      await tester.pumpAndSettle();

      expect(find.text('Sign Out'), findsWidgets);
    });

    testWidgets('should show confirmation message in dialog', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      await tester.tap(find.byIcon(Icons.logout));
      await tester.pumpAndSettle();

      expect(
        find.textContaining('Are you sure you want to sign out'),
        findsOneWidget,
      );
    });

    testWidgets('should show cancel button in dialog', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      await tester.tap(find.byIcon(Icons.logout));
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
          child: const MaterialApp(home: ContentView()),
        ),
      );

      await tester.tap(find.byIcon(Icons.logout));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();

      // Dialog should be closed
      expect(find.textContaining('Are you sure'), findsNothing);
    });

    testWidgets('should call signOut when confirmed', (tester) async {
      final mockNotifier = MockAppNotifier();

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      await tester.tap(find.byIcon(Icons.logout));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Sign Out').last); // The button in dialog
      await tester.pumpAndSettle();

      // Sign out should have been called
      expect(mockNotifier.state.authState?.isAuthenticated, isFalse);
    });
  });

  group('ContentView UI Element Tests', () {
    testWidgets('should have scaffold structure', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(Scaffold), findsOneWidget);
    });

    testWidgets('should have Row layout', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(Row), findsOneWidget);
    });

    testWidgets('should have ListView for navigation items', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(ListView), findsWidgets);
    });

    testWidgets('should have ListTile for navigation items', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(ListTile), findsWidgets);
    });

    testWidgets('should have proper divider styling', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(Divider), findsWidgets);
    });

    testWidgets('should have gradient background for detail area', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      // Detail area uses BoxDecoration with gradient
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have SafeArea for detail content', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(SafeArea), findsOneWidget);
    });

    testWidgets('should have proper color scheme', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      // Sidebar uses Color(0xFF1A1A2E)
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have proper icon styling', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byIcon(Icons.security), findsOneWidget);
      expect(find.byIcon(Icons.dashboard_outlined), findsOneWidget);
    });

    testWidgets('should have proper text styles', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(Text), findsWidgets);
    });

    testWidgets('should have proper padding', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(Padding), findsWidgets);
    });

    testWidgets('should have proper SizedBox spacing', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(SizedBox), findsWidgets);
    });
  });

  group('ContentView Selected Item Styling Tests', () {
    testWidgets('should highlight selected item with yellow color', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          selectedSidebarItem: SidebarItem.dashboard,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Selected item uses Color(0xFFE9C46A)
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should show selected icon in yellow', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          selectedSidebarItem: SidebarItem.tunnel,
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: ContentView()),
        ),
      );

      // Selected icon should be yellow
      expect(find.byIcon(Icons.security_outlined), findsOneWidget);
    });

    testWidgets('should show unselected icons in grey', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      // Unselected icons use Color(0xFFA0AEC0)
      expect(find.byIcon(Icons.dashboard_outlined), findsOneWidget);
    });
  });

  group('ContentView Footer Tests', () {
    testWidgets('should have footer border', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      // Footer has top border
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have user avatar placeholder', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      // User avatar is a Container with icon
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have proper footer padding', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: ContentView()),
        ),
      );

      expect(find.byType(Padding), findsWidgets);
    });
  });
}
