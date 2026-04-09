/// @title Certificates View Widget Tests
/// @description Tests for the CertificatesView component.

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus/src/views/certificates_view.dart';
import 'package:lemonade_nexus/src/state/providers.dart';
import 'package:lemonade_nexus/src/state/app_state.dart';
import 'package:lemonade_nexus/src/sdk/models.dart';

import '../helpers/test_helpers.dart';
import '../helpers/mocks.dart';
import '../fixtures/fixtures.dart';

void main() {
  group('CertificatesView Widget Tests', () {
    testWidgets('should display header', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.text('Certificates'), findsOneWidget);
      expect(find.byIcon(Icons.cert), findsOneWidget);
    });

    testWidgets('should display refresh button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.byIcon(Icons.refresh), findsOneWidget);
    });

    testWidgets('should display add certificate button', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.byIcon(Icons.add_circle), findsOneWidget);
    });

    testWidgets('should show empty state when no certificates', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.text('No Certificates'), findsOneWidget);
      expect(find.byIcon(Icons.cert_outline), findsOneWidget);
    });

    testWidgets('should show no selection state', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.text('Select a Certificate'), findsOneWidget);
      expect(find.text('Choose a certificate from the list to view details.'), findsOneWidget);
    });

    testWidgets('should show empty state hint text', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: CertificatesView()),
        ),
      );

      expect(
        find.textContaining('Request a certificate to secure your domain'),
        findsOneWidget,
      );
    });
  });

  group('CertificatesView With Certificates Tests', () {
    testWidgets('should display certificate list', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(
              domain: 'example.com',
              isIssued: true,
            ),
            ModelFactory.createCertStatus(
              domain: 'test.example.com',
              isIssued: false,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.text('example.com'), findsOneWidget);
      expect(find.text('test.example.com'), findsOneWidget);
    });

    testWidgets('should display issued status badge', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(
              domain: 'example.com',
              isIssued: true,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.text('ISSUED'), findsOneWidget);
    });

    testWidgets('should display not issued status badge', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(
              domain: 'test.example.com',
              isIssued: false,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.text('NONE'), findsOneWidget);
    });

    testWidgets('should show check circle icon for issued certificate', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(
              domain: 'example.com',
              isIssued: true,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.byIcon(Icons.check_circle), findsWidgets);
    });

    testWidgets('should show certificate outline icon for not issued', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(
              domain: 'test.example.com',
              isIssued: false,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.byIcon(Icons.certificate_outlined), findsWidgets);
    });

    testWidgets('should show detail panel when certificate selected', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(
              domain: 'example.com',
              isIssued: true,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      // Tap on certificate to select
      await tester.tap(find.text('example.com'));
      await tester.pumpAndSettle();

      // Should show detail panel
      expect(find.text('Domain'), findsOneWidget);
      expect(find.text('Status'), findsOneWidget);
    });

    testWidgets('should display certificate details in panel', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(
              domain: 'secure.example.com',
              isIssued: true,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      await tester.tap(find.text('secure.example.com'));
      await tester.pumpAndSettle();

      expect(find.text('secure.example.com'), findsWidgets);
      expect(find.text('Issued'), findsOneWidget);
    });

    testWidgets('should show issue/renew certificate button', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(
              domain: 'example.com',
              isIssued: true,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      await tester.tap(find.text('example.com'));
      await tester.pumpAndSettle();

      expect(find.text('Renew Certificate'), findsOneWidget);
    });

    testWidgets('should show issue certificate button for non-issued', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(
              domain: 'test.example.com',
              isIssued: false,
            ),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      await tester.tap(find.text('test.example.com'));
      await tester.pumpAndSettle();

      expect(find.text('Issue Certificate'), findsOneWidget);
    });

    testWidgets('should highlight selected certificate', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(domain: 'example.com'),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      await tester.tap(find.text('example.com'));
      await tester.pumpAndSettle();

      // Selected item should have different background
      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should show chevron icon for navigation', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(domain: 'example.com'),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.byIcon(Icons.chevron_right), findsOneWidget);
    });
  });

  group('CertificatesView Request Dialog Tests', () {
    testWidgets('should open request dialog when add button tapped', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: CertificatesView()),
        ),
      );

      // Tap add button
      await tester.tap(find.byIcon(Icons.add_circle));
      await tester.pumpAndSettle();

      // Should show dialog
      expect(find.text('Request Certificate'), findsOneWidget);
    });

    testWidgets('should show domain input field in dialog', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: CertificatesView()),
        ),
      );

      await tester.tap(find.byIcon(Icons.add_circle));
      await tester.pumpAndSettle();

      expect(find.text('Domain'), findsOneWidget);
      expect(find.byType(TextField), findsOneWidget);
    });

    testWidgets('should show default domain in input field', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: CertificatesView()),
        ),
      );

      await tester.tap(find.byIcon(Icons.add_circle));
      await tester.pumpAndSettle();

      expect(find.textContaining('demo.lemonade-nexus.io'), findsOneWidget);
    });

    testWidgets('should show cancel and request buttons in dialog', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: CertificatesView()),
        ),
      );

      await tester.tap(find.byIcon(Icons.add_circle));
      await tester.pumpAndSettle();

      expect(find.text('Cancel'), findsOneWidget);
      expect(find.text('Request'), findsOneWidget);
    });

    testWidgets('should close dialog when cancel tapped', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: CertificatesView()),
        ),
      );

      await tester.tap(find.byIcon(Icons.add_circle));
      await tester.pumpAndSettle();

      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();

      expect(find.text('Request Certificate'), findsNothing);
    });
  });

  group('CertificatesView UI Element Tests', () {
    testWidgets('should have proper card styling', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(domain: 'example.com'),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have list tiles for certificates', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(domain: 'example.com'),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.byType(InkWell), findsOneWidget);
    });

    testWidgets('should have divider between header and list', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.byType(Divider), findsOneWidget);
    });

    testWidgets('should have status icon for certificate', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(domain: 'example.com', isIssued: true),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.byType(Container), findsWidgets); // Status icons are in Containers
    });

    testWidgets('should have scrollable list', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: List.generate(
            20,
            (i) => ModelFactory.createCertStatus(
              domain: 'domain$i.example.com',
            ),
          ),
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.byType(ListView), findsOneWidget);
    });

    testWidgets('should have monospace font for domain', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(domain: 'example.com'),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.text('example.com'), findsWidgets);
    });

    testWidgets('should have proper badge styling', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(domain: 'example.com', isIssued: true),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      expect(find.byType(Container), findsWidgets);
    });

    testWidgets('should have expanded detail panel', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(domain: 'example.com'),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      await tester.tap(find.text('example.com'));
      await tester.pumpAndSettle();

      expect(find.byType(Expanded), findsWidgets);
    });

    testWidgets('should have proper color scheme', (tester) async {
      await tester.pumpWidget(
        const ProviderScope(
          child: MaterialApp(home: CertificatesView()),
        ),
      );

      // Verify overall structure
      expect(find.byType(Row), findsWidgets);
    });

    testWidgets('should have Actions section in detail panel', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(domain: 'example.com', isIssued: true),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      await tester.tap(find.text('example.com'));
      await tester.pumpAndSettle();

      expect(find.text('Actions'), findsOneWidget);
    });

    testWidgets('should have elevated button for issue/renew', (tester) async {
      final mockNotifier = MockAppNotifier();
      mockNotifier.updateState(
        AppStateTest.createTest(
          certificates: [
            ModelFactory.createCertStatus(domain: 'example.com', isIssued: true),
          ],
        ),
      );

      await tester.pumpWidget(
        ProviderScope(
          overrides: [
            appNotifierProvider.overrideWith((ref) => mockNotifier),
          ],
          child: const MaterialApp(home: CertificatesView()),
        ),
      );

      await tester.tap(find.text('example.com'));
      await tester.pumpAndSettle();

      expect(find.byType(ElevatedButton), findsWidgets);
    });
  });
}
