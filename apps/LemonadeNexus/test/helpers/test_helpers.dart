/// @title Test Helpers
/// @description Common test utilities for Lemonade Nexus tests.
///
/// Provides:
/// - Test configuration
/// - Async test helpers
/// - Assertion utilities
/// - Test data generators

import 'package:flutter_test/flutter_test.dart';
import 'package:riverpod/riverpod.dart';
import 'package:mockito/mockito.dart';

// Import mocks
import 'mocks.dart';

/// Extension methods for [WidgetTester] to simplify common test operations.
extension WidgetTesterExtension on WidgetTester {
  /// Pump widget with default test configuration.
  Future<void> pumpTestApp(Widget widget) async {
    await pumpWidget(widget);
    await pumpAndSettle();
  }

  /// Enter text into a field by label.
  Future<void> enterTextByLabel(String label, String text) async {
    final finder = find.byWidgetPredicate((widget) {
      if (widget is EditableText) {
        return false;
      }
      return false;
    });

    // Find by label text
    final labelFinder = find.text(label);
    expect(labelFinder, findsOneWidget,
        reason: 'Label "$label" not found');

    // Navigate to next widget (the TextField)
    await tap(labelFinder);
    await enterText(text);
  }

  /// Tap a button by its text content.
  Future<void> tapButtonByText(String text) async {
    final finder = find.text(text);
    expect(finder, findsOneWidget, reason: 'Button "$text" not found');
    await tap(finder);
    await pumpAndSettle();
  }

  /// Wait for a condition to be true.
  Future<bool> waitFor(
    bool Function() condition, {
    Duration timeout = const Duration(seconds: 5),
    Duration pollInterval = const Duration(milliseconds: 100),
  }) async {
    final stopwatch = Stopwatch()..start();
    while (!condition()) {
      if (stopwatch.elapsed > timeout) {
        return false;
      }
      await Future.delayed(pollInterval);
    }
    return true;
  }
}

/// Creates a [ProviderContainer] for testing Riverpod providers.
ProviderContainer createTestContainer({
  List<Override> overrides = const [],
  List<ProviderObserver>? observers,
}) {
  final container = ProviderContainer(
    overrides: overrides,
    observers: observers,
  );
  addTearDown(container.dispose);
  return container;
}

/// Asserts that a function throws a [SdkException].
void expectSdkException<T>(Future<T> Function() fn) {
  expectLater(
    fn,
    throwsA(isA<SdkException>()),
  );
}

/// Asserts that a function throws a [JsonParseException].
void expectJsonParseException<T>(Future<T> Function() fn) {
  expectLater(
    fn,
    throwsA(isA<JsonParseException>()),
  );
}

/// Creates a mock exception for testing.
SdkException createMockSdkException({
  LnError error = LnError.internal,
  String? message,
}) {
  return SdkException(error, message: message);
}

/// Utility class for generating test data.
class TestDataGenerator {
  /// Generate a random string for testing.
  static String randomString({int length = 10}) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    return String.fromCharCodes(
      Iterable.generate(
        length,
        (_) => chars.codeUnitAt(Random().nextInt(chars.length)),
      ),
    );
  }

  /// Generate a random ID.
  static String randomId() => 'test_${randomString(length: 8)}';

  /// Generate a random hostname.
  static String randomHostname() => '${randomString(length: 6)}.local';

  /// Generate a random IP address.
  static String randomIp() =>
      '10.${Random().nextInt(256)}.${Random().nextInt(256)}.${Random().nextInt(256)}';

  /// Generate a random public key (base64-like).
  static String randomPublicKey() {
    return base64Encode(Random().nextInt(32).toString().codeUnits);
  }

  /// Generate a random session token.
  static String randomSessionToken() {
    return 'sess_${randomString(length: 32)}';
  }

  /// Generate a random timestamp.
  static String randomTimestamp() {
    return DateTime.now().toIso8601String();
  }
}

import 'dart:convert';
import 'dart:math';

import 'package:lemonade_nexus/src/sdk/ffi_bindings.dart';
import 'package:lemonade_nexus/src/sdk/models.dart';
import 'package:lemonade_nexus/src/sdk/lemonade_nexus_sdk.dart';

/// Extension for creating test instances of models.
extension AuthStateTest on AuthState {
  static AuthState createTest({
    bool isAuthenticated = true,
    String? username,
    String? userId,
    String? sessionToken,
    String? publicKeyBase64,
  }) {
    return AuthState(
      isAuthenticated: isAuthenticated,
      username: username ?? 'testuser',
      userId: userId ?? TestDataGenerator.randomId(),
      sessionToken: sessionToken ?? TestDataGenerator.randomSessionToken(),
      publicKeyBase64: publicKeyBase64 ?? TestDataGenerator.randomPublicKey(),
      authenticatedAt: DateTime.now(),
    );
  }

  static const unauthenticated = AuthState();
}

/// Extension for creating test instances of settings.
extension SettingsTest on Settings {
  static Settings createTest({
    String serverHost = 'localhost',
    int serverPort = 9100,
    bool autoDiscoveryEnabled = true,
    bool autoConnectOnLaunch = false,
    bool useTls = false,
    bool darkModeEnabled = true,
  }) {
    return Settings(
      serverHost: serverHost,
      serverPort: serverPort,
      autoDiscoveryEnabled: autoDiscoveryEnabled,
      autoConnectOnLaunch: autoConnectOnLaunch,
      useTls: useTls,
      darkModeEnabled: darkModeEnabled,
    );
  }
}

/// Extension for creating test instances of AppState.
extension AppStateTest on AppState {
  static AppState createTest({
    ConnectionStatus connectionStatus = ConnectionStatus.disconnected,
    AuthState? authState,
    PeerState? peerState,
    Settings? settings,
    TunnelStatus? tunnelStatus,
    bool isLoading = false,
  }) {
    return AppState(
      connectionStatus: connectionStatus,
      authState: authState ?? AuthStateTest.createTest(),
      peerState: peerState ?? PeerState.initial,
      settings: settings ?? SettingsTest.createTest(),
      tunnelStatus: tunnelStatus,
      isLoading: isLoading,
    );
  }
}

/// Matcher for verifying FFI pointer cleanup.
class IsNonNullPointer extends Matcher {
  @override
  Description describe(Description description) {
    return description.add('a non-null pointer');
  }

  @override
  bool matches(dynamic item, Map matchState) {
    return item != null && item.toString() != 'nullptr';
  }
}

/// Waits for all microtasks to complete.
Future<void> pumpMicrotasks() async {
  await Future.delayed(Duration.zero);
  await Future.delayed(Duration.zero);
}
