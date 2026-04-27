# Lemonade Nexus Test Suite

## Test Suite Overview

**Coverage Target:** 80%+ across all modules
**Created:** 2026-04-08
**Version:** 1.0.0

## Test Files

### Test Infrastructure

| File | Description |
|------|-------------|
| `test/helpers/test_helpers.dart` | Common test utilities, WidgetTester extensions, ProviderContainer helper |
| `test/helpers/mocks.dart` | Manual mock implementations (MockSdk, MockAppNotifier, FakeSdk) |
| `test/helpers/mocks.mocks.dart` | Auto-generated Mockito mocks |
| `test/fixtures/fixtures.dart` | JSON fixtures and ModelFactory for test data generation |

### FFI Binding Tests (Critical - 95% Target)

| File | Description | Tests |
|------|-------------|-------|
| `test/ffi/ffi_bindings_test.dart` | LnError enum tests, FFI class tests | ~50 |
| `test/ffi/ffi_verification_test.dart` | Complete FFI binding verification | ~100 |

**Coverage Areas:**
- All LnError codes and methods
- SDK lifecycle (create, connect, dispose)
- Authentication methods
- Tunnel operations
- Mesh operations
- Tree operations
- Memory management
- Type conversion
- JSON parsing

### Unit Tests (High - 90% Target)

| File | Description | Tests |
|------|-------------|-------|
| `test/unit/models_test.dart` | JSON serialization for 25+ model classes | ~100 |
| `test/unit/sdk_test.dart` | SDK wrapper tests, lifecycle, exceptions | ~80 |
| `test/unit/state_management_test.dart` | State classes, providers, services | ~120 |

**Coverage Areas:**
- All model classes (AuthResponse, TreeNode, TunnelStatus, MeshPeer, etc.)
- LemonadeNexusSdk class
- AppState, AuthState, PeerState, Settings
- AppNotifier and Riverpod providers
- Service classes (AuthService, TunnelService, etc.)

### Widget Tests (Medium - 75% Target)

| File | Description | Tests |
|------|-------------|-------|
| `test/widget/login_view_test.dart` | Login UI, validation, tabs | ~50 |
| `test/widget/dashboard_view_test.dart` | Dashboard cards, stats, activity | ~60 |
| `test/widget/tunnel_control_view_test.dart` | Tunnel/mesh controls | ~30 |
| `test/widget/peers_view_test.dart` | Peer list, search, detail panel | ~25 |
| `test/widget/servers_view_test.dart` | Server list, health status | ~25 |
| `test/widget/certificates_view_test.dart` | Certificate management | ~25 |
| `test/widget/settings_view_test.dart` | Settings sections, toggles | ~40 |
| `test/widget/network_monitor_view_test.dart` | Network stats, bandwidth | ~35 |
| `test/widget/tree_browser_view_test.dart` | Tree navigation, CRUD | ~40 |
| `test/widget/vpn_menu_view_test.dart` | System tray menu | ~35 |
| `test/widget/node_detail_view_test.dart` | Node properties, keys | ~35 |
| `test/widget/content_view_test.dart` | Main container, sidebar | ~40 |
| `test/widget/main_navigation_test.dart` | Navigation flow, auth transition | ~30 |

**Total Widget Tests:** ~500+

### Integration Tests (High - 85% Target)

| File | Description | Tests |
|------|-------------|-------|
| `test/integration/integration_flows_test.dart` | End-to-end user flows | ~30 |

**Coverage Areas:**
- Authentication flow (login, validation, transition)
- Tunnel connection flow (connect, disconnect, status)
- Mesh network flow (enable, disable, peers)
- Server selection flow (list, select, health)
- Settings persistence (update, toggle, sign out)
- Dashboard display flow
- Navigation flow
- Error handling

## Running Tests

### Run All Tests
```bash
cd apps/LemonadeNexus
flutter test
```

### Run Specific Category
```bash
# FFI tests
flutter test test/ffi/

# Unit tests
flutter test test/unit/

# Widget tests
flutter test test/widget/

# Integration tests
flutter test test/integration/
```

### Run with Coverage
```bash
flutter test --coverage
```

### Run Test Runner Script
```bash
# Windows
scripts\run_tests.bat

# Unix/Mac
scripts/run_tests.sh
```

## Test Patterns

### Widget Test Pattern
```dart
testWidgets('should display header', (tester) async {
  await tester.pumpWidget(
    const ProviderScope(
      child: MaterialApp(home: MyView()),
    ),
  );

  expect(find.text('Header'), findsOneWidget);
});
```

### Unit Test Pattern
```dart
test('should create instance', () {
  final instance = MyClass();
  expect(instance, isNotNull);
});
```

### Integration Test Pattern
```dart
testWidgets('should complete flow', (tester) async {
  final mockNotifier = MockAppNotifier();

  // Setup
  await tester.pumpWidget(...);

  // Action
  await tester.tap(find.text('Button'));
  await tester.pumpAndSettle();

  // Verify
  expect(result, expected);
});
```

## Mock Objects

### MockAppNotifier
```dart
final mockNotifier = MockAppNotifier();
mockNotifier.updateState(
  AppStateTest.createTest(
    authState: AuthStateTest.createTest(isAuthenticated: true),
  ),
);
```

### ModelFactory
```dart
final peer = ModelFactory.createMeshPeer(
  nodeId: 'peer_1',
  hostname: 'peer1.local',
  isOnline: true,
);
```

## Coverage Targets

| Module | Target | Priority | Status |
|--------|--------|----------|--------|
| FFI Bindings | 95% | Critical | Complete |
| Services | 90% | High | Complete |
| State Management | 85% | High | Complete |
| Models | 90% | High | Complete |
| UI Components | 75% | Medium | Complete |
| Integration | 85% | High | Complete |

## Test Statistics

- **Total Test Files:** 20
- **Total Test Cases:** ~700+
- **Test Categories:** 4 (FFI, Unit, Widget, Integration)
- **Infrastructure Files:** 4

## Key Features

1. **Comprehensive Coverage:** All views, services, and models tested
2. **Mockito Integration:** Auto-generated mocks for dependencies
3. **Factory Pattern:** ModelFactory for consistent test data
4. **Extension Methods:** Test helpers for AppState, AuthState, Settings
5. **WidgetTester Extensions:** Custom helpers for common operations
6. **Integration Flows:** End-to-end user journey testing
7. **FFI Verification:** Complete binding verification tests

## Maintenance Notes

- Run tests before committing changes
- Update mocks when SDK interface changes
- Add tests for new features
- Maintain 80%+ coverage threshold
