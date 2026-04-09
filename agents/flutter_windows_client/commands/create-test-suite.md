# Command: Create Test Suite

## Description
Delegates test creation to the Testing Agent for comprehensive unit, widget, and integration tests.

## Purpose
Ensure code quality and functionality through automated testing.

## Delegation Target
**Testing Agent** (`../testing_agent/agent.md`)

## Steps

### 1. Invoke Testing Agent
```
Delegate to Testing Agent:
"Create comprehensive test suite for Flutter Windows client"
```

### 2. Testing Agent Deliverables

#### Unit Tests
- FFI binding tests
- Service logic tests
- State management tests
- Model parsing tests

#### Widget Tests
- All 12 view tests
- Custom widget tests
- Theme tests
- Navigation tests

#### Integration Tests
- Login flow
- Tunnel connect/disconnect
- Peer discovery
- Settings persistence

### 3. Test Structure

```
test/
├── unit/
│   ├── ffi_bindings_test.dart
│   ├── sdk_wrapper_test.dart
│   ├── auth_service_test.dart
│   ├── tunnel_service_test.dart
│   └── state_test.dart
├── widget/
│   ├── login_view_test.dart
│   ├── dashboard_view_test.dart
│   ├── tunnel_control_view_test.dart
│   ├── peers_view_test.dart
│   └── ... (all views)
└── integration/
    ├── auth_flow_test.dart
    ├── tunnel_lifecycle_test.dart
    ├── peer_discovery_test.dart
    └── settings_persistence_test.dart
```

### 4. Test Coverage Goals

| Component | Target Coverage |
|-----------|----------------|
| FFI Bindings | 100% |
| Services | 90% |
| State Management | 85% |
| UI Components | 75% |
| **Overall** | **80%+** |

### 5. CI/CD Integration

```yaml
# .github/workflows/flutter_tests.yml
name: Flutter Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - uses: subosito/flutter-action@v2
      - run: flutter pub get
      - run: flutter test --coverage
      - uses: codecov/codecov-action@v3
```

## Expected Output
- Complete test suite
- Coverage reports
- CI/CD integration
- Test documentation

## Success Criteria
- All tests pass
- 80%+ code coverage
- Fast test execution
- Meaningful assertions
