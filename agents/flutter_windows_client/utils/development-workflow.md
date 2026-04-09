# Utility: Development Workflow Guide

## Description
Step-by-step development workflow for the Flutter Windows client.

## Daily Development Flow

### Morning Setup
```bash
# 1. Navigate to project
cd apps/LemonadeNexus

# 2. Get latest changes
git pull origin main

# 3. Install dependencies
flutter pub get

# 4. Clean build (if needed)
flutter clean
flutter pub get

# 5. Run with hot reload
flutter run -d windows
```

### Development Cycle
```
1. Identify task from project board
2. Review relevant agent documentation
3. Use templates for code generation
4. Implement feature
5. Run tests
6. Commit changes
```

### End of Day
```bash
# 1. Run all tests
flutter test

# 2. Check code style
flutter analyze

# 3. Stage changes
git add -A

# 4. Commit with message
git commit -m "feat: description"
```

## Feature Development Workflow

### Example: Adding a New View

#### 1. Review Requirements
- Check macOS equivalent view
- Review functional requirements
- Identify state dependencies

#### 2. Use Templates
```
Template: flutter-view-component.md
Template: macos-to-flutter-converter.md
```

#### 3. Create View File
```dart
// lib/src/views/my_view.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

class MyView extends StatelessWidget {
  const MyView({super.key});

  @override
  Widget build(BuildContext context) {
    return Consumer<MyState>(
      builder: (context, state, child) {
        return Scaffold(...);
      },
    );
  }
}
```

#### 4. Create Tests
```
Template: widget-test.md
```

#### 5. Update Navigation
Add to `ContentView` navigation

#### 6. Test
```bash
flutter test test/widget/my_view_test.dart
```

## FFI Development Workflow

### Adding a New FFI Binding

#### 1. Review C Function
```c
ln_error_t ln_my_function(ln_client_t* client, const char* param, char** out_json);
```

#### 2. Use Template
```
Template: ffi-binding-definition.md
```

#### 3. Add Typedefs
```dart
typedef LnMyFunctionNative = Int32 Function(
  Pointer<Void> client,
  Pointer<Utf8> param,
  Pointer<Pointer<CChar>> outJson,
);

typedef LnMyFunction = int Function(
  Pointer<Void> client,
  Pointer<Utf8> param,
  Pointer<Pointer<CChar>> outJson,
);
```

#### 4. Add Lookup
```dart
late final LnMyFunction _myFunction;

// In constructor:
_myFunction = _lib
    .lookup<ffi.NativeFunction<LnMyFunctionNative>>('ln_my_function')
    .asFunction<LnMyFunction>();
```

#### 5. Add Wrapper
```dart
Future<Map<String, dynamic>> myFunction(String param) async {
  final paramPtr = param.toNativeUtf8();
  final jsonPtr = calloc<Pointer<CChar>>();
  try {
    final result = _myFunction(_client, paramPtr, jsonPtr);
    if (result != 0) throw SdkException(result);
    final jsonString = jsonPtr.value.cast<Utf8>().toDartString();
    _lnFree(jsonPtr.value);
    return jsonDecode(jsonString);
  } finally {
    calloc.free(paramPtr);
    calloc.free(jsonPtr);
  }
}
```

#### 6. Test
```bash
flutter test test/unit/ffi/my_function_test.dart
```

## Debugging Workflows

### Hot Reload Issues
```bash
# Force restart
r (in Flutter terminal)

# Full restart
R (in Flutter terminal)

# Quit and restart
flutter run -d windows
```

### FFI Debugging
```dart
// Add logging
print('Calling ln_my_function with param: $param');
final result = _myFunction(_client, paramPtr, jsonPtr);
print('Result: $result');

// Check for null pointers
if (jsonPtr.value == nullptr) {
  throw Exception('Null JSON pointer returned');
}
```

### State Debugging
```dart
// Add debugPrint
debugPrint('State updated: ${state.status}');

// Use DevTools
// Navigate to: http://localhost:9100
```

## Testing Workflows

### Run Specific Test
```bash
flutter test test/unit/my_test.dart
flutter test test/widget/my_view_test.dart
flutter test test/integration/my_flow_test.dart
```

### Run All Tests with Coverage
```bash
flutter test --coverage
genhtml coverage/lcov.info -o coverage/html
# Open coverage/html/index.html
```

### Debug Tests
```bash
# Run with verbose output
flutter test --verbose test/unit/my_test.dart

# Run specific test group
flutter test --plain-name "MyService login returns user"
```

## Build Workflows

### Debug Build
```bash
flutter build windows --debug
```

### Release Build
```bash
flutter build windows --release
```

### MSIX Package
```bash
flutter pub run msix:create --release
```

## Common Issues & Solutions

### Issue: DLL Not Found
```
Solution: Ensure lemonade_nexus_sdk.dll is in windows/ folder
```

### Issue: FFI Type Mismatch
```
Solution: Check C header typedef matches Dart typedef
```

### Issue: State Not Updating
```
Solution: Ensure notifyListeners() called or use StateNotifier
```

### Issue: Hot Reload Not Working
```
Solution: Restart app, check for const changes
```

## Related Files
- `checklists/` - Quality checklists
- `templates/` - Code templates
- `data/flutter-best-practices.md` - Best practices
