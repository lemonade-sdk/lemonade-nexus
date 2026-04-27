# Command: Initialize Flutter Project

## Description
Creates the complete Flutter project structure for the Lemonade Nexus Windows client with C SDK FFI integration.

## Purpose
Establish the foundational project scaffolding that all other components will build upon.

## Steps

### 1. Create Flutter Project
```bash
flutter create --platforms=windows,macos,linux --org=com.lemonade --project-name=lemonade_nexus apps/LemonadeNexus
```

### 2. Configure Project Structure
```
apps/LemonadeNexus/
├── lib/
│   ├── main.dart
│   ├── src/
│   │   ├── sdk/              # FFI bindings (from FFI Agent)
│   │   ├── services/         # Business logic
│   │   ├── state/            # State management (from State Agent)
│   │   ├── views/            # UI components (from UI Agent)
│   │   └── widgets/          # Reusable widgets
│   └── theme/
│       └── app_theme.dart
├── c_ffi/
│   └── lemonade_nexus.h      # Symlink to SDK header
├── windows/
│   ├── runner/
│   └── CMakeLists.txt        # Configure for C SDK linking
├── macos/
│   └── Runner/
├── linux/
│   └── flutter/
└── test/                     # Unit tests
```

### 3. Add Dependencies (pubspec.yaml)
```yaml
name: lemonade_nexus
description: Lemonade Nexus VPN Client
version: 1.0.0+1

environment:
  sdk: '>=3.0.0 <4.0.0'
  flutter: '>=3.10.0'

dependencies:
  flutter:
    sdk: flutter
  provider: ^6.1.1
  riverpod: ^2.4.9
  ffi: ^2.1.0
  path: ^1.8.3
  json_annotation: ^4.8.1
  package_info_plus: ^5.0.1
  tray_manager: ^0.2.1

dev_dependencies:
  flutter_test:
    sdk: flutter
  mockito: ^5.4.3
  integration_test:
    sdk: flutter
  msix: ^3.16.6
  build_runner: ^2.4.6
  json_serializable: ^6.7.1
```

### 4. Configure C SDK Integration
- Create `windows/CMakeLists.txt` to link C SDK
- Copy or symlink `lemonade_nexus.h` to `c_ffi/`
- Configure DLL path for runtime

### 5. Create Main Entry Point
```dart
// lib/main.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'src/state/app_state.dart';
import 'src/views/login_view.dart';
import 'theme/app_theme.dart';

void main() {
  runApp(const LemonadeNexusApp());
}

class LemonadeNexusApp extends StatelessWidget {
  const LemonadeNexusApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => AppState()),
        // Additional providers from State Agent
      ],
      child: MaterialApp(
        title: 'Lemonade Nexus',
        theme: AppTheme.lightTheme,
        darkTheme: AppTheme.darkTheme,
        themeMode: ThemeMode.system,
        home: const LoginView(),
      ),
    );
  }
}
```

### 6. Create Theme Configuration
```dart
// lib/theme/app_theme.dart
import 'package:flutter/material.dart';

class AppTheme {
  static const primaryColor = Color(0xFFFF6B35); // Lemonade orange
  static const secondaryColor = Color(0xFF004E89); // Deep blue

  static ThemeData get lightTheme {
    return ThemeData(
      useMaterial3: true,
      colorScheme: ColorScheme.light(
        primary: primaryColor,
        secondary: secondaryColor,
        surface: Colors.white,
        background: Colors.grey[100]!,
      ),
      // ... additional theme configuration
    );
  }

  static ThemeData get darkTheme {
    return ThemeData(
      useMaterial3: true,
      colorScheme: ColorScheme.dark(
        primary: primaryColor,
        secondary: secondaryColor,
        surface: const Color(0xFF1E1E1E),
        background: const Color(0xFF121212),
      ),
      // ... additional theme configuration
    );
  }
}
```

## Expected Output
- Complete Flutter project structure
- All dependencies configured
- C SDK FFI integration ready
- Main entry point with theme
- Base state management scaffolding

## Error Handling
- Check Flutter installation: `flutter doctor`
- Verify C SDK build artifacts exist
- Ensure symlinks created correctly on Windows

## Delegation
- FFI Agent: Generate initial FFI bindings
- State Agent: Set up base providers
- UI Agent: Create initial theme widgets

## Success Criteria
- `flutter run` launches the app
- C SDK DLL can be loaded via FFI
- Theme applied correctly
- State management providers active
