# Development Guide

**Version:** 1.0.0
**Last Updated:** 2026-04-09
**Platform:** Windows, Linux, macOS

---

## Table of Contents

- [Overview](#overview)
- [Development Environment Setup](#development-environment-setup)
- [Building Both Components](#building-both-components)
- [Testing Procedures](#testing-procedures)
- [Debugging Tips](#debugging-tips)
- [CI/CD Pipeline](#cicd-pipeline)
- [Code Style and Standards](#code-style-and-standards)
- [Contributing](#contributing)

---

## Overview

This guide covers the complete development workflow for the Lemonade-Nexus project, including both the C++ server/SDK and the Flutter Windows client.

### Project Structure

```
lemonade-nexus/
├── projects/                    # C++ projects
│   ├── LemonadeNexus/           # Main server
│   ├── LemonadeNexusSDK/        # Client SDK
│   └── ...                      # Other C++ components
├── apps/
│   └── LemonadeNexus/           # Flutter client
│       ├── lib/                 # Dart source
│       ├── windows/             # Windows native code
│       ├── test/                # Flutter tests
│       └── windows/packaging/   # Windows packaging
├── docs/                        # Documentation
├── scripts/                     # Build and utility scripts
├── cmake/                       # CMake configuration
└── tests/                       # C++ tests
```

---

## Development Environment Setup

### Windows Development

#### Prerequisites

| Component | Version | Installation Command |
|-----------|---------|---------------------|
| Visual Studio 2022 | 17.x+ | `winget install Microsoft.VisualStudio.2022.Community` |
| C++ Build Tools | Latest | Select "Desktop development with C++" workload |
| CMake | 3.25.1+ | `winget install Kitware.CMake` |
| Ninja | 1.11.1+ | `winget install Ninja-build.Ninja` |
| Git | Latest | `winget install Git.Git` |
| Flutter | 3.19.0+ | `winget install Flutter.Flutter` |
| Rust (optional) | Latest | `winget install Rustlang.Rustup` |

#### Detailed Setup Steps

```powershell
# 1. Install Visual Studio 2022 with C++ workload
# Download from: https://visualstudio.microsoft.com/
# Select workload: "Desktop development with C++"
# Optional components:
#   - Windows 10/11 SDK
#   - C++ CMake tools
#   - C++ profiling tools

# 2. Install CMake and Ninja
winget install Kitware.CMake
winget install Ninja-build.Ninja

# 3. Install Git
winget install Git.Git

# 4. Install Flutter
winget install Flutter.Flutter

# 5. Verify installations
cmake --version
ninja --version
git --version
flutter doctor -v
```

#### Flutter Configuration

```powershell
# Enable Windows desktop development
flutter config --enable-windows-desktop

# Run Flutter doctor
flutter doctor -v

# Expected output (relevant sections):
# [✓] Windows Version (10.0.x.x)
# [✓] Visual Studio - full Windows development support
# [✓] Flutter Windows plugin
```

### Linux Development

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y \
    build-essential \
    cmake \
    ninja-build \
    git \
    curl \
    libssl-dev \
    pkg-config \
    clang \
    libgtk-3-dev \
    liblzma-dev \
    libmpv-dev \
    mpv

# Install Flutter
sudo snap install flutter --classic

# Verify
flutter doctor -v
```

### macOS Development

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install cmake ninja git curl

# Install Flutter
brew install --cask flutter

# Verify
flutter doctor -v
```

---

## Building Both Components

### C++ Server and SDK

#### Standard Build

```powershell
# Navigate to repository root
cd C:\Users\YourName\lemonade-nexus

# Configure with CMake
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug

# Build all targets
cmake --build build -j$(nproc)

# Build specific targets
cmake --build build --target LemonadeNexus
cmake --build build --target LemonadeNexusSDK

# Build in Release mode
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

#### Build Options

```powershell
# MSVC-specific options
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release

# With custom install prefix
cmake -B build -DCMAKE_INSTALL_PREFIX=C:\local\lemonade-nexus

# Enable testing
cmake -B build -DBUILD_TESTING=ON

# Build with sanitizers (Debug only)
cmake -B build -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined"
```

#### Build Output

| Target | Debug Path | Release Path |
|--------|------------|--------------|
| Server | `build\projects\LemonadeNexus\Debug\lemonade-nexus.exe` | `build\projects\LemonadeNexus\Release\lemonade-nexus.exe` |
| SDK DLL | `build\projects\LemonadeNexusSDK\Debug\lemonade_nexus_sdk.dll` | `build\projects\LemonadeNexusSDK\Release\lemonade_nexus_sdk.dll` |
| Libraries | `build\projects\*\Debug\*.lib` | `build\projects\*\Release\*.lib` |

### Flutter Client

#### Initial Setup

```powershell
# Navigate to Flutter app
cd apps\LemonadeNexus

# Get dependencies
flutter pub get

# Copy C SDK DLL (required for FFI)
Copy-Item ..\..\build\projects\LemonadeNexusSDK\Debug\lemonade_nexus_sdk.dll `
          windows\

# Or for Release
Copy-Item ..\..\build\projects\LemonadeNexusSDK\Release\lemonade_nexus_sdk.dll `
          windows\
```

#### Development Build

```powershell
# Run in debug mode with hot reload
flutter run -d windows

# Run with debugging enabled
flutter run -d windows --debug

# Run specific device (if multiple)
flutter devices
flutter run -d windows-12345
```

#### Release Build

```powershell
# Build release
flutter build windows --release

# Output location
# build\windows\runner\Release\lemonade_nexus.exe

# Build with custom output
flutter build windows --release --output=dist
```

#### Generate Code (for json_serializable)

```powershell
# Install build_runner
flutter pub add --dev build_runner

# Run build
flutter pub run build_runner build

# Watch mode (auto-regenerate on changes)
flutter pub run build_runner watch
```

### Full Build Script

```powershell
# scripts/build-all.ps1

param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Debug",
    [switch]$RunTests,
    [switch]$BuildFlutter
)

Write-Host "Building Lemonade-Nexus ($Configuration)" -ForegroundColor Cyan

# 1. Build C++ components
Write-Host "`nBuilding C++ components..." -ForegroundColor Yellow
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=$Configuration
cmake --build build -j$(nproc)

if ($LASTEXITCODE -ne 0) {
    Write-Error "C++ build failed"
    exit 1
}

# 2. Copy SDK DLL to Flutter
if ($BuildFlutter) {
    Write-Host "`nCopying SDK DLL..." -ForegroundColor Yellow
    Copy-Item "build\projects\LemonadeNexusSDK\$Configuration\lemonade_nexus_sdk.dll" `
              "apps\LemonadeNexus\windows\" -Force
}

# 3. Build Flutter
if ($BuildFlutter) {
    Write-Host "`nBuilding Flutter client..." -ForegroundColor Yellow
    Set-Location apps\LemonadeNexus
    flutter build windows --$Configuration
    Set-Location ..\..
}

# 4. Run tests
if ($RunTests) {
    Write-Host "`nRunning tests..." -ForegroundColor Yellow

    # C++ tests
    ctest --test-dir build --output-on-failure

    # Flutter tests
    Set-Location apps\LemonadeNexus
    flutter test
    Set-Location ..\..
}

Write-Host "`nBuild complete!" -ForegroundColor Green
```

---

## Testing Procedures

### C++ Tests

#### Running Tests

```powershell
# Run all tests
cd build
ctest --output-on-failure -j$(nproc)

# Run specific test
ctest -R TestName --output-on-failure

# Run with verbose output
ctest -V

# Run tests matching pattern
ctest -R "WireGuard.*" --output-on-failure

# Generate coverage (requires gcov/lcov)
ctest -T Coverage
```

#### Test Categories

| Category | Pattern | Count |
|----------|---------|-------|
| Unit Tests | `Test*` | ~200 |
| Integration Tests | `Integration*` | ~50 |
| ACME Tests | `Acme*` | ~30 (4 disabled) |
| WireGuard Tests | `WireGuard*` | ~29 |

#### Writing Tests

```cpp
// tests/test_wireguard.cpp
#include <gtest/gtest.h>
#include <LemonadeNexus/WireGuard/WireGuardService.hpp>

class WireGuardServiceTest : public ::testing::Test {
protected:
    void SetUp() override {
        service = std::make_unique<nexus::wireguard::WireGuardService>(
            "test0", "/tmp/test-wg");
    }

    std::unique_ptr<nexus::wireguard::WireGuardService> service;
};

TEST_F(WireGuardServiceTest, ValidatesInterfaceName) {
    EXPECT_FALSE(nexus::wireguard::is_valid_interface_name(""));
    EXPECT_FALSE(nexus::wireguard::is_valid_interface_name("a" + std::string(16, 'a')));
    EXPECT_TRUE(nexus::wireguard::is_valid_interface_name("wg0"));
    EXPECT_TRUE(nexus::wireguard::is_valid_interface_name("LemonadeNexus"));
}

TEST_F(WireGuardServiceTest, CreatesConfigFile) {
    // Test implementation
}
```

### Flutter Tests

#### Running Tests

```powershell
cd apps\LemonadeNexus

# Run all tests
flutter test

# Run specific category
flutter test test/ffi/
flutter test test/unit/
flutter test test/widget/
flutter test test/integration/

# Run with coverage
flutter test --coverage

# Run specific test file
flutter test test/unit/models_test.dart

# Run tests matching name
flutter test --plain-name "AuthResponse"

# Run on specific device
flutter test --device-id windows
```

#### Test Categories

| Category | Files | Tests | Coverage Target |
|----------|-------|-------|-----------------|
| FFI Tests | `test/ffi/` | ~150 | 95% |
| Unit Tests | `test/unit/` | ~300 | 90% |
| Widget Tests | `test/widget/` | ~500 | 75% |
| Integration Tests | `test/integration/` | ~30 | 85% |

#### Writing Tests

```dart
// test/unit/models_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:lemonade_nexus/src/sdk/models.dart';

void main() {
  group('AuthResponse', () {
    test('serializes correctly', () {
      final auth = AuthResponse(
        sessionToken: 'token123',
        userId: 'user456',
        username: 'testuser',
      );

      final json = auth.toJson();
      expect(json['sessionToken'], 'token123');
      expect(json['userId'], 'user456');

      final roundTrip = AuthResponse.fromJson(json);
      expect(roundTrip.sessionToken, auth.sessionToken);
    });
  });

  group('TunnelStatus', () {
    test('parses from JSON', () {
      final json = {
        'isUp': true,
        'tunnelIp': '10.64.0.10',
        'peerCount': 5,
        'bytesReceived': 1024,
        'bytesSent': 512,
      };

      final status = TunnelStatus.fromJson(json);
      expect(status.isUp, true);
      expect(status.tunnelIp, '10.64.0.10');
      expect(status.peerCount, 5);
    });
  });
}

// test/widget/login_view_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:lemonade_nexus/src/views/login_view.dart';
import 'package:lemonade_nexus/src/state/providers.dart';

void main() {
  testWidgets('LoginView shows error on failed auth', (tester) async {
    final mockNotifier = MockAppNotifier();
    when(mockNotifier.signIn(any, any))
        .thenAnswer((_) async => false);

    await tester.pumpWidget(
      ProviderScope(
        overrides: [
          appNotifierProvider.overrideWith((ref) => mockNotifier),
        ],
        child: MaterialApp(home: LoginView()),
      ),
    );

    await tester.enterText(
      find.byType(TextFormField).at(0),
      'testuser',
    );
    await tester.enterText(
      find.byType(TextFormField).at(1),
      'wrongpass',
    );
    await tester.tap(find.text('Sign In'));
    await tester.pumpAndSettle();

    expect(find.text('Authentication failed'), findsOneWidget);
  });
}
```

---

## Debugging Tips

### C++ Debugging

#### Visual Studio Debugger

1. **Open Project in Visual Studio**
   ```powershell
   # Generate Visual Studio solution
   cmake -B build -G "Visual Studio 17 2022"
   ```

2. **Set Breakpoints**
   - Click in left margin or press F9
   - Red dot indicates breakpoint

3. **Start Debugging**
   - Press F5 or Debug > Start Debugging
   - Select `lemonade-nexus.exe` as startup project

4. **Debug Windows Service**
   ```cpp
   // In ServiceMain.cpp, add for debugging:
   #ifdef _DEBUG
       // Wait for debugger attachment
       if (!IsDebuggerPresent()) {
           MessageBox(NULL, L"Attach debugger now", L"Debug", MB_OK);
       }
   #endif
   ```

#### Debugging with GDB/LLDB

```bash
# Linux with GDB
gdb build/projects/LemonadeNexus/lemonade-nexus
(gdb) break main
(gdb) run --console
(gdb) bt  # Backtrace

# macOS with LLDB
lldb build/projects/LemonadeNexus/lemonade-nexus
(lldb) breakpoint set --name main
(lldb) run
(lldb) thread backtrace
```

#### Memory Debugging

```powershell
# AddressSanitizer (ASan)
cmake -B build -DCMAKE_BUILD_TYPE=Debug `
    -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer"

# Run with ASan
.\build\projects\LemonadeNexus\Debug\lemonade-nexus.exe

# UndefinedBehaviorSanitizer (UBSan)
cmake -B build -DCMAKE_BUILD_TYPE=Debug `
    -DCMAKE_CXX_FLAGS="-fsanitize=undefined"
```

### Flutter Debugging

#### Dart DevTools

```powershell
# Run with DevTools
flutter run -d windows

# DevTools opens automatically or access at:
# http://127.0.0.1:9100

# Or launch separately
flutter pub global activate devtools
flutter pub global run devtools
```

#### Debug Mode Features

```dart
// Enable debug painting
flutter run --debug-paint

// Enable profile mode (for performance)
flutter run --profile

// Show performance overlay
flutter run --show-performance-overlay
```

#### Debugging FFI Issues

```dart
// Add logging to FFI bindings
class LemonadeNexusFFI {
  void _logCall(String functionName) {
    print('[FFI] Calling $functionName');
  }

  LemonadeNexusFFI(String libPath) : _lib = ffi.DynamicLibrary.open(libPath) {
    print('[FFI] Loaded library from: $libPath');
    _create = _lib.lookup<ffi.NativeFunction<LnCreateNative>>('ln_create')
        .asFunction<LnCreate>();
    print('[FFI] Bound ln_create');
  }
}
```

#### Flutter DevTools Features

| Feature | Description |
|---------|-------------|
| Widget Inspector | Examine widget tree |
| Performance Tab | Profile CPU/GPU usage |
| Memory Tab | Analyze memory usage |
| Network Tab | View HTTP requests |
| Logging Tab | View app logs |

### Logging

#### C++ Logging

```cpp
// Configure spdlog
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>(
    "logs/lemonade-nexus.log", true);

spdlog::sinks_init_list sinks{console_sink, file_sink};
auto logger = std::make_shared<spdlog::logger>(
    "lemonade-nexus", sinks.begin(), sinks.end());

spdlog::set_default_logger(logger);
spdlog::set_level(spdlog::level::debug);  // Set log level

// Usage
spdlog::info("Server started on port {}", 9100);
spdlog::error("Failed to bind port: {}", error_message);
spdlog::debug("Processing request from {}", client_ip);
```

#### Flutter Logging

```dart
// Use dart:developer for structured logging
import 'dart:developer' as developer;

void logMessage(String message, {String level = 'INFO'}) {
  developer.log(
    message,
    name: 'LemonadeNexus',
    level: _logLevelToInt(level),
  );
}

int _logLevelToInt(String level) {
  switch (level) {
    case 'DEBUG': return 500;
    case 'INFO': return 800;
    case 'WARNING': return 900;
    case 'ERROR': return 1000;
    default: return 800;
  }
}

// Usage in services
class AuthService {
  Future<bool> signIn(String username, String password) async {
    logMessage('Attempting sign in for $username');
    try {
      // ... authentication logic
      logMessage('Sign in successful');
      return true;
    } catch (e) {
      logMessage('Sign in failed: $e', level: 'ERROR');
      return false;
    }
  }
}
```

---

## CI/CD Pipeline

### GitHub Actions Workflows

#### Build Windows Packages

```yaml
# .github/workflows/build-windows-packages.yml

name: Build Windows Packages

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  build-windows:
    runs-on: windows-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup CMake
        uses: lukka/get-cmake@latest

      - name: Setup Flutter
        uses: subosito/flutter-action@v2
        with:
          channel: stable

      - name: Configure CMake
        run: cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release

      - name: Build C++ Components
        run: cmake --build build -j$(nproc)

      - name: Copy SDK DLL
        run: |
          Copy-Item build\projects\LemonadeNexusSDK\Release\lemonade_nexus_sdk.dll `
                    apps\LemonadeNexus\windows\

      - name: Build Flutter
        run: |
          cd apps/LemonadeNexus
          flutter build windows --release

      - name: Package MSIX
        run: |
          cd apps/LemonadeNexus
          flutter pub get
          flutter pub run msix:create

      - name: Upload Artifacts
        uses: actions/upload-artifact@v4
        with:
          name: windows-packages
          path: apps/LemonadeNexus/build/windows/runner/Release/
```

#### Release Workflow

```yaml
# .github/workflows/release-windows.yml

name: Release Windows

on:
  push:
    tags:
      - 'v*'

jobs:
  release:
    runs-on: windows-latest
    permissions:
      contents: write

    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: |
          cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
          cmake --build build
          cd apps/LemonadeNexus
          flutter build windows --release

      - name: Create Release
        uses: softprops/action-gh-release@v1
        with:
          files: |
            build/projects/LemonadeNexus/Release/lemonade-nexus.exe
            apps/LemonadeNexus/build/windows/runner/Release/lemonade_nexus.exe
          generate_release_notes: true
```

---

## Code Style and Standards

### C++ Code Style

```cpp
// Naming conventions
class ClassName {};           // PascalCase for classes
struct StructName {};         // PascalCase for structs
void functionName() {}        // snake_case for functions
void MemberClass::method() {} // snake_case for methods
Type member_variable_;        // snake_case with trailing underscore
Type local_variable;          // snake_case for locals
constexpr int kConstant;      // kConstant for constants
enum class EnumName {};       // PascalCase for enums

// File organization
// Header: #pragma once, includes, forward declarations, class definition
// Source: Implementation, alphabetical order for methods

// Comments
// Single line comment
/* Multi-line comment */
/// Documentation comment (Doxygen style)
```

### Dart Code Style

```dart
// Follow Effective Dart guidelines
// https://dart.dev/guides/language/effective-dart

// Naming
class ClassName {}            // PascalCase
void functionName() {}        // snake_case
Type _privateMember;          // _underscore for private
const kConstant = value;      // kConstant for constants

// Documentation
/// Documentation comment for public API
///
/// Longer description here.
class MyClass {}

// Formatting (use dart format)
// dart format lib/ test/

// Linting (use flutter analyze)
// flutter analyze
```

### Pre-commit Hooks

```bash
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/mirrors-clang-format
    rev: v17.0.0
    hooks:
      - id: clang-format
        types: [c++]

  - repo: https://github.com/dart-lang/dart_style
    rev: 2.3.2
    hooks:
      - id: dart_format
        files: \.dart$

  - repo: https://github.com/pre-commit/mirrors-prettier
    rev: v3.0.0
    hooks:
      - id: prettier
        types: [markdown]
```

---

## Contributing

### Pull Request Process

1. **Fork the Repository**
   ```bash
   git fork https://github.com/antmi/lemonade-nexus
   ```

2. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Changes**
   - Follow code style guidelines
   - Add tests for new functionality
   - Update documentation

4. **Run Tests**
   ```bash
   # C++ tests
   cmake -B build -DBUILD_TESTING=ON
   cmake --build build
   ctest --test-dir build --output-on-failure

   # Flutter tests
   cd apps/LemonadeNexus
   flutter test
   ```

5. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add your feature description

   Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
   "
   ```

6. **Push and Create PR**
   ```bash
   git push origin feature/your-feature-name
   # Then create PR on GitHub
   ```

### Commit Message Format

```
type(scope): subject

body (optional)

footer (optional)

Types:
  feat:     New feature
  fix:      Bug fix
  docs:     Documentation changes
  style:    Code style changes (formatting)
  refactor: Code refactoring
  test:     Test additions/changes
  chore:    Build/config changes
```

### Code Review Checklist

- [ ] Code follows style guidelines
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] No security vulnerabilities introduced
- [ ] Performance impact considered
- [ ] Backward compatibility maintained

---

## Related Documentation

- [Windows Port](WINDOWS-PORT.md) - Server architecture
- [Flutter Client](FLUTTER-CLIENT.md) - Client architecture
- [Building from Source](Building.md) - General build instructions
- [Architecture](Architecture.md) - System design

---

**Document History:**

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-09 | Initial release |
