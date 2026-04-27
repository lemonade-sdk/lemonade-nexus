# Utility: Project Scaffolding Script

## Description
Automated script for creating the Flutter project structure.

## Usage
Run from the repository root to initialize the Flutter Windows client project.

## PowerShell Script

```powershell
# scripts/scaffold_flutter_project.ps1
param(
    [string]$ProjectPath = "apps/LemonadeNexus",
    [string]$SdkHeaderPath = "projects/LemonadeNexusSDK/include/LemonadeNexusSDK/lemonade_nexus.h"
)

Write-Host "=== Lemonade Nexus Flutter Project Scaffolding ===" -ForegroundColor Cyan

# Step 1: Verify Flutter installation
Write-Host "`n[1/7] Checking Flutter installation..." -ForegroundColor Yellow
$flutterVersion = flutter --version
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERROR: Flutter not installed or not in PATH" -ForegroundColor Red
    exit 1
}
Write-Host "Flutter installed: $flutterVersion" -ForegroundColor Green

# Step 2: Enable Windows desktop support
Write-Host "`n[2/7] Enabling Windows desktop support..." -ForegroundColor Yellow
flutter config --enable-windows-desktop

# Step 3: Create Flutter project
Write-Host "`n[3/7] Creating Flutter project..." -ForegroundColor Yellow
if (Test-Path $ProjectPath) {
    Write-Host "Project already exists at $ProjectPath" -ForegroundColor Yellow
} else {
    flutter create --platforms=windows,macos,linux --org=com.lemonade --project-name=lemonade_nexus $ProjectPath
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: Failed to create Flutter project" -ForegroundColor Red
        exit 1
    }
}

# Step 4: Create directory structure
Write-Host "`n[4/7] Creating directory structure..." -ForegroundColor Yellow
$directories = @(
    "$ProjectPath/lib/src/sdk",
    "$ProjectPath/lib/src/services",
    "$ProjectPath/lib/src/state",
    "$ProjectPath/lib/src/views",
    "$ProjectPath/lib/src/widgets",
    "$ProjectPath/lib/theme",
    "$ProjectPath/c_ffi",
    "$ProjectPath/assets/icons"
)

foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        Write-Host "  Created: $dir" -ForegroundColor Gray
    }
}

# Step 5: Copy/symlink C SDK header
Write-Host "`n[5/7] Setting up C SDK header..." -ForegroundColor Yellow
if (Test-Path $SdkHeaderPath) {
    $targetPath = "$ProjectPath/c_ffi/lemonade_nexus.h"
    if (-not (Test-Path $targetPath)) {
        New-Item -ItemType SymbolicLink -Path $targetPath -Value (Resolve-Path $SdkHeaderPath) | Out-Null
        Write-Host "  Created symlink: $targetPath" -ForegroundColor Green
    }
} else {
    Write-Host "WARNING: C SDK header not found at $SdkHeaderPath" -ForegroundColor Yellow
}

# Step 6: Update pubspec.yaml
Write-Host "`n[6/7] Updating pubspec.yaml..." -ForegroundColor Yellow
$pubspecPath = "$ProjectPath/pubspec.yaml"
if (Test-Path $pubspecPath) {
    $pubspec = Get-Content $pubspecPath -Raw
    $pubspec = $pubspec -replace "description: A new Flutter project\.", "description: Lemonade Nexus VPN Client"
    $pubspec | Set-Content $pubspecPath
    Write-Host "  Updated description" -ForegroundColor Gray
}

# Add dependencies
$dependencies = @"

dependencies:
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
"@

Write-Host "  Adding dependencies..." -ForegroundColor Gray
# Note: In practice, use flutter pub add for each package

Write-Host "  Run 'flutter pub get' to install dependencies" -ForegroundColor Yellow

# Step 7: Create initial files
Write-Host "`n[7/7] Creating initial source files..." -ForegroundColor Yellow

# main.dart
$mainDart = @"
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import 'theme/app_theme.dart';

void main() {
  runApp(const LemonadeNexusApp());
}

class LemonadeNexusApp extends StatelessWidget {
  const LemonadeNexusApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Lemonade Nexus',
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.darkTheme,
      themeMode: ThemeMode.system,
      home: const Scaffold(
        body: Center(
          child: Text('Lemonade Nexus - Coming Soon'),
        ),
      ),
    );
  }
}
"@

$mainDart | Out-File -FilePath "$ProjectPath/lib/main.dart" -Encoding utf8
Write-Host "  Created: lib/main.dart" -ForegroundColor Gray

# app_theme.dart
$appTheme = @"
import 'package:flutter/material.dart';

class AppTheme {
  static const primaryColor = Color(0xFFFF6B35);
  static const secondaryColor = Color(0xFF004E89);

  static ThemeData get lightTheme {
    return ThemeData(
      useMaterial3: true,
      colorScheme: ColorScheme.light(
        primary: primaryColor,
        secondary: secondaryColor,
      ),
    );
  }

  static ThemeData get darkTheme {
    return ThemeData(
      useMaterial3: true,
      colorScheme: ColorScheme.dark(
        primary: primaryColor,
        secondary: secondaryColor,
      ),
    );
  }
}
"@

$appTheme | Out-File -FilePath "$ProjectPath/lib/theme/app_theme.dart" -Encoding utf8
Write-Host "  Created: lib/theme/app_theme.dart" -ForegroundColor Gray

# Complete
Write-Host "`n=== Scaffolding Complete ===" -ForegroundColor Green
Write-Host "`nNext steps:" -ForegroundColor Cyan
Write-Host "  1. cd $ProjectPath"
Write-Host "  2. flutter pub get"
Write-Host "  3. flutter run -d windows"
Write-Host "`nSee agents/flutter_windows_client/ for development agents." -ForegroundColor Yellow
```

## Bash Script (Linux/macOS)

```bash
#!/bin/bash
# scripts/scaffold_flutter_project.sh

PROJECT_PATH="${1:-apps/LemonadeNexus}"
SDK_HEADER_PATH="${2:-projects/LemonadeNexusSDK/include/LemonadeNexusSDK/lemonade_nexus.h}"

echo "=== Lemonade Nexus Flutter Project Scaffolding ==="

# Step 1: Verify Flutter
echo -e "\n[1/7] Checking Flutter installation..."
if ! command -v flutter &> /dev/null; then
    echo "ERROR: Flutter not installed"
    exit 1
fi
flutter --version

# Step 2: Enable Windows desktop
echo -e "\n[2/7] Enabling Windows desktop support..."
flutter config --enable-windows-desktop

# Step 3: Create project
echo -e "\n[3/7] Creating Flutter project..."
if [ -d "$PROJECT_PATH" ]; then
    echo "Project exists at $PROJECT_PATH"
else
    flutter create --platforms=windows,macos,linux --org=com.lemonade --project-name=lemonade_nexus "$PROJECT_PATH"
fi

# Step 4: Create directories
echo -e "\n[4/7] Creating directory structure..."
mkdir -p "$PROJECT_PATH/lib/src/sdk"
mkdir -p "$PROJECT_PATH/lib/src/services"
mkdir -p "$PROJECT_PATH/lib/src/state"
mkdir -p "$PROJECT_PATH/lib/src/views"
mkdir -p "$PROJECT_PATH/lib/src/widgets"
mkdir -p "$PROJECT_PATH/lib/theme"
mkdir -p "$PROJECT_PATH/c_ffi"
mkdir -p "$PROJECT_PATH/assets/icons"

# Step 5: Symlink header
echo -e "\n[5/7] Setting up C SDK header..."
if [ -f "$SDK_HEADER_PATH" ]; then
    ln -sf "$(realpath "$SDK_HEADER_PATH")" "$PROJECT_PATH/c_ffi/lemonade_nexus.h"
    echo "Created symlink"
else
    echo "WARNING: C SDK header not found"
fi

echo -e "\n=== Scaffolding Complete ==="
echo "Next steps:"
echo "  1. cd $PROJECT_PATH"
echo "  2. flutter pub get"
echo "  3. flutter run -d windows"
```

## Usage Examples

```powershell
# Default scaffolding
.\scripts\scaffold_flutter_project.ps1

# Custom project path
.\scripts\scaffold_flutter_project.ps1 -ProjectPath "my_flutter_app"

# Custom SDK header path
.\scripts\scaffold_flutter_project.ps1 -SdkHeaderPath "custom/path/lemonade_nexus.h"
```

## Output Files

The script creates:
- Complete Flutter project structure
- Directory layout for SDK, services, state, views
- Symlink to C SDK header
- Basic `main.dart` and `app_theme.dart`
- Updated `pubspec.yaml`

## Related Files
- `agents/flutter_windows_client/agent.md` - Master agent
- `templates/` - Code templates
- `docs/Windows-Client-Strategy.md` - Strategy document
