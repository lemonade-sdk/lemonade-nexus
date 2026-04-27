# Template: MSIX Package Configuration

## Description
Standard template for configuring MSIX packaging for Windows distribution.

## Usage
Use this template when setting up MSIX packaging.

## pubspec.yaml Configuration

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
  # ... other dependencies

dev_dependencies:
  flutter_test:
    sdk: flutter
  msix: ^3.16.6
  # ... other dev dependencies

# MSIX Configuration
msix_config:
  display_name: Lemonade Nexus
  publisher_display_name: Lemonade
  identity_name: Lemonade.LemonadeNexus
  msix_version: 1.0.0.0
  logo_path: assets\icons\logo.png
  capabilities: >
    internetClient,
    privateNetworkClientServer
  start_menu: true
  desktop: true
  tray_icon:
    - images\tray_icon.ico

  # Certificate signing
  certificate_path: C:\Certificates\lemonade_nexus.pfx
  certificate_password: '${CERT_PASSWORD}'

  # Optional: Store configuration
  store: false  # Set true for Windows Store submission

  # Runtime execution
  runable: true

  # Build output
  output_dir: build\msix

  # Additional metadata
  languages: en-us
  publisher: CN=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
```

## GitHub Actions Workflow

```yaml
# .github/workflows/build_msix.yml
name: Build MSIX

on:
  push:
    branches: [main]
    tags: ['v*']
  pull_request:
    branches: [main]

jobs:
  build:
    runs-on: windows-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Flutter
        uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.x'
          channel: 'stable'

      - name: Install dependencies
        run: flutter pub get

      - name: Build C SDK
        run: |
          cd projects/LemonadeNexusSDK
          cmake -B build -DCMAKE_BUILD_TYPE=Release
          cmake --build build --config Release
        shell: bash

      - name: Copy C SDK DLL
        run: |
          Copy-Item `
            "projects/LemonadeNexusSDK/build/Release/lemonade_nexus_sdk.dll" `
            "apps/LemonadeNexus/windows/"
        shell: pwsh

      - name: Build Flutter Windows
        run: flutter build windows --release
        working-directory: apps/LemonadeNexus

      - name: Create MSIX
        run: flutter pub run msix:create
        working-directory: apps/LemonadeNexus
        env:
          CERT_PASSWORD: ${{ secrets.CERT_PASSWORD }}

      - name: Sign MSIX (SignPath)
        if: startsWith(github.ref, 'refs/tags/')
        uses: signpath/github-action-sign-app@v1
        with:
          signpath-organization-id: '${{ secrets.SIGNPATH_ORG_ID }}'
          project-slug: 'lemonade-nexus'
          signing-policy-slug: 'release-signing'
          github-artifact-id: 'msix-bundle'
          signpath-receive-api-token: '${{ secrets.SIGNPATH_TOKEN }}'
          wait_for_completion: true

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: msix-bundle
          path: apps/LemonadeNexus/build/msix/*.msix
```

## Build Commands

```bash
# Development build (unsigned)
cd apps/LemonadeNexus
flutter pub get
flutter pub run msix:create

# Release build (signed)
$env:CERT_PASSWORD = "xxx"
flutter pub run msix:create --release

# Clean build
flutter clean
flutter pub get
flutter pub run msix:create
```

## Output Structure

```
build/msix/
├── LemonadeNexus.msix       # Main package
├── LemonadeNexus.msix.bundle  # Bundle (if multi-arch)
└── MsiXConfig.json          # Generated config
```

## Capabilities Reference

```yaml
# Common capabilities for VPN client
capabilities: >
  internetClient,
  privateNetworkClientServer,
  localNetwork,
  codeGeneration

# Full list:
# - internetClient (outbound HTTP)
# - internetClientServer (inbound HTTP)
# - privateNetworkClientServer (LAN)
# - localNetwork (discovery)
# - codeGeneration (JIT)
# - runFullTrust (requires package family name exception)
```

## Related Templates
- Code Signing Template
- CI/CD Pipeline Template
- App Manifest Template

## Notes
- Certificate required for distribution
- Identity name must be unique
- Version follows semantic versioning
- Capabilities affect store approval
