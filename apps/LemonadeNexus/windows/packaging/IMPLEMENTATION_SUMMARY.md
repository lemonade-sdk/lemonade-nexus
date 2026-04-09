# Windows Packaging Implementation Summary

## Overview

This document summarizes the complete Windows packaging implementation for the Lemonade Nexus VPN Flutter client.

**Date:** 2026-04-09
**Version:** 1.0.0.0
**Status:** COMPLETE

## Files Created

### Configuration Files

| File | Purpose | Status |
|------|---------|--------|
| `apps/LemonadeNexus/pubspec.yaml` | Updated with msix_config | DONE |
| `apps/LemonadeNexus/windows/packaging/MSIX/AppxManifest.xml` | MSIX package manifest | DONE |
| `apps/LemonadeNexus/windows/packaging/MSIX/msix.yaml` | MSIX build settings | DONE |
| `apps/LemonadeNexus/windows/packaging/MSI/Product.wxs` | WiX product definition | DONE |
| `apps/LemonadeNexus/windows/packaging/MSI/Installer.wxs` | WiX installer config | DONE |
| `apps/LemonadeNexus/windows/packaging/MSI/BuildFiles.wxs` | WiX heat template | DONE |
| `apps/LemonadeNexus/windows/packaging/MSI/LemonadeNexus.wixproj` | WiX MSBuild project | DONE |
| `apps/LemonadeNexus/windows/packaging/signing/sign-config.yaml` | Code signing config | DONE |

### Build Scripts

| File | Purpose | Status |
|------|---------|--------|
| `apps/LemonadeNexus/windows/packaging/build.ps1` | PowerShell build script | DONE |
| `apps/LemonadeNexus/windows/packaging/build.bat` | Batch build script | DONE |
| `apps/LemonadeNexus/windows/packaging/build.sh` | Bash build script | DONE |

### CI/CD Workflows

| File | Purpose | Status |
|------|---------|--------|
| `.github/workflows/build-windows-packages.yml` | Build on push/PR | DONE |
| `.github/workflows/release-windows.yml` | Release on tag | DONE |

### Documentation

| File | Purpose | Status |
|------|---------|--------|
| `apps/LemonadeNexus/windows/packaging/README.md` | Packaging overview | DONE |
| `apps/LemonadeNexus/windows/packaging/PACKAGING.md` | Detailed guide | DONE |
| `apps/LemonadeNexus/assets/README.md` | Asset requirements | DONE |
| `apps/LemonadeNexus/keys/README.md` | Certificate guide | DONE |

### Directory Structure Created

```
apps/LemonadeNexus/
├── pubspec.yaml (updated)
├── assets/
│   └── README.md
├── keys/
│   └── README.md
└── windows/
    └── packaging/
        ├── README.md
        ├── PACKAGING.md
        ├── build.ps1
        ├── build.bat
        ├── build.sh
        ├── MSIX/
        │   ├── AppxManifest.xml
        │   └── msix.yaml
        ├── MSI/
        │   ├── Product.wxs
        │   ├── Installer.wxs
        │   ├── BuildFiles.wxs
        │   └── LemonadeNexus.wixproj
        └── signing/
            └── sign-config.yaml

.github/workflows/
├── build-windows-packages.yml
└── release-windows.yml
```

## Package Types Supported

### 1. MSIX Package

**Configuration:**
- Package Name: LemonadeNexus.LemonadeNexusVPN
- Publisher: CN=Lemonade Nexus, O=Lemonade Nexus, C=US
- Architecture: x64
- Min Windows Version: 10.0.17763.0

**Features:**
- Microsoft Store compatible
- Clean install/uninstall
- Automatic updates support
- Protocol activation (lemonade-nexus://)
- File type association (.lnxconfig)
- Startup task configuration

**Output:** `build/windows/runner/Release/lemonade_nexus.msix`

### 2. MSI Installer

**Configuration:**
- Product Code: {A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
- Manufacturer: Lemonade Nexus
- Architecture: x64
- Install Scope: perMachine

**Features:**
- Enterprise deployment ready
- SCCM/Intune compatible
- Custom install directory
- Desktop/Start menu shortcuts
- Auto-start option
- Service installation

**Output:** `windows/packaging/MSI/lemonade_nexus_setup.msi`

### 3. Portable EXE

**Features:**
- No installation required
- Self-contained
- ZIP archive format

**Output:** `build/windows/packages/lemonade_nexus_portable.zip`

## Code Signing Configuration

### Supported Signing Methods

1. **PFX File**
   - Local certificate file
   - Password protected

2. **Certificate Store**
   - Windows certificate store
   - Subject name or thumbprint lookup

3. **Azure Key Vault** (configured via sign-config.yaml)

4. **SignPath.io** (configured via sign-config.yaml)

### Timestamp Servers

- Primary: http://timestamp.digicert.com
- Backup: http://timestamp.sectigo.com
- Algorithm: SHA-256

## CI/CD Pipeline

### Build Workflow (build-windows-packages.yml)

**Triggers:**
- Push to main/develop branches
- Pull requests to main

**Jobs:**
1. build-msix - Creates MSIX package
2. build-msi - Creates MSI installer
3. build-standalone - Creates portable ZIP
4. build-all - Aggregator job with summary

### Release Workflow (release-windows.yml)

**Triggers:**
- Tag push (v*)
- Manual workflow dispatch

**Jobs:**
1. get-version - Extract version from tag/input
2. build-windows-packages - Build all packages
3. sign-packages - Code signing (optional)
4. create-release - GitHub release with assets
5. publish-winget - Submit to Winget (optional)

## Build Commands

### PowerShell (Recommended)

```powershell
cd apps/LemonadeNexus
.\windows\packaging\build.ps1 -BuildType all -Configuration release
```

### Batch

```batch
cd apps\LemonadeNexus
windows\packaging\build.bat all release
```

### Dart/Flutter Direct

```powershell
# MSIX only
flutter pub get
dart run msix:create
```

### WiX Toolset (MSI)

```powershell
# Compile
candle -arch x64 -dBuildDir="path\to\build" Product.wxs Installer.wxs

# Link
light -out lemonade_nexus_setup.msi Product.wixobj Installer.wixobj
```

## Required Assets

Before building, create these files in `assets/`:

| File | Size | Format | Required |
|------|------|--------|----------|
| app_icon.png | 256x256 | PNG | Yes (MSIX) |
| app_icon.ico | Multi-size | ICO | Yes (MSI) |
| splash_screen.png | 620x300 | PNG | Optional |
| banner.bmp | 493x58 | BMP | Yes (MSI) |
| dialog.bmp | 493x312 | BMP | Yes (MSI) |

## Environment Variables

### For Building

```bash
FLUTTER_ROOT=C:/src/flutter  # If not default
```

### For Signing

```bash
CERT_PASSWORD=your-password
CERT_FILE_PATH=path/to/certificate.pfx
```

### For CI/CD

```yaml
secrets:
  CERT_PASSWORD: <pfx-password>
  CERT_PFX_BASE64: <base64-encoded-pfx>
  WINGET_TOKEN: <winget-pat>
```

## Distribution Channels

| Channel | Package | Status |
|---------|---------|--------|
| GitHub Releases | MSIX, MSI, ZIP | CONFIGURED |
| Microsoft Store | MSIX (.appxupload) | READY |
| Winget | MSIX | AUTO-SUBMIT |
| SCCM/Intune | MSI | READY |
| Direct Download | MSIX, MSI, ZIP | CONFIGURED |

## Testing Checklist

### Pre-Build

- [ ] Flutter SDK installed (3.19.0+)
- [ ] WiX Toolset installed (v3.14)
- [ ] Windows SDK installed
- [ ] Assets created in assets/
- [ ] Certificate available (for signing)

### Post-Build

- [ ] MSIX installs successfully
- [ ] MSI installs successfully
- [ ] Portable EXE runs
- [ ] Signatures valid (if signed)
- [ ] Shortcuts created correctly
- [ ] Uninstall works cleanly

## Next Steps

1. **Create Icon Assets**
   - Design and export app_icon.png
   - Generate multi-size ICO file
   - Create MSI bitmaps

2. **Obtain Code Signing Certificate**
   - Purchase EV certificate (recommended)
   - Configure in sign-config.yaml
   - Add to GitHub secrets

3. **Test Build Locally**
   - Run build.ps1
   - Test installers
   - Verify functionality

4. **First Release**
   - Create git tag (v1.0.0)
   - Push to trigger release workflow
   - Verify GitHub release assets
   - Test Winget submission

## Known Limitations

1. **MSIX Sandbox**
   - Currently configured for full trust
   - Sandbox mode requires additional testing

2. **MSI Custom Actions**
   - CustomActions.dll placeholder
   - Requires implementation for advanced features

3. **Code Signing**
   - Self-signed certs trigger SmartScreen warnings
   - EV certificate recommended for production

## Support

- Documentation: See PACKAGING.md
- Issues: https://github.com/antmi/lemonade-nexus/issues
- CI/CD: Check Actions tab for build status

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0.0 | 2026-04-09 | Initial implementation |
