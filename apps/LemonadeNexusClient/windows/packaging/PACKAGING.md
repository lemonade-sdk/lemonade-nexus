# Windows Packaging Guide

## Overview

This document describes the Windows packaging options available for Lemonade Nexus VPN.

## Package Types

### 1. MSIX Package (Recommended)

**Best for:** Modern Windows deployment, Microsoft Store distribution

**Features:**
- Clean install/uninstall
- Automatic updates via Microsoft Store
- Sandbox support (optional)
- Windows 10/11 optimized
- Enterprise deployment ready (Intune, SCCM)

**File:** `nexus-client-<version>.msix`

**Installation:**
```powershell
# Double-click to install
# Or use PowerShell
Add-AppxPackage nexus-client-1.0.0.msix
```

**Requirements:**
- Windows 10 version 1809 or later
- PowerShell 5.1 or later

### 2. MSI Installer

**Best for:** Enterprise deployment, traditional Windows environments

**Features:**
- Traditional Windows installer
- SCCM/Intune deployment support
- Custom installation options
- Registry integration

**File:** `nexus-client-setup.msi`

**Installation:**
```powershell
# Silent installation
msiexec /i nexus-client-setup.msi /quiet

# Interactive installation
msiexec /i nexus-client-setup.msi

# Deploy via SCCM
# Use the MSI file in your application deployment
```

**Requirements:**
- Windows 10 or later
- Windows Installer 5.0 or later

### 3. Portable EXE

**Best for:** Testing, portable use, no-admin installations

**Features:**
- No installation required
- Self-contained executable
- Can be run from USB drive
- Minimal system footprint

**File:** `nexus-client-portable-<version>.zip`

**Installation:**
```powershell
# Extract and run
Expand-Archive nexus-client-portable-1.0.0.zip
cd nexus-client-portable
.\nexus-client.exe
```

**Requirements:**
- Windows 10 or later
- No admin privileges required

## Building Packages

### Prerequisites

1. **Flutter SDK** (3.19.0 or later)
   ```powershell
   # Install via winget
   winget install Flutter.Flutter
   ```

2. **WiX Toolset** (for MSI builds)
   ```powershell
   winget install WixToolset.WixToolset
   ```

3. **Windows SDK** (for SignTool)
   ```powershell
   winget install Microsoft.WindowsSDK.10.0.19041.0
   ```

4. **Git**
   ```powershell
   winget install Git.Git
   ```

### Build Commands

```powershell
# Navigate to Flutter app directory
cd apps/LemonadeNexusClient

# Get dependencies
flutter pub get

# Build all packages
.\windows\packaging\build.ps1 -BuildType all

# Build specific package
.\windows\packaging\build.ps1 -BuildType msix
.\windows\packaging\build.ps1 -BuildType msi
.\windows\packaging\build.ps1 -BuildType exe

# Clean build
.\windows\packaging\build.ps1 -BuildType clean
```

### CI/CD Builds

CI (`.github/workflows/flutter-clients.yml`) builds and sanity-checks the raw
Windows release bundle on every push/PR touching the client, but does not yet
produce installer packages. MSIX/MSI/portable packages are built locally with
the scripts above.

## Code Signing

### Certificate Requirements

For production releases, packages should be signed with:
- **EV Code Signing Certificate** (recommended)
- SHA-256 signature algorithm
- RFC 3161 timestamp server

### Signing Configuration

Edit `windows/packaging/signing/sign-config.yaml`:

```yaml
certificate_path: keys\code_signing.pfx
certificate_password: '${CERT_PASSWORD}'
timestamp_url: 'http://timestamp.digicert.com'
```

### Manual Signing

```powershell
# Sign MSIX
signtool sign /f code_signing.pfx /p <password> \
  /t http://timestamp.digicert.com /fd sha256 \
  nexus-client.msix

# Sign MSI
signtool sign /f code_signing.pfx /p <password> \
  /t http://timestamp.digicert.com /fd sha256 \
  nexus-client-setup.msi
```

## Distribution Channels

### 1. Direct Download (GitHub Releases)

Packages are distributed via GitHub Releases:
- Navigate to https://github.com/antmi/lemonade-nexus/releases
- Download the appropriate package for your needs

### 2. Microsoft Store

To submit to Microsoft Store:

1. Create an `.appxupload` file:
   ```powershell
   dart run msix:create --output-name nexus-client --create-appxupload
   ```

2. Submit via Microsoft Partner Center

### 3. Winget (Windows Package Manager)

Manifest is automatically created and submitted on release.

```powershell
# Install via winget
winget install LemonadeNexus.LemonadeNexusVPN
```

### 4. Enterprise Deployment

**SCCM:**
1. Import the MSI into SCCM
2. Create deployment type
3. Deploy to target collections

**Intune:**
1. Upload MSIX or MSI to Intune
2. Configure deployment settings
3. Assign to users/devices

## Troubleshooting

### MSIX Installation Fails

**Error:** `0x80073CF0` - Package is invalid
- Ensure the MSIX is properly signed
- Check Windows version compatibility

**Error:** `0x80073D02` - Package needs updates
- Uninstall existing version first
- Check for pending Windows updates

### MSI Installation Fails

**Error:** "This application requires Windows 10"
- Verify Windows version: `winver`
- Minimum required: Windows 10 version 1809

**Error:** "Another version is already installed"
- Uninstall existing version via Control Panel
- Or use: `msiexec /x {product-code} /quiet`

### Code Signing Issues

**Error:** "Certificate not found"
- Ensure certificate is imported to certificate store
- Check certificate thumbprint in config

**Error:** "Timestamp server unavailable"
- Try backup timestamp server: `http://timestamp.sectigo.com`

## File Locations

### Installation Paths

| Package Type | Installation Path |
|--------------|-------------------|
| MSIX | `C:\Program Files\WindowsApps\LemonadeNexus.LemonadeNexusVPN_*` |
| MSI | `C:\Program Files\Lemonade Nexus\` |
| Portable | User-defined (wherever extracted) |

### Configuration Paths

| Type | Path |
|------|------|
| User config | `%APPDATA%\LemonadeNexus\` |
| Machine config | `%PROGRAMDATA%\LemonadeNexus\` |
| Logs | `%LOCALAPPDATA%\LemonadeNexus\logs\` |

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0.0 | 2026-04-09 | Initial release |

## Support

- Issues: https://github.com/antmi/lemonade-nexus/issues
- Documentation: https://github.com/antmi/lemonade-nexus/tree/main/docs
