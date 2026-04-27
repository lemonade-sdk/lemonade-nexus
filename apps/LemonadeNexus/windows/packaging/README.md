# Windows Packaging for Lemonade Nexus VPN

Complete Windows packaging solution for the Lemonade Nexus VPN Flutter client.

## Directory Structure

```
windows/packaging/
├── MSIX/                      # MSIX package configuration
│   ├── AppxManifest.xml       # MSIX manifest file
│   └── msix.yaml              # MSIX package settings
│
├── MSI/                       # MSI installer configuration
│   ├── Product.wxs            # WiX product definition
│   ├── Installer.wxs          # WiX installer configuration
│   ├── BuildFiles.wxs         # WiX heat-generated files
│   └── LemonadeNexus.wixproj  # WiX project file
│
├── signing/                   # Code signing configuration
│   └── sign-config.yaml       # Signing settings
│
├── build.ps1                  # PowerShell build script
├── build.bat                  # Batch build script
├── build.sh                   # Bash build script (WSL)
└── PACKAGING.md               # Detailed packaging guide
```

## Quick Start

### Prerequisites

1. **Flutter SDK** 3.19.0 or later
2. **WiX Toolset** v3.14 (for MSI builds)
3. **Windows SDK** (for SignTool)
4. **Visual Studio Build Tools**

### Building Packages

```powershell
# Navigate to Flutter app directory
cd apps/LemonadeNexus

# Get dependencies
flutter pub get

# Build all packages
.\windows\packaging\build.ps1 -BuildType all

# Build specific package
.\windows\packaging\build.ps1 -BuildType msix
.\windows\packaging\build.ps1 -BuildType msi
.\windows\packaging\build.ps1 -BuildType exe
```

## Package Types

| Type | File | Use Case |
|------|------|----------|
| MSIX | `lemonade_nexus.msix` | Modern Windows, Microsoft Store |
| MSI | `lemonade_nexus_setup.msi` | Enterprise deployment |
| EXE | `lemonade_nexus_portable.zip` | Portable, no install |

## Configuration Files

### pubspec.yaml

MSIX configuration is in the root `pubspec.yaml`:

```yaml
msix_config:
  display_name: Lemonade Nexus VPN
  publisher_display_name: Lemonade Nexus
  identity_name: LemonadeNexus.LemonadeNexusVPN
  logo_path: assets\app_icon.png
  version: 1.0.0.0
  sign_msix: true
```

### MSIX Settings

Edit `windows/packaging/MSIX/msix.yaml` for:
- Package identity
- Capabilities
- Protocol associations
- File type associations

### MSI Settings

Edit `windows/packaging/MSI/Product.wxs` for:
- Installation directory
- Components
- Features
- UI customization

### Code Signing

Edit `windows/packaging/signing/sign-config.yaml` for:
- Certificate configuration
- Timestamp servers
- Signing options

## CI/CD Integration

### GitHub Actions

Workflows are in `.github/workflows/`:

- `build-windows-packages.yml` - Build on push/PR
- `release-windows.yml` - Release on tag

### Environment Variables

```yaml
# Required for signing
CERT_PASSWORD: ${{ secrets.CERT_PASSWORD }}
CERT_PFX_BASE64: ${{ secrets.CERT_PFX_BASE64 }}
```

## Assets Required

Place in `assets/` directory:

- `app_icon.png` (256x256)
- `app_icon.ico` (multi-size)
- `splash_screen.png` (optional)
- `banner.bmp` (for MSI)
- `dialog.bmp` (for MSI)

## Code Signing

### Self-Signed (Development)

```powershell
New-SelfSignedCertificate `
    -DnsName "Lemonade Nexus" `
    -Type CodeSigning `
    -CertStoreLocation "Cert:\CurrentUser\My"
```

### EV Certificate (Production)

Purchase from trusted CA:
- DigiCert
- Sectigo
- GlobalSign

## Distribution

### GitHub Releases

Packages are automatically uploaded on release tags.

### Microsoft Store

1. Create `.appxupload`:
   ```powershell
   dart run msix:create --create-appxupload
   ```

2. Submit via Partner Center

### Winget

Manifest automatically submitted on release.

### Enterprise

- **SCCM**: Import MSI
- **Intune**: Upload MSIX or MSI

## Troubleshooting

### MSIX Build Fails

```powershell
# Check Flutter installation
flutter doctor

# Clean and rebuild
flutter clean
flutter pub get
flutter build windows
```

### MSI Build Fails

```powershell
# Verify WiX installation
candle -version

# Check build output exists
dir build\windows\runner\Release
```

### Signing Fails

```powershell
# Verify certificate
Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert

# Check SignTool path
where signtool
```

## Documentation

- [PACKAGING.md](PACKAGING.md) - Detailed packaging guide
- [assets/README.md](../assets/README.md) - Asset requirements
- [keys/README.md](../keys/README.md) - Code signing guide

## Support

- Issues: https://github.com/antmi/lemonade-nexus/issues
- Documentation: https://github.com/antmi/lemonade-nexus/tree/main/docs
