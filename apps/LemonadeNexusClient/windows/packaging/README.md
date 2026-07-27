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
│   ├── Product.wxs            # WiX product definition (shortcuts, features)
│   └── LemonadeNexus.wixproj  # WiX project file
│   (HarvestedFiles.wxs is generated at build time by heat.exe — not in git)
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
cd apps/LemonadeNexusClient

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
| MSIX | `nexus-client.msix` | Modern Windows, Microsoft Store |
| MSI | `nexus-client-setup.msi` | Enterprise deployment |
| EXE | `nexus-client-portable.zip` | Portable, no install |

## Configuration Files

### pubspec.yaml

MSIX configuration is in the root `pubspec.yaml` (the package version derives
from the pubspec `version:` field):

```yaml
msix_config:
  display_name: Lemonade Nexus VPN
  publisher_display_name: Lemonade Nexus
  identity_name: LemonadeNexus.LemonadeNexusVPN
  architecture: x64
  sign_msix: false
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

`.github/workflows/flutter-clients.yml` builds and sanity-checks the raw
Windows release bundle on every push/PR touching the client. Installer
packaging (MSIX/MSI/ZIP) is not automated yet — run the build scripts locally.

### Environment Variables

```yaml
# Required for signing (when packaging CI is added)
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

Attach locally built packages to releases (no release automation yet).

### Microsoft Store

1. Create `.appxupload`:
   ```powershell
   dart run msix:create --create-appxupload
   ```

2. Submit via Partner Center

### Winget

Submit a manifest manually per release (not automated).

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
dir build\windows\x64\runner\Release
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
- [signing/sign-config.yaml](signing/sign-config.yaml) - Code signing configuration

## Support

- Issues: https://github.com/antmi/lemonade-nexus/issues
- Documentation: https://github.com/antmi/lemonade-nexus/tree/main/docs
