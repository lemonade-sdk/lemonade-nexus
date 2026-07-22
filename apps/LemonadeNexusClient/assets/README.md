# Assets Directory for Lemonade Nexus VPN

This directory contains visual assets required for building Windows packages.

## Required Files

### Icons

1. **app_icon.png** (Required)
   - Size: 256x256 pixels (recommended)
   - Format: PNG with transparency
   - Used for: MSIX package logo, Start menu, desktop shortcut

2. **app_icon.ico** (Required for MSI)
   - Sizes: 16x16, 32x32, 48x48, 256x256
   - Format: ICO
   - Used for: MSI installer, executable icon, Control Panel

3. **splash_screen.png** (Optional)
   - Size: 620x300 pixels
   - Format: PNG
   - Used for: MSIX splash screen

### MSI Installer Graphics

4. **banner.bmp** (Required for MSI)
   - Size: 493x58 pixels
   - Format: BMP
   - Used for: MSI installer banner

5. **dialog.bmp** (Required for MSI)
   - Size: 493x312 pixels
   - Format: BMP
   - Used for: MSI installer dialog background

6. **error.ico** (Required for MSI)
   - Size: 32x32 pixels
   - Format: ICO
   - Used for: MSI error dialog icon

7. **info.ico** (Required for MSI)
   - Size: 32x32 pixels
   - Format: ICO
   - Used for: MSI info dialog icon

8. **up.ico** (Required for MSI)
   - Size: 16x16 pixels
   - Format: ICO
   - Used for: MSI up navigation icon

## Creating Icons

### Using PowerShell (Windows)

```powershell
# Convert PNG to ICO (requires ImageMagick)
magick convert app_icon.png -define icon:auto-resize=256,48,32,16 app_icon.ico
```

### Using Online Tools

- https://convertio.co/png-ico/
- https://www.icoconverter.com/

### Using Flutter

```bash
# Use flutter_launcher_icons package
flutter pub run flutter_launcher_icons:main
```

## Recommended Icon Design

- **Style**: Clean, modern, professional
- **Colors**: Green (#48BB78) for VPN/security theme
- **Symbol**: Shield or lock icon representing security
- **Background**: Transparent or solid color

## File Checklist

Before building packages, ensure you have:

- [ ] app_icon.png (256x256)
- [ ] app_icon.ico (multi-size)
- [ ] splash_screen.png (optional)
- [ ] banner.bmp (for MSI)
- [ ] dialog.bmp (for MSI)

## Adding Assets to pubspec.yaml

```yaml
flutter:
  assets:
    - assets/app_icon.png
    - assets/splash_screen.png
```
