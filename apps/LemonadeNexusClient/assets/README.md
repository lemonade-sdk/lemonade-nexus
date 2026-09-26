# Assets Directory

Visual assets for the client and for Windows packaging.

## What is here

| File | Used for |
|------|----------|
| `app_icon.png` | App icon source (256x256 PNG with transparency) |
| `icons/app_icon.png` / `icons/app_icon.ico` / `icons/app_icon.svg` | Platform app icons (multi-size ICO for Windows) |
| `icons/tray_icon.png` / `icons/tray_icon.ico` / `icons/tray_icon.svg` | System tray icon |

## Windows packaging notes

- The MSIX logo and Windows app icon come from the assets above.
- The MSI build uses the **WiX default UI bitmaps** (`banner.bmp`,
  `dialog.bmp`, `error.ico`, `info.ico`, `up.ico`) when they are not
  provided; supplying custom ones is optional polish, not a build
  requirement.
- `splash_screen.png` (620x300) is optional for the MSIX splash screen.

## Regenerating icons

```powershell
# From the PNG source (requires ImageMagick)
magick convert app_icon.png -define icon:auto-resize=256,48,32,16 app_icon.ico
```

or the `flutter_launcher_icons` package.

## Adding assets to pubspec.yaml

List runtime assets under `flutter: assets:` in `pubspec.yaml`; build-time
packaging assets are referenced by the packaging scripts and do not need to
be in that list.
