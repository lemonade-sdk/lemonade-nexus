# Windows Packaging Implementation Summary

## Overview

Current state of Windows packaging for the Lemonade Nexus VPN Flutter client.

**Version:** 1.0.0 (from `pubspec.yaml`; MSIX derives its quad version from it)

## What Exists

### Configuration

| File | Purpose |
|------|---------|
| `apps/LemonadeNexusClient/pubspec.yaml` | `msix_config` for `dart run msix:create` |
| `windows/packaging/MSIX/AppxManifest.xml` | MSIX manifest reference |
| `windows/packaging/MSIX/msix.yaml` | MSIX package settings reference |
| `windows/packaging/MSI/Product.wxs` | WiX product: directories, shortcuts, features |
| `windows/packaging/MSI/LemonadeNexus.wixproj` | WiX MSBuild project |
| `windows/packaging/signing/sign-config.yaml` | Code signing configuration |

`HarvestedFiles.wxs` (the `ApplicationFiles` component group with the actual
file payload) is generated at build time by `heat.exe` from the Flutter
release bundle — it is not checked in.

### Build Scripts

`build.ps1` (canonical), mirrored by `build.bat` and `build.sh`. Targets:

| Target | Output |
|--------|--------|
| `msix` | `build/windows/msix/nexus-client.msix` (copied to `build/windows/packages/msix/`) |
| `msi` | `build/windows/packages/msi/nexus-client-setup.msi` (ps1) / `windows/packaging/MSI/` (bat, sh) |
| `exe` | `build/windows/packages/exe/nexus-client-portable.zip` — the full Release bundle |
| `all` | All of the above |

The MSI flow is: `heat` harvests `build/windows/x64/runner/Release` →
`candle` compiles `Product.wxs` + `HarvestedFiles.wxs` → `light` links with
`WixUIExtension`. The MSI installs the client app and shortcuts only — no
Windows service (the coordination server ships separately).

### CI

`.github/workflows/flutter-clients.yml` builds the raw Windows release bundle
and verifies its completeness (exe, engine, SDK DLL, assets, plugin
DLLs). Installer packaging is **not** automated yet; run the scripts locally.

## Bundled Runtime Pieces

Every package carries the full Release bundle produced by
`flutter build windows --release`: the runner exe, `flutter_windows.dll`,
`lemonade_nexus_sdk.dll` (self-contained; OpenSSL/sodium/boringtun statically
embedded), plugin DLLs, and `data/` (flutter_assets, icudtl.dat, app.so).

## Prerequisites

- Flutter SDK (CI pins the version in `flutter-clients.yml`)
- Built native SDK staged at `build/projects/LemonadeNexusSDK/Release/`
  (see `docs/Building.md`)
- WiX Toolset v3 (`heat`/`candle`/`light` on PATH) for MSI
- Windows SDK SignTool for signing (optional; `sign_msix: false` by default)

## Known Gaps / Next Steps

1. No packaging CI — MSIX/MSI/ZIP are built locally.
2. Packages are unsigned by default; production needs a code-signing
   certificate (see `signing/sign-config.yaml`).
3. MSI UI bitmaps (`banner.bmp`, `dialog.bmp`) use WiX defaults; custom art
   is optional polish.
