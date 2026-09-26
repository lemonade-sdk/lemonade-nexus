# Windows Packaging — Entry Point

The authoritative guide is
[PACKAGING.md](PACKAGING.md): package types (MSIX, MSI, portable), build
scripts, signing, distribution, and troubleshooting.

```
windows/packaging/
├── PACKAGING.md           # authoritative packaging guide
├── MSIX/                  # MSIX manifest and settings references
├── MSI/                   # WiX product definition
├── signing/               # code signing configuration
├── build.ps1              # canonical build script (msix | msi | exe | all | clean)
├── build.bat              # batch mirror
└── build.sh               # WSL mirror
```

Quick start:

```powershell
cd apps/LemonadeNexusClient
flutter pub get
.\windows\packaging\build.ps1 -BuildType all
```

**Status:** the Windows client CI job is currently disabled, so these
packages are not CI-qualified. Build and test locally. See
[PACKAGING.md — CI/CD Builds](PACKAGING.md#cicd-builds).

Links: [Issues](https://github.com/lemonade-sdk/lemonade-nexus/issues) ·
[Documentation](https://lemonade-sdk.github.io/lemonade-nexus/)
