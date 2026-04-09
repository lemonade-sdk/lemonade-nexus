# Command: Package for Windows

## Description
Delegates packaging to the Packaging Agent for MSIX/MSI creation and code signing.

## Purpose
Create production-ready Windows packages for distribution.

## Delegation Target
**Packaging Agent** (`../packaging_agent/agent.md`)

## Steps

### 1. Invoke Packaging Agent
```
Delegate to Packaging Agent:
"Create MSIX/MSI packages with code signing for Windows distribution"
```

### 2. Packaging Agent Deliverables

#### MSIX Package
- `pubspec.yaml` MSIX configuration
- Package manifest
- Asset declarations
- Capability definitions

#### Code Signing
- Sign tool configuration
- Certificate management
- Timestamp server setup
- GitHub Actions integration

#### Distribution
- Windows Store prep
- Direct download package
- Installer customization
- Update mechanism

### 3. MSIX Configuration

```yaml
# pubspec.yaml
msix_config:
  display_name: Lemonade Nexus
  publisher_display_name: Lemonade
  identity_name: Lemonade.LemonadeNexus
  publisher: CN=XXXX-XXXX-XXXX
  version: 1.0.0.0
  logo_path: assets\icon\logo.png
  capabilities: internetClient, privateNetworkClientServer
  start_menu: true
  desktop: true
  tray_icon:
    - images\icon.ico
```

### 4. Code Signing Configuration

```yaml
# .github/workflows/sign.yml
- name: Sign MSIX
  uses: signpath/github-action-sign-app@v1
  with:
    signpath-organization-id: 'xxx'
    project-slug: 'lemonade-nexus'
    signing-policy-slug: 'release-signing'
    github-artifact-id: 'msix-bundle'
    signpath-receive-api-token: '${{ secrets.SIGNPATH_TOKEN }}'
```

### 5. Build Pipeline

```
┌─────────────────────────────────────────────────────┐
│              Build Pipeline                          │
└─────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│  flutter      │  │  Build C SDK  │  │  Copy DLLs    │
│  build        │  │  for Windows  │  │  to output    │
│  windows      │  │               │  │               │
└───────────────┘  └───────────────┘  └───────────────┘
        │                 │                 │
        └─────────────────┼─────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│           Create MSIX Package                        │
│           (flutter pub run msix:create)             │
└─────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│           Code Sign Package                          │
│           (SignPath / Azure Trusted Signing)        │
└─────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│           Distribution                               │
│           (Store, Direct Download, CI/CD)           │
└─────────────────────────────────────────────────────┘
```

## Expected Output
- MSIX package created
- Code signed bundle
- Distribution ready
- Documentation complete

## Success Criteria
- Package installs cleanly
- No SmartScreen warnings
- Auto-updates configured
- Store submission ready
