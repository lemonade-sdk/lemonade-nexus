# Installation Guide

**Version:** 1.0.0
**Last Updated:** 2026-04-09
**Platform:** Windows

---

## Table of Contents

- [Overview](#overview)
- [System Requirements](#system-requirements)
- [C++ Server Installation](#c-server-installation)
- [Flutter Client Installation](#flutter-client-installation)
- [PowerShell Scripts Usage](#powershell-scripts-usage)
- [Service Management](#service-management)
- [Configuration](#configuration)
- [Uninstallation](#uninstallation)
- [Troubleshooting](#troubleshooting)

---

## Overview

This guide covers installation of both the Lemonade-Nexus C++ Server and Flutter Windows Client on Windows platforms.

### Installation Components

| Component | Description | Required For |
|-----------|-------------|--------------|
| C++ Server | WireGuard mesh VPN server | Server deployments |
| Flutter Client | Desktop GUI application | Client/end-user deployments |
| PowerShell Scripts | Automation scripts | Both components |
| Windows Service | SCM integration | Server deployments |

---

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| Operating System | Windows 10 version 1809 or later |
| Processor | 1.6 GHz or faster, 2-core |
| Memory | 4 GB RAM (8 GB recommended) |
| Disk Space | 500 MB available space |
| Network | Broadband Internet connection |

### Server-Specific Requirements

| Component | Requirement |
|-----------|-------------|
| Administrator Rights | Required for service installation |
| WireGuard Driver | Auto-installed (wireguard-nt) |
| Network Ports | 9100/tcp, 9101/tcp, 51820/udp |

### Client-Specific Requirements

| Component | Requirement |
|-----------|-------------|
| Administrator Rights | Optional (for auto-start) |
| .NET Runtime | Included with Windows 10+ |
| Visual C++ Redistributable | Auto-installed |

---

## C++ Server Installation

### Pre-Built Installer (Recommended)

#### Download

1. Navigate to [GitHub Releases](https://github.com/antmi/lemonade-nexus/releases)
2. Download the latest `lemonade-nexus-setup-<version>.exe`
3. Verify the SHA256 checksum (provided in release notes)

#### Installation Steps

```powershell
# Run the installer
.\lemonade-nexus-setup-1.0.0.exe

# Or silent installation
.\lemonade-nexus-setup-1.0.0.exe /S

# Install to custom directory
.\lemonade-nexus-setup-1.0.0.exe /D=C:\Program Files\LemonadeNexus
```

#### Installation Options

| Option | Description | Default |
|--------|-------------|---------|
| `/S` | Silent installation | Interactive |
| `/D=path` | Installation directory | `C:\Program Files\LemonadeNexus` |
| `/STARTSERVICE` | Start service after install | Yes |
| `/ADDFIREWALL` | Add firewall rules | Yes |

#### Post-Installation

After installation:

1. **Service Status** - Check Windows Services MMC (`services.msc`)
2. **Firewall Rules** - Verify inbound rules in Windows Defender Firewall
3. **Configuration** - Edit configuration files in `%PROGRAMDATA%\LemonadeNexus\`

### Manual Installation

#### Prerequisites

```powershell
# Install Visual C++ Redistributable
winget install Microsoft.VCRedist.2015+.x64

# Install .NET Runtime (if needed)
winget install Microsoft.DotNet.Runtime.8
```

#### Installation Steps

```powershell
# 1. Create installation directory
New-Item -ItemType Directory -Path "C:\Program Files\LemonadeNexus" -Force

# 2. Copy binaries
Copy-Item "build\projects\LemonadeNexus\Release\*" `
          "C:\Program Files\LemonadeNexus\" -Recurse

# 3. Create data directory
New-Item -ItemType Directory -Path "C:\ProgramData\LemonadeNexus\data" -Force

# 4. Set permissions (optional - restrict to admins)
$acl = Get-Acl "C:\ProgramData\LemonadeNexus"
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "Administrators", "FullControl", "ContainerInherit,ObjectInherit",
    "None", "Allow")
$acl.AddAccessRule($rule)
Set-Acl "C:\ProgramData\LemonadeNexus" $acl
```

#### Create Windows Service

```powershell
# Using sc.exe
sc create LemonadeNexus `
    binPath= "\"C:\Program Files\LemonadeNexus\lemonade-nexus.exe\"" `
    start= auto `
    DisplayName= "Lemonade Nexus VPN Server"

# Set description
sc description LemonadeNexus "Lemonade-Nexus Mesh VPN Server"

# Configure recovery (restart on failure)
sc failure LemonadeNexus `
    reset= 86400 `
    actions= restart/60000/restart/60000/restart/60000

# Start the service
sc start LemonadeNexus
```

---

## Flutter Client Installation

### MSIX Package (Recommended)

#### Installation

```powershell
# Download MSIX from releases
# Install via double-click or PowerShell

Add-AppxPackage lemonade_nexus-1.0.0.msix

# Or with PowerShell 7+
winget install LemonadeNexus.LemonadeNexusVPN
```

#### Verification

```powershell
# Check installed app
Get-AppxPackage | Where-Object Name -like "*LemonadeNexus*"

# Launch the app
Start-Process "lemonade-nexus:"
```

### MSI Installer

#### Installation

```powershell
# Interactive installation
msiexec /i lemonade_nexus_setup-1.0.0.msi

# Silent installation
msiexec /i lemonade_nexus_setup-1.0.0.msi /quiet

# Silent with logging
msiexec /i lemonade_nexus_setup-1.0.0.msi /quiet /l*v install.log
```

#### Enterprise Deployment (SCCM/Intune)

**SCCM:**
1. Import MSI as application
2. Configure detection rules
3. Deploy to target collections

**Intune:**
1. Upload MSIX/MSI to Intune
2. Configure deployment settings
3. Assign to users/devices

### Portable Installation

```powershell
# Download and extract
Expand-Archive lemonade_nexus_portable-1.0.0.zip -DestinationPath C:\Apps\LemonadeNexus

# Run directly
C:\Apps\LemonadeNexus\lemonade_nexus.exe
```

---

## PowerShell Scripts Usage

### Available Scripts

| Script | Purpose | Location |
|--------|---------|----------|
| `install-service.ps1` | Install Windows Service | `scripts/` |
| `uninstall-service.ps1` | Remove Windows Service | `scripts/` |
| `auto-update.ps1` | Auto-update mechanism | `scripts/` |
| `backup-config.ps1` | Backup configuration | `scripts/` |
| `restore-config.ps1` | Restore configuration | `scripts/` |

### Install Service Script

```powershell
# scripts/install-service.ps1

# Usage:
# .\install-service.ps1 [-ServiceName <string>] [-InstallPath <string>] [-AutoStart]

param(
    [string]$ServiceName = "LemonadeNexus",
    [string]$InstallPath = "C:\Program Files\LemonadeNexus",
    [switch]$AutoStart = $true
)

# Create service
New-Service -Name $ServiceName `
            -BinaryPathName "`"$InstallPath\lemonade-nexus.exe`"" `
            -DisplayName "Lemonade Nexus VPN Server" `
            -Description "Lemonade-Nexus Mesh VPN Server" `
            -StartupType $(if ($AutoStart) { "Automatic" } else { "Manual" })

# Configure recovery
$failureActions = @(
    @{ Type = "restart"; Delay = 60000 },
    @{ Type = "restart"; Delay = 60000 },
    @{ Type = "restart"; Delay = 60000 }
)

# Add firewall rules
New-NetFirewallRule -DisplayName "LemonadeNexus API" `
                    -Direction Inbound `
                    -Protocol TCP `
                    -LocalPort 9100,9101 `
                    -Action Allow

New-NetFirewallRule -DisplayName "LemonadeNexus WireGuard" `
                    -Direction Inbound `
                    -Protocol UDP `
                    -LocalPort 51820 `
                    -Action Allow

Write-Host "Service installed successfully" -ForegroundColor Green
```

### Auto-Update Script

```powershell
# scripts/auto-update.ps1

param(
    [string]$Repo = "antmi/lemonade-nexus",
    [string]$InstallPath = "C:\Program Files\LemonadeNexus"
)

# Check for updates
$releases = Invoke-RestMethod `
    "https://api.github.com/repos/$Repo/releases"

$latest = $releases[0]
$currentVersion = (Get-Item "$InstallPath\lemonade-nexus.exe").VersionInfo.ProductVersion

if ($latest.tag_name -ne "v$currentVersion") {
    Write-Host "Update available: $($latest.tag_name)" -ForegroundColor Yellow

    # Download installer
    $installer = $latest.assets | Where-Object name -like "*setup.exe"
    $tempPath = "$env:TEMP\lemonade-nexus-update.exe"
    Invoke-WebRequest $installer.browser_download_url -OutFile $tempPath

    # Stop service
    Stop-Service -Name LemonadeNexus -Force

    # Run installer silently
    Start-Process -FilePath $tempPath -ArgumentList "/S" -Wait

    # Restart service
    Start-Service -Name LemonadeNexus

    Write-Host "Update completed successfully" -ForegroundColor Green
} else {
    Write-Host "Already up to date" -ForegroundColor Green
}
```

### Running PowerShell Scripts

```powershell
# Check execution policy
Get-ExecutionPolicy

# If Restricted, allow local scripts
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# Run script
.\scripts\install-service.ps1

# Run with parameters
.\scripts\install-service.ps1 -ServiceName "MyVPN" -AutoStart:$false
```

---

## Service Management

### Using Services MMC

1. Press `Win + R`
2. Type `services.msc`
3. Find "Lemonade Nexus VPN Server"
4. Right-click for options: Start, Stop, Restart, Properties

### Using sc.exe

```powershell
# Check service status
sc query LemonadeNexus

# Start service
sc start LemonadeNexus

# Stop service
sc stop LemonadeNexus

# Get service configuration
sc qc LemonadeNexus

# Change startup type
sc config LemonadeNexus start= auto   # Automatic
sc config LemonadeNexus start= demand  # Manual
sc config LemonadeNexus start= disabled

# Delete service (uninstall)
sc delete LemonadeNexus
```

### Using PowerShell

```powershell
# Check status
Get-Service -Name LemonadeNexus

# Start
Start-Service -Name LemonadeNexus

# Stop
Stop-Service -Name LemonadeNexus

# Restart
Restart-Service -Name LemonadeNexus

# Set to automatic
Set-Service -Name LemonadeNexus -StartupType Automatic

# View event log
Get-EventLog -LogName Application -Source LemonadeNexus -Newest 50
```

### Service Recovery Configuration

```powershell
# Configure automatic restart on failure
sc failure LemonadeNexus `
    reset= 86400 `
    actions= restart/60000/restart/60000/restart/60000

# View current recovery settings
sc qfailure LemonadeNexus
```

---

## Configuration

### Server Configuration

#### Configuration File Location

```
%PROGRAMDATA%\LemonadeNexus\
├── config.json           # Main configuration
├── identity/
│   ├── keypair.pub       # Public key
│   └── keypair.enc       # Encrypted private key
└── data/
    └── ...               # Runtime data
```

#### Configuration File

```json
{
  "hostname": "vpn.example.com",
  "region": "us-west",
  "wireguard": {
    "port": 51820,
    "interface_name": "LemonadeNexus"
  },
  "api": {
    "public_port": 9100,
    "private_port": 9101,
    "use_tls": true
  },
  "dns": {
    "port": 5353,
    "upstream": "8.8.8.8"
  },
  "gossip": {
    "port": 9102,
    "peers": []
  },
  "logging": {
    "level": "info",
    "file": "C:\\ProgramData\\LemonadeNexus\\logs\\server.log"
  }
}
```

### Client Configuration

#### Configuration File Location

```
%APPDATA%\LemonadeNexus\
├── config.json           # User configuration
└── logs\
    └── client.log        # Client logs
```

#### Configuration File

```json
{
  "server": {
    "host": "vpn.example.com",
    "port": 443,
    "use_tls": true
  },
  "identity": {
    "path": "identity.json",
    "auto_generate": true
  },
  "wireguard": {
    "mtu": 1420,
    "keepalive": 25
  },
  "ui": {
    "theme": "dark",
    "auto_start": true,
    "minimize_to_tray": true
  }
}
```

### Identity Generation

```powershell
# Generate new identity (server)
& "C:\Program Files\LemonadeNexus\lemonade-nexus.exe" --generate-identity

# Output:
# Public Key: 6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b
# Identity saved to: C:\ProgramData\LemonadeNexus\identity\keypair.enc
```

---

## Uninstallation

### Server Uninstallation

```powershell
# 1. Stop the service
Stop-Service -Name LemonadeNexus -Force

# 2. Delete the service
sc delete LemonadeNexus

# 3. Run uninstaller (if installed via NSIS)
& "C:\Program Files\LemonadeNexus\uninstall.exe"

# Or manual removal:
Remove-Item "C:\Program Files\LemonadeNexus" -Recurse -Force
Remove-Item "C:\ProgramData\LemonadeNexus" -Recurse -Force

# 4. Remove firewall rules
Remove-NetFirewallRule -DisplayName "LemonadeNexus API"
Remove-NetFirewallRule -DisplayName "LemonadeNexus WireGuard"
```

### Client Uninstallation

```powershell
# MSIX package
Get-AppxPackage *LemonadeNexus* | Remove-AppxPackage

# MSI installer
msiexec /x {product-code} /quiet
# Or find product code in registry:
# HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\

# Portable installation
Remove-Item "C:\Apps\LemonadeNexus" -Recurse -Force
Remove-Item "$env:APPDATA\LemonadeNexus" -Recurse -Force
```

---

## Troubleshooting

### Installation Issues

#### Installer Won't Run

**Error:** "This application requires Windows 10 version 1809"

**Solution:**
```powershell
# Check Windows version
winver

# Minimum required: Windows 10 version 1809 (build 17763)
```

#### Service Installation Fails

**Error:** "Access is denied"

**Solution:** Run PowerShell as Administrator.

### Runtime Issues

#### Service Won't Start

```powershell
# Check event log
Get-EventLog -LogName Application -Source LemonadeNexus -Newest 20

# Run in console mode for debugging
& "C:\Program Files\LemonadeNexus\lemonade-nexus.exe" --console

# Check if port is in use
netstat -ano | findstr :9100
netstat -ano | findstr :51820
```

#### WireGuard Adapter Issues

```powershell
# Check if wireguard-nt is loaded
Get-WindowsDriver -Online | Where-Object Driver -like "*wireguard*"

# Reinstall wireguard-nt driver
sc stop LemonadeNexus
& "C:\Program Files\LemonadeNexus\lemonade-nexus.exe" --reinstall-driver
sc start LemonadeNexus
```

#### Client Won't Connect

```powershell
# Check server connectivity
Test-NetConnection vpn.example.com -Port 443

# Check DNS resolution
Resolve-DnsName vpn.example.com

# Check certificate (if using TLS)
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
$webClient = New-Object System.Net.WebClient
$webClient.DownloadString("https://vpn.example.com:9100/api/health")
```

### Log File Locations

| Component | Log Location |
|-----------|--------------|
| Server Service | `%PROGRAMDATA%\LemonadeNexus\logs\server.log` |
| Client Application | `%APPDATA%\LemonadeNexus\logs\client.log` |
| Windows Event Log | Application log, source: LemonadeNexus |
| WireGuard | `%PROGRAMDATA%\LemonadeNexus\logs\wireguard.log` |

### Getting Support

1. **Documentation** - Check [docs/](https://github.com/antmi/lemonade-nexus/tree/main/docs)
2. **Issues** - Report at [GitHub Issues](https://github.com/antmi/lemonade-nexus/issues)
3. **Discussions** - Ask at [GitHub Discussions](https://github.com/antmi/lemonade-nexus/discussions)

---

## Related Documentation

- [Windows Port](WINDOWS-PORT.md) - Server architecture details
- [Flutter Client](FLUTTER-CLIENT.md) - Client application details
- [Development Guide](DEVELOPMENT.md) - Building from source
- [Configuration](Configuration.md) - Advanced configuration options

---

**Document History:**

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-04-09 | Initial release |
