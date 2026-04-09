# Command: Integrate Windows Native

## Description
Delegates Windows-specific integration to the Windows Integration Agent for system tray, service, and native API access.

## Purpose
Ensure the Flutter app integrates seamlessly with Windows for a native experience.

## Delegation Target
**Windows Integration Agent** (`../windows_integration_agent/agent.md`)

## Steps

### 1. Invoke Windows Agent
```
Delegate to Windows Integration Agent:
"Implement Windows-native integration for system tray, service, and auto-start"
```

### 2. Windows Agent Deliverables

#### System Tray Integration
- `tray_service.dart` - Tray menu management
- `tray_icons.dart` - Status icons
- Context menu with tunnel control

#### Windows Service
- Service wrapper for VPN tunnel
- Start/stop via Flutter
- Run on system startup

#### Auto-Start Configuration
- Registry key management
- Startup folder integration
- User preference handling

#### Native API Access
- Windows notification API
- Network status monitoring
- Clipboard integration

### 3. Integration Architecture

```
┌─────────────────────────────────────────────────────┐
│              Flutter Application                     │
└─────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│  tray_manager │  │  windows_rpc  │  │  win32       │
│  (Tray Menu)  │  │  (Service)    │  │  (Native)    │
└───────────────┘  └───────────────┘  └───────────────┘
        │                 │                 │
        └─────────────────┼─────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│              Windows OS APIs                         │
│  (Shell, Registry, Service Control Manager)         │
└─────────────────────────────────────────────────────┘
```

## Windows-Specific Features

### System Tray
- Minimize to tray
- Tunnel status icon
- Quick actions menu
- Show/hide window

### Windows Service
- Background tunnel management
- Start on boot
- Recovery options
- Event logging

### Native Integration
- Windows Hello (passkeys)
- Credential storage
- Network awareness
- Toast notifications

## Expected Output
- System tray functional
- Windows service configured
- Auto-start working
- Native APIs accessible

## Success Criteria
- Native Windows feel
- Reliable background operation
- Proper cleanup on exit
- No security warnings
