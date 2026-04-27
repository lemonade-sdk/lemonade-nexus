# Command: Build UI Components

## Description
Delegates UI view creation to the UI Components Agent, replicating all 12 macOS SwiftUI views in Flutter.

## Purpose
Create a complete, polished Flutter UI that matches the macOS app functionality and design.

## Delegation Target
**UI Components Agent** (`../ui_components_agent/agent.md`)

## Steps

### 1. Invoke UI Agent
```
Delegate to UI Components Agent:
"Create Flutter UI components matching macOS app views"
```

### 2. UI Agent Deliverables

#### Core Views (6)
1. `login_view.dart` - Authentication screens
2. `dashboard_view.dart` - Main dashboard
3. `tunnel_control_view.dart` - Tunnel toggle/status
4. `peers_view.dart` - Peer list
5. `network_monitor_view.dart` - Network stats
6. `tree_browser_view.dart` - Tree navigation

#### Advanced Views (6)
7. `servers_view.dart` - Server list
8. `certificates_view.dart` - Cert management
9. `settings_view.dart` - App settings
10. `node_detail_view.dart` - Node details
11. `vpn_menu_view.dart` - System menu
12. `content_view.dart` - Main navigation

### 3. Shared Components
- Custom widgets library
- Theme configuration
- Navigation structure
- Responsive layouts

## macOS to Flutter View Mapping

| SwiftUI View | Flutter Equivalent | File |
|--------------|-------------------|------|
| ContentView | ContentView | content_view.dart |
| LoginView | LoginView | login_view.dart |
| DashboardView | DashboardView | dashboard_view.dart |
| TunnelControlView | TunnelControlView | tunnel_control_view.dart |
| PeersListView | PeersView | peers_view.dart |
| NetworkMonitorView | NetworkMonitorView | network_monitor_view.dart |
| TreeBrowserView | TreeBrowserView | tree_browser_view.dart |
| ServersView | ServersView | servers_view.dart |
| CertificatesView | CertificatesView | certificates_view.dart |
| SettingsView | SettingsView | settings_view.dart |
| NodeDetailView | NodeDetailView | node_detail_view.dart |
| VPNMenuView | VPNMenuView | vpn_menu_view.dart |

## SwiftUI to Flutter Widget Mapping

| SwiftUI | Flutter |
|---------|---------|
| `NavigationView` | `NavigationDrawer` / `NavigationRail` |
| `List` | `ListView.builder` |
| `VStack` | `Column` |
| `HStack` | `Row` |
| `@State` | `StatefulWidget` / `Provider` |
| `@EnvironmentObject` | `Provider.of<T>` |
| `.sheet` | `showModalBottomSheet` |
| `.alert` | `showDialog` |

## Expected Output
- 12 complete view files
- Shared widget library
- Theme system
- Navigation structure

## Success Criteria
- All views render correctly
- Matching functionality to macOS
- Responsive design
- Accessibility support
