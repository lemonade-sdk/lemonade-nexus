# Utility: macOS to Flutter View Converter

## Description
Reference guide for converting macOS SwiftUI views to Flutter Dart views.

## Purpose
Help developers systematically convert each macOS view to its Flutter equivalent.

## Conversion Checklist

### For Each SwiftUI View File

#### 1. File Setup
- [ ] Create corresponding `.dart` file in `lib/src/views/`
- [ ] Add imports (flutter/material, provider, services)
- [ ] Create widget class extending StatelessWidget/StatefulWidget
- [ ] Add documentation comment referencing macOS source

#### 2. Structure Conversion
- [ ] Convert `@EnvironmentObject` to `Provider.of<T>` or `Consumer`
- [ ] Convert `@State` to local state or provider state
- [ ] Convert `var body: some View` to `Widget build(BuildContext context)`

#### 3. Layout Conversion
| SwiftUI | Flutter | Notes |
|---------|---------|-------|
| `VStack` | `Column` | Use `MainAxisAlignment` for spacing |
| `HStack` | `Row` | Use `MainAxisAlignment` for spacing |
| `ZStack` | `Stack` | Use `Positioned` for absolute |
| `Spacer()` | `Expanded()` or `SizedBox.expand` | |

#### 4. Widget Conversion
| SwiftUI | Flutter | Notes |
|---------|---------|-------|
| `Text` | `Text` | Direct equivalent |
| `TextField` | `TextField` | Use TextEditingController |
| `SecureField` | `TextField(obscureText: true)` | |
| `Button` | `ElevatedButton` | Or `TextButton` |
| `Toggle` | `Switch` | Use ValueNotifier or provider |
| `Picker` | `DropdownButton` | Different API |
| `List` | `ListView.builder` | For long lists |
| `ScrollView` | `SingleChildScrollView` | |
| `Image` | `Image` | Use `Image.asset` or `Image.network` |
| `Icon` | `Icon` | Material icons |
| `ProgressView` | `CircularProgressIndicator` | Or `LinearProgressIndicator` |

#### 5. Navigation Conversion
| SwiftUI | Flutter | Notes |
|---------|---------|-------|
| `NavigationView` | `NavigationRail` | Desktop |
| `NavigationView` | `NavigationDrawer` | Mobile-style |
| `NavigationLink` | `ListTile(onTap: navigate)` | |
| `.sheet` | `showModalBottomSheet` | |
| `.fullScreenCover` | `Navigator.push` | Full page |

#### 6. Modifier Conversion
| SwiftUI Modifier | Flutter Equivalent |
|------------------|-------------------|
| `.padding()` | `Padding` widget |
| `.background(Color)` | `Container(color: ...)` |
| `.foregroundColor()` | `Text(style: TextStyle(color: ...))` |
| `.font(.title)` | `Text(style: Theme.textTheme.titleLarge)` |
| `.cornerRadius()` | `Container(decoration: BoxDecoration(borderRadius: ...))` |
| `.shadow()` | `Container(decoration: BoxDecoration(boxShadow: ...))` |
| `.frame(width:height:)` | `SizedBox(width: height:)` |
| `.opacity()` | `Opacity` widget |
| `.disabled()` | Set `enabled` property on button |

## Example Conversion

### SwiftUI Source (LoginView.swift)
```swift
struct LoginView: View {
    @EnvironmentObject var appState: AppState
    @State private var username = ""
    @State private var password = ""

    var body: some View {
        VStack(spacing: 20) {
            Text("Login to Lemonade Nexus")
                .font(.title)

            TextField("Username", text: $username)
                .textFieldStyle(RoundedBorderTextFieldStyle())

            SecureField("Password", text: $password)
                .textFieldStyle(RoundedBorderTextFieldStyle())

            Button(action: {
                Task { await appState.login(username, password) }
            }) {
                Text("Login")
            }
            .disabled(appState.isAuthenticating)

            if appState.error != nil {
                Text(appState.error!)
                    .foregroundColor(.red)
            }
        }
        .padding()
    }
}
```

### Flutter Target (login_view.dart)
```dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../state/auth_state.dart';

/// Login view for authentication.
///
/// Converted from macOS SwiftUI: LoginView.swift
class LoginView extends StatelessWidget {
  const LoginView({super.key});

  @override
  Widget build(BuildContext context) {
    final authState = context.watch<AuthState>();
    final usernameController = TextEditingController();
    final passwordController = TextEditingController();

    return Padding(
      padding: const EdgeInsets.all(24.0),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            'Login to Lemonade Nexus',
            style: Theme.of(context).textTheme.headlineSmall,
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 32),
          TextField(
            controller: usernameController,
            decoration: const InputDecoration(
              labelText: 'Username',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 16),
          TextField(
            controller: passwordController,
            obscureText: true,
            decoration: const InputDecoration(
              labelText: 'Password',
              border: OutlineInputBorder(),
            ),
          ),
          const SizedBox(height: 24),
          ElevatedButton(
            onPressed: authState.isAuthenticating
                ? null
                : () => authState.login(
                      usernameController.text,
                      passwordController.text,
                    ),
            child: const Text('Login'),
          ),
          if (authState.error != null) ...[
            const SizedBox(height: 16),
            Text(
              authState.error!,
              style: const TextStyle(color: Colors.red),
              textAlign: TextAlign.center,
            ),
          ],
        ],
      ),
    );
  }
}
```

## Conversion Order

Convert views in this order for proper dependencies:

1. **Theme & Shared Widgets** (first)
   - `Theme.swift` → `app_theme.dart`
   - Shared components

2. **Core Views**
   - `ContentView` → Main navigation
   - `LoginView` → Authentication

3. **Main Feature Views**
   - `DashboardView` → Dashboard
   - `TunnelControlView` → Tunnel control
   - `PeersListView` → Peer list

4. **Advanced Views**
   - `NetworkMonitorView` → Network stats
   - `TreeBrowserView` → Tree navigation
   - `ServersView` → Server list
   - `CertificatesView` → Cert management
   - `SettingsView` → Settings
   - `NodeDetailView` → Node details
   - `VPNMenuView` → System tray menu

## Testing After Conversion

For each converted view:
- [ ] Widget compiles without errors
- [ ] Layout renders correctly
- [ ] All interactions work
- [ ] State updates propagate
- [ ] Visual comparison with macOS

## Related Files
- `templates/flutter-view-component.md` - View template
- `data/macos-app-structure.md` - macOS analysis
- macOS source files in `apps/LemonadeNexusMac/`
