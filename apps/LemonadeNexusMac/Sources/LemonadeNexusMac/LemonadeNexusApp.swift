import SwiftUI
import AppKit

@main
struct LemonadeNexusApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
                .frame(minWidth: 900, minHeight: 600)
                .onAppear {
                    configureAppearance()
                    // Clean up tunnel on app quit
                    NotificationCenter.default.addObserver(
                        forName: NSApplication.willTerminateNotification,
                        object: nil, queue: .main) { _ in
                            TunnelManager.shared.cleanupStaleHelper()
                        }
                    if appState.autoDiscoveryEnabled {
                        Task {
                            await appState.discoverNearestServer()
                            if appState.autoConnectOnLaunch {
                                attemptAutoConnect()
                            }
                        }
                    } else if appState.autoConnectOnLaunch {
                        attemptAutoConnect()
                    }
                }
        }
        .windowStyle(.titleBar)
        .defaultSize(width: 1100, height: 750)
        .commands {
            CommandGroup(replacing: .newItem) { }

            CommandGroup(after: .appInfo) {
                Button("Check for Updates...") {
                    // Placeholder for update check
                }
            }

            CommandMenu("Network") {
                Button("Refresh All") {
                    Task { await appState.refreshAllData() }
                }
                .keyboardShortcut("r", modifiers: .command)

                Divider()

                Button("Dashboard") {
                    appState.selectedSidebarItem = .dashboard
                }
                .keyboardShortcut("1", modifiers: .command)

                Button("Endpoints") {
                    appState.selectedSidebarItem = .endpoints
                }
                .keyboardShortcut("2", modifiers: .command)

                Button("Servers") {
                    appState.selectedSidebarItem = .servers
                }
                .keyboardShortcut("3", modifiers: .command)

                Button("Certificates") {
                    appState.selectedSidebarItem = .certificates
                }
                .keyboardShortcut("4", modifiers: .command)

                Button("Relays") {
                    appState.selectedSidebarItem = .relays
                }
                .keyboardShortcut("5", modifiers: .command)

                Divider()

                Button("Settings") {
                    appState.selectedSidebarItem = .settings
                }
                .keyboardShortcut(",", modifiers: .command)
            }
        }

        #if os(macOS)
        Settings {
            SettingsView()
                .environmentObject(appState)
                .frame(width: 600, height: 500)
        }
        #endif
    }

    private func configureAppearance() {
        // Kill any stale tunnel helper from a previous session
        TunnelManager.shared.cleanupStaleHelper()

        // Set the accent color globally
        NSApplication.shared.appearance = NSAppearance(named: .aqua)

        // When launched as a bare binary (not .app bundle), macOS may not
        // activate the process or make the window key.  Force both.
        NSApplication.shared.activate(ignoringOtherApps: true)
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            NSApplication.shared.windows.first?.makeKeyAndOrderFront(nil)
        }
    }

    private func attemptAutoConnect() {
        guard KeychainHelper.hasIdentity() else { return }
        do {
            let identity = try KeychainHelper.loadIdentity()
            let token = try? KeychainHelper.loadSessionToken()
            if let token = token {
                appState.sessionToken = token
                appState.publicKeyBase64 = identity.pubkey
                appState.username = identity.username
                appState.isAuthenticated = true
                appState.updateBaseURL()
                appState.sdk.setSessionToken(token)
                appState.connectedSince = Date()
                Task { await appState.refreshAllData() }
            }
        } catch {
            // Auto-connect failed silently; user can sign in manually
        }
    }
}
