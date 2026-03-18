import SwiftUI
import AppKit

/// Menu bar tray dropdown showing VPN status and quick actions.
struct VPNMenuView: View {
    @EnvironmentObject private var appState: AppState

    var body: some View {
        // Status
        if appState.isAuthenticated {
            if appState.isTunnelActive {
                Label("VPN: Connected", systemImage: "checkmark.circle.fill")
                    .foregroundColor(.green)
                if let ip = appState.tunnelIP {
                    Text("IP: \(ip)")
                        .font(.caption)
                }
            } else {
                Label("VPN: Disconnected", systemImage: "xmark.circle")
                    .foregroundColor(.secondary)
            }
        } else {
            Label("Not signed in", systemImage: "person.slash")
                .foregroundColor(.secondary)
        }

        Divider()

        // Connect / Disconnect
        if appState.isAuthenticated {
            Button(appState.isTunnelActive ? "Disconnect VPN" : "Connect VPN") {
                Task {
                    if appState.isTunnelActive {
                        await appState.disconnectTunnel()
                    } else {
                        await appState.connectTunnel()
                    }
                }
            }
            .disabled(appState.isTunnelTransitioning || appState.tunnelIP == nil)
        }

        Divider()

        // Open Manager
        Button("Open Manager") {
            NSApplication.shared.activate(ignoringOtherApps: true)
            if let window = NSApplication.shared.windows.first(where: { $0.canBecomeMain }) {
                window.makeKeyAndOrderFront(nil)
            }
        }
        .keyboardShortcut("o")

        Divider()

        Button("Quit Lemonade Nexus") {
            TunnelManager.shared.cleanupStaleHelper()
            NSApplication.shared.terminate(nil)
        }
        .keyboardShortcut("q")
    }
}
