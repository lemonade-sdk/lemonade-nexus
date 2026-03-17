import SwiftUI

struct ContentView: View {
    @EnvironmentObject private var appState: AppState

    var body: some View {
        if appState.isAuthenticated {
            mainView
        } else {
            LoginView()
        }
    }

    private var mainView: some View {
        NavigationSplitView {
            sidebarView
        } detail: {
            detailView
        }
        .navigationSplitViewStyle(.balanced)
        .frame(minWidth: 900, minHeight: 600)
        .task {
            await appState.refreshAllData()
        }
    }

    // MARK: - Sidebar

    private var sidebarView: some View {
        List(SidebarItem.allCases, selection: $appState.selectedSidebarItem) { item in
            Label(item.rawValue, systemImage: item.sfSymbol)
                .tag(item)
        }
        .listStyle(.sidebar)
        .safeAreaInset(edge: .top) {
            sidebarHeader
        }
        .safeAreaInset(edge: .bottom) {
            sidebarFooter
        }
        .frame(minWidth: 200)
    }

    private var sidebarHeader: some View {
        VStack(spacing: 8) {
            HStack(spacing: 10) {
                ZStack {
                    Circle()
                        .fill(Color.lemonYellow.opacity(0.2))
                        .frame(width: 36, height: 36)
                    Image(systemName: "shield.checkered")
                        .foregroundColor(.lemonYellow)
                        .font(.system(size: 16))
                }
                VStack(alignment: .leading, spacing: 2) {
                    Text("Lemonade Nexus")
                        .font(.headline)
                        .foregroundColor(.textPrimary)
                    HStack(spacing: 4) {
                        StatusDot(isHealthy: appState.isServerHealthy, size: 6)
                        Text(appState.isServerHealthy ? "Connected" : "Disconnected")
                            .font(.caption2)
                            .foregroundColor(.textSecondary)
                    }
                }
                Spacer()
            }
            .padding(.horizontal, 16)
            .padding(.top, 12)
            .padding(.bottom, 8)

            Divider()
        }
    }

    private var sidebarFooter: some View {
        VStack(spacing: 0) {
            Divider()
            HStack {
                Image(systemName: "person.circle.fill")
                    .foregroundColor(.textSecondary)
                Text(appState.username.isEmpty ? "User" : appState.username)
                    .font(.caption)
                    .foregroundColor(.textSecondary)
                Spacer()
                Button(action: { appState.signOut() }) {
                    Image(systemName: "rectangle.portrait.and.arrow.right")
                        .foregroundColor(.textTertiary)
                }
                .buttonStyle(.plain)
                .help("Sign Out")
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 10)
        }
    }

    // MARK: - Detail View

    @ViewBuilder
    private var detailView: some View {
        switch appState.selectedSidebarItem {
        case .dashboard:
            DashboardView()
        case .tunnel:
            TunnelControlView()
        case .peers:
            PeersListView()
        case .network:
            NetworkMonitorView()
        case .endpoints:
            TreeBrowserView()
        case .servers:
            ServersView()
        case .certificates:
            CertificatesView()
        case .relays:
            RelaysView()
        case .settings:
            SettingsView()
        }
    }
}

// MARK: - Relays View (inline here since it's a simple list)

struct RelaysView: View {
    @EnvironmentObject private var appState: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                SectionHeaderView(title: "Relay Servers", icon: "antenna.radiowaves.left.and.right")

                if appState.relays.isEmpty {
                    EmptyStateView(
                        icon: "antenna.radiowaves.left.and.right",
                        title: "No Relays",
                        message: "No relay servers are currently registered in the mesh network."
                    )
                    .frame(height: 300)
                } else {
                    LazyVStack(spacing: 12) {
                        ForEach(appState.relays) { relay in
                            relayRow(relay)
                        }
                    }
                }
            }
            .padding(24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.surfaceDark)
        .task {
            await appState.refreshRelays()
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button(action: { Task { await appState.refreshRelays() } }) {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh Relays")
            }
        }
    }

    private func relayRow(_ relay: RelayInfoEntry) -> some View {
        HStack(spacing: 16) {
            Image(systemName: "antenna.radiowaves.left.and.right")
                .foregroundColor(.lemonYellow)
                .font(.title2)
                .frame(width: 40)

            VStack(alignment: .leading, spacing: 4) {
                Text(relay.endpoint)
                    .font(.headline)
                HStack(spacing: 12) {
                    Label(relay.region, systemImage: "globe")
                        .font(.caption)
                        .foregroundColor(.textSecondary)
                    if let latency = relay.latency_ms {
                        Label("\(Int(latency))ms", systemImage: "clock")
                            .font(.caption)
                            .foregroundColor(latency < 50 ? .green : latency < 150 ? .orange : .red)
                    }
                }
            }

            Spacer()

            if let load = relay.load {
                VStack(alignment: .trailing, spacing: 2) {
                    Text("\(Int(load * 100))%")
                        .font(.subheadline.monospacedDigit())
                        .foregroundColor(load < 0.5 ? .green : load < 0.8 ? .orange : .red)
                    Text("Load")
                        .font(.caption2)
                        .foregroundColor(.textTertiary)
                }
            }

            Text(relay.pubkey.prefix(12) + "...")
                .font(.caption.monospaced())
                .foregroundColor(.textTertiary)
        }
        .cardStyle()
    }
}
