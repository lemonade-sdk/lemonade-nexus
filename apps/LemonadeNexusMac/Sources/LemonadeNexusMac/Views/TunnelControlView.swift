import SwiftUI

struct TunnelControlView: View {
    @EnvironmentObject private var appState: AppState

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                SectionHeaderView(title: "WireGuard Tunnel", icon: "network")

                // Tunnel toggle card
                tunnelCard

                // Mesh toggle card
                meshCard

                // Connection details
                if let status = appState.meshStatus, status.is_up {
                    connectionDetailsCard(status)
                }
            }
            .padding(24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.surfaceDark)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button(action: { Task { await appState.refreshMeshStatus() } }) {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh Status")
            }
        }
    }

    private var tunnelCard: some View {
        HStack(spacing: 16) {
            ZStack {
                Circle()
                    .fill((appState.tunnelIP != nil ? Color.green : Color.red).opacity(0.2))
                    .frame(width: 48, height: 48)
                Image(systemName: appState.tunnelIP != nil ? "checkmark.shield.fill" : "shield.slash")
                    .foregroundColor(appState.tunnelIP != nil ? .green : .red)
                    .font(.title2)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("Tunnel Status")
                    .font(.headline)
                Text(appState.tunnelIP != nil ? "Connected" : "Disconnected")
                    .font(.subheadline)
                    .foregroundColor(.textSecondary)
                if let ip = appState.tunnelIP {
                    Text(ip)
                        .font(.caption.monospaced())
                        .foregroundColor(.textTertiary)
                }
            }

            Spacer()

            if let since = appState.connectedSince {
                VStack(alignment: .trailing, spacing: 2) {
                    Text("Uptime")
                        .font(.caption2)
                        .foregroundColor(.textTertiary)
                    Text(since, style: .relative)
                        .font(.caption.monospacedDigit())
                        .foregroundColor(.textSecondary)
                }
            }
        }
        .cardStyle()
    }

    private var meshCard: some View {
        HStack(spacing: 16) {
            ZStack {
                Circle()
                    .fill((appState.isMeshEnabled ? Color.lemonYellow : Color.gray).opacity(0.2))
                    .frame(width: 48, height: 48)
                Image(systemName: appState.isMeshEnabled ? "person.2.wave.2.fill" : "person.2.slash")
                    .foregroundColor(appState.isMeshEnabled ? .lemonYellow : .gray)
                    .font(.title2)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("P2P Mesh Networking")
                    .font(.headline)
                Text(appState.isMeshEnabled ? "Active" : "Inactive")
                    .font(.subheadline)
                    .foregroundColor(.textSecondary)
                if let status = appState.meshStatus {
                    Text("\(status.online_count)/\(status.peer_count) peers online")
                        .font(.caption)
                        .foregroundColor(.textTertiary)
                }
            }

            Spacer()

            Button(action: { Task { await appState.toggleMesh() } }) {
                Text(appState.isMeshEnabled ? "Disable" : "Enable")
            }
            .buttonStyle(LemonButtonStyle(isProminent: !appState.isMeshEnabled))
        }
        .cardStyle()
    }

    private func connectionDetailsCard(_ status: NexusSDK.SDKMeshStatus) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeaderView(title: "Connection Details", icon: "info.circle")

            LazyVGrid(columns: [
                GridItem(.flexible()),
                GridItem(.flexible()),
                GridItem(.flexible()),
            ], spacing: 12) {
                StatCard(title: "Tunnel IP", value: status.tunnel_ip, icon: "network", color: .lemonGreen)
                StatCard(title: "Peers", value: "\(status.peer_count)", icon: "person.2", color: .lemonYellow)
                StatCard(title: "Online", value: "\(status.online_count)", icon: "wifi", color: .green)
            }

            HStack(spacing: 24) {
                Label(formatBytes(status.total_rx_bytes) + " received", systemImage: "arrow.down.circle")
                    .font(.caption)
                    .foregroundColor(.textSecondary)
                Label(formatBytes(status.total_tx_bytes) + " sent", systemImage: "arrow.up.circle")
                    .font(.caption)
                    .foregroundColor(.textSecondary)
            }
            .padding(.top, 4)
        }
        .cardStyle()
    }
}

private func formatBytes(_ bytes: UInt64) -> String {
    let kb = Double(bytes) / 1024
    let mb = kb / 1024
    let gb = mb / 1024
    if gb >= 1 { return String(format: "%.1f GB", gb) }
    if mb >= 1 { return String(format: "%.1f MB", mb) }
    if kb >= 1 { return String(format: "%.0f KB", kb) }
    return "\(bytes) B"
}
