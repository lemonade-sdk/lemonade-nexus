import SwiftUI

struct NetworkMonitorView: View {
    @EnvironmentObject private var appState: AppState
    @State private var refreshTimer: Timer?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                SectionHeaderView(title: "Network Monitor", icon: "chart.bar.xaxis")

                // Summary cards
                summaryCards

                // Peer topology
                if !appState.meshPeers.isEmpty {
                    peerTopology
                }

                // Bandwidth breakdown
                if let status = appState.meshStatus, !status.peers.isEmpty {
                    bandwidthBreakdown(status.peers)
                }
            }
            .padding(24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.surfaceDark)
        .onAppear { startAutoRefresh() }
        .onDisappear { stopAutoRefresh() }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button(action: { Task { await appState.refreshMeshStatus() } }) {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh")
            }
        }
    }

    private var summaryCards: some View {
        LazyVGrid(columns: [
            GridItem(.flexible()),
            GridItem(.flexible()),
            GridItem(.flexible()),
            GridItem(.flexible()),
        ], spacing: 12) {
            StatCard(
                title: "Total Peers",
                value: "\(appState.meshStatus?.peer_count ?? 0)",
                icon: "person.2",
                color: .lemonYellow
            )
            StatCard(
                title: "Online",
                value: "\(appState.meshStatus?.online_count ?? 0)",
                icon: "wifi",
                color: .green
            )
            StatCard(
                title: "Total Received",
                value: formatBytes(appState.meshStatus?.total_rx_bytes ?? 0),
                icon: "arrow.down.circle",
                color: .blue
            )
            StatCard(
                title: "Total Sent",
                value: formatBytes(appState.meshStatus?.total_tx_bytes ?? 0),
                icon: "arrow.up.circle",
                color: .orange
            )
        }
    }

    private var peerTopology: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeaderView(title: "Peer Topology", icon: "point.3.connected.trianglepath.dotted")

            LazyVStack(spacing: 8) {
                ForEach(appState.meshPeers) { peer in
                    HStack(spacing: 12) {
                        StatusDot(isHealthy: peer.is_online, size: 10)

                        VStack(alignment: .leading, spacing: 2) {
                            Text(peer.hostname.isEmpty ? peer.node_id.prefix(12) + "..." : peer.hostname)
                                .font(.body)
                            Text(peer.tunnel_ip)
                                .font(.caption.monospaced())
                                .foregroundColor(.textTertiary)
                        }

                        Spacer()

                        // Connection type indicator
                        if !peer.endpoint.isEmpty {
                            BadgeView(text: "Direct", color: .green)
                        } else if !peer.relay_endpoint.isEmpty {
                            BadgeView(text: "Relay", color: .orange)
                        } else {
                            BadgeView(text: "No Route", color: .red)
                        }

                        // Latency
                        if peer.latency_ms >= 0 {
                            Text("\(peer.latency_ms)ms")
                                .font(.caption.monospacedDigit())
                                .foregroundColor(latencyColor(peer.latency_ms))
                                .frame(width: 50, alignment: .trailing)
                        } else {
                            Text("--")
                                .font(.caption.monospacedDigit())
                                .foregroundColor(.textTertiary)
                                .frame(width: 50, alignment: .trailing)
                        }

                        // Bandwidth
                        VStack(alignment: .trailing, spacing: 1) {
                            Text(formatBytes(peer.rx_bytes))
                                .font(.caption2.monospacedDigit())
                                .foregroundColor(.textSecondary)
                            Text(formatBytes(peer.tx_bytes))
                                .font(.caption2.monospacedDigit())
                                .foregroundColor(.textSecondary)
                        }
                        .frame(width: 70, alignment: .trailing)
                    }
                    .padding(.vertical, 6)
                    .padding(.horizontal, 12)
                }
            }
            .cardStyle()
        }
    }

    private func bandwidthBreakdown(_ peers: [NexusSDK.SDKMeshPeer]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeaderView(title: "Bandwidth by Peer", icon: "chart.bar")

            let totalRx = peers.reduce(UInt64(0)) { $0 + $1.rx_bytes }
            let totalTx = peers.reduce(UInt64(0)) { $0 + $1.tx_bytes }
            let maxTotal = peers.map { $0.rx_bytes + $0.tx_bytes }.max() ?? 1

            ForEach(peers) { peer in
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        Text(peer.hostname.isEmpty ? String(peer.node_id.prefix(12)) : peer.hostname)
                            .font(.caption)
                            .foregroundColor(.textPrimary)
                        Spacer()
                        Text(formatBytes(peer.rx_bytes + peer.tx_bytes))
                            .font(.caption.monospacedDigit())
                            .foregroundColor(.textSecondary)
                    }

                    GeometryReader { geo in
                        let peerTotal = peer.rx_bytes + peer.tx_bytes
                        let fraction = maxTotal > 0 ? CGFloat(peerTotal) / CGFloat(maxTotal) : 0
                        HStack(spacing: 1) {
                            let rxFrac = peerTotal > 0 ? CGFloat(peer.rx_bytes) / CGFloat(peerTotal) : 0.5
                            Rectangle()
                                .fill(Color.blue.opacity(0.7))
                                .frame(width: geo.size.width * fraction * rxFrac)
                            Rectangle()
                                .fill(Color.orange.opacity(0.7))
                                .frame(width: geo.size.width * fraction * (1 - rxFrac))
                        }
                        .clipShape(RoundedRectangle(cornerRadius: 3))
                    }
                    .frame(height: 8)
                }
            }

            if totalRx + totalTx > 0 {
                HStack(spacing: 16) {
                    HStack(spacing: 4) {
                        Circle().fill(Color.blue.opacity(0.7)).frame(width: 8, height: 8)
                        Text("Received (\(formatBytes(totalRx)))")
                            .font(.caption2)
                            .foregroundColor(.textTertiary)
                    }
                    HStack(spacing: 4) {
                        Circle().fill(Color.orange.opacity(0.7)).frame(width: 8, height: 8)
                        Text("Sent (\(formatBytes(totalTx)))")
                            .font(.caption2)
                            .foregroundColor(.textTertiary)
                    }
                }
                .padding(.top, 4)
            }
        }
        .cardStyle()
    }

    private func latencyColor(_ ms: Int32) -> Color {
        if ms < 50 { return .green }
        if ms < 150 { return .orange }
        return .red
    }

    private func startAutoRefresh() {
        refreshTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { _ in
            Task { @MainActor in
                await appState.refreshMeshStatus()
            }
        }
    }

    private func stopAutoRefresh() {
        refreshTimer?.invalidate()
        refreshTimer = nil
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
