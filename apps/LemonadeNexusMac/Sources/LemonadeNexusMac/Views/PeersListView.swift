import SwiftUI

struct PeersListView: View {
    @EnvironmentObject private var appState: AppState
    @State private var searchText = ""
    @State private var selectedPeer: NexusSDK.SDKMeshPeer?

    private var filteredPeers: [NexusSDK.SDKMeshPeer] {
        if searchText.isEmpty { return appState.meshPeers }
        let query = searchText.lowercased()
        return appState.meshPeers.filter {
            $0.hostname.lowercased().contains(query) ||
            $0.node_id.lowercased().contains(query) ||
            $0.tunnel_ip.lowercased().contains(query)
        }
    }

    var body: some View {
        HSplitView {
            // Peer list
            VStack(spacing: 0) {
                // Header
                HStack {
                    SectionHeaderView(title: "Mesh Peers", icon: "person.2.wave.2")
                    Spacer()
                    if !appState.meshPeers.isEmpty {
                        Text("\(appState.meshPeers.filter(\.is_online).count)/\(appState.meshPeers.count) online")
                            .font(.caption)
                            .foregroundColor(.textSecondary)
                    }
                }
                .padding(.horizontal, 24)
                .padding(.top, 24)
                .padding(.bottom, 12)

                if appState.meshPeers.isEmpty {
                    EmptyStateView(
                        icon: "person.2.slash",
                        title: "No Peers",
                        message: appState.isMeshEnabled
                            ? "No mesh peers discovered yet. Other clients must join your network group."
                            : "Enable mesh networking in the Tunnel tab to discover peers."
                    )
                } else {
                    List(filteredPeers, selection: $selectedPeer) { peer in
                        peerRow(peer)
                            .tag(peer)
                    }
                    .listStyle(.inset(alternatesRowBackgrounds: true))
                }
            }
            .frame(minWidth: 350)

            // Detail panel
            if let peer = selectedPeer {
                peerDetail(peer)
                    .frame(minWidth: 300)
            } else {
                VStack {
                    EmptyStateView(
                        icon: "person.circle",
                        title: "Select a Peer",
                        message: "Choose a peer from the list to view details."
                    )
                }
                .frame(minWidth: 300)
            }
        }
        .searchable(text: $searchText, prompt: "Search peers...")
        .background(Color.surfaceDark)
        .task {
            await appState.refreshMeshStatus()
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button(action: {
                    appState.refreshMeshPeers()
                    Task { await appState.refreshMeshStatus() }
                }) {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh Peers")
            }
        }
    }

    private func peerRow(_ peer: NexusSDK.SDKMeshPeer) -> some View {
        HStack(spacing: 12) {
            StatusDot(isHealthy: peer.is_online, size: 8)

            VStack(alignment: .leading, spacing: 2) {
                Text(peer.hostname.isEmpty ? peer.node_id : peer.hostname)
                    .font(.body)
                    .foregroundColor(.textPrimary)
                Text(peer.tunnel_ip)
                    .font(.caption.monospaced())
                    .foregroundColor(.textTertiary)
            }

            Spacer()

            if peer.latency_ms >= 0 {
                Text("\(peer.latency_ms)ms")
                    .font(.caption.monospacedDigit())
                    .foregroundColor(peer.latency_ms < 50 ? .green : peer.latency_ms < 150 ? .orange : .red)
            }

            VStack(alignment: .trailing, spacing: 1) {
                Label(formatBytes(peer.rx_bytes), systemImage: "arrow.down")
                    .font(.caption2)
                    .foregroundColor(.textTertiary)
                Label(formatBytes(peer.tx_bytes), systemImage: "arrow.up")
                    .font(.caption2)
                    .foregroundColor(.textTertiary)
            }
        }
        .padding(.vertical, 4)
    }

    private func peerDetail(_ peer: NexusSDK.SDKMeshPeer) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Header
                HStack(spacing: 12) {
                    ZStack {
                        Circle()
                            .fill((peer.is_online ? Color.green : Color.red).opacity(0.2))
                            .frame(width: 40, height: 40)
                        Image(systemName: peer.is_online ? "person.fill.checkmark" : "person.fill.xmark")
                            .foregroundColor(peer.is_online ? .green : .red)
                    }
                    VStack(alignment: .leading) {
                        Text(peer.hostname.isEmpty ? "Unnamed Peer" : peer.hostname)
                            .font(.title3.bold())
                        BadgeView(text: peer.is_online ? "Online" : "Offline",
                                  color: peer.is_online ? .green : .red)
                    }
                }

                Divider()

                detailRow("Node ID", peer.node_id)
                detailRow("Tunnel IP", peer.tunnel_ip)
                detailRow("Private Subnet", peer.private_subnet)
                detailRow("WG Public Key", String(peer.wg_pubkey.prefix(20)) + "...")
                detailRow("Endpoint", peer.endpoint.isEmpty ? "Unknown" : peer.endpoint)
                if !peer.relay_endpoint.isEmpty {
                    detailRow("Relay Endpoint", peer.relay_endpoint)
                }
                detailRow("Latency", peer.latency_ms >= 0 ? "\(peer.latency_ms) ms" : "Unknown")
                detailRow("Last Handshake", peer.last_handshake > 0
                    ? relativeTimeString(fromEpoch: UInt64(peer.last_handshake))
                    : "Never")
                detailRow("Received", formatBytes(peer.rx_bytes))
                detailRow("Sent", formatBytes(peer.tx_bytes))
                detailRow("Keepalive", "\(peer.keepalive)s")
            }
            .padding(24)
        }
        .background(Color.surfaceLight)
    }

    private func detailRow(_ label: String, _ value: String) -> some View {
        HStack {
            Text(label)
                .font(.subheadline)
                .foregroundColor(.textSecondary)
                .frame(width: 120, alignment: .trailing)
            Text(value)
                .font(.subheadline.monospaced())
                .foregroundColor(.textPrimary)
                .textSelection(.enabled)
            Spacer()
        }
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
