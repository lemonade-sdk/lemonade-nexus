import SwiftUI

struct PeersListView: View {
    @EnvironmentObject private var appState: AppState
    @State private var searchText = ""
    @State private var selectedPeer: NexusSDK.SDKMeshPeer?

    private var filteredPeers: [NexusSDK.SDKMeshPeer] {
        if searchText.isEmpty { return appState.meshPeers }
        let query = searchText.lowercased()
        return appState.meshPeers.filter {
            ($0.hostname ?? "").lowercased().contains(query) ||
            $0.node_id.lowercased().contains(query) ||
            ($0.tunnel_ip ?? "").lowercased().contains(query)
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
                        Text("\(appState.meshPeers.filter { $0.is_online ?? false }.count)/\(appState.meshPeers.count) online")
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
            StatusDot(isHealthy: peer.is_online ?? false, size: 8)

            VStack(alignment: .leading, spacing: 2) {
                let hostname = peer.hostname ?? ""
                Text(hostname.isEmpty ? peer.node_id : hostname)
                    .font(.body)
                    .foregroundColor(.textPrimary)
                    .lineLimit(1)
                Text(peer.tunnel_ip ?? "—")
                    .font(.caption.monospaced())
                    .foregroundColor(.textTertiary)
            }

            Spacer()

            let latency = peer.latency_ms ?? -1
            if latency >= 0 {
                Text("\(latency)ms")
                    .font(.caption.monospacedDigit())
                    .foregroundColor(latency < 50 ? .green : latency < 150 ? .orange : .red)
            }

            VStack(alignment: .trailing, spacing: 1) {
                Label(formatBytes(peer.rx_bytes ?? 0), systemImage: "arrow.down")
                    .font(.caption2)
                    .foregroundColor(.textTertiary)
                Label(formatBytes(peer.tx_bytes ?? 0), systemImage: "arrow.up")
                    .font(.caption2)
                    .foregroundColor(.textTertiary)
            }
        }
        .padding(.vertical, 4)
    }

    private func peerDetail(_ peer: NexusSDK.SDKMeshPeer) -> some View {
        let isOnline = peer.is_online ?? false
        let hostname = peer.hostname ?? ""
        return ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Header
                HStack(spacing: 12) {
                    ZStack {
                        Circle()
                            .fill((isOnline ? Color.green : Color.red).opacity(0.2))
                            .frame(width: 40, height: 40)
                        Image(systemName: isOnline ? "person.fill.checkmark" : "person.fill.xmark")
                            .foregroundColor(isOnline ? .green : .red)
                    }
                    VStack(alignment: .leading) {
                        Text(hostname.isEmpty ? "Unnamed Peer" : hostname)
                            .font(.title3.bold())
                            .lineLimit(1)
                        BadgeView(text: isOnline ? "Online" : "Offline",
                                  color: isOnline ? .green : .red)
                    }
                }

                Divider()

                detailRow("Node ID", peer.node_id)
                detailRow("Tunnel IP", peer.tunnel_ip ?? "—")
                detailRow("Private Subnet", peer.private_subnet ?? "—")
                let pubkey = peer.wg_pubkey ?? ""
                detailRow("WG Public Key", pubkey.isEmpty ? "—" : String(pubkey.prefix(20)) + "...")
                let endpoint = peer.endpoint ?? ""
                detailRow("Endpoint", endpoint.isEmpty ? "Unknown" : endpoint)
                let relay = peer.relay_endpoint ?? ""
                if !relay.isEmpty {
                    detailRow("Relay Endpoint", relay)
                }
                let latency = peer.latency_ms ?? -1
                detailRow("Latency", latency >= 0 ? "\(latency) ms" : "Unknown")
                let handshake = peer.last_handshake ?? 0
                detailRow("Last Handshake", handshake > 0
                    ? relativeTimeString(fromEpoch: UInt64(handshake))
                    : "Never")
                detailRow("Received", formatBytes(peer.rx_bytes ?? 0))
                detailRow("Sent", formatBytes(peer.tx_bytes ?? 0))
                detailRow("Keepalive", "\(peer.keepalive ?? 0)s")
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
                .lineLimit(1)
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
