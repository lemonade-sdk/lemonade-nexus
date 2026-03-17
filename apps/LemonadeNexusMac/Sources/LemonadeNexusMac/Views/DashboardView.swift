import SwiftUI

struct DashboardView: View {
    @EnvironmentObject private var appState: AppState
    @State private var refreshTimer: Timer?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header
                SectionHeaderView(title: "Dashboard", icon: "gauge.with.dots.needle.33percent")

                // Top Stats Row
                statsRow

                // Mesh P2P Status Row
                meshStatusRow

                // Health & Connection Cards
                HStack(alignment: .top, spacing: 16) {
                    serverHealthCard
                    connectionStatusCard
                }

                // Trust & Network Info
                HStack(alignment: .top, spacing: 16) {
                    networkInfoCard
                    trustCard
                }

                // Recent Activity
                activitySection
            }
            .padding(24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.surfaceDark)
        .task {
            await appState.refreshAllData()
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button(action: { Task { await appState.refreshAllData() } }) {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh All Data")
            }
        }
    }

    // MARK: - Stats Row

    private var statsRow: some View {
        HStack(spacing: 16) {
            StatCard(
                title: "Peer Count",
                value: "\(appState.stats?.peer_count ?? 0)",
                icon: "person.3.fill",
                color: .lemonYellow
            )
            StatCard(
                title: "Servers",
                value: "\(appState.servers.count)",
                icon: "server.rack",
                color: .blue
            )
            StatCard(
                title: "Relays",
                value: "\(appState.relays.count)",
                icon: "antenna.radiowaves.left.and.right",
                color: .lemonGreen
            )
            StatCard(
                title: "Uptime",
                value: uptimeString,
                icon: "clock.fill",
                color: .orange
            )
        }
    }

    private var uptimeString: String {
        guard let since = appState.connectedSince else { return "--" }
        let interval = Date().timeIntervalSince(since)
        let hours = Int(interval) / 3600
        let minutes = (Int(interval) % 3600) / 60
        if hours > 0 {
            return "\(hours)h \(minutes)m"
        }
        return "\(minutes)m"
    }

    // MARK: - Mesh Status Row

    private var meshStatusRow: some View {
        HStack(spacing: 16) {
            // Tunnel status
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Label("Tunnel", systemImage: "lock.shield")
                        .font(.headline)
                    Spacer()
                    StatusDot(isHealthy: appState.tunnelIP != nil)
                }
                Divider()
                LabeledContent("Status") {
                    BadgeView(
                        text: appState.tunnelIP != nil ? "UP" : "DOWN",
                        color: appState.tunnelIP != nil ? .green : .gray
                    )
                }
                LabeledContent("Mesh") {
                    BadgeView(
                        text: appState.isMeshEnabled ? "ENABLED" : "DISABLED",
                        color: appState.isMeshEnabled ? .lemonGreen : .gray
                    )
                }
                if let ip = appState.meshStatus?.tunnel_ip, !ip.isEmpty {
                    LabeledContent("Mesh IP") {
                        Text(ip)
                            .font(.subheadline.monospaced())
                            .foregroundColor(.textSecondary)
                    }
                }
            }
            .cardStyle()
            .frame(maxWidth: .infinity)

            // Mesh peers
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Label("Mesh Peers", systemImage: "point.3.connected.trianglepath.dotted")
                        .font(.headline)
                    Spacer()
                }
                Divider()
                let online = appState.meshStatus?.online_count ?? 0
                let total = appState.meshStatus?.peer_count ?? 0
                LabeledContent("Online") {
                    Text("\(online) / \(total)")
                        .font(.subheadline.monospacedDigit())
                        .foregroundColor(online > 0 ? .green : .textSecondary)
                }
                LabeledContent("Direct") {
                    let direct = appState.meshPeers.filter { !$0.endpoint.isEmpty }.count
                    Text("\(direct)")
                        .font(.subheadline.monospacedDigit())
                        .foregroundColor(.textSecondary)
                }
                LabeledContent("Relayed") {
                    let relayed = appState.meshPeers.filter { $0.endpoint.isEmpty && !$0.relay_endpoint.isEmpty }.count
                    Text("\(relayed)")
                        .font(.subheadline.monospacedDigit())
                        .foregroundColor(.textSecondary)
                }
            }
            .cardStyle()
            .frame(maxWidth: .infinity)

            // Bandwidth
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Label("Bandwidth", systemImage: "arrow.up.arrow.down")
                        .font(.headline)
                    Spacer()
                }
                Divider()
                let rx = appState.meshStatus?.total_rx_bytes ?? 0
                let tx = appState.meshStatus?.total_tx_bytes ?? 0
                LabeledContent("Received") {
                    Text(formatDashboardBytes(rx))
                        .font(.subheadline.monospacedDigit())
                        .foregroundColor(.blue)
                }
                LabeledContent("Sent") {
                    Text(formatDashboardBytes(tx))
                        .font(.subheadline.monospacedDigit())
                        .foregroundColor(.orange)
                }
                LabeledContent("Total") {
                    Text(formatDashboardBytes(rx + tx))
                        .font(.subheadline.monospacedDigit())
                        .foregroundColor(.textSecondary)
                }
            }
            .cardStyle()
            .frame(maxWidth: .infinity)
        }
    }

    private func formatDashboardBytes(_ bytes: UInt64) -> String {
        let kb = Double(bytes) / 1024
        let mb = kb / 1024
        let gb = mb / 1024
        if gb >= 1 { return String(format: "%.1f GB", gb) }
        if mb >= 1 { return String(format: "%.1f MB", mb) }
        if kb >= 1 { return String(format: "%.0f KB", kb) }
        return "\(bytes) B"
    }

    // MARK: - Server Health Card

    private var serverHealthCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label("Server Health", systemImage: "heart.fill")
                    .font(.headline)
                Spacer()
                StatusDot(isHealthy: appState.isServerHealthy)
            }

            Divider()

            if let health = appState.healthStatus {
                LabeledContent("Status") {
                    BadgeView(
                        text: health.status.uppercased(),
                        color: appState.isServerHealthy ? .green : .red
                    )
                }
                LabeledContent("Service") {
                    Text(health.service)
                        .font(.subheadline.monospaced())
                        .foregroundColor(.textSecondary)
                }
            } else {
                HStack {
                    Image(systemName: "exclamationmark.triangle")
                        .foregroundColor(.orange)
                    Text("Unable to reach server")
                        .font(.subheadline)
                        .foregroundColor(.textSecondary)
                }
            }

            LabeledContent("URL") {
                Text(appState.serverURL)
                    .font(.caption.monospaced())
                    .foregroundColor(.textTertiary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .cardStyle()
        .frame(maxWidth: .infinity)
    }

    // MARK: - Connection Status Card

    private var connectionStatusCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label("Connection", systemImage: "network")
                    .font(.headline)
                Spacer()
                BadgeView(
                    text: appState.isAuthenticated ? "ACTIVE" : "INACTIVE",
                    color: appState.isAuthenticated ? .green : .gray
                )
            }

            Divider()

            if let tunnelIP = appState.tunnelIP {
                LabeledContent("Tunnel IP") {
                    Text(tunnelIP)
                        .font(.subheadline.monospaced())
                        .foregroundColor(.textSecondary)
                }
            }

            if let userId = appState.userId {
                LabeledContent("User ID") {
                    Text(userId)
                        .font(.caption.monospaced())
                        .foregroundColor(.textTertiary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }

            if let pubkey = appState.publicKeyBase64 {
                LabeledContent("Public Key") {
                    Text(String(pubkey.prefix(20)) + "...")
                        .font(.caption.monospaced())
                        .foregroundColor(.textTertiary)
                }
            }

            if let since = appState.connectedSince {
                LabeledContent("Connected Since") {
                    Text(since, style: .relative)
                        .font(.caption)
                        .foregroundColor(.textSecondary)
                }
            }

            if appState.isMeshEnabled {
                Divider()
                LabeledContent("Mesh Peers") {
                    let online = appState.meshStatus?.online_count ?? 0
                    let total = appState.meshStatus?.peer_count ?? 0
                    Text("\(online)/\(total) online")
                        .font(.caption.monospacedDigit())
                        .foregroundColor(online > 0 ? .green : .textTertiary)
                }
            }
        }
        .cardStyle()
        .frame(maxWidth: .infinity)
    }

    // MARK: - Network Info Card

    private var networkInfoCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label("Network", systemImage: "globe")
                    .font(.headline)
                Spacer()
            }

            Divider()

            if let stats = appState.stats {
                LabeledContent("Service") {
                    Text(stats.service)
                        .font(.subheadline.monospaced())
                        .foregroundColor(.textSecondary)
                }
                LabeledContent("Peer Count") {
                    Text("\(stats.peer_count)")
                        .font(.subheadline.monospacedDigit())
                        .foregroundColor(.textSecondary)
                }
                LabeledContent("Private API") {
                    BadgeView(
                        text: stats.private_api_enabled ? "ENABLED" : "DISABLED",
                        color: stats.private_api_enabled ? .green : .gray
                    )
                }
            } else {
                Text("No stats available")
                    .font(.subheadline)
                    .foregroundColor(.textTertiary)
            }

            LabeledContent("Mesh Servers") {
                Text("\(appState.servers.filter { $0.healthy }.count)/\(appState.servers.count) healthy")
                    .font(.subheadline)
                    .foregroundColor(.textSecondary)
            }
        }
        .cardStyle()
        .frame(maxWidth: .infinity)
    }

    // MARK: - Trust Card

    private var trustCard: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack {
                Label("Trust Status", systemImage: "shield.checkered")
                    .font(.headline)
                Spacer()
            }

            Divider()

            if let trust = appState.trustStatus {
                LabeledContent("Our Tier") {
                    BadgeView(
                        text: "TIER \(trust.our_tier)",
                        color: trust.our_tier == 1 ? .green : .orange
                    )
                }
                LabeledContent("Platform") {
                    Text(trust.our_platform)
                        .font(.subheadline)
                        .foregroundColor(.textSecondary)
                }
                LabeledContent("TEE Required") {
                    Image(systemName: trust.require_tee ? "checkmark.circle.fill" : "xmark.circle")
                        .foregroundColor(trust.require_tee ? .green : .textTertiary)
                }
                LabeledContent("Trusted Peers") {
                    Text("\(trust.peer_count)")
                        .font(.subheadline.monospacedDigit())
                        .foregroundColor(.textSecondary)
                }
            } else {
                Text("Trust data unavailable")
                    .font(.subheadline)
                    .foregroundColor(.textTertiary)
            }
        }
        .cardStyle()
        .frame(maxWidth: .infinity)
    }

    // MARK: - Activity Section

    private var activitySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeaderView(title: "Recent Activity", icon: "list.bullet.rectangle")

            if appState.activityLog.isEmpty {
                HStack {
                    Spacer()
                    Text("No recent activity")
                        .font(.subheadline)
                        .foregroundColor(.textTertiary)
                        .padding(.vertical, 24)
                    Spacer()
                }
                .cardStyle()
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(appState.activityLog.prefix(10))) { entry in
                        activityRow(entry)
                        if entry.id != appState.activityLog.prefix(10).last?.id {
                            Divider()
                                .padding(.horizontal, 8)
                        }
                    }
                }
                .cardStyle(padding: 8)
            }
        }
    }

    private func activityRow(_ entry: ActivityEntry) -> some View {
        HStack(spacing: 10) {
            Circle()
                .fill(activityColor(entry.level))
                .frame(width: 8, height: 8)

            Text(entry.message)
                .font(.subheadline)
                .foregroundColor(.textPrimary)
                .lineLimit(1)

            Spacer()

            Text(entry.timestamp, style: .relative)
                .font(.caption2)
                .foregroundColor(.textTertiary)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 6)
    }

    private func activityColor(_ level: ActivityLevel) -> Color {
        switch level {
        case .info: return .blue
        case .warning: return .orange
        case .error: return .red
        case .success: return .green
        }
    }
}
