import SwiftUI
import AppKit

struct ServersView: View {
    @EnvironmentObject private var appState: AppState
    @State private var selectedServer: ServerEntry?
    @State private var isLoading: Bool = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Header
                HStack {
                    SectionHeaderView(title: "Mesh Servers", icon: "server.rack")
                    Spacer()
                    serverCountBadge
                }

                if isLoading {
                    ProgressView("Loading servers...")
                        .frame(maxWidth: .infinity)
                        .padding(40)
                } else if appState.servers.isEmpty {
                    EmptyStateView(
                        icon: "server.rack",
                        title: "No Servers",
                        message: "No mesh servers are currently visible. Check your connection."
                    )
                    .frame(height: 300)
                } else {
                    serverList
                }
            }
            .padding(24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.surfaceDark)
        .task {
            isLoading = true
            await appState.refreshServers()
            isLoading = false
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button(action: {
                    Task {
                        isLoading = true
                        await appState.refreshServers()
                        isLoading = false
                    }
                }) {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh Servers")
            }
        }
        .sheet(item: $selectedServer) { server in
            ServerDetailSheet(server: server)
        }
    }

    // MARK: - Server Count Badge

    private var serverCountBadge: some View {
        let healthyCount = appState.servers.filter { $0.healthy }.count
        let totalCount = appState.servers.count
        return HStack(spacing: 6) {
            StatusDot(isHealthy: healthyCount > 0, size: 8)
            Text("\(healthyCount)/\(totalCount) healthy")
                .font(.subheadline)
                .foregroundColor(.textSecondary)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(Color(NSColor.controlBackgroundColor))
        .clipShape(Capsule())
    }

    // MARK: - Server List

    private var serverList: some View {
        LazyVStack(spacing: 12) {
            ForEach(appState.servers) { server in
                serverCard(server)
                    .onTapGesture { selectedServer = server }
            }
        }
    }

    private func serverCard(_ server: ServerEntry) -> some View {
        HStack(spacing: 16) {
            // Health indicator
            VStack {
                StatusDot(isHealthy: server.healthy, size: 12)
            }
            .frame(width: 20)

            // Server info
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Text(server.endpoint)
                        .font(.headline)
                        .foregroundColor(.textPrimary)

                    BadgeView(
                        text: server.healthy ? "HEALTHY" : "UNHEALTHY",
                        color: server.healthy ? .green : .red
                    )
                }

                HStack(spacing: 16) {
                    Label("Port \(server.http_port)", systemImage: "network")
                        .font(.caption)
                        .foregroundColor(.textSecondary)

                    Label(relativeTimeString(from: server.last_seen), systemImage: "clock")
                        .font(.caption)
                        .foregroundColor(.textTertiary)
                }
            }

            Spacer()

            // Pubkey preview
            VStack(alignment: .trailing, spacing: 4) {
                Text("Public Key")
                    .font(.caption2)
                    .foregroundColor(.textTertiary)
                Text(String(server.pubkey.prefix(16)) + "...")
                    .font(.caption.monospaced())
                    .foregroundColor(.textSecondary)
            }

            Image(systemName: "chevron.right")
                .foregroundColor(.textTertiary)
                .font(.caption)
        }
        .cardStyle()
        .contentShape(Rectangle())
    }
}

// MARK: - Server Detail Sheet

struct ServerDetailSheet: View {
    let server: ServerEntry

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            // Header
            HStack(spacing: 16) {
                ZStack {
                    RoundedRectangle(cornerRadius: 12)
                        .fill(server.healthy ? Color.green.opacity(0.15) : Color.red.opacity(0.15))
                        .frame(width: 56, height: 56)
                    Image(systemName: "server.rack")
                        .foregroundColor(server.healthy ? .green : .red)
                        .font(.title)
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text(server.endpoint)
                        .font(.title2.bold())
                    BadgeView(
                        text: server.healthy ? "HEALTHY" : "UNHEALTHY",
                        color: server.healthy ? .green : .red
                    )
                }

                Spacer()

                Button(action: { dismiss() }) {
                    Image(systemName: "xmark.circle.fill")
                        .foregroundColor(.textTertiary)
                        .font(.title2)
                }
                .buttonStyle(.plain)
            }

            Divider()

            // Details
            VStack(spacing: 12) {
                detailRow("Endpoint", value: server.endpoint)
                detailRow("HTTP Port", value: "\(server.http_port)")
                detailRow("Last Seen", value: formatDate(server.last_seen))
                detailRow("Health", value: server.healthy ? "Healthy" : "Unhealthy")

                Divider()

                VStack(alignment: .leading, spacing: 6) {
                    Text("Public Key")
                        .font(.caption)
                        .foregroundColor(.textSecondary)
                    Text(server.pubkey)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.textPrimary)
                        .textSelection(.enabled)
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(Color(NSColor.textBackgroundColor))
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                }

                HStack {
                    Button(action: {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(server.pubkey, forType: .string)
                    }) {
                        Label("Copy Public Key", systemImage: "doc.on.doc")
                    }
                    .buttonStyle(.bordered)

                    Spacer()
                }
            }

            Spacer()

            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .buttonStyle(LemonButtonStyle())
            }
        }
        .padding(24)
        .frame(width: 520, height: 500)
    }

    private func detailRow(_ label: String, value: String) -> some View {
        HStack {
            Text(label)
                .font(.subheadline)
                .foregroundColor(.textSecondary)
                .frame(width: 100, alignment: .leading)
            Text(value)
                .font(.subheadline)
                .foregroundColor(.textPrimary)
                .textSelection(.enabled)
            Spacer()
        }
    }
}
