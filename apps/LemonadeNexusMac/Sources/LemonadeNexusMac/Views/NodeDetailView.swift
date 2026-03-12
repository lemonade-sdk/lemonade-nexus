import SwiftUI
import AppKit

struct NodeDetailView: View {
    let node: TreeNode

    @EnvironmentObject private var appState: AppState
    @State private var isEditing: Bool = false
    @State private var editHostname: String = ""
    @State private var editRegion: String = ""
    @State private var showDeleteConfirmation: Bool = false
    @State private var isSaving: Bool = false
    @State private var statusMessage: String?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header
                headerSection

                Divider()

                // Properties
                propertiesSection

                Divider()

                // Network Info
                networkSection

                Divider()

                // Keys
                keysSection

                // Assignments
                if let assignments = node.assignments, !assignments.isEmpty {
                    Divider()
                    assignmentsSection(assignments)
                }

                Spacer(minLength: 20)

                // Actions
                actionsSection
            }
            .padding(24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.surfaceDark)
        .onAppear {
            editHostname = node.hostname
            editRegion = node.region ?? ""
        }
        .alert("Delete Node", isPresented: $showDeleteConfirmation) {
            Button("Cancel", role: .cancel) { }
            Button("Delete", role: .destructive) {
                Task { await deleteNode() }
            }
        } message: {
            Text("Are you sure you want to delete \"\(node.hostname)\"? This action cannot be undone.")
        }
    }

    // MARK: - Header

    private var headerSection: some View {
        HStack(spacing: 16) {
            ZStack {
                RoundedRectangle(cornerRadius: 12)
                    .fill(nodeColor.opacity(0.15))
                    .frame(width: 56, height: 56)
                Image(systemName: node.nodeType.sfSymbol)
                    .foregroundColor(nodeColor)
                    .font(.title)
            }

            VStack(alignment: .leading, spacing: 4) {
                if isEditing {
                    TextField("Hostname", text: $editHostname)
                        .font(.title2.bold())
                        .textFieldStyle(.roundedBorder)
                } else {
                    Text(node.hostname)
                        .font(.title2.bold())
                        .foregroundColor(.textPrimary)
                }
                HStack(spacing: 8) {
                    BadgeView(text: node.nodeType.displayName, color: nodeColor)
                    Text(node.id)
                        .font(.caption.monospaced())
                        .foregroundColor(.textTertiary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }

            Spacer()

            Button(action: { isEditing.toggle() }) {
                Image(systemName: isEditing ? "checkmark.circle.fill" : "pencil.circle")
                    .font(.title2)
                    .foregroundColor(isEditing ? .lemonGreen : .textSecondary)
            }
            .buttonStyle(.plain)
            .help(isEditing ? "Done Editing" : "Edit Node")
        }
    }

    // MARK: - Properties

    private var propertiesSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeaderView(title: "Properties", icon: "info.circle")

            VStack(spacing: 10) {
                propertyRow("Node ID", value: node.id, monospaced: true)
                propertyRow("Parent ID", value: node.parent_id, monospaced: true)
                propertyRow("Type", value: node.nodeType.displayName)

                if isEditing {
                    HStack {
                        Text("Hostname")
                            .font(.subheadline)
                            .foregroundColor(.textSecondary)
                            .frame(width: 120, alignment: .leading)
                        TextField("Hostname", text: $editHostname)
                            .textFieldStyle(.roundedBorder)
                    }
                    HStack {
                        Text("Region")
                            .font(.subheadline)
                            .foregroundColor(.textSecondary)
                            .frame(width: 120, alignment: .leading)
                        TextField("Region", text: $editRegion)
                            .textFieldStyle(.roundedBorder)
                    }
                } else {
                    propertyRow("Hostname", value: node.hostname)
                    if let region = node.region {
                        propertyRow("Region", value: region)
                    }
                }
            }
            .cardStyle()
        }
    }

    // MARK: - Network

    private var networkSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeaderView(title: "Network", icon: "network")

            VStack(spacing: 10) {
                if let tunnelIP = node.tunnel_ip {
                    propertyRow("Tunnel IP", value: tunnelIP, monospaced: true)
                }
                if let subnet = node.private_subnet {
                    propertyRow("Private Subnet", value: subnet, monospaced: true)
                }
                if let endpoint = node.listen_endpoint {
                    propertyRow("Listen Endpoint", value: endpoint, monospaced: true)
                }
            }
            .cardStyle()
        }
    }

    // MARK: - Keys

    private var keysSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeaderView(title: "Cryptographic Keys", icon: "key")

            VStack(spacing: 10) {
                if let mgmtKey = node.mgmt_pubkey {
                    keyRow("Management Key", value: mgmtKey)
                }
                if let wgKey = node.wg_pubkey {
                    keyRow("WireGuard Key", value: wgKey)
                }
            }
            .cardStyle()
        }
    }

    // MARK: - Assignments

    private func assignmentsSection(_ assignments: [NodeAssignment]) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeaderView(title: "Assignments (\(assignments.count))", icon: "person.badge.key")

            VStack(spacing: 8) {
                ForEach(assignments) { assignment in
                    VStack(alignment: .leading, spacing: 6) {
                        Text(assignment.management_pubkey)
                            .font(.caption.monospaced())
                            .foregroundColor(.textSecondary)
                            .lineLimit(1)
                            .truncationMode(.middle)

                        HStack(spacing: 4) {
                            ForEach(assignment.permissions, id: \.self) { perm in
                                BadgeView(
                                    text: perm,
                                    color: permissionColor(perm)
                                )
                            }
                        }
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.surfaceDark)
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }
            }
            .cardStyle()
        }
    }

    // MARK: - Actions

    private var actionsSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            if let message = statusMessage {
                HStack {
                    Image(systemName: "info.circle")
                        .foregroundColor(.blue)
                    Text(message)
                        .font(.caption)
                        .foregroundColor(.textSecondary)
                }
                .padding(10)
                .background(Color.blue.opacity(0.1))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            HStack(spacing: 12) {
                if isEditing {
                    Button(action: { Task { await saveChanges() } }) {
                        HStack {
                            if isSaving {
                                ProgressView()
                                    .scaleEffect(0.7)
                            }
                            Text("Save Changes")
                        }
                    }
                    .buttonStyle(LemonButtonStyle())
                    .disabled(isSaving)

                    Button("Cancel") {
                        isEditing = false
                        editHostname = node.hostname
                        editRegion = node.region ?? ""
                    }
                    .buttonStyle(LemonButtonStyle(isProminent: false))
                }

                Spacer()

                Button(role: .destructive, action: { showDeleteConfirmation = true }) {
                    HStack {
                        Image(systemName: "trash")
                        Text("Delete Node")
                    }
                }
                .buttonStyle(.bordered)
                .tint(.red)
            }
        }
    }

    // MARK: - Helpers

    private var nodeColor: Color {
        switch node.nodeType {
        case .root: return .purple
        case .customer: return .blue
        case .endpoint: return .lemonYellow
        case .relay: return .lemonGreen
        }
    }

    private func propertyRow(_ label: String, value: String, monospaced: Bool = false) -> some View {
        HStack {
            Text(label)
                .font(.subheadline)
                .foregroundColor(.textSecondary)
                .frame(width: 120, alignment: .leading)
            Text(value)
                .font(monospaced ? .subheadline.monospaced() : .subheadline)
                .foregroundColor(.textPrimary)
                .textSelection(.enabled)
            Spacer()
        }
    }

    private func keyRow(_ label: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.caption)
                .foregroundColor(.textSecondary)
            HStack {
                Text(value)
                    .font(.caption.monospaced())
                    .foregroundColor(.textPrimary)
                    .lineLimit(2)
                    .textSelection(.enabled)
                Spacer()
                Button(action: {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(value, forType: .string)
                    statusMessage = "Copied \(label) to clipboard"
                }) {
                    Image(systemName: "doc.on.doc")
                        .font(.caption)
                        .foregroundColor(.textTertiary)
                }
                .buttonStyle(.plain)
            }
        }
    }

    private func permissionColor(_ perm: String) -> Color {
        switch perm {
        case "read": return .blue
        case "write": return .orange
        case "admin": return .red
        case "manage": return .purple
        default: return .gray
        }
    }

    // MARK: - Actions

    private func saveChanges() async {
        isSaving = true
        statusMessage = nil

        if editHostname != node.hostname {
            let delta = TreeDelta(
                node_id: node.id,
                field: "hostname",
                value: editHostname,
                author_pubkey: appState.publicKeyBase64 ?? "",
                signature: ""
            )
            do {
                let response = try await appState.client.submitTreeDelta(delta)
                if response.success {
                    statusMessage = "Hostname updated"
                    appState.addActivity(.success, "Updated hostname for \(node.id)")
                } else {
                    statusMessage = response.error ?? "Failed to update hostname"
                }
            } catch {
                statusMessage = error.localizedDescription
            }
        }

        isEditing = false
        isSaving = false
    }

    private func deleteNode() async {
        let delta = TreeDelta(
            node_id: node.id,
            field: "delete",
            value: "true",
            author_pubkey: appState.publicKeyBase64 ?? "",
            signature: ""
        )
        do {
            let response = try await appState.client.submitTreeDelta(delta)
            if response.success {
                appState.addActivity(.success, "Deleted node: \(node.hostname)")
            } else {
                appState.addActivity(.error, "Failed to delete: \(response.error ?? "unknown")")
            }
        } catch {
            appState.addActivity(.error, "Delete failed: \(error.localizedDescription)")
        }
    }
}
