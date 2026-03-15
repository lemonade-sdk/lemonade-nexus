import SwiftUI

struct TreeBrowserView: View {
    @EnvironmentObject private var appState: AppState
    @State private var searchText: String = ""
    @State private var selectedNode: TreeNode?
    @State private var rootId: String = "root"
    @State private var isLoadingTree: Bool = false
    @State private var showingAddSheet: Bool = false
    @State private var showingDeleteConfirmation: Bool = false
    @State private var localTreeNodes: [TreeNode] = []

    var filteredNodes: [TreeNode] {
        if searchText.isEmpty {
            return localTreeNodes
        }
        return localTreeNodes.filter { node in
            node.hostname.localizedCaseInsensitiveContains(searchText) ||
            node.id.localizedCaseInsensitiveContains(searchText) ||
            node.type.localizedCaseInsensitiveContains(searchText) ||
            (node.tunnel_ip?.localizedCaseInsensitiveContains(searchText) ?? false) ||
            (node.region?.localizedCaseInsensitiveContains(searchText) ?? false)
        }
    }

    var body: some View {
        HSplitView {
            // Tree List
            VStack(spacing: 0) {
                // Search Bar
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.textTertiary)
                    TextField("Search nodes...", text: $searchText)
                        .textFieldStyle(.plain)
                }
                .padding(10)
                .background(Color(NSColor.controlBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 8))
                .padding(.horizontal, 12)
                .padding(.vertical, 8)

                Divider()

                if isLoadingTree {
                    ProgressView("Loading tree...")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if filteredNodes.isEmpty {
                    EmptyStateView(
                        icon: "point.3.connected.trianglepath.dotted",
                        title: "No Nodes",
                        message: searchText.isEmpty
                            ? "No tree nodes found. The network tree may be empty."
                            : "No nodes match your search."
                    )
                } else {
                    List(filteredNodes, selection: $selectedNode) { node in
                        nodeRow(node)
                            .tag(node)
                    }
                    .listStyle(.inset(alternatesRowBackgrounds: true))
                }
            }
            .frame(minWidth: 220, idealWidth: 300, maxWidth: 450)

            // Detail Panel
            if let node = selectedNode {
                NodeDetailView(node: node)
                    .frame(minWidth: 400, idealWidth: 550)
            } else {
                VStack(spacing: 16) {
                    Image(systemName: "sidebar.squares.right")
                        .font(.system(size: 48))
                        .foregroundColor(.textTertiary)
                    Text("Select a node")
                        .font(.headline)
                        .foregroundColor(.textSecondary)
                    Text("Choose a node from the tree to view its details.")
                        .font(.subheadline)
                        .foregroundColor(.textTertiary)
                        .multilineTextAlignment(.center)
                }
                .frame(minWidth: 400, idealWidth: 550, maxWidth: .infinity, maxHeight: .infinity)
                .background(Color.surfaceDark)
            }
        }
        .task {
            await loadTree()
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button(action: { showingAddSheet = true }) {
                    Image(systemName: "plus")
                }
                .help("Add Node")

                Button(action: { Task { await loadTree() } }) {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh Tree")
            }
        }
        .sheet(isPresented: $showingAddSheet) {
            AddNodeSheet(parentId: selectedNode?.id ?? rootId) {
                Task { await loadTree() }
            }
        }
    }

    // MARK: - Node Row

    private func nodeRow(_ node: TreeNode) -> some View {
        HStack(spacing: 10) {
            Image(systemName: node.nodeType.sfSymbol)
                .foregroundColor(nodeColor(node.nodeType))
                .font(.title3)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 2) {
                Text(node.hostname)
                    .font(.body)
                    .foregroundColor(.textPrimary)
                    .lineLimit(1)

                HStack(spacing: 8) {
                    BadgeView(text: node.nodeType.displayName, color: nodeColor(node.nodeType))

                    if let ip = node.tunnel_ip {
                        Text(ip)
                            .font(.caption.monospaced())
                            .foregroundColor(.textTertiary)
                    }

                    if let region = node.region {
                        Label(region, systemImage: "globe")
                            .font(.caption2)
                            .foregroundColor(.textTertiary)
                    }
                }
            }

            Spacer()
        }
        .padding(.vertical, 4)
    }

    private func nodeColor(_ type: NodeType) -> Color {
        switch type {
        case .root: return .purple
        case .customer: return .blue
        case .endpoint: return .lemonYellow
        case .relay: return .lemonGreen
        }
    }

    // MARK: - Load Tree

    private func loadTree() async {
        isLoadingTree = true
        do {
            var nodes: [TreeNode] = []
            // Load the root node itself via SDK
            if let rootDict = try? appState.sdk.getTreeNode(id: rootId) {
                let rootData = try JSONSerialization.data(withJSONObject: rootDict, options: [])
                let root = try JSONDecoder().decode(TreeNode.self, from: rootData)
                nodes.append(root)
                appState.rootNode = root
            }
            // Then load children
            let childDicts = try appState.sdk.getTreeChildren(parentId: rootId)
            let childData = try JSONSerialization.data(withJSONObject: childDicts, options: [])
            let children = try JSONDecoder().decode([TreeNode].self, from: childData)
            nodes.append(contentsOf: children)
            localTreeNodes = nodes
        } catch {
            appState.addActivity(.error, "Failed to load tree: \(error.localizedDescription)")
        }
        isLoadingTree = false
    }
}

// MARK: - Add Node Sheet

struct AddNodeSheet: View {
    let parentId: String
    let onComplete: () -> Void

    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var hostname: String = ""
    @State private var nodeType: NodeType = .endpoint
    @State private var region: String = ""
    @State private var errorMessage: String?
    @State private var isSubmitting: Bool = false

    private static func generateHostname() -> String {
        let base = ProcessInfo.processInfo.hostName
            .replacingOccurrences(of: ".local", with: "")
            .replacingOccurrences(of: ".lan", with: "")
            .lowercased()
            .replacingOccurrences(of: " ", with: "-")
        let suffix = String(format: "%04d", Int.random(in: 1000...9999))
        return "\(base)-\(suffix)"
    }

    private static func detectRegion() -> String {
        let tz = TimeZone.current.identifier.lowercased()
        if tz.contains("america/los_angeles") || tz.contains("america/denver")
            || tz.contains("america/phoenix") || tz.contains("america/boise")
            || tz.contains("america/anchorage") || tz.contains("pacific/honolulu") {
            return "us-west"
        } else if tz.contains("america/chicago") || tz.contains("america/indiana")
            || tz.contains("america/menominee") || tz.contains("america/north_dakota") {
            return "us-central"
        } else if tz.contains("america/new_york") || tz.contains("america/detroit")
            || tz.contains("america/kentucky") {
            return "us-east"
        } else if tz.contains("europe/") {
            return "eu-west"
        } else if tz.contains("asia/tokyo") || tz.contains("asia/seoul") {
            return "ap-northeast"
        } else if tz.contains("asia/") {
            return "ap-southeast"
        } else if tz.contains("australia/") || tz.contains("pacific/auckland") {
            return "ap-south"
        } else if tz.contains("america/sao_paulo") || tz.contains("america/argentina") {
            return "sa-east"
        }
        return Locale.current.region?.identifier.lowercased() ?? "unknown"
    }

    var body: some View {
        VStack(spacing: 20) {
            Text("Add New Node")
                .font(.title2.bold())

            Form {
                LabeledContent("Hostname") {
                    Text(hostname)
                        .foregroundColor(.textSecondary)
                }
                Picker("Type", selection: $nodeType) {
                    ForEach(NodeType.allCases, id: \.self) { type in
                        Text(type.displayName).tag(type)
                    }
                }
                LabeledContent("Region") {
                    Text(region)
                        .foregroundColor(.textSecondary)
                }

                LabeledContent("Parent ID") {
                    Text(parentId)
                        .font(.caption.monospaced())
                        .foregroundColor(.textSecondary)
                }
            }
            .formStyle(.grouped)
            .onAppear {
                if hostname.isEmpty { hostname = Self.generateHostname() }
                if region.isEmpty { region = Self.detectRegion() }
            }

            if let error = errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
            }

            HStack {
                Button("Cancel") { dismiss() }
                    .buttonStyle(LemonButtonStyle(isProminent: false))

                Button("Add Node") {
                    Task { await addNode() }
                }
                .buttonStyle(LemonButtonStyle())
                .disabled(hostname.isEmpty || isSubmitting)
            }
        }
        .padding(24)
        .frame(width: 420)
    }

    private func addNode() async {
        isSubmitting = true
        errorMessage = nil

        do {
            let response = try appState.createChildNode(
                parentId: parentId,
                nodeType: nodeType.rawValue
            )
            if response.success == true {
                appState.addActivity(.success, "Added node: \(hostname)")
                onComplete()
                dismiss()
            } else {
                errorMessage = response.error ?? "Failed to add node"
            }
        } catch {
            errorMessage = error.localizedDescription
        }

        isSubmitting = false
    }
}
