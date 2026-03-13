import SwiftUI
import AuthenticationServices

struct LoginView: View {
    @EnvironmentObject private var appState: AppState
    @State private var serverURL: String = ""
    @State private var username: String = ""
    @State private var password: String = ""
    @State private var selectedTab: AuthTab = .password
    @State private var isRegistering: Bool = false
    @State private var statusMessage: String?
    @State private var isError: Bool = false
    @State private var showManualURL: Bool = false

    enum AuthTab: String, CaseIterable {
        case password = "Password"
        case passkey = "Passkey"
    }

    var body: some View {
        VStack(spacing: 0) {
            Spacer()

            // Logo
            logoView
                .padding(.bottom, 8)

            Text("Lemonade Nexus")
                .font(.system(size: 28, weight: .bold, design: .rounded))
                .foregroundColor(.textPrimary)
                .padding(.bottom, 4)

            Text("Secure Mesh VPN")
                .font(.subheadline)
                .foregroundColor(.textSecondary)
                .padding(.bottom, 32)

            // Login Card
            VStack(spacing: 20) {
                // Server connection status
                serverConnectionSection
                    .onAppear {
                        serverURL = appState.serverURL
                    }
                    .onChange(of: serverURL) { _, newValue in
                        appState.serverURL = newValue
                    }
                    .onChange(of: appState.serverURL) { _, newValue in
                        serverURL = newValue
                    }

                // Tab Selection
                Picker("Authentication", selection: $selectedTab) {
                    ForEach(AuthTab.allCases, id: \.self) { tab in
                        Text(tab.rawValue).tag(tab)
                    }
                }
                .pickerStyle(.segmented)

                // Tab Content
                switch selectedTab {
                case .password:
                    passwordTabContent
                case .passkey:
                    passkeyTabContent
                }

                // Status Message
                if let message = statusMessage {
                    HStack {
                        Image(systemName: isError ? "exclamationmark.triangle.fill" : "info.circle.fill")
                            .foregroundColor(isError ? .red : .blue)
                        Text(message)
                            .font(.caption)
                            .foregroundColor(isError ? .red : .textSecondary)
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background((isError ? Color.red : Color.blue).opacity(0.1))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }

                if let errorMsg = appState.errorMessage {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.red)
                        Text(errorMsg)
                            .font(.caption)
                            .foregroundColor(.red)
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color.red.opacity(0.1))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }
            }
            .cardStyle(padding: 24)
            .frame(maxWidth: 380)

            Spacer()

            // Footer
            Text("v0.1.0")
                .font(.caption2)
                .foregroundColor(.textTertiary)
                .padding(.bottom, 16)
        }
        .frame(minWidth: 500, minHeight: 600)
        .background(Color.surfaceDark)
        .overlay {
            if appState.isLoading {
                LoadingOverlay(message: isRegistering ? "Registering..." : "Signing in...")
            }
        }
    }

    // MARK: - Logo

    private var logoView: some View {
        ZStack {
            // Lemon shape
            Ellipse()
                .fill(Color.lemonYellow)
                .frame(width: 80, height: 60)
                .shadow(color: Color.lemonYellow.opacity(0.4), radius: 10)

            // Network lines inside
            Path { path in
                path.move(to: CGPoint(x: 30, y: 10))
                path.addLine(to: CGPoint(x: 50, y: 30))
                path.addLine(to: CGPoint(x: 30, y: 50))
                path.move(to: CGPoint(x: 50, y: 10))
                path.addLine(to: CGPoint(x: 50, y: 50))
                path.move(to: CGPoint(x: 20, y: 30))
                path.addLine(to: CGPoint(x: 60, y: 30))
            }
            .stroke(Color.black.opacity(0.3), lineWidth: 1)
            .frame(width: 80, height: 60)

            // Node dots
            ForEach(nodePositions, id: \.0) { pos in
                Circle()
                    .fill(Color.nodeOrange)
                    .frame(width: 6, height: 6)
                    .offset(x: pos.1, y: pos.2)
            }

            // Leaf
            Path { path in
                path.move(to: CGPoint(x: 40, y: 0))
                path.addQuadCurve(to: CGPoint(x: 55, y: -10),
                                  control: CGPoint(x: 50, y: -12))
                path.addQuadCurve(to: CGPoint(x: 40, y: 0),
                                  control: CGPoint(x: 48, y: -2))
            }
            .fill(Color.lemonGreen)
            .offset(y: -25)
        }
        .frame(width: 100, height: 100)
    }

    private var nodePositions: [(Int, CGFloat, CGFloat)] {
        [
            (0, -10, -20),
            (1, 10, 0),
            (2, -10, 20),
            (3, 10, -20),
            (4, 10, 20),
            (5, -20, 0),
        ]
    }

    // MARK: - Server Connection

    private var serverConnectionSection: some View {
        VStack(alignment: .leading, spacing: 6) {
            if appState.isDiscovering {
                // Discovering state
                HStack(spacing: 8) {
                    ProgressView()
                        .controlSize(.small)
                    Text("Discovering servers on lemonade-nexus.io...")
                        .font(.caption)
                        .foregroundColor(.textSecondary)
                }
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.vertical, 4)
            } else if !appState.discoveredServers.isEmpty && !showManualURL {
                // Discovery succeeded — show connected server, no text field
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.circle.fill")
                        .foregroundColor(.green)
                        .font(.caption)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Connected to \(appState.discoveredServers.first?.displayName ?? "")")
                            .font(.caption)
                            .foregroundColor(.textPrimary)
                        Text("\(appState.discoveredServers.count) server\(appState.discoveredServers.count == 1 ? "" : "s") found — \(Int(appState.discoveredServers.first?.latencyMs ?? 0))ms latency")
                            .font(.caption2)
                            .foregroundColor(.textTertiary)
                    }
                    Spacer()
                    Button(action: { Task { await appState.discoverNearestServer() } }) {
                        Image(systemName: "arrow.clockwise")
                            .font(.caption)
                    }
                    .buttonStyle(.plain)
                    .foregroundColor(.textTertiary)
                }

                // Server picker if multiple
                if appState.discoveredServers.count > 1 {
                    DisclosureGroup("Switch server") {
                        ForEach(appState.discoveredServers) { server in
                            HStack {
                                Image(systemName: server.url == serverURL ? "circle.inset.filled" : "circle")
                                    .font(.caption2)
                                    .foregroundColor(server.url == serverURL ? .lemonYellow : .textTertiary)
                                VStack(alignment: .leading, spacing: 1) {
                                    Text(server.displayName)
                                        .font(.caption)
                                        .foregroundColor(.textPrimary)
                                    if server.hostname != nil {
                                        Text(server.ip)
                                            .font(.caption2)
                                            .foregroundColor(.textTertiary)
                                    }
                                }
                                Spacer()
                                Text("\(Int(server.latencyMs))ms")
                                    .font(.caption2)
                                    .foregroundColor(.textTertiary)
                            }
                            .contentShape(Rectangle())
                            .onTapGesture {
                                serverURL = server.url
                                appState.serverURL = server.url
                            }
                        }
                    }
                    .font(.caption2)
                    .foregroundColor(.textSecondary)
                }

                // Manual override link
                Button(action: { showManualURL = true }) {
                    HStack(spacing: 3) {
                        Image(systemName: "link")
                        Text("Enter URL manually")
                    }
                    .font(.caption2)
                }
                .buttonStyle(.plain)
                .foregroundColor(.textTertiary)
            } else {
                // No discovery or manual mode — show text field
                HStack {
                    Label("Server URL", systemImage: "link")
                        .font(.caption)
                        .foregroundColor(.textSecondary)
                    Spacer()
                    if showManualURL && !appState.discoveredServers.isEmpty {
                        Button(action: {
                            showManualURL = false
                            if let fastest = appState.discoveredServers.first {
                                serverURL = fastest.url
                                appState.serverURL = fastest.url
                            }
                        }) {
                            HStack(spacing: 3) {
                                Image(systemName: "antenna.radiowaves.left.and.right")
                                Text("Use auto-discovered")
                            }
                            .font(.caption2)
                        }
                        .buttonStyle(.plain)
                        .foregroundColor(.lemonYellow)
                    } else {
                        Button(action: { Task { await appState.discoverNearestServer() } }) {
                            HStack(spacing: 3) {
                                Image(systemName: "antenna.radiowaves.left.and.right")
                                Text("Auto-discover")
                            }
                            .font(.caption2)
                        }
                        .buttonStyle(.plain)
                        .foregroundColor(.lemonYellow)
                    }
                }

                TextField("https://localhost:9100", text: $serverURL)
                    .textFieldStyle(.roundedBorder)

                if let msg = appState.discoveryMessage, appState.discoveredServers.isEmpty {
                    HStack(spacing: 4) {
                        Image(systemName: "exclamationmark.circle")
                            .font(.caption2)
                            .foregroundColor(.orange)
                        Text(msg)
                            .font(.caption2)
                            .foregroundColor(.textTertiary)
                    }
                }
            }
        }
    }

    // MARK: - Password Tab

    private var passwordTabContent: some View {
        VStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 6) {
                Label("Username", systemImage: "person")
                    .font(.caption)
                    .foregroundColor(.textSecondary)
                TextField("Enter username", text: $username)
                    .textFieldStyle(.roundedBorder)
                    .textContentType(.username)
            }

            VStack(alignment: .leading, spacing: 6) {
                Label("Password", systemImage: "lock")
                    .font(.caption)
                    .foregroundColor(.textSecondary)
                SecureField("Enter password", text: $password)
                    .textFieldStyle(.roundedBorder)
                    .textContentType(.password)
                    .onSubmit { signIn() }
            }

            HStack(spacing: 12) {
                Button("Sign In") { signIn() }
                    .buttonStyle(LemonButtonStyle())
                    .disabled(username.isEmpty || password.isEmpty || appState.isLoading)

                Button("Register") { registerUser() }
                    .buttonStyle(LemonButtonStyle(isProminent: false))
                    .disabled(username.isEmpty || password.isEmpty || appState.isLoading)
            }
            .padding(.top, 4)
        }
    }

    // MARK: - Passkey Tab

    private var passkeyTabContent: some View {
        VStack(spacing: 16) {
            Image(systemName: "touchid")
                .font(.system(size: 48))
                .foregroundColor(.lemonYellow)
                .padding(.top, 8)

            if PasskeyManager.shared.hasCredential {
                // Existing passkey — show sign-in
                if let storedUser = PasskeyManager.shared.storedUserId {
                    Text("Sign in as **\(storedUser)** using Touch ID.")
                        .font(.subheadline)
                        .foregroundColor(.textSecondary)
                        .multilineTextAlignment(.center)
                }

                Button(action: signInWithPasskey) {
                    HStack {
                        Image(systemName: "person.badge.key.fill")
                        Text("Sign in with Passkey")
                    }
                }
                .buttonStyle(LemonButtonStyle())
                .disabled(appState.isLoading)

                Button(action: { PasskeyManager.shared.deleteCredential() }) {
                    Text("Remove stored passkey")
                        .font(.caption2)
                }
                .buttonStyle(.plain)
                .foregroundColor(.textTertiary)
            } else {
                // No passkey — show registration
                Text("Create a passkey to sign in with Touch ID. Enter your username to get started.")
                    .font(.subheadline)
                    .foregroundColor(.textSecondary)
                    .multilineTextAlignment(.center)

                VStack(alignment: .leading, spacing: 6) {
                    Label("Username", systemImage: "person")
                        .font(.caption)
                        .foregroundColor(.textSecondary)
                    TextField("Enter username", text: $username)
                        .textFieldStyle(.roundedBorder)
                        .textContentType(.username)
                }

                Button(action: registerPasskey) {
                    HStack {
                        Image(systemName: "person.badge.key.fill")
                        Text("Create Passkey")
                    }
                }
                .buttonStyle(LemonButtonStyle())
                .disabled(username.isEmpty || appState.isLoading)
            }
        }
        .padding(.bottom, 8)
    }

    // MARK: - Actions

    private func signIn() {
        isRegistering = false
        statusMessage = nil
        isError = false
        Task {
            await appState.signIn(username: username, password: password)
            if !appState.isAuthenticated {
                isError = true
                statusMessage = appState.errorMessage ?? "Sign-in failed"
            }
        }
    }

    private func registerUser() {
        isRegistering = true
        statusMessage = nil
        isError = false
        Task {
            await appState.register(username: username, password: password)
            if !appState.isAuthenticated {
                isError = true
                statusMessage = appState.errorMessage ?? "Registration failed"
            }
        }
    }

    private func signInWithPasskey() {
        statusMessage = nil
        isError = false
        Task {
            await appState.signInWithPasskey()
            if !appState.isAuthenticated {
                isError = true
                statusMessage = appState.errorMessage ?? "Passkey sign-in failed"
            }
        }
    }

    private func registerPasskey() {
        isRegistering = true
        statusMessage = nil
        isError = false
        Task {
            await appState.registerPasskey(username: username)
            if !appState.isAuthenticated {
                isError = true
                statusMessage = appState.errorMessage ?? "Passkey registration failed"
            }
        }
    }
}
