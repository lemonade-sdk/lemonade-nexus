import Foundation
import SwiftUI

@MainActor
final class AppState: ObservableObject {
    // MARK: - Connection
    @Published var serverURL: String {
        didSet { UserDefaults.standard.set(serverURL, forKey: "serverURL") }
    }
    @Published var isAuthenticated: Bool = false
    @Published var sessionToken: String?
    @Published var userId: String?

    // MARK: - Identity
    @Published var publicKeyBase64: String?
    @Published var username: String = ""

    // MARK: - Health & Stats
    @Published var healthStatus: HealthResponse?
    @Published var stats: StatsResponse?
    @Published var isServerHealthy: Bool = false

    // MARK: - Data
    @Published var servers: [ServerEntry] = []
    @Published var treeNodes: [TreeNode] = []
    @Published var rootNode: TreeNode?
    @Published var certificates: [CertStatusResponse] = []
    @Published var relays: [RelayInfoEntry] = []
    @Published var dnsBaseDomain: String = ""
    @Published var trustStatus: TrustStatusResponse?
    @Published var ddnsStatus: DdnsStatusResponse?
    @Published var enrollmentStatus: EnrollmentStatusResponse?
    @Published var proposals: [GovernanceProposal] = []
    @Published var attestationManifests: AttestationManifestsResponse?

    // MARK: - UI State
    @Published var selectedSidebarItem: SidebarItem = .dashboard
    @Published var isLoading: Bool = false
    @Published var errorMessage: String?
    @Published var activityLog: [ActivityEntry] = []
    @Published var autoConnectOnLaunch: Bool {
        didSet { UserDefaults.standard.set(autoConnectOnLaunch, forKey: "autoConnectOnLaunch") }
    }
    @Published var logLevel: LogLevel = .info {
        didSet { UserDefaults.standard.set(logLevel.rawValue, forKey: "logLevel") }
    }

    // MARK: - Discovery
    @Published var discoveredServers: [DiscoveredServer] = []
    @Published var isDiscovering: Bool = false
    @Published var discoveryMessage: String?
    @Published var autoDiscoveryEnabled: Bool {
        didSet { UserDefaults.standard.set(autoDiscoveryEnabled, forKey: "autoDiscoveryEnabled") }
    }

    // MARK: - Connection Info
    @Published var tunnelIP: String?
    @Published var connectedSince: Date?

    // MARK: - Mesh P2P
    @Published var isMeshEnabled: Bool = false
    @Published var meshStatus: NexusSDK.SDKMeshStatus?
    @Published var meshPeers: [NexusSDK.SDKMeshPeer] = []

    let sdk: NexusSDK

    init() {
        let savedURL = UserDefaults.standard.string(forKey: "serverURL") ?? "https://localhost:9100"
        self.serverURL = savedURL
        self.autoConnectOnLaunch = UserDefaults.standard.bool(forKey: "autoConnectOnLaunch")
        self.autoDiscoveryEnabled = UserDefaults.standard.object(forKey: "autoDiscoveryEnabled") as? Bool ?? true
        let savedLogLevel = UserDefaults.standard.string(forKey: "logLevel") ?? "info"
        self.logLevel = LogLevel(rawValue: savedLogLevel) ?? .info

        // Parse URL to extract host, port, TLS for SDK
        let url = URL(string: savedURL)
        let host = url?.host ?? "127.0.0.1"
        let port = UInt16(url?.port ?? 9100)
        let useTLS = url?.scheme == "https"
        self.sdk = NexusSDK(host: host, port: port, useTLS: useTLS)
    }

    func updateBaseURL() {
        guard let url = URL(string: serverURL) else { return }
        let host = url.host ?? "127.0.0.1"
        let port = UInt16(url.port ?? 9100)
        let useTLS = url.scheme == "https"
        sdk.reconnect(host: host, port: port, useTLS: useTLS)
        if let token = sessionToken {
            sdk.setSessionToken(token)
        }
    }

    // MARK: - DNS Auto-Discovery

    func discoverNearestServer() async {
        // Prevent duplicate concurrent discovery runs (SwiftUI can re-fire onAppear)
        guard !isDiscovering else { return }
        isDiscovering = true
        discoveryMessage = "Querying lemonade-nexus.io DNS mesh..."
        discoveredServers = []

        let discovery = DnsDiscoveryService()
        let servers = await discovery.discoverServers()
        discoveredServers = servers

        if let fastest = servers.first {
            serverURL = fastest.url
            updateBaseURL()
            discoveryMessage = "Found \(servers.count) server\(servers.count == 1 ? "" : "s") — selected \(fastest.displayName) (\(Int(fastest.latencyMs))ms)"
            addActivity(.success, "Auto-discovered server: \(fastest.displayName) at \(fastest.url) (\(Int(fastest.latencyMs))ms)")
        } else {
            discoveryMessage = "No servers found via DNS. Enter URL manually."
            addActivity(.warning, "DNS auto-discovery found no reachable servers on lemonade-nexus.io")
        }

        isDiscovering = false
    }

    // MARK: - Authentication

    func signIn(username: String, password: String) async {
        isLoading = true
        errorMessage = nil
        self.username = username
        updateBaseURL()

        do {
            // SDK handles PBKDF2 + Ed25519 keypair derivation internally
            try sdk.deriveIdentity(username: username, password: password)

            // SDK handles challenge-response auth (request challenge, sign, authenticate)
            let authResult = try sdk.authenticateEd25519()

            guard authResult.authenticated == true else {
                errorMessage = authResult.error ?? "Authentication failed"
                addActivity(.error, "Sign-in failed: \(errorMessage ?? "unknown")")
                isLoading = false
                return
            }

            if let token = authResult.session_token {
                sessionToken = token
                sdk.setSessionToken(token)
            }
            userId = authResult.user_id

            // Extract base64 public key from SDK's "ed25519:base64..." format
            let pubkey = sdk.publicKeyString ?? ""
            let pubkeyBase64 = pubkey.hasPrefix("ed25519:") ? String(pubkey.dropFirst("ed25519:".count)) : pubkey
            publicKeyBase64 = pubkeyBase64

            isAuthenticated = true
            connectedSince = Date()

            // Save credentials to macOS Keychain for session restore on next launch.
            // We save the identity stub (empty privateKey since SDK manages keys internally)
            // so auto-connect can restore username/pubkey context.
            try KeychainHelper.saveIdentity(
                privateKey: Data(),
                pubkey: pubkeyBase64,
                username: username
            )
            try KeychainHelper.saveSessionToken(sessionToken ?? "")

            addActivity(.info, "Signed in as \(username)")
            await joinAsEndpoint()
            await refreshAllData()
        } catch {
            errorMessage = error.localizedDescription
            addActivity(.error, "Sign-in error: \(error.localizedDescription)")
        }

        isLoading = false
    }

    func register(username: String, password: String) async {
        isLoading = true
        errorMessage = nil
        self.username = username
        updateBaseURL()

        do {
            // SDK handles PBKDF2 + Ed25519 keypair derivation internally
            try sdk.deriveIdentity(username: username, password: password)

            // Ed25519 challenge-response auto-registers the pubkey on the server
            // if it doesn't exist yet. The SDK handles the full flow internally.
            // NOTE: If the server requires explicit registration via /api/auth/register/ed25519,
            // a dedicated SDK C API binding (ln_register_ed25519) will need to be added.
            let authResult = try sdk.authenticateEd25519()

            guard authResult.authenticated == true else {
                errorMessage = authResult.error ?? "Registration failed"
                isLoading = false
                return
            }

            if let token = authResult.session_token {
                sessionToken = token
                sdk.setSessionToken(token)
            }
            userId = authResult.user_id

            let pubkey = sdk.publicKeyString ?? ""
            let pubkeyBase64 = pubkey.hasPrefix("ed25519:") ? String(pubkey.dropFirst("ed25519:".count)) : pubkey
            publicKeyBase64 = pubkeyBase64

            isAuthenticated = true
            connectedSince = Date()

            try KeychainHelper.saveIdentity(
                privateKey: Data(),
                pubkey: pubkeyBase64,
                username: username
            )
            try KeychainHelper.saveSessionToken(sessionToken ?? "")

            addActivity(.info, "Registered and signed in as \(username)")
            await joinAsEndpoint()
            await refreshAllData()
        } catch {
            errorMessage = error.localizedDescription
        }

        isLoading = false
    }

    // MARK: - Endpoint Join

    /// Joins the mesh network as an endpoint after authentication.
    /// The SDK handles auth + node creation + IP allocation in one call.
    private func joinAsEndpoint() async {
        do {
            // The SDK's joinNetwork does auth + create_node + IP allocation.
            // Identity must already be set (done during signIn/register).
            let joinResult = try sdk.joinNetwork(username: username, password: "")
            // Note: password is empty because identity is already derived and set on the SDK.
            // The SDK uses the existing identity for the join flow.

            tunnelIP = joinResult.tunnel_ip

            if let nodeId = joinResult.node_id {
                sdk.setNodeId(nodeId)
            }

            addActivity(.success, "Joined network — tunnel IP: \(joinResult.tunnel_ip ?? "pending")")
        } catch {
            // Join failure is non-fatal — user is still authenticated.
            // Fall back to refreshing tree to discover our node info.
            addActivity(.warning, "Network join failed: \(error.localizedDescription)")
        }
    }

    // MARK: - Tree Operations (delegated to SDK)

    /// Create a child node — SDK handles signing and delta construction.
    func createChildNode(parentId: String, nodeType: String) throws -> NexusSDK.SDKDeltaResponse {
        try sdk.createChildNode(parentId: parentId, nodeType: nodeType)
    }

    /// Update a node — SDK handles signing and delta construction.
    func updateNode(nodeId: String, updates: [String: Any]) throws -> NexusSDK.SDKDeltaResponse {
        try sdk.updateNode(nodeId: nodeId, updates: updates)
    }

    /// Delete a node — SDK handles signing and delta construction.
    func deleteNode(nodeId: String) throws -> NexusSDK.SDKDeltaResponse {
        try sdk.deleteNode(nodeId: nodeId)
    }

    // MARK: - Passkey Authentication

    func registerPasskey(username: String) async {
        isLoading = true
        errorMessage = nil
        self.username = username
        updateBaseURL()

        do {
            // Generate P-256 credential (Secure Enclave + Touch ID) — platform-specific
            let (credentialId, pubKeyX, pubKeyY) = try PasskeyManager.shared.generateCredential(userId: username)

            // Register with server via SDK
            let authResp = try sdk.registerPasskey(
                userId: username,
                credentialId: credentialId,
                publicKeyX: pubKeyX,
                publicKeyY: pubKeyY
            )

            if authResp.authenticated == true, let token = authResp.session_token {
                sessionToken = token
                userId = authResp.user_id
                publicKeyBase64 = credentialId
                isAuthenticated = true
                sdk.setSessionToken(token)
                connectedSince = Date()

                try? KeychainHelper.saveSessionToken(token)
                addActivity(.info, "Registered passkey for \(username)")
                await refreshAllData()
            } else {
                errorMessage = authResp.error ?? "Passkey registration failed"
                addActivity(.error, "Passkey registration failed: \(errorMessage ?? "unknown")")
            }
        } catch {
            errorMessage = error.localizedDescription
            addActivity(.error, "Passkey registration error: \(error.localizedDescription)")
        }

        isLoading = false
    }

    func signInWithPasskey() async {
        isLoading = true
        errorMessage = nil
        updateBaseURL()

        do {
            // rpId for assertion — platform-specific (Touch ID / Secure Enclave)
            let rpId = "lemonade-nexus.local"

            // Sign assertion (triggers Touch ID if Secure Enclave)
            let (credentialId, authData, clientDataJson, signature) = try PasskeyManager.shared.signAssertion(rpId: rpId)

            // Authenticate with server via SDK
            let authResp = try sdk.authenticatePasskey(
                credentialId: credentialId,
                authenticatorData: authData,
                clientDataJson: clientDataJson,
                signature: signature
            )

            if authResp.authenticated == true, let token = authResp.session_token {
                sessionToken = token
                userId = authResp.user_id
                username = PasskeyManager.shared.storedUserId ?? ""
                publicKeyBase64 = credentialId
                isAuthenticated = true
                sdk.setSessionToken(token)
                connectedSince = Date()

                // Generate Ed25519 identity for tree operations
                sdk.generateIdentity()

                // Register the Ed25519 key with the server so it gets
                // add_child permission on root for creating nodes
                if let _ = try? sdk.authenticateEd25519() {
                    // Re-set the passkey session token (ed25519 auth returns its own)
                    sdk.setSessionToken(token)
                }

                try? KeychainHelper.saveSessionToken(token)
                addActivity(.info, "Signed in with passkey")
                await joinAsEndpoint()
                await refreshAllData()
            } else {
                errorMessage = authResp.error ?? "Passkey authentication failed"
                addActivity(.error, "Passkey auth failed: \(errorMessage ?? "unknown")")
            }
        } catch {
            errorMessage = error.localizedDescription
            addActivity(.error, "Passkey error: \(error.localizedDescription)")
        }

        isLoading = false
    }

    func signOut() {
        sessionToken = nil
        userId = nil
        isAuthenticated = false
        publicKeyBase64 = nil
        tunnelIP = nil
        connectedSince = nil
        healthStatus = nil
        stats = nil
        isServerHealthy = false
        servers = []
        treeNodes = []
        rootNode = nil
        certificates = []
        relays = []
        dnsBaseDomain = ""
        trustStatus = nil
        ddnsStatus = nil
        enrollmentStatus = nil
        proposals = []
        attestationManifests = nil
        sdk.setSessionToken("")
        addActivity(.info, "Signed out")
    }

    // MARK: - Data Refresh

    func refreshAllData() async {
        await refreshHealth()
        await refreshServers()
        await refreshStats()
        await refreshRelays()
        await refreshTrustStatus()
        await refreshMeshStatus()
    }

    // MARK: - Mesh P2P

    func toggleMesh() async {
        if isMeshEnabled {
            do {
                try sdk.meshDisable()
                isMeshEnabled = false
                meshStatus = nil
                meshPeers = []
                addActivity(.info, "Mesh networking disabled")
            } catch {
                addActivity(.error, "Failed to disable mesh: \(error)")
            }
        } else {
            do {
                try sdk.meshEnable()
                isMeshEnabled = true
                addActivity(.success, "Mesh networking enabled")
                await refreshMeshStatus()
            } catch {
                addActivity(.error, "Failed to enable mesh: \(error)")
            }
        }
    }

    func refreshMeshStatus() async {
        guard isMeshEnabled else { return }
        do {
            let status = try sdk.meshStatus()
            meshStatus = status
            meshPeers = status.peers
        } catch {
            // Mesh may not be ready yet — silently ignore
        }
    }

    func refreshMeshPeers() {
        sdk.meshRefresh()
    }

    func refreshHealth() async {
        do {
            let health = try sdk.getHealth()
            healthStatus = HealthResponse(
                status: health.status ?? "unknown",
                service: health.service ?? ""
            )
            isServerHealthy = (health.status == "ok" || health.status == "healthy")
            if let domain = health.dns_base_domain, !domain.isEmpty {
                dnsBaseDomain = domain
            }
        } catch {
            isServerHealthy = false
            healthStatus = nil
        }
    }

    func refreshServers() async {
        do {
            let serverDicts = try sdk.getServers()
            servers = serverDicts.map { ServerEntry(from: $0) }
        } catch {
            servers = []
        }
    }

    func refreshStats() async {
        do {
            let sdkStats = try sdk.getStats()
            stats = StatsResponse(
                service: sdkStats.service ?? "",
                peer_count: Int(sdkStats.peer_count ?? 0),
                private_api_enabled: sdkStats.private_api_enabled ?? false
            )
        } catch {
            stats = nil
        }
    }

    func refreshTree(parentId: String) async {
        do {
            let childDicts = try sdk.getTreeChildren(parentId: parentId)
            // Convert [[String: Any]] to [TreeNode] via JSON round-trip
            let jsonData = try JSONSerialization.data(withJSONObject: childDicts, options: [])
            treeNodes = try JSONDecoder().decode([TreeNode].self, from: jsonData)
        } catch {
            addActivity(.error, "Failed to load tree: \(error.localizedDescription)")
        }
    }

    func refreshRelays() async {
        do {
            let relayDicts = try sdk.getRelayList()
            relays = relayDicts.map { RelayInfoEntry(from: $0) }
        } catch {
            relays = []
        }
    }

    func refreshCertificates(domains: [String]) async {
        var certs: [CertStatusResponse] = []
        for domain in domains {
            do {
                let sdkCert = try sdk.getCertStatus(domain: domain)
                // Convert SDK cert status to APIModels type
                let expiresStr: String? = sdkCert.expires_at.map { ts in
                    ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: TimeInterval(ts)))
                }
                certs.append(CertStatusResponse(
                    domain: sdkCert.domain ?? domain,
                    has_cert: sdkCert.has_cert ?? false,
                    expires_at: expiresStr
                ))
            } catch {
                // skip domains that error
            }
        }
        certificates = certs
    }

    func refreshTrustStatus() async {
        do {
            let trustDict = try sdk.getTrustStatus()
            // Convert [String: Any] to TrustStatusResponse via JSON round-trip
            let jsonData = try JSONSerialization.data(withJSONObject: trustDict, options: [])
            trustStatus = try JSONDecoder().decode(TrustStatusResponse.self, from: jsonData)
        } catch {
            trustStatus = nil
        }
    }

    func refreshDdnsStatus() async {
        do {
            let sdkDdns = try sdk.getDdnsStatus()
            ddnsStatus = DdnsStatusResponse(
                has_credentials: sdkDdns.has_credentials ?? false,
                last_ip: sdkDdns.last_ip,
                binary_hash: sdkDdns.binary_hash,
                binary_approved: sdkDdns.binary_approved
            )
        } catch {
            ddnsStatus = nil
        }
    }

    func refreshEnrollmentStatus() async {
        do {
            let enrollDict = try sdk.getEnrollmentStatus()
            let jsonData = try JSONSerialization.data(withJSONObject: enrollDict, options: [])
            enrollmentStatus = try JSONDecoder().decode(EnrollmentStatusResponse.self, from: jsonData)
        } catch {
            enrollmentStatus = nil
        }
    }

    func refreshProposals() async {
        do {
            let proposalDicts = try sdk.getGovernanceProposals()
            let jsonData = try JSONSerialization.data(withJSONObject: proposalDicts, options: [])
            proposals = try JSONDecoder().decode([GovernanceProposal].self, from: jsonData)
        } catch {
            proposals = []
        }
    }

    func refreshAttestationManifests() async {
        do {
            let manifestDict = try sdk.getAttestationManifests()
            let jsonData = try JSONSerialization.data(withJSONObject: manifestDict, options: [])
            attestationManifests = try JSONDecoder().decode(AttestationManifestsResponse.self, from: jsonData)
        } catch {
            attestationManifests = nil
        }
    }

    // MARK: - Activity Log

    func addActivity(_ level: ActivityLevel, _ message: String) {
        let entry = ActivityEntry(timestamp: Date(), level: level, message: message)
        activityLog.insert(entry, at: 0)
        if activityLog.count > 200 {
            activityLog = Array(activityLog.prefix(200))
        }
    }
}

// MARK: - Supporting Types

enum SidebarItem: String, CaseIterable, Identifiable {
    case dashboard = "Dashboard"
    case tunnel = "Tunnel"
    case peers = "Peers"
    case network = "Network"
    case endpoints = "Endpoints"
    case servers = "Servers"
    case certificates = "Certificates"
    case relays = "Relays"
    case settings = "Settings"

    var id: String { rawValue }

    var sfSymbol: String {
        switch self {
        case .dashboard: return "gauge.with.dots.needle.33percent"
        case .tunnel: return "network"
        case .peers: return "person.2.wave.2"
        case .network: return "chart.bar.xaxis"
        case .endpoints: return "point.3.connected.trianglepath.dotted"
        case .servers: return "server.rack"
        case .certificates: return "lock.shield"
        case .relays: return "antenna.radiowaves.left.and.right"
        case .settings: return "gearshape"
        }
    }
}

struct ActivityEntry: Identifiable {
    let id = UUID()
    let timestamp: Date
    let level: ActivityLevel
    let message: String
}

enum ActivityLevel {
    case info, warning, error, success
}

enum LogLevel: String, CaseIterable {
    case debug, info, warning, error
}
