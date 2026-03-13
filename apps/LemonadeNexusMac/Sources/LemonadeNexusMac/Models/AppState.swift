import Foundation
import SwiftUI
import CryptoKit

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

    var client: NexusClient

    init() {
        let savedURL = UserDefaults.standard.string(forKey: "serverURL") ?? "https://localhost:9100"
        self.serverURL = savedURL
        self.autoConnectOnLaunch = UserDefaults.standard.bool(forKey: "autoConnectOnLaunch")
        self.autoDiscoveryEnabled = UserDefaults.standard.object(forKey: "autoDiscoveryEnabled") as? Bool ?? true
        let savedLogLevel = UserDefaults.standard.string(forKey: "logLevel") ?? "info"
        self.logLevel = LogLevel(rawValue: savedLogLevel) ?? .info
        self.client = NexusClient(baseURL: savedURL)
    }

    func updateBaseURL() {
        client = NexusClient(baseURL: serverURL)
        if let token = sessionToken {
            client.setSessionToken(token)
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
            let seed = try KeychainHelper.deriveEd25519Seed(username: username, password: password)
            let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            let pubkeyData = signingKey.publicKey.rawRepresentation
            let pubkeyBase64 = pubkeyData.base64EncodedString()

            let challengeResp = try await client.requestChallenge(pubkey: pubkeyBase64)

            guard let challengeData = Data(base64Encoded: challengeResp.challenge) ?? challengeResp.challenge.data(using: .utf8) else {
                throw NexusClientError.invalidResponse
            }
            let signatureData = try signingKey.signature(for: challengeData)
            let signatureBase64 = signatureData.base64EncodedString()

            let authResp = try await client.authenticate(
                method: "ed25519",
                pubkey: pubkeyBase64,
                challenge: challengeResp.challenge,
                signature: signatureBase64
            )

            if authResp.authenticated, let token = authResp.session_token {
                sessionToken = token
                userId = authResp.user_id
                publicKeyBase64 = pubkeyBase64
                isAuthenticated = true
                client.setSessionToken(token)
                connectedSince = Date()

                try KeychainHelper.saveIdentity(
                    privateKey: signingKey.rawRepresentation,
                    pubkey: pubkeyBase64,
                    username: username
                )

                addActivity(.info, "Signed in as \(username)")
                await refreshAllData()
            } else {
                errorMessage = authResp.error ?? "Authentication failed"
                addActivity(.error, "Sign-in failed: \(errorMessage ?? "unknown")")
            }
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
            let seed = try KeychainHelper.deriveEd25519Seed(username: username, password: password)
            let signingKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            let pubkeyData = signingKey.publicKey.rawRepresentation
            let pubkeyBase64 = pubkeyData.base64EncodedString()

            let challengeResp = try await client.requestChallenge(pubkey: pubkeyBase64)

            guard let challengeData = Data(base64Encoded: challengeResp.challenge) ?? challengeResp.challenge.data(using: .utf8) else {
                throw NexusClientError.invalidResponse
            }
            let signatureData = try signingKey.signature(for: challengeData)
            let signatureBase64 = signatureData.base64EncodedString()

            let authResp = try await client.registerEd25519(
                pubkey: pubkeyBase64,
                challenge: challengeResp.challenge,
                signature: signatureBase64
            )

            if authResp.authenticated, let token = authResp.session_token {
                sessionToken = token
                userId = authResp.user_id
                publicKeyBase64 = pubkeyBase64
                isAuthenticated = true
                client.setSessionToken(token)
                connectedSince = Date()

                try KeychainHelper.saveIdentity(
                    privateKey: signingKey.rawRepresentation,
                    pubkey: pubkeyBase64,
                    username: username
                )

                addActivity(.info, "Registered and signed in as \(username)")
                await refreshAllData()
            } else {
                errorMessage = authResp.error ?? "Registration failed"
            }
        } catch {
            errorMessage = error.localizedDescription
        }

        isLoading = false
    }

    // MARK: - Passkey Authentication

    func registerPasskey(username: String) async {
        isLoading = true
        errorMessage = nil
        self.username = username
        updateBaseURL()

        do {
            // Fetch RP ID from server
            let health = try await client.getHealth()
            let rpId = health.rp_id ?? "lemonade-nexus.local"

            // Generate P-256 credential (Secure Enclave + Touch ID)
            let (credentialId, pubKeyX, pubKeyY) = try PasskeyManager.shared.generateCredential(userId: username)

            // Register with server
            let authResp = try await client.registerPasskey(
                userId: username,
                credentialId: credentialId,
                publicKeyX: pubKeyX,
                publicKeyY: pubKeyY
            )

            if authResp.authenticated, let token = authResp.session_token {
                sessionToken = token
                userId = authResp.user_id
                publicKeyBase64 = credentialId
                isAuthenticated = true
                client.setSessionToken(token)
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
            // Fetch RP ID from server
            let health = try await client.getHealth()
            let rpId = health.rp_id ?? "lemonade-nexus.local"

            // Sign assertion (triggers Touch ID if Secure Enclave)
            let (credentialId, authData, clientDataJson, signature) = try PasskeyManager.shared.signAssertion(rpId: rpId)

            // Authenticate with server
            let authResp = try await client.authenticatePasskey(
                credentialId: credentialId,
                authenticatorData: authData,
                clientDataJson: clientDataJson,
                signature: signature
            )

            if authResp.authenticated, let token = authResp.session_token {
                sessionToken = token
                userId = authResp.user_id
                username = PasskeyManager.shared.storedUserId ?? ""
                publicKeyBase64 = credentialId
                isAuthenticated = true
                client.setSessionToken(token)
                connectedSince = Date()

                try? KeychainHelper.saveSessionToken(token)
                addActivity(.info, "Signed in with passkey")
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
        trustStatus = nil
        ddnsStatus = nil
        enrollmentStatus = nil
        proposals = []
        attestationManifests = nil
        client.clearSessionToken()
        addActivity(.info, "Signed out")
    }

    // MARK: - Data Refresh

    func refreshAllData() async {
        await refreshHealth()
        await refreshServers()
        await refreshStats()
        await refreshRelays()
        await refreshTrustStatus()
    }

    func refreshHealth() async {
        do {
            let health = try await client.getHealth()
            healthStatus = health
            isServerHealthy = (health.status == "ok" || health.status == "healthy")
        } catch {
            isServerHealthy = false
            healthStatus = nil
        }
    }

    func refreshServers() async {
        do {
            servers = try await client.getServers()
        } catch {
            servers = []
        }
    }

    func refreshStats() async {
        do {
            stats = try await client.getStats()
        } catch {
            stats = nil
        }
    }

    func refreshTree(parentId: String) async {
        do {
            treeNodes = try await client.getTreeChildren(parentId: parentId)
        } catch {
            addActivity(.error, "Failed to load tree: \(error.localizedDescription)")
        }
    }

    func refreshRelays() async {
        do {
            relays = try await client.getRelayList()
        } catch {
            relays = []
        }
    }

    func refreshCertificates(domains: [String]) async {
        var certs: [CertStatusResponse] = []
        for domain in domains {
            do {
                let cert = try await client.getCertStatus(domain: domain)
                certs.append(cert)
            } catch {
                // skip domains that error
            }
        }
        certificates = certs
    }

    func refreshTrustStatus() async {
        do {
            trustStatus = try await client.getTrustStatus()
        } catch {
            trustStatus = nil
        }
    }

    func refreshDdnsStatus() async {
        do {
            ddnsStatus = try await client.getDdnsStatus()
        } catch {
            ddnsStatus = nil
        }
    }

    func refreshEnrollmentStatus() async {
        do {
            enrollmentStatus = try await client.getEnrollmentStatus()
        } catch {
            enrollmentStatus = nil
        }
    }

    func refreshProposals() async {
        do {
            proposals = try await client.getGovernanceProposals()
        } catch {
            proposals = []
        }
    }

    func refreshAttestationManifests() async {
        do {
            attestationManifests = try await client.getAttestationManifests()
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
    case endpoints = "Endpoints"
    case servers = "Servers"
    case certificates = "Certificates"
    case relays = "Relays"
    case settings = "Settings"

    var id: String { rawValue }

    var sfSymbol: String {
        switch self {
        case .dashboard: return "gauge.with.dots.needle.33percent"
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
