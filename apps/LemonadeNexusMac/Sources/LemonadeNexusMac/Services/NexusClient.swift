import Foundation

enum NexusClientError: LocalizedError {
    case invalidURL
    case invalidResponse
    case httpError(statusCode: Int, body: String)
    case decodingError(String)
    case networkError(Error)
    case unauthorized

    var errorDescription: String? {
        switch self {
        case .invalidURL:
            return "Invalid server URL"
        case .invalidResponse:
            return "Invalid response from server"
        case .httpError(let code, let body):
            return "HTTP \(code): \(body)"
        case .decodingError(let detail):
            return "Failed to decode response: \(detail)"
        case .networkError(let error):
            return "Network error: \(error.localizedDescription)"
        case .unauthorized:
            return "Unauthorized. Please sign in again."
        }
    }
}

@MainActor
final class NexusClient {
    private var baseURL: String
    private var sessionToken: String?
    private let session: URLSession
    private let decoder: JSONDecoder
    private let encoder: JSONEncoder

    init(baseURL: String) {
        self.baseURL = baseURL.hasSuffix("/") ? String(baseURL.dropLast()) : baseURL

        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 60

        // Allow self-signed certs for local development
        let delegate = InsecureSessionDelegate()
        self.session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)

        self.decoder = JSONDecoder()
        self.encoder = JSONEncoder()
    }

    func setSessionToken(_ token: String) {
        sessionToken = token
    }

    func clearSessionToken() {
        sessionToken = nil
    }

    // MARK: - Request Helpers

    private func buildURL(_ path: String) throws -> URL {
        guard let url = URL(string: "\(baseURL)\(path)") else {
            throw NexusClientError.invalidURL
        }
        return url
    }

    private func buildRequest(_ method: String, path: String, body: (any Encodable)? = nil, authenticated: Bool = false) throws -> URLRequest {
        let url = try buildURL(path)
        var request = URLRequest(url: url)
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("LemonadeNexusMac/0.1.0", forHTTPHeaderField: "User-Agent")

        if authenticated, let token = sessionToken {
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        if let body = body {
            request.httpBody = try encoder.encode(AnyEncodable(body))
        }

        return request
    }

    private func perform<T: Decodable>(_ request: URLRequest) async throws -> T {
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw NexusClientError.networkError(error)
        }

        guard let httpResponse = response as? HTTPURLResponse else {
            throw NexusClientError.invalidResponse
        }

        if httpResponse.statusCode == 401 {
            throw NexusClientError.unauthorized
        }

        guard (200..<300).contains(httpResponse.statusCode) else {
            let body = String(data: data, encoding: .utf8) ?? "Unknown error"
            throw NexusClientError.httpError(statusCode: httpResponse.statusCode, body: body)
        }

        do {
            return try decoder.decode(T.self, from: data)
        } catch {
            throw NexusClientError.decodingError(error.localizedDescription)
        }
    }

    // MARK: - Public API (No Auth)

    func getHealth() async throws -> HealthResponse {
        let request = try buildRequest("GET", path: "/api/health")
        return try await perform(request)
    }

    func getServers() async throws -> [ServerEntry] {
        let request = try buildRequest("GET", path: "/api/servers")
        return try await perform(request)
    }

    func getStats() async throws -> StatsResponse {
        let request = try buildRequest("GET", path: "/api/stats")
        return try await perform(request)
    }

    func requestChallenge(pubkey: String) async throws -> ChallengeResponse {
        let body = ChallengeRequest(pubkey: pubkey)
        let request = try buildRequest("POST", path: "/api/auth/challenge", body: body)
        return try await perform(request)
    }

    func authenticate(method: String, pubkey: String, challenge: String, signature: String) async throws -> AuthResponse {
        let body = AuthRequest(method: method, pubkey: pubkey, challenge: challenge, signature: signature)
        let request = try buildRequest("POST", path: "/api/auth", body: body)
        return try await perform(request)
    }

    func registerEd25519(pubkey: String, challenge: String, signature: String) async throws -> AuthResponse {
        let body = RegisterRequest(pubkey: pubkey, challenge: challenge, signature: signature)
        let request = try buildRequest("POST", path: "/api/auth/register/ed25519", body: body)
        return try await perform(request)
    }

    func joinNetwork(hostname: String, wgPubkey: String, mgmtPubkey: String) async throws -> JoinResponse {
        let body = JoinRequest(hostname: hostname, wg_pubkey: wgPubkey, mgmt_pubkey: mgmtPubkey)
        let request = try buildRequest("POST", path: "/api/join", body: body)
        return try await perform(request)
    }

    // MARK: - Private API (Auth Required)

    func getTreeNode(id: String) async throws -> TreeNode {
        let request = try buildRequest("GET", path: "/api/tree/node/\(id)", authenticated: true)
        return try await perform(request)
    }

    func getTreeChildren(parentId: String) async throws -> [TreeNode] {
        let request = try buildRequest("GET", path: "/api/tree/children/\(parentId)", authenticated: true)
        return try await perform(request)
    }

    func submitTreeDelta(_ delta: TreeDelta) async throws -> DeltaResponse {
        let request = try buildRequest("POST", path: "/api/tree/delta", body: delta, authenticated: true)
        return try await perform(request)
    }

    func allocateIP(nodeId: String, subnetType: String) async throws -> IPAMAllocateResponse {
        let body = IPAMAllocateRequest(node_id: nodeId, subnet_type: subnetType)
        let request = try buildRequest("POST", path: "/api/ipam/allocate", body: body, authenticated: true)
        return try await perform(request)
    }

    func getRelayList() async throws -> [RelayInfoEntry] {
        let request = try buildRequest("GET", path: "/api/relay/list", authenticated: true)
        return try await perform(request)
    }

    func getNearestRelays(region: String, max: Int = 5) async throws -> NearestRelayResponse {
        let request = try buildRequest("GET", path: "/api/relay/nearest?region=\(region)&max=\(max)", authenticated: true)
        return try await perform(request)
    }

    func getCertStatus(domain: String) async throws -> CertStatusResponse {
        let request = try buildRequest("GET", path: "/api/certs/\(domain)", authenticated: true)
        return try await perform(request)
    }

    func issueCert(domain: String) async throws -> CertIssueResponse {
        let body = CertIssueRequest(domain: domain)
        let request = try buildRequest("POST", path: "/api/certs/issue", body: body, authenticated: true)
        return try await perform(request)
    }

    func getTrustStatus() async throws -> TrustStatusResponse {
        let request = try buildRequest("GET", path: "/api/trust/status", authenticated: true)
        return try await perform(request)
    }

    func getDdnsStatus() async throws -> DdnsStatusResponse {
        let request = try buildRequest("GET", path: "/api/ddns/status", authenticated: true)
        return try await perform(request)
    }

    func getEnrollmentStatus() async throws -> EnrollmentStatusResponse {
        let request = try buildRequest("GET", path: "/api/enrollment/status", authenticated: true)
        return try await perform(request)
    }

    func getGovernanceProposals() async throws -> [GovernanceProposal] {
        let request = try buildRequest("GET", path: "/api/governance/proposals", authenticated: true)
        return try await perform(request)
    }

    func getAttestationManifests() async throws -> AttestationManifestsResponse {
        let request = try buildRequest("GET", path: "/api/attestation/manifests", authenticated: true)
        return try await perform(request)
    }
}

// MARK: - AnyEncodable Wrapper

private struct AnyEncodable: Encodable {
    private let _encode: (Encoder) throws -> Void

    init<T: Encodable>(_ wrapped: T) {
        _encode = { encoder in
            try wrapped.encode(to: encoder)
        }
    }

    func encode(to encoder: Encoder) throws {
        try _encode(encoder)
    }
}

// MARK: - Insecure Session Delegate (for self-signed certs in dev)

final class InsecureSessionDelegate: NSObject, URLSessionDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let serverTrust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}
