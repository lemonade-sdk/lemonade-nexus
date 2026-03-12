import Foundation

// MARK: - Health

struct HealthResponse: Codable {
    let status: String
    let service: String
}

// MARK: - Server Discovery

struct ServerEntry: Codable, Identifiable, Hashable {
    let endpoint: String
    let pubkey: String
    let http_port: Int
    let last_seen: String
    let healthy: Bool

    var id: String { endpoint }
}

// MARK: - Stats

struct StatsResponse: Codable {
    let service: String
    let peer_count: Int
    let private_api_enabled: Bool
}

// MARK: - Authentication

struct ChallengeRequest: Codable {
    let pubkey: String
}

struct ChallengeResponse: Codable {
    let challenge: String
    let expires_at: String
}

struct AuthRequest: Codable {
    let method: String
    let pubkey: String
    let challenge: String
    let signature: String
}

struct AuthResponse: Codable {
    let authenticated: Bool
    let user_id: String?
    let session_token: String?
    let error: String?
}

struct RegisterRequest: Codable {
    let pubkey: String
    let challenge: String
    let signature: String
}

// MARK: - Join Network

struct JoinRequest: Codable {
    let hostname: String
    let wg_pubkey: String
    let mgmt_pubkey: String
}

struct JoinResponse: Codable {
    let token: String
    let node_id: String
    let tunnel_ip: String
    let server_tunnel_ip: String
    let private_api_port: Int
    let wg_server_pubkey: String
    let wg_endpoint: String
    let dns_servers: [String]
}

// MARK: - Tree Nodes

struct TreeNode: Codable, Identifiable, Hashable {
    let id: String
    let parent_id: String
    let type: String
    let hostname: String
    let tunnel_ip: String?
    let private_subnet: String?
    let mgmt_pubkey: String?
    let wg_pubkey: String?
    let assignments: [NodeAssignment]?
    let region: String?
    let listen_endpoint: String?

    var nodeType: NodeType {
        NodeType(rawValue: type) ?? .endpoint
    }

    var children: [TreeNode]? = nil

    enum CodingKeys: String, CodingKey {
        case id, parent_id, type, hostname, tunnel_ip, private_subnet
        case mgmt_pubkey, wg_pubkey, assignments, region, listen_endpoint
    }
}

struct NodeAssignment: Codable, Identifiable, Hashable {
    let management_pubkey: String
    let permissions: [String]

    var id: String { management_pubkey }
}

enum NodeType: String, Codable, CaseIterable {
    case root
    case customer
    case endpoint
    case relay

    var displayName: String {
        switch self {
        case .root: return "Root"
        case .customer: return "Customer"
        case .endpoint: return "Endpoint"
        case .relay: return "Relay"
        }
    }

    var sfSymbol: String {
        switch self {
        case .root: return "server.rack"
        case .customer: return "building.2"
        case .endpoint: return "laptopcomputer"
        case .relay: return "antenna.radiowaves.left.and.right"
        }
    }
}

// MARK: - Tree Delta

struct TreeDelta: Codable {
    let node_id: String
    let field: String
    let value: String
    let author_pubkey: String
    let signature: String
}

struct DeltaResponse: Codable {
    let success: Bool
    let error: String?
}

// MARK: - IPAM

struct IPAMAllocateRequest: Codable {
    let node_id: String
    let subnet_type: String
}

struct IPAMAllocateResponse: Codable {
    let success: Bool
    let network: String?
    let node_id: String?
}

// MARK: - Relay

struct RelayInfoEntry: Codable, Identifiable, Hashable {
    let pubkey: String
    let endpoint: String
    let region: String
    let load: Double?
    let latency_ms: Double?

    var id: String { pubkey }
}

struct NearestRelayResponse: Codable {
    let client_region: String
    let relays: [RelayInfoEntry]
}

// MARK: - Certificates

struct CertStatusResponse: Codable, Identifiable, Hashable {
    let domain: String
    let has_cert: Bool
    let expires_at: String?

    var id: String { domain }

    var expiryDate: Date? {
        guard let expiresAt = expires_at else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: expiresAt) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: expiresAt)
    }

    var certStatus: CertStatus {
        guard has_cert, let expiry = expiryDate else { return .none }
        let daysUntilExpiry = Calendar.current.dateComponents([.day], from: Date(), to: expiry).day ?? 0
        if daysUntilExpiry < 0 { return .expired }
        if daysUntilExpiry < 30 { return .expiring }
        return .valid
    }
}

enum CertStatus {
    case valid, expiring, expired, none
}

struct CertIssueRequest: Codable {
    let domain: String
}

struct CertIssueResponse: Codable {
    let domain: String
    let fullchain_pem: String
    let encrypted_privkey: String
    let nonce: String
    let ephemeral_pubkey: String
    let expires_at: String
}

// MARK: - Trust

struct TrustStatusResponse: Codable {
    let our_tier: Int
    let our_platform: String
    let require_tee: Bool
    let peer_count: Int
    let peers: [TrustPeer]
}

struct TrustPeer: Codable, Identifiable, Hashable {
    let pubkey: String
    let tier: Int
    let platform: String?
    let last_verified: String?

    var id: String { pubkey }
}

// MARK: - DDNS

struct DdnsStatusResponse: Codable {
    let has_credentials: Bool
    let last_ip: String?
    let binary_hash: String?
    let binary_approved: Bool?
}

// MARK: - Enrollment

struct EnrollmentEntry: Codable, Identifiable, Hashable {
    let node_id: String
    let pubkey: String
    let state: String?
    let votes: Int?

    var id: String { node_id }
}

struct EnrollmentStatusResponse: Codable {
    let enabled: Bool
    let quorum_ratio: Double
    let enrollments: [EnrollmentEntry]
}

// MARK: - Governance

struct GovernanceProposal: Codable, Identifiable, Hashable {
    let proposal_id: String
    let parameter: String
    let new_value: String
    let state_name: String
    let votes: Int

    var id: String { proposal_id }
}

// MARK: - Attestation

struct AttestationManifestsResponse: Codable {
    let self_hash: String
    let self_approved: Bool
    let manifests: [AttestationManifest]
}

struct AttestationManifest: Codable, Identifiable, Hashable {
    let hash: String
    let signer: String?
    let version: String?

    var id: String { hash }
}

// MARK: - Generic Error

struct APIError: Codable {
    let error: String
}
