import Foundation
import CLemonadeNexusSDK

/// Swift wrapper around the C++ LemonadeNexusSDK.
/// All protocol logic (auth, signing, delta construction, crypto) is handled by the SDK.
/// This class just marshals data between Swift types and the C FFI.
@MainActor
final class NexusSDK {
    private var client: OpaquePointer?
    private var identity: OpaquePointer?

    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()

    init(host: String, port: UInt16, useTLS: Bool = false) {
        if useTLS {
            client = ln_create_tls(host, port)
        } else {
            client = ln_create(host, port)
        }
    }

    deinit {
        if let identity { ln_identity_destroy(identity) }
        if let client { ln_destroy(client) }
    }

    // MARK: - Helpers

    /// Call a C function that returns JSON via out_json, parse it into T.
    private func callJSON<T: Decodable>(
        _ block: (OpaquePointer, UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> ln_error_t
    ) throws -> T {
        guard let client else { throw SDKError.notInitialized }
        var jsonPtr: UnsafeMutablePointer<CChar>? = nil
        let err = block(client, &jsonPtr)
        defer { if let jsonPtr { ln_free(jsonPtr) } }

        guard let jsonPtr else {
            throw SDKError.connectionFailed
        }

        let jsonString = String(cString: jsonPtr)
        guard let jsonData = jsonString.data(using: .utf8) else {
            throw SDKError.parseError("Invalid UTF-8 in response")
        }

        if err != LN_OK {
            // Try to extract error message from JSON
            if let errorObj = try? JSONSerialization.jsonObject(with: jsonData) as? [String: Any],
               let errorMsg = errorObj["error"] as? String {
                throw SDKError.apiError(Int(err.rawValue), errorMsg)
            }
            throw SDKError.apiError(Int(err.rawValue), "SDK error code: \(err.rawValue)")
        }

        return try decoder.decode(T.self, from: jsonData)
    }

    /// Call a C function that returns a string. Caller gets a Swift String.
    private func callString(
        _ block: (OpaquePointer) -> UnsafeMutablePointer<CChar>?
    ) -> String? {
        guard let client else { return nil }
        guard let ptr = block(client) else { return nil }
        let result = String(cString: ptr)
        ln_free(ptr)
        return result
    }

    // MARK: - Identity Management

    /// Generate a new random Ed25519 identity.
    func generateIdentity() {
        if let identity { ln_identity_destroy(identity) }
        identity = ln_identity_generate()
        if let client, let identity {
            ln_set_identity(client, identity)
        }
    }

    /// Create identity from PBKDF2-derived seed (username + password).
    func deriveIdentity(username: String, password: String) throws {
        let seed = NexusSDK.derive_seed_swift(username: username, password: password)
        guard seed.count == 32 else {
            throw SDKError.derivationFailed
        }

        if let identity { ln_identity_destroy(identity) }
        identity = seed.withUnsafeBytes { ptr in
            ln_identity_from_seed(ptr.baseAddress?.assumingMemoryBound(to: UInt8.self), UInt32(seed.count))
        }
        guard identity != nil else {
            throw SDKError.derivationFailed
        }
        if let client, let identity {
            ln_set_identity(client, identity)
        }
    }

    /// Get the public key string ("ed25519:base64...").
    var publicKeyString: String? {
        guard let identity else { return nil }
        guard let ptr = ln_identity_pubkey(identity) else { return nil }
        let result = String(cString: ptr)
        ln_free(ptr)
        return result
    }

    /// Load identity from a JSON file.
    func loadIdentity(path: String) throws {
        if let identity { ln_identity_destroy(identity) }
        identity = ln_identity_load(path)
        guard identity != nil else {
            throw SDKError.identityNotFound
        }
        if let client, let identity {
            ln_set_identity(client, identity)
        }
    }

    /// Save identity to a JSON file.
    func saveIdentity(path: String) throws {
        guard let identity else { throw SDKError.noIdentity }
        let err = ln_identity_save(identity, path)
        guard err == LN_OK else {
            throw SDKError.apiError(Int(err.rawValue), "Failed to save identity")
        }
    }

    // MARK: - Session Management

    func setSessionToken(_ token: String) {
        guard let client else { return }
        ln_set_session_token(client, token)
    }

    var sessionToken: String? {
        callString { ln_get_session_token($0) }
    }

    func setNodeId(_ id: String) {
        guard let client else { return }
        ln_set_node_id(client, id)
    }

    var nodeId: String? {
        callString { ln_get_node_id($0) }
    }

    // MARK: - Health

    struct SDKHealthResponse: Codable {
        let status: String?
        let service: String?
        let dns_base_domain: String?
        let ok: Bool?
        let error: String?
    }

    func getHealth() throws -> SDKHealthResponse {
        try callJSON { ln_health($0, $1) }
    }

    // MARK: - Authentication

    struct SDKAuthResponse: Codable {
        let authenticated: Bool?
        let user_id: String?
        let session_token: String?
        let error: String?
    }

    /// Authenticate using Ed25519 challenge-response (primary method).
    /// Identity must be set first via deriveIdentity() or generateIdentity().
    func authenticateEd25519() throws -> SDKAuthResponse {
        try callJSON { ln_auth_ed25519($0, $1) }
    }

    /// Authenticate with username/password (deprecated).
    func authenticatePassword(username: String, password: String) throws -> SDKAuthResponse {
        try callJSON { ln_auth_password($0, username, password, $1) }
    }

    /// Register a passkey credential.
    func registerPasskey(userId: String, credentialId: String,
                         publicKeyX: String, publicKeyY: String) throws -> SDKAuthResponse {
        try callJSON { ln_register_passkey($0, userId, credentialId, publicKeyX, publicKeyY, $1) }
    }

    /// Authenticate with a passkey assertion (FIDO2/WebAuthn).
    func authenticatePasskey(credentialId: String, authenticatorData: String,
                             clientDataJson: String, signature: String) throws -> SDKAuthResponse {
        let passkeyData: [String: Any] = [
            "method": "passkey",
            "assertion": [
                "credential_id": credentialId,
                "authenticator_data": authenticatorData,
                "client_data_json": clientDataJson,
                "signature": signature
            ]
        ]
        let jsonData = try JSONSerialization.data(withJSONObject: passkeyData, options: [])
        let jsonString = String(data: jsonData, encoding: .utf8)!
        return try callJSON { ln_auth_passkey($0, jsonString, $1) }
    }

    // MARK: - Tree Operations

    func getTreeNode(id: String) throws -> [String: Any] {
        guard let client else { throw SDKError.notInitialized }
        var jsonPtr: UnsafeMutablePointer<CChar>? = nil
        let err = ln_tree_get_node(client, id, &jsonPtr)
        defer { if let jsonPtr { ln_free(jsonPtr) } }
        guard let jsonPtr else { throw SDKError.connectionFailed }
        let jsonString = String(cString: jsonPtr)
        guard let data = jsonString.data(using: .utf8),
              let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw SDKError.parseError("Invalid JSON")
        }
        if err != LN_OK, let error = obj["error"] as? String {
            throw SDKError.apiError(Int(err.rawValue), error)
        }
        return obj
    }

    struct SDKDeltaResponse: Codable {
        let success: Bool?
        let delta_sequence: UInt64?
        let node_id: String?
        let tunnel_ip: String?
        let private_subnet: String?
        let error: String?
    }

    /// Submit a signed tree delta. The SDK handles signing automatically.
    func submitDelta(deltaJSON: String) throws -> SDKDeltaResponse {
        guard let client else { throw SDKError.notInitialized }
        var jsonPtr: UnsafeMutablePointer<CChar>? = nil
        let err = ln_tree_submit_delta(client, deltaJSON, &jsonPtr)
        defer { if let jsonPtr { ln_free(jsonPtr) } }
        guard let jsonPtr else { throw SDKError.connectionFailed }
        let data = String(cString: jsonPtr).data(using: .utf8)!
        if err != LN_OK {
            if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let error = obj["error"] as? String {
                throw SDKError.apiError(Int(err.rawValue), error)
            }
        }
        return try decoder.decode(SDKDeltaResponse.self, from: data)
    }

    /// Create a child node — SDK handles delta construction and signing.
    func createChildNode(parentId: String, nodeType: String) throws -> SDKDeltaResponse {
        try callJSON { ln_create_child_node($0, parentId, nodeType, $1) }
    }

    /// Update a node — SDK handles delta construction and signing.
    func updateNode(nodeId: String, updates: [String: Any]) throws -> SDKDeltaResponse {
        let data = try JSONSerialization.data(withJSONObject: updates, options: [])
        let json = String(data: data, encoding: .utf8)!
        return try callJSON { ln_update_node($0, nodeId, json, $1) }
    }

    /// Delete a node — SDK handles delta construction and signing.
    func deleteNode(nodeId: String) throws -> SDKDeltaResponse {
        try callJSON { ln_delete_node($0, nodeId, $1) }
    }

    func getTreeChildren(parentId: String) throws -> [[String: Any]] {
        guard let client else { throw SDKError.notInitialized }
        var jsonPtr: UnsafeMutablePointer<CChar>? = nil
        let err = ln_tree_get_children(client, parentId, &jsonPtr)
        defer { if let jsonPtr { ln_free(jsonPtr) } }
        guard let jsonPtr else { throw SDKError.connectionFailed }
        let jsonString = String(cString: jsonPtr)
        guard let data = jsonString.data(using: .utf8),
              let arr = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            throw SDKError.parseError("Expected array")
        }
        if err != LN_OK { throw SDKError.apiError(Int(err.rawValue), "Failed to get children") }
        return arr
    }

    // MARK: - IPAM

    struct SDKAllocationResponse: Codable {
        let success: Bool?
        let network: String?
        let node_id: String?
        let error: String?
    }

    func allocateIP(nodeId: String, blockType: String) throws -> SDKAllocationResponse {
        try callJSON { ln_ipam_allocate($0, nodeId, blockType, $1) }
    }

    // MARK: - Relay

    func getRelayList() throws -> [[String: Any]] {
        guard let client else { throw SDKError.notInitialized }
        var jsonPtr: UnsafeMutablePointer<CChar>? = nil
        let err = ln_relay_list(client, &jsonPtr)
        defer { if let jsonPtr { ln_free(jsonPtr) } }
        guard let jsonPtr else { throw SDKError.connectionFailed }
        let data = String(cString: jsonPtr).data(using: .utf8)!
        guard let arr = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            throw SDKError.parseError("Expected array")
        }
        if err != LN_OK { throw SDKError.apiError(Int(err.rawValue), "Failed to list relays") }
        return arr
    }

    // MARK: - Certificates

    struct SDKCertStatusResponse: Codable {
        let domain: String?
        let has_cert: Bool?
        let expires_at: UInt64?
        let error: String?
    }

    func getCertStatus(domain: String) throws -> SDKCertStatusResponse {
        try callJSON { ln_cert_status($0, domain, $1) }
    }

    struct SDKCertIssueResponse: Codable {
        let domain: String?
        let fullchain_pem: String?
        let encrypted_privkey: String?
        let nonce: String?
        let ephemeral_pubkey: String?
        let expires_at: UInt64?
        let error: String?
    }

    func requestCert(hostname: String) throws -> SDKCertIssueResponse {
        try callJSON { ln_cert_request($0, hostname, $1) }
    }

    struct SDKDecryptedCert: Codable {
        let domain: String?
        let fullchain_pem: String?
        let privkey_pem: String?
        let expires_at: UInt64?
        let error: String?
    }

    func decryptCert(bundleJSON: String) throws -> SDKDecryptedCert {
        guard let client else { throw SDKError.notInitialized }
        var jsonPtr: UnsafeMutablePointer<CChar>? = nil
        let err = ln_cert_decrypt(client, bundleJSON, &jsonPtr)
        defer { if let jsonPtr { ln_free(jsonPtr) } }
        guard let jsonPtr else { throw SDKError.connectionFailed }
        let data = String(cString: jsonPtr).data(using: .utf8)!
        if err != LN_OK {
            if let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let error = obj["error"] as? String {
                throw SDKError.apiError(Int(err.rawValue), error)
            }
        }
        return try decoder.decode(SDKDecryptedCert.self, from: data)
    }

    // MARK: - Stats & Servers

    struct SDKStatsResponse: Codable {
        let service: String?
        let peer_count: UInt32?
        let private_api_enabled: Bool?
        let error: String?
    }

    func getStats() throws -> SDKStatsResponse {
        try callJSON { ln_stats($0, $1) }
    }

    func getServers() throws -> [[String: Any]] {
        guard let client else { throw SDKError.notInitialized }
        var jsonPtr: UnsafeMutablePointer<CChar>? = nil
        let err = ln_servers(client, &jsonPtr)
        defer { if let jsonPtr { ln_free(jsonPtr) } }
        guard let jsonPtr else { throw SDKError.connectionFailed }
        let data = String(cString: jsonPtr).data(using: .utf8)!
        guard let arr = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            throw SDKError.parseError("Expected array")
        }
        if err != LN_OK { throw SDKError.apiError(Int(err.rawValue), "Failed to get servers") }
        return arr
    }

    // MARK: - Trust & Attestation

    func getTrustStatus() throws -> [String: Any] {
        guard let client else { throw SDKError.notInitialized }
        var jsonPtr: UnsafeMutablePointer<CChar>? = nil
        let err = ln_trust_status(client, &jsonPtr)
        defer { if let jsonPtr { ln_free(jsonPtr) } }
        guard let jsonPtr else { throw SDKError.connectionFailed }
        let data = String(cString: jsonPtr).data(using: .utf8)!
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw SDKError.parseError("Invalid JSON")
        }
        if err != LN_OK, let error = obj["error"] as? String {
            throw SDKError.apiError(Int(err.rawValue), error)
        }
        return obj
    }

    // MARK: - DDNS

    struct SDKDdnsStatus: Codable {
        let has_credentials: Bool?
        let last_ip: String?
        let binary_hash: String?
        let binary_approved: Bool?
        let error: String?
    }

    func getDdnsStatus() throws -> SDKDdnsStatus {
        try callJSON { ln_ddns_status($0, $1) }
    }

    // MARK: - Enrollment

    func getEnrollmentStatus() throws -> [String: Any] {
        guard let client else { throw SDKError.notInitialized }
        var jsonPtr: UnsafeMutablePointer<CChar>? = nil
        let err = ln_enrollment_status(client, &jsonPtr)
        defer { if let jsonPtr { ln_free(jsonPtr) } }
        guard let jsonPtr else { throw SDKError.connectionFailed }
        let data = String(cString: jsonPtr).data(using: .utf8)!
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw SDKError.parseError("Invalid JSON")
        }
        if err != LN_OK, let error = obj["error"] as? String {
            throw SDKError.apiError(Int(err.rawValue), error)
        }
        return obj
    }

    // MARK: - Governance

    func getGovernanceProposals() throws -> [[String: Any]] {
        guard let client else { throw SDKError.notInitialized }
        var jsonPtr: UnsafeMutablePointer<CChar>? = nil
        let err = ln_governance_proposals(client, &jsonPtr)
        defer { if let jsonPtr { ln_free(jsonPtr) } }
        guard let jsonPtr else { throw SDKError.connectionFailed }
        let data = String(cString: jsonPtr).data(using: .utf8)!
        guard let arr = try JSONSerialization.jsonObject(with: data) as? [[String: Any]] else {
            throw SDKError.parseError("Expected array")
        }
        if err != LN_OK { throw SDKError.apiError(Int(err.rawValue), "Failed to get proposals") }
        return arr
    }

    // MARK: - Attestation Manifests

    func getAttestationManifests() throws -> [String: Any] {
        guard let client else { throw SDKError.notInitialized }
        var jsonPtr: UnsafeMutablePointer<CChar>? = nil
        let err = ln_attestation_manifests(client, &jsonPtr)
        defer { if let jsonPtr { ln_free(jsonPtr) } }
        guard let jsonPtr else { throw SDKError.connectionFailed }
        let data = String(cString: jsonPtr).data(using: .utf8)!
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw SDKError.parseError("Invalid JSON")
        }
        if err != LN_OK, let error = obj["error"] as? String {
            throw SDKError.apiError(Int(err.rawValue), error)
        }
        return obj
    }

    // MARK: - High-Level Operations

    struct SDKJoinResult: Codable {
        let success: Bool?
        let node_id: String?
        let tunnel_ip: String?
        let private_subnet: String?
        let wg_pubkey: String?
        let error: String?
    }

    func joinNetwork(username: String, password: String) throws -> SDKJoinResult {
        try callJSON { ln_join_network($0, username, password, $1) }
    }

    struct SDKLeaveResult: Codable {
        let success: Bool?
        let error: String?
    }

    func leaveNetwork() throws -> SDKLeaveResult {
        try callJSON { ln_leave_network($0, $1) }
    }

    // MARK: - WireGuard

    struct SDKTunnelStatus: Codable {
        let is_up: Bool?
        let tunnel_ip: String?
        let server_endpoint: String?
        let last_handshake: Int64?
        let rx_bytes: UInt64?
        let tx_bytes: UInt64?
        let latency_ms: Int32?
    }

    func tunnelStatus() throws -> SDKTunnelStatus {
        try callJSON { ln_tunnel_status($0, $1) }
    }

    func tunnelUp(configJSON: String) throws {
        guard let client else { throw SDKError.notInitialized }
        var jsonPtr: UnsafeMutablePointer<CChar>? = nil
        let err = ln_tunnel_up(client, configJSON, &jsonPtr)
        defer { if let jsonPtr { ln_free(jsonPtr) } }
        guard err == LN_OK else {
            throw SDKError.apiError(Int(err.rawValue), "Failed to bring up tunnel")
        }
    }

    func tunnelDown() throws {
        guard let client else { throw SDKError.notInitialized }
        var jsonPtr: UnsafeMutablePointer<CChar>? = nil
        let err = ln_tunnel_down(client, &jsonPtr)
        defer { if let jsonPtr { ln_free(jsonPtr) } }
        guard err == LN_OK else {
            throw SDKError.apiError(Int(err.rawValue), "Failed to bring down tunnel")
        }
    }

    var wireguardConfig: String? {
        guard let client else { return nil }
        guard let ptr = ln_get_wg_config(client) else { return nil }
        let result = String(cString: ptr)
        ln_free(ptr)
        return result
    }

    // MARK: - Group Membership

    func joinGroup(parentNodeId: String) throws -> [String: Any] {
        guard let client else { throw SDKError.notInitialized }
        var jsonPtr: UnsafeMutablePointer<CChar>? = nil
        let err = ln_join_group(client, parentNodeId, &jsonPtr)
        defer { if let jsonPtr { ln_free(jsonPtr) } }
        guard let jsonPtr else { throw SDKError.connectionFailed }
        let data = String(cString: jsonPtr).data(using: .utf8)!
        guard let obj = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw SDKError.parseError("Invalid JSON")
        }
        if err != LN_OK, let error = obj["error"] as? String {
            throw SDKError.apiError(Int(err.rawValue), error)
        }
        return obj
    }

    // MARK: - Mesh P2P Networking

    struct SDKMeshPeer: Codable, Identifiable, Hashable {
        var id: String { node_id }
        let node_id: String
        let hostname: String
        let wg_pubkey: String
        let tunnel_ip: String
        let private_subnet: String
        let endpoint: String
        let relay_endpoint: String
        let is_online: Bool
        let last_handshake: Int64
        let rx_bytes: UInt64
        let tx_bytes: UInt64
        let latency_ms: Int32
        let keepalive: UInt16
    }

    struct SDKMeshStatus: Codable {
        let is_up: Bool
        let tunnel_ip: String
        let peer_count: UInt32
        let online_count: UInt32
        let total_rx_bytes: UInt64
        let total_tx_bytes: UInt64
        let peers: [SDKMeshPeer]
    }

    func meshEnable() throws {
        guard let client else { throw SDKError.notInitialized }
        let err = ln_mesh_enable(client)
        guard err == LN_OK else {
            throw SDKError.apiError(Int(err.rawValue), "Failed to enable mesh")
        }
    }

    func meshEnableConfig(configJSON: String) throws {
        guard let client else { throw SDKError.notInitialized }
        let err = ln_mesh_enable_config(client, configJSON)
        guard err == LN_OK else {
            throw SDKError.apiError(Int(err.rawValue), "Failed to enable mesh")
        }
    }

    func meshDisable() throws {
        guard let client else { throw SDKError.notInitialized }
        let err = ln_mesh_disable(client)
        guard err == LN_OK else {
            throw SDKError.apiError(Int(err.rawValue), "Failed to disable mesh")
        }
    }

    func meshStatus() throws -> SDKMeshStatus {
        try callJSON { ln_mesh_status($0, $1) }
    }

    func meshPeers() throws -> [SDKMeshPeer] {
        guard let client else { throw SDKError.notInitialized }
        var jsonPtr: UnsafeMutablePointer<CChar>? = nil
        let err = ln_mesh_peers(client, &jsonPtr)
        defer { if let jsonPtr { ln_free(jsonPtr) } }
        guard let jsonPtr else { throw SDKError.connectionFailed }
        let jsonString = String(cString: jsonPtr)
        guard let jsonData = jsonString.data(using: .utf8) else {
            throw SDKError.parseError("Invalid UTF-8")
        }
        if err != LN_OK {
            throw SDKError.apiError(Int(err.rawValue), "Failed to get mesh peers")
        }
        return try JSONDecoder().decode([SDKMeshPeer].self, from: jsonData)
    }

    func meshRefresh() {
        guard let client else { return }
        ln_mesh_refresh(client)
    }

    // MARK: - Reconnect

    /// Reinitialize the client with a new host/port.
    func reconnect(host: String, port: UInt16, useTLS: Bool = false) {
        if let client { ln_destroy(client) }
        if useTLS {
            client = ln_create_tls(host, port)
        } else {
            client = ln_create(host, port)
        }
        // Re-attach identity if we have one
        if let client, let identity {
            ln_set_identity(client, identity)
        }
    }
}

// MARK: - SDK Error Type

enum SDKError: LocalizedError {
    case notInitialized
    case connectionFailed
    case noIdentity
    case identityNotFound
    case derivationFailed
    case parseError(String)
    case apiError(Int, String)

    var errorDescription: String? {
        switch self {
        case .notInitialized: return "SDK client not initialized"
        case .connectionFailed: return "Connection to server failed"
        case .noIdentity: return "No identity loaded"
        case .identityNotFound: return "Identity file not found"
        case .derivationFailed: return "Key derivation failed"
        case .parseError(let msg): return "Parse error: \(msg)"
        case .apiError(_, let msg): return msg
        }
    }
}

// MARK: - Identity Helper (PBKDF2 via SDK)

private extension NexusSDK {
    /// Derive seed using the C SDK's PBKDF2 implementation.
    static func derive_seed_swift(username: String, password: String) -> [UInt8] {
        guard let seedPtr = ln_derive_seed(username, password) else {
            return []
        }
        let seedBase64 = String(cString: seedPtr)
        ln_free(seedPtr)

        // Decode base64 seed to raw bytes
        guard let seedData = Data(base64Encoded: seedBase64) else {
            // Try URL-safe base64
            var urlSafe = seedBase64
                .replacingOccurrences(of: "-", with: "+")
                .replacingOccurrences(of: "_", with: "/")
            // Add padding if needed
            while urlSafe.count % 4 != 0 {
                urlSafe += "="
            }
            guard let data = Data(base64Encoded: urlSafe) else {
                return []
            }
            return Array(data)
        }
        return Array(seedData)
    }
}
