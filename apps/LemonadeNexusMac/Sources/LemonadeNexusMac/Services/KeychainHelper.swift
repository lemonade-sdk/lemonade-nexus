import Foundation
import Security
import CryptoKit
import CommonCrypto

enum KeychainError: LocalizedError {
    case unableToSave(OSStatus)
    case unableToLoad(OSStatus)
    case unableToDelete(OSStatus)
    case itemNotFound
    case unexpectedData
    case derivationFailed

    var errorDescription: String? {
        switch self {
        case .unableToSave(let status):
            return "Keychain save failed: \(status)"
        case .unableToLoad(let status):
            return "Keychain load failed: \(status)"
        case .unableToDelete(let status):
            return "Keychain delete failed: \(status)"
        case .itemNotFound:
            return "Keychain item not found"
        case .unexpectedData:
            return "Unexpected keychain data format"
        case .derivationFailed:
            return "Key derivation failed"
        }
    }
}

struct StoredIdentity: Codable {
    let privateKey: Data
    let pubkey: String
    let username: String
}

enum KeychainHelper {
    private static let service = "io.lemonade-nexus.mac"
    private static let identityAccount = "identity"
    private static let sessionAccount = "session"

    // MARK: - PBKDF2 Key Derivation

    static func deriveEd25519Seed(username: String, password: String) throws -> Data {
        let salt = "lemonade-nexus:\(username)"
        guard let passwordData = password.data(using: .utf8),
              let saltData = salt.data(using: .utf8) else {
            throw KeychainError.derivationFailed
        }

        var derivedKey = Data(count: 32)
        let result = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            passwordData.withUnsafeBytes { passwordBytes in
                saltData.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                        passwordData.count,
                        saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        saltData.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        100_000,
                        derivedKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        32
                    )
                }
            }
        }

        guard result == kCCSuccess else {
            throw KeychainError.derivationFailed
        }

        return derivedKey
    }

    // MARK: - Identity Storage

    static func saveIdentity(privateKey: Data, pubkey: String, username: String) throws {
        let identity = StoredIdentity(privateKey: privateKey, pubkey: pubkey, username: username)
        let data = try JSONEncoder().encode(identity)
        try save(data: data, account: identityAccount)
    }

    static func loadIdentity() throws -> StoredIdentity {
        let data = try load(account: identityAccount)
        return try JSONDecoder().decode(StoredIdentity.self, from: data)
    }

    static func deleteIdentity() throws {
        try delete(account: identityAccount)
    }

    static func hasIdentity() -> Bool {
        do {
            _ = try loadIdentity()
            return true
        } catch {
            return false
        }
    }

    // MARK: - Session Token

    static func saveSessionToken(_ token: String) throws {
        guard let data = token.data(using: .utf8) else {
            throw KeychainError.unexpectedData
        }
        try save(data: data, account: sessionAccount)
    }

    static func loadSessionToken() throws -> String {
        let data = try load(account: sessionAccount)
        guard let token = String(data: data, encoding: .utf8) else {
            throw KeychainError.unexpectedData
        }
        return token
    }

    static func deleteSessionToken() throws {
        try delete(account: sessionAccount)
    }

    // MARK: - Key Export / Import

    static func exportIdentity() throws -> String {
        let identity = try loadIdentity()
        let data = try JSONEncoder().encode(identity)
        return data.base64EncodedString()
    }

    static func importIdentity(from base64String: String) throws {
        guard let data = Data(base64Encoded: base64String) else {
            throw KeychainError.unexpectedData
        }
        let identity = try JSONDecoder().decode(StoredIdentity.self, from: data)
        try saveIdentity(privateKey: identity.privateKey, pubkey: identity.pubkey, username: identity.username)
    }

    // MARK: - Generic Keychain Operations

    private static func save(data: Data, account: String) throws {
        // Delete any existing item first
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.unableToSave(status)
        }
    }

    private static func load(account: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess else {
            if status == errSecItemNotFound {
                throw KeychainError.itemNotFound
            }
            throw KeychainError.unableToLoad(status)
        }

        guard let data = result as? Data else {
            throw KeychainError.unexpectedData
        }

        return data
    }

    private static func delete(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]

        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unableToDelete(status)
        }
    }
}
