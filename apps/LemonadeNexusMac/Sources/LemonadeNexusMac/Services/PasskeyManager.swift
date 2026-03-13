import Foundation
import CryptoKit
import LocalAuthentication

enum PasskeyError: LocalizedError {
    case secureEnclaveUnavailable
    case noCredentialStored
    case keyGenerationFailed(String)
    case signingFailed(String)
    case biometricFailed(String)
    case keychainError(OSStatus)

    var errorDescription: String? {
        switch self {
        case .secureEnclaveUnavailable:
            return "Secure Enclave is not available on this device"
        case .noCredentialStored:
            return "No passkey credential found. Register first."
        case .keyGenerationFailed(let detail):
            return "Key generation failed: \(detail)"
        case .signingFailed(let detail):
            return "Signing failed: \(detail)"
        case .biometricFailed(let detail):
            return "Biometric authentication failed: \(detail)"
        case .keychainError(let status):
            return "Keychain error: \(status)"
        }
    }
}

struct PasskeyCredentialInfo: Codable {
    let credentialId: String    // base64url
    let userId: String
    let privateKeyTag: String   // Keychain tag for SE key reference
    var signCount: UInt32 = 0
}

final class PasskeyManager {
    static let shared = PasskeyManager()

    private let service = "io.lemonade-nexus.passkey"
    private let credentialAccount = "passkey-credential"

    private init() {}

    // MARK: - Registration

    /// Generate a new P-256 passkey in the Secure Enclave (or software fallback).
    /// Returns (credentialId, publicKeyX_hex, publicKeyY_hex).
    func generateCredential(userId: String) throws -> (credentialId: String, publicKeyX: String, publicKeyY: String) {
        let tag = "io.lemonade-nexus.passkey.\(UUID().uuidString)"

        let privateKey: P256.Signing.PrivateKey

        if SecureEnclave.isAvailable {
            // Secure Enclave: key never leaves hardware, biometric required for signing
            var accessError: Unmanaged<CFError>?
            guard let access = SecAccessControlCreateWithFlags(
                nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                [.privateKeyUsage, .biometryCurrentSet],
                &accessError
            ) else {
                throw PasskeyError.keyGenerationFailed("Failed to create access control")
            }

            let seKey = try SecureEnclave.P256.Signing.PrivateKey(
                accessControl: access
            )

            // Store SE key data representation in Keychain
            try saveToKeychain(data: seKey.dataRepresentation, tag: tag)

            // Extract public key from SE key
            let pubKeyRaw = seKey.publicKey.rawRepresentation  // 64 bytes: x || y
            let x = pubKeyRaw.prefix(32)
            let y = pubKeyRaw.suffix(32)

            let credentialId = Data(SHA256.hash(data: pubKeyRaw)).base64urlEncoded()

            let info = PasskeyCredentialInfo(
                credentialId: credentialId,
                userId: userId,
                privateKeyTag: tag,
                signCount: 0
            )
            try saveCredentialInfo(info)

            return (credentialId, x.hexEncodedString(), y.hexEncodedString())
        } else {
            // Software fallback (for VMs, older Macs without T2/Apple Silicon)
            privateKey = P256.Signing.PrivateKey()
            try saveToKeychain(data: privateKey.rawRepresentation, tag: tag)

            let pubKeyRaw = privateKey.publicKey.rawRepresentation
            let x = pubKeyRaw.prefix(32)
            let y = pubKeyRaw.suffix(32)

            let credentialId = Data(SHA256.hash(data: pubKeyRaw)).base64urlEncoded()

            let info = PasskeyCredentialInfo(
                credentialId: credentialId,
                userId: userId,
                privateKeyTag: tag,
                signCount: 0
            )
            try saveCredentialInfo(info)

            return (credentialId, x.hexEncodedString(), y.hexEncodedString())
        }
    }

    // MARK: - Authentication (Assertion)

    /// Sign a WebAuthn assertion. Triggers Touch ID if using Secure Enclave.
    /// Returns (credentialId, authenticatorData_base64url, clientDataJson_base64url, signature_base64url_DER).
    func signAssertion(rpId: String) throws -> (credentialId: String, authenticatorData: String, clientDataJson: String, signature: String) {
        guard var info = loadCredentialInfo() else {
            throw PasskeyError.noCredentialStored
        }

        // Increment sign count
        info.signCount += 1
        try saveCredentialInfo(info)

        // Build authenticator data: rpIdHash (32) + flags (1) + signCount (4) = 37 bytes
        var authData = Data()
        let rpIdHash = SHA256.hash(data: Data(rpId.utf8))
        authData.append(contentsOf: rpIdHash)
        authData.append(0x05)  // flags: UP (0x01) | UV (0x04) = user present + user verified
        withUnsafeBytes(of: info.signCount.bigEndian) { authData.append(contentsOf: $0) }

        // Build clientDataJSON
        var challengeBytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, 32, &challengeBytes)
        let challenge = Data(challengeBytes).base64urlEncoded()

        let clientDataDict: [String: String] = [
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": rpId
        ]
        let clientDataJson = try JSONSerialization.data(
            withJSONObject: clientDataDict,
            options: [.sortedKeys]
        )

        // Compute signed data: authenticatorData || SHA-256(clientDataJSON)
        let clientDataHash = SHA256.hash(data: clientDataJson)
        var signedData = authData
        signedData.append(contentsOf: clientDataHash)

        // Load key and sign
        let keyData = try loadFromKeychain(tag: info.privateKeyTag)
        let derSignature: Data

        if SecureEnclave.isAvailable {
            let context = LAContext()
            context.localizedReason = "Sign in with your passkey"
            let seKey = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: keyData,
                authenticationContext: context
            )
            let sig = try seKey.signature(for: signedData)
            derSignature = sig.derRepresentation
        } else {
            let softwareKey = try P256.Signing.PrivateKey(rawRepresentation: keyData)
            let sig = try softwareKey.signature(for: signedData)
            derSignature = sig.derRepresentation
        }

        return (
            info.credentialId,
            authData.base64urlEncoded(),
            clientDataJson.base64urlEncoded(),
            derSignature.base64urlEncoded()
        )
    }

    // MARK: - Credential Info Check

    var hasCredential: Bool {
        loadCredentialInfo() != nil
    }

    var storedUserId: String? {
        loadCredentialInfo()?.userId
    }

    func deleteCredential() {
        guard let info = loadCredentialInfo() else { return }
        // Delete the private key
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: info.privateKeyTag,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        // Delete credential info
        let infoQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: credentialAccount,
        ]
        SecItemDelete(infoQuery as CFDictionary)
    }

    // MARK: - Keychain Helpers

    private func saveToKeychain(data: Data, tag: String) throws {
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: tag,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: tag,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw PasskeyError.keychainError(status)
        }
    }

    private func loadFromKeychain(tag: String) throws -> Data {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: tag,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            throw PasskeyError.keychainError(status)
        }
        return data
    }

    private func saveCredentialInfo(_ info: PasskeyCredentialInfo) throws {
        let data = try JSONEncoder().encode(info)
        try saveToKeychain(data: data, tag: credentialAccount)
    }

    private func loadCredentialInfo() -> PasskeyCredentialInfo? {
        guard let data = try? loadFromKeychain(tag: credentialAccount) else { return nil }
        return try? JSONDecoder().decode(PasskeyCredentialInfo.self, from: data)
    }
}

// MARK: - Data Extensions for base64url and hex

extension Data {
    func base64urlEncoded() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    func hexEncodedString() -> String {
        map { String(format: "%02x", $0) }.joined()
    }
}
