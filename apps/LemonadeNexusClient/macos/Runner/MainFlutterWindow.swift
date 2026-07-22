import Cocoa
import FlutterMacOS
import CryptoKit
import LocalAuthentication

class MainFlutterWindow: NSWindow {
  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    RegisterGeneratedPlugins(registry: flutterViewController)
    PasskeyManager.register(with: flutterViewController.engine.binaryMessenger)

    super.awakeFromNib()
  }
}

/// Secure-Enclave-backed passkey (WebAuthn) manager, ported from the macOS app.
/// Exposed to Flutter over the `io.lemonade-nexus/passkey` MethodChannel.
final class PasskeyManager {
  static let shared = PasskeyManager()

  private let service = "io.lemonade-nexus.passkey"
  private let credentialAccount = "passkey-credential"

  struct CredentialInfo: Codable {
    let credentialId: String
    let userId: String
    let privateKeyTag: String
    var signCount: UInt32 = 0
  }

  enum PasskeyError: Error { case noCredential, keychain(OSStatus), keygen(String) }

  var hasCredential: Bool { loadCredentialInfo() != nil }
  var storedUserId: String? { loadCredentialInfo()?.userId }

  /// Generate a new P-256 passkey. Returns (credentialId, publicKeyX_hex, publicKeyY_hex).
  func generateCredential(userId: String) throws -> (String, String, String) {
    let tag = "io.lemonade-nexus.passkey.\(UUID().uuidString)"
    let pubKeyRaw: Data

    if SecureEnclave.isAvailable {
      var accessError: Unmanaged<CFError>?
      guard let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet],
        &accessError
      ) else { throw PasskeyError.keygen("access control") }
      let seKey = try SecureEnclave.P256.Signing.PrivateKey(accessControl: access)
      try saveToKeychain(data: seKey.dataRepresentation, tag: tag)
      pubKeyRaw = seKey.publicKey.rawRepresentation
    } else {
      let key = P256.Signing.PrivateKey()
      try saveToKeychain(data: key.rawRepresentation, tag: tag)
      pubKeyRaw = key.publicKey.rawRepresentation
    }

    let x = pubKeyRaw.prefix(32), y = pubKeyRaw.suffix(32)
    let credentialId = Data(SHA256.hash(data: pubKeyRaw)).base64urlEncoded()
    try saveCredentialInfo(CredentialInfo(
      credentialId: credentialId, userId: userId, privateKeyTag: tag, signCount: 0))
    return (credentialId, x.hexEncodedString(), y.hexEncodedString())
  }

  /// Sign a WebAuthn assertion (triggers Touch ID for Secure Enclave keys).
  /// Returns (credentialId, authenticatorData, clientDataJson, signature) — all base64url.
  func signAssertion(rpId: String) throws -> (String, String, String, String) {
    guard var info = loadCredentialInfo() else { throw PasskeyError.noCredential }
    info.signCount += 1
    try saveCredentialInfo(info)

    var authData = Data()
    authData.append(contentsOf: SHA256.hash(data: Data(rpId.utf8)))
    authData.append(0x05) // UP | UV
    withUnsafeBytes(of: info.signCount.bigEndian) { authData.append(contentsOf: $0) }

    var challengeBytes = [UInt8](repeating: 0, count: 32)
    _ = SecRandomCopyBytes(kSecRandomDefault, 32, &challengeBytes)
    let clientData = try JSONSerialization.data(
      withJSONObject: [
        "type": "webauthn.get",
        "challenge": Data(challengeBytes).base64urlEncoded(),
        "origin": rpId,
      ],
      options: [.sortedKeys])

    var signedData = authData
    signedData.append(contentsOf: SHA256.hash(data: clientData))

    let keyData = try loadFromKeychain(tag: info.privateKeyTag)
    let derSignature: Data
    if SecureEnclave.isAvailable {
      let context = LAContext()
      context.localizedReason = "Sign in with your passkey"
      let seKey = try SecureEnclave.P256.Signing.PrivateKey(
        dataRepresentation: keyData, authenticationContext: context)
      derSignature = try seKey.signature(for: signedData).derRepresentation
    } else {
      let key = try P256.Signing.PrivateKey(rawRepresentation: keyData)
      derSignature = try key.signature(for: signedData).derRepresentation
    }

    return (info.credentialId, authData.base64urlEncoded(),
            clientData.base64urlEncoded(), derSignature.base64urlEncoded())
  }

  func deleteCredential() {
    guard let info = loadCredentialInfo() else { return }
    for account in [info.privateKeyTag, credentialAccount] {
      SecItemDelete([
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
      ] as CFDictionary)
    }
  }

  // MARK: Keychain

  private func saveToKeychain(data: Data, tag: String) throws {
    SecItemDelete([
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: tag,
    ] as CFDictionary)
    let status = SecItemAdd([
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: tag,
      kSecValueData as String: data,
      kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
    ] as CFDictionary, nil)
    guard status == errSecSuccess else { throw PasskeyError.keychain(status) }
  }

  private func loadFromKeychain(tag: String) throws -> Data {
    var result: AnyObject?
    let status = SecItemCopyMatching([
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: service,
      kSecAttrAccount as String: tag,
      kSecReturnData as String: true,
      kSecMatchLimit as String: kSecMatchLimitOne,
    ] as CFDictionary, &result)
    guard status == errSecSuccess, let data = result as? Data else {
      throw PasskeyError.keychain(status)
    }
    return data
  }

  private func saveCredentialInfo(_ info: CredentialInfo) throws {
    try saveToKeychain(data: try JSONEncoder().encode(info), tag: credentialAccount)
  }

  private func loadCredentialInfo() -> CredentialInfo? {
    guard let data = try? loadFromKeychain(tag: credentialAccount) else { return nil }
    return try? JSONDecoder().decode(CredentialInfo.self, from: data)
  }

  // MARK: Channel

  static func register(with messenger: FlutterBinaryMessenger) {
    let channel = FlutterMethodChannel(
      name: "io.lemonade-nexus/passkey", binaryMessenger: messenger)
    channel.setMethodCallHandler { call, result in
      let mgr = PasskeyManager.shared
      let args = call.arguments as? [String: Any] ?? [:]
      do {
        switch call.method {
        case "hasCredential":
          result(mgr.hasCredential)
        case "storedUserId":
          result(mgr.storedUserId)
        case "deleteCredential":
          mgr.deleteCredential(); result(nil)
        case "generateCredential":
          let (id, x, y) = try mgr.generateCredential(userId: args["userId"] as? String ?? "")
          result(["credentialId": id, "publicKeyX": x, "publicKeyY": y])
        case "signAssertion":
          let (id, ad, cd, sig) = try mgr.signAssertion(
            rpId: args["rpId"] as? String ?? "lemonade-nexus.io")
          result(["credentialId": id, "authenticatorData": ad,
                  "clientDataJson": cd, "signature": sig])
        default:
          result(FlutterMethodNotImplemented)
        }
      } catch {
        result(FlutterError(code: "passkey_error", message: "\(error)", details: nil))
      }
    }
  }
}

private extension Data {
  func base64urlEncoded() -> String {
    base64EncodedString()
      .replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_")
      .replacingOccurrences(of: "=", with: "")
  }
  func hexEncodedString() -> String { map { String(format: "%02x", $0) }.joined() }
}
