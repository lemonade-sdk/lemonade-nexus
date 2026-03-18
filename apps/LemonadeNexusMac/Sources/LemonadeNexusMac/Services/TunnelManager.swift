import Foundation
import AppKit

/// Manages the WireGuard tunnel on macOS using the built-in BoringTun backend.
/// The main app stays unprivileged — only the tunnel helper binary is elevated
/// via the standard macOS password dialog (AppleScript `with administrator privileges`).
@MainActor
final class TunnelManager: ObservableObject {
    static let shared = TunnelManager()

    @Published var isTunnelActive: Bool = false
    @Published var isTransitioning: Bool = false
    @Published var lastError: String?

    private let configPath = "/tmp/lnsdk_wg0.json"
    private let pidPath = "/tmp/lnsdk_tunnel.pid"

    /// Clean up any stale tunnel from a previous app session.
    /// Called once on app launch before any tunnel operations.
    func cleanupStaleHelper() {
        killExistingHelper()
    }

    /// Path to the tunnel helper binary (built alongside the main app).
    private var helperPath: String {
        // The helper binary is in the same directory as the main app binary
        let mainBundle = Bundle.main.executablePath ?? ""
        let dir = (mainBundle as NSString).deletingLastPathComponent
        return "\(dir)/LemonadeNexusTunnelHelper"
    }

    // MARK: - Tunnel Control

    /// Write the WireGuard config and launch the tunnel helper with privilege escalation.
    /// Shows the macOS password dialog — the app itself never runs as root.
    func bringUp(config: String? = nil) async throws {
        guard !isTransitioning else { return }
        isTransitioning = true
        lastError = nil
        defer { isTransitioning = false }

        // Write config if provided
        if let config {
            try config.write(toFile: configPath, atomically: true, encoding: .utf8)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o600], ofItemAtPath: configPath)
        }

        guard FileManager.default.fileExists(atPath: configPath) else {
            throw TunnelError.noConfig
        }

        guard FileManager.default.fileExists(atPath: helperPath) else {
            throw TunnelError.helperNotFound(helperPath)
        }

        // Kill any existing tunnel helper first
        killExistingHelper()

        // AppleScript's `do shell script` waits for ALL child file descriptors
        // to close, not just the main process. We must fully detach the helper:
        //   - close stdin (<&-)
        //   - redirect stdout/stderr away from the pipe
        //   - disown to remove from job table
        let logPath = "/tmp/lnsdk_tunnel.log"
        let launcherPath = "/tmp/lnsdk_launcher.sh"
        let launcherContent = """
            #!/bin/bash
            "\(helperPath)" "\(configPath)" </dev/null >>/dev/null 2>"\(logPath)" &
            disown $!
            exit 0
            """
        try launcherContent.write(toFile: launcherPath, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o755], ofItemAtPath: launcherPath)

        let script = "do shell script \"/bin/bash \(launcherPath)\" with administrator privileges"

        var errorDict: NSDictionary?
        guard let appleScript = NSAppleScript(source: script) else {
            throw TunnelError.scriptError("Failed to create AppleScript")
        }

        appleScript.executeAndReturnError(&errorDict)

        if let errorDict {
            let msg = errorDict[NSAppleScript.errorMessage] as? String ?? "Unknown error"
            if let errorNum = errorDict[NSAppleScript.errorNumber] as? Int, errorNum == -128 {
                throw TunnelError.userCancelled
            }
            throw TunnelError.privilegeEscalationFailed(msg)
        }

        // Wait for the helper to write its PID file (confirms tunnel is up)
        for _ in 0..<20 {
            try? await Task.sleep(nanoseconds: 250_000_000)
            if FileManager.default.fileExists(atPath: pidPath) {
                isTunnelActive = true
                return
            }
        }

        // PID file not created — tunnel may have failed
        isTunnelActive = false
        throw TunnelError.tunnelFailed("Helper did not start within 5 seconds")
    }

    /// Stop the tunnel by signalling the helper process.
    func bringDown() async throws {
        guard !isTransitioning else { return }
        isTransitioning = true
        lastError = nil
        defer { isTransitioning = false }

        killExistingHelper()
        isTunnelActive = false
    }

    /// Check if the tunnel helper is still running.
    /// The helper runs as root, so kill(pid, 0) returns EPERM (errno 1) when
    /// the process exists but we lack permission — that still means it's alive.
    func refreshStatus() {
        guard let pidStr = try? String(contentsOfFile: pidPath, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
              let pid = Int32(pidStr) else {
            // No PID file — only mark inactive if we didn't just start the tunnel
            if !isTransitioning {
                isTunnelActive = false
            }
            return
        }
        let result = kill(pid, 0)
        // result == 0: we own the process (alive)
        // result == -1, errno == EPERM: process exists but owned by root (alive)
        // result == -1, errno == ESRCH: no such process (dead)
        isTunnelActive = (result == 0 || (result == -1 && errno == EPERM))
    }

    // MARK: - Private

    private func killExistingHelper() {
        guard let pidStr = try? String(contentsOfFile: pidPath, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
              let pid = Int32(pidStr) else { return }

        // Try direct kill first (works if we own the process)
        if kill(pid, SIGTERM) == 0 {
            for _ in 0..<10 {
                if kill(pid, 0) != 0 { break }
                Thread.sleep(forTimeInterval: 0.2)
            }
            if kill(pid, 0) == 0 {
                kill(pid, SIGKILL)
            }
        } else if errno == EPERM {
            // Helper runs as root — need privilege escalation to kill it
            let script = "do shell script \"kill \(pid) 2>/dev/null; sleep 1; kill -9 \(pid) 2>/dev/null; rm -f \(pidPath)\" with administrator privileges"
            if let as_ = NSAppleScript(source: script) {
                var err: NSDictionary?
                as_.executeAndReturnError(&err)
            }
        }

        try? FileManager.default.removeItem(atPath: pidPath)
    }
}

// MARK: - Error Types

enum TunnelError: LocalizedError {
    case helperNotFound(String)
    case noConfig
    case tunnelFailed(String)
    case scriptError(String)
    case privilegeEscalationFailed(String)
    case userCancelled

    var errorDescription: String? {
        switch self {
        case .helperNotFound(let path):
            return "Tunnel helper not found at \(path)"
        case .noConfig:
            return "No WireGuard configuration available. Join a network first."
        case .tunnelFailed(let output):
            return "Tunnel failed to start: \(output)"
        case .scriptError(let msg):
            return "Script error: \(msg)"
        case .privilegeEscalationFailed(let msg):
            return "Authorization failed: \(msg)"
        case .userCancelled:
            return "Authorization cancelled"
        }
    }
}
