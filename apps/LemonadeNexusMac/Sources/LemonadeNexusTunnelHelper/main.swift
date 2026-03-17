/// Tunnel helper — runs BoringTun with privileges to create the utun device.
/// Launched by the main app via AppleScript privilege escalation.
/// Usage: LemonadeNexusTunnelHelper <config.json>
///
/// Reads WireGuard config JSON, brings up the tunnel (utun + BoringTun),
/// then stays alive until SIGTERM/SIGINT, at which point it tears down.

import Foundation
import CLemonadeNexusSDK

// MARK: - Signal handling

var running = true

func handleSignal(_ sig: Int32) {
    running = false
}

signal(SIGTERM, handleSignal)
signal(SIGINT, handleSignal)

// MARK: - Main

guard CommandLine.arguments.count >= 2 else {
    fputs("Usage: LemonadeNexusTunnelHelper <config.json>\n", stderr)
    exit(1)
}

let configPath = CommandLine.arguments[1]

guard let configData = FileManager.default.contents(atPath: configPath),
      let configJSON = String(data: configData, encoding: .utf8) else {
    fputs("Error: cannot read config file '\(configPath)'\n", stderr)
    exit(1)
}

// Create a minimal client — we only need tunnel functionality, not networking.
// Use 127.0.0.1:0 since we won't make any HTTP calls from the helper.
guard let client = ln_create("127.0.0.1", 0) else {
    fputs("Error: failed to create SDK client\n", stderr)
    exit(1)
}

// Bring up the tunnel (creates utun device, configures IP, starts BoringTun threads)
var outJson: UnsafeMutablePointer<CChar>? = nil
let err = ln_tunnel_up(client, configJSON, &outJson)
if let outJson { ln_free(outJson) }

guard err == LN_OK else {
    fputs("Error: tunnel bring-up failed (code \(err.rawValue))\n", stderr)
    ln_destroy(client)
    exit(1)
}

fputs("Tunnel up. PID=\(ProcessInfo.processInfo.processIdentifier). Send SIGTERM to stop.\n", stderr)

// Write our PID to a well-known file so the main app can signal us
let pidPath = "/tmp/lnsdk_tunnel.pid"
try? "\(ProcessInfo.processInfo.processIdentifier)".write(
    toFile: pidPath, atomically: true, encoding: .utf8)

// Stay alive until signalled
while running {
    Thread.sleep(forTimeInterval: 0.5)
}

// Tear down
fputs("Shutting down tunnel...\n", stderr)
var downJson: UnsafeMutablePointer<CChar>? = nil
_ = ln_tunnel_down(client, &downJson)
if let downJson { ln_free(downJson) }
ln_destroy(client)
try? FileManager.default.removeItem(atPath: pidPath)
fputs("Tunnel stopped.\n", stderr)
