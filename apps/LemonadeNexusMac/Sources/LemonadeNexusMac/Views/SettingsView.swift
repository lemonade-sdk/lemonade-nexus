import SwiftUI
import AppKit

struct SettingsView: View {
    @EnvironmentObject private var appState: AppState
    @State private var serverURL: String = ""
    @State private var showExportAlert: Bool = false
    @State private var exportedKey: String = ""
    @State private var importKeyText: String = ""
    @State private var showImportSheet: Bool = false
    @State private var showSignOutConfirmation: Bool = false
    @State private var statusMessage: String?
    @State private var isStatusError: Bool = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                SectionHeaderView(title: "Settings", icon: "gearshape")

                // Server Configuration
                serverSection

                // Identity
                identitySection

                // Preferences
                preferencesSection

                // About
                aboutSection

                // Danger Zone
                dangerZone
            }
            .padding(24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.surfaceDark)
        .onAppear {
            serverURL = appState.serverURL
        }
        .sheet(isPresented: $showImportSheet) {
            importKeySheet
        }
        .alert("Sign Out", isPresented: $showSignOutConfirmation) {
            Button("Cancel", role: .cancel) { }
            Button("Sign Out", role: .destructive) {
                appState.signOut()
            }
        } message: {
            Text("Are you sure you want to sign out? You will need to re-enter your credentials.")
        }
    }

    // MARK: - Server Section

    private var serverSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Server Connection", systemImage: "link")
                .font(.headline)

            VStack(spacing: 14) {
                HStack {
                    Text("Server URL")
                        .font(.subheadline)
                        .foregroundColor(.textSecondary)
                        .frame(width: 120, alignment: .leading)
                    TextField("https://localhost:9100", text: $serverURL)
                        .textFieldStyle(.roundedBorder)
                    Button("Save") {
                        appState.serverURL = serverURL
                        appState.updateBaseURL()
                        showStatus("Server URL updated", isError: false)
                    }
                    .buttonStyle(LemonButtonStyle())
                }

                HStack {
                    Text("Status")
                        .font(.subheadline)
                        .foregroundColor(.textSecondary)
                        .frame(width: 120, alignment: .leading)
                    HStack(spacing: 6) {
                        StatusDot(isHealthy: appState.isServerHealthy)
                        Text(appState.isServerHealthy ? "Connected" : "Disconnected")
                            .font(.subheadline)
                            .foregroundColor(.textPrimary)
                    }
                    Spacer()
                    Button("Test Connection") {
                        Task {
                            await appState.refreshHealth()
                            if appState.isServerHealthy {
                                showStatus("Connection successful", isError: false)
                            } else {
                                showStatus("Connection failed", isError: true)
                            }
                        }
                    }
                    .buttonStyle(LemonButtonStyle(isProminent: false))
                }
            }
            .cardStyle()
        }
    }

    // MARK: - Identity Section

    private var identitySection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Identity", systemImage: "person.badge.key")
                .font(.headline)

            VStack(spacing: 14) {
                if let pubkey = appState.publicKeyBase64 {
                    HStack {
                        Text("Public Key")
                            .font(.subheadline)
                            .foregroundColor(.textSecondary)
                            .frame(width: 120, alignment: .leading)
                        Text(pubkey)
                            .font(.caption.monospaced())
                            .foregroundColor(.textPrimary)
                            .lineLimit(2)
                            .textSelection(.enabled)
                        Spacer()
                        Button(action: {
                            NSPasteboard.general.clearContents()
                            NSPasteboard.general.setString(pubkey, forType: .string)
                            showStatus("Public key copied to clipboard", isError: false)
                        }) {
                            Image(systemName: "doc.on.doc")
                                .font(.caption)
                        }
                        .buttonStyle(.plain)
                    }
                }

                if !appState.username.isEmpty {
                    HStack {
                        Text("Username")
                            .font(.subheadline)
                            .foregroundColor(.textSecondary)
                            .frame(width: 120, alignment: .leading)
                        Text(appState.username)
                            .font(.subheadline)
                            .foregroundColor(.textPrimary)
                        Spacer()
                    }
                }

                if let userId = appState.userId {
                    HStack {
                        Text("User ID")
                            .font(.subheadline)
                            .foregroundColor(.textSecondary)
                            .frame(width: 120, alignment: .leading)
                        Text(userId)
                            .font(.caption.monospaced())
                            .foregroundColor(.textPrimary)
                            .textSelection(.enabled)
                        Spacer()
                    }
                }

                Divider()

                HStack(spacing: 12) {
                    Button(action: exportIdentity) {
                        Label("Export Identity", systemImage: "square.and.arrow.up")
                    }
                    .buttonStyle(LemonButtonStyle(isProminent: false))

                    Button(action: { showImportSheet = true }) {
                        Label("Import Identity", systemImage: "square.and.arrow.down")
                    }
                    .buttonStyle(LemonButtonStyle(isProminent: false))
                }
            }
            .cardStyle()
        }
    }

    // MARK: - Preferences Section

    private var preferencesSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Preferences", systemImage: "slider.horizontal.3")
                .font(.headline)

            VStack(spacing: 14) {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("DNS Auto-discovery")
                            .font(.subheadline)
                            .foregroundColor(.textPrimary)
                        Text("Resolve lemonade-nexus.io to find the nearest server")
                            .font(.caption2)
                            .foregroundColor(.textTertiary)
                    }
                    Spacer()
                    Toggle("", isOn: $appState.autoDiscoveryEnabled)
                        .toggleStyle(.switch)
                        .tint(.lemonYellow)
                }

                HStack {
                    Text("Auto-connect on launch")
                        .font(.subheadline)
                        .foregroundColor(.textPrimary)
                    Spacer()
                    Toggle("", isOn: $appState.autoConnectOnLaunch)
                        .toggleStyle(.switch)
                        .tint(.lemonYellow)
                }

                HStack {
                    Text("Log Level")
                        .font(.subheadline)
                        .foregroundColor(.textPrimary)
                    Spacer()
                    Picker("", selection: $appState.logLevel) {
                        ForEach(LogLevel.allCases, id: \.self) { level in
                            Text(level.rawValue.capitalized).tag(level)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(width: 280)
                }
            }
            .cardStyle()
        }
    }

    // MARK: - About Section

    private var aboutSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("About", systemImage: "info.circle")
                .font(.headline)

            VStack(spacing: 10) {
                HStack {
                    Text("App Version")
                        .font(.subheadline)
                        .foregroundColor(.textSecondary)
                        .frame(width: 120, alignment: .leading)
                    Text("0.1.0")
                        .font(.subheadline.monospacedDigit())
                        .foregroundColor(.textPrimary)
                    Spacer()
                }
                HStack {
                    Text("Build")
                        .font(.subheadline)
                        .foregroundColor(.textSecondary)
                        .frame(width: 120, alignment: .leading)
                    Text("1")
                        .font(.subheadline.monospacedDigit())
                        .foregroundColor(.textPrimary)
                    Spacer()
                }
                HStack {
                    Text("Platform")
                        .font(.subheadline)
                        .foregroundColor(.textSecondary)
                        .frame(width: 120, alignment: .leading)
                    Text("macOS \(ProcessInfo.processInfo.operatingSystemVersionString)")
                        .font(.subheadline)
                        .foregroundColor(.textPrimary)
                    Spacer()
                }
            }
            .cardStyle()
        }
    }

    // MARK: - Danger Zone

    private var dangerZone: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Session", systemImage: "rectangle.portrait.and.arrow.right")
                .font(.headline)

            VStack(spacing: 14) {
                if let message = statusMessage {
                    HStack {
                        Image(systemName: isStatusError ? "exclamationmark.triangle.fill" : "checkmark.circle.fill")
                            .foregroundColor(isStatusError ? .red : .green)
                        Text(message)
                            .font(.caption)
                            .foregroundColor(isStatusError ? .red : .green)
                    }
                    .padding(10)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background((isStatusError ? Color.red : Color.green).opacity(0.1))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                }

                HStack {
                    Text("End your current session and return to the login screen.")
                        .font(.subheadline)
                        .foregroundColor(.textSecondary)
                    Spacer()
                    Button(action: { showSignOutConfirmation = true }) {
                        HStack {
                            Image(systemName: "rectangle.portrait.and.arrow.right")
                            Text("Sign Out")
                        }
                    }
                    .buttonStyle(.bordered)
                    .tint(.red)
                }
            }
            .cardStyle()
        }
    }

    // MARK: - Import Key Sheet

    private var importKeySheet: some View {
        VStack(spacing: 20) {
            Text("Import Identity")
                .font(.title2.bold())

            Text("Paste your exported identity key below to restore your identity on this device.")
                .font(.subheadline)
                .foregroundColor(.textSecondary)
                .multilineTextAlignment(.center)

            TextEditor(text: $importKeyText)
                .font(.system(size: 11, design: .monospaced))
                .frame(height: 120)
                .border(Color.textTertiary.opacity(0.3))
                .clipShape(RoundedRectangle(cornerRadius: 6))

            HStack(spacing: 12) {
                Button("Cancel") { showImportSheet = false }
                    .buttonStyle(LemonButtonStyle(isProminent: false))

                Button("Import") {
                    do {
                        try KeychainHelper.importIdentity(from: importKeyText.trimmingCharacters(in: .whitespacesAndNewlines))
                        showStatus("Identity imported successfully", isError: false)
                        showImportSheet = false
                    } catch {
                        showStatus("Import failed: \(error.localizedDescription)", isError: true)
                    }
                }
                .buttonStyle(LemonButtonStyle())
                .disabled(importKeyText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(32)
        .frame(width: 480)
    }

    // MARK: - Helpers

    private func exportIdentity() {
        do {
            let exported = try KeychainHelper.exportIdentity()
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(exported, forType: .string)
            showStatus("Identity exported to clipboard", isError: false)
        } catch {
            showStatus("Export failed: \(error.localizedDescription)", isError: true)
        }
    }

    private func showStatus(_ message: String, isError: Bool) {
        statusMessage = message
        isStatusError = isError
        Task {
            try? await Task.sleep(for: .seconds(4))
            await MainActor.run {
                if statusMessage == message {
                    statusMessage = nil
                }
            }
        }
    }
}
