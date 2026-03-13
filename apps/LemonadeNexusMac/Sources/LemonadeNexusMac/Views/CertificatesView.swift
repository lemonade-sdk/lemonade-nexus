import SwiftUI

struct CertificatesView: View {
    @EnvironmentObject private var appState: AppState
    @State private var selectedCert: CertStatusResponse?
    @State private var showRequestSheet: Bool = false
    @State private var issuedCerts: [CertIssueResponse] = []
    @State private var certDomains: [String] = []
    @State private var isLoading: Bool = false

    var body: some View {
        HSplitView {
            // Certificate List
            VStack(spacing: 0) {
                // Header
                HStack {
                    Text("Certificates")
                        .font(.headline)
                    Spacer()
                    Button(action: { showRequestSheet = true }) {
                        Image(systemName: "plus.circle.fill")
                            .foregroundColor(.lemonYellow)
                    }
                    .buttonStyle(.plain)
                    .help("Request Certificate")
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 12)

                Divider()

                if isLoading {
                    ProgressView("Loading certificates...")
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                } else if appState.certificates.isEmpty {
                    EmptyStateView(
                        icon: "lock.shield",
                        title: "No Certificates",
                        message: "Request a certificate to secure your domain with TLS."
                    )
                } else {
                    List(appState.certificates, selection: $selectedCert) { cert in
                        certRow(cert)
                            .tag(cert)
                    }
                    .listStyle(.inset(alternatesRowBackgrounds: true))
                }
            }
            .frame(minWidth: 300, idealWidth: 350)

            // Detail Panel
            if let cert = selectedCert {
                certDetailPanel(cert)
            } else {
                VStack(spacing: 16) {
                    Image(systemName: "lock.shield")
                        .font(.system(size: 48))
                        .foregroundColor(.textTertiary)
                    Text("Select a Certificate")
                        .font(.headline)
                        .foregroundColor(.textSecondary)
                    Text("Choose a certificate from the list to view its details.")
                        .font(.subheadline)
                        .foregroundColor(.textTertiary)
                        .multilineTextAlignment(.center)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color.surfaceDark)
            }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button(action: { Task { await refreshCerts() } }) {
                    Image(systemName: "arrow.clockwise")
                }
                .help("Refresh Certificates")
            }
        }
        .sheet(isPresented: $showRequestSheet) {
            RequestCertSheet { domain in
                certDomains.append(domain)
                Task { await refreshCerts() }
            }
        }
    }

    // MARK: - Certificate Row

    private func certRow(_ cert: CertStatusResponse) -> some View {
        HStack(spacing: 12) {
            certStatusIcon(cert.certStatus)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 2) {
                Text(cert.domain)
                    .font(.body)
                    .foregroundColor(.textPrimary)

                HStack(spacing: 8) {
                    certStatusBadge(cert.certStatus)

                    if let expiresAt = cert.expires_at {
                        Text("Expires \(relativeTimeString(from: expiresAt))")
                            .font(.caption2)
                            .foregroundColor(.textTertiary)
                    }
                }
            }

            Spacer()
        }
        .padding(.vertical, 4)
    }

    // MARK: - Detail Panel

    private func certDetailPanel(_ cert: CertStatusResponse) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                // Header
                HStack(spacing: 16) {
                    certStatusIcon(cert.certStatus)
                        .font(.system(size: 32))

                    VStack(alignment: .leading, spacing: 4) {
                        Text(cert.domain)
                            .font(.title2.bold())
                        certStatusBadge(cert.certStatus)
                    }

                    Spacer()
                }

                Divider()

                // Details
                VStack(alignment: .leading, spacing: 12) {
                    SectionHeaderView(title: "Certificate Details", icon: "doc.text")

                    VStack(spacing: 10) {
                        detailRow("Domain", value: cert.domain)
                        detailRow("Has Certificate", value: cert.has_cert ? "Yes" : "No")

                        if let expiresAt = cert.expires_at {
                            detailRow("Expires At", value: formatDate(expiresAt))
                            detailRow("Expires In", value: relativeTimeString(from: expiresAt))
                        }
                    }
                    .cardStyle()
                }

                // Issued cert details if available
                if let issued = issuedCerts.first(where: { $0.domain == cert.domain }) {
                    issuedCertSection(issued)
                }

                // Actions
                VStack(alignment: .leading, spacing: 12) {
                    SectionHeaderView(title: "Actions", icon: "bolt.circle")

                    HStack(spacing: 12) {
                        Button(action: { Task { await issueCert(domain: cert.domain) } }) {
                            HStack {
                                Image(systemName: "arrow.triangle.2.circlepath")
                                Text(cert.has_cert ? "Renew Certificate" : "Issue Certificate")
                            }
                        }
                        .buttonStyle(LemonButtonStyle())
                    }
                }
            }
            .padding(24)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .background(Color.surfaceDark)
    }

    // MARK: - Issued Certificate Section

    private func issuedCertSection(_ issued: CertIssueResponse) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeaderView(title: "Certificate Chain", icon: "lock.doc")

            VStack(alignment: .leading, spacing: 8) {
                Text("Full Chain PEM")
                    .font(.caption)
                    .foregroundColor(.textSecondary)
                ScrollView {
                    Text(issued.fullchain_pem)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.textPrimary)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 200)
                .padding(8)
                .background(Color(NSColor.textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 6))

                HStack {
                    Button(action: {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(issued.fullchain_pem, forType: .string)
                    }) {
                        Label("Copy PEM", systemImage: "doc.on.doc")
                            .font(.caption)
                    }
                    .buttonStyle(.bordered)

                    Spacer()

                    detailRow("Ephemeral Pubkey", value: String(issued.ephemeral_pubkey.prefix(24)) + "...")
                }
            }
            .cardStyle()
        }
    }

    // MARK: - Helpers

    private func certStatusIcon(_ status: CertStatus) -> some View {
        Group {
            switch status {
            case .valid:
                Image(systemName: "checkmark.shield.fill")
                    .foregroundColor(.green)
            case .expiring:
                Image(systemName: "exclamationmark.shield.fill")
                    .foregroundColor(.yellow)
            case .expired:
                Image(systemName: "xmark.shield.fill")
                    .foregroundColor(.red)
            case .none:
                Image(systemName: "shield.slash")
                    .foregroundColor(.gray)
            }
        }
    }

    private func certStatusBadge(_ status: CertStatus) -> BadgeView {
        switch status {
        case .valid:
            return BadgeView(text: "VALID", color: .green)
        case .expiring:
            return BadgeView(text: "EXPIRING", color: .yellow)
        case .expired:
            return BadgeView(text: "EXPIRED", color: .red)
        case .none:
            return BadgeView(text: "NONE", color: .gray)
        }
    }

    private func detailRow(_ label: String, value: String) -> some View {
        HStack {
            Text(label)
                .font(.subheadline)
                .foregroundColor(.textSecondary)
                .frame(width: 130, alignment: .leading)
            Text(value)
                .font(.subheadline)
                .foregroundColor(.textPrimary)
                .textSelection(.enabled)
            Spacer()
        }
    }

    // MARK: - Actions

    private func refreshCerts() async {
        isLoading = true
        await appState.refreshCertificates(domains: certDomains)
        isLoading = false
    }

    private func issueCert(domain: String) async {
        do {
            let sdkIssued = try appState.sdk.requestCert(hostname: domain)
            let issued = CertIssueResponse(
                domain: sdkIssued.domain ?? domain,
                fullchain_pem: sdkIssued.fullchain_pem ?? "",
                encrypted_privkey: sdkIssued.encrypted_privkey ?? "",
                nonce: sdkIssued.nonce ?? "",
                ephemeral_pubkey: sdkIssued.ephemeral_pubkey ?? "",
                expires_at: sdkIssued.expires_at.map {
                    ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: TimeInterval($0)))
                } ?? ""
            )
            issuedCerts.removeAll { $0.domain == domain }
            issuedCerts.append(issued)
            appState.addActivity(.success, "Certificate issued for \(domain)")
            await refreshCerts()
        } catch {
            appState.addActivity(.error, "Failed to issue cert: \(error.localizedDescription)")
        }
    }
}

// MARK: - Request Cert Sheet

struct RequestCertSheet: View {
    let onComplete: (String) -> Void

    @EnvironmentObject private var appState: AppState
    @Environment(\.dismiss) private var dismiss

    @State private var selectedHostname: String = ""
    @State private var isSubmitting: Bool = false
    @State private var errorMessage: String?

    /// Build FQDN from short hostname using the server's base domain.
    private func fqdn(for hostname: String) -> String {
        let base = appState.dnsBaseDomain
        if base.isEmpty {
            return hostname
        }
        return "\(hostname).capi.\(base)"
    }

    /// Collect all hostnames from the user's tree (root + children),
    /// displayed as full cert domains (hostname.capi.basedomain).
    private var availableEntries: [(hostname: String, fqdn: String)] {
        var seen = Set<String>()
        var entries: [(hostname: String, fqdn: String)] = []
        if let root = appState.rootNode, seen.insert(root.hostname).inserted {
            entries.append((root.hostname, fqdn(for: root.hostname)))
        }
        for node in appState.treeNodes {
            if seen.insert(node.hostname).inserted {
                entries.append((node.hostname, fqdn(for: node.hostname)))
            }
        }
        return entries
    }

    var body: some View {
        VStack(spacing: 20) {
            Text("Request Certificate")
                .font(.title2.bold())

            Text("Select a hostname from your tree to request a TLS certificate.")
                .font(.subheadline)
                .foregroundColor(.textSecondary)
                .multilineTextAlignment(.center)

            if availableEntries.isEmpty {
                Text("No hostnames available. Add endpoints to your tree first.")
                    .font(.caption)
                    .foregroundColor(.textTertiary)
                    .padding(.vertical, 8)
            } else {
                Picker("Hostname", selection: $selectedHostname) {
                    Text("Select a hostname...").tag("")
                    ForEach(availableEntries, id: \.hostname) { entry in
                        Text(entry.fqdn).tag(entry.hostname)
                    }
                }
                .pickerStyle(.menu)
                .frame(maxWidth: 400)
            }

            if let error = errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
            }

            HStack(spacing: 12) {
                Button("Cancel") { dismiss() }
                    .buttonStyle(LemonButtonStyle(isProminent: false))

                Button("Request") {
                    Task { await requestCert() }
                }
                .buttonStyle(LemonButtonStyle())
                .disabled(selectedHostname.isEmpty || isSubmitting)
            }
        }
        .padding(32)
        .frame(width: 420)
        .onAppear {
            // Pre-select the first hostname if available
            if selectedHostname.isEmpty, let first = availableEntries.first {
                selectedHostname = first.hostname
            }
        }
    }

    private func requestCert() async {
        isSubmitting = true
        errorMessage = nil

        let domain = fqdn(for: selectedHostname)
        do {
            _ = try appState.sdk.requestCert(hostname: selectedHostname)
            appState.addActivity(.success, "Certificate requested for \(domain)")
            onComplete(domain)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }

        isSubmitting = false
    }
}
