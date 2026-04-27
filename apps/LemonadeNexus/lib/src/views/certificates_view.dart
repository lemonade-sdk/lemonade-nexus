/// @title Certificates View
/// @description TLS certificate management.
///
/// Matches macOS CertificatesView.swift functionality:
/// - Certificate list with status
/// - Certificate detail panel
/// - Request certificate action
/// - Issue/renew certificate

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import '../state/app_state.dart';
import '../sdk/models.dart';

class CertificatesView extends ConsumerStatefulWidget {
  const CertificatesView({super.key});

  @override
  ConsumerState<CertificatesView> createState() => _CertificatesViewState();
}

class _CertificatesViewState extends ConsumerState<CertificatesView> {
  CertStatus? _selectedCert;
  bool _isLoading = false;
  final List<String> _certDomains = [];

  @override
  void initState() {
    super.initState();
    _loadCertificates();
  }

  Future<void> _loadCertificates() async {
    setState(() => _isLoading = true);
    final notifier = ref.read(appNotifierProvider.notifier);
    if (_certDomains.isEmpty) {
      // Add default domain for demo
      _certDomains.add('demo.lemonade-nexus.io');
    }
    await notifier.refreshCertificates(_certDomains);
    setState(() => _isLoading = false);
  }

  @override
  Widget build(BuildContext context) {
    final appState = ref.watch(appNotifierProvider);
    final certificates = appState.certificates;

    return Row(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Certificate list panel
        Container(
          width: 350,
          decoration: const BoxDecoration(
            color: Color(0xFF1A1A2E),
            border: Border(right: BorderSide(color: Color(0xFF2D3748), width: 1)),
          ),
          child: Column(
            children: [
              // Header
              Padding(
                padding: const EdgeInsets.all(16),
                child: Row(
                  children: [
                    const Icon(Icons.cert, color: Color(0xFFE9C46A), size: 20),
                    const SizedBox(width: 8),
                    const Text('Certificates', style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
                    const Spacer(),
                    IconButton(
                      icon: const Icon(Icons.add_circle, size: 20),
                      color: const Color(0xFFE9C46A),
                      onPressed: _showRequestDialog,
                      tooltip: 'Request Certificate',
                      padding: EdgeInsets.zero,
                      constraints: const BoxConstraints(),
                    ),
                    const SizedBox(width: 8),
                    IconButton(
                      icon: const Icon(Icons.refresh, size: 18),
                      color: const Color(0xFFA0AEC0),
                      onPressed: _loadCertificates,
                      padding: EdgeInsets.zero,
                      constraints: const BoxConstraints(),
                    ),
                  ],
                ),
              ),
              const Divider(color: Color(0xFF2D3748), height: 1),
              // List
              Expanded(
                child: _isLoading
                    ? const Center(child: CircularProgressIndicator())
                    : certificates.isEmpty
                        ? _buildEmptyState()
                        : ListView.builder(
                            padding: const EdgeInsets.all(8),
                            itemCount: certificates.length,
                            itemBuilder: (context, index) => _buildCertRow(certificates[index]),
                          ),
              ),
            ],
          ),
        ),
        // Detail panel
        Expanded(
          child: _selectedCert != null ? _buildDetailPanel(_selectedCert!) : _buildNoSelectionState(),
        ),
      ],
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.cert_outline, size: 48, color: Colors.white.withOpacity(0.2)),
          const SizedBox(height: 16),
          Text('No Certificates', style: TextStyle(color: Colors.white.withOpacity(0.6), fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 32),
            child: Text('Request a certificate to secure your domain with TLS.', textAlign: TextAlign.center, style: TextStyle(color: Colors.white.withOpacity(0.4), fontSize: 13)),
          ),
        ],
      ),
    );
  }

  Widget _buildCertRow(CertStatus cert) {
    final isSelected = _selectedCert?.domain == cert.domain;
    return Container(
      margin: const EdgeInsets.symmetric(vertical: 2, horizontal: 4),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: isSelected ? const Color(0xFFE9C46A).withOpacity(0.15) : Colors.transparent,
        borderRadius: BorderRadius.circular(8),
      ),
      child: InkWell(
        onTap: () => setState(() => _selectedCert = cert),
        child: Row(
          children: [
            _buildStatusIcon(cert.isIssued),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    cert.domain,
                    style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w600),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 4),
                  Row(
                    children: [
                      _buildBadge(text: cert.isIssued ? 'ISSUED' : 'NONE', color: cert.isIssued ? const Color(0xFF2A9D8F) : Colors.grey),
                      if (cert.domain.isNotEmpty) ...[
                        const SizedBox(width: 8),
                        Text('Expires: ${cert.domain.substring(0, 10)}', style: const TextStyle(color: Color(0xFF718096), fontSize: 10)),
                      ],
                    ],
                  ),
                ],
              ),
            ),
            const Icon(Icons.chevron_right, color: Color(0xFF718096), size: 16),
          ],
        ),
      ),
    );
  }

  Widget _buildStatusIcon(bool isIssued) {
    return Container(
      width: 32, height: 32,
      decoration: BoxDecoration(
        color: (isIssued ? const Color(0xFF2A9D8F) : Colors.grey).withOpacity(0.15),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Icon(
        isIssued ? Icons.check_circle : Icons.certificate_outlined,
        color: isIssued ? const Color(0xFF2A9D8F) : Colors.grey,
        size: 18,
      ),
    );
  }

  Widget _buildDetailPanel(CertStatus cert) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          Row(
            children: [
              Container(
                width: 56, height: 56,
                decoration: BoxDecoration(
                  color: (cert.isIssued ? const Color(0xFF2A9D8F) : Colors.grey).withOpacity(0.15),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Icon(
                  cert.isIssued ? Icons.check_circle : Icons.certificate_outlined,
                  color: cert.isIssued ? const Color(0xFF2A9D8F) : Colors.grey,
                  size: 28,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(cert.domain, style: const TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold)),
                    const SizedBox(height: 4),
                    _buildBadge(text: cert.isIssued ? 'ISSUED' : 'NONE', color: cert.isIssued ? const Color(0xFF2A9D8F) : Colors.grey),
                  ],
                ),
              ),
            ],
          ),
          const Divider(color: Color(0xFF2D3748), height: 24),
          // Details
          _buildDetailRow('Domain', cert.domain),
          _buildDetailRow('Status', cert.isIssued ? 'Issued' : 'Not Issued'),
          // Actions
          const SizedBox(height: 24),
          const Text('Actions', style: TextStyle(color: Colors.white, fontSize: 14, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: () => _issueCertificate(cert.domain),
              icon: const Icon(Icons.refresh),
              label: Text(cert.isIssued ? 'Renew Certificate' : 'Issue Certificate'),
              style: ElevatedButton.styleFrom(
                backgroundColor: const Color(0xFFE9C46A),
                foregroundColor: Colors.black,
                padding: const EdgeInsets.symmetric(vertical: 12),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildNoSelectionState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.cert_outline, size: 64, color: Colors.white.withOpacity(0.2)),
          const SizedBox(height: 16),
          Text('Select a Certificate', style: TextStyle(color: Colors.white.withOpacity(0.6), fontSize: 18, fontWeight: FontWeight.bold)),
          const SizedBox(height: 8),
          Text('Choose a certificate from the list to view details.', style: TextStyle(color: Colors.white.withOpacity(0.4), fontSize: 14), textAlign: TextAlign.center),
        ],
      ),
    );
  }

  Widget _buildDetailRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(width: 100, child: Text(label, style: const TextStyle(color: Color(0xFF718096), fontSize: 13))),
          Expanded(child: Text(value, style: const TextStyle(color: Colors.white, fontSize: 13, fontFamily: 'monospace'))),
        ],
      ),
    );
  }

  Widget _buildBadge({required String text, required Color color}) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      decoration: BoxDecoration(color: color.withOpacity(0.15), borderRadius: BorderRadius.circular(4)),
      child: Text(text, style: TextStyle(color: color, fontSize: 10, fontWeight: FontWeight.bold)),
    );
  }

  Future<void> _showRequestDialog() async {
    final domainController = TextEditingController(text: 'demo.lemonade-nexus.io');
    return showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: const Color(0xFF1A1A2E),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12), side: const BorderSide(color: Color(0xFF2D3748))),
        title: const Text('Request Certificate', style: TextStyle(color: Colors.white)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('Enter the domain to request a TLS certificate for.', style: TextStyle(color: Color(0xFFA0AEC0), fontSize: 13)),
            const SizedBox(height: 16),
            TextField(
              controller: domainController,
              decoration: InputDecoration(
                labelText: 'Domain',
                labelStyle: const TextStyle(color: Color(0xFFA0AEC0)),
                filled: true,
                fillColor: const Color(0xFF2D3748),
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(8), borderSide: BorderSide.none),
              ),
              style: const TextStyle(color: Colors.white),
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel', style: TextStyle(color: Color(0xFFA0AEC0)))),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              setState(() {
                if (!_certDomains.contains(domainController.text)) {
                  _certDomains.add(domainController.text);
                }
              });
              _issueCertificate(domainController.text);
            },
            style: ElevatedButton.styleFrom(backgroundColor: const Color(0xFFE9C46A), foregroundColor: Colors.black),
            child: const Text('Request'),
          ),
        ],
      ),
    );
  }

  Future<void> _issueCertificate(String domain) async {
    final notifier = ref.read(appNotifierProvider.notifier);
    final result = await notifier.requestCertificate(domain);
    if (result != null) {
      _loadCertificates();
    }
  }
}
