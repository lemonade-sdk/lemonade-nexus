/// @title Certificates View
/// @description TLS certificate management.
///
/// Matches macOS CertificatesView.swift functionality:
/// - Certificate list with status
/// - Certificate detail panel
/// - Request certificate action
/// - Issue/renew certificate
library;

import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import '../sdk/models.dart';
import '../../theme/app_theme.dart';
import '../../theme/components.dart';

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

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          Row(
            children: [
              const SectionHeader(title: 'Certificates', icon: Icons.verified_user),
              const Spacer(),
              IconButton(
                icon: const Icon(Icons.add_circle, size: 20),
                onPressed: _showRequestDialog,
                tooltip: 'Request Certificate',
              ),
              IconButton(
                icon: const Icon(Icons.refresh, size: 20),
                onPressed: _loadCertificates,
                tooltip: 'Refresh',
              ),
            ],
          ),
          const SizedBox(height: 20),
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Certificate list panel
              SizedBox(
                width: 350,
                child: _isLoading
                    ? const Center(child: CircularProgressIndicator())
                    : certificates.isEmpty
                        ? _buildEmptyState()
                        : Column(
                            children: [
                              for (final cert in certificates) _buildCertRow(cert),
                            ],
                          ),
              ),
              const SizedBox(width: 16),
              // Detail panel
              Expanded(
                child: _selectedCert != null
                    ? _buildDetailPanel(_selectedCert!)
                    : _buildNoSelectionState(),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyState() {
    return const EmptyState(
      icon: Icons.verified_user_outlined,
      title: 'No Certificates',
      message: 'Request a certificate to secure your domain with TLS.',
    );
  }

  Widget _buildCertRow(CertStatus cert) {
    final scheme = Theme.of(context).colorScheme;
    final isSelected = _selectedCert?.domain == cert.domain;
    return Container(
      margin: const EdgeInsets.symmetric(vertical: 4),
      child: AppCard(
        padding: EdgeInsets.zero,
        child: InkWell(
          onTap: () => setState(() => _selectedCert = cert),
          borderRadius: BorderRadius.circular(12),
          child: Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: isSelected
                  ? AppTheme.lemonYellow.withValues(alpha: 0.15)
                  : Colors.transparent,
              borderRadius: BorderRadius.circular(12),
            ),
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
                        style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                      ),
                      const SizedBox(height: 4),
                      Row(
                        children: [
                          LemonBadge(
                            text: cert.isIssued ? 'ISSUED' : 'NONE',
                            color: cert.isIssued ? AppTheme.lemonGreen : Colors.grey,
                          ),
                          if (cert.domain.isNotEmpty) ...[
                            const SizedBox(width: 8),
                            Text('Expires: ${cert.domain.substring(0, 10)}',
                                style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 10)),
                          ],
                        ],
                      ),
                    ],
                  ),
                ),
                Icon(Icons.chevron_right, color: scheme.onSurfaceVariant, size: 16),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildStatusIcon(bool isIssued) {
    final color = isIssued ? AppTheme.lemonGreen : Colors.grey;
    return Container(
      width: 32, height: 32,
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Icon(
        isIssued ? Icons.check_circle : Icons.verified_user_outlined,
        color: color,
        size: 18,
      ),
    );
  }

  Widget _buildDetailPanel(CertStatus cert) {
    final scheme = Theme.of(context).colorScheme;
    final iconColor = cert.isIssued ? AppTheme.lemonGreen : Colors.grey;
    return AppCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          Row(
            children: [
              Container(
                width: 56, height: 56,
                decoration: BoxDecoration(
                  color: iconColor.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Icon(
                  cert.isIssued ? Icons.check_circle : Icons.verified_user_outlined,
                  color: iconColor,
                  size: 28,
                ),
              ),
              const SizedBox(width: 16),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(cert.domain,
                        style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold)),
                    const SizedBox(height: 4),
                    LemonBadge(
                      text: cert.isIssued ? 'ISSUED' : 'NONE',
                      color: cert.isIssued ? AppTheme.lemonGreen : Colors.grey,
                    ),
                  ],
                ),
              ),
            ],
          ),
          Divider(height: 24, color: scheme.outline),
          // Details
          _buildDetailRow('Domain', cert.domain),
          _buildDetailRow('Status', cert.isIssued ? 'Issued' : 'Not Issued'),
          // Actions
          const SizedBox(height: 24),
          const SectionHeader(title: 'Actions', icon: Icons.bolt),
          const SizedBox(height: 12),
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: () => _issueCertificate(cert.domain),
              icon: const Icon(Icons.refresh),
              label: Text(cert.isIssued ? 'Renew Certificate' : 'Issue Certificate'),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildNoSelectionState() {
    return const EmptyState(
      icon: Icons.verified_user_outlined,
      title: 'Select a Certificate',
      message: 'Choose a certificate from the list to view details.',
    );
  }

  Widget _buildDetailRow(String label, String value) {
    final scheme = Theme.of(context).colorScheme;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 100,
            child: Text(label,
                style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 13)),
          ),
          Expanded(
            child: Text(value,
                style: const TextStyle(fontSize: 13, fontFamily: 'monospace')),
          ),
        ],
      ),
    );
  }

  Future<void> _showRequestDialog() async {
    final scheme = Theme.of(context).colorScheme;
    final domainController = TextEditingController(text: 'demo.lemonade-nexus.io');
    return showDialog(
      context: context,
      builder: (context) => AlertDialog(
        backgroundColor: scheme.surface,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: BorderSide(color: scheme.outline),
        ),
        title: const Text('Request Certificate'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text('Enter the domain to request a TLS certificate for.',
                style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 13)),
            const SizedBox(height: 16),
            TextField(
              controller: domainController,
              decoration: const InputDecoration(labelText: 'Domain'),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
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
