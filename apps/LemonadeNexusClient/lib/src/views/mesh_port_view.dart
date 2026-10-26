/// @title Mesh Port View
/// @description Device URLs served on 127.0.0.1:13306, the selection, and TLS state.
library;

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'package:lemonade_nexus_sdk/lemonade_nexus_sdk.dart';
import '../state/providers.dart';
import '../../theme/app_theme.dart';
import '../../theme/components.dart';

class MeshPortView extends ConsumerWidget {
  const MeshPortView({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final status = ref.watch(appNotifierProvider.select((s) => s.meshPortStatus));
    final notifier = ref.read(appNotifierProvider.notifier);
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: MeshPortPanel(
        status: status,
        onSelect: notifier.setMeshPortSelection,
        onRetry: notifier.startMeshPort,
      ),
    );
  }
}

/// Selection value of the dropdown that means "no selection".
const String _noSelection = '';

/// Renders a [MeshPortStatus]. Holds no state, so tests can pump it directly.
class MeshPortPanel extends StatelessWidget {
  final MeshPortStatus status;
  final ValueChanged<String?> onSelect;
  final VoidCallback? onRetry;

  /// Copies a URL. Defaults to the system clipboard.
  final Future<void> Function(String url)? onCopy;

  const MeshPortPanel({
    super.key,
    required this.status,
    required this.onSelect,
    this.onRetry,
    this.onCopy,
  });

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            const SectionHeader(title: 'Mesh Port', icon: Icons.lan),
            const Spacer(),
            _TlsBadge(status: status),
          ],
        ),
        const SizedBox(height: 16),
        if (status.error.isNotEmpty) ...[
          _Notice(
            key: const ValueKey('mesh-port-error'),
            text: status.error,
            color: AppTheme.errorColor,
            action: !status.running && onRetry != null
                ? TextButton(onPressed: onRetry, child: const Text('Retry'))
                : null,
          ),
          const SizedBox(height: 12),
        ],
        if (status.running && status.tlsError.isNotEmpty && !status.tlsActive) ...[
          _Notice(text: status.tlsError, color: AppTheme.nodeOrange),
          const SizedBox(height: 12),
        ],
        AppCard(child: _selection(context)),
        const SizedBox(height: 16),
        AppCard(child: _urls(context)),
      ],
    );
  }

  Widget _selection(BuildContext context) {
    final items = <DropdownMenuItem<String>>[
      const DropdownMenuItem(value: _noSelection, child: Text('None')),
      const DropdownMenuItem(value: 'auto', child: Text('Auto')),
      if (status.localService) const DropdownMenuItem(value: 'local', child: Text('This device')),
      for (final device in status.devices)
        DropdownMenuItem(
          value: device.nodeId,
          child: Text(device.isOnline ? device.label : '${device.label} (offline)'),
        ),
    ];
    final current = status.selection ?? _noSelection;
    final known = items.any((item) => item.value == current);
    return Row(
      children: [
        const Expanded(
          child: Text('This device\'s name serves', style: TextStyle(fontWeight: FontWeight.w600)),
        ),
        DropdownButton<String>(
          key: const ValueKey('mesh-port-selection'),
          value: known ? current : _noSelection,
          items: items,
          onChanged: status.running
              ? (value) => onSelect(value == null || value == _noSelection ? null : value)
              : null,
        ),
      ],
    );
  }

  Widget _urls(BuildContext context) {
    if (!status.running) {
      return const EmptyState(
        icon: Icons.lan_outlined,
        title: 'Mesh port is off',
        message: 'Connect and turn on the mesh to serve group devices on port 13306.',
      );
    }
    if (status.urls.isEmpty) {
      return const EmptyState(
        icon: Icons.devices_other,
        title: 'No reachable devices',
        message: 'Online Tier 3 devices that you may connect to appear here.',
      );
    }
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (final url in status.urls)
          ListTile(
            key: ValueKey('mesh-port-url-${url.nodeId}'),
            contentPadding: EdgeInsets.zero,
            leading: Icon(url.isSelf ? Icons.computer : Icons.dns),
            title: Text(url.isSelf
                ? 'This device'
                : (url.deviceName.isEmpty ? url.nodeId : url.deviceName)),
            subtitle: SelectableText(url.url),
            trailing: IconButton(
              key: ValueKey('mesh-port-copy-${url.nodeId}'),
              icon: const Icon(Icons.copy, size: 18),
              tooltip: 'Copy URL',
              onPressed: () => _copy(context, url.url),
            ),
          ),
      ],
    );
  }

  Future<void> _copy(BuildContext context, String url) async {
    final messenger = ScaffoldMessenger.maybeOf(context);
    if (onCopy != null) {
      await onCopy!(url);
    } else {
      await Clipboard.setData(ClipboardData(text: url));
    }
    messenger?.showSnackBar(SnackBar(content: Text('Copied $url')));
  }
}

class _TlsBadge extends StatelessWidget {
  final MeshPortStatus status;
  const _TlsBadge({required this.status});

  @override
  Widget build(BuildContext context) {
    if (!status.running) return const LemonBadge(text: 'Off', color: Colors.grey);
    switch (status.tlsState) {
      case 'active':
        return const LemonBadge(text: 'TLS active');
      case 'waiting':
        return const LemonBadge(text: 'HTTP: waiting for certificate', color: AppTheme.nodeOrange);
      case 'activating':
        return const LemonBadge(text: 'HTTP: TLS starts when open requests finish', color: AppTheme.nodeOrange);
      case 'unsupported_certificate':
        return const LemonBadge(text: 'HTTP: certificate not usable', color: AppTheme.nodeOrange);
      default:
        return const LemonBadge(text: 'TLS error', color: AppTheme.errorColor);
    }
  }
}

class _Notice extends StatelessWidget {
  final String text;
  final Color color;
  final Widget? action;
  const _Notice({super.key, required this.text, required this.color, this.action});

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Icon(Icons.info_outline, size: 18, color: color),
        const SizedBox(width: 8),
        Expanded(child: Text(text, style: TextStyle(color: color))),
        if (action != null) action!,
      ],
    );
  }
}
