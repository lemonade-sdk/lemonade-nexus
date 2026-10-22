/// @title Member Access dialog
/// @description Lets a Cluster admin set what one device may do: its role and
/// permissions on the Cluster group, and which other devices may see or
/// connect to it. Every change goes through POST /api/tree/node/assignments,
/// where the server applies the admin and joined-device rules.
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/cluster_keyring.dart';
import '../state/providers.dart';
import '../../theme/app_theme.dart';

/// Group-level permissions offered for a member. `admin` is the role switch.
const _groupPermissions = <String, String>{
  'read': 'See the Cluster',
  'write': 'Write Cluster data',
  'add_child': 'Add devices',
  'edit_node': 'Edit the Cluster',
  'delete_node': 'Remove devices',
};

/// Device-level permissions another member can hold on the target device.
const _nodePermissions = <String, String>{
  'read': 'See',
  'connect_private': 'Connect',
};

Future<bool?> showMemberAccessDialog(BuildContext context,
    {required ClusterDevice device, required List<ClusterDevice> devices}) {
  return showDialog<bool>(
    context: context,
    builder: (_) => MemberAccessDialog(device: device, devices: devices),
  );
}

class MemberAccessDialog extends ConsumerStatefulWidget {
  final ClusterDevice device;
  final List<ClusterDevice> devices;
  const MemberAccessDialog({super.key, required this.device, required this.devices});

  @override
  ConsumerState<MemberAccessDialog> createState() => _MemberAccessDialogState();
}

class _MemberAccessDialogState extends ConsumerState<MemberAccessDialog> {
  String? _groupId;
  bool _loading = true;
  bool _saving = false;
  String? _error;

  /// Current and edited permission sets, keyed by canonical principal.
  Set<String> _groupBefore = {};
  Set<String> _groupAfter = {};
  final Map<String, Set<String>> _nodeBefore = {};
  final Map<String, Set<String>> _nodeAfter = {};

  List<ClusterDevice> get _others =>
      widget.devices.where((d) => d.nodeId != widget.device.nodeId && d.mgmtPubkey.isNotEmpty).toList();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) => _load());
  }

  Set<String> _permsFor(List<Map<String, dynamic>> assignments, String principal) {
    final want = canonicalPrincipal(principal);
    final out = <String>{};
    for (final a in assignments) {
      if (canonicalPrincipal(a['management_pubkey']?.toString() ?? '') != want) continue;
      out.addAll(((a['permissions'] as List?) ?? const []).map((p) => p.toString()));
    }
    return out;
  }

  Future<void> _load() async {
    final notifier = ref.read(appNotifierProvider.notifier);
    try {
      final groupId = await notifier.clusterGroupId();
      if (groupId == null) throw Exception('this device is not in a Cluster');
      final groupAssignments = await notifier.nodeAssignments(groupId);
      final nodeAssignments = await notifier.nodeAssignments(widget.device.nodeId);
      if (!mounted) return;
      setState(() {
        _groupId = groupId;
        _groupBefore = _permsFor(groupAssignments, widget.device.mgmtPubkey);
        _groupAfter = {..._groupBefore};
        for (final other in _others) {
          final key = canonicalPrincipal(other.mgmtPubkey);
          _nodeBefore[key] = _permsFor(nodeAssignments, other.mgmtPubkey);
          _nodeAfter[key] = {..._nodeBefore[key]!};
        }
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = 'Could not load access: $e';
        _loading = false;
      });
    }
  }

  bool _sameSet(Set<String> a, Set<String> b) => a.length == b.length && a.containsAll(b);

  bool get _dirty =>
      !_sameSet(_groupBefore, _groupAfter) ||
      _nodeAfter.entries.any((e) => !_sameSet(_nodeBefore[e.key] ?? {}, e.value));

  Future<void> _save() async {
    final notifier = ref.read(appNotifierProvider.notifier);
    setState(() {
      _saving = true;
      _error = null;
    });
    try {
      if (!_sameSet(_groupBefore, _groupAfter)) {
        await notifier.setMemberPermissions(
            _groupId!, widget.device.mgmtPubkey, _groupAfter.toList()..sort());
      }
      for (final other in _others) {
        final key = canonicalPrincipal(other.mgmtPubkey);
        final after = _nodeAfter[key] ?? {};
        // Keep permissions this dialog does not show (for example the owner's
        // management rights on the device); change only See and Connect.
        if (_sameSet(_nodeBefore[key] ?? {}, after)) continue;
        await notifier.setMemberPermissions(
            widget.device.nodeId, other.mgmtPubkey, after.toList()..sort());
      }
      if (mounted) Navigator.pop(context, true);
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = '$e'.replaceFirst('Exception: ', '');
        _saving = false;
      });
    }
  }

  void _toggle(Set<String> set, String perm, bool on) =>
      setState(() => on ? set.add(perm) : set.remove(perm));

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final self = widget.device.isThisDevice;
    final isAdmin = _groupAfter.contains('admin');
    return AlertDialog(
      backgroundColor: scheme.surface,
      shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12), side: BorderSide(color: scheme.outline)),
      title: Text('Access — ${widget.device.hostname}'),
      content: SizedBox(
        width: 460,
        child: _loading
            ? const Padding(
                padding: EdgeInsets.all(32),
                child: Center(child: CircularProgressIndicator()))
            : SingleChildScrollView(
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _heading('Cluster role'),
                    if (self)
                      _note(scheme,
                          'You cannot change your own role. Another admin must do it.')
                    else
                      SegmentedButton<bool>(
                        segments: const [
                          ButtonSegment(value: false, label: Text('Member')),
                          ButtonSegment(value: true, label: Text('Admin')),
                        ],
                        selected: {isAdmin},
                        onSelectionChanged: _saving
                            ? null
                            : (v) => _toggle(_groupAfter, 'admin', v.first),
                      ),
                    const SizedBox(height: 4),
                    _note(scheme,
                        'An admin can change roles and access for every device in this Cluster.'),
                    const SizedBox(height: 16),
                    _heading('Cluster permissions'),
                    for (final entry in _groupPermissions.entries)
                      CheckboxListTile(
                        dense: true,
                        contentPadding: EdgeInsets.zero,
                        title: Text(entry.value, style: const TextStyle(fontSize: 13)),
                        subtitle: Text(entry.key,
                            style: TextStyle(fontSize: 10, color: scheme.onSurfaceVariant)),
                        value: isAdmin || _groupAfter.contains(entry.key),
                        onChanged: (self || isAdmin || _saving)
                            ? null
                            : (v) => _toggle(_groupAfter, entry.key, v ?? false),
                      ),
                    const SizedBox(height: 16),
                    _heading('Who can reach this device'),
                    if (_others.isEmpty)
                      _note(scheme, 'No other devices in this Cluster.')
                    else
                      for (final other in _others) _reachRow(scheme, other),
                    if (_error != null) ...[
                      const SizedBox(height: 12),
                      Text(_error!,
                          style: const TextStyle(fontSize: 12, color: AppTheme.errorColor)),
                    ],
                  ],
                ),
              ),
      ),
      actions: [
        TextButton(
            onPressed: _saving ? null : () => Navigator.pop(context, false),
            child: const Text('Cancel')),
        ElevatedButton(
          onPressed: (_loading || _saving || !_dirty) ? null : _save,
          child: _saving
              ? const SizedBox(
                  width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
              : const Text('Save'),
        ),
      ],
    );
  }

  Widget _reachRow(ColorScheme scheme, ClusterDevice other) {
    final key = canonicalPrincipal(other.mgmtPubkey);
    final perms = _nodeAfter[key] ?? <String>{};
    return Row(
      children: [
        Expanded(
          child: Text(other.hostname,
              maxLines: 1, overflow: TextOverflow.ellipsis, style: const TextStyle(fontSize: 13)),
        ),
        for (final entry in _nodePermissions.entries) ...[
          Checkbox(
            value: perms.contains(entry.key),
            onChanged: _saving
                ? null
                : (v) => _toggle(_nodeAfter.putIfAbsent(key, () => <String>{}), entry.key,
                    v ?? false),
          ),
          Text(entry.value, style: const TextStyle(fontSize: 12)),
          const SizedBox(width: 8),
        ],
      ],
    );
  }

  Widget _heading(String text) => Padding(
        padding: const EdgeInsets.only(bottom: 6),
        child: Text(text, style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
      );

  Widget _note(ColorScheme scheme, String text) =>
      Text(text, style: TextStyle(fontSize: 11, color: scheme.onSurfaceVariant));
}
