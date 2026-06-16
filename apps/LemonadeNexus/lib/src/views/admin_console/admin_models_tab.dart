/// Admin console — Models tab.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../api/admin_endpoint.dart';
import '../../api/lemonade_api_client.dart';
import 'server_admin_provider.dart';

class AdminModelsTab extends ConsumerStatefulWidget {
  const AdminModelsTab({super.key});

  @override
  ConsumerState<AdminModelsTab> createState() => _AdminModelsTabState();
}

class _AdminModelsTabState extends ConsumerState<AdminModelsTab> {
  List<Map<String, dynamic>> _models = [];
  Set<String> _loaded = {};
  bool _loading = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final client = ref.read(serverAdminProvider)!;
      final list = await client.admin.listModels();
      final health = await client.admin.health();
      final loaded = ((health['all_models_loaded'] as List?) ?? const [])
          .whereType<Map>()
          .map((m) => (m['model_name'] ?? '').toString())
          .where((s) => s.isNotEmpty)
          .toSet();
      if (!mounted) return;
      setState(() {
        _models = list;
        _loaded = loaded;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loading = false;
        _error = e.toString();
      });
    }
  }

  Future<void> _load(String modelName) async {
    final client = ref.read(serverAdminProvider)!;
    _snack('Loading $modelName…');
    try {
      await client.admin.load(modelName: modelName);
    } catch (e) {
      _errorSnack('Load failed: $e');
    } finally {
      await _refresh();
    }
  }

  Future<void> _unload(String modelName) async {
    final client = ref.read(serverAdminProvider)!;
    _snack('Unloading $modelName…');
    try {
      await client.admin.unload(modelName: modelName);
    } catch (e) {
      _errorSnack('Unload failed: $e');
    } finally {
      await _refresh();
    }
  }

  Future<void> _delete(String modelName) async {
    final ok = await showDialog<bool>(
          context: context,
          builder: (ctx) => AlertDialog(
            title: Text('Delete $modelName?'),
            content: const Text(
                'This removes the model from local storage. Cannot be undone.'),
            actions: [
              TextButton(
                  onPressed: () => Navigator.pop(ctx, false),
                  child: const Text('Cancel')),
              ElevatedButton(
                  onPressed: () => Navigator.pop(ctx, true),
                  child: const Text('Delete')),
            ],
          ),
        ) ??
        false;
    if (!ok) return;

    final client = ref.read(serverAdminProvider)!;
    try {
      await client.admin.delete(modelName: modelName);
    } catch (e) {
      _errorSnack('Delete failed: $e');
    } finally {
      await _refresh();
    }
  }

  void _snack(String text) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(text), duration: const Duration(seconds: 1)),
    );
  }

  void _errorSnack(String text) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(text), backgroundColor: Colors.redAccent),
    );
  }

  Future<void> _pull() async {
    final spec = await showDialog<_PullSpec>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Pull a model'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              TextField(
                decoration: const InputDecoration(
                  labelText: 'Model name',
                  helperText: 'For HuggingFace pulls use the user.* namespace',
                ),
              ),
              TextField(
                decoration: const InputDecoration(
                  labelText: 'HF checkpoint (optional)',
                  hintText: 'e.g. unsloth/Qwen3-8B-GGUF:Q4_K_M',
                ),
              ),
              TextField(
                decoration: const InputDecoration(labelText: 'Recipe'),
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx),
              child: const Text('Cancel')),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(ctx, _PullSpec());
            },
            child: const Text('Pull'),
          ),
        ],
      ),
    );
    if (spec == null) return;

    final client = ref.read(serverAdminProvider)!;
    final progress = ValueNotifier<double?>(null);
    final status = ValueNotifier<String>('Starting…');

    if (!mounted) return;
    showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) => AlertDialog(
        title: const Text('Pulling model…'),
        content: ValueListenableBuilder<String>(
          valueListenable: status,
          builder: (_, s, __) => Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              ValueListenableBuilder<double?>(
                valueListenable: progress,
                builder: (_, p, __) => LinearProgressIndicator(value: p),
              ),
              const SizedBox(height: 12),
              Text(s),
            ],
          ),
        ),
      ),
    );

    try {
      await for (final ev in client.admin.pullStream(
        modelName: spec.modelName,
        checkpoint: spec.checkpoint,
        recipe: spec.recipe,
      )) {
        switch (ev) {
          case PullProgress():
            if (ev.percent != null) progress.value = ev.percent! / 100.0;
            status.value =
                '${ev.file ?? "Downloading"} (${ev.percent?.toStringAsFixed(0) ?? "?"}%)';
          case PullComplete():
            status.value = 'Complete';
          case PullError():
            status.value = 'Error: ${ev.message}';
        }
      }
    } catch (e) {
      status.value = 'Error: $e';
    } finally {
      if (mounted) Navigator.of(context, rootNavigator: true).pop();
      await _refresh();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      floatingActionButtonLocation: FloatingActionButtonLocation.startFloat,
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _pull,
        icon: const Icon(Icons.download),
        label: const Text('Pull'),
      ),
      body: RefreshIndicator(
        onRefresh: _refresh,
        child: _loading && _models.isEmpty
            ? const Center(child: CircularProgressIndicator())
            : _error != null
                ? Center(child: Text('Error: $_error'))
                : ListView(
                    padding: const EdgeInsets.only(bottom: 88),
                    children: [
                      for (final m in _models)
                        _ModelTile(
                          model: m,
                          loaded: _loaded.contains(m['id'] ?? ''),
                          onLoad: () => _load(m['id'].toString()),
                          onUnload: () => _unload(m['id'].toString()),
                          onDelete: () => _delete(m['id'].toString()),
                        ),
                    ],
                  ),
      ),
    );
  }
}

class _PullSpec {
  final String modelName;
  final String? checkpoint;
  final String? recipe;
  _PullSpec({this.modelName = '', this.checkpoint, this.recipe});
}

class _ModelTile extends StatelessWidget {
  final Map<String, dynamic> model;
  final bool loaded;
  final VoidCallback onLoad;
  final VoidCallback onUnload;
  final VoidCallback onDelete;

  const _ModelTile({
    required this.model,
    required this.loaded,
    required this.onLoad,
    required this.onUnload,
    required this.onDelete,
  });

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final id = model['id']?.toString() ?? '';
    final labels = (model['labels'] as List?)?.whereType<String>().toList() ?? [];
    final recipe = model['recipe'] as String?;
    final installed = (model['downloaded'] as bool?) ?? false;

    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          ListTile(
            leading: Icon(
              loaded ? Icons.memory : Icons.model_training,
              color: loaded ? Colors.green : scheme.outline,
            ),
            title: Text(id, overflow: TextOverflow.ellipsis),
            subtitle: Text(
              [if (labels.isNotEmpty) labels.join(', '), if (recipe != null) recipe, if (loaded) 'loaded'].join(' · '),
              style: Theme.of(context).textTheme.bodySmall,
            ),
            trailing: _buildTrailing(installed),
          ),
        ],
      ),
    );
  }

  Widget _buildTrailing(bool installed) {
    if (!installed) {
      return TextButton.icon(
        onPressed: () {}, // Pull button is the FAB
        icon: const Icon(Icons.download, size: 18),
        label: const Text('Download'),
      );
    }

    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
          decoration: BoxDecoration(
            color: Colors.green.withValues(alpha: 0.18),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: Colors.green.withValues(alpha: 0.45)),
          ),
          child: const Text(
            'Installed',
            style: TextStyle(color: Colors.green, fontSize: 11, fontWeight: FontWeight.w600),
          ),
        ),
        PopupMenuButton<String>(
          onSelected: (action) {
            switch (action) {
              case 'load':
                break;
              case 'unload':
                break;
              case 'delete':
                break;
            }
          },
          itemBuilder: (_) => [
            if (!loaded) const PopupMenuItem(value: 'load', child: Text('Load')),
            if (loaded) const PopupMenuItem(value: 'unload', child: Text('Unload')),
            const PopupMenuItem(value: 'delete', child: Text('Delete')),
          ],
        ),
      ],
    );
  }
}
