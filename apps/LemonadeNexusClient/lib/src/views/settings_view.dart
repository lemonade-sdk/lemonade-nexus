/// @title Settings View
/// @description App settings and configuration.
///
/// Matches macOS SettingsView.swift functionality:
/// - Server connection settings
/// - Identity management
/// - Preferences (auto-discovery, auto-connect)
/// - About section
/// - Sign out
library;

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'dart:io';
import '../state/providers.dart';
import '../state/app_state.dart';
import '../windows/windows_integration.dart';
import '../../theme/app_theme.dart';
import '../../theme/components.dart';

class SettingsView extends ConsumerStatefulWidget {
  const SettingsView({super.key});

  @override
  ConsumerState<SettingsView> createState() => _SettingsViewState();
}

class _SettingsViewState extends ConsumerState<SettingsView> {
  final _serverController = TextEditingController();
  bool _hasChanges = false;

  @override
  void initState() {
    super.initState();
    final settings = ref.read(settingsProvider);
    _serverController.text = '${settings.serverHost}:${settings.serverPort}';
  }

  @override
  void dispose() {
    _serverController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final appState = ref.watch(appNotifierProvider);
    final notifier = ref.read(appNotifierProvider.notifier);

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header
          const SectionHeader(title: 'Settings', icon: Icons.settings),
          const SizedBox(height: 24),

          // Server Connection Section
          _buildSection(
            icon: Icons.link,
            title: 'Server Connection',
            child: Column(
              children: [
                Row(
                  children: [
                    Text('Server URL', style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 13)),
                    const SizedBox(width: 12),
                    Expanded(
                      child: TextField(
                        controller: _serverController,
                        decoration: const InputDecoration(
                          hintText: 'localhost:9100',
                          contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                        ),
                        style: const TextStyle(fontSize: 13, fontFamily: 'monospace'),
                        onChanged: (_) => setState(() => _hasChanges = true),
                      ),
                    ),
                    const SizedBox(width: 12),
                    ElevatedButton(
                      onPressed: _hasChanges || appState.serverHost == 'localhost'
                          ? () async {
                              final parts = _serverController.text.split(':');
                              final host = parts[0].trim();
                              final port = parts.length > 1 ? int.tryParse(parts[1].trim()) ?? 9100 : 9100;
                              await notifier.connectToServer(host, port);
                              if (!context.mounted) return;
                              setState(() => _hasChanges = false);
                              ScaffoldMessenger.of(context).showSnackBar(
                                SnackBar(
                                  content: Text('Server URL updated to $host:$port'),
                                  backgroundColor: AppTheme.lemonGreen,
                                ),
                              );
                            }
                          : null,
                      child: const Text('Save'),
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                Row(
                  children: [
                    Text('Status', style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 13)),
                    const SizedBox(width: 12),
                    Row(
                      children: [
                        StatusDot(isHealthy: appState.isServerHealthy, size: 8),
                        const SizedBox(width: 6),
                        Text(appState.isServerHealthy ? 'Connected' : 'Disconnected', style: const TextStyle(fontSize: 13)),
                      ],
                    ),
                    const Spacer(),
                    TextButton.icon(
                      onPressed: () async {
                        await notifier.refreshHealth();
                        if (!context.mounted) return;
                        if (appState.isServerHealthy) {
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text('Connection successful'), backgroundColor: Colors.green),
                          );
                        } else {
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text('Connection failed'), backgroundColor: Colors.red),
                          );
                        }
                      },
                      icon: const Icon(Icons.refresh, size: 16),
                      label: const Text('Test Connection'),
                    ),
                  ],
                ),
              ],
            ),
          ),

          const SizedBox(height: 20),

          // Identity Section
          _buildSection(
            icon: Icons.person,
            title: 'Identity',
            child: Column(
              children: [
                if (appState.publicKeyBase64 != null) ...[
                  _buildIdentityRow('Public Key', '${appState.publicKeyBase64!.substring(0, appState.publicKeyBase64!.length.clamp(0, 32))}...'),
                  const SizedBox(height: 12),
                ],
                if (appState.username != null && appState.username!.isNotEmpty) ...[
                  _buildIdentityRow('Username', appState.username!),
                  const SizedBox(height: 12),
                ],
                if (appState.userId != null && appState.userId!.isNotEmpty) ...[
                  _buildIdentityRow('User ID', appState.userId!),
                  const SizedBox(height: 12),
                ],
                Row(
                  children: [
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: () {
                          // TODO: Implement export identity
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text('Export identity not yet implemented'), backgroundColor: Colors.orange),
                          );
                        },
                        icon: const Icon(Icons.upload),
                        label: const Text('Export Identity'),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: OutlinedButton.icon(
                        onPressed: () {
                          // TODO: Implement import identity
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(content: Text('Import identity not yet implemented'), backgroundColor: Colors.orange),
                          );
                        },
                        icon: const Icon(Icons.download),
                        label: const Text('Import Identity'),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),

          const SizedBox(height: 20),

          // Preferences Section
          _buildSection(
            icon: Icons.tune,
            title: 'Preferences',
            child: Column(
              children: [
                _buildPreferenceToggle(
                  'DNS Auto-discovery',
                  'Resolve lemonade-nexus.io to find the nearest server',
                  appState.settings.autoDiscoveryEnabled,
                  (value) => notifier.setAutoDiscoveryEnabled(value),
                ),
                Divider(color: scheme.outline, height: 16),
                _buildPreferenceToggle(
                  'Auto-connect on launch',
                  'Automatically connect to the VPN on app startup',
                  appState.settings.autoConnectOnLaunch,
                  (value) => notifier.setAutoConnectOnLaunch(value),
                ),
              ],
            ),
          ),

          const SizedBox(height: 20),

          // Windows Integration Section (Windows only)
          if (Platform.isWindows) ...[
            _buildSection(
              icon: Icons.desktop_windows,
              title: 'Windows Integration',
              child: Column(
                children: [
                  _buildWindowsPreferenceToggle(
                    'Start on login',
                    'Automatically start the VPN when you log in to Windows',
                    ref.watch(windowsIntegrationNotifierProvider).enableAutoStart,
                    (value) async {
                      final result = await ref
                          .read(windowsIntegrationNotifierProvider.notifier)
                          .toggleAutoStart(value);
                      if (!result && context.mounted) {
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(
                            content: Text('Failed to update auto-start: ${Platform.isWindows ? "May require administrator privileges" : "Not available on this platform"}'),
                            backgroundColor: Colors.orange,
                          ),
                        );
                      }
                    },
                  ),
                  const SizedBox(height: 12),
                  _buildWindowsPreferenceToggle(
                    'Minimize to system tray',
                    'Minimize to the system tray instead of closing the app',
                    ref.watch(windowsIntegrationNotifierProvider).minimizeToTray,
                    (value) {
                      ref
                          .read(windowsIntegrationNotifierProvider.notifier)
                          .toggleMinimizeToTray(value);
                    },
                  ),
                  const SizedBox(height: 12),
                  _buildWindowsPreferenceToggle(
                    'Run in background',
                    'Continue running the VPN tunnel when the window is closed',
                    ref.watch(windowsIntegrationNotifierProvider).runInBackground,
                    (value) {
                      ref
                          .read(windowsIntegrationNotifierProvider.notifier)
                          .toggleRunInBackground(value);
                    },
                  ),
                  const SizedBox(height: 12),
                  // Windows Service Section (Advanced)
                  _buildWindowsServiceSection(ref),
                ],
              ),
            ),
            const SizedBox(height: 20),
          ],

          // About Section
          _buildSection(
            icon: Icons.info,
            title: 'About',
            child: Column(
              children: [
                _buildAboutRow('App Version', '1.0.0'),
                const SizedBox(height: 8),
                _buildAboutRow('Build', '1'),
                const SizedBox(height: 8),
                _buildAboutRow('Platform', Platform.operatingSystem),
                if (Platform.isWindows) ...[
                  const SizedBox(height: 8),
                  _buildAboutRow('Windows Version', Platform.operatingSystemVersion),
                ],
              ],
            ),
          ),

          const SizedBox(height: 24),

          // Sign Out Button
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: () => _showSignOutDialog(notifier),
              icon: const Icon(Icons.logout),
              label: const Text('Sign Out'),
              style: ElevatedButton.styleFrom(
                backgroundColor: AppTheme.errorColor,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(vertical: 16),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSection({required IconData icon, required String title, required Widget child}) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SectionHeader(title: title, icon: icon),
        const SizedBox(height: 12),
        AppCard(child: child),
      ],
    );
  }

  Widget _buildIdentityRow(String label, String value) {
    final scheme = Theme.of(context).colorScheme;
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(width: 100, child: Text(label, style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 13))),
        Expanded(
          child: Text(value, style: const TextStyle(fontSize: 13, fontFamily: 'monospace')),
        ),
      ],
    );
  }

  Widget _buildPreferenceToggle(String title, String description, bool value, ValueChanged<bool> onChanged) {
    final scheme = Theme.of(context).colorScheme;
    return Row(
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(title, style: const TextStyle(fontSize: 13)),
              Text(description, style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 11)),
            ],
          ),
        ),
        Switch(
          value: value,
          onChanged: onChanged,
          activeThumbColor: AppTheme.lemonYellow,
        ),
      ],
    );
  }

  Widget _buildWindowsPreferenceToggle(String title, String description, bool value, ValueChanged<bool> onChanged) {
    final scheme = Theme.of(context).colorScheme;
    return Row(
      children: [
        Expanded(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(title, style: const TextStyle(fontSize: 13)),
              Text(description, style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 11)),
            ],
          ),
        ),
        Switch(
          value: value,
          onChanged: onChanged,
          activeThumbColor: AppTheme.lemonYellow,
        ),
      ],
    );
  }

  Widget _buildWindowsServiceSection(WidgetRef ref) {
    final scheme = Theme.of(context).colorScheme;
    final notifier = ref.read(windowsIntegrationNotifierProvider.notifier);
    final service = ref.read(windowsIntegrationProvider);
    final isInstalled = notifier.isServiceInstalled();

    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: scheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: scheme.outline),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Row(
            children: [
              Icon(Icons.admin_panel_settings, color: AppTheme.lemonYellowDark, size: 16),
              SizedBox(width: 8),
              Text('Windows Service (Advanced)', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'Install as a Windows Service for enterprise deployment. Requires administrator privileges.',
            style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 11),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              if (!isInstalled)
                Expanded(
                  child: ElevatedButton(
                    onPressed: () async {
                      final result = await notifier.installService();
                      if (!mounted) return;
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          content: Text(result
                              ? 'Service installed successfully'
                              : 'Failed to install service. Run as administrator.'),
                          backgroundColor: result ? AppTheme.lemonGreen : Colors.orange,
                        ),
                      );
                    },
                    style: ElevatedButton.styleFrom(
                      padding: const EdgeInsets.symmetric(vertical: 8),
                    ),
                    child: const Text('Install Service'),
                  ),
                )
              else
                Expanded(
                  child: Row(
                    children: [
                      Expanded(
                        child: ElevatedButton(
                          onPressed: () async {
                            final result = await service.startService();
                            if (!mounted) return;
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(
                                content: Text(result
                                    ? 'Service started'
                                    : 'Failed to start service'),
                                backgroundColor: result ? AppTheme.lemonGreen : Colors.orange,
                              ),
                            );
                          },
                          style: ElevatedButton.styleFrom(
                            backgroundColor: AppTheme.lemonGreen,
                            foregroundColor: Colors.white,
                            padding: const EdgeInsets.symmetric(vertical: 8),
                          ),
                          child: const Text('Start'),
                        ),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: ElevatedButton(
                          onPressed: () async {
                            final result = await service.stopService();
                            if (!mounted) return;
                            ScaffoldMessenger.of(context).showSnackBar(
                              SnackBar(
                                content: Text(result
                                    ? 'Service stopped'
                                    : 'Failed to stop service'),
                                backgroundColor: result ? Colors.orange : AppTheme.lemonGreen,
                              ),
                            );
                          },
                          style: ElevatedButton.styleFrom(
                            backgroundColor: AppTheme.nodeOrange,
                            foregroundColor: Colors.white,
                            padding: const EdgeInsets.symmetric(vertical: 8),
                          ),
                          child: const Text('Stop'),
                        ),
                      ),
                    ],
                  ),
                ),
              const SizedBox(width: 12),
              if (isInstalled)
                ElevatedButton(
                  onPressed: () async {
                    final result = await notifier.uninstallService();
                    if (!mounted) return;
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text(result
                            ? 'Service uninstalled'
                            : 'Failed to uninstall service'),
                        backgroundColor: result ? Colors.orange : Colors.red,
                      ),
                    );
                  },
                  style: ElevatedButton.styleFrom(
                    backgroundColor: AppTheme.errorColor,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 8),
                  ),
                  child: const Text('Uninstall'),
                ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildAboutRow(String label, String value) {
    final scheme = Theme.of(context).colorScheme;
    return Row(
      children: [
        SizedBox(width: 120, child: Text(label, style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 13))),
        Text(value, style: const TextStyle(fontSize: 13, fontFamily: 'monospace')),
      ],
    );
  }

  void _showSignOutDialog(AppNotifier notifier) {
    showDialog(
      context: context,
      builder: (context) {
        final scheme = Theme.of(context).colorScheme;
        return AlertDialog(
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
          title: const Text('Sign Out'),
          content: Text('Are you sure you want to sign out? You will need to re-enter your credentials.', style: TextStyle(color: scheme.onSurfaceVariant, fontSize: 13)),
          actions: [
            TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
            ElevatedButton(
              onPressed: () {
                Navigator.pop(context);
                notifier.signOut();
              },
              style: ElevatedButton.styleFrom(backgroundColor: AppTheme.errorColor, foregroundColor: Colors.white),
              child: const Text('Sign Out'),
            ),
          ],
        );
      },
    );
  }
}
