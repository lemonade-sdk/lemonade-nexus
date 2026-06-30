/// @title Login View
/// @description Passkey-first authentication with region-aware server discovery.
/// Styled to match the macOS app.
library;

import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../state/providers.dart';
import '../state/app_state.dart';
import '../services/dns_discovery.dart';
import '../../theme/app_theme.dart';
import '../../theme/components.dart';

class LoginView extends ConsumerStatefulWidget {
  const LoginView({super.key});

  @override
  ConsumerState<LoginView> createState() => _LoginViewState();
}

class _LoginViewState extends ConsumerState<LoginView> {
  final _formKey = GlobalKey<FormState>();
  final _usernameController = TextEditingController();
  final _passwordController = TextEditingController();

  AuthTab _selectedTab = AuthTab.passkey;
  String? _error;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final notifier = ref.read(appNotifierProvider.notifier);
      final state = ref.read(appNotifierProvider);
      if (state.settings.autoDiscoveryEnabled &&
          state.discoveredServers.isEmpty &&
          !state.isDiscovering) {
        notifier.discoverNearestServer();
      }
    });
  }

  @override
  void dispose() {
    _usernameController.dispose();
    _passwordController.dispose();
    super.dispose();
  }

  AppNotifier get _notifier => ref.read(appNotifierProvider.notifier);

  Future<void> _run(Future<bool> Function() action, String failMsg) async {
    setState(() => _error = null);
    final ok = await action();
    if (!ok && mounted) {
      setState(() => _error = ref.read(appNotifierProvider).errorMessage ?? failMsg);
    }
  }

  Future<void> _handleSignIn() async {
    if (!_formKey.currentState!.validate()) return;
    await _run(
        () => _notifier.signIn(
            _usernameController.text.trim(), _passwordController.text),
        'Sign in failed');
  }

  Future<void> _handleRegister() async {
    if (!_formKey.currentState!.validate()) return;
    await _run(
        () => _notifier.register(
            _usernameController.text.trim(), _passwordController.text),
        'Registration failed');
  }

  Future<void> _handlePasskeySignIn() =>
      _run(_notifier.signInWithPasskey, 'Passkey sign-in failed');

  Future<void> _handlePasskeyRegister() {
    final username = _usernameController.text.trim();
    if (username.isEmpty) {
      setState(() => _error = 'Please enter a username');
      return Future.value();
    }
    return _run(() => _notifier.registerPasskey(username),
        'Passkey registration failed');
  }

  @override
  Widget build(BuildContext context) {
    final appState = ref.watch(appNotifierProvider);
    final scheme = Theme.of(context).colorScheme;

    return Scaffold(
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 380),
          child: Padding(
            padding: const EdgeInsets.all(24),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const LemonLogo(size: 96),
                const SizedBox(height: 8),
                const Text('Lemonade Nexus',
                    style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold)),
                const SizedBox(height: 4),
                Text('Secure Mesh VPN',
                    style: TextStyle(fontSize: 14, color: scheme.onSurfaceVariant)),
                const SizedBox(height: 28),
                AppCard(
                  padding: const EdgeInsets.all(24),
                  child: Form(
                    key: _formKey,
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        _serverSection(appState),
                        const SizedBox(height: 20),
                        _tabSelection(scheme),
                        const SizedBox(height: 20),
                        if (_selectedTab == AuthTab.passkey)
                          _passkeyTab(appState, scheme)
                        else
                          _passwordTab(),
                        if (_error != null) ...[
                          const SizedBox(height: 16),
                          _errorBox(_error!),
                        ],
                        const SizedBox(height: 16),
                        if (_selectedTab == AuthTab.passkey)
                          _passkeyActions(appState)
                        else
                          _passwordActions(appState),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 24),
                Text('v1.0.0',
                    style: TextStyle(
                        fontSize: 11,
                        color: scheme.onSurfaceVariant.withValues(alpha: 0.6))),
              ],
            ),
          ),
        ),
      ),
    );
  }

  // ---- server discovery (no manual entry) -----------------------------------

  Widget _serverSection(AppState appState) {
    final scheme = Theme.of(context).colorScheme;

    if (appState.isDiscovering) {
      return Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const SizedBox(
              width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2)),
          const SizedBox(width: 10),
          Flexible(
            child: Text('Discovering servers on lemonade-nexus.io…',
                style: TextStyle(fontSize: 12, color: scheme.onSurfaceVariant)),
          ),
        ],
      );
    }

    final servers = appState.discoveredServers;
    if (servers.isNotEmpty) {
      final best = servers.first;
      final currentKey =
          '${appState.settings.serverHost}:${appState.settings.serverPort}';
      return Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const StatusDot(isHealthy: true, size: 8),
              const SizedBox(width: 8),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Connected to ${best.displayName}',
                        maxLines: 1,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(fontSize: 12)),
                    Text(
                      '${servers.length} server${servers.length == 1 ? '' : 's'} found — ${best.latencyMs.round()}ms latency',
                      style: TextStyle(fontSize: 11, color: scheme.onSurfaceVariant),
                    ),
                  ],
                ),
              ),
              IconButton(
                tooltip: 'Re-discover',
                visualDensity: VisualDensity.compact,
                icon: Icon(Icons.refresh, size: 16, color: scheme.onSurfaceVariant),
                onPressed: _notifier.discoverNearestServer,
              ),
            ],
          ),
          if (servers.length > 1)
            ...servers.map((s) => _serverPickerRow(s, currentKey)),
        ],
      );
    }

    // No servers discovered — offer to retry.
    return Column(
      crossAxisAlignment: CrossAxisAlignment.center,
      children: [
        if (appState.discoveryMessage != null)
          Padding(
            padding: const EdgeInsets.only(bottom: 8),
            child: Text(appState.discoveryMessage!,
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 12, color: scheme.onSurfaceVariant)),
          ),
        OutlinedButton.icon(
          onPressed: _notifier.discoverNearestServer,
          icon: const Icon(Icons.wifi_tethering, size: 16),
          label: const Text('Discover servers'),
        ),
      ],
    );
  }

  Widget _serverPickerRow(DiscoveredServer s, String currentKey) {
    final scheme = Theme.of(context).colorScheme;
    final host = s.connectHost ?? s.hostname ?? s.ip;
    final selected = '$host:${s.port}' == currentKey;
    return InkWell(
      onTap: () => _notifier.connectToServer(host, s.port, useTls: s.scheme == 'https'),
      child: Padding(
        padding: const EdgeInsets.symmetric(vertical: 4),
        child: Row(
          children: [
            Icon(
              selected ? Icons.radio_button_checked : Icons.radio_button_unchecked,
              size: 13,
              color: selected ? AppTheme.lemonYellowDark : scheme.onSurfaceVariant,
            ),
            const SizedBox(width: 8),
            Expanded(
              child: Text(s.displayName,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: const TextStyle(fontSize: 12)),
            ),
            Text('${s.latencyMs.round()}ms',
                style: TextStyle(fontSize: 11, color: scheme.onSurfaceVariant)),
          ],
        ),
      ),
    );
  }

  // ---- tabs -----------------------------------------------------------------

  Widget _tabSelection(ColorScheme scheme) {
    return Container(
      padding: const EdgeInsets.all(2),
      decoration: BoxDecoration(
        color: scheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: AuthTab.values.map((tab) {
          final selected = _selectedTab == tab;
          return Expanded(
            child: GestureDetector(
              onTap: () => setState(() {
                _selectedTab = tab;
                _error = null;
              }),
              child: Container(
                padding: const EdgeInsets.symmetric(vertical: 8),
                decoration: BoxDecoration(
                  color: selected ? AppTheme.lemonYellow : Colors.transparent,
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Center(
                  child: Text(
                    tab.label,
                    style: TextStyle(
                      color: selected ? Colors.black : scheme.onSurfaceVariant,
                      fontWeight: selected ? FontWeight.w600 : FontWeight.normal,
                      fontSize: 13,
                    ),
                  ),
                ),
              ),
            ),
          );
        }).toList(),
      ),
    );
  }

  Widget _passwordTab() {
    return Column(
      children: [
        TextFormField(
          controller: _usernameController,
          textInputAction: TextInputAction.next,
          decoration: const InputDecoration(
            labelText: 'Username',
            prefixIcon: Icon(Icons.person_outline, size: 18),
          ),
          validator: (v) => (v == null || v.isEmpty) ? 'Enter your username' : null,
        ),
        const SizedBox(height: 14),
        TextFormField(
          controller: _passwordController,
          obscureText: true,
          textInputAction: TextInputAction.done,
          onFieldSubmitted: (_) => _handleSignIn(),
          decoration: const InputDecoration(
            labelText: 'Password',
            prefixIcon: Icon(Icons.lock_outline, size: 18),
          ),
          validator: (v) => (v == null || v.isEmpty) ? 'Enter your password' : null,
        ),
      ],
    );
  }

  Widget _passkeyTab(AppState appState, ColorScheme scheme) {
    if (!Platform.isMacOS) {
      return Column(
        children: [
          Icon(Icons.fingerprint, size: 44, color: scheme.onSurfaceVariant),
          const SizedBox(height: 10),
          Text('Passkeys are available on macOS.',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 13, color: scheme.onSurfaceVariant)),
        ],
      );
    }

    return Column(
      children: [
        const Icon(Icons.fingerprint, size: 48, color: AppTheme.lemonYellowDark),
        const SizedBox(height: 12),
        if (appState.hasStoredPasskey)
          Text.rich(
            TextSpan(children: [
              const TextSpan(text: 'Sign in as '),
              TextSpan(
                  text: appState.storedPasskeyUserId ?? 'your account',
                  style: const TextStyle(fontWeight: FontWeight.w600)),
              const TextSpan(text: ' using Touch ID.'),
            ]),
            textAlign: TextAlign.center,
            style: TextStyle(fontSize: 13, color: scheme.onSurfaceVariant),
          )
        else ...[
          Text('Create a passkey to sign in with Touch ID.',
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 13, color: scheme.onSurfaceVariant)),
          const SizedBox(height: 16),
          TextFormField(
            controller: _usernameController,
            decoration: const InputDecoration(
              labelText: 'Username',
              prefixIcon: Icon(Icons.person_outline, size: 18),
            ),
          ),
        ],
      ],
    );
  }

  // ---- actions --------------------------------------------------------------

  Widget _passwordActions(AppState appState) {
    final loading = appState.isLoading;
    return Row(
      children: [
        Expanded(
          child: ElevatedButton(
            onPressed: loading ? null : _handleSignIn,
            child: loading ? _spinner() : const Text('Sign In'),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: OutlinedButton(
            onPressed: loading ? null : _handleRegister,
            child: const Text('Register'),
          ),
        ),
      ],
    );
  }

  Widget _passkeyActions(AppState appState) {
    if (!Platform.isMacOS) return const SizedBox.shrink();
    final loading = appState.isLoading;
    if (appState.hasStoredPasskey) {
      return Column(
        children: [
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: loading ? null : _handlePasskeySignIn,
              icon: loading
                  ? _spinner()
                  : const Icon(Icons.fingerprint, size: 18),
              label: const Text('Sign in with Passkey'),
            ),
          ),
          const SizedBox(height: 8),
          TextButton(
            onPressed: loading ? null : _notifier.deletePasskey,
            style: TextButton.styleFrom(
              foregroundColor: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            child: const Text('Remove stored passkey', style: TextStyle(fontSize: 11)),
          ),
        ],
      );
    }
    return SizedBox(
      width: double.infinity,
      child: ElevatedButton.icon(
        onPressed: loading ? null : _handlePasskeyRegister,
        icon: loading ? _spinner() : const Icon(Icons.person_add_alt, size: 18),
        label: const Text('Create Passkey'),
      ),
    );
  }

  Widget _spinner() => const SizedBox(
        width: 18,
        height: 18,
        child: CircularProgressIndicator(
            strokeWidth: 2,
            valueColor: AlwaysStoppedAnimation<Color>(Colors.black)),
      );

  Widget _errorBox(String message) {
    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: AppTheme.errorColor.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          const Icon(Icons.error_outline, size: 16, color: AppTheme.errorColor),
          const SizedBox(width: 8),
          Expanded(
            child: Text(message,
                style: const TextStyle(fontSize: 12, color: AppTheme.errorColor)),
          ),
        ],
      ),
    );
  }
}

enum AuthTab { passkey, password }

extension AuthTabExtension on AuthTab {
  String get label => this == AuthTab.passkey ? 'Passkey' : 'Password';
}
