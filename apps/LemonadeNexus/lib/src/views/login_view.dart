/// @title Login View
/// @description Authentication screen with password and passkey support.
/// Styled to match the macOS app: flat surface, lemon-yellow brand.

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../state/providers.dart';
import '../state/app_state.dart';
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
  final _serverController = TextEditingController();

  AuthTab _selectedTab = AuthTab.password;
  bool _isLoading = false;
  bool _isRegistering = false;
  String? _statusMessage;
  bool _isError = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addPostFrameCallback((_) {
      final settings = ref.read(settingsProvider);
      _serverController.text = '${settings.serverHost}:${settings.serverPort}';
    });
  }

  @override
  void dispose() {
    _usernameController.dispose();
    _passwordController.dispose();
    _serverController.dispose();
    super.dispose();
  }

  Future<void> _handleSignIn() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() {
      _isLoading = true;
      _isRegistering = false;
      _statusMessage = null;
      _isError = false;
    });
    final notifier = ref.read(appNotifierProvider.notifier);
    final success = await notifier.signIn(
      _usernameController.text.trim(),
      _passwordController.text,
    );
    if (!success && mounted) {
      setState(() {
        _isLoading = false;
        _isError = true;
        _statusMessage = ref.read(errorMessageProvider) ?? 'Sign in failed';
      });
    }
  }

  Future<void> _handleRegister() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() {
      _isLoading = true;
      _isRegistering = true;
      _statusMessage = null;
      _isError = false;
    });
    final notifier = ref.read(appNotifierProvider.notifier);
    final success = await notifier.register(
      _usernameController.text.trim(),
      _passwordController.text,
    );
    if (!success && mounted) {
      setState(() {
        _isLoading = false;
        _isError = true;
        _statusMessage = ref.read(errorMessageProvider) ?? 'Registration failed';
      });
    }
  }

  Future<void> _handlePasskeySignIn() async {
    setState(() {
      _isError = true;
      _statusMessage = 'Passkey authentication not yet implemented';
    });
  }

  Future<void> _handlePasskeyRegister() async {
    if (_usernameController.text.trim().isEmpty) {
      setState(() {
        _isError = true;
        _statusMessage = 'Please enter a username';
      });
      return;
    }
    setState(() {
      _isError = true;
      _statusMessage = 'Passkey registration not yet implemented';
    });
  }

  Future<void> _handleConnect() async {
    final notifier = ref.read(appNotifierProvider.notifier);
    final hostPort = _serverController.text.split(':');
    final host = hostPort[0].trim();
    final port = hostPort.length > 1 ? int.tryParse(hostPort[1].trim()) ?? 9100 : 9100;
    await notifier.connectToServer(host, port);
  }

  @override
  Widget build(BuildContext context) {
    final appState = ref.watch(appNotifierProvider);
    final scheme = Theme.of(context).colorScheme;

    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 380),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const SizedBox(height: 24),
                const LemonLogo(size: 100),
                const SizedBox(height: 8),
                const Text(
                  'Lemonade Nexus',
                  style: TextStyle(fontSize: 28, fontWeight: FontWeight.bold),
                ),
                const SizedBox(height: 4),
                Text(
                  'Secure Mesh VPN',
                  style: TextStyle(fontSize: 14, color: scheme.onSurfaceVariant),
                ),
                const SizedBox(height: 32),
                AppCard(
                  padding: const EdgeInsets.all(24),
                  child: Form(
                    key: _formKey,
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.stretch,
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        _buildServerSection(appState),
                        const SizedBox(height: 20),
                        _buildTabSelection(scheme),
                        const SizedBox(height: 20),
                        if (_selectedTab == AuthTab.password)
                          _buildPasswordTab()
                        else
                          _buildPasskeyTab(scheme),
                        if (_statusMessage != null) ...[
                          const SizedBox(height: 16),
                          _buildStatusMessage(scheme),
                        ],
                        const SizedBox(height: 16),
                        if (_selectedTab == AuthTab.password)
                          _buildPasswordActions()
                        else
                          _buildPasskeyActions(scheme),
                      ],
                    ),
                  ),
                ),
                const SizedBox(height: 24),
                Text(
                  'v1.0.0',
                  style: TextStyle(
                    fontSize: 11,
                    color: scheme.onSurfaceVariant.withValues(alpha: 0.6),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildServerSection(AppState appState) {
    final scheme = Theme.of(context).colorScheme;
    final settings = appState.settings;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(Icons.link, size: 14, color: scheme.onSurfaceVariant),
            const SizedBox(width: 6),
            Text('Server',
                style: TextStyle(fontSize: 12, color: scheme.onSurfaceVariant)),
            const Spacer(),
            TextButton.icon(
              onPressed: _handleConnect,
              style: TextButton.styleFrom(
                minimumSize: Size.zero,
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                foregroundColor:
                    appState.isConnected ? AppTheme.lemonGreen : AppTheme.lemonYellowDark,
              ),
              icon: Icon(
                appState.isConnected ? Icons.check_circle : Icons.wifi_tethering,
                size: 14,
              ),
              label: Text(appState.isConnected ? 'Connected' : 'Connect',
                  style: const TextStyle(fontSize: 12)),
            ),
          ],
        ),
        const SizedBox(height: 8),
        if (appState.isConnected)
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: AppTheme.lemonGreen.withValues(alpha: 0.12),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: AppTheme.lemonGreen.withValues(alpha: 0.3)),
            ),
            child: Row(
              children: [
                const StatusDot(isHealthy: true, size: 8),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    'Connected to ${settings.serverHost}:${settings.serverPort}',
                    style: const TextStyle(fontSize: 12),
                  ),
                ),
              ],
            ),
          )
        else
          TextFormField(
            controller: _serverController,
            decoration: const InputDecoration(
              hintText: 'localhost:9100',
              prefixIcon: Icon(Icons.link, size: 18),
              isDense: true,
            ),
            onFieldSubmitted: (_) => _handleConnect(),
          ),
      ],
    );
  }

  Widget _buildTabSelection(ColorScheme scheme) {
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
              onTap: () => setState(() => _selectedTab = tab),
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

  Widget _buildPasswordTab() {
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

  Widget _buildPasskeyTab(ColorScheme scheme) {
    return Column(
      children: [
        const Icon(Icons.fingerprint, size: 48, color: AppTheme.lemonYellowDark),
        const SizedBox(height: 12),
        Text(
          'Create a passkey to sign in with Touch ID.',
          textAlign: TextAlign.center,
          style: TextStyle(fontSize: 13, color: scheme.onSurfaceVariant),
        ),
        const SizedBox(height: 16),
        TextFormField(
          controller: _usernameController,
          decoration: const InputDecoration(
            labelText: 'Username',
            prefixIcon: Icon(Icons.person_outline, size: 18),
          ),
        ),
      ],
    );
  }

  Widget _buildStatusMessage(ColorScheme scheme) {
    final color = _isError ? AppTheme.errorColor : AppTheme.infoColor;
    return Container(
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Icon(_isError ? Icons.error_outline : Icons.info_outline, size: 16, color: color),
          const SizedBox(width: 8),
          Expanded(
            child: Text(_statusMessage!,
                style: TextStyle(fontSize: 12, color: color)),
          ),
        ],
      ),
    );
  }

  Widget _buildPasswordActions() {
    return Row(
      children: [
        Expanded(
          child: ElevatedButton(
            onPressed: _isLoading ? null : _handleSignIn,
            child: _isLoading
                ? const SizedBox(
                    width: 18,
                    height: 18,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      valueColor: AlwaysStoppedAnimation<Color>(Colors.black),
                    ),
                  )
                : Text(_isRegistering ? 'Registering…' : 'Sign In'),
          ),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: OutlinedButton(
            onPressed: _isLoading ? null : _handleRegister,
            child: const Text('Register'),
          ),
        ),
      ],
    );
  }

  Widget _buildPasskeyActions(ColorScheme scheme) {
    return Column(
      children: [
        SizedBox(
          width: double.infinity,
          child: ElevatedButton.icon(
            onPressed: _isLoading ? null : _handlePasskeySignIn,
            icon: const Icon(Icons.key, size: 18),
            label: const Text('Sign in with Passkey'),
          ),
        ),
        const SizedBox(height: 10),
        SizedBox(
          width: double.infinity,
          child: OutlinedButton.icon(
            onPressed: _isLoading ? null : _handlePasskeyRegister,
            icon: const Icon(Icons.person_add_alt, size: 18),
            label: const Text('Create Passkey'),
          ),
        ),
      ],
    );
  }
}

enum AuthTab { password, passkey }

extension AuthTabExtension on AuthTab {
  String get label => this == AuthTab.password ? 'Password' : 'Passkey';
}
