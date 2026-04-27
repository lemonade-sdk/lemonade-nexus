/// @title Login View
/// @description Authentication screen with password and passkey support.
///
/// Matches macOS LoginView.swift functionality:
/// - Server URL input with auto-discovery
/// - Password authentication tab
/// - Passkey authentication tab
/// - Registration support

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../state/providers.dart';
import '../state/app_state.dart';

class LoginView extends ConsumerStatefulWidget {
  const LoginView({super.key});

  @override
  ConsumerState<LoginView> createState() => _LoginViewState();
}

class _LoginViewState extends ConsumerState<LoginView> with SingleTickerProviderStateMixin {
  final _formKey = GlobalKey<FormState>();
  final _usernameController = TextEditingController();
  final _passwordController = TextEditingController();
  final _serverController = TextEditingController();

  AuthTab _selectedTab = AuthTab.password;
  bool _isLoading = false;
  bool _isRegistering = false;
  bool _showManualUrl = false;
  String? _statusMessage;
  bool _isError = false;

  @override
  void initState() {
    super.initState();
    // Load server URL from settings
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

    if (!success) {
      final errorMessage = ref.read(errorMessageProvider);
      setState(() {
        _isLoading = false;
        _isError = true;
        _statusMessage = errorMessage ?? 'Sign in failed';
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

    if (!success) {
      final errorMessage = ref.read(errorMessageProvider);
      setState(() {
        _isLoading = false;
        _isError = true;
        _statusMessage = errorMessage ?? 'Registration failed';
      });
    }
  }

  Future<void> _handlePasskeySignIn() async {
    setState(() {
      _isLoading = true;
      _isRegistering = false;
      _statusMessage = null;
      _isError = false;
    });

    // TODO: Implement passkey authentication
    setState(() {
      _isLoading = false;
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
      _isLoading = true;
      _isRegistering = true;
      _statusMessage = null;
      _isError = false;
    });

    // TODO: Implement passkey registration
    setState(() {
      _isLoading = false;
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
    final settings = ref.watch(settingsProvider);

    return Scaffold(
      body: Container(
        decoration: BoxDecoration(
          gradient: LinearGradient(
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
            colors: [
              const Color(0xFF1A1A2E),
              const Color(0xFF16213E),
              const Color(0xFF0F3460),
            ],
          ),
        ),
        child: SafeArea(
          child: Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(24.0),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 420),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    const SizedBox(height: 40),

                    // Logo
                    _buildLogo(),

                    const SizedBox(height: 16),

                    // Title
                    Text(
                      'Lemonade Nexus',
                      style: Theme.of(context).textTheme.headlineMedium?.copyWith(
                            fontWeight: FontWeight.bold,
                            color: const Color(0xFFE9C46A),
                          ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'Secure Mesh VPN',
                      style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                            color: Colors.white.withOpacity(0.7),
                          ),
                    ),

                    const SizedBox(height: 32),

                    // Login Card
                    Card(
                      elevation: 8,
                      shadowColor: Colors.black.withOpacity(0.3),
                      shape: RoundedRectangleBorder(
                        borderRadius: BorderRadius.circular(16),
                      ),
                      child: Padding(
                        padding: const EdgeInsets.all(28.0),
                        child: Form(
                          key: _formKey,
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.stretch,
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              // Server Connection Section
                              _buildServerConnectionSection(appState),

                              const SizedBox(height: 24),

                              // Tab Selection
                              _buildTabSelection(),

                              const SizedBox(height: 20),

                              // Tab Content
                              if (_selectedTab == AuthTab.password)
                                _buildPasswordTabContent()
                              else
                                _buildPasskeyTabContent(),

                              const SizedBox(height: 20),

                              // Status Message
                              if (_statusMessage != null)
                                _buildStatusMessage(),

                              const SizedBox(height: 16),

                              // Action Buttons
                              if (_selectedTab == AuthTab.password)
                                _buildPasswordActionButtons()
                              else
                                _buildPasskeyActionButtons(),
                            ],
                          ),
                        ),
                      ),
                    ),

                    const SizedBox(height: 32),

                    // Version
                    Text(
                      'v1.0.0',
                      style: Theme.of(context).textTheme.bodySmall?.copyWith(
                            color: Colors.white.withOpacity(0.4),
                          ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildLogo() {
    return SizedBox(
      width: 100,
      height: 100,
      child: Stack(
        alignment: Alignment.center,
        children: [
          // Lemon shape
          Container(
            width: 80,
            height: 60,
            decoration: BoxDecoration(
              color: const Color(0xFFE9C46A),
              borderRadius: BorderRadius.circular(40),
              boxShadow: [
                BoxShadow(
                  color: const Color(0xFFE9C46A).withOpacity(0.4),
                  blurRadius: 20,
                  spreadRadius: 5,
                ),
              ],
            ),
          ),
          // Network lines
          CustomPaint(
            size: const Size(80, 60),
            painter: _NetworkLinesPainter(),
          ),
          // Node dots
          ..._buildNodeDots(),
          // Leaf
          Positioned(
            top: 5,
            child: CustomPaint(
              size: const Size(20, 15),
              painter: _LeafPainter(),
            ),
          ),
        ],
      ),
    );
  }

  List<Widget> _buildNodeDots() {
    const positions = [
      (-10.0, -20.0),
      (10.0, 0.0),
      (-10.0, 20.0),
      (10.0, -20.0),
      (10.0, 20.0),
      (-20.0, 0.0),
    ];
    return positions.map((pos) {
      return Positioned(
        left: 40 + pos.$1,
        top: 30 + pos.$2,
        child: Container(
          width: 8,
          height: 8,
          decoration: const BoxDecoration(
            color: Color(0xFFF4A261),
            shape: BoxShape.circle,
          ),
        ),
      );
    }).toList();
  }

  Widget _buildServerConnectionSection(AppState appState) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Icon(
              Icons.link,
              size: 14,
              color: Colors.white.withOpacity(0.6),
            ),
            const SizedBox(width: 6),
            Text(
              'Server',
              style: Theme.of(context).textTheme.caption?.copyWith(
                    color: Colors.white.withOpacity(0.6),
                  ),
            ),
            const Spacer(),
            TextButton(
              onPressed: _handleConnect,
              style: TextButton.styleFrom(
                minimumSize: Size.zero,
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    Icons.wifi_tethering,
                    size: 14,
                    color: appState.isConnected
                        ? const Color(0xFFE9C46A)
                        : Colors.white.withOpacity(0.6),
                  ),
                  const SizedBox(width: 4),
                  Text(
                    appState.isConnected ? 'Connected' : 'Connect',
                    style: Theme.of(context).textTheme.caption?.copyWith(
                          color: appState.isConnected
                              ? const Color(0xFFE9C46A)
                              : Colors.white.withOpacity(0.6),
                        ),
                  ),
                ],
              ),
            ),
          ],
        ),
        const SizedBox(height: 8),
        if (appState.isConnected)
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.green.withOpacity(0.1),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                color: Colors.green.withOpacity(0.3),
              ),
            ),
            child: Row(
              children: [
                Icon(
                  Icons.check_circle,
                  size: 16,
                  color: Colors.green.shade400,
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Connected to ${settings.serverHost}:${settings.serverPort}',
                        style: Theme.of(context).textTheme.bodySmall?.copyWith(
                              color: Colors.white,
                            ),
                      ),
                      Text(
                        'Ready to authenticate',
                        style: Theme.of(context).textTheme.caption?.copyWith(
                              color: Colors.white.withOpacity(0.6),
                            ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          )
        else
          TextFormField(
            controller: _serverController,
            decoration: InputDecoration(
              labelText: 'Server URL',
              labelStyle: TextStyle(color: Colors.white.withOpacity(0.6)),
              hintText: 'localhost:9100',
              hintStyle: TextStyle(color: Colors.white.withOpacity(0.4)),
              prefixIcon: Icon(Icons.link, color: Colors.white.withOpacity(0.6)),
              enabledBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: BorderSide(color: Colors.white.withOpacity(0.3)),
              ),
              focusedBorder: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: const BorderSide(color: Color(0xFFE9C46A)),
              ),
              filled: true,
              fillColor: Colors.white.withOpacity(0.05),
            ),
            style: const TextStyle(color: Colors.white),
            onFieldSubmitted: (_) => _handleConnect(),
          ),
      ],
    );
  }

  Widget _buildTabSelection() {
    return Container(
      decoration: BoxDecoration(
        color: Colors.white.withOpacity(0.05),
        borderRadius: BorderRadius.circular(8),
      ),
      padding: const EdgeInsets.all(2),
      child: Row(
        children: AuthTab.values.map((tab) {
          final isSelected = _selectedTab == tab;
          return Expanded(
            child: GestureDetector(
              onTap: () => setState(() => _selectedTab = tab),
              child: Container(
                padding: const EdgeInsets.symmetric(vertical: 10),
                decoration: BoxDecoration(
                  color: isSelected ? const Color(0xFFE9C46A) : Colors.transparent,
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Center(
                  child: Text(
                    tab.label,
                    style: TextStyle(
                      color: isSelected ? Colors.black : Colors.white.withOpacity(0.7),
                      fontWeight: isSelected ? FontWeight.bold : FontWeight.normal,
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

  Widget _buildPasswordTabContent() {
    return Column(
      children: [
        _buildFormField(
          controller: _usernameController,
          label: 'Username',
          icon: Icons.person_outline,
          textInputAction: TextInputAction.next,
        ),
        const SizedBox(height: 16),
        _buildFormField(
          controller: _passwordController,
          label: 'Password',
          icon: Icons.lock_outline,
          isPassword: true,
          textInputAction: TextInputAction.done,
          onFieldSubmitted: (_) => _handleSignIn(),
        ),
      ],
    );
  }

  Widget _buildPasskeyTabContent() {
    return Column(
      children: [
        Icon(
          Icons.fingerprint,
          size: 56,
          color: const Color(0xFFE9C46A),
        ),
        const SizedBox(height: 16),
        Text(
          'Sign in with your fingerprint or face',
          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Colors.white.withOpacity(0.7),
              ),
          textAlign: TextAlign.center,
        ),
        const SizedBox(height: 20),
        _buildFormField(
          controller: _usernameController,
          label: 'Username',
          icon: Icons.person_outline,
          textInputAction: TextInputAction.done,
        ),
      ],
    );
  }

  Widget _buildFormField({
    required TextEditingController controller,
    required String label,
    required IconData icon,
    bool isPassword = false,
    TextInputAction? textInputAction,
    Function(String)? onFieldSubmitted,
  }) {
    return TextFormField(
      controller: controller,
      obscureText: isPassword,
      textInputAction: textInputAction,
      onFieldSubmitted: onFieldSubmitted,
      style: const TextStyle(color: Colors.white),
      decoration: InputDecoration(
        labelText: label,
        labelStyle: TextStyle(color: Colors.white.withOpacity(0.6)),
        prefixIcon: Icon(icon, color: Colors.white.withOpacity(0.6)),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: Colors.white.withOpacity(0.3)),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: Color(0xFFE9C46A)),
        ),
        filled: true,
        fillColor: Colors.white.withOpacity(0.05),
      ),
      validator: (value) {
        if (value == null || value.isEmpty) {
          return 'Please enter your ${label.toLowerCase()}';
        }
        return null;
      },
    );
  }

  Widget _buildStatusMessage() {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: (_isError ? Colors.red : Colors.blue).withOpacity(0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: (_isError ? Colors.red : Colors.blue).withOpacity(0.3),
        ),
      ),
      child: Row(
        children: [
          Icon(
            _isError ? Icons.error_outline : Icons.info_outline,
            size: 18,
            color: _isError ? Colors.red.shade400 : Colors.blue.shade400,
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              _statusMessage!,
              style: TextStyle(
                color: _isError ? Colors.red.shade400 : Colors.blue.shade400,
                fontSize: 13,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildPasswordActionButtons() {
    return Column(
      children: [
        SizedBox(
          width: double.infinity,
          height: 48,
          child: ElevatedButton(
            onPressed: _isLoading ? null : _handleSignIn,
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFFE9C46A),
              foregroundColor: Colors.black,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(8),
              ),
            ),
            child: _isLoading
                ? const SizedBox(
                    width: 20,
                    height: 20,
                    child: CircularProgressIndicator(
                      strokeWidth: 2,
                      valueColor: AlwaysStoppedAnimation<Color>(Colors.black),
                    ),
                  )
                : Text(
                    _isRegistering ? 'Registering...' : 'Sign In',
                    style: const TextStyle(
                      fontWeight: FontWeight.bold,
                      fontSize: 15,
                    ),
                  ),
          ),
        ),
        const SizedBox(height: 12),
        SizedBox(
          width: double.infinity,
          height: 48,
          child: OutlinedButton(
            onPressed: _isLoading ? null : _handleRegister,
            style: OutlinedButton.styleFrom(
              foregroundColor: const Color(0xFFE9C46A),
              side: const BorderSide(color: Color(0xFFE9C46A)),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(8),
              ),
            ),
            child: Text(
              _isRegistering ? 'Registering...' : 'Register',
              style: const TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 15,
              ),
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildPasskeyActionButtons() {
    return Column(
      children: [
        SizedBox(
          width: double.infinity,
          height: 48,
          child: ElevatedButton.icon(
            onPressed: _isLoading ? null : _handlePasskeySignIn,
            icon: const Icon(Icons.fingerprint),
            label: Text(
              _isLoading ? 'Signing In...' : 'Sign In with Passkey',
              style: const TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 15,
              ),
            ),
            style: ElevatedButton.styleFrom(
              backgroundColor: const Color(0xFFE9C46A),
              foregroundColor: Colors.black,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(8),
              ),
            ),
          ),
        ),
        const SizedBox(height: 12),
        SizedBox(
          width: double.infinity,
          height: 48,
          child: ElevatedButton.icon(
            onPressed: _isLoading ? null : _handlePasskeyRegister,
            icon: const Icon(Icons.person_add),
            label: Text(
              _isLoading ? 'Creating...' : 'Create Passkey',
              style: const TextStyle(
                fontWeight: FontWeight.bold,
                fontSize: 15,
              ),
            ),
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.white.withOpacity(0.1),
              foregroundColor: Colors.white,
              side: BorderSide(color: Colors.white.withOpacity(0.3)),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(8),
              ),
            ),
          ),
        ),
      ],
    );
  }
}

enum AuthTab {
  password,
  passkey,
}

extension AuthTabExtension on AuthTab {
  String get label {
    switch (this) {
      case AuthTab.password:
        return 'Password';
      case AuthTab.passkey:
        return 'Passkey';
    }
  }
}

class _NetworkLinesPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = Colors.black.withOpacity(0.3)
      ..strokeWidth = 1.5
      ..style = PaintingStyle.stroke;

    final path = Path();

    // Draw network lines
    path.moveTo(size.width * 0.35, size.height * 0.25);
    path.lineTo(size.width * 0.5, size.height * 0.5);
    path.lineTo(size.width * 0.35, size.height * 0.75);

    path.moveTo(size.width * 0.65, size.height * 0.25);
    path.lineTo(size.width * 0.5, size.height * 0.5);
    path.lineTo(size.width * 0.65, size.height * 0.75);

    path.moveTo(size.width * 0.2, size.height * 0.5);
    path.lineTo(size.width * 0.8, size.height * 0.5);

    canvas.drawPath(path, paint);
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

class _LeafPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()
      ..color = const Color(0xFF2A9D8F)
      ..style = PaintingStyle.fill;

    final path = Path();
    path.moveTo(size.width * 0.5, size.height);
    path.quadraticBezierTo(
      size.width * 0.8,
      size.height * 0.3,
      size.width,
      size.height * 0.5,
    );
    path.quadraticBezierTo(
      size.width * 0.8,
      size.height * 0.8,
      size.width * 0.5,
      size.height,
    );

    canvas.drawPath(path, paint);
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}
