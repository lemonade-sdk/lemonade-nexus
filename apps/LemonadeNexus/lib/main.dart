import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:window_manager/window_manager.dart';

import 'src/state/providers.dart';
import 'src/views/login_view.dart';
import 'src/views/main_navigation.dart';
import 'theme/app_theme.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  if (Platform.isWindows || Platform.isMacOS || Platform.isLinux) {
    await windowManager.ensureInitialized();
    const options = WindowOptions(
      size: Size(1100, 750),
      minimumSize: Size(900, 600),
      center: true,
      title: 'Lemonade Nexus',
      titleBarStyle: TitleBarStyle.normal,
    );
    await windowManager.waitUntilReadyToShow(options, () async {
      await windowManager.setTitle('Lemonade Nexus');
      await windowManager.show();
      await windowManager.focus();
    });
  }
  runApp(
    const ProviderScope(
      child: LemonadeNexusApp(),
    ),
  );
}

class LemonadeNexusApp extends ConsumerWidget {
  const LemonadeNexusApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final themeMode = ref.watch(themeProvider);

    return MaterialApp(
      title: 'Lemonade Nexus',
      debugShowCheckedModeBanner: false,
      theme: AppTheme.light,
      darkTheme: AppTheme.dark,
      themeMode: themeMode,
      home: const AppShell(),
    );
  }
}

class AppShell extends ConsumerStatefulWidget {
  const AppShell({super.key});

  @override
  ConsumerState<AppShell> createState() => _AppShellState();
}

class _AppShellState extends ConsumerState<AppShell> {
  @override
  void initState() {
    super.initState();
    // Initialize app state on startup
    WidgetsBinding.instance.addPostFrameCallback((_) {
      ref.read(appNotifierProvider.notifier).initialize();
      ref.read(platformIntegrationProvider).initialize();
    });
  }

  @override
  Widget build(BuildContext context) {
    final appState = ref.watch(appNotifierProvider);

    // Show login view if not authenticated, otherwise show main navigation
    if (!appState.isAuthenticated) {
      return const LoginView();
    }

    return const MainNavigation();
  }
}
