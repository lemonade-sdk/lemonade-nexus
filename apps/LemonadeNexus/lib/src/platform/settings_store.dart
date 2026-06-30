/// Non-secret preference persistence via shared_preferences.

import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../state/app_state.dart';

class SettingsStore {
  static const _kHost = 'serverHost';
  static const _kPort = 'serverPort';
  static const _kAutoDiscovery = 'autoDiscoveryEnabled';
  static const _kAutoConnect = 'autoConnectOnLaunch';
  static const _kTls = 'useTls';
  static const _kDarkMode = 'darkModeEnabled';
  static const _kThemeMode = 'themeMode';

  Future<Settings> load() async {
    final prefs = await SharedPreferences.getInstance();
    const defaults = Settings();
    return Settings(
      serverHost: prefs.getString(_kHost) ?? defaults.serverHost,
      serverPort: prefs.getInt(_kPort) ?? defaults.serverPort,
      autoDiscoveryEnabled: prefs.getBool(_kAutoDiscovery) ?? defaults.autoDiscoveryEnabled,
      autoConnectOnLaunch: prefs.getBool(_kAutoConnect) ?? defaults.autoConnectOnLaunch,
      useTls: prefs.getBool(_kTls) ?? defaults.useTls,
      darkModeEnabled: prefs.getBool(_kDarkMode) ?? defaults.darkModeEnabled,
    );
  }

  Future<void> save(Settings s) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_kHost, s.serverHost);
    await prefs.setInt(_kPort, s.serverPort);
    await prefs.setBool(_kAutoDiscovery, s.autoDiscoveryEnabled);
    await prefs.setBool(_kAutoConnect, s.autoConnectOnLaunch);
    await prefs.setBool(_kTls, s.useTls);
    await prefs.setBool(_kDarkMode, s.darkModeEnabled);
  }

  Future<ThemeMode> loadThemeMode() async {
    final prefs = await SharedPreferences.getInstance();
    final idx = prefs.getInt(_kThemeMode);
    if (idx == null || idx < 0 || idx >= ThemeMode.values.length) {
      return ThemeMode.system;
    }
    return ThemeMode.values[idx];
  }

  Future<void> saveThemeMode(ThemeMode mode) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt(_kThemeMode, mode.index);
  }
}
