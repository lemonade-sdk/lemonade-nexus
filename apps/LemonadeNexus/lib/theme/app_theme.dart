import 'package:flutter/material.dart';

/// Lemonade Nexus theme — mirrors the macOS app's design system (Theme.swift):
/// a lemon-yellow brand on flat, native-style surfaces. The system font is used
/// (SF Pro on macOS) by leaving fontFamily unset.
class AppTheme {
  // Brand colors (from the macOS app).
  static const Color lemonYellow = Color(0xFFFFE135);
  static const Color lemonYellowDark = Color(0xFFE6C71A);
  static const Color lemonGreen = Color(0xFF4CAF50);
  static const Color nodeOrange = Color(0xFFFF6B00);

  // Status.
  static const Color errorColor = Color(0xFFFF3B30);
  static const Color infoColor = Color(0xFF0A84FF);

  // Surfaces approximating NSColor window/control backgrounds.
  static const Color _lightWindow = Color(0xFFECECEC);
  static const Color _lightControl = Color(0xFFFFFFFF);
  static const Color _lightText = Color(0xFF1A1A1A);
  static const Color _lightTextSecondary = Color(0x993C3C43); // ~60%
  static const Color _lightDivider = Color(0xFFE0E0E0);

  static const Color _darkWindow = Color(0xFF1E1E1E);
  static const Color _darkControl = Color(0xFF2B2B2B);
  static const Color _darkText = Color(0xFFECECEC);
  static const Color _darkTextSecondary = Color(0x99EBEBF5); // ~60%
  static const Color _darkDivider = Color(0xFF3A3A3C);

  static ThemeData get light => _build(
        brightness: Brightness.light,
        window: _lightWindow,
        control: _lightControl,
        onSurface: _lightText,
        onSurfaceSecondary: _lightTextSecondary,
        divider: _lightDivider,
      );

  static ThemeData get dark => _build(
        brightness: Brightness.dark,
        window: _darkWindow,
        control: _darkControl,
        onSurface: _darkText,
        onSurfaceSecondary: _darkTextSecondary,
        divider: _darkDivider,
      );

  static ThemeData _build({
    required Brightness brightness,
    required Color window,
    required Color control,
    required Color onSurface,
    required Color onSurfaceSecondary,
    required Color divider,
  }) {
    final scheme = ColorScheme(
      brightness: brightness,
      primary: lemonYellow,
      onPrimary: Colors.black,
      secondary: lemonGreen,
      onSecondary: Colors.white,
      tertiary: nodeOrange,
      onTertiary: Colors.white,
      error: errorColor,
      onError: Colors.white,
      surface: control,
      onSurface: onSurface,
      surfaceContainerHighest: brightness == Brightness.light
          ? const Color(0xFFF2F2F2)
          : const Color(0xFF323232),
      onSurfaceVariant: onSurfaceSecondary,
      outline: divider,
    );

    return ThemeData(
      useMaterial3: true,
      brightness: brightness,
      colorScheme: scheme,
      scaffoldBackgroundColor: window,
      canvasColor: window,
      dividerColor: divider,
      appBarTheme: AppBarTheme(
        backgroundColor: window,
        foregroundColor: onSurface,
        elevation: 0,
        centerTitle: false,
        titleTextStyle: TextStyle(
          color: onSurface,
          fontSize: 18,
          fontWeight: FontWeight.w600,
        ),
      ),
      cardTheme: CardThemeData(
        color: control,
        elevation: 1,
        shadowColor: Colors.black.withValues(alpha: 0.08),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        margin: EdgeInsets.zero,
      ),
      elevatedButtonTheme: ElevatedButtonThemeData(
        style: ElevatedButton.styleFrom(
          backgroundColor: lemonYellow,
          foregroundColor: Colors.black,
          elevation: 0,
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
          textStyle: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
        ),
      ),
      outlinedButtonTheme: OutlinedButtonThemeData(
        style: OutlinedButton.styleFrom(
          foregroundColor: lemonYellowDark,
          side: const BorderSide(color: lemonYellow, width: 1.5),
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
          shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
          textStyle: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600),
        ),
      ),
      textButtonTheme: TextButtonThemeData(
        style: TextButton.styleFrom(foregroundColor: lemonYellowDark),
      ),
      progressIndicatorTheme: const ProgressIndicatorThemeData(color: lemonYellow),
      inputDecorationTheme: InputDecorationTheme(
        filled: true,
        fillColor: brightness == Brightness.light
            ? const Color(0xFFF5F5F5)
            : const Color(0xFF1E1E1E),
        contentPadding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: divider),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: BorderSide(color: divider),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: lemonYellow, width: 2),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(8),
          borderSide: const BorderSide(color: errorColor),
        ),
        labelStyle: TextStyle(color: onSurfaceSecondary),
      ),
      dividerTheme: DividerThemeData(color: divider, thickness: 0.5),
    );
  }
}
