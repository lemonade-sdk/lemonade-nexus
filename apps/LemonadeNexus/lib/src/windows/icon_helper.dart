/// @title Windows Icon Helper
/// @description Helper for creating and managing Windows tray icons.
///
/// Provides:
/// - Icon creation from assets
/// - Icon color based on connection status
/// - Icon scaling for different DPI settings

import 'dart:io';
import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';

/// Connection status colors for icons
class IconColors {
  static const Color disconnected = Color(0xFF718096);
  static const Color connecting = Color(0xFFF6AD55);
  static const Color connected = Color(0xFF48BB78);
  static const Color error = Color(0xFFF56565);
}

/// Helper class for Windows tray icons
class TrayIconHelper {
  /// Create an icon from a color
  static Future<ByteData?> createIconFromColor(
    Color color, {
    int size = 64,
  }) async {
    try {
      final recorder = ui.PictureRecorder();
      final canvas = Canvas(recorder);
      final paint = Paint()..color = color;

      // Draw circle background
      canvas.drawCircle(
        Offset(size / 2, size / 2),
        size / 2 - 2,
        paint,
      );

      // Draw VPN shield symbol
      final shieldPaint = Paint()..color = Colors.white;
      final shieldPath = Path();

      final centerX = size / 2;
      final centerY = size / 2;
      final shieldSize = size * 0.4;

      // Simple shield shape
      shieldPath.moveTo(centerX, centerY - shieldSize / 2);
      shieldPath.lineTo(centerX + shieldSize / 2, centerY - shieldSize / 4);
      shieldPath.lineTo(centerX + shieldSize / 2, centerY + shieldSize / 4);
      shieldPath.lineTo(centerX, centerY + shieldSize / 2);
      shieldPath.lineTo(centerX - shieldSize / 2, centerY + shieldSize / 4);
      shieldPath.lineTo(centerX - shieldSize / 2, centerY - shieldSize / 4);
      shieldPath.close();

      canvas.drawPath(shieldPath, shieldPaint);

      final picture = recorder.endRecording();
      final image = await picture.toImage(size, size);
      final byteData = await image.toByteData(format: ui.ImageByteFormat.png);

      return byteData;
    } catch (e) {
      debugPrint('Failed to create icon: $e');
      return null;
    }
  }

  /// Get icon color based on connection status
  static Color getColorForStatus(bool isConnected, bool isConnecting) {
    if (isConnecting) {
      return IconColors.connecting;
    } else if (isConnected) {
      return IconColors.connected;
    } else {
      return IconColors.disconnected;
    }
  }

  /// Save icon to file
  static Future<bool> saveIconToFile(ByteData byteData, String path) async {
    try {
      final file = File(path);
      await file.writeAsBytes(byteData.buffer.asUint8List());
      return true;
    } catch (e) {
      debugPrint('Failed to save icon: $e');
      return false;
    }
  }

  /// Create ICO file with multiple sizes
  static Future<bool> createIcoFile(String outputPath) async {
    try {
      // ICO files contain multiple sizes
      // For simplicity, we create a PNG which Windows can use
      final byteData = await createIconFromColor(IconColors.connected);
      if (byteData != null) {
        final file = File(outputPath);
        await file.writeAsBytes(byteData.buffer.asUint8List());
        return true;
      }
      return false;
    } catch (e) {
      debugPrint('Failed to create ICO file: $e');
      return false;
    }
  }
}

/// Widget for displaying VPN status icon
class VpnStatusIcon extends StatelessWidget {
  final bool isConnected;
  final bool isConnecting;
  final double size;

  const VpnStatusIcon({
    super.key,
    required this.isConnected,
    this.isConnecting = false,
    this.size = 24,
  });

  @override
  Widget build(BuildContext context) {
    final color = TrayIconHelper.getColorForStatus(isConnected, isConnecting);

    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        color: color,
        shape: BoxShape.circle,
      ),
      child: Icon(
        Icons.security,
        color: Colors.white,
        size: size * 0.6,
      ),
    );
  }
}

/// Status indicator widget for tray
class TrayStatusIndicator extends StatelessWidget {
  final bool isConnected;
  final bool isConnecting;
  final String? tooltip;

  const TrayStatusIndicator({
    super.key,
    required this.isConnected,
    this.isConnecting = false,
    this.tooltip,
  });

  @override
  Widget build(BuildContext context) {
    final color = TrayIconHelper.getColorForStatus(isConnected, isConnecting);
    final statusText = isConnecting
        ? 'Connecting...'
        : isConnected
            ? 'Connected'
            : 'Disconnected';

    return Tooltip(
      message: tooltip ?? statusText,
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            width: 8,
            height: 8,
            decoration: BoxDecoration(
              color: color,
              shape: BoxShape.circle,
            ),
          ),
          const SizedBox(width: 4),
          Text(
            statusText,
            style: const TextStyle(fontSize: 10, color: Colors.white),
          ),
        ],
      ),
    );
  }
}
