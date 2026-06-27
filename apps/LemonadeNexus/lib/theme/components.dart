/// Reusable UI components mirroring the macOS app's Theme.swift helpers:
/// the lemon logo, cards, status dots, badges, section headers, stat cards and
/// empty states. Keeps the Flutter views looking like the original app.

import 'package:flutter/material.dart';

import 'app_theme.dart';

/// The brand lemon mark: a yellow lemon with orange mesh nodes and a green leaf.
class LemonLogo extends StatelessWidget {
  final double size;
  const LemonLogo({super.key, this.size = 100});

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: size,
      height: size,
      child: CustomPaint(painter: _LemonLogoPainter()),
    );
  }
}

class _LemonLogoPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    final w = size.width, h = size.height;
    final cx = w / 2, cy = h / 2;
    final body = Rect.fromCenter(center: Offset(cx, cy), width: w * 0.8, height: h * 0.6);

    // Glow.
    canvas.drawOval(
      body.inflate(w * 0.04),
      Paint()
        ..color = AppTheme.lemonYellow.withValues(alpha: 0.35)
        ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 10),
    );
    // Lemon body.
    canvas.drawOval(body, Paint()..color = AppTheme.lemonYellow);

    // Mesh lines.
    final line = Paint()
      ..color = Colors.black.withValues(alpha: 0.30)
      ..strokeWidth = w * 0.012
      ..style = PaintingStyle.stroke;
    final p = Path()
      ..moveTo(cx - w * 0.18, cy - h * 0.16)
      ..lineTo(cx, cy)
      ..lineTo(cx - w * 0.18, cy + h * 0.16)
      ..moveTo(cx + w * 0.18, cy - h * 0.16)
      ..lineTo(cx, cy)
      ..lineTo(cx + w * 0.18, cy + h * 0.16)
      ..moveTo(cx - w * 0.28, cy)
      ..lineTo(cx + w * 0.28, cy);
    canvas.drawPath(p, line);

    // Mesh nodes.
    final node = Paint()..color = AppTheme.nodeOrange;
    final r = w * 0.035;
    for (final o in [
      Offset(cx - w * 0.18, cy - h * 0.16),
      Offset(cx + w * 0.18, cy - h * 0.16),
      Offset(cx - w * 0.18, cy + h * 0.16),
      Offset(cx + w * 0.18, cy + h * 0.16),
      Offset(cx - w * 0.28, cy),
      Offset(cx + w * 0.28, cy),
      Offset(cx, cy),
    ]) {
      canvas.drawCircle(o, r, node);
    }

    // Leaf.
    final leaf = Paint()..color = AppTheme.lemonGreen;
    final ly = body.top - h * 0.02;
    final leafPath = Path()
      ..moveTo(cx, ly)
      ..quadraticBezierTo(cx + w * 0.14, ly - h * 0.12, cx + w * 0.04, ly - h * 0.14)
      ..quadraticBezierTo(cx - w * 0.02, ly - h * 0.06, cx, ly);
    canvas.drawPath(leafPath, leaf);
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

/// Rounded card with a subtle shadow (mirrors Swift cardStyle()).
class AppCard extends StatelessWidget {
  final Widget child;
  final EdgeInsetsGeometry padding;
  final double radius;
  const AppCard({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.all(16),
    this.radius = 12,
  });

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Container(
      padding: padding,
      decoration: BoxDecoration(
        color: scheme.surface,
        borderRadius: BorderRadius.circular(radius),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.08),
            blurRadius: 4,
            offset: const Offset(0, 2),
          ),
        ],
      ),
      child: child,
    );
  }
}

/// Small status dot with a soft glow.
class StatusDot extends StatelessWidget {
  final bool isHealthy;
  final double size;
  const StatusDot({super.key, required this.isHealthy, this.size = 10});

  @override
  Widget build(BuildContext context) {
    final color = isHealthy ? AppTheme.lemonGreen : AppTheme.errorColor;
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        color: color,
        shape: BoxShape.circle,
        boxShadow: [BoxShadow(color: color.withValues(alpha: 0.5), blurRadius: 3)],
      ),
    );
  }
}

/// Capsule badge (mirrors Swift BadgeView).
class LemonBadge extends StatelessWidget {
  final String text;
  final Color color;
  const LemonBadge({super.key, required this.text, this.color = AppTheme.lemonGreen});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.2),
        borderRadius: BorderRadius.circular(100),
      ),
      child: Text(
        text,
        style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.w600),
      ),
    );
  }
}

/// Section header with a lemon-yellow leading icon.
class SectionHeader extends StatelessWidget {
  final String title;
  final IconData icon;
  const SectionHeader({super.key, required this.title, required this.icon});

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        Icon(icon, color: AppTheme.lemonYellowDark, size: 18),
        const SizedBox(width: 8),
        Text(title,
            style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
      ],
    );
  }
}

/// Stat card with an icon, a big value and a caption (mirrors Swift StatCard).
class StatCard extends StatelessWidget {
  final String title;
  final String value;
  final IconData icon;
  final Color color;
  const StatCard({
    super.key,
    required this.title,
    required this.value,
    required this.icon,
    this.color = AppTheme.lemonYellowDark,
  });

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return AppCard(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, color: color, size: 22),
          const SizedBox(height: 8),
          Text(value,
              style: const TextStyle(fontSize: 26, fontWeight: FontWeight.bold)),
          const SizedBox(height: 2),
          Text(title,
              style: TextStyle(fontSize: 12, color: scheme.onSurfaceVariant)),
        ],
      ),
    );
  }
}

/// Centered empty-state placeholder (mirrors Swift EmptyStateView).
class EmptyState extends StatelessWidget {
  final IconData icon;
  final String title;
  final String message;
  const EmptyState({
    super.key,
    required this.icon,
    required this.title,
    required this.message,
  });

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(40),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 48, color: scheme.onSurfaceVariant.withValues(alpha: 0.5)),
            const SizedBox(height: 16),
            Text(title,
                style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.w600,
                    color: scheme.onSurfaceVariant)),
            const SizedBox(height: 6),
            Text(message,
                textAlign: TextAlign.center,
                style: TextStyle(
                    fontSize: 13,
                    color: scheme.onSurfaceVariant.withValues(alpha: 0.7))),
          ],
        ),
      ),
    );
  }
}
