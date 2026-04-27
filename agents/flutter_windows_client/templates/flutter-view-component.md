# Template: Flutter View Component

## Description
Standard template for creating Flutter view components that match macOS SwiftUI views.

## Usage
Use this template when creating any new view component.

## Template Structure

```dart
// lib/src/views/{view_name}_view.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../state/{state_provider}.dart';
import '../widgets/{related_widget}.dart';

/// {@template {viewName}View}
/// Description of what this view displays.
///
/// Corresponds to macOS SwiftUI view: {MacOSViewName}.swift
/// {@endtemplate}
class {ViewName}View extends StatelessWidget {
  const {ViewName}View({super.key});

  @override
  Widget build(BuildContext context) {
    return Consumer<{StateClass}>(
      builder: (context, state, child) {
        return Scaffold(
          appBar: AppBar(
            title: const Text('{View Title}'),
            actions: [
              // AppBar actions
            ],
          ),
          body: _buildBody(context, state),
          floatingActionButton: _buildFab(context),
        );
      },
    );
  }

  Widget _buildBody(BuildContext context, {StateClass} state) {
    return Padding(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // View content
        ],
      ),
    );
  }

  Widget? _buildFab(BuildContext context) {
    // Optional floating action button
    return null;
  }
}
```

## Example Usage

```dart
// lib/src/views/dashboard_view.dart
import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../state/tunnel_provider.dart';
import '../widgets/status_indicator.dart';

/// {@template DashboardView}
/// Main dashboard showing tunnel status, peer count, and quick stats.
///
/// Corresponds to macOS SwiftUI view: DashboardView.swift
/// {@endtemplate}
class DashboardView extends StatelessWidget {
  const DashboardView({super.key});

  @override
  Widget build(BuildContext context) {
    return Consumer<TunnelProvider>(
      builder: (context, tunnelState, child) {
        return Scaffold(
          appBar: AppBar(
            title: const Text('Dashboard'),
            actions: [
              IconButton(
                icon: const Icon(Icons.refresh),
                onPressed: () => tunnelState.refresh(),
              ),
            ],
          ),
          body: _buildBody(context, tunnelState),
        );
      },
    );
  }

  Widget _buildBody(BuildContext context, TunnelState state) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Tunnel status card
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16.0),
              child: Column(
                children: [
                  StatusIndicator(status: state.status),
                  const SizedBox(height: 16),
                  Text(
                    state.status.displayString,
                    style: Theme.of(context).textTheme.headlineSmall,
                  ),
                  if (state.tunnelIp != null) ...[
                    const SizedBox(height: 8),
                    Text('IP: ${state.tunnelIp}'),
                  ],
                ],
              ),
            ),
          ),
          const SizedBox(height: 16),
          // Stats row
          Row(
            children: [
              Expanded(child: _buildStatCard('Peers', state.peerCount.toString())),
              const SizedBox(width: 16),
              Expanded(child: _buildStatCard('Latency', '${state.latency?.toStringAsFixed(0) ?? '-'} ms')),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildStatCard(String label, String value) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          children: [
            Text(value, style: const TextStyle(fontSize: 24, fontWeight: FontWeight.bold)),
            Text(label, style: TextStyle(color: Colors.grey[600])),
          ],
        ),
      ),
    );
  }
}
```

## Related Templates
- Widget Component Template
- State Provider Template
- Service Class Template

## Notes
- Always include documentation comments
- Reference corresponding macOS view
- Use Consumer for state access
- Follow Material Design 3 guidelines
