# Command: Setup State Management

## Description
Delegates state management implementation to the State Management Agent using Provider/Riverpod.

## Purpose
Create a robust, scalable state management system for the Flutter client.

## Delegation Target
**State Management Agent** (`../state_management_agent/agent.md`)

## Steps

### 1. Invoke State Agent
```
Delegate to State Management Agent:
"Implement Provider/Riverpod state management for Lemonade Nexus client"
```

### 2. State Agent Deliverables

#### State Infrastructure
- `app_state.dart` - Main application state
- `providers.dart` - Provider definitions
- `state_notifiers.dart` - Reactive state classes

#### Service Providers
- `auth_provider.dart` - Authentication state
- `tunnel_provider.dart` - Tunnel state
- `peers_provider.dart` - Peer list state
- `network_provider.dart` - Network monitor state

#### Data Models
- `user_model.dart` - User data
- `peer_model.dart` - Peer data
- `tunnel_model.dart` - Tunnel status
- `server_model.dart` - Server data

### 3. State Flow Architecture

```
┌─────────────────────────────────────────────────────┐
│                   UI Layer                           │
│  (Views consume providers, dispatch actions)        │
└─────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│                State Management Layer                │
│  (Providers, StateNotifiers, ChangeNotifiers)       │
└─────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│                 Service Layer                        │
│  (Business logic, FFI SDK wrappers)                 │
└─────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────┐
│                  FFI Layer                           │
│  (Dart FFI bindings to C SDK)                       │
└─────────────────────────────────────────────────────┘
```

## State Categories

### Authentication State
```dart
enum AuthStatus { unauthenticated, authenticating, authenticated, error }

class AuthState {
  final AuthStatus status;
  final String? userId;
  final String? sessionToken;
  final String? error;
}
```

### Tunnel State
```dart
enum TunnelStatus { disconnected, connecting, connected, error }

class TunnelState {
  final TunnelStatus status;
  final String? tunnelIp;
  final String? serverEndpoint;
  final int rxBytes;
  final int txBytes;
  final double? latency;
}
```

### Peer State
```dart
class PeersState {
  final List<Peer> peers;
  final bool isLoading;
  final DateTime? lastRefresh;
  final String? error;
}
```

## Expected Output
- Complete provider setup
- Reactive state classes
- Service integration
- Data models

## Success Criteria
- State updates propagate to UI
- No memory leaks
- Clean separation of concerns
- Testable architecture
