# Command: Orchestrate Full Build

## Description
Coordinates all specialized subagents to complete the full Flutter Windows client build.

## Purpose
Master orchestration command that ensures all components are built in the correct sequence with proper integration.

## Steps

### Phase 1: Foundation (Week 1)
1. Run `initialize-flutter-project`
2. Run `generate-ffi-bindings` (FFI Agent)
3. Run `setup-state-management` (State Agent)

### Phase 2: UI Development (Week 2-3)
4. Run `build-ui-components` (UI Agent)
   - Login/Authentication views
   - Dashboard view
   - Tunnel control view
   - Peer list view

### Phase 3: Advanced Features (Week 3-4)
5. Run `integrate-windows-native` (Windows Agent)
   - System tray integration
   - Windows service setup
   - Auto-start configuration

### Phase 4: Quality & Release (Week 4-5)
6. Run `create-test-suite` (Testing Agent)
7. Run `package-for-windows` (Packaging Agent)

## Orchestration Workflow

```
┌─────────────────────────────────────────────────────┐
│           Master Agent Orchestrator                  │
└─────────────────────────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│  FFI Agent    │  │  State Agent  │  │   UI Agent    │
│  (40 FFI)     │  │  (Providers)  │  │  (12 Views)   │
└───────────────┘  └───────────────┘  └───────────────┘
        │                 │                 │
        └─────────────────┼─────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        │                 │                 │
        ▼                 ▼                 ▼
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│ Windows Agent │  │ Testing Agent │  │ Packaging Agt │
│  (Native)     │  │  (Tests)      │  │  (MSIX)       │
└───────────────┘  └───────────────┘  └───────────────┘
```

## Integration Points

### FFI → State Management
- FFI bindings provide raw SDK access
- State management wraps FFI in reactive providers

### State → UI Components
- UI components consume providers
- UI events trigger state changes

### UI → Windows Integration
- System tray reflects UI state
- Windows service manages tunnel lifecycle

### All → Testing
- Unit tests for FFI, services, state
- Widget tests for UI components
- Integration tests for full flows

### All → Packaging
- All artifacts included in MSIX
- Code signing applied

## Quality Gates

Before proceeding to next phase:
- [ ] All tests pass
- [ ] Code review completed
- [ ] Integration verified
- [ ] Documentation updated

## Timeline

| Phase | Duration | Deliverables |
|-------|----------|--------------|
| Foundation | 1 week | FFI bindings, state management |
| UI Core | 1 week | Login, Dashboard, Tunnel, Peers |
| UI Advanced | 1 week | Network Monitor, Tree, Servers, Certs, Settings |
| Windows | 0.5 week | System tray, service, auto-start |
| Testing | 0.5 week | Test suite, CI/CD |
| Packaging | 0.5 week | MSIX, signing, distribution |

## Success Criteria
- All 6 subagents complete their deliverables
- Full integration testing passes
- MSIX package ready for distribution
- Documentation complete
