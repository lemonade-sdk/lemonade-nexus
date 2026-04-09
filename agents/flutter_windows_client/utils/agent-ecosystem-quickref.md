# Utility: Agent Ecosystem Quick Reference

## Overview
Quick reference for the Flutter Windows Client agent ecosystem.

## Agent Directory Structure

```
agents/
└── flutter_windows_client/           # Master Agent
    ├── agent.md                       # Main agent definition
    ├── commands/                      # 8 orchestration commands
    ├── tasks/                         # 6 coordination tasks
    ├── templates/                     # 7 code templates
    ├── checklists/                    # 5 quality checklists
    ├── data/                          # 5 knowledge files
    └── utils/                         # 5 utility guides

└── ffi_bindings_agent/               # FFI Subagent
└── ui_components_agent/              # UI Subagent
└── state_management_agent/           # State Subagent
└── windows_integration_agent/        # Windows Subagent
└── testing_agent/                    # Testing Subagent
└── packaging_agent/                  # Packaging Subagent
```

## Master Agent Commands

| Command | Purpose | Delegates To |
|---------|---------|--------------|
| `initialize-flutter-project` | Project scaffolding | All agents |
| `orchestrate-full-build` | Full coordination | All agents |
| `generate-ffi-bindings` | FFI creation | FFI Agent |
| `build-ui-components` | UI creation | UI Agent |
| `setup-state-management` | State setup | State Agent |
| `integrate-windows-native` | Windows integration | Windows Agent |
| `create-test-suite` | Testing | Testing Agent |
| `package-for-windows` | Packaging | Packaging Agent |

## Subagent Summary

### FFI Bindings Agent
**Purpose:** Create Dart FFI wrappers for C SDK
**Components:** ~28
**Deliverables:**
- `ffi_bindings.dart` - Raw FFI
- `sdk_wrapper.dart` - Idiomatic API
- `types.dart` - Model classes

### UI Components Agent
**Purpose:** Build Flutter UI views
**Components:** ~28
**Deliverables:**
- 12 view files
- Widget library
- Theme system

### State Management Agent
**Purpose:** Implement Provider/Riverpod
**Components:** ~28
**Deliverables:**
- State providers
- Service classes
- Data models

### Windows Integration Agent
**Purpose:** Windows-native features
**Components:** ~28
**Deliverables:**
- System tray
- Windows service
- Auto-start

### Testing Agent
**Purpose:** Create test suite
**Components:** ~28
**Deliverables:**
- Unit tests
- Widget tests
- Integration tests

### Packaging Agent
**Purpose:** MSIX/MSI packaging
**Components:** ~28
**Deliverables:**
- MSIX configuration
- Code signing setup
- Distribution pipeline

## Quick Start Workflow

```
1. Initialize Project
   └─> Command: initialize-flutter-project

2. Generate FFI Bindings
   └─> Command: generate-ffi-bindings
   └─> Agent: ffi_bindings_agent

3. Create UI Components
   └─> Command: build-ui-components
   └─> Agent: ui_components_agent

4. Setup State Management
   └─> Command: setup-state-management
   └─> Agent: state_management_agent

5. Integrate Windows
   └─> Command: integrate-windows-native
   └─> Agent: windows_integration_agent

6. Create Tests
   └─> Command: create-test-suite
   └─> Agent: testing_agent

7. Package for Release
   └─> Command: package-for-windows
   └─> Agent: packaging_agent
```

## Component Counts

| Agent | Commands | Tasks | Templates | Checklists | Data | Utils | Total |
|-------|----------|-------|-----------|------------|------|-------|-------|
| Master | 8 | 6 | 7 | 5 | 5 | 5 | 36 |
| FFI | 8 | 6 | 7 | 5 | 5 | 5 | ~36 |
| UI | 8 | 6 | 7 | 5 | 5 | 5 | ~36 |
| State | 8 | 6 | 7 | 5 | 5 | 5 | ~36 |
| Windows | 8 | 6 | 7 | 5 | 5 | 5 | ~36 |
| Testing | 8 | 6 | 7 | 5 | 5 | 5 | ~36 |
| Packaging | 8 | 6 | 7 | 5 | 5 | 5 | ~36 |

**Total Ecosystem:** ~250 components

## Key Reference Files

| File | Purpose |
|------|---------|
| `docs/Windows-Client-Strategy.md` | Technology decision |
| `apps/LemonadeNexusMac/` | Reference implementation |
| `projects/LemonadeNexusSDK/include/` | C SDK headers |
| `agents/flutter_windows_client/agent.md` | Master agent |

## Usage Patterns

### Invoking Master Agent
```
"Use the Flutter Windows Client Master Agent to [action]"

Examples:
- "Initialize the Flutter project structure"
- "Orchestrate the full build process"
- "Generate FFI bindings for the C SDK"
```

### Invoking Subagents
```
"Delegate to [SUBAGENT] for [TASK]"

Examples:
- "Delegate to FFI Bindings Agent for C SDK wrappers"
- "Delegate to UI Agent for LoginView conversion"
- "Delegate to Testing Agent for widget tests"
```

### Using Templates
```
"Use the [TEMPLATE] template for [COMPONENT]"

Examples:
- "Use the flutter-view-component template for DashboardView"
- "Use the ffi-binding-definition template for ln_health"
- "Use the widget-test template for LoginView tests"
```

## Related Documentation
- Individual agent `agent.md` files
- Template files in each agent's `templates/`
- Checklist files for quality assurance
