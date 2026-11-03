---
layout: default
title: Home
---

# Lemonade-Nexus

A self-hosted userspace mesh VPN with encrypted peer-to-peer connections, cryptographic identity, and an attestation-based security protocol.

> **Development status:** The Tier 1/Tier 2 security protocol, permission-tree operations through Tier 1 consensus, threshold storage encryption, and in-place server updates are implemented. Tier 1 attestation uses AMD SEV-SNP with a COCONUT-SVSM vTPM, and only a server that runs a signed release for its network can qualify. Read [current limitations](Security#current-limitations) before planning a deployment.

## Documentation

### Getting Started
- [Getting Started](Getting-Started) — Build, install, bootstrap a new network, onboard an existing one
- [FAQ](FAQ) — Frequently asked questions
- [Why Use This?](Why-Use-This) — What Lemonade-Nexus offers, and what it does not yet offer

### Architecture
- [Architecture](Architecture) — Components, startup, state stores, API routing
- [Network Architecture](Network-Architecture) — Traffic paths, userspace netstack, security transport
- [DNS Discovery](DNS-Discovery) — SEIP/EP subdomains, NS slots, client discovery

### Security
- [Security](Security) — Roles, epoch authority, Genesis, trust chain, threat assumptions, limitations
- [Design: Tree Consensus and Threshold Storage Key](Design-Tree-Consensus-and-Storage-Key) — Approved; Phases 1 to 7 implemented: tree changes through Tier 1 consensus, a 65% threshold storage key, the sealed boot set, and encrypted data files
- [Tree Merge Ceremony](Tree-Merge-Ceremony) — One-time migration: merge every server's tree into tree log height 1, signed by the root management key
- [Design: In-Place Auto-Update](Design-Auto-Update) — Draft; release workflow, updater, approval supersession, mixed-version gate, and upgrade turns implemented and in use for date releases, not hardware-qualified
- [Wire and Storage Compatibility Between Releases](Wire-Compatibility) — What a release may change and what it must keep
- [Upgrade Control Interface](Upgrade-Control) — The root-only socket between the server and `nexus-updater`
- [Attestation](Attestation) — Providers, evidence path, `nexus-attestd`, profile requirements, fail-closed diagnostics

### Reference
- [Ports and Firewall](Ports-and-Firewall) — All ports, NAT and filter rules
- [IP Ranges](IP-Ranges) — IPAM allocation, client/server/backbone ranges
- [Configuration](Configuration) — Trust anchors, CLI flags, environment variables, JSON config

### Development
- [SDK Guide](SDK-Guide) — C++ and C API reference with examples
- [Client SDK](Client-SDK) — SDK overview and linking
- [Frameworks and Libraries](Frameworks-and-Libraries) — Tech stack and dependencies
- [Building](Building) — Build instructions and platform status
- [Releasing](Releasing) — The release workflow, required repository settings, and the server updater
- [Live SDK E2E](Live-E2E) — The CI test that runs the SDK against the production fleet as two clients

## Quick Links

- **Releases:** date versions (`vYYYY.MM.DD`) from one release workflow; see [Releasing](Releasing) and [GitHub Releases](https://github.com/lemonade-sdk/lemonade-nexus/releases)
- **Repository:** [github.com/lemonade-sdk/lemonade-nexus](https://github.com/lemonade-sdk/lemonade-nexus)
- **Issues:** [GitHub Issues](https://github.com/lemonade-sdk/lemonade-nexus/issues)
