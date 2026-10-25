---
layout: default
title: Home
---

# Lemonade-Nexus

A self-hosted userspace mesh VPN with encrypted peer-to-peer connections, cryptographic identity, and an attestation-based security protocol.

> **Development status:** The two-tier security protocol is merged. The protocol and evidence-collection code are present, but the shipped attestation profile still lacks the approved measurements needed to qualify a Tier 1 node. Read [current limitations](Security#current-limitations) before planning a deployment.

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
- [Design: Tree Consensus and Threshold Storage Key](Design-Tree-Consensus-and-Storage-Key) — Approved; Phases 1 to 3 experimental: tree changes through Tier 1 consensus, and a 65% threshold storage key
- [Tree Merge Ceremony](Tree-Merge-Ceremony) — Experimental runbook: merge every server's tree into tree log height 1, then switch to tree operations
- [Design: In-Place Auto-Update](Design-Auto-Update) — Draft; release workflow, updater, approval supersession, mixed-version gate, and upgrade turns implemented, not hardware-qualified
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

- **Current version:** v0.9.0-alpha
- **Repository:** [github.com/lemonade-sdk/lemonade-nexus](https://github.com/lemonade-sdk/lemonade-nexus)
- **Issues:** [GitHub Issues](https://github.com/lemonade-sdk/lemonade-nexus/issues)
