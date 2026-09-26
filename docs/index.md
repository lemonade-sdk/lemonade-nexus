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

## Quick Links

- **Current version:** v0.9.0-alpha
- **Repository:** [github.com/lemonade-sdk/lemonade-nexus](https://github.com/lemonade-sdk/lemonade-nexus)
- **Issues:** [GitHub Issues](https://github.com/lemonade-sdk/lemonade-nexus/issues)
