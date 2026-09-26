---
layout: default
title: Why Use Lemonade-Nexus?
---

# Why Use Lemonade-Nexus?

## Self-Hosted, No Kernel Module

You operate the servers and own every key. The whole mesh — BoringTun plus
the TCP/IP stack — runs **in userspace**: no kernel WireGuard module, no TUN
device, no root, no capabilities. A compromised or misconfigured server still
cannot reach the kernel networking stack.

## Cryptographic Identity, Not Accounts

Every server and client has an Ed25519 identity. Servers carry
network-bound certificates signed by the root management key; clients
authenticate by Ed25519 challenge-response or WebAuthn passkey. There is no
password-derived trust to phish and no shared secret to leak.

## Authority That Can Be Verified

After the Genesis bootstrap, authority is **epoch-scoped and consensus-based**:

- Tier 1 membership is established by verified platform evidence and
  finalized consensus state — not by configuration, not by uptime, not by a
  root server's say-so.
- Each epoch's authority key is generated **dealerless** by the committee
  (FROST DKG); no single node or third party ever holds the full key.
- The deterministic rules (fault tolerance, quorum, signing thresholds) are
  **compiled into the binary**, so no operator setting can weaken them.

Genesis's unilateral authority ends when Epoch 1 activates, and restored
authority is reauthenticated from the pinned Genesis anchor at every
startup.

## Hardware-Rooted Evidence (with honest status)

The implemented attestation path verifies an AMD SEV-SNP guest, a
paravisor-bound vTPM, and IMA runtime measurements, bound to a fresh
challenge and to the network. The evidence is collected by a
privilege-separated helper daemon that holds no Nexus keys.

The status is explicit: the shipped profile is not yet pinned with approved
measurements, so no node can qualify for Tier 1 with the current release.
That is a fail-closed limit we document rather than a gap we hide. See
[Attestation](Attestation).

## Encrypted End to End

- Mesh traffic: WireGuard-protocol encryption (BoringTun), with NAT
  traversal and relay fallback. Relays see only ciphertext.
- Control planes: HTTPS only, with ACME-provisioned certificates. The
  private API additionally lives behind the mesh.
- At rest: one versioned AEAD construction (XChaCha20-Poly1305-IETF) for
  wrapped keys and credentials.

## Built-in Discovery and Addressing

Servers publish regional DNS records (SEIP) and claim bootstrap nameserver
slots; clients find the nearest healthy server automatically. IPAM assigns
client, private, shared, and backbone addresses deterministically. You can
use your own domain for the discovery zone.

## Embedded, Not Just a Binary

The C++ SDK and C ABI bring the whole dataplane into your application:
identity, authentication, join, tree operations, P2P mesh, relay,
certificates, and publishing local services to mesh peers. The Flutter
desktop client is a reference consumer over the same C ABI.

## What It Does Not Claim

- It does not claim protection from privileged root inside the guest.
- It does not claim universal TEE support: one provider is implemented, two
  are declared-but-refusing, and the rest are absent.
- It does not claim automatic reclamation of departed servers' backbone IPs,
  or consensus authorization of every application write — those are listed
  as current limits in [Security — Current
  Limitations](Security#current-limitations) rather than papered over.
