---
layout: default
title: Frequently Asked Questions
---

# Frequently Asked Questions

## What is Lemonade-Nexus?

A self-hosted userspace mesh VPN with encrypted peer-to-peer connections,
cryptographic identity, and an attestation-based security protocol. You run
the servers; the software provides the mesh, discovery, addressing,
certificates, and the security protocol.

## Do I need to run my own server?

Yes, at least one. A packaged install plus `nexus-bootstrap` gets a Genesis
server configured in a few commands; see [Getting
Started](Getting-Started).

## Is there a central authority?

There is a **root management key** and a **Genesis bootstrap anchor**, both
operator-pinned. The root key signs server admission certificates, and the
Genesis anchor establishes the network identity. Neither is a live control
plane: the root key does not grant Tier 1 authority, and Genesis's unilateral
security authority ends at Epoch 1 activation. After that, authority is
epoch-scoped and follows finalized consensus state. See
[Security](Security).

## How does the two-tier model work?

- **Tier 2** servers hold a valid network-bound certificate and serve mesh
  services, clients, and non-authoritative state.
- **Tier 1** servers are the epoch committee: verified platform evidence and
  mesh observations establish eligibility, and finalized eligibility, plan,
  readiness, and handoff establish the role. Tier 1 members run HotStuff
  consensus and participate in the per-epoch FROST key generation.

Tier 1 is an **epoch-scoped** role, not a permanent status.

## Can I run it without TEE hardware?

Yes. Servers without qualifying platform evidence operate as Tier 2: they
serve clients, participate in the mesh, and synchronize state. They simply
do not qualify for Tier 1.

**Important:** with the currently shipped attestation profile, *no* node can
qualify for Tier 1, because the profile's required measurements and release
hashes are not yet pinned in a qualifying release. This is a fail-closed
blocker, not a configuration problem. See [Attestation](Attestation) and
[Security — Current
Limitations](Security#current-limitations).

## Which attestation platforms are supported?

The implemented provider verifies the **AMD SEV-SNP/HCL/vTPM** path (with
IMA runtime measurements). The SVSM-vTPM and direct-boot providers are
declared but refuse evidence (`ProviderUnsupported`), and there is no SGX,
TDX, or Secure Enclave provider in this repository. See the
[provider matrix](Attestation#provider-matrix).

## How does NAT traversal work?

1. STUN (UDP `3478`) discovers each peer's reflexive address.
2. The routing API (`/api/routing/*`) coordinates candidate exchange and
   verifies candidates against the observed control-connection source.
3. Both sides send WireGuard-protocol (BoringTun) handshakes to each other's
   discovered endpoints on the **shared mesh UDP port `51940`** — there is no
   separate hole-punch port.
4. If a direct path cannot be formed, the coordinator issues a relay ticket
   and traffic flows through a relay server (UDP `9103`). Relays see only
   ciphertext.

## How are IP addresses allocated?

- **Clients:** sequential from `10.64.0.0/10`, starting at `.10` (first ten
  reserved).
- **Servers:** deterministic from the server's identity key, in
  `172.16.0.0/22`, with pubkey-based conflict resolution.

Details in [IP Ranges](IP-Ranges). Note that automatic reclamation of
departed servers' backbone IPs is not yet wired.

## What happens if a server goes down?

- Clients of that server lose their tunnel; the client SDK re-discovers via
  DNS and switches to the next best server (latency plus load scoring),
  re-joining with the preserved identity.
- Other servers continue operating.
- The downed server's backbone IP is not automatically reclaimed in the
  current revision (see [IP Ranges — Staleness and
  Reclamation](IP-Ranges#staleness-and-reclamation)).

## How do I add a new server?

Use **server onboarding** against an existing server — never initialize a
second Genesis for the same network:

1. Obtain the network's `root_pubkey` out of band.
2. Run `lemonade-nexus --onboard-server <fqdn>:9100 --root-pubkey <hex>` as
   the service user.
3. Approve the pending request on the existing server (private API) or mint a
   single-use enrollment token.
4. Set `release_signing_pubkey` on the new server, then start the service.

The full flow, including what onboarding persists and what you configure
separately, is in [Getting Started — Join an existing
network](Getting-Started#join-an-existing-network-server-onboarding).

## What is stored on disk?

File-backed signed JSON records for identity, tree, IPAM, and the durable
security stores, plus a SQLite database for the application ACL store. There
is no external database service. See [Architecture —
Storage](Architecture#storage).

## Is it free / open source?

The repository is released under the [MIT
License](https://github.com/lemonade-sdk/lemonade-nexus/blob/main/LICENSE).

## What platforms are supported?

- **Server:** Linux is the primary target (packaged install, systemd,
  evidence helper). macOS builds run in CI. Windows build definitions exist
  but the Windows CI jobs are disabled, so Windows is not a qualified
  platform yet.
- **Client:** macOS desktop (CI-verified) and Windows desktop (build
  definitions present; CI disabled).
- **SDK:** C++ and C ABI, consumed by the Flutter client and by embedders.

Tier 1 attestation support and platform build support are separate questions;
see [Building — Windows Status](Building#windows-status) and
[Attestation](Attestation).

## How is this different from Tailscale / ZeroTier / Nebula?

| | Lemonade-Nexus | Tailscale | ZeroTier | Nebula |
|---|---|---|---|---|
| Coordination | Self-hosted servers you operate | SaaS coordination server | Controller (SaaS or self-hosted) | Self-hosted static config |
| Transport | Userspace WireGuard (BoringTun) + userspace netstack | WireGuard (kernel) | Custom (ZT) | Custom (Nebula) |
| Server authority | Epoch committee: attestation + consensus + threshold signing | Company-operated | Controller | Static root CA |
| DNS | Built-in authoritative DNS | MagicDNS | None | None |
| Hardware attestation | SEV-SNP/HCL/vTPM path implemented (qualification pending) | No | No | No |

The comparison is structural, not a performance claim.
