---
layout: default
title: Getting Started
---

# Getting Started

This guide covers the supported server path: build, package install, starting a
new network (Genesis), joining an existing network (server onboarding), and
diagnosing the services. It ends with the current blockers you must know before
planning a deployment.

- [Prerequisites](#prerequisites)
- [Build the server](#build-the-server)
- [Install the Debian/Ubuntu package](#install-the-debianubuntu-package)
- [Start a new network (Genesis)](#start-a-new-network-genesis)
- [Join an existing network (server onboarding)](#join-an-existing-network-server-onboarding)
- [TLS and DNS prerequisites](#tls-and-dns-prerequisites)
- [Service diagnostics](#service-diagnostics)
- [Current blockers](#current-blockers)

## Prerequisites

A Linux server (Debian 12+ or Ubuntu 22.04+) with a public IP and a DNS zone
you control for the discovery base domain. For a packaged install the machine
needs Python 3 for `nexus-bootstrap`.

To build from source you also need:

- C++20 compiler, CMake 3.25.1+, Ninja
- Rust/Cargo toolchain (`rustc` and `cargo` on `PATH`)
- Debian/Ubuntu development packages: `libjson-c-dev`, `libcurl4-openssl-dev`, `uuid-dev`

The normal Linux build compiles TPM2-TSS from source; you do not install a
system TPM2-TSS package. See [Building](Building) for details.

Open the ports listed in [Ports and Firewall](Ports-and-Firewall). In short:
TCP `9100`, UDP `51940` (mesh and hole punching share this port), UDP `9102`,
UDP `3478`, and, for DNS-serving nodes, UDP+TCP `53` mapped to local `5335`.

## Build the server

```bash
git clone https://github.com/lemonade-sdk/lemonade-nexus.git
cd lemonade-nexus
cmake -S . -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON
cmake --build build --parallel
```

The server executable is `build/projects/LemonadeNexus/lemonade-nexus`.

Hardware-dependent tests skip when their required environment is absent.
Skipped tests do not establish hardware qualification.

## Install the Debian/Ubuntu package

For a systemd deployment, build the package and install it:

```bash
cpack --config build/CPackConfig.cmake -G DEB -B build/packages
sudo apt install ./build/packages/lemonade-nexus-*.deb
```

The package installs:

- `/usr/bin/lemonade-nexus` — the server
- `/usr/bin/nexus-attestd` — the platform evidence helper
- `/usr/bin/nexus-bootstrap` — the Genesis setup command
- The `lemonade-nexus.service` and `nexus-attestd.service` units

The install **enables** the services without starting them. Start them only
after the configuration below is in place.

## Start a new network (Genesis)

Genesis starts a **new network**. Use the packaged bootstrap command:

```bash
sudo nexus-bootstrap \
  --release-signing-pubkey 'YOUR_RELEASE_SIGNING_PUBLIC_KEY'
```

`--release-signing-pubkey` is the Ed25519 public key that verifies your release
manifests, encoded as 64 hex characters or base64 for 32 bytes. Generate one
with:

```bash
python3 scripts/generate_release_signing_key.py
```

Bootstrap creates the node identities, pins the root and Genesis public keys,
and writes:

- Configuration: `/var/lib/lemonade-nexus/lemonade-nexus.json` (root-owned,
  mode 0640, parent directory mode 0750 — the daemon cannot edit its trust
  anchors)
- Runtime state: `/var/lib/lemonade-nexus/data` (service-owned, mode 0700)

The on-disk values:

| Config key | Value for the Genesis server |
|---|---|
| `root_pubkey` | The node identity public key (hex Ed25519). This is the mesh root; every other server must use the same value. |
| `genesis_pubkey` | The node gossip public key (base64 Ed25519). It pins the Genesis bootstrap anchor, whose unilateral security authority ends at Epoch 1 activation. |
| `release_signing_pubkey` | The release-signing key you supplied (or, for `--test-release-key`, the node identity). |

If this host serves public authoritative DNS, add `--install-dns-nat` to map
UDP/TCP `53` to `5335` with nftables. That option requires `nft` and `ip`;
`--wan-interface` selects the external interface when auto-detection is
ambiguous. You can also configure the mapping on your router. See
[Ports and Firewall](Ports-and-Firewall).

For a disposable development network, `sudo nexus-bootstrap --test-release-key`
uses the node identity as the test release key. It does not bypass attestation
requirements or enable Tier 1 qualification.

Then start the server:

```bash
sudo systemctl start lemonade-nexus.service
systemctl status lemonade-nexus.service nexus-attestd.service
sudo journalctl -u lemonade-nexus.service -u nexus-attestd.service -f
```

The server unit also requests `nexus-attestd`, so starting the server pulls the
helper in.

**A successful bootstrap or daemon start does not mean that Epoch 1 has
formed.** The shipped attestation profile is incomplete by design, so no node
can currently reach Tier 1 with it. See [current blockers](#current-blockers)
and [Security — current limitations](Security#current-limitations).

## Join an existing network (server onboarding)

Use server onboarding instead of initializing another Genesis. A candidate
server asks an existing server for admission over the public API and installs
the returned network-bound certificate.

### Trust values the candidate needs

| Value | How the candidate obtains it | Where it goes |
|---|---|---|
| `root_pubkey` (hex Ed25519) | **Out of band**, before onboarding. On the Genesis server it is the `Identity pubkey` printed by `--first-run`; it is also in the Genesis server's protected configuration. | Passed as `--root-pubkey` and written to the candidate's config. Onboarding *confirms* it against the bundle but never establishes it. |
| `genesis_pubkey` (base64 Ed25519) | **The onboarding bundle authenticates it**: the certificate's network ID must derive from the bundle's Genesis key. No separate out-of-band exchange is needed. | Written to the candidate's config by the onboarding client. |
| `release_signing_pubkey` | **Not part of the bundle.** Configure it separately with the key that verifies the releases you will run. | Candidate's config. Required for a normal daemon start. |

Do not copy security state (certificates, keypairs, epoch stores) from another
server to make a candidate join. Onboarding produces the candidate's own
certificate and keys.

### Run the onboarding client

From the candidate server:

```bash
sudo runuser -u lemonade-nexus -- /usr/bin/lemonade-nexus \
  --data-root /var/lib/lemonade-nexus/data \
  --config /var/lib/lemonade-nexus/lemonade-nexus.json \
  --root-pubkey <EXPECTED_ROOT_HEX> \
  --onboard-server <existing-server-fqdn>:9100
```

Notes on the options:

- `--onboard-server <fqdn[:port]>` — the target's **certificate FQDN**. The
  connection is verified HTTPS; a bare IP cannot verify a certificate. If the
  FQDN must resolve to a specific address (for example local development),
  pass `--onboard-addr <ip>` to pin the connect address while still verifying
  the FQDN certificate.
- Without a target, the client discovers
  `tier1.<region>.seip.<domain>` and `tier2.<region>.seip.<domain>` from the
  configured `region` and `dns_base_domain`.
- `--onboard-id <label>` requests a specific DNS label; otherwise one is
  auto-derived.
- `--onboard-token <tok>` presents a single-use enrollment token for immediate
  admission (no admin approval wait). The root server mints one with
  `--mint-admission-token --token-candidate <b64-gossip-pubkey>`
  (optionally `--token-ttl <sec>`).
- `--onboard-timeout <sec>` bounds the wait for a decision (default 900).

The candidate must have a data directory (run `--first-run` once as the service
user, or let the packaged flow create it). The candidate's platform evidence,
when the host can produce it, is attached to the admission request and bound to
the challenge nonce. A host without usable evidence receives a Tier 2
certificate; that is not a failure.

### What happens during onboarding

1. The client sends a challenge request with its gossip public key.
2. It answers with a signed admission request (identity proof of possession),
   optionally with platform evidence and an enrollment token.
3. On the existing server, an administrator approves the pending request on the
   private API (`POST /api/onboard/approve/<request_id>`, reachable over the
   mesh), or the request was admitted immediately via its token.
4. The client polls, then verifies the returned bundle: the root key matches
   the pinned `--root-pubkey`, the certificate is bound to the candidate's
   public key and signed by the root, and the bundle's Genesis binding holds.
5. The client persists:
   - the certificate to `<data_root>/identity/server_cert.json`
   - `root_pubkey`, `genesis_pubkey`, and the merged seed peers to the config
     file (the address it just reached is seeded first)

It then prints the server ID, the installed paths, and the command to start
the server.

### After onboarding

1. Verify `release_signing_pubkey` is set in the protected configuration
   (edit with `sudoedit`; it is not delivered by onboarding).
2. Start the packaged service:

   ```bash
   sudo systemctl start lemonade-nexus.service
   ```

3. Confirm the server registers its discovery records and gossips with the
   seeded peers.

Admission grants a **server identity**, not Tier 1 membership. Tier 1
authority is established only by the epoch protocol described in
[Security](Security).

## TLS and DNS prerequisites

- The server obtains TLS certificates for its FQDNs through ACME
  (Let's Encrypt by default; `letsencrypt_staging` and `zerossl` are also
  supported). Both API listeners are **withheld until a usable certificate
  exists** — there is no plaintext fallback.
- The public certificate target is the server's SEIP FQDN
  (`<id>.<region>.seip.<domain>`), so that name must resolve publicly to the
  server's public IP for ACME DNS-01 and for clients.
- A server that serves public authoritative DNS listens on UDP+TCP `5335` as
  an unprivileged user. Public UDP+TCP `53` reaches it only through a
  firewall/NAT mapping. Verify the mapping on **both** transports and scope it
  to the external interface so the host's own resolver is untouched.
  An authoritative server that answers only UDP fails queries whose response
  is truncated.
- DNS is how clients and joining servers find the mesh. Pinned keys, verified
  certificates, and finalized security state establish trust; DNS only
  provides reachability.

## Service diagnostics

```bash
# Service state
systemctl status lemonade-nexus.service nexus-attestd.service
systemctl status nexus-dns-nat.service   # only when --install-dns-nat was used

# Logs
sudo journalctl -u lemonade-nexus.service -f
sudo journalctl -u nexus-attestd.service -f

# Startup lines to look for
#   "All services started. HTTPS:9100, PrivateHTTPS:..., UDP:51940, ..."
#   "Public API withheld: no TLS certificate yet ..."  (expected on first boot;
#    the background ACME thread brings the listener up once a cert is issued)
#   "Attestation profile v1 is incomplete: ..." (expected; see current blockers)

# Listener check
ss -ltnup | grep -E '9100|9101|51940|9102|3478|9103|5335'
```

If the startup log contains
`SECURITY: No tunnel_bind_ip configured — private API routes are exposed on
the public HTTP server`, the private API is not isolated on the mesh. Route
authentication still applies, but network isolation does not. Review the
server's mesh configuration before exposing it.

## Current blockers

These are implementation limits, not settings an operator can disable:

- **Tier 1 qualification is blocked in the shipped profile.** The compiled
  attestation profile pins no launch measurement, TCB floor, IMA policy
  digest, or approved component hashes. Until a qualifying release pins those
  values, every attestation fails with `ProfileIncomplete` and no node can
  reach Tier 1. See [Attestation](Attestation).
- **Application-root initialization is incomplete.** Public authentication
  does not initialize an application-root owner, and several admission and
  application paths are root- or identity-gated rather than derived from
  finalized security state. Fresh-network administrative approval flows are
  affected. See [Security — current limitations](Security#current-limitations).

Everything in this guide that does not depend on those two items works as
documented: mesh transport, client join, discovery, certificates, and Tier 2
server operation.
