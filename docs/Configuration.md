---
layout: default
title: Configuration Reference
---

# Configuration Reference

## Table of Contents
- [Configuration Sources and Precedence](#configuration-sources-and-precedence)
- [Trust Anchors (Required for a Normal Start)](#trust-anchors-required-for-a-normal-start)
- [Network](#network)
- [Identity and Auth](#identity-and-auth)
- [DNS](#dns)
- [TLS / ACME](#tls--acme)
- [DDNS](#ddns)
- [Onboarding](#onboarding)
- [JSON Config Example](#json-config-example)
- [Retired and Inert Settings](#retired-and-inert-settings)

## Configuration Sources and Precedence

A normal start reads settings from four sources. **Highest priority first:**

1. **Environment variables** — `SP_*` (for the packaged service:
   `/etc/lemonade-nexus/lemonade-nexus.env`)
2. **CLI arguments** — for example `--http-port 8443`
3. **JSON config file** — `lemonade-nexus.json` (packaged default location:
   `/var/lib/lemonade-nexus/lemonade-nexus.json`)
4. **Defaults**

Two deliberate exceptions to "environment wins":

- **Explicit trust anchors win over the environment.** If you pass
  `--root-pubkey` or `--genesis-pubkey` on the command line, the corresponding
  `SP_ROOT_PUBKEY` / `SP_GENESIS_PUBKEY` environment values are ignored (with a
  warning). An environment variable must not silently replace an anchor the
  operator pinned in the start command.
- **Environment seed peers append.** `SP_SEED_PEERS` (comma-separated) is
  added to the seed list from the config file and `--seed-peer`; it does not
  replace it.

Note: an environment variable overrides a CLI value for *every other* setting
(for example `SP_HTTP_PORT` overrides `--http-port`). Keep the packaged
environment file for deliberate operator overrides only.

## Trust Anchors (Required for a Normal Start)

A normal daemon start refuses to run without all three values:

| Setting | Purpose | Accepted encoding |
|---|---|---|
| `root_pubkey` | Mesh root management key. Verifies server admission certificates; without it no certificate can be verified. | Hex Ed25519 public key (64 hex characters) |
| `genesis_pubkey` | Pins the Genesis bootstrap anchor. The network identity derives from it, and the epoch authority chain verifies from it. Its unilateral authority ends at Epoch 1 activation. | Base64 Ed25519 public key (32 bytes) |
| `release_signing_pubkey` | Verifies signed release manifests. Without it no binary can be approved and the server can never reach Tier 1. | Ed25519 public key; base64 in the daemon config, hex or base64 via `nexus-bootstrap` |

```
--root-pubkey <hex>          SP_ROOT_PUBKEY
--genesis-pubkey <b64>       SP_GENESIS_PUBKEY
--release-signing-pubkey <key>  SP_RELEASE_SIGNING_PUBKEY
```

On the Genesis server, `nexus-bootstrap` writes all three (see
[Getting Started](Getting-Started)). On a joining server, onboarding writes
`root_pubkey` (confirmed against your pinned value) and `genesis_pubkey`
(authenticated in the bundle); `release_signing_pubkey` is always configured
by the operator.

These are the only trust inputs. There is no supported configuration switch to
force Tier 1, skip evidence, or change quorums or thresholds: those are
compiled protocol rules, not settings.

## Network

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--http-port <N>` | `SP_HTTP_PORT` | `http_port` | `9100` | Public HTTPS API |
| `--udp-port <N>` | `SP_UDP_PORT` | `udp_port` | `51940` | Mesh tunnel and hole punching (shared) |
| `--gossip-port <N>` | `SP_GOSSIP_PORT` | `gossip_port` | `9102` | Gossip and security protocol |
| `--stun-port <N>` | `SP_STUN_PORT` | `stun_port` | `3478` | STUN NAT traversal |
| `--relay-port <N>` | `SP_RELAY_PORT` | `relay_port` | `9103` | Relay forwarding |
| `--dns-port <N>` | `SP_DNS_PORT` | `dns_port` | `5335` | Local authoritative DNS, UDP+TCP |
| `--public-dns-port <N>` | `SP_PUBLIC_DNS_PORT` | `public_dns_port` | `53` | DNS port advertised to clients (NAT-mapped to `dns_port`) |
| `--private-http-port <N>` | `SP_PRIVATE_HTTP_PORT` | `private_http_port` | `9101` | Private API (virtual mesh addresses; loopback-backed) |
| `--bind-address <addr>` | `SP_BIND_ADDRESS` | `bind_address` | `0.0.0.0` | Listen address |
| `--public-ip <addr>` | `SP_PUBLIC_IP` | `public_ip` | (auto) | Public IP for DNS records and discovery |
| `--region <code>` | `SP_REGION` | `region` | (auto) | Cloud region code (lowercase DNS label) |
| `--mesh-interface <name>` | `SP_MESH_INTERFACE` | `mesh_interface` | `nexus0` | BoringTun dataplane instance name |

All six service ports plus the private port must be unique. Every port the
server binds is unprivileged; public `53` (and `443`, where used) is reached
by firewall/NAT mapping, not by the server binding it.

## Identity and Auth

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--data-root <path>` | `SP_DATA_ROOT` | `data_root` | `data` | Data directory (identity, state, security stores) |
| `--log-level <level>` | `SP_LOG_LEVEL` | `log_level` | `info` | `trace`, `debug`, `info`, `warn`, `error` |
| `--rp-id <domain>` | `SP_RP_ID` | `rp_id` | `lemonade-nexus.local` | WebAuthn relying party ID |
| `--seed-peer <host:port>` | `SP_SEED_PEERS` | `seed_peers` | | Gossip seed peers (repeatable / comma-separated; env appends) |
| `--server-hostname <name>` | `SP_SERVER_HOSTNAME` | `server_hostname` | (auto) | Server hostname for the TLS certificate |
| `--closed-registration` | `SP_CLOSED_REGISTRATION` | `open_registration` | open | New identities need a device link token to join |

## DNS

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--dns-base-domain <dom>` | `SP_DNS_BASE_DOMAIN` | `dns_base_domain` | `lemonade-nexus.io` | Discovery zone suffix |
| `--dns-ns-hostname <fqdn>` | `SP_DNS_NS_HOSTNAME` | `dns_ns_hostname` | (auto) | This server's NS hostname (pins its NS slot) |
| `--dns-provider <name>` | `SP_DNS_PROVIDER` | `dns_provider` | `local` | `local` (self-hosted authoritative) or `cloudflare` |
| `--no-dns-seed-discovery` | `SP_DNS_SEED_DISCOVERY=0` | `dns_seed_discovery` | on | Do not auto-discover seed peers from tier/region DNS records |

## TLS / ACME

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--acme-provider <name>` | `SP_ACME_PROVIDER` | `acme_provider` | `letsencrypt` | `letsencrypt`, `letsencrypt_staging`, `zerossl` |
| `--acme-eab-kid <kid>` | `SP_ACME_EAB_KID` | `acme_eab_kid` | | ZeroSSL External Account Binding key ID |
| `--acme-eab-hmac-key <key>` | `SP_ACME_EAB_HMAC_KEY` | `acme_eab_hmac_key` | | ZeroSSL EAB HMAC key (base64url) |

Listeners are withheld until a usable certificate exists for the server's
FQDNs; the background ACME thread retries with backoff and upgrades the
listener in place. There is no plaintext fallback.

## DDNS

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--ddns-domain <dom>` | `SP_DDNS_DOMAIN` | `ddns_domain` | | Base domain for DDNS (Namecheap) |
| `--ddns-password <pw>` | `SP_DDNS_PASSWORD` | `ddns_password` | | DDNS password |
| `--ddns-enabled` | `SP_DDNS_ENABLED` | `ddns_enabled` | `false` | Enable dynamic DNS updates |

Release manifest fetching (`SP_GITHUB_RELEASES_URL`,
`SP_MANIFEST_FETCH_INTERVAL`, `SP_MINIMUM_VERSION`) controls how the server
checks for signed manifests of other versions.

## Onboarding

Server-side (a server that holds the root key accepts onboarding by default):

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--no-onboard` | | `onboard_enabled` | on | Refuse onboarding requests |
| `--mint-admission-token` | | `mint_admission_token` | | Mint a single-use enrollment token and exit (root holder only) |
| `--token-candidate <b64>` | | `mint_token_candidate` | | Candidate gossip pubkey the token binds to (required with mint) |
| `--token-ttl <sec>` | | `mint_token_ttl_sec` | `600` | Minted-token lifetime (60–3600) |

Candidate-side:

| CLI Flag | Env Var | Description |
|----------|---------|-------------|
| `--onboard-server [fqdn[:port]]` | | Run the onboarding client against an existing server (verified HTTPS by FQDN). Requires `--root-pubkey`. |
| `--onboard-addr <ip>` | | Pin the connect IP while still verifying the FQDN certificate |
| `--onboard-id <label>` | | Requested DNS label for the new server |
| `--onboard-timeout <sec>` | | Give up waiting for admission after this (default 900) |
| `--onboard-token <tok>` | `SP_ONBOARD_TOKEN` | Single-use enrollment token for immediate admission |

## JSON Config Example

```json
{
  "http_port": 9100,
  "udp_port": 51940,
  "gossip_port": 9102,
  "stun_port": 3478,
  "relay_port": 9103,
  "dns_port": 5335,
  "public_dns_port": 53,
  "private_http_port": 9101,
  "data_root": "/var/lib/lemonade-nexus/data",
  "region": "us-west",
  "dns_base_domain": "lemonade-nexus.io",
  "server_hostname": "ns1",
  "acme_provider": "letsencrypt",
  "log_level": "info",
  "root_pubkey": "<hex ed25519 root management key>",
  "genesis_pubkey": "<base64 ed25519 genesis anchor>",
  "release_signing_pubkey": "<release signing key>",
  "seed_peers": ["<server-ip>:9102"]
}
```

The packaged bootstrap writes this file for you. Edit it with `sudoedit`; the
service unit mounts it read-only.

## Command-Mode Flags

These flags select a one-shot command instead of running the daemon:

| Flag | Description |
|----------|-------------|
| `--first-run` | Bootstrap the node identity and print the trust anchors to pin (`Identity pubkey` = root, `Gossip pubkey` = Genesis). One-time, per node. |
| `--verify-platform [blob]` | Verify this host's platform evidence (AMD signature chain, guest policy, memory-encryption guarantees) and exit. Optional: a pre-captured evidence blob instead of the local helper. |
| `--enroll-server <pubkey> <id>` | Root-side: enroll a server identity (used by the onboarding approve path and manual enrollment). |
| `--revoke-server <pubkey>` | Root-side: revoke a server identity. |
| `--enroll-tpm-ak <b64>` | With enrollment: pin the server's platform binding key (base64 DER SPKI) in its certificate. |
| `--enroll-tpm-ek-cert <path>` | With enrollment: attach the server's TPM EK certificate (PEM) for audit/validation. |
| `--add-manifest <path>` | Load a signed release manifest from a local file and exit. |
| `--github-releases-url <url>` | Override the GitHub releases URL for manifest fetching (env: `SP_GITHUB_RELEASES_URL`). |
| `--manifest-fetch-interval <sec>` | Manifest fetch interval (env: `SP_MANIFEST_FETCH_INTERVAL`). |
| `--minimum-version <ver>` | Minimum client version gate (env: `SP_MINIMUM_VERSION`). |

`--config <path>`, `--data-root <path>`, `--log-level <level>`, and the
port flags apply to the command as well where relevant. Note two current
mismatches in the `--help` text: it still lists `--require-peer-confirmation`,
which the binary does not accept (see
[Retired and Inert Settings](#retired-and-inert-settings)), and it does not
list the parsed `--onboard-timeout` flag.

## Retired and Inert Settings

The following settings no longer do anything and are not recognized:

- `require_tee_attestation`, `tee_platform_override`,
  `require_binary_attestation`, `tee_attestation_validity_sec` — the old TEE
  knobs were unreachable, inert, or dead. Attestation is enforced by the
  compiled protocol, not by configuration.
- `admission_quorum_ratio`, `enrollment_*`, `onboard_min_tier1_for_vote`,
  `--require-peer-confirmation` — the old quorum/enrollment votes were
  removed with the retired governance system. Admission is root-gated
  approval or a single-use token.

These inert settings are listed so that older runbooks and environment files
can be read correctly; remove them from your configuration when you touch
it.
