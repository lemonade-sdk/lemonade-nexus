---
layout: default
title: Configuration Reference
---

# Configuration Reference

## Table of Contents
- [Configuration Sources](#configuration-sources)
- [Network](#network)
- [Identity and Auth](#identity-and-auth)
- [DNS](#dns)
- [Security and Trust](#security-and-trust)
- [DDNS](#ddns)
- [JSON Config Example](#json-config-example)

## Configuration Sources

Priority (highest to lowest):
1. **CLI arguments** — `--http-port 8443`
2. **Environment variables** — `SP_HTTP_PORT=8443`
3. **JSON config file** — `lemonade-nexus.json`
4. **Defaults**

## Network

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--http-port <N>` | `SP_HTTP_PORT` | `http_port` | `9100` | Public HTTPS API |
| `--udp-port <N>` | `SP_UDP_PORT` | `udp_port` | `51940` | WireGuard tunnel |
| `--gossip-port <N>` | `SP_GOSSIP_PORT` | `gossip_port` | `9102` | Gossip protocol |
| `--stun-port <N>` | `SP_STUN_PORT` | `stun_port` | `3478` | STUN NAT traversal |
| `--relay-port <N>` | `SP_RELAY_PORT` | `relay_port` | `9103` | Relay forwarding |
| `--dns-port <N>` | `SP_DNS_PORT` | `dns_port` | `53` | Authoritative DNS |
| `--private-http-port <N>` | `SP_PRIVATE_HTTP_PORT` | `private_http_port` | `9101` | Private HTTPS API |
| `--bind-address <addr>` | `SP_BIND_ADDRESS` | `bind_address` | `0.0.0.0` | Listen address |
| `--region <code>` | `SP_REGION` | `region` | (auto) | Cloud region code |

> Hole punch uses hardcoded port 51941 (separate from WireGuard on 51940).

## Identity and Auth

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--root-pubkey <hex>` | `SP_ROOT_PUBKEY` | `root_pubkey` | | Root Ed25519 key (hex) |
| `--rp-id <domain>` | `SP_RP_ID` | `rp_id` | `lemonade-nexus.local` | WebAuthn relying party ID |
| `--seed-peer <host:port>` | `SP_SEED_PEERS` | `seed_peers` | | Gossip seed peers (repeatable) |
| `--server-hostname <name>` | `SP_SERVER_HOSTNAME` | `server_hostname` | (auto) | Server hostname |
| `--data-root <path>` | `SP_DATA_ROOT` | `data_root` | `data` | Data directory |
| `--log-level <level>` | `SP_LOG_LEVEL` | `log_level` | `info` | Log level |

## DNS

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--dns-base-domain <dom>` | `SP_DNS_BASE_DOMAIN` | `dns_base_domain` | `lemonade-nexus.io` | DNS zone |
| `--dns-ns-hostname <fqdn>` | `SP_DNS_NS_HOSTNAME` | `dns_ns_hostname` | (auto) | NS hostname |
| `--dns-provider <name>` | `SP_DNS_PROVIDER` | `dns_provider` | `local` | DNS provider |

## Security and Trust

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--require-tee` | `SP_REQUIRE_TEE` | `require_tee_attestation` | `false` | Require TEE for Tier 1 |
| `--tee-platform <name>` | `SP_TEE_PLATFORM` | `tee_platform_override` | (auto) | Force TEE platform |
| `--release-signing-pubkey <b64>` | `SP_RELEASE_SIGNING_PUBKEY` | `release_signing_pubkey` | | Release signing key |
| `--require-attestation` | `SP_REQUIRE_ATTESTATION` | `require_binary_attestation` | `false` | Require binary attestation |
| `--require-peer-confirmation` | | `require_peer_confirmation` | `false` | Quorum enrollment |

## TLS / ACME

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--tls-cert-path <path>` | `SP_TLS_CERT_PATH` | `tls_cert_path` | | Manual TLS cert |
| `--tls-key-path <path>` | `SP_TLS_KEY_PATH` | `tls_key_path` | | Manual TLS key |
| `--no-auto-tls` | `SP_NO_AUTO_TLS` | `auto_tls` | `true` | Disable ACME |
| `--acme-provider <name>` | `SP_ACME_PROVIDER` | `acme_provider` | `zerossl` | ACME CA |
| `--acme-eab-kid <kid>` | `SP_ACME_EAB_KID` | `acme_eab_kid` | | ZeroSSL EAB Key ID |
| `--acme-eab-hmac-key <key>` | `SP_ACME_EAB_HMAC_KEY` | `acme_eab_hmac_key` | | ZeroSSL EAB HMAC |

## DDNS

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--ddns-domain <dom>` | `SP_DDNS_DOMAIN` | `ddns_domain` | | Namecheap DDNS domain |
| `--ddns-password <pw>` | `SP_DDNS_PASSWORD` | `ddns_password` | | DDNS password |
| `--ddns-enabled` | `SP_DDNS_ENABLED` | `ddns_enabled` | `false` | Enable DDNS |

## JSON Config Example

```json
{
  "http_port": 9100,
  "udp_port": 51940,
  "gossip_port": 9102,
  "stun_port": 3478,
  "relay_port": 9103,
  "dns_port": 5353,
  "private_http_port": 9101,
  "region": "us-west",
  "dns_base_domain": "lemonade-nexus.io",
  "server_hostname": "ns1",
  "auto_tls": true,
  "acme_provider": "zerossl",
  "log_level": "info",
  "seed_peers": ["185.x.x.x:9102"]
}
```

Save as `lemonade-nexus.json` in the working directory.
