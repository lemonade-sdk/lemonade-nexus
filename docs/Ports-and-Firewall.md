---
layout: default
title: Ports and Firewall
---

# Ports and Firewall

## Table of Contents
- [Port Reference](#port-reference)
- [Packet Order for DNS NAT](#packet-order-for-dns-nat)
- [iptables Rules](#iptables-rules)
- [UFW Rules](#ufw-rules)
- [nftables (Packaged DNS NAT)](#nftables-packaged-dns-nat)
- [MikroTik Rules](#mikrotik-rules)

## Port Reference

| Port | Protocol | Direction | Source | Service |
|------|----------|-----------|--------|---------|
| **9100** | TCP | Inbound | Any | Public HTTPS API (discovery, auth, join, onboarding) |
| **51940** | UDP | Inbound | Any | Mesh transport **and hole punching** (shared) |
| **9102** | UDP | Inbound | Mesh servers | Gossip and security protocol (signed envelopes) |
| **3478** | UDP | Inbound | Peers | STUN (NAT discovery) |
| **9103** | UDP | Inbound | Peers | Relay (forwarded mesh traffic) |
| **9101** | TCP | Virtual | Mesh only | Private API — see below |
| **5335** | UDP + TCP | Inbound | Per policy | Local authoritative DNS listener |
| **53** | UDP + TCP | Inbound | Per policy | Public authoritative DNS (NAT-mapped to `5335` on DNS-serving nodes only) |

Notes:

- **Hole punching shares `51940`.** There is no separate hole-punch port;
  an older `51941` rule is not required and does nothing on the current
  server.
- **`9101` needs no inbound firewall rule.** The private API listens on
  loopback, and the userspace netstack forwards virtual TCP connections from
  the mesh addresses (client tunnel IP and server backbone IP) to it. It is
  reachable only from the mesh. In the rare configuration where no tunnel
  address exists, the server logs a security warning and registers the
  private routes on the public listener: route authentication still applies,
  but network isolation does not.
- **`53` is only for nodes that serve public authoritative DNS.** Map both
  UDP and TCP; a UDP-only authoritative server fails truncated responses.
  Do not expose public DNS from a node that does not serve it.
- `9100/tcp` and `51940/udp` must accept any source — clients connect from
  unknown IPs. Gossip (`9102`), STUN (`3478`), and relay (`9103`) can be
  restricted to known mesh server IPs.
- Mapping port `53` to `5335` does not replace the rest of your firewall
  policy.

## Packet Order for DNS NAT

A destination-NAT redirect (`53 → 5335`) is applied in the prerouting phase,
**before** the packet is evaluated by the host's input filter chain. After
the redirect, the packet's destination port is `5335`. Therefore:

- The input chain must accept **`5335`** (the port the daemon actually
  binds), not `53`.
- Nothing listens on local `53`, so accepting it in the input chain protects
  nothing.
- Scope the redirect to the external interface. Without that, the host's own
  stub resolver (systemd-resolved on `127.0.0.53:53`) is captured and the
  machine loses its own DNS.
- Locally generated queries do not traverse the prerouting redirect at all;
  test public `53` from another host, and on the server query `5335`
  directly.

## iptables Rules

```bash
# Required on every server
iptables -A INPUT -p tcp --dport 9100 -j ACCEPT   # Public HTTPS API
iptables -A INPUT -p udp --dport 51940 -j ACCEPT  # Mesh + hole punching
iptables -A INPUT -p udp --dport 9102 -j ACCEPT   # Gossip + security
iptables -A INPUT -p udp --dport 3478 -j ACCEPT   # STUN
# Optional
iptables -A INPUT -p udp --dport 9103 -j ACCEPT   # Relay

# DNS-serving nodes only: accept the local listener directly ...
iptables -A INPUT -p udp --dport 5335 -j ACCEPT
iptables -A INPUT -p tcp --dport 5335 -j ACCEPT
# ... and redirect public 53 to it, on the external interface only
# (replace <wan-if> with your external interface, e.g. eth0)
iptables -t nat -A PREROUTING -i <wan-if> -p udp --dport 53 -j REDIRECT --to-port 5335
iptables -t nat -A PREROUTING -i <wan-if> -p tcp --dport 53 -j REDIRECT --to-port 5335
```

On a packaged install, `nexus-bootstrap --install-dns-nat` does the DNS
mapping in its own nftables table (`inet nexus-dns`) behind
`nexus-dns-nat.service`, so it can be inspected with
`nft list table inet nexus-dns` and removed with
`systemctl disable --now nexus-dns-nat.service` without disturbing other
rules.

## UFW Rules

```bash
ufw allow 9100/tcp   # Public HTTPS API
ufw allow 51940/udp  # Mesh + hole punching
ufw allow 9102/udp   # Gossip + security
ufw allow 3478/udp   # STUN
ufw allow 9103/udp   # Relay (optional)

# DNS-serving nodes only
ufw allow 5335/udp   # Local DNS listener
ufw allow 5335/tcp
# Public 53 mapping: UFW does not express interface-scoped prerouting
# redirects cleanly; use the packaged nftables unit or the iptables rules
# above for the 53 -> 5335 redirect.
```

## nftables (Packaged DNS NAT)

`--install-dns-nat` installs `/usr/lib/lemonade-nexus/nexus-dns-nat.nft`,
driven by `/etc/lemonade-nexus/nexus-dns-nat.conf` (WAN interface, ports),
loaded by `nexus-dns-nat.service`. The table holds exactly two redirects
(UDP and TCP `53 → 5335`) in a purpose-built prerouting chain, so it cannot
affect any other host traffic. The load is a single transaction: both rules
install or nothing changes.

Verify:

```bash
nft list table inet nexus-dns
systemctl status nexus-dns-nat.service
```

## MikroTik Rules

Replace `<public-ip>` and `<server-ip>` with your addresses.

**Filter rules:**
```routeros
/ip firewall filter add chain=forward action=accept protocol=tcp dst-address=<server-ip> dst-port=9100 comment="NEXUS-HTTPS-API"
/ip firewall filter add chain=forward action=accept protocol=udp dst-address=<server-ip> dst-port=51940 comment="NEXUS-MESH+HOLEPUNCH"
/ip firewall filter add chain=forward action=accept protocol=udp dst-address=<server-ip> dst-port=9102 comment="NEXUS-GOSSIP+SECURITY"
/ip firewall filter add chain=forward action=accept protocol=udp dst-address=<server-ip> dst-port=3478 comment="NEXUS-STUN"
/ip firewall filter add chain=forward action=accept protocol=udp dst-address=<server-ip> dst-port=9103 comment="NEXUS-RELAY"
/ip firewall filter add chain=forward action=accept protocol=udp dst-address=<server-ip> dst-port=5335 comment="NEXUS-DNS"
/ip firewall filter add chain=forward action=accept protocol=tcp dst-address=<server-ip> dst-port=5335 comment="NEXUS-DNS-TCP"
```

**NAT rules (DNS-serving nodes only):**
```routeros
/ip firewall nat add chain=dstnat action=dst-nat protocol=udp dst-address=<public-ip> dst-port=53 to-addresses=<server-ip> to-ports=5335 comment="NEXUS-DNS-NAT"
/ip firewall nat add chain=dstnat action=dst-nat protocol=tcp dst-address=<public-ip> dst-port=53 to-addresses=<server-ip> to-ports=5335 comment="NEXUS-DNS-NAT-TCP"
```
