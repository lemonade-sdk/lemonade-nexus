---
layout: default
title: Ports and Firewall
---

# Ports and Firewall

## Table of Contents
- [Port Reference](#port-reference)
- [iptables Rules](#iptables-rules)
- [MikroTik Rules](#mikrotik-rules)
- [UFW Rules](#ufw-rules)

## Port Reference

| Port | Protocol | Direction | Source | Service |
|------|----------|-----------|--------|---------|
| **9100** | TCP | Inbound | Any | Public HTTPS API (bootstrap, auth, join, discovery) |
| **51940** | UDP | Inbound | Any | WireGuard encrypted tunnel |
| **51941** | UDP | Inbound | Any | UDP hole punch (NAT traversal signaling) |
| **9102** | UDP | Inbound | Mesh servers | Gossip protocol (state sync, IPAM, NS slots) |
| **3478** | UDP | Inbound | Mesh servers | STUN (NAT traversal, external IP discovery) |
| **9103** | UDP | Inbound | Mesh servers | Relay (forwarded WireGuard traffic) |
| **53** | UDP | Inbound | Any | Authoritative DNS (NAT to 5353 on server) |
| **9101** | TCP | N/A | WG tunnel only | Private HTTPS API (not externally exposed) |

> **9100/tcp**, **51940/udp**, and **51941/udp** must allow ANY source — clients connect from unknown IPs. Gossip and STUN can be restricted to known mesh server IPs.

> **9101/tcp** does NOT need a firewall rule — it binds to the WireGuard tunnel IP (10.64.x.x) and is only reachable over the encrypted tunnel.

## iptables Rules

```bash
# Required on every server
iptables -A INPUT -p tcp --dport 9100 -j ACCEPT   # Public HTTPS API
iptables -A INPUT -p udp --dport 51940 -j ACCEPT  # WireGuard tunnel
iptables -A INPUT -p udp --dport 51941 -j ACCEPT  # Hole punch
iptables -A INPUT -p udp --dport 9102 -j ACCEPT   # Gossip
iptables -A INPUT -p udp --dport 3478 -j ACCEPT   # STUN

# Optional
iptables -A INPUT -p udp --dport 9103 -j ACCEPT   # Relay
iptables -A INPUT -p udp --dport 53 -j ACCEPT     # DNS
```

## MikroTik Rules

**Filter rules** (internal server IP: 10.10.12.16):
```routeros
/ip firewall filter add chain=forward action=accept protocol=tcp dst-address=10.10.12.16 dst-port=9100 comment="FRS-LMND-NXS-HTTPS-API"
/ip firewall filter add chain=forward action=accept protocol=udp dst-address=10.10.12.16 dst-port=51940 comment="FRS-LMND-NXS-WIREGUARD"
/ip firewall filter add chain=forward action=accept protocol=udp dst-address=10.10.12.16 dst-port=51941 comment="FRS-LMND-NXS-HOLEPUNCH"
/ip firewall filter add chain=forward action=accept protocol=udp dst-address=10.10.12.16 dst-port=9102 comment="FRS-LMND-NXS-GOSSIP"
/ip firewall filter add chain=forward action=accept protocol=udp dst-address=10.10.12.16 dst-port=3478 comment="FRS-LMND-NXS-STUN"
/ip firewall filter add chain=forward action=accept protocol=udp dst-address=10.10.12.16 dst-port=9103 comment="FRS-LMND-NXS-RELAY"
/ip firewall filter add chain=forward action=accept protocol=udp dst-address=10.10.12.16 dst-port=5353 comment="FRS-LMND-NXS-DNS"
```

**NAT rules** (public IP: 67.204.56.242 → internal: 10.10.12.16):
```routeros
/ip firewall nat add chain=dstnat action=dst-nat protocol=tcp dst-address=67.204.56.242 dst-port=9100 to-addresses=10.10.12.16 to-ports=9100 comment="FRS-LMND-NXS-HTTPS-API"
/ip firewall nat add chain=dstnat action=dst-nat protocol=udp dst-address=67.204.56.242 dst-port=51940 to-addresses=10.10.12.16 to-ports=51940 comment="FRS-LMND-NXS-WIREGUARD"
/ip firewall nat add chain=dstnat action=dst-nat protocol=udp dst-address=67.204.56.242 dst-port=51941 to-addresses=10.10.12.16 to-ports=51941 comment="FRS-LMND-NXS-HOLEPUNCH"
/ip firewall nat add chain=dstnat action=dst-nat protocol=udp dst-address=67.204.56.242 dst-port=9102 to-addresses=10.10.12.16 to-ports=9102 comment="FRS-LMND-NXS-GOSSIP"
/ip firewall nat add chain=dstnat action=dst-nat protocol=udp dst-address=67.204.56.242 dst-port=3478 to-addresses=10.10.12.16 to-ports=3478 comment="FRS-LMND-NXS-STUN"
/ip firewall nat add chain=dstnat action=dst-nat protocol=udp dst-address=67.204.56.242 dst-port=9103 to-addresses=10.10.12.16 to-ports=9103 comment="FRS-LMND-NXS-RELAY"
/ip firewall nat add chain=dstnat action=dst-nat protocol=udp dst-address=67.204.56.242 dst-port=53 to-addresses=10.10.12.16 to-ports=5353 comment="FRS-LMND-NXS-DNS-NAT"
```

## UFW Rules

```bash
ufw allow 9100/tcp   # Public HTTPS API
ufw allow 51940/udp  # WireGuard
ufw allow 51941/udp  # Hole punch
ufw allow 9102/udp   # Gossip
ufw allow 3478/udp   # STUN
ufw allow 9103/udp   # Relay (optional)
ufw allow 53/udp     # DNS (optional)
```
