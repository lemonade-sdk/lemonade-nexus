---
layout: default
title: Getting Started
---

# Getting Started

## Prerequisites

- Linux server (Ubuntu 22.04+ or Debian 12+) with a public IP
- Open ports: 9100/tcp, 51940/udp, 51941/udp, 9102/udp, 3478/udp, 53/udp and 53/tcp
- C++20 compiler, CMake 3.25+, Ninja, Rust toolchain

## Step 1: Build

```bash
git clone https://github.com/lemonade-sdk/lemonade-nexus.git
cd lemonade-nexus
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

## Step 2: Install

```bash
cpack --config build/CPackConfig.cmake -G DEB -B build/packages
sudo dpkg -i build/packages/lemonade-nexus-*.deb
```

The package installs `/usr/bin/lemonade-nexus` and `/usr/bin/nexus-bootstrap`
and enables the service without starting it. Bootstrap requires Python 3,
which the package declares as a dependency.

## Step 3: Configure Firewall

```bash
# iptables
sudo iptables -A INPUT -p tcp --dport 9100 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 51940 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 51941 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 9102 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 3478 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 53 -j ACCEPT
```

The server binds DNS on **5335** as an unprivileged user and is never granted
`CAP_NET_BIND_SERVICE`, so public 53 has to be mapped to it — on **both**
transports. An authoritative server that answers only UDP fails every query
whose response is truncated.

Genesis needs public authoritative DNS during bootstrap, including delegation
and glue pointing at this server, so ACME DNS-01 can succeed before Tier 1.

On a packaged install this is one flag, and it installs its own nftables table
(`inet nexus-dns`) plus a `nexus-dns-nat.service` unit, touching no other
firewall policy:

```bash
sudo nexus-bootstrap --release-signing-pubkey <KEY> --install-dns-nat
```

The equivalent by hand:
```bash
sudo iptables -t nat -A PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-port 5335
sudo iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 53 -j REDIRECT --to-port 5335
```
Scope it to the external interface: without `-i`, the redirect also captures
systemd-resolved's stub on `127.0.0.53:53` and breaks the host's own resolver.

## Step 4: Start the Server

```bash
sudo systemctl start lemonade-nexus
journalctl -u lemonade-nexus
```

`nexus-bootstrap` initializes the keys and writes
`/var/lib/lemonade-nexus/lemonade-nexus.json`. The configuration is root-owned
(mode 0640, group `lemonade-nexus`), and its parent is root-owned (0750), so the
daemon can neither edit nor replace its trust anchors. Runtime state remains
writable under `/var/lib/lemonade-nexus/data` (0700, owned by the service user).
Use `sudoedit` for operator configuration changes. Keep `root_pubkey`,
`genesis_pubkey`, and `release_signing_pubkey` in this protected file.

The server obtains its TLS certificate through ACME. Public and private API
listeners remain withheld until their TLS certificates are available.

## Step 5: Connect a macOS Client

1. Build and install the macOS app (see [Building](../wiki/Building.md))
2. Launch "Lemonade Nexus" from /Applications
3. The app auto-discovers the server via DNS
4. Sign in with username + password (creates your identity)
5. Click "Connect" on the tunnel tab
6. Verify: `ping 10.64.0.1` — should respond in ~30-40ms

## Step 6: Add a Second Server (Optional)

Prepare an operator-reviewed `node-config.json` with the expected network's
`root_pubkey`, `genesis_pubkey`, and `release_signing_pubkey`, plus
`data_root` set to `/var/lib/lemonade-nexus/data`. Install it as protected
configuration, then use a separate writable copy for the one-shot onboarding
client's seed-peer write-back:

```bash
sudo install -o root -g lemonade-nexus -m 0640 node-config.json /var/lib/lemonade-nexus/lemonade-nexus.json
sudo install -o lemonade-nexus -g lemonade-nexus -m 0600 node-config.json /var/lib/lemonade-nexus/data/onboarding.json
sudo runuser -u lemonade-nexus -- /usr/bin/lemonade-nexus \
  --config /var/lib/lemonade-nexus/data/onboarding.json \
  --onboard-server <existing-server-fqdn>:9100 --root-pubkey <EXPECTED_ROOT_HEX>
```

After admission, inspect `seed_peers` in the staging file and add those peers to
the protected config with `sudoedit`. Retain the operator-pinned trust anchors;
the staging file is runtime-writable. The certificate and identity are already
stored under `data_root`. Start the packaged service after this step.

## Step 7: Verify

```bash
# Check server health
curl -k https://<server-ip>:9100/api/health

# Check DNS discovery
dig @<server-ip> -p 53 us-west.seip.lemonade-nexus.io A

# Check SEIP records
dig @<server-ip> -p 53 _config.server-0edf40003dfe0f7a.us-west.seip.lemonade-nexus.io TXT
```

## Systemd Service

Use the packaged `lemonade-nexus.service`. It runs `/usr/bin/lemonade-nexus`
with no arguments from `/var/lib/lemonade-nexus`, reads the protected config,
and grants write access only to the `data` subdirectory. Its capability set is
empty; public UDP+TCP 53 reaches local 5335 through the DNS NAT unit.
