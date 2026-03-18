# Getting Started

## Prerequisites

- Linux server (Ubuntu 22.04+ or Debian 12+) with a public IP
- Open ports: 9100/tcp, 51940/udp, 51941/udp, 9102/udp, 3478/udp, 53/udp
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
sudo cp build/projects/LemonadeNexus/lemonade-nexus /usr/local/bin/
sudo mkdir -p /var/lib/lemonade-nexus
```

## Step 3: Configure Firewall

```bash
# iptables
sudo iptables -A INPUT -p tcp --dport 9100 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 51940 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 51941 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 9102 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 3478 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 53 -j ACCEPT
```

If using NAT (port 53 → 5353):
```bash
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-port 5353
```

## Step 4: Start the Server

```bash
cd /var/lib/lemonade-nexus
lemonade-nexus --dns-port 5353
```

The server will:
- Generate an Ed25519 identity keypair
- Auto-detect its region (e.g. `us-west`)
- Allocate tunnel IP `10.64.0.1`
- Allocate backbone IP from `172.16.0.0/22`
- Obtain a TLS certificate via ACME (ZeroSSL)
- Claim NS slot `ns1`
- Register SEIP DNS records
- Start all services

## Step 5: Connect a macOS Client

1. Build and install the macOS app (see [Building](../wiki/Building.md))
2. Launch "Lemonade Nexus" from /Applications
3. The app auto-discovers the server via DNS
4. Sign in with username + password (creates your identity)
5. Click "Connect" on the tunnel tab
6. Verify: `ping 10.64.0.1` — should respond in ~30-40ms

## Step 6: Add a Second Server (Optional)

```bash
lemonade-nexus --seed-peer <first-server-ip>:9102 --region eu-west --dns-port 5353
```

The new server will join the mesh, sync state via gossip, allocate its own IPs, and start serving clients in its region.

## Step 7: Verify

```bash
# Check server health
curl -k https://<server-ip>:9100/api/health

# Check DNS discovery
dig @<server-ip> -p 53 us-west.seip.lemonade-nexus.io A

# Check SEIP records
dig @<server-ip> -p 53 _config.server-0edf40003dfe0f7a.us-west.seip.lemonade-nexus.io TXT
```

## Systemd Service (Recommended)

```ini
[Unit]
Description=Lemonade-Nexus Mesh VPN Server
After=network-online.target

[Service]
Type=simple
WorkingDirectory=/var/lib/lemonade-nexus
ExecStart=/usr/local/bin/lemonade-nexus --dns-port 5353
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now lemonade-nexus
```
