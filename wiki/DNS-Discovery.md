# DNS Discovery

## Table of Contents
- [Subdomain Hierarchy](#subdomain-hierarchy)
- [SEIP — Server Endpoint IP](#seip--server-endpoint-ip)
- [EP — Client Endpoints](#ep--client-endpoints)
- [NS Bootstrap](#ns-bootstrap)
- [Client Discovery Flow](#client-discovery-flow)
- [Config TXT Format](#config-txt-format)
- [Region Codes](#region-codes)

## Subdomain Hierarchy

All DNS records are served by our authoritative DNS (port 5353, NAT from 53) and gossip-synced across all servers.

### SEIP — Server Endpoint IP

```
<id>.<region>.seip.lemonade-nexus.io              A   → public IP
_config.<id>.<region>.seip.lemonade-nexus.io      TXT → ports + region + load
private.<id>.<region>.seip.lemonade-nexus.io      A   → tunnel IP (10.64.0.x)
backend.<id>.<region>.seip.lemonade-nexus.io      A   → backbone IP (172.16.0.x)
```

**Example:**
```
server-0edf40003dfe0f7a.us-west.seip.lemonade-nexus.io       → 67.204.56.242
private.server-0edf40003dfe0f7a.us-west.seip.lemonade-nexus.io → 10.64.0.1
backend.server-0edf40003dfe0f7a.us-west.seip.lemonade-nexus.io → 172.16.0.66
```

### EP — Client Endpoints

```
private.<node_id>.ep.lemonade-nexus.io    A → client tunnel IP
```

**Example:**
```
private.09ba6947c069fe09.ep.lemonade-nexus.io → 10.64.0.10
```

Registered by the server when a client joins via `/api/join`.

## NS Bootstrap

The first 9 servers claim `ns1` through `ns9` via democratic gossip:

```
ns1.lemonade-nexus.io → 67.204.56.242  (us-west)
ns2.lemonade-nexus.io → 185.x.x.x     (eu-west)
ns3.lemonade-nexus.io → 103.x.x.x     (ap-south)
...
ns9.lemonade-nexus.io → x.x.x.x
```

- **Claiming:** First-come-first-served with LWW timestamp tiebreak
- **Conflict:** If two servers claim the same slot, higher pubkey wins
- **Gossip message:** `NsSlotClaim` (0x14)
- **Persistence:** Claims survive server restarts

These NS records are set at the registrar (Namecheap) and cached globally by recursive resolvers.

## Client Discovery Flow

```
1. Determine own region
   └─ ip-api.com geo lookup → nearest cloud region code
   └─ Fallback: system locale

2. Bootstrap DNS
   └─ getaddrinfo("lemonade-nexus.io") → NS records
   └─ Find ns1-ns9 with glue A records

3. Query regional servers
   └─ A query: <our-region>.seip.lemonade-nexus.io
   └─ Returns IPs of all servers in that region

4. Get config for each server
   └─ TXT query: _config.<id>.<region>.seip.lemonade-nexus.io
   └─ Parse: ports, region, load, hostname

5. Health probe + latency
   └─ HTTPS GET /api/health on each server
   └─ Measure round-trip time

6. Score and sort
   └─ score = latency_ms + (load × 10)
   └─ Pick lowest score

7. Region fallback
   └─ If no servers in own region → try adjacent regions
   └─ Order by geographic distance (haversine)
```

## Config TXT Format

```
v=sp1 http=9100 udp=51940 gossip=9102 stun=3478 relay=9103 dns=5353 private_http=9101 region=us-west load=5 host=ns1.srv.lemonade-nexus.io
```

| Field | Description |
|-------|-------------|
| `v=sp1` | Protocol version |
| `http=` | Public HTTPS API port |
| `udp=` | WireGuard port |
| `gossip=` | Gossip protocol port |
| `stun=` | STUN port |
| `relay=` | Relay port |
| `dns=` | Authoritative DNS port |
| `private_http=` | Private HTTPS API port (over WG tunnel) |
| `region=` | Server's cloud region code |
| `load=` | Connected client count |
| `host=` | Server's TLS certificate FQDN |

## Region Codes

| Code | Location |
|------|----------|
| `us-east` | US East (Virginia) |
| `us-west` | US West (California) |
| `us-central` | US Central (Iowa) |
| `ca-central` | Canada (Montreal) |
| `eu-west` | Europe West (Ireland) |
| `eu-central` | Europe Central (Frankfurt) |
| `eu-north` | Europe North (Stockholm) |
| `ap-south` | Asia Pacific South (Mumbai) |
| `ap-southeast` | Asia Pacific SE (Singapore) |
| `ap-northeast` | Asia Pacific NE (Tokyo) |
| `ap-east` | Asia Pacific East (Hong Kong) |
| `sa-east` | South America (Sao Paulo) |
| `af-south` | Africa South (Cape Town) |
| `me-south` | Middle East (Bahrain) |
| `oc-south` | Oceania (Sydney) |
