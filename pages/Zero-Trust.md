# Zero-Trust Architecture

## What Zero-Trust Means Here

In Lemonade-Nexus, **nothing is trusted by default**. Every server must continuously prove its identity, integrity, and authorization. There is no privileged "root server" — all servers earn trust through cryptographic verification.

## Trust Tiers

```
┌──────────────────────────────────────────────────┐
│                   TIER 1                         │
│  Full Mesh Participant                           │
│                                                  │
│  ✓ Valid server certificate (Ed25519 signed)     │
│  ✓ TEE hardware attestation                      │
│  ✓ Binary hash in signed release manifests       │
│  ✓ 90% uptime over 100+ health checks           │
│                                                  │
│  Can: hold Shamir key shares, vote on governance,│
│       vote on enrollment, serve authoritative DNS│
└──────────────────────────────────────────────────┘
                      ↑
            TEE Challenge-Response
            + Binary Attestation
            + Sustained Uptime
                      ↑
┌──────────────────────────────────────────────────┐
│                   TIER 2                         │
│  Certificate-Only Participant                    │
│                                                  │
│  ✓ Valid server certificate                      │
│  ✗ No TEE attestation                            │
│                                                  │
│  Can: serve clients, participate in gossip,      │
│       hole punch, basic mesh operations          │
└──────────────────────────────────────────────────┘
                      ↑
            Certificate Verification
                      ↑
┌──────────────────────────────────────────────────┐
│                 UNTRUSTED                        │
│  Unknown / Revoked Server                        │
│                                                  │
│  Can: nothing (all requests rejected)            │
└──────────────────────────────────────────────────┘
```

## Attestation Tokens

Every sensitive gossip message includes an `AttestationToken`:

```json
{
  "server_pubkey": "base64...",
  "platform": "sgx",
  "attestation_hash": "hex...",
  "binary_hash": "hex...",
  "timestamp": 1710720000,
  "attestation_timestamp": 1710719000,
  "signature": "base64..."
}
```

Receiving servers verify:
1. Signature is valid (Ed25519)
2. Binary hash is in approved manifests
3. Attestation is fresh (< validity window)
4. Platform matches expectations

## TEE Challenge-Response

When a new server joins, existing servers challenge it:

```
Server A                              Server B (new)
   │                                      │
   │──── TeeChallenge (random nonce) ────>│
   │                                      │
   │                                      │ Generate attestation report
   │                                      │ with nonce embedded
   │                                      │
   │<──── TeeResponse (quote + report) ───│
   │                                      │
   │ Verify quote against TEE platform    │
   │ Check binary hash                    │
   │ Check attestation freshness          │
   │                                      │
   │ If valid: promote to Tier 1          │
   │ If invalid: stay Tier 2             │
```

## Trust Demotion

Trust is not permanent. Servers are continuously monitored:

- **Failed verification:** 1 failure = warning, 3 consecutive = demotion
- **Tier 1 → Tier 2:** Lost TEE attestation or binary mismatch
- **Tier 2 → Untrusted:** Certificate expired or revoked
- **Immediate untrust:** Revocation list (persisted to `data/identity/revoked_servers.json`)

## Democratic Governance

Protocol parameters are changed via governance proposals, not by any single server:

```
Server A: "I propose changing rate_limit_rpm from 120 to 200"
    │
    ├── GovernanceProposal broadcast via gossip
    │
    ├── Server B: GovernanceVote (approve)
    ├── Server C: GovernanceVote (approve)
    ├── Server D: GovernanceVote (reject)
    │
    └── Quorum reached (>50% Tier 1 servers approve)
        → Parameter change applied across all servers
```

## Gossip Message Trust Enforcement

All sensitive gossip handlers check trust before processing:

```cpp
if (!verify_message_trust(sender_pubkey, payload)) {
    // Reject: no valid attestation token, or sender is Untrusted
    return;
}
```

Sensitive operations requiring trust:
- Digest exchange (tree state sync)
- Delta request/response (tree mutations)
- Peer exchange (peer list sharing)
- Backbone IPAM sync
- NS slot claiming
- Shamir share distribution
- Governance proposals and votes
