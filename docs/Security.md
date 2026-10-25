---
layout: default
title: Security
---

# Security

This is the primary security overview for Lemonade-Nexus. It explains the
roles, how authority is established and renewed, what the protocol protects
against, and what it does not yet protect.

- [Identity and Cryptography](#identity-and-cryptography)
- [Server Roles](#server-roles)
- [Epoch Authority](#epoch-authority)
- [Genesis and Trust Continuity](#genesis-and-trust-continuity)
- [Compiled Rules](#compiled-rules)
- [Attestation and Key Boundaries](#attestation-and-key-boundaries)
- [Threat Assumptions](#threat-assumptions)
- [Transport and Message Security](#transport-and-message-security)
- [Permission Tree Administration](#permission-tree-administration)
- [Application Authority Gaps](#application-authority-gaps)
- [Current Limitations](#current-limitations)
- [Retired Mechanisms](#retired-mechanisms)

## Identity and Cryptography

| Primitive | Algorithm | Purpose |
|-----------|-----------|---------|
| Identity keys | Ed25519 | Server and client identity, signing |
| Mesh keys | X25519 (Curve25519) | Tunnel encryption (derived from the Ed25519 identity) |
| Consensus votes | Ed25519 (per-epoch vote keys) | Chained HotStuff voting |
| Authority signatures | FROST(Ed25519, SHA-512) | Threshold signing by the epoch committee |
| Symmetric AEAD | XChaCha20-Poly1305-IETF | Encrypted objects at rest and in transfer |
| Key derivation | HKDF-SHA256 | Derive encryption keys from shared secrets |
| Hashing | SHA-256 / SHA-512 | Digests, canonical encoding, challenge binding |
| TLS | OpenSSL | HTTPS for the public and private APIs |

Every encrypted object under Nexus control uses one construction:

```text
EncryptedBlob {
    version      // 1
    nonce        // exactly 24 bytes, random per encryption
    ciphertext   // includes the 16-byte Poly1305 tag
}
```

Version 1 is always XChaCha20-Poly1305-IETF. The reader checks the version and
the exact nonce length before any bytes reach the AEAD; unknown versions fail
closed. Objects carrying this format include the wrapped node identity
(`identity/keypair.enc`), ACL values, epoch vote keys, DDNS credentials, and
the issued-certificate bundle.

Authentication for clients uses Ed25519 challenge-response (primary) and
WebAuthn passkeys (backup). Password authentication is a deprecated server
stub that always fails.

## Server Roles

| Role | What establishes it | Capabilities |
|---|---|---|
| **Tier 2** | A valid network-bound server certificate and authenticated mesh participation | A pure proxy of end-to-end encrypted data and connections: relay, STUN, discovery DNS, and the security transport. Holds no permission tree, serves no tree route or client session, and forwards no packet between dataplane peers. No Tier 1 authority share. |
| **Pending member** | Selection in a finalized next-epoch plan | State synchronization and readiness preparation. No active Tier 1 authority. |
| **Tier 1** | Verified platform evidence and mesh observations establish eligibility; the protocol's finalized eligibility, plan, readiness, and handoff establish the role | HotStuff consensus, epoch transitions, dealerless DKG participation, threshold authority signing. Holds and serves the permission tree and client sessions. |

Tier 1 is an **epoch-scoped** role. A transport connection or a valid
certificate never grants it, and a pending candidate holds preparation rights
only — proving participation grants no authority before the finalized
handoff.

Clients use the mesh under their application permissions. They do not become
members of the server authority committee.

### The tree lives on Tier 1 only

The permission tree follows finalized epoch membership, never configuration
or a peer's word (`Tree/TreeRole.hpp`):

- **A current Tier 1 member** loads the tree and serves the tree routes,
  client sessions (`/api/auth*`, `/api/join`), and endpoint forwarding.
- **Any other server** refuses every tree route with `421` and the body
  `{"error":"this server does not serve the tree"}`: no redirect, no other
  server named, and no tree data (`Api/TreeRouteGate.hpp`). It runs no tree
  replication, no record transfer pool, and no tree log, takes no replicated
  tree entry, and keeps no tree file.
- **A server that leaves Tier 1** closes the gate, stops those services, and
  deletes its tree copy in the tick in which finalized state shows that its
  last epoch ended. Each file under `data/tree/` is overwritten with zeros,
  flushed, and removed. This is best effort: a journaling or copy-on-write
  file system, snapshots, or SSD remapping can keep older blocks.
- **A server whose membership is not known** (before Epoch 1 activates, or
  before its persisted state verifies) serves no tree and deletes nothing.
  Unknown is not evidence that it left Tier 1.

A server that enters Tier 1 gets the tree through Tier 1 replication in ops
mode. The default direct-write mode has no tree replication: a new member
starts from an empty tree with the application root from `root_pubkey`.

Clients send every tree read and write directly to a Tier 1 server. The SDK
verifies the membership from its pinned Genesis key and accepts a server only
after it signs an endpoint proof for the host and port the client reached
(see [Client SDK](Client-SDK#tier-1-servers)). A server never vouches for a
session it did not issue.

A client with no stored Genesis key can discover it on first connect from
`GET /api/onboard/info`. The SDK pins the key only when at least 3 hosts in the
network DNS domain report the same key and network id over verified HTTPS.
This is trust on first use: it rests on domain ownership and host agreement,
not on a signature. After the key is pinned, discovery never replaces it.

### Relay tickets

A Tier 1 server issues a relay ticket (`POST /api/relay/ticket`) only for the
caller's own session. It signs the ticket with its node identity key, the key
the finalized membership names, under `lemonade-nexus/relay-ticket:v2`. The
ticket names the network, the issuer's epoch, the session, the relay, a fresh
nonce, and an expiry at most 120 seconds after issue. Any relay accepts it
only when the issuer is a member of the Tier 1 membership the relay verified
from the authority chain, the network and epoch match, the signature
verifies, and it has not expired (`Relay/RelayTicketAuth.hpp`). Each issuer
and nonce allocates one session; the relay keeps that record until the ticket
expires. The relay needs no tree and no session state, so a Tier 2 relay
carries ciphertext for any session a Tier 1 server authorized. A ticket from
the previous epoch is refused after an epoch change and must be requested
again.

Endpoints, the devices that join a group, come in two roles. Neither holds any
server or authority role:

| Role | What establishes it | Capabilities |
|---|---|---|
| **Tier 3** | An endpoint that joins with `ln_set_inference_node(client, 1)` (the Lemonade server, for example). The server records `is_inference` when it creates the endpoint, and the routing identifier starts with `infer-`. | Serves inference to the group members its permissions allow. |
| **Tier 4** | Any other endpoint (the default). Its routing identifier starts with `client-`. | Uses the group's inference nodes and other services under its permissions. |

Which members may reach a Tier 3 node is decided by the permission tree, as for
any endpoint. The role is set when the endpoint is created; a device that
already joined keeps its role.

Two device permissions control reachability. `read` lets a member see a
device in the tree. `connect_private` or `connect_shared` lets a member
connect to it. The mesh peer list (`GET /api/mesh/peers/{node_id}`) and the
routing layer use the same rule: a device in the member's group is listed or
resolved only when the member holds a connect permission on that device
itself. `admin` includes both connect permissions. A grant on the group does
not count, because permissions are not inherited. Relays in the group are
listed with `read`.

A client's server peer covers the whole tunnel plane, so the server's
dataplane sees traffic that one endpoint sends to another. The server forwards
it only when the source endpoint's key may connect to the destination
endpoint: the destination is in the source's group, and the source key holds
`connect_private`, `connect_shared`, or `admin` on the destination device
itself. Only a Tier 1 server forwards between endpoints: forwarding needs
the tree, so a Tier 2 server installs a policy that forwards no packet between
dataplane peers. Endpoints that cannot reach each other directly use the relay
service, which carries only ciphertext. This is the rule the routing layer
applies. Replies return without a
grant in the other direction: a TCP segment that is not a bare SYN, and ICMP
echo replies and errors. A device that may only be reached cannot open a TCP
connection back, and a UDP reply needs a grant in its own direction. Relays
and addresses outside the tunnel plane, such as backbone servers, are not
restricted by this rule. An address in the plane that is not an endpoint or
relay in the tree is dropped. The server rebuilds the rule off the packet path
when the tree changes; a revoked grant stops forwarding within about one
second.

## Epoch Authority

After Genesis, the current committee finalizes four transitions in order at
each epoch boundary, each a pure function of finalized inputs:

```text
eligibility state  ->  NextEpochPlan  ->  CandidateReadiness  ->  EpochHandoff
```

- **Eligibility** is computed from verified platform evidence and mesh
  observations signed by current members. Observations are epoch-scoped and
  affect the *next* epoch's eligibility only.
- **The next-epoch plan** selects the target membership.
- **Candidate readiness** requires the selected candidates (including new
  members) to sync to the checkpoint, create their vote keys, and attest
  freshly under a plan-bound challenge.
- **The epoch handoff** activates the new membership. A fresh **dealerless
  FROST DKG** ceremony follows finalized readiness and establishes the new
  epoch's authority key. The finalized handoff, verified against the
  predecessor's anchor, is what makes the new members authoritative.

HotStuff (chained, lock on the two-chain, commit on the three-chain) uses
**individual Ed25519 vote signatures**. FROST supplies threshold *authority*
signatures; it is not the consensus voting mechanism. Old vote keys and old
FROST shares are discarded on epoch replacement, and the full FROST private
key is not routinely reconstructed.

Membership and rule changes apply only at the epoch boundary. An epoch can
legitimately outlive its target duration; the target is a pacing goal, not a
timer that expires authority.

## Genesis and Trust Continuity

Genesis is a temporary bootstrap authority, not a permanent root:

- The founding path requires **five qualifying founders**, agreement on the
  founding facts (signed transcript attestations from every founder), and a
  fresh Epoch 1 DKG. When more than five candidates qualify, the five lowest
  node identities found Epoch 1.
- Genesis signs the bootstrap certificate. Its unilateral **security-protocol
  authority ends when Epoch 1 activates**. There is no restart, recovery, or
  administrative path that restores it.
- Later authority verifies from the **pinned Genesis anchor** through the
  finalized epoch handoff chain. Certificates, peer announcements, local
  configuration, and attestation results cannot independently create Tier 1
  authority.

### Restored authority

Persisted anchors and epochs are **candidate data**, not authority. At
startup, a node reauthenticates the Epoch 1 base from the pinned Genesis key
(the bootstrap certificate plus its exact founder/vote-key listing) and then
verifies every sequential handoff proof before it restores authority or
membership. A recomputed record digest provides corruption detection, not
authentication.

Any surviving post-Genesis durable state consumes the one-shot Genesis
signing role before startup selects a phase, so a former Genesis node cannot
reuse its bootstrap role. A node that finds only an authentic historical
chain resumes as Tier 2 and walks the chain. Corrupt or contradictory state
fails closed.

This does **not** protect against deleting or rolling back the whole store to
a valid pre-Epoch-1 snapshot, and an authenticated historical chain does not
by itself prove it is the newest chain. See [Current
Limitations](#current-limitations).

## Compiled Rules

The deterministic rules live in
[`SecurityConstants.hpp`](https://github.com/lemonade-sdk/lemonade-nexus/blob/main/projects/LemonadeNexus/include/LemonadeNexus/Security/Policy/SecurityConstants.hpp).
They are compiled into the binary, not operator settings:

| Rule | Value |
|---|---|
| Maximum Byzantine faults | `f = floor((N - 1) / 3)` |
| Consensus quorum | `N - f` |
| Authority-signing threshold | `max(5, N - f)` |
| Genesis founding threshold | 5 qualifying founders |
| Active Tier 1 bounds | minimum 5, preferred minimum 7, maximum 31, plus a reserve of 2 |
| Target epoch duration | 3600 s (pacing goal, not an authority expiry) |
| Re-attestation interval | 900 s |
| Final attestation max age | 300 s |

The **target Tier 1 population table** (for example 5 admitted servers target
5 active members; 100 admitted target 13) is a selection goal. It is not
available address capacity, not a quorum, and not a measured scalability
claim.

## Attestation and Key Boundaries

See [Attestation](Attestation) for the provider matrix and the evidence path.
The boundary that matters here:

- The implemented provider verifies the **AMD SEV-SNP/HCL/vTPM** evidence
  chain plus IMA runtime measurements, bound to a fresh challenge, the node
  identity, the epoch, and the network.
- `nexus-attestd` runs under a separate service identity with scoped TPM/IMA
  access and filesystem restrictions. It collects evidence without holding
  the server's Nexus identity key, consensus vote key, or FROST share. It
  seals and unseals a PCR-bound key for the server's boot set but never
  receives the key material that key protects. The server itself has no TPM
  access.
- Confidential computing protects against a **hostile host or hypervisor**.
  It is not a claim that privileged root inside the guest cannot inspect
  guest processes.

## Threat Assumptions

What the protocol defends:

- Forging or replaying consensus votes or authority signatures (quorum plus
  FROST threshold, canonical digests, domain separation, epoch and network
  binding).
- A compromised or partitioned minority of the committee (`f` Byzantine
  faults).
- A hostile hypervisor substituting the guest image or forging vTPM quotes
  outside the confidential boundary (SNP launch measurement plus the
  paravisor-bound vTPM, IMA runtime measurements).
- Substituting the running binary (signed release manifests verified against
  the pinned release-signing key).

What it does not defend:

- Privileged root **inside** the guest.
- Rolling back or deleting the whole durable security store to an authentic
  older snapshot (see Current Limitations).
- A network that never reaches Tier 1. With the shipped profile no node
  qualifies, so a deployment without a qualifying platform has no authority
  committee at all.

## Transport and Message Security

- **Public API:** HTTPS only. Listeners are withheld until usable
  certificates exist; there is no plaintext fallback.
- **Private API:** HTTPS on virtual mesh addresses, forwarded through the
  userspace netstack to a loopback listener. Every private route is
  JWT-gated.
- **Mesh:** BoringTun (WireGuard protocol) over UDP `51940`.
- **Security protocol:** signed gossip envelopes on UDP `9102`. The envelope
  is authenticated and size-bounded before parsing, never relayed, and
  carries attestation, consensus, DKG, and epoch-announcement messages.
  Sensitive pairwise DKG payloads are additionally sealed to the recipient
  identity. Security messages are not all carried inside WireGuard.

Rate limiting is per-client (default 120 requests/minute, burst 20). Security
messages have per-peer budgets and deduplication windows compiled into the
router.

## Permission Tree Administration

Each tree node carries assignments: a management key and the permissions it
holds on that node. Permissions are not inherited, with one exception for
administration (below). A signed tree delta must pass these rules on the
server that applies it:

- **The operation permission.** `create_node` needs `add_child` on the
  parent. `update_node` and `update_assignment` need `edit_node` on the node.
  `delete_node` needs `delete_node` on the node.
- **An update keeps the node's identity.** The `id`, `parent_id`, `type`,
  management key, and endpoint identifier cannot change. A record that
  renames itself onto another node, or moves into another group, is refused.
- **Only an admin changes assignments.** The signer must hold `admin` on the
  node or on one of its ancestors. That nearest admin node is the signer's
  scope. `edit_node` alone never changes who holds what.
- **Only joined identities are granted.** Each added or changed assignment
  must name a key that is the management key of a node inside the signer's
  scope. A key that never joined, or joined a different group, is refused.
- **A create names no one else unless the signer is an admin.** The new
  node may name its creator and its own management key. Any other key needs
  an admin of the parent and the joined rule above.
- **The root is fixed.** No delta creates a second root or deletes the root.

The creator of a group holds `admin` on it, so the owner can promote a member
device by giving its key `admin` on the group.

An admin of a group also administers the group's devices without an entry on
each one: it reads a device's full assignment list and removes the device. No
caller removes the root node through the API.

Clients change assignments through `POST /api/tree/node/assignments/{id}`
with `{"pubkey", "permissions"}`. The server sets exactly that list for the
key, replacing its entry, and an empty list removes it. The same admin and
joined rules apply. An admin cannot change its own entry on the node that
grants its admin, so no admin locks itself out; another admin must do it. Groups created before this
rule gain `admin` for their owner on the owner's next join.

On load, a node file whose record names a different node is refused.

## Application Authority Gaps

Admission and several replicated application stores are **not** derived from
finalized security state. This is the boundary between what the security
protocol authorizes and what the application layer still gates on identity or
root:

- **Server admission** (certificate issuance, enrollment tokens, supersede)
  is root-gated or token-gated. It grants transport membership, not Tier 1.
- **Replicated application stores** (ACL, DNS records, backbone IPAM, NS
  slots, account group-key envelopes) sync through gossip under root-signed
  peer certificates. A Tier 2 server holds no tree, so it accepts no account
  envelope. Their
  mutation paths are audited against permission rules but are not yet
  consensus-authorized.
- **Author-signed record receipt is not authorization.** Receiving a
  signed tree record transfers it; it never by itself authorizes or applies a
  remote tree or ACL mutation.
- **Public authentication does not initialize an application-root owner.**
  Fresh-network administrative approval flows remain incomplete.

No one of these paths can touch epochs, eligibility, or authority keys.

## Current Limitations

These are implementation limits, not settings an operator can disable:

1. **Tier 1 qualification is blocked in the shipped profile.** The compiled
   attestation profile pins no launch measurement, TCB floor, IMA policy
   digest, or approved component hashes. Every attestation fails with
   `ProfileIncomplete` until a qualifying release pins those values. See
   [Attestation](Attestation).
2. **Provider support is narrower than the design.** The SVSM-vTPM and
   direct-boot providers currently refuse with `ProviderUnsupported`. SGX,
   TDX, and Secure Enclave are not implemented Tier 1 providers here.
3. **Application authority is not fully integrated.** Admission and several
   replicated application stores still use root- or identity-gated paths.
   Receiving an author-signed record does not by itself authorize remote
   tree/ACL mutation. Public authentication does not initialize an
   application-root owner.
4. **Recovery and freshness have limits.** The quorum-authorized
   incarnation-advance lifecycle is unfinished. Deleting or rolling back the
   whole store to a valid pre-Epoch-1 snapshot is not addressed, and a valid
   historical authority chain cannot in isolation prove it is the newest
   chain.
5. **IMA checkpoint/resume acceptance is not implemented.** The bounded
   evidence path must satisfy the current complete verification
   requirements.
6. **No tree without Tier 1.** Only Tier 1 members hold the tree. Before Epoch
   1 activates, and while no server qualifies for Tier 1 (item 1), no server
   serves a tree route or a client session, and no client can join.
7. **Relay allocation has no wire message.** Any relay, Tier 1 or Tier 2,
   accepts a relay ticket that a current Tier 1 member signed (see
   [Relay tickets](#relay-tickets)), but the relay protocol has no handler for
   its `Allocate` message, so a session is allocated only in process.
8. **Tree-derived DNS names are Tier 1 answers.** A nameserver that is not a
   Tier 1 member has no tree and does not answer endpoint host names.

## Retired Mechanisms

The security overhaul removed the old network-authority system. These terms
appear in older documents and in the C ABI compatibility stubs, which return
`LN_ERR_UNSUPPORTED`:

- Democratic parameter governance and governance votes
- Root key rotation on a fixed interval and Shamir secret sharing of the root
- Enrollment ballots and operator quorum knobs
- The `AttestationToken` rolling-trust layer
- The `/api/trust/*`, `/api/enrollment/status`, and `/api/governance/*`
  endpoints, and the old gossip wire types in the range `0x07`–`0x10`
  (reserved forever)

They are described here only so that historical material can be read
correctly. They are not current behavior, and they are not coming back.
