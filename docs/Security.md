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

A server that enters Tier 1 gets the tree through Tier 1 tree log
replication. Tree operations are the only tree write path; no server changes
its tree outside the committed log.

### The one-time tree merge

Servers that wrote their trees before tree operations hold different trees.
The [Tree Merge Ceremony](Tree-Merge-Ceremony) commits one merged tree as tree
log height 1, once. Its security rules:

- **Authority is the root management key's signature.** Every server
  verifies the merge commit against its own configured `root_pubkey` and the
  network id from its own Genesis key, whoever delivers it (the `"tree"`
  stream, or `POST /api/tree/merge/commit`). The deliverer is not trusted.
- **One-shot.** The commit is valid only as height 1 on the empty base. A
  server whose log holds height 1 refuses another merge; a merge entry at any
  other height does not verify. No command replaces the tree after that.
- **Nothing takes height 1 first.** A server that holds a pre-merge tree opens
  its log on the empty base, refuses tree writes (`503`, retryable), proposes
  nothing, withholds its vote from every tree block, requests no root, and
  refuses every consensus entry. It applies only the merge commit.
- **Signed, complete inputs.** A Tier 1 member gives its export only for a
  request that the root management key signed for that member, issued within
  10 minutes, with a nonce it has not served. It signs the export with its
  gossip identity under `lemonade-nexus/tree-export-signature:v1`, bound to
  the network. The root server merges only when the signers are exactly the
  current Tier 1 members by finalized membership, each once, plus its own
  backup export, which only it may mark as the root server's.
- **Deterministic merge.** The merge rule (`tree::merge_tree_exports`,
  TreeMerge.hpp) depends only on the exports. It always decides, and it
  reports every tie-break and every dropped node.
- **Narrow signing.** On the root server's control socket (root peers only)
  the root management key signs two document types: an export request for a
  current member, and the preimage of a merge that the server built itself
  from verified exports, and only when the rebuilt tree digest equals the
  reviewed dry run.
- **Keys stay in the process.** The data key reads the root server's backup
  (`StorageVault::copy_view`, read-only, same relative paths, current data
  key only). The script holds no key.

Limits:

- The root holder reviews the dry run. The merge rule decides by evidence on
  disk (IPAM records, the delta log) and then by the tie-break; it cannot know
  which of two differing copies a user meant.
- Dropped nodes (shared identifiers, nodes that do not reach the root) are
  gone after the merge; those devices join again.
- The script reaches Tier 1 members over their public HTTPS API. For an
  address URL it checks the certificate chain but not the name. The exports
  stay authenticated by their signatures; their confidentiality against an
  active attacker on that path then rests on the chain check only.
- A backup whose files are under an earlier data key (before a monthly
  rotation) does not open.

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
from the authority chain, the network and epoch match, the ticket names this
relay by its base64 node identity key, the signature verifies, and it has not
expired (`Relay/RelayTicketAuth.hpp`). A relay with no relay id refuses every
ticket. Each issuer and nonce allocates one session; the relay keeps that
record until the ticket expires. The relay needs no tree and no session
state, so a Tier 2 relay carries ciphertext for any session a Tier 1 server
authorized. A ticket from the previous epoch is refused after an epoch change
and must be requested again.

### Relay sessions

Two peers that cannot reach each other directly share one relay session
(`Relay/RelayService.hpp`, wire format in `Relay/RelayWire.hpp`). Each peer
sends the relay an `Allocate` request with its own ticket and its rendezvous
material. A peer derives that material from the X25519 secret it shares with
the other peer, the relay id, both mesh public keys, and a 300-second window.
Only the two peers can derive it. The material is a rendezvous id, the
sender's proof, and a commitment to the other side's proof.

- The first request creates a waiting session bound to the sender's endpoint.
- The relay joins a second request to it only when each request opens the
  commitment that the other made, the two tickets name different holders, and
  the two requests come from different endpoints. A copy of the first request
  with another ticket is refused.
- The relay forwards data only between the two bound endpoints. It drops data
  from any other sender, and data that starts with the relay magic, so a peer
  cannot forge relay control messages for the other peer.
- Only a bound endpoint gets heartbeat answers or may end the session.
- A ticket allocates once. A retransmission from the same endpoint learns the
  same session; the same ticket from anywhere else is refused.

`RelayLimits` bounds every table: at most 4096 sessions, 16 sessions for each
ticket holder, 16384 used-ticket records, and 6000 `Allocate` checks per
minute across all senders. The rate check runs before the ticket signature
check. A session that waits 30 seconds for its second side, is idle for 90
seconds, or reaches one hour is dropped. The peers then allocate again with
new tickets, so their authorization is checked again.

The relay sees only BoringTun ciphertext; the BoringTun session between the
peers authenticates every packet. An attacker on the network path of the
second request who holds a valid ticket can race that request to the relay.
The attacker then receives ciphertext it cannot read, and the BoringTun
handshake fails. This is a denial of service on that relay session, which an
on-path attacker can cause anyway.

### Direct paths

The SDK punches direct paths between mesh peers (`HolePunch.hpp`). No new
cryptography is involved, and a punch grants no authority:

- **Probe targets come from the authenticated tree.** A peer's endpoint comes
  only from the verified Tier 1 server's peer list (`GET /api/mesh/peers`),
  which lists only peers the caller may connect to. The SDK never takes a
  probe target from a received packet. It ignores a listed endpoint that is
  not a dotted IPv4 unicast address, and it accepts a loopback endpoint only
  when the session server is on loopback.
- **A probe changes no state.** A probe is a normal BoringTun handshake
  initiation sent to the listed endpoint (`UserspaceDataplane::probe_endpoint`);
  the peer's stored endpoint stays as it is. Only a valid handshake answer
  from the probed address moves the peer there (the dataplane's existing
  authenticated roaming). The handshake authenticates the peer by its mesh
  key, so an attacker who answers in its place cannot complete it.
- **STUN is a hint.** STUN answers are not authenticated. The dataplane hands
  STUN messages to the reflexive-address query and never to a Noise session.
  The query accepts an answer only from the queried server, with its own
  random transaction id, and with a valid IPv4 `XOR-MAPPED-ADDRESS`
  (`Network/StunWire.hpp`, shared with the server's `StunService`). The SDK
  publishes the address only when the STUN server could have observed it
  (`reflexive_publishable`). A forged answer can at worst publish a wrong
  endpoint: peers then probe a dead address and fall back to a relay.
- **The server stores what the node's owner reports.** The heartbeat writes
  the endpoint only for the caller's own node, as a `SetEndpoint` tree
  operation when tree operations are on. It refuses IPv4 addresses that are
  not unicast. An empty endpoint keeps the stored one.
- **Probes are rate limited.** At most 16 probes go out per pass and passes
  are at least 250 ms apart. A peer gets a burst of five probes, then two
  probes per 15-second slot, or per 60-second slot while it is relayed. A peer
  with a fresh direct handshake gets none.

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
  A node changes groups only through the move route (see "Moves" below).
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

### Invites and group membership

An invite is a single-use link token for a target group
(`POST /api/link/token`, optional `target_node_id` and `permissions`). Without
a target, the target is the caller's own group. The rules
(`tree::rules::invite_refusal`) are:

- **The target is a group.** An invite never targets a device or the root.
- **The inviter has authority on the target.** The inviter holds `add_child`
  on the target or administers it (`admin` on the target or an ancestor).
- **An invite never grants more than the inviter holds.** Each permission is
  one of `read`, `write`, `add_child`, `connect_private`, and
  `connect_shared`, and the inviter holds it on the target or administers the
  target. `admin`, `edit_node`, and `delete_node` are never granted by an
  invite, so neither side gains control over the other's group. Without
  `permissions`, the invite carries `read` and `connect_private`, reduced to
  what the inviter holds.

A new device uses the token in `POST /api/join` and is placed under the
target, as before. An identity that already joined uses the token in
`POST /api/link/accept` (or `POST /api/join` from its existing device). It
becomes a **member**: the server sets exactly the invite's permissions as the
identity's entry on the target (`AcceptInvite`). Nothing the member owns
moves, and no other node changes. At acceptance the server checks the rules
again against the current tree (`tree::rules::invite_acceptance_refusal`):
an inviter that lost its authority voids the invite, and an identity that
already joined inside the target, or administers it, is refused. A refused
acceptance does not spend the token. Tokens stay single use and expire after
at most one hour. Any Tier 1 server redeems a token, whichever Tier 1 server
minted it (see "Invite replication" below).

**Linked devices see each other.** When a new device joins with a token, each
device already in the target group (same parent group, Endpoint nodes only)
and the new device get `read` and `connect_private` on each other
(`tree::rules::grant_link_peer_access`). The group owner's key already holds
an entry on the new device (it keeps control of the device), so the grant
adds the two permissions to that entry; earlier releases skipped it, and the
owner's first device did not list devices linked later. No other group and
no other permission is touched.

**Membership reach.** A literal `connect_private` or `connect_shared` entry
for key K on a group G is a membership. It lets each device whose management
key is K connect to every device beneath G, and lets every device beneath G
connect to those devices (`tree::rules::endpoint_may_connect`). It covers no
other device: the member's other devices (other keys) and the rest of its
network stay invisible to G, and the member sees nothing of the inviter's
other groups. An `admin` entry is not a membership and gives no connect
reach. The mesh peer list, the routing chokepoint (`resolve_authorized`), and
the dataplane forwarding policy (`ForwardAuthorizer`) apply this one rule.

**Leaving.** An admin of the group removes a member through
`POST /api/tree/node/assignments/{id}` with an empty list. A member removes
its own entry the same way without admin, but only on a group it has not
joined and only when that entry holds no `admin`
(`tree::rules::assignment_change_refusal`). Removing the entry removes all
membership reach at once.

Limit: an admin can remove a member but cannot change a member's
permissions in place, because the joined-identity rule above refuses a key
that did not join inside the group. Send a new invite instead.

### Moves

`POST /api/tree/node/move/{id}` with `{"parent_id"}` moves a device or a
subgroup under another group (`MoveNode`, `tree::rules::move_refusal`):

- The node is an Endpoint or a Customer group. The root and every top-level
  group (a group directly under the root) never move, so no one moves another
  user's network out from under its owner.
- The new parent is a group, differs from the current parent, and is not the
  node or one of its descendants.
- For a device, the signer holds `delete_node` on it or administers it. For a
  subgroup, the signer administers it: `delete_node` alone cannot take over a
  subtree.
- The signer holds `add_child` on the new parent or administers it.

A move keeps the node's id, tunnel address, endpoint identifier, and own
assignments. It clears the node's parent signature, which no longer covers
the record. It grants nothing: access in the new group comes from that
group's rules (its admins administer the node; its memberships cover it).
Connect grants that depended on the old group's scope stop applying. When a
moved device's key owns no other node, the entries that its old group and old
sibling devices held for that key (the link-join grants) are removed, as a
delete removes them.

### Invite replication

A token is minted on one Tier 1 server and can be redeemed on any Tier 1
server (`Auth/LinkTokenLedger.hpp`, `TokenLinkAuthProvider`).

- **The token never leaves the minting server.** Every record names it by
  `link_token_hash_hex(token)`, SHA-256 under the domain
  `lemonade-nexus/link-token-hash:v1`. The token is returned once, to the
  inviter.
- **Events, not mutable records.** A token's life is a set of events: `Mint`
  (target group, permissions, inviter, network id, issue and expiry times),
  `Spend` (a server consumed generation g), and `Refund` (the server whose
  spend counts restored the token as generation g + 1). Each event is signed
  by the gossip identity of the server that made it, under the domain
  `lemonade-nexus/link-token-event:v1`, and binds the network id. Replicas
  that hold the same events derive the same state in any arrival order. When
  two servers spend the same generation, the spend with the smallest origin
  key counts on every server, and a refund by any other server never restores
  the token. A `Revoke` from any server ends the token for good: an account
  deletion revokes the tokens the account minted and the tokens that target
  a removed group (`TokenLinkAuthProvider::revoke_where`), and the revocation
  replicates like every other event.
- **Transport.** Events use the change-numbered catch-up replication
  (`sync::OriginReplica`, stream `link`, gossip type `LinkTokenSync`) that DNS
  records and account envelopes use. They travel only on the encrypted
  backbone, only from a sender that is a current Tier 1 member, and only to
  Tier 1: a Tier 2 server neither receives, requests, nor serves them, and a
  server that leaves Tier 1 deletes them with the tree files. A receiver
  checks the network id, the origin signature, and that the origin holds a
  root-signed certificate, the same origin rule as account envelopes.
- **Bounds.** At most 64 live tokens per inviter, 16384 tokens per server, 64
  events per token, and 8 refunds per token. A token's events are kept for 10
  minutes after its expiry and then pruned on every server; an event outside
  that window, or with an expiry or timestamp too far ahead of the receiver's
  clock, is refused.
- **Storage.** The provider's ledger (`link_tokens/ledger.json`) and the
  replica file (`link_replica/replica.json`) are storage-vault files,
  encrypted under the data key once the vault runs encrypted. On restart the
  replica entries are verified again before use. A plaintext token file from
  an earlier release (`link_tokens/<sha256>.json`) is still redeemed, once, on
  the server that minted it, until it expires.

**Single use.** A `Join` with a token and an
`AcceptInvite` carry the signed `Mint` in a link extension of the op
(`TreeOpBody::invite_grant`). Every replica checks, against the block: the
grant is a well-formed mint signed by a trusted submitter of the block's
epoch, for this network, unexpired at the block time, and bound to the op's
group, inviter, and permissions. The op records the invite's redemption id in
the committed id set until the invite expires, so a second op that redeems
the same token is refused (`Replayed`) on every replica, whichever server
submitted it. A refused op does not commit the redemption, and its submitter
restores the token. An invite minted by a server that is not a trusted
submitter of the block's epoch is refused.

The replicated `Spend` and `Refund` events keep every server's ledger in
step; they decide no redemption. A redemption fails while the token's `Mint`
has not reached the redeeming server yet (normally under a second after
minting).

### Account deletion

An account deletes itself through `POST /api/account/delete` (SDK
`delete_account`, C `ln_account_delete`). There is no form of the route that
names another account, and no operator or admin path deletes an account.

**Fresh proof.** A session token alone does not delete an account. The client
gets a challenge from the session's server
(`POST /api/account/delete/challenge`, the Ed25519 challenge store of
`/api/auth/challenge`) and signs `auth::account_delete_proof_message`: the
canonical encoding, under the domain `lemonade-nexus/account-delete:v1`, of
the challenge and the account's public key. The server checks that the
challenge was issued to the session's key, is less than 60 seconds old, and
was not used, and then verifies the signature. A login signature never
verifies as a deletion proof, and a deletion proof never opens a session.

**Scope** (`tree::rules::account_scope`). The deletion removes:

- every Customer or Endpoint node whose management key is the account key
  (its `customer-<user_id>` group, its device, and any node it created
  elsewhere), and every node beneath one of them. This includes devices and
  subgroups that other identities placed in the account's groups. Those
  identities keep their own accounts, but they lose access to this network;
  a device key that owns no other node is revoked.
- every assignment, on every remaining node, that names the account key or
  the key of a removed node that owns no remaining node: the account's
  memberships in other users' groups, and the connect and link-join grants
  that named its keys.

The root node is never removed or changed, whoever calls. When the root
management key also owns a Customer group, deleting that account removes the
group and leaves the root, the root's owner assignment, and the key itself.

**Cleanup on every server that applies the deletion.** The removed-nodes
cascade (`TreeApiHandler::cascade_node_cleanup`) revokes device keys that own
no node, releases IPAM allocations, removes mesh peers, removes the private
DNS name, and removes the device and group certificates. The account cleanup
(`AccountDataApiHandler::cleanup_deleted_account`) deletes the account's chat
blobs and group-key envelopes (on disk and in the replicated envelope
stream), revokes the link tokens it minted or that target a removed group
(a replicated `Revoke` event, see "Invite replication"), and deletes its
passkey credentials. When the account key owns no node any longer, the
server revokes it. A revoked key cannot authenticate, and its sessions end,
including a session that names only the user id (passkey).

**Ordering.** The route submits one `DeleteAccount` operation (kind 10).
Every Tier 1 server validates and applies it at the same block, computes the
same scope, and runs both cleanups. The committed op id keeps a replay
refused after a restart.

**Idempotence.** A deletion with nothing left changes nothing and succeeds.
After a deletion the revoked key cannot request another one.

Limits:

- An envelope is dropped from the replicated stream without a tombstone. A
  peer that has not yet applied the deletion can offer it again; a server
  that applied the deletion refuses it, because its tree no longer
  authorizes the envelope.
- Key revocations, passkey credentials, and chat blobs are stored per server.
  Each Tier 1 server that applies the deletion removes its own copies; a
  server outside Tier 1 at that time keeps its copies. Link token revocations
  replicate to every Tier 1 server; a token whose `Mint` has not reached the
  deleting server yet (normally under a second after minting) is not revoked
  there.
- Local files (the identity key, the account image cache, and certificate
  directories) stay on the client. The client deletes them (see
  [Client SDK](Client-SDK#account-deletion)).

## Application Authority Gaps

Admission and several replicated application stores are **not** derived from
finalized security state. This is the boundary between what the security
protocol authorizes and what the application layer still gates on identity or
root:

- **Server admission** (certificate issuance, enrollment tokens, supersede)
  is root-gated or token-gated. It grants transport membership, not Tier 1.
- **Replicated application stores** (ACL, DNS records, backbone IPAM, NS
  slots, account group-key envelopes, link token events) sync through gossip
  under root-signed peer certificates. A Tier 2 server holds no tree, so it
  accepts no account envelope and no link token event. Without tree
  operations, link token single use is not consensus-authorized (see "Invite
  replication"). Their
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
7. **Relay fallback and hole punching are tested only in software.** Relay
   allocation, pairing, forwarding, expiry, the SDK fallback, reflexive-address
   learning, and hole punching have unit tests and loopback end-to-end tests
   (`test_relay_service`, `test_sdk_relay_fallback`, `test_sdk_hole_punch`).
   They are not tested across real NAT devices or under load. Each device
   publishes one reflexive endpoint from one STUN server: there are no LAN
   candidates, and the SDK does not detect endpoint-dependent (symmetric) NAT
   mappings. Two peers behind the same NAT connect directly only when the NAT
   supports hairpinning. Pair slots assume that the two device clocks agree to
   within the NAT mapping lifetime. A peer without a listed direct endpoint
   always uses a relay. Both peers pick the relay from their own
   candidate lists; when the lists differ, the peers can pick different relays
   until a failed relay is skipped. The client dataplane reaches relays over
   IPv4 only.
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
