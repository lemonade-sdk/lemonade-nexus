# Account images

Account devices store image bytes locally. The Nexus servers store and replicate
only a signed SHA-256 reference for each Customer account. Another authorized
device downloads a matching image from a device with a cached copy over the
existing encrypted userspace mesh. No image data URL enters the server API,
account store, or backbone replica. A relay can carry packets in transit.

`GET /api/account/avatar` requires an authenticated Endpoint under a Customer
group with Read access. It returns `protocol`, `group_id`, `record` (a signed
reference or null), `revision` (zero if none exists), `can_write`, and `devices`.
Each device directory entry contains `node_id`, `pubkey`, `can_fetch_from_me`,
and `can_serve_me`. Entries are current same-account Endpoints with Read;
the directional flags require ConnectPrivate or ConnectShared on the serving
Endpoint. Read access alone does not grant peer connection rights.

`POST /api/account/avatar` accepts a device-signed record. The caller must be
that device, directly belong to the signed group, and have Read and Write.
The server checks the signature, digest shape, and logical revision. A stale
local write returns 409. The client must refresh before retrying. It must not
retry an ambiguous POST automatically.

The SDK provides `ln_account_avatar_configure`, `ln_account_avatar_sign`,
`ln_account_avatar_get`, and `ln_account_avatar_put`. Configure a device-local
cache directory after setting its identity. The signing helper uses that
identity in memory. It does not export the key. Returned C strings belong to
the caller and use `ln_free`. Missing APIs return 404. Unsupported reference
protocols return `LN_ERR_UNSUPPORTED`. Keep account sign-in available in both
cases and disable image editing until the server supports the reference API.

## Record format

The signed bytes are the compact, sorted-key JSON serialization of:

```json
{"author_pubkey":"<standard padded base64 Ed25519 key>","group_id":"<Customer id>","image_hash":"<lowercase SHA-256 or empty string>","revision":1,"type":"nexus.account_avatar.ref.v2"}
```

The transport adds `signature`, in standard padded base64. The group ID is
1..128 bytes. `image_hash` is the lowercase SHA-256 of the complete normalized
PNG data URL, or empty for removal. The whole reference is at most 2048 bytes.
The server rejects image fields and old payload-bearing records.

The client fully decodes and re-encodes selected images as PNG. The SDK bounds
the resulting data URL to 128 KiB and checks PNG/IHDR dimensions in 1..128.
A receiving device verifies those bounds and the exact hash before caching or
displaying data. It must not load arbitrary external image URLs.

Revisions are integers in 1..2^53-1. A writer increments the largest revision
it read for the account. An empty hash is a removal record. Servers retain
the newest signed record per account and author, ordered by revision and then
hash. Across authors, the visible record orders by revision, author,
then hash. This resolves simultaneous writes without a wall-clock dependency.
It does not provide consensus ordering. A concurrent replacement and removal
use the same rule; removal does not override a concurrent higher-order record.

## Device transfers and cache

Each device exposes a loopback HTTP service through mesh virtual port 9193.
It does not open a public or LAN listener. A download uses a random challenge
valid for 30 seconds and a device signature with the
`nexus.account_avatar.fetch.v1` domain. The proof binds the account, image
hash, requester, recipient and challenge. Challenges are single-use and capped
at 64. Requests are capped at 2048 bytes; responses are bounded while streaming.

The serving device verifies the proof, then fetches current account metadata
and permissions from the private API. It serves only the current hash to an
account member with Read and the required peer connection permission. Failure
to verify current access fails closed. A hash match is not authorization.

The downloader matches peers by verified directory node ID and identity. It
uses the existing encrypted mesh egress and never forwards its server session
token or API key to a peer. It retries at most two devices per refresh attempt,
rotates across candidates, and waits ten seconds before another failed attempt.
Downloaded copies can serve other devices after the original source goes offline.

Caches are scoped by device identity and hashed account ID. Writes atomically
replace local files. A signed pending reference retains an uncertain upload
across a lost response, restart or a lagging metadata read. A first definitive
refusal clears its staged copy. A prior uncertain change remains cached even
if an explicit retry is refused. The user can explicitly retry the same image;
no POST is replayed automatically. Replacements prune
old bytes after a confirmed reference is available. Removals clear the local
account copy when observed. Revocation cannot erase a copy already held by a
previously authorized device.

The SDK's GUI-facing result is `{group_id, revision, can_write, image, pending}`.
If a nonempty reference has no reachable copy, `image` is null and `pending` is
true. The UI shows initials and guidance to connect a device with the image.
This does not remove the shared reference or block account access. A matching
local cache continues to work when other devices are offline. If every cached
copy is lost, an authorized writer must choose the image again.

## Replication and restart

The `avatar-ref` origin-replica stream uses `AccountAvatarSync` (0x1B) on the
encrypted backbone only. It transfers bounded entry chunks and uses the
existing digest and catch-up messages. The record's authority comes from its
device signature and the receiver's current account tree. A server certificate
only authorizes transport. This stream can carry records from any certified
server; the Tier 1 restrictions for DNS, tree commits and key envelopes remain.

Each replica origin is a SHA-256 hash of the group ID and canonical device key.
It retains one entry per origin, including removals, with a 4096-entry cap.
The stream opts in to payload ordering and payload hashes for equal logical
versions. Existing replica streams keep their previous ordering and digests.
Partial transfers use an 8-record memory budget and a 30-second timeout.

Records and replica snapshots use the storage service's atomic replacement
path. Reload verifies the device signature and current Write authority again.
A record from a revoked or removed device is refused. This is replay ordering
within retained state, not protection against an operator rolling storage back.

Removing an author's Write access or Endpoint membership also makes that
author's stored reference ineligible. The next eligible author's record
becomes visible, or the image becomes empty. A currently authorized writer can
replace it. Image retention across authority revocation is not a historical
permission-proof feature of this stream.

Deploy this server change before enabling image editing in clients. All mesh
servers that may serve account references need the update. Devices also need
the updated SDK to cache and serve bytes. Older servers do not
replicate this new stream. Mixed deployments can therefore return an old reference
or no reference until the relevant servers are upgraded.

## Validation

`test_account_avatar_client` exercises encrypted device transfers, cache restart
and resharing, replacement/removal, lost responses, offline sources, hash
validation, replay, revoked Read/Connect rights and cross-account rejection.
Its directory and reference API are a local fixture; image bytes use the real
userspace mesh. `test_mesh_ingress` covers existing service transports.
`test_account_data` checks that server storage contains no image data and covers account isolation, read-only devices, SDK signature
interoperability, replacement/removal, stale records, tampering and restart.
`test_origin_replica` covers equal-version convergence and unchanged default
ordering. `test_gossip_ingress_security` covers the real backbone dispatcher,
three server replicas, missed-update catch-up, Tier 2 profile transport,
tampering, public-socket rejection and removal after restart.
`test_file_storage` covers atomic replacement and existing pool-write behavior.
These tests do not establish deployment or interoperability with a live mesh.
