---
title: "Upgrade Control Interface"
---

# Upgrade Control Interface

Status: **implemented, not hardware-qualified.** This is the local interface
between the server and `nexus-updater` (Design-Auto-Update Phases 4 and 5).
The turn rule behind it is in `Security/Upgrade/UpgradeProgress.hpp`; the
server side is `Core/UpgradeControl.hpp`; the updater side is
`LemonadeNexusUpdater/ControlClient.hpp`. This is the only control interface
between the two; there is no other socket.

## Transport

- A Unix stream socket at `/run/lemonade-nexus/upgrade.sock`, mode `0600`.
  The directory is the service's runtime directory.
- The server reads the peer's user id from the kernel (`SO_PEERCRED` on
  Linux, `getpeereid` elsewhere) and accepts **root only**. It closes every
  other peer before it reads a byte.
- There is no network listener and no token. Nothing in the server
  configuration changes the socket path or the accepted user.
- One JSON object per line in each direction. A line is at most 32 MiB: the
  tree merge requests carry every server's tree export.
- If the socket cannot bind, the server logs a warning and runs without it.
  The updater then sees no gate and waits.

## Requests and replies

Every reply has `"ok"` (bool). A refusal adds `"error"` (string).

| Request | Reply fields | Meaning |
|---|---|---|
| `{"op":"status"}` | `running_release`, `accepted_release`, `staged_release`, `rollout` | `rollout` is `null` before a Start record, else `release_number`, `sequence`, `halted`, `participants`, `upgraded`, `complete`, `in_turn` (node id hex or `null`) |
| `{"op":"health"}` | `running_release`, `accepted_release`, `driver_phase`, `driver_failed`, `verified_authority`, `tier1_member`, `epoch`, `data_key`, `healthy`, `tree` | Facts this process holds. See [Health](#health) |
| `{"op":"offer_approval","bundle":"<JSON text>"}` | `result`, `accepted_release` | Hands a downloaded approval bundle to the server (Phase 4 step 4). `ok` is true for `adopted` and `current` |
| `{"op":"stage","release_number":N}` | | The updater staged release N and asks for a turn |
| `{"op":"turn","release_number":N}` | `gate` | The turn gate. See [Gate](#gate) |
| `{"op":"report","release_number":N,"result":"failed"}` | | The health gate failed and the updater rolled back. The server reports Failed in its status; a Halt record follows |
| `{"op":"report","release_number":N,"result":"upgraded"}` | `counted` (always `false`) | Informational. "Upgraded" counts only through a witness quorum |
| `{"op":"stage_boot_chain","bundle":"<JSON text>"}` | `staged`, `detail` | Before a reboot into a new boot chain: seal a second copy of the boot set to the PCR 8/9 of the approval. The bundle must be the approval the release chain accepted (offer it first); any other bundle is refused, so the updater cannot choose the PCRs |
| `{"op":"tree_merge_context"}` and the other `tree_merge_*` requests | see [Tree Merge Ceremony](Tree-Merge-Ceremony) | The one-time tree merge, run by `nexus-tree-migrate` on the root server: the context, a root-signed export request for a member, the backup export, the dry-run build, and the signature for the reviewed merge (`Core/TreeMigrationControl.hpp`) |

`release_number` is `YYYYMMDD * 100 + N`, from 1 to `9999123199`.

`offer_approval` results: `adopted`, `current`, `stale` (number not greater
than the highest accepted), `wrong_signer` (not the pinned release signer),
`invalid` (signature, network, protocol identity, TCB floor, or form), `oversize` (over
32 KiB), `unavailable` (no pinned signer or a corrupt release record).

## Gate

The gate comes only from finalized upgrade records. A report from the updater
never opens it.

| `gate` | Updater action |
|---|---|
| `go` | Restart now: finalized state opened this server's turn, or this server takes no part in the order and every participant is upgraded |
| `wait` | Poll again. A server ahead is not upgraded, a turn is open, or a participant is down |
| `done` | Finalized state shows this server upgraded for release N |
| `halted` | The rollout of release N halted. Do not restart; wait for a newer release |
| `not_started` | No rollout for release N yet, or a newer release replaced it |

A server that already restarted can read `go` from its own copy of the
records until the Upgraded record reaches it. The updater restarts only when
the staged release differs from the installed one, so it does not restart
twice.

## Health

`healthy` is true when the server holds verified epoch authority and its
security driver has not failed. It is the Healthy flag the witnesses require.

`data_key` is `unlocked`, `locked`, `retired`, `no_storage_key`, or
`unknown`. It is informational. During a rollout a server can stay `locked`
until enough storage holders run the new release (pending quorum). That is not
a failure: it does not block the Upgraded record, and the updater's health
gate must not treat it as a failure or wait on it.

`tree` is `null` while the server runs no tree log, else `healthy`, `height`,
`applied_height`, `behind`, and `held`. The tree log starts only after the
data key unlocks, and only on a current Tier 1 member: a Tier 2 server holds
no tree and always reports `null`.

The updater's health gate (`LemonadeNexusUpdater/HealthGate.hpp`) passes when
`running_release` is the new release, the driver has not failed, `healthy` is
true, a former Tier 1 member is a member again in the same or a later epoch,
and, on a current Tier 1 member, a tree log that ran before has caught up. A
Tier 2 server is not held to a tree log, even when an older release ran one. A
`locked` data key skips the tree check and never fails or delays the gate.

## What the updater sees during one rollout

1. Every server polls the releases, verifies, and stages. Its updater sends
   `offer_approval` (a refusal stops the cycle), then `stage`, then `turn`.
   On `not_started` or `wait` the cycle asks `turn` again every 10 seconds
   for up to 20 minutes in all, so a server that staged before the Start is
   waiting when it finalizes. When no cycle runs, the server's wake marker
   (`/run/lemonade-nexus/updater-wake`, watched by `nexus-updater.path`)
   starts one when a Start it takes part in finalizes.
2. A Tier 1 leader proposes a Start record when every Tier 1 member reports a
   live status and some server runs an older release. The order is Tier 2
   servers first (those that report a configured attestation collector), then
   Tier 1, each group by SHA-256 of the release number and the node id. A
   member that lacks records of the previous rollout, but holds a later
   record with its commit proof, judges the Start against that record: the
   records it lacks finalized before it, and the Start replaces them. It
   votes for no other record while it is behind.
3. The first server in the order gets a Turn record; its gate says `go`. The
   server touches its wake marker, so a cycle starts within seconds, and a
   cycle already waiting reads `go` at its next poll.
4. It restarts on the new release. When its signed status names the new
   release and the Healthy flag, Tier 1 witnesses challenge it with an
   UpgradeHealth attestation. A witness does not challenge earlier: each
   chain position has a small attempt budget, and the install takes a minute
   or two. A Tier 2 server admits these challenges from the Tier 1 members
   of its verified epoch authority. When a witness quorum saw it attested,
   healthy, and measuring only the new release's hashes, an Upgraded record
   follows.
5. The next server's Turn needs every other participant live. One server is
   down at a time at most.
6. A `report` with `failed` from the server in its turn finalizes a Halt.

## Rollout proof

`GET /api/upgrade/rollout-proof` on the public HTTP API returns this server's
rollout proof (`Security/Upgrade/RolloutProof.hpp`): the authority chain from
Genesis and the records since the latest Start, each with its commit proof.
The release workflow verifies it with `nexus-rollout-check` before it
publishes ([Releasing](Releasing), Release guards). The server answers 503
when it lacks a commit proof for any record. Servers keep the commit proofs
with the records, so a restart does not lose them.

A server that lacks a record or a record's commit proof asks the Tier 1
members for it on each record sync round. When no member holds the proof, a
Tier 1 member rebuilds it from the certified block chain that the other
members' consensus still holds: it requests consensus sync pages in the
current epoch and takes the three-chain over the block that carries the
record. Every proof, sent or rebuilt, must verify under the vote keys and
quorum of the epoch that finalized it before the server keeps it. A member's
consensus serves only blocks of the current epoch that it committed since its
last restart, so a proof that no member holds and no running member can
rebuild stays lost. The members that lack that record then stay behind the
finalized head of that rollout, but they still vote for the Start of the next
release (step 2 above), so the lost proof does not block the next release.
