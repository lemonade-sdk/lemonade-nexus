---
layout: default
title: Live SDK E2E
---

# Live SDK E2E

The workflow `.github/workflows/live-e2e.yml` tests the SDK built from a
commit against the live production fleet. Two GitHub-hosted runners act as
real clients. They use the public SDK C ABI (`lemonade_nexus.h`) through the
shared library that applications load.

## Table of Contents
- [What the test proves](#what-the-test-proves)
- [What the test does not prove](#what-the-test-does-not-prove)
- [How it works](#how-it-works)
- [Accounts, secrets, and variables](#accounts-secrets-and-variables)
- [One-time setup](#one-time-setup)
- [When it runs](#when-it-runs)
- [Cleanup](#cleanup)
- [Security notes](#security-notes)
- [Limits](#limits)
- [Run the client by hand](#run-the-client-by-hand)

## What the test proves

Each run proves these steps with the SDK from the commit under test:

| Step | Proof |
|---|---|
| Discovery | The client finds the Tier 1 servers from the region's SEIP DNS records, then pins the Genesis key with first-connect discovery (`ln_discover_genesis_key`) and verifies the Tier 1 membership (`ln_tier1_refresh`). |
| Join | Both persistent accounts join through a verified Tier 1 server (`ln_join_network`), bring up the mesh, and reach the private API over the mesh. |
| Invite | The owner creates two single-use invites into the CI group (`ln_invite_create` with the CI group as the target). |
| Accept | The member accepts an invite with its existing account (`ln_invite_accept`) and is listed as a member of the CI group (`ln_memberships_list`). |
| Peers | Each device lists the other as a mesh peer (`ln_mesh_peers`). |
| Direct path | The member fetches a 64 KiB body from a service that the owner exposes over the mesh (`ln_mesh_expose_service`, `ln_mesh_open_egress`). The dataplane status of the owner's peer (`ln_mesh_status`) shows a direct endpoint, no relay endpoint, a fresh handshake, and traffic in both directions during the fetch. |
| Relay path | Both devices restart the mesh with `prefer_direct` set to false. The fetch succeeds again, and the status shows a relay endpoint, a fresh handshake, and traffic on that peer. |
| Leave | The member leaves the CI group (`ln_membership_leave`). The membership disappears, the owner leaves the member's peer list, and the service becomes unreachable. |
| Removal | The member accepts the second invite. The owner removes the member's entry (`ln_remove_group_member`). The member then has no membership, no owner peer, and no reachable service, and the owner no longer lists the member. |

The path checks need a fresh handshake with the peer itself and traffic on
that peer. Traffic that a Tier 1 server forwards does not count as a direct
or relayed path.

## What the test does not prove

- **A direct path on every runner pair.** Hole punching can be impossible
  between two runners, for example behind endpoint-dependent NAT. When the
  direct check finds no direct path in 150 seconds, it records the check as
  skipped with the last observed path, adds a warning annotation, and
  continues. The run does not fail only for this reason. A run with a skipped
  direct check proves nothing about hole punching.
- **New-device onboarding.** Both accounts exist before the run. The test does
  not create a device under an invite (`ln_set_link_token` with a new
  identity).
- **Other platforms.** Both runners are Ubuntu 24.04 x86-64. The test does not
  cover macOS, Windows, the Flutter app, or `lemond`.
- **Other regions.** Discovery uses one SEIP region (`us-west` by default).
- **Server code from the commit.** The fleet runs its released server
  binaries. A pull request that changes server code tests only the SDK side
  against the current fleet.
- **Production qualification.** A passing run is a functional check of one
  scenario. It is not attestation, load, or security qualification.

## How it works

The workflow has six jobs:

| Job | Runner | Work |
|---|---|---|
| `preflight` | any | Checks the trigger and that the secrets exist. Sets `enabled`. |
| `build` | Ubuntu 24.04 | Builds `LemonadeNexusSDKShared` and `nexus-e2e`, runs the offline self-test, and uploads both files. |
| `owner-invite` | Ubuntu 24.04 | The owner creates two invites and writes them into a sealed bundle (the job output). |
| `owner-serve` | Ubuntu 24.04 | The owner joins, exposes the test service on mesh port 18080, and answers the member's control requests. |
| `member` | Ubuntu 24.04 | The member opens the bundle and runs the scenario. |
| `cleanup` | Ubuntu 24.04 | Runs after success, failure, or cancellation. Removes per-run state. |

`owner-serve` and `member` run at the same time on separate runners, so they
use different NAT paths. They coordinate over the mesh: the owner's service
has control routes (`/e2e/mode`, `/e2e/remove`) that the member calls. The
owner removes only the key in `NEXUS_E2E_MEMBER_PUBKEY`; the request does not
choose the key.

The test client is `tests/live-e2e/nexus_e2e.cpp`. It is built only when
`BUILD_TESTING` is on, so release builds do not include it. CTest runs only
its offline self-test (`LiveE2E.SelfTest`).

### The invite bundle

Job outputs appear in logs, so the workflow never passes a raw invite code.
`owner-invite` generates a 32-byte key and seals it to the member account's
Ed25519 key with the SDK's group-key envelope (`ln_group_key_wrap`, a
libsodium sealed box). That key encrypts the payload (the two codes, the CI
group id, and the owner's node id) with XChaCha20-Poly1305. The associated
data binds the bundle to its format version, the recipient key, and the run
id (`<run_id>-<run_attempt>`). Only the member identity opens the bundle, and
only in the same run.

## Accounts, secrets, and variables

The test uses two persistent accounts. A run does not create accounts.

| Account | Role |
|---|---|
| Owner | Has its own top-level group. That group is the CI group. The owner administers it, so it can invite and remove members. |
| Member | A second account with its own top-level group, as a user of another network. Each run, it becomes a member of the CI group through an invite ("join another network"). The run ends by removing that membership. |

An account is one Ed25519 device identity. The test needs no passkey: the
server authenticates the device with an Ed25519 challenge, and every step
uses that session. The client app's passkey sign-in also only authenticates
and then uses a device Ed25519 identity. The account group key (the
zero-knowledge account data key) is not used by any step.

| Name | Kind | Content |
|---|---|---|
| `NEXUS_E2E_OWNER_IDENTITY` | Secret | The owner identity file (`{"public_key","private_key"}`). |
| `NEXUS_E2E_MEMBER_IDENTITY` | Secret | The member identity file. |
| `NEXUS_E2E_MEMBER_PUBKEY` | Variable | The member's public key (`ed25519:...`). The owner seals the bundle to it and removes only it. Required. |
| `NEXUS_E2E_OWNER_PUBKEY` | Variable | The owner's public key. Cleanup then leaves only the owner's groups. Optional. |
| `NEXUS_E2E_GENESIS_KEY` | Variable | The expected Genesis key. Every job then fails when discovery pins another key. Optional. |

## One-time setup

The repository owner does this once, on a trusted computer.

1. Build the client:

   ```bash
   cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
   cmake --build build --target nexus-e2e
   ```

2. Create both accounts:

   ```bash
   scripts/live-e2e-setup
   ```

   The script generates two identities, writes each to
   `live-e2e-secrets/<role>-identity.json` (mode 0600, directory mode 0700),
   and joins each one through the production fleet. Each account gets its own
   top-level group. The script checks that the owner administers its group.
   It prints only public values: the keys, node ids, group ids, and the
   Genesis key.

3. Run the `gh` commands that the script prints. They store the two identity
   files as the secrets `NEXUS_E2E_OWNER_IDENTITY` and
   `NEXUS_E2E_MEMBER_IDENTITY`, and the public values as the variables above.

4. Delete the local directory: `rm -rf live-e2e-secrets`.

5. Start the workflow once by hand (**Actions → Live SDK E2E → Run workflow**)
   and read the job summaries.

Do not use either account for anything else. Cleanup leaves every group that
the member entered through an invite from the owner (or every invite group,
when `NEXUS_E2E_OWNER_PUBKEY` is not set), and removes every member entry
from the CI group except the owner's.

### Closed registration

A new account gets its own top-level group only when the network has open
registration (the server default). With closed registration, `/api/join`
refuses a new identity without an invite, and an invite places the identity
as a device inside the inviter's group, with only `read` on that group. Such
an account cannot administer a CI group, so it cannot be the owner. In that
case the owner setup fails with "registration closed — link token required".
The member account can still be created from an invite code with
`scripts/live-e2e-setup --member-invite`; the script asks for the code
without echo.

## When it runs

| Trigger | Condition |
|---|---|
| `pull_request` to `main` | The pull request changes the SDK, the dataplane, relay, STUN wire, tree, API, or crate sources, or this test. |
| `schedule` | Nightly at 07:23 UTC. |
| `workflow_run` | After the `Release` workflow completes successfully. |
| `workflow_dispatch` | By hand. |

The jobs skip, and do not fail, when the secrets or the member key variable
are not available. GitHub does not give secrets to pull requests from forks,
so those runs skip. A run after a failed release also skips.

All runs share the concurrency group `live-e2e-production-ci-group`, so two
runs never use the CI group at the same time. A new run waits for the run in
progress. GitHub keeps only the newest waiting run and cancels older waiting
runs.

## Cleanup

The `cleanup` job runs when the build succeeded, also after a failure or a
cancellation. It removes only per-run state:

- `cleanup-owner` removes every member entry from the CI group except the
  owner's own. It reports, and does not delete, any device in the CI group
  that the owner does not own. The scenario never places a device there.
- `cleanup-member` leaves the invite memberships of the member account.

The accounts, their groups, and their devices persist. Unused invites expire
on the server after the invite lifetime (`--ttl`, 3600 seconds, the server
maximum).

## Security notes

- The workflow changes production state only inside the CI group: one
  membership entry per run, which the run removes.
- The identity files reach a runner only through the secrets. Each job writes
  them with mode 0600 to the runner's temporary directory and deletes them at
  the end. The client never prints invite codes, tokens, or private keys.
- A pull request from a branch of this repository receives the secrets and
  runs its own version of the workflow and the client. Anyone who can push a
  branch here can therefore use the two CI accounts. The accounts can do only
  what the CI group allows; they hold no other authority. Move the secrets to
  a protected GitHub environment if that trust level is too broad.

## Limits

- **Invites are local to one server.** The server stores an invite only on the
  Tier 1 server that minted it (`TokenLinkAuthProvider`). The owner and the
  member normally reach the same server first, because the SDK tries verified
  servers in membership order. When they reach different servers, the accept
  fails with `LN_ERR_AUTH`, and the member job reports this cause.
- **The relay check needs a relay.** The relay path fails when the fleet lists
  no usable relay.
- **Timing.** The member waits up to 10 minutes for the owner's service. The
  owner stops when the member does not call within 15 minutes, or is silent
  for 20 minutes before the removal step.
- **Release timing.** After a release, servers update one at a time. A run
  that the release triggers can meet a fleet that is part way through the
  rollout.
- **POSIX only.** The client uses BSD sockets for discovery. CMake does not
  build it on Windows.

## Run the client by hand

Offline checks (argument parsing, bundle sealing and refusal cases, path
rules):

```bash
ctest --test-dir build -R '^LiveE2E\.' --output-on-failure
```

Discovery only. This sends read requests to the fleet and changes nothing:

```bash
build/tests/live-e2e/nexus-e2e discover
```

`build/tests/live-e2e/nexus-e2e --help` lists every command and option.
