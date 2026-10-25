# Design: Storage Encryption On By Default

Status: **design proposal, not approved, not implemented.** This document
designs the end state in which the storage-key and at-rest encryption paths
are always on and the feature flags are removed. It does not ship that end
state. The current code behind `storage_key_enabled` and
`storage_files_enabled` is not externally reviewed; the B3 review gate in
`docs/B3-Review-Package.md` is still open.

## 1. The decision being designed

The owner considers storage encryption non-optional security behaviour and
does not want feature flags in front of it. The target end state:

- `ServerConfig::storage_key_enabled`
  (`projects/LemonadeNexus/include/LemonadeNexus/Core/ServerConfig.hpp:149`)
  and `storage_files_enabled` (line 156) are removed.
- `StorageKeyService` and `StorageVault` always exist. The holder duties, the
  unlock protocol, and the file vault run on every server.
- The CLI flags `--storage-key` and `--storage-files`
  (`src/Core/ServerConfig.cpp:357-362`) and the `SP_STORAGE_KEY` /
  `SP_STORAGE_FILES` environment variables (`src/Core/ServerConfig.cpp:437-438`)
  are removed. Config files that still name the keys are rejected or ignored
  per the migration rules in section 6.

This design answers six questions: what happens with no data key, with fewer
than five holders, on hosts that cannot seal, the startup order, the migration
of existing deployments, and the test strategy.

## 2. What is verified and what is inferred

**Verified in this checkout** (branch `storage-dek-phase7`):

- The full suite is green: macOS 1944 pass / 0 fail / 28 skip; Linux
  1976 pass / 2 fail / 4 skip. The two Linux failures are root-privilege
  artifacts in `FileStorageTest` (a `chmod 0` file is still readable as
  root), not defects.
- `main.cpp` already implements the deferred startup: with the vault loaded
  and not `files_ready()`, it starts the io context (gossip, attestation, the
  security mesh, holder duties) and blocks in
  `wait_for_storage_unlock` (`src/Core/SecurityMeshStartup.cpp:90`) in 100 ms
  slices until the DEK is in memory or a signal arrives. There is no timeout.
- `StorageKeyService` is constructed only when `storage_key_enabled` is true
  (`src/Security/Lifecycle/SecurityMeshService.cpp:123`); the flag is
  propagated from the config at `src/Core/SecurityMeshStartup.cpp:63-74`.
- The share store is chosen per host: `SealedStorageShareStore` when the seal
  backend is available, `FileStorageShareStore` otherwise
  (`SecurityMeshService.cpp:128-148`). The choice is made at construction and
  does not depend on either flag.
- `StorageVault`'s migration state machine (`Plaintext`, `Migrating`,
  `Encrypted`) and the `vault-state.json` rules are implemented and tested in
  `tests/security/storage/vault.cpp`, including crash resume, wrong-key
  refusal, and the "missing state file with encrypted files loads as
  Encrypted" rule.
- `main.cpp:144-158` already refuses to start with the flag off when the
  state file records encryption or migration.
- The memory-mesh test `tests/security/lifecycle/storage_key_path.cpp`
  builds a real multi-node mesh in one process (founders, Tier 1 set,
  eligibility, a vault per node) and already exercises key creation, unlock
  at exactly `t` and `t − 1` holders, per-epoch refresh, holder loss down to
  three, and a file migration through a holder round trip. It constructs the
  services directly; it does not go through `ServerConfig` or `main.cpp`.

**Inferred, not verified:** the behaviour of a deployed mesh after upgrading
a running server from the `c382d2d` binary (flag off, plaintext files) to a
default-on build; the interaction of the always-on service with a Tier 2 host
that has no attestd daemon; the effect of removing the flags on the two
`SP_*` env-file consumers (the Tier 1 contract parser in
`ServerConfig.cpp` reads env files and currently ignores unlisted keys —
removing the keys from the accepted list is a behaviour change that needs a
decision, see section 9).

## 3. The B3 review gate stays

The design does not propose removing the B3 gate. The two facts that are
easily confused:

1. **The code is always on.** After this design ships, a new build runs
   `StorageKeyService` and `StorageVault` unconditionally.
2. **The code is reviewed and production-ready.** That is a separate claim.
   It stays false until an independent vendor completes the review described
   in `docs/B3-Review-Package.md` and its findings are resolved. The
   unaudited paths are the FROST 2.2.0 share refresh and repair and the
   `elastic-elgamal` DLEQ.

The review package is scoped to the library paths, not to the default-on
wiring. The wiring changes the *blast radius* of a flaw (every deployment,
not the opt-in ones) and it adds a *new* class of problem: migration of
live plaintext state, which the review package does not cover at all.
Therefore the sequence is:

- Design and implement the default-on wiring and the migration, behind
  nothing, because the whole point is that there is no opt-out.
- **Gate the production release** of that build on the B3 review being done
  and findings resolved, exactly as today's docs gate the flag.
- Keep the `docs/Configuration.md` "keep it off in production" statement
  accurate: it changes from "keep the flag off" to "do not deploy this
  release to production until the B3 review is done."

This document says that plainly: always-on code is not the same as
production-ready.

## 4. Q1 — No data key available

A node that cannot complete an unlock round trip through `t` holders has a
wrapped DEK on disk it cannot open. Options:

| Option | Verdict |
|---|---|
| A. Refuse to start | Rejected. A node that cannot unlock must still be able to run as a *holder*: it unseals its share from the boot set (sealed by the vTPM, not the DEK) and answers other nodes' unlock requests. That is design B8. A node that quits before its first unlock cannot carry the mesh past an outage; the first node to come up needs the other `t − 1` up before it, which is impossible. |
| B. Start and serve nothing that needs the files | **Accepted.** This is what the code already does: `main.cpp` starts gossip, attestation, the mesh, and the holder duties, then blocks the process startup in `wait_for_storage_unlock` until `files_ready()`. The API server does not start in the meantime, so the node serves nothing on the control plane either. It is reachable as a holder. |
| C. Fall back to plaintext or machine-wrapped storage | **Rejected.** It is a fail-open path. The design's own fail-closed rule is already in place: a covered file that does not open under the DEK is refused, and a missing state file with encrypted files present loads as `Encrypted`. A fallback would make every dev box and CI runner silently run the unencrypted path, which is the worst combination: a global "always encrypt" switch whose only escape is the implicit default that no operator consciously chose. |

**Accepted behaviour.** The node starts its networking and holder duties,
waits with the existing retry/backoff in `DataKeyService::tick`, and serves
nothing until the DEK is in memory. The wait has no timeout today
(`wait_for_storage_unlock` loops until `files_ready()` or a signal); that
stays, because a timeout that ends in "serve plaintext" is exactly option C,
and a timeout that ends in "quit" would make a slow holder set a liveness
incident. The process must stay killable (SIGINT/SIGTERM already cancel the
wait) and must log the wait state so an operator can see a node that is up
but unlocked.

Consequences:

- A single-node deployment cannot unlock (there is no one else to hold a
  share, and a node cannot be a holder for itself in a way that satisfies
  `t ≥ 2` for any supported plan). It starts its holder duties, waits, and
  serves nothing. See Q2 for what that means operationally.
- The API surface while locked: none. The HTTP servers start only after
  `load_node_identity()` in the current code, which is after the wait. Keep
  it that way.

## 5. Q2 — Below the minimum holder count

The minimum is a protocol rule: the first key needs at least 5 holders
(`StorageKeyService`, the crate's `MIN_HOLDERS = 5`); refresh and rotation
need at least 3. The production mesh is 6 nodes (root at Tier 2, five Tier
1), which is exactly the minimum. The question is what a deployment with
fewer than 5 eligible attested holders does when the flag is gone.

**Proposed rule: fewer than 5 holders is a state, not a configuration.**
There is no "reduced mode" flag, because a mode switch is the same decision
as a flag, named differently. Instead:

- The services always run. With fewer than 5 eligible holders, no storage
  key is created, no DEK exists, and the vault stays in `Plaintext` mode.
  The files are exactly as they are today (machine-wrapped where they are
  wrapped today, plaintext where they are plaintext today). Nothing is
  encrypted, and nothing is refused.
- The node is **not** in a degraded-secure state; it is in the *pre-key*
  state. The design's B10 step 1 says the key is created "once at least 5
  holders are attested." Before that, there is nothing to protect with the
  storage key.
- The difference from today is that the pre-key state is **visible and
  bounded**, not a silent configuration:
  - `GET /api/storage/status` (and the startup log) reports the holder count
    and the reason no key exists. Today the flag-off node reports nothing,
    because the service does not exist.
  - The moment the mesh reaches 5 eligible holders, the first key is created
    at the next epoch boundary, and the vault begins migration. There is no
    operator action to take: the encryption turns on itself, which is the
    whole point of default-on.
- A single-node deployment and a CI runner therefore keep working exactly
  as they do today, until someone builds a real mesh around them. That is
  the honest statement: default-on does not encrypt a single node, because
  the threshold protocol cannot. It removes the *choice* to leave a 5+ node
  mesh in the plaintext state.

**What this is not.** It is not a hidden insecure default, because:

- The threshold rule is unchanged and remains in the crate and the service;
  no code path below 5 holders produces a key.
- The pre-key state is reported, not silent.
- Once the mesh grows, encryption is not opt-in.

**The alternative and why it is worse.** Making fewer than 5 holders a
startup error forces every dev laptop and CI runner to be exempted somehow,
and every exemption is a hole in "always on." Making it a reduced mode with
a lower threshold changes a protocol rule (the 5-holder minimum protects the
first key generation from small, fully-colluding sets) and is a trust-model
change this design is not authorized to make.

## 6. Q3 — Hosts that cannot seal

The share store choice is already host-driven, not flag-driven:
`SealedStorageShareStore` when the seal backend is available, otherwise
`FileStorageShareStore` under today's machine-bound wrapping. Default-on does
not change that rule; it changes only that the rule always applies, because
the service always exists.

Platform rules, kept behind the existing boundaries:

- **Tier 1 mesh (SEV-SNP + SVSM vTPM + nexus-attestd):** the share is sealed
  in the boot set under the `storage-share` domain, with the same PCR 8/9
  binding, two-boot migration, and upgrade staging as the gossip identity
  (B6). Unseal failure stops the share, not the node: the node runs without
  its share and cannot act as a holder. That is the existing `Missing` /
  `PolicyMismatch` / `Corrupt` status handling.
- **Certificate-only hosts (Tier 2, no TPM):** the file store stands. This is
  the documented B6 limit and it already exists for the gossip identity
  (`keypair.json` at mode 600). Nothing about a macOS or Linux change may
  remove this path: a Tier 2 node that cannot seal must keep running, and it
  must still be able to hold a share, because the holder set includes Tier 2
  (B4).
- **Hosts without SEV-SNP never unlock a data key.** A holder answers an
  unlock only after a `StorageUnlock` verdict that proves every claim of the
  Tier 1 attestation profile (`StorageKeyService::on_verdict`). A
  certificate-only host cannot produce that evidence, so it never completes
  the B10 round trip, its vault stays `Plaintext`, and its files stay as they
  are. The root server of the production mesh is such a host: its files stay
  plaintext. It still holds a share and answers other servers' unlocks. This
  is the current behaviour, not a decision to keep it.
- **macOS / dev hosts without attestd:** file store, as above. The
  `FileStorageShareStore` is the fallback for every build and host without a
  sealing backend, and it is the one tests use.

One consequence of always-on: the share store is constructed on every host,
so the file store's directory (`data/security/storage/sealed/`) is created
even where sealing is later added. The migration path from file store to
sealed store already exists in `SealedStorageShareStore` (the `legacy`
adapter moves the value across on first use), so a host that gains a vTPM
and attestd migrates its share the same way the gossip identity migrates.

## 7. Q4 — Startup ordering, always on

The current order in `main.cpp` (with both flags on) already is the target
order. Default-on keeps it and removes the conditionals:

1. `StorageVault` is constructed unconditionally at the data directory, and
   `load()` reads `vault-state.json`. A damaged or missing state file with
   encrypted files present loads as `Encrypted` (fail closed, existing rule).
2. `defer_file_services = !storage_vault->files_ready()`. This is true for a
   fresh node (`Plaintext` mode: ready) and false for an encrypted node that
   has not unlocked yet.
3. Services that do not read covered files start immediately: storage,
   key wrapping, IPAM, boot set / gossip identity, gossip, the security mesh
   (including `StorageKeyService`, holder duties, and the `DataKeyService`
   that drives unlock attempts).
4. The process then runs the io context in `wait_for_storage_unlock` until
   `files_ready()` or a signal. The DEK unlock itself retries with its own
   backoff inside `DataKeyService::tick`; the wait loop paces in 100 ms
   slices. **There is no wall-clock timeout on the wait**, and none is
   proposed. The node is killable; an operator who wants a bounded wait
   kills the process.
5. After unlock: `tree.start()`, the pending root write, `load_node_identity()`
   (the node identity `keypair.enc` is covered and is read under the DEK),
   then everything after (API, DDNS, relay, DNS, HTTP servers).
6. A fresh node in `Plaintext` mode skips the wait. It starts fully up, and
   the vault's migration work runs on the io thread tick: when a verified
   plan exists and the DEK is created and proven through one unlock round
   trip, the vault stages, verifies, and promotes the files (B10, B12).

**What gets served while locked:** nothing on the control plane. The node
participates as a holder (answers `StorageUnlockRequest` after a passing
`StorageUnlock` attestation) and runs gossip, so it can help bring up the
mesh. The API returns nothing because the API server has not started.

**The ordering hazard this must keep.** The root-management write
(`ensure_application_root`) is deferred while the tree is not started, and
the node identity is loaded only after the wait, because both touch covered
files. Removing the flags must not re-order these. A crash between the vault
promoting a file and the dependent service starting is safe only because the
vault's mode is durable: a restart reads the same mode and waits again.

## 8. Q5 — Migration for existing deployments

The current live binary is built from `c382d2d` with both paths off: the
`StorageKeyService` is never constructed, there is no `records.json`, no
`data-key.json`, no `vault-state.json`, and the covered files are plaintext
or machine-wrapped exactly as in the "Current State" table of the design doc.

### 8.1 First boot after the upgrade

- The new build constructs the vault. No state file exists → `Plaintext`
  mode. `files_ready()` is true. The node starts fully, serving today's
  plaintext or machine-wrapped files. **Nothing is forced, nothing is
  blocked.**
- The mesh now runs the storage key path on every node. When the mesh has at
  least 5 eligible attested holders, the first `StorageHolderPlan` is
  finalized at the next epoch boundary and the key is created (B10 step 1).
- Each node then creates its DEK, wraps it to `S`, and proves the unwrap
  through the holders. Only after that proof does the vault begin migrating
  its files: stage `<file>.vault-new`, a fresh unlock round trip, verify every
  staged copy against the plaintext, overwrite and replace (B10 step 2, B12).
- The plaintext stays authoritative until `encrypted` is durable. A crash at
  any point resumes the staging.

An operator who upgrades a 5+ holder mesh gets at-rest encryption within one
epoch boundary plus the migration time, with no manual step. That is the
property the flag-less design buys.

### 8.2 Crash during migration

Already covered by the existing vault state machine and its tests
(`InterruptedMigrationResumesAfterACrashAtEveryStep`,
`CrashBetweenOverwriteAndReplacementLosesNothing`): the state file records
`migrating`, staged files are verified on restart, and the plaintext is
authoritative until the `encrypted` record is durable. No new behaviour is
needed for default-on; the same machine runs without a flag.

### 8.3 The state file records encryption but the flag is gone

This is the trap. Today, `main.cpp:144-158` refuses to start with
`storage_files_enabled` off when `vault-state.json` records `migrating` or
`encrypted`. In the default-on world that check is the *normal* path: the
service is always on, so an encrypted state file always finds a service.

But there is one real case: **a node that was migrated while a previous
binary had the flag on** (an operator ran today's experimental build with
`--storage-key --storage-files` on some hosts) then upgrades to the
default-on build. The state file is there and valid; the default-on build
reads it, loads as `Encrypted`, waits for the unlock, and runs. No problem.

The dangerous case is the reverse: a node whose state file records
`encrypted` but whose `data-key.json` is missing (lost, or never created
because the operator started the flag-on build, let the vault migrate, then
the data key file was deleted or the data directory partially restored).
The existing rule handles it: `DataKeyService` stays in `NoStorageKey`/`Locked`,
the vault is `Encrypted`, `files_ready()` never becomes true, and the node
waits forever serving only holder duties. **There is no recovery: no offline
recovery key (B8), and the DEK exists only wrapped in that file.** This is
already the behaviour today with the flag on; default-on does not change it,
but it does make it the only path, so it must be stated in the runbook:
**back up `data/security/storage/` (records.json, data-key.json,
vault-state.json, the share store, the sealed blobs) before and after the
upgrade.** A node without its data key and with encrypted files cannot be
brought back except by restoring those files from a backup of the same host.

### 8.4 Rollback

Rolling back to the `c382d2d` binary after the upgrade:

- **Before migration finished** (state `plaintext` or `migrating`): the old
  binary does not know the storage service exists. Its `recorded_mode` check
  does not run (the check is in the new `main.cpp`). It reads the plaintext
  files, which still exist (authoritative until `encrypted`). The staged
  `.vault-new` files are ignored orphans. Rollback is safe. On re-upgrade,
  the vault resumes from the state file.
- **After migration finished** (state `encrypted`, plaintext overwritten):
  the old binary reads the covered files as plaintext, fails to parse them,
  and — worse — some paths would regenerate files in place (a missing node
  identity generates a new identity). **Rollback to the pre-default-on binary
  after a completed migration is not supported.** The operator must keep the
  new binary (or at least a flag-on binary from the same release line, with
  both flags set) running that node. This is a one-way upgrade and must be
  said so in the release notes and the runbook.
- The `data-key.json` file is machine-independent in format (it is wrapped to
  `S`, not to the host), so the wrapped key survives a disk move; the share
  does not (it is sealed or machine-wrapped per host).

### 8.5 What the operator must do manually

1. Nothing to turn on: the encryption turns on itself when the mesh reaches
   the holder minimum.
2. **Back up `data/security/storage/` and `data/sealed/` on every node**
   before the upgrade, and re-back up after the migration completes.
3. Watch the status endpoint and logs for the holder count, the key creation,
   and the migration phase per node.
4. If a node's data key is lost and its files are encrypted, restore from
   backup; there is no other recovery (B8).
5. If the mesh never reaches 5 eligible holders, the node stays in the
   pre-key state by design; the operator's decision is whether to grow the
   mesh or accept the reported pre-key status.

## 9. Q6 — Test strategy

**What exists today** (verified):

- `tests/security/storage/vault.cpp`: the vault against a fake
  `DataKeySource`. Migration, crash resume at every step, rotation, wrong
  key, tampered file, deleted state file, and `LockedRestartServesNothingAnd
  DependentsWait` (which drives `wait_for_storage_unlock` on a real io
  context). These tests run in CI and will run unchanged.
- `tests/security/lifecycle/storage_key_path.cpp`: a memory mesh with real
  `StorageKeyService` instances, real eligibility and consensus, real
  holder sessions, and vaults. It covers key creation, cold start at `t` and
  `t − 1`, bad partials, attestation-gated unlock, replay, budgets,
  per-epoch refresh, holder loss down to three, the retiring plan after a
  rotation (a server away for two rotation intervals, and the hard cap), a
  rewrap interrupted before its verification, requests for another server's
  `R`, lost or foreign storage state, and a full file migration through a
  holder round trip. It constructs the
  services directly with a `StorageKeyServiceConfig`; it does not read
  `ServerConfig` and does not run `main.cpp`.
- `tests/security/storage/records.cpp` and `share_store.cpp`: record
  validation and both share stores.

**What is missing for default-on:**

1. **A config-level test that the service is unconditional.** The existing
   `tests/test_security_mesh_service.cpp` builds the mesh with
   `config.storage_key_enabled = storage_key` (line 138) — a parameterized
   on/off test. After the flag is removed, that test must assert the storage
   service is *present* (non-null `storage_key()`, vault attached) in every
   construction. That is a small edit but it is the test that proves
   "always on" instead of "on when I set the flag."
2. **A `main.cpp`-level startup test.** Nothing today runs the real startup
   sequence — vault load, `defer_file_services`, the wait, the deferred
   service starts — except by hand. A test is missing that starts the real
   startup path in two states: (a) fresh, `Plaintext` mode, full start with
   no wait; (b) pre-seeded `vault-state.json` in `Encrypted` mode with a
   data key, and asserts the node serves nothing until the DEK is in memory
   and then starts the deferred services in the right order (tree before
   identity, root write after tree). `LockedRestartServesNothingAndDependents
   Wait` tests the wait in isolation; it does not test that the *startup
   code* wires it up correctly once the flag is gone.
3. **A below-5-holders end state test.** `storage_key_path.cpp` starts with
   5 founders. A test is missing that builds a 1-, 2-, 3-, and 4-node mesh,
   runs several epoch boundaries, and asserts: no key created, no DEK, vault
   stays `Plaintext`, all nodes fully up and serving, and the status
   reporting (see section 5) reflects the holder count. Then add a fifth
   node and assert the key appears at the next boundary without a restart.
   This is the test that proves section 5's rule is not a silent gap.
4. **A mixed-version migration test.** No test covers a node whose data
   directory already holds `vault-state.json` and encrypted files (the
   8.3 case) coming up on a default-on binary. The vault tests fake the data
   key source; the lifecycle test's `FilesMigrate...` case migrates from
   plaintext in the same run. A test is missing that pre-seeds an encrypted
   data directory with a real wrapped key and a real multi-node holder set,
   restarts the requester, and asserts it unlocks and reads.
5. **CI coverage of the crate's own unit tests.** Done: the native Linux and
   macOS CI jobs run `cargo test --locked` for `crates/storage-threshold`.

The infrastructure that is genuinely absent is items 2 and 3: a startup-path
test harness (the `main.cpp` sequence as a testable unit) and a
small-mesh lifecycle fixture with fewer than 5 eligible holders. Both are
test-only work; neither changes product code.

## 10. Files an implementation would touch

Design only; nothing below is implemented. The expected edit set:

- `projects/LemonadeNexus/include/LemonadeNexus/Core/ServerConfig.hpp` —
  remove the two members and their comments.
- `projects/LemonadeNexus/src/Core/ServerConfig.cpp` — remove the JSON keys,
  the CLI flags, the `SP_*` env reads, and the
  `storage_files_enabled requires storage_key_enabled` validation. Decide
  the behaviour for config files that still name the keys (reject with an
  error that names the removed flag, or ignore; see section 11).
- `projects/LemonadeNexus/include/LemonadeNexus/Core/SecurityMeshStartup.hpp`
  and `.cpp` — drop `storage_key_enabled` from `SecurityMeshConfig` use; the
  mesh always receives the storage inputs.
- `projects/LemonadeNexus/src/Core/SecurityMeshStartup.cpp` — the
  `if (config.storage_key_enabled)` block becomes unconditional.
- `projects/LemonadeNexus/src/main.cpp` — the vault is constructed
  unconditionally; the `recorded_mode` refusal (lines 144-158) is deleted
  (the service is always on); `defer_file_services` is
  `!storage_vault->files_ready()`.
- `projects/LemonadeNexus/src/Security/Lifecycle/SecurityMeshService.cpp`
  and `.hpp` — `storage_key_enabled` is removed from `SecurityMeshConfig`;
  the construction block at line 123 becomes unconditional.
- `projects/LemonadeNexus/include/LemonadeNexus/Security/Storage/*.hpp` and
  `src/Security/Storage/*.cpp` — comment updates only (the "behind
  ServerConfig::…" notes and the "EXPERIMENTAL" startup log line in
  `main.cpp:1058`).
- `tests/test_security_mesh_service.cpp`, `tests/test_server_config_discovery.cpp`
  — the flag assertions become presence assertions.
- `tests/security/lifecycle/storage_key_path.cpp` — new below-5-holders and
  pre-seeded-encrypted cases (section 9, items 3 and 4).
- `docs/Configuration.md`, `docs/Design-Tree-Consensus-and-Storage-Key.md`,
  `docs/B3-Review-Package.md` — the flag table, the "keep it off" language,
  and the flag status section are rewritten to the "do not deploy until the
  B3 review is done" language.
- `cmake` / packaging / `scripts/` — no known references; `SP_STORAGE_KEY`
  and `SP_STORAGE_FILES` were not found in `packaging/` or `scripts/` in this
  checkout. Confirm before removing the env names from the Tier 1 contract's
  accepted env-file keys.

## 11. Open questions for the owner

These need a decision before anyone writes code.

1. **Unknown keys in config files.** After the flags are removed, a config
   file that still contains `storage_key_enabled` or `storage_files_enabled`
   is encountered by `from_json`. Today `from_json` silently ignores keys it
   does not read (it only reads listed keys), so a stale config would be
   ignored. Is ignore-acceptably-safe here, or should a config that names a
   removed security flag be a hard startup error? The safer choice is an
   error: an operator who set the flag to *force it on* would be silently
   wrong in the opposite direction otherwise. A hard error also catches the
   "this config was written for the old build" case.
2. **The Tier 1 env-file contract.** `load_tier1_environment_file` accepts a
   fixed list of `SP_*` keys. `SP_STORAGE_KEY` and `SP_STORAGE_FILES` are
   currently accepted (as no-ops once read) or rejected; confirm the current
   list and decide whether removing them from the accepted list is part of
   this change. A Tier 1 unit with a stale env file must not be able to
   start (or must not be refused) — this is a deployment contract change,
   not a code detail.
3. **The bounded wait.** Section 4 keeps the wait unbounded with no timeout.
   Does the owner accept that, or do they want a diagnostic timeout (e.g.
   log an error after 30 minutes and expose it in the status endpoint) while
   still serving nothing and still not quitting? A log-and-report timeout
   changes no behaviour and is recommended.
4. **Status reporting in the pre-key state.** Section 5 requires the node to
   report why no key exists (holder count below 5). `GET /api/storage/status`
   exists but is wired for a running service; confirm it reports the
   pre-key state usefully or define what it must show.
5. **Rollback statement.** Section 8.4 says rollback after a completed
   migration is not supported. The owner should confirm that is acceptable
   for the release train and that the release notes will say so.
6. **Release gating.** Confirm that the default-on release is gated on the
   B3 review the same way the flag was (section 3), and that the review
   package is extended to cover the migration state machine (8.3: an
   encrypted node without its data key is unrecoverable by design, and the
   review should confirm that is the intended invariant).
7. **macOS/Linux parity for the file share store.** The file store is the
   path every non-SEV host uses. Confirm the owner is satisfied that the
   machine-bound wrapping is the intended at-rest protection for Tier 2
   shares on macOS dev hosts, with no plan to strengthen it, or whether a
   later phase is expected to.

## 12. Summary of the two decisions that decide everything else

**Q1 — No data key available:** the node starts its networking and holder
duties, waits for the unlock with the existing retry backoff, and serves
nothing until the DEK is in memory. No timeout, no plaintext fallback, no
plaintext service. The wait is killable by signal. A node that cannot unlock
must still be able to help other nodes unlock, so it cannot quit.

**Q2 — Below 5 holders:** fewer than 5 eligible attested holders is a
reported pre-key state, not an error and not a reduced-encryption mode. The
services run, no key is created, the files stay as they are today, the node
is fully up, and the status reports why. When the mesh grows to 5 holders,
the key is created and the encryption migrates on itself, with no operator
action. The 5-holder minimum is a protocol rule and is unchanged.
