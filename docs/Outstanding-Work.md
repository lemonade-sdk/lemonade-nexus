# Outstanding work — storage and Tier 1

Status snapshot taken 2026-10-22 on `storage-dek-phase7` (`f2f0900`, content equal to `origin/main`).
Check this list before the next release. Nothing below is a blocker unless marked **decide first**.

## Decisions already made

- **Storage encryption goes default-on.** `storage_key_enabled` and `storage_files_enabled` were
  removed rather than defaulted on behind a flag. Owner position: these are not optional, so they do
  not get flags. Done deciding; treat as accepted. Implemented 2026-10-23.
- **Fail closed**, per the TLS decision. No plaintext fallback after migration completes.
- **B3 external review not commissioned** (owner decision, 2026-10-22). The gate in
  `Design-Tree-Consensus-and-Storage-Key.md` line 22 is therefore **waived, not satisfied**. Recorded
  here so nobody later reads `B3-Review-Package.md` as clearance. If review ever happens, it must
  target the shipped versions, not the ones the doc cites.
- **Genesis and root management keys** stay on the root server for now.
- **Tier 2 servers hold no tree** (owner decision, 2026-10-24). Only current Tier 1 members load, serve,
  and keep the permission tree; clients send every tree read and write to a Tier 1 server they verify
  from the Genesis key. Follow-ups: a Tier 2 relay accepts no relay ticket today (tickets are signed by
  the session server, and only Tier 1 issues sessions), and tree-derived DNS names are answered by Tier 1
  nameservers only. See `Security.md`, current limitations 6 to 8.

## 1. Remove the two storage flags

**Design is written: `docs/Storage-Default-On-Design.md`. Read it before implementing.**
It proposes answers to the two questions that block the code, and they are consistent with the
fail-closed decision above:

- **No data key:** start networking and holder duties, wait for the unlock, serve nothing until the DEK
  is in memory. No timeout, no plaintext fallback. Does not quit, because a node that cannot unlock
  still has to act as a holder for the others.
- **Below 5 holders:** a reported pre-key state, not an error and not a reduced mode. Services run, no
  key is created, files stay as they are, and the status reports the holder count. At 5 holders the key
  and the migration start on their own. The 5-holder minimum is unchanged.

Both keep dev boxes and CI working, which was the reason the flag existed.

Still open, needs an owner call:

- **One-way upgrade.** A node whose vault state says `encrypted` but whose `data-key.json` is gone is
  unrecoverable, by design. Rollback to the `c382d2d` binary after a completed migration is not
  supported. This is a product decision about the upgrade path, not a security question. It needs a
  decision before release, plus a backup requirement for `data/security/storage/` and `data/sealed/`.
- Resolved: stale `SP_STORAGE_KEY` / `SP_STORAGE_FILES` keys, the JSON keys, and the
  `--storage-key` / `--storage-files` options are **ignored**, not rejected. The config parser is a
  `strcmp` chain with no unknown-option branch, so a unit file that still names them starts normally
  and runs with encryption on. The Tier 1 environment-file contract changes accordingly.
- What the status endpoint shows in the pre-key state.
- Whether the file share store stays the accepted at-rest protection for Tier 2 shares on macOS and
  Linux dev hosts.

Files an implementation touches: `Core/ServerConfig.{hpp,cpp}`, `main.cpp` (delete the flag-off refusal
at lines 144-158, drive deferred file services off `files_ready()`),
`SecurityMeshStartup.{hpp,cpp}`, `SecurityMeshService.{hpp,cpp}`,
`Security/Storage/{StorageVault,DataKeyService,StorageShareStore}.*`, plus `test_security_mesh_service.cpp`,
`test_server_config_discovery.cpp`, `security/lifecycle/storage_key_path.cpp`, and three docs.

Test infrastructure that does not exist yet: a `main.cpp` startup test for the fresh and
pre-seeded-encrypted paths; a 1-4 holder mesh fixture proving the pre-key state and the key appearing at
the fifth holder without a restart; and a mixed-version test of an already-encrypted data directory
coming up on a default-on binary.

## 2. Tier 2 to Tier 1 promotion

The consensus side **already works** and is enforced in code, not convention: eligibility observations →
HotStuff-finalized digest → frozen membership pool → deterministic selector → epoch activation bound to a
consensus certificate. Proven by `tests/security/lifecycle/adoption_path.cpp`. Do not add a direct way to
write Tier 1 membership. There isn't one today; that is the property worth keeping.

Missing pieces:

- **Storage share does not follow promotion.** A promoted node joins Tier 1 but gets no share. The C++
  `StorageOperation` enum has no `Repair`, and nothing calls `repair_share_*`. Blocked on missing
  session and consensus wiring, not on crypto. 5 to 6 holders keeps threshold 4, so the
  rotate-on-threshold-change rule does not fire.
- **"Stable enough" has no data source.** Only attestation continuity and mesh participation are
  consensus-verifiable today. A multi-epoch stability streak needs new instrumentation. Rate-limiter
  stats and tree-log lag are locally observable only, so they are spoofable and must not drive authority.
- **Azure secured-compute VMs do not fit.** Attestation today is local device node and ioctl based,
  with SVSM active. Azure uses a different attestation surface. That is a new profile, transport, trust
  broker, and freshness story — a protocol ruleset change, not a config option. Marked *inferred* in the
  research, so confirm against current Azure docs before planning.
- **Quorum self-inflation.** If existing holders can promote at will, they can grow quorum to
  themselves. Stability criteria delay this, they do not prevent it.

Open questions for the owner, repeated from `Tier1-Promotion-Research.md`:

1. Stability = existing finalized `uptime_valid` and `mesh_health_valid`, or a new streak requirement?
2. Is growth hash-ranked selection from the eligible pool, or an explicit gated "promote node X"?
3. Azure evidence transport and which trust broker is accepted.
4. Accept that criteria delay self-inflation, or add a growth cap or separate promotion quorum?
5. First promotion: wire up `Repair`, or accept a `Rotate`?

## 3. Deploy runbook — storage

**Back up `data/security/storage/` and `data/sealed/` before upgrading any node.** These hold the data
key and the sealed boot set. They are not recoverable if lost — there is no offline recovery key by
design (B8). Include them in the runbook, not just in someone's memory.

**Upgrade one node at a time. Verify it unlocked before starting the next.** Do not run two at once.

Why the strictness: with 5 Tier 1 nodes, `t = ceil(0.65 × n) = 4`. Unlock needs 4 partials, so one
unavailable holder is exactly survivable and two are not. One-at-a-time therefore works, but only if
nothing else goes down during the window. A crash during a rolling upgrade is two nodes down, and that
stops every node that still needs to unlock. Verify-and-wait is what buys the margin back.

Check before you start:

- How many holders are currently up and eligible. If it is already 5 with none spare, fix that first or
  accept the risk knowingly.
- Whether the node you are about to take down is one of the holders the others still need.
- That you have the two backups, and that you have tested reading them back.

Rollback: not supported after a migration completes. This is the one-way part — a node whose vault state
says `encrypted` but has lost its data key cannot be brought back by reinstalling the old binary.
Bring the node up on a test data directory first, or on one production node that you are prepared to
rebuild from scratch.

Holder counts and the margin they give:

| Tier 1 holders | `t` | Unavailable at once | Note |
|---|---|---|---|
| 3 | 2 | 1 | floor; below this no rotation runs |
| 4 | 3 | 1 | |
| 5 | 4 | 1 | **current mesh** — exactly enough, no margin |
| 6 | 4 | 2 | first size with real margin |
| 7 | 5 | 2 | |

If you want margin at 5 nodes, the alternative is not a flag or a timeout, it is more holders. See
section 2.

## 4. Test and CI notes

- **Verification done, no action needed.** Full-suite run of this code: macOS 1944 passed / 0 failed /
  28 skipped; Linux 1976 passed / 2 failed / 4 skipped. The 2 failures are the root artifacts below.
  First completed run; PR #70 merged without one.
- `cargo test` does not run in CI. `crates/storage-threshold` has 35 tests covering DLEQ rejection,
  sub-quorum refresh, and stale-share combination. They passed locally in 8 seconds. Nothing runs them
  automatically, so that result goes stale on the next crate edit.
- `FileStorageTest.UnreadableRecordFileIsIoErrorNotAbsent` and
  `UnscannablePoolDirectoryIsAnErrorNotAnEmptyPool` fail when run as root. Both use `chmod 0` to
  simulate unreadable input, and root bypasses permission checks. Test-design artifact, not a defect.
  CI uses the unprivileged `citest` user, where they behave.
- Running as root makes the two `FileStorageTest` cases above fail for everyone, including anyone
  testing locally with sudo. Worth knowing so it is not read as a regression.

## 5. Housekeeping

- `~/.claude/projects/...-lemonade-nexus/memory/MEMORY.md` is stale and actively misleading. It
  describes `Security/Trust/TrustPolicy*`, `TrustTier`, `is_operation_allowed`, and `TeeAttestationService`
  as current work. **None of that exists in this checkout** — those are the old SecurePunch hardening
  phases, a different numbering from the design doc's Phases 0-7. Real tier machinery lives in
  Epoch, Eligibility, and Attestation. It also still claims "213/213 tests"; the tree has 1972. Fix or
  mark it, otherwise every future run wastes effort on phantom files.
- The plan file `~/.claude/plans/clever-painting-toucan.md` that MEMORY.md points to no longer exists.
- A stray `plan.md` sits at the repo root, left by a research agent. It duplicates
  `docs/Tier1-Promotion-Research.md`. Do not commit it.
- The worktree mixes several separate changes: doc edits, two new docs, and in-progress TLS work across
  `ServerIdentity`, `HttpServer`, `AcmeService`, `main.cpp`, and three test files. Keep those out of one
  commit.

## 6. Environment facts worth keeping

- Build box `10.10.14.116` (`ubuntu@`, passwordless sudo) is a **build server only**: no encrypted
  memory, no vTPM. SEV flags in `/proc/cpuinfo` are host CPU passthrough, not a guest capability. Do
  not plan attestation work on it.
- Production mesh: root `10.10.12.40` (Tier 2, ns1) plus five Tier 1 on `10.10.12.50-.54` (ns2-ns6),
  on LXD host `10.10.12.38`. These are live nameservers and hold the production storage key path.
- Deploy is a manual signed ceremony: build on the build box, generate the approval preimage, owner
  signs, install, re-found. No auto-update.
- Subagent runs are capped by the local inference engine's memory ceiling, not by agent count.
  Fresh-context agents with short briefs fit; forked-context agents inherit the whole session and get
  refused before they start.