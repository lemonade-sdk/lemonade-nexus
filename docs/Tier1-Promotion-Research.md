# Tier 1 Promotion Research

Research only. No code, tests, config, or flags are changed. Every claim is
labeled **[V]** (verified from source in this checkout) or **[I]** (inferred).
Open items that need an owner decision are listed at the end.

The security principles in `AGENTS.md` bind this analysis: identity is not
authority, authority follows finalized state, Genesis is one-shot, evidence
fails closed, and keys have separate roles.

> **Correction to the task brief.** `Security/Trust/TrustPolicy*` does not
> exist. Neither do `TrustTier`, `is_operation_allowed`, `verify_and_update`,
> or `challenge_peer` anywhere in the tree **[V]** (grep, no matches). The
> "tier" concept lives instead in the Epoch + Eligibility + Attestation
> subsystems. All analysis below uses the real symbols.

---

## 1. Where Tier 1 membership authority lives today

**Answer: promotion is already expressible through finalized,
consensus-verifiable state. A finalized path exists and is enforced in code,
not by convention.**

- The per-node "am I Tier 1" answer is `SecurityDriver::is_tier1_member()` →
  `EpochManager::current().tier1_members.contains(self)` **[V]**
  (`src/Security/Lifecycle/SecurityDriver.cpp:157`). It is a read of
  `EpochState`, not a local opinion.
- `EpochState` is immutable after activation: "there are no mutating helpers,
  and membership changes only through the next atomic epoch transition"
  **[V]** (`include/.../Security/Epoch/EpochState.hpp:13`).
- `kEpochMembershipFrozen = true` and
  `kMembershipChangesOnlyAtEpochBoundary = true` **[V]**
  (`include/.../Security/Policy/SecurityConstants.hpp`).
- The selection that populates the next epoch is **pure and deterministic**:
  `Tier1Selector::rank/select` takes a frozen eligible set, the current epoch
  group key, and the next epoch — "no network, no local randomness, no
  operator input, no mutable state" **[V]** (`include/.../Epoch/Tier1Selector.hpp:12`).
  Its seed is `current_epoch_group_key`, fixed before selection, so a
  candidate cannot steer its own score **[V]**.
- The *eligible set* is itself consensus-finalized. `EligibilityService`
  computes an `EligibilityState`, whose digest is "what HotStuff finalizes,"
  and `finalize()` is only called "when consensus committed an eligibility
  commitment" **[V]** (`include/.../Eligibility/EligibilityService.hpp`).
  `frozen_pool()` returns a set only when a finalized state exists AND the
  local recomputation still matches the finalized digest
  **[V]** (`EligibilityService.hpp`, `frozen_pool` doc).
- The full Tier 2→Tier 1 lifecycle is exercised end-to-end in
  `tests/security/lifecycle/adoption_path.cpp`: observe → finalize → plan
  commits → candidate enters `PendingNextEpoch` (no authority yet) → final
  attest → DKG with the candidate → handoff commits → epoch activates and the
  candidate `is_tier1_member()` becomes true **[V]**.

So the owner's ask ("promote a stable Tier 2 node to Tier 1") is **not a new
authority path to invent** — it is the existing epoch-boundary selection,
gated by the eligibility policy. What is *missing* is (a) a "stability"
predicate, and (b) a platform floor (see Q3, Q5).

---

## 2. Does the codebase honour "identity is not authority"?

Largely yes, enforced in code. The enforcing checks:

- **Certificate alone ≠ Tier 1.** `certificate_valid` is only *one* of
  fifteen prerequisites in `Tier1EvidenceState`; `Tier1EligibilityPolicy`
  is a strict conjunction with "no override, no score, and no vote"
  **[V]** (`include/.../Policy/Tier1Eligibility.hpp:11`). A root-signed cert
  without platform + uptime + mesh-health facts cannot pass.
- **Healthy / authenticated peer ≠ Tier 1.** `ParticipationProof` and the
  participation observation carry "no field here is a health score"
  **[V]** (`EligibilityService.hpp`, `ParticipationProof` doc). A vote proves
  synchronization, not eligibility.
- **A node never attests itself.** "A candidate cannot say how long it has
  been up ... the members that watched it say so, each signs its own
  statement, and a quorum of them is what makes a fact" **[V]**
  (`include/.../Eligibility/EligibilityObservation.hpp:5`). A
  `SelfObservation` is an explicit refusal
  **[[V]]** (`EligibilityLedger.hpp`, `ObservationOutcome`).
- **Local config cannot mint Tier 1.** `tier1_membership_` is a callback set
  by the mesh; unset "denies tier1 labels" **[V]** (`Gossip/GossipService.hpp:663`).
- **Evidence fails closed.** Every prerequisite defaults to false;
  "evidence that was never collected is failed evidence" **[V]**
  (`Tier1Eligibility.hpp:6`). A provider cannot express a mesh fact even by
  mistake because `VerifiedPlatformClaims` has no field for them **[V]**
  (`Tier1Evidence.hpp`, `Tier1MeshFacts` doc).

**Convention-only spot (reporting, not a defect):** `GossipService::is_tier1`
reads the `tier1_membership_` callback; whether the *backbone* is protected
relies on the caller having wired a finalized-state source. If a caller sets a
source that is not actually consensus-finalized, gossip trusts it. The wire
itself is fine — it is a trust boundary placed by the caller
**[I]** (`GossipService.cpp:3580`).

---

## 3. Candidate stability criteria ("stable enough")

The code's own definition of continuity is epoch-bounded, not wall-clock:
"Nothing here carries a wall-clock time ... continuity is measured in protocol
state ... the epoch the observation belongs to, and the quorum-certified height
the observer held" **[V]** (`EligibilityObservation.hpp:12`).
`uptime_valid` is *mesh-observed*: same incarnation + ≥2 attestations + an
interval ≥ `kReattestIntervalSeconds` (900 s), proven by a witness threshold of
the current committee **[V]** (`Tier1Evidence.hpp`, `SecurityConstants.hpp`).

For each criterion below: **Collectible now?** and **Tamper-evident &
consensus-verifiable?** Only the latter may drive authority.

| # | Criterion | Collectible today? | Consensus-verifiable? | Notes |
|---|-----------|--------------------|-----------------------|-------|
| A | **Attestation freshness / continuity** — ≥ `kMinContinuityObservations`(2) distinct verified attestations, same incarnation | **Yes** — already computed as `uptime_valid` | **Yes** — it is one of the two mesh facts in the finalized `EligibilityState` digest **[V]** | This *is* the existing "stable" signal. |
| B | **Mesh participation (mesh_health_valid)** — witness threshold saw the node alive/authenticated, current network/epoch/incarnation/rulesets, no unresolved fault | **Yes** — computed as `mesh_health_valid` | **Yes** — second mesh fact in the finalized digest **[V]** | Also already finalized. |
| C | **Passing-attestation duration** (how long a node has held a passing verdict) | **Partially** — `verdicts_` map is per-epoch; `kObservationValidityEpochs = 1` drops prior epochs **[V]** (`SecurityConstants.hpp`) | **No, as-is** — the ledger is epoch-scoped, so "N epochs of passing" is not currently recorded | **New instrumentation** to count consecutive qualifying epochs. |
| D | **Peer-liveness horizon** (`expire_stale_peers`) | **No** — no such function exists in the tree **[V]** (grep) | Unknown — would be locally observable | **New instrumentation + consensus path required.** |
| E | **Rate-limiter / replay-cache stats** | **No** — `kSecurityPeerMessagesPerWindow`, `kSecurityDedupeWindow` are enforcement limits, not published per-peer counters **[V]** (`SecurityConstants.hpp`) | **No** — these are local router state | Local observation is spoofable; cannot drive authority without a consensus-committed fault record. |
| F | **Tree-log replication lag** | **No** — gossip tracks catch-up status but no lag metric is recorded or signed **[V]** (grep of `Gossip/GossipService.hpp`) | **No** as-is | Local observation. |
| G | **QC verification failures** | **Partially** — `ObjectiveFault::InvalidConsensusBehavior` / `Equivocation` are a fault *enum* and can be recorded via `record_fault` **[V]** (`EligibilityObservation.hpp`, `EligibilityService.hpp`) | **Yes** — a recorded fault is a bit in the finalized digest and "denies mesh health for the rest of the epoch" **[V]** (`EligibilityLedger.hpp`) | The fault *record* is consensus-verifiable; who detects the fault today is the gap. |
| H | **Objective faults (duplication/incarnation equivocation)** | **Yes** — the bit is in the finalized `EligibilityState` | **Yes** | Already consensus-verifiable. |

**Bottom line:** the two facts that are *already* consensus-verifiable —
**(A) attestation continuity** and **(B) mesh participation** — are the safe
stability basis. Criteria C, D, E, F need new instrumentation and, critically, a
path into the finalized digest (a signed, quorum-witnessed fault/observation),
otherwise they are locally-observable and spoofable and must not drive
authority **[I]**. This matches the design intent: "a peer-supplied timestamp
is a value an adversary chooses, so continuity is measured in protocol state
instead" **[V]**.

---

## 4. Can `repair_share_*` enroll a new holder at unchanged threshold?

**Yes, in the crate — but it is not wired into the C++ storage service, and a
5→6 promotion changes the threshold, so it does *not* apply.**

- `repair_part1/2/3` exist and are correct at the same threshold. `repair_part1`
  requires `new_holder` not already in `plan` and `helpers ≥ t`; `repair_part3`
  requires `sigmas ≥ t` and checks the result against the interpolated
  commitment **[V]** (`crates/storage-threshold/src/keys.rs:364–475`).
  FFI: `storage_repair_part1/2/3` **[V]** (`crates/storage-threshold/src/ffi.rs:392–460`).
  C++ wrappers: `StorageThreshold::repair_part1/2/3`
  **[V]** (`src/Crypto/StorageThreshold.cpp:401–443`).
- **No production caller.** The only callers of the C++ wrappers are tests
  (`tests/test_storage_threshold.cpp`) **[V]** (grep). `StorageKeyService`
  never calls them. The design doc itself flags this: "not called directly by
  `StorageKeyService` on this branch — the enrollment session runs inside the
  DKG session machinery; confirm the current C++ call site before relying on
  it" **[V]** (`docs/B3-Review-Package.md:127`). **The confirmation: there is
  no production call site.**
- **Holder-count bounds:** `MIN_HOLDERS = 5`, `MIN_RESHARE_HOLDERS = 3`,
  `MAX_HOLDERS = 50` **[V]** (`crates/storage-threshold/src/params.rs`).
- **Threshold formula:** `t = ceil(0.65 × n)` **[V]** (`params.rs::threshold_for`).
  - `n = 5 → t = 4`; **`n = 6 → t = 4`** (ceil(3.9) = 4).
- **So a 5→6 promotion keeps `t = 4`.** That means the "rotate rather than
  re-share when the threshold changes" rule is **not** triggered: 5→6 is the
  *same-threshold* case and the design says "a new holder is enrolled through
  share repair. No file and no data key changes" **[V]**
  (`docs/Design-Tree-Consensus-and-Storage-Key.md:411`). If the holder set went
  5→8 (t = 6) the rule would force a rotation (new `S`, rewrap data keys)
  **[V]** (`Design-...:416`, `StorageRecords.cpp::reshare` returns `Rotate`
  when `*t != state.current->threshold`).
- **What actually blocks it:** the C++ selection only ever emits
  `Create / Refresh / Rotate` — there is **no `Repair` operation**
  **[V]** (`include/.../Storage/StorageRecords.hpp:44`,
  `StorageRecords.cpp::reshare`). A same-threshold holder *addition* today can
  only happen via a `Rotate` (full key generation). The `repair_*` primitives
  are ready but the consensus/session state machine does not schedule them.
- **What else a 5→6 promotion touches:** consensus quorum (`consensus_quorum(6)
  = 5` **[V]** static_assert), authority threshold (`authority_threshold(6) = 5`,
  unchanged from 5 **[V]**), a fresh FROST DKG for the new epoch group key,
  new per-member BFT vote keys, and the sealed-share store gains a 6th holder's
  commitment in the new plan.

**Net:** `repair_share` *could* do the storage-share half of a 5→6 promotion at
no threshold change, but (a) nothing in `src/` drives it, and (b) it is
separate from the *consensus* promotion, which is governed by the epoch
eligibility/selection machinery of Q1. Do not conflate the two.

---

## 5. Is an Azure secured-compute VM supportable?

**Verdict: it does *not* fit the existing profile machinery as-is. It needs a
new attestation profile, a new evidence transport/trust broker, and a
freshness/replay story. "Also confidential compute" is not free integration.**

**[V] from source:**
- The only *active* Tier 1 profile is `kTier1AttestationProfileId =
  AttestationProfileId::SnpSvsmVtpm` **[V]**
  (`include/.../Attestation/AttestationProfileId.hpp`). `AzureSnpVtpm = 1`
  exists as an enum value and `PlatformEvidence` includes a
  `SnpVtpmEvidence` (helper named `azure_evidence`) — but the **active**
  profile is the SVSM one, and the profile ID "names WHICH evidence format and
  provider examine a candidate ... an unknown ID has no provider and fails
  closed" **[V]** (`AttestationProfileId.hpp:7`).
- All existing evidence is **device-node / ioctl based against a local TEE**:
  `/dev/sev-guest`, `/dev/tdx-guest`, `/dev/sgx_enclave`, Apple Secure Enclave,
  and TPM via `Esys_*` (FAPI) **[V]** (`src/Security/PlatformProbe.cpp`,
  `TpmQuote.cpp`). There is no HTTP/RP attestation path.
- The prover is a narrow local daemon (`nexus-attestd`) reached over a local
  socket: "turns one fully-formed AttestationChallenge into one
  hardware-backed AttestationEvidence and does nothing else" **[V]**
  (`projects/LemonadeNexusAttestd/include/.../AttestdGate.hpp`).
- Evidence is a bounded wire blob (`kMaxPlatformEvidenceWireBytes = 56 KiB`)
  transferred over the mesh security plane **[V]** (`SecurityConstants.hpp`).

**[I] inference (Azure differs structurally):**
- An Azure secured-compute VM (SEV-SNP/Azure confidential VM, or a
  confidential VM using vTPM attestation) typically exposes attestation through
  a **TPM attestation report** and/or the **Azure Attestation (AA) service**,
  with a **trust broker** (a remote attestation authority) that vouches for the
  TCB — not through a guest-local `/dev/sev-guest` ioctl the verifier can read
  directly. *(Azure Attestation docs describe a remote attestation authority
  issuing signed endorsements; confirm against current upstream docs.)*
- That means a new profile would need: a new `AttestationProfileId`, a new
  evidence type in the `PlatformEvidence` variant, a new **transport** (call to
  the AA service, or a vTPM report + AA endorsement), a **trust-broker trust
  anchor** (AA root/intermediate certs — a new trust decision), and a
  **freshness/replay** story (nonce binding to the AA challenge, report
  expiration). The existing freshness machinery is
  `kReattestIntervalSeconds` / challenge-nonce bound to the *mesh* plane, not to
  a third-party attestation authority **[I]**.

**Verified vs inferred:** verified that the current profiles are local-device
based and that only SVSM is active; *inferred* (needs the owner to confirm
against current Azure docs) that Azure's model requires a broker/transport that
the code has none of. This is a **new attestation profile + provider**, a ruleset
bump (which "invalidates every outstanding challenge"
**[V]** `AttestationProfileId.hpp:50`), and a new trust anchor — i.e. a
security-protocol change, not a config flag.

---

## 6. Hazards

**(a) The admin-shortcut-to-mint-Tier-1 vector — where it must be blocked.**
The promotion path is `EligibilityService::finalize()` → `frozen_pool()` →
`Tier1Selector` → `EpochManager::prepare_next_epoch` → `activate_next_epoch`.
A shortcut would appear as: (1) an operator-injected eligible set or a
`certificate_source_` / observation that bypasses the witness threshold; or
(2) a `record_handoff_authorization`/`activate_next_epoch` call not bound to a
real HotStuff certificate digest. **Block points:** `frozen_pool` already
requires the local recomputation to match the finalized digest
**[V]**; keep it that way. `record_handoff_authorization` takes a
`consensus_certificate_digest` **[V]** (`EpochManager.hpp`) — any new "promote
this node" API must not write directly into `EpochState.tier1_members` (which
has no mutating helper today) nor accept a non-consensus digest. The `Repair`
gap in the storage layer (Q4) is a second place a "just add this holder"
shortcut could hide **[I]**.

**(b) Genesis unilateral authority must not be restored.**
`GenesisService::finalize_epoch_one` sets `finalized_ = true` — "Genesis
unilateral authority ends here, permanently" **[V]**
(`src/Security/Genesis/GenesisService.cpp:221`). `restore_finalized()` is
only reachable while that genesis node is still the founding key and only
replays the *already-agreed* founding eligibility, not a re-mint
**[V]**. Any promotion code must not call back into the genesis path, and a
restarted node "must reach finality again through the mesh, never read it off
its own disk" **[V]** (`EligibilityService::enter_epoch` doc).

**(c) Colluding-majority / quorum inflation.**
The derived criteria **delay** but do not *by themselves* prevent it. Because
the eligible set is finalized by a *full HotStuff quorum* and selection is
hash-ranked off the current epoch group key, a colluding quorum can only
promote nodes it can *observe as passing* (criteria A/B are quorum-witnessed).
If the current holders can make a fake node "pass" attestation + participation,
they could inflate the set at the boundary — which then also raises
`consensus_quorum(N)` in their favor. The defense is that attestation is
hardware-bound and self-attestation is refused, so a fake Tier-1 needs real
attested TEE hardware **[I]**. This is a **trust-model** limit the derived
stability criteria do not close; it needs an explicit owner decision (e.g.
whether population growth itself is quorum-gated by an independent rule, or
whether reserve/rank ordering is enough).

**(d) The "old authority still valid" window — `StorageKeyService::live_plan`.**
`live_plan` returns the *current* plan or, if `retiring_live()`, the *retiring*
plan inside its grace window (`kStorageGraceEpochs = 1`)
**[V]** (`StorageKeyService.cpp:1165`, `retiring_live` `:225`). A promotion that
adds a holder and produces a new plan extends exactly this dual-plan window.
**Test coverage: `live_plan` has zero direct unit tests** **[V]** (grep of
`tests/**` → no matches for `live_plan`). The grace-period *behavior* is covered
by `tests/security/lifecycle/storage_key_path.cpp::DailyRotationCatchUpAndTheGracePeriod`
and `tests/security/storage/records.cpp` (rotation/catch-up paths), but the
grace window in a **promotion/holder-add** (not daily-rotation) scenario is not
covered **[V]**. Any promotion change must add a test that the retiring plan
stops unwrapping exactly after `kStorageGraceEpochs` and that no plan outside
{current, retiring-in-grace} is honored.

---

## Open questions needing an owner decision

1. **Stability definition:** Is "stable" the existing
   `uptime_valid ∧ mesh_health_valid` (already consensus-finalized), or does the
   owner want a *multi-epoch* passing streak (criterion C), which requires new
   consensus-verifiable instrumentation? Decide before any implementation.
2. **Population growth rule:** Is adding a Tier 1 holder purely a
   hash-ranked selection from the finalized eligible pool (current design), or
   does the owner want an explicit, separately-gated "promote node X" consensus
   operation? The latter is a new authority surface and needs its own
   trust-model review.
3. **Azure platform floor:** Confirm against current Azure Attestation docs
   the exact evidence/transport model the owner requires (AA service vs vTPM
   report, which trust broker/root is accepted). This decides whether it is a
   new profile + provider + trust anchor (a ruleset change) — and is therefore
   a security-protocol change requiring a migration + validation plan.
4. **Colluding-majority bound:** Accept that derived stability criteria delay
   (not eliminate) self-inflating promotion, or add an independent rule
   (reserve ordering / max-growth-per-epoch / separate promotion quorum)?
5. **5→6 storage-share path:** Use `repair_share_*` (ready but unwired; needs a
   new `Repair` consensus operation + session), or accept a `Rotate` (full key
   generation, rewrap data keys) as the simpler path for the first promotion?

*Report: a finalized-state promotion authority **exists** (epoch-boundary
Eligibility→Selection→Activation, enforced in code — Q1). Top stability signals
collectible now: attestation continuity (A) and mesh participation (B), both
already consensus-finalized; C needs new instrumentation. `repair_share_*` can
enroll at unchanged t (5→6 keeps t=4) but has no production caller and the C++
state machine has no Repair operation — blocked by design, not crypto. Azure
does not fit the current local-device profile machinery (needs new
profile/transport/trust-broker/freshness). Most dangerous failure mode: an
admin shortcut that writes `EpochState.tier1_members` or a non-consensus
handoff digest to mint Tier 1 (Q6a). Open items 1–5 need a human decision.*
