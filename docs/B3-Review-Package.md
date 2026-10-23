# B3 External-Review Package — Threshold Storage Key

**Status:** preparation artifact only. This document and the internal analysis
in it do **not** constitute external review. `storage_key_enabled` and
`storage_files_enabled` stay **off** until a real external review of the
unaudited library paths is commissioned, performed by an independent vendor,
and its findings are resolved. `AGENTS.md` forbids treating internal analysis,
simulated tests, or a passing `ctest` as that evidence.

**Repo checkout:** branch `storage-dek-phase7`.

**Crate under review:** `crates/storage-threshold/` (`lemonade-storage-threshold`),
a Rust staticlib + rlib with a C ABI consumed by
`projects/LemonadeNexus/src/Crypto/StorageThreshold.cpp`.

## 1. Scope

Out of scope for this review: the audited FROST dealerless DKG
(`frost::keys::dkg::*`) and the audited Lagrange-coefficient helper
(`frost_core::compute_lagrange_coefficient`). The NCC Group audit of
`frost` v0.6.0 does not cover the paths listed below, and the version
currently locked in this repository is 2.2.0. Treat everything the crate
wraps as unaudited until the vendor completes review.

In scope, three protocol paths in three libraries:

1. Share refresh and holder removal (`frost::keys::refresh::refresh_dkg_*`)
   in `frost-ristretto255` 2.2.0.
2. New-holder enrollment at the same threshold
   (`frost::keys::repairable::repair_share_step_*`) in `frost-ristretto255`
   2.2.0.
3. Chaum–Pedersen (DLEQ) proof attached to every unlock partial
   (`elastic_elgamal::LogEqualityProof`) in `elastic-elgamal` 0.3.1.

Also in scope, and adjacent to the paths above, are the crate's own glue
modules (`plan.rs`, `unlock.rs`, `keys.rs`, `ffi.rs`, `wrap.rs`,
`params.rs`) because they are the only code between the C++ service and the
unaudited libraries. Any of the crate's own code being wrong is a
first-order review target, not a secondary one.

## 2. Locked versions (verify against the lockfile before review)

| Crate | Locked version | Pinned in Cargo.toml |
|---|---|---|
| `frost-ristretto255` | 2.2.0 | `=2.2.0` |
| `frost-core` (with feature `internals`) | 2.2.0 | `=2.2.0` |
| `frost-rerandomized` (transitive) | 2.2.0 | — |
| `elastic-elgamal` (features `std`, `curve25519-dalek`) | 0.3.1 | `=0.3.1` |
| `curve25519-dalek` | 4.1.3 | `=4.1.3` |
| `merlin` | 3.x | `3` |
| `rand_core` (feature `getrandom`) | 0.6.x | `0.6` |
| `zeroize` | 1.x | `1` |

Source: `crates/storage-threshold/Cargo.toml` and
`crates/storage-threshold/Cargo.lock`. Both the `lemonade-storage-threshold`
crate and the FROST FFI crate (`crates/frost-ffi/Cargo.toml`) pin
`frost-ed25519 = "=2.2.0"` and `frost-ristretto255 = "=2.2.0"` at the same
lockfile version. The two `frost-*` crates therefore ship the same version,
but **that version is not the version the NCC Group audit covered** (see
§3).

The design document
(`docs/Design-Tree-Consensus-and-Storage-Key.md`, section B3) states that
the FROST row is "pinned to the same version as `frost-ed25519` (2.2.0)" and
cites "NCC Group, 2023-10-23 (v0.6.0)". The pin is correct; the audit
citation is not. The audit covers `frost` v0.6.0; the repository ships
2.2.0. The rows marked "Audited" in the design document do not describe the
shipped code. The vendor must review the 2.2.0 code as if it were
unaudited, or produce a mapping showing that the 2.2.0 code is functionally
equivalent to the 0.6.0 code that was audited. This is a factual correction,
not a recommendation to downgrade the audit claim; the shipped code is
2.2.0 and the audit does not cover it.

## 3. What the NCC Group audit does and does not cover

- **Audited (v0.6.0):** the FROST dealerless key-generation protocol
  (three-round DKG) and, in that version, the Lagrange-coefficient helper.
  The audit predates both the 2.2.0 release and the `internals` feature
  surface that this repository uses to reach `frost::keys::refresh` and
  `frost::keys::repairable`.
- **Not audited (any version):**
  - `frost::keys::refresh::refresh_dkg_part1/2`,
    `refresh::refresh_dkg_shares` — share refresh, holder removal.
  - `frost::keys::repairable::repair_share_step_1/2/3` — new-holder
    enrollment (share repair).
  - `elastic-elgamal::LogEqualityProof` (Chaum–Pedersen DLEQ) — the proof
    attached to every unlock partial.
  - Any of the code in this repository's crate (the FFI boundary, the
    plan checks, the transcript construction, the combiner, the ECIES
    wrapper, the threshold arithmetic in `params.rs`).

The vendor should treat the two rows in the design document's B3 table that
say "Audited" as **unaudited in the shipped version**.

## 4. Target paths — exact call sites

### 4.1 `frost-ristretto255` `refresh_dkg_*`

| Operation | Rust call site | C ABI | C++ call site |
|---|---|---|---|
| Part 1 (round-1 broadcast) | `crates/storage-threshold/src/keys.rs:244` (`refresh::refresh_dkg_part1`) | `crates/storage-threshold/src/ffi.rs:298` (`storage_refresh_part1`) | `projects/LemonadeNexus/src/Security/Storage/StorageKeyService.cpp:757` (`StorageThreshold::refresh_part1`, case `StorageOperation::Refresh` in `start_round1`) |
| Part 2 (pairwise secret packages) | `crates/storage-threshold/src/keys.rs:265` (`refresh::refresh_dkg_part2`) | `crates/storage-threshold/src/ffi.rs:321` (`storage_refresh_part2`) | `StorageKeyService.cpp:848` (`StorageThreshold::refresh_part2`, inside `maybe_round2`) |
| Part 3 (share + new plan) | `crates/storage-threshold/src/keys.rs:349` (`refresh::refresh_dkg_shares`) | `crates/storage-threshold/src/ffi.rs:354` (`storage_refresh_part3`) | `StorageKeyService.cpp:935` (`StorageThreshold::refresh_part3`, inside `maybe_finish`) |

Protocol operation this enables: same-`t` re-share (design B5). A refresh
keeps `S` and `t`, retires pre-refresh shares, and drops removed holders.
The crate enforces that at least `t_old` old holders contribute
(`keys.rs:235` — `if old_holders < t` → `StorageError::BelowThreshold`);
below that, a bad refresh cannot succeed. The design's "no-dealer" property
depends on this check plus the fact that `refresh_dkg_shares` uses the
round-1 packages of *all* participants (see `keys.rs:228` — participants
must match `state.holder_count`).

What a flaw in this path would enable: a malicious holder set below
`t_old`, or a holder that equivocates round 1, could push a new plan whose
share commitments do not lie on the same polynomial as the old plan, so
that `S` effectively changes or the effective threshold changes. A holder
that removes itself from the round-1 set and lets a colluding minority
finish part 3 could produce a share that combines with an old pre-refresh
share, breaking the "attacker must collect 65% within one epoch" property
of B5.

### 4.2 `frost-ristretto255` `repair_share_step_*`

| Operation | Rust call site | C ABI | C++ call site |
|---|---|---|---|
| Step 1 (helper's delta, one per helper) | `crates/storage-threshold/src/keys.rs:395` (`repairable::repair_share_step_1`) | `crates/storage-threshold/src/ffi.rs:392` (`storage_repair_part1`) | `projects/LemonadeNexus/src/Crypto/StorageThreshold.cpp:401` (`StorageThreshold::repair_part1`); not called directly by `StorageKeyService` on this branch — the enrollment session runs inside the DKG session machinery; confirm the current C++ call site before relying on it |
| Step 2 (helper's sigma) | `crates/storage-threshold/src/keys.rs:421` (`repairable::repair_share_step_2`) | `crates/storage-threshold/src/ffi.rs:425` (`storage_repair_part2`) | `projects/LemonadeNexus/src/Crypto/StorageThreshold.cpp:418` (`StorageThreshold::repair_part2`) |
| Step 3 (new holder assembles share) | `crates/storage-threshold/src/keys.rs:444` (`repairable::repair_share_step_3`) | `crates/storage-threshold/src/ffi.rs:447` (`storage_repair_part3`) | `projects/LemonadeNexus/src/Crypto/StorageThreshold.cpp:433` (`StorageThreshold::repair_part3`) |

Protocol operation: enrolling a new holder at the same threshold (design
B5). The new holder's commitment is interpolated from the plan by
`Plan::interpolate_share` (`plan.rs:132`); fewer than `t` honest helpers
cannot push the interpolated commitment off the polynomial, because
`Share::from_key_package` checks `s·G == commitment` (`keys.rs:75`) and
`repair_part3` checks `sigmas.len() >= t` (`keys.rs:372`).

What a flaw would enable: if `repair_share_step_3` accepts a sigma set
whose sum is not on the polynomial (e.g. a bug in the Lagrange
reconstruction inside the library), a new holder could obtain a share that
does not satisfy `Y_i = s_i·G` for the plan's polynomial, and that share
would combine with other holders' shares to reconstruct a wrong value.
The crate's own check (`from_key_package`) catches the case where the
repaired `s_i` and the plan's `Y_i` disagree, but only after
`repair_share_step_3` returns. The vendor should confirm that
`repair_share_step_3` is internally consistent with the interpolated
commitment.

### 4.3 `elastic-elgamal` 0.3.1 `LogEqualityProof`

| Operation | Rust call site | C ABI | C++ call site |
|---|---|---|---|
| Holder creates partial + proof | `crates/storage-threshold/src/unlock.rs:91` (`LogEqualityProof::new`) | `crates/storage-threshold/src/ffi.rs:475` (`storage_partial_create`) | `projects/LemonadeNexus/src/Security/Storage/StorageKeyService.cpp:1185` (`StorageThreshold::create_partial`, in `own_partial`) |
| Requester verifies one partial | `crates/storage-threshold/src/unlock.rs:130-133` (`LogEqualityProof::from_bytes` + `.verify`) | `crates/storage-threshold/src/ffi.rs:501` (`storage_partial_verify`) | `projects/LemonadeNexus/src/Security/Storage/DataKeyService.cpp:519` (`StorageThreshold::verify_partial`, in `DataKeyService::on_partial`) |
| Requester verifies + combines `t` partials | `crates/storage-threshold/src/unlock.rs:147` (`unlock::combine`, which calls `verify_partial` per partial) | `crates/storage-threshold/src/ffi.rs:528` (`storage_combine`) | `projects/LemonadeNexus/src/Crypto/StorageThreshold.cpp:503` (`StorageThreshold::unwrap_data_key`, which calls `storage_combine`) |

Protocol operation: the Chaum–Pedersen DLEQ proof that `log_G(Y_i) ==
log_R(P_i)`. Without it, a holder could submit `P_i` from a different
scalar than its committed `s_i`, and the Lagrange combination would
reconstruct a wrong shared point and therefore a wrong data key.

**How a failed DLEQ blocks the combine step.** Verified from the C++
side, a bad proof **does** block the combine step and is not logged and
skipped:

- `DataKeyService::on_partial`
  (`projects/LemonadeNexus/src/Security/Storage/DataKeyService.cpp:519`)
  calls `StorageThreshold::verify_partial` on every incoming partial. If
  the return value is not `Ok`, the function returns before adding the
  partial to `attempt_->partials`. A failed partial is dropped, not
  counted, and `finish_attempt` (line 533) only proceeds when
  `attempt_->partials.size() >= plan.threshold`.
- `StorageThreshold::unwrap_data_key`
  (`projects/LemonadeNexus/src/Crypto/StorageThreshold.cpp:503`) calls
  `storage_combine`, which in turn calls
  `unlock::combine` (`unlock.rs:147`). That function verifies every
  partial in the map it is handed and returns
  `StorageError::Proof` on the first failure. There is no code path that
  skips a failing partial.
- Therefore, an unlock attempt fails closed when fewer than `t` partials
  pass DLEQ verification. A single bad partial among `t` good ones
  prevents the combine.

The DLEQ is bound to `network_id`, `epoch`, `plan_digest`,
`request_nonce`, `S`, the holder id, and the ephemeral point `R` via a
merlin transcript (`unlock.rs:47`). Tests
(`crates/storage-threshold/src/tests.rs:326`
`proof_bound_to_request_context`;
`tests/test_storage_threshold.cpp::PartialBoundToRequestNonceAndEpoch`)
confirm that flipping any of those fields fails verification. This is
consistent with the project's "evidence fails closed" rule, but the
closure is only as strong as the DLEQ primitive itself, which the NCC
Group audit does not cover.

## 5. Trust-model invariants a vendor should attack

These are the invariants the design depends on; a review should look for
any code path, in the audited or unaudited libraries, that violates them.

1. **Quorum (B4).** At most 50 holders; `t = ceil(0.65·n)`; at least 5 for
   the first key; at least 3 for a refresh or rotation. The crate
   enforces this in `params.rs` (`MIN_HOLDERS = 5`,
   `MIN_RESHARE_HOLDERS = 3`, `MAX_HOLDERS = 50`). Any path that accepts
   a `holder_count` outside the bound is a defect. The C++ side
   additionally enforces `t` via `validate_plan` and `refresh_part1`.

2. **No-dealer property.** No single holder or external party can push
   the plan to a state that is not on the original polynomial. Key
   generation is dealerless by construction in FROST DKG; refresh and
   repair are dealerless only if the crate's `t_old` quorum check and the
   library's internal checks together prevent a malicious minority from
   completing part 3. The vendor should specifically check
   `refresh_dkg_shares` for a path where a round-1 package set that does
   not include every participant still succeeds, and
   `repair_share_step_3` for a path where a sigma set that is not on the
   polynomial still produces a share that passes `from_key_package`.

3. **Epoch / plan binding.** Every partial, delta, and sigma is bound to
   a specific finalized plan via `plan_digest` (for partials, in the
   merlin transcript) or via the plan bytes (for deltas and sigmas, which
   travel over encrypted pairwise channels). A stale share combined with a
   fresh one must not combine. `Share::check_in_plan`
   (`keys.rs:108`) and `Plan::validate` (`plan.rs:117`) are the first
   line of defense; the crate's own tests
   (`refresh_keeps_key_and_retires_old_shares`,
   `refresh_removes_a_holder`, `enrollment_replaces_a_lost_holder`)
   exercise the failure modes.

4. **Share-refresh ordering.** A pre-refresh share cannot produce a
   partial for a post-refresh plan, and a pre-refresh partial does not
   verify against a post-refresh plan. This is enforced by
   `Share::check_in_plan` at `create_partial` time and by
   `verify_partial` at combine time. The vendor should check whether
   `create_partial` or `verify_partial` can be tricked into accepting a
   stale partial by swapping the plan bytes at verification time.

5. **DLEQ verification.** A failed DLEQ must block the combine step.
   See §4.3. The vendor should also check whether a DLEQ that is valid
   but constructed for a different `(Y_i, P_i)` pair (e.g. for a
   different `R`) can be replayed into a combine. The merlin transcript
   binding is the defense; the tests cover nonce, epoch, network, and
   `R` substitution but the vendor should confirm the transcript covers
   every field the design says it does.

6. **Secret destruction.** Every share, delta, sigma, and round-2 package
   is `zeroize`d on drop (`keys.rs`, `unlock.rs`). The C ABI frees
   buffers with `storage_buffer_free` / `storage_peer_buffers_free`,
   which zeroize then free (`ffi.rs:717-745`). The vendor should check
   that no code path retains a raw pointer to a secret after the owning
   `Share` or `Zeroizing` is dropped.

7. **Panics do not cross the C ABI.** Every `#[no_mangle] pub unsafe
   extern "C" fn` in `crates/storage-threshold/src/ffi.rs` either calls
   the `guard(|| …)` wrapper (which uses `catch_unwind`) or is a free
   function that wraps its body in `catch_unwind`. `catch_unwind` is used
   at:
   - `ffi.rs:79` (the `guard` function), which every fallible entry
     point goes through;
   - `ffi.rs:725` (`storage_buffer_free`);
   - `ffi.rs:740` (`storage_peer_buffers_free`);
   - `ffi.rs:760` (the `handle_free!` macro, applied to all
     `*_free` entry points).
   The `frost-ffi` crate uses the same pattern at
   `crates/frost-ffi/src/lib.rs:103`. This satisfies the `AGENTS.md`
   rule that panics never cross an FFI boundary. The vendor should
   confirm that no `no_mangle` symbol exists that is not wrapped.

## 6. Test-gap analysis

### 6.1 `cargo test` in the crate

Command: `cd crates/storage-threshold && cargo test`.
Result on this checkout (branch `storage-dek-phase7`, 2026-02-12):
**35 passed, 0 failed, 1 ignored.** The one ignored test is
`key_generation_every_holder_count_exact_threshold`, which is a long
sweep and is `#[ignore]`d by design.

The crate's tests (`crates/storage-threshold/src/tests.rs`, plus
`params::tests` and the FFI inline tests in `ffi.rs`) cover:

- DLEQ rejection: `invalid_dleq_partial`, `partial_for_a_different_r`,
  `proof_bound_to_request_context`, `malformed_points_rejected`.
  **Covered.**
- Refresh below `t_old`: `refresh_with_fewer_than_t_old_holders`
  (expects `StorageError::BelowThreshold`). **Covered.**
- Repair contributed by fewer than `t` helpers:
  `enrollment_with_fewer_than_t_helpers` (expects
  `StorageError::BelowThreshold` at both `repair_part1` and
  `repair_part3`). **Covered.**
- Stale share combined with a fresh one:
  `refresh_keeps_key_and_retires_old_shares` (a pre-refresh partial does
  not verify against the post-refresh plan),
  `refresh_removes_a_holder`, `refresh_at_four_and_three_holders`.
  **Covered.**
- Old `S` used after its grace period: **not covered at the crate
  level.** The grace-period logic lives in the C++ service
  (`StorageKeyService::live_plan`, which returns `nullptr` for a
  retiring plan outside its grace window, at
  `StorageKeyService.cpp:1211`), and the crate has no concept of time
  or grace periods. The C++ CTest case does not exercise the grace
  boundary either; it tests the crate through the C ABI with a fixed
  `UnlockContext` that has a fixed `epoch` field. This is a real gap:
  no test verifies that a partial created for a retiring plan is
  rejected once the grace period has passed.
- Threshold change requiring rotation: `threshold_change_requires_rotation`,
  `shrinking_changes_the_threshold_and_needs_rotation`. **Covered.**
- Tampered sigma in repair: `enrollment_with_a_tampered_sigma`.
  **Covered.**
- Malformed inputs: `malformed_share_and_plan_bytes`,
  `inconsistent_plan_fails_validation`, `first_key_needs_five_holders`,
  `key_generation_rejects_out_of_range_counts`,
  `rotation_rejects_out_of_range_counts`. **Covered.**

### 6.2 What is not exercised by the crate tests

- **Grace-period expiry of a retiring `S`.** As above: no crate test,
  no CTest case exercises the boundary where a retiring plan stops being
  accepted.
- **A DLEQ proof that is internally inconsistent but still passes
  `LogEqualityProof::verify`** (i.e. a bug in the `elastic-elgamal`
  library itself). The crate tests verify the wrapper logic; they cannot
  detect a bug in the underlying DLEQ verification.
- **A refresh where `refresh_dkg_shares` succeeds on a round-1 set that
  does not include every participant.** The crate's `refresh_part3`
  checks that the participant set matches `state.holder_count`
  (`keys.rs:232`), but the library-internal check in
  `refresh_dkg_shares` is not directly tested.
- **A repair where `repair_share_step_3` returns a share that does not
  lie on the plan's polynomial but still passes
  `Share::from_key_package`** (a bug in the library's Lagrange
  reconstruction). The crate test
  `enrollment_with_a_tampered_sigma` tampers a sigma *before*
  `repair_part2`, so it does not exercise the case where the library
  itself produces an off-polynomial result.

### 6.3 CI coverage

`.github/workflows/ci.yml` has **no `cargo test` step.** The Rust crate
is built by CMake via Corrosion
(`cmake/libraries/storage-threshold.cmake`) and the CTest case
`test_storage_threshold`
(`tests/CMakeLists.txt:181`,
`tests/test_storage_threshold.cpp`) drives the crate through the C ABI
and **does run in CI**. The CTest case covers the same rejection
scenarios as the crate tests (DLEQ failure, below-threshold refresh,
below-threshold repair, stale share, threshold change, tampered sigma,
malformed inputs) and additionally exercises the ECIES wrap/unwrap path
end-to-end. So the paths are **not** entirely unexercised in CI; the
gap is specifically that `cargo test` (the crate's own unit tests,
including the 35 that currently pass) is not run in CI.

The distinction matters for the vendor: the crate's unit tests and the
CTest case have overlapping coverage, but the CTest case does not run
every unit test in `tests.rs`. If a regression is introduced in a crate
test that the CTest case does not exercise, CI will not catch it.

## 7. Feature-flag status

`storage_key_enabled` and `storage_files_enabled` are both
**default-off** in
`projects/LemonadeNexus/include/LemonadeNexus/Core/ServerConfig.hpp:149,156`
(`bool storage_key_enabled{false};` and
`bool storage_files_enabled{false};`). They can be turned on via
`ServerConfig` JSON or the `SP_STORAGE_KEY` / `SP_STORAGE_FILES`
environment variables
(`projects/LemonadeNexus/src/Core/ServerConfig.cpp:437-438`). `main.cpp`
logs an "EXPERIMENTAL" warning when `storage_key_enabled` is on
(`projects/LemonadeNexus/src/main.cpp:1058-1059`). **Do not enable either
flag in production until the external review is complete and its findings
are resolved.**

## 8. Reproducible build and test commands

From the repository root:

```bash
# Build the native server, the SDK, and the Rust crates (including
# storage-threshold). Requires CMake >= 3.25.1, Ninja, a Rust toolchain,
# and (on Linux) json-c, libcurl, and UUID development packages.
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel

# Run the CTest case that drives storage-threshold through the C ABI.
# This is the only storage-threshold test that runs in CI.
ctest --test-dir build -R test_storage_threshold --output-on-failure

# Run the crate's own unit tests. This does NOT run in CI.
cd crates/storage-threshold
cargo test
```

To exercise a specific unit test:

```bash
cd crates/storage-threshold
cargo test invalid_dleq_partial -- --nocapture
cargo test refresh_with_fewer_than_t_old_holders -- --nocapture
cargo test enrollment_with_fewer_than_t_helpers -- --nocapture
```

To build only the crate (faster iteration):

```bash
cd crates/storage-threshold
cargo build --release
```

## 9. Known limitations and unverified items

- The NCC Group audit of `frost` v0.6.0 has not been obtained or
  re-read for this package. The statement that it covers the DKG and not
  the refresh/repair paths is based on the audit's published scope and
  the fact that `refresh_dkg_*` and `repair_share_*` were added to FROST
  after v0.6.0. The vendor should confirm this directly from the audit
  document.
- The grace-period boundary for a retiring `S` is implemented in the
  C++ service, not the crate. No test (crate or CTest) exercises the
  expiry moment. This is an open test gap, not a known defect.
- The `elastic-elgamal` library's `LogEqualityProof` implementation has
  not been read line-by-line in this package. The crate's wrapper logic
  is documented in §4.3; the vendor must review the library's
  `verify` method directly.
- The `frost-ristretto255` 2.2.0 source for `refresh_dkg_shares` and
  `repair_share_step_3` has not been read in this package. The crate's
  call sites and pre/post conditions are documented in §4.1 and §4.2;
  the vendor must review the library implementations.
