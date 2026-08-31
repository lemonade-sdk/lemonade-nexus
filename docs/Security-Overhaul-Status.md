# Security Overhaul Status

**Branch:** `tier-security-overhaul`
**Baseline:** Security Architecture Final Draft 1.1 (the only architecture revision; 1.0 is removed)
**Structure reference:** `.idea/lemonade-nexus-security-class-structure.md`
**Updated:** 2026-08-26

This document records the state of the security foundation, the protocol
details the implementation fixed, and the next implementation tasks.

## 1. Delivered layers

All code lives under `projects/LemonadeNexus/include/LemonadeNexus/Security/`
and `src/Security/`, plus `Crypto/FrostProvider` and `Crypto/SecureBuffer`.
Tests mirror the include tree under `tests/security/`.

| Layer | Files | Tests |
|---|---|---|
| Compiled ruleset and policy | `Policy/SecurityConstants.hpp`, `SecurityRuleset.hpp`, `SecurityTypes.hpp`, `Tier1Eligibility`, `Tier1TargetPolicy.hpp` | `policy/` (24) |
| Canonical encoding | `CanonicalEncoding` | `policy/canonical_encoding.cpp` |
| Attestation protocol layer | `Attestation/AttestationTypes`, `LinuxAttestationProfile`, `AttestationVerifier`, `AttestationService` | `attestation/` (38) |
| Epoch layer | `Epoch/Tier1Set`, `EpochState`, `Tier1Selector`, `EpochTransition.hpp`, `EpochAuthority.hpp`, `IncarnationState.hpp`, `EpochManager` | `epoch/` (39) |
| Consensus types and rules | `Consensus/ConsensusTypes`, `Quorum.hpp`, `VoteKey`, `QuorumValidation`, `LeaderSelection`, `Pacemaker` | `consensus/` (40) |
| HotStuff service | `Consensus/HotStuffState`, `ConsensusStore`, `HotStuffService` | `consensus/hotstuff_*` (42) |
| Authority | `Authority/AuthorityObject.hpp`, `SigningSession.hpp`, `NonceCommitmentStore`, `DkgSession`, `AuthorityService` | `authority/` (30) |
| Genesis | `Genesis/BootstrapCertificate`, `GenesisService` | `genesis/` (8) |
| FROST primitive boundary | `crates/frost-ffi` (Rust, `frost-ed25519 =2.2.0`), `Crypto/FrostProvider` | `cargo test` (7), `test_frost_provider` (9) |
| Guarded key memory | `Crypto/SecureBuffer` | `test_secure_buffer` (8) |
| Runtime | `SecurityRuntime` | `integration/first_path.cpp` |

The existing `nexus::security` evidence chain (SNP report and chain, HCL
report, TPM quote, IMA replay, evidence binding, platform probe) is unchanged.
The new attestation layer composes it.

## 2. First integrated path

`tests/security/integration/first_path.cpp` runs five in-process runtimes
through:

```text
verdicts -> Tier1EligibilityPolicy -> GenesisService founding set
        -> Epoch 1 DKG (real FROST) -> BootstrapCertificate
        -> SecurityRuntime adopts Epoch 1
        -> Chained HotStuff three-chain commit
        -> FROST authority signature over the finalized AuthorityObject
        -> Epoch 2 handoff (select, attest, vote keys, DKG, authorize, activate)
        -> old vote key and old share rejected in Epoch 2
```

The attestation verifier's positive path needs a real confidential VM. The
integration test constructs verdicts. Every later step runs real code and real
cryptography.

## 3. Protocol details the implementation fixed

The architecture delegates exact serialization and several values to the
implementation. These are now defined in code:

* **Canonical encoding.** Every digest and signature preimage goes through
  `CanonicalEncoder`: a domain string, then length-prefixed fields (u32-LE
  length). Integers encode fixed-width little-endian. The architecture's
  pseudo-code concatenations (selection seed, leader seed, challenge) all use
  this encoder with a kind label as the second field.
* **Network identity.** `NetworkId = SHA-256(domain, genesis public key,
  security ruleset, consensus ruleset)`. It exists before the bootstrap
  certificate, and the certificate binds to it.
* **Challenge value.** `challenge_digest(AttestationChallenge)` is the value
  `C` from architecture 5.5. The prover uses it as the nonce input of the
  existing `evidence_binding()`, so one TPM quote binds node identity,
  incarnation, epoch, and policy. The node identity key signs the evidence
  envelope, which binds the epoch vote key (architecture 11.2).
* **Participant set digest.** `Tier1Set::digest()` over the sorted member
  list. FROST identifiers are the 1-based positions in that sorted list.
* **HotStuff parent rule.** `REQUIRE_PARENT_QC` is implemented strictly: a
  proposal's parent is the block its justify certifies. Lock on the two-chain,
  commit on the three-chain by direct parent links.
* **Genesis anchor.** Each epoch's consensus starts from a synthetic genesis
  certificate (view 0, no signers) whose proposal digest is the checkpoint
  that authorized the epoch (the bootstrap certificate digest for Epoch 1).
* **Key generation.** `key_generation == epoch` for the main authority key.
* **Founding set.** When more than five candidates qualify at Genesis, the
  five lowest node identities found Epoch 1.
* **Attestation budget.** `kMaxTier1AttestAttemptsPerEpoch = 4` (tuning item).
* **Evidence size bound.** `kMaxPlatformEvidenceBytes = 4 MiB` in
  `AttestationVerifier.hpp`, applied before any hash or parse.
* **Restart rule.** A stored safety file makes the service unsynced until
  `sync_to_certified(view_floor)`. A corrupt file makes the service unusable.
  Corrupt is never treated as absent.

## 3a. Live cutover progress

### M1 — Security transport wiring (done)

| Piece | Files | Tests |
|---|---|---|
| Transport contract | `Transport/SecurityTransport.hpp` (`ISecurityTransport`, `SecuritySink`) | — |
| Wire codec | `Transport/SecurityCodec` — hand-written fixed layouts, length-prefixed fields with explicit maxima, no nesting, no generic parser | `transport/codec.cpp` (11) |
| Pairwise seal | `Transport/PairwiseSeal` — X25519 sealed box to the recipient identity for DKG round-2 packages | in router tests |
| Router | `Transport/SecurityRouter` — bound, per-peer budget, decode, sender binding (envelope and body), compiled rulesets, network, epoch window, dedupe, then one service; carries service answers back to the wire | `transport/router.cpp` (5, includes a five-node mesh over encoded envelopes) |
| Gossip path | `GossipMsgType::SecurityEnvelope = 0x16`; `GossipService` implements `ISecurityTransport` and delivers to one sink; signature-only authentication, size bound, no parse, no relay | `test_gossip_security_transport.cpp` (9) |

Transport bounds are compiled constants (`kMaxSecurityMessageBytes = 60000`,
per-kind payload maxima, `kSecurityPeerMessagesPerWindow = 256` per second,
`kSecurityDedupeWindow = 4096`).

Message classes on the wire: `AttestationChallenge`, `AttestationEvidence`,
`HotStuffProposal` (with its justify certificate), `HotStuffVote`,
`HotStuffTimeout`, `DkgBroadcast`, `DkgPairwise` (sealed), `FrostCommitment`,
`FrostSignatureShare`, `EpochAnnouncement`.

The router reports protocol outcomes through `ISecurityEvents`; the lifecycle
driver (M2) decides what happens next. Evidence production behind
`IEvidenceProducer` is not wired yet: a node without a producer answers no
challenge and stays ineligible.

### M2 — SecurityRuntime server lifecycle integration (done)

| Piece | Files | Tests |
|---|---|---|
| Bootstrap and sync messages | `GenesisFounding`, `DkgTranscriptAttest`, `BootstrapCertificate`, `SyncRequest`, `SyncResponse` in the codec and router; `GenesisService` requires all founders' signed transcript attestations before it signs | codec, router, genesis suites |
| Durable epoch state | `Epoch/EpochStore` — bootstrap certificate, current epoch with vote keys and checkpoint, authority history, own vote key wrapped (machine binding) | `epoch/epoch_store.cpp` |
| Evidence prover | `Attestation/PlatformEvidenceProducer` — answers only challenges for this identity, binds the epoch vote key, empty platform bundle on a host without a platform path, signs last | `attestation/producer.cpp` |
| Lifecycle driver | `Lifecycle/SecurityDriver` — genesis bootstrap, tick-paced proposing, pacemaker timeouts, re-attestation and epoch cadence, committed-handoff activation, restart recovery | `lifecycle/driver.cpp` (5) |
| Restart sync | `SyncResponse` carries the responder's uncommitted chain; `HotStuffService::adopt_certified_block` accepts certified facts without voting, one parentless anchor on an empty chain; voting waits for the certified floor | lifecycle + `hotstuff_safety` |
| Server wiring | `Lifecycle/SecurityMeshService` (IService: timers, sink, peer hook), `ServerConfig.genesis_pubkey` (pinned bootstrap anchor; empty = not configured), `main.cpp` construction and ordered shutdown, `GossipService::set_peer_certified_callback` | `test_security_mesh_service.cpp` (real UDP, honest failed-verdict path) |

Driver design rules: proposals originate only from `tick` (time-paced, never
certificate-triggered), verdicts carry the epoch they are FOR (a final
challenge names the target epoch), corrupt durable state fails the driver
permanently, and a node without a platform path answers with an empty bundle
that the verifier fails.

Known M2 scope cuts, to close in M4/M5: the eligible pool for rotation is
derived from locally recorded re-attestation verdicts (divergent pools fail
the DKG set digest and retry; consensus-finalized eligibility is the fix),
incarnations are constant 1 pending the 23.B rule, and `EpochAnnouncement`
is informational only.

### M3 — Old network authority removal (done)

Deleted outright: `GovernanceService`, `RootKeyChainService` (rotation and
Shamir distribution), `ShamirSecretSharing`, `TrustPolicyService`,
`TeeAttestationService`, `TeeAttestationTpm` (the Model-A TPM path and its
`--print-tpm-ak` CLI mode), the gossip wire types `0x07`–`0x10` (TEE
challenge/response, enrollment votes, root-key rotation, Shamir shares, peer
health, governance — values reserved forever), the `AttestationToken`
rolling-trust layer, the admission ballots, the `/api/trust/*`,
`/api/enrollment/*`, and `/api/governance/*` endpoints, and the operator
quorum knobs (`admission_quorum_ratio`, `enrollment_*`,
`require_peer_confirmation`, `onboard_min_tier1_for_vote`).

Re-pointed: gossip state-mutating ingress now requires a root-signed peer
certificate (never fail-open, no tokens, no Tier-1 decisions in gossip);
DNS credential distribution asks the mesh security system for Tier 1
membership (an unset gate denies); the published tier record derives from
current epoch membership.

Documented residuals, replaced when the epoch authority signs membership
credentials: the root-signed `ServerCertificate` stays as the Tier-2
TRANSPORT credential; admission stays sole-discretion (admin or single-use
token) and grants transport membership only; `TrustTypes` shrank to the
evidence-pinning remnants (`kMaxInlineEvidenceBytes`, `PeerPlatformBinding`).

One active security system remains: Tier 1 authority exists only through
attestation, deterministic selection, HotStuff finality, and per-epoch FROST
keys. `tests/test_legacy_removal.cpp` proves retired wire types and removed
endpoints cannot affect mesh state.

An adversarial review of the M3 test files (23 agents, 3 lenses, refute-style
verification) drove one production fix and a hardening pass:

- **`handle_ns_slot_claim` was ungated.** It parsed the claim signature and
  never verified it, and mutated `ns_slots_` (which feeds DNS NS
  registration) from unauthenticated ingress. It now verifies the claim
  signature against the claimant key and requires
  `peer_certificate_is_root_signed(claimant)`. The gate binds to the
  CLAIMANT, not the forwarding sender, because claims travel epidemically.
- The retired range `0x07`–`0x10` is pinned by a `static_assert` in
  `GossipTypes.hpp`: every live enumerator must stay outside it.
- The poll/ack domain-separation tags moved to `kOnboardPollTag` /
  `kOnboardAckTag` constants; the endpoints and the test share them.
- The drop-by-type tests now inject payloads their controls PROVE a live
  type accepts from the same (certified) sender, so the type byte is the
  only discriminating variable; the mesh-attached test gained a real
  positive control (a verified `ServerHello` fires the peer-certified
  callback and the genesis authority spends an attestation challenge).
- New admission negatives: nonce replay, stale timestamp, server_id-bound
  tokens, the approve-time evidence gate, denial cooldown across restart,
  pending-capacity 429 with the token carve-out, acknowledge lifecycle,
  status ownership, the reserved root server_id, and approve-time supersede
  with revocation of the old key.
- The cooldown-across-restart test caught a real bug:
  `ServerAdmissionService::load()` iterated `root.value(...)` temporaries
  directly in range-fors. Under C++20 the temporary dies at the end of the
  range-init expression (P2718 extends it only in C++23), so the restore
  loops read destroyed objects — in practice a restart silently cleared
  every active denial cooldown. Both loops now materialize locals first; a
  codebase sweep found no other instance of the pattern.

Known residual gaps, carried to M5/M7: the `AclDelta` / `DnsRecordSync` /
`BackboneIpamSync` cert gates share the exact `DeltaResponse` rule but have
no wire-level test of their own (their handlers also verify inner delta
signatures); `handle_misbehavior_proof` is verified only at the function
level (`test_misbehavior_detector.cpp`), not through hostile wire packets;
hostile `ServerHello` variants (forged cert, packet-signer mismatch) have no
dedicated negative wire test.

### M4 — Real multi-node development mesh (in progress)

`scripts/dev-mesh.sh` runs five separate `lemonade-nexus` processes on
localhost with real UDP transport: node 0 first-runs as the mesh root and
pinned genesis anchor, enrolls all five identities, and the harness copies
the root-signed certificates to the joining nodes — the same file movement
an operator performs. No code path was added for the harness; it drives the
shipped binary through its normal configuration.

On hardware without SEV-SNP the run proves the fail-closed path end to end
across processes: the anchor enters `GenesisCollecting`, admits the
certified peers, sends real attestation challenges over UDP, receives
evidence, and records FAILING verdicts from the real verifier. Founding
never happens, no epoch activates, and all five processes stay healthy.
The first run recorded five failing verdicts and zero foundings.

The security driver now logs its phase transitions and genesis verdicts
(`set_phase`, INFO level) — the security plane was previously silent, which
made multi-process behavior unobservable for operators and tests alike.

Still open for M4: the positive Genesis path needs five Tier 1-capable
(SEV-SNP + vTPM + anchored IMA) hosts — no local machine or the current
test server qualifies, and the profile will not be weakened to compensate;
the test server (10.10.12.40) remains the target for Tier-2, ineligible-peer,
and transport testing against a real network.

### M6 — Attestation against real SEV-SNP silicon (in progress)

The test host `uwb-nx0-mesh-root` (10.10.12.40) was rebuilt as a native
SEV-SNP guest on AMD EPYC 9354 (Genoa) with a vTPM. It was collected again on
2026-08-26 in both collector modes. Full detail, including what regressed,
lives in `docs/attestation/test-host-capabilities.md`. The earlier negative
collection is retained as the record of the host before the change.

**The SEV-SNP evidence is genuine and now verifiable by the shipped binary.**
Three properties were checked off-host against the archived bytes and are now
pinned by tests:

* The AMD chain validates: VCEK ← ASK (`SEV-Genoa`) ← ARK (`ARK-Genoa`).
* The report signature verifies under the VCEK: ECDSA P-384 over SHA-384 of
  report bytes `0x000`–`0x2A0`.
* `REPORT_DATA` equals `SHA-512(challenge)`, so the report is bound to a fresh
  challenge. A `reference` run of the same guest carries the same launch
  measurement and a different binding.

Changes this drove:

* **The AMD root pin is no longer Milan-only.** `verify_snp_signature` hard-coded
  `"Milan"` for both the pinned chain and the pinned root, so a valid Genoa chain
  was rejected outright. The real Genoa ARK and ASK are now compiled in, and the
  product is resolved by matching the chain against the compiled-in roots rather
  than by trusting any claim. A generation we hold no root for still fails
  closed — it never borrows another generation's root.
* **`tests/test_snp_genoa.cpp`** drives real hardware bytes. These are the first
  tests in the tree that assert the AMD chain *accepts* evidence; every other SNP
  test asserts a rejection. It also covers the negatives that matter: a tampered
  measurement, a tampered `REPORT_DATA`, the wrong VCEK, a Milan chain against a
  Genoa report, an absent VCEK, a TCB floor above the platform, and a wrong
  pinned measurement.
* **Profile completeness is explicit and fails closed.** `LinuxAttestationProfile`
  gained `profile_gaps()`, `profile_is_complete()` and `profile_gap_name()`.
  `AttestationVerifier::examine` now checks completeness **first** and returns the
  new `AttestationFailure::ProfileIncomplete`. Previously an unpinned profile
  failed by accident at the last step, with a misleading
  `BinaryMeasurementInvalid`.
* **`linux_attestation_profile_v1()` is the named compiled profile**, and
  `main.cpp` uses it instead of a default-constructed struct. It fixes the rules
  (debug denied, migration agent denied, VMPL0, IMA enforced, `no_new_privs`,
  seccomp) and deliberately pins **no** launch measurement, TCB floor, IMA policy
  digest or approved binary, because those values may only be read from a host
  that already satisfies the rules. Until such a host exists every candidate
  fails with `ProfileIncomplete`, and the server logs each gap at startup. This
  is the intended behavior: pinning values observed on an unqualified host would
  make the profile decide nothing.

#### Why this host cannot be Tier 1 Genesis yet

The guest runs at **VMPL0** with no SVSM and no paravisor, and its vTPM is a
host-side `swtpm` attached by QEMU with no EK certificate. The vTPM therefore
sits outside the SEV-SNP boundary: a hostile hypervisor can forge any quote it
produces, including PCR contents. Measured-boot and IMA evidence taken from it
prove nothing against the threat model SEV-SNP exists to address.

This is exactly the binding the compiled chain requires and the reason it
requires it. Under a paravisor the vTPM lives inside the guest boundary and the
SNP report's runtime data publishes `HCLAkPub`, so the hardware vouches for the
vTPM key. This host publishes no such binding, so its evidence is refused.

Two host changes would resolve it, and both are the operator's call:

1. Run a **COCONUT-SVSM vTPM** at VMPL0 with the guest at VMPL1 or above, so the
   vTPM lives inside the confidential boundary and the SNP report can bind it.
2. Use **SNP measured direct boot** — kernel, initrd and command line inside the
   launch measurement, with a dm-verity root hash pinned on that command line —
   so software integrity rests on the SNP measurement and needs no vTPM.

Secondary gaps on the same host, none of which decide the question: Secure Boot
is off, no IMA policy is loaded (`CONFIG_IMA_WRITE_POLICY` is unset and the
kernel command line carries no `ima_policy=`, so nothing is measured), the boot
chain runs through GRUB from an unmeasured LVM volume, and no Nexus binary is
installed.

The profile must not be relaxed to accept an unbound vTPM. Accepting one would
let any hypervisor mint a passing Tier 1 node.

#### M4 positive-path status

Unchanged and blocked. The positive Genesis path needs **five** hosts that
satisfy the compiled profile. Zero qualify today: this host fails on the vTPM
binding above, and no other candidate exists. The bootstrap threshold stays at
five and the profile stays as it is.

### M7 — Revision 1.1 attestation provider boundary (done)

Revision 1.1 of the architecture separates *proving platform facts* from
*deciding Tier 1*. Nexus verified one evidence format and returned a pass flag,
so a second confidential-computing platform would have meant either a second
eligibility path or a weaker shared one. The boundary is now:

```text
PlatformEvidenceProvider -> VerifiedPlatformClaims -> Tier1EligibilityPolicy
```

**The claim model.** `VerifiedPlatformClaims` carries the eleven facts Revision
1.1 requires, plus the three steps behind runtime integrity, because Tier 1
names three separate runtime prerequisites and one composite claim cannot tell
them apart. A claim is true only when a verifier step ran and held. Claims that
contradict their own steps, or that name no provider, are refused whole rather
than trusted in part.

**The provider interface.** `PlatformEvidenceProvider` identifies its compiled
profile, states whether it can decide, and returns claims. It cannot select
Tier 1, change quorum, grant authority, or set a required claim true because
its platform has no equivalent mechanism. `AttestationVerifier` keeps the
provider-neutral checks — profile dispatch, challenge, node, incarnation, epoch,
identity signature — and merges what the provider proved.

**Providers.**

| Profile ID | Provider | State |
|---|---|---|
| `snp-hcl-vtpm` | `AzureSnpVtpmProvider` | Implemented. The existing SNP/HCL/vTPM chain, moved unchanged behind the boundary. |
| `snp-svsm-vtpm` | `SnpSvsmVtpmProvider` | Declared, refuses. The SVSM service-manifest format is not invented; it waits on real evidence from an approved SVSM host. |
| `snp-direct-boot` | `SnpDirectBootProvider` | Declared, refuses, and **not Tier 1 capable**. No protected runtime measurement accumulator exists on a TPM-less measured boot, so implementing its evidence format will not change that. |
| `tdx` | none | Named so the enum stays stable. No provider. |

`SnpSvsmVtpmProvider` carries one warning that must not be lost: under SVSM the
guest Linux runs at VMPL1 or lower, so `SnpPolicyRequirements::require_vmpl0`
cannot be applied to a guest-requested report. Which component requests the
report, and at which VMPL, is part of what captured SVSM evidence must settle.

**Profile binding.** `attestation_profile_id` and `attestation_profile_ruleset`
are inside the challenge digest and the signed evidence digest. Evidence built
for one profile cannot answer a challenge for another, a candidate cannot
request a weaker profile than the one it was challenged under, and a profile ID
this binary does not name is refused at the parser rather than folded into
`Unknown`.

**Eligibility.** `Tier1EligibilityPolicy` reads claims, never
`AttestationVerdict::passed`, and gained two prerequisites the claim model made
nameable: an approved platform profile, and the TCB floor as its own fact
rather than a side effect of the guest policy check. Fifteen prerequisites,
conjunction, fail closed.

**Hardening closed alongside it.**

* **Challenge consumption.** A bundle that answers no live challenge no longer
  cancels one. Any peer that knew a node ID could otherwise deny that node
  attestation by replaying one stale bundle per challenge.
* **AMD revocation.** The VCEK and its issuing ASK are checked against a cached
  KDS CRL, verified under the same chain that had to root in a compiled-in AMD
  key, and refused when expired. The check runs immediately after the AMD
  signature and before guest policy. Absent, unparsable, wrongly signed and
  expired data all fail closed, as does having no trusted clock. This gates NEW
  attestation only: epoch membership is frozen once selected, so a KDS outage
  cannot shrink a live quorum.
* **Runtime integrity is not a self-report.** `runtime_integrity_valid` is the
  conjunction of IMA anchoring, an approved binary, and the runtime profile.
  The self-reported `no_new_privs` and seccomp fields count only alongside a
  log that replays into a quoted PCR and a binary on the approved list.

**Tests.** `tests/security/attestation/providers.cpp` (24) covers dispatch,
downgrade and substitution. Three run against the captured SNP report: a
structurally perfect quote under a key AMD never vouched for (the host `swtpm`
and foreign-vTPM case), a quote with no SNP report behind it, and the launch
measurement pin being checked before the quote — the control that stops a guest
choosing its own `REPORT_DATA` from naming an AK it holds, and the reason a
profile may only be pinned from a host already known good.

### M8 — Network binding, VMPL policy, and the revocation cache (done)

**`network_id` is inside the attestation context.** Network separation rested on
`SecurityEnvelope` alone, and transport authentication is not trust: a node
enrolled in one Nexus network could answer another network's challenge with the
same identity, the same platform and the same fresh quote. `network_id` now
enters `AttestationChallenge`, `AttestationEvidence`, both digests and the wire
codec. The quote commits to `challenge_digest`, so it commits to the mesh that
asked. The full bound context is:

```text
network_id  profile_id  profile_ruleset  security_ruleset  consensus_ruleset
node_id  node_key  incarnation  epoch  nonce  policy_digest
```

`AttestationService` takes its network explicitly rather than defaulting: an
all-zero network is a real value, and a service that silently used one would
accept a challenge from any mesh that did the same. A cross-network answer
reports `NetworkMismatch` rather than surfacing as a digest mismatch.

**VMPL is provider-specific.** `SnpPolicyRequirements::require_vmpl0` was a
boolean defaulted true, with a comment claiming the recorded level must be 0
either way. That is wrong for the SVSM shape:

```text
SVSM  = VMPL0                 most privileged inside the guest
Linux = VMPL1 or higher       strictly less privileged than the SVSM
```

VMPL is a privilege level and lower is more privileged, so the Linux guest runs
*above* VMPL0. `VmplPolicy` replaces the boolean with `Unconstrained` (the new
default, so no profile inherits a rule it did not choose), `RequireVmpl0` for a
paravisor or a native guest requesting its own report, and `RequireAboveVmpl0`
for the SVSM shape, where a guest-requested report recorded at VMPL0 would prove
the opposite of what is wanted. `LinuxAttestationProfileV1` pins `RequireVmpl0`.

**`tier1_capable()` is informational.** It states that a provider's *design* can
satisfy Tier 1. It is not consulted by `AttestationVerifier` and not consulted
by `Tier1EligibilityPolicy`. Pinned by tests: a capable provider that is not
ready produces no claim and no eligibility; a capable, ready provider missing
one required claim is still ineligible; and eligibility does not read the flag
at all, which is why the flag must never be relied on as a control. What
actually stops `SnpDirectBootProvider` is a claim it cannot produce.

**The AMD revocation cache.** `AmdRevocationCache` is the missing producer: one
file per AMD product under `data_root/security/revocation`, written through a
temporary and renamed so a crash cannot leave a truncated list. Fetching and
storage stay apart from cryptographic validation — the cache hands over what it
holds and `verify_snp_revocation` decides. Storing garbage stores garbage the
verifier refuses, and a filesystem timestamp never substitutes for the signed
`nextUpdate`.

`AmdRevocationState` carries every cached list rather than one. A mesh spans
silicon generations and a verifier does not know which one a peer runs until it
resolves that peer's chain, so it is handed all of them and uses the one that
verifies under the chain in hand. A list for another product verifies under
neither the ARK nor the ASK there, which rejects the wrong product without
anyone naming a product.

A refresh outage leaves the last good bytes in place until their own
`nextUpdate` passes. New Tier 1 attestation then fails closed. Membership is
decided once, at selection, so nothing here reaches back into a frozen epoch.

`tests/fixtures/amd_milan_crl.der` is the real KDS list for Milan, signed by
ARK-Milan and valid 2026-08-19 to 2026-10-04. Against fixed timestamps it makes
the accepting, expired and not-yet-valid branches all testable under a genuine
AMD signature.

#### Known gaps

* **The end-to-end revoked-VCEK path is untestable off platform.** It needs a
  CRL signed by AMD's own key that names our fixture VCEK, and AMD's real Milan
  list revokes nothing today. The listing logic is covered through
  `amd_crl_revoked_serials()`, and a foreign list that *does* revoke a serial is
  covered as a refusal — publishing your own CRL does not revoke anyone.
* **No CRL fetcher.** The cache stores and serves; nothing populates it yet.
  Refreshing from `amd_crl_kds_url()` is operator tooling, deliberately outside
  the verified binary's network surface.
* **`uptime_valid` and `mesh_health_valid` still have no producer.** The agreed
  definitions are recorded on `Tier1MeshFacts`; both stay false and both keep a
  node ineligible. A locally computed answer would be a self-report wearing
  another name, so none was written.
* **`SnpSvsmVtpmProvider` stays fail-closed.** No manifest schema is invented,
  and Azure HCL bytes are not reused as a stand-in SVSM format. The capture from
  `.40` should carry as much of the following as the live implementation
  supplies, and only the observed binding gets implemented:

  ```text
  SNP report
  SVSM attestation response
  service manifest
  certificates
  vTPM identity or AK
  fresh TPM quote
  ```

  The required chain is AMD endorsement → SNP instance → approved SVSM instance
  → SVSM-bound vTPM identity → fresh TPM quote.

### M9 — Mesh eligibility facts, conformance, fuzzing and measurement (done)

**`uptime_valid` and `mesh_health_valid` have producers.** Both are built from
signed statements by current Tier 1 members, never from anything a node says
about itself. `Security/Eligibility/` holds the observation type, the pure
ledger that turns observations into facts, and the durable store.

An observation binds network, epoch, subject, subject incarnation, kind, the
attestation the observer verified, the observer's quorum-certified height, the
finalized state it held, and the observer identity. Nothing carries a
wall-clock time: a peer-supplied timestamp is a value an adversary picks.

```text
uptime_valid
    = a consensus quorum of distinct observers, each having verified
      kMinContinuityObservations distinct attestations of the same subject at
      the same incarnation in this epoch

mesh_health_valid
    = a consensus quorum of distinct observers reporting participation at the
      current epoch and incarnation, AND no unresolved objective fault
```

Distinct challenge nonces make distinct evidence digests, so two of them are
two real rounds; the local re-attest cadence is what puts an interval between
them without trusting a peer's clock. A changed incarnation restarts the count.

Objective faults are proved, not judged: duplicate incarnation, equivocation,
invalid consensus behavior. Any unresolved fault denies health.

**Byzantine observers.** Observers are deduplicated by node identity, so a
cloned member counts once. An observer cannot rewind its height, observe
itself, sign as another, or contribute from outside the frozen set. One
observer never makes a fact, and a partition below quorum denies rather than
guesses.

**Genesis.** Before Epoch 1 there is no prior quorum, so the founding set
observes itself: every founder must be seen by every other. That is the mutual
attestation and mutual connectivity the bootstrap rules require, and since no
node observes itself the bar is one less than the founding set. The bootstrap
threshold stays five.

**Expiry and rollback.** Observations are epoch-scoped and affect next-epoch
eligibility only, so a node stays eligible while the mesh keeps seeing it and
nothing here can shrink a frozen epoch. `EligibilityStore` writes
crash-atomically, reports damage as `Corrupt` rather than `Absent`, and
re-verifies every signature on load — an edited file cannot assert a fact no
observer signed, and a renamed file cannot be served as another epoch's.

**VMPL is an explicit choice.** A Tier 1-capable profile that never chose a
`VmplPolicy` is incomplete. Choosing `Unconstrained` explicitly still completes;
forgetting does not, and the profile digest distinguishes the two.

**AMD CRL operational flow.** `scripts/nexus-refresh-amd-crl` fetches one
product's KDS list and installs it atomically into the layout
`AmdRevocationCache` reads. It shape-checks that the response parses as a CRL so
a captive portal cannot overwrite a good entry, and decides nothing else. A
fetch failure keeps the existing entry; revocation data then expires on its own
signed `nextUpdate`, after which new Tier 1 attestation fails closed.

**Provider conformance.** `tests/support/provider_conformance.hpp` is the
contract every Tier 1-capable provider satisfies: wrong network, node, epoch,
incarnation, ruleset, profile ruleset or challenge all refuse, and claims stay
self-consistent. It asserts claims and failures only, never eligibility. It
found one real inconsistency — the verifier set `attestation_profile_valid`
before recording which provider was examining.

**Fuzzing.** Nine targets over the parsers that read attacker-controlled bytes.
A deterministic corpus drives them inside the normal suite so they stay
exercised on every build; `NEXUS_BUILD_FUZZERS=ON` builds each as a libFuzzer
binary, and fails at configure time on a toolchain without libFuzzer rather
than at link.

**Scale measurement.** `security/simulation/scale.cpp` records quorum,
authority threshold, proposals, votes, commits, view changes under leader
failure, QC signature bytes, encoded proposal size, DKG traffic and FROST
traffic for every population from 5 to 31. It asserts invariants only. No
constant is tuned.

#### Known gaps

* **The ledger is not yet wired into the driver.** `SecurityDriver` still builds
  its next-epoch pool from local re-attestation results. The facts, their store
  and their tests exist; replacing the driver's local pool with a
  consensus-finalized eligible set is the next step, and until then the mesh
  facts are computed but not consumed in production.
* **No participation producer.** `ObservationKind::Participation` has no emitter
  in the driver yet, so mesh health has evidence plumbing but no live source.
* **The end-to-end revoked-VCEK path stays untestable off platform**, as before.
* **`SnpSvsmVtpmProvider` remains fail-closed** with no parser, awaiting real
  `.40` evidence.

## 4. Test host

See `docs/attestation/test-host-capabilities.md`. The first test host
(`uwb-nx0-mesh-root`) is a plain KVM guest with no TPM and no SEV-SNP. The
collector `scripts/nexus-attest-profile` runs there in both modes and records
every missing facility. The host cannot pass the compiled profile; that is
the correct result.

## 5. Old trust model

Removed in M3. `TrustPolicyService`, `GovernanceService`, `RootKeyChainService`
with Shamir shares, `ServerAdmissionService` ballots, and the gossip handlers
that served them are gone. `tests/test_legacy_removal.cpp` fails the build if
any of them returns.

## 6. Next implementation tasks

1. **Gossip transport for security messages.** Add message classes for
   `AttestationChallenge`, `AttestationEvidence`, `HotStuffProposal` (with its
   justify certificate), `HotStuffVote`, `HotStuffTimeout`, `DkgBroadcast`,
   `DkgPairwise`, `FrostCommitment`, `FrostSignatureShare`, and
   `EpochAnnouncement`. Route them to `SecurityRuntime`. Apply size limits
   before parsing. Do not decide security truth in gossip.
2. **`SecurityRuntime` in `main.cpp`.** Construct it after crypto and
   storage. Give `HotStuffService` an ASIO timer driven by `Pacemaker`
   (`on_timeout` → `make_timeout_vote`).
3. **Remove the old authority paths.** `RootKeyChainService` rotation and
   Shamir distribution, `GovernanceService`, admission ballots, the admin
   approve/deny and token-mint endpoints, the `AttestationToken` rolling
   trust, and the operator-configurable quorum ratios in `ServerConfig`.
   Repoint `TrustOperation` gating and the tier DNS records to epoch
   membership.
4. **DKG broadcast through consensus.** Order round-1 broadcasts through the
   current epoch's HotStuff transcript (architecture 12.7). Genesis sequences
   Epoch 1.
5. **Final-attestation cadence.** Re-attest every `kReattestIntervalSeconds`;
   enforce `kFinalAttestMaxAgeSeconds` before a handoff. Feed verdicts to
   `EpochManager::record_final_attestation`.
6. **Incarnation replacement rule** (architecture 23.B). `IncarnationManager`
   with one current incarnation per node identity.
7. **Approved release ledger.** Move approved binary digests from
   `LinuxAttestationProfile.approved_binary_sha256` into finalized mesh state
   with the APPROVED → ELIGIBLE → ACTIVE transition.
8. **Profile completion.** Boot event log replay, IMA policy digest, and the
   runtime security state (`no_new_privs`, seccomp) as evidence fields;
   `RuntimeProfileInvalid` and `BootMeasurementInvalid` become reachable.
9. **DKG culprit attribution.** Extend `frost-ffi` to return the culprit
   identifier on an invalid proof of knowledge, so `DkgSession` can name the
   participant the epoch replaces.
10. **Physical move of the evidence files** into `Security/Attestation/` once
    the old `Core` attestation classes are gone.
11. **Fuzzing.** Parsers for `HotStuffState` JSON, DKG and FROST message
    payloads, and the attestation evidence envelope.
12. **Provision a SEV-SNP host** for the first compiled Linux profile
    (architecture 22, 23.A) and run `nexus-attest-profile reference` there.


## M10 — Tier 2 eligibility and the witness bar

The live eligibility path shipped in M9 had two defects the integration
exposed. Both are fixed.

### Tier 2 can now qualify for Tier 1

The only participation producer was an accepted HotStuff vote, which only a
current member can make. A node therefore had to be Tier 1 already to prove it
was fit for Tier 1.

The vote path is unchanged and remains the stronger proof: it is signed under
the epoch vote key the mesh froze, names the network, epoch and consensus
ruleset, and votes at a height the observer can compare against its own
finalized floor. A second path joins it for candidates that hold no vote key —
`Security/Eligibility/ParticipationProof.hpp`, message kinds 18 and 19:

```
current Tier 1 observer
    -- ParticipationChallenge: nonce, network, epoch, rulesets, node,
       incarnation, and the observer's own finalized height and state root
candidate
    -- ParticipationResponse: the challenge digest and every binding,
       signed under the candidate's identity key
observer
    -- match before consume, verify, then sign a Participation observation
```

No existing exchange proved enough. Attestation evidence binds identity,
incarnation, epoch and ruleset but says nothing about finalized state, and it is
already what continuity counts. A sync request is unsigned. Gossip and WireGuard
authenticate a transport, which is not an authorization result.

Candidates enter the eligibility state through the observations themselves
rather than a local peer list, bounded at `f + 1` distinct observers, so all
honest nodes converge on the same candidate set and a Byzantine minority cannot
inject subjects nobody has seen.

### The witness bar excludes the subject from its own committee

The bar was a full consensus quorum of external observers. A subject never
witnesses itself, so a member was one short of its own committee by
construction: at every population, `f` offline members made continuity
unreachable for everyone while HotStuff still held its quorum. At N = 5 that
was a single offline node.

```
Q = ConsensusQuorum(N)
subject in the current committee: Q - 1 external witnesses
subject outside it:               Q   external witnesses
floor:                            f + 1
```

`Q - 1 = N - f - 1` is exactly what remains with `f` offline and the subject
excluded, and it exceeds `f` at every population in the table — 3 against 1 at
N = 5, 20 against 10 at N = 31 — so the adversary alone can never make a fact.
A candidate outside the committee gets the full quorum, but it spends no witness
on itself, so `N - f = Q` members remain and it is reachable too. Both kinds of
subject stay provable exactly while consensus has its quorum and both stop one
member later.

This is a witness rule, not a consensus rule. `ConsensusQuorum(N)` is untouched;
the state these facts feed is still finalized by a full HotStuff quorum, which
is what makes two honest nodes agree on it.

### Claim provenance

Platform claims travel inside signed observations so honest replicas compute one
deterministic state. `observe_attestation` now takes only a subject and reads
the verdict this node's own verifier recorded, so there is no parameter left for
a caller to sign a claim set it did not verify. Fabricated claims, claims copied
onto another node, incarnation or network, the same evidence digest with claims
altered, and an observation relayed under another observer's identity all break
the signature.

### `certificate_valid`

Sourced from `GossipService::peer_is_root_certified`, which requires a
configured root anchor (never fail-open), a stored certificate belonging to that
pubkey, issuer equal to the root, an unexpired `expires_at`, a non-revoked
identity, and an Ed25519 signature over the canonical certificate under the root
key — with proof of possession enforced at `handle_server_hello`, where the
packet signer must equal the certificate identity.

It means ordinary authenticated server identity. It is one prerequisite of
fifteen and implies none of the others.

**Gap:** the certificate binds to the root anchor rather than to `network_id`
explicitly. With one root per deployment that is sound, but an explicit network
field would be a strict improvement.

### Known gap: a selected Tier 2 node cannot yet join the next epoch

A candidate can become finalized-eligible and be selected into the next-epoch
set. It cannot yet take up the role, because the handoff protocol has no path
for a non-member:

- `maybe_start_next_dkg` requires an `EpochManager` transition, which only
  current members have, so a selected candidate never joins the target-epoch
  DKG;
- `activate_next_epoch` builds the new state from that transition, so there is
  no adoption path for a node that was not in the previous epoch.

Closing it needs a quorum-gated adoption path — a selected node learning the
target participant set, joining the DKG, and adopting the epoch on agreeing
announcements from current members. That is where a mistake would grant
authority, so it is left as its own milestone rather than added under this one.
`Tier2Path.ProvingParticipationGrantsNoAuthority` pins the boundary as it
stands: a candidate that has proved everything holds no consensus, no authority
key, no epoch state and no membership.

### Fuzzing

Two targets past the codec: an observation through every rule that judges it,
and a participation answer against a challenge the observer holds, both reached
with genuinely signed messages plus bit-flips and truncations.
`scripts/nexus-run-fuzzers` builds and runs the real fuzz binaries under Linux
Clang in a container. AppleClang ships no libFuzzer runtime, so on a Mac only
the deterministic corpus runs.

### Measurement

`security/simulation/eligibility_scale.cpp` records, for every population from
5 to 31, the witness bar for each kind of subject, whether each fact still forms
with one, `f` and `f + 1` members offline, and what expiry, participation loss,
candidate restart and a proved fault do to it. Assertions are invariants only.
