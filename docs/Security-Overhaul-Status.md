# Security Overhaul Status

**Branch:** `tier-security-overhaul`
**Baseline:** Security Architecture Final Draft 1.1 (supersedes Final Draft 1.0)
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

#### Known gaps

* **No CRL cache producer.** `SecurityMeshService` installs no
  `AmdRevocationSource`, so revocation data is absent and new Tier 1 attestation
  fails closed on it. Intended until a cache producer lands.
* **The accepting revocation branch is untested off platform.** A CRL this chain
  accepts must be signed by AMD's own key, and the captured fixtures predate any
  published CRL. Every refusing branch is covered.
* **`uptime_valid` and `mesh_health_valid` still have no producer.** The agreed
  definitions are recorded on `Tier1MeshFacts`; both stay false and both keep a
  node ineligible. A locally computed answer would be a self-report wearing
  another name, so none was written.

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
