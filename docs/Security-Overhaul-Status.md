# Security Overhaul Status

**Branch:** `tier-security-overhaul`
**Baseline:** `.idea/lemonade-nexus-security-architecture-final-draft-1.0.md` (Final Draft 1.0)
**Structure reference:** `.idea/lemonade-nexus-security-class-structure.md`
**Updated:** 2026-08-23

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

## 4. Test host

See `docs/attestation/test-host-capabilities.md`. The first test host
(`uwb-nx0-mesh-root`) is a plain KVM guest with no TPM and no SEV-SNP. The
collector `scripts/nexus-attest-profile` runs there in both modes and records
every missing facility. The host cannot pass the compiled profile; that is
the correct result.

## 5. Old trust model

The old trust model stays active: `TrustPolicyService`, `GovernanceService`,
`RootKeyChainService` with Shamir shares, `ServerAdmissionService` ballots,
and the gossip handlers that serve them. The new foundation is not yet wired
to gossip or to `main.cpp`. Two security systems are not active at the same
time because the new one has no network path yet. The removal happens when
the replacement path exists (task 3 below).

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
