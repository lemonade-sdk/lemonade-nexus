# Agent instructions for Lemonade Nexus

## Scope

These instructions apply to the repository unless a closer `AGENTS.md` provides a more specific rule for its directory. Follow the agent runtime's instruction precedence and explicit task instructions. Do not edit instruction files to bypass a requirement.

Complete the requested work, including relevant validation. Resolve routine implementation choices without repeated confirmation. If a decision would expand the task or change a protected security principle, explain the specific conflict and obtain direction for that part. Continue independent work that is already authorized.

## Project map

Lemonade Nexus contains a C++20 mesh server and SDK, Rust networking and cryptographic integrations, and a Flutter desktop client.

| Path | Responsibility |
|---|---|
| `projects/LemonadeNexus/` | Server, application services, and security protocol |
| `projects/LemonadeNexus/include/LemonadeNexus/Security/` | Security interfaces, types, and compiled policy |
| `projects/LemonadeNexus/src/Security/` | Security implementation |
| `projects/LemonadeNexusSDK/` | C++ client SDK and C ABI |
| `projects/LemonadeNexusAttestd/` | Separate platform-evidence helper |
| `projects/LemonadeNexusSidecar/` | Sidecar integration |
| `crates/` | Rust transport, virtual netstack, and FROST integrations |
| `apps/LemonadeNexusClient/` | Flutter/Dart client and native platform code |
| `tests/` | Native tests, security lifecycle tests, and fuzzing support |
| `cmake/`, `packaging/`, `scripts/` | Dependencies, builds, packaging, and operations |
| `docs/` | User and developer documentation |

## Establish the facts before editing

- Inspect the current branch, commit, and worktree. Preserve unrelated changes. Read the affected implementation, callers, and relevant tests before choosing a fix.
- Use source code to determine implemented behavior. Verify documentation, comments, examples, and previous reports against it. A PR description or passing historical test count is not evidence about the current checkout.
- Source can contain defects. If code conflicts with a security invariant, report and fix the defect within scope; do not redefine the invariant to match the code.
- Correct stale comments and documentation affected by the change. Report other material discrepancies with a file or symbol reference and the behavior actually found. Avoid unrelated documentation rewrites.
- Distinguish implemented, tested, hardware-qualified, and planned behavior. Do not promote a stub, interface, fixture, or declared provider to a supported feature.
- Use `rg` and targeted file reads. Consult current upstream documentation when external API behavior is uncertain. Do not invent APIs, flags, paths, or results.

## Engineering practices

- Make the smallest coherent change that fixes the cause. Preserve existing architecture, naming, formatting, and error-handling conventions. Avoid speculative abstractions and unrelated cleanup.
- Search for existing project utilities and approved dependencies before adding an implementation. Reuse the established cryptography, serialization, storage, transport, and validation paths. Do not write replacement cryptographic primitives.
- Keep dependencies necessary and scoped. Use the repository's dependency mechanisms and update the relevant manifests or lockfiles together. Do not add a dependency or framework for a small task already served by existing code.
- Keep functions focused and interfaces explicit. Prefer clear names, strong types, `const` correctness, RAII, and explicit ownership. Avoid hidden side effects and unnecessary shared mutable state.
- Check failure paths, bounds, integer conversions, resource limits, cancellation, callback lifetimes, and concurrency. Reject malformed input before expensive work. Do not catch and ignore errors that affect correctness or security.
- Preserve C ABI contracts and wire/storage compatibility. Coordinate changes across C++, Rust, C bindings, and Dart as applicable. Do not allow exceptions or Rust panics to cross an FFI boundary.
- Keep deterministic protocol logic independent of unordered iteration, local clocks, platform behavior, or local observations unless the protocol explicitly defines those inputs.
- Keep platform-specific code behind established boundaries. A fix for one platform must not silently remove behavior from another.
- Regenerate generated files with the repository's generator when available. Do not hand-edit generated output as a substitute for changing its source.
- Never log or commit private keys, shares, nonces, tokens, credentials, or raw secret-bearing evidence. Use the existing secret-memory and key-management facilities.

## Security principles

Preserve these boundaries during implementation, refactoring, testing, and documentation:

- **Identity is not authority.** A certificate, authenticated tunnel, signed record, healthy peer, or local configuration does not grant Tier 1 membership or permission to mutate authoritative state.
- **Authority follows finalized state.** Tier 1 is epoch-scoped. Preserve the Genesis bootstrap and finalized eligibility, selection, readiness, DKG, and handoff rules. Peer announcements and local state cannot substitute for the required proofs.
- **Genesis is one-shot.** Its unilateral security authority ends at Epoch 1 activation. Do not introduce a restart, recovery, or administrative path that restores it after that boundary.
- **Evidence fails closed.** Missing, stale, invalid, unsupported, or incomplete evidence must not become acceptance. Do not weaken an attestation profile, introduce a production mock, or lower quorum to make startup or tests succeed.
- **Keys have separate roles.** Keep identity, consensus voting, epoch authority, admission, storage, and infrastructure key uses distinct. Preserve epoch/session binding, nonce safety, and secret destruction. Do not reconstruct an authority key for convenience.
- **Verification crosses every boundary.** Preserve canonical encoding, domain separation, network/ruleset/epoch binding, freshness, replay checks, and authorization at network, API, FFI, and persistence boundaries. A valid record digest alone is not authenticated authority.
- **Security rules are protocol rules.** Do not add operator overrides for eligibility, quorum, thresholds, provider requirements, or finalized authority. Do not reintroduce retired governance or root-share mechanisms.

Use `Security/Policy/SecurityConstants.hpp`, the relevant verifier and lifecycle code, and their tests to identify the exact rules. Normal fixes that preserve these principles are in scope. Changes to the principles, trust model, deterministic rules, or compatibility requirements need an explicit task covering that change and its migration and validation plan.

Keep unresolved implementation limits visible. Do not describe admission or application stores as consensus-authorized until their actual write paths establish that authority. Do not claim rollback protection, freshness, or production platform qualification beyond what is verified.

## Language and documentation

- Write explanations, documentation, comments, commit messages, and PR descriptions in American English with a Simplified Technical English (STE) style: short sentences, active voice, direct instructions, and consistent technical terms.
- Use one term for each concept. Define an acronym on first use when the reader needs it. Preserve exact identifiers and protocol terminology.
- Prefer concrete statements over marketing language, filler, or claims such as “fully secure.” State assumptions and limitations where they affect a decision.
- Preserve the README's established flow and useful visual cues, including emojis. A technical correction is not permission for a wholesale editorial redesign.

### Source comments

Prefer code that explains itself. Add implementation comments only for non-obvious intent, invariants, security constraints, platform workarounds, or complex algorithms. Explain why a choice is necessary; do not narrate ordinary statements.

Remove or update comments made incorrect by the change. Do not add change diaries, task transcripts, redundant section banners, or commented-out implementations. Keep comments close to the code they explain.

### Header and public-interface documentation

Document public and shared interfaces well enough for editor hover information. Use the existing Doxygen-style convention, such as `///`, next to the declaration.

Describe purpose and the contract. Where applicable, include parameter meaning and units, valid ranges, ownership and lifetime, nullability, thread safety, preconditions, return/error behavior, and security requirements. Document exported C ABI allocation and release rules explicitly. Use parameter tags when they add information; avoid boilerplate that repeats names and types.

Keep interface contracts at declarations and implementation rationale in source. Update both when behavior changes.

## Build and validation

Read the affected `CMakeLists.txt`, Cargo manifest, Flutter configuration, and CI workflow for task-specific requirements. The native build uses C++20, CMake 3.25.1 or newer, Ninja, and Rust/Cargo. The normal Linux TPM build also needs system json-c, libcurl, and UUID development packages. Check `cmake/libraries/` for the current dependency setup.

From the repository root, use a compatible existing build directory or configure a new one:

```bash
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

Do not reuse a build directory with an incompatible generator or toolchain. Adjust the directory consistently. Multi-configuration generators also require the appropriate build/test configuration.

Useful scoped checks:

```bash
ctest --test-dir build -N
cmake --build build --target LemonadeNexusSDKShared --parallel
```

CTest discovers GoogleTest case names. Use the listed names to select focused tests with `ctest -R`; do not assume a CMake executable target is a CTest case name. For Rust-only changes, run the relevant crate's checks using its actual manifest path and preserve its lockfile policy.

For Flutter changes, from `apps/LemonadeNexusClient/`:

```bash
flutter pub get
flutter analyze
flutter test
```

Native integration changes may also require rebuilding and staging the SDK shared library for the target platform.

- Run focused checks during development. For a behavior change, add or update tests that prove the intended contract; for a defect, cover the failure that caused it.
- Security changes require relevant rejection cases as well as the valid path. Include replay, substitution, malformed input, restart, or boundary cases when the change affects them.
- Expand validation for shared components, protocol changes, or cross-language integration. Follow applicable CI requirements. Do not rerun unrelated expensive checks without a concrete reason.
- For documentation-only edits, validate links, examples, option names, and formatting. Do not add code tests that merely assert prose or mirror implementation details.
- Do not weaken assertions, disable checks, or modify fixtures to conceal a failure. Separate pre-existing failures from regressions and identify the evidence.
- Report the exact checks run and their results. Identify skips, disabled jobs, missing tools, and unavailable hardware. A skipped hardware test or simulated provider is not production attestation evidence.

## Git and completion

- Review the final diff and run `git diff --check`. Keep unrelated changes and generated/build artifacts out of the deliverable.
- Do not discard user work, reset branches, rewrite history, or force-push without explicit authorization. Editing files alone does not authorize a push, merge, release, or deployment.
- When a commit is requested, use the configured author identity and a concise imperative subject. Explain the reason and relevant validation when a body is useful. **Do not add `Co-authored-by` trailers or agent attribution.**
- Summarize the result, why it was needed, checks performed, and any remaining limitation. Cite changed paths or symbols when useful. Call out outdated documentation or comments found during the task and whether they were corrected.
- Do not claim completion based only on a plan, an unrun command, or an assumed result. If blocked, state the exact blocker and the work that is complete.
