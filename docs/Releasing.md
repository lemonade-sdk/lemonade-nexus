---
layout: default
title: Releasing
---

# Releasing

One GitHub Actions workflow, `.github/workflows/release.yml`, builds, versions,
signs, and publishes a release. Servers install it in place with
`nexus-updater`. The design is in
[Design: In-Place Auto-Update](Design-Auto-Update).

## Table of Contents
- [Run a release](#run-a-release)
- [What a release contains](#what-a-release-contains)
- [Repository settings](#repository-settings)
- [Reviewed release inputs](#reviewed-release-inputs)
- [The updater on a server](#the-updater-on-a-server)
- [Limits](#limits)

## Run a release

1. Open **Actions → Release → Run workflow**.
2. Select the branch `main`. The workflow refuses every other ref.
3. Approve the two `release` environment deployments when they ask (the
   approval signature, then the manifest signature).

There are no inputs. The workflow picks the version from the UTC date:

| Release of the day | Tag | Release number |
|---|---|---|
| First | `vYYYY.MM.DD` | `YYYYMMDD * 100 + 1` |
| Second, third, ... | `vYYYY.MM.DD.2`, `.3`, ... | `YYYYMMDD * 100 + N` |

The workflow fails if the tag already exists. Servers refuse a release whose
number is not greater than the one they have installed.

Do not push `v*` tags by hand. A tag push no longer starts a release.

## What a release contains

| Asset | Purpose |
|---|---|
| `lemonade-nexus-linux-x86_64`, `nexus-attestd-linux-x86_64` | Fleet server binaries, built in the pinned Ubuntu 24.04 / GCC 13.3 container. `nexus-updater` installs these. |
| `nexus-updater-linux-x86_64` | The updater binary, for operators. The updater does not replace itself. |
| `release-approval.json` | The approval, signed by the release key. It lists the new hashes first and the previous release's hashes after them. |
| `manifest.json`, `manifest.json.sig` | Version, release number, file hashes, wire versions, and the OS package lock. The signature is Ed25519 by the release key over `lemonade-nexus/release-manifest/v1\n` followed by the file. |
| `os-packages.lock` | The exact OS package versions of the release. |
| `*.sigstore.json` | Sigstore build provenance for the file of the same name. |
| `lemonade-nexus-*.deb` | Server package with the signed approval. |
| `.pkg`, `.rpm`, `.tar.gz`, SDK libraries, desktop client zips | Other platforms. They are not covered by the approval. |

Check provenance by hand with `gh`:

```bash
gh attestation verify lemonade-nexus-linux-x86_64 \
  --repo lemonade-sdk/lemonade-nexus \
  --signer-workflow lemonade-sdk/lemonade-nexus/.github/workflows/release.yml@refs/heads/main
```

`scripts/nexus-release-ingest` runs the same check for several files.

## Repository settings

The workflow depends on these settings. A repository administrator sets them;
the workflow does not change them.

### Environment `release` and the secret

1. **Settings → Environments → New environment**, name `release`.
2. **Deployment branches and tags:** "Selected branches and tags", add only
   `main`. A run from any other ref cannot read the secret.
3. **Required reviewers:** at least one maintainer. Enable "Prevent self-review"
   so the person who dispatches a release cannot approve its signing alone.
4. Turn off "Allow administrators to bypass configured protection rules".
5. **Environment secret** `RELEASE_SIGNING_KEY`: base64 of the 32-byte Ed25519
   seed (the output of `scripts/generate_release_signing_key.py`) or of the
   64-byte libsodium secret key. Its public half must equal `release_signer`
   in `release/fleet-profile.json`, which Genesis delegated. The signing step
   checks this before it signs.

Only the `approve` and `publish` jobs use the environment. Only their signing
step receives the secret, and `scripts/nexus-release-sign` passes the key to
`openssl` through a pipe. It never prints or writes the key.

### Branch protection on `main`

Use a branch ruleset (or classic branch protection) for `main`:

- Require a pull request with at least one approving review. Dismiss stale
  approvals on new commits. Require approval of the most recent push.
- Require the CI status checks to pass.
- Block force pushes and deletion.
- Apply the rules to administrators too (no bypass list).

Anyone who can change `main` or run the workflow can ship code to the mesh.
These rules are the control for that risk.

### Tags

Add a tag ruleset for `v*` that blocks updates and deletion. Do not block tag
creation: the workflow creates the tag with the job token.

### Who may dispatch

`workflow_dispatch` requires write access to the repository. Give write access
only to maintainers (**Settings → Collaborators and teams**). The environment
reviewers are the second person on every release.

Under **Settings → Actions → General**, keep the default workflow permissions
at "Read repository contents". `release.yml` asks for more only in the jobs
that need it.

### Optional: reference VM runner

To compare the fleet profile's PCR 8/9 with a real measurement in every
release, register a self-hosted runner on the reference VM and set the
repository variable `REFERENCE_VM_RUNNER` to its label. The
`measure-boot-chain` job then runs `scripts/nexus-measure-boot-chain` there and
fails the release on a mismatch. Without the variable the job is skipped.

## Reviewed release inputs

CI cannot measure the fleet's boot chain or read its system libraries. These
inputs live in the repository and change only through reviewed pull requests.

### `release/fleet-profile.json`

| Field | Content | How to update |
|---|---|---|
| `network_id`, `release_signer` | The network and the Genesis-delegated release key | Never in a normal release |
| `authority_genesis_signature` | Genesis signature over the release authority (public) | Only with a new Genesis delegation |
| `expected_pcrs` | PCR 8/9 of the boot chain that `os-packages.lock` pins | Boot the reference VM with the new lock, run `scripts/nexus-measure-boot-chain` |
| `svsm_launch_measurements` | Approved SVSM launch measurements | With a VM shape change; must match the compiled set |
| `system_libraries` | SHA-256 of each pinned system library | Hash the libraries on the reference VM after a library package change |

The current values come from release r21 (`v0.9.8-tier1-svsm-epoch1-r21`).

### `release/os-packages.lock`

The exact package versions of the fleet OS. Generate it on the reference VM:

```bash
scripts/nexus-os-lock boot:grub-efi-amd64-signed boot:shim-signed \
    library:libc6 library:libssl3t64 library:libstdc++6 library:libgcc-s1 \
    library:zlib1g library:libzstd1 > release/os-packages.lock
```

Use the package names of the reference image. A change to a `boot` package
needs new `expected_pcrs` in the same pull request; the workflow refuses a lock
that changes the boot chain while the PCRs stay the same, and the reverse.

## The updater on a server

The package installs `nexus-updater.timer` (enabled, not started). It runs one
cycle three minutes after boot and every 15 minutes after the last cycle.

```bash
systemctl status nexus-updater.timer
journalctl -u nexus-updater
cat /var/lib/nexus-updater/state.json
```

| Path | Content |
|---|---|
| `/var/lib/nexus-updater/state.json` | Installed and halted release numbers, the update phase, the last result |
| `/var/lib/nexus-updater/staged/<tag>/` | Verified files waiting for the upgrade turn |
| `/var/lib/nexus-updater/previous/<tag>/` | The files from before `<tag>` was installed |
| `/run/lemonade-nexus/update-control.sock` | The server's control socket (owner-only) |

A failed release halts on that server until a newer release appears. To retry
the same release after a fix on the host, an operator sets
`halted_release_number` back to 0 in the state file.

The package also disables `unattended-upgrades` and `apt-daily-upgrade.timer`:
every OS change comes through a release.

## Limits

- **The upgrade turn is a stub.** Until Phase 5, the server's turn gate
  refuses every restart. A cycle verifies and stages a release and installs
  nothing.
- **Approval change on restart (Phase 0 gate 1).** Until Phase 2 lands, a
  server refuses to recover with an approval other than the one its bootstrap
  certificate commits. The health gate then fails, and the updater rolls back.
- **PCR measurement.** A GitHub-hosted runner cannot boot the fleet's SEV-SNP
  guest. PCR 8/9 come from the reviewed profile, and the optional reference VM
  job only compares them. The workflow never computes PCR values.
- **No pinned packages yet.** `release/os-packages.lock` lists no packages:
  the fleet's package versions are not in this repository. Releases change no
  OS package and never reboot until the lock is seeded from the reference VM.
- **GRUB.** A boot-chain update requires `GRUB_DEFAULT=saved`. Whether GRUB's
  measurement of `grubenv` and of the previous entry gives the old PCR 8/9 is
  not verified on the reference VM. After a server has started on the new
  chain, the sealed boot set is promoted to it; booting the previous entry
  after that point does not unseal.
- **First release.** The latest GitHub release before the first date release
  has no `release-approval.json`, so the first date release lists only its own
  hashes. The fleet moves from r21 by the one-time procedure in Phase 6.
- **Provenance.** The updater accepts only Rekor v1 entries with an inclusion
  promise, against the trusted root pinned in the package
  (`release/sigstore-trusted-root.json`). A Sigstore key rotation or a move to
  Rekor v2 needs an updater release.
- **Reproducible builds.** The server build pins the image digest, the Ubuntu
  snapshot, GCC 13.3, the Rust toolchain, source paths, and
  `SOURCE_DATE_EPOCH`. A second run at the same commit is expected to give the
  same hashes; no run has confirmed this yet.
- **The updater does not update itself.** Its hash is not in the approval.
  Install a new updater with the package.
