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
- [Release guards](#release-guards)
- [Bootstrap procedure (one time)](#bootstrap-procedure-one-time)
- [The tree operations release (one time)](#the-tree-operations-release-one-time)
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
| `release-approval.json` | The approval (format 3), signed by the release key. `release_number` is the tag's number. `approved_paths` lists this release's hashes; `previous_release_paths` lists the previous release's hashes, so servers on both releases attest each other. After a halted rollout it lists the hashes of the halted release and of the release before it ([Release guards](#release-guards)). The bootstrap release lists none. It also carries the boot line from `release/fleet-profile.json`. |
| `manifest.json`, `manifest.json.sig` | Version, release number, file hashes, wire versions, and the OS package lock. The signature is Ed25519 by the release key over `lemonade-nexus/release-manifest/v1\n` followed by the file. |
| `os-packages.lock` | The exact OS package versions of the release. |
| `*.sigstore.json` | Sigstore build provenance for the file of the same name. |
| `lemonade-nexus-*.deb` | Server package with the signed approval. |
| `.pkg`, `.rpm`, `.tar.gz`, SDK libraries, desktop client zips | Other platforms. They are not covered by the approval. |

After a successful release, the `Live SDK E2E` workflow runs the SDK from
`main` against the production fleet as two real clients. See
[Live SDK E2E](Live-E2E).

Check provenance by hand with `gh`:

```bash
gh attestation verify lemonade-nexus-linux-x86_64 \
  --repo lemonade-sdk/lemonade-nexus \
  --signer-workflow lemonade-sdk/lemonade-nexus/.github/workflows/release.yml@refs/heads/main
```

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
| `source_commit`, `starting_patched_tree` | The source line the fleet kernel and image were built from | With a new release line |
| `ima_policy` | The IMA policy id and SHA-256 | With a policy change |
| `kernel` | Kernel release, bzImage, vmlinux, module tree, and module certificate SHA-256 | With a kernel change, measured on the reference VM |
| `svsm_launch_measurements` | Approved SVSM launch measurements, one per VM shape | With a VM shape change |
| `system_libraries` | SHA-256 of each shared library the server and `nexus-attestd` load: the glibc objects `libc.so.6`, `libm.so.6`, and `ld-linux-x86-64.so.2` | Hash the libraries on the reference VM after a `libc6` package change |

The current values come from release r21 (`v0.9.8-tier1-svsm-epoch1-r21`).

The boot line (`source_commit`, `starting_patched_tree`, `ima_policy`,
`kernel`, `svsm_launch_measurements`) is not compiled into the server
(Design-Auto-Update Phase 0.3). The signed approval carries it, and servers
verify it against that approval only. The approval is signed by the
Genesis-pinned release key and its number must exceed every number a server
accepted, so a reviewed change to this file is the only way to change the boot
line. The compiled floors that stay are the TCB minimum (AMD-SB-3030,
AMD-SB-3034) and the protocol identity (wire and ruleset versions, attestation
profile, attestd wire version), which name what the binary implements.

### `release/os-packages.lock`

The exact package versions of the fleet OS. Generate it on the reference VM:

```bash
scripts/nexus-os-lock boot:grub-efi-amd64-signed boot:shim-signed \
    library:libc6 > release/os-packages.lock
```

Use the package names of the reference image. A change to a `boot` package
needs new `expected_pcrs` in the same pull request; the workflow refuses a lock
that changes the boot chain while the PCRs stay the same, and the reverse.

`libc6` is the only `library` package. The server does not load the
distribution's OpenSSL, zlib, zstd, libstdc++, or libgcc, so the lock does not
pin `libssl3t64`, `zlib1g`, `libzstd1`, `libstdc++6`, or `libgcc-s1`.

### Embedded libraries

The fleet server build links these libraries statically into
`lemonade-nexus`, `nexus-attestd`, and `nexus-updater`:

- OpenSSL: the static `libssl.a` and `libcrypto.a` of Ubuntu 24.04
  `libssl-dev`, installed from the Ubuntu snapshot `UBUNTU_SNAPSHOT` in
  `release.yml`. Configure accepts only the version
  `LEMONADE_NEXUS_OPENSSL_VERSION_UBUNTU` in `cmake/libraries/openssl.cmake`
  (3.0.13). This `libcrypto.a` needs no zlib or zstd.
- libstdc++ and libgcc (`-static-libstdc++ -static-libgcc`).

`LEMONADE_NEXUS_STATIC_DEPS` controls both; it is on by default.

glibc (`libc.so.6`, `libm.so.6`, `ld-linux-x86-64.so.2`) stays shared, and
`system_libraries` pins its hashes. A distribution update of an embedded
library cannot change what attestation measures. The embedded OpenSSL still
reads the host's configuration and CA certificates from its Ubuntu
`OPENSSLDIR`, `/usr/lib/ssl` (Ubuntu links `openssl.cnf` and `certs/` to
`/etc/ssl`). A configuration that activates a provider module (for example,
`legacy`) would load a host module built for the OS OpenSSL; the default
Ubuntu configuration activates none.

An OpenSSL security fix ships in a Nexus release. Ubuntu backports fixes into
new `libssl-dev` package revisions of the same upstream version, so move
`UBUNTU_SNAPSHOT` in `release.yml` to a snapshot that has the fix, in a
reviewed pull request. Change `LEMONADE_NEXUS_OPENSSL_VERSION_UBUNTU` only if
the upstream version changes. The new binary hashes go into the approval as
usual; `release/fleet-profile.json` does not change.

The `server` job checks the binaries before it builds the approval:
`scripts/nexus-release-tool libraries` reads the `NEEDED` entries of
`lemonade-nexus` and `nexus-attestd`. It fails when a binary needs a shared
library that `system_libraries` does not pin, or when `system_libraries` pins
a library that neither binary needs. The approval requires each pinned path in
the IMA log, so a pinned library that is never loaded would fail attestation
on every server.

The `sdk` job builds the Linux SDK shared library with the same static
OpenSSL and fails when it needs `libssl`, `libcrypto`, `libz`, `libzstd`, or
`libsodium`. The SDK keeps the C++ runtime of its host process.

The macOS arm64 and Windows x64 builds link a static OpenSSL archive that
`.github/workflows/deps-openssl.yml` builds from the official source tarball
and publishes on the release `deps-openssl-<version>`, or
`deps-openssl-<version>-r<n>` for a later build of the same version. The macOS
archive targets macOS 11.0, the oldest macOS on Apple silicon. CMake downloads the
archive and checks the SHA-256 pinned in `cmake/libraries/openssl.cmake`
(`LEMONADE_NEXUS_OPENSSL_PREBUILT_*`). A hash mismatch or a failed download
stops the configure step. The build never compiles OpenSSL. The `native` and
`sdk` jobs fail when a macOS binary links a Homebrew, `/usr/local`, or OpenSSL
shared library.

To move to a new OpenSSL version on these platforms:

1. Run `deps-openssl.yml` by hand with the new version and the SHA-256 that
   OpenSSL publishes for its source tarball, and `revision` 1. The workflow
   never replaces an existing asset; to rebuild the same version, run it with
   the next `revision`.
2. In a reviewed pull request, set `LEMONADE_NEXUS_OPENSSL_PREBUILT_VERSION`
   and `LEMONADE_NEXUS_OPENSSL_PREBUILT_RELEASE`, and copy the two printed SHA-256 values into
   `LEMONADE_NEXUS_OPENSSL_PREBUILT_SHA256_MACOS_ARM64` and
   `LEMONADE_NEXUS_OPENSSL_PREBUILT_SHA256_WINDOWS_X64`.

A project that vendors `cmake/libraries/openssl.cmake` and does not define
`LEMONADE_NEXUS_STATIC_DEPS` gets the pinned archive on macOS arm64 and
Windows x64, and the system OpenSSL on other platforms. It must not pass
`-DLEMONADE_NEXUS_STATIC_DEPS=ON` on Linux unless it provides the pinned
Ubuntu `libssl-dev`.

### `release/bootstrap-complete` (one time)

The first date-tagged release is the bootstrap release (Design-Auto-Update
Phase 6). It has no previous release. The workflow detects it; there is no
input or switch for it. A run is the bootstrap release only when both hold:

- no earlier date tag and no published date-tagged release exists, and
- `release/bootstrap-complete` does not exist.

A date tag without a published release, or the file without any date-tagged
release, fails the run.

| File | Content | When |
|---|---|---|
| `release/bootstrap-complete` | The bootstrap tag, one line | After every server runs the bootstrap release ([Bootstrap procedure](#bootstrap-procedure-one-time)). The release after it refuses to publish until this names the bootstrap tag. |

### `release/hand-installed`

A release installed by hand on every server, outside the rolling update, has
no complete rollout records, so no server can prove its rollout. List its tag
in `release/hand-installed` (one tag per line) through a reviewed pull request
after every server runs it and reports healthy. The next release then treats
that rollout as complete and lists its hashes as `previous_release_paths`.
Add a tag only when every server runs that release: a server still on an
older release drops out of attestation when the next release publishes.

## Release guards

The workflow refuses to publish in these cases:

1. **No previous approval.** For every release after the bootstrap release,
   the previous date-tagged release's `release-approval.json` and
   `os-packages.lock` must download. `nexus-release-bundle
   --previous-approval` checks that the same release key signed it for this
   network and copies its hashes to `previous_release_paths`. There is no
   fallback to an approval without the overlap. The bootstrap release has no
   previous release and no overlap.
2. **An open rollout.** Each approval lists the hashes that servers can still
   run. A release published while servers run a release that the new approval
   does not list would drop those servers out of attestation. The `server`
   job fetches a rollout proof from the servers in the repository variable
   `ROLLOUT_PROOF_URLS` (space-separated
   `https://<server>/api/upgrade/rollout-proof` URLs) and runs
   `nexus-rollout-check`. The proof must verify from the Genesis key that
   derives `network_id` in the fleet profile, through the epoch authority
   chain and the commit proof of every upgrade record. The previous release's
   published approval must be the approval that the finalized Start record
   names. The servers are not trusted for the result; a server that holds no
   complete proof answers 503 and the next URL is tried. Without the variable,
   or without a verifying proof, the release fails.
   - **Complete:** the new approval lists the previous release's hashes as
     `previous_release_paths`.
   - **Halted:** the servers in the Upgraded records run the halted release,
     and every other server runs the release before it. The new release is
     the fix. `nexus-release-bundle --previous-halted` lists the hashes of
     both releases: the halted approval's `approved_paths` and its
     `previous_release_paths`.
   - **Open, or any other state:** the release fails.

   After the approval is built, `nexus-rollout-check --approval` checks it
   against the same proof. It passes only when `previous_release_paths` holds
   exactly the hashes that the proven state requires for every path, with the
   same release signer and network and a higher release number. A fix that
   omits either release's hashes fails. An approval that keeps an older
   release after a completed rollout also fails. For the release after the
   bootstrap release, `release/bootstrap-complete` replaces the proof: the
   bootstrap release has no rollout records. For the release after a release
   listed in `release/hand-installed`, that file replaces the proof.
3. **A failed mixed-version gate.** The `mixed-version` job
   (`mixed-version.yml`) runs the previous release's server next to the new
   one. For the bootstrap release this job is skipped: there is no previous
   release, and every server installs the bootstrap release by hand.

Why a Tier 1 proof and not a status file: a status file that each updater
publishes would be a self-report by individual servers, and every server
would need a credential to publish it. A rollout proof is finalized state: a
Tier 1 quorum signed every record, witnesses observed every upgrade, and CI
checks it from the Genesis key with no trust in the server that serves it.

## Bootstrap procedure (one time)

The servers move to the release line once, with the bootstrap release and a
fresh founding. No server keeps state from an earlier release. There is no
storage state yet, so a fresh founding is safe here, and only here. After this
procedure, every release installs in place and the network is never founded
again.

1. Run the release workflow. With no earlier date-tagged release and no
   `release/bootstrap-complete`, the run is the bootstrap release. It needs
   no previous approval and no rollout proof, and it skips the mixed-version
   gate.
2. On every server, stop the services and remove `<data_root>/security/`
   and `<data_root>/sealed/`. They hold the epoch, consensus, storage-key,
   release, upgrade, and sealed state of the earlier release. Nothing from
   them is migrated.
3. Install the bootstrap release's server package on every server by hand.
   The package carries the signed approval at
   `/usr/lib/lemonade-nexus/release/release-approval.json`.
4. Found the network fresh. The founding Genesis key must be the key behind
   `network_id` in `release/fleet-profile.json`: the approval names that
   network, and that key signed the delegation of `release_signer`. A
   different Genesis key needs a reviewed change of `network_id` and
   `authority_genesis_signature` (a new delegation of the release key) before
   step 1.
5. Confirm that every server reaches its role: Tier 1 members active in
   Epoch 1, the data key unlocked, and Tier 2 servers attested.
6. Commit `release/bootstrap-complete` with the bootstrap tag through a
   reviewed pull request. The next release refuses to publish until the file
   names that tag.

## The tree operations release (one time)

**Empty start (no tree data kept).** When the fleet is installed directly
with each Tier 1 server's `data/tree` moved aside, no merge is needed: Tier 1
commits the application root for `root_pubkey` as tree log height 1 by itself
(see [Tree Merge Ceremony](Tree-Merge-Ceremony#empty-start-no-tree-data-kept)).
`sudo nexus-tree-migrate` on ns1 only confirms that no server awaits a merge.

**Keeping existing trees.** The rest of this section applies when the trees
must survive.

The first release in which tree operations always run (no
`tree_ops_enabled` setting) needs one owner step after its rollout: the
[Tree Merge Ceremony](Tree-Merge-Ceremony). The rollout itself is a normal
release; no server is deployed by hand.

1. **Release.** Run the release workflow as usual. The release needs no
   configuration change: a configuration that still names `tree_ops_enabled`
   or `tree_log_enabled` starts and logs that the setting is ignored.
2. **Rolling update.** `nexus-updater` installs it on one server at a time.
   On each Tier 1 server the new release keeps the tree it holds, refuses tree
   writes with `503` and `Retry-After` (joins, group edits, invites, moves,
   deletions, account deletion), and votes for no tree block. Tree reads and
   existing tunnels keep working. A server that still runs the old release
   keeps its direct writes until its turn; those writes are in its tree when
   the merge collects it. The health gate passes: the tree log is healthy at
   height 0.
3. **Wait for every server.** The merge refuses to start while any Tier 1
   member runs the old release (it has no export route) and refuses to build
   without an export from every current Tier 1 member.
4. **Owner step on the root server (ns1).** Get the script (the package
   installs it as `/usr/bin/nexus-tree-migrate`; `nexus-updater` replaces only
   the server binaries, so on an updated server fetch `scripts/nexus-tree-migrate`
   from the release tag). Then:

   ```bash
   sudo python3 nexus-tree-migrate \
       --backup /var/lib/lemonade-nexus-backup-20261025-boot/state.tar
   ```

   Review the report: what each server gains and loses, every tie-break, and
   every dropped node. Then sign and deliver with the digest it printed:

   ```bash
   sudo python3 nexus-tree-migrate \
       --backup /var/lib/lemonade-nexus-backup-20261025-boot/state.tar \
       --commit --expect-tree-digest <tree digest from the dry run>
   ```

5. **Check.** On every Tier 1 server `GET /api/tree/sync` shows `"mode":
   "ops"`, `"height": 1`, and the same `"state_root"`. Tree writes work again
   and go through Tier 1 consensus.

Until step 4, tree writes stay refused on the updated servers. There is no
time limit, but plan the rollout and step 4 together.

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
| `/var/lib/nexus-updater/previous/<tag>/` | The files from before `<tag>` was installed. When `<tag>` installs OS packages, `boot/` holds the running kernel's measured initramfs |
| `/run/lemonade-nexus/upgrade.sock` | The server's upgrade control socket, root peers only ([Upgrade Control](Upgrade-Control)) |

A failed release halts on that server until a newer release appears. To retry
the same release after a fix on the host, an operator sets
`halted_release_number` back to 0 in the state file.

The package also disables `unattended-upgrades` and `apt-daily-upgrade.timer`:
every OS change comes through a release.

PCR 9 measures the initramfs, so a rebuilt image stops unsealing and
attestation at the next boot. Two rules keep the measured image:

- Before an OS package install, the updater copies
  `/boot/initrd.img-$(uname -r)` to `previous/<tag>/boot/`. A package can
  rebuild the image through a dpkg trigger. A release without a boot-chain
  change keeps PCR 8/9, so the updater puts the copy back after the install.
  A rollback puts it back in every case. A missing copy fails the update and
  rolls it back.
- The server package (`apt install ./lemonade-nexus-*.deb`) rebuilds the
  initramfs only when its own early-boot files change: a fresh install, or an
  upgrade that changes the AppArmor blob, the initramfs-tools hook and loader,
  or the dracut module. `preinst` records the digest of the installed files,
  and `postinst` compares it with the new files.

## Limits

- **Upgrade turns have no hardware qualification yet.** The turn gate answers
  from finalized UpgradeProgress records (Phase 5). The tests inject the
  `UpgradeHealth` attestation verdicts; no rollout has run on the fleet.
- **A fix after a halt.** A second halt in a row adds the first fix's hashes
  to the next fix, so the overlap grows by one release for each consecutive
  halt until a rollout completes. The approval holds one PCR 8/9 pair, so a
  fix for a halted release that changed the boot chain needs a reviewed
  decision about which boot chain the fix approves.
- **PCR measurement.** A GitHub-hosted runner cannot boot the fleet's SEV-SNP
  guest. PCR 8/9 come from the reviewed profile, and the optional reference VM
  job only compares them. The workflow never computes PCR values.
- **OS package lock.** `release/os-packages.lock` was captured on the
  reference VM. A lock change that touches a `boot` package needs new PCR 8/9
  in `release/fleet-profile.json`, measured on the reference VM. When those
  packages build a new initramfs on each server, the measured PCR 9 is correct
  only if every server builds the same bytes as the reference VM. That is not
  verified.
- **Embedded libraries.** Fleet OS updates of OpenSSL do not reach Nexus. An
  OpenSSL fix reaches the fleet only when a release moves `UBUNTU_SNAPSHOT`;
  track the Ubuntu security notices for `openssl` in Ubuntu 24.04. A local
  build links whatever `libssl-dev` 3.0.13 revision its host has; only the
  release build is snapshot-pinned. The TPM2-TSS link interface still names the system
  libcurl, json-c, and libuuid. The binaries do not need them only because
  they use no symbol from them and Ubuntu's GCC links with `--as-needed`. If a
  change makes a binary need one of them, the `libraries` check fails the
  release.
- **GRUB.** A boot-chain update requires `GRUB_DEFAULT=saved`. Whether GRUB's
  measurement of `grubenv` and of the previous entry gives the old PCR 8/9 is
  not verified on the reference VM. After a server has started on the new
  chain, the sealed boot set is promoted to it; booting the previous entry
  after that point does not unseal.
- **First release.** The `vX.Y.Z-alpha` releases are never a previous
  release: they predate the approval chain and use another security wire
  version. The bootstrap release has no previous release; the fleet moves to
  it by the [Bootstrap procedure](#bootstrap-procedure-one-time).
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
