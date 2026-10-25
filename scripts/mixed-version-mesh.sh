#!/usr/bin/env bash
# Mixed-version gate (Design-Auto-Update Phase 3, docs/Wire-Compatibility.md).
#
# Runs the previous release's server binary next to the new binary in one
# five-process mesh on localhost (scripts/dev-mesh.sh), twice: once with the
# new binary as the Genesis anchor and old binaries as candidates, once the
# other way round.
#
# Without SEV-SNP (the default) the run proves wire compatibility only: the
# anchor challenges every candidate across versions, the evidence comes back
# over the wire, every verdict fails closed, and no new-binary node drops a
# message from an old-binary node as malformed or unknown. It does NOT prove
# founding, epoch transition, storage unlock, or cross attestation.
#
# With NEXUS_MIXED_HARDWARE=snp on an SEV-SNP host with nexus-attestd and a
# qualified approval installed, the run waits for founding and checks that
# both binaries reach Active, that verdicts pass across versions, that an
# epoch activates, and that every node unlocks its data key.
#
# Baseline: the previous date-tagged release. The first date-tagged release is
# the bootstrap release (Design-Auto-Update Phase 6). Every server installs it
# by hand on a fresh founding, so it has no baseline and no mixed-version run.
#
# Usage:
#   scripts/mixed-version-mesh.sh
# Env:
#   BIN        new server binary (default: build/projects/LemonadeNexus/lemonade-nexus)
#   OLD_BIN    previous server binary; when unset it is downloaded
#   OLD_TAG    release tag to download (default: the newest date-tagged release,
#              vYYYY.MM.DD[.N]; the older vX.Y.Z-alpha tags use another security
#              wire version and are not a baseline)
#   OLD_ASSET  asset name pattern (default: lemonade-nexus-*-linux-x86_64)
#   REPO       GitHub repository (default: lemonade-sdk/lemonade-nexus)
#   WORK       working directory (default: /tmp/nexus-mixed-mesh)
#   WAIT       seconds to observe each pass (default: 30; 900 with snp)
#   NEXUS_MIXED_HARDWARE  "snp" for the hardware checks

set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${BIN:-build/projects/LemonadeNexus/lemonade-nexus}"
REPO="${REPO:-lemonade-sdk/lemonade-nexus}"
WORK="${WORK:-/tmp/nexus-mixed-mesh}"
HARDWARE="${NEXUS_MIXED_HARDWARE:-}"
if [ "$HARDWARE" = "snp" ]; then WAIT="${WAIT:-900}"; else WAIT="${WAIT:-30}"; fi
OLD_ASSET="${OLD_ASSET:-lemonade-nexus-*-linux-x86_64}"

say()  { printf '\033[1m[mixed]\033[0m %s\n' "$*"; }
FAILURES=0
fail() { printf '\033[31m[mixed] FAIL:\033[0m %s\n' "$*"; FAILURES=$((FAILURES+1)); }

[ -x "$BIN" ] || { say "new binary $BIN is missing"; exit 2; }

if [ -z "${OLD_BIN:-}" ]; then
    # The download is release data, so it lands in its own empty directory.
    download="$WORK/previous-release"
    rm -rf "$download"
    mkdir -p "$download"
    tag="${OLD_TAG:-$(gh release list --repo "$REPO" --exclude-drafts --limit 100 \
        --json tagName --jq '.[].tagName' |
        grep -E '^v[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[1-9][0-9]?)?$' | sort -V | tail -n 1)}"
    [ -n "$tag" ] || {
        say "no date-tagged release in $REPO: the next release is the bootstrap release,"
        say "which has no baseline (see the header); set OLD_BIN to test another build"
        exit 2
    }
    say "downloading $OLD_ASSET from $REPO $tag"
    gh release download "$tag" --repo "$REPO" --pattern "$OLD_ASSET" --dir "$download" \
        || { say "download failed"; exit 2; }
    OLD_BIN="$(find "$download" -type f -name "${OLD_ASSET}" | head -n 1)"
    [ -n "$OLD_BIN" ] || { say "asset $OLD_ASSET not in $tag"; exit 2; }
    chmod +x "$OLD_BIN"
fi
say "new: $BIN"
say "old: $OLD_BIN"

# Drop reasons in SecurityRouter's DropReason: Malformed = 2, UnknownKind = 3,
# WireVersionMismatch = 14. Only the per-drop debug lines are counted; the
# rate-limited info lines repeat them.
check_new_nodes_decode_old() {
    local pass_dir="$1" old_nodes="$2"
    for i in 0 1 2 3 4; do
        case " $old_nodes " in *" $i "*) continue ;; esac
        local bad skew
        bad=$(grep -cE '\[debug\].*route drop reason=(2|3) ' "$pass_dir/n$i.log" || true)
        [ "$bad" -eq 0 ] || fail "new-binary node n$i dropped $bad message(s) as malformed or unknown"
        skew=$(grep -cE '\[debug\].*route drop reason=14 ' "$pass_dir/n$i.log" || true)
        [ "$skew" -eq 0 ] || fail "new-binary node n$i dropped $skew message(s) of another security \
wire version: the old binary is not a valid baseline (docs/Wire-Compatibility.md)"
    done
    for i in $old_nodes; do
        local unknown
        unknown=$(grep -cE '\[debug\].*route drop reason=3 ' "$pass_dir/n$i.log" || true)
        say "old-binary node n$i ignored $unknown message(s) of a newer kind (allowed: additions;" \
            "a binary older than this drop log reports 0)"
    done
}

check_hardware() {
    local pass_dir="$1"
    grep -q 'bootstrap certificate issued' "$pass_dir/n0.log" || fail "no founding"
    for i in 0 1 2 3 4; do
        grep -qE 'phase .* -> (Active|Idle)' "$pass_dir/n$i.log" || fail "n$i never settled"
        grep -q 'data key unlocked through the holders' "$pass_dir/n$i.log" \
            || fail "n$i did not unlock its data key"
    done
    local passed
    passed=$(grep -c 'genesis verdict for .*: PASSED' "$pass_dir/n0.log" || true)
    [ "$passed" -ge 4 ] || fail "only $passed founder verdict(s) passed across versions"
    grep -qh 'epoch [2-9][0-9]* activated' "$pass_dir"/n*.log || fail "no epoch transition"
}

run_pass() {
    local name="$1" old_nodes="$2"
    local pass_dir="$WORK/$name"
    say "pass $name: old binary on nodes [$old_nodes]"
    if [ "$HARDWARE" = "snp" ]; then
        BIN="$BIN" OLD_BIN="$OLD_BIN" OLD_NODES="$old_nodes" WORK="$pass_dir" \
            "$HERE/dev-mesh.sh" start
        sleep "$WAIT"
        check_hardware "$pass_dir"
        WORK="$pass_dir" "$HERE/dev-mesh.sh" stop
    else
        BIN="$BIN" OLD_BIN="$OLD_BIN" OLD_NODES="$old_nodes" WORK="$pass_dir" WAIT="$WAIT" \
            "$HERE/dev-mesh.sh" run || fail "pass $name: the fail-closed mesh checks failed"
    fi
    check_new_nodes_decode_old "$pass_dir" "$old_nodes"
}

mkdir -p "$WORK"
run_pass new-anchor "1 3"
run_pass old-anchor "0 2 4"

if [ "$FAILURES" -eq 0 ]; then
    if [ "$HARDWARE" = "snp" ]; then
        say "PASS: founding, epoch transition, storage unlock, and attestation across versions"
    else
        say "PASS: wire compatibility across versions (no hardware evidence; see the script header)"
    fi
    exit 0
fi
say "$FAILURES check(s) failed"
exit 1
