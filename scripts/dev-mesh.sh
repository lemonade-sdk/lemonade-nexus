#!/usr/bin/env bash
# Five-process development mesh for the security cutover (M4).
#
# Runs five lemonade-nexus processes on localhost with real UDP transport:
# node 0 is the mesh root and the pinned genesis anchor; nodes 1-4 are
# enrolled Tier-2 servers. On hosts without SEV-SNP the run PROVES the
# fail-closed path: the genesis authority collects candidates, challenges
# them over the wire, receives evidence, records FAILING verdicts, and never
# finalizes an epoch. No flag weakens this; a passing run on this harness
# means the mesh refused to found itself on unproven hardware.
#
# Usage:
#   scripts/dev-mesh.sh [start|check|stop|run]   (default: run)
# Env:
#   BIN   path to the server binary (default: build/projects/LemonadeNexus/lemonade-nexus)
#   WORK  working directory          (default: /tmp/nexus-dev-mesh)
#   WAIT  seconds to observe         (default: 20)

set -u
BIN="${BIN:-build/projects/LemonadeNexus/lemonade-nexus}"
WORK="${WORK:-/tmp/nexus-dev-mesh}"
WAIT="${WAIT:-20}"
NODES=5
MODE="${1:-run}"

say()  { printf '\033[1m[dev-mesh]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[dev-mesh] FAIL:\033[0m %s\n' "$*"; FAILURES=$((FAILURES+1)); }

gossip_port() { echo $((9410 + $1)); }

provision() {
    rm -rf "$WORK"
    mkdir -p "$WORK"

    declare -a GOSSIP
    ROOT_HEX=""

    for i in $(seq 0 $((NODES-1))); do
        mkdir -p "$WORK/n$i"
        out=$("$BIN" --first-run --data-root "$WORK/n$i" 2>&1)
        idhex=$(echo "$out" | sed -n 's/^Identity pubkey:  *\([0-9a-f]*\).*/\1/p')
        gb64=$(echo "$out" | sed -n 's/^Gossip pubkey:    *\([A-Za-z0-9+/=]*\).*/\1/p')
        if [ -z "$gb64" ]; then
            echo "$out"; say "first-run of n$i produced no gossip pubkey"; exit 1
        fi
        GOSSIP[$i]="$gb64"
        [ "$i" -eq 0 ] && ROOT_HEX="$idhex"
    done
    say "root identity: $ROOT_HEX"
    say "genesis anchor (n0 gossip key): ${GOSSIP[0]}"

    # Node 0 (the root holder) enrolls everyone. Its own certificate installs
    # in place; the others' certificates are copied to the joining nodes —
    # the same file movement an operator performs.
    for i in $(seq 0 $((NODES-1))); do
        "$BIN" --enroll-server "${GOSSIP[$i]}" "mesh-n$i" \
               --data-root "$WORK/n0" --root-pubkey "$ROOT_HEX" >"$WORK/enroll-n$i.log" 2>&1
        if [ "$i" -ne 0 ]; then
            cp "$WORK/n0/identity/server_cert_mesh-n$i.json" \
               "$WORK/n$i/identity/server_cert.json" || { say "enroll copy failed for n$i"; exit 1; }
        fi
    done

    # The release signing key must be a valid Ed25519 key for config
    # validation; no release manifest exists in a dev mesh, so no binary is
    # ever approved through it. Reusing the anchor key changes nothing: only
    # a signed manifest could, and none is signed by it.
    RELEASE_B64="${GOSSIP[0]}"

    for i in $(seq 0 $((NODES-1))); do
        seeds='"127.0.0.1:'$(gossip_port 0)'"'
        [ "$i" -eq 0 ] && seeds='"127.0.0.1:'$(gossip_port 1)'"'
        cat > "$WORK/n$i/config.json" <<EOF
{
  "data_root": "$WORK/n$i",
  "bind_address": "127.0.0.1",
  "http_port": $((9210 + i)),
  "private_http_port": $((9260 + i)),
  "udp_port": $((9310 + i)),
  "gossip_port": $(gossip_port "$i"),
  "stun_port": $((9510 + i)),
  "relay_port": $((9610 + i)),
  "dns_port": $((9710 + i)),
  "public_dns_port": $((9710 + i)),
  "wg_interface": "nexusdev$i",
  "log_level": "debug",
  "root_pubkey": "$ROOT_HEX",
  "genesis_pubkey": "${GOSSIP[0]}",
  "release_signing_pubkey": "$RELEASE_B64",
  "seed_peers": [$seeds],
  "ddns_enabled": false,
  "onboard_enabled": false
}
EOF
    done
}

start() {
    for i in $(seq 0 $((NODES-1))); do
        "$BIN" --config "$WORK/n$i/config.json" >"$WORK/n$i.log" 2>&1 &
        echo $! > "$WORK/n$i.pid"
    done
    say "five nodes started (logs: $WORK/n*.log)"
}

stop() {
    for i in $(seq 0 $((NODES-1))); do
        [ -f "$WORK/n$i.pid" ] && kill "$(cat "$WORK/n$i.pid")" 2>/dev/null
    done
    wait 2>/dev/null
    say "stopped"
}

check() {
    FAILURES=0

    for i in $(seq 0 $((NODES-1))); do
        if ! kill -0 "$(cat "$WORK/n$i.pid" 2>/dev/null)" 2>/dev/null; then
            fail "node n$i is not running"
        fi
    done

    # The anchor collects; the others wait for the mesh.
    grep -q 'phase Idle -> GenesisCollecting' "$WORK/n0.log" \
        || fail "n0 never entered GenesisCollecting"

    # Real cross-process attestation: challenges left the anchor and verdicts
    # came back over UDP.
    grep -q 'genesis challenge ->' "$WORK/n0.log" \
        || fail "n0 issued no genesis challenges"
    verdicts=$(grep -c 'genesis verdict for' "$WORK/n0.log" || true)
    [ "$verdicts" -ge 1 ] || fail "n0 recorded no genesis verdicts"

    # Fail-closed: every verdict on unproven hardware fails, so no founding,
    # no epoch, no active phase — anywhere.
    if grep -q 'genesis verdict for .*: PASSED' "$WORK/n0.log"; then
        fail "a verdict PASSED on a host with no platform evidence"
    fi
    for i in $(seq 0 $((NODES-1))); do
        grep -q 'genesis founding' "$WORK/n$i.log" && fail "n$i saw a founding"
        grep -qE 'phase .* -> Active' "$WORK/n$i.log" && fail "n$i went Active"
    done

    if [ "$FAILURES" -eq 0 ]; then
        say "PASS: five processes, real challenges, $verdicts failing verdict(s), no founding, no active epoch"
        return 0
    fi
    say "$FAILURES check(s) failed"
    return 1
}

case "$MODE" in
    start) provision; start ;;
    check) check ;;
    stop)  stop ;;
    run)
        provision
        start
        say "observing for ${WAIT}s..."
        sleep "$WAIT"
        check; rc=$?
        stop
        exit $rc
        ;;
    *) say "unknown mode '$MODE' (start|check|stop|run)"; exit 2 ;;
esac
