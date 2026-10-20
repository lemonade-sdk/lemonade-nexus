#!/bin/bash

check() {
    require_binaries /usr/sbin/apparmor_parser grep mount mkdir || return 1
    [ -r /usr/lib/lemonade-nexus/apparmor/nexus-tier1-authority-probe.bin ] || return 1
    return 0
}

depends() {
    echo "base securityfs"
    return 0
}

install() {
    inst_binary /usr/sbin/apparmor_parser
    inst_multiple grep mount mkdir
    inst_simple \
        /usr/lib/lemonade-nexus/apparmor/nexus-tier1-authority-probe.bin \
        /usr/lib/lemonade-nexus/apparmor/nexus-tier1-authority-probe.bin
    # pre-mount/01 runs after securityfs setup and before real-root userspace.
    inst_hook pre-mount 01 "$moddir/nexus-tier1-apparmor.sh"
}
