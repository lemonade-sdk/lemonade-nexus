#!/usr/bin/env bash
# auto-update.sh — Automatically check for and install new lemonade-nexus .deb releases
#
# Usage:
#   sudo ./auto-update.sh              # Run once
#   sudo ./auto-update.sh --install    # Install as a systemd timer (runs every 15 min)
#   sudo ./auto-update.sh --uninstall  # Remove the systemd timer
#
# Environment (optional):
#   GITHUB_REPO    — GitHub repo (default: lemonade-sdk/lemonade-nexus)
#   CHECK_INTERVAL — Systemd timer interval (default: 15min)

set -euo pipefail

REPO="${GITHUB_REPO:-lemonade-sdk/lemonade-nexus}"
SERVICE_NAME="lemonade-nexus"
DEB_PATTERN="lemonade-nexus-*.deb"
DOWNLOAD_DIR="/tmp/lemonade-nexus-update"
LOG_TAG="lemonade-nexus-updater"
CHECK_INTERVAL="${CHECK_INTERVAL:-15min}"
VERSION_FILE="/var/lib/lemonade-nexus/.installed-release"

log() { logger -t "$LOG_TAG" "$*"; echo "[$(date '+%H:%M:%S')] $*"; }

# Compare two semver strings (strips leading 'v'). Returns 0 if $1 > $2.
version_gt() {
    local a="${1#v}" b="${2#v}"
    # Split on dots and compare numerically
    local IFS='.-'
    read -ra va <<< "$a"
    read -ra vb <<< "$b"
    local max=$(( ${#va[@]} > ${#vb[@]} ? ${#va[@]} : ${#vb[@]} ))
    for ((i=0; i<max; i++)); do
        local pa="${va[i]:-0}" pb="${vb[i]:-0}"
        # Compare numeric parts numerically, alpha parts lexically
        if [[ "$pa" =~ ^[0-9]+$ ]] && [[ "$pb" =~ ^[0-9]+$ ]]; then
            (( pa > pb )) && return 0
            (( pa < pb )) && return 1
        else
            [[ "$pa" > "$pb" ]] && return 0
            [[ "$pa" < "$pb" ]] && return 1
        fi
    done
    return 1  # equal
}

# ---- Install/uninstall systemd timer ----

install_timer() {
    cat > /etc/systemd/system/${SERVICE_NAME}-updater.service <<UNIT
[Unit]
Description=Lemonade Nexus Auto-Updater
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$(realpath "$0")
StandardOutput=journal
StandardError=journal
UNIT

    cat > /etc/systemd/system/${SERVICE_NAME}-updater.timer <<UNIT
[Unit]
Description=Check for Lemonade Nexus updates every ${CHECK_INTERVAL}

[Timer]
OnBootSec=2min
OnUnitActiveSec=${CHECK_INTERVAL}
RandomizedDelaySec=60

[Install]
WantedBy=timers.target
UNIT

    systemctl daemon-reload
    systemctl enable --now ${SERVICE_NAME}-updater.timer
    log "Installed systemd timer (interval: ${CHECK_INTERVAL})"
    systemctl status ${SERVICE_NAME}-updater.timer --no-pager
    exit 0
}

uninstall_timer() {
    systemctl disable --now ${SERVICE_NAME}-updater.timer 2>/dev/null || true
    rm -f /etc/systemd/system/${SERVICE_NAME}-updater.{service,timer}
    systemctl daemon-reload
    log "Removed systemd timer"
    exit 0
}

case "${1:-}" in
    --install)   install_timer ;;
    --uninstall) uninstall_timer ;;
esac

# ---- Main update logic ----

# Fetch the latest release JSON once (avoid duplicate API calls / rate limits)
RELEASE_JSON=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null) || true

if [[ -z "$RELEASE_JSON" ]]; then
    log "ERROR: Could not fetch latest release from GitHub"
    exit 1
fi

LATEST=$(echo "$RELEASE_JSON" | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')

if [[ -z "$LATEST" ]]; then
    log "ERROR: Could not parse release tag from GitHub response"
    exit 1
fi

# Check currently installed release
CURRENT=""
if [[ -f "$VERSION_FILE" ]]; then
    CURRENT=$(cat "$VERSION_FILE" 2>/dev/null || true)
fi

if [[ "$CURRENT" == "$LATEST" ]]; then
    log "Already on latest release: $LATEST"
    exit 0
fi

if [[ -n "$CURRENT" ]] && ! version_gt "$LATEST" "$CURRENT"; then
    log "Installed version ($CURRENT) is already >= latest release ($LATEST)"
    exit 0
fi

log "New release available: $LATEST (current: ${CURRENT:-none})"

# Find the .deb asset URL from cached response
DEB_URL=$(echo "$RELEASE_JSON" \
    | grep '"browser_download_url"' \
    | grep '\.deb"' \
    | head -1 \
    | sed 's/.*"\(https:\/\/[^"]*\.deb\)".*/\1/')

if [[ -z "$DEB_URL" ]]; then
    log "No .deb asset found in release $LATEST — skipping"
    exit 0
fi

log "Downloading: $DEB_URL"
mkdir -p "$DOWNLOAD_DIR"
DEB_FILE="${DOWNLOAD_DIR}/lemonade-nexus-${LATEST}.deb"
curl -fsSL -o "$DEB_FILE" "$DEB_URL"

if [[ ! -s "$DEB_FILE" ]]; then
    log "ERROR: Downloaded file is empty"
    rm -f "$DEB_FILE"
    exit 1
fi

log "Installing $DEB_FILE"
dpkg -i "$DEB_FILE" || apt-get install -f -y

# Record the installed version
mkdir -p "$(dirname "$VERSION_FILE")"
echo "$LATEST" > "$VERSION_FILE"

# Restart (or start) the service
log "Restarting $SERVICE_NAME service"
systemctl restart "$SERVICE_NAME" 2>/dev/null || systemctl start "$SERVICE_NAME" 2>/dev/null || true

# Cleanup
rm -rf "$DOWNLOAD_DIR"

log "Updated to $LATEST successfully"
