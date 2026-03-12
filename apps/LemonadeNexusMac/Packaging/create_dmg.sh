#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

APP_NAME="LemonadeNexus"
APP_DIR="$PROJECT_DIR/.build/${APP_NAME}.app"
DMG_DIR="$PROJECT_DIR/.build/dmg"
DMG_OUTPUT="$PROJECT_DIR/.build/${APP_NAME}.dmg"
DMG_VOLUME_NAME="Lemonade Nexus"
DMG_SIZE="50m"

echo "=== Lemonade Nexus Mac - Create DMG ==="
echo ""

# Check that .app exists
if [ ! -d "$APP_DIR" ]; then
    echo "ERROR: App bundle not found at $APP_DIR"
    echo "Run build.sh first."
    exit 1
fi

# Clean previous DMG artifacts
echo "[1/5] Cleaning previous DMG..."
rm -rf "$DMG_DIR"
rm -f "$DMG_OUTPUT"
rm -f "${DMG_OUTPUT/.dmg/.tmp.dmg}"

# Create staging directory
echo "[2/5] Staging DMG contents..."
mkdir -p "$DMG_DIR"
cp -R "$APP_DIR" "$DMG_DIR/"
ln -s /Applications "$DMG_DIR/Applications"

# Create a README file
cat > "$DMG_DIR/.background_info" << 'README_EOF'
Drag Lemonade Nexus to Applications to install.
README_EOF

# Create temporary DMG
echo "[3/5] Creating temporary DMG..."
hdiutil create -srcfolder "$DMG_DIR" \
    -volname "$DMG_VOLUME_NAME" \
    -fs HFS+ \
    -fsargs "-c c=64,a=16,e=16" \
    -format UDRW \
    -size "$DMG_SIZE" \
    "${DMG_OUTPUT/.dmg/.tmp.dmg}"

# Mount temporary DMG
echo "[4/5] Configuring DMG appearance..."
MOUNT_DIR=$(hdiutil attach -readwrite -noverify -noautoopen "${DMG_OUTPUT/.dmg/.tmp.dmg}" | grep -E '^\S+\s+\S+\s+/' | tail -1 | awk '{print $3}')

if [ -n "$MOUNT_DIR" ]; then
    # Set DMG window properties using AppleScript
    osascript << APPLESCRIPT_EOF
    tell application "Finder"
        tell disk "$DMG_VOLUME_NAME"
            open
            set current view of container window to icon view
            set toolbar visible of container window to false
            set statusbar visible of container window to false
            set the bounds of container window to {100, 100, 640, 400}
            set viewOptions to the icon view options of container window
            set arrangement of viewOptions to not arranged
            set icon size of viewOptions to 80
            set position of item "${APP_NAME}.app" of container window to {140, 150}
            set position of item "Applications" of container window to {400, 150}
            close
            open
            update without registering applications
        end tell
    end tell
APPLESCRIPT_EOF

    # Wait for Finder to process
    sleep 2

    # Unmount
    hdiutil detach "$MOUNT_DIR" -quiet 2>/dev/null || hdiutil detach "$MOUNT_DIR" -force 2>/dev/null || true
fi

# Convert to compressed DMG
echo "[5/5] Compressing final DMG..."
hdiutil convert "${DMG_OUTPUT/.dmg/.tmp.dmg}" \
    -format UDZO \
    -imagekey zlib-level=9 \
    -o "$DMG_OUTPUT"

# Clean up
rm -f "${DMG_OUTPUT/.dmg/.tmp.dmg}"
rm -rf "$DMG_DIR"

echo ""
echo "=== DMG Created ==="
echo "Output: $DMG_OUTPUT"
echo "Size: $(du -h "$DMG_OUTPUT" | cut -f1)"
