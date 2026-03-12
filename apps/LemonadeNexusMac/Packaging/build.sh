#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

echo "=== Lemonade Nexus Mac - Build ==="
echo "Project: $PROJECT_DIR"
echo ""

# Clean previous build
echo "[1/4] Cleaning previous build..."
swift package clean 2>/dev/null || true

# Build release
echo "[2/4] Building release..."
swift build -c release

# Create .app bundle
echo "[3/4] Creating .app bundle..."
APP_DIR="$PROJECT_DIR/.build/LemonadeNexus.app"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS"
mkdir -p "$APP_DIR/Contents/Resources"

# Copy Info.plist
cp "$SCRIPT_DIR/Info.plist" "$APP_DIR/Contents/"

# Copy binary
BINARY_PATH="$PROJECT_DIR/.build/release/LemonadeNexusMac"
if [ ! -f "$BINARY_PATH" ]; then
    echo "ERROR: Binary not found at $BINARY_PATH"
    exit 1
fi
cp "$BINARY_PATH" "$APP_DIR/Contents/MacOS/LemonadeNexusMac"

# Copy resources
if [ -f "$PROJECT_DIR/Resources/logo.svg" ]; then
    cp "$PROJECT_DIR/Resources/logo.svg" "$APP_DIR/Contents/Resources/"
fi

# Copy entitlements (for reference)
if [ -f "$SCRIPT_DIR/Entitlements.plist" ]; then
    cp "$SCRIPT_DIR/Entitlements.plist" "$APP_DIR/Contents/Resources/"
fi

# Write PkgInfo
echo -n "APPL????" > "$APP_DIR/Contents/PkgInfo"

# Sign the app
# If SIGNING_IDENTITY is set, use Developer ID signing; otherwise ad-hoc
echo "[4/4] Code signing..."
if [ -n "$SIGNING_IDENTITY" ]; then
    echo "  Signing with identity: $SIGNING_IDENTITY"
    codesign --force --deep --options runtime \
        --sign "$SIGNING_IDENTITY" \
        --entitlements "$SCRIPT_DIR/Entitlements.plist" \
        --timestamp \
        "$APP_DIR"
    echo "  Verifying signature..."
    codesign --verify --deep --strict --verbose=2 "$APP_DIR"
else
    echo "  Ad-hoc signing (no SIGNING_IDENTITY set)"
    codesign --force --deep --sign - \
        --entitlements "$SCRIPT_DIR/Entitlements.plist" \
        "$APP_DIR" 2>/dev/null || echo "Warning: Code signing failed (may need Developer ID)"
fi

echo ""
echo "=== Build Complete ==="
echo "App bundle: $APP_DIR"
echo ""
echo "To run: open \"$APP_DIR\""
echo "To create DMG: $SCRIPT_DIR/create_dmg.sh"
