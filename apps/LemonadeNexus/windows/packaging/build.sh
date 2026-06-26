# Build script for Lemonade Nexus VPN Windows packages
# Usage: ./build.sh [msix|msi|exe|all|clean] [debug|release]

#!/bin/bash

set -e

# Default values
BUILD_TYPE="${1:-all}"
CONFIGURATION="${2:-release}"

echo "============================================"
echo "Lemonade Nexus VPN - Windows Package Builder"
echo "============================================"
echo "Build Type: $BUILD_TYPE"
echo "Configuration: $CONFIGURATION"
echo "============================================"
echo

# Check if running in correct directory
if [ ! -f "pubspec.yaml" ]; then
    echo "ERROR: Please run this script from the LemonadeNexus directory"
    exit 1
fi

# Clean build
if [ "$BUILD_TYPE" = "clean" ]; then
    echo "Cleaning build artifacts..."
    rm -rf build
    rm -rf .dart_tool
    rm -f .flutter-plugins
    rm -f .flutter-plugins-dependencies
    echo "Clean complete."
    exit 0
fi

# Get Flutter dependencies
echo "Getting Flutter dependencies..."
flutter pub get

# Build Flutter Windows app (only on Windows)
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    echo "Building Flutter Windows app..."
    flutter build windows --"$CONFIGURATION"
    echo "Flutter build completed successfully."
else
    echo "WARNING: Windows build only supported on Windows"
    echo "Skipping Flutter build..."
fi

echo

# Build functions
build_msix() {
    echo "Creating MSIX package..."
    dart run msix:create
    echo "MSIX package created successfully."
}

build_msi() {
    echo "Creating MSI installer..."

    if ! command -v candle &> /dev/null; then
        echo "ERROR: WiX Toolset not found. Please install from https://wixtoolset.org"
        exit 1
    fi

    BUILD_DIR="$(pwd)/build/windows/runner/Release"
    MSI_DIR="$(pwd)/windows/packaging/MSI"

    mkdir -p "$MSI_DIR/obj"

    echo "Compiling WiX source files..."
    candle -arch x64 -dBuildDir="$BUILD_DIR" -out "$MSI_DIR/obj/" "$MSI_DIR/Product.wxs" "$MSI_DIR/Installer.wxs"

    echo "Linking WiX object files..."
    light -cultures:en-us -out "$MSI_DIR/lemonade_nexus_setup.msi" -sval "$MSI_DIR/obj/Product.wixobj" "$MSI_DIR/obj/Installer.wixobj"

    echo "MSI installer created successfully."
}

build_exe() {
    echo "Creating standalone package..."

    BUILD_DIR="$(pwd)/build/windows/runner/Release"
    EXE_DIR="$(pwd)/build/windows/packages/exe"

    mkdir -p "$EXE_DIR"

    cp "$BUILD_DIR/lemonade_nexus.exe" "$EXE_DIR/"
    cp "$BUILD_DIR/flutter_windows.dll" "$EXE_DIR/"
    cp "$BUILD_DIR/icudtl.dat" "$EXE_DIR/"
    cp -r "$BUILD_DIR/data" "$EXE_DIR/"

    echo "Creating ZIP archive..."
    (cd "$EXE_DIR" && zip -r ../../packages/lemonade_nexus_portable.zip .)

    echo "Standalone package created successfully."
}

# Build requested package type
case "$BUILD_TYPE" in
    msix)
        build_msix
        ;;
    msi)
        build_msi
        ;;
    exe)
        build_exe
        ;;
    all)
        echo "Creating all package types..."

        build_msix

        if command -v candle &> /dev/null; then
            build_msi
        else
            echo "WARNING: WiX Toolset not found, skipping MSI build"
        fi

        build_exe

        echo "All packages created."
        ;;
    *)
        echo "Unknown build type: $BUILD_TYPE"
        echo "Usage: $0 [msix|msi|exe|all|clean] [debug|release]"
        exit 1
        ;;
esac

echo
echo "============================================"
echo "Build Complete!"
echo "Output directory: $(pwd)/build/windows"
echo "============================================"
