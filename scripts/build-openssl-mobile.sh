#!/bin/bash
# Builds the static OpenSSL archives for the mobile SDK builds (iOS and
# Android), the same way .github/workflows/deps-openssl.yml builds the macOS and
# Windows ones: the official release tarball checked against its SHA-256,
# static (no-shared), without zlib, zstd and Brotli. deps-openssl.yml runs this
# script for the published archives; run it by hand for a local build and pass
# the output directory to CMake as LEMONADE_NEXUS_OPENSSL_ROOT.
#
# Usage:
#   scripts/build-openssl-mobile.sh <platform> <source-tarball> <out-dir>
#
# platform: ios-arm64 | iossimulator-arm64 | iossimulator-x86_64 |
#           android-arm64-v8a | android-armeabi-v7a | android-x86_64
#
# Writes <out-dir>/include/openssl and <out-dir>/lib/lib{ssl,crypto}.a, and
# <out-dir>/../openssl-<version>-<platform>.tar.gz in the published layout.
#
# Environment:
#   IOS_DEPLOYMENT_TARGET  minimum iOS version (default 15.0)
#   ANDROID_NDK_ROOT       Android NDK (required for android-*)
#   ANDROID_API            minimum Android API level (default 24)
set -euo pipefail

platform="${1:?platform}"
tarball="$(cd "$(dirname "${2:?source tarball}")" && pwd)/$(basename "$2")"
mkdir -p "${3:?output directory}"
out="$(cd "$3" && pwd)"

OPENSSL_OPTIONS="no-shared no-tests no-docs no-ui-console no-zlib no-zstd no-brotli"
IOS_DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET:-15.0}"
ANDROID_API="${ANDROID_API:-24}"

version="$(basename "$tarball" .tar.gz)"
version="${version#openssl-}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tar -xzf "$tarball" -C "$work"
cd "$work/openssl-$version"

extra=()
case "$platform" in
  ios-arm64)
    target=ios64-xcrun
    extra=("-mios-version-min=$IOS_DEPLOYMENT_TARGET")
    ;;
  iossimulator-arm64)
    target=iossimulator-arm64-xcrun
    extra=("-mios-simulator-version-min=$IOS_DEPLOYMENT_TARGET")
    ;;
  iossimulator-x86_64)
    # The generic simulator target takes its architecture from the flags. One
    # argument: Configure reads a bare "x86_64" as a second target name, and
    # the flag string is split again in the generated Makefile.
    target=iossimulator-xcrun
    extra=("-arch x86_64" "-mios-simulator-version-min=$IOS_DEPLOYMENT_TARGET")
    ;;
  android-*)
    : "${ANDROID_NDK_ROOT:?ANDROID_NDK_ROOT must point at the Android NDK}"
    case "$platform" in
      android-arm64-v8a)   target=android-arm64 ;;
      android-armeabi-v7a) target=android-arm ;;
      android-x86_64)      target=android-x86_64 ;;
      *) echo "unknown platform: $platform" >&2; exit 2 ;;
    esac
    host="$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64"
    export PATH="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/$host/bin:$PATH"
    extra=("-D__ANDROID_API__=$ANDROID_API")
    ;;
  *) echo "unknown platform: $platform" >&2; exit 2 ;;
esac

# Target-filesystem paths, as in the desktop archives: the archive holds no
# build-machine path.
./Configure "$target" --prefix=/usr --openssldir=/etc/ssl --libdir=lib \
  $OPENSSL_OPTIONS "${extra[@]}"
make -j"$(getconf _NPROCESSORS_ONLN)" build_libs
make DESTDIR="$PWD/stage" install_dev

rm -rf "$out"
mkdir -p "$out/lib"
cp -R stage/usr/include "$out/include"
cp stage/usr/lib/libssl.a stage/usr/lib/libcrypto.a "$out/lib/"
tar -C "$out" -czf "$(dirname "$out")/openssl-$version-$platform.tar.gz" \
  include/openssl lib/libssl.a lib/libcrypto.a
echo "OpenSSL $version for $platform -> $out"
