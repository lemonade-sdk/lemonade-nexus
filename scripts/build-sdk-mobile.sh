#!/bin/bash
# Builds the client SDK shared library for iOS and Android and packs it for
# the Flutter plugin in packages/lemonade_nexus_sdk:
#
#   build/mobile/dist/ios/lemonade_nexus_sdk.xcframework   (device arm64 +
#                                                           simulator arm64/x86_64)
#   build/mobile/dist/android/jniLibs/<abi>/liblemonade_nexus_sdk.so
#
# Usage:
#   scripts/build-sdk-mobile.sh [platform...]
#
# platform: ios-arm64 | iossimulator-arm64 | iossimulator-x86_64 |
#           android-arm64-v8a | android-armeabi-v7a | android-x86_64
# (default: all). The XCFramework is packed when the three iOS platforms are
# built; Xcode builds the simulator for both architectures.
#
# OpenSSL comes from LEMONADE_NEXUS_OPENSSL_DIR/<platform> (default
# build/mobile/openssl, as written by scripts/build-openssl-mobile.sh) when it
# exists, otherwise from the pinned archive (cmake/libraries/openssl.cmake).
#
# Environment:
#   IOS_DEPLOYMENT_TARGET  minimum iOS version (default 15.0)
#   ANDROID_NDK_ROOT       Android NDK (required for android-*)
#   ANDROID_API            minimum Android API level (default 24)
#   MOBILE_SDK_VERSION     version in the archive names (default: VERSION).
#                          A rebuild of the same VERSION needs its own, such as
#                          0.9.8.1, so it gets its own release and SHA-256.
set -euo pipefail
cd "$(dirname "$0")/.."
root="$PWD"

IOS_DEPLOYMENT_TARGET="${IOS_DEPLOYMENT_TARGET:-15.0}"
ANDROID_API="${ANDROID_API:-24}"
OPENSSL_DIR="${LEMONADE_NEXUS_OPENSSL_DIR:-$root/build/mobile/openssl}"
DIST="$root/build/mobile/dist"

all=(ios-arm64 iossimulator-arm64 iossimulator-x86_64
     android-arm64-v8a android-armeabi-v7a android-x86_64)
platforms=("$@")
[[ ${#platforms[@]} -eq 0 ]] && platforms=("${all[@]}")

build_one () {
  local platform="$1" bdir="$root/build/mobile/$1"
  local args=(
    -G Ninja -DCMAKE_BUILD_TYPE=Release
    -DLEMONADE_NEXUS_SDK_ONLY=ON -DBUILD_TESTING=OFF -DBUILD_SDK_SHARED=ON
  )
  # A local OpenSSL build when there is one, else the pinned archive.
  if [[ -f "$OPENSSL_DIR/$platform/lib/libcrypto.a" ]]; then
    args+=(-DLEMONADE_NEXUS_OPENSSL_ROOT="$OPENSSL_DIR/$platform")
  fi
  case "$platform" in
    ios-arm64|iossimulator-arm64|iossimulator-x86_64)
      local sysroot=iphoneos target=aarch64-apple-ios arch=arm64
      case "$platform" in
        iossimulator-arm64)  sysroot=iphonesimulator target=aarch64-apple-ios-sim ;;
        iossimulator-x86_64) sysroot=iphonesimulator target=x86_64-apple-ios arch=x86_64 ;;
      esac
      # Rust objects must not require a newer iOS than the framework.
      export IPHONEOS_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET"
      args+=(-DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT="$sysroot"
             -DCMAKE_OSX_ARCHITECTURES="$arch"
             -DCMAKE_OSX_DEPLOYMENT_TARGET="$IOS_DEPLOYMENT_TARGET"
             -DRust_CARGO_TARGET="$target")
      ;;
    android-*)
      : "${ANDROID_NDK_ROOT:?ANDROID_NDK_ROOT must point at the Android NDK}"
      local abi="${platform#android-}" target clang_target
      case "$abi" in
        arm64-v8a)   target=aarch64-linux-android   clang_target=aarch64-linux-android ;;
        armeabi-v7a) target=armv7-linux-androideabi clang_target=armv7a-linux-androideabi ;;
        x86_64)      target=x86_64-linux-android    clang_target=x86_64-linux-android ;;
        *) echo "unknown platform: $platform" >&2; exit 2 ;;
      esac
      # Corrosion links with the NDK's plain clang and passes --target only to
      # the top crate; a dependency that is also a cdylib (boringtun) would be
      # linked for the host. Give every crate built for this triple the target.
      local triple_var
      triple_var="CARGO_TARGET_$(echo "$target" | tr '[:lower:]-' '[:upper:]_')_RUSTFLAGS"
      export "$triple_var=-Clink-arg=--target=$clang_target$ANDROID_API"
      # Static C++ runtime: the .so is self-contained. 16 KB page alignment is
      # required by Google Play for Android 15+ devices.
      args+=(-DCMAKE_TOOLCHAIN_FILE="$ANDROID_NDK_ROOT/build/cmake/android.toolchain.cmake"
             -DANDROID_ABI="$abi" -DANDROID_PLATFORM="android-$ANDROID_API"
             -DANDROID_STL=c++_static -DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON
             -DRust_CARGO_TARGET="$target")
      ;;
    *) echo "unknown platform: $platform" >&2; exit 2 ;;
  esac
  echo ">> $platform"
  cmake -S "$root" -B "$bdir" "${args[@]}"
  cmake --build "$bdir" --target LemonadeNexusSDKShared --parallel
}

for p in "${platforms[@]}"; do build_one "$p"; done

# --- iOS: one XCFramework, device arm64 + universal simulator ---------------
fw () { find "$root/build/mobile/$1" -name lemonade_nexus_sdk.framework -type d -not -path "*/_deps/*" | head -1; }
if [[ -d "$root/build/mobile/ios-arm64" && -d "$root/build/mobile/iossimulator-arm64" \
      && -d "$root/build/mobile/iossimulator-x86_64" ]]; then
  # Drop local symbols; the exported ln_* API stays.
  for p in ios-arm64 iossimulator-arm64 iossimulator-x86_64; do
    xcrun strip -x "$(fw "$p")/lemonade_nexus_sdk"
  done
  # An XCFramework holds one slice per platform: merge the two simulator
  # architectures into one framework.
  sim="$root/build/mobile/iossimulator-universal/lemonade_nexus_sdk.framework"
  rm -rf "$(dirname "$sim")"
  mkdir -p "$(dirname "$sim")"
  cp -R "$(fw iossimulator-arm64)" "$sim"
  lipo -create "$(fw iossimulator-arm64)/lemonade_nexus_sdk" \
    "$(fw iossimulator-x86_64)/lemonade_nexus_sdk" -output "$sim/lemonade_nexus_sdk"
  rm -rf "$DIST/ios/lemonade_nexus_sdk.xcframework"
  mkdir -p "$DIST/ios"
  xcodebuild -create-xcframework \
    -framework "$(fw ios-arm64)" -framework "$sim" \
    -output "$DIST/ios/lemonade_nexus_sdk.xcframework"
fi

# --- Android: jniLibs/<abi>/liblemonade_nexus_sdk.so ------------------------
for p in "${platforms[@]}"; do
  [[ "$p" == android-* ]] || continue
  abi="${p#android-}"
  so="$(find "$root/build/mobile/$p" -name liblemonade_nexus_sdk.so -not -path "*/_deps/*" | head -1)"
  mkdir -p "$DIST/android/jniLibs/$abi"
  host="$(uname -s | tr '[:upper:]' '[:lower:]')-x86_64"
  "$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/$host/bin/llvm-strip" --strip-unneeded \
    -o "$DIST/android/jniLibs/$abi/liblemonade_nexus_sdk.so" "$so"
done

# --- Install into the Flutter plugin and pack the release archives ---------
# The archives are what packages/lemonade_nexus_sdk/native/manifest.json pins.
PKG="$root/packages/lemonade_nexus_sdk"
version="${MOBILE_SDK_VERSION:-$(cat "$root/VERSION")}"
if [[ -d "$DIST/ios/lemonade_nexus_sdk.xcframework" ]]; then
  rm -rf "$PKG/ios/Frameworks"
  mkdir -p "$PKG/ios/Frameworks"
  cp -R "$DIST/ios/lemonade_nexus_sdk.xcframework" "$PKG/ios/Frameworks/"
  rm -f "$DIST/lemonade_nexus_sdk-ios-$version.zip"
  (cd "$DIST/ios" && ditto -c -k --keepParent lemonade_nexus_sdk.xcframework \
    "$DIST/lemonade_nexus_sdk-ios-$version.zip")
fi
if [[ -d "$DIST/android/jniLibs" ]]; then
  rm -rf "$PKG/android/src/main/jniLibs"
  mkdir -p "$PKG/android/src/main"
  cp -R "$DIST/android/jniLibs" "$PKG/android/src/main/"
  rm -f "$DIST/lemonade_nexus_sdk-android-$version.zip"
  (cd "$DIST/android/jniLibs" && zip -qr "$DIST/lemonade_nexus_sdk-android-$version.zip" .)
fi
for zip in "$DIST"/lemonade_nexus_sdk-*-"$version".zip; do
  [[ -f "$zip" ]] && echo "$(basename "$zip") sha256 $(shasum -a 256 "$zip" | cut -d' ' -f1)"
done

echo "done -> $DIST"
