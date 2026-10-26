# Native library

The plugin ships the SDK built by `scripts/build-sdk-mobile.sh`:

| Platform | Location in this package |
| --- | --- |
| iOS | `ios/Frameworks/lemonade_nexus_sdk.xcframework` (device arm64 + simulator arm64/x86_64) |
| Android | `android/src/main/jniLibs/<abi>/liblemonade_nexus_sdk.so` (arm64-v8a, armeabi-v7a, x86_64) |

Neither is committed. A local build installs both:

```bash
scripts/build-openssl-mobile.sh <platform> openssl-3.5.9.tar.gz build/mobile/openssl/<platform>   # once per platform
ANDROID_NDK_ROOT=... scripts/build-sdk-mobile.sh
```

When they are missing, the podspec (`pod install`) and the Android build
download the archives named in `manifest.json` from `base_url`, check their
SHA-256 and unpack them. An empty `sha256` means no archive is published for
that version yet; the build then stops and asks for a local build.

CI: `.github/workflows/mobile-sdk.yml` builds both (with a release tag it
also uploads the archives and prints their SHA-256), and
`.github/workflows/deps-openssl-mobile.yml` publishes the pinned mobile
OpenSSL archives it builds against.

To publish by hand: run `scripts/build-sdk-mobile.sh`, upload
`build/mobile/dist/lemonade_nexus_sdk-{ios,android}-<version>.zip` to the
release in `base_url`, and copy the printed SHA-256 values into
`manifest.json`.
