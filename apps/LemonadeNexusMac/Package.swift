// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "LemonadeNexusMac",
    platforms: [
        .macOS(.v14)
    ],
    targets: [
        .target(
            name: "CLemonadeNexusSDK",
            path: "Sources/CLemonadeNexusSDK",
            publicHeadersPath: "include"
        ),
        .executableTarget(
            name: "LemonadeNexusMac",
            dependencies: ["CLemonadeNexusSDK"],
            linkerSettings: [
                // Link against the pre-built SDK and all deps (all from CMake build tree)
                .unsafeFlags([
                    "-L", "../../build/projects/LemonadeNexusSDK",
                    "-lLemonadeNexusSDK",
                    "-L", "../../build",
                    "-llemonade_boringtun_ffi",
                    "-L", "../../build/_deps/sodium-build",
                    "-lsodium",
                    "-L", "../../build/_deps/spdlog-build",
                    "-lspdlog",
                    "-L", "../../build/openssl-install/lib",
                    "-lssl", "-lcrypto",
                ]),
                .linkedLibrary("z"),
                .linkedLibrary("c++"),
                .linkedFramework("Security"),
                .linkedFramework("SystemConfiguration"),
                .linkedFramework("CoreFoundation"),
            ]
        ),
        // Tunnel helper — tiny binary that runs BoringTun with root privileges.
        // The main app launches this via AppleScript privilege escalation so the
        // GUI never needs to run as root.
        .executableTarget(
            name: "LemonadeNexusTunnelHelper",
            dependencies: ["CLemonadeNexusSDK"],
            linkerSettings: [
                .unsafeFlags([
                    "-L", "../../build/projects/LemonadeNexusSDK",
                    "-lLemonadeNexusSDK",
                    "-L", "../../build",
                    "-llemonade_boringtun_ffi",
                    "-L", "../../build/_deps/sodium-build",
                    "-lsodium",
                    "-L", "../../build/_deps/spdlog-build",
                    "-lspdlog",
                    "-L", "../../build/openssl-install/lib",
                    "-lssl", "-lcrypto",
                ]),
                .linkedLibrary("z"),
                .linkedLibrary("c++"),
                .linkedFramework("Security"),
                .linkedFramework("SystemConfiguration"),
                .linkedFramework("CoreFoundation"),
            ]
        ),
    ]
)
