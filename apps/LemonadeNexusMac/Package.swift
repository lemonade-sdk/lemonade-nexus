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
