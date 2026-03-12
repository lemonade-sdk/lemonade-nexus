// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "LemonadeNexusMac",
    platforms: [
        .macOS(.v14)
    ],
    targets: [
        .executableTarget(
            name: "LemonadeNexusMac",
            path: "Sources/LemonadeNexusMac"
        )
    ]
)
