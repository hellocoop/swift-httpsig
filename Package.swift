// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "HTTPMessageSignatures",
    platforms: [
        .iOS(.v17),
        .macOS(.v14),
    ],
    products: [
        .library(
            name: "HTTPMessageSignatures",
            targets: ["HTTPMessageSignatures"]
        ),
    ],
    targets: [
        .target(
            name: "HTTPMessageSignatures",
            dependencies: []
        ),
        .testTarget(
            name: "HTTPMessageSignaturesTests",
            dependencies: ["HTTPMessageSignatures"]
        ),
        .executableTarget(
            name: "CrossTest",
            dependencies: ["HTTPMessageSignatures"],
            path: "Sources/CrossTest"
        ),
    ]
)
