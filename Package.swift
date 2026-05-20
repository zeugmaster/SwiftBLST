// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "SwiftBLST",
    platforms: [
        .macOS(.v13), .iOS(.v16), .tvOS(.v16), .watchOS(.v9)
    ],
    products: [
        .library(name: "SwiftBLST", targets: ["SwiftBLST"]),
        .library(name: "Cblst", targets: ["Cblst"])
    ],
    targets: [
        .target(
            name: "Cblst",
            path: "Sources/Cblst",
            exclude: ["vendor/src", "vendor/build"],
            sources: ["blst.c", "assembly.S"],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include"),
                .headerSearchPath("vendor/src"),
                .headerSearchPath("vendor/build"),
                .define("__BLST_PORTABLE__")
            ]
        ),
        .target(name: "SwiftBLST", dependencies: ["Cblst"]),
        .testTarget(name: "SwiftBLSTTests", dependencies: ["SwiftBLST"])
    ]
)
