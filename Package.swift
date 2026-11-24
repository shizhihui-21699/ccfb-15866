// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "PVSAudit",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "pvsaudit", targets: ["pvsaudit"]),
        .library(name: "PVSAuditCore", targets: ["PVSAuditCore"]),
    ],
    targets: [
        .target(
            name: "PVSAuditCore",
            linkerSettings: [
                .linkedLibrary("sqlite3"),
                .linkedFramework("Security"),
            ]
        ),
        .executableTarget(
            name: "pvsaudit",
            dependencies: ["PVSAuditCore"]
        ),
        // Self-tests live in an executable rather than an XCTest target because
        // the build machines here have Command Line Tools only — no XCTest.
        .executableTarget(
            name: "pvsaudit-selftest",
            dependencies: ["PVSAuditCore"]
        ),
    ]
)
