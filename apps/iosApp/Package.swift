// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ChurScratch",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [.library(name: "ChurScratch", targets: ["ChurScratch"])],
    targets: [
        .target(name: "ChurScratch", path: "Sources", exclude: ["ChurApp.swift", "AdaptiveScene.swift"], sources: ["ScratchCopy.swift", "DirectoryExport.swift", "DocumentImport.swift", "PublicCamera.swift", "IncomingShareInbox.swift", "IncomingShareSelection.swift", "IncomingShareItems.swift", "MediaOriginalSafety.swift", "LivePhotoBundle.swift", "LivePhotoCapture.swift", "LauncherQuickAction.swift"]),
        .testTarget(name: "ChurScratchTests", dependencies: ["ChurScratch"], path: "Tests"),
    ]
)
