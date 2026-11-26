// swift-tools-version: 6.0
import Foundation
import PackageDescription

// build-inbox.sh stages the host archive here before the Swift tests link.
let inboxLibrary = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
    .appendingPathComponent(".build/inbox-native/debug/libchur_ffi.a").path

let package = Package(
    name: "ChurScratch",
    platforms: [.macOS(.v15), .iOS(.v18)],
    products: [.library(name: "ChurScratch", targets: ["ChurScratch"])],
    targets: [
        .systemLibrary(name: "ChurInboxNative", path: "InboxNative"),
        .target(name: "ChurScratch", dependencies: ["ChurInboxNative"], path: "Sources", exclude: ["ChurApp.swift", "AdaptiveScene.swift"], sources: ["ScratchCopy.swift", "DirectoryExport.swift", "DocumentImport.swift", "PublicCamera.swift", "IncomingShareInbox.swift", "IncomingShareSelection.swift", "IncomingShareItems.swift", "MediaOriginalSafety.swift", "LivePhotoBundle.swift", "LivePhotoCapture.swift", "LauncherQuickAction.swift"],
            linkerSettings: [.unsafeFlags(["-Xlinker", inboxLibrary], .when(platforms: [.macOS]))]),
        .testTarget(name: "ChurScratchTests", dependencies: ["ChurScratch"], path: "Tests"),
    ]
)
