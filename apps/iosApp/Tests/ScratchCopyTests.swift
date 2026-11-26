import Foundation
import XCTest
@testable import ChurScratch

final class ScratchCopyTests: XCTestCase {
    private var directory: URL!
    private var source: URL { directory.appendingPathComponent("source") }
    private var target: URL { directory.appendingPathComponent("target") }

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try FileManager.default.removeItem(at: directory)
    }

    func testCopiesTheExactBudgetWithPrivatePermissions() throws {
        let bytes = Data(repeating: 23, count: 65_536)
        try bytes.write(to: source)
        try ScratchCopy.copy(from: source, to: target, limit: Int64(bytes.count), shouldContinue: { true })
        XCTAssertEqual(try Data(contentsOf: target), bytes)
        let attributes = try FileManager.default.attributesOfItem(atPath: target.path)
        XCTAssertEqual((attributes[.posixPermissions] as? NSNumber)?.intValue, 0o600)
    }

    func testOversizedSourceCreatesNoPlaintextCopy() throws {
        try Data(repeating: 1, count: 5).write(to: source)
        XCTAssertThrowsError(try ScratchCopy.copy(from: source, to: target, limit: 4, shouldContinue: { true })) {
            XCTAssertEqual($0 as? ScratchCopyError, .limitExceeded)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
    }

    func testCancellationRemovesThePartialCopy() throws {
        try Data(repeating: 1, count: 131_072).write(to: source)
        var checks = 0
        XCTAssertThrowsError(try ScratchCopy.copy(from: source, to: target, shouldContinue: {
            checks += 1
            return checks < 3
        })) {
            XCTAssertEqual($0 as? ScratchCopyError, .cancelled)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
    }

    func testExpiredCopyRemovesItsOutput() throws {
        try Data([1]).write(to: source)
        XCTAssertThrowsError(try ScratchCopy.copy(from: source, to: target, timeout: 0, shouldContinue: { true })) {
            XCTAssertEqual($0 as? ScratchCopyError, .timedOut)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
    }

    func testImportsAndExportsShareOneCountAndByteBudget() throws {
        let imports = directory.appendingPathComponent("imports")
        let exports = directory.appendingPathComponent("exports")
        try FileManager.default.createDirectory(at: imports, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: exports, withIntermediateDirectories: true)
        try Data(repeating: 1, count: 3).write(to: imports.appendingPathComponent("one"))
        try Data(repeating: 2, count: 4).write(to: exports.appendingPathComponent("two"))
        XCTAssertEqual(try ScratchCopy.remainingBudget(in: [imports, exports], maxEntries: 3, maxTotal: 10, maxEntry: 4), 3)
        XCTAssertThrowsError(try ScratchCopy.remainingBudget(in: [imports, exports], maxEntries: 2, maxTotal: 10, maxEntry: 4)) {
            XCTAssertEqual($0 as? ScratchCopyError, .limitExceeded)
        }
        XCTAssertThrowsError(try ScratchCopy.remainingBudget(in: [imports, exports], maxEntries: 3, maxTotal: 6, maxEntry: 4)) {
            XCTAssertEqual($0 as? ScratchCopyError, .limitExceeded)
        }
    }

    func testShrinkingSourceRemovesTheIncompleteCopy() throws {
        try Data(repeating: 1, count: 131_072).write(to: source)
        let writer = try FileHandle(forWritingTo: source)
        defer { try? writer.close() }
        XCTAssertThrowsError(try ScratchCopy.copy(from: source, to: target, progress: { processed, _ in
            if processed > 0 { try! writer.truncate(atOffset: UInt64(processed)) }
            return true
        }, shouldContinue: { true })) {
            XCTAssertEqual($0 as? ScratchCopyError, .sourceIncomplete)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
    }

    func testGrowingSourceCannotExceedTheBudget() throws {
        try Data([1]).write(to: source)
        var checks = 0
        XCTAssertThrowsError(try ScratchCopy.copy(from: source, to: target, limit: 2, shouldContinue: {
            checks += 1
            if checks == 2 {
                let append = try! FileHandle(forWritingTo: self.source)
                try! append.seekToEnd()
                try! append.write(contentsOf: Data([2, 3]))
                try! append.close()
            }
            return true
        })) {
            XCTAssertEqual($0 as? ScratchCopyError, .limitExceeded)
        }
        XCTAssertFalse(FileManager.default.fileExists(atPath: target.path))
    }
}
