import Darwin
import Foundation
import Security
import XCTest
@testable import ChurScratch

final class IncomingShareSelectionTests: XCTestCase {
    private var root: URL!
    private var inbox: IncomingShareInbox!
    private var scratch: URL!
    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let key = try XCTUnwrap(SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048] as CFDictionary, nil))
        inbox = try IncomingShareInbox(root: root.appendingPathComponent("inbox"), publicKey: XCTUnwrap(SecKeyCopyPublicKey(key)), privateKey: key)
        scratch = root.appendingPathComponent("scratch")
        try IncomingShareSelection.prepareScratch(scratch)
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: root) }
    private func makeBatch(_ data: Data, type: String) throws -> URL {
        let source = root.appendingPathComponent("source")
        try data.write(to: source)
        let batch = try inbox.begin()
        try inbox.append(source: source, name: "Original", contentType: type, to: batch, shouldContinue: { true })
        try inbox.finish(batch)
        return try XCTUnwrap(inbox.pending().first)
    }
    func testJpegXlContentWithGenericOrWrongMimeUsesTheMediaPathAndKeepsExactBytes() throws {
        let repository = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let bytes = try Data(contentsOf: repository.appendingPathComponent("tests/media/jpeg-xl/still-container.jxl"))
        for hint in ["application/octet-stream", "text/plain", "image/jpeg", "image/jxl"] {
            let batch = try makeBatch(bytes, type: hint)
            let finished = expectation(description: "JPEG XL media path for \(hint)")
            let selection = try IncomingShareSelection(inbox: inbox, batch: batch, scratch: scratch, onClosed: {})
            selection.load(index: 0, shouldContinue: { true }) { fd, _, type, size, path, release in
                XCTAssertEqual(fd, -1)
                XCTAssertEqual(type, "image/jxl")
                XCTAssertEqual(size, Int64(bytes.count))
                guard let path else { XCTFail("JPEG XL must reach the media decoder"); finished.fulfill(); return }
                XCTAssertEqual(URL(fileURLWithPath: path).pathExtension, "jxl")
                XCTAssertEqual(try? Data(contentsOf: URL(fileURLWithPath: path)), bytes)
                release()
                XCTAssertFalse(FileManager.default.fileExists(atPath: path))
                finished.fulfill()
            }
            wait(for: [finished], timeout: 10)
            selection.close()
        }
    }
    func testDocumentStreamsExactBytesWithoutPlaintextScratch() throws {
        let bytes = Data(repeating: 37, count: 2 * IncomingShareInbox.chunkSize + 5)
        let batch = try makeBatch(bytes, type: "application/pdf")
        let finished = expectation(description: "read pipe")
        let selection = try IncomingShareSelection(inbox: inbox, batch: batch, scratch: scratch, onClosed: {})
        selection.load(index: 0, shouldContinue: { true }) { fd, name, type, size, path, release in
            XCTAssertGreaterThanOrEqual(fd, 0); XCTAssertNil(path)
            XCTAssertEqual(name, "Original"); XCTAssertEqual(type, "application/pdf"); XCTAssertEqual(size, Int64(bytes.count))
            DispatchQueue.global().async {
                let input = FileHandle(fileDescriptor: fd, closeOnDealloc: false)
                XCTAssertEqual(try? input.readToEnd(), bytes)
                release(); finished.fulfill()
            }
        }
        wait(for: [finished], timeout: 10)
        XCTAssertTrue(try FileManager.default.contentsOfDirectory(atPath: scratch.path).isEmpty)
        selection.close()
        XCTAssertTrue(try inbox.pending().isEmpty)
    }
    func testCorruptFinalChunkRejectsBeforeExposingAnySourceDescriptor() throws {
        let batch = try makeBatch(Data(repeating: 8, count: 2 * IncomingShareInbox.chunkSize + 17), type: "text/plain")
        let file = try XCTUnwrap(inbox.entries(batch).first)
        var bytes = try Data(contentsOf: file); bytes[bytes.count - 1] ^= 1; try bytes.write(to: file)
        let finished = expectation(description: "malformed source rejected")
        let selection = try IncomingShareSelection(inbox: inbox, batch: batch, scratch: scratch, onClosed: {})
        selection.load(index: 0, shouldContinue: { true }) { fd, _, _, _, path, release in
            XCTAssertEqual(fd, -1); XCTAssertNil(path); release(); finished.fulfill()
        }
        wait(for: [finished], timeout: 10)
        selection.close()
    }
    func testMediaGetsProtectedRandomURLUntilConsumerRelease() throws {
        let bytes = Data([1, 2, 3, 4])
        let batch = try makeBatch(bytes, type: "image/png")
        let finished = expectation(description: "media URL")
        let selection = try IncomingShareSelection(inbox: inbox, batch: batch, scratch: scratch, onClosed: {})
        selection.load(index: 0, shouldContinue: { true }) { fd, name, _, _, path, release in
            XCTAssertEqual(fd, -1); XCTAssertEqual(name, "Original")
            guard let path else { XCTFail("No media URL"); finished.fulfill(); return }
            XCTAssertTrue(path.hasPrefix(self.scratch.path + "/"))
            XCTAssertFalse(path.contains("Original"))
            XCTAssertEqual(try? Data(contentsOf: URL(fileURLWithPath: path)), bytes)
            release(); release()
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
            finished.fulfill()
        }
        wait(for: [finished], timeout: 10)
        selection.close()
    }
    func testCloseCancelsBlockedProducerAndRemovesBatch() throws {
        let batch = try makeBatch(Data(repeating: 3, count: 2 * IncomingShareInbox.chunkSize), type: "application/octet-stream")
        let finished = expectation(description: "pipe offered")
        let selection = try IncomingShareSelection(inbox: inbox, batch: batch, scratch: scratch, onClosed: {})
        selection.load(index: 0, shouldContinue: { true }) { fd, _, _, _, _, _ in
            XCTAssertGreaterThanOrEqual(fd, 0)
            selection.close()
            XCTAssertEqual(fcntl(fd, F_GETFD), -1)
            finished.fulfill()
        }
        wait(for: [finished], timeout: 10)
        XCTAssertTrue(try inbox.pending().isEmpty)
    }
    func testLockDropsActiveMediaButKeepsUnopenedEncryptedBatch() throws {
        let batch = try makeBatch(Data([1, 2, 3]), type: "image/png")
        let selection = try IncomingShareSelection(inbox: inbox, batch: batch, scratch: scratch, onClosed: {})
        selection.cancelPlaintext()
        XCTAssertEqual(try inbox.pending(), [batch])
        let finished = expectation(description: "still usable after unlock")
        selection.load(index: 0, shouldContinue: { true }) { _, _, _, _, path, release in
            guard let path else { XCTFail("Queue lost on lock"); finished.fulfill(); return }
            XCTAssertTrue(FileManager.default.fileExists(atPath: path))
            selection.cancelPlaintext()
            XCTAssertFalse(FileManager.default.fileExists(atPath: path))
            XCTAssertTrue(FileManager.default.fileExists(atPath: batch.path))
            release(); finished.fulfill()
        }
        wait(for: [finished], timeout: 10)
        selection.close()
        XCTAssertTrue(try inbox.pending().isEmpty)
    }

    func testExpiredMediaLeaseDeletesCopyAndRequestsOperationCancellation() throws {
        let batch = try makeBatch(Data([1, 2, 3]), type: "image/png")
        let offered = expectation(description: "offered")
        let expired = expectation(description: "expired")
        var output: String?
        let selection = try IncomingShareSelection(inbox: inbox, batch: batch, scratch: scratch,
            lifetime: 0.15, onExpired: { expired.fulfill() }, onClosed: {})
        selection.load(index: 0, shouldContinue: { true }) { _, _, _, _, path, _ in
            output = path; offered.fulfill()
        }
        wait(for: [offered, expired], timeout: 5)
        XCTAssertFalse(FileManager.default.fileExists(atPath: try XCTUnwrap(output)))
        selection.close()
    }

    func testStartupRemovesAbandonedMediaCopy() throws {
        let stale = scratch.appendingPathComponent("opaque.png")
        try Data([1]).write(to: stale)
        try IncomingShareSelection.prepareScratch(scratch)
        XCTAssertFalse(FileManager.default.fileExists(atPath: stale.path))
    }
}
