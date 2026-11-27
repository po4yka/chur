import Darwin
import Foundation
import Security
import XCTest
@testable import ChurScratch

final class IncomingShareInboxTests: XCTestCase {
    private var root: URL!
    private var inbox: IncomingShareInbox!
    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let key = try XCTUnwrap(SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048] as CFDictionary, nil))
        inbox = try IncomingShareInbox(root: root.appendingPathComponent("inbox"),
            publicKey: XCTUnwrap(SecKeyCopyPublicKey(key)), privateKey: key)
    }
    override func tearDownWithError() throws { try FileManager.default.removeItem(at: root) }
    private func ready(_ data: Data) throws -> URL {
        let source = root.appendingPathComponent("original document.bin")
        try data.write(to: source)
        let batch = try inbox.begin()
        try inbox.append(source: source, name: "private original.bin", contentType: "application/octet-stream", to: batch, shouldContinue: { true })
        try inbox.finish(batch)
        return try XCTUnwrap(inbox.pending().first)
    }
    private func consume(_ file: URL) throws -> (IncomingShareInbox.Metadata, Data) {
        let reader = try inbox.open(file)
        let output = root.appendingPathComponent(UUID().uuidString)
        let fd = Darwin.open(output.path, O_CREAT | O_EXCL | O_RDWR, S_IRUSR | S_IWUSR)
        defer { Darwin.close(fd) }
        try reader.stream(to: fd, shouldContinue: { true })
        return (reader.metadata, try Data(contentsOf: output))
    }
    func testMultipleChunksRoundTripWithoutPlaintextInInbox() throws {
        var data = Data(repeating: 42, count: IncomingShareInbox.chunkSize * 2 + 13)
        data.replaceSubrange(0..<25, with: Data("confidential payload text".utf8))
        let batch = try ready(data)
        let file = try XCTUnwrap(inbox.entries(batch).first)
        let bytes = try Data(contentsOf: file)
        XCTAssertNil(bytes.range(of: Data("confidential payload text".utf8)))
        XCTAssertNil(bytes.range(of: Data("private original.bin".utf8)))
        let (meta, result) = try consume(file)
        XCTAssertEqual(result, data)
        XCTAssertEqual(meta.name, "private original.bin")
        XCTAssertEqual(meta.size, Int64(data.count))
        XCTAssertEqual(try inbox.entries(batch).count, 1)
        inbox.discard(batch)
        XCTAssertTrue(try inbox.pending().isEmpty)
    }
    func testTextAndEmptyFileRoundTripAndPreserveOrder() throws {
        let batch = try inbox.begin()
        try inbox.appendText("Приватный текст\nhttps://example.com", name: "Shared link.txt", to: batch, shouldContinue: { true })
        try inbox.appendText("", name: "Empty.txt", to: batch, shouldContinue: { true })
        try inbox.finish(batch)
        let files = try inbox.entries(XCTUnwrap(inbox.pending().first))
        XCTAssertEqual(String(data: try consume(files[0]).1, encoding: .utf8), "Приватный текст\nhttps://example.com")
        XCTAssertTrue(try consume(files[1]).1.isEmpty)
    }
    func testTamperTruncateAndAppendedBytesAreRejected() throws {
        let batch = try ready(Data(repeating: 7, count: 500))
        let file = try XCTUnwrap(inbox.entries(batch).first)
        let original = try Data(contentsOf: file)
        var corrupted = original; corrupted[corrupted.count - 1] ^= 1
        try corrupted.write(to: file); XCTAssertThrowsError(try consume(file))
        try original.dropLast().write(to: file); XCTAssertThrowsError(try consume(file))
        try (original + Data([0])).write(to: file); XCTAssertThrowsError(try consume(file))
        var header = original; header[0] ^= 1
        try header.write(to: file); XCTAssertThrowsError(try inbox.open(file))
    }
    func testReorderedAuthenticatedChunksAreRejected() throws {
        let batch = try ready(Data(repeating: 5, count: IncomingShareInbox.chunkSize * 2))
        let file = try XCTUnwrap(inbox.entries(batch).first)
        let original = try Data(contentsOf: file)
        func length(_ at: Int) -> Int {
            original[at..<(at + 4)].reduce(0) { ($0 << 8) | Int($1) }
        }
        let first = 264 + 4 + length(264)
        let second = first + 4 + length(first)
        let firstFrame = original[first..<second]
        let secondFrame = original[second..<original.count]
        try (original.prefix(first) + secondFrame + firstFrame).write(to: file)
        XCTAssertThrowsError(try inbox.open(file))
    }

    func testCancelledInputLeavesNoEntryAndUnfinishedBatchIsNotPublished() throws {
        let source = root.appendingPathComponent("source")
        try Data(repeating: 4, count: IncomingShareInbox.chunkSize * 2).write(to: source)
        let batch = try inbox.begin()
        var checks = 0
        XCTAssertThrowsError(try inbox.append(source: source, name: "source", contentType: "x/test", to: batch, shouldContinue: { checks += 1; return checks < 3 }))
        XCTAssertTrue(try inbox.entries(batch).isEmpty)
        XCTAssertTrue(try inbox.pending().isEmpty)
        XCTAssertTrue(FileManager.default.fileExists(atPath: source.path))
        inbox.discard(batch)
    }
    func testRejectsSymlinkSourceAndOversizedText() throws {
        let batch = try inbox.begin()
        let source = root.appendingPathComponent("source")
        try Data([1]).write(to: source)
        let link = root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: source)
        XCTAssertThrowsError(try inbox.append(source: link, name: "link", contentType: "x/test", to: batch, shouldContinue: { true }))
        XCTAssertThrowsError(try inbox.appendText(String(repeating: "a", count: 1024 * 1024 + 1), name: "large", to: batch, shouldContinue: { true }))
        XCTAssertTrue(try inbox.entries(batch).isEmpty)
    }
    func testReaderCancellationStopsBeforeReleasingPlaintext() throws {
        let batch = try ready(Data([1, 2, 3]))
        let reader = try inbox.open(XCTUnwrap(inbox.entries(batch).first))
        let output = root.appendingPathComponent("output")
        let fd = Darwin.open(output.path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR)
        defer { Darwin.close(fd) }
        XCTAssertThrowsError(try reader.stream(to: fd, shouldContinue: { false }))
        XCTAssertEqual(try Data(contentsOf: output).count, 0)
    }
    func testHostileUnicodeAndJsonEscapesStayInsideMetadataByteBounds() throws {
        let source = root.appendingPathComponent("source")
        try Data([1, 2, 3]).write(to: source)
        let batch = try inbox.begin()
        let combiningName = "A" + String(repeating: "\u{0301}", count: 10_000)
        XCTAssertEqual(combiningName.count, 1)
        try inbox.append(source: source, name: combiningName, contentType: combiningName, to: batch, shouldContinue: { true })
        try inbox.append(source: source, name: String(repeating: "\u{0001}", count: 2000),
            contentType: String(repeating: "\u{0002}", count: 1000), to: batch, shouldContinue: { true })
        try inbox.finish(batch)
        let files = try inbox.entries(XCTUnwrap(inbox.pending().first))
        for file in files {
            let (metadata, data) = try consume(file)
            XCTAssertLessThanOrEqual(metadata.name.utf8.count, 1026)
            XCTAssertLessThanOrEqual(metadata.contentType.utf8.count, 258)
            XCTAssertEqual(data, Data([1, 2, 3]))
        }
    }

    func testWriteOnlyExtensionCannotReadEnvelope() throws {
        let batch = try ready(Data([9]))
        let key = try XCTUnwrap(SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048] as CFDictionary, nil))
        let extensionInbox = try IncomingShareInbox(root: inbox.root, publicKey: XCTUnwrap(SecKeyCopyPublicKey(key)))
        XCTAssertThrowsError(try extensionInbox.open(XCTUnwrap(inbox.entries(batch).first)))
    }
}
