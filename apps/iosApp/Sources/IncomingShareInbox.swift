import CryptoKit
import Darwin
import Foundation
import Security

/// Local, write-only inbox. The extension gets a public key, never vault keys.
enum IncomingShareFailure: Error { case unavailable, invalid, limit, cancelled }

final class IncomingShareInbox: @unchecked Sendable {
    static let group = "group.dev.po4yka.chur.incoming"
    static let entryLimit: Int64 = 4 * 1024 * 1024 * 1024
    static let totalLimit: Int64 = 8 * 1024 * 1024 * 1024
    static let itemLimit = 64
    static let lifetime: TimeInterval = 24 * 60 * 60
    static let chunkSize = 1024 * 1024
    private static let magic = Data("CHURIN01".utf8)
    let root: URL
    private let publicKey: SecKey
    private let privateKey: SecKey?

    init(root: URL, publicKey: SecKey, privateKey: SecKey? = nil) throws {
        self.root = root; self.publicKey = publicKey; self.privateKey = privateKey
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.complete])
        try (root as NSURL).setResourceValue(true, forKey: .isExcludedFromBackupKey)
    }

    static func open(forApplication: Bool) throws -> IncomingShareInbox {
        guard let groupRoot = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: group) else {
            throw IncomingShareFailure.unavailable
        }
        let root = groupRoot.appendingPathComponent("inbox", isDirectory: true)
        let publicURL = groupRoot.appendingPathComponent("ingress-public-key")
        if forApplication {
            let tag = Data("dev.po4yka.chur.incoming.rsa.v1".utf8)
            let query: [CFString: Any] = [kSecClass: kSecClassKey, kSecAttrApplicationTag: tag,
                kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecReturnRef: true]
            var found: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &found)
            let key: SecKey
            if status == errSecSuccess, let found { key = (found as! SecKey) }
            else if status == errSecItemNotFound {
                var error: Unmanaged<CFError>?
                guard let created = SecKeyCreateRandomKey([
                    kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048,
                    kSecPrivateKeyAttrs: [kSecAttrIsPermanent: true, kSecAttrApplicationTag: tag,
                        kSecAttrAccessible: kSecAttrAccessibleWhenUnlockedThisDeviceOnly],
                ] as CFDictionary, &error) else { throw IncomingShareFailure.unavailable }
                key = created
            } else { throw IncomingShareFailure.unavailable }
            guard let publicKey = SecKeyCopyPublicKey(key), let bytes = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
                throw IncomingShareFailure.unavailable
            }
            try bytes.write(to: publicURL, options: .atomic)
            try (publicURL as NSURL).setResourceValue(true, forKey: .isExcludedFromBackupKey)
            return try IncomingShareInbox(root: root, publicKey: publicKey, privateKey: key)
        }
        let bytes = try Data(contentsOf: publicURL, options: .mappedIfSafe)
        guard bytes.count <= 1024, let key = SecKeyCreateWithData(bytes as CFData,
            [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic,
             kSecAttrKeySizeInBits: 2048] as CFDictionary, nil) else { throw IncomingShareFailure.unavailable }
        return try IncomingShareInbox(root: root, publicKey: key)
    }

    private func locked<T>(_ body: () throws -> T) throws -> T {
        let fd = Darwin.open(root.appendingPathComponent("lock").path, O_CREAT | O_RDWR | O_NOFOLLOW, S_IRUSR | S_IWUSR)
        guard fd >= 0 else { throw IncomingShareFailure.unavailable }
        defer { Darwin.close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw IncomingShareFailure.unavailable }
        defer { flock(fd, LOCK_UN) }
        return try body()
    }
    private func directories() throws -> [URL] {
        try FileManager.default.contentsOfDirectory(at: root, includingPropertiesForKeys: [.creationDateKey, .isDirectoryKey])
            .filter { $0.pathExtension == "ready" || $0.pathExtension == "pending" }
    }
    private func prune() throws {
        for url in try directories() {
            let values = try url.resourceValues(forKeys: [.creationDateKey, .isDirectoryKey, .isSymbolicLinkKey])
            guard values.isDirectory == true, values.isSymbolicLink != true else { throw IncomingShareFailure.invalid }
            if Date().timeIntervalSince(values.creationDate ?? .distantPast) > Self.lifetime {
                try FileManager.default.removeItem(at: url)
            }
        }
    }
    func begin() throws -> URL {
        try locked {
            try prune()
            guard try directories().count < 8 else { throw IncomingShareFailure.limit }
            let batch = root.appendingPathComponent(UUID().uuidString + ".pending", isDirectory: true)
            try FileManager.default.createDirectory(at: batch, withIntermediateDirectories: false,
                attributes: [.protectionKey: FileProtectionType.complete])
            return batch
        }
    }
    func discard(_ batch: URL) { try? locked { try FileManager.default.removeItem(at: batch) } }
    func finish(_ batch: URL) throws {
        try locked {
            let files = try entries(batch)
            guard !files.isEmpty, files.count <= Self.itemLimit else { throw IncomingShareFailure.invalid }
            try FileManager.default.moveItem(at: batch, to: batch.deletingPathExtension().appendingPathExtension("ready"))
        }
    }
    func pending() throws -> [URL] {
        try locked {
            try prune()
            return try directories().filter { $0.pathExtension == "ready" }.sorted { $0.lastPathComponent < $1.lastPathComponent }
        }
    }
    func entries(_ batch: URL) throws -> [URL] {
        let files = try FileManager.default.contentsOfDirectory(at: batch, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey])
        guard files.count <= Self.itemLimit else { throw IncomingShareFailure.limit }
        for file in files {
            let values = try file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
            guard values.isRegularFile == true, values.isSymbolicLink != true, file.pathExtension == "cipher" else { throw IncomingShareFailure.invalid }
        }
        return files.sorted { $0.lastPathComponent < $1.lastPathComponent }
    }

    struct Metadata: Codable, Equatable { let name: String; let contentType: String; let size: Int64 }

    func append(source: URL, name: String, contentType: String, to batch: URL, shouldContinue: () -> Bool) throws {
        try locked {
            guard shouldContinue() else { throw IncomingShareFailure.cancelled }
            let inputFD = Darwin.open(source.path, O_RDONLY | O_NOFOLLOW)
            guard inputFD >= 0 else { throw IncomingShareFailure.invalid }
            let input = FileHandle(fileDescriptor: inputFD, closeOnDealloc: true)
            defer { try? input.close() }
            var stat = Darwin.stat()
            guard fstat(inputFD, &stat) == 0, (stat.st_mode & S_IFMT) == S_IFREG,
                stat.st_size >= 0, stat.st_size <= Self.entryLimit else { throw IncomingShareFailure.limit }
            try writeEntry(size: stat.st_size, name: name, contentType: contentType, to: batch,
                shouldContinue: shouldContinue, read: { try input.read(upToCount: $0) })
        }
    }
    func appendText(_ text: String, name: String, to batch: URL, shouldContinue: () -> Bool) throws {
        var bytes = Data(text.utf8)
        defer { bytes.resetBytes(in: 0..<bytes.count) }
        guard bytes.count <= 1024 * 1024 else { throw IncomingShareFailure.limit }
        var offset = 0
        try locked {
            try writeEntry(size: Int64(bytes.count), name: name, contentType: "text/plain", to: batch,
                shouldContinue: shouldContinue, read: { count in
                    let end = min(bytes.count, offset + count)
                    defer { offset = end }
                    return bytes.subdata(in: offset..<end)
                })
        }
    }
    private func writeEntry(size: Int64, name: String, contentType: String, to batch: URL,
        shouldContinue: () -> Bool, read: (Int) throws -> Data?) throws {
            let own = try entries(batch)
            guard own.count < Self.itemLimit else { throw IncomingShareFailure.limit }
            var used: Int64 = 0
            for dir in try directories() {
                for file in try entries(dir) {
                    used += Int64(try file.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0)
                    guard used <= Self.totalLimit else { throw IncomingShareFailure.limit }
                }
            }
            let overhead: Int64 = (size / Int64(Self.chunkSize) + 1) * 32 + 8192
            guard size >= 0, size <= Self.entryLimit, size <= Self.totalLimit - used - overhead else { throw IncomingShareFailure.limit }
            // Provider names are untrusted. A single Swift Character can contain
            // thousands of combining scalars; bound UTF-8 bytes, not graphemes.
            let cleanName = String(decoding: name.utf8.prefix(1024), as: UTF8.self)
            let cleanType = String(decoding: contentType.utf8.prefix(256), as: UTF8.self)
            let meta = Metadata(name: cleanName.isEmpty ? "Shared file" : cleanName, contentType: cleanType, size: size)
            let key = SymmetricKey(size: .bits256)
            var keyBytes = key.withUnsafeBytes { Data($0) }
            defer { keyBytes.resetBytes(in: 0..<keyBytes.count) }
            guard let wrapped = SecKeyCreateEncryptedData(publicKey, .rsaEncryptionOAEPSHA256, keyBytes as CFData, nil) as Data?, wrapped.count == 256 else {
                throw IncomingShareFailure.unavailable
            }
            let header = Self.magic + wrapped
            let output = batch.appendingPathComponent(String(format: "%03d", own.count) + ".cipher")
            let fd = Darwin.open(output.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, S_IRUSR | S_IWUSR)
            guard fd >= 0 else { throw IncomingShareFailure.unavailable }
            let writer = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
            var complete = false
            defer { try? writer.close(); if !complete { try? FileManager.default.removeItem(at: output) } }
            // iOS data protection is not supported by every macOS host filesystem.
            #if os(iOS)
            try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: output.path)
            #endif
            try writer.write(contentsOf: header)
            var metadata = try JSONEncoder().encode(meta)
            defer { metadata.resetBytes(in: 0..<metadata.count) }
            guard metadata.count <= 8192 else { throw IncomingShareFailure.limit }
            try Self.writeFrame(metadata, to: writer, key: key, aad: header + Self.number(0))
            var remaining = size
            var index: UInt32 = 1
            let deadline = ProcessInfo.processInfo.systemUptime + 10 * 60
            while remaining > 0 {
                guard shouldContinue(), ProcessInfo.processInfo.systemUptime < deadline else { throw IncomingShareFailure.cancelled }
                let expected = min(Self.chunkSize, Int(remaining))
                var bytes = Data()
                defer { bytes.resetBytes(in: 0..<bytes.count) }
                while bytes.count < expected {
                    guard shouldContinue(), ProcessInfo.processInfo.systemUptime < deadline,
                        var part = try read(expected - bytes.count), !part.isEmpty else { throw IncomingShareFailure.cancelled }
                    bytes.append(part); part.resetBytes(in: 0..<part.count)
                }
                try Self.writeFrame(bytes, to: writer, key: key, aad: header + Self.number(index))
                remaining -= Int64(bytes.count); index += 1
            }
            guard try read( 1)?.isEmpty != false, shouldContinue() else { throw IncomingShareFailure.cancelled }
            try writer.synchronize(); complete = true
    }
    private static func number(_ value: UInt32) -> Data { var n = value.bigEndian; return withUnsafeBytes(of: &n) { Data($0) } }
    private static func writeFrame(_ bytes: Data, to writer: FileHandle, key: SymmetricKey, aad: Data) throws {
        guard let combined = try AES.GCM.seal(bytes, using: key, authenticating: aad).combined else { throw IncomingShareFailure.invalid }
        try writer.write(contentsOf: number(UInt32(combined.count))); try writer.write(contentsOf: combined)
    }
    private static func exact(_ count: Int, from reader: FileHandle) throws -> Data {
        var result = Data()
        while result.count < count {
            guard let bytes = try reader.read(upToCount: count - result.count), !bytes.isEmpty else { throw IncomingShareFailure.invalid }
            result.append(bytes)
        }
        return result
    }
    private static func readFrame(from reader: FileHandle, key: SymmetricKey, aad: Data, limit: Int) throws -> Data {
        let size = try exact(4, from: reader).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
        guard size >= 28, size <= limit + 28 else { throw IncomingShareFailure.invalid }
        return try AES.GCM.open(AES.GCM.SealedBox(combined: exact(Int(size), from: reader)), using: key, authenticating: aad)
    }
    /// Only called after an unlocked-vault confirmation. Plaintext never touches disk.
    func open(_ file: URL, shouldContinue: () -> Bool = { true }) throws -> Reader {
        guard let privateKey else { throw IncomingShareFailure.unavailable }
        let fd = Darwin.open(file.path, O_RDONLY | O_NOFOLLOW)
        guard fd >= 0 else { throw IncomingShareFailure.invalid }
        let reader = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            let header = try Self.exact(264, from: reader)
            guard header.prefix(8) == Self.magic,
                var bytes = SecKeyCreateDecryptedData(privateKey, .rsaEncryptionOAEPSHA256, header.suffix(256) as CFData, nil) as Data?, bytes.count == 32 else { throw IncomingShareFailure.invalid }
            let key = SymmetricKey(data: bytes); bytes.resetBytes(in: 0..<bytes.count)
            var metadataBytes = try Self.readFrame(from: reader, key: key, aad: header + Self.number(0), limit: 8192)
            defer { metadataBytes.resetBytes(in: 0..<metadataBytes.count) }
            let meta = try JSONDecoder().decode(Metadata.self, from: metadataBytes)
            guard meta.size >= 0, meta.size <= Self.entryLimit, meta.name.utf8.count <= 2048,
                meta.contentType.utf8.count <= 1024 else { throw IncomingShareFailure.limit }
            let result = Reader(handle: reader, key: key, header: header, metadata: meta)
            let payloadOffset = try reader.offset()
            // A pipe EOF is a normal source end to Rust. Verify the whole immutable
            // completed envelope before exposing any bytes, then rewind for import.
            try result.consume(shouldContinue: shouldContinue, write: { _ in })
            try reader.seek(toOffset: payloadOffset)
            return result
        } catch { try? reader.close(); throw error }
    }

    final class Reader {
        private let handle: FileHandle
        private let key: SymmetricKey
        private let header: Data
        let metadata: Metadata
        fileprivate init(handle: FileHandle, key: SymmetricKey, header: Data, metadata: Metadata) {
            self.handle = handle; self.key = key; self.header = header; self.metadata = metadata
        }
        deinit { try? handle.close() }
        /// Checks authenticated content without consuming the later import stream.
        func isJpegXl(shouldContinue: () -> Bool) throws -> Bool {
            guard metadata.size >= 2 else { return false }
            guard shouldContinue() else { throw IncomingShareFailure.cancelled }
            let offset = try handle.offset()
            defer { try? handle.seek(toOffset: offset) }
            var first = try IncomingShareInbox.readFrame(from: handle, key: key,
                aad: header + IncomingShareInbox.number(1), limit: IncomingShareInbox.chunkSize)
            defer { first.resetBytes(in: 0..<first.count) }
            return first.starts(with: [0xff, 0x0a]) ||
                first.starts(with: [0, 0, 0, 12, 0x4a, 0x58, 0x4c, 0x20, 0x0d, 0x0a, 0x87, 0x0a])
        }
        func stream(to descriptor: Int32, shouldContinue: () -> Bool) throws {
            // Suppress SIGPIPE when cancellation closes the native consumer.
            guard fcntl(descriptor, F_SETNOSIGPIPE, 1) == 0 else { throw IncomingShareFailure.unavailable }
            let oldFlags = fcntl(descriptor, F_GETFL)
            guard oldFlags >= 0, fcntl(descriptor, F_SETFL, oldFlags | O_NONBLOCK) == 0 else { throw IncomingShareFailure.unavailable }
            try consume(shouldContinue: shouldContinue) { part in
                try part.withUnsafeBytes { raw in
                    var offset = 0
                    while offset < raw.count {
                        guard shouldContinue() else { throw IncomingShareFailure.cancelled }
                        let n = Darwin.write(descriptor, raw.baseAddress!.advanced(by: offset), raw.count - offset)
                        if n > 0 { offset += n }
                        else if n < 0 && errno == EINTR { continue }
                        else if n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) { usleep(20_000) }
                        else { throw IncomingShareFailure.cancelled }
                    }
                }
            }
        }
        fileprivate func consume(shouldContinue: () -> Bool, write: (Data) throws -> Void) throws {
            var remaining = metadata.size; var index: UInt32 = 1
            while remaining > 0 {
                guard shouldContinue() else { throw IncomingShareFailure.cancelled }
                var part = try IncomingShareInbox.readFrame(from: handle, key: key, aad: header + IncomingShareInbox.number(index), limit: IncomingShareInbox.chunkSize)
                defer { part.resetBytes(in: 0..<part.count) }
                guard !part.isEmpty, part.count == min(IncomingShareInbox.chunkSize, Int(remaining)) else { throw IncomingShareFailure.invalid }
                // Verify trailing framing before releasing the final bytes. A truncated
                // or appended archive cannot become a committed original.
                if Int64(part.count) == remaining {
                    guard try handle.read(upToCount: 1)?.isEmpty != false else { throw IncomingShareFailure.invalid }
                }
                try write(part)
                remaining -= Int64(part.count); index += 1
            }
            if metadata.size == 0 { guard try handle.read(upToCount: 1)?.isEmpty != false else { throw IncomingShareFailure.invalid } }
        }
    }
}
