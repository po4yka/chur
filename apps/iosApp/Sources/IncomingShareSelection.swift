import Darwin
import Foundation
import UniformTypeIdentifiers

/// One batch, with plaintext leases only after explicit vault confirmation.
final class IncomingShareSelection: @unchecked Sendable {
    typealias Loaded = (Int32, String?, String, Int64, String?, @escaping () -> Void) -> Void
    private let lock = NSLock()
    private var active = true
    private var closed = false
    private var cancellationEpoch = 0
    private var leases: [UUID: IncomingShareLease] = [:]
    private let inbox: IncomingShareInbox
    private let batch: URL
    private let files: [URL]
    private let scratch: URL
    private let onClosed: () -> Void
    private let onExpired: () -> Void
    private let lifetime: TimeInterval
    var batchID: String { batch.lastPathComponent }
    var count: Int { files.count }

    init(inbox: IncomingShareInbox, batch: URL, scratch: URL, lifetime: TimeInterval = 30 * 60,
        onExpired: @escaping () -> Void = {}, onClosed: @escaping () -> Void) throws {
        self.inbox = inbox; self.batch = batch; self.files = try inbox.entries(batch)
        self.scratch = scratch; self.onClosed = onClosed
        self.lifetime = lifetime; self.onExpired = onExpired
    }
    private var isActive: Bool { lock.lock(); defer { lock.unlock() }; return active }
    func cancelPlaintext() {
        lock.lock(); cancellationEpoch += 1; let current = Array(leases.values); leases.removeAll(); lock.unlock()
        current.forEach { $0.close() }
    }
    func close() {
        lock.lock()
        guard !closed else { lock.unlock(); return }
        closed = true; active = false; lock.unlock()
        cancelPlaintext()
        inbox.discard(batch)
        onClosed()
    }
    func load(index: Int, shouldContinue: @escaping () -> Bool, loaded: @escaping Loaded) {
        guard files.indices.contains(index), isActive else { loaded(-1, nil, "application/octet-stream", 0, nil, {}); return }
        DispatchQueue.global(qos: .userInitiated).async {
            let id = UUID()
            let lease = IncomingShareLease(lifetime: self.lifetime) { [weak self] in
                DispatchQueue.main.async {
                    guard let self, self.isActive else { return }
                    self.onExpired()
                }
            }
            self.lock.lock()
            let accepted = self.active
            let epoch = self.cancellationEpoch
            if accepted { self.leases[id] = lease }
            self.lock.unlock()
            guard accepted else { loaded(-1, nil, "application/octet-stream", 0, nil, {}); return }
            let continuing = {
                self.lock.lock(); let current = self.active && self.cancellationEpoch == epoch; self.lock.unlock()
                return current && lease.isActive && shouldContinue()
            }
            let release = {
                lease.close()
                self.lock.lock(); self.leases.removeValue(forKey: id); self.lock.unlock()
            }
            var delivered = false
            do {
                guard continuing() else { throw IncomingShareFailure.cancelled }
                let reader = try self.inbox.open(self.files[index], shouldContinue: continuing)
                let meta = reader.metadata
                let jpegXl = try reader.isJpegXl(shouldContinue: continuing)
                let nativeType = UTType(mimeType: meta.contentType)
                let isMedia = jpegXl || nativeType.map {
                    $0.conforms(to: .image) || $0.conforms(to: .movie) || $0.conforms(to: .audio)
                } == true
                // Existing ImageIO/AVFoundation codecs need a file URL. Only media
                // uses protected scratch; documents and text always stream.
                if isMedia,
                    let budget = try? ScratchCopy.remainingBudget(in: [self.scratch,
                        FileManager.default.temporaryDirectory.appendingPathComponent("chur-media-imports"),
                        FileManager.default.temporaryDirectory.appendingPathComponent("chur-exports")]), meta.size <= budget {
                    let suffix = jpegXl ? "jxl" : nativeType?.preferredFilenameExtension ?? "bin"
                    let target = self.scratch.appendingPathComponent(UUID().uuidString).appendingPathExtension(suffix)
                    let fd = Darwin.open(target.path, O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW, S_IRUSR | S_IWUSR)
                    guard fd >= 0 else { throw IncomingShareFailure.unavailable }
                    defer { Darwin.close(fd) }
                    // Keep the file until the producer exits even if cancellation
                    // runs during decryption. unlink is safe while fd remains open.
                    lease.add { try? FileManager.default.removeItem(at: target) }
                    // Keep data protection mandatory on iOS; host tests use owner-only files.
                    #if os(iOS)
                    try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: target.path)
                    #endif
                    try reader.stream(to: fd, shouldContinue: continuing)
                    guard continuing() else { throw IncomingShareFailure.cancelled }
                    delivered = true
                    loaded(-1, meta.name, jpegXl ? "image/jxl" : meta.contentType, meta.size, target.path, release)
                } else {
                    var descriptors: [Int32] = [-1, -1]
                    guard pipe(&descriptors) == 0 else { throw IncomingShareFailure.unavailable }
                    let readFD = descriptors[0]; let writeFD = descriptors[1]
                    lease.add { Darwin.close(readFD) }
                    defer { Darwin.close(writeFD) }
                    guard continuing() else { throw IncomingShareFailure.cancelled }
                    delivered = true
                    loaded(readFD, meta.name, meta.contentType, meta.size, nil, release)
                    try reader.stream(to: writeFD, shouldContinue: continuing)
                }
            } catch {
                release()
                if !delivered { loaded(-1, nil, "application/octet-stream", 0, nil, {}) }
            }
        }
    }
    static func prepareScratch(_ directory: URL) throws {
        if FileManager.default.fileExists(atPath: directory.path) { try FileManager.default.removeItem(at: directory) }
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
            attributes: [.protectionKey: FileProtectionType.complete])
        try (directory as NSURL).setResourceValue(true, forKey: .isExcludedFromBackupKey)
    }
}
private final class IncomingShareLease: @unchecked Sendable {
    private let lock = NSLock()
    private var active = true
    private var cleanup: [() -> Void] = []
    private var timer: DispatchSourceTimer?
    init(lifetime: TimeInterval, expired: @escaping () -> Void) {
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        self.timer = timer
        timer.schedule(deadline: .now() + lifetime)
        timer.setEventHandler { [weak self] in
            guard let self, self.closeOnce() else { return }
            expired()
        }
        timer.resume()
    }
    var isActive: Bool { lock.lock(); defer { lock.unlock() }; return active }
    func add(_ body: @escaping () -> Void) { lock.lock(); if active { cleanup.append(body); lock.unlock() } else { lock.unlock(); body() } }
    @discardableResult private func closeOnce() -> Bool {
        lock.lock(); guard active else { lock.unlock(); return false }
        active = false; let current = cleanup; cleanup.removeAll(); let currentTimer = timer; timer = nil; lock.unlock()
        currentTimer?.cancel(); current.forEach { $0() }; return true
    }
    func close() { closeOnce() }
    deinit { timer?.cancel() }
}
