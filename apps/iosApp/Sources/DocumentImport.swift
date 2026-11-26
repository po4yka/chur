import Darwin
import Foundation
import UniformTypeIdentifiers

/// A transient multi-selection. Closing it drops unconsumed provider URLs.
final class DocumentImportSelection: @unchecked Sendable {
    private let lock = NSLock()
    private var urls: [URL]
    private var active = true
    private var pending: [UUID: (NSFileCoordinator, DocumentImportAnswer)] = [:]
    private let startAccess: (URL) -> Bool
    private let stopAccess: (URL) -> Void

    init(urls: [URL], startAccess: @escaping (URL) -> Bool = { $0.startAccessingSecurityScopedResource() }, stopAccess: @escaping (URL) -> Void = { $0.stopAccessingSecurityScopedResource() }) {
        self.urls = urls
        self.startAccess = startAccess
        self.stopAccess = stopAccess
    }

    var count: Int { lock.lock(); defer { lock.unlock() }; return urls.count }
    private var isActive: Bool { lock.lock(); defer { lock.unlock() }; return active }

    func close() {
        lock.lock(); active = false; urls.removeAll(); let waiting = Array(pending.values); pending.removeAll(); lock.unlock()
        waiting.forEach { coordinator, answer in coordinator.cancel(); _ = answer.opened(nil) }
    }

    func load(index: Int, maxBytes: Int64 = 1 << 40, shouldContinue: @escaping () -> Bool = { true }, opened: @escaping (DocumentImportSource?) -> Void) {
        lock.lock()
        let url = active && urls.indices.contains(index) ? urls[index] : nil
        lock.unlock()
        guard let url else { opened(nil); return }
        let answer = DocumentImportAnswer(opened)
        let check = DocumentImportCheck(shouldContinue)
        DispatchQueue.global(qos: .userInitiated).async {
            guard self.isActive, check.shouldContinue(), self.startAccess(url) else { _ = answer.opened(nil); return }
            let coordinator = NSFileCoordinator()
            let id = UUID()
            self.lock.lock()
            let accepted = self.active
            if accepted { self.pending[id] = (coordinator, answer) }
            self.lock.unlock()
            guard accepted else { self.stopAccess(url); _ = answer.opened(nil); return }
            let monitor = DocumentImportCancellation(coordinator: coordinator, answer: answer, check: check)
            monitor.start()
            var error: NSError?
            let values = try? url.resourceValues(forKeys: [.nameKey, .contentTypeKey])
            let originalName = values?.name ?? url.lastPathComponent
            let originalType = Self.contentType(provider: values?.contentType, originalFilename: originalName)
            coordinator.coordinate(readingItemAt: url, options: [], error: &error) { readable in
                guard self.isActive, check.shouldContinue() else { _ = answer.opened(nil); return }
                let fd = Darwin.open(readable.path, O_RDONLY | O_NOFOLLOW)
                guard fd >= 0 else { _ = answer.opened(nil); return }
                defer { Darwin.close(fd) }
                var status = stat()
                guard fstat(fd, &status) == 0, (status.st_mode & S_IFMT) == S_IFREG,
                      status.st_size >= 0, status.st_size <= maxBytes, self.isActive else {
                    _ = answer.opened(nil); return
                }
                let leased = DocumentImportSource(descriptor: fd, readablePath: readable.path, name: originalName, contentType: originalType, size: status.st_size)
                monitor.stop()
                let delivered = answer.opened(leased)
                // Rust consumes its duplicate while this accessor and the
                // security scope remain active. No plaintext copy is made.
                if delivered { leased.awaitClose() }
            }
            monitor.stop()
            self.lock.lock(); self.pending.removeValue(forKey: id); self.lock.unlock()
            _ = answer.opened(nil)
            self.stopAccess(url)
        }
    }

    static func contentType(provider: UTType?, originalFilename: String) -> String {
        provider?.preferredMIMEType
            ?? UTType(filenameExtension: (originalFilename as NSString).pathExtension)?.preferredMIMEType
            ?? "application/octet-stream"
    }
}

private final class DocumentImportAnswer: @unchecked Sendable {
    private let lock = NSLock()
    private var callback: ((DocumentImportSource?) -> Void)?
    init(_ callback: @escaping (DocumentImportSource?) -> Void) { self.callback = callback }
    @discardableResult func opened(_ source: DocumentImportSource?) -> Bool {
        lock.lock(); let answer = callback; callback = nil; lock.unlock()
        answer?(source)
        return answer != nil
    }
}

private final class DocumentImportCheck: @unchecked Sendable {
    let shouldContinue: () -> Bool
    init(_ shouldContinue: @escaping () -> Bool) { self.shouldContinue = shouldContinue }
}

/// A provider may download before invoking its accessor. Cancellation must
/// wake that wait even before a readable descriptor exists.
private final class DocumentImportCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private let coordinator: NSFileCoordinator
    private let answer: DocumentImportAnswer
    private let check: DocumentImportCheck
    private var timer: DispatchSourceTimer?
    init(coordinator: NSFileCoordinator, answer: DocumentImportAnswer, check: DocumentImportCheck) {
        self.coordinator = coordinator; self.answer = answer; self.check = check
    }
    func start() {
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .userInitiated))
        self.timer = timer
        timer.schedule(deadline: .now() + .milliseconds(100), repeating: .milliseconds(100))
        timer.setEventHandler { [weak self] in
            guard let self, !self.check.shouldContinue() else { return }
            self.coordinator.cancel()
            _ = self.answer.opened(nil)
            self.stop()
        }
        timer.resume()
    }
    func stop() { lock.lock(); let current = timer; timer = nil; lock.unlock(); current?.cancel() }
    deinit { stop() }
}

/// The caller closes this only after native import releases its source fd.
final class DocumentImportSource: @unchecked Sendable {
    let descriptor: Int32
    /// Valid while the coordinated source lease is open.
    let readablePath: String
    let name: String
    let contentType: String
    let size: Int64
    private let lock = NSLock()
    private let closed = DispatchSemaphore(value: 0)
    private var didClose = false

    fileprivate init(descriptor: Int32, readablePath: String, name: String, contentType: String, size: Int64) {
        self.descriptor = descriptor; self.readablePath = readablePath; self.name = name; self.contentType = contentType; self.size = size
    }
    func close() {
        lock.lock()
        guard !didClose else { lock.unlock(); return }
        didClose = true
        lock.unlock()
        closed.signal()
    }
    fileprivate func awaitClose() { closed.wait() }
}
