import Foundation
import UIKit
import UniformTypeIdentifiers

/// A real Share extension. Completion returns to the source app; no URL-opening hacks.
final class ShareViewController: UIViewController {
    private let stateLock = NSLock()
    private var cancelled = false
    private var progress: Progress?
    private let status = UILabel()
    private let save = UIButton(type: .system)
    private let cancel = UIButton(type: .system)
    private var busy = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground
        status.text = "Save this share, then open the app to complete import. Shared links are saved as text; the app does not fetch them."
        status.numberOfLines = 0
        status.font = .preferredFont(forTextStyle: .body)
        status.adjustsFontForContentSizeCategory = true
        status.textAlignment = .center
        save.setTitle("Save files", for: .normal)
        cancel.setTitle("Cancel", for: .normal)
        save.addTarget(self, action: #selector(saveItems), for: .touchUpInside)
        cancel.addTarget(self, action: #selector(cancelShare), for: .touchUpInside)
        for button in [save, cancel] {
            button.titleLabel?.font = .preferredFont(forTextStyle: .headline)
            button.titleLabel?.adjustsFontForContentSizeCategory = true
            button.heightAnchor.constraint(greaterThanOrEqualToConstant: 44).isActive = true
        }
        let scroll = UIScrollView()
        scroll.translatesAutoresizingMaskIntoConstraints = false
        let stack = UIStackView(arrangedSubviews: [status, save, cancel])
        stack.axis = .vertical; stack.spacing = 20; stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(scroll); scroll.addSubview(stack)
        NSLayoutConstraint.activate([
            scroll.leadingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.leadingAnchor),
            scroll.trailingAnchor.constraint(equalTo: view.safeAreaLayoutGuide.trailingAnchor),
            scroll.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scroll.bottomAnchor.constraint(equalTo: view.safeAreaLayoutGuide.bottomAnchor),
            stack.leadingAnchor.constraint(equalTo: scroll.contentLayoutGuide.leadingAnchor, constant: 24),
            stack.trailingAnchor.constraint(equalTo: scroll.contentLayoutGuide.trailingAnchor, constant: -24),
            stack.topAnchor.constraint(equalTo: scroll.contentLayoutGuide.topAnchor, constant: 24),
            stack.bottomAnchor.constraint(equalTo: scroll.contentLayoutGuide.bottomAnchor, constant: -24),
            stack.widthAnchor.constraint(equalTo: scroll.frameLayoutGuide.widthAnchor, constant: -48),
        ])
    }
    private var active: Bool { stateLock.lock(); defer { stateLock.unlock() }; return !cancelled }
    @objc private func cancelShare() {
        stateLock.lock(); cancelled = true; let current = progress; stateLock.unlock()
        current?.cancel()
        extensionContext?.cancelRequest(withError: IncomingShareFailure.cancelled)
    }
    @objc private func saveItems() {
        guard !busy else { return }
        busy = true; save.isEnabled = false; status.text = "Saving shared items…"
        let items = extensionContext?.inputItems.compactMap { $0 as? NSExtensionItem } ?? []
        let providers = IncomingShareItems.providers(from: items)
        guard !providers.isEmpty, providers.count <= IncomingShareInbox.itemLimit else {
            fail("Share 1 to 64 files, text items, or links at a time."); return
        }
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let inbox = try IncomingShareInbox.open(forApplication: false)
                let batch = try inbox.begin()
                var completed = false
                defer { if !completed { inbox.discard(batch) } }
                let seenText = IncomingShareTextSet()
                for provider in providers {
                    guard self.active else { throw IncomingShareFailure.cancelled }
                    try self.save(provider, inbox: inbox, batch: batch, seenText: seenText)
                }
                guard self.active else { throw IncomingShareFailure.cancelled }
                try inbox.finish(batch); completed = true
                DispatchQueue.main.async {
                    guard self.active else { return }
                    self.status.text = "Saved. Open the app to complete import."
                    self.cancel.setTitle("Done", for: .normal)
                    self.cancel.removeTarget(self, action: #selector(self.cancelShare), for: .touchUpInside)
                    self.cancel.addTarget(self, action: #selector(self.complete), for: .touchUpInside)
                }
            } catch {
                DispatchQueue.main.async { self.fail("Could not save this share. Open the app once to prepare sharing, then try again. Check available storage and share at most 4 GiB per file and 8 GiB in total.") }
            }
        }
    }
    @objc private func complete() { extensionContext?.completeRequest(returningItems: nil) }
    private func fail(_ message: String) { guard active else { return }; status.text = message; busy = false; save.isEnabled = true }
    private func save(_ provider: NSItemProvider, inbox: IncomingShareInbox, batch: URL, seenText: IncomingShareTextSet) throws {
        // Provider URLs are valid only inside the completion handler. Encrypt there.
        let selected = provider.registeredTypeIdentifiers.first {
            guard let type = UTType($0) else { return false }
            return type.conforms(to: .data) && !type.conforms(to: .url)
                && (!type.conforms(to: .plainText) || provider.suggestedName != nil)
        }
        if let identifier = selected {
            try waitFor { done in
                provider.loadFileRepresentation(forTypeIdentifier: identifier) { url, _ in
                    guard let url else { done(.failure(IncomingShareFailure.invalid)); return }
                    do {
                        let name = provider.suggestedName ?? url.lastPathComponent
                        let providerType = UTType(identifier)
                        let type = providerType == .data ?
                            (try? url.resourceValues(forKeys: [.contentTypeKey]).contentType) ?? UTType(filenameExtension: url.pathExtension) : providerType
                        try inbox.append(source: url, name: name, contentType: type?.preferredMIMEType ?? "application/octet-stream", to: batch, shouldContinue: { self.active })
                        done(.success(()))
                    } catch { done(.failure(error)) }
                }
            }
        } else if provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            try waitFor { done in
                provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { value, _ in
                    guard let url = value as? URL, url.isFileURL else { done(.failure(IncomingShareFailure.invalid)); return }
                    let scoped = url.startAccessingSecurityScopedResource()
                    defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                    let coordinator = NSFileCoordinator()
                    var coordinationError: NSError?
                    var result: Result<Void, Error> = .failure(IncomingShareFailure.invalid)
                    coordinator.coordinate(readingItemAt: url, options: [], error: &coordinationError) { readable in
                        do {
                            let values = try readable.resourceValues(forKeys: [.contentTypeKey, .nameKey])
                            try inbox.append(source: readable, name: values.name ?? url.lastPathComponent,
                                contentType: values.contentType?.preferredMIMEType ?? "application/octet-stream", to: batch,
                                shouldContinue: { self.active })
                            result = .success(())
                        } catch { result = .failure(error) }
                    }
                    if let coordinationError { done(.failure(coordinationError)) } else { done(result) }
                }
                return Progress(totalUnitCount: 1)
            }
        } else {
            let isURL = provider.hasItemConformingToTypeIdentifier(UTType.url.identifier)
            let identifier = isURL ? UTType.url.identifier : UTType.plainText.identifier
            guard provider.hasItemConformingToTypeIdentifier(identifier) else { throw IncomingShareFailure.invalid }
            try waitFor { done in
                provider.loadItem(forTypeIdentifier: identifier, options: nil) { value, _ in
                    let text: String?
                    if let url = value as? URL, !url.isFileURL { text = url.absoluteString }
                    else if let string = value as? String { text = string }
                    else if let data = value as? Data, data.count <= 1024 * 1024 { text = String(data: data, encoding: .utf8) }
                    else { text = nil }
                    guard let text, text.utf8.count <= 1024 * 1024 else { done(.failure(IncomingShareFailure.limit)); return }
                    // A host may repeat the same payload in its attachment and
                    // attributed body. Keep it once, using exact UTF-8 equality.
                    guard seenText.insert(text) else { done(.success(())); return }
                    // Text is bounded in memory. No temporary plaintext file is created.
                    do { try inbox.appendText(text, name: isURL ? "shared-link.txt" : "shared-text.txt", to: batch, shouldContinue: { self.active }); done(.success(())) }
                    catch { done(.failure(error)) }
                }
                return Progress(totalUnitCount: 1)
            }
        }
    }
    private func waitFor(_ start: (@escaping (Result<Void, Error>) -> Void) -> Progress) throws {
        let answer = ShareProviderAnswer()
        let operation = start { answer.complete($0) }
        stateLock.lock(); progress = operation; stateLock.unlock()
        let deadline = Date().addingTimeInterval(10 * 60)
        while answer.ready.wait(timeout: .now() + .milliseconds(100)) == .timedOut {
            guard active, Date() < deadline else { operation.cancel(); throw IncomingShareFailure.cancelled }
        }
        stateLock.lock(); progress = nil; stateLock.unlock()
        try answer.result!.get()
    }
}
private final class ShareProviderAnswer: @unchecked Sendable {
    let ready = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private(set) var result: Result<Void, Error>?
    func complete(_ result: Result<Void, Error>) { lock.lock(); guard self.result == nil else { lock.unlock(); return }; self.result = result; lock.unlock(); ready.signal() }
}
