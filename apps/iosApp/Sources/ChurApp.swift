import ChurApp
import Darwin
import PhotosUI
import Photos
import UIKit
import UniformTypeIdentifiers

@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    let privacy = IosPrivacyCover()
    private(set) var controller: ChurController!
    private(set) var gate: GateResult!
    private(set) var storageReady = false
    weak var scene: SceneDelegate?
    private var incomingSelection: IncomingShareSelection?
    private var checkingIncoming = false
    private var incomingRefreshCompletions: [() -> Void] = []
    var incomingShareBusy: Bool { checkingIncoming || incomingSelection != nil || IosIncomingShares.shared.hasPending() }
    private var incomingScratchReady = false
    private let incomingScratch = FileManager.default.temporaryDirectory
        .appendingPathComponent("chur-incoming-media", isDirectory: true)

    func refreshIncomingShares(completion: @escaping () -> Void = {}) {
        guard storageReady, gate is GateResultCompatible,
            UIApplication.shared.applicationState == .active else { completion(); return }
        if checkingIncoming {
            incomingRefreshCompletions.append(completion)
            return
        }
        guard incomingSelection == nil, !IosIncomingShares.shared.hasPending() else { completion(); return }
        incomingRefreshCompletions.append(completion)
        checkingIncoming = true
        DispatchQueue.global(qos: .userInitiated).async {
            var prepared: IncomingShareSelection?
            do {
                if !self.incomingScratchReady {
                    try IncomingShareSelection.prepareScratch(self.incomingScratch)
                    self.incomingScratchReady = true
                }
                let inbox = try IncomingShareInbox.openForApplication()
                if let batch = try inbox.pending().first {
                    prepared = try IncomingShareSelection(inbox: inbox, batch: batch,
                        scratch: self.incomingScratch, onExpired: { [weak self] in
                            guard self?.incomingSelection?.batchID == batch.lastPathComponent else { return }
                            IosIncomingShares.shared.cancelImport()
                        }, onClosed: { [weak self] in
                            DispatchQueue.main.async {
                                self?.incomingSelection = nil
                                self?.refreshIncomingShares()
                            }
                        })
                }
            } catch { /* Unavailable App Group or locked Keychain: try on next activation. */ }
            DispatchQueue.main.async {
                self.checkingIncoming = false
                defer {
                    let completions = self.incomingRefreshCompletions
                    self.incomingRefreshCompletions.removeAll()
                    completions.forEach { $0() }
                }
                guard let selected = prepared else { return }
                guard UIApplication.shared.applicationState == .active,
                    !IosIncomingShares.shared.hasPending() else { return }
                self.controller.cancelLauncherAction()
                self.incomingSelection = selected
                _ = IosIncomingShares.shared.offer(count: Int32(selected.count), load: { index, prepare, loaded in
                    selected.load(index: Int(truncating: index), shouldContinue: {
                        prepare(KotlinLong(longLong: 0), KotlinLong(longLong: 0)).boolValue
                    }) { descriptor, name, type, size, path, release in
                        _ = loaded(KotlinInt(int: descriptor), name, type, KotlinLong(longLong: size), path,
                            { release(); return KotlinUnit() })
                    }
                }, releaseSelection: { selected.close() })
            }
        }
    }

    private lazy var publicCamera = PublicCamera(
        presenter: { [weak self] in self?.scene?.window?.rootViewController },
        beginPrompt: { [unowned self] in self.controller.beginPrompt() },
        endPrompt: { [unowned self] in self.controller.endPrompt(bracket: $0) }
    )

    private func updatePublicPresentation(enabled: Bool, shell: String) {
        let app = UIApplication.shared
        let rows: [(LauncherQuickAction, String, String)] = enabled ? [
            (.publicNotes, NSLocalizedString("New note", comment: ""), "square.and.pencil"),
            (.publicCalculator, NSLocalizedString("Calculator", comment: ""), "plus.forwardslash.minus"),
            (.publicCamera, NSLocalizedString("Camera", comment: ""), "camera"),
            (.publicPet, NSLocalizedString("Chur", comment: ""), "sparkles")
        ] : [(.importItems, "Import", "square.and.arrow.down"), (.search, "Search", "magnifyingglass"),
             (.lockAndHide, "Lock and hide", "lock.fill"), (.newPrivateNote, "New private note", "square.and.pencil")]
        app.shortcutItems = rows.map { UIApplicationShortcutItem(type: $0.0.rawValue, localizedTitle: NSLocalizedString($0.1, comment: ""), localizedSubtitle: nil, icon: UIApplicationShortcutIcon(systemImageName: $0.2), userInfo: nil) }
        let icon: String? = enabled ? (shell == "calculator" ? "UtilityCalculator" : shell == "camera" ? "UtilityCamera" : shell == "pet" ? "UtilityPet" : "UtilityNotes") : nil
        if app.supportsAlternateIcons && app.alternateIconName != icon {
            app.setAlternateIconName(icon) { error in
                if error != nil { /* Keep the supported system icon. Retry on the next explicit settings change. */ }
            }
        }
    }

    func cancelPublicCamera() { publicCamera.cancel() }
    func suspendPublicCamera() { publicCamera.suspend() }
    func resumePublicCamera() { publicCamera.resume() }

    private lazy var exports = ShareExportSink(
        present: { [weak self] url, target in
            if let scene = self?.scene {
                scene.presentExport(url, target: target)
            } else {
                try? FileManager.default.removeItem(at: url)
            }
        },
        cancel: { [weak self] in
            self?.incomingSelection?.cancelPlaintext()
            self?.scene?.cancelPendingExports()
        }
    )

    func registerExportDirectory(_ url: URL) -> String? { exports.registerDirectory(url) }

    func application(
        _ application: UIApplication,
        shouldAllowExtensionPointIdentifier extensionPointIdentifier: UIApplication.ExtensionPointIdentifier
    ) -> Bool {
        // Private notes and search use ordinary text fields. Keep their input in the system keyboard.
        extensionPointIdentifier != .keyboard
    }

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        configureAdaptiveBars()
        #if CHUR_FILAMENT
        ChurSpiritRendererInstaller.install()
        #endif
        #if DEBUG
        let releaseApplication = false
        #else
        let releaseApplication = true
        #endif
        gate = IosEntryPointKt.churNativeGate(releaseApplication: releaseApplication)
        controller = IosEntryPointKt.churController(privacy: privacy, exports: exports)

        do {
            for path in [IosEntryPointKt.churStorageRoot()] {
                let url = NSURL(fileURLWithPath: path, isDirectory: true)
                try url.setResourceValue(true, forKey: .isExcludedFromBackupKey)
            }
            storageReady = true
        } catch {
            storageReady = false
        }

        PublicPresentation.shared.version = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""
        PublicPresentation.shared.apply = { [weak self] enabled, shell in
            guard let self, UIApplication.shared.applicationState == .active else { return }
            self.updatePublicPresentation(enabled: enabled.boolValue, shell: shell)
            return
        }
        _ = publicCamera.prepare()
        IosPublicCamera.shared.previewView = { [weak self] in self?.publicCamera.view() ?? UIView() }
        IosPublicCamera.shared.start = { [weak self] in self?.publicCamera.start() }
        IosPublicCamera.shared.capture = { [weak self] in self?.publicCamera.capture() }
        IosPublicCamera.shared.setVideo = { [weak self] value in self?.publicCamera.setVideo(value.boolValue) }
        IosPublicCamera.shared.flip = { [weak self] in self?.publicCamera.flip() }
        IosPublicCamera.shared.setZoom = { [weak self] value in self?.publicCamera.zoom(value.floatValue) }
        IosPublicCamera.shared.setLens = { [weak self] id in self?.publicCamera.lens(id) }
        IosPublicCamera.shared.setExposure = { [weak self] value in self?.publicCamera.exposure(value.floatValue) }
        IosPublicCamera.shared.toggleFlash = { [weak self] in self?.publicCamera.toggleFlash() }
        IosPublicCamera.shared.toggleSound = { [weak self] in self?.publicCamera.toggleSound() }
        IosPublicCamera.shared.list = { [weak self] in self?.publicCamera.list() ?? [] }
        IosPublicCamera.shared.thumbnail = { [weak self] id, edge, answer in
            guard let self else { _ = answer(nil); return }
            self.publicCamera.thumbnail(id, edge: edge.intValue, answer: answer)
        }
        IosPublicCamera.shared.playbackView = { [weak self] id in self?.publicCamera.playback(id) }
        IosPublicCamera.shared.closePlayback = { [weak self] in self?.publicCamera.closePlayback() }
        IosPublicCamera.shared.delete_ = { [weak self] id in self?.publicCamera.delete(id) }
        IosPublicCamera.shared.export_ = { [weak self] ids in self?.publicCamera.export(ids) }
        IosPublicCamera.shared.cancel = { [weak self] in self?.publicCamera.cancel() }
        IosPublicCamera.shared.retry = { [weak self] in self?.publicCamera.retry() }
        let mediaScratchReady = MediaPickerDelegate.prepareScratch()
        IosMediaPicker.shared.present = { [weak self] answer in
            guard mediaScratchReady, let scene = self?.scene else { MediaPickerDelegate.answerNothing(answer); return }
            scene.presentMediaPicker(answer)
        }
        IosLivePhotoPicker.shared.present = { [weak self] answer in
            guard mediaScratchReady, let scene = self?.scene else { MediaPickerDelegate.answerNothing(answer); return }
            scene.presentMediaPicker(answer, fullLivePhotos: true)
        }
        let pairingScratchReady = ApprovalPickerDelegate.prepareScratch()
        IosPairingFiles.shared.presentOpen = { [weak self] answer in
            guard pairingScratchReady, let scene = self?.scene else { _ = answer(nil); return }
            scene.presentApprovalPicker(answer)
        }
        IosPairingFiles.shared.presentSave = { [weak self] path, answer in
            guard pairingScratchReady, let scene = self?.scene else { _ = answer(nil); return }
            scene.presentApprovalExport(path, answer: answer)
        }
        IosBackupPicker.shared.present = { [weak self] request in
            guard let scene = self?.scene else { request.openFailed(); return }
            scene.presentBackupPicker(request)
        }
        IosAlbumExportPicker.shared.present = { [weak self] answer in
            guard let scene = self?.scene else { _ = answer(nil); return }
            scene.presentAlbumExportPicker(answer)
        }
        IosAlbumExportPicker.shared.discard = { [weak self] token in self?.exports.discardDirectory(token) }
        IosDocumentPicker.shared.present = { [weak self] answer in
            guard let scene = self?.scene else { DocumentPickerDelegate.answerNothing(answer); return }
            scene.presentDocumentPicker(answer)
        }
        IosDocumentPicker.shared.cancel = { [weak self] in self?.scene?.cancelDocumentImports() }
        IosMediaFilesPicker.shared.present = { [weak self] answer in
            guard let scene = self?.scene else { DocumentPickerDelegate.answerNoAudio(answer); return }
            scene.presentMediaFilesPicker(answer)
        }
        IosMediaFilesPicker.shared.cancel = { [weak self] in self?.scene?.cancelDocumentImports() }
        IosAudioPicker.shared.present = { [weak self] answer in
            guard let scene = self?.scene else { DocumentPickerDelegate.answerNoAudio(answer); return }
            scene.presentAudioPicker(answer)
        }
        IosAudioPicker.shared.cancel = { [weak self] in self?.scene?.cancelDocumentImports() }
        IosLivePhotoFilesPicker.shared.present = { [weak self] answer in
            guard let scene = self?.scene else { DocumentPickerDelegate.answerNoAudio(answer); return }
            scene.presentLivePhotoFilesPicker(answer)
        }
        IosLivePhotoFilesPicker.shared.cancel = { [weak self] in self?.scene?.cancelDocumentImports() }
        IosAlbumExportPicker.shared.cancel = { [weak self] in self?.scene?.cancelAlbumExportPicker() }
        return true
    }

    func application(
        _ application: UIApplication,
        configurationForConnecting connectingSceneSession: UISceneSession,
        options: UIScene.ConnectionOptions
    ) -> UISceneConfiguration {
        let configuration = UISceneConfiguration(name: "Default Configuration", sessionRole: connectingSceneSession.role)
        configuration.delegateClass = SceneDelegate.self
        return configuration
    }
}

final class SceneDelegate: UIResponder, UIWindowSceneDelegate {
    var window: UIWindow?
    private var mediaPicker: MediaPickerDelegate?
    private var approvalPicker: ApprovalPickerDelegate?
    private var approvalExporter: ExportPickerDelegate?
    private var exportPicker: ExportPickerDelegate?
    private var albumExportPicker: AlbumExportPickerDelegate?
    private var documentPicker: DocumentPickerDelegate?
    private weak var documentPickerController: UIViewController?
    private let documentSelections = NSHashTable<DocumentImportSelection>.weakObjects()
    private weak var albumExportController: UIViewController?
    private var pendingExports: [(URL, ExportTarget)] = []
    private var presentingExport = false
    private var exportUsesHostActivity = false
    private var exportPermissionPrompt: Int64?
    private var activeExportURL: URL?
    private var activeExportController: UIViewController?
    private var exportGeneration = 0
    private let quickActions = LauncherQuickActionDispatcher()
    private var quickActionMaskPending = false

    private var host: AppDelegate { UIApplication.shared.delegate as! AppDelegate }

    func scene(_ scene: UIScene, willConnectTo session: UISceneSession, options: UIScene.ConnectionOptions) {
        guard let scene = scene as? UIWindowScene else { return }
        host.scene = self
        IosLauncherActions.shared.onMaskRendered = { [weak self] in
            guard let self else { return }
            self.quickActionMaskPending = false
            if UIApplication.shared.applicationState == .active { self.host.privacy.detach() }
        }
        let window = UIWindow(windowScene: scene)
        if host.storageReady {
            let root = IosEntryPointKt.ChurViewController(controller: host.controller, gate: host.gate, privacy: host.privacy)
            installAdaptiveGeometry(on: root)
            window.rootViewController = root
        } else {
            let failure = UIViewController()
            failure.view.backgroundColor = .systemBackground
            let label = UILabel()
            label.text = "Private storage is unavailable."
            label.textAlignment = .center
            label.translatesAutoresizingMaskIntoConstraints = false
            failure.view.addSubview(label)
            NSLayoutConstraint.activate([
                label.centerXAnchor.constraint(equalTo: failure.view.centerXAnchor),
                label.centerYAnchor.constraint(equalTo: failure.view.centerYAnchor),
            ])
            window.rootViewController = failure
        }
        self.window = window
        window.makeKeyAndVisible()
        if host.storageReady, host.gate is GateResultCompatible {
            host.controller.begin()
        }
        if let shortcut = options.shortcutItem {
            receiveQuickAction(shortcut) { _ in }
        }
    }

    func windowScene(_ windowScene: UIWindowScene, performActionFor shortcutItem: UIApplicationShortcutItem,
                     completionHandler: @escaping (Bool) -> Void) {
        receiveQuickAction(shortcutItem, completion: completionHandler)
    }

    private func receiveQuickAction(_ shortcut: UIApplicationShortcutItem, completion: @escaping (Bool) -> Void) {
        // Even an active scene must finish its inbox scan before navigation.
        // The dispatcher still executes lock immediately, without this wait.
        quickActions.receive(type: shortcut.type, active: false,
            perform: performQuickAction, completion: completion)
        if let action = LauncherQuickAction(rawValue: shortcut.type), action != .lockAndHide,
            UIApplication.shared.applicationState == .active {
            activateQuickActionsAfterInboxRefresh()
        }
    }

    private func activateQuickActionsAfterInboxRefresh() {
        IosLauncherActions.shared.setSceneReady(ready: false)
        host.refreshIncomingShares { [weak self] in
            guard let self, self.host.scene === self,
                UIApplication.shared.applicationState == .active else { return }
            self.host.controller.refreshPublicPresentation()
            IosLauncherActions.shared.setSceneReady(ready: true)
            self.quickActions.activate(perform: self.performQuickAction)
        }
    }

    private func performQuickAction(_ action: LauncherQuickAction) -> Bool {
        guard host.storageReady, host.gate is GateResultCompatible else { return false }
        guard let command = LauncherAction.companion.fromExternalAction(value: action.rawValue) else { return false }
        if action == .lockAndHide {
            // Conceal before the controller revokes the session and routes to
            // the public shell/app gate. This action never prompts for unlock.
            host.privacy.attach()
            quickActionMaskPending = true
            let handled = host.controller.requestLauncherAction(action: command)
            host.cancelPublicCamera()
            mediaPicker?.cancel()
            cancelPendingExports()
            // Lock also leaves any native picker. Its detached callback cannot
            // authorize work in the revoked session.
            window?.rootViewController?.dismiss(animated: false)
            IosLauncherActions.shared.requestMask()
            return handled
        }
        guard UIApplication.shared.applicationState == .active,
            window?.rootViewController?.presentedViewController == nil,
            !host.incomingShareBusy else { return false }
        return host.controller.requestLauncherAction(action: command)
    }

    func sceneWillResignActive(_ scene: UIScene) {
        IosLauncherActions.shared.setSceneReady(ready: false)
        // The cover exists only while the scene is inactive, and only over a
        // screen the switcher must not show; `IosPrivacyCover` says why.
        if host.controller.privacyCoverNeeded { host.privacy.attach() }
        guard host.storageReady, host.gate is GateResultCompatible else { return }
        host.controller.background()
    }

    func sceneDidEnterBackground(_ scene: UIScene) {
        IosLauncherActions.shared.setSceneReady(ready: false)
        // An action still waiting for the inbox/scene belongs to this visit.
        quickActions.cancel()
        host.suspendPublicCamera()
        // Recheck before UIKit takes the switcher picture: native work can
        // finish between lifecycle callbacks even when its stale UI result
        // is rejected by the controller. Attaching an existing cover is safe.
        if host.controller.privacyCoverNeeded { host.privacy.attach() }
        // A system prompt the app asked for (the owner check, a Photos alert,
        // the local network alert) holds the lock off but only makes the
        // scene inactive; leaving the app ends every prompt and locks at
        // once, `IOS.md` §21.2.
        if host.storageReady, host.gate is GateResultCompatible { host.controller.enteredBackground() }
    }

    func sceneDidBecomeActive(_ scene: UIScene) {
        host.controller.foreground()
        host.resumePublicCamera()
        if !quickActionMaskPending { host.privacy.detach() }
        // UIApplication can remain inactive during the scene callback. Check
        // its foreground guard after UIKit completes that state transition.
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.activateQuickActionsAfterInboxRefresh()
        }
    }

    func sceneDidDisconnect(_ scene: UIScene) {
        quickActions.cancel()
        host.cancelPublicCamera()
        cancelAlbumExportPicker()
        cancelDocumentImports()
        if host.scene === self {
            IosLauncherActions.shared.setSceneReady(ready: false)
            host.scene = nil
            IosLauncherActions.shared.onMaskRendered = nil
        }
    }

    func presentMediaPicker(_ answer: @escaping MediaAnswer, fullLivePhotos: Bool = false) {
        if fullLivePhotos {
            let status = PHPhotoLibrary.authorizationStatus(for: .readWrite)
            if status == .notDetermined {
                let prompt = host.controller.beginPrompt()
                PHPhotoLibrary.requestAuthorization(for: .readWrite) { [weak self] _ in
                    DispatchQueue.main.async {
                        guard let self, self.host.controller.endPrompt(bracket: prompt) else { MediaPickerDelegate.answerNothing(answer); return }
                        self.presentMediaPicker(answer, fullLivePhotos: true)
                    }
                }
                return
            }
            guard status == .authorized || status == .limited else {
                host.controller.report(message: "Full Live Photo import needs Photos access. Allow access in Settings, then try again.")
                MediaPickerDelegate.answerNothing(answer)
                return
            }
        }
        guard let presenter = window?.rootViewController else { MediaPickerDelegate.answerNothing(answer); return }
        var configuration = PHPickerConfiguration(photoLibrary: .shared())
        configuration.filter = fullLivePhotos ? .livePhotos : .any(of: [.images, .videos])
        // Any number of items, in the order picked, `IOS.md` §15.1. `.current`
        // hands over each item as stored rather than transcoded, so a HEIC
        // original stays HEIC (§15.3).
        configuration.selectionLimit = 0
        configuration.selection = .ordered
        configuration.preferredAssetRepresentationMode = .current
        let picker = PHPickerViewController(configuration: configuration)
        let delegate = MediaPickerDelegate(answer: answer, fullLivePhotos: fullLivePhotos) { [weak self] in self?.mediaPicker = nil }
        mediaPicker = delegate
        picker.delegate = delegate
        presenter.present(picker, animated: true)
    }

    func presentApprovalPicker(_ answer: @escaping (String?) -> KotlinUnit) {
        guard let root = window?.rootViewController, root.presentedViewController == nil else { _ = answer(nil); return }
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.data], asCopy: false)
        let delegate = ApprovalPickerDelegate(answer: answer) { [weak self] in self?.approvalPicker = nil }
        approvalPicker = delegate
        picker.delegate = delegate
        picker.allowsMultipleSelection = false
        root.present(picker, animated: true)
    }

    func presentApprovalExport(_ path: String, answer: @escaping (String?) -> KotlinUnit) {
        guard let root = window?.rootViewController, root.presentedViewController == nil else { _ = answer(nil); return }
        let picker = UIDocumentPickerViewController(forExporting: [URL(fileURLWithPath: path)], asCopy: true)
        let delegate = ExportPickerDelegate { [weak self] saved in
            self?.approvalExporter = nil
            _ = answer(saved ? path : nil)
        }
        approvalExporter = delegate
        picker.delegate = delegate
        root.present(picker, animated: true)
    }

    func presentBackupPicker(_ request: IosArchivePickRequest) {
        guard let presenter = window?.rootViewController, presenter.presentedViewController == nil else {
            request.openFailed(); return
        }
        let generation = exportGeneration
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.data], asCopy: false)
        let delegate = DocumentPickerDelegate { [weak self] urls in
            guard let self else { request.cancelled(); return }
            self.documentPicker = nil
            self.documentPickerController = nil
            guard self.exportGeneration == generation, let url = urls.first else { request.cancelled(); return }
            let selection = DocumentImportSelection(urls: [url])
            self.documentSelections.add(selection)
            request.beginOpening(cancel: selection.close)
            // A full backup can contain many individually bounded media objects.
            selection.load(index: 0, maxBytes: Int64.max) { source in
                DispatchQueue.main.async { [weak self] in
                    guard self?.exportGeneration == generation else {
                        source?.close(); request.cancelled(); return
                    }
                    guard let source else { request.openFailed(); return }
                    request.opened(source: ArchiveSource(descriptor: source.descriptor, close: source.close))
                }
            }
        }
        documentPicker = delegate
        documentPickerController = picker
        picker.delegate = delegate
        presenter.present(picker, animated: true)
    }

    func presentDocumentPicker(_ answer: @escaping DocumentAnswer) {
        guard let presenter = window?.rootViewController, presenter.presentedViewController == nil else {
            DocumentPickerDelegate.answerNothing(answer)
            host.controller.report(message: "The document picker is unavailable. Please try again.")
            return
        }
        let generation = exportGeneration
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.item], asCopy: false)
        picker.allowsMultipleSelection = true
        let delegate = DocumentPickerDelegate { [weak self] urls in
            guard let self else { DocumentPickerDelegate.answerNothing(answer); return }
            self.documentPicker = nil
            self.documentPickerController = nil
            guard self.exportGeneration == generation, !urls.isEmpty else {
                DocumentPickerDelegate.answerNothing(answer); return
            }
            let selected = DocumentImportSelection(urls: urls)
            self.documentSelections.add(selected)
            _ = answer(KotlinInt(int: Int32(selected.count)), { index, prepare, loaded in
                selected.load(index: Int(truncating: index), shouldContinue: {
                    prepare(KotlinLong(longLong: 0), KotlinLong(longLong: 0)).boolValue
                }) { source in
                    guard let source else { _ = loaded(KotlinInt(int: -1), nil, "application/octet-stream", KotlinLong(longLong: 0), { KotlinUnit() }); return }
                    _ = loaded(KotlinInt(int: source.descriptor), source.name, source.contentType, KotlinLong(longLong: source.size), { source.close(); return KotlinUnit() })
                }
                return KotlinUnit()
            }, { selected.close(); return KotlinUnit() })
        }
        documentPicker = delegate
        documentPickerController = picker
        picker.delegate = delegate
        presenter.present(picker, animated: true)
    }

    func presentMediaFilesPicker(_ answer: @escaping AudioDocumentAnswer) {
        // Some image formats are not registered by the OS or available in Photos.
        // Content signatures in the media codec determine how to import them.
        presentMediaDocumentPicker(answer, types: [.item])
    }

    func presentAudioPicker(_ answer: @escaping AudioDocumentAnswer) {
        presentMediaDocumentPicker(answer, types: [.audio])
    }

    func presentLivePhotoFilesPicker(_ answer: @escaping AudioDocumentAnswer) {
        presentMediaDocumentPicker(answer, types: [UTType(exportedAs: "dev.po4yka.chur.live-photo", conformingTo: .data)])
    }

    private func presentMediaDocumentPicker(_ answer: @escaping AudioDocumentAnswer, types: [UTType]) {
        guard let presenter = window?.rootViewController, presenter.presentedViewController == nil else {
            DocumentPickerDelegate.answerNoAudio(answer)
            host.controller.report(message: "The media file picker is unavailable. Please try again.")
            return
        }
        let generation = exportGeneration
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: types, asCopy: false)
        picker.allowsMultipleSelection = true
        let delegate = DocumentPickerDelegate { [weak self] urls in
            guard let self else { DocumentPickerDelegate.answerNoAudio(answer); return }
            self.documentPicker = nil
            self.documentPickerController = nil
            guard self.exportGeneration == generation, !urls.isEmpty else {
                DocumentPickerDelegate.answerNoAudio(answer); return
            }
            let selected = DocumentImportSelection(urls: urls)
            self.documentSelections.add(selected)
            _ = answer(KotlinInt(int: Int32(selected.count)), { index, prepare, loaded in
                selected.load(index: Int(truncating: index), shouldContinue: {
                    prepare(KotlinLong(longLong: 0), KotlinLong(longLong: 0)).boolValue
                }) { source in
                    guard let source else {
                        _ = loaded(KotlinInt(int: -1), nil, "application/octet-stream", KotlinLong(longLong: 0), nil, { KotlinUnit() })
                        return
                    }
                    _ = loaded(KotlinInt(int: source.descriptor), source.name, source.contentType,
                        KotlinLong(longLong: source.size), source.readablePath, { source.close(); return KotlinUnit() })
                }
                return KotlinUnit()
            }, { selected.close(); return KotlinUnit() })
        }
        documentPicker = delegate
        documentPickerController = picker
        picker.delegate = delegate
        presenter.present(picker, animated: true)
    }

    func cancelDocumentImports() {
        documentPickerController?.dismiss(animated: false)
        documentPickerController = nil
        let delegate = documentPicker
        documentPicker = nil
        delegate?.finish([])
        documentSelections.allObjects.forEach { $0.close() }
        documentSelections.removeAllObjects()
    }

    func presentAlbumExportPicker(_ answer: @escaping (String?) -> KotlinUnit) {
        guard let presenter = window?.rootViewController, presenter.presentedViewController == nil else {
            _ = answer(nil)
            host.controller.report(message: "The folder picker is unavailable. Please try again.")
            return
        }
        let generation = exportGeneration
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.folder], asCopy: false)
        picker.allowsMultipleSelection = false
        let delegate = AlbumExportPickerDelegate { [weak self] url in
            guard let self else { _ = answer(nil); return }
            self.albumExportPicker = nil
            self.albumExportController = nil
            guard self.exportGeneration == generation else { _ = answer(nil); return }
            let token = url.flatMap { self.host.registerExportDirectory($0) }
            if url != nil, token == nil {
                self.host.controller.report(message: "That folder could not be opened for export.")
            }
            _ = answer(token)
        }
        albumExportPicker = delegate
        albumExportController = picker
        picker.delegate = delegate
        presenter.present(picker, animated: true)
    }

    func cancelAlbumExportPicker() {
        albumExportController?.dismiss(animated: false)
        albumExportController = nil
        let delegate = albumExportPicker
        albumExportPicker = nil
        delegate?.finish(nil)
    }

    func presentExport(_ url: URL, target: ExportTarget) {
        pendingExports.append((url, target))
        presentNextExport()
    }

    private func presentNextExport() {
        guard !presentingExport, !pendingExports.isEmpty else { return }
        presentingExport = true
        let (url, target) = pendingExports.removeFirst()
        let generation = exportGeneration
        activeExportURL = url
        exportUsesHostActivity = target != .mediaLibrary
        if exportUsesHostActivity { host.controller.beginHostActivity() }
        guard FileManager.default.fileExists(atPath: url.path) else {
            finishExport(url, generation: generation)
            host.controller.report(message: "Export expired. Please try again.")
            return
        }
        guard let presenter = window?.rootViewController else {
            finishExport(url, generation: generation)
            host.controller.report(message: "Could not open the export destination.")
            return
        }
        if target == .mediaLibrary {
            let isLivePhoto = url.pathExtension.lowercased() == "churlive"
            let type = UTType(filenameExtension: url.pathExtension)
            guard isLivePhoto || type?.conforms(to: .image) == true || type?.conforms(to: .movie) == true else {
                finishExport(url, generation: generation)
                host.controller.report(message: "Only photos and videos can be saved to Photos.")
                return
            }
            let prompt = PHPhotoLibrary.authorizationStatus(for: .addOnly) == .notDetermined
                ? host.controller.beginPrompt() : nil
            exportPermissionPrompt = prompt
            PHPhotoLibrary.requestAuthorization(for: .addOnly) { [weak self] status in
                DispatchQueue.main.async {
                    guard let self, self.exportGeneration == generation else { return }
                    if let prompt {
                        self.exportPermissionPrompt = nil
                        guard self.host.controller.endPrompt(bracket: prompt) else { return }
                    }
                    guard status == .authorized else {
                        if self.finishExport(url, generation: generation) {
                            self.host.controller.report(message: "Photos access was not granted.")
                        }
                        return
                    }
                    if isLivePhoto {
                        LivePhotoRestoration.save(url, shouldContinue: { [weak self] in
                            DispatchQueue.main.sync { self?.exportGeneration == generation }
                        }) { [weak self] saved in
                            if self?.finishExport(url, generation: generation) == true {
                                self?.host.controller.report(message: saved ? "Live Photo saved to Photos. The copy is outside the vault." : "Photos could not restore every Live Photo resource. Export the bundle to Files to keep all resources.")
                            }
                        }
                        return
                    }
                    PHPhotoLibrary.shared().performChanges({
                        if type?.conforms(to: .movie) == true {
                            PHAssetChangeRequest.creationRequestForAssetFromVideo(atFileURL: url)
                        } else {
                            PHAssetChangeRequest.creationRequestForAssetFromImage(atFileURL: url)
                        }
                    }) { [weak self] saved, _ in
                        DispatchQueue.main.async {
                            if self?.finishExport(url, generation: generation) == true {
                                self?.host.controller.report(message: saved ? "Saved to Photos. The copy is outside the vault." : "Could not save to Photos.")
                            }
                        }
                    }
                }
            }
            return
        }
        if target == .files {
            let picker = UIDocumentPickerViewController(forExporting: [url], asCopy: true)
            let delegate = ExportPickerDelegate { [weak self] saved in
                self?.exportPicker = nil
                if self?.finishExport(url, generation: generation) == true {
                    self?.host.controller.report(message: saved ? "Saved to Files. The copy is outside the vault." : "Save to Files cancelled.")
                }
            }
            exportPicker = delegate
            picker.delegate = delegate
            activeExportController = picker
            presenter.present(picker, animated: true)
            return
        }
        let sheet = UIActivityViewController(activityItems: [url], applicationActivities: nil)
        sheet.completionWithItemsHandler = { _, completed, _, error in
            if self.finishExport(url, generation: generation) {
                if error != nil {
                    self.host.controller.report(message: "Could not share the file.")
                } else {
                    self.host.controller.report(message: completed ? "Shared. The copy is outside the vault." : "Sharing cancelled.")
                }
            }
        }
        if let popover = sheet.popoverPresentationController {
            popover.sourceView = presenter.view
            popover.sourceRect = CGRect(x: presenter.view.bounds.midX, y: presenter.view.bounds.midY, width: 1, height: 1)
        }
        activeExportController = sheet
        presenter.present(sheet, animated: true)
    }

    func cancelPendingExports() {
        exportGeneration += 1
        cancelAlbumExportPicker()
        cancelDocumentImports()
        if let prompt = exportPermissionPrompt {
            exportPermissionPrompt = nil
            _ = host.controller.endPrompt(bracket: prompt)
        }
        pendingExports.forEach { try? FileManager.default.removeItem(at: $0.0) }
        pendingExports.removeAll()
        if let activeExportURL { try? FileManager.default.removeItem(at: activeExportURL) }
        activeExportController?.dismiss(animated: false)
        activeExportController = nil
        activeExportURL = nil
        if exportUsesHostActivity { host.controller.endHostActivity() }
        exportUsesHostActivity = false
        presentingExport = false
        exportPicker = nil
    }

    @discardableResult private func finishExport(_ url: URL, generation: Int) -> Bool {
        try? FileManager.default.removeItem(at: url)
        guard generation == exportGeneration, activeExportURL == url else { return false }
        if exportUsesHostActivity { host.controller.endHostActivity() }
        exportUsesHostActivity = false
        presentingExport = false
        activeExportURL = nil
        activeExportController = nil
        presentNextExport()
        return true
    }
}

typealias DocumentLoaded = (KotlinInt, String?, String, KotlinLong, @escaping () -> KotlinUnit) -> KotlinUnit
typealias DocumentLoad = (KotlinInt, @escaping (KotlinLong, KotlinLong) -> KotlinBoolean, @escaping DocumentLoaded) -> KotlinUnit
typealias DocumentAnswer = (KotlinInt, @escaping DocumentLoad, @escaping () -> KotlinUnit) -> KotlinUnit
// AVFoundation needs the coordinated URL in addition to the source fd. The
// source lease keeps both readable until Kotlin releases the imported item.
typealias AudioDocumentLoaded = (KotlinInt, String?, String, KotlinLong, String?, @escaping () -> KotlinUnit) -> KotlinUnit
typealias AudioDocumentLoad = (KotlinInt, @escaping (KotlinLong, KotlinLong) -> KotlinBoolean, @escaping AudioDocumentLoaded) -> KotlinUnit
typealias AudioDocumentAnswer = (KotlinInt, @escaping AudioDocumentLoad, @escaping () -> KotlinUnit) -> KotlinUnit

private final class DocumentPickerDelegate: NSObject, UIDocumentPickerDelegate {
    private var answer: (([URL]) -> Void)?
    init(answer: @escaping ([URL]) -> Void) { self.answer = answer }
    func finish(_ urls: [URL]) { let callback = answer; answer = nil; callback?(urls) }
    static func answerNoAudio(_ answer: AudioDocumentAnswer) {
        _ = answer(KotlinInt(int: 0), { _, _, loaded in
            _ = loaded(KotlinInt(int: -1), nil, "application/octet-stream", KotlinLong(longLong: 0), nil, { KotlinUnit() })
            return KotlinUnit()
        }, { KotlinUnit() })
    }
    static func answerNothing(_ answer: DocumentAnswer) {
        _ = answer(KotlinInt(int: 0), { _, _, loaded in
            _ = loaded(KotlinInt(int: -1), nil, "application/octet-stream", KotlinLong(longLong: 0), { KotlinUnit() })
            return KotlinUnit()
        }, { KotlinUnit() })
    }
    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        controller.dismiss(animated: true) { self.finish(urls) }
    }
    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        controller.dismiss(animated: true) { self.finish([]) }
    }
}

private final class AlbumExportPickerDelegate: NSObject, UIDocumentPickerDelegate {
    private var answer: ((URL?) -> Void)?
    init(answer: @escaping (URL?) -> Void) { self.answer = answer }
    func finish(_ url: URL?) { let callback = answer; answer = nil; callback?(url) }
    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        controller.dismiss(animated: true) { self.finish(urls.first) }
    }
    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        controller.dismiss(animated: true) { self.finish(nil) }
    }
}

private final class ExportPickerDelegate: NSObject, UIDocumentPickerDelegate {
    private let done: (Bool) -> Void

    init(done: @escaping (Bool) -> Void) {
        self.done = done
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        controller.dismiss(animated: true) { self.done(!urls.isEmpty) }
    }
    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) {
        controller.dismiss(animated: true) { self.done(false) }
    }
}

/// Loads one picked item for Kotlin, `IosMediaPicker`: the item's index, a
/// report of the fetch that answers false once the user cancels, and the
/// answer with the copy's path and the item's own name.
typealias MediaLoad = (
    KotlinInt,
    @escaping (KotlinLong, KotlinLong) -> KotlinBoolean,
    @escaping (String?, String?) -> KotlinUnit
) -> KotlinUnit

/// Deletes the originals of the picked items at the given indices, and
/// answers how many it found and how many were deleted.
typealias MediaReview = ([KotlinInt], @escaping (KotlinInt, KotlinInt) -> KotlinUnit) -> KotlinUnit

/// The answer to a pick: how many items, how to load each one, and how to
/// delete their originals after the import.
typealias MediaAnswer = (KotlinInt, @escaping MediaLoad, @escaping MediaReview, @escaping (KotlinInt) -> KotlinBoolean) -> KotlinUnit

private final class MediaPickerDelegate: NSObject, PHPickerViewControllerDelegate {
    private static let scratch = FileManager.default.temporaryDirectory
        .appendingPathComponent("chur-media-imports", isDirectory: true)
    private var answer: MediaAnswer?
    private let done: () -> Void
    private let fullLivePhotos: Bool

    static func prepareScratch() -> Bool {
        do {
            if FileManager.default.fileExists(atPath: scratch.path) {
                try FileManager.default.removeItem(at: scratch)
            }
            try FileManager.default.createDirectory(
                at: scratch,
                withIntermediateDirectories: true,
                attributes: [.protectionKey: FileProtectionType.complete]
            )
            try (scratch as NSURL).setResourceValue(true, forKey: .isExcludedFromBackupKey)
            return true
        } catch {
            return false
        }
    }

    /// Answers a picker that could not be shown as a pick of nothing.
    static func answerNothing(_ answer: MediaAnswer) {
        _ = answer(
            KotlinInt(int: 0),
            { _, _, loaded in loaded(nil, nil) },
            { _, done in done(KotlinInt(int: 0), KotlinInt(int: 0)) },
            { _ in KotlinBoolean(bool: false) }
        )
    }

    init(answer: @escaping MediaAnswer, fullLivePhotos: Bool = false, done: @escaping () -> Void) {
        self.fullLivePhotos = fullLivePhotos
        self.answer = answer
        self.done = done
    }

    func cancel() {
        guard let answer else { return }
        self.answer = nil
        Self.answerNothing(answer)
        done()
    }

    /// Answers with the pick and fetches nothing yet: Kotlin loads one item
    /// at a time and deletes its copy before it loads the next, so at most
    /// one plaintext copy exists, `IOS.md` §15.2. The providers stay with the
    /// load closure, which Kotlin holds until the pick is imported, and the
    /// Photos identifiers with the review closure, which Kotlin holds until
    /// the user answers the step after the import, §15.4.
    func picker(_ picker: PHPickerViewController, didFinishPicking results: [PHPickerResult]) {
        picker.dismiss(animated: true)
        guard let answer else { return }
        self.answer = nil
        let fullLivePhotos = self.fullLivePhotos
        let providers = results.map(\.itemProvider)
        let photoAccess = PHPhotoLibrary.authorizationStatus(for: .readWrite)
        let canReadMetadata = photoAccess == .authorized || photoAccess == .limited
        let identifiers = providers.map(Self.fileType)
        let safety = MediaOriginalSafety(items: results.enumerated().map { index, result in
            let type = identifiers[index].flatMap { UTType($0) }
            let concrete = type?.preferredFilenameExtension != nil
            let kind: MediaOriginalSafety.Kind = concrete && type?.conforms(to: .image) == true ? .photo
                : concrete && type?.conforms(to: .movie) == true ? .video : .unknown
            var compound = result.itemProvider.canLoadObject(ofClass: PHLivePhoto.self)
                || result.itemProvider.hasItemConformingToTypeIdentifier(UTType.livePhoto.identifier)
            // Use metadata only if Photos already permits it. Import itself
            // must not ask for photo-library access.
            if canReadMetadata, let id = result.assetIdentifier,
               let asset = PHAsset.fetchAssets(withLocalIdentifiers: [id], options: nil).firstObject {
                compound = compound || asset.mediaSubtypes.contains(.photoLive)
                    || PHAssetResource.assetResources(for: asset).count != 1
            }
            return .init(assetIdentifier: result.assetIdentifier, kind: kind, isCompound: compound)
        })
        _ = answer(
            KotlinInt(int: Int32(providers.count)),
            { index, prepare, loaded in
                let position = index.intValue
                guard providers.indices.contains(position) else { return loaded(nil, nil) }
                safety.recordLoaded(index: position, typeIdentifier: nil)
                if fullLivePhotos {
                    guard let id = results[position].assetIdentifier,
                          let asset = PHAsset.fetchAssets(withLocalIdentifiers: [id], options: nil).firstObject else { return loaded(nil, nil) }
                    Self.loadLivePhoto(asset, prepare: { prepare(KotlinLong(longLong: $0), KotlinLong(longLong: $1)).boolValue }, loaded: { path, name in _ = loaded(path, name) })
                    return KotlinUnit()
                }
                Self.load(
                    providers[position], identifier: identifiers[position],
                    prepare: { prepare(KotlinLong(longLong: $0), KotlinLong(longLong: $1)).boolValue },
                    loaded: { path, name in
                        safety.recordLoaded(index: position, typeIdentifier: path == nil ? nil : identifiers[position])
                        _ = loaded(path, name)
                    }
                )
                return KotlinUnit()
            },
            { indices, done in
                Self.deleteOriginals(safety.candidates(indices: indices.map(\.intValue)), safety: safety) { found, deleted in
                    _ = done(KotlinInt(int: found), KotlinInt(int: deleted))
                }
                return KotlinUnit()
            },
            { index in KotlinBoolean(bool: safety.canReview(index: index.intValue)) }
        )
        done()
    }

    /// Deletes originals from the photo library, `DESIGN.md` §15.3 and
    /// `IOS.md` §15.4.
    ///
    /// Read-write access is asked for here, when the user chose to review the
    /// deletion, and not at import, which the picker serves without it. Photos
    /// shows the items and asks before it deletes them, and a refusal of
    /// either deletes nothing. An item outside the access the user granted is
    /// not found. The answer comes on the main thread.
    private static func deleteOriginals(_ candidates: [(index: Int, identifier: String)], safety: MediaOriginalSafety, done: @escaping (Int32, Int32) -> Void) {
        guard !candidates.isEmpty else { done(0, 0); return }
        PHPhotoLibrary.requestAuthorization(for: .readWrite) { status in
            let granted = status == .authorized || status == .limited
            let assets: [PHAsset] = granted ? candidates.compactMap { candidate in
                guard let asset = PHAsset.fetchAssets(withLocalIdentifiers: [candidate.identifier], options: nil).firstObject else { return nil }
                let resources = PHAssetResource.assetResources(for: asset).map { resource in
                    MediaOriginalSafety.Resource(
                        kind: resource.type == .photo ? .photo : resource.type == .video ? .video : .unknown,
                        typeIdentifier: resource.uniformTypeIdentifier
                    )
                }
                return safety.canDelete(index: candidate.index, isLivePhoto: asset.mediaSubtypes.contains(.photoLive), resources: resources) ? asset : nil
            } : []
            guard !assets.isEmpty else {
                DispatchQueue.main.async { done(0, 0) }
                return
            }
            let found = Int32(assets.count)
            PHPhotoLibrary.shared().performChanges({
                PHAssetChangeRequest.deleteAssets(assets as NSArray)
            }) { deleted, _ in
                DispatchQueue.main.async { done(found, deleted ? found : 0) }
            }
        }
    }

    /// Fetches one item into a protected copy, `IOS.md` §15.1-15.2.
    ///
    /// An iCloud original may not be on the device yet. A timer on the main
    /// run loop reports the fetch four times a second, and each report also
    /// asks whether the user cancelled: a timer rather than a progress
    /// observer keeps a fetch that stalls on the network cancellable. The
    /// copy is made before the provider's callback returns, because the
    /// provider deletes its file then. Kotlin calls this on the main thread.
    private static func fileType(_ provider: NSItemProvider) -> String? {
        provider.registeredTypeIdentifiers.first { identifier in
            guard let type = UTType(identifier), !type.conforms(to: .livePhoto) else { return false }
            return type.conforms(to: .image) || type.conforms(to: .movie)
        }
    }

    private static func load(
        _ provider: NSItemProvider,
        identifier: String?,
        prepare: @escaping (Int64, Int64) -> Bool,
        loaded: @escaping (String?, String?) -> Void
    ) {
        guard let identifier else {
            loaded(nil, nil)
            return
        }
        let box = FetchBox()
        let ticker = Timer(timeInterval: 0.25, repeats: true) { ticker in
            guard let fetch = box.progress else { return }
            // A fetch of unknown size reports no total, and the bar stays
            // indeterminate.
            let total: Int64 = fetch.isIndeterminate ? 0 : 1_000
            if !prepare(Int64(fetch.fractionCompleted * 1_000), total) {
                ticker.invalidate()
                fetch.cancel()
            }
        }
        box.progress = provider.loadFileRepresentation(forTypeIdentifier: identifier) { source, _ in
            let copy = source.flatMap { copyToScratch($0, identifier: identifier, prepare: prepare) }
            let name = copy.flatMap { copy in
                provider.suggestedName.map {
                    $0.lowercased().hasSuffix("." + copy.pathExtension.lowercased()) ? $0 : "\($0).\(copy.pathExtension)"
                }
            }
            DispatchQueue.main.async {
                ticker.invalidate()
                loaded(copy?.path, name)
            }
        }
        RunLoop.main.add(ticker, forMode: .common)
    }

    private static func loadLivePhoto(_ asset: PHAsset, prepare: @escaping (Int64, Int64) -> Bool, loaded: @escaping (String?, String?) -> Void) {
        let capture = LivePhotoCapture()
        let keepGoing: () -> Bool = {
            if Thread.isMainThread { return prepare(0, 0) }
            return DispatchQueue.main.sync { prepare(0, 0) }
        }
        let ticker = Timer(timeInterval: 0.25, repeats: true) { timer in
            if !keepGoing() { capture.cancel(); timer.invalidate() }
        }
        RunLoop.main.add(ticker, forMode: .common)
        do {
            let exports = FileManager.default.temporaryDirectory.appendingPathComponent("chur-exports")
            let budget = try ScratchCopy.remainingBudget(in: [scratch, exports, FileManager.default.temporaryDirectory.appendingPathComponent("chur-incoming-media")])
            capture.capture(asset: asset, directory: scratch, limit: UInt64(max(0, budget)), shouldContinue: keepGoing) { url in
                ticker.invalidate()
                loaded(url?.path, url == nil ? nil : "Live Photo.churlive")
            }
        } catch { ticker.invalidate(); loaded(nil, nil) }
    }

    /// Holds the fetch for the timer, which is made before the fetch starts.
    /// The timer and the assignment both run on the main thread.
    private final class FetchBox {
        var progress: Progress?
    }

    /// Copies a provider's file under a random name, which `IOS.md` §12 asks
    /// for: a file name must not tell the filename.
    private static func copyToScratch(_ source: URL, identifier: String, prepare: @escaping (Int64, Int64) -> Bool) -> URL? {
        let ext = source.pathExtension.isEmpty ? (UTType(identifier)?.preferredFilenameExtension ?? "bin") : source.pathExtension
        let target = scratch.appendingPathComponent(UUID().uuidString).appendingPathExtension(ext)
        do {
            let exports = FileManager.default.temporaryDirectory.appendingPathComponent("chur-exports", isDirectory: true)
            let limit = try ScratchCopy.remainingBudget(in: [scratch, exports, FileManager.default.temporaryDirectory.appendingPathComponent("chur-incoming-media")])
            let continueCopy: (Int64, Int64) -> Bool = { processed, total in
                if Thread.isMainThread { return prepare(processed, total) }
                return DispatchQueue.main.sync { prepare(processed, total) }
            }
            try ScratchCopy.copy(
                from: source, to: target, limit: limit,
                attributes: [.protectionKey: FileProtectionType.complete],
                progress: continueCopy,
                shouldContinue: { continueCopy(0, 0) }
            )
            return target
        } catch {
            try? FileManager.default.removeItem(at: target)
            return nil
        }
    }
}

private final class ApprovalPickerDelegate: NSObject, UIDocumentPickerDelegate {
    private static let directory = FileManager.default.temporaryDirectory.appendingPathComponent("chur-pairing", isDirectory: true)
    private var answer: ((String?) -> KotlinUnit)?
    private let done: () -> Void

    static func prepareScratch() -> Bool {
        do {
            if FileManager.default.fileExists(atPath: directory.path) { try FileManager.default.removeItem(at: directory) }
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true,
                attributes: [.protectionKey: FileProtectionType.complete])
            try (directory as NSURL).setResourceValue(true, forKey: .isExcludedFromBackupKey)
            return true
        } catch { return false }
    }

    init(answer: @escaping (String?) -> KotlinUnit, done: @escaping () -> Void) {
        self.answer = answer
        self.done = done
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        guard let source = urls.first else { finish(nil); return }
        controller.dismiss(animated: true)
        let scoped = source.startAccessingSecurityScopedResource()
        DispatchQueue.global(qos: .userInitiated).async {
            defer { if scoped { source.stopAccessingSecurityScopedResource() } }
            let target = Self.directory.appendingPathComponent(UUID().uuidString).appendingPathExtension("churpair")
            let copied: String?
            do {
                let limit = try ScratchCopy.remainingBudget(in: [Self.directory], maxEntries: 4,
                    maxTotal: 64 * 1024 * 1024, maxEntry: 16 * 1024 * 1024)
                try ScratchCopy.copy(from: source, to: target, limit: limit, timeout: 60,
                    attributes: [.protectionKey: FileProtectionType.complete], shouldContinue: { true })
                copied = target.path
            } catch { copied = nil }
            DispatchQueue.main.async { self.finish(copied) }
        }
    }

    func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) { finish(nil) }

    private func finish(_ path: String?) {
        guard let answer else {
            if let path { try? FileManager.default.removeItem(atPath: path) }
            return
        }
        self.answer = nil
        _ = answer(path)
        done()
    }
}

private final class ShareExportSink: NSObject, ExportSink {
    private let present: (URL, ExportTarget) -> Void
    private let cancel: () -> Void
    private let directory = FileManager.default.temporaryDirectory.appendingPathComponent("chur-exports", isDirectory: true)
    private var generation = 0
    private var ready = false
    private let directoryLock = NSLock()
    private var pickedDirectories: [String: DirectoryExportSession] = [:]
    private let activeDirectories = NSHashTable<DirectoryExportSession>.weakObjects()

    init(present: @escaping (URL, ExportTarget) -> Void, cancel: @escaping () -> Void) {
        self.present = present
        self.cancel = cancel
        super.init()
        // A terminated share sheet leaves plaintext behind; only our own
        // scratch directory is removed on the next process launch.
        ready = resetDirectory()
    }

    func registerDirectory(_ url: URL) -> String? {
        guard let session = DirectoryExportSession(
            url: url,
            startAccess: { url.startAccessingSecurityScopedResource() },
            stopAccess: { url.stopAccessingSecurityScopedResource() }
        ) else { return nil }
        let token = UUID().uuidString
        directoryLock.lock(); pickedDirectories[token] = session; directoryLock.unlock()
        return token
    }

    func discardDirectory(_ token: String) {
        directoryLock.lock(); let session = pickedDirectories.removeValue(forKey: token); directoryLock.unlock()
        session?.close()
    }

    func openDirectory(uri: String) -> ExportDirectory? {
        directoryLock.lock()
        let session = pickedDirectories.removeValue(forKey: uri)
        if let session { activeDirectories.add(session) }
        directoryLock.unlock()
        guard let session, let directory = session.directory else { return nil }
        return ScopedExportDirectory(directory: directory)
    }

    func cancelDirectoryOperations() {
        directoryLock.lock()
        let sessions = Array(pickedDirectories.values) + activeDirectories.allObjects
        pickedDirectories.removeAll()
        activeDirectories.removeAllObjects()
        directoryLock.unlock()
        sessions.forEach { $0.close() }
    }

    func cancelPending() {
        cancelDirectoryOperations()
        generation += 1
        cancel()
        ready = resetDirectory()
    }

    private func resetDirectory() -> Bool {
        do {
            if FileManager.default.fileExists(atPath: directory.path) {
                try FileManager.default.removeItem(at: directory)
            }
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true,
                attributes: [.protectionKey: FileProtectionType.complete]
            )
            try (directory as NSURL).setResourceValue(true, forKey: .isExcludedFromBackupKey)
            return true
        } catch {
            return false
        }
    }

    func archiveCapacity(target: ExportTarget) -> Int64 {
        guard target == .files || target == .share else { return 0 }
        let imports = FileManager.default.temporaryDirectory.appendingPathComponent("chur-media-imports", isDirectory: true)
        return (try? ScratchCopy.remainingBudget(in: [directory, imports, FileManager.default.temporaryDirectory.appendingPathComponent("chur-incoming-media")])) ?? 0
    }

    func create(displayName: String, contentType: String) -> ExportSinkDestination? {
        create(displayName: displayName, contentType: contentType, target: .default_, uri: nil)
    }

    func createArchive(displayName: String, contentType: String, target: ExportTarget, uri: String?, capacity: Int64) -> ExportSinkDestination? {
        // iOS exports already use a protected, seekable app-private file.
        create(displayName: displayName, contentType: contentType, target: target, uri: uri, plaintextSize: capacity)
    }

    func create(displayName: String, contentType: String, target: ExportTarget, uri: String?, plaintextSize: Int64) -> ExportSinkDestination? {
        let imports = FileManager.default.temporaryDirectory.appendingPathComponent("chur-media-imports", isDirectory: true)
        guard let budget = try? ScratchCopy.remainingBudget(in: [directory, imports, FileManager.default.temporaryDirectory.appendingPathComponent("chur-incoming-media")]),
              plaintextSize >= 0, plaintextSize <= budget else { return nil }
        return create(displayName: displayName, contentType: contentType, target: target, uri: uri)
    }

    func create(displayName: String, contentType: String, target: ExportTarget, uri: String?) -> ExportSinkDestination? {
        guard ready else { return nil }
        let createdGeneration = generation
        let ext = UTType(mimeType: contentType)?.preferredFilenameExtension
            ?? URL(fileURLWithPath: displayName).pathExtension
        let suffix = ext.range(of: "^[A-Za-z0-9]{1,10}$", options: .regularExpression) == nil ? "bin" : ext
        let folder = directory.appendingPathComponent(UUID().uuidString, isDirectory: true)
        guard (try? FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)) != nil else { return nil }
        let original = URL(fileURLWithPath: displayName).lastPathComponent
        let base = original.isEmpty || original == "." ? "chur-export" : original
        let name = URL(fileURLWithPath: base).pathExtension.isEmpty ? "\(base).\(suffix)" : base
        let url = folder.appendingPathComponent(target == .files ? name : "export.\(suffix)")
        let descriptor = Darwin.open(url.path, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else { return nil }
        do {
            try FileManager.default.setAttributes([.protectionKey: FileProtectionType.complete], ofItemAtPath: url.path)
        } catch {
            Darwin.close(descriptor)
            try? FileManager.default.removeItem(at: url)
            return nil
        }
        return ShareDestination(
            url: url,
            descriptor: descriptor,
            target: target,
            present: present,
            valid: { [weak self] in self?.generation == createdGeneration }
        )
    }
}

private final class ShareDestination: NSObject, ExportSinkDestination {
    let descriptor: Int32
    private let url: URL
    private let target: ExportTarget
    private let present: (URL, ExportTarget) -> Void
    private let valid: () -> Bool
    private var closed = false

    init(url: URL, descriptor: Int32, target: ExportTarget, present: @escaping (URL, ExportTarget) -> Void, valid: @escaping () -> Bool) {
        self.url = url
        self.descriptor = descriptor
        self.target = target
        self.present = present
        self.valid = valid
    }

    func publish() {
        DispatchQueue.main.async {
            guard self.valid() else { self.discard(); return }
            self.present(self.url, self.target)
            let url = self.url
            DispatchQueue.main.asyncAfter(deadline: .now() + 30 * 60) {
                try? FileManager.default.removeItem(at: url)
            }
        }
    }
    func publishChecked() -> Bool { publish(); return true }
    func discard() { try? FileManager.default.removeItem(at: url) }
    func close() {
        if !closed { Darwin.close(descriptor); closed = true }
    }
}

private final class ScopedExportDirectory: NSObject, ExportDirectory {
    private let directory: DirectoryExportNode
    init(directory: DirectoryExportNode) { self.directory = directory }
    func createDirectory(displayName: String) -> ExportDirectory? {
        directory.createDirectory(displayName: displayName).map { ScopedExportDirectory(directory: $0) }
    }
    func createFile(displayName: String, contentType: String, plaintextSize: Int64) -> ExportSinkDestination? {
        directory.createFile(displayName: displayName, plaintextSize: plaintextSize).map { ScopedDirectoryDestination(file: $0) }
    }
    func close() { directory.close() }
}

private final class ScopedDirectoryDestination: NSObject, ExportSinkDestination {
    private let file: DirectoryExportFile
    init(file: DirectoryExportFile) { self.file = file }
    var descriptor: Int32 { file.descriptor }
    func publish() { _ = file.publishChecked() }
    func publishChecked() -> Bool { file.publishChecked() }
    func discard() { file.discard() }
    func close() { file.close() }
}
