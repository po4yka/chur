@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package dev.po4yka.chur.app

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.CompositionLocalProvider
import dev.po4yka.chur.app.vault.LocalIosVaultChrome
import dev.po4yka.chur.app.vault.LocalIosVaultScenes
import dev.po4yka.chur.app.vault.LocalIosVaultScene
import dev.po4yka.chur.app.vault.IosVaultScreen
import dev.po4yka.chur.app.vault.IosViewerPanelState
import dev.po4yka.chur.app.vault.IosViewerPanelActions
import dev.po4yka.chur.app.vault.forScene
import dev.po4yka.chur.app.theme.LocalChurColors
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.runtime.withFrameNanos
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.platform.LocalFocusManager
import dev.po4yka.chur.app.notes.NoteEditorScreen
import dev.po4yka.chur.app.notes.NotesScreen
import dev.po4yka.chur.app.notes.OpenNote
import dev.po4yka.chur.app.notes.PublicSettingsScreen
import dev.po4yka.chur.app.PublicShell as PublicShellKind
import dev.po4yka.chur.app.publicshell.CalculatorScreen
import androidx.compose.runtime.key
import dev.po4yka.chur.app.notes.rememberOpenNote
import dev.po4yka.chur.app.vault.CreateVaultScreen
import dev.po4yka.chur.app.vault.loadedObjectSelection
import dev.po4yka.chur.app.vault.LibraryTile
import dev.po4yka.chur.app.vault.AlbumExportDialog
import dev.po4yka.chur.app.vault.AlbumPickerDialog
import dev.po4yka.chur.app.vault.DeleteSelectionDialog
import dev.po4yka.chur.app.vault.ExportOptionsDialog
import dev.po4yka.chur.app.vault.canSaveToPhotos
import dev.po4yka.chur.app.vault.NewAlbumDialog
import dev.po4yka.chur.app.vault.TagPickerDialog
import dev.po4yka.chur.app.vault.TagBrowserDialog
import dev.po4yka.chur.app.vault.RecoveryPhraseScreen
import dev.po4yka.chur.app.vault.RecoveryScreen
import dev.po4yka.chur.app.vault.RestoreBackupScreen
import dev.po4yka.chur.app.vault.SourceDeletionCopy
import dev.po4yka.chur.app.vault.SourceDeletionDialog
import dev.po4yka.chur.app.vault.importedOriginals
import dev.po4yka.chur.app.vault.ThumbnailCache
import dev.po4yka.chur.app.vault.ThumbnailRendition
import dev.po4yka.chur.app.vault.rememberGalleryThumbnails
import dev.po4yka.chur.app.vault.rememberViewerThumbnails
import dev.po4yka.chur.app.vault.thumbnailRendition
import dev.po4yka.chur.app.vault.UnlockScreen
import dev.po4yka.chur.app.vault.LocalPrivatePanic
import dev.po4yka.chur.app.vault.PrivateAlertDialog
import dev.po4yka.chur.app.vault.PrivateModalPresentation
import dev.po4yka.chur.app.vault.PrivateModalAnchor
import dev.po4yka.chur.app.vault.LocalPrivateModalGuard
import dev.po4yka.chur.app.vault.privateModalAction
import dev.po4yka.chur.app.vault.ViewerDetailContent
import dev.po4yka.chur.app.vault.VaultActions
import dev.po4yka.chur.app.vault.VaultDestination
import dev.po4yka.chur.app.vault.ContentView
import dev.po4yka.chur.app.vault.AlbumOrder
import dev.po4yka.chur.app.vault.browseQuery
import dev.po4yka.chur.app.vault.browseSearchScope
import dev.po4yka.chur.app.vault.BrowseQueryLocation
import dev.po4yka.chur.app.vault.SelectiveExportDialog
import dev.po4yka.chur.app.vault.SelectiveImportDialog
import dev.po4yka.chur.app.vault.PrivateNotesRoute
import dev.po4yka.chur.app.vault.albumParent
import dev.po4yka.chur.app.vault.albumPath
import dev.po4yka.chur.app.vault.VaultShell
import dev.po4yka.chur.app.vault.MEDIA_CLASS_AUDIO
import dev.po4yka.chur.app.vault.MEDIA_CLASS_IMAGE
import dev.po4yka.chur.app.vault.MEDIA_CLASS_VIDEO
import dev.po4yka.chur.app.vault.viewerPages
import dev.po4yka.chur.app.vault.ViewerStillState
import dev.po4yka.chur.app.vault.viewerStill
import dev.po4yka.chur.app.vault.rememberViewerAnimation
import dev.po4yka.chur.app.vault.VaultPlayer
import dev.po4yka.chur.app.vault.VaultDocument
import dev.po4yka.chur.app.vault.VaultUiState
import dev.po4yka.chur.app.vault.ViewerChrome
import dev.po4yka.chur.app.vault.ViewerScreen
import dev.po4yka.chur.app.vault.PresentedState
import dev.po4yka.chur.app.vault.playbackFor
import dev.po4yka.chur.ffi.AlbumSummary
import dev.po4yka.chur.ffi.ObjectDetail
import dev.po4yka.chur.ffi.ObjectPage
import dev.po4yka.chur.ffi.ObjectProjection
import dev.po4yka.chur.ffi.ObjectQuery
import dev.po4yka.chur.ffi.QueryScope
import dev.po4yka.chur.ffi.QuerySort
import dev.po4yka.chur.ffi.StreamKind
import dev.po4yka.chur.ffi.TagSummary
import dev.po4yka.chur.ffi.fromHex
import dev.po4yka.chur.imports.IosMediaCodec
import dev.po4yka.chur.notes.Note
import dev.po4yka.chur.vault.VaultState
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import platform.Foundation.NSDate
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSURL
import platform.Foundation.timeIntervalSince1970
import platform.UIKit.UIApplication
import platform.UIKit.endEditing
import platform.UIKit.accessibilityElementsHidden
import platform.UIKit.navigationItem
import platform.posix.unlink

/**
 * The iOS route table.
 *
 * The photo picker is presented by the Xcode host through [IosMediaPicker].
 */
@Composable
internal fun IosRoutes(controller: ChurController, route: AppRoute, vaultState: VaultState) {
    val chrome = LocalIosVaultChrome.current
    dev.po4yka.chur.app.onboarding.GuideHost(controller, route,
        onDockHeight = { chrome?.setGuideInset(if (route == AppRoute.Vault) it.toDouble() else 0.0) }) {
        IosRoutesGuided(controller, route, vaultState)
    }
}

@Composable
private fun IosRoutesGuided(controller: ChurController, route: AppRoute, vaultState: VaultState) {
    val phrase by controller.recoveryPhrase.collectAsState()
    val panic: (() -> Unit)? = if (route == AppRoute.Vault || vaultState is VaultState.Unlocked || phrase != null) {
        { controller.panic() }
    } else null
    CompositionLocalProvider(LocalPrivatePanic provides panic) {
        IosRoutesContent(controller, route, vaultState)
    }
}

@Composable
private fun IosRoutesContent(controller: ChurController, route: AppRoute, vaultState: VaultState) {
    val phrase by controller.recoveryPhrase.collectAsState()
    val formError by controller.formError.collectAsState()
    val unlocking by controller.unlocking.collectAsState()
    val maskRequest by IosLauncherActions.maskRequest.collectAsState()
    LaunchedEffect(route, maskRequest, phrase) {
        if (maskRequest > 0 && phrase == null && (route == AppRoute.PublicShell || route == AppRoute.AppUnlock)) {
            // Let the neutral composition draw before removing the UIKit cover.
            withFrameNanos { }
            withFrameNanos { }
            IosLauncherActions.onMaskRendered?.invoke()
        }
    }
    val incomingCodec = remember { IosMediaCodec() }
    val incomingImporter = remember(incomingCodec) { MediaImporter(incomingCodec) }
    DisposableEffect(controller) {
        IosIncomingShares.cancelOperation = controller::cancelActiveOperation
        onDispose { IosIncomingShares.cancelOperation = null }
    }
    IncomingSharePrompt(IosIncomingShares.inbox, controller, route, incomingImporter)

    phrase?.let { value ->
        // Copying 24 words by hand, `RECOVERY.md` §2.3, outlasts the
        // auto-lock, which backgrounds the scene and drops the phrase. The
        // repository's phrase window bounds how long the display stays awake.
        DisposableEffect(Unit) {
            UIApplication.sharedApplication.idleTimerDisabled = true
            onDispose { UIApplication.sharedApplication.idleTimerDisabled = false }
        }
        RecoveryPhraseScreen(
            phrase = value,
            onAcknowledged = controller::acknowledgeRecoveryPhrase,
            onLock = { controller.lock() },
            onPanic = { controller.panic() },
        )
        return
    }

    when (route) {
        AppRoute.PublicShell, AppRoute.PublicSettings -> PublicShellRoute(controller, route)
        AppRoute.CreateVault -> CreateVaultScreen(
            busy = vaultState is VaultState.Creating,
            error = formError,
            onCreate = controller::create,
            onHide = { controller.panic() },
            // A second vault is set up over an open session, and the public
            // shell is the last step of a lock, `PLAINTEXT_LIFECYCLE.md` §8.
            // The route check keeps a lock that already moved the route from
            // being undone by this composition's stale vault state.
            onCancel = {
                if (controller.route.value == route) {
                    controller.goTo(if (vaultState is VaultState.Unlocked) AppRoute.Vault else AppRoute.PublicShell)
                }
            },
            onRestore = if (vaultState is VaultState.NoVault) {
                { controller.goTo(AppRoute.RestoreBackup) }
            } else {
                null
            },
        )
        AppRoute.RestoreBackup -> IosRestoreRoute(controller)
        AppRoute.EncryptFiles -> IosExternalArchiveRoute(controller)
        AppRoute.Unlock -> UnlockScreen(
            busy = unlocking,
            error = formError,
            onUnlock = controller::unlock,
            onUseRecovery = { controller.goTo(AppRoute.Recover) },
            onReturnToPublic = { controller.panic() },
            deviceUnlockOffered = controller.deviceUnlockOffered.collectAsState().value,
            onUseDevice = controller::unlockWithAppleDevice,
        )
        AppRoute.AppUnlock -> UnlockScreen(
            busy = unlocking,
            error = formError,
            onUnlock = controller::unlock,
            onUseRecovery = { controller.goTo(AppRoute.AppRecover) },
            deviceUnlockOffered = controller.deviceUnlockOffered.collectAsState().value,
            onUseDevice = controller::unlockWithAppleDevice,
            appGate = true,
        )
        AppRoute.Recover -> RecoveryScreen(
            busy = unlocking,
            error = formError,
            onRecover = controller::recover,
            onBack = { controller.goTo(AppRoute.Unlock) },
            onReturnToPublic = { controller.panic() },
        )
        AppRoute.AppRecover -> RecoveryScreen(
            busy = unlocking,
            error = formError,
            onRecover = controller::recover,
            onBack = { controller.panic() },
        )
        AppRoute.Vault -> key((vaultState as? VaultState.Unlocked)?.generation) {
            VaultRoute(controller, vaultState)
        }
    }
}

@Composable
private fun PublicShellRoute(controller: ChurController, route: AppRoute) {
    dev.po4yka.chur.app.publicshell.PublicUtilityTheme(controller.publicUtilities) { PublicShellContent(controller, route) }
}

@Composable
private fun PublicShellContent(controller: ChurController, route: AppRoute) {
    val discreet by controller.publicUtilities.discreet.collectAsState()
    val shell by controller.publicShell.collectAsState()
    val error by controller.publicShellError.collectAsState()
    val disclosureDue by controller.publicDisclosureRequired.collectAsState()
    if (route == AppRoute.PublicSettings) {
        PublicSettingsScreen(
            onBack = { controller.goTo(AppRoute.PublicShell) },
            onOpenVault = controller::openVaultEntry,
            onEncryptExternalFiles = controller::openExternalArchive,
            discreet = discreet,
            selectedShell = shell,
            onTutorial = { controller.startPublicGuide() },
            onSelectShell = controller::setPublicShell,
            error = error,
        )
        return
    }
    key(shell) {
        when (shell) {
            PublicShellKind.PET -> {
                val inputEpoch by controller.publicInputEpoch.collectAsState()
                dev.po4yka.chur.app.publicshell.PetScreen(
                    onOpenSettings = { controller.goTo(AppRoute.PublicSettings) },
                    onSubmitCode = controller::submitPublicCode, inputEpoch = inputEpoch,
                    onNavigationBusy = controller::setLauncherNavigationBusy)
            }
            PublicShellKind.NOTES -> PublicNotesShell(controller) { controller.goTo(AppRoute.PublicSettings) }
            PublicShellKind.CALCULATOR -> CalculatorScreen(onOpenSettings = { controller.goTo(AppRoute.PublicSettings) }, onSubmitCode = controller::submitPublicCode,
                showFirstWriteDisclosure = disclosureDue, onAcknowledgeDisclosure = controller::acknowledgeDisclosure)
            PublicShellKind.CAMERA -> IosPublicCameraScreen(
                onSubmitCode = controller::submitPublicCode,
                onOpenSettings = { controller.goTo(AppRoute.PublicSettings) },
                showFirstWriteDisclosure = disclosureDue,
                onAcknowledgeDisclosure = controller::acknowledgeDisclosure,
                onNavigationBusyChange = controller::setLauncherNavigationBusy,
            )
        }
    }
}

@Composable
private fun PublicNotesShell(controller: ChurController, onOpenSettings: () -> Unit) {
    val focus = LocalFocusManager.current
    val notes by controller.notesState.collectAsState()
    val trashedNotes by controller.trashedNotesState.collectAsState()
    val writeFailureId by controller.publicNoteWriteFailureId.collectAsState()
    val disclosureDue by controller.disclosureDue.collectAsState()
    var query by remember { mutableStateOf("") }
    // Saved state, shared with the Android host. This host does not persist
    // the composition's saved state, so on iOS it lasts as long as the view
    // controller; the editor saves its own draft whenever it leaves.
    var editing by rememberOpenNote()
    val newNoteRequest by controller.publicNoteRequest.collectAsState()
    LaunchedEffect(newNoteRequest) { controller.takePublicNoteRequest()?.let { editing = OpenNote(it, isNew = true) } }

    DisposableEffect(controller, editing != null) {
        controller.setLauncherNavigationBusy(editing != null)
        onDispose { controller.setLauncherNavigationBusy(false) }
    }

    editing?.let { open ->
        NoteEditorScreen(
            open = open,
            savedNote = notes.firstOrNull { it.id == open.note.id },
            writeFailed = writeFailureId == open.note.id,
            showFirstWriteDisclosure = disclosureDue,
            onAcknowledgeDisclosure = controller::acknowledgeDisclosure,
            onSave = controller::putNote,
            onAddAttachment = controller::addPublicNoteAttachment,
            onReadAttachment = { id -> controller.readPublicNoteAttachment(open.note.id, id) },
            onRemoveAttachment = { id -> controller.removePublicNoteAttachment(open.note.id, id) },
            onExportPackage = controller::exportPublicNotePackage,
            onOrganize = { folder, tags -> controller.organizePublicNote(open.note.id, folder, tags) },
            onHistory = { controller.publicNoteHistory(open.note.id) },
            onRestoreRevision = { revision -> controller.restorePublicNoteRevision(open.note.id, revision) },
            onRemove = controller::removeNote,
            onTrash = controller::trashPublicNote,
            onBack = { editing = null },
            onOpenSettings = {
                focus.clearFocus(force = true)
                onOpenSettings()
            },
        )
        return
    }

    NotesScreen(
        notes = notes,
        trashedNotes = trashedNotes,
        onRefreshTrash = controller::refreshPublicTrash,
        onRestore = controller::restorePublicNote,
        onPurge = controller::purgePublicNote,
        onImport = { title, body ->
            val imported = Note(id = "note-${(NSDate().timeIntervalSince1970 * 1_000_000).toLong()}", title = title, body = body, updatedMs = (NSDate().timeIntervalSince1970 * 1000).toLong())
            controller.putNote(imported)
            editing = OpenNote(imported, isNew = false)
        },
        onImportPackage = { bytes ->
            val imported = controller.importPublicNotePackage(bytes, "note-${(NSDate().timeIntervalSince1970 * 1_000_000).toLong()}")
            editing = OpenNote(imported, isNew = false)
        },
        query = query,
        onQueryChange = { query = it },
        onSubmitSearch = { if (controller.matchesPublicCode(query)) { val submitted = query; query = ""; controller.submitPublicCode(submitted) } },
        onBulkAction = controller::updatePublicNotes,
        onOpen = { editing = OpenNote(it, isNew = false) },
        onCreate = {
            val now = (NSDate().timeIntervalSince1970 * 1000).toLong()
            editing = OpenNote(Note(id = "note-$now", title = "", body = "", updatedMs = now), isNew = true)
        },
        onOpenSettings = { onOpenSettings() },
        showFirstWriteDisclosure = disclosureDue,
        onAcknowledgeDisclosure = controller::acknowledgeDisclosure,
    )
}

/** Each source keeps its scoped provider lease until native encryption returns. */
@Composable
private fun IosExternalArchiveRoute(controller: ChurController) {
    val codec = remember { IosMediaCodec() }
    var alive by remember(controller) { mutableStateOf(true) }
    var pending by remember(controller) { mutableStateOf<((ExternalArchiveSelection?) -> Unit)?>(null) }
    DisposableEffect(controller) {
        onDispose {
            alive = false
            val pickerWasOpen = pending != null
            pending = null
            // Once handed over, only the operation owner may close source grants.
            if (pickerWasOpen) {
                IosDocumentPicker.cancel?.invoke()
                IosAudioPicker.cancel?.invoke()
                IosLivePhotoFilesPicker.cancel?.invoke()
                IosMediaFilesPicker.cancel?.invoke()
            }
        }
    }
    ExternalArchiveScreen(
        controller = controller,
        selectFiles = { answer ->
            val present = IosDocumentPicker.present
            if (present == null) {
                controller.report("This build cannot open the document picker.")
                answer(null)
            } else {
                pending = answer
                try {
                    present { count, load, releaseSelection ->
                        val current = pending
                        pending = null
                        if (!alive || current == null || count <= 0 || count > 32) {
                            releaseSelection()
                            if (alive && current != null) {
                                if (count > 32) controller.report("Select at most 32 files for one encrypted archive.")
                                current(null)
                            }
                        } else {
                            current(ExternalArchiveSelection(
                                count = count,
                                open = { index, prepare ->
                                    withContext(Dispatchers.Main) {
                                        suspendCancellableCoroutine { continuation ->
                                            load(index, prepare) { fd, name, type, size, release ->
                                                val picked = codec.openDocument(fd, name, type, size, release)
                                                continuation.resume(picked) { _, item, _ -> item?.close?.invoke() }
                                            }
                                        }
                                    }
                                },
                                close = releaseSelection,
                            ))
                        }
                    }
                } catch (_: Exception) {
                    pending = null
                    controller.report("The file picker could not be opened.")
                    answer(null)
                }
            }
        },
    )
}

@Composable
private fun VaultRoute(controller: ChurController, vaultState: VaultState) {
    val contentIndex by controller.contentIndex.collectAsState()
    val page by controller.page.collectAsState()
    val albums by controller.albums.collectAsState()
    val tags by controller.tags.collectAsState()
    val slots by controller.slots.collectAsState()
    val reencryptionNotice by controller.reencryptionNotice.collectAsState()
    val deviceSlotStrict by controller.deviceSlotStrict.collectAsState()
    val appLockEnabled by controller.appLockEnabled.collectAsState()
    val autoLock by controller.autoLock.collectAsState()
    val notice by controller.notice.collectAsState()
    val operation by controller.activeOperation.collectAsState()
    val syncStatus by controller.syncStatus.collectAsState()
    val focusManager = LocalFocusManager.current
    val vaultDevicePairing by controller.devicePairing.collectAsState()
    val pairingFiles = rememberPairingFiles(controller)
    val generation = (vaultState as? VaultState.Unlocked)?.generation ?: 0L
    val archiveTransfers = remember(controller, generation) { ArchiveTransferOwner(controller, generation) }
    DisposableEffect(archiveTransfers) { onDispose { archiveTransfers.close() } }
    var choosingArchive by remember(generation) { mutableStateOf<SelectiveExportRequest?>(null) }
    var choosingArchiveImport by remember(generation) { mutableStateOf(false) }
    var showingPrivateNotes by remember(generation) { mutableStateOf(false) }
    var privateNotesBusy by remember(generation) { mutableStateOf(false) }
    var initialCreateRequest by remember(generation) { mutableStateOf<Long?>(null) }
    var searchFocusRequest by remember(generation) { mutableStateOf<Long?>(null) }
    val nativeChrome = checkNotNull(LocalIosVaultChrome.current)
    val scenes = checkNotNull(LocalIosVaultScenes.current)
    val guideSession by controller.guide.session.collectAsState()
    val guideObscured by controller.guideObscured.collectAsState()
    LaunchedEffect(nativeChrome, guideSession, guideObscured) {
        try {
            if (guideSession?.publicOnly == false && !guideObscured) {
                while (true) {
                    nativeChrome.updateGuide(controller.guide)
                    kotlinx.coroutines.delay(200)
                }
            }
        } finally { nativeChrome.updateGuide(null) }
    }
    val colors = LocalChurColors.current
    DisposableEffect(controller, nativeChrome, scenes, generation) {
        if (controller.route.value == AppRoute.Vault &&
            (controller.vaultState.value as? VaultState.Unlocked)?.generation == generation
        ) {
            nativeChrome.beginPresentation(generation)
            scenes.begin(generation)
        }
        onDispose { nativeChrome.clear(); scenes.clear() }
    }
    var viewerNavigationBusy by remember(generation) { mutableStateOf(false) }
    var viewerVisit by remember(generation) { mutableStateOf(0L) }
    var shellNavigationBusy by remember(generation) { mutableStateOf(false) }
    var choosingPrivateNoteExport by remember(generation) { mutableStateOf<PrivateNoteExportRequest?>(null) }
    var thumbnailsConcealed by remember(generation) { mutableStateOf(true) }
    var destination by remember { mutableStateOf(VaultDestination.LIBRARY) }
    var mediaView by remember { mutableStateOf(ContentView.GRID) }
    var albumView by remember { mutableStateOf(ContentView.LIST) }
    var mediaSort by remember { mutableStateOf(QuerySort.CAPTURE_DESC) }
    var albumSort by remember { mutableStateOf(QuerySort.ALBUM_MANUAL) }
    var mediaKinds by remember { mutableStateOf(0) }
    var albumOrder by remember { mutableStateOf(AlbumOrder.MANUAL) }
    var albumFilter by remember { mutableStateOf("") }
    var terms by remember(generation) { mutableStateOf("") }
    var openAlbum by remember(generation) { mutableStateOf<AlbumSummary?>(null) }
    var exportingAlbum by remember(generation) { mutableStateOf<AlbumSummary?>(null) }
    var albumPickerPending by remember(generation) { mutableStateOf(false) }
    var documentPickerPending by remember(generation) { mutableStateOf(false) }
    var choosingImportSource by remember(generation) { mutableStateOf(false) }
    DisposableEffect(controller, generation) {
        onDispose {
            IosDocumentPicker.cancel?.invoke()
            IosAudioPicker.cancel?.invoke()
            IosLivePhotoFilesPicker.cancel?.invoke()
            IosMediaFilesPicker.cancel?.invoke()
            if (documentPickerPending) {
                documentPickerPending = false
                val current = controller.vaultState.value as? VaultState.Unlocked
                if (current?.generation == generation) controller.endHostActivity()
            }
            if (albumPickerPending) {
                IosAlbumExportPicker.cancel?.invoke()
                if (albumPickerPending) {
                    albumPickerPending = false
                    val current = controller.vaultState.value as? VaultState.Unlocked
                    if (current?.generation == generation) controller.endHostActivity()
                }
            }
        }
    }

    var openTag by remember { mutableStateOf<TagSummary?>(null) }
    var favoritesOnly by remember { mutableStateOf(false) }
    var trashOpen by remember { mutableStateOf(false) }
    var quarantineOpen by remember { mutableStateOf(false) }
    var recentlyAdded by remember(generation) { mutableStateOf(false) }
    LaunchedEffect(tags) {
        openTag = openTag?.let { current -> tags.firstOrNull { it.id == current.id } }
    }
    var selection by remember(generation) { mutableStateOf(setOf<String>()) }
    // The item on screen in the viewer; a swipe moves it through the page.
    var viewing by remember(generation) { mutableStateOf<ObjectProjection?>(null) }
    LaunchedEffect(albums) {
        val current = openAlbum
        if (current != null) {
            val resolved = albumPath(albums, current.id).lastOrNull()
            if (resolved == null) {
                terms = ""
                selection = emptySet()
                viewing = null
                destination = VaultDestination.ALBUMS
            }
            openAlbum = resolved
        }
    }
    fun navigateAlbum(target: AlbumSummary?) {
        focusManager.clearFocus()
        terms = ""
        searchFocusRequest = null
        viewing = null
        selection = emptySet()
        openTag = null
        favoritesOnly = false
        trashOpen = false
        quarantineOpen = false
        recentlyAdded = false
        destination = VaultDestination.ALBUMS
        openAlbum = target?.let { albumPath(albums, it.id).lastOrNull() }
    }

    var visibleMediaIds by remember(generation) { mutableStateOf(emptySet<String>()) }
    var creatingAlbum by remember { mutableStateOf(false) }
    var choosingAlbum by remember { mutableStateOf(false) }
    var movingSelection by remember { mutableStateOf(false) }
    var organizingIds by remember { mutableStateOf<List<ByteArray>>(emptyList()) }
    var choosingTag by remember { mutableStateOf(false) }
    var managingTags by remember { mutableStateOf(false) }
    var taggingIds by remember { mutableStateOf<List<ByteArray>>(emptyList()) }
    var confirmingDelete by remember { mutableStateOf(false) }
    var confirmingEmptyTrash by remember { mutableStateOf(false) }
    var choosingExport by remember { mutableStateOf(false) }
    // The originals of the last import, until the user answers the step of
    // `DESIGN.md` §15.3. A lock disposes of the route and of them.
    var originals by remember { mutableStateOf<PickedOriginals?>(null) }
    val scope = rememberCoroutineScope()
    val codec = remember { IosMediaCodec() }
    val importer = remember { MediaImporter(codec) }
    val launcherRequest by controller.launcherRequest.collectAsState()
    val launcherSceneReady by IosLauncherActions.sceneReady.collectAsState()
    val incomingShare by IosIncomingShares.inbox.state.collectAsState()
    val modalNavigationBusy = choosingArchive != null || choosingArchiveImport || choosingPrivateNoteExport != null ||
        exportingAlbum != null || albumPickerPending || documentPickerPending || choosingImportSource ||
        creatingAlbum || choosingAlbum || choosingTag || managingTags || confirmingDelete ||
        confirmingEmptyTrash || choosingExport || originals != null || incomingShare != null
    val guideNavigationBusy = shellNavigationBusy || privateNotesBusy || selection.isNotEmpty() || modalNavigationBusy
    val navigationBusy = guideNavigationBusy || viewing != null
    DisposableEffect(controller, navigationBusy, guideNavigationBusy) {
        controller.setVaultNavigationBusy(navigationBusy, guideNavigationBusy)
        onDispose { controller.setLauncherNavigationBusy(false) }
    }
    LaunchedEffect(launcherRequest?.token, generation, navigationBusy, launcherSceneReady) {
        val request = launcherRequest ?: return@LaunchedEffect
        if (!launcherSceneReady) return@LaunchedEffect
        if (navigationBusy || nativeChrome.hasVisibleMenu()) {
            controller.rejectLauncherAction(request.token)
            return@LaunchedEffect
        }
        if (!controller.acknowledgeLauncherAction(request.token, generation)) return@LaunchedEffect
        focusManager.clearFocus()
        openAlbum = null
        openTag = null
        favoritesOnly = false
        trashOpen = false
        quarantineOpen = false
        recentlyAdded = false
        selection = emptySet()
        terms = ""
        mediaKinds = 0
        searchFocusRequest = null
        when (request.action) {
            LauncherAction.IMPORT -> {
                showingPrivateNotes = false
                initialCreateRequest = null
                destination = VaultDestination.LIBRARY
                choosingImportSource = true
            }
            LauncherAction.SEARCH -> {
                showingPrivateNotes = false
                initialCreateRequest = null
                destination = VaultDestination.SEARCH
                searchFocusRequest = request.token
            }
            LauncherAction.NEW_PRIVATE_NOTE -> {
                initialCreateRequest = request.token
                showingPrivateNotes = true
            }
            LauncherAction.PUBLIC_NOTES, LauncherAction.PUBLIC_CALCULATOR, LauncherAction.PUBLIC_CAMERA, LauncherAction.PUBLIC_PET -> Unit
            LauncherAction.LOCK_AND_HIDE -> Unit // The controller handles this synchronously.
        }
    }

    val browseLocation = BrowseQueryLocation(
        browseSearchScope(destination, openAlbum, openTag, favoritesOnly, trashOpen, quarantineOpen, recentlyAdded),
        terms, mediaSort, albumSort, mediaKinds,
    )
    var loadedLocation by remember(generation) { mutableStateOf<BrowseQueryLocation?>(null) }
    LaunchedEffect(destination, openAlbum, openTag, favoritesOnly, trashOpen, quarantineOpen, recentlyAdded,
        terms, mediaSort, albumSort, mediaKinds) {
        val query = browseQuery(destination, openAlbum, openTag, favoritesOnly,
            trashOpen, terms, mediaSort, albumSort, mediaKinds, quarantine = quarantineOpen,
            recentlyAdded = recentlyAdded)
        when {
            query != null -> controller.load(query)
            destination == VaultDestination.SEARCH -> controller.load(
                ObjectQuery(QueryScope.SEARCH, terms = ""))
            destination == VaultDestination.ALBUMS -> controller.loadAlbums()
            destination == VaultDestination.SETTINGS -> {
                controller.loadSlots()
            }
            else -> Unit
        }
        loadedLocation = browseLocation
    }

    // The cache is the controller's: its lock transitions clear it whether
    // or not this screen is composed, §4 of `PLAINTEXT_LIFECYCLE.md`. The
    // session generation in the key is what makes a stale entry unreachable
    // after a new session opens.
    val cache = controller.thumbnailCache
    LaunchedEffect(generation) {
        if (vaultState is VaultState.Unlocked) controller.loadAlbums()
    }

    val thumbnails = rememberGalleryThumbnails(
        controller.vault, cache, generation, page.objects.filter { it.id in visibleMediaIds }, thumbnailsConcealed,
    )
    // Plain pixels are loaded separately only while the viewer is open. They
    // never enter the gallery map, including the viewer's adjacent pages.
    val viewerThumbnails = rememberViewerThumbnails(
        controller.vault, cache, generation, page.objects, currentObjectId = viewing?.id,
    )

    originals?.let { picked ->
        SourceDeletionDialog(
            count = picked.count,
            onKeep = { originals = null },
            onReview = {
                originals = null
                // Photos asks for access and then to confirm. Each alert only
                // makes the scene resign active, so the two run in one prompt,
                // which leaving the app ends with a lock, `IOS.md` §21.2.
                val session = controller.vaultState.value
                val prompt = controller.beginPrompt()
                picked.delete { found, deleted ->
                    // Leaving or a lock ended the prompt with the session, and
                    // the outcome belongs to no screen of a later one.
                    if (controller.endPrompt(prompt) && controller.vaultState.value == session) {
                        controller.report(SourceDeletionCopy.verifiedOutcome(picked.count, found, deleted))
                    }
                }
            },
        )
    }

    fun modalSessionCurrent(): Boolean = controller.route.value == AppRoute.Vault &&
        (controller.vaultState.value as? VaultState.Unlocked)?.generation == generation &&
        !showingPrivateNotes && viewing == null

    if (creatingAlbum) {
        val visit = rememberIosRouteModalVisit()
        val sourceDestination = remember(visit) { destination }
        val sourceAlbumId = remember(visit) { openAlbum?.id }
        val sourceSelection = remember(visit) { selection.toSet() }
        val sourceScope = remember(visit) { browseSearchScope(destination, openAlbum, openTag,
            favoritesOnly, trashOpen, quarantineOpen, recentlyAdded) }
        fun scopeCurrent(): Boolean = sourceScope == browseSearchScope(destination, openAlbum, openTag,
            favoritesOnly, trashOpen, quarantineOpen, recentlyAdded)
        fun canCreate(): Boolean = modalSessionCurrent() && creatingAlbum &&
            controller.activeOperation.value == null && scopeCurrent() && destination == sourceDestination &&
            openAlbum?.id == sourceAlbumId && selection == sourceSelection
        CompositionLocalProvider(LocalPrivateModalGuard provides ::canCreate) {
            NewAlbumDialog(
                onCreate = { name -> visit.complete(canCreate()) {
                    creatingAlbum = false
                    controller.createAlbum(name)
                } },
                onDismiss = { visit.complete(modalSessionCurrent() && creatingAlbum) { creatingAlbum = false } },
            )
        }
    }
    if (choosingAlbum) {
        val visit = rememberIosRouteModalVisit()
        val sourceAlbum = remember(visit) { openAlbum }
        val sourceSelection = remember(visit) { selection.toSet() }
        val sourceScope = remember(visit) { browseSearchScope(destination, openAlbum, openTag,
            favoritesOnly, trashOpen, quarantineOpen, recentlyAdded) }
        fun scopeCurrent(): Boolean = sourceScope == browseSearchScope(destination, openAlbum, openTag,
            favoritesOnly, trashOpen, quarantineOpen, recentlyAdded)
        val objectIds = remember(visit) { organizingIds.map { it.copyOf() } }
        val move = remember(visit) { movingSelection }
        fun canPlace(): Boolean = modalSessionCurrent() && choosingAlbum &&
            controller.activeOperation.value == null && scopeCurrent() && selection == sourceSelection &&
            openAlbum?.id == sourceAlbum?.id && movingSelection == move
        val clearSelection: () -> Unit = {
            if (modalSessionCurrent() && selection == sourceSelection) selection = emptySet()
        }
        CompositionLocalProvider(LocalPrivateModalGuard provides ::canPlace) {
            AlbumPickerDialog(
                albums = albums,
                currentAlbum = sourceAlbum,
                move = move,
                onChoose = { album -> visit.complete(canPlace()) {
                    choosingAlbum = false
                    controller.placeObjectsInAlbum(album.albumId, objectIds, sourceAlbum?.albumId, move, onSuccess = clearSelection)
                } },
                onCreate = { name, parent -> visit.complete(canPlace()) {
                    choosingAlbum = false
                    controller.createAlbumWithObjects(name, parent?.albumId, objectIds, sourceAlbum?.albumId, move, clearSelection)
                } },
                onDismiss = { visit.complete(modalSessionCurrent() && choosingAlbum) { choosingAlbum = false } },
            )
        }
    }
    if (choosingTag) {
        val visit = rememberIosRouteModalVisit()
        val sourceSelection = remember(visit) { selection.toSet() }
        val sourceScope = remember(visit) { browseSearchScope(destination, openAlbum, openTag,
            favoritesOnly, trashOpen, quarantineOpen, recentlyAdded) }
        fun scopeCurrent(): Boolean = sourceScope == browseSearchScope(destination, openAlbum, openTag,
            favoritesOnly, trashOpen, quarantineOpen, recentlyAdded)
        val objectIds = remember(visit) { taggingIds.map { it.copyOf() } }
        val sourceAlbumId = remember(visit) { openAlbum?.id }
        fun canTag(): Boolean = modalSessionCurrent() && choosingTag &&
            controller.activeOperation.value == null && scopeCurrent() && selection == sourceSelection && openAlbum?.id == sourceAlbumId
        val clearSelection: () -> Unit = {
            if (modalSessionCurrent() && selection == sourceSelection) selection = emptySet()
        }
        CompositionLocalProvider(LocalPrivateModalGuard provides ::canTag) {
            TagPickerDialog(
                tags = tags,
                onAdd = { tag -> visit.complete(canTag()) {
                    choosingTag = false
                    controller.setTagForAll(tag.tagId, objectIds, true, clearSelection)
                } },
                onRemove = { tag -> visit.complete(canTag()) {
                    choosingTag = false
                    controller.setTagForAll(tag.tagId, objectIds, false, clearSelection)
                } },
                onCreate = { name -> visit.complete(canTag()) {
                    choosingTag = false
                    controller.createTagWithObjects(name, objectIds, clearSelection)
                } },
                onDismiss = { visit.complete(modalSessionCurrent() && choosingTag) { choosingTag = false } },
            )
        }
    }
    if (managingTags) {
        TagBrowserDialog(tags = tags,
            onOpen = { tag ->
                managingTags = false
                selection = emptySet()
                openTag = tag
                terms = ""
                favoritesOnly = false
                trashOpen = false
                quarantineOpen = false
                recentlyAdded = false
                destination = VaultDestination.LIBRARY
            },
            onCreate = controller::createTag,
            onRename = { tag, name -> controller.renameTag(tag.tagId, name) },
            onDelete = { tag -> controller.deleteTag(tag.tagId) {
                if (openTag?.id == tag.id) openTag = null
            } },
            onDismiss = { managingTags = false },
        )
    }
    if (confirmingDelete) {
        DeleteSelectionDialog(
            count = selection.size,
            permanent = trashOpen,
            onDelete = {
                confirmingDelete = false
                val ids = selectedObjects(page, selection)
                if (trashOpen) controller.permanentlyDeleteAll(ids) { selection = emptySet() }
                else controller.deleteAll(ids) { selection = emptySet() }
            },
            onDismiss = { confirmingDelete = false },
        )
    }
    if (confirmingEmptyTrash) {
        DeleteSelectionDialog(count = 0, permanent = true, emptyTrash = true,
            onDelete = { confirmingEmptyTrash = false; controller.emptyTrash { selection = emptySet() } },
            onDismiss = { confirmingEmptyTrash = false })
    }
    val importFiles: () -> Unit = {
        val present = IosDocumentPicker.present
        if (present == null) {
            controller.report("This build cannot open the document picker.")
        } else {
            val albumId = openAlbum?.albumId
            documentPickerPending = true
            controller.beginHostActivity()
            present { count, load, releaseSelection ->
                val current = controller.vaultState.value as? VaultState.Unlocked
                val currentSession = current?.generation == generation
                val accepted = documentPickerPending && currentSession
                if (documentPickerPending) {
                    documentPickerPending = false
                    if (currentSession) controller.endHostActivity()
                }
                if (!accepted || count <= 0) {
                    releaseSelection()
                } else {
                    scope.launch {
                        try {
                            controller.importAll(importer, count, albumId) { index, prepare ->
                                suspendCancellableCoroutine { continuation ->
                                    load(index, prepare) { fd, name, type, size, release ->
                                        val picked = codec.openDocument(fd, name, type, size, release)
                                        continuation.resume(picked) { _, item, _ -> item?.close?.invoke() }
                                    }
                                }
                            }
                        } finally {
                            releaseSelection()
                        }
                    }
                }
            }
        }
    }
    val importMediaFiles: (IosMediaFileSource) -> Unit = { source ->
        val present = when (source) {
            IosMediaFileSource.Audio -> IosAudioPicker.present
            IosMediaFileSource.LivePhoto -> IosLivePhotoFilesPicker.present
            IosMediaFileSource.Media -> IosMediaFilesPicker.present
        }
        if (present == null) {
            controller.report("This build cannot open the media file picker.")
        } else {
            val albumId = openAlbum?.albumId
            documentPickerPending = true
            controller.beginHostActivity()
            present { count, load, releaseSelection ->
                val currentSession = (controller.vaultState.value as? VaultState.Unlocked)?.generation == generation
                val accepted = documentPickerPending && currentSession
                if (documentPickerPending) {
                    documentPickerPending = false
                    if (currentSession) controller.endHostActivity()
                }
                if (!accepted || count <= 0) {
                    releaseSelection()
                } else {
                    scope.launch {
                        try {
                            controller.importAll(importer, count, albumId) { index, prepare ->
                                suspendCancellableCoroutine { continuation ->
                                    load(index, prepare) { fd, name, type, size, path, release ->
                                        try {
                                            val picked = path?.let {
                                                codec.openMediaDocument(NSURL.fileURLWithPath(it), fd, name, type, size, release)
                                            }
                                            if (path == null) release()
                                            continuation.resume(picked) { _, item, _ -> item?.close?.invoke() }
                                        } catch (failure: Exception) {
                                            release()
                                            continuation.resumeWith(Result.failure(failure))
                                        }
                                    }
                                }
                            }
                        } finally {
                            releaseSelection()
                        }
                    }
                }
            }
        }
    }
    val importMedia: (Boolean) -> Unit = { fullLivePhoto ->
        val present = if (fullLivePhoto) IosLivePhotoPicker.present else IosMediaPicker.present
        if (present == null) {
            controller.report("This build cannot open the photo picker.")
        } else {
            val albumId = openAlbum?.albumId
            controller.beginHostActivity()
            present { count, load, review, canDeleteOriginal ->
                controller.endHostActivity()
                if (count > 0) {
                    scope.launch {
                        val outcomes = controller.importAll(importer, count, albumId) { index, prepare ->
                            // One item is fetched and copied at a
                            // time, and its copy is deleted when
                            // its import closes it, so at most one
                            // plaintext copy exists, `IOS.md` §15.2.
                            val (path, name) = withContext(Dispatchers.Main) {
                                suspendCancellableCoroutine { continuation ->
                                    load(index, prepare) { path, name ->
                                        continuation.resume(path to name) { _, _, _ ->
                                            path?.let(::discardPickedCopy)
                                        }
                                    }
                                }
                            }
                            path?.let { copy ->
                                val media = codec.open(NSURL.fileURLWithPath(copy), name)
                                if (media == null) discardPickedCopy(copy)
                                media?.copy(close = {
                                    media.close()
                                    discardPickedCopy(copy)
                                })
                            }
                        }
                        val imported = importedOriginals(List(count) { it }, outcomes)
                        val deletable = imported.filter(canDeleteOriginal)
                        if ((controller.vaultState.value as? VaultState.Unlocked)?.generation == generation) {
                            if (!fullLivePhoto && imported.size > deletable.size) {
                                val summary = controller.notice.value?.text.orEmpty()
                                controller.report("$summary Some Photos originals may contain additional media or edits. " +
                                    "Keep them in Photos; Chur has not verified a complete copy.")
                            }
                            if (deletable.isNotEmpty()) {
                                originals = PickedOriginals(deletable.size) { done -> review(deletable, done) }
                            }
                        }
                    }
                }
            }
        }
    }
    if (choosingImportSource) {
        PrivateAlertDialog(
            onDismissRequest = { choosingImportSource = false },
            title = { Text("Import") },
            text = {
                Column {
                    TextButton(onClick = { choosingImportSource = false; importMedia(false) }, modifier = Modifier.fillMaxWidth()) { Text("Photos and videos") }
                    TextButton(onClick = { choosingImportSource = false; importMedia(true) }, modifier = Modifier.fillMaxWidth()) { Text("Full Live Photos (Photos access)") }
                    TextButton(onClick = { choosingImportSource = false; importMediaFiles(IosMediaFileSource.Media) }, modifier = Modifier.fillMaxWidth()) { Text("Media files") }
                    TextButton(onClick = { choosingImportSource = false; importMediaFiles(IosMediaFileSource.Audio) }, modifier = Modifier.fillMaxWidth()) { Text("Audio files") }
                    TextButton(onClick = { choosingImportSource = false; importMediaFiles(IosMediaFileSource.LivePhoto) }, modifier = Modifier.fillMaxWidth()) { Text("Live Photo packages") }
                    TextButton(onClick = { choosingImportSource = false; importFiles() }, modifier = Modifier.fillMaxWidth()) { Text("Documents and files") }
                    TextButton(onClick = { choosingImportSource = false; choosingArchiveImport = true }, modifier = Modifier.fillMaxWidth()) { Text("Encrypted archive") }
                }
            },
            confirmButton = { TextButton(onClick = { choosingImportSource = false }) { Text("Cancel") } },
        )
    }
    exportingAlbum?.let { album ->
        AlbumExportDialog(
            album = album,
            onConfirm = {
                exportingAlbum = null
                val present = IosAlbumExportPicker.present
                if (present == null) {
                    controller.report("This build cannot open the folder picker.")
                } else {
                    controller.beginHostActivity()
                    albumPickerPending = true
                    present { token ->
                        val current = controller.vaultState.value as? VaultState.Unlocked
                        val currentSession = current?.generation == generation
                        val accepted = albumPickerPending && currentSession
                        if (albumPickerPending) {
                            albumPickerPending = false
                            if (currentSession) controller.endHostActivity()
                        }
                        if (token != null) {
                            if (accepted && controller.activeOperation.value == null) {
                                controller.exportAlbum(album.albumId, token)
                            } else {
                                IosAlbumExportPicker.discard?.invoke(token)
                            }
                        }
                    }
                }
            },
            onDismiss = { exportingAlbum = null },
        )
    }
    if (choosingExport) {
        val visit = rememberIosRouteModalVisit()
        val sourceSelection = remember(visit) { selection.toSet() }
        val sourceScope = remember(visit) { browseSearchScope(destination, openAlbum, openTag,
            favoritesOnly, trashOpen, quarantineOpen, recentlyAdded) }
        val selected = remember(visit) { page.objects.filter { it.id in sourceSelection } }
        fun exportCurrent(): Boolean = modalSessionCurrent() && choosingExport &&
            controller.activeOperation.value == null && selection == sourceSelection &&
            sourceScope == browseSearchScope(destination, openAlbum, openTag,
                favoritesOnly, trashOpen, quarantineOpen, recentlyAdded)
        CompositionLocalProvider(LocalPrivateModalGuard provides ::exportCurrent) {
            ExportOptionsDialog(
                media = selected.isNotEmpty() && selected.all { canSaveToPhotos(it.mediaKind) },
                files = true,
                share = true,
                onChoose = { target -> visit.complete(exportCurrent()) {
                    choosingExport = false
                    controller.exportAll(selected.map { it.objectId }, target) {
                        if (modalSessionCurrent() && selection == sourceSelection) selection = emptySet()
                    }
                } },
                onDismiss = { visit.complete(modalSessionCurrent() && choosingExport) { choosingExport = false } },
            )
        }
    }

    choosingArchive?.let { request ->
        SelectiveExportDialog(summary = request.summary, enabled = operation == null,
            onChoose = { password, target ->
                choosingArchive = null
                archiveTransfers.export(request, ArchiveCredential(password), target)
            }, onDismiss = { choosingArchive = null })
    }
    if (choosingArchiveImport) {
        SelectiveImportDialog(enabled = operation == null,
            onChoose = { password ->
                choosingArchiveImport = false
                archiveTransfers.import(ArchiveCredential(password)) {
                    val present = IosBackupPicker.present ?: error("the file picker is unavailable")
                    present(archiveTransfers::importedFile)
                }
            }, onDismiss = { choosingArchiveImport = false })
    }

    if (showingPrivateNotes) {
        SideEffect {
            scenes.activate(null)
            nativeChrome.suspendNavigation()
            nativeChrome.controller.view.endEditing(true)
            nativeChrome.presentationController.view.hidden = true
            nativeChrome.presentationController.view.accessibilityElementsHidden = true
            nativeChrome.controller.view.hidden = true
            nativeChrome.controller.view.accessibilityElementsHidden = true
            scenes.viewerChrome?.invoke(null)
        }
        PrivateNotesRoute(
            vault = controller.vault, generation = generation,
            lockOwner = controller,
            onClose = { focusManager.clearFocus(); showingPrivateNotes = false; initialCreateRequest = null },
            onLock = { controller.lock() }, onPanic = controller::panic,
            onTouch = { controller.recordPrivateNoteActivity(generation) },
            onImportActivity = { active ->
                if ((controller.vaultState.value as? VaultState.Unlocked)?.generation == generation) {
                    if (active) controller.beginHostActivity() else controller.endHostActivity()
                }
            },
            onExport = { choosingPrivateNoteExport = PrivateNoteExportRequest.from(it, generation) },
            onAttachmentExport = { note, attachment -> choosingPrivateNoteExport = PrivateNoteExportRequest.fromAttachment(note, attachment, generation) },
            systemBack = { _, _ -> }, operation = operation,
            onCancelOperation = controller::cancelActiveOperation,
            notice = notice, onNoticeShown = controller::consume,
            onEncryptedExport = { choosingArchive = SelectiveExportRequest(generation, notes = it) },
            initialCreateRequest = initialCreateRequest,
            onNavigationBusyChange = { privateNotesBusy = it },
        )
        choosingPrivateNoteExport?.let { request ->
            ExportOptionsDialog(media = false, files = true, share = true,
                presentation = PrivateModalPresentation.Dialog,
                onChoose = { target ->
                    choosingPrivateNoteExport = null
                    controller.exportPrivateNote(request, target)
                }, onDismiss = { choosingPrivateNoteExport = null })
        }
        return
    }

    // Query registration clears the old page synchronously. Do not publish a
    // destination with another screen's page while its load effect is pending.
    val currentPage = if (loadedLocation == browseLocation) controller.page.value
        else ObjectPage(emptyList(), 0, 0, null)
    val shellState = VaultUiState(
        destination = destination,
        tiles = currentPage.objects.map { projection ->
            LibraryTile(
                projection = projection,
                thumbnail = thumbnails[projection.id],
                selected = projection.id in selection,
                thumbnailConcealed = thumbnailRendition(projection.mediaKind, thumbnailsConcealed) ==
                    ThumbnailRendition.Mosaic,
            )
        },
        albums = albums,
        searchTerms = terms,
        searchContext = browseLocation.scope,
        contentIndex = contentIndex,
        slots = slots,
        reencryptionNotice = reencryptionNotice,
        openAlbum = openAlbum,
        libraryScopeTitle = if (recentlyAdded) "Recently added" else if (trashOpen) "Trash" else if (quarantineOpen) "Quarantine" else openTag?.name ?: if (favoritesOnly) "Favorites" else null,
        trashOpen = trashOpen,
        recentlyAdded = recentlyAdded,
        mediaView = mediaView,
        thumbnailsConcealed = thumbnailsConcealed,
        albumView = albumView,
        sort = if (openAlbum != null) albumSort else if (recentlyAdded) QuerySort.IMPORT_DESC else mediaSort,
        kinds = mediaKinds,
        albumOrder = albumOrder,
        albumFilter = albumFilter,
        // The viewer is drawn over the shell here, so the shell leaves
        // the notice to it while it is open rather than show it twice.
        notice = notice.takeIf { viewing == null },
        operation = operation,
        selectedCount = selection.size,
        selectionIds = selection,
        canLoadMore = currentPage.nextCursor != null,
        deviceSlotAvailable = controller.deviceUnlockAvailable,
        deviceSlotStrict = deviceSlotStrict,
        appLockEnabled = appLockEnabled,
        autoLock = autoLock,
        sync = syncStatus,
        devicePairing = vaultDevicePairing,
    )
    // Callbacks can outlive this rendered selection until Compose publishes
    // the next frame. Never let that interval retarget an old action.
    fun currentSearchScope() = browseSearchScope(destination, openAlbum, openTag,
        favoritesOnly, trashOpen, quarantineOpen, recentlyAdded)
    val renderedSearchScope = currentSearchScope()
    val renderedSearchTerms = terms
    fun renderedMediaIsCurrent(): Boolean = terms == renderedSearchTerms &&
        currentSearchScope() == renderedSearchScope && controller.route.value == AppRoute.Vault &&
        (controller.vaultState.value as? VaultState.Unlocked)?.generation == generation
    // Read the route's mutable flags when an event arrives, before UIKit or
    // child NavigationBusyEffect has received the next Compose frame.
    fun routeModalCommandsBlocked(): Boolean = (viewing != null && !nativeChrome.dualPane) || viewerNavigationBusy || showingPrivateNotes ||
        controller.activeOperation.value != null ||
        choosingArchive != null || choosingArchiveImport || choosingPrivateNoteExport != null ||
        exportingAlbum != null || albumPickerPending || documentPickerPending || choosingImportSource ||
        creatingAlbum || choosingAlbum || choosingTag || managingTags || confirmingDelete ||
        confirmingEmptyTrash || choosingExport || originals != null || incomingShare != null
    fun searchCommandsBlocked(): Boolean = selection.isNotEmpty() || shellNavigationBusy ||
        privateNotesBusy || routeModalCommandsBlocked()
    fun ordinaryShellAction(block: () -> Unit) {
        if (!routeModalCommandsBlocked() && controller.route.value == AppRoute.Vault &&
            (controller.vaultState.value as? VaultState.Unlocked)?.generation == generation
        ) {
            // Browse commands leave the current detail before changing its query or opening a modal.
            viewing = null
            block()
        }
    }
    fun updateSearch(value: String) {
        if (!trashOpen && currentSearchScope() == renderedSearchScope &&
            (destination == VaultDestination.LIBRARY || destination == VaultDestination.SEARCH || openAlbum != null) &&
            !searchCommandsBlocked() && controller.route.value == AppRoute.Vault &&
            (controller.vaultState.value as? VaultState.Unlocked)?.generation == generation
        ) {
            viewing = null
            terms = value
        }
    }
    val renderedSelection = selection.toSet()
    fun selectionAction(block: () -> Unit) {
        if (renderedSelection.isNotEmpty() && selection == renderedSelection &&
            !routeModalCommandsBlocked() && controller.route.value == AppRoute.Vault &&
            (controller.vaultState.value as? VaultState.Unlocked)?.generation == generation
        ) block()
    }
    val shellActions = VaultActions(
        publicSettingsContent = { dev.po4yka.chur.app.publicshell.DiscreetSettings(controller) },
        onThumbnailsConcealedChange = { thumbnailsConcealed = it },
        onDestination = { target -> ordinaryShellAction {
            terms = ""
            searchFocusRequest = null
            openAlbum = null
            openTag = null
            favoritesOnly = false
            trashOpen = false
            quarantineOpen = false
            recentlyAdded = false
            selection = emptySet()
            destination = target
        } },
        // Opening is opening. Before the viewer existed on this host it
        // toggled selection, which made a video unreachable and a tap on a
        // photograph mean two things.
        onOpen = open@{ projection ->
            // A queued tile event cannot open or select a result from the previous query.
            if (!renderedMediaIsCurrent() || routeModalCommandsBlocked()) return@open
            if (selection.isEmpty()) {
                controller.report(null)
                // A text field of the shell left focused would keep
                // the keyboard open over the viewer, which is edge to
                // edge (`ChurApp`), and take what is typed under it.
                focusManager.clearFocus()
                searchFocusRequest = null
                viewerVisit++
                viewing = projection
            } else {
                selection = selection.toggle(projection.id)
            }
        },
        onToggleSelection = { projection ->
            if (renderedMediaIsCurrent() && !routeModalCommandsBlocked()) { viewing = null; selection = selection.toggle(projection.id) }
        },
        onOpenPrivateNotes = { ordinaryShellAction { terms = ""; focusManager.clearFocus(); searchFocusRequest = null; selection = emptySet(); recentlyAdded = false; initialCreateRequest = null; showingPrivateNotes = true } },
        onImport = { ordinaryShellAction { choosingImportSource = true } },
        onSearch = ::updateSearch,
        onIndexContent = { controller.indexContent() },
        onRebuildContentIndex = { controller.indexContent(rebuild = true) },
        onCancelContentIndex = controller::cancelContentIndex,
        onClearContentIndex = controller::clearContentIndex,
        onExportAlbum = { album -> ordinaryShellAction { exportingAlbum = album } },
        onEncryptedExportAlbum = { album -> ordinaryShellAction { choosingArchive = SelectiveExportRequest(generation, albumIds = listOf(album.albumId)) } },
        onOpenAlbum = { album -> ordinaryShellAction { navigateAlbum(album) } },
        onCloseAlbum = { ordinaryShellAction { navigateAlbum(albumParent(albums, openAlbum?.id)) } },
        onAlbumRoot = { ordinaryShellAction { navigateAlbum(null) } },
        onCreateAlbum = { ordinaryShellAction { creatingAlbum = true } },
        onMediaViewChange = { view -> ordinaryShellAction { mediaView = view } },
        onAlbumViewChange = { view -> ordinaryShellAction { albumView = view } },
        onSortChange = { sort -> ordinaryShellAction {
            if (openAlbum != null) albumSort = sort else if (!recentlyAdded) mediaSort = sort
            selection = emptySet()
        } },
        onKindsChange = { kinds -> ordinaryShellAction { mediaKinds = kinds; selection = emptySet() } },
        onAlbumOrderChange = { order -> ordinaryShellAction { albumOrder = order } },
        onAlbumFilterChange = { filter -> ordinaryShellAction { albumFilter = filter } },
        onShowRecentlyAdded = { ordinaryShellAction {
            terms = ""
            focusManager.clearFocus()
            openAlbum = null
            openTag = null
            favoritesOnly = false
            trashOpen = false
            quarantineOpen = false
            selection = emptySet()
            destination = VaultDestination.LIBRARY
            recentlyAdded = true
        } },
        onShowAllMedia = { ordinaryShellAction { terms = ""; recentlyAdded = false; openTag = null; favoritesOnly = false; trashOpen = false; quarantineOpen = false; selection = emptySet() } },
        onShowFavorites = { ordinaryShellAction { terms = ""; recentlyAdded = false; openTag = null; favoritesOnly = true; trashOpen = false; quarantineOpen = false; selection = emptySet() } },
        onShowTags = { ordinaryShellAction { controller.loadTags(); managingTags = true } },
        onShowTrash = { ordinaryShellAction { terms = ""; recentlyAdded = false; openTag = null; favoritesOnly = false; trashOpen = true; quarantineOpen = false; selection = emptySet() } },
        onShowQuarantine = { ordinaryShellAction { terms = ""; recentlyAdded = false; openTag = null; favoritesOnly = false; trashOpen = false; quarantineOpen = true; selection = emptySet() } },
        onEmptyTrash = { ordinaryShellAction { confirmingEmptyTrash = true } },
        onRestoreTrash = { controller.restoreTrash { selection = emptySet() } },
        onRenameAlbum = { album, name -> controller.renameAlbum(album.albumId, name) },
        onDeleteAlbum = { album ->
            controller.deleteAlbum(album.albumId) {
                if (openAlbum?.id == album.id) openAlbum = null
            }
        },
        onMoveAlbum = { album, parent, before ->
            controller.moveAlbum(album.albumId, parent?.albumId, before?.albumId)
        },
        onMoveAlbumMember = { objectToMove, before ->
            if (terms.isBlank() && currentSearchScope() == renderedSearchScope &&
                !searchCommandsBlocked() && controller.route.value == AppRoute.Vault &&
                (controller.vaultState.value as? VaultState.Unlocked)?.generation == generation
            ) openAlbum?.let { album ->
                controller.moveAlbumMember(album.albumId, objectToMove.objectId, before?.objectId)
            }
        },
        onDropMediaIntoAlbum = { objects, target -> ordinaryShellAction {
            if (target != null) {
                controller.placeObjectsInAlbum(target.albumId, objects.map { it.objectId },
                    openAlbum?.albumId, openAlbum != null) { selection = emptySet() }
            } else {
                controller.loadAlbums()
                organizingIds = objects.map { it.objectId }
                movingSelection = openAlbum != null
                choosingAlbum = true
            }
        } },
        onLoadMore = controller::loadNextPage,
        onVisibleMediaChanged = { visibleMediaIds = it },
        onLock = { controller.lock() },
        onPanic = { controller.panic() },
        onDeleteDamagedFiles = { controller.deleteDamagedFiles() },
        onVerifyAll = { controller.verifyEverything() },
        onAddRecoverySlot = controller::addRecoverySlot,
        onChangePassword = controller::changePassword,
        onToggleAppLock = controller::toggleAppLock,
        onSetAutoLock = controller::setAutoLock,
        onAddDeviceSlot = controller::enrollAppleDeviceSlot,
        onToggleDeviceSlotPolicy = controller::toggleDeviceSlotPolicy,
        onListenPeer = controller::listenForPeer,
        onConnectPeer = controller::connectToPeer,
        onStopPeer = controller::stopPeerSync,
        onPrepareDevicePairing = { controller.prepareDevicePairing() },
        onInspectDevicePairing = { controller.inspectDevicePairing(it) },
        onApproveDevicePairing = { request, fingerprint -> controller.approveDevicePairing(request, fingerprint) },
        onSavePairingApproval = pairingFiles.save,
        onOpenPairingApproval = pairingFiles.open,
        onLoadPairedDevices = { controller.loadPairedDevices() },
        onRevokePairedDevice = { controller.revokePairedDevice(it) },
        onCreateBackup = controller::createBackup,
        onEncryptExternalFiles = controller::openExternalArchive,
        onImportArchive = { choosingArchiveImport = true },
        onRestoreArchive = controller::restoreArchiveAsSeparateVault,
        onCreateSecondIdentity = controller::createSecondIdentity,
        onSelectLoadedItems = { selectionAction { selection = loadedObjectSelection(page) } },
        onClearSelection = { selectionAction { selection = emptySet() } },
        onExportSelection = { selectionAction { choosingExport = true } },
        onEncryptedExportSelection = {
            selectionAction {
                if (renderedSelection.size > 1000) controller.report("Select at most 1000 items for one encrypted archive.")
                else choosingArchive = SelectiveExportRequest(generation, objectIds = renderedSelection.sorted().map { it.fromHex() })
            }
        },
        onAddSelectionToAlbum = {
            selectionAction {
                controller.loadAlbums()
                organizingIds = renderedSelection.sorted().map { it.fromHex() }
                movingSelection = false
                choosingAlbum = true
            }
        },
        onMoveSelectionToAlbum = {
            selectionAction {
                controller.loadAlbums()
                organizingIds = renderedSelection.sorted().map { it.fromHex() }
                movingSelection = true
                choosingAlbum = true
            }
        },
        onTagSelection = {
            selectionAction {
                controller.loadTags()
                taggingIds = renderedSelection.sorted().map { it.fromHex() }
                choosingTag = true
            }
        },
        onSetSelectionFavorite = { favorite ->
            selectionAction {
                controller.setFavoritesForAll(renderedSelection.sorted().map { it.fromHex() }, favorite) {
                    selection = emptySet()
                }
            }
        },
        onRemoveSelectionFromAlbum = {
            selectionAction {
                openAlbum?.let { album ->
                    controller.removeAllFromAlbum(album.albumId, selectedObjects(page, renderedSelection)) {
                        selection = emptySet()
                    }
                }
            }
        },
        onDeleteSelection = { selectionAction { confirmingDelete = true } },
        onRestoreSelection = {
            selectionAction {
                controller.restoreAll(selectedObjects(page, renderedSelection)) {
                    selection = emptySet()
                }
            }
        },
        onCancelOperation = controller::cancelActiveOperation,
        onNoticeShown = controller::consume,
        // The controller brackets iOS's local-network alert during a direct
        // peer connection so the alert does not prematurely lock the vault.
    )
    val albumScreens = openAlbum?.let { albumPath(albums, it.id) }.orEmpty()
        .map { IosVaultScreen.Album(it.id) }
    val shellScreen = albumScreens.lastOrNull() ?: IosVaultScreen.Root(destination)
    val shellSearchFocusRequest = searchFocusRequest
    val projection = viewing
    val viewerScreen = projection?.let { IosVaultScreen.Viewer(viewerVisit) }
    val viewerPage = projection?.let { viewerPages(currentPage.objects, it) }.orEmpty()
    val screenStack = listOf(IosVaultScreen.Root(destination)) + albumScreens + listOfNotNull(viewerScreen)
    // Read child-owned busy state during composition. A read made only inside
    // SideEffect is not observed by this composition, so opening Viewer Info
    // would otherwise leave UIKit Back and toolbar commands enabled.
    val nativeNavigationBusy = modalNavigationBusy || shellNavigationBusy || viewerNavigationBusy
    SideEffect {
        if (controller.route.value != AppRoute.Vault ||
            (controller.vaultState.value as? VaultState.Unlocked)?.generation != generation
        ) return@SideEffect
        if (loadedLocation != browseLocation) {
            scenes.activate(null)
            nativeChrome.suspendNavigation(preserveSearch =
                browseLocation.isTextChangeFrom(loadedLocation) &&
                    (destination == VaultDestination.LIBRARY || openAlbum != null) && !searchCommandsBlocked())
            return@SideEffect
        }
        scenes.publish(shellScreen, scrollScope = browseLocation, scrollAllowed = {
            renderedMediaIsCurrent() && !searchCommandsBlocked() &&
                BrowseQueryLocation(currentSearchScope(), terms, mediaSort, albumSort, mediaKinds) == browseLocation
        }) { scene ->
            VaultShell(
                state = shellState,
                actions = shellActions.forScene(scene),
                searchFocusRequest = shellSearchFocusRequest,
                onNavigationBusyChange = { if (scene.canObserve()) shellNavigationBusy = it },
                browseSearchInPlatformChrome = true,
                systemBack = { _, _ -> },
            )
        }
        if (viewerScreen != null && projection != null) {
            scenes.publish(viewerScreen) { scene ->
                IosViewerRoute(
                    controller = controller, operation = operation, notice = notice,
                    cache = cache, generation = generation, projection = projection,
                    viewerToken = viewerScreen.token,
                    isCurrentItem = { viewing?.id == projection.id },
                    pages = viewerPage, thumbnails = viewerThumbnails,
                    canLoadMore = currentPage.nextCursor != null, trashOpen = shellState.trashOpen,
                    onSettled = { if (scene.canAct()) viewing = it },
                    onBack = { if (scene.canAct()) viewing = null },
                    onDeleted = { if (scene.canObserve()) viewing = null },
                    onChromeChanged = { if (scene.canObserve()) scenes.viewerChrome?.invoke(it) },
                    onNavigationBusyChange = { if (scene.canObserve()) viewerNavigationBusy = it },
                )
            }
        } else {
            viewerNavigationBusy = false
            scenes.viewerChrome?.invoke(null)
        }
        nativeChrome.onVisibleScreens = scenes::activateAll
        nativeChrome.configureScreens(factory = { screen ->
            scenes.createController(screen).also { content ->
                content.navigationItem.title = when (screen) {
                    is IosVaultScreen.Root -> screen.destination.label
                    is IosVaultScreen.Album -> albums.firstOrNull { it.id == screen.id }?.name
                    is IosVaultScreen.Viewer -> null
                }
            }
        }, onPop = { target ->
            if (controller.route.value == AppRoute.Vault &&
                (controller.vaultState.value as? VaultState.Unlocked)?.generation == generation
            ) {
                if (viewing != null && target == shellScreen) viewing = null
                else {
                    // A primary-pane Back changes the browse query just like a tile navigation.
                    viewing = null
                    when (target) {
                        is IosVaultScreen.Album -> navigateAlbum(albums.firstOrNull { it.id == target.id })
                        is IosVaultScreen.Root -> if (target.destination == VaultDestination.ALBUMS)
                            navigateAlbum(null) else shellActions.onDestination(target.destination)
                        is IosVaultScreen.Viewer -> Unit
                    }
                }
            }
        }, onRetire = scenes::retire)
        nativeChrome.reconcile(generation, screenStack, destination)
        nativeChrome.update(shellState, shellActions, colors.accent,
            navigationBusy = nativeNavigationBusy,
            covered = modalNavigationBusy)
    }

}

/**
 * The viewer over one object, with the platform player when it has one.
 *
 * `MEDIA_PIPELINE.md` §8 has the timeline read derivatives and the viewer
 * decrypt more only for detailed viewing, which is why the preview is loaded
 * here rather than in the grid, and §9 has a video ask for ranges rather than
 * for a decoded file.
 *
 * A swipe moves through [pages], `DESIGN.md` §13.1, and this route follows
 * it: [projection] is the item on screen, and its detail, its still, its
 * player and its dialogs are keyed to it, so they are made once, for that
 * item, and not for each page a swipe passes.
 */
@Composable
private fun IosViewerRoute(
    controller: ChurController,
    operation: ActiveOperation?,
    notice: Notice?,
    cache: ThumbnailCache,
    generation: Long,
    projection: ObjectProjection,
    viewerToken: Long,
    isCurrentItem: () -> Boolean,
    pages: List<ObjectProjection>,
    thumbnails: Map<String, ImageBitmap>,
    canLoadMore: Boolean,
    onSettled: (ObjectProjection) -> Unit,
    trashOpen: Boolean,
    onBack: () -> Unit,
    onDeleted: () -> Unit,
    onChromeChanged: (Boolean?) -> Unit,
    onNavigationBusyChange: (Boolean) -> Unit,
) {
    val scene = checkNotNull(LocalIosVaultScene.current)
    val nativeChrome = checkNotNull(LocalIosVaultChrome.current)
    val colors = LocalChurColors.current
    // A scene survives paging. A never-reused identity also rejects an old A
    // callback after paging A → B → A; the parent predicate closes the gap
    // between a settled page changing and this composition being refreshed.
    val itemVisit = remember(projection.id, generation) { Any() }
    val currentItemVisit by rememberUpdatedState(itemVisit)
    fun canAct(): Boolean = scene.canAct() && isCurrentItem() && currentItemVisit === itemVisit
    fun canObserve(): Boolean = scene.canObserve() && isCurrentItem() && currentItemVisit === itemVisit
    val currentChromeChanged by rememberUpdatedState(onChromeChanged)
    val currentNavigationBusyChanged by rememberUpdatedState(onNavigationBusyChange)
    var detail by remember(projection.id) { mutableStateOf<ObjectDetail?>(null) }
    var favorite by remember(projection.id) { mutableStateOf(projection.favorite) }
    val tags by controller.tags.collectAsState()
    var choosingTags by remember(projection.id) { mutableStateOf(false) }
    val viewerScope = rememberCoroutineScope()
    var livePlayback by remember(projection.id, generation) { mutableStateOf<dev.po4yka.chur.app.vault.PlaybackSource?>(null) }
    var preview by remember(projection.id, generation) { mutableStateOf<ImageBitmap?>(null) }
    var stillState by remember(projection.id, generation) { mutableStateOf(ViewerStillState.Loading) }
    var showDetail by remember(projection.id) { mutableStateOf(false) }
    var waveform by remember(projection.id) { mutableStateOf<ByteArray?>(null) }
    var confirmingDelete by remember(projection.id) { mutableStateOf(false) }
    var choosingExport by remember(projection.id) { mutableStateOf(false) }
    fun canInteract(): Boolean = canAct() && !showDetail && !choosingTags && !choosingExport &&
        !confirmingDelete && controller.activeOperation.value == null
    val chrome = remember { ViewerChrome() }
    val chromePinned = projection.mediaKind == 4 || showDetail || choosingTags || choosingExport || confirmingDelete || operation != null
    val chromeVisible = chrome.visible(chromePinned)
    // §6.2 and §13.1: the status bar is light over the black canvas and goes
    // with the chrome, and it gets the theme's style back when the viewer goes.
    val navigationBusy = showDetail || choosingTags || choosingExport || confirmingDelete || operation != null
    LaunchedEffect(scene, scene.active, chromeVisible) {
        if (canObserve()) currentChromeChanged(chromeVisible)
    }
    LaunchedEffect(scene, scene.active, navigationBusy) {
        if (canObserve()) currentNavigationBusyChanged(navigationBusy)
    }
    DisposableEffect(scene) {
        onDispose {
            nativeChrome.clearViewer(generation, viewerToken)
            // A retired outgoing scene must not reset a newer Viewer's status.
            if (canObserve()) {
                currentChromeChanged(null)
                currentNavigationBusyChanged(false)
            }
        }
    }

    var zoomedPhoto by remember(projection.id, generation) { mutableStateOf(false) }
    val animation = rememberViewerAnimation(controller.vault, projection, generation, detail?.contentType)
    LaunchedEffect(projection.id, generation, zoomedPhoto, scene.active) {
        if (!canObserve()) return@LaunchedEffect
        // `IOS.md` §18: a preview before full-resolution ranges. A retired
        // native scene must never accept a late decrypted result.
        val cached = cache.load(controller.vault, generation, projection.objectId, projection.id)
        if (!canObserve()) return@LaunchedEffect
        preview = cached
        if (projection.mediaKind == MEDIA_CLASS_AUDIO) {
            val loaded = controller.derivativeOf(projection.objectId, StreamKind.AUDIO_WAVEFORM)
            if (!canObserve()) return@LaunchedEffect
            waveform = loaded
        }
        val loadedDetail = controller.detailOf(projection.objectId)
        if (!canObserve()) return@LaunchedEffect
        detail = loadedDetail
        if (loadedDetail?.contentType == dev.po4yka.chur.imports.LivePhotoBundle.CONTENT_TYPE) {
            val loaded = dev.po4yka.chur.app.vault.livePhotoPlaybackFor(
                controller.vault, projection.objectId,
                onVerify = { if (canAct()) controller.verifyEverything() })
            if (!canObserve()) return@LaunchedEffect
            livePlayback = loaded
        }
        val still = viewerStill(controller.vault, cache, generation, projection,
            highResolution = zoomedPhoto && animation == null)
        if (!canObserve()) return@LaunchedEffect
        still?.let { preview = it }
        stillState = if (preview != null || thumbnails[projection.id] != null) {
            ViewerStillState.Ready
        } else {
            ViewerStillState.Unavailable
        }
    }

    // DESIGN.md §20.3: a quarantined object is never silently retried in a
    // viewer, and CATALOG_SCHEMA_V1.md §5.1 says its container is absent or
    // unreadable. A player would retry the failed lease with no sign to the
    // user, so the viewer opens it without one.
    val playback = if (PresentedState.of(projection) == PresentedState.QUARANTINED) {
        null
    } else {
        livePlayback ?: playbackFor(
            vault = controller.vault,
            objectId = projection.objectId,
            mediaKind = projection.mediaKind,
            detail = detail,
            onVerify = { if (canInteract()) controller.verifyEverything() },
            onExport = { if (canInteract()) choosingExport = true },
        )
    }

    val touch: () -> Unit = { if (canInteract()) chrome.touched() }
    val back: () -> Unit = { if (canInteract()) onBack() }
    val toggleFavorite: () -> Unit = {
        if (canInteract()) {
            val next = !favorite
            controller.setFavorite(projection.objectId, next) { if (canObserve()) favorite = next }
        }
    }
    val editTags: () -> Unit = { if (canInteract()) { controller.loadTags(); choosingTags = true } }
    val export: () -> Unit = { if (canInteract()) choosingExport = true }
    val delete: () -> Unit = { if (canInteract()) confirmingDelete = true }
    val restore: () -> Unit = {
        if (canInteract()) controller.restoreAll(listOf(projection.objectId)) { if (canObserve()) onDeleted() }
    }
    val toggleDetail: () -> Unit = {
        if (canObserve() && !nativeChrome.transitionInFlight && !choosingTags && !choosingExport &&
            !confirmingDelete && controller.activeOperation.value == null
        ) showDetail = !showDetail
    }
    SideEffect {
        if (canObserve()) nativeChrome.updateViewer(
            IosViewerPanelState(
                generation = generation,
                token = viewerToken,
                itemId = projection.id,
                title = when (projection.mediaKind) {
                    MEDIA_CLASS_IMAGE -> "Photo"
                    MEDIA_CLASS_VIDEO -> "Video"
                    MEDIA_CLASS_AUDIO -> "Audio"
                    else -> "File"
                },
                favorite = favorite,
                trashed = trashOpen,
                busy = choosingTags || choosingExport || confirmingDelete || operation != null,
                visible = chromeVisible,
                infoVisible = showDetail,
            ),
            IosViewerPanelActions(
                onBack = back,
                onTouch = touch,
                onFavorite = toggleFavorite,
                onInfo = toggleDetail,
                onExport = export,
                onTags = editTags,
                onDelete = delete,
                onRestore = restore,
            ),
            colors.accent,
        )
    }

    ViewerScreen(
        projection = projection.copy(favorite = favorite),
        pages = pages,
        thumbnails = thumbnails,
        canLoadMore = canLoadMore,
        onLoadMore = { if (canObserve()) controller.loadNextPage() },
        onSettled = { if (canInteract()) onSettled(it) },
        detail = detail,
        preview = preview,
        stillState = stillState,
        onVerifyStill = { if (canInteract()) controller.verifyEverything() },
        onZoomChanged = { if (canInteract()) zoomedPhoto = it },
        animation = animation,
        showDetail = false,
        chromeVisible = chromeVisible,
        onToggleChrome = { if (canInteract()) chrome.toggle(chromePinned) },
        onTouch = touch,
        onBack = back,
        onLock = { if (scene.canEscape()) nativeChrome.lockNow() },
        onPanic = { if (scene.canEscape()) nativeChrome.requestPanic() },
        onToggleFavorite = toggleFavorite,
        onEditTags = editTags,
        onExport = export,
        onDelete = delete,
        trashOpen = trashOpen,
        onRestore = restore,
        onToggleDetail = toggleDetail,
        nativeControls = true,
        player = playback?.let { source ->
            { modifier, controlsPadding ->
                // `DESIGN.md` §13.1 and §13.2: the video opens on its poster,
                // and its controls show and hide with the chrome.
                VaultPlayer(
                    source = source,
                    modifier = modifier,
                    poster = preview,
                    controlsVisible = chromeVisible,
                    controlsPinned = chromePinned,
                    onControlsVisibleChange = { if (canObserve()) chrome.follow(it, chromePinned) },
                    controlsPadding = controlsPadding,
                    touches = chrome.touches,
                )
            }
        },
        document = if (projection.mediaKind == 4) {
            { modifier, contentPadding ->
                VaultDocument(controller.vault, generation, projection, detail, modifier, contentPadding)
            }
        } else null,
        waveform = waveform,
        operation = operation,
        onCancelOperation = { if (canAct()) controller.cancelActiveOperation() },
        notice = notice,
        onNoticeShown = { if (canObserve()) controller.consume(it) },
    )
    if (showDetail) {
        val visit = rememberIosRouteModalVisit()
        fun infoCurrent(): Boolean = canObserve() && showDetail && controller.activeOperation.value == null
        CompositionLocalProvider(LocalPrivateModalGuard provides ::infoCurrent) {
            PrivateAlertDialog(
                presentation = PrivateModalPresentation.Popover,
                anchor = PrivateModalAnchor.Info,
                onDismissRequest = { visit.complete(canObserve() && showDetail) { showDetail = false } },
                title = { Text("Info") },
                text = {
                    val facts = detail
                    if (facts != null) ViewerDetailContent(facts, projection,
                        containerColor = colors.surface, contentColor = colors.ink)
                    else Text("Loading…")
                },
                confirmButton = {},
                dismissButton = { TextButton(onClick = privateModalAction {
                    visit.complete(canObserve() && showDetail) { showDetail = false }
                }) { Text("Close") } },
            )
        }
    }
    if (choosingTags) {
        val visit = rememberIosRouteModalVisit()
        fun tagsCurrent(): Boolean = canObserve() && choosingTags && controller.activeOperation.value == null
        val selected = listOf(projection.objectId)
        val refresh: () -> Unit = {
            if (canObserve()) viewerScope.launch {
                val loaded = controller.detailOf(projection.objectId)
                if (canObserve()) detail = loaded
            }
        }
        CompositionLocalProvider(LocalPrivateModalGuard provides ::tagsCurrent) {
            TagPickerDialog(tags = tags,
                onAdd = { tag -> visit.complete(tagsCurrent()) { choosingTags = false; controller.setTagForAll(tag.tagId, selected, true, refresh) } },
                onRemove = { tag -> visit.complete(tagsCurrent()) { choosingTags = false; controller.setTagForAll(tag.tagId, selected, false, refresh) } },
                onCreate = { name -> visit.complete(tagsCurrent()) { choosingTags = false; controller.createTagWithObjects(name, selected, refresh) } },
                onDismiss = { visit.complete(canObserve() && choosingTags) { choosingTags = false } })
        }
    }
    if (confirmingDelete) {
        DeleteSelectionDialog(
            count = 1,
            permanent = trashOpen,
            onDelete = {
                if (canAct()) {
                    confirmingDelete = false
                    if (trashOpen) controller.permanentlyDeleteAll(listOf(projection.objectId)) { if (canObserve()) onDeleted() }
                    else controller.delete(projection.objectId) { if (canObserve()) onDeleted() }
                }
            },
            onDismiss = { if (canAct()) confirmingDelete = false },
        )
    }
    if (choosingExport) {
        val visit = rememberIosRouteModalVisit()
        fun exportCurrent(): Boolean = canObserve() && choosingExport && controller.activeOperation.value == null
        CompositionLocalProvider(LocalPrivateModalGuard provides ::exportCurrent) {
            ExportOptionsDialog(
                media = canSaveToPhotos(projection.mediaKind) || detail?.contentType == dev.po4yka.chur.imports.LivePhotoBundle.CONTENT_TYPE,
                files = true,
                share = true,
                onChoose = { target -> visit.complete(exportCurrent()) {
                    choosingExport = false
                    controller.export(projection.objectId, target)
                } },
                onDismiss = { visit.complete(canObserve() && choosingExport) { choosingExport = false } },
            )
        }
    }

}

/** The object identifiers the selection names, in the page's order. */
private fun selectedObjects(
    page: ObjectPage,
    selection: Set<String>,
): List<ByteArray> = page.objects.filter { it.id in selection }.map { it.objectId }

private fun Set<String>.toggle(id: String): Set<String> =
    if (id in this) this - id else this + id

/**
 * The photo picker the Xcode host presents, `IOS.md` §15.1.
 *
 * The host answers once, with how many items the user picked, in the order
 * picked, and a way to load each one. A load fetches the item, from iCloud
 * when it is not on the device, and reports the fetch to `prepare`; when
 * `prepare` answers false, the user has cancelled and the host stops the
 * fetch. It then answers with the path of a protected copy in the app's
 * temporary directory and the item's own name, or with no path when there is
 * nothing to import. The copy has a random name, because §12 keeps a file
 * name from telling the filename; the name travels here instead.
 *
 * `review` deletes the originals of the items at the given indices from the
 * photo library, `DESIGN.md` §15.3 and `IOS.md` §15.4: the host asks for
 * read-write access then and not before, and Photos asks the user before it
 * deletes. It answers on the main thread with how many originals it found
 * and how many were deleted. The host keeps the items' Photos identifiers,
 * which §28 keeps out of every log, only as long as Kotlin keeps `review`.
 */
public object IosMediaPicker {
    public var present: (
        (
            answer: (
                count: Int,
                load: (
                    index: Int,
                    prepare: (processed: Long, total: Long) -> Boolean,
                    loaded: (path: String?, name: String?) -> Unit,
                ) -> Unit,
                review: (indices: List<Int>, done: (found: Int, deleted: Int) -> Unit) -> Unit,
                canDeleteOriginal: (index: Int) -> Boolean,
            ) -> Unit,
        ) -> Unit
    )? = null
}

/** Full resource capture uses the same protected-file bridge and never offers source deletion. */
public object IosLivePhotoPicker {
    public var present: (
        (
            answer: (
                count: Int,
                load: (
                    index: Int,
                    prepare: (processed: Long, total: Long) -> Boolean,
                    loaded: (path: String?, name: String?) -> Unit,
                ) -> Unit,
                review: (indices: List<Int>, done: (found: Int, deleted: Int) -> Unit) -> Unit,
                canDeleteOriginal: (index: Int) -> Boolean,
            ) -> Unit,
        ) -> Unit
    )? = null
}

/** The originals an import committed, and the host's way to delete them. */
private class PickedOriginals(val count: Int, val delete: (done: (found: Int, deleted: Int) -> Unit) -> Unit)

/** Deletes a copy the photo picker made, and nothing outside the temporary directory. */
private fun discardPickedCopy(path: String) {
    if (path.startsWith(NSTemporaryDirectory())) unlink(path)
}

/**
 * The restore route, `docs/format/BACKUP_FORMAT_V1.md` §8.
 *
 * The host holds a coordinated file descriptor until the restore finishes.
 */
@Composable
private fun IosRestoreRoute(controller: ChurController) {
    val formError by controller.formError.collectAsState()
    val operation by controller.activeOperation.collectAsState()
    var running by remember { mutableStateOf(false) }
    var cancelled by remember { mutableStateOf(false) }
    var pending by remember { mutableStateOf<ArchiveCredential?>(null) }
    var pickerOpen by remember { mutableStateOf(false) }
    DisposableEffect(controller) {
        onDispose {
            pending?.clear(); pending = null
            if (pickerOpen) { pickerOpen = false; controller.endHostActivity() }
        }
    }
    RestoreBackupScreen(
        busy = running, error = formError, cancelled = cancelled, operation = operation,
        onChoose = { password ->
            cancelled = false
            controller.report(null)
            val present = IosBackupPicker.present
            if (present == null) {
                controller.report("This build cannot open the file picker.")
            } else {
                pending?.clear()
                pending = ArchiveCredential(password)
                running = true
                controller.beginHostActivity()
                pickerOpen = true
                try {
                    present { source ->
                        val credential = pending
                        pending = null
                        if (pickerOpen) { pickerOpen = false; controller.endHostActivity() }
                        if (source == null || credential == null) {
                            credential?.clear()
                            source?.close?.invoke()
                            running = false
                        } else {
                            controller.restoreBackup(source.descriptor, credential) { wasCancelled ->
                                source.close()
                                running = false
                                cancelled = wasCancelled
                            }
                        }
                    }
                } catch (_: Exception) {
                    pending?.clear(); pending = null
                    pickerOpen = false; controller.endHostActivity()
                    running = false
                    controller.report("The file picker could not be opened.")
                }
            }
        },
        onBack = { if (!running) controller.goTo(if (controller.vaultState.value is VaultState.NoVault) AppRoute.CreateVault else AppRoute.PublicShell) },
        onCancel = controller::cancelActiveOperation,
    )
}

/** The host delivers a coordinated archive source, or null when the picker is dismissed. */
public object IosBackupPicker {
    public var present: ((answer: (ArchiveSource?) -> Unit) -> Unit)? = null
}

/** The host keeps a selected folder grant and returns one transient opaque token. */
public object IosAlbumExportPicker {
    public var present: ((answer: (String?) -> Unit) -> Unit)? = null
    public var discard: ((token: String) -> Unit)? = null
    public var cancel: (() -> Unit)? = null
}

/** The host retains source grants only until the sequential import closes them. */
public object IosDocumentPicker {
    public var present: ((answer: (
        count: Int,
        load: (index: Int, prepare: (processed: Long, total: Long) -> Boolean, loaded: (descriptor: Int, name: String?, contentType: String, size: Long, release: () -> Unit) -> Unit) -> Unit,
        releaseSelection: () -> Unit,
    ) -> Unit) -> Unit)? = null
    public var cancel: (() -> Unit)? = null
}

private enum class IosMediaFileSource { Audio, LivePhoto, Media }

/** Media from Files uses the codec pipeline and keeps its scoped source lease. */
public object IosMediaFilesPicker {
    public var present: ((answer: (
        count: Int,
        load: (index: Int, prepare: (processed: Long, total: Long) -> Boolean,
            loaded: (descriptor: Int, name: String?, contentType: String, size: Long, path: String?, release: () -> Unit) -> Unit) -> Unit,
        releaseSelection: () -> Unit,
    ) -> Unit) -> Unit)? = null
    public var cancel: (() -> Unit)? = null
}

/** Audio files use a coordinated readable URL until the import releases the source. */
public object IosAudioPicker {
    public var present: ((answer: (
        count: Int,
        load: (index: Int, prepare: (processed: Long, total: Long) -> Boolean,
            loaded: (descriptor: Int, name: String?, contentType: String, size: Long, path: String?, release: () -> Unit) -> Unit) -> Unit,
        releaseSelection: () -> Unit,
    ) -> Unit) -> Unit)? = null
    public var cancel: (() -> Unit)? = null
}

/** Portable Live Photo packages use the media pipeline and keep their scoped source lease. */
public object IosLivePhotoFilesPicker {
    public var present: ((answer: (
        count: Int,
        load: (index: Int, prepare: (processed: Long, total: Long) -> Boolean,
            loaded: (descriptor: Int, name: String?, contentType: String, size: Long, path: String?, release: () -> Unit) -> Unit) -> Unit,
        releaseSelection: () -> Unit,
    ) -> Unit) -> Unit)? = null
    public var cancel: (() -> Unit)? = null
}

/** One opening of a route modal; completing or disposing it can never revive it. */
internal class IosRouteModalVisit {
    private var active = true

    fun complete(allowed: Boolean, action: () -> Unit) {
        if (!active || !allowed) return
        active = false
        action()
    }

    fun retire() { active = false }
}

@Composable
private fun rememberIosRouteModalVisit(): IosRouteModalVisit {
    val visit = remember { IosRouteModalVisit() }
    DisposableEffect(visit) { onDispose { visit.retire() } }
    return visit
}
