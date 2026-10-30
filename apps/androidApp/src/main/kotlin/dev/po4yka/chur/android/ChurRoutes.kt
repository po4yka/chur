package dev.po4yka.chur.android

import android.content.Context
import android.content.Intent
import android.content.res.Configuration
import android.net.Uri
import android.provider.DocumentsContract
import androidx.activity.compose.ManagedActivityResultLauncher
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.key
import androidx.compose.runtime.saveable.LocalSaveableStateRegistry
import androidx.activity.compose.BackHandler
import androidx.activity.compose.LocalActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.PickVisualMediaRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.focusGroup
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.focusProperties
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import dev.po4yka.chur.app.LauncherAction
import dev.po4yka.chur.app.AppRoute
import dev.po4yka.chur.app.ActiveOperation
import dev.po4yka.chur.app.ChurController
import dev.po4yka.chur.app.ExportTarget
import dev.po4yka.chur.app.ExternalArchiveScreen
import dev.po4yka.chur.app.ExternalArchiveSelection
import dev.po4yka.chur.app.MediaImporter
import dev.po4yka.chur.app.Notice
import dev.po4yka.chur.app.notes.NoteEditorScreen
import dev.po4yka.chur.app.notes.NotesScreen
import dev.po4yka.chur.app.notes.OpenNote
import dev.po4yka.chur.app.notes.PublicSettingsScreen
import dev.po4yka.chur.app.PublicShell as PublicShellKind
import dev.po4yka.chur.app.publicshell.CalculatorScreen
import dev.po4yka.chur.app.notes.rememberOpenNote
import dev.po4yka.chur.app.vault.CreateVaultScreen
import dev.po4yka.chur.app.vault.loadedObjectSelection
import dev.po4yka.chur.app.vault.LibraryTile
import dev.po4yka.chur.app.vault.AlbumPickerDialog
import dev.po4yka.chur.app.vault.AlbumExportDialog
import dev.po4yka.chur.app.vault.DeleteSelectionDialog
import dev.po4yka.chur.app.vault.ExportOptionsDialog
import dev.po4yka.chur.app.vault.canSaveToPhotos
import dev.po4yka.chur.app.vault.NewAlbumDialog
import dev.po4yka.chur.app.vault.TagPickerDialog
import dev.po4yka.chur.app.vault.TagBrowserDialog
import dev.po4yka.chur.app.vault.RecoveryPhraseScreen
import dev.po4yka.chur.app.vault.RecoveryScreen
import dev.po4yka.chur.app.vault.RestoreBackupScreen
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
import dev.po4yka.chur.app.vault.VaultActions
import dev.po4yka.chur.app.vault.VaultDestination
import dev.po4yka.chur.app.vault.ContentView
import dev.po4yka.chur.app.vault.AlbumOrder
import dev.po4yka.chur.app.vault.browseQuery
import dev.po4yka.chur.app.vault.browseSearchScope
import dev.po4yka.chur.app.ArchiveCredential
import dev.po4yka.chur.app.ArchiveSource
import dev.po4yka.chur.app.ArchiveTransferOwner
import dev.po4yka.chur.app.SelectiveExportRequest
import dev.po4yka.chur.app.vault.SelectiveExportDialog
import dev.po4yka.chur.app.vault.SelectiveImportDialog
import dev.po4yka.chur.app.PrivateNoteExportRequest
import dev.po4yka.chur.app.vault.PrivateNotesRoute
import dev.po4yka.chur.app.vault.albumParent
import dev.po4yka.chur.app.vault.albumPath
import dev.po4yka.chur.app.vault.VaultShell
import dev.po4yka.chur.app.vault.VaultUiState
import androidx.compose.ui.graphics.ImageBitmap
import dev.po4yka.chur.app.vault.MEDIA_CLASS_AUDIO
import dev.po4yka.chur.app.vault.viewerPages
import dev.po4yka.chur.app.vault.ViewerStillState
import dev.po4yka.chur.app.vault.viewerStill
import dev.po4yka.chur.app.vault.rememberViewerAnimation
import dev.po4yka.chur.app.vault.VaultPlayer
import dev.po4yka.chur.app.vault.VaultDocument
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
import dev.po4yka.chur.imports.AndroidMediaCodec
import dev.po4yka.chur.notes.Note
import dev.po4yka.chur.vault.VaultState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The route table.
 *
 * `docs/security/PROVISIONING.md` §2 fixes the first route: the public shell,
 * with the route to the vault a visible settings entry. Nothing here can reach
 * a private route without passing through [AppRoute.Unlock] or
 * [AppRoute.CreateVault], because those are the only two that call into the
 * application's unlock and create.
 *
 * System Back does what the screen's own back or cancel control does, and a
 * screen without one returns to where it is entered from. A screen that must
 * not be left (the recovery phrase, a creation or a restore in progress) holds
 * Back. Without a handler Back is the platform's back-to-home, and the
 * background lock of `MainActivity.onPause` then closes the vault and drops
 * whatever the screen held. Only the roots let it through: the public shell,
 * the app gate, and the vault's Library.
 */
@Composable
fun ChurRoutes(controller: ChurController, route: AppRoute, vaultState: VaultState) {
    dev.po4yka.chur.app.onboarding.GuideHost(controller, route) { ChurRoutesGuided(controller, route, vaultState) }
}

@Composable
private fun ChurRoutesGuided(controller: ChurController, route: AppRoute, vaultState: VaultState) {
    val phrase by controller.recoveryPhrase.collectAsState()
    val panic: (() -> Unit)? = if (route == AppRoute.Vault || vaultState is VaultState.Unlocked || phrase != null) {
        { controller.panic() }
    } else null
    CompositionLocalProvider(LocalPrivatePanic provides panic) {
        ChurRoutesContent(controller, route, vaultState)
    }
}

@Composable
private fun ChurRoutesContent(controller: ChurController, route: AppRoute, vaultState: VaultState) {
    val phrase by controller.recoveryPhrase.collectAsState()
    val formError by controller.formError.collectAsState()
    val unlocking by controller.unlocking.collectAsState()

    // The phrase is shown once and takes precedence over every route, because
    // `RECOVERY.md` §2 shows it exactly once and a navigation that skipped it
    // would be that once spent. Back is held for the same reason: leaving
    // would run the background lock, which clears the phrase for good.
    phrase?.let { value ->
        BackHandler {}
        // Copying 24 words by hand, `RECOVERY.md` §2.3, outlasts the screen
        // timeout, and the pause that follows it used to lock and drop the
        // phrase mid-copy. The repository's phrase window bounds how long the
        // display stays awake.
        val view = LocalView.current
        DisposableEffect(view) {
            view.keepScreenOn = true
            onDispose { view.keepScreenOn = false }
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
        AppRoute.CreateVault -> {
            // A second identity is created from an open session, `DECOY_VAULT.md`
            // §3, so leaving returns to that vault and never shows the public
            // shell over it: a vault entry from there would open a second
            // session beside the first. During creation, Back hides immediately
            // and invalidates the pending result instead of waiting for key derivation.
            val leave = {
                when (controller.vaultState.value) {
                    is VaultState.Creating -> controller.panic()
                    is VaultState.Unlocked -> controller.goTo(AppRoute.Vault)
                    else -> controller.goTo(AppRoute.PublicShell)
                }
            }
            BackHandler(onBack = leave)
            CreateVaultScreen(
                busy = vaultState is VaultState.Creating,
                error = formError,
                onCreate = controller::create,
                onHide = { controller.panic() },
                onCancel = leave,
                // The offer exists only where no identity does. `DECOY_VAULT.md`
                // §8 and §10: this screen is also where a second identity is
                // created, and a restore offered there would reach for a registry
                // that already holds one.
                onRestore = if (vaultState is VaultState.NoVault) {
                    { controller.goTo(AppRoute.RestoreBackup) }
                } else {
                    null
                },
            )
        }
        AppRoute.RestoreBackup -> RestoreRoute(controller)
        AppRoute.EncryptFiles -> ExternalArchiveRoute(controller)
        AppRoute.Unlock -> {
            // Cancel invalidates pending credentials before returning to the public shell.
            BackHandler { controller.panic() }
            UnlockScreen(
                busy = unlocking,
                error = formError,
                onUnlock = controller::unlock,
                onUseRecovery = { controller.goTo(AppRoute.Recover) },
                onReturnToPublic = { controller.panic() },
                deviceUnlockOffered = controller.deviceUnlockOffered.collectAsState().value,
                onUseDevice = controller::unlockWithDevice,
            )
        }
        AppRoute.AppUnlock -> UnlockScreen(
            busy = unlocking,
            error = formError,
            onUnlock = controller::unlock,
            onUseRecovery = { controller.goTo(AppRoute.AppRecover) },
            deviceUnlockOffered = controller.deviceUnlockOffered.collectAsState().value,
            onUseDevice = controller::unlockWithDevice,
            appGate = true,
        )
        AppRoute.Recover -> {
            val back = { controller.goTo(AppRoute.Unlock) }
            BackHandler(onBack = back)
            RecoveryScreen(
                busy = unlocking,
                error = formError,
                onRecover = controller::recover,
                onBack = back,
                onReturnToPublic = { controller.panic() },
            )
        }
        AppRoute.AppRecover -> {
            val back = { controller.panic() }
            BackHandler(onBack = back)
            RecoveryScreen(
                busy = unlocking,
                error = formError,
                onRecover = controller::recover,
                onBack = back,
            )
        }
        AppRoute.Vault -> key((vaultState as? VaultState.Unlocked)?.generation ?: 0L) {
            VaultRoute(controller)
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
        BackHandler { controller.goTo(AppRoute.PublicShell) }
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
            PublicShellKind.CAMERA -> AndroidPublicCameraScreen(
                onSubmitCode = controller::submitPublicCode,
                onOpenSettings = { controller.goTo(AppRoute.PublicSettings) },
                showFirstWriteDisclosure = disclosureDue,
                onAcknowledgeDisclosure = controller::acknowledgeDisclosure,
                onBeginCapture = controller::beginPublicCameraActivity,
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
    // Saved state, so a recreation or a process restart reopens the note being
    // written; the editor saves its own draft whenever it leaves.
    var editing by rememberOpenNote()
    val newNoteRequest by controller.publicNoteRequest.collectAsState()
    LaunchedEffect(newNoteRequest) { controller.takePublicNoteRequest()?.let { editing = OpenNote(it, isNew = true) } }

    val focusManager = LocalFocusManager.current
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
            systemBack = { onBack -> BackHandler(onBack = onBack) },
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
            val imported = Note(id = "note-${System.nanoTime()}", title = title, body = body, updatedMs = System.currentTimeMillis())
            controller.putNote(imported)
            editing = OpenNote(imported, isNew = false)
        },
        onImportPackage = { bytes ->
            val imported = controller.importPublicNotePackage(bytes, "note-${System.nanoTime()}")
            editing = OpenNote(imported, isNew = false)
        },
        query = query,
        onQueryChange = { query = it },
        onSubmitSearch = { if (controller.matchesPublicCode(query)) { val submitted = query; query = ""; controller.submitPublicCode(submitted) } },
        onBulkAction = controller::updatePublicNotes,
        onOpen = { editing = OpenNote(it, isNew = false) },
        onCreate = {
            editing = OpenNote(
                Note(
                    id = "note-${System.nanoTime()}",
                    title = "",
                    body = "",
                    updatedMs = System.currentTimeMillis(),
                ),
                isNew = true,
            )
        },
        // §2: the route to the vault is a visible settings entry.
        // `DISCREET_MODE.md` "The v1 decision" makes it the session gate, and
        // it now opens the public shell's own settings, where the permanent
        // disclosure sits beside the vault row. The search field stays
        // composed under them, so it gives up the keyboard first: an open IME
        // would take keystrokes meant for nothing and the first Back.
        onOpenSettings = {
            focusManager.clearFocus()
            onOpenSettings()
        },
        showFirstWriteDisclosure = disclosureDue,
        onAcknowledgeDisclosure = controller::acknowledgeDisclosure,
    )
}

/**
 * The restore route, `docs/format/BACKUP_FORMAT_V1.md` §8.
 *
 * The picker is `OpenDocument` and its filter is unrestricted: a package has no
 * registered media type, and one copied from another device carries whatever
 * type the provider that holds it reports.
 *
 * The bracket around the launch is the media picker's, for the media picker's
 * reason. The platform stops this activity while the documents UI is up, and
 * the background transition would move the shell back to the public route and
 * take this screen with it.
 */
@Composable
private fun RestoreRoute(controller: ChurController) {
    val formError by controller.formError.collectAsState()
    val operation by controller.activeOperation.collectAsState()
    val context = LocalContext.current
    var pending by remember { mutableStateOf<ArchiveCredential?>(null) }
    var pickerOpen by remember { mutableStateOf(false) }
    var running by remember { mutableStateOf(false) }
    var cancelled by remember { mutableStateOf(false) }
    DisposableEffect(controller) {
        onDispose {
            pending?.clear()
            pending = null
            if (pickerOpen) { pickerOpen = false; controller.endHostActivity() }
        }
    }
    val stagingScope = rememberCoroutineScope()
    var staging by remember { mutableStateOf<kotlinx.coroutines.Job?>(null) }
    val restorePickerOwner = remember { Any() }
    lateinit var picker: ManagedActivityResultLauncher<Array<String>, Uri?>
    key(restorePickerOwner) {
        CompositionLocalProvider(LocalSaveableStateRegistry provides null) {
            picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
                val credential = pending
                pending = null
                if (pickerOpen) { pickerOpen = false; controller.endHostActivity() }
                if (credential != null) {
                    if (uri == null || controller.route.value != AppRoute.RestoreBackup) {
                        credential.clear()
                        running = false
                    } else {
                        val hold = controller.retainArchiveCredential(credential)
                        val job = stagingScope.launch(start = kotlinx.coroutines.CoroutineStart.LAZY) {
                            var source: ArchiveSource? = null
                            var transferred = false
                            try {
                                val ready = AndroidArchiveInput.open(context, uri)
                                source = ready
                                controller.restoreBackup(ready.descriptor, credential) { wasCancelled ->
                                    ready.close()
                                    running = false
                                    cancelled = wasCancelled
                                }
                                transferred = true
                            } catch (failure: kotlinx.coroutines.CancellationException) {
                                cancelled = true
                                throw failure
                            } catch (_: Exception) {
                                controller.report("That file could not be opened.")
                            } finally {
                                if (!transferred) {
                                    source?.close?.invoke()
                                    credential.clear()
                                    running = false
                                }
                                hold.release()
                                staging = null
                            }
                        }
                        staging = job
                        hold.attach(job)
                        job.start()
                    }
                }
            }
        }
    }
    val back = { controller.goTo(if (controller.vaultState.value is VaultState.NoVault) AppRoute.CreateVault else AppRoute.PublicShell) }
    BackHandler { if (!running) back() }
    RestoreBackupScreen(
        busy = running, error = formError, cancelled = cancelled, operation = operation,
        onChoose = { entered ->
            pending?.clear()
            pending = ArchiveCredential(entered)
            running = true
            cancelled = false
            controller.report(null)
            controller.beginHostActivity()
            pickerOpen = true
            try { picker.launch(arrayOf("*/*")) } catch (_: Exception) {
                pending?.clear(); pending = null
                pickerOpen = false; controller.endHostActivity()
                running = false
                controller.report("The file picker could not be opened.")
            }
        },
        onBack = back, onCancel = { staging?.cancel(); controller.cancelActiveOperation() },
    )
}

/** Picked URIs stay in this route's memory and are opened only for encryption. */
@Composable
private fun ExternalArchiveRoute(controller: ChurController) {
    val context = LocalContext.current
    val codec = remember(context) { AndroidMediaCodec(context) }
    val pickerOwner = remember(controller) { Any() }
    var alive by remember(controller) { mutableStateOf(true) }
    var pendingFiles by remember(controller) { mutableStateOf<((ExternalArchiveSelection?) -> Unit)?>(null) }
    var pendingDestination by remember(controller) { mutableStateOf<((String?) -> Unit)?>(null) }
    DisposableEffect(controller) {
        onDispose {
            alive = false
            pendingFiles = null
            pendingDestination = null
        }
    }
    lateinit var files: ManagedActivityResultLauncher<Array<String>, List<Uri>>
    lateinit var destination: ManagedActivityResultLauncher<String, Uri?>
    // Restored activity results cannot attach to a new screen owner.
    key(pickerOwner) {
        CompositionLocalProvider(LocalSaveableStateRegistry provides null) {
            files = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
                val answer = pendingFiles
                pendingFiles = null
                if (alive && answer != null) {
                    if (uris.size > 32) {
                        controller.report("Select at most 32 files for one encrypted archive.")
                        answer(null)
                    } else {
                        answer(uris.takeIf { it.isNotEmpty() }?.toList()?.let { selected ->
                            ExternalArchiveSelection(
                                count = selected.size,
                                open = { index, _ -> codec.open(selected[index], asFile = true) },
                                close = {},
                            )
                        })
                    }
                }
            }
            destination = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
                val answer = pendingDestination
                pendingDestination = null
                if (alive && answer != null) answer(uri?.toString())
                else uri?.let { controller.discardArchiveDestination(it.toString()) }
            }
        }
    }
    ExternalArchiveScreen(
        controller = controller,
        selectFiles = { answer ->
            pendingFiles = answer
            try {
                files.launch(arrayOf("*/*"))
            } catch (_: Exception) {
                pendingFiles = null
                controller.report("The file picker could not be opened.")
                answer(null)
            }
        },
        chooseDestination = { answer ->
            pendingDestination = answer
            try {
                destination.launch("chur-archive.churbak")
            } catch (_: Exception) {
                pendingDestination = null
                controller.report("The destination picker could not be opened.")
                answer(null)
            }
        },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun VaultRoute(controller: ChurController) {
    val contentIndex by controller.contentIndex.collectAsState()
    val page by controller.page.collectAsState()
    val albums by controller.albums.collectAsState()
    val tags by controller.tags.collectAsState()
    val slots by controller.slots.collectAsState()
    val reencryptionNotice by controller.reencryptionNotice.collectAsState()
    val notice by controller.notice.collectAsState()
    val operation by controller.activeOperation.collectAsState()
    val vaultState by controller.vaultState.collectAsState()
    val syncStatus by controller.syncStatus.collectAsState()
    val vaultDevicePairing by controller.devicePairing.collectAsState()
    val deviceSlotStrict by controller.deviceSlotStrict.collectAsState()
    val appLockEnabled by controller.appLockEnabled.collectAsState()
    val autoLock by controller.autoLock.collectAsState()
    val context = LocalContext.current
    val activity = LocalActivity.current
    val quickSettingsLock = remember(activity) { activity?.let(::QuickSettingsLock) }
    val quickSettingsLockAvailable = activity != null
    var quickSettingsLockBusy by remember(activity) { mutableStateOf(false) }
    var quickSettingsLockMessage by remember(activity) { mutableStateOf<String?>(null) }
    val focusManager = LocalFocusManager.current
    val scope = rememberCoroutineScope()
    val host = remember(context) { ChurHost.of(context) }
    val incomingShare by host.incomingShares.state.collectAsState()
    val deviceControl = host.deviceControl
    val devicePairing by deviceControl.pairing.collectAsState()
    val deviceConnected by deviceControl.connected.collectAsState()

    val generation = (vaultState as? VaultState.Unlocked)?.generation ?: 0L
    val archiveTransfers = remember(controller, generation) { ArchiveTransferOwner(controller, generation) }
    DisposableEffect(archiveTransfers) { onDispose { archiveTransfers.close() } }
    var choosingArchive by remember(generation) { mutableStateOf<SelectiveExportRequest?>(null) }
    var choosingArchiveImport by remember(generation) { mutableStateOf(false) }
    var showingPrivateNotes by remember(generation) { mutableStateOf(false) }
    var privateNotesBusy by remember(generation) { mutableStateOf(false) }
    var privateNoteCreateRequest by remember(generation) { mutableStateOf<Long?>(null) }
    var searchFocusRequest by remember(generation) { mutableStateOf<Long?>(null) }
    var shellNavigationBusy by remember(generation) { mutableStateOf(false) }
    var choosingPrivateNoteExport by remember(generation) { mutableStateOf<PrivateNoteExportRequest?>(null) }
    var pendingPrivateNoteExport by remember(generation) { mutableStateOf<PrivateNoteExportRequest?>(null) }
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

    var openTag by remember { mutableStateOf<TagSummary?>(null) }
    var favoritesOnly by remember { mutableStateOf(false) }
    var trashOpen by remember { mutableStateOf(false) }
    var quarantineOpen by remember { mutableStateOf(false) }
    var recentlyAdded by remember(generation) { mutableStateOf(false) }
    LaunchedEffect(tags) {
        openTag = openTag?.let { current -> tags.firstOrNull { it.id == current.id } }
    }
    // The item on screen in the viewer; a swipe moves it through the page.
    var viewing by remember(generation) { mutableStateOf<ObjectProjection?>(null) }
    var visibleMediaIds by remember(generation) { mutableStateOf(emptySet<String>()) }
    var selection by remember(generation) { mutableStateOf(setOf<String>()) }
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
    var exportingAlbum by remember(generation) { mutableStateOf<AlbumSummary?>(null) }
    var pendingAlbumExport by remember(generation) { mutableStateOf<ByteArray?>(null) }
    var pendingDocumentImport by remember(generation) { mutableStateOf<Pair<Long, ByteArray?>?>(null) }
    DisposableEffect(controller, generation) {
        onDispose {
            if (pendingAlbumExport != null) {
                pendingAlbumExport = null
                if ((controller.vaultState.value as? VaultState.Unlocked)?.generation == generation) {
                    controller.endHostActivity()
                }
            }
            if (pendingPrivateNoteExport != null) {
                pendingPrivateNoteExport = null
                if ((controller.vaultState.value as? VaultState.Unlocked)?.generation == generation) {
                    controller.endHostActivity()
                }
            }
            if (pendingDocumentImport != null) {
                pendingDocumentImport = null
                if ((controller.vaultState.value as? VaultState.Unlocked)?.generation == generation) {
                    controller.endHostActivity()
                }
            }
        }
    }
    var choosingImport by remember { mutableStateOf(false) }
    var importAlbumId by remember { mutableStateOf<ByteArray?>(null) }
    // The picked items whose import committed, until the user answers the
    // step of `DESIGN.md` §15.3. A lock disposes of the route and of them.
    var originals by remember { mutableStateOf<List<Uri>>(emptyList()) }
    val launcherRequest by controller.launcherRequest.collectAsState()
    val lifecycleState by LocalLifecycleOwner.current.lifecycle.currentStateFlow.collectAsState()
    val guideNavigationBusy = incomingShare != null || shellNavigationBusy || privateNotesBusy || selection.isNotEmpty() ||
        creatingAlbum || choosingAlbum || movingSelection || choosingTag || managingTags ||
        confirmingDelete || confirmingEmptyTrash || choosingExport || choosingImport ||
        choosingArchive != null || choosingArchiveImport || choosingPrivateNoteExport != null ||
        pendingPrivateNoteExport != null || exportingAlbum != null || pendingAlbumExport != null ||
        pendingDocumentImport != null || originals.isNotEmpty() || devicePairing != null ||
        quickSettingsLockBusy || operation != null
    val launcherNavigationBusy = guideNavigationBusy || viewing != null
    DisposableEffect(controller, launcherNavigationBusy, guideNavigationBusy) {
        controller.setVaultNavigationBusy(launcherNavigationBusy, guideNavigationBusy)
        onDispose { controller.setLauncherNavigationBusy(false) }
    }
    LaunchedEffect(launcherRequest?.token, lifecycleState) {
        val request = launcherRequest ?: return@LaunchedEffect
        if (lifecycleState != Lifecycle.State.RESUMED) return@LaunchedEffect
        if (launcherNavigationBusy) {
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
        when (request.action) {
            LauncherAction.IMPORT -> {
                showingPrivateNotes = false
                privateNoteCreateRequest = null
                destination = VaultDestination.LIBRARY
                importAlbumId = null
                choosingImport = true
            }
            LauncherAction.SEARCH -> {
                showingPrivateNotes = false
                privateNoteCreateRequest = null
                destination = VaultDestination.SEARCH
                searchFocusRequest = request.token
            }
            LauncherAction.NEW_PRIVATE_NOTE -> {
                privateNoteCreateRequest = request.token
                showingPrivateNotes = true
            }
            LauncherAction.PUBLIC_NOTES, LauncherAction.PUBLIC_CALCULATOR, LauncherAction.PUBLIC_CAMERA, LauncherAction.PUBLIC_PET -> Unit
            LauncherAction.LOCK_AND_HIDE -> Unit // Handled synchronously by the controller.
        }
    }
    val deleteOriginals = rememberOriginalDeletion(controller)
    val localNetwork = rememberLocalNetworkAccess(controller)
    val pairingFiles = rememberPairingApprovalFiles(controller)
    // Request local-network access only when the user starts a peer connection.

    // `ANDROID.md` §25.1: the levels are read when Settings opens, over IPC
    // only. The published check is the user's tap, and a lock disposes of its
    // result with the route.
    val inSettings = destination == VaultDestination.SETTINGS
    val patchLevels by produceState<SystemPatchLevels?>(null, inSettings) {
        if (inSettings) value = readSystemPatchLevels(context)
    }
    var publishedCheck by remember { mutableStateOf<PublishedCheck>(PublishedCheck.NotChecked) }

    DisposableEffect(deviceControl) {
        onDispose { deviceControl.stop() }
    }
    LaunchedEffect(destination, vaultState) {
        if (destination != VaultDestination.SETTINGS || vaultState !is VaultState.Unlocked) {
            deviceControl.stop()
        }
    }

    // The cache is the controller's: its lock transitions clear it whether
    // or not this screen is composed, §4 of `PLAINTEXT_LIFECYCLE.md`. The
    // session generation in the key is what makes a stale entry unreachable
    // after a new session opens.
    val cache = controller.thumbnailCache
    LaunchedEffect(generation) {
        if (vaultState is VaultState.Unlocked) controller.loadAlbums()
    }

    val codec = remember { AndroidMediaCodec(context) }
    val importer = remember { MediaImporter(codec) }
    val onPicked: (List<Uri>) -> Unit = fun(uris: List<Uri>) {
        if ((controller.vaultState.value as? VaultState.Unlocked)?.generation != generation) return
        // The picker is an activity of ours, so the vault stayed open while it
        // ran. It ends here whether the user chose something or dismissed it.
        controller.endHostActivity()
        val albumId = importAlbumId
        importAlbumId = null
        // The grants live in this list for the one batch and its §15.3 step,
        // and never reach saved state, `ANDROID.md` §14.2.
        if (uris.isNotEmpty()) {
            scope.launch {
                val outcomes = controller.importAll(importer, uris.size, albumId) { index, _ -> codec.open(uris[index]) }
                if (controller.vaultState.value is VaultState.Unlocked) originals = importedOriginals(uris, outcomes)
            }
        }
    }
    // Both pickers take many items in one session. The photo picker keeps
    // its platform limit, and on API levels without it the contract falls
    // back to a document picker that allows multiple selection (§14.1).
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.PickMultipleVisualMedia(), onPicked)
    val mediaFilePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments(), onPicked)
    val audioPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments(), onPicked)
    val livePhotoPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments(), onPicked)
    val documentPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        val pending = pendingDocumentImport
        pendingDocumentImport = null
        if (pending != null && (controller.vaultState.value as? VaultState.Unlocked)?.generation == pending.first) {
            controller.endHostActivity()
            if (uris.isNotEmpty()) scope.launch {
                controller.importAll(importer, uris.size, pending.second) { index, _ -> codec.open(uris[index], asFile = true) }
            }
        }
    }
    lateinit var archiveExportPicker: ManagedActivityResultLauncher<String, Uri?>
    lateinit var archiveImportPicker: ManagedActivityResultLauncher<Array<String>, Uri?>
    // A new session gets new launcher keys. A stale result cannot consume a new session's credential.
    key(archiveTransfers) {
        CompositionLocalProvider(LocalSaveableStateRegistry provides null) {
            archiveExportPicker = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
                archiveTransfers.exportedFile(uri?.toString())
            }
            archiveImportPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
                val staging = scope.launch(start = kotlinx.coroutines.CoroutineStart.LAZY) {
                    var source: ArchiveSource? = null
                    try {
                        source = uri?.let { AndroidArchiveInput.open(context, it) }
                        archiveTransfers.importedFile(source)
                        source = null
                    } catch (failure: kotlinx.coroutines.CancellationException) {
                        archiveTransfers.importedFile(null)
                        throw failure
                    } catch (_: Exception) {
                        if ((controller.vaultState.value as? VaultState.Unlocked)?.generation == generation) {
                            controller.report("That file could not be opened.")
                        }
                        archiveTransfers.importedFile(null)
                    } finally { source?.close?.invoke() }
                }
                archiveTransfers.importPickerReturned(staging)
                staging.start()
            }
        }
    }
    val onPrivateNoteFilePicked: (android.net.Uri?) -> Unit = { uri ->
        val request = pendingPrivateNoteExport
        pendingPrivateNoteExport = null
        if (request != null) {
            if ((controller.vaultState.value as? VaultState.Unlocked)?.generation == request.generation) {
                controller.endHostActivity()
            }
            if (uri != null) controller.exportPrivateNote(request, ExportTarget.FILES, uri.toString())
        } else if (uri != null) {
            // This launcher created the destination, even if its session ended before delivery.
            scope.launch(Dispatchers.IO) { runCatching { DocumentsContract.deleteDocument(context.contentResolver, uri) } }
        }
    }
    val privateNoteFilePicker = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        onPrivateNoteFilePicked(if (result.resultCode == android.app.Activity.RESULT_OK) result.data?.data else null)
    }
    val albumExportPicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        val albumId = pendingAlbumExport
        pendingAlbumExport = null
        val current = controller.vaultState.value as? VaultState.Unlocked
        if (albumId != null && current?.generation == generation) {
            controller.endHostActivity()
            if (uri != null) controller.exportAlbum(albumId, uri.toString())
        }
    }

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
    }

    val thumbnails = rememberGalleryThumbnails(
        controller.vault, cache, generation, page.objects.filter { it.id in visibleMediaIds }, thumbnailsConcealed,
    )
    // Plain pixels are loaded separately only while the viewer is open. They
    // never enter the gallery map, including the viewer's adjacent pages.
    val viewerThumbnails = rememberViewerThumbnails(
        controller.vault, cache, generation, page.objects, currentObjectId = viewing?.id,
    )

    if (choosingImport) {
        // `DESIGN.md` §26: a sheet for a contextual choice. Each source is a
        // row of its own, and the scrim and Back dismiss the sheet. The
        // dialog it replaces put "Audio files" in the dismiss slot, so no
        // button only closed it.
        ModalBottomSheet(onDismissRequest = { choosingImport = false }) {
            TextButton(onClick = { controller.panic() }, modifier = Modifier.fillMaxWidth()) {
                Text("Lock and hide")
            }
            Text(
                "Import",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp).semantics { heading() },
            )
            ListItem(
                headlineContent = { Text("Photos and videos") },
                modifier = Modifier.clickable(role = Role.Button) {
                    choosingImport = false
                    importAlbumId = openAlbum?.albumId
                    controller.beginHostActivity()
                    picker.launch(PickVisualMediaRequest(ActivityResultContracts.PickVisualMedia.ImageAndVideo))
                },
            )
            ListItem(
                headlineContent = { Text("Media files") },
                modifier = Modifier.clickable(role = Role.Button) {
                    choosingImport = false
                    importAlbumId = openAlbum?.albumId
                    controller.beginHostActivity()
                    try {
                        // A file provider can report a portable image codec as
                        // generic data. The media codec confirms the bytes.
                        mediaFilePicker.launch(arrayOf("*/*"))
                    } catch (_: Exception) {
                        controller.endHostActivity()
                        controller.report("The media file picker could not be opened.")
                    }
                },
            )
            ListItem(
                headlineContent = { Text("Audio files") },
                modifier = Modifier.clickable(role = Role.Button) {
                    choosingImport = false
                    importAlbumId = openAlbum?.albumId
                    controller.beginHostActivity()
                    audioPicker.launch(arrayOf("audio/*"))
                },
            )
            ListItem(
                headlineContent = { Text("Live Photo packages") },
                modifier = Modifier.clickable(role = Role.Button) {
                    choosingImport = false
                    importAlbumId = openAlbum?.albumId
                    controller.beginHostActivity()
                    try {
                        livePhotoPicker.launch(arrayOf("application/vnd.chur.live-photo", "application/octet-stream"))
                    } catch (_: Exception) {
                        controller.endHostActivity()
                        controller.report("The Live Photo file picker could not be opened.")
                    }
                },
            )
            ListItem(
                headlineContent = { Text("Encrypted archive") },
                modifier = Modifier.clickable(role = Role.Button) {
                    choosingImport = false
                    choosingArchiveImport = true
                },
            )
            ListItem(
                headlineContent = { Text("Documents and files") },
                modifier = Modifier.clickable(role = Role.Button) {
                    choosingImport = false
                    if ((controller.vaultState.value as? VaultState.Unlocked)?.generation == generation) {
                        pendingDocumentImport = generation to openAlbum?.albumId?.copyOf()
                        controller.beginHostActivity()
                        try {
                            documentPicker.launch(arrayOf("*/*"))
                        } catch (_: Exception) {
                            pendingDocumentImport = null
                            controller.endHostActivity()
                            controller.report("The file picker could not be opened.")
                        }
                    }
                },
            )
        }
    }

    if (originals.isNotEmpty()) {
        SourceDeletionDialog(
            count = originals.size,
            onKeep = { originals = emptyList() },
            onReview = {
                deleteOriginals(originals)
                originals = emptyList()
            },
        )
    }

    devicePairing?.let { pairing ->
        PrivateAlertDialog(
            onDismissRequest = deviceControl::stop,
            title = { Text("Control from computer") },
            text = {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Text(if (deviceConnected) "Computer connected" else "Waiting for computer",
                        color = MaterialTheme.colorScheme.primary,
                        style = MaterialTheme.typography.labelLarge)
                    Text("Keep Chur open and unlocked. Connect your computer with USB debugging enabled.")
                    Surface(
                        modifier = Modifier.fillMaxWidth(),
                        shape = MaterialTheme.shapes.medium,
                        color = MaterialTheme.colorScheme.surfaceVariant,
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                        ) {
                            Text("Session link", style = MaterialTheme.typography.labelMedium)
                            Text(pairing.link, fontFamily = FontFamily.Monospace)
                        }
                    }
                    Text(
                        "Type this link at the hidden prompt of scripts/chur-device.py --session-stdin. " +
                            "Chur does not copy it to the clipboard. Only ADB on the connected computer can " +
                            "use it. Keep it private: anyone with the link and ADB access can control this " +
                            "vault. Stop revokes the session. It also stops after 10 minutes without a command.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
            },
            confirmButton = { TextButton(onClick = deviceControl::stop) { Text("Stop") } },
        )
    }

    if (creatingAlbum) {
        NewAlbumDialog(
            onCreate = { name ->
                creatingAlbum = false
                controller.createAlbum(name)
            },
            onDismiss = { creatingAlbum = false },
        )
    }
    if (choosingAlbum) {
        AlbumPickerDialog(
            albums = albums,
            currentAlbum = openAlbum,
            move = movingSelection,
            onChoose = { album ->
                choosingAlbum = false
                controller.placeObjectsInAlbum(
                    album.albumId, organizingIds, openAlbum?.albumId, movingSelection,
                ) { selection = emptySet() }
            },
            onCreate = { name, parent ->
                choosingAlbum = false
                controller.createAlbumWithObjects(
                    name, parent?.albumId, organizingIds, openAlbum?.albumId, movingSelection,
                ) { selection = emptySet() }
            },
            onDismiss = { choosingAlbum = false },
        )
    }
    if (choosingTag) {
        TagPickerDialog(
            tags = tags,
            onAdd = { tag ->
                choosingTag = false
                controller.setTagForAll(tag.tagId, taggingIds, true) {
                    selection = emptySet()
                }
            },
            onRemove = { tag ->
                choosingTag = false
                controller.setTagForAll(tag.tagId, taggingIds, false) {
                    selection = emptySet()
                }
            },
            onCreate = { name ->
                choosingTag = false
                controller.createTagWithObjects(name, taggingIds) {
                    selection = emptySet()
                }
            },
            onDismiss = { choosingTag = false },
        )
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
    if (choosingExport) {
        val selected = page.objects.filter { it.id in selection }
        ExportOptionsDialog(
            media = selected.isNotEmpty() && selected.all { canSaveToPhotos(it.mediaKind) },
            files = false,
            share = false,
            downloads = true,
            onChoose = { target ->
                choosingExport = false
                controller.exportAll(selectedObjects(page, selection), target) { selection = emptySet() }
            },
            onDismiss = { choosingExport = false },
        )
    }
    exportingAlbum?.let { album ->
        AlbumExportDialog(
            album = album,
            onConfirm = {
                exportingAlbum = null
                if ((controller.vaultState.value as? VaultState.Unlocked)?.generation == generation) {
                    pendingAlbumExport = album.albumId.copyOf()
                    controller.beginHostActivity()
                    try {
                        albumExportPicker.launch(null)
                    } catch (_: Exception) {
                        pendingAlbumExport = null
                        controller.endHostActivity()
                        controller.report("The folder picker could not be opened.")
                    }
                }
            },
            onDismiss = { exportingAlbum = null },
        )
    }

    choosingArchive?.let { request ->
        SelectiveExportDialog(summary = request.summary, enabled = operation == null,
            onChoose = { password, target ->
                choosingArchive = null
                archiveTransfers.export(request, ArchiveCredential(password), target) { archiveExportPicker.launch(it) }
            }, onDismiss = { choosingArchive = null })
    }
    if (choosingArchiveImport) {
        SelectiveImportDialog(enabled = operation == null,
            onChoose = { password ->
                choosingArchiveImport = false
                archiveTransfers.import(ArchiveCredential(password)) { archiveImportPicker.launch(arrayOf("*/*")) }
            }, onDismiss = { choosingArchiveImport = false })
    }

    if (showingPrivateNotes) {
        PrivateNotesRoute(
            vault = controller.vault, generation = generation,
            lockOwner = controller,
            initialCreateRequest = privateNoteCreateRequest,
            onNavigationBusyChange = { privateNotesBusy = it },
            onClose = { focusManager.clearFocus(); showingPrivateNotes = false; privateNoteCreateRequest = null },
            onLock = { controller.lock() }, onPanic = controller::panic,
            onTouch = { controller.recordPrivateNoteActivity(generation) },
            onImportActivity = { active ->
                if ((controller.vaultState.value as? VaultState.Unlocked)?.generation == generation) {
                    if (active) controller.beginHostActivity() else controller.endHostActivity()
                }
            },
            onExport = { choosingPrivateNoteExport = PrivateNoteExportRequest.from(it, generation) },
            onAttachmentExport = { note, attachment -> choosingPrivateNoteExport = PrivateNoteExportRequest.fromAttachment(note, attachment, generation) },
            systemBack = { enabled, back -> BackHandler(enabled = enabled, onBack = back) },
            operation = operation, onCancelOperation = controller::cancelActiveOperation,
            notice = notice, onNoticeShown = controller::consume,
            onEncryptedExport = { choosingArchive = SelectiveExportRequest(generation, notes = it) },
        )
        choosingPrivateNoteExport?.let { request ->
            ExportOptionsDialog(media = false, files = true, share = true, downloads = true,
                onChoose = { target ->
                    choosingPrivateNoteExport = null
                    if (target == ExportTarget.FILES) {
                        pendingPrivateNoteExport = request
                        controller.beginHostActivity()
                        try { privateNoteFilePicker.launch(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                            addCategory(Intent.CATEGORY_OPENABLE)
                            type = request.contentType
                            putExtra(Intent.EXTRA_TITLE, request.filename)
                        }) } catch (_: Exception) {
                            pendingPrivateNoteExport = null
                            controller.endHostActivity()
                            controller.report("The file picker could not be opened.")
                        }
                    } else controller.exportPrivateNote(request, target)
                }, onDismiss = { choosingPrivateNoteExport = null })
        }
        return
    }

    // Callbacks can outlive this rendered selection until Compose publishes
    // the next frame. Never let that interval retarget an old action.
    fun currentSearchScope() = browseSearchScope(destination, openAlbum, openTag,
        favoritesOnly, trashOpen, quarantineOpen, recentlyAdded)
    val renderedSearchScope = currentSearchScope()
    val renderedSearchTerms = terms
    fun renderedMediaIsCurrent(): Boolean = terms == renderedSearchTerms &&
        currentSearchScope() == renderedSearchScope && controller.route.value == AppRoute.Vault &&
        (controller.vaultState.value as? VaultState.Unlocked)?.generation == generation
    fun searchCommandsBlocked(): Boolean = selection.isNotEmpty() || viewing != null || showingPrivateNotes ||
        controller.activeOperation.value != null || shellNavigationBusy || privateNotesBusy ||
        creatingAlbum || choosingAlbum || choosingTag || managingTags || confirmingDelete || confirmingEmptyTrash ||
        choosingExport || choosingImport || choosingArchive != null || choosingArchiveImport ||
        choosingPrivateNoteExport != null || pendingPrivateNoteExport != null || exportingAlbum != null ||
        pendingAlbumExport != null || pendingDocumentImport != null || originals.isNotEmpty() ||
        devicePairing != null || quickSettingsLockBusy || incomingShare != null
    fun updateSearch(value: String) {
        if (!trashOpen && currentSearchScope() == renderedSearchScope &&
            (destination == VaultDestination.LIBRARY || destination == VaultDestination.SEARCH || openAlbum != null) &&
            !searchCommandsBlocked() && controller.route.value == AppRoute.Vault &&
            (controller.vaultState.value as? VaultState.Unlocked)?.generation == generation
        ) terms = value
    }
    val renderedSelection = selection.toSet()
    fun selectionCommandsBlocked(): Boolean = controller.activeOperation.value != null ||
        choosingExport || choosingAlbum || choosingTag || confirmingDelete || choosingArchive != null
    fun selectionAction(block: () -> Unit) {
        if (renderedSelection.isNotEmpty() && selection == renderedSelection &&
            !selectionCommandsBlocked() && controller.route.value == AppRoute.Vault &&
            (controller.vaultState.value as? VaultState.Unlocked)?.generation == generation
        ) block()
    }
    // The viewer is drawn over the shell rather than in its place, as on
    // iOS: `ChurApp` stacks a route's content, so the shell stays composed and
    // its grid and list keep their scroll positions when the viewer closes.
    // Covered, the shell is out of a screen reader's reach, §4 of
    // `PLAINTEXT_LIFECYCLE.md`, and the viewer's pointer input keeps touches
    // from it. It is out of keyboard focus too, §23.3 of `DESIGN.md`: opening
    // the viewer takes the focus from it, and a hardware keyboard cannot move
    // the focus back in. The viewer's Back handlers are registered after the
    // shell's, so they answer first.
    Box(
        if (viewing != null) {
            Modifier
                .clearAndSetSemantics {}
                .focusProperties { onEnter = { cancelFocusChange() } }
                .focusGroup()
        } else {
            Modifier
        },
    ) {
        VaultShell(
            searchFocusRequest = searchFocusRequest,
            onNavigationBusyChange = { shellNavigationBusy = it },
            state = VaultUiState(
                destination = destination,
                tiles = page.objects.map { projection ->
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
                searchContext = renderedSearchScope,
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
                // The viewer is drawn over the shell, so the shell leaves the
                // notice to it while it is open rather than show it twice.
                notice = notice.takeIf { viewing == null },
                operation = operation,
                selectedCount = selection.size,
                selectionIds = selection,
                canLoadMore = page.nextCursor != null,
                deviceSlotAvailable = true,
                deviceSlotStrict = deviceSlotStrict,
                appLockEnabled = appLockEnabled,
                autoLock = autoLock,
                deviceControlAvailable = true,
                quickSettingsLockAvailable = quickSettingsLockAvailable,
                quickSettingsLockBusy = quickSettingsLockBusy,
                quickSettingsLockMessage = quickSettingsLockMessage,
                sync = syncStatus,
                devicePairing = vaultDevicePairing,
                systemSecurity = systemSecurityLine(patchLevels, publishedCheck),
            ),
            actions = VaultActions(
                publicSettingsContent = { dev.po4yka.chur.app.publicshell.DiscreetSettings(controller) },
                onThumbnailsConcealedChange = { thumbnailsConcealed = it },
                onDestination = {
                    terms = ""
                    openAlbum = null
                    openTag = null
                    favoritesOnly = false
                    trashOpen = false
                    quarantineOpen = false
                    recentlyAdded = false
                    selection = emptySet()
                    destination = it
                },
                onOpen = open@{ projection ->
                    // A queued tile event cannot open or select a result from the previous query.
                    if (!renderedMediaIsCurrent()) return@open
                    // §11.4: a tap opens the viewer, unless a selection is running,
                    // in which case it extends the selection. Selection is a mode
                    // and an open would leave it silently.
                    // Keep the selection while its operation or dialog owns input.
                    if (selection.isNotEmpty() && selectionCommandsBlocked()) return@open
                    if (selection.isEmpty()) {
                        controller.report(null)
                        // A text field of the shell left focused would keep
                        // the keyboard open over the viewer, which is edge to
                        // edge (`ChurApp`), and take what is typed under it.
                        focusManager.clearFocus()
                        viewing = projection
                    } else {
                        selection = selection.toggle(projection.id)
                    }
                },
                onToggleSelection = { projection ->
                    if (renderedMediaIsCurrent() && !selectionCommandsBlocked()) selection = selection.toggle(projection.id)
                },
                onOpenPrivateNotes = { terms = ""; focusManager.clearFocus(); selection = emptySet(); recentlyAdded = false; privateNoteCreateRequest = null; showingPrivateNotes = true },
                onImport = { choosingImport = true },
                onSearch = ::updateSearch,
                onIndexContent = { controller.indexContent() },
                onRebuildContentIndex = { controller.indexContent(rebuild = true) },
                onCancelContentIndex = controller::cancelContentIndex,
                onClearContentIndex = controller::clearContentIndex,
                onOpenAlbum = { navigateAlbum(it) },
                onCloseAlbum = { navigateAlbum(albumParent(albums, openAlbum?.id)) },
                onAlbumRoot = { navigateAlbum(null) },
                onCreateAlbum = { creatingAlbum = true },
                onMediaViewChange = { mediaView = it },
                onAlbumViewChange = { albumView = it },
                onSortChange = {
                    if (openAlbum != null) albumSort = it else if (!recentlyAdded) mediaSort = it
                    selection = emptySet()
                },
                onKindsChange = { mediaKinds = it; selection = emptySet() },
                onAlbumOrderChange = { albumOrder = it },
                onAlbumFilterChange = { albumFilter = it },
                onShowRecentlyAdded = {
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
                },
                onShowAllMedia = { terms = ""; recentlyAdded = false; openTag = null; favoritesOnly = false; trashOpen = false; quarantineOpen = false; selection = emptySet() },
                onShowFavorites = { terms = ""; recentlyAdded = false; openTag = null; favoritesOnly = true; trashOpen = false; quarantineOpen = false; selection = emptySet() },
                onShowTags = { controller.loadTags(); managingTags = true },
                onShowTrash = { terms = ""; recentlyAdded = false; openTag = null; favoritesOnly = false; trashOpen = true; quarantineOpen = false; selection = emptySet() },
                onShowQuarantine = { terms = ""; recentlyAdded = false; openTag = null; favoritesOnly = false; trashOpen = false; quarantineOpen = true; selection = emptySet() },
                onEmptyTrash = { confirmingEmptyTrash = true },
                onRestoreTrash = { controller.restoreTrash { selection = emptySet() } },
                onRenameAlbum = { album, name -> controller.renameAlbum(album.albumId, name) },
                onExportAlbum = { exportingAlbum = it },
                onEncryptedExportAlbum = { choosingArchive = SelectiveExportRequest(generation, albumIds = listOf(it.albumId)) },
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
                onDropMediaIntoAlbum = { objects, target ->
                    if (target != null) {
                        controller.placeObjectsInAlbum(target.albumId, objects.map { it.objectId },
                            openAlbum?.albumId, openAlbum != null) { selection = emptySet() }
                    } else {
                        controller.loadAlbums()
                        organizingIds = objects.map { it.objectId }
                        movingSelection = openAlbum != null
                        choosingAlbum = true
                    }
                },
                onLoadMore = controller::loadNextPage,
                onVisibleMediaChanged = { visibleMediaIds = it },
                onLock = { controller.lock() },
                onPanic = { controller.panic() },
                onDeleteDamagedFiles = { controller.deleteDamagedFiles() },
                onVerifyAll = { controller.verifyEverything() },
                onCheckSystemSecurity = {
                    if (publishedCheck != PublishedCheck.Checking) {
                        publishedCheck = PublishedCheck.Checking
                        scope.launch { publishedCheck = checkPublishedSystemPatchLevel(context) }
                    }
                },
                onAddRecoverySlot = controller::addRecoverySlot,
                onChangePassword = controller::changePassword,
                onToggleAppLock = controller::toggleAppLock,
                onSetAutoLock = controller::setAutoLock,
                onDeviceControl = { deviceControl.start() },
                onAddQuickSettingsLock = {
                    if (!quickSettingsLockBusy && quickSettingsLock != null) {
                        quickSettingsLockBusy = true
                        quickSettingsLockMessage = null
                        quickSettingsLock.request { message ->
                            quickSettingsLockBusy = false
                            quickSettingsLockMessage = message
                        }
                    }
                },
                onPrepareDevicePairing = { controller.prepareDevicePairing() },
                onInspectDevicePairing = { controller.inspectDevicePairing(it) },
                onApproveDevicePairing = controller::approveDevicePairing,
                onSavePairingApproval = pairingFiles.save,
                onOpenPairingApproval = pairingFiles.open,
                onLoadPairedDevices = controller::loadPairedDevices,
                onRevokePairedDevice = controller::revokePairedDevice,
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
                onAddDeviceSlot = controller::enrollDeviceSlot,
                onToggleDeviceSlotPolicy = controller::toggleDeviceSlotPolicy,
                onListenPeer = { address -> localNetwork { controller.listenForPeer(address) } },
                onConnectPeer = { invitation -> localNetwork { controller.connectToPeer(invitation) } },
                onStopPeer = controller::stopPeerSync,
            ),
            systemBack = { enabled, onBack -> BackHandler(enabled = enabled, onBack = onBack) },
        )
    }

    viewing?.let { projection ->
        ViewerRoute(
            controller = controller,
            operation = operation,
            notice = notice,
            cache = cache,
            generation = generation,
            projection = projection,
            pages = viewerPages(page.objects, projection),
            thumbnails = viewerThumbnails,
            canLoadMore = page.nextCursor != null,
            onSettled = { viewing = it },
            trashOpen = trashOpen,
            onBack = { viewing = null },
            // Delete, restore and permanent delete reload the current query
            // themselves, and a second load would empty the page first.
            onDeleted = { viewing = null },
        )
    }
}

private fun Set<String>.toggle(id: String): Set<String> =
    if (id in this) this - id else this + id

/**
 * The viewer, `DESIGN.md` §13.
 *
 * The thumbnail the grid already decoded shows at once, and `viewerStill`
 * replaces it with the sharpest still the object has: the screen preview, or
 * for a photograph that never needed one the decoded original, which §8 of
 * the media pipeline permits for detailed viewing and which is small enough
 * to be its own preview.
 *
 * A swipe moves through [pages], §13.1, and this route follows it:
 * [projection] is the item on screen, and its detail, its still, its player
 * and its dialogs are keyed to it, so they are made once, for that item, and
 * not for each page a swipe passes.
 */
@Composable
private fun ViewerRoute(
    controller: ChurController,
    operation: ActiveOperation?,
    notice: Notice?,
    cache: ThumbnailCache,
    generation: Long,
    projection: ObjectProjection,
    pages: List<ObjectProjection>,
    thumbnails: Map<String, ImageBitmap>,
    canLoadMore: Boolean,
    onSettled: (ObjectProjection) -> Unit,
    trashOpen: Boolean,
    onBack: () -> Unit,
    onDeleted: () -> Unit,
) {
    var detail by remember(projection.id) { mutableStateOf<ObjectDetail?>(null) }
    var favorite by remember(projection.id) { mutableStateOf(projection.favorite) }
    val tags by controller.tags.collectAsState()
    var choosingTags by remember(projection.id) { mutableStateOf(false) }
    val viewerScope = rememberCoroutineScope()
    var preview by remember(projection.id, generation) { mutableStateOf<ImageBitmap?>(null) }
    var stillState by remember(projection.id, generation) { mutableStateOf(ViewerStillState.Loading) }
    var showDetail by remember(projection.id) { mutableStateOf(false) }
    var waveform by remember(projection.id) { mutableStateOf<ByteArray?>(null) }
    var confirmingDelete by remember(projection.id) { mutableStateOf(false) }
    var choosingExport by remember(projection.id) { mutableStateOf(false) }
    var livePlayback by remember(projection.id, generation) {
        mutableStateOf<dev.po4yka.chur.app.vault.PlaybackSource?>(null)
    }
    var pendingLiveRestore by remember(projection.id, generation) { mutableStateOf<ByteArray?>(null) }
    // The viewer is drawn over the shell, not a back-stack entry, so Back is
    // routed to its own Back here; a press that reached the shell would act
    // on the screen under it, and one that reached the platform would go
    // home and lock.
    BackHandler(onBack = onBack)
    // Registered after the viewer's handler, so it answers first: Back closes
    // the Info overlay before it closes the viewer. The overlay is drawn only
    // once the detail has loaded.
    BackHandler(enabled = showDetail && detail != null) { showDetail = false }
    // §6.2: the viewer's canvas is black in both themes, so the system bars
    // draw light icons over it while it is shown and get the theme's choice
    // back when it goes, whether Back, a delete, or a lock ends it. The
    // activity handles rotation and theme changes itself, and edge-to-edge
    // then reapplies the theme's icons, so the effect runs again on every
    // configuration and restores from the theme now in force rather than
    // from a value saved under the old one.
    val window = LocalActivity.current?.window
    val configuration = LocalConfiguration.current
    DisposableEffect(window, configuration) {
        val bars = window?.let { WindowCompat.getInsetsController(it, it.decorView) }
        bars?.isAppearanceLightStatusBars = false
        bars?.isAppearanceLightNavigationBars = false
        onDispose {
            // What `enableEdgeToEdge`'s automatic style picks: dark icons on
            // the light theme, light icons on the dark one.
            val night = window?.context?.resources?.configuration?.uiMode
                ?.and(Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES
            bars?.isAppearanceLightStatusBars = !night
            bars?.isAppearanceLightNavigationBars = !night
        }
    }
    val chrome = remember { ViewerChrome() }
    val chromePinned = projection.mediaKind == 4 || showDetail || choosingTags || choosingExport || confirmingDelete || operation != null
    val chromeVisible = chrome.visible(chromePinned)
    // §13.1: the system bars go with the chrome, so a tap leaves the media
    // alone on the screen. An edge swipe shows them for a moment without the
    // chrome, and they come back for good when the viewer goes.
    DisposableEffect(window, chromeVisible) {
        val bars = window?.let { WindowCompat.getInsetsController(it, it.decorView) }
        bars?.systemBarsBehavior = WindowInsetsControllerCompat.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE
        if (chromeVisible) {
            bars?.show(WindowInsetsCompat.Type.systemBars())
        } else {
            bars?.hide(WindowInsetsCompat.Type.systemBars())
        }
        onDispose { bars?.show(WindowInsetsCompat.Type.systemBars()) }
    }
    val context = LocalContext.current
    val liveRestorePicker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        val selected = pendingLiveRestore
        pendingLiveRestore = null
        if (selected != null && (controller.vaultState.value as? VaultState.Unlocked)?.generation == generation) {
            controller.endHostActivity()
            if (uri != null) controller.restoreLivePhoto(selected, uri.toString())
        }
    }
    DisposableEffect(projection.id, generation) {
        onDispose {
            if (pendingLiveRestore != null &&
                (controller.vaultState.value as? VaultState.Unlocked)?.generation == generation) {
                controller.endHostActivity()
            }
            pendingLiveRestore = null
        }
    }
    val filePicker = rememberLauncherForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        controller.endHostActivity()
        result.data?.data?.let { uri ->
            if (controller.vaultState.value is VaultState.Unlocked) {
                controller.export(projection.objectId, ExportTarget.FILES, uri.toString())
            } else {
                viewerScope.launch(Dispatchers.IO) { runCatching { DocumentsContract.deleteDocument(context.contentResolver, uri) } }
            }
        }
    }

    var zoomedPhoto by remember(projection.id, generation) { mutableStateOf(false) }
    val animation = rememberViewerAnimation(controller.vault, projection, generation, detail?.contentType)
    LaunchedEffect(projection.id, generation, zoomedPhoto) {
        // `ANDROID.md` §16: a preview before full-resolution ranges. The
        // cached thumbnail shows at once, and the sharper still comes last so
        // the detail does not wait for an original to decode.
        preview = cache.load(controller.vault, generation, projection.objectId, projection.id)
        if (projection.mediaKind == MEDIA_CLASS_AUDIO) {
            waveform = controller.derivativeOf(projection.objectId, StreamKind.AUDIO_WAVEFORM)
        }
        detail = controller.detailOf(projection.objectId)
        if (detail?.contentType == dev.po4yka.chur.imports.LivePhotoBundle.CONTENT_TYPE) {
            livePlayback = try {
                dev.po4yka.chur.app.vault.livePhotoPlaybackFor(
                    controller.vault, projection.objectId, onVerify = controller::verifyEverything)
            } catch (cancel: kotlinx.coroutines.CancellationException) { throw cancel
            } catch (_: Exception) { null }
        }
        viewerStill(controller.vault, cache, generation, projection,
            highResolution = zoomedPhoto && animation == null)?.let { preview = it }
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
            onVerify = controller::verifyEverything,
            onExport = { choosingExport = true },
        )
    }

    ViewerScreen(
        projection = projection.copy(favorite = favorite),
        pages = pages,
        thumbnails = thumbnails,
        canLoadMore = canLoadMore,
        onLoadMore = controller::loadNextPage,
        onSettled = onSettled,
        detail = detail,
        preview = preview,
        stillState = stillState,
        onVerifyStill = { controller.verifyEverything() },
        onZoomChanged = { zoomedPhoto = it },
        animation = animation,
        showDetail = showDetail,
        chromeVisible = chromeVisible,
        onToggleChrome = { chrome.toggle(chromePinned) },
        onTouch = chrome::touched,
        onBack = onBack,
        onLock = { controller.lock() },
        onPanic = { controller.panic() },
        onToggleFavorite = {
            val next = !favorite
            controller.setFavorite(projection.objectId, next) { favorite = next }
        },
        onEditTags = { controller.loadTags(); choosingTags = true },
        onExport = { choosingExport = true },
        onDelete = { confirmingDelete = true },
        trashOpen = trashOpen,
        onRestore = { controller.restoreAll(listOf(projection.objectId), onDeleted) },
        onToggleDetail = { showDetail = !showDetail },
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
                    onControlsVisibleChange = { chrome.follow(it, chromePinned) },
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
        onCancelOperation = controller::cancelActiveOperation,
        notice = notice,
        onNoticeShown = controller::consume,
    )
    if (choosingTags) {
        val selected = listOf(projection.objectId)
        val refresh: () -> Unit = { viewerScope.launch { detail = controller.detailOf(projection.objectId) } }
        TagPickerDialog(tags = tags,
            onAdd = { tag -> choosingTags = false; controller.setTagForAll(tag.tagId, selected, true, refresh) },
            onRemove = { tag -> choosingTags = false; controller.setTagForAll(tag.tagId, selected, false, refresh) },
            onCreate = { name -> choosingTags = false; controller.createTagWithObjects(name, selected, refresh) },
            onDismiss = { choosingTags = false })
    }
    if (confirmingDelete) {
        DeleteSelectionDialog(
            count = 1,
            permanent = trashOpen,
            onDelete = {
                confirmingDelete = false
                if (trashOpen) controller.permanentlyDeleteAll(listOf(projection.objectId), onDeleted)
                else controller.delete(projection.objectId, onDeleted)
            },
            onDismiss = { confirmingDelete = false },
        )
    }
    if (choosingExport) {
        ExportOptionsDialog(
            media = canSaveToPhotos(projection.mediaKind) &&
                detail?.contentType != dev.po4yka.chur.imports.LivePhotoBundle.CONTENT_TYPE,
            files = true,
            share = true,
            downloads = true,
            onChoose = { target ->
                choosingExport = false
                if (target == ExportTarget.FILES) {
                    controller.beginHostActivity()
                    filePicker.launch(Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                        addCategory(Intent.CATEGORY_OPENABLE)
                        type = detail?.contentType ?: "application/octet-stream"
                        putExtra(Intent.EXTRA_TITLE, detail?.filename?.ifBlank { "chur-export" } ?: "chur-export")
                    })
                } else {
                    controller.export(projection.objectId, target)
                }
            },
            onDismiss = { choosingExport = false },
            onRestoreLivePhoto = if (detail?.contentType == dev.po4yka.chur.imports.LivePhotoBundle.CONTENT_TYPE) {
                {
                    choosingExport = false
                    pendingLiveRestore = projection.objectId.copyOf()
                    controller.beginHostActivity()
                    try { liveRestorePicker.launch(null) } catch (_: Exception) {
                        pendingLiveRestore = null
                        controller.endHostActivity()
                        controller.report("The destination folder picker could not be opened.")
                    }
                }
            } else null,
        )
    }
}

/** The object identifiers the selection names, in the page's order. */
private fun selectedObjects(
    page: ObjectPage,
    selection: Set<String>,
): List<ByteArray> = page.objects.filter { it.id in selection }.map { it.objectId }
