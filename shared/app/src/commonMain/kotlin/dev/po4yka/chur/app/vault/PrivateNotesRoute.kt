package dev.po4yka.chur.app.vault

import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import dev.po4yka.chur.app.ActiveOperation
import dev.po4yka.chur.app.ChurController
import dev.po4yka.chur.app.LockDrafts
import dev.po4yka.chur.app.Notice
import dev.po4yka.chur.app.PrivateNotesController
import dev.po4yka.chur.ffi.PrivateNote
import dev.po4yka.chur.ffi.PrivateNoteSelection
import dev.po4yka.chur.vault.VaultRepository
import dev.po4yka.chur.vault.VaultState

/** A separate unlocked surface. No public note store or saved-state registry is in this subtree. */
@Composable
fun PrivateNotesRoute(
    vault: VaultRepository,
    generation: Long,
    onClose: () -> Unit,
    onLock: () -> Unit,
    onPanic: () -> Unit,
    onTouch: () -> Unit,
    onExport: (PrivateNote) -> Unit,
    systemBack: @Composable (Boolean, () -> Unit) -> Unit,
    operation: ActiveOperation? = null,
    onCancelOperation: () -> Unit = {},
    notice: Notice? = null,
    onNoticeShown: (Long) -> Unit = {},
    onEncryptedExport: (List<PrivateNoteSelection>) -> Unit = {},
    initialCreateRequest: Long? = null,
    onNavigationBusyChange: (Boolean) -> Unit = {},
    onImportActivity: (Boolean) -> Unit = {},
    onAttachmentExport: (PrivateNote, dev.po4yka.chur.ffi.PrivateNoteAttachment) -> Unit = { _, _ -> },
    lockOwner: ChurController? = null,
) {
    val scope = rememberCoroutineScope()
    val close by rememberUpdatedState(onClose)
    val export by rememberUpdatedState(onExport)
    val touch by rememberUpdatedState(onTouch)
    val encryptedExport by rememberUpdatedState(onEncryptedExport)
    val attachmentExport by rememberUpdatedState(onAttachmentExport)
    val controller = remember(vault, generation) {
        PrivateNotesController(vault, generation, scope, { close() }, { export(it) }, { touch() }, { encryptedExport(it) }, { note, attachment -> attachmentExport(note, attachment) })
    }
    DisposableEffect(controller, lockOwner) {
        // An ordinary lock of [lockOwner] saves the open unsaved text before the session closes.
        val unregister = lockOwner?.lockDrafts?.register(LockDrafts.Source(controller::captureForLock))
        onDispose { unregister?.invoke(); controller.close() }
    }
    val session by vault.state.collectAsState()
    val state by controller.state.collectAsState()
    if ((session as? VaultState.Unlocked)?.generation != generation) return
    NavigationBusyEffect(state.editor != null || state.busy || state.selection.isNotEmpty() ||
        state.confirmation != null || state.filtersVisible, onNavigationBusyChange)
    LaunchedEffect(controller, initialCreateRequest) {
        controller.recoverDraft()
        if (initialCreateRequest != null) controller.create()
    }
    systemBack(true, controller::back)
    Box(Modifier.fillMaxSize().pointerInput(Unit) {
        awaitEachGesture {
            awaitFirstDown(requireUnconsumed = false, pass = PointerEventPass.Initial)
            touch()
        }
    }) {
        PrivateNotesScreen(state, controller, onLock, onPanic, operation, onCancelOperation, notice, onNoticeShown, onImportActivity)
    }
}
