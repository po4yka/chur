@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlinx.cinterop.BetaInteropApi::class)
package dev.po4yka.chur.app.notes

import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.*
import androidx.compose.ui.uikit.LocalUIViewController
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.usePinned
import kotlinx.coroutines.*
import platform.Foundation.*
import platform.UIKit.UIDocumentPickerViewController
import platform.UniformTypeIdentifiers.UTTypeData

@Composable
actual fun NoteBinaryImportAction(label: String, maxBytes: Int, enabled: Boolean,
    onPickerActive: (Boolean) -> Unit, onImported: (String, ByteArray) -> Unit, onFailure: () -> Unit) {
    val presenter = LocalUIViewController.current
    val scope = rememberCoroutineScope()
    val latestEnabled by rememberUpdatedState(enabled)
    val imported by rememberUpdatedState(onImported)
    val activity by rememberUpdatedState(onPickerActive)
    val failure by rememberUpdatedState(onFailure)
    val lease = remember { NotePickerActivityLease() }
    val presentation = remember { NotePickerPresentation() }
    var pending by remember { mutableStateOf(false) }
    var epoch by remember { mutableIntStateOf(0) }
    var alive by remember { mutableStateOf(true) }
    DisposableEffect(Unit) { onDispose { alive = false; presentation.clear(); lease.finish() } }
    DisposableEffect(enabled) {
        if (!enabled) { pending = false; presentation.clear(); lease.finish() }
        onDispose { epoch++ }
    }
    TextButton(enabled = enabled && !pending, onClick = {
        val ticket = epoch
        try {
            val picker = UIDocumentPickerViewController(forOpeningContentTypes = listOf(UTTypeData), asCopy = false)
            picker.allowsMultipleSelection = false
            val delegate = NotePickerDelegate { url ->
                val accepted = pending && alive && latestEnabled && ticket == epoch
                pending = false; presentation.clear(); lease.finish()
                if (accepted && url != null) scope.launch {
                    var bytes: ByteArray? = null
                    try {
                        withContext(Dispatchers.Default) { bytes = readNoteDocument(url, maxBytes) }
                        ensureActive()
                        if (alive && latestEnabled && ticket == epoch) {
                            val owned = bytes!!
                            imported(url.lastPathComponent ?: "attachment", owned)
                            bytes = null
                        }
                    } catch (cancelled: CancellationException) { throw cancelled
                    } catch (_: Exception) { if (alive && latestEnabled && ticket == epoch) failure()
                    } finally { bytes?.fill(0) }
                }
            }
            pending = true; lease.begin { activity(it) }
            presentation.show(presenter, picker, delegate)
        } catch (_: Exception) { pending = false; presentation.clear(); lease.finish(); failure() }
    }) { Text(label) }
}

@Composable
actual fun PublicNoteBinaryExportAction(filename: String, mimeType: String, enabled: Boolean,
    label: String, load: suspend () -> ByteArray, onFailure: () -> Unit) {
    val presenter = LocalUIViewController.current
    val scope = rememberCoroutineScope()
    val latestEnabled by rememberUpdatedState(enabled)
    val loader by rememberUpdatedState(load)
    val failure by rememberUpdatedState(onFailure)
    val presentation = remember { NotePickerPresentation() }
    var alive by remember { mutableStateOf(true) }
    var pending by remember { mutableStateOf(false) }
    DisposableEffect(Unit) { onDispose { alive = false; presentation.clear() } }
    TextButton(enabled = enabled && !pending, onClick = {
        pending = true
        val directory = NSTemporaryDirectory() + "chur-public-note-" + NSUUID().UUIDString
        scope.launch {
            var bytes: ByteArray? = null
            try {
                dev.po4yka.chur.notes.NoteAttachments.validateName(filename)
                bytes = loader()
                presentation.temporaryDirectory = directory
                val path = "$directory/$filename"
                withContext(Dispatchers.Default) {
                    check(NSFileManager.defaultManager.createDirectoryAtPath(directory, true, null, null))
                    val data = if (bytes!!.isEmpty()) NSData() else bytes!!.usePinned {
                        NSData.create(bytes = it.addressOf(0), length = bytes!!.size.toULong())
                    }
                    check(data.writeToFile(path, atomically = true))
                }
                ensureActive()
                check(alive && latestEnabled)
                val picker = UIDocumentPickerViewController(forExportingURLs = listOf(NSURL.fileURLWithPath(path)), asCopy = true)
                val delegate = NotePickerDelegate { _ -> pending = false; presentation.clear() }
                presentation.show(presenter, picker, delegate)
            } catch (cancelled: CancellationException) {
                presentation.clear(); NSFileManager.defaultManager.removeItemAtPath(directory, null); throw cancelled
            } catch (_: Exception) {
                presentation.clear(); NSFileManager.defaultManager.removeItemAtPath(directory, null)
                pending = false; if (alive && latestEnabled) failure()
            } finally { bytes?.fill(0) }
        }
    }) { Text(label) }
}
