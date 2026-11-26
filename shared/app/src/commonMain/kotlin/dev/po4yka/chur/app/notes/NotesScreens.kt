package dev.po4yka.chur.app.notes

import dev.po4yka.chur.app.ExcludeWindowFromCapture
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.ImeAction
import dev.po4yka.chur.app.publicshell.utilityText
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.ime
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.Saver
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import dev.po4yka.chur.app.theme.BackGlyph
import dev.po4yka.chur.app.theme.ChurSpacing
import dev.po4yka.chur.app.theme.DestructiveButton
import dev.po4yka.chur.app.theme.PlusGlyph
import dev.po4yka.chur.app.theme.SettingsGlyph
import dev.po4yka.chur.app.theme.LocalChurColors
import dev.po4yka.chur.app.theme.churOutlinedTextFieldColors
import dev.po4yka.chur.notes.Note
import dev.po4yka.chur.notes.NoteFormat
import dev.po4yka.chur.notes.NoteAttachment
import dev.po4yka.chur.notes.NoteAttachments
import dev.po4yka.chur.notes.Notes
import dev.po4yka.chur.notes.NoteOrganization
import dev.po4yka.chur.notes.NoteRevision
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart

/**
 * The public Notes shell, `DESIGN.md` §19.
 *
 * It is a real application, because a shell nobody would use announces what it
 * hides. It reaches nothing private: this file imports `:shared:feature-notes`
 * and no vault type at all, which the module graph also enforces.
 *
 * The route to the vault is the visible settings entry `PROVISIONING.md` §2
 * requires and that v1 cannot remove. It is a plain row, not a secret.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NotesScreen(
    notes: List<Note>,
    query: String,
    onQueryChange: (String) -> Unit,
    onSubmitSearch: () -> Unit = {},
    onBulkAction: suspend (List<Note>, Boolean?) -> Unit = { _, _ -> },
    onOpen: (Note) -> Unit,
    onCreate: () -> Unit,
    onOpenSettings: () -> Unit,
    showFirstWriteDisclosure: Boolean = false,
    onAcknowledgeDisclosure: () -> Unit = {},
    onImport: (String, String) -> Unit = { _, _ -> },
    onImportPackage: suspend (ByteArray) -> Unit = { error("package import unavailable") },
    trashedNotes: List<Note> = emptyList(),
    onRefreshTrash: () -> Unit = {},
    onRestore: suspend (String) -> Unit = { error("restore unavailable") },
    onPurge: suspend (String) -> Unit = { error("purge unavailable") },
) {
    val scope = rememberCoroutineScope()
    var tools by remember { mutableStateOf(false) }
    var selecting by remember { mutableStateOf(false) }
    var selection by remember { mutableStateOf(setOf<String>()) }
    var packageBusy by remember { mutableStateOf(false) }
    var packageFailed by remember { mutableStateOf(false) }
    var importFailed by remember { mutableStateOf(false) }
    var trash by remember { mutableStateOf(false) }
    var filters by remember { mutableStateOf(false) }
    var folder by remember { mutableStateOf("") }
    var tag by remember { mutableStateOf("") }
    var pendingPurge by remember { mutableStateOf<Note?>(null) }
    if (filters) AlertDialog(onDismissRequest = { filters = false },
        title = { ExcludeWindowFromCapture(); Text(utilityText("Folders and tags", "Папки и теги")) },
        text = { Column(Modifier.heightIn(max = 360.dp).verticalScroll(rememberScrollState())) {
            NoteFilterFields(folder, tag, !packageBusy, onApply = { f, t -> folder = f; tag = t; filters = false })
        } },
        confirmButton = { TextButton(onClick = { filters = false }) { Text(utilityText("Close", "Закрыть")) } })

    pendingPurge?.let { note -> AlertDialog(onDismissRequest = { pendingPurge = null },
        title = { ExcludeWindowFromCapture(); Text(utilityText("Delete this note permanently?", "Удалить заметку навсегда?")) },
        text = { Text(utilityText("The note, its retained versions and all their files will be removed. You cannot undo this.", "Заметка, её версии и вложения будут удалены. Это действие нельзя отменить.")) },
        confirmButton = { TextButton(enabled = !packageBusy, onClick = {
            packageBusy = true
            scope.launch { try { onPurge(note.id); pendingPurge = null; packageFailed = false
            } catch (cancelled: CancellationException) { throw cancelled
            } catch (_: Exception) { packageFailed = true
            } finally { packageBusy = false } }
        }) { Text(utilityText("Delete permanently", "Удалить навсегда")) } },
        dismissButton = { TextButton(onClick = { pendingPurge = null }) { Text(utilityText("Cancel", "Отмена")) } }) }
                if (tools) ModalBottomSheet(onDismissRequest = { tools = false }) {
                Column(Modifier.heightIn(max = 400.dp).verticalScroll(rememberScrollState()).padding(16.dp)) {
                    NoteImportAction(onImported = onImport, onFailure = { importFailed = true })
                    TextButton(onClick = { selecting = !selecting; selection = emptySet(); tools = false }) { Text(utilityText("Select notes", "Выбрать заметки")) }
                    Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())) {
                    NoteBinaryImportAction("Import note package", NoteAttachments.MAX_PACKAGE_BYTES, enabled = !packageBusy,
                        onImported = { _, bytes ->
                            packageBusy = true
                            scope.launch(start = CoroutineStart.UNDISPATCHED) {
                                try {
                                    onImportPackage(bytes)
                                    packageFailed = false
                                } catch (cancelled: CancellationException) { throw cancelled
                                } catch (_: Exception) { packageFailed = true
                                } finally { bytes.fill(0); packageBusy = false }
                            }
                        }, onFailure = { packageFailed = true })
                    if (packageBusy) Text(utilityText("Importing…", "Импорт…"))
                }
                }
                }
    val colors = LocalChurColors.current
    Scaffold(
        containerColor = colors.canvas,
        topBar = {
            TopAppBar(
                title = { Text(utilityText("Notes", "Заметки")) },
                actions = {
                    TextButton(onClick = { tools = !tools }) { Text(utilityText("More", "Ещё")) }
                    IconButton(onClick = onOpenSettings) {
                        Icon(SettingsGlyph, contentDescription = utilityText("Settings", "Настройки"))
                    }
                },
            )
        },
        floatingActionButton = {
            if (!trash && notes.isNotEmpty()) {
                FloatingActionButton(onClick = onCreate) {
                    Icon(PlusGlyph, contentDescription = utilityText("New note", "Новая заметка"))
                }
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            Column(modifier = Modifier.fillMaxSize()) {
                FlowRow {
                    TextButton(enabled = !packageBusy, onClick = { trash = !trash; if (trash) onRefreshTrash() }) {
                        Text(if (trash) utilityText("Active notes", "Заметки") else utilityText("Trash", "Корзина"))
                    }
                    TextButton(enabled = !packageBusy && !filters, onClick = { filters = true }) { Text(utilityText("Folders and tags", "Папки и теги")) }
                }
                NoteFilterSummary(folder, tag, !packageBusy && !filters) { folder = ""; tag = "" }
                if (importFailed) Text("The Markdown file could not be imported. Use UTF-8 text up to 256 KiB.", color = colors.error)
                if (packageFailed) Text(utilityText("The action could not be completed. Check your notes and try again.", "Не удалось завершить действие. Проверьте заметки и повторите попытку."), color = colors.error)
                if (showFirstWriteDisclosure) {
                    FirstWriteDisclosure(onAcknowledge = onAcknowledgeDisclosure)
                }
                OutlinedTextField(value = query, onValueChange = onQueryChange, singleLine = true,
                    label = { Text(utilityText("Search notes", "Поиск заметок")) },
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(onSearch = { onSubmitSearch() }),
                    modifier = Modifier.fillMaxWidth().padding(horizontal = ChurSpacing.gutter),
                    colors = churOutlinedTextFieldColors())
                val source = if (trash) trashedNotes else notes
                val visible = NoteOrganization.filter(Notes.search(source, query), folder.takeIf { it.isNotEmpty() }, tag.takeIf { it.isNotEmpty() })
                if (selecting && !trash) {
                    val selectedNotes = visible.filter { it.id in selection }
                    FlowRow {
                        TextButton(onClick = { selection = visible.map { it.id }.toSet() }) { Text(utilityText("Select all", "Выбрать все")) }
                        listOf(true to "Pin", false to "Unpin", null to "Trash").forEach { (pin, label) ->
                            TextButton(enabled = selectedNotes.isNotEmpty() && !packageBusy, onClick = {
                                packageBusy = true
                                scope.launch {
                                    try { onBulkAction(selectedNotes, pin); selection = emptySet(); selecting = false; packageFailed = false }
                                    catch (cancelled: CancellationException) { throw cancelled }
                                    catch (_: Exception) { packageFailed = true }
                                    finally { packageBusy = false }
                                }
                            }) { Text(label) }
                        }
                        TextButton(onClick = { selecting = false; selection = emptySet() }) { Text(utilityText("Done", "Готово")) }
                    }
                }
                if (source.isEmpty() && !trash) {
                    EmptyNotes(hasQuery = false, onCreate = {
                        onQueryChange("")
                        onCreate()
                    })
                } else {
                    if (visible.isEmpty()) {
                        if (trash) Text(utilityText("Trash is empty or no notes match these filters.", "Корзина пуста или нет заметок по этим фильтрам."), modifier = Modifier.padding(ChurSpacing.gutter))
                        else EmptyNotes(hasQuery = true)
                    } else {
                        LazyColumn(
                            contentPadding = androidx.compose.foundation.layout.PaddingValues(
                                horizontal = ChurSpacing.gutter,
                                vertical = ChurSpacing.two,
                            ),
                            verticalArrangement = Arrangement.spacedBy(ChurSpacing.two),
                        ) {
                            items(visible, key = { it.id }) { note ->
                                if (!trash) Row(verticalAlignment = Alignment.CenterVertically) {
                                    if (selecting) Checkbox(note.id in selection, onCheckedChange = { selected -> selection = if (selected) selection + note.id else selection - note.id })
                                    Box(Modifier.weight(1f)) { NoteRow(note = note, onClick = {
                                        if (selecting) selection = if (note.id in selection) selection - note.id else selection + note.id else onOpen(note)
                                    }, onLongClick = { selecting = true; selection = selection + note.id }) }
                                }
                                else Card(Modifier.fillMaxWidth()) { Column(Modifier.padding(ChurSpacing.two)) {
                                    Text(note.displayTitle.ifBlank { "Untitled" })
                                    Text(note.preview, maxLines = 2, overflow = TextOverflow.Ellipsis)
                                    Row {
                                        TextButton(enabled = !packageBusy, onClick = {
                                            packageBusy = true
                                            scope.launch { try { onRestore(note.id); packageFailed = false
                                            } catch (cancelled: CancellationException) { throw cancelled
                                            } catch (_: Exception) { packageFailed = true
                                            } finally { packageBusy = false } }
                                        }) { Text(utilityText("Restore note", "Восстановить")) }
                                        TextButton(enabled = !packageBusy, onClick = { pendingPurge = note }) { Text(utilityText("Delete permanently", "Удалить навсегда")) }
                                    }
                                } }
                            }
                        }
                    }
                }
            }

        }
    }
}

/**
 * The statement `DISCREET_MODE.md` requires on the first public-shell write.
 *
 * It is shown once and dismissed by acknowledgement rather than by time, so a
 * user who writes a note and closes the application has still been told. The
 * copy names the vault as the protected alternative and claims nothing for the
 * shell, which that section forbids: a disclosure presented as a feature is not
 * a disclosure.
 */
@Composable
private fun FirstWriteDisclosure(onAcknowledge: () -> Unit) {
    val colors = LocalChurColors.current
    Card(modifier = Modifier.fillMaxWidth().padding(ChurSpacing.gutter)) {
        Column(
            modifier = Modifier.padding(ChurSpacing.three),
            verticalArrangement = Arrangement.spacedBy(ChurSpacing.two),
        ) {
            Text(
                text = utilityText(Disclosure.FIRST_WRITE, "Заметки не зашифрованы приложением. Их может читать любой, у кого есть доступ к разблокированному устройству. Они входят в системную резервную копию."),
                style = MaterialTheme.typography.bodyMedium,
                color = colors.ink,
            )
            TextButton(
                onClick = onAcknowledge,
                modifier = Modifier.align(Alignment.End),
            ) {
                Text(utilityText("Got it", "Понятно"))
            }
        }
    }
}

@Composable
private fun NoteRow(note: Note, onClick: () -> Unit, onLongClick: () -> Unit) {
    val colors = LocalChurColors.current
    Card(modifier = Modifier.fillMaxWidth().combinedClickable(onClick = onClick, onLongClick = onLongClick, onLongClickLabel = utilityText("Select note", "Выбрать заметку"))) {
        Column(modifier = Modifier.padding(ChurSpacing.three)) {
            Text(
                text = note.displayTitle.ifBlank { "Untitled" },
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            if (note.preview.isNotBlank()) {
                Text(
                    text = note.preview,
                    style = MaterialTheme.typography.bodyMedium,
                    color = colors.inkMuted,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (note.pinned) Text(utilityText("Pinned", "Закреплено"), style = MaterialTheme.typography.labelSmall)
            note.folder?.let { Text("Folder: $it", style = MaterialTheme.typography.labelSmall) }
            if (note.tags.isNotEmpty()) Text(note.tags.joinToString(" · ") { "#$it" }, style = MaterialTheme.typography.labelSmall)
            if (note.attachments.isNotEmpty()) Text("${note.attachments.size} attachments", style = MaterialTheme.typography.labelSmall)
        }
    }
}

/**
 * The empty state.
 *
 * §21 of `DESIGN.md` keeps an empty state neutral, and §6.3 keeps it out of the
 * semantic colours: nothing has gone wrong.
 */
@Composable
private fun EmptyNotes(hasQuery: Boolean, onCreate: (() -> Unit)? = null) {
    val colors = LocalChurColors.current
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(ChurSpacing.two),
            modifier = Modifier.padding(ChurSpacing.gutterExpanded),
        ) {
            Text(
                text = if (hasQuery) utilityText("No notes match", "Заметки не найдены") else utilityText("No notes yet", "Пока нет заметок"),
                style = MaterialTheme.typography.titleMedium,
            )
            Text(
                text = if (hasQuery) {
                    "Try a different word."
                } else {
                    // "Notes stay on this device" read as a privacy
                    // assurance for content `DISCREET_MODE.md` requires be
                    // disclosed as unprotected and platform-backed-up.
                    utilityText(Disclosure.EMPTY_STATE, "Запишите что-нибудь.")
                },
                style = MaterialTheme.typography.bodyMedium,
                color = colors.inkMuted,
            )
            onCreate?.let { Button(onClick = it) { Text(utilityText("Create note", "Создать заметку")) } }
        }
    }
}

/**
 * The note editor, §10.2's "folders/list/editor".
 *
 * It saves as the user writes rather than on the way out. `DISCREET_MODE.md`
 * requires a public shell that is "functional rather than a static decoy
 * screen" and "usable after process restart without opening a vault", and a
 * notes editor that drops what was typed is neither. A save on the arrow and on
 * system Back alone missed every other way out: the whole-app gate taking the
 * route on a background, an activity recreated for a font or locale change,
 * and a process the platform reclaimed each dropped what had been typed. The
 * draft is now written after a pause in typing and again when the editor
 * leaves composition, whatever took it away, and the text is saved state, so a
 * recreation brings the editor back as it was; [rememberOpenNote] says how the
 * two are restored together. [rememberNoteDraft] holds the text and makes the
 * writes.
 *
 * Which of those writes is a change is the controller's to decide against the
 * store, not this screen's against the note it opened with: text typed and then
 * typed back to what it was has still been saved once in between. The one
 * exception is a note that "Create note" made, [OpenNote.isNew], and that is
 * blank when the editor leaves. The controller cannot tell it from a stored
 * note the user emptied, which stays, so this screen removes it through
 * [onRemove]: "Create note", a word, and the word erased leave no empty
 * "Untitled" row. Only leaving removes it, never the autosave, and never a
 * note the store held when the editor opened, so opening a note the user
 * emptied earlier leaves it where it is.
 *
 * Trash asks first and persists the latest text before moving the saved note.
 * Permanent deletion is available separately from the public Trash list. The question is saved state, so a
 * rotation keeps it open. Confirming clears the draft, so the save on leaving
 * has nothing to write back into the note it has just removed.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NoteEditorScreen(open: OpenNote, onSave: (Note) -> Unit, onRemove: (String) -> Unit, onBack: () -> Unit,
    onOpenSettings: () -> Unit,
    showFirstWriteDisclosure: Boolean = false,
    onAcknowledgeDisclosure: () -> Unit = {},
    savedNote: Note? = null, writeFailed: Boolean = false,
    onAddAttachment: suspend (Note, String, ByteArray) -> NoteAttachment = { _, _, _ -> error("attachments unavailable") },
    onReadAttachment: suspend (String) -> ByteArray = { error("attachments unavailable") },
    onRemoveAttachment: suspend (String) -> Unit = { error("attachments unavailable") },
    onExportPackage: suspend (Note) -> ByteArray = { error("package export unavailable") },
    onOrganize: suspend (String?, List<String>) -> Unit = { _, _ -> error("organization unavailable") },
    onHistory: suspend () -> List<NoteRevision> = { error("history unavailable") },
    onRestoreRevision: suspend (String) -> Note = { error("history restore unavailable") },
    onTrash: suspend (Note) -> Unit = { error("trash unavailable") },
    systemBack: @Composable (onBack: () -> Unit) -> Unit = {}) {
    var pinned by rememberSaveable(open.note.id) { mutableStateOf(open.note.pinned) }
    var formatName by rememberSaveable(open.note.id) { mutableStateOf(open.note.format.name) }
    val format = NoteFormat.valueOf(formatName)
    val attachments = savedNote?.attachments ?: open.note.attachments
    var restoringHistory by remember { mutableStateOf(false) }
    val saveWithMetadata: (Note) -> Unit = {
        if (!restoringHistory) onSave(it.copy(pinned = pinned, format = NoteFormat.valueOf(formatName), attachments = attachments))
    }
    var draft by rememberNoteDraft(open, saveWithMetadata, onRemove, { attachments.isNotEmpty() })
    val scope = rememberCoroutineScope()
    var attachmentBusy by remember(open.note.id) { mutableStateOf(false) }
    var attachmentFailed by remember(open.note.id) { mutableStateOf(false) }
    var pendingRemoval by remember { mutableStateOf<String?>(null) }
    var history by remember { mutableStateOf<List<NoteRevision>?>(null) }
    var selectedVersion by remember { mutableStateOf<NoteRevision?>(null) }
    var restoreConfirm by remember { mutableStateOf(false) }
    val (title, body) = draft ?: run {
        LaunchedEffect(Unit) { onBack() }
        return
    }
    var exportFailed by remember { mutableStateOf(false) }
    var details by remember { mutableStateOf(false) }
    val exit = remember(open.note.id) { PublicNoteExitGuard() }
    fun currentDraftNote(): Note? = draft?.let { (currentTitle, currentBody) ->
        open.note.copy(title = currentTitle, body = currentBody, pinned = pinned,
            format = NoteFormat.valueOf(formatName), attachments = attachments,
            folder = savedNote?.folder, tags = savedNote?.tags.orEmpty(), revision = savedNote?.revision ?: open.note.revision)
    }
    val current = requireNotNull(currentDraftNote())
    var leavingForSettings by remember(open.note.id) { mutableStateOf(false) }
    val closeWithoutSave = { draft = null; if (leavingForSettings) onOpenSettings() else onBack() }
    fun requestLeave(settings: Boolean) {
        val latest = currentDraftNote() ?: return
        leavingForSettings = settings
        if (attachmentBusy) return
        if (open.isNew && latest.title.isBlank() && latest.body.isBlank() && latest.attachments.isEmpty()) {
            draft = null
            onRemove(open.note.id)
            closeWithoutSave()
        } else exit.request(latest, savedNote, onSave, closeWithoutSave)
    }
    val requestBack = { requestLeave(false) }
    systemBack(requestBack)
    LaunchedEffect(exit.requested, current, savedNote) { currentDraftNote()?.let { exit.acknowledge(it, savedNote, closeWithoutSave) } }
    LaunchedEffect(pinned, format) { currentDraftNote()?.let(onSave) }
    if (exit.requested) {
        AlertDialog(
            onDismissRequest = exit::keepEditing,
            title = { ExcludeWindowFromCapture(); Text(if (writeFailed) "Save failed" else "Saving note") },
            text = { Text(if (writeFailed) "Your draft is still here. Retry saving before leaving, or discard unsaved changes."
                else "The editor will close after this note has been saved.") },
            confirmButton = { TextButton(enabled = writeFailed, onClick = {
                currentDraftNote()?.let { exit.request(it, savedNote, onSave, closeWithoutSave) }
            }) { Text(if (writeFailed) "Retry" else "Saving…") } },
            dismissButton = { Row {
                TextButton(onClick = exit::keepEditing) { Text("Keep editing") }
                TextButton(onClick = { exit.discard(closeWithoutSave) }) { Text("Discard") }
            } },
        )
    }

    var confirmingDelete by rememberSaveable { mutableStateOf(false) }
    if (confirmingDelete) {
        AlertDialog(
            onDismissRequest = { confirmingDelete = false },
            title = { ExcludeWindowFromCapture(); Text("Move this note to Trash?") },
            text = { Text("You can restore the note and its retained versions from Trash.") },
            confirmButton = {
                DestructiveButton(enabled = !attachmentBusy, onClick = {
                    val latest = currentDraftNote() ?: return@DestructiveButton
                    attachmentBusy = true
                    scope.launch(start = CoroutineStart.UNDISPATCHED) {
                        try {
                            onTrash(latest)
                            confirmingDelete = false; draft = null; onBack()
                        } catch (cancelled: CancellationException) { throw cancelled
                        } catch (_: Exception) { attachmentFailed = true
                        } finally { attachmentBusy = false }
                    }
                }) { Text("Move to Trash") }
            },
            dismissButton = { TextButton(onClick = { confirmingDelete = false }) { Text(utilityText("Cancel", "Отмена")) } },
        )
    }

    history?.let { versions -> AlertDialog(onDismissRequest = { if (!attachmentBusy) history = null },
        title = { ExcludeWindowFromCapture(); Text(utilityText("Version history", "История версий")) },
        text = { LazyColumn(Modifier.height(360.dp)) {
            item { Text("Up to 20 previous versions and 64 MiB of historical files are retained. Restoring creates a new current version.") }
            if (versions.isEmpty()) item { Text("No previous versions yet.") }
            items(versions, key = { it.id }) { version ->
                TextButton(enabled = !attachmentBusy, onClick = { selectedVersion = version }) {
                    Text("Revision ${version.note.revision} · ${version.note.displayTitle.ifBlank { "Untitled" }} · ${version.note.attachments.size} files")
                }
            }
            selectedVersion?.let { version -> item {
                Text("Selected revision ${version.note.revision}", style = MaterialTheme.typography.titleSmall)
                Text(version.note.body.take(4000))
                if (version.note.body.length > 4000) Text("Preview shows the first 4000 characters. Restore includes the complete note and files.")
                Text("Folder: ${version.note.folder.orEmpty()} · ${version.note.tags.joinToString(", ")}")
                TextButton(enabled = !attachmentBusy, onClick = { restoreConfirm = true }) { Text("Restore this version") }
            } }
        } },
        confirmButton = { TextButton(enabled = !attachmentBusy, onClick = { history = null; selectedVersion = null }) { Text(utilityText("Close", "Закрыть")) } }) }
    if (restoreConfirm) AlertDialog(onDismissRequest = { if (!attachmentBusy) restoreConfirm = false },
        title = { ExcludeWindowFromCapture(); Text("Restore this version?") },
        text = { Text("Its text, folder, tags and files become current. The current version is retained within history limits.") },
        confirmButton = { TextButton(enabled = !attachmentBusy, onClick = {
            val version = selectedVersion ?: return@TextButton
            attachmentBusy = true; restoringHistory = true
            scope.launch(start = CoroutineStart.UNDISPATCHED) {
                try {
                    onRestoreRevision(version.id)
                    draft = null; history = null; restoreConfirm = false; onBack()
                } catch (cancelled: CancellationException) { throw cancelled
                } catch (_: Exception) { attachmentFailed = true
                } finally { attachmentBusy = false; restoringHistory = false }
            }
        }) { Text("Restore version") } },
        dismissButton = { TextButton(enabled = !attachmentBusy, onClick = { restoreConfirm = false }) { Text(utilityText("Cancel", "Отмена")) } })

    pendingRemoval?.let { id ->
        AlertDialog(onDismissRequest = { if (!attachmentBusy) pendingRemoval = null },
            title = { ExcludeWindowFromCapture(); Text("Remove this attachment?") },
            text = { Text("The file is removed from the current version. Earlier versions may retain it until history expires or the note is permanently deleted.") },
            confirmButton = { TextButton(enabled = !attachmentBusy, onClick = {
                attachmentBusy = true
                scope.launch(start = CoroutineStart.UNDISPATCHED) {
                    try { onRemoveAttachment(id); pendingRemoval = null; attachmentFailed = false
                    } catch (cancelled: CancellationException) { throw cancelled
                    } catch (_: Exception) { attachmentFailed = true
                    } finally { attachmentBusy = false }
                }
            }) { Text(utilityText("Remove", "Удалить")) } },
            dismissButton = { TextButton(enabled = !attachmentBusy, onClick = { pendingRemoval = null }) { Text(utilityText("Cancel", "Отмена")) } })
    }
    val colors = LocalChurColors.current
    Scaffold(
        containerColor = colors.canvas,
        topBar = {
            TopAppBar(
                title = { Text(utilityText("Note", "Заметка")) },
                navigationIcon = {
                    IconButton(enabled = !attachmentBusy, onClick = requestBack) {
                        Icon(BackGlyph, contentDescription = utilityText("Back", "Назад"))
                    }
                },
                actions = {
                    IconButton(enabled = !exit.requested && !attachmentBusy, onClick = { requestLeave(true) }) { Icon(SettingsGlyph, contentDescription = utilityText("Settings", "Настройки")) }
                    TextButton(onClick = { details = !details }) { Text(utilityText("More", "Ещё")) }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).verticalScroll(rememberScrollState()).padding(ChurSpacing.gutter),
            verticalArrangement = Arrangement.spacedBy(ChurSpacing.two),
        ) {
            if (showFirstWriteDisclosure) FirstWriteDisclosure(onAcknowledgeDisclosure)
            OutlinedTextField(
                value = title,
                onValueChange = { changed -> draft?.let { draft = changed to it.second } },
                enabled = !exit.requested && !attachmentBusy,
                singleLine = true,
                label = { Text(utilityText("Title", "Заголовок")) },
                modifier = Modifier.fillMaxWidth(),
                colors = churOutlinedTextFieldColors(),
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (details) Checkbox(pinned, onCheckedChange = { pinned = it }, enabled = !exit.requested && !attachmentBusy)
                if (details) Text(utilityText("Pinned", "Закреплено"))
                val saved = samePublicNoteContent(current, savedNote)
                Text(if (writeFailed) utilityText("Save failed", "Ошибка сохранения") else if (saved) utilityText("Saved", "Сохранено") else utilityText("Saving…", "Сохранение…"), modifier = Modifier.weight(1f))
                if (writeFailed) TextButton(onClick = { currentDraftNote()?.let(onSave) }) { Text(utilityText("Retry", "Повторить")) }
            }
            if (exportFailed) Text(utilityText("The file could not be exported. Try again.", "Не удалось экспортировать файл. Повторите попытку."), color = colors.error)
            MarkdownEditor(body, { changed -> draft?.let { draft = it.first to changed } }, format == NoteFormat.MARKDOWN,
                { formatName = if (it) NoteFormat.MARKDOWN.name else NoteFormat.PLAIN_TEXT.name }, Modifier.fillMaxWidth().height(400.dp), enabled = !exit.requested && !attachmentBusy,
                attachmentIds = attachments.map { it.id }.toSet(),
                readAttachment = { id ->
                    require(attachments.any { it.id == id }) { "attachment not found" }
                    onReadAttachment(id)
                })
            val clean = samePublicNoteContent(current, savedNote)
            if (details) {
            PublicNoteExportAction(title, body, format == NoteFormat.MARKDOWN, enabled = !exit.requested && !attachmentBusy, onFailure = { exportFailed = true })
            TextButton(enabled = !exit.requested && !attachmentBusy, onClick = { confirmingDelete = true }) { Text(utilityText("Trash", "Корзина")) }
            NoteOrganizationFields(savedNote?.folder.orEmpty(), savedNote?.tags.orEmpty(), clean && !attachmentBusy && !exit.requested,
                onApply = { folder, tags ->
                    attachmentBusy = true
                    scope.launch(start = CoroutineStart.UNDISPATCHED) {
                        try { onOrganize(folder.takeIf { it.isNotEmpty() }, tags); attachmentFailed = false
                        } catch (cancelled: CancellationException) { throw cancelled
                        } catch (_: Exception) { attachmentFailed = true
                        } finally { attachmentBusy = false }
                    }
                })
            TextButton(enabled = clean && !attachmentBusy && !exit.requested, onClick = {
                attachmentBusy = true
                scope.launch { try { history = onHistory(); selectedVersion = null; attachmentFailed = false
                } catch (cancelled: CancellationException) { throw cancelled
                } catch (_: Exception) { attachmentFailed = true
                } finally { attachmentBusy = false } }
            }) { Text(utilityText("Version history", "История версий")) }
            }
            TextButton(onClick = { details = !details }) { Text(utilityText(utilityText("Images and attachments", "Изображения и файлы"), "Изображения и файлы")) }
            if (details) {
            Text(utilityText("Images and attachments", "Изображения и файлы"), style = MaterialTheme.typography.titleMedium)

            Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())) {
                NoteBinaryImportAction("Add image or file", NoteAttachments.MAX_FILE_BYTES,
                    enabled = !exit.requested && !attachmentBusy && attachments.size < NoteAttachments.MAX_ATTACHMENTS,
                    onImported = { name, bytes ->
                        attachmentBusy = true
                        scope.launch(start = CoroutineStart.UNDISPATCHED) {
                            try {
                                val added = onAddAttachment(requireNotNull(currentDraftNote()), name, bytes)
                                draft?.takeIf { NoteFormat.valueOf(formatName) == NoteFormat.MARKDOWN }?.let { text ->
                                    val reference = attachmentMarkdownReference(added.name, added.id, added.mimeType.startsWith("image/"))
                                    draft = text.first to (text.second + if (text.second.isEmpty()) reference else "\n\n$reference")
                                }
                                attachmentFailed = false
                            } catch (cancelled: CancellationException) { throw cancelled
                            } catch (_: Exception) { attachmentFailed = true
                            } finally { bytes.fill(0); attachmentBusy = false }
                        }
                    }, onFailure = { attachmentFailed = true })
                PublicNoteBinaryExportAction(noteExportFilename(title, true).removeSuffix(".md") + ".churnote",
                    "application/vnd.chur.note+json", enabled = !exit.requested && !attachmentBusy,
                    label = "Export note package", load = { onExportPackage(requireNotNull(currentDraftNote())) },
                    onFailure = { attachmentFailed = true })
            }
            }
            if (attachmentBusy) Text(utilityText("Updating attachments…", "Обновление вложений…"))
            if (attachmentFailed) Text(utilityText("The attachment operation failed. Your note is still here. Try again.", "Не удалось обновить вложения. Заметка сохранена. Повторите попытку."), color = colors.error)
            attachments.forEach { attachment ->
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(ChurSpacing.two)) {
                        Text(attachment.name, style = MaterialTheme.typography.titleSmall)
                        Text("${attachment.sizeBytes} bytes · ${attachment.mimeType}", style = MaterialTheme.typography.bodySmall)
                        if (attachment.mimeType.startsWith("image/")) NoteAttachmentImage(attachment.id, attachment.name,
                            read = { onReadAttachment(attachment.id) })
                        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())) {
                            PublicNoteBinaryExportAction(attachment.name, attachment.mimeType,
                                enabled = !exit.requested && !attachmentBusy, load = { onReadAttachment(attachment.id) },
                                onFailure = { attachmentFailed = true })
                            TextButton(enabled = !exit.requested && !attachmentBusy, onClick = { pendingRemoval = attachment.id }) {
                                Text(utilityText("Remove attachment", "Удалить вложение"))
                            }
                        }
                    }
                }
            }
        }
    }
}

/** A close request is completed only by the store's acknowledgement of every edited field. */
internal class PublicNoteExitGuard {
    var requested: Boolean by mutableStateOf(false)
        private set

    fun request(current: Note, saved: Note?, onSave: (Note) -> Unit, onClose: () -> Unit) {
        if (samePublicNoteContent(current, saved)) {
            requested = false
            onClose()
        } else {
            requested = true
            onSave(current)
        }
    }

    fun acknowledge(current: Note, saved: Note?, onClose: () -> Unit) {
        if (requested && samePublicNoteContent(current, saved)) {
            requested = false
            onClose()
        }
    }

    fun keepEditing() { requested = false }
    fun discard(onClose: () -> Unit) { requested = false; onClose() }
}

internal fun samePublicNoteContent(current: Note, saved: Note?): Boolean =
    saved != null && current.copy(updatedMs = saved.updatedMs) == saved

/**
 * [NoteEditorScreen]'s text and the writes it makes, apart from its layout, so
 * a test can compose them without a window.
 *
 * The text is the note's title and body. It is null, and the editor closes
 * without a write, when there is no text to show: the draft was too long to
 * keep as saved state, [DRAFT_STATE_LIMIT]; saved state brought [open] back
 * without the draft, whose text [OpenNoteSaver] does not keep; or Delete has
 * removed the note. In each case the store has what was last written, and the
 * list opens the note again from there.
 *
 * The autosave writes the text [AUTOSAVE_DELAY_MS] after it last changed. When
 * this leaves composition it writes the text again, or, for a new note that is
 * blank, removes it. The removal waits for that moment: a pause while the
 * fields are empty is not the user leaving the note.
 */
@Composable
internal fun rememberNoteDraft(
    open: OpenNote,
    onSave: (Note) -> Unit,
    onRemove: (String) -> Unit,
    hasAttachments: () -> Boolean = { false },
): MutableState<Pair<String, String>?> {
    val note = open.note
    val draft = rememberSaveable(note.id, saver = DraftSaver) {
        // A restore that reaches this has lost the draft, and the restored
        // note's blank text is a placeholder, not the note's.
        mutableStateOf<Pair<String, String>?>(if (open.restored) null else note.title to note.body)
    }
    val save by rememberUpdatedState(onSave)
    val remove by rememberUpdatedState(onRemove)
    val attachmentsPresent by rememberUpdatedState(hasAttachments)
    val text = draft.value ?: return draft

    LaunchedEffect(text) {
        delay(AUTOSAVE_DELAY_MS)
        save(note.copy(title = text.first, body = text.second))
    }
    DisposableEffect(note.id) {
        onDispose {
            // Read now, so what is on screen as the editor leaves is written.
            val (title, body) = draft.value ?: return@onDispose
            if (open.isNew && title.isBlank() && body.isBlank() && !attachmentsPresent()) {
                remove(note.id)
            } else {
                save(note.copy(title = title, body = body))
            }
        }
    }
    return draft
}

/**
 * How long the editor waits after the last keystroke before it writes.
 *
 * Long enough that a word is one write rather than one per letter, because
 * `FileNoteStore` rewrites its whole file on every change; short enough that a
 * process the platform reclaims soon after the user stops typing has already
 * written.
 */
private const val AUTOSAVE_DELAY_MS = 500L

/**
 * The most text, title and body together, the editor keeps as saved state.
 *
 * ponytail: a longer draft is not saved state, because the Android saved-state
 * Bundle has a size ceiling that a note does not: past the binder's 1 MB
 * transaction limit, onStop throws TransactionTooLargeException, and Android's
 * guidance for saved state is under 50 KB, which 20,000 UTF-16 characters keep
 * to. Above it a recreation or a process restart closes the editor, and the
 * note opens again from the list, that is from the store, which has what the
 * autosave and the save on leaving last wrote. Keep drafts in the store by id
 * if long notes must reopen in the editor.
 */
internal const val DRAFT_STATE_LIMIT = 20_000

/**
 * [NoteEditorScreen]'s text as saved state: the title and body, or, over
 * [DRAFT_STATE_LIMIT], only that the draft was too long, which restores as
 * null.
 */
internal val DraftSaver: Saver<MutableState<Pair<String, String>?>, Any> = Saver(
    save = { draft ->
        draft.value?.takeIf { (title, body) -> title.length + body.length <= DRAFT_STATE_LIMIT }?.toList() ?: false
    },
    restore = { saved -> mutableStateOf((saved as? List<*>)?.let { it[0] as String to it[1] as String }) },
)

/**
 * A note open in [NoteEditorScreen].
 *
 * [isNew] marks a note that "Create note" made, which the store did not hold
 * when the editor opened. It stays set for the editor's whole session, also
 * after the autosave has stored the note, because such a note is the only one
 * the editor removes when it leaves it blank.
 *
 * [restored] marks a note that saved state brought back, [rememberOpenNote].
 * [OpenNoteSaver] keeps no text, so its title and body are blank placeholders
 * that the editor never reads: it takes its own saved draft, or closes.
 */
data class OpenNote(val note: Note, val isNew: Boolean, val restored: Boolean = false)

/**
 * The note the editor has open, kept across an activity recreation and a
 * process restart.
 *
 * `ANDROID.md` §6.3 and `IOS.md` §6.3 allow the public-shell route and public
 * notes state to be restored, and this is both: one public note, nothing from
 * the vault. Only the note's identity and [OpenNote.isNew] are saved, not its
 * text: [NoteEditorScreen] saves the draft, which is the text worth restoring,
 * and a second copy would double what the Bundle carries for nothing. The
 * restored note carries no text; the editor restores its own draft in its
 * place, or closes when that is missing or was too long to keep.
 *
 * On iOS the composition's registry is in memory and the host does not persist
 * it, so there it lasts as long as the view controller and a relaunch opens the
 * list.
 */
@Composable
fun rememberOpenNote(): MutableState<OpenNote?> =
    rememberSaveable(stateSaver = OpenNoteSaver) { mutableStateOf(null) }

internal val OpenNoteSaver: Saver<OpenNote?, Any> = Saver(
    save = { open -> open?.run { listOf(note.id, note.updatedMs, note.pinned, isNew, note.format.name, note.recoveryEpoch) } },
    restore = restoreNote@{ saved ->
        val fields = saved as? List<*> ?: return@restoreNote null
        if (fields.size != 6) return@restoreNote null
        val id = fields[0] as? String ?: return@restoreNote null
        val updatedMs = fields[1] as? Long ?: return@restoreNote null
        val pinned = fields[2] as? Boolean ?: return@restoreNote null
        val isNew = fields[3] as? Boolean ?: return@restoreNote null
        val format = NoteFormat.entries.firstOrNull { it.name == fields[4] } ?: return@restoreNote null
        val epoch = fields[5] as? Long ?: return@restoreNote null
        if (id.isBlank() || epoch < 0) return@restoreNote null
        OpenNote(Note(id, "", "", updatedMs, pinned, format, recoveryEpoch = epoch), isNew = isNew, restored = true)
    },
)
