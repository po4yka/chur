package dev.po4yka.chur.app

import dev.po4yka.chur.core.model.ChurStatus
import dev.po4yka.chur.ffi.ChurFailure
import dev.po4yka.chur.ffi.PrivateNote
import dev.po4yka.chur.ffi.PrivateNoteDraft
import dev.po4yka.chur.ffi.PrivateNoteAttachment
import dev.po4yka.chur.ffi.PrivateNoteAttachmentData
import dev.po4yka.chur.ffi.fromHex
import dev.po4yka.chur.notes.NoteAttachments
import dev.po4yka.chur.notes.NotePackages
import dev.po4yka.chur.notes.NoteFormat
import dev.po4yka.chur.app.notes.attachmentMarkdownReference
import kotlin.uuid.Uuid
import kotlinx.coroutines.CoroutineStart
import dev.po4yka.chur.ffi.PrivateNoteFormat
import dev.po4yka.chur.ffi.PrivateNoteAction
import dev.po4yka.chur.ffi.PrivateNotePage
import dev.po4yka.chur.ffi.PrivateNoteSelection
import dev.po4yka.chur.ffi.PrivateNoteSummary
import dev.po4yka.chur.ffi.PrivateNoteOrganization
import dev.po4yka.chur.ffi.PrivateNoteRevision
import dev.po4yka.chur.ffi.PrivateNoteRevisionDetail
import dev.po4yka.chur.ffi.PrivateNoteWorkspacePage
import dev.po4yka.chur.vault.VaultRepository
import dev.po4yka.chur.vault.VaultState
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

const val PRIVATE_NOTE_TITLE_MAX_BYTES = 256
const val PRIVATE_NOTE_BODY_MAX_BYTES = 262_144

/** No serializer or saver: this value exists only in its unlocked route. */
data class PrivateNoteEditorState(
    val saved: PrivateNote? = null,
    val title: String = saved?.title.orEmpty(),
    val body: String = saved?.body.orEmpty(),
    val pinned: Boolean = saved?.pinned ?: false,
    val format: PrivateNoteFormat = saved?.format ?: PrivateNoteFormat.MARKDOWN,
    val attachments: List<PrivateNoteAttachment> = emptyList(),
    val organization: PrivateNoteOrganization = PrivateNoteOrganization(),
) {
    val trashed: Boolean get() = saved?.trashedAtMs != null
    val dirty: Boolean get() = if (saved == null) title.isNotEmpty() || body.isNotEmpty() || pinned
        else title != saved.title || body != saved.body || pinned != saved.pinned || format != saved.format
    val canSave: Boolean get() = !trashed && dirty && (saved != null || title.isNotBlank() || body.isNotBlank())
    override fun toString(): String = "PrivateNoteEditorState(<redacted>)"
}

enum class PrivateNoteConfirmation { LEAVE, TRASH, PURGE, EXPORT, ENCRYPTED_EXPORT }

data class PrivateNotesUiState(
    val notes: List<PrivateNoteSummary> = emptyList(),
    val terms: String = "",
    val trash: Boolean = false,
    val loading: Boolean = false,
    val busy: Boolean = false,
    val editor: PrivateNoteEditorState? = null,
    val confirmation: PrivateNoteConfirmation? = null,
    val error: String? = null,
    val page: Int = 1,
    val hasPrevious: Boolean = false,
    val hasNext: Boolean = false,
    val selection: Map<String, PrivateNoteSelection> = emptyMap(),
    val folderFilter: String = "",
    val tagFilter: String = "",
    val filtersVisible: Boolean = false,
    val organization: Map<String, PrivateNoteOrganization> = emptyMap(),
    val history: List<PrivateNoteRevision>? = null,
    val historical: PrivateNoteRevisionDetail? = null,
) {
    override fun toString(): String = "PrivateNotesUiState(<redacted>)"
}

/** Every storage method must validate [generation] while holding the repository mutex. */
internal interface PrivateNotesAccess {
    suspend fun load(generation: Long, id: ByteArray): PrivateNote
    /** [proceed] is checked under the repository mutex just before the native call. */
    suspend fun save(generation: Long, saved: PrivateNote?, title: String, body: String, pinned: Boolean, format: PrivateNoteFormat, proceed: () -> Boolean = { true }): PrivateNote
    suspend fun readDraft(generation: Long): PrivateNoteDraft? = null
    suspend fun writeDraft(generation: Long, draft: PrivateNoteDraft?) {}
    suspend fun saveForLock(generation: Long, editor: PrivateNoteEditorState, proceed: () -> Boolean): PrivateNote =
        save(generation, editor.saved, editor.title, editor.body, editor.pinned, editor.format, proceed)
    suspend fun change(generation: Long, id: ByteArray, revision: Long, action: PrivateNoteAction): PrivateNote?
    suspend fun attachments(generation: Long, id: ByteArray): List<PrivateNoteAttachment>
    suspend fun readAttachment(generation: Long, id: ByteArray, attachmentId: ByteArray): ByteArray
    suspend fun putAttachment(generation: Long, saved: PrivateNote, attachment: PrivateNoteAttachmentData): PrivateNote
    suspend fun removeAttachment(generation: Long, saved: PrivateNote, attachmentId: ByteArray): PrivateNote
    suspend fun importPackage(generation: Long, title: String, body: String, format: PrivateNoteFormat, attachments: List<PrivateNoteAttachmentData>): PrivateNote
    suspend fun workspace(generation: Long, terms: String, trash: Boolean, cursor: ByteArray?, folder: String, tag: String): PrivateNoteWorkspacePage
    suspend fun organization(generation: Long, id: ByteArray): PrivateNoteOrganization
    suspend fun organize(generation: Long, saved: PrivateNote, organization: PrivateNoteOrganization): PrivateNote
    suspend fun history(generation: Long, id: ByteArray): List<PrivateNoteRevision>
    suspend fun historical(generation: Long, id: ByteArray, revision: Long): PrivateNoteRevisionDetail
    suspend fun restoreRevision(generation: Long, saved: PrivateNote, revision: Long): PrivateNote
}

private class VaultPrivateNotesAccess(private val vault: VaultRepository) : PrivateNotesAccess {
    override suspend fun workspace(generation: Long, terms: String, trash: Boolean, cursor: ByteArray?, folder: String, tag: String) =
        vault.privateNoteWorkspace(generation, terms, trash, 50, cursor, folder, tag)
    override suspend fun organization(generation: Long, id: ByteArray) = vault.privateNoteOrganization(generation, id)
    override suspend fun organize(generation: Long, saved: PrivateNote, organization: PrivateNoteOrganization) =
        vault.organizePrivateNote(generation, saved.noteId, saved.revision, organization)
    override suspend fun history(generation: Long, id: ByteArray) = vault.privateNoteHistory(generation, id)
    override suspend fun historical(generation: Long, id: ByteArray, revision: Long) = vault.privateNoteRevision(generation, id, revision)
    override suspend fun restoreRevision(generation: Long, saved: PrivateNote, revision: Long) =
        vault.restorePrivateNoteRevision(generation, saved.noteId, saved.revision, revision)
    override suspend fun readDraft(generation: Long) = vault.privateNoteDraft(generation)
    override suspend fun writeDraft(generation: Long, draft: PrivateNoteDraft?) = vault.writePrivateNoteDraft(generation, draft)
    override suspend fun saveForLock(generation: Long, editor: PrivateNoteEditorState, proceed: () -> Boolean) =
        vault.savePrivateNote(generation, id = editor.saved?.noteId, expectedRevision = editor.saved?.revision ?: 0,
            title = editor.title, body = editor.body, pinned = editor.pinned, format = editor.format, proceed = proceed, preserveDraft = true)
    override suspend fun load(generation: Long, id: ByteArray) = vault.privateNote(generation, id)
    override suspend fun save(generation: Long, saved: PrivateNote?, title: String, body: String, pinned: Boolean, format: PrivateNoteFormat, proceed: () -> Boolean) =
        vault.savePrivateNote(generation, id = saved?.noteId, expectedRevision = saved?.revision ?: 0,
            title = title, body = body, pinned = pinned, format = format, proceed = proceed)
    override suspend fun change(generation: Long, id: ByteArray, revision: Long, action: PrivateNoteAction) =
        if (action == PrivateNoteAction.TRASH) vault.trashPrivateNoteFromEditor(generation, id, revision)
        else vault.changePrivateNote(generation, id, revision, action)
    override suspend fun attachments(generation: Long, id: ByteArray) = vault.privateNoteAttachments(generation, id)
    override suspend fun readAttachment(generation: Long, id: ByteArray, attachmentId: ByteArray) = vault.readPrivateNoteAttachment(generation, id, attachmentId)
    override suspend fun putAttachment(generation: Long, saved: PrivateNote, attachment: PrivateNoteAttachmentData) =
        vault.putPrivateNoteAttachment(generation, saved.noteId, saved.revision, attachment)
    override suspend fun removeAttachment(generation: Long, saved: PrivateNote, attachmentId: ByteArray) =
        vault.removePrivateNoteAttachment(generation, saved.noteId, saved.revision, attachmentId)
    override suspend fun importPackage(generation: Long, title: String, body: String, format: PrivateNoteFormat, attachments: List<PrivateNoteAttachmentData>) =
        vault.importPrivateNotePackage(generation, title, body, format, attachments)
}

/**
 * Saves are explicit, with one exception: an ordinary lock saves unsaved text
 * as a new revision through [captureForLock] and [LockDrafts], with the same
 * expected-revision check. Panic, disposal, and identity change cancel work
 * and drop UI text; they never write. Native generation and revision guards
 * are the write boundary.
 */
class PrivateNotesController internal constructor(
    private val generation: Long,
    private val vaultState: StateFlow<VaultState>,
    private val access: PrivateNotesAccess,
    parentScope: CoroutineScope,
    private val onLeave: () -> Unit,
    private val onExport: (PrivateNote) -> Unit,
    private val dispatcher: CoroutineDispatcher,
    private val onActivity: () -> Unit = {},
    private val onEncryptedExport: (List<PrivateNoteSelection>) -> Unit = {},
    private val onAttachmentExport: (PrivateNote, PrivateNoteAttachment) -> Unit = { _, _ -> },
) : PrivateNotesActions {
    constructor(vault: VaultRepository, generation: Long, scope: CoroutineScope,
        onLeave: () -> Unit, onExport: (PrivateNote) -> Unit, onActivity: () -> Unit = {},
        onEncryptedExport: (List<PrivateNoteSelection>) -> Unit = {},
        onAttachmentExport: (PrivateNote, PrivateNoteAttachment) -> Unit = { _, _ -> }) :
        this(generation, vault.state, VaultPrivateNotesAccess(vault), scope, onLeave, onExport, Dispatchers.Default, onActivity, onEncryptedExport, onAttachmentExport)

    private val job = SupervisorJob(parentScope.coroutineContext[Job])
    private val scope = CoroutineScope(parentScope.coroutineContext + job)
    private val mutableState = MutableStateFlow(PrivateNotesUiState())
    val state: StateFlow<PrivateNotesUiState> = mutableState.asStateFlow()
    private var closed = false
    /** Set by [captureForLock]: the capture is the editor's last action. */
    private var lockCaptured = false
    private var request = 0L
    private var listing: Job? = null
    private var draftWrite: Job? = null
    private var cursor: ByteArray? = null
    private var nextCursor: ByteArray? = null
    private val previous = mutableListOf<ByteArray?>()

    init {
        scope.launch {
            vaultState.collect { if (!current()) close() }
        }
        refresh()
    }

    private fun current(): Boolean = !closed && !lockCaptured && (vaultState.value as? VaultState.Unlocked)?.generation == generation
    override fun activity() { if (current()) onActivity() }
    private fun update(change: (PrivateNotesUiState) -> PrivateNotesUiState) {
        if (current()) mutableState.value = change(mutableState.value)
    }

    fun close() {
        if (closed) return
        closed = true
        request++
        cursor = null
        nextCursor = null
        previous.clear()
        mutableState.value = PrivateNotesUiState()
        job.cancel()
    }

    override fun refresh() {
        update { it.copy(selection = emptyMap()) }
        loadPage(reset = true)
    }
    override fun search(terms: String) {
        if (!current() || state.value.editor != null || state.value.busy) return
        if (terms != state.value.terms) onActivity()
        if (utf8Size(terms) > 256 || terms.splitToSequence(Regex("\\s+")).count { it.isNotEmpty() } > 32) {
            update { it.copy(error = "Use at most 256 UTF-8 bytes and 32 words in the search.") }
            return
        }
        update { it.copy(terms = terms, error = null, selection = if (terms != it.terms) emptyMap() else it.selection) }
        loadPage(reset = true, debounce = true)
    }
    override fun showTrash(trash: Boolean) {
        if (!current() || state.value.editor != null || state.value.busy) return
        update { it.copy(trash = trash, terms = "", error = null, selection = emptyMap()) }
        loadPage(reset = true)
    }
    override fun showFilters(visible: Boolean) {
        if (!current() || state.value.editor != null || state.value.busy) return
        onActivity()
        update { it.copy(filtersVisible = visible) }
    }
    override fun filter(folder: String, tag: String) {
        if (!current() || state.value.editor != null || state.value.busy) return
        if (utf8Size(folder) > 64 || utf8Size(tag) > 64 || (folder + tag).any { it.isISOControl() }) {
            update { it.copy(error = "Folder and tag filters must fit in 64 UTF-8 bytes each.") }; return
        }
        onActivity()
        update { it.copy(folderFilter = folder.trim(), tagFilter = tag.trim(), filtersVisible = false, selection = emptyMap()) }
        loadPage(reset = true)
    }
    override fun organize(folder: String, tags: List<String>) {
        val editor = state.value.editor ?: return
        val saved = editor.saved ?: return
        if (editor.dirty || editor.trashed) return
        runAction {
            val organization = PrivateNoteOrganization(dev.po4yka.chur.notes.NoteOrganization.folder(folder).orEmpty(),
                dev.po4yka.chur.notes.NoteOrganization.tags(tags))
            val changed = withContext(dispatcher) { access.organize(generation, saved, organization) }
            val authoritative = withContext(dispatcher) { access.organization(generation, changed.noteId) }
            update { it.copy(editor = PrivateNoteEditorState(changed, attachments = editor.attachments, organization = authoritative), history = null, historical = null) }
        }
    }
    override fun showHistory() {
        val editor = state.value.editor ?: return
        val saved = editor.saved ?: return
        if (editor.dirty) return
        runAction {
            val history = withContext(dispatcher) { access.history(generation, saved.noteId) }
            update { it.copy(history = history, historical = null) }
        }
    }
    override fun previewRevision(revision: Long) {
        val saved = state.value.editor?.saved ?: return
        if (state.value.editor?.dirty != false || state.value.history?.none { it.revision == revision } != false) return
        runAction {
            val detail = withContext(dispatcher) { access.historical(generation, saved.noteId, revision) }
            update { it.copy(historical = detail) }
        }
    }
    override fun closeHistory() = update { it.copy(history = null, historical = null) }
    override fun restoreRevision() {
        val editor = state.value.editor ?: return
        val saved = editor.saved ?: return
        val historical = state.value.historical ?: return
        if (editor.dirty || editor.trashed) return
        runAction {
            val restored = withContext(dispatcher) { access.restoreRevision(generation, saved, historical.note.revision) }
            val attachments = withContext(dispatcher) { access.attachments(generation, restored.noteId) }
            val organization = withContext(dispatcher) { access.organization(generation, restored.noteId) }
            update { it.copy(editor = PrivateNoteEditorState(restored, attachments = attachments, organization = organization), history = null, historical = null) }
        }
    }
    override fun nextPage() {
        if (!current() || state.value.loading || nextCursor == null) return
        previous += cursor
        cursor = nextCursor?.copyOf()
        loadPage(reset = false)
    }
    override fun previousPage() {
        if (!current() || state.value.loading || previous.isEmpty()) return
        cursor = previous.removeAt(previous.lastIndex)
        loadPage(reset = false)
    }
    private fun loadPage(reset: Boolean, debounce: Boolean = false) {
        if (!current()) return
        listing?.cancel()
        if (reset) { cursor = null; nextCursor = null; previous.clear() }
        val revision = ++request
        val snapshot = state.value
        val pageCursor = cursor?.copyOf()
        update { it.copy(loading = true, error = null, notes = if (reset) emptyList() else it.notes,
            hasNext = false, hasPrevious = previous.isNotEmpty(), page = previous.size + 1) }
        listing = scope.launch {
            try {
                if (debounce) delay(200)
                val result = withContext(dispatcher) { access.workspace(generation, snapshot.terms, snapshot.trash, pageCursor,
                    snapshot.folderFilter, snapshot.tagFilter) }
                if (current() && request == revision) {
                    nextCursor = result.page.nextCursor?.copyOf()
                    update { it.copy(notes = result.page.notes, organization = result.organization, loading = false, hasNext = nextCursor != null) }
                }
            } catch (cancelled: CancellationException) { throw cancelled
            } catch (failure: Exception) {
                if (request == revision) update { it.copy(loading = false, error = errorCopy(failure)) }
            }
        }
    }

    suspend fun recoverDraft() {
        if (!current() || state.value.editor != null || state.value.busy) return
        update { it.copy(busy = true) }
        try {
            val recovered = withContext(dispatcher) {
                val draft = access.readDraft(generation) ?: return@withContext null
                val saved = draft.noteId?.let { id ->
                    try { access.load(generation, id) }
                    catch (failure: ChurFailure) {
                        if (failure.status == ChurStatus.NOT_FOUND) null else throw failure
                    }
                }
                if (saved != null && saved.trashedAtMs == null && saved.title == draft.title &&
                    saved.body == draft.body && saved.pinned == draft.pinned && saved.format == draft.format) {
                    access.writeDraft(generation, null)
                    return@withContext null
                }
                val base = saved?.takeIf { it.revision == draft.revision && it.trashedAtMs == null }
                PrivateNoteEditorState(
                    saved = base, title = draft.title, body = draft.body, pinned = draft.pinned, format = draft.format,
                    attachments = base?.let { access.attachments(generation, it.noteId) }.orEmpty(),
                    organization = base?.let { access.organization(generation, it.noteId) } ?: PrivateNoteOrganization(),
                )
            }
            if (recovered != null) {
                listing?.cancel()
                request++
                update { it.copy(editor = recovered, loading = false, error = "Recovered unsaved changes.") }
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            update { it.copy(error = "The encrypted note draft could not be recovered.") }
        } finally {
            update { it.copy(busy = false) }
        }
    }

    override fun create() {
        if (!current() || state.value.busy || state.value.editor != null) return
        listing?.cancel()
        request++
        update { it.copy(editor = PrivateNoteEditorState(), confirmation = null, error = null, loading = false, selection = emptyMap()) }
    }
    override fun open(note: PrivateNoteSummary) = runAction {
        if (state.value.editor != null || state.value.selection.isNotEmpty()) return@runAction
        listing?.cancel()
        request++
        val loaded = withContext(dispatcher) { access.load(generation, note.noteId) }
        val attachments = withContext(dispatcher) { access.attachments(generation, loaded.noteId) }
        val organization = withContext(dispatcher) { access.organization(generation, loaded.noteId) }
        update { it.copy(editor = PrivateNoteEditorState(loaded, attachments = attachments, organization = organization), history = null, historical = null, confirmation = null, loading = false) }
    }
    override fun title(value: String) = edit { copy(title = value) }
    override fun body(value: String) = edit { copy(body = value) }
    override fun pinned(value: Boolean) = edit { copy(pinned = value) }
    override fun format(value: PrivateNoteFormat) = edit { copy(format = value) }
    override fun importMarkdown(title: String, body: String) {
        if (!current() || state.value.busy || state.value.editor != null) return
        create()
        edit { copy(title = title, body = body, format = PrivateNoteFormat.MARKDOWN) }
    }
    override fun importPackage(bytes: ByteArray) {
        if (!current() || state.value.busy || state.value.editor != null) { bytes.fill(0); return }
        runAction(cleanup = { bytes.fill(0) }) {
            val imported = withContext(dispatcher) {
                val packageNote = NotePackages.decode(bytes)
                try {
                    access.importPackage(generation, packageNote.title, packageNote.body,
                        if (packageNote.format == NoteFormat.MARKDOWN) PrivateNoteFormat.MARKDOWN else PrivateNoteFormat.PLAIN_TEXT,
                        packageNote.attachments.map { PrivateNoteAttachmentData(it.id.fromHex(), it.name, it.mimeType, it.data) })
                } finally { packageNote.attachments.forEach { it.data.fill(0) } }
            }
            val attachments = withContext(dispatcher) { access.attachments(generation, imported.noteId) }
            update { it.copy(editor = PrivateNoteEditorState(imported, attachments = attachments), selection = emptyMap(), confirmation = null) }
        }
    }
    override fun addAttachment(name: String, bytes: ByteArray) {
        val editor = state.value.editor
        if (!current() || state.value.busy || editor?.saved == null || editor.dirty || editor.trashed) { bytes.fill(0); return }
        runAction(cleanup = { bytes.fill(0) }) {
            val id = Uuid.random().toString().replace("-", "")
            val saved = withContext(dispatcher) {
                val mime = NoteAttachments.validate(name, bytes)
                access.putAttachment(generation, editor.saved, PrivateNoteAttachmentData(id.fromHex(), name, mime, bytes))
            }
            val attachments = withContext(dispatcher) { access.attachments(generation, saved.noteId) }
            // Attaching is an explicit durable action. Inserting a reference remains an unsaved text edit.
            val image = attachments.first { it.id == id }.mimeType.startsWith("image/")
            val body = if (editor.format == PrivateNoteFormat.MARKDOWN) editor.body +
                (if (editor.body.isEmpty()) "" else "\n\n") + attachmentMarkdownReference(name, id, image) else editor.body
            val canInsert = utf8Size(body) <= PRIVATE_NOTE_BODY_MAX_BYTES
            update { it.copy(editor = PrivateNoteEditorState(saved, body = if (canInsert) body else editor.body, attachments = attachments, organization = editor.organization), history = null, historical = null,
                error = if (canInsert) null else "The attachment was saved. Its reference would exceed the 256 KiB text limit.") }
        }
    }
    override fun removeAttachment(id: String) {
        val editor = state.value.editor ?: return
        val attachment = editor.attachments.firstOrNull { it.id == id } ?: return
        if (!current() || state.value.busy || editor.saved == null || editor.dirty || editor.trashed) return
        runAction {
            val saved = withContext(dispatcher) { access.removeAttachment(generation, editor.saved, attachment.attachmentId) }
            update { it.copy(editor = PrivateNoteEditorState(saved, attachments = editor.attachments.filterNot { it.id == id }, organization = editor.organization), history = null, historical = null) }
        }
    }
    override fun exportAttachment(id: String) {
        if (!current() || state.value.busy) return
        val editor = state.value.editor ?: return
        if (editor.dirty) return
        val saved = editor.saved ?: return
        val attachment = editor.attachments.firstOrNull { it.id == id } ?: return
        onActivity()
        onAttachmentExport(saved, attachment)
    }
    override suspend fun readAttachment(id: String): ByteArray {
        check(current())
        val editor = state.value.editor ?: error("note is not open")
        val attachment = editor.attachments.firstOrNull { it.id == id } ?: error("attachment is unavailable")
        val saved = editor.saved ?: error("note is not saved")
        val bytes = access.readAttachment(generation, saved.noteId, attachment.attachmentId)
        if (!current() || state.value.editor?.saved?.id != saved.id) { bytes.fill(0); error("session ended") }
        return bytes
    }
    private fun edit(change: PrivateNoteEditorState.() -> PrivateNoteEditorState) {
        if (!current() || state.value.busy) return
        val editor = state.value.editor?.takeUnless { it.trashed } ?: return
        val changed = editor.change()
        if (changed != editor) onActivity()
        if (utf8Size(changed.title) > PRIVATE_NOTE_TITLE_MAX_BYTES || utf8Size(changed.body) > PRIVATE_NOTE_BODY_MAX_BYTES) {
            update { it.copy(error = "Use at most 256 UTF-8 bytes for the title and 256 KiB for the note.") }
            return
        }
        update { it.copy(editor = changed, history = null, historical = null, error = null) }
        draftWrite?.cancel()
        draftWrite = scope.launch {
            try {
                withContext(dispatcher) {
                    access.writeDraft(generation, if (changed.canSave) PrivateNoteDraft(
                        changed.saved?.noteId, changed.saved?.revision ?: 0, changed.title, changed.body,
                        changed.pinned, changed.format,
                    ) else null)
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                update { it.copy(error = "The encrypted draft could not be saved. Save the note before locking.") }
            }
        }
    }

    override fun back() {
        if (!current() || state.value.busy) return
        if (state.value.filtersVisible) { showFilters(false); return }
        if (state.value.history != null) { closeHistory(); return }
        val editor = state.value.editor
        when {
            editor == null && state.value.selection.isNotEmpty() -> clearSelection()
            editor == null -> onLeave()
            editor.dirty -> update { it.copy(confirmation = PrivateNoteConfirmation.LEAVE) }
            else -> leaveEditor()
        }
    }
    override fun dismissConfirmation() = update { it.copy(confirmation = null) }
    override fun discardAndBack() {
        if (state.value.confirmation != PrivateNoteConfirmation.LEAVE) return
        runAction {
            draftWrite?.cancelAndJoin()
            withContext(dispatcher) { access.writeDraft(generation, null) }
            leaveEditor()
        }
    }
    private fun leaveEditor() {
        update { it.copy(editor = null, history = null, historical = null, confirmation = null, error = null) }
        // A saved or trashed note changes the native cursor generation.
        loadPage(reset = true)
    }
    /**
     * The save that a lock runs before the session closes, or `null` when
     * nothing is unsaved. The lock conceals the editor next, so the capture
     * is its last action: no later edit, Save, or capture follows, and a
     * never-saved note gets one save with one owner, never a copy. An action
     * in flight owns its write, so a busy editor captures nothing. A stale
     * revision fails as a conflict and the newer revision stays.
     */
    internal fun captureForLock(): LockDrafts.Save? {
        if (!current()) return null
        lockCaptured = true
        val snapshot = state.value
        if (snapshot.busy) return null
        val editor = snapshot.editor ?: return null
        if (!editor.canSave) return null
        draftWrite?.cancel()
        return LockDrafts.Save { proceed ->
            withContext(dispatcher) { access.saveForLock(generation, editor, proceed) }
        }
    }

    override fun save() = saveThen()
    override fun saveAndBack() = saveThen(leave = true)
    override fun saveAndExport() = saveThen(export = true,
        encrypted = state.value.confirmation == PrivateNoteConfirmation.ENCRYPTED_EXPORT)
    private fun saveThen(leave: Boolean = false, export: Boolean = false, encrypted: Boolean = false) {
        val editor = state.value.editor ?: return
        if (!editor.canSave) return
        update { it.copy(confirmation = null) }
        runAction {
            draftWrite?.cancelAndJoin()
            val saved = withContext(dispatcher) { access.save(generation, editor.saved, editor.title, editor.body, editor.pinned, editor.format) }
            update { it.copy(editor = PrivateNoteEditorState(saved, attachments = editor.attachments, organization = editor.organization), history = null, historical = null) }
            withContext(dispatcher) { access.writeDraft(generation, null) }
            when {
                export && current() -> if (encrypted) sendEncrypted(listOf(saved.selection())) else onExport(saved)
                leave -> leaveEditor()
            }
        }
    }
    override fun export() {
        if (!current() || state.value.busy) return
        val editor = state.value.editor ?: return
        if (editor.dirty) update { it.copy(confirmation = PrivateNoteConfirmation.EXPORT) }
        else editor.saved?.let(onExport)
    }
    override fun exportEncrypted() {
        if (!current() || state.value.busy) return
        val editor = state.value.editor?.takeUnless { it.trashed } ?: return
        if (editor.dirty) update { it.copy(confirmation = PrivateNoteConfirmation.ENCRYPTED_EXPORT) }
        else editor.saved?.let { sendEncrypted(listOf(it.selection())) }
    }
    override fun toggleSelection(note: PrivateNoteSummary) {
        if (!current() || state.value.busy || state.value.trash || state.value.editor != null || note.trashedAtMs != null) return
        val selected = state.value.selection
        if (note.id !in selected && selected.size >= 1_000) {
            update { it.copy(error = "Select at most 1000 private notes for one archive.") }
            return
        }
        update { it.copy(selection = if (note.id in selected) selected - note.id
            else selected + (note.id to PrivateNoteSelection(note.noteId.copyOf(), note.revision)), error = null) }
    }
    override fun selectPage() {
        if (!current() || state.value.busy || state.value.loading || state.value.trash || state.value.editor != null) return
        val additions = state.value.notes.filter { it.trashedAtMs == null && it.id !in state.value.selection }
        if (state.value.selection.size + additions.size > 1_000) {
            update { it.copy(error = "Select at most 1000 private notes for one archive.") }
            return
        }
        update { it.copy(selection = it.selection + additions.associate { note ->
            note.id to PrivateNoteSelection(note.noteId.copyOf(), note.revision)
        }, error = null) }
    }
    override fun clearSelection() = update { it.copy(selection = emptyMap()) }
    override fun exportEncryptedSelection() {
        if (!current() || state.value.busy || state.value.trash || state.value.editor != null) return
        sendEncrypted(state.value.selection.values.toList())
    }
    private fun sendEncrypted(notes: List<PrivateNoteSelection>) {
        if (current() && notes.isNotEmpty()) onEncryptedExport(notes.map { PrivateNoteSelection(it.noteId.copyOf(), it.revision) })
    }
    private fun PrivateNote.selection() = PrivateNoteSelection(noteId.copyOf(), revision)
    override fun requestTrash() {
        if (state.value.editor?.saved != null) update { it.copy(confirmation = PrivateNoteConfirmation.TRASH) }
    }
    override fun requestPurge() {
        if (state.value.editor?.trashed == true) update { it.copy(confirmation = PrivateNoteConfirmation.PURGE) }
    }
    override fun trash() = changeOpen(PrivateNoteAction.TRASH)
    override fun restore() = changeOpen(PrivateNoteAction.RESTORE)
    override fun purge() = changeOpen(PrivateNoteAction.PURGE)
    private fun changeOpen(action: PrivateNoteAction) {
        if (action == PrivateNoteAction.TRASH && state.value.confirmation != PrivateNoteConfirmation.TRASH) return
        if (action == PrivateNoteAction.PURGE && state.value.confirmation != PrivateNoteConfirmation.PURGE) return
        val saved = state.value.editor?.saved ?: return
        update { it.copy(confirmation = null) }
        runAction {
            if (action == PrivateNoteAction.TRASH) draftWrite?.join()
            withContext(dispatcher) { access.change(generation, saved.noteId, saved.revision, action) }
            leaveEditor()
        }
    }
    override fun pin(note: PrivateNoteSummary) = runAction {
        if (state.value.selection.isNotEmpty()) return@runAction
        withContext(dispatcher) { access.change(generation, note.noteId, note.revision,
            if (note.pinned) PrivateNoteAction.UNPIN else PrivateNoteAction.PIN) }
        loadPage(reset = true)
    }

    private fun runAction(cleanup: () -> Unit = {}, action: suspend () -> Unit) {
        if (!current() || state.value.busy) { cleanup(); return }
        update { it.copy(busy = true, error = null) }
        scope.launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                if (current()) action()
            } catch (cancelled: CancellationException) { throw cancelled
            } catch (failure: Exception) {
                update { it.copy(error = errorCopy(failure)) }
            } finally { cleanup(); update { it.copy(busy = false) } }
        }
    }
    private fun errorCopy(failure: Exception): String = when (failure) {
        is ChurFailure -> if (failure.status == ChurStatus.CONFLICT) {
            if (state.value.editor != null) "This note changed. Your unsaved text is still here. Reopen the note to load the saved version."
            else "This note changed. Refresh the list and try again."
        } else userCopy(failure.status)
        else -> if (state.value.editor != null) "The note operation could not finish. Your unsaved text is still here. Try again."
            else "The note operation could not finish. Try again."
    }
}

/** Counts without allocating another complete plaintext byte array on each key press. */
internal fun utf8Size(text: String): Int {
    var size = 0
    var index = 0
    while (index < text.length) {
        val c = text[index++]
        size += when {
            c.code <= 0x7f -> 1
            c.code <= 0x7ff -> 2
            c.isHighSurrogate() && index < text.length && text[index].isLowSurrogate() -> { index++; 4 }
            c.isSurrogate() -> 3 // A conservative replacement-character bound on every host.
            else -> 3
        }
    }
    return size
}
