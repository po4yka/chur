package dev.po4yka.chur.notes

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * The public store, which is one JSON file.
 *
 * `docs/product/DISCREET_MODE.md` requires a shell that is a real application,
 * and a notes application that forgets every note when the process ends is a
 * decoy with extra steps. So the shell persists, and it persists in the plain:
 * `PLAINTEXT_LIFECYCLE.md` §1 forbids private data in a public store, and the
 * converse is what makes this file safe to write unencrypted. Nothing here has
 * ever been inside the vault.
 *
 * One file rather than a database, because the scale is a person's notes. The
 * whole file is rewritten on every change, which is the same reasoning: at this
 * size the simplest durable write is also the fastest one.
 */
class FileNoteStore internal constructor(
    private val path: String,
    private val readFile: (String) -> String?,
    private val writeFile: (String, String) -> Unit,
    private val listDirectory: (String) -> List<String> = { emptyList() },
) : NoteStore {
    constructor(path: String) : this(path, ::readNoteFile, ::writeNoteFile, ::listNoteDirectory)

    private val mutex = Mutex()
    private var cache: NoteState? = null

    override suspend fun all(): List<Note> = mutex.withLock {
        Notes.ordered(load().notes.values.filter { it.trashedAtMs == null })
    }

    override suspend fun trash(): List<Note> = mutex.withLock {
        Notes.ordered(load().notes.values.filter { it.trashedAtMs != null })
    }

    override suspend fun put(note: Note): Note = mutate {
        val next = load().put(note)
        commit(next)
        next.current(note.id)
    }

    override suspend fun remove(id: String): Unit = mutate {
        val state = load()
        val note = state.notes[id] ?: return@mutate
        if (note.trashedAtMs == null) commit(state.replace(note.copy(trashedAtMs = nowMs(),
            revision = nextRevision(note), recoveryEpoch = nextEpoch(note))))
    }

    override suspend fun restore(id: String, updatedMs: Long): Note = mutate {
        val state = load()
        val note = state.current(id, allowTrashed = true)
        check(note.trashedAtMs != null) { "note is not in Trash" }
        val restored = note.copy(trashedAtMs = null, updatedMs = updatedMs,
            revision = nextRevision(note), recoveryEpoch = nextEpoch(note))
        commit(state.replace(restored))
        restored
    }

    override suspend fun purge(id: String): Unit = mutate {
        val state = load()
        val note = state.current(id, allowTrashed = true)
        check(note.trashedAtMs != null) { "only trashed notes can be purged" }
        commit(state.copy(notes = state.notes - id, history = state.history - id))
    }

    override suspend fun updateOrganization(id: String, folder: String?, tags: List<String>): Note = mutate {
        val state = load()
        val note = state.current(id)
        val organized = note.copy(folder = NoteOrganization.folder(folder), tags = NoteOrganization.tags(tags))
        if (organized == note) return@mutate note
        val next = organized.copy(revision = nextRevision(note), updatedMs = nowMs())
        commit(state.replace(next))
        next
    }

    override suspend fun history(id: String): List<NoteRevision> = mutex.withLock {
        val state = load()
        state.current(id, allowTrashed = true)
        state.history[id].orEmpty()
    }

    override suspend fun restoreRevision(noteId: String, revisionId: String): Note = mutate {
        val state = load()
        val note = state.current(noteId)
        val version = state.history[noteId].orEmpty().singleOrNull { it.id == revisionId } ?: error("revision not found")
        // Verify retained payloads before making the snapshot current. A corrupt or missing
        // payload must fail without changing either current state or history.
        version.note.attachments.forEach { readBlob(it).fill(0) }
        val restored = version.note.copy(updatedMs = nowMs(), trashedAtMs = null,
            revision = nextRevision(note), recoveryEpoch = nextEpoch(note))
        commit(state.replace(restored))
        restored
    }

    override suspend fun addAttachment(noteId: String, name: String, data: ByteArray): NoteAttachment = mutate {
        val state = load()
        val note = state.current(noteId)
        val attachment = NoteAttachment(newAttachmentId(), name, NoteAttachments.validate(name, data), data.size)
        NoteAttachments.validateList(note.attachments + attachment)
        writeBlob(attachment.storageId, data)
        try {
            commit(state.replace(note.copy(attachments = note.attachments + attachment, revision = nextRevision(note), updatedMs = nowMs())))
        } catch (cause: Throwable) {
            deleteBlob(attachment.storageId)
            throw cause
        }
        attachment
    }

    override suspend fun readAttachment(noteId: String, attachmentId: String): ByteArray = mutex.withLock {
        val note = load().current(noteId, allowTrashed = true)
        val attachment = note.attachments.singleOrNull { it.id == attachmentId } ?: error("attachment not found")
        readBlob(attachment)
    }

    override suspend fun removeAttachment(noteId: String, attachmentId: String): Unit = mutate {
        val state = load()
        val note = state.current(noteId)
        val attachment = note.attachments.singleOrNull { it.id == attachmentId } ?: return@mutate
        commit(state.replace(note.copy(attachments = note.attachments - attachment, revision = nextRevision(note), updatedMs = nowMs())))
    }

    override suspend fun exportPackage(noteId: String): ByteArray = mutex.withLock {
        val note = load().current(noteId, allowTrashed = true)
        val contents = mutableListOf<NotePackageAttachment>()
        try {
            note.attachments.forEach {
                contents += NotePackageAttachment(it.id, it.name, it.mimeType, readBlob(it))
            }
            NotePackages.encode(NotePackage(note.title, note.body, note.format, contents))
        } finally {
            contents.forEach { it.data.fill(0) }
        }
    }

    override suspend fun importPackage(data: ByteArray, noteId: String, updatedMs: Long): Note = mutate {
        val state = load()
        require(noteId !in state.notes) { "note already exists" }
        val imported = NotePackages.decode(data)
        try {
            val attachments = imported.attachments.map {
                NoteAttachment(it.id, it.name, it.mimeType, it.data.size, storageId = newAttachmentId())
            }
            val note = Note(noteId, imported.title, imported.body, updatedMs, format = imported.format, attachments = attachments)
            val written = mutableListOf<String>()
            try {
                attachments.zip(imported.attachments).forEach { (descriptor, content) ->
                    writeBlob(descriptor.storageId, content.data)
                    written += descriptor.storageId
                }
                commit(state.replace(note))
            } catch (cause: Throwable) {
                written.forEach { deleteBlob(it) }
                throw cause
            }
            note
        } finally {
            imported.attachments.forEach { it.data.fill(0) }
        }
    }

    // Once a durable mutation starts, finish its metadata/cache publication and cleanup even
    // when the composing screen goes away. Waiting for another writer remains cancellable.
    private suspend fun <T> mutate(block: suspend () -> T): T = mutex.withLock {
        withContext(NonCancellable) { block() }
    }

    private fun blobPath(storageId: String): String {
        require(NoteAttachments.validId(storageId)) { "invalid attachment identifier" }
        return "$path.attachments/$storageId"
    }

    private suspend fun writeBlob(storageId: String, data: ByteArray) = withContext(Dispatchers.Default) {
        writeNoteBlob(blobPath(storageId), data)
    }

    private suspend fun readBlob(attachment: NoteAttachment): ByteArray {
        var owned: ByteArray? = null
        try {
            // Assign before switching back: prompt cancellation must not drop an unowned array.
            withContext(Dispatchers.Default) {
                owned = readNoteBlob(blobPath(attachment.storageId), NoteAttachments.MAX_FILE_BYTES)
                    ?: error("attachment content is missing")
                val data = requireNotNull(owned)
                check(data.size == attachment.sizeBytes && NoteAttachments.validate(attachment.name, data) == attachment.mimeType) {
                    "attachment content is invalid"
                }
            }
            return requireNotNull(owned).also { owned = null }
        } finally {
            owned?.fill(0)
        }
    }

    // A failed cleanup leaves an unreachable public blob, never a broken saved note;
    // the sweep of the next load removes it.
    private suspend fun deleteBlob(storageId: String) = withContext(Dispatchers.Default) {
        runCatching { deleteNoteBlob(blobPath(storageId)) }
        Unit
    }

    override suspend fun disclosureAcknowledged(): Boolean = mutex.withLock {
        load().acknowledged
    }

    override suspend fun acknowledgeDisclosure(): Unit = mutate {
        val state = load()
        if (!state.acknowledged) save(state.copy(acknowledged = true))
    }

    /**
     * An unreadable or unsupported file is an error, never an empty store that
     * a subsequent write could overwrite. Failed reads do not populate cache.
     */
    private suspend fun load(): NoteState {
        cache?.let { return it }
        val text = withContext(Dispatchers.Default) { readFile(path) }
        require(text == null || text.encodeToByteArray(throwOnInvalidSequence = true).size <= NoteState.MAX_STORE_BYTES) { "note store is too large" }
        val state = if (text != null) {
            val file = try {
                val document = json.parseToJsonElement(text).jsonObject
                val version = document["version"]?.let {
                    it.jsonPrimitive.intOrNull ?: error("invalid note file version")
                } ?: 1
                check(version in 1..4) { "unsupported note file version $version" }
                json.decodeFromJsonElement(NoteFile.serializer(), document)
            } catch (cause: Exception) {
                throw IllegalStateException("the note file at $path is not readable", cause)
            }
            check(file.notes.map { it.id }.toSet().size == file.notes.size) { "duplicate note identifier" }
            NoteState(file.notes.associateBy { it.id }, file.disclosureAcknowledged, file.history).also { it.validate() }
        } else {
            NoteState()
        }
        if (text != null) sweep(state)
        cache = state
        return state
    }

    /**
     * Removes what an interrupted write left behind: the temporary copy of
     * the state file, attachment temporaries, and attachment blobs that no
     * note or revision names (a blob is written before the commit that
     * references it). It runs only after the state file parsed, so a state
     * that cannot be read never costs a blob. It removes only names this
     * store makes. One store instance owns a path. A failed removal is
     * retried at the next load.
     */
    private suspend fun sweep(state: NoteState) = withContext(Dispatchers.Default) {
        runCatching {
            val name = path.substringAfterLast('/')
            val directory = path.substringBeforeLast('/', "")
            val attachments = "$path.attachments"
            val live = state.blobs().keys
            val stale = listDirectory(directory).filter { it == "$name.tmp" }
                .map { if (directory.isEmpty()) it else "$directory/$it" } +
                listDirectory(attachments).filter { entry ->
                    val id = entry.removeSuffix(".tmp")
                    NoteAttachments.validId(id) && (entry != id || id !in live)
                }.map { "$attachments/$it" }
            stale.forEach { runCatching { deleteNoteBlob(it) } }
        }
        Unit
    }

    /** Publish the new in-memory state only after its atomic write succeeds. */
    private suspend fun save(state: NoteState) {
        // Reject oversized text before allocating the full document. The serializer below
        // accounts for the exact metadata and punctuation in files near the limit.
        val versions = state.notes.values.toList() + state.history.values.flatten().map { it.note }
        val contentBytes = versions.sumOf { note ->
            jsonStringBytes(note.title) + jsonStringBytes(note.body) + jsonStringBytes(note.id) +
                jsonStringBytes(note.folder.orEmpty()) + note.tags.sumOf(::jsonStringBytes) +
                note.attachments.sumOf { jsonStringBytes(it.name) + jsonStringBytes(it.mimeType) }
        }
        require(contentBytes <= NoteState.MAX_STORE_BYTES) { "note store is too large" }
        val text = json.encodeToString(
            NoteFile.serializer(),
            NoteFile(version = 4, notes = state.notes.values.toList(), disclosureAcknowledged = state.acknowledged, history = state.history),
        )
        require(text.encodeToByteArray(throwOnInvalidSequence = true).size <= NoteState.MAX_STORE_BYTES) { "note store is too large" }
        withContext(Dispatchers.Default) { writeFile(path, text) }
        cache = state
    }

    private suspend fun commit(next: NoteState) {
        val old = load()
        if (old == next) return
        next.validate()
        save(next)
        val live = next.blobs().keys
        old.blobs().keys.filterNot { it in live }.forEach { deleteBlob(it) }
    }

    private companion object {
        fun jsonStringBytes(value: String): Long = value.encodeToByteArray(throwOnInvalidSequence = true).size.toLong() +
            value.sumOf { character ->
                when (character) {
                    '"', '\\', '\b', '\u000C', '\n', '\r', '\t' -> 1L
                    in '\u0000'..'\u001F' -> 5L
                    else -> 0L
                }
            }

        val json: Json = Json { encodeDefaults = true }
    }
}

/** Version 1 omitted note formats; the note serializer preserves those as plain text. */
@Serializable
private data class NoteFile(
    val version: Int = 1,
    val notes: List<Note>,
    val disclosureAcknowledged: Boolean = false,
    val history: Map<String, List<NoteRevision>> = emptyMap(),
)

/** The file's text, or `null` when no file is there yet. */
internal expect fun readNoteFile(path: String): String?

/**
 * Replaces the file's text.
 *
 * The replacement must be atomic: a half-written note file is a lost note
 * file, and the write happens while a person is typing.
 */
internal expect fun writeNoteFile(path: String, text: String)

/** Binary content is bounded before allocation and atomically replaced in the app-owned directory. */
internal expect fun readNoteBlob(path: String, maxBytes: Int): ByteArray?
internal expect fun writeNoteBlob(path: String, bytes: ByteArray)
internal expect fun deleteNoteBlob(path: String)

/** The entry names in a directory, or none when it does not exist. */
internal expect fun listNoteDirectory(path: String): List<String>
