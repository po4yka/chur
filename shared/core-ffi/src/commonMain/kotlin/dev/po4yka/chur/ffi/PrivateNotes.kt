package dev.po4yka.chur.ffi

enum class PrivateNoteFormat { PLAIN_TEXT, MARKDOWN }

/** Private plaintext exists only in the unlocked session. Never log or save these records. */
data class PrivateNote(
    val noteId: ByteArray,
    val revision: Long,
    val title: String,
    val body: String,
    val createdMs: Long,
    val updatedMs: Long,
    val pinned: Boolean,
    val trashedAtMs: Long?,
    val exportSize: Long,
    val format: PrivateNoteFormat = PrivateNoteFormat.PLAIN_TEXT,
    val attachmentCount: Int = 0,
) {
    val id: String get() = noteId.joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
    override fun toString(): String = "PrivateNote(<redacted>)"
}

data class PrivateNoteSummary(
    val noteId: ByteArray,
    val revision: Long,
    val title: String,
    val preview: String,
    val createdMs: Long,
    val updatedMs: Long,
    val pinned: Boolean,
    val trashedAtMs: Long?,
    val exportSize: Long,
    val format: PrivateNoteFormat = PrivateNoteFormat.PLAIN_TEXT,
    val attachmentCount: Int = 0,
) {
    val id: String get() = noteId.joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
    override fun toString(): String = "PrivateNoteSummary(<redacted>)"
}

data class PrivateNotePage(val notes: List<PrivateNoteSummary>, val nextCursor: ByteArray?) {
    override fun toString(): String = "PrivateNotePage(<redacted>)"
}

/** Catalog metadata; like note text it belongs only to the unlocked session. */
data class PrivateNoteOrganization(val folder: String = "", val tags: List<String> = emptyList()) {
    override fun toString(): String = "PrivateNoteOrganization(<redacted>)"
}
data class PrivateNoteWorkspacePage(val page: PrivateNotePage, val organization: Map<String, PrivateNoteOrganization>) {
    override fun toString(): String = "PrivateNoteWorkspacePage(<redacted>)"
}
data class PrivateNoteRevision(val revision: Long, val updatedMs: Long, val title: String,
    val format: PrivateNoteFormat, val attachmentCount: Int) {
    override fun toString(): String = "PrivateNoteRevision(<redacted>)"
}
data class PrivateNoteRevisionDetail(val note: PrivateNote, val organization: PrivateNoteOrganization,
    val attachments: List<PrivateNoteAttachment>) {
    override fun toString(): String = "PrivateNoteRevisionDetail(<redacted>)"
}

enum class PrivateNoteAction { PIN, UNPIN, TRASH, RESTORE, PURGE }

internal class PrivateNoteWriter(size: Int) {
    val bytes = ByteArray(size)
    private var at = 0
    fun byte(value: Int) { bytes[at++] = value.toByte() }
    fun number(value: Long) { for (shift in 56 downTo 0 step 8) byte((value ushr shift).toInt()) }
    fun raw(value: ByteArray) { value.copyInto(bytes, at); at += value.size }
    fun count(value: Int) { for (shift in 24 downTo 0 step 8) byte(value ushr shift) }
    fun sized(value: ByteArray) { for (shift in 24 downTo 0 step 8) byte(value.size ushr shift); raw(value) }
}
/** Unsaved text from the current vault's encrypted recovery record. */
class PrivateNoteDraft(
    val noteId: ByteArray?,
    val revision: Long,
    val title: String,
    val body: String,
    val pinned: Boolean,
    val format: PrivateNoteFormat,
) {
    override fun toString(): String = "PrivateNoteDraft(<redacted>)"
}

internal class PrivateNoteReader(private val bytes: ByteArray) {
    private var at = 0
    fun byte(): Int { require(at < bytes.size); return bytes[at++].toInt() and 255 }
    fun number(): Long { var out = 0L; repeat(8) { out = (out shl 8) or byte().toLong() }; return out }
    fun raw(size: Int): ByteArray { require(size >= 0 && size <= bytes.size - at); return bytes.copyOfRange(at, at + size).also { at += size } }
    fun count():Int { var n=0L;repeat(4){n=(n shl 8) or byte().toLong()};require(n<=Int.MAX_VALUE);return n.toInt() }
    fun sized(max: Int): ByteArray { var n = 0L; repeat(4) { n = (n shl 8) or byte().toLong() }; require(n <= max); return raw(n.toInt()) }
    fun text(max: Int): String { val b = sized(max); return try { b.decodeToString(throwOnInvalidSequence = true) } finally { b.fill(0) } }
    fun note(): PrivateNote {
        val id = raw(16); require(id.any { it != 0.toByte() })
        val revision = number(); val created = number(); val updated = number(); val deleted = number()
        val pin = byte(); val format = byte(); val attachmentCount = count(); val size = number()
        require(revision > 0 && created >= 0 && updated >= 0 && (deleted == -1L || deleted >= 0) && pin <= 1 && format in 0..1 && attachmentCount in 0..32 && size in 0..(if (attachmentCount > 0) 25165824 else if (format == 1) 262144 else 262402) && (format == 1 || size >= 2))
        return PrivateNote(id, revision, text(256), text(262144), created, updated, pin == 1, if (deleted == -1L) null else deleted, size, PrivateNoteFormat.entries[format], attachmentCount)
    }
    fun end() { require(at == bytes.size) }
}

internal fun decodePrivateNote(bytes: ByteArray): PrivateNote = PrivateNoteReader(bytes).let { r -> r.note().also { r.end() } }
internal fun PrivateNoteReader.page(): PrivateNotePage {
    val r = this
    val countBytes = r.raw(4)
    val count = countBytes.fold(0) { a, b -> (a shl 8) or (b.toInt() and 255) }
    require(count in 0..100)
    val notes = List(count) {
        val n = r.note()
        PrivateNoteSummary(n.noteId, n.revision, n.title, n.body, n.createdMs, n.updatedMs, n.pinned, n.trashedAtMs, n.exportSize, n.format, n.attachmentCount)
    }
    val cursor = r.sized(65).takeIf { it.isNotEmpty() }
    require(cursor == null || cursor.size == 65)
    return PrivateNotePage(notes, cursor)
}
internal fun decodePrivateNotePage(bytes: ByteArray): PrivateNotePage = PrivateNoteReader(bytes).let { r -> r.page().also { r.end() } }

internal fun PrivateNoteReader.organization(): PrivateNoteOrganization {
    val folder = text(64)
    val count = count(); require(count in 0..16)
    val tags = List(count) { text(64) }
    require(folder == folder.trim() && '\u0000' !in folder && folder.none { it.isISOControl() })
    require(tags.all { it.isNotBlank() && it == it.trim() && it.none { c -> c.isISOControl() } } && tags.distinct().size == tags.size)
    return PrivateNoteOrganization(folder, tags)
}
internal fun PrivateNoteReader.attachments(): List<PrivateNoteAttachment> {
    val count = count(); require(count in 0..32)
    return List(count) {
        PrivateNoteAttachment(raw(16), text(240), text(128), number()).also { require(it.size in 0..8_388_608) }
    }
}

/** Metadata for a note-owned encrypted file. Never persist outside the unlocked session. */
data class PrivateNoteAttachment(val attachmentId: ByteArray, val name: String, val mimeType: String, val size: Long) {
    val id: String get() = attachmentId.joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
    override fun toString(): String = "PrivateNoteAttachment(<redacted>)"
}
/** Import payload; the caller must erase [data] after the operation, including failure. */
data class PrivateNoteAttachmentData(val attachmentId: ByteArray, val name: String, val mimeType: String, val data: ByteArray) {
    override fun toString(): String = "PrivateNoteAttachmentData(<redacted>)"
}
