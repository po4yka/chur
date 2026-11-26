package dev.po4yka.chur.app.notes

import androidx.compose.runtime.Composable
import dev.po4yka.chur.notes.NoteAttachments

/** Opens one Markdown file. Source stays in the owning screen's memory only. */
@Composable
expect fun NoteImportAction(
    enabled: Boolean = true,
    onPickerActive: (Boolean) -> Unit = {},
    onImported: (title: String, body: String) -> Unit,
    onFailure: () -> Unit,
)

/** Exports public content through the platform's document picker. */
@Composable
expect fun PublicNoteExportAction(
    title: String,
    body: String,
    markdown: Boolean,
    enabled: Boolean = true,
    onFailure: () -> Unit,
)

internal const val NOTE_IMPORT_MAX_BYTES = 262_144
internal data class ImportedMarkdownNote(val title: String, val body: String) {
    override fun toString(): String = "ImportedMarkdownNote(<redacted>)"
}

internal fun decodeMarkdownNote(filename: String, bytes: ByteArray): ImportedMarkdownNote {
    require(bytes.size <= NOTE_IMPORT_MAX_BYTES) { "note is too large" }
    val name = filename.substringAfterLast('/').substringAfterLast('\\')
    require(name.endsWith(".md", ignoreCase = true) || name.endsWith(".markdown", ignoreCase = true)) {
        "a Markdown file is required"
    }
    val body = bytes.decodeToString(throwOnInvalidSequence = true)
    require('\u0000' !in body) { "note contains NUL" }
    val title = truncateNoteTitle(name.substringBeforeLast('.').ifBlank { "Untitled" })
    return ImportedMarkdownNote(title, body)
}

internal fun truncateNoteTitle(value: String): String = truncateUtf8(value, 256)

private fun truncateUtf8(value: String, maxBytes: Int): String {
    val bytes = value.encodeToByteArray()
    if (bytes.size <= maxBytes) return value
    var end = maxBytes
    while (end > 0 && (bytes[end].toInt() and 0xc0) == 0x80) end--
    return bytes.decodeToString(endIndex = end, throwOnInvalidSequence = true)
}

private fun exportBasename(title: String, maxBytes: Int): String =
    truncateUtf8(title.map { char ->
        if (char.isISOControl() || char in "/\\:*?\"<>|") '_' else char
    }.joinToString("").trim().trim('.').ifBlank { "Note" }, maxBytes)

internal fun noteExportFilename(title: String, markdown: Boolean): String =
    "${exportBasename(title, 240)}.${if (markdown) "md" else "txt"}"

internal fun notePackageExportFilename(title: String): String =
    exportBasename(title, NoteAttachments.MAX_NAME_BYTES - ".churnote".length) + ".churnote"

internal fun publicNoteExportBytes(title: String, body: String, markdown: Boolean): ByteArray =
    (if (markdown) body else "$title\n\n$body").encodeToByteArray()

/** A native picker may complete, fail and dispose in the same lifecycle transition. */
internal class NotePickerActivityLease {
    private var end: (() -> Unit)? = null

    fun begin(onActive: (Boolean) -> Unit) {
        if (end != null) return
        end = { onActive(false) }
        onActive(true)
    }

    fun finish() {
        val callback = end
        end = null
        callback?.invoke()
    }
}
