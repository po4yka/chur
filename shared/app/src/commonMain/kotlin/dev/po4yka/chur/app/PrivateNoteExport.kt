package dev.po4yka.chur.app

import dev.po4yka.chur.ffi.PrivateNote
import dev.po4yka.chur.ffi.PrivateNoteFormat
import dev.po4yka.chur.ffi.PrivateNoteAttachment
import dev.po4yka.chur.app.notes.noteExportFilename
import dev.po4yka.chur.app.notes.notePackageExportFilename

/** A session-bound export reference. It holds no note body or plaintext file path. */
class PrivateNoteExportRequest private constructor(
    val noteId: ByteArray,
    val revision: Long,
    val generation: Long,
    val filename: String,
    val exportSize: Long,
    val contentType: String,
    val attachmentId: ByteArray? = null,
) {
    override fun toString(): String = "PrivateNoteExportRequest"

    companion object {
        fun fromAttachment(note: PrivateNote, attachment: PrivateNoteAttachment, generation: Long): PrivateNoteExportRequest {
            dev.po4yka.chur.notes.NoteAttachments.validateName(attachment.name)
            require(attachment.attachmentId.size == 16 && attachment.size in 0..8_388_608)
            return PrivateNoteExportRequest(note.noteId.copyOf(), note.revision, generation,
                attachment.name, attachment.size, attachment.mimeType, attachment.attachmentId.copyOf())
        }
        fun from(note: PrivateNote, generation: Long): PrivateNoteExportRequest = PrivateNoteExportRequest(
            note.noteId.copyOf(), note.revision, generation,
            if (note.attachmentCount > 0) notePackageExportFilename(safeExportName(note.title, "private-note"))
            else noteExportFilename(safeExportName(note.title, "private-note"), note.format == PrivateNoteFormat.MARKDOWN), note.exportSize,
            if (note.attachmentCount > 0) "application/octet-stream" else if (note.format == PrivateNoteFormat.MARKDOWN) "text/markdown" else "text/plain",
        )
    }
}
