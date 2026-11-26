package dev.po4yka.chur.app

import dev.po4yka.chur.app.notes.NOTE_IMPORT_MAX_BYTES
import dev.po4yka.chur.app.notes.NotePickerActivityLease
import dev.po4yka.chur.app.notes.decodeMarkdownNote
import dev.po4yka.chur.app.notes.publicNoteExportBytes
import dev.po4yka.chur.app.notes.noteExportFilename
import dev.po4yka.chur.app.notes.notePackageExportFilename
import dev.po4yka.chur.app.notes.truncateNoteTitle
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class NoteFileActionsTest {
    @Test
    fun managed_attachment_resolution_accepts_only_a_complete_opaque_local_reference() {
        val id = "0123456789abcdef0123456789abcdef"
        kotlin.test.assertEquals(id, dev.po4yka.chur.app.notes.noteAttachmentId("attachment:$id"))
        for (uri in listOf("https://example.invalid/attachment:$id", "file:///attachment:$id", "attachment:../$id", "attachment:$id?remote=1", "attachment:${id.uppercase()}")) {
            kotlin.test.assertNull(dev.po4yka.chur.app.notes.noteAttachmentId(uri))
        }
        kotlin.test.assertEquals("![a\\[b\\].png](attachment:$id)",
            dev.po4yka.chur.app.notes.attachmentMarkdownReference("a[b].png", id, true))
    }

    @Test
    fun markdown_import_preserves_the_exact_source_and_uses_the_filename_as_title() {
        val source = "# Heading\r\n\r\n**bold**  \n- [ ] item\n| a | b |\n| - | - |\n| 1 | 2 |\n"
        val note = decodeMarkdownNote("Document.MD", source.encodeToByteArray())
        assertEquals("Document", note.title)
        assertEquals(source, note.body)
        assertEquals("Untitled", decodeMarkdownNote(".md", byteArrayOf()).title)
    }

    @Test
    fun import_requires_markdown_and_strict_utf8_without_nul() {
        assertFailsWith<IllegalArgumentException> { decodeMarkdownNote("note.txt", "text".encodeToByteArray()) }
        assertFails { decodeMarkdownNote("note.md", byteArrayOf(0xc3.toByte(), 0x28)) }
        assertFailsWith<IllegalArgumentException> { decodeMarkdownNote("note.md", byteArrayOf(65, 0, 66)) }
    }

    @Test
    fun import_accepts_the_limit_and_rejects_the_next_byte() {
        val bytes = ByteArray(NOTE_IMPORT_MAX_BYTES) { 65 }
        assertEquals(NOTE_IMPORT_MAX_BYTES, decodeMarkdownNote("note.markdown", bytes).body.length)
        assertFailsWith<IllegalArgumentException> {
            decodeMarkdownNote("note.md", ByteArray(NOTE_IMPORT_MAX_BYTES + 1) { 65 })
        }
    }

    @Test
    fun multibyte_titles_are_truncated_at_a_utf8_boundary() {
        val title = "a" + "😀".repeat(100)
        assertEquals("a" + "😀".repeat(63), truncateNoteTitle(title))
        val imported = decodeMarkdownNote("${title}.md", byteArrayOf())
        assertTrue(imported.title.encodeToByteArray().size <= 256)
        assertEquals(truncateNoteTitle(title), imported.title)
    }

    @Test
    fun public_markdown_export_is_exact_and_plain_text_includes_the_title() {
        val body = "# Heading  \n\n```kotlin\nval a = 1\n```\n"
        assertEquals(body, publicNoteExportBytes("Title", body, true).decodeToString())
        assertEquals("Title\n\n$body", publicNoteExportBytes("Title", body, false).decodeToString())
    }

    @Test
    fun export_names_cannot_escape_the_chosen_directory_or_exceed_a_filesystem_component() {
        assertEquals("bad_name.md", noteExportFilename("bad/name", true))
        assertEquals("Note.txt", noteExportFilename("..", false))
        assertTrue(noteExportFilename("😀".repeat(100), true).encodeToByteArray().size <= 255)
        assertEquals("я".repeat(115) + ".churnote", notePackageExportFilename("я".repeat(116)))
        assertEquals("a".repeat(231) + ".churnote", notePackageExportFilename("a".repeat(240)))
    }

    @Test
    fun picker_lease_ends_once_for_result_failure_and_disposal_and_can_be_reused() {
        val lease = NotePickerActivityLease()
        val events = mutableListOf<Boolean>()
        lease.begin(events::add)
        lease.finish()
        lease.finish()
        lease.begin(events::add)
        lease.finish()
        assertEquals(listOf(true, false, true, false), events)
    }

}
