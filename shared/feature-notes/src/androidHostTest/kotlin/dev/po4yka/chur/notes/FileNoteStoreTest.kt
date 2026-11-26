package dev.po4yka.chur.notes

import java.io.File
import java.io.IOException
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.launch

/**
 * The store keeps notes across instances, which is the whole point of it: a
 * shell that forgets is the decoy `DISCREET_MODE.md` forbids.
 */
class FileNoteStoreTest {
    private val directory: File = File.createTempFile("chur-notes", "").let { file ->
        file.delete()
        file.mkdirs()
        file
    }

    private val path: String = File(directory, "notes.json").path

    @AfterTest
    fun clean() {
        directory.deleteRecursively()
    }

    @Test
    fun a_note_survives_a_new_store() = runTest {
        FileNoteStore(path).put(Note(id = "a", title = "Groceries", body = "milk", updatedMs = 7))

        val reopened = FileNoteStore(path).all()

        assertEquals(1, reopened.size)
        assertEquals("Groceries", reopened.first().title)
        assertEquals("milk", reopened.first().body)
    }

    @Test
    fun a_body_with_quotes_and_newlines_round_trips() = runTest {
        val body = "line one\n\"quoted\", \\escaped\\\ttabbed"
        FileNoteStore(path).put(Note(id = "a", title = "", body = body, updatedMs = 1))

        assertEquals(body, FileNoteStore(path).all().first().body)
    }

    @Test
    fun removal_persists() = runTest {
        val store = FileNoteStore(path)
        store.put(Note(id = "a", title = "one", body = "", updatedMs = 1))
        store.put(Note(id = "b", title = "two", body = "", updatedMs = 2))
        store.remove("a")

        assertEquals(listOf("b"), FileNoteStore(path).all().map { it.id })
    }

    @Test
    fun an_absent_file_is_an_empty_store() = runTest {
        assertEquals(emptyList(), FileNoteStore(path).all())
        assertTrue(!File(path).exists())
    }

    @Test
    fun a_failed_file_lookup_retries_before_the_next_write() = runTest {
        val parent = File(directory, "public")
        val parked = File(directory, "parked")
        val notesPath = File(parent, "notes.json").path
        val original = Note("a", "Saved", "original", 1)
        val next = Note("b", "New", "second", 2)
        assertTrue(parent.mkdir())
        FileNoteStore(notesPath).put(original)
        assertTrue(parent.renameTo(parked))
        assertTrue(parent.createNewFile())

        val store = FileNoteStore(notesPath)
        assertFailsWith<IOException> { store.all() }
        assertTrue(parent.delete())
        assertTrue(parked.renameTo(parent))
        store.put(next)
        assertEquals(setOf(original, next), FileNoteStore(notesPath).all().toSet())
    }

    /**
     * An unreadable file must not be replaced by the next write. Reporting the
     * failure keeps whatever is in the file; answering "empty" would delete it
     * on the next keystroke.
     */
    @Test
    fun an_unreadable_file_is_reported_rather_than_replaced() = runTest {
        File(path).writeText("{ this is not the note file")

        assertFailsWith<IllegalStateException> { FileNoteStore(path).all() }
        assertEquals("{ this is not the note file", File(path).readText())
    }

    @Test
    fun a_failed_update_keeps_the_saved_state_and_the_same_value_can_be_retried() = runTest {
        val original = Note("a", "Saved", "original", 1)
        FileNoteStore(path).put(original)
        val writer = FailingWriter()
        val store = FileNoteStore(path, ::readNoteFile, writer::write)
        val changed = original.copy(body = "# Unsaved\n\n- [x] exact source  \n", updatedMs = 2)

        writer.failNext = true
        assertFailsWith<IOException> { store.put(changed) }
        assertEquals(listOf(original), store.all())
        assertEquals(listOf(original), FileNoteStore(path).all())

        store.put(changed)
        assertEquals(listOf(changed.copy(revision = 1)), store.all())
        assertEquals(listOf(changed.copy(revision = 1)), FileNoteStore(path).all())
    }

    @Test
    fun a_failed_delete_keeps_the_note_and_retry_persists_its_removal() = runTest {
        val note = Note("a", "Saved", "body", 1)
        FileNoteStore(path).put(note)
        val writer = FailingWriter()
        val store = FileNoteStore(path, ::readNoteFile, writer::write)

        writer.failNext = true
        assertFailsWith<IOException> { store.remove(note.id) }
        assertEquals(listOf(note), store.all())
        assertEquals(listOf(note), FileNoteStore(path).all())

        store.remove(note.id)
        assertEquals(emptyList(), store.all())
        assertEquals(emptyList(), FileNoteStore(path).all())
    }

    @Test
    fun a_failed_disclosure_write_does_not_acknowledge_and_retry_survives_reopen() = runTest {
        val writer = FailingWriter()
        val store = FileNoteStore(path, ::readNoteFile, writer::write)

        writer.failNext = true
        assertFailsWith<IOException> { store.acknowledgeDisclosure() }
        assertFalse(store.disclosureAcknowledged())
        assertFalse(FileNoteStore(path).disclosureAcknowledged())

        store.acknowledgeDisclosure()
        assertTrue(store.disclosureAcknowledged())
        assertTrue(FileNoteStore(path).disclosureAcknowledged())
    }

    @Test
    fun version_one_is_migrated_without_reinterpreting_its_plain_text() = runTest {
        File(path).writeText(
            """{"version":1,"notes":[{"id":"old","title":"Legacy","body":"# literal heading","updatedMs":1}],"disclosureAcknowledged":true}""",
        )
        val store = FileNoteStore(path)
        val legacy = store.all().single()
        assertEquals(NoteFormat.PLAIN_TEXT, legacy.format)
        assertEquals("# literal heading", legacy.body)
        assertTrue(store.disclosureAcknowledged())

        val markdown = Note("new", "Markdown", "# Heading\n\n| a | b |\n| - | - |\n| 1 | 2 |\n", 2)
        store.put(markdown)

        val reopened = FileNoteStore(path).all()
        assertEquals(listOf(markdown, legacy), reopened)
        assertTrue(File(path).readText().contains("\"version\":4"))
        assertTrue(File(path).readText().contains("\"format\":\"PLAIN_TEXT\""))
        assertTrue(File(path).readText().contains("\"format\":\"MARKDOWN\""))
    }

    @Test
    fun version_three_migrates_attachments_without_copying_or_losing_payloads() = runTest {
        val id = "0123456789abcdef0123456789abcdef"
        File("$path.attachments").mkdirs()
        File("$path.attachments/$id").writeBytes(byteArrayOf(4, 5))
        File(path).writeText("""{"version":3,"notes":[{"id":"a","title":"Old","body":"[file](attachment:$id)","updatedMs":1,"format":"MARKDOWN","attachments":[{"id":"$id","name":"file.bin","mimeType":"application/octet-stream","sizeBytes":2,"storageId":"$id"}]}]}""")
        val store = FileNoteStore(path)
        val old = store.all().single()
        assertEquals(null, old.folder)
        assertTrue(old.tags.isEmpty())
        assertTrue(store.history("a").isEmpty())
        store.put(old.copy(body = "new source"))
        assertTrue(File(path).readText().contains("\"version\":4"))
        val reopened = FileNoteStore(path)
        assertEquals(old, reopened.history("a").single().note)
        assertContentEquals(byteArrayOf(4, 5), reopened.readAttachment("a", id))
        assertEquals(1, File("$path.attachments").listFiles().orEmpty().size)
    }

    @Test
    fun an_unsupported_version_cannot_be_read_or_overwritten() = runTest {
        for (version in listOf(0, 5, 999)) {
            val contents = """{"version":$version,"notes":[],"disclosureAcknowledged":false}"""
            File(path).writeText(contents)
            val store = FileNoteStore(path)

            assertFailsWith<IllegalStateException> { store.all() }
            assertFailsWith<IllegalStateException> { store.put(Note("a", "", "body", 1)) }
            assertFailsWith<IllegalStateException> { store.remove("a") }
            assertFailsWith<IllegalStateException> { store.acknowledgeDisclosure() }
            assertEquals(contents, File(path).readText())
        }
    }

    @Test
    fun attachments_survive_restart_and_removal_deletes_only_after_metadata_save() = runTest {
        val note = Note("a", "Files", "source", 1)
        val store = FileNoteStore(path)
        store.put(note)
        val bytes = byteArrayOf(0, 1, -1)
        val attachment = store.addAttachment(note.id, "example.bin", bytes)
        val reopened = FileNoteStore(path)
        assertEquals(listOf(attachment), reopened.all().single().attachments)
        assertContentEquals(bytes, reopened.readAttachment(note.id, attachment.id))

        val writer = FailingWriter()
        val failing = FileNoteStore(path, ::readNoteFile, writer::write)
        writer.failNext = true
        assertFailsWith<IOException> { failing.removeAttachment(note.id, attachment.id) }
        assertContentEquals(bytes, failing.readAttachment(note.id, attachment.id))
        assertContentEquals(bytes, FileNoteStore(path).readAttachment(note.id, attachment.id))

        failing.removeAttachment(note.id, attachment.id)
        assertTrue(FileNoteStore(path).all().single().attachments.isEmpty())
        assertTrue(File("$path.attachments/${attachment.storageId}").exists(), "retained history owns the removed payload")
    }

    @Test
    fun attachment_metadata_is_never_published_after_a_failed_write() = runTest {
        val note = Note("a", "Files", "source", 1)
        FileNoteStore(path).put(note)
        val writer = FailingWriter()
        val store = FileNoteStore(path, ::readNoteFile, writer::write)
        writer.failNext = true
        assertFailsWith<IOException> { store.addAttachment(note.id, "example.bin", byteArrayOf(1)) }
        assertEquals(note, store.all().single())
        assertEquals(note, FileNoteStore(path).all().single())
        assertTrue(File("$path.attachments").listFiles().orEmpty().isEmpty())
    }

    @Test
    fun package_import_is_atomic_and_equal_reference_ids_do_not_overwrite_other_notes() = runTest {
        val id = "0123456789abcdef0123456789abcdef"
        fun content(byte: Byte) = NotePackages.encode(NotePackage("Imported", "[file](attachment:$id)  ", NoteFormat.MARKDOWN,
            listOf(NotePackageAttachment(id, "file.bin", "application/octet-stream", byteArrayOf(byte)))))
        val store = FileNoteStore(path)
        val first = store.importPackage(content(1), "first", 1)
        val second = store.importPackage(content(2), "second", 2)
        assertEquals(first.body, second.body)
        assertContentEquals(byteArrayOf(1), store.readAttachment("first", id))
        assertContentEquals(byteArrayOf(2), store.readAttachment("second", id))
        assertContentEquals(byteArrayOf(1), NotePackages.decode(store.exportPackage("first")).attachments.single().data)

        val writer = FailingWriter()
        val failing = FileNoteStore(path, ::readNoteFile, writer::write)
        writer.failNext = true
        assertFailsWith<IOException> { failing.importPackage(content(3), "failed", 3) }
        assertEquals(setOf("first", "second"), FileNoteStore(path).all().map { it.id }.toSet())
        assertEquals(2, File("$path.attachments").listFiles().orEmpty().size)
    }

    @Test
    fun forged_or_stale_metadata_and_oversized_blob_are_rejected() = runTest {
        val store = FileNoteStore(path)
        val note = Note("a", "Files", "source", 1)
        store.put(note)
        val attachment = store.addAttachment(note.id, "example.bin", byteArrayOf(1))
        store.put(note.copy(title = "stale"))
        assertEquals(listOf(attachment), store.all().single().attachments)
        store.put(store.all().single().copy(attachments = listOf(attachment.copy(name = "changed"))))
        assertEquals(listOf(attachment), store.all().single().attachments)
        File("$path.attachments/${attachment.storageId}").writeBytes(ByteArray(NoteAttachments.MAX_FILE_BYTES + 1))
        assertFailsWith<IllegalArgumentException> { store.readAttachment(note.id, attachment.id) }
        assertFailsWith<IllegalStateException> { store.readAttachment(note.id, "../notes.json") }
    }

    @Test
    fun cancellation_during_metadata_commit_keeps_blob_metadata_and_cache_consistent() = runTest {
        FileNoteStore(path).put(Note("a", "Files", "body", 1))
        var duringWrite: () -> Unit = {}
        val store = FileNoteStore(path, ::readNoteFile, writeFile = { file, contents ->
            duringWrite()
            writeNoteFile(file, contents)
        })
        val operation = launch { store.addAttachment("a", "file.bin", byteArrayOf(1, 2, 3)) }
        duringWrite = { operation.cancel() }
        operation.join()
        val attachment = store.all().single().attachments.single()
        assertContentEquals(byteArrayOf(1, 2, 3), store.readAttachment("a", attachment.id))
        assertEquals(store.all(), FileNoteStore(path).all())
        assertContentEquals(byteArrayOf(1, 2, 3), FileNoteStore(path).readAttachment("a", attachment.id))
    }

    @Test
    fun organization_is_canonical_durable_searchable_and_protected_from_queued_autosave() = runTest {
        val store = FileNoteStore(path)
        val stale = store.put(Note("a", "Title", "Body", 1))
        store.updateOrganization("a", "  Work  ", listOf(" Travel ", "Travel", "Ideas"))
        val saved = store.put(stale.copy(body = "typed before organization", updatedMs = 2))
        assertEquals("Work", saved.folder)
        assertEquals(listOf("Ideas", "Travel"), saved.tags)
        assertEquals(saved, FileNoteStore(path).all().single())
        assertEquals(listOf(saved), Notes.search(listOf(saved), "travel"))
        assertEquals(listOf(saved), NoteOrganization.filter(listOf(saved), "Work", "Ideas"))
        assertTrue(NoteOrganization.filter(listOf(saved), "Other").isEmpty())
        assertFailsWith<IllegalArgumentException> { store.updateOrganization("a", "x".repeat(65), emptyList()) }
        assertFailsWith<IllegalArgumentException> { store.updateOrganization("a", null, List(17) { "$it" }) }
    }

    @Test
    fun history_restores_exact_source_organization_and_removed_attachment_across_restart() = runTest {
        val store = FileNoteStore(path)
        store.put(Note("a", "Original", "![x](attachment:pending)  ", 1))
        store.updateOrganization("a", "Research", listOf("source"))
        val attachment = store.addAttachment("a", "original.bin", byteArrayOf(1, 2, -1))
        val original = store.all().single()
        store.removeAttachment("a", attachment.id)
        val changed = store.put(store.all().single().copy(title = "Changed", body = "new body", format = NoteFormat.PLAIN_TEXT))
        val reopened = FileNoteStore(path)
        val selected = reopened.history("a").single { it.note.revision == original.revision }
        val restored = reopened.restoreRevision("a", selected.id)
        assertEquals(original.title, restored.title)
        assertEquals(original.body, restored.body)
        assertEquals(original.folder, restored.folder)
        assertEquals(original.tags, restored.tags)
        assertEquals(original.format, restored.format)
        assertContentEquals(byteArrayOf(1, 2, -1), reopened.readAttachment("a", attachment.id))
        assertTrue(reopened.history("a").any { it.note == changed }, "restore retains the replaced current state")
        assertTrue(reopened.history("a").any { it.id == selected.id }, "restore keeps selected history")
        assertFailsWith<IllegalStateException> { reopened.put(changed.copy(body = "late autosave")) }
        assertEquals(restored, FileNoteStore(path).all().single())
    }

    @Test
    fun trash_restore_and_purge_preserve_then_collect_all_versions_and_payloads() = runTest {
        val store = FileNoteStore(path)
        val stale = store.put(Note("a", "Title", "Body", 1))
        val attachment = store.addAttachment("a", "file.bin", byteArrayOf(1))
        store.removeAttachment("a", attachment.id)
        store.remove("a")
        val reopened = FileNoteStore(path)
        assertTrue(reopened.all().isEmpty())
        assertEquals("a", reopened.trash().single().id)
        assertTrue(reopened.history("a").isNotEmpty())
        assertTrue(File("$path.attachments/${attachment.storageId}").exists())
        assertFailsWith<IllegalStateException> { reopened.put(stale) }
        val restored = reopened.restore("a", 22)
        assertTrue(reopened.trash().isEmpty())
        assertEquals(22L, restored.updatedMs)
        assertFailsWith<IllegalStateException> { reopened.put(stale) }
        assertFailsWith<IllegalStateException> { reopened.purge("a") }
        reopened.remove("a")
        reopened.purge("a")
        assertTrue(FileNoteStore(path).trash().isEmpty())
        assertTrue(File("$path.attachments").listFiles().orEmpty().isEmpty())
    }

    @Test
    fun history_is_bounded_without_duplicating_attachment_payloads_and_gc_follows_retention() = runTest {
        val store = FileNoteStore(path)
        store.put(Note("a", "Title", "Body", 1))
        val attachment = store.addAttachment("a", "file.bin", byteArrayOf(1))
        repeat(25) { store.put(store.all().single().copy(pinned = it % 2 == 0)) }
        assertEquals(20, store.history("a").size)
        assertEquals(1, File("$path.attachments").listFiles().orEmpty().size)
        store.removeAttachment("a", attachment.id)
        repeat(20) { store.put(store.all().single().copy(pinned = it % 2 != 0)) }
        assertEquals(20, FileNoteStore(path).history("a").size)
        assertTrue(File("$path.attachments").listFiles().orEmpty().isEmpty())
    }

    @Test
    fun failed_restore_and_purge_leave_cache_disk_and_retained_payloads_unchanged() = runTest {
        val originalStore = FileNoteStore(path)
        originalStore.put(Note("a", "Original", "Body", 1))
        val attachment = originalStore.addAttachment("a", "file.bin", byteArrayOf(1))
        originalStore.removeAttachment("a", attachment.id)
        val writer = FailingWriter()
        val store = FileNoteStore(path, ::readNoteFile, writer::write)
        val before = store.all().single()
        val history = store.history("a")
        writer.failNext = true
        assertFailsWith<IOException> { store.restoreRevision("a", history.first().id) }
        assertEquals(before, store.all().single())
        assertEquals(history, store.history("a"))
        assertEquals(before, FileNoteStore(path).all().single())
        store.remove("a")
        val trash = store.trash()
        writer.failNext = true
        assertFailsWith<IOException> { store.purge("a") }
        assertEquals(trash, store.trash())
        assertEquals(trash, FileNoteStore(path).trash())
        assertTrue(File("$path.attachments/${attachment.storageId}").exists())
    }

    @Test
    fun missing_historical_payload_prevents_restore_without_changing_current_state() = runTest {
        val store = FileNoteStore(path)
        store.put(Note("a", "Title", "Body", 1))
        val attachment = store.addAttachment("a", "file.bin", byteArrayOf(1))
        store.removeAttachment("a", attachment.id)
        val before = store.all().single()
        val revision = store.history("a").first()
        File("$path.attachments/${attachment.storageId}").delete()
        assertFailsWith<IllegalStateException> { store.restoreRevision("a", revision.id) }
        assertEquals(before, FileNoteStore(path).all().single())
    }

    @Test
    fun corrupt_persisted_history_and_noncanonical_metadata_cannot_be_overwritten() = runTest {
        for (extra in listOf("\"tags\":[\" x \" ]", "\"revision\":-1", "\"folder\":\"x\\ny\"")) {
            val text = """{"version":4,"notes":[{"id":"a","title":"","body":"body","updatedMs":1,$extra}]}"""
            File(path).writeText(text)
            val store = FileNoteStore(path)
            assertFailsWith<IllegalArgumentException> { store.all() }
            assertFailsWith<IllegalArgumentException> { store.put(Note("new", "", "body", 1)) }
            assertEquals(text, File(path).readText())
        }
    }

    @Test
    fun malformed_persisted_history_owner_or_revision_is_fail_safe() = runTest {
        val current = """{"id":"a","title":"","body":"body","updatedMs":1,"revision":1}"""
        val id = "0123456789abcdef0123456789abcdef"
        val contents = listOf(
            """{"version":4,"notes":[$current],"history":{"missing":[]}}""",
            """{"version":4,"notes":[$current],"history":{"a":[{"id":"$id","savedAtMs":1,"note":$current}]}}""",
        )
        for (text in contents) {
            File(path).writeText(text)
            val store = FileNoteStore(path)
            assertFailsWith<IllegalArgumentException> { store.all() }
            assertFailsWith<IllegalArgumentException> { store.acknowledgeDisclosure() }
            assertEquals(text, File(path).readText())
        }
    }

    @Test
    fun text_checkpoint_survives_restart_while_every_current_autosave_is_durable() = runTest {
        val original = FileNoteStore(path).put(Note("a", "Title", "before burst", 1))
        repeat(30) { index ->
            val store = FileNoteStore(path)
            store.put(store.all().single().copy(body = "typed $index"))
            assertEquals("typed $index", FileNoteStore(path).all().single().body)
        }
        val reopened = FileNoteStore(path)
        assertEquals(listOf(original), reopened.history("a").map { it.note })
        val beforeOrganization = reopened.all().single()
        reopened.updateOrganization("a", "Work", listOf("tag"))
        assertEquals(beforeOrganization, reopened.history("a").first().note)
        val beforeFile = reopened.all().single()
        val attachment = reopened.addAttachment("a", "file.bin", byteArrayOf(1))
        assertEquals(beforeFile, reopened.history("a").first().note)
        val withFile = reopened.all().single()
        reopened.removeAttachment("a", attachment.id)
        assertEquals(withFile, reopened.history("a").first().note)
        val beforeText = reopened.all().single()
        reopened.put(beforeText.copy(body = "next text window after file removal"))
        assertEquals(beforeText, reopened.history("a").first().note)
    }

    private class FailingWriter {
        var failNext = false

        fun write(path: String, contents: String) {
            if (failNext) {
                failNext = false
                throw IOException("injected atomic-write failure")
            }
            writeNoteFile(path, contents)
        }
    }

    @Test
    fun load_removes_interrupted_write_leftovers_and_unreferenced_blobs_but_keeps_live_ones() = runTest {
        val store = FileNoteStore(path)
        val note = store.put(Note(id = "a", title = "with file", body = "", updatedMs = 1))
        val live = store.addAttachment(note.id, "example.bin", byteArrayOf(1, 2, 3))
        val attachments = File("$path.attachments")
        val liveBlob = File(attachments, store.all().single().attachments.single().storageId)
        assertTrue(liveBlob.isFile)
        // What a kill leaves: a blob written before its commit, temporaries, and the state temporary.
        val orphan = File(attachments, "0123456789abcdef0123456789abcdef").apply { writeBytes(byteArrayOf(9)) }
        val blobTemporary = File(attachments, "fedcba9876543210fedcba9876543210.tmp").apply { writeBytes(byteArrayOf(8)) }
        val liveTemporary = File(attachments, "${liveBlob.name}.tmp").apply { writeBytes(byteArrayOf(7)) }
        val stateTemporary = File("$path.tmp").apply { writeText("{") }
        // Names that this store never makes stay where they are.
        val foreign = File(attachments, "keep-me.tmp").apply { writeBytes(byteArrayOf(6)) }
        val neighbour = File(directory, "other.tmp").apply { writeText("other") }

        val reopened = FileNoteStore(path)
        assertEquals(listOf("a"), reopened.all().map { it.id })

        assertFalse(orphan.exists())
        assertFalse(blobTemporary.exists())
        assertFalse(liveTemporary.exists())
        assertFalse(stateTemporary.exists())
        assertTrue(foreign.exists())
        assertTrue(neighbour.exists())
        assertContentEquals(byteArrayOf(1, 2, 3), reopened.readAttachment(note.id, live.id))
    }

    @Test
    fun a_blob_that_only_a_retained_revision_names_survives_the_sweep() = runTest {
        val store = FileNoteStore(path)
        val note = store.put(Note(id = "a", title = "with file", body = "", updatedMs = 1))
        val attachment = store.addAttachment(note.id, "example.bin", byteArrayOf(4, 5))
        val storageId = store.all().single().attachments.single().storageId
        store.removeAttachment(note.id, attachment.id)
        val blob = File("$path.attachments", storageId)
        val named = store.history(note.id).any { version -> version.note.attachments.any { it.storageId == storageId } }

        FileNoteStore(path).all()

        // A retained revision keeps its payload for restoration; only an unnamed blob goes.
        assertEquals(named, blob.exists())
    }

    @Test
    fun an_unreadable_state_file_deletes_nothing() = runTest {
        val store = FileNoteStore(path)
        val note = store.put(Note(id = "a", title = "with file", body = "", updatedMs = 1))
        store.addAttachment(note.id, "example.bin", byteArrayOf(1))
        val attachments = File("$path.attachments")
        val before = attachments.list()!!.toSortedSet()
        File(path).writeText("{ not json")
        val stateTemporary = File("$path.tmp").apply { writeText("{") }
        val orphan = File(attachments, "0123456789abcdef0123456789abcdef").apply { writeBytes(byteArrayOf(9)) }

        assertFailsWith<IllegalStateException> { FileNoteStore(path).all() }

        assertTrue(stateTemporary.exists())
        assertTrue(orphan.exists())
        assertEquals(before + orphan.name, attachments.list()!!.toSortedSet())
    }

    @Test
    fun a_missing_state_file_deletes_nothing() = runTest {
        val attachments = File("$path.attachments").apply { mkdirs() }
        val orphan = File(attachments, "0123456789abcdef0123456789abcdef").apply { writeBytes(byteArrayOf(9)) }

        assertTrue(FileNoteStore(path).all().isEmpty())

        assertTrue(orphan.exists())
    }

    @Test
    fun an_atomic_write_leaves_no_temporary_beside_the_file() = runTest {
        FileNoteStore(path).put(Note(id = "a", title = "one", body = "", updatedMs = 1))

        assertEquals(listOf("notes.json"), directory.list()!!.toList())
    }

    @Test
    fun a_failed_directory_sync_after_the_rename_fails_no_write() = runTest {
        assertTrue(syncNoteDirectory(directory))
        assertFalse(syncNoteDirectory(directory) { throw IOException("sync failed") })
        assertFalse(syncNoteDirectory(File(directory, "missing")))
        // The store's own writes keep their state and blobs whatever the sync reports.
        val store = FileNoteStore(path)
        val note = store.put(Note(id = "a", title = "with file", body = "", updatedMs = 1))
        val attachment = store.addAttachment(note.id, "example.bin", byteArrayOf(1, 2))
        assertContentEquals(byteArrayOf(1, 2), FileNoteStore(path).readAttachment(note.id, attachment.id))
    }
}
