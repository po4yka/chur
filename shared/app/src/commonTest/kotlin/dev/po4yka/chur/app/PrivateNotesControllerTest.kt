package dev.po4yka.chur.app

import dev.po4yka.chur.core.model.ChurStatus
import dev.po4yka.chur.ffi.ChurFailure
import dev.po4yka.chur.ffi.PrivateNote
import dev.po4yka.chur.ffi.PrivateNoteAction
import dev.po4yka.chur.ffi.PrivateNotePage
import dev.po4yka.chur.ffi.PrivateNoteSelection
import dev.po4yka.chur.ffi.PrivateNoteSummary
import dev.po4yka.chur.vault.VaultState
import kotlinx.coroutines.async
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertContentEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class PrivateNotesControllerTest {
    @Test
    fun attachment_add_requires_a_saved_revision_then_keeps_the_inserted_reference_unsaved() = runTest {
        val access = Access()
        val controller = controller(access)
        controller.create()
        val rejected = byteArrayOf(1, 2)
        controller.addAttachment("file.bin", rejected)
        assertTrue(rejected.all { it == 0.toByte() })
        controller.body("new note")
        controller.format(dev.po4yka.chur.ffi.PrivateNoteFormat.MARKDOWN)
        controller.save(); advanceUntilIdle()
        val data = byteArrayOf(1, 2, 3)
        controller.addAttachment("file.bin", data); advanceUntilIdle()
        assertTrue(data.all { it == 0.toByte() })
        val editor = controller.state.value.editor!!
        assertEquals(1, editor.attachments.size)
        assertEquals(1, editor.saved!!.attachmentCount)
        assertTrue(editor.body.contains("attachment:${editor.attachments.single().id}"))
        assertTrue(editor.dirty)
        controller.removeAttachment(editor.attachments.single().id); advanceUntilIdle()
        assertEquals(1, access.files.size)
        controller.save(); advanceUntilIdle()
        controller.removeAttachment(editor.attachments.single().id); advanceUntilIdle()
        assertTrue(access.files.isEmpty())
        controller.close()
    }

    @Test
    fun a_late_attachment_read_is_cleared_and_cannot_cross_a_lock_or_identity_change() = runTest {
        val state = MutableStateFlow<VaultState>(VaultState.Unlocked(1))
        val access = Access()
        val idBytes = ByteArray(16) { 1 }
        val id = "01".repeat(16)
        access.files[id] = dev.po4yka.chur.ffi.PrivateNoteAttachmentData(idBytes, "a.bin", "application/octet-stream", byteArrayOf(3, 4))
        access.record = access.record.copy(attachmentCount = 1)
        val controller = controller(access, state)
        controller.open(summary(access.record)); advanceUntilIdle()
        val blocked = CompletableDeferred<Unit>()
        access.attachmentGate = blocked
        val result = async { runCatching { controller.readAttachment(id) } }
        runCurrent()
        state.value = VaultState.Unlocked(2); runCurrent()
        blocked.complete(Unit); advanceUntilIdle()
        assertTrue(result.await().isFailure)
        assertTrue(access.lastAttachmentRead!!.all { it == 0.toByte() })
        assertNull(controller.state.value.editor)
    }

    @Test
    fun importing_a_package_commits_files_and_source_together_and_clears_input() = runTest {
        val access = Access()
        val controller = controller(access)
        val id = "0123456789abcdef0123456789abcdef"
        val body = "[file](attachment:$id)\n"
        val bytes = dev.po4yka.chur.notes.NotePackages.encode(dev.po4yka.chur.notes.NotePackage("Imported", body,
            dev.po4yka.chur.notes.NoteFormat.MARKDOWN, listOf(dev.po4yka.chur.notes.NotePackageAttachment(id, "a.bin",
                "application/octet-stream", byteArrayOf(4, 5)))))
        controller.importPackage(bytes); advanceUntilIdle()
        assertTrue(bytes.all { it == 0.toByte() })
        assertEquals(body, controller.state.value.editor!!.body)
        assertFalse(controller.state.value.editor!!.dirty)
        assertEquals(1, controller.state.value.editor!!.attachments.size)
        assertContentEquals(byteArrayOf(4, 5), access.files.values.single().data)
        controller.close()
        val late = byteArrayOf(8, 9)
        controller.importPackage(late)
        assertTrue(late.all { it == 0.toByte() })
    }

    @Test
    fun markdown_import_and_format_only_edits_survive_explicit_save_without_rewriting_source() = runTest {
        val access = Access()
        val controller = controller(access)
        runCurrent()
        val source = "# Заголовок\n\n- [ ] task\n\n| a | b |\n| --- | --- |\n| x | y |\n\n[ref]: https://example.invalid\n"
        controller.importMarkdown("Imported", source)
        assertEquals(0, access.saves)
        assertEquals(dev.po4yka.chur.ffi.PrivateNoteFormat.MARKDOWN, controller.state.value.editor!!.format)
        controller.save()
        advanceUntilIdle()
        assertEquals(source, controller.state.value.editor!!.saved!!.body)
        assertFalse(controller.state.value.editor!!.dirty)
        controller.format(dev.po4yka.chur.ffi.PrivateNoteFormat.PLAIN_TEXT)
        assertTrue(controller.state.value.editor!!.dirty)
        controller.save()
        advanceUntilIdle()
        assertEquals(source, controller.state.value.editor!!.saved!!.body)
        assertEquals(dev.po4yka.chur.ffi.PrivateNoteFormat.PLAIN_TEXT, controller.state.value.editor!!.saved!!.format)
        controller.close()
    }

    @Test
    fun a_new_note_is_only_a_session_draft_until_explicit_save() = runTest {
        val access = Access()
        val controller = controller(access)
        runCurrent()
        controller.create()
        controller.title("Private title")
        controller.body("Private body")
        advanceTimeBy(10_000)
        runCurrent()
        assertEquals(0, access.saves)
        assertTrue(controller.state.value.editor!!.dirty)
        controller.save()
        advanceUntilIdle()
        assertEquals(1, access.saves)
        assertFalse(controller.state.value.editor!!.dirty)
        assertEquals("Private body", controller.state.value.editor!!.saved!!.body)
        controller.close()
    }

    @Test
    fun a_save_failure_keeps_the_draft_and_back_requires_an_explicit_choice() = runTest {
        val access = Access().apply { saveFailure = ChurStatus.STORAGE_UNAVAILABLE }
        val controller = controller(access)
        controller.create(); controller.body("keep this text")
        controller.back()
        assertEquals(PrivateNoteConfirmation.LEAVE, controller.state.value.confirmation)
        controller.dismissConfirmation()
        assertEquals("keep this text", controller.state.value.editor!!.body)
        controller.saveAndBack()
        advanceUntilIdle()
        assertNotNull(controller.state.value.error)
        assertEquals("keep this text", controller.state.value.editor!!.body)
        assertTrue(controller.state.value.editor!!.dirty)
        controller.back(); controller.discardAndBack(); advanceUntilIdle()
        assertNull(controller.state.value.editor)
        assertEquals(1, access.saves)
        controller.close()
    }

    @Test
    fun lock_clears_text_and_a_late_save_result_cannot_restore_it_or_export_in_a_new_identity() = runTest {
        val state = MutableStateFlow<VaultState>(VaultState.Unlocked(1))
        val blocked = CompletableDeferred<Unit>()
        val access = Access().apply { saveGate = blocked }
        var exports = 0
        val controller = controller(access, state, onExport = { exports++ })
        controller.create(); controller.body("old identity draft")
        controller.saveAndExport()
        runCurrent()
        assertTrue(controller.state.value.busy)
        state.value = VaultState.Unlocked(2)
        runCurrent()
        assertNull(controller.state.value.editor)
        assertTrue(controller.state.value.notes.isEmpty())
        blocked.complete(Unit)
        advanceUntilIdle()
        assertEquals(0, exports)
        assertNull(controller.state.value.editor)
        controller.body("late input")
        controller.save()
        assertNull(controller.state.value.editor)
    }

    @Test
    fun closing_a_dirty_editor_never_writes_from_disposal() = runTest {
        val access = Access()
        val controller = controller(access)
        controller.create(); controller.body("discard on lock")
        controller.close()
        advanceUntilIdle()
        assertEquals(0, access.saves)
        assertNull(controller.state.value.editor)
    }

    @Test
    fun search_is_debounced_and_only_the_latest_query_reaches_the_list() = runTest {
        val access = Access()
        val controller = controller(access)
        runCurrent()
        controller.search("first")
        advanceTimeBy(100)
        controller.search("second")
        advanceTimeBy(200)
        runCurrent()
        assertEquals(listOf("", "second"), access.queries)
        assertEquals("second", controller.state.value.terms)
        controller.close()
    }

    @Test
    fun oversized_search_keeps_the_last_valid_query_and_does_not_call_native() = runTest {
        val access = Access()
        val controller = controller(access)
        advanceUntilIdle()
        controller.search("é".repeat(128))
        advanceUntilIdle()
        controller.search("é".repeat(129))
        advanceUntilIdle()
        assertEquals("é".repeat(128), controller.state.value.terms)
        assertEquals(2, access.queries.size)
        assertNotNull(controller.state.value.error)
        controller.search((1..33).joinToString(" ") { "x" })
        advanceUntilIdle()
        assertEquals(2, access.queries.size)
        controller.close()
    }

    @Test
    fun a_mutation_does_not_reuse_the_previous_catalog_cursor() = runTest {
        val access = Access().apply { paged = true }
        val controller = controller(access)
        advanceUntilIdle()
        controller.nextPage()
        advanceUntilIdle()
        assertEquals(2, controller.state.value.page)
        controller.pin(summary(access.record))
        advanceUntilIdle()
        assertNull(access.cursors.last())
        assertEquals(1, controller.state.value.page)
        controller.nextPage()
        advanceUntilIdle()
        controller.open(summary(access.record))
        advanceUntilIdle()
        controller.body("changed")
        controller.saveAndBack()
        advanceUntilIdle()
        assertNull(access.cursors.last())
        assertEquals(1, controller.state.value.page)
        controller.close()
    }

    @Test
    fun paging_uses_opaque_cursors_and_keeps_only_one_summary_page() = runTest {
        val access = Access().apply { paged = true }
        val controller = controller(access)
        advanceUntilIdle()
        assertTrue(controller.state.value.hasNext)
        assertEquals(1, controller.state.value.notes.size)
        controller.nextPage()
        advanceUntilIdle()
        assertEquals(2, controller.state.value.page)
        assertTrue(controller.state.value.hasPrevious)
        assertEquals(1, controller.state.value.notes.size)
        assertEquals(1, access.cursors.last()!!.single().toInt())
        controller.previousPage()
        advanceUntilIdle()
        assertEquals(1, controller.state.value.page)
        assertNull(access.cursors.last())
        controller.close()
    }

    @Test
    fun trash_restore_and_permanent_delete_use_the_loaded_revision_and_require_confirmation() = runTest {
        val access = Access()
        val controller = controller(access)
        advanceUntilIdle()
        controller.open(summary(access.record)); advanceUntilIdle()
        controller.trash() // No confirmation: do not remove anything.
        assertTrue(access.changes.isEmpty())
        controller.body("unsaved change")
        controller.requestTrash(); controller.trash(); advanceUntilIdle()
        assertEquals(PrivateNoteAction.TRASH, access.changes.last().first)
        assertEquals(1L, access.changes.last().second)
        assertNull(controller.state.value.editor)
        access.record = access.record.copy(trashedAtMs = 10)
        controller.open(summary(access.record)); advanceUntilIdle()
        controller.restore(); advanceUntilIdle()
        assertEquals(PrivateNoteAction.RESTORE, access.changes.last().first)
        access.record = access.record.copy(trashedAtMs = 10)
        controller.open(summary(access.record)); advanceUntilIdle()
        controller.purge()
        assertEquals(2, access.changes.size)
        controller.requestPurge(); controller.purge(); advanceUntilIdle()
        assertEquals(PrivateNoteAction.PURGE, access.changes.last().first)
        controller.close()
    }

    @Test
    fun export_of_dirty_text_requires_save_and_uses_only_the_committed_result() = runTest {
        val access = Access()
        val exported = mutableListOf<PrivateNote>()
        val controller = controller(access, onExport = { exported += it })
        advanceUntilIdle()
        controller.open(summary(access.record)); advanceUntilIdle()
        controller.body("new body")
        controller.export()
        assertEquals(PrivateNoteConfirmation.EXPORT, controller.state.value.confirmation)
        assertTrue(exported.isEmpty())
        controller.saveAndExport(); advanceUntilIdle()
        assertEquals("new body", exported.single().body)
        assertEquals(2L, exported.single().revision)
        controller.close()
    }

    @Test
    fun pin_toggles_the_committed_summary_and_trash_search_is_a_separate_query() = runTest {
        val access = Access()
        val controller = controller(access)
        advanceUntilIdle()
        controller.pin(summary(access.record)); advanceUntilIdle()
        assertEquals(PrivateNoteAction.PIN, access.changes.single().first)
        controller.showTrash(true); advanceUntilIdle()
        assertTrue(access.trashQueries.last())
        controller.close()
    }

    @Test
    fun byte_limits_accept_unicode_at_the_boundary_and_preserve_text_on_overflow() = runTest {
        val controller = controller(Access())
        controller.create()
        controller.title("é".repeat(128))
        assertEquals(256, utf8Size(controller.state.value.editor!!.title))
        controller.title("é".repeat(129))
        assertEquals("é".repeat(128), controller.state.value.editor!!.title)
        assertNotNull(controller.state.value.error)
        controller.body("🌍".repeat(PRIVATE_NOTE_BODY_MAX_BYTES / 4))
        assertEquals(PRIVATE_NOTE_BODY_MAX_BYTES, utf8Size(controller.state.value.editor!!.body))
        controller.body(controller.state.value.editor!!.body + "x")
        assertEquals(PRIVATE_NOTE_BODY_MAX_BYTES, utf8Size(controller.state.value.editor!!.body))
        controller.close()
    }

    @Test
    fun actual_edits_notify_activity_without_a_background_keepalive() = runTest {
        var touches = 0
        val controller = controller(Access(), onActivity = { touches++ })
        advanceUntilIdle()
        assertEquals(0, touches)
        controller.create()
        controller.title("Title")
        controller.body("Body")
        assertEquals(2, touches)
        controller.body("Body") // No actual edit.
        advanceTimeBy(200_000)
        runCurrent()
        assertEquals(2, touches)
        controller.activity() // Metadata IME/hardware editing reports activity explicitly.
        assertEquals(3, touches)
        controller.close()
        controller.activity()
        assertEquals(3, touches)
    }

    @Test
    fun encrypted_selection_spans_pages_and_keeps_the_revision_selected_without_loading_bodies() = runTest {
        val access = Access().apply {
            paged = true
            secondRecord = record.copy(noteId = byteArrayOf(2), revision = 7, title = "Second", body = "Second body")
        }
        val exports = mutableListOf<List<PrivateNoteSelection>>()
        val controller = controller(access, onEncryptedExport = { exports += it })
        advanceUntilIdle()
        controller.selectPage()
        controller.nextPage()
        advanceUntilIdle()
        controller.selectPage()
        assertEquals(2, controller.state.value.selection.size)
        // A later list refresh must not silently change the selected revision.
        access.record = access.record.copy(revision = 9)
        controller.exportEncryptedSelection()
        assertEquals(listOf(1L, 7L), exports.single().map { it.revision })
        assertContentEquals(byteArrayOf(1), exports.single().first().noteId)
        assertContentEquals(byteArrayOf(2), exports.single().last().noteId)
        assertEquals(0, access.loads)
        assertEquals(0, access.saves)
        // The host may retain a reference without sharing mutable IDs with the list.
        exports.single().first().noteId[0] = 99
        assertContentEquals(byteArrayOf(1), controller.state.value.selection.values.first().noteId)
        controller.close()
    }

    @Test
    fun selection_is_cleared_by_back_search_trash_create_and_lock_and_never_exports_after_lock() = runTest {
        val state = MutableStateFlow<VaultState>(VaultState.Unlocked(1))
        val access = Access()
        var leaves = 0
        var exports = 0
        val controller = controller(access, state, onLeave = { leaves++ }, onEncryptedExport = { exports++ })
        advanceUntilIdle()
        controller.selectPage()
        controller.back()
        assertTrue(controller.state.value.selection.isEmpty())
        assertEquals(0, leaves)
        controller.back()
        assertEquals(1, leaves)
        controller.selectPage()
        controller.search("Saved")
        assertTrue(controller.state.value.selection.isEmpty())
        advanceUntilIdle()
        controller.selectPage()
        controller.showTrash(true)
        assertTrue(controller.state.value.selection.isEmpty())
        advanceUntilIdle()
        controller.selectPage()
        assertTrue(controller.state.value.selection.isEmpty())
        controller.showTrash(false)
        advanceUntilIdle()
        controller.selectPage()
        controller.create()
        assertTrue(controller.state.value.selection.isEmpty())
        controller.back()
        advanceUntilIdle()
        controller.selectPage()
        state.value = VaultState.Unlocked(2)
        runCurrent()
        assertTrue(controller.state.value.selection.isEmpty())
        controller.exportEncryptedSelection()
        assertEquals(0, exports)
    }

    @Test
    fun an_encrypted_editor_export_saves_first_and_never_calls_the_plaintext_export_callback() = runTest {
        val access = Access()
        val encrypted = mutableListOf<List<PrivateNoteSelection>>()
        var plaintext = 0
        val controller = controller(access, onExport = { plaintext++ }, onEncryptedExport = { encrypted += it })
        advanceUntilIdle()
        controller.open(summary(access.record))
        advanceUntilIdle()
        controller.body("Updated private body")
        controller.exportEncrypted()
        assertEquals(PrivateNoteConfirmation.ENCRYPTED_EXPORT, controller.state.value.confirmation)
        assertTrue(encrypted.isEmpty())
        controller.saveAndExport()
        advanceUntilIdle()
        assertEquals(1, access.saves)
        assertEquals(2L, encrypted.single().single().revision)
        assertContentEquals(access.record.noteId, encrypted.single().single().noteId)
        assertEquals(0, plaintext)
        assertFalse(controller.state.value.editor!!.dirty)
        controller.close()
    }

    @Test
    fun a_failed_encrypted_save_keeps_the_draft_and_late_completion_after_lock_cannot_export() = runTest {
        val state = MutableStateFlow<VaultState>(VaultState.Unlocked(1))
        val gate = CompletableDeferred<Unit>()
        val access = Access().apply { saveFailure = ChurStatus.STORAGE_UNAVAILABLE }
        var exports = 0
        val controller = controller(access, state, onEncryptedExport = { exports++ })
        controller.create()
        controller.body("Keep private text")
        controller.exportEncrypted()
        controller.saveAndExport()
        advanceUntilIdle()
        assertEquals("Keep private text", controller.state.value.editor!!.body)
        assertTrue(controller.state.value.editor!!.dirty)
        assertEquals(0, exports)
        access.saveFailure = null
        access.saveGate = gate
        controller.exportEncrypted()
        controller.saveAndExport()
        runCurrent()
        state.value = VaultState.Unlocked(2)
        runCurrent()
        gate.complete(Unit)
        advanceUntilIdle()
        assertNull(controller.state.value.editor)
        assertEquals(0, exports)
    }

    @Test
    fun encrypted_note_selection_has_a_bound_and_trashed_notes_cannot_be_added() = runTest {
        val access = Access()
        val controller = controller(access)
        advanceUntilIdle()
        repeat(1_001) { value ->
            val id = ByteArray(16).apply { this[0] = (value ushr 8).toByte(); this[1] = value.toByte(); this[15] = 1 }
            controller.toggleSelection(summary(access.record.copy(noteId = id)))
        }
        assertEquals(1_000, controller.state.value.selection.size)
        assertNotNull(controller.state.value.error)
        controller.clearSelection()
        controller.toggleSelection(summary(access.record.copy(trashedAtMs = 10)))
        assertTrue(controller.state.value.selection.isEmpty())
        controller.close()
    }

    private fun kotlinx.coroutines.test.TestScope.controller(access: Access,
        state: MutableStateFlow<VaultState> = MutableStateFlow(VaultState.Unlocked(1)),
        onExport: (PrivateNote) -> Unit = {}, onActivity: () -> Unit = {}, onLeave: () -> Unit = {},
        onEncryptedExport: (List<PrivateNoteSelection>) -> Unit = {}): PrivateNotesController =
        PrivateNotesController(1, state, access, this, onLeave, onExport, StandardTestDispatcher(testScheduler), onActivity, onEncryptedExport)

    private fun kotlinx.coroutines.test.TestScope.lockDrafts(vararg controllers: PrivateNotesController): LockDrafts =
        LockDrafts(LOCK_DRAFT_SAVE_BOUND_MS, StandardTestDispatcher(testScheduler)).also { drafts ->
            controllers.forEach { drafts.register(LockDrafts.Source(it::captureForLock)) }
        }

    @Test
    fun a_lock_saves_edited_text_as_a_new_revision_before_it_ends() = runTest {
        val access = Access().apply { strictRevision = true }
        val controller = controller(access)
        val drafts = lockDrafts(controller)
        controller.open(summary(access.record)); advanceUntilIdle()
        controller.body("Edited before the lock")
        val saves = drafts.capture()
        assertEquals(1, saves.size)
        assertTrue(drafts.save(saves))
        assertEquals(1, access.saves)
        assertEquals(2, access.record.revision)
        assertEquals("Edited before the lock", access.record.body)
        assertEquals(0, drafts.lost)
        controller.close()
    }

    @Test
    fun a_lock_writes_nothing_for_a_clean_note_or_a_new_empty_editor() = runTest {
        val access = Access()
        val list = controller(access)
        val clean = controller(access)
        val empty = controller(access)
        clean.open(summary(access.record)); advanceUntilIdle()
        empty.create()
        val drafts = lockDrafts(list, clean, empty)
        assertTrue(drafts.capture().isEmpty())
        assertTrue(drafts.save(drafts.capture()))
        assertEquals(0, access.saves)
        listOf(list, clean, empty).forEach { it.close() }
    }

    @Test
    fun the_capture_is_the_last_action_so_a_new_note_is_saved_once() = runTest {
        val access = Access()
        val controller = controller(access)
        val drafts = lockDrafts(controller)
        controller.create()
        controller.body("Never saved before")
        val saves = drafts.capture()
        assertEquals(1, saves.size)
        // A second lock, a tap on Save, and further typing all come too late.
        assertTrue(drafts.capture().isEmpty())
        controller.save(); controller.body("Typed after the lock"); advanceUntilIdle()
        assertEquals(0, access.saves)
        assertTrue(drafts.save(saves))
        assertEquals(1, access.saves)
        assertEquals("Never saved before", access.record.body)
        controller.close()
    }

    @Test
    fun a_lock_save_with_a_stale_revision_keeps_the_newer_revision() = runTest {
        val access = Access().apply { strictRevision = true }
        val controller = controller(access)
        val drafts = lockDrafts(controller)
        controller.open(summary(access.record)); advanceUntilIdle()
        controller.body("Stale editor text")
        // Another writer committed a newer revision after the editor opened.
        access.record = access.record.copy(revision = 7, body = "Newer saved body")
        assertFalse(drafts.save(drafts.capture()))
        assertEquals(7, access.record.revision)
        assertEquals("Newer saved body", access.record.body)
        assertEquals(1, drafts.lost)
        controller.close()
    }

    @Test
    fun a_native_save_that_does_not_return_stops_the_wait_at_the_bound() = runTest {
        val access = Access()
        val controller = controller(access)
        val drafts = lockDrafts(controller)
        controller.open(summary(access.record)); advanceUntilIdle()
        controller.body("Edited text")
        access.saveGate = CompletableDeferred()
        val started = testScheduler.currentTime
        assertFalse(drafts.save(drafts.capture()))
        assertEquals(LOCK_DRAFT_SAVE_BOUND_MS, testScheduler.currentTime - started)
        assertEquals(1, drafts.lost)
        access.saveGate!!.complete(Unit); advanceUntilIdle()
        controller.close()
    }

    @Test
    fun a_save_still_waiting_for_the_repository_at_the_bound_never_starts() = runTest {
        val access = Access()
        val controller = controller(access)
        val drafts = lockDrafts(controller)
        controller.open(summary(access.record)); advanceUntilIdle()
        controller.body("Edited text")
        access.mutexGate = CompletableDeferred()
        assertFalse(drafts.save(drafts.capture()))
        // The repository becomes free only after the lock stopped waiting.
        access.mutexGate!!.complete(Unit); advanceUntilIdle()
        assertEquals(1, access.saves)
        assertEquals(0, access.writes)
        assertEquals("Saved body", access.record.body)
        controller.close()
    }

    @Test
    fun a_panic_ends_the_wait_of_an_earlier_lock_and_its_save_never_starts() = runTest {
        val access = Access()
        val controller = controller(access)
        val drafts = lockDrafts(controller)
        controller.open(summary(access.record)); advanceUntilIdle()
        controller.body("Edited text")
        access.mutexGate = CompletableDeferred()
        val result = async { drafts.save(drafts.capture()) }
        advanceTimeBy(100); runCurrent()
        val panicAt = testScheduler.currentTime
        drafts.abort()
        runCurrent()
        assertTrue(result.isCompleted)
        assertFalse(result.await())
        assertEquals(panicAt, testScheduler.currentTime)
        access.mutexGate!!.complete(Unit); advanceUntilIdle()
        assertEquals(0, access.writes)
        assertEquals("Saved body", access.record.body)
        controller.close()
    }

    @Test
    fun any_failure_of_a_save_is_a_lost_edit_and_never_escapes_the_lock() = runTest {
        val drafts = LockDrafts(LOCK_DRAFT_SAVE_BOUND_MS, StandardTestDispatcher(testScheduler))
        val failures = listOf<Throwable>(IllegalStateException("failure"), AssertionError("error"),
            kotlinx.coroutines.CancellationException("cancelled"))
        assertFalse(drafts.save(failures.map { failure -> LockDrafts.Save { throw failure } }))
        assertEquals(3, drafts.lost)
    }

    @Test
    fun a_busy_editor_captures_nothing_because_its_action_owns_the_write() = runTest {
        val access = Access()
        val controller = controller(access)
        val drafts = lockDrafts(controller)
        controller.create()
        controller.body("New note")
        access.saveGate = CompletableDeferred()
        controller.save(); runCurrent()
        assertTrue(controller.state.value.busy)
        assertTrue(drafts.capture().isEmpty())
        access.saveGate!!.complete(Unit); advanceUntilIdle()
        assertEquals(1, access.saves)
        controller.close()
    }

    @Test
    fun organization_is_explicit_filters_reach_storage_and_history_restore_replaces_current_editor() = runTest {
        val access = Access()
        val controller = controller(access)
        advanceUntilIdle()
        controller.showFilters(true)
        assertTrue(controller.state.value.filtersVisible)
        controller.back()
        assertFalse(controller.state.value.filtersVisible)
        controller.showFilters(true)
        controller.filter(" Projects ", " todo "); advanceUntilIdle()
        assertFalse(controller.state.value.filtersVisible)
        assertEquals("Projects" to "todo", access.filters)
        controller.open(controller.state.value.notes.single()); advanceUntilIdle()
        controller.organize(" Projects ", listOf("todo", "todo")); advanceUntilIdle()
        assertEquals("Projects", controller.state.value.editor!!.organization.folder)
        assertEquals(listOf("todo"), controller.state.value.editor!!.organization.tags)
        access.historicalNote = access.record.copy(title = "Recovered", body = "Original source")
        controller.showHistory(); advanceUntilIdle()
        controller.previewRevision(access.historicalNote.revision); advanceUntilIdle()
        assertNotNull(controller.state.value.historical)
        controller.restoreRevision(); advanceUntilIdle()
        assertEquals("Original source", controller.state.value.editor!!.body)
        assertFalse(controller.state.value.editor!!.dirty)
        assertNull(controller.state.value.history)
        controller.close()
    }

    @Test
    fun late_history_result_cannot_repopulate_a_locked_session() = runTest {
        val state = MutableStateFlow<VaultState>(VaultState.Unlocked(1))
        val access = Access()
        val controller = controller(access, state)
        advanceUntilIdle()
        controller.open(controller.state.value.notes.single()); advanceUntilIdle()
        access.historyGate = CompletableDeferred()
        controller.showHistory(); runCurrent()
        state.value = VaultState.Locked(); runCurrent()
        access.historyGate!!.complete(Unit); advanceUntilIdle()
        assertEquals(PrivateNotesUiState(), controller.state.value)
    }

    private class Access : PrivateNotesAccess {
        var noteOrganization = dev.po4yka.chur.ffi.PrivateNoteOrganization()
        var historicalNote = note()
        var historyGate: CompletableDeferred<Unit>? = null
        var filters = "" to ""
        override suspend fun workspace(generation: Long, terms: String, trash: Boolean, cursor: ByteArray?, folder: String, tag: String): dev.po4yka.chur.ffi.PrivateNoteWorkspacePage {
            filters = folder to tag
            val page = page(generation, terms, trash, cursor)
            return dev.po4yka.chur.ffi.PrivateNoteWorkspacePage(page, page.notes.associate { it.id to noteOrganization })
        }
        override suspend fun organization(generation: Long, id: ByteArray) = noteOrganization
        override suspend fun organize(generation: Long, saved: PrivateNote, organization: dev.po4yka.chur.ffi.PrivateNoteOrganization): PrivateNote {
            check(saved.revision == record.revision)
            noteOrganization = organization
            record = record.copy(revision = record.revision + 1)
            return record
        }
        override suspend fun history(generation: Long, id: ByteArray): List<dev.po4yka.chur.ffi.PrivateNoteRevision> {
            historyGate?.let { withContext(NonCancellable) { it.await() } }
            return listOf(dev.po4yka.chur.ffi.PrivateNoteRevision(historicalNote.revision, historicalNote.updatedMs,
                historicalNote.title, historicalNote.format, historicalNote.attachmentCount))
        }
        override suspend fun historical(generation: Long, id: ByteArray, revision: Long) =
            dev.po4yka.chur.ffi.PrivateNoteRevisionDetail(historicalNote, noteOrganization, emptyList())
        override suspend fun restoreRevision(generation: Long, saved: PrivateNote, revision: Long): PrivateNote {
            check(saved.revision == record.revision)
            record = historicalNote.copy(revision = record.revision + 1)
            return record
        }

        var record = note()
        var saves = 0
        var loads = 0
        var saveFailure: ChurStatus? = null
        var saveGate: CompletableDeferred<Unit>? = null
        /** Rejects a save whose expected revision is not the stored one, as Rust does. */
        var strictRevision = false
        /** Holds a save before the repository mutex, where `proceed` is checked. */
        var mutexGate: CompletableDeferred<Unit>? = null
        var writes = 0
        var paged = false
        var secondRecord: PrivateNote? = null
        val queries = mutableListOf<String>()
        val trashQueries = mutableListOf<Boolean>()
        val cursors = mutableListOf<ByteArray?>()
        val changes = mutableListOf<Pair<PrivateNoteAction, Long>>()
        private suspend fun page(generation: Long, terms: String, trash: Boolean, cursor: ByteArray?): PrivateNotePage {
            queries += terms; trashQueries += trash; cursors += cursor
            return PrivateNotePage(listOf(summary(if (cursor != null) secondRecord ?: record else record)),
                if (paged && cursor == null) byteArrayOf(1) else null)
        }
        override suspend fun load(generation: Long, id: ByteArray): PrivateNote { loads++; return record }
        override suspend fun save(generation: Long, saved: PrivateNote?, title: String, body: String, pinned: Boolean, format: dev.po4yka.chur.ffi.PrivateNoteFormat, proceed: () -> Boolean): PrivateNote {
            saves++
            mutexGate?.let { withContext(NonCancellable) { it.await() } }
            if (!proceed()) throw ChurFailure(ChurStatus.VAULT_LOCKED, "private note")
            saveGate?.let { withContext(NonCancellable) { it.await() } }
            saveFailure?.let { throw ChurFailure(it, "private note") }
            if (strictRevision && saved != null && saved.revision != record.revision) throw ChurFailure(ChurStatus.CONFLICT, "private note")
            record = record.copy(revision = (saved?.revision ?: 0) + 1, title = title, body = body, pinned = pinned, format = format)
            writes++
            return record
        }
        val files = mutableMapOf<String, dev.po4yka.chur.ffi.PrivateNoteAttachmentData>()
        var attachmentGate: CompletableDeferred<Unit>? = null
        var attachmentReads = 0
        var lastAttachmentRead: ByteArray? = null
        override suspend fun attachments(generation: Long, id: ByteArray) = files.values.map {
            dev.po4yka.chur.ffi.PrivateNoteAttachment(it.attachmentId, it.name, it.mimeType, it.data.size.toLong())
        }
        override suspend fun readAttachment(generation: Long, id: ByteArray, attachmentId: ByteArray): ByteArray {
            attachmentReads++
            attachmentGate?.let { withContext(NonCancellable) { it.await() } }
            return files.values.first { it.attachmentId.contentEquals(attachmentId) }.data.copyOf().also { lastAttachmentRead = it }
        }
        override suspend fun putAttachment(generation: Long, saved: PrivateNote, attachment: dev.po4yka.chur.ffi.PrivateNoteAttachmentData): PrivateNote {
            check(saved.revision == record.revision)
            files[attachment.attachmentId.joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }] = attachment.copy(data = attachment.data.copyOf())
            record = record.copy(revision = record.revision + 1, attachmentCount = files.size)
            return record
        }
        override suspend fun removeAttachment(generation: Long, saved: PrivateNote, attachmentId: ByteArray): PrivateNote {
            check(saved.revision == record.revision)
            files.entries.removeAll { it.value.attachmentId.contentEquals(attachmentId) }
            record = record.copy(revision = record.revision + 1, attachmentCount = files.size)
            return record
        }
        override suspend fun importPackage(generation: Long, title: String, body: String, format: dev.po4yka.chur.ffi.PrivateNoteFormat,
            attachments: List<dev.po4yka.chur.ffi.PrivateNoteAttachmentData>): PrivateNote {
            record = record.copy(title = title, body = body, format = format, attachmentCount = attachments.size)
            attachments.forEach { files[it.attachmentId.joinToString("") { b -> (b.toInt() and 255).toString(16).padStart(2, '0') }] = it.copy(data = it.data.copyOf()) }
            return record
        }
        override suspend fun change(generation: Long, id: ByteArray, revision: Long, action: PrivateNoteAction): PrivateNote? {
            changes += action to revision
            return record
        }
    }
    companion object {
        private fun note() = PrivateNote(byteArrayOf(1), 1, "Saved title", "Saved body", 1, 1, false, null, 23)
        private fun summary(note: PrivateNote) = PrivateNoteSummary(note.noteId, note.revision, note.title, note.body.take(160),
            note.createdMs, note.updatedMs, note.pinned, note.trashedAtMs, note.exportSize)
    }
}
