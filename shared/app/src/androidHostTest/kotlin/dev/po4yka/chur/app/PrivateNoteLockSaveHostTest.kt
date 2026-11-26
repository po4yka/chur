package dev.po4yka.chur.app

import dev.po4yka.chur.ffi.PrivateNote
import dev.po4yka.chur.ffi.PrivateNoteSummary
import dev.po4yka.chur.notes.InMemoryNoteStore
import dev.po4yka.chur.vault.VaultRepository
import dev.po4yka.chur.vault.VaultState
import java.io.File
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The save of unsaved private-note text at an ordinary lock,
 * `PRIVATE_NOTES.md`, against a real controller and vault.
 */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class PrivateNoteLockSaveHostTest {
    private val root = File(System.getProperty("java.io.tmpdir"), "chur-note-lock-save-${System.nanoTime()}")

    @Volatile
    private var now = 1_700_000_000_000L
    private val made = mutableListOf<ChurController>()
    private val routeScope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)

    @BeforeTest
    fun open() {
        Dispatchers.setMain(Dispatchers.Unconfined)
        root.mkdirs()
    }

    @AfterTest
    fun close(): Unit = runBlocking {
        routeScope.cancel()
        made.forEach { it.vault.shutdown() }
        Dispatchers.resetMain()
        root.deleteRecursively()
    }

    @Test
    fun the_lock_control_saves_an_edited_note_before_the_session_closes() = runBlocking {
        val (controller, note) = vaultWithNote()
        val notes = openEditor(controller, note)
        notes.body("Edited before the lock")
        controller.lock()
        assertEquals("Edited before the lock", reopened(controller, note).body)
    }

    @Test
    fun confirming_trash_discards_the_checkpoint_but_keeps_the_saved_note_in_trash() = runBlocking {
        val (controller, note) = vaultWithNote()
        val notes = openEditor(controller, note)
        val generation = (controller.vault.state.value as VaultState.Unlocked).generation
        notes.body("Discard this edit")
        withTimeout(10_000) {
            while (controller.vault.privateNoteDraft(generation)?.body != "Discard this edit") delay(10)
        }
        notes.requestTrash()
        notes.trash()
        withTimeout(10_000) { notes.state.first { it.editor == null && !it.busy } }
        notes.close()

        val trashed = controller.vault.privateNote(generation, note.noteId)
        assertNotNull(trashed.trashedAtMs)
        assertEquals("Saved body", trashed.body)
        val reopened = PrivateNotesController(controller.vault, generation, routeScope, {}, {})
        reopened.recoverDraft()
        assertNull(reopened.state.value.editor)
        reopened.close()
    }

    @Test
    fun a_trash_conflict_preserves_the_editors_checkpoint() = runBlocking {
        val (controller, note) = vaultWithNote()
        val notes = openEditor(controller, note)
        val generation = (controller.vault.state.value as VaultState.Unlocked).generation
        notes.body("Keep this edit")
        controller.vault.savePrivateNote(generation, note.noteId, note.revision, note.title, "Newer version")
        notes.requestTrash()
        notes.trash()
        withTimeout(10_000) { notes.state.first { it.error != null && !it.busy } }
        assertEquals("Keep this edit", controller.vault.privateNoteDraft(generation)?.body)
        assertNull(controller.vault.privateNote(generation, note.noteId).trashedAtMs)
        notes.close()
    }

    @Test
    fun the_background_lock_saves_an_edited_note_before_it_returns() = runBlocking {
        val (controller, note) = vaultWithNote()
        val notes = openEditor(controller, note)
        notes.body("Edited before the app left")
        controller.onBackground()
        assertIs<VaultState.Locked>(controller.vault.state.value)
        val saved = reopened(controller, note)
        assertEquals("Edited before the app left", saved.body)
        assertEquals(note.revision + 1, saved.revision)
    }

    @Test
    fun the_idle_lock_saves_an_edited_note_and_still_locks() = runBlocking {
        val (controller, note) = vaultWithNote()
        val notes = openEditor(controller, note)
        notes.body("Edited before the timeout")
        now += 3 * 60_000
        controller.checkIdle()
        assertIs<VaultState.Locked>(controller.vault.state.value)
        assertEquals("Edited before the timeout", reopened(controller, note).body)
    }

    @Test
    fun an_unedited_note_and_a_panic_lock_write_nothing() = runBlocking {
        val (controller, note) = vaultWithNote()
        openEditor(controller, note)
        controller.lock()
        assertEquals(note.revision, reopened(controller, note).revision)
        val notes = openEditor(controller, note)
        notes.body("Dropped by the panic lock")
        controller.panic()
        val after = reopened(controller, note)
        assertEquals(note.revision, after.revision)
        assertEquals(note.body, after.body)
        assertEquals(0, controller.lockDrafts.lost)
    }

    @Test
    fun a_revision_conflict_keeps_an_encrypted_draft_for_the_next_unlock() = runBlocking {
        val (controller, note) = vaultWithNote()
        val notes = openEditor(controller, note)
        val generation = (controller.vault.state.value as VaultState.Unlocked).generation
        val newer = controller.vault.savePrivateNote(generation, note.noteId, note.revision, note.title, "Newer revision")
        notes.body("Text from the older editor")
        controller.lock()
        assertEquals(newer.body, reopened(controller, note).body)
        val sealed = root.walkTopDown().single { it.isFile && it.name == "note-draft" }
        assertFalse(sealed.readBytes().decodeToString().contains("Text from the older editor"))

        val unlocked = (controller.vault.state.value as VaultState.Unlocked).generation
        val editor = PrivateNotesController(controller.vault, unlocked, routeScope, {}, {})
        editor.recoverDraft()
        assertEquals("Text from the older editor", editor.state.value.editor?.body)
        assertNull(editor.state.value.editor?.saved)
        controller.panic()
        reopened(controller, note)
        val afterPanic = (controller.vault.state.value as VaultState.Unlocked).generation
        assertNull(controller.vault.privateNoteDraft(afterPanic))
        editor.close()
    }

    @Test
    fun every_ordinary_lock_conceals_before_its_save_starts() = runBlocking {
        val (controller, note) = vaultWithNote()
        val routes = mutableListOf<AppRoute>()
        controller.lockDrafts.register(LockDrafts.Source { LockDrafts.Save { routes += controller.route.value } })
        controller.lock()
        reopened(controller, note)
        now += 3 * 60_000
        controller.checkIdle()
        assertIs<VaultState.Locked>(controller.vault.state.value)
        assertEquals(2, routes.size)
        assertTrue(routes.none { it == AppRoute.Vault }, "a save ran while the vault route was on screen")
    }

    @Test
    fun a_save_that_never_returns_cannot_hold_the_lock_past_the_bound(): Unit = runBlocking {
        val (controller, _) = vaultWithNote()
        val hung = CompletableDeferred<Unit>()
        controller.lockDrafts.register(LockDrafts.Source { LockDrafts.Save { withContext(NonCancellable) { hung.await() } } })
        val started = System.nanoTime()
        controller.lock()
        withTimeout(LOCK_DRAFT_SAVE_BOUND_MS + 3_000) { controller.vault.state.first { it is VaultState.Locked } }
        assertTrue((System.nanoTime() - started) / 1_000_000 >= LOCK_DRAFT_SAVE_BOUND_MS - 100)
        assertEquals(1, controller.lockDrafts.lost)
        hung.complete(Unit)
    }

    @Test
    fun a_panic_during_the_save_wait_of_an_earlier_lock_closes_at_once(): Unit = runBlocking {
        val (controller, _) = vaultWithNote()
        val held = CompletableDeferred<Unit>()
        // Holds the first lock's wait, as a save queued behind the repository does.
        controller.lockDrafts.register(LockDrafts.Source { LockDrafts.Save { withContext(NonCancellable) { held.await() } } })
        val started = System.nanoTime()
        controller.lock()
        controller.panic()
        withTimeout(10_000) { controller.vault.state.first { it is VaultState.Locked } }
        assertTrue((System.nanoTime() - started) / 1_000_000 < LOCK_DRAFT_SAVE_BOUND_MS / 2, "the panic waited for a save")
        assertEquals(1, controller.lockDrafts.lost)
        held.complete(Unit)
    }

    @Test
    fun an_error_thrown_by_a_save_still_closes_the_session() = runBlocking {
        val (controller, _) = vaultWithNote()
        controller.lockDrafts.register(LockDrafts.Source { LockDrafts.Save { throw AssertionError("save failed hard") } })
        controller.lock()
        withTimeout(10_000) { controller.vault.state.first { it is VaultState.Locked } }
        assertEquals(1, controller.lockDrafts.lost)
    }

    @Test
    fun a_second_lock_before_the_editor_goes_saves_a_new_note_once() = runBlocking {
        val (controller, note) = vaultWithNote()
        val generation = (controller.vault.state.value as VaultState.Unlocked).generation
        val notes = PrivateNotesController(controller.vault, generation, routeScope, {}, {})
        controller.lockDrafts.register(LockDrafts.Source(notes::captureForLock))
        notes.create()
        notes.body("A note that was never saved")
        controller.lock()
        controller.onBackground()
        reopened(controller, note)
        val unlocked = (controller.vault.state.value as VaultState.Unlocked).generation
        val bodies = controller.vault.privateNotes(unlocked).notes.map { controller.vault.privateNote(unlocked, it.noteId).body }
        assertEquals(1, bodies.count { it == "A note that was never saved" })
    }

    /** A controller open on a new vault that holds one saved private note. */
    private suspend fun vaultWithNote(): Pair<ChurController, PrivateNote> {
        val setup = VaultRepository(root.absolutePath, { now })
        try {
            setup.start()
            setup.create(PASSWORD.encodeToByteArray(), offerRecovery = false)
        } finally {
            setup.shutdown()
        }
        val controller = ChurController(
            storageRoot = root.absolutePath,
            privacy = NoPrivacyCover,
            exports = NoExports,
            clock = { now },
            notes = InMemoryNoteStore(),
        ).also { made += it }
        controller.start()
        unlock(controller)
        val generation = (controller.vault.state.value as VaultState.Unlocked).generation
        return controller to controller.vault.savePrivateNote(generation, title = "Lock fixture", body = "Saved body")
    }

    private suspend fun unlock(controller: ChurController) {
        controller.openVaultEntry()
        controller.unlock(PASSWORD)
        withTimeout(10_000) { controller.unlocking.first { !it } }
        assertEquals(AppRoute.Vault, controller.route.value)
    }

    /** The route's notes controller, registered as `PrivateNotesRoute` does, with [note] open. */
    private suspend fun openEditor(controller: ChurController, note: PrivateNote): PrivateNotesController {
        val generation = (controller.vault.state.value as VaultState.Unlocked).generation
        val notes = PrivateNotesController(controller.vault, generation, routeScope, {}, {})
        controller.lockDrafts.register(LockDrafts.Source(notes::captureForLock))
        notes.open(PrivateNoteSummary(note.noteId, note.revision, note.title, note.body, note.createdMs,
            note.updatedMs, note.pinned, note.trashedAtMs, note.exportSize))
        withTimeout(10_000) { notes.state.first { it.editor != null && !it.busy } }
        return notes
    }

    /** Waits for the lock to end, unlocks again, and reads [note]. */
    private suspend fun reopened(controller: ChurController, note: PrivateNote): PrivateNote {
        withTimeout(10_000) { controller.vault.state.first { it is VaultState.Locked } }
        unlock(controller)
        val generation = (controller.vault.state.value as VaultState.Unlocked).generation
        return assertNotNull(controller.vault.privateNote(generation, note.noteId))
    }

    private object NoExports : ExportSink {
        override fun cancelPending() = Unit
        override fun create(displayName: String, contentType: String): ExportSink.Destination? = null
        override fun create(
            displayName: String,
            contentType: String,
            target: ExportTarget,
            uri: String?,
        ): ExportSink.Destination? = null
    }

    private companion object {
        const val PASSWORD = "Lock-save-password"
    }
}
