package dev.po4yka.chur.app

import dev.po4yka.chur.core.model.ChurStatus
import dev.po4yka.chur.ffi.ChurFailure
import dev.po4yka.chur.ffi.PrivateNote
import dev.po4yka.chur.ffi.PrivateNoteSelection
import dev.po4yka.chur.vault.VaultState
import java.io.File
import java.io.RandomAccessFile
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.launch
import kotlinx.coroutines.yield
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Real controller, JNI, SQLCipher, and archive files. Credentials and content are public fixtures. */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class SelectiveArchiveControllerHostTest {
    @Test
    fun share_export_respects_host_capacity_and_restores_selected_notes_with_its_new_password() = scenario {
        val archive = exportArchive()
        assertEquals(Creation("chur-archive.churbak", "application/octet-stream", ExportTarget.SHARE, null, sink.capacity), archive.creation)
        assertEquals(listOf(ExportTarget.SHARE), sink.capacityRequests)
        assertTrue(archive.file.length() in 1L..sink.capacity)
        assertContentEquals("CHURBAK1".encodeToByteArray(), archive.file.inputStream().use { it.readNBytes(8) })
        assertEquals(listOf("publishChecked", "close"), archive.events)

        // The public standalone-restore entry must close the source identity first.
        controller.restoreArchiveAsSeparateVault()
        withTimeout(TIMEOUT) { controller.route.first { it == AppRoute.RestoreBackup } }
        assertTrue(controller.vault.state.value is VaultState.Locked)
        val input = RandomAccessFile(archive.file, "r")
        val closed = CompletableDeferred<Boolean>()
        val credential = ArchiveCredential(ARCHIVE_PASSWORD)
        val stagingHold = controller.retainArchiveCredential(credential)
        controller.restoreBackup(descriptor(input), credential) { cancelled -> input.close(); closed.complete(cancelled) }
        stagingHold.release()
        assertFalse(withTimeout(TIMEOUT) { closed.await() })
        assertCleared(credential)
        withTimeout(TIMEOUT) { controller.route.first { it == AppRoute.Unlock } }
        controller.unlock(ARCHIVE_PASSWORD)
        withTimeout(TIMEOUT) { controller.route.first { it == AppRoute.Vault } }
        val generation = (controller.vault.state.value as VaultState.Unlocked).generation
        val notes = controller.vault.privateNotes(generation).notes
        assertEquals(1, notes.size)
        val restored = controller.vault.privateNote(generation, notes.single().noteId)
        assertEquals(selected.title, restored.title)
        assertEquals(selected.body, restored.body)
        assertFalse(restored.noteId.contentEquals(selected.noteId))
    }

    @Test
    fun a_restore_under_an_installed_password_says_the_creation_sentence() = scenario {
        // An archive sealed under the vault's own password is refused by the
        // core as a collision (`DECOY_VAULT.md` §5). The refusal must read as a
        // refused creation, not as the sync conflict copy of `CONFLICT`.
        ArchiveTransferOwner(controller, generation).export(request, ArchiveCredential(SOURCE_PASSWORD), ExportTarget.SHARE)
        val archive = sink.closedOutput()
        withTimeout(TIMEOUT) { controller.notice.first { it?.text?.startsWith("Encrypted archive ready.") == true } }
        controller.restoreArchiveAsSeparateVault()
        withTimeout(TIMEOUT) { controller.route.first { it == AppRoute.RestoreBackup } }
        val input = RandomAccessFile(archive.file, "r")
        val closed = CompletableDeferred<Boolean>()
        controller.restoreBackup(descriptor(input), ArchiveCredential(SOURCE_PASSWORD)) { cancelled -> input.close(); closed.complete(cancelled) }
        assertFalse(withTimeout(TIMEOUT) { closed.await() })
        assertEquals("This vault could not be created. Try a different credential.", controller.formError.value)
        assertEquals(AppRoute.RestoreBackup, controller.route.value)
    }

    @Test
    fun a_tiny_host_capacity_reaches_native_and_discards_the_incomplete_archive() = scenario {
        sink.capacity = 64
        val credential = ArchiveCredential(ARCHIVE_PASSWORD)
        controller.exportSelectiveArchive(request, credential, ExportTarget.SHARE)
        val output = sink.closedOutput()
        val notice = withTimeout(TIMEOUT) { controller.notice.first { it != null } }!!
        assertEquals(64L, output.creation.capacity)
        assertEquals(listOf(ExportTarget.SHARE), sink.capacityRequests)
        // The supplied regular file has no OS quota: only the native writer
        // can enforce this capacity rather than merely passing it to the adapter.
        assertTrue(output.lengthOnDiscard in 0L..64L)
        assertEquals(listOf("discard", "close"), output.events)
        assertFalse(output.file.exists())
        assertEquals(userCopy(ChurStatus.RESOURCE_LIMIT_EXCEEDED), notice.text)
        assertFalse("archive ready" in notice.text)
        assertCleared(credential)
        assertEquals(2, controller.vault.privateNotes(generation).notes.size)
    }

    @Test
    fun importing_into_the_existing_vault_reports_counts_and_keeps_both_original_notes() = scenario {
        val archive = exportArchive()
        val owner = ArchiveTransferOwner(controller, generation)
        val credential = ArchiveCredential(ARCHIVE_PASSWORD)
        val source = RandomAccessFile(archive.file, "r")
        val closed = CompletableDeferred<Unit>()
        try {
            owner.import(credential) { }
            owner.importedFile(ArchiveSource(descriptor(source)) { source.close(); closed.complete(Unit) })
            withTimeout(TIMEOUT) { closed.await() }
            val notice = withTimeout(TIMEOUT) {
                controller.notice.first { it?.text?.contains("items imported from the encrypted archive") == true }
            }!!
            assertTrue(notice.text.startsWith("1 "), notice.text)
            assertTrue("Existing items were kept." in notice.text)
            val notes = controller.vault.privateNotes(generation).notes
            assertEquals(3, notes.size)
            assertEquals(selected.body, controller.vault.privateNote(generation, selected.noteId).body)
            assertEquals(kept.body, controller.vault.privateNote(generation, kept.noteId).body)
            val imported = notes.single { !it.noteId.contentEquals(selected.noteId) && !it.noteId.contentEquals(kept.noteId) }
            assertEquals(selected.body, controller.vault.privateNote(generation, imported.noteId).body)
            assertCleared(credential)
            assertNull(controller.activeOperation.value)
        } finally { owner.close(); source.close() }
    }

    @Test
    fun package_staging_is_cancelled_and_its_credential_cleared_before_a_late_callback() = scenario {
        val owner = ArchiveTransferOwner(controller, generation)
        val credential = ArchiveCredential(ARCHIVE_PASSWORD)
        owner.import(credential) { }
        var entered = false
        val staging = CoroutineScope(currentCoroutineContext()).launch(start = CoroutineStart.LAZY) {
            entered = true
            awaitCancellation()
        }
        owner.importPickerReturned(staging)
        staging.start()
        yield()
        assertTrue(entered)
        controller.background()
        // No staging completion or late callback is needed to erase the secret.
        assertCleared(credential)
        assertTrue(staging.isCancelled)
        controller.onBackground()
        assertTrue(controller.vault.state.value is VaultState.Locked)
        val staged = RandomAccessFile(File(root, "late-staged.churbak"), "rw")
        var closed = false
        owner.importedFile(ArchiveSource(descriptor(staged)) { staged.close(); closed = true })
        assertTrue(closed)
        assertNull(controller.activeOperation.value)
        owner.close()
    }

    @Test
    fun restore_staging_credential_is_cleared_synchronously_when_the_application_locks() = scenario {
        controller.restoreArchiveAsSeparateVault()
        withTimeout(TIMEOUT) { controller.route.first { it == AppRoute.RestoreBackup } }
        val credential = ArchiveCredential(ARCHIVE_PASSWORD)
        val hold = controller.retainArchiveCredential(credential)
        var entered = false
        val staging = CoroutineScope(currentCoroutineContext()).launch(start = CoroutineStart.LAZY) {
            entered = true
            awaitCancellation()
        }
        hold.attach(staging)
        staging.start()
        yield()
        assertTrue(entered)
        controller.lock()
        assertCleared(credential)
        assertFalse(hold.active)
        assertTrue(staging.isCancelled)
        assertNull(controller.activeOperation.value)
        controller.onBackground()
    }

    @Test
    fun cancelling_restore_staging_before_it_starts_still_clears_its_credential() = scenario {
        val credential = ArchiveCredential(ARCHIVE_PASSWORD)
        val hold = controller.retainArchiveCredential(credential)
        var entered = false
        val staging = CoroutineScope(currentCoroutineContext()).launch(start = CoroutineStart.LAZY) {
            entered = true
            awaitCancellation()
        }
        hold.attach(staging)
        staging.cancel()
        assertCleared(credential)
        assertFalse(hold.active)
        assertFalse(entered)
    }

    @Test
    fun a_disposed_picker_owner_discards_a_late_files_document_even_after_the_vault_locks() = scenario {
        val owner = ArchiveTransferOwner(controller, generation)
        val credential = ArchiveCredential(ARCHIVE_PASSWORD)
        var offeredName: String? = null
        owner.export(request, credential, ExportTarget.FILES) { offeredName = it }
        assertEquals("chur-archive.churbak", offeredName)
        owner.close()
        assertCleared(credential)
        controller.lock()
        withTimeout(TIMEOUT) { controller.route.first { it == AppRoute.PublicShell } }
        sink.returnedDocument = File(root, "late-returned.churbak").apply { createNewFile() }
        owner.exportedFile(RETURNED_URI)
        assertReturnedDocumentDiscarded(sink.closedOutput())
        withTimeout(TIMEOUT) { controller.vault.state.first { it is VaultState.Locked } }
        assertTrue(controller.vault.state.value is VaultState.Locked)
        assertNull(controller.activeOperation.value)
    }

    @Test
    fun a_picker_result_losing_the_busy_race_is_discarded_without_interrupting_the_running_operation() = scenario {
        val owner = ArchiveTransferOwner(controller, generation)
        val credential = ArchiveCredential(ARCHIVE_PASSWORD)
        owner.export(request, credential, ExportTarget.FILES) { }
        val entered = CompletableDeferred<Unit>()
        val release = CountDownLatch(1)
        val directoryClosed = CompletableDeferred<Unit>()
        sink.directory = object : ExportDirectory {
            override fun createDirectory(displayName: String): ExportDirectory {
                entered.complete(Unit)
                check(release.await(30, TimeUnit.SECONDS)) { "the test did not release its directory" }
                return object : ExportDirectory {
                    override fun createDirectory(displayName: String): ExportDirectory? = error("no descendant albums")
                    override fun createFile(displayName: String, contentType: String, plaintextSize: Long): ExportSink.Destination? = error("no album members")
                    override fun close() = Unit
                }
            }
            override fun createFile(displayName: String, contentType: String, plaintextSize: Long): ExportSink.Destination? = error("only the empty album folder is created")
            override fun close() { directoryClosed.complete(Unit) }
        }
        val album = controller.vault.createAlbum("Public empty album fixture")
        controller.exportAlbum(album, "transient-directory-token")
        try {
            withTimeout(TIMEOUT) { entered.await() }
            val operation = assertNotNull(controller.activeOperation.value)
            sink.returnedDocument = File(root, "busy-returned.churbak").apply { createNewFile() }
            owner.exportedFile(RETURNED_URI)
            assertReturnedDocumentDiscarded(sink.closedOutput(), capacity = sink.capacity)
            withTimeout(TIMEOUT) { controller.notice.first { it?.text == "Finish the current operation first." } }
            assertEquals(operation.id, controller.activeOperation.value?.id)
            assertCleared(credential)
        } finally {
            release.countDown()
            withTimeout(TIMEOUT) { directoryClosed.await() }
            withTimeout(TIMEOUT) { controller.activeOperation.first { it == null } }
            owner.close()
        }
    }

    @Test
    fun disposing_an_import_picker_clears_its_credential_and_closes_a_late_valid_source_without_import() = scenario {
        val archive = exportArchive()
        val owner = ArchiveTransferOwner(controller, generation)
        val credential = ArchiveCredential(ARCHIVE_PASSWORD)
        owner.import(credential) { }
        owner.close()
        assertCleared(credential)
        val input = RandomAccessFile(archive.file, "r")
        var closes = 0
        owner.importedFile(ArchiveSource(descriptor(input)) { closes++; input.close() })
        assertEquals(1, closes)
        assertNull(controller.activeOperation.value)
        assertEquals(2, controller.vault.privateNotes(generation).notes.size)
        assertEquals(kept.body, controller.vault.privateNote(generation, kept.noteId).body)
    }

    private fun scenario(test: suspend Fixture.() -> Unit) = runBlocking {
        Dispatchers.setMain(Dispatchers.Unconfined)
        val root = File(System.getProperty("java.io.tmpdir"), "chur-archive-controller-${System.nanoTime()}").apply { mkdirs() }
        val sink = Sink(root)
        val controller = ChurController(root.absolutePath, NoPrivacyCover, sink, clock = { 1_700_000_000_000L })
        try {
            controller.start()
            controller.create(SOURCE_PASSWORD, offerRecovery = false)
            withTimeout(TIMEOUT) { controller.route.first { it == AppRoute.Vault } }
            val generation = (controller.vault.state.value as VaultState.Unlocked).generation
            val selected = controller.vault.savePrivateNote(generation, title = "Selected public 🌍 fixture", body = "Public literal <text>\n日本語 🔐")
            val kept = controller.vault.savePrivateNote(generation, title = "Unselected public fixture", body = "Keep this existing body")
            Fixture(root, sink, controller, generation, selected, kept).test()
        } finally {
            controller.vault.shutdown()
            Dispatchers.resetMain()
            root.deleteRecursively()
        }
    }

    private class Fixture(val root: File, val sink: Sink, val controller: ChurController,
        val generation: Long, val selected: PrivateNote, val kept: PrivateNote) {
        val request = SelectiveExportRequest(generation, notes = listOf(PrivateNoteSelection(selected.noteId, selected.revision)))
        suspend fun exportArchive(): Output {
            val credential = ArchiveCredential(ARCHIVE_PASSWORD)
            ArchiveTransferOwner(controller, generation).export(request, credential, ExportTarget.SHARE)
            val output = sink.closedOutput()
            withTimeout(TIMEOUT) { controller.notice.first { it?.text?.startsWith("Encrypted archive ready.") == true } }
            assertCleared(credential)
            assertTrue(output.file.exists())
            return output
        }
        fun assertReturnedDocumentDiscarded(output: Output, capacity: Long? = null) {
            assertEquals(Creation("", "", ExportTarget.FILES, RETURNED_URI, capacity), output.creation)
            assertEquals(listOf("discard", "close"), output.events)
            assertFalse(output.file.exists())
        }
    }

    private data class Creation(val name: String, val type: String, val target: ExportTarget, val uri: String?, val capacity: Long?)
    private class Sink(private val root: File) : ExportSink {
        var capacity = 16L * 1024 * 1024
        val capacityRequests = mutableListOf<ExportTarget>()
        var returnedDocument: File? = null
        var directory: ExportDirectory? = null
        private var count = 0
        private val outputs = Channel<Output>(Channel.UNLIMITED)
        override fun cancelPending() = Unit
        override fun archiveCapacity(target: ExportTarget): Long { capacityRequests += target; return capacity }
        override fun openDirectory(uri: String): ExportDirectory? = directory
        override fun create(displayName: String, contentType: String): ExportSink.Destination? = error("an archive needs an explicit target")
        override fun create(displayName: String, contentType: String, target: ExportTarget, uri: String?): ExportSink.Destination =
            output(Creation(displayName, contentType, target, uri, null))
        override fun create(displayName: String, contentType: String, target: ExportTarget, uri: String?, plaintextSize: Long): ExportSink.Destination =
            output(Creation(displayName, contentType, target, uri, plaintextSize))
        private fun output(creation: Creation): Output {
            val file = if (creation.target == ExportTarget.FILES) requireNotNull(returnedDocument)
                else File(root, "archive-${count++}.churbak")
            return Output(file, creation).also { check(outputs.trySend(it).isSuccess) }
        }
        suspend fun closedOutput(): Output = withTimeout(TIMEOUT) { outputs.receive().also { it.closed.await() } }
    }
    private class Output(val file: File, val creation: Creation) : ExportSink.Destination {
        private val output = RandomAccessFile(file, "rw")
        override val descriptor = descriptor(output)
        val events = mutableListOf<String>()
        var lengthOnDiscard = -1L
            private set
        val closed = CompletableDeferred<Unit>()
        override fun publish(): Unit = error("archive publication must be checked")
        override fun publishChecked(): Boolean { events += "publishChecked"; return true }
        override fun discard() { events += "discard"; lengthOnDiscard = file.length(); file.delete() }
        override fun close() { events += "close"; output.close(); closed.complete(Unit) }
    }

    private companion object {
        const val TIMEOUT = 60_000L
        const val SOURCE_PASSWORD = "source-vault-public-fixture-password"
        const val ARCHIVE_PASSWORD = "independent-archive-public-fixture-password"
        const val RETURNED_URI = "content://test-provider/returned-archive-document"
        fun descriptor(file: RandomAccessFile): Int = file.fd.javaClass.getDeclaredField("fd").apply { isAccessible = true }.getInt(file.fd)
        fun assertCleared(credential: ArchiveCredential) {
            assertEquals(ChurStatus.SESSION_EXPIRED, assertFailsWith<ChurFailure> { credential.copyBytes() }.status)
        }
    }
}
