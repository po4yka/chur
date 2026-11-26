package dev.po4yka.chur.ffi

import dev.po4yka.chur.core.model.ChurStatus
import java.io.File
import java.io.FileOutputStream
import java.io.RandomAccessFile
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * The Kotlin adapter against the real native library.
 *
 * This is the only test that runs both halves of the boundary at once, and it
 * is the only one that can: a decoder here that disagrees with the encoder in
 * Rust is a defect neither side's own tests find. Every record of
 * `docs/interop/FFI_CONTRACT.md` §6.4 and §6.5 is therefore decoded from bytes
 * Rust produced rather than from a fixture this file wrote.
 *
 * It loads `libchur_jni` through the JNI adapter of ADR-0040, which is what
 * Android does. The Gradle task that builds it sets `java.library.path`.
 */
class ChurVaultHostTest {
    private val roots = mutableListOf<File>()
    private var runtime = 0L

    @AfterTest
    fun releaseEverything() {
        if (runtime != 0L) {
            ChurVault.closeRuntime(runtime)
            runtime = 0L
        }
        roots.forEach { it.deleteRecursively() }
    }

    private fun scratch(): File {
        val directory = File(System.getProperty("java.io.tmpdir"), "chur-kt-${System.nanoTime()}")
        directory.mkdirs()
        roots.add(directory)
        return directory
    }

    private fun openRuntime(): Long {
        val root = scratch()
        runtime = ChurVault.openRuntime(root.absolutePath)
        return runtime
    }

    private fun createVault(runtime: Long, password: String = PASSWORD): Long {
        val creation = ChurVault.beginCreation(runtime, password.encodeToByteArray())
        return ChurVault.activateCreation(creation)
    }

    /** Imports bytes through a real descriptor, as a platform picker does. */
    private fun import(session: Long, bytes: ByteArray, filename: String): ByteArray {
        val source = File.createTempFile("chur-source", ".bin")
        source.deleteOnExit()
        FileOutputStream(source).use { it.write(bytes) }
        RandomAccessFile(source, "r").use { handle ->
            val descriptor = descriptorOf(handle)
            val operation = ChurVault.beginImport(
                session,
                descriptor,
                ImportRequest(
                    contentType = "image/jpeg",
                    seekable = true,
                    mediaClass = 1,
                    width = 1200,
                    height = 900,
                    knownLength = bytes.size.toLong(),
                    captureTimeMs = 1_700_000_000_000L,
                    originalFilename = filename,
                ),
            )
            val terminal = drain(operation)
            assertEquals(ChurStatus.OK, terminal, "the import failed")
            ChurVault.closeOperation(operation)
        }
        val page = ChurVault.query(session, ObjectQuery())
        return page.objects.first().objectId
    }

    /** Polls to the terminal result, which §10 makes the only way to observe one. */
    private fun drain(operation: Long): Int {
        while (true) {
            val progress = ChurVault.poll(operation)
            if (progress.terminal) return progress.status
            Thread.yield()
        }
    }

    /**
     * The integer descriptor behind a `RandomAccessFile`.
     *
     * §13 has Rust duplicate what it is given, so this one closes on its own
     * schedule when the `use` block ends.
     */
    private fun descriptorOf(handle: RandomAccessFile): Int {
        val descriptor = handle.fd
        val field = descriptor.javaClass.getDeclaredField("fd")
        field.isAccessible = true
        return field.getInt(descriptor)
    }

    /**
     * The Android Keystore round trip of §6.6, with a stand-in cipher.
     *
     * A JVM host test has no Keystore, and it does not need one: Rust neither
     * performs nor verifies that AEAD. What this proves is the part only a test
     * with both halves running can prove, which is that the alias, the AAD, the
     * nonce, and the wrapped bytes survive the encoder here and the decoder
     * there, and that the root the platform returns opens the vault.
     */
    @Test
    fun the_keystore_slot_enrolls_and_unlocks_through_the_adapter() {
        val runtime = openRuntime()
        val session = createVault(runtime)

        val enrollment = ChurVault.beginKeystoreSlot(session)
        assertEquals(32, enrollment.alias.size)
        assertEquals(32, enrollment.rootSecret.size)
        assertTrue(enrollment.aad.isNotEmpty())
        val (nonce, wrapped) = standInWrap(enrollment.aad, enrollment.rootSecret)
        ChurVault.commitKeystoreSlot(session, nonce, wrapped)
        ChurVault.lock(session, LockReason.USER)
        ChurVault.closeSession(session)

        val material = ChurVault.keystoreMaterial(runtime)
        assertEquals(1, material.size)
        assertContentEquals(enrollment.alias, material[0].alias)
        assertContentEquals(enrollment.aad, material[0].aad)
        assertContentEquals(nonce, material[0].gcmNonce)

        val root = standInUnwrap(material[0])
        val reopened = ChurVault.unlockWithKeystoreRoot(runtime, root)
        assertTrue(reopened != 0L)
        ChurVault.closeSession(reopened)
    }

    @Test
    fun a_root_the_platform_did_not_return_is_one_external_result() {
        val runtime = openRuntime()
        val session = createVault(runtime)
        val enrollment = ChurVault.beginKeystoreSlot(session)
        val (nonce, wrapped) = standInWrap(enrollment.aad, enrollment.rootSecret)
        ChurVault.commitKeystoreSlot(session, nonce, wrapped)
        ChurVault.closeSession(session)

        val failure = assertFailsWith<ChurFailure> {
            ChurVault.unlockWithKeystoreRoot(runtime, ByteArray(32) { 7 })
        }
        assertEquals(ChurStatus.AUTHENTICATION_FAILED, failure.status)
    }

    @Test
    fun a_vault_with_no_keystore_slot_reports_no_material() {
        val runtime = openRuntime()
        ChurVault.closeSession(createVault(runtime))

        assertTrue(ChurVault.keystoreMaterial(runtime).isEmpty())
    }

    /**
     * The stand-in for the Keystore cipher.
     *
     * A keyed digest over the nonce and the AAD gives the one property that
     * matters here: a value wrapped under one AAD does not open under another.
     */
    private fun standInWrap(aad: ByteArray, root: ByteArray): Pair<ByteArray, ByteArray> {
        val nonce = ByteArray(12) { index -> (index * 7 + 1).toByte() }
        val mask = standInMask(nonce, aad)
        val wrapped = ByteArray(48)
        for (index in 0 until 32) wrapped[index] = (root[index].toInt() xor mask[index].toInt()).toByte()
        mask.copyInto(wrapped, 32, 0, 16)
        return nonce to wrapped
    }

    private fun standInUnwrap(material: KeystoreMaterial): ByteArray {
        val mask = standInMask(material.gcmNonce, material.aad)
        assertContentEquals(mask.copyOfRange(0, 16), material.wrappedRootSecret.copyOfRange(32, 48))
        return ByteArray(32) { index ->
            (material.wrappedRootSecret[index].toInt() xor mask[index].toInt()).toByte()
        }
    }

    private fun standInMask(nonce: ByteArray, aad: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").apply {
            update("chur/test/keystore-stand-in".encodeToByteArray())
            update(nonce)
            update(aad)
        }.digest()

    @Test
    fun the_sharing_identity_is_public_and_idempotent() {
        val runtime = openRuntime()
        val session = createVault(runtime)

        val first = ChurVault.sharingIdentity(session)
        val replay = ChurVault.sharingIdentity(session)

        assertEquals(16, first.vaultId.size)
        assertEquals(16, first.deviceId.size)
        assertEquals(1952, first.signingPublicKey.size)
        assertEquals(1216, first.hpkePublicKey.size)
        assertEquals(79, first.fingerprint.length)
        assertTrue(first.enrollment.isNotEmpty())
        assertTrue(first.initialOperation.isNotEmpty())
        assertContentEquals(first.vaultId, replay.vaultId)
        assertContentEquals(first.deviceId, replay.deviceId)
        assertContentEquals(first.enrollment, replay.enrollment)
        assertContentEquals(first.initialOperation, replay.initialOperation)
        val overview = ChurVault.sharingOverview(session)
        assertEquals(16, overview.collectionId.size)
        assertTrue(overview.members.isEmpty())
        val inspected = ChurVault.inspectEnrollment(first.enrollment)
        assertContentEquals(first.vaultId, inspected.vaultId)
        assertContentEquals(first.deviceId, inspected.deviceId)
        assertEquals(first.fingerprint, inspected.fingerprint)
        val altered = first.enrollment.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertFailsWith<ChurFailure> { ChurVault.inspectEnrollment(altered) }
        ChurVault.closeSession(session)
    }

    @Test
    fun the_sync_fork_state_crosses_the_jni_boundary() {
        // §6.24 through the real library: a vault with no fork reads zero in
        // each state, an acknowledgement with nothing detected changes
        // nothing, and a locked session reads nothing at all.
        val runtime = openRuntime()
        val session = createVault(runtime)

        assertEquals(SyncForkState(detected = 0, acknowledged = 0), ChurVault.syncForkState(session))
        ChurVault.acknowledgeSyncForks(session)
        assertEquals(SyncForkState(detected = 0, acknowledged = 0), ChurVault.syncForkState(session))
        ChurVault.lock(session, LockReason.USER)
        val failure = assertFailsWith<ChurFailure> { ChurVault.syncForkState(session) }
        assertEquals(ChurStatus.VAULT_LOCKED, failure.status)
        ChurVault.closeSession(session)
    }

    @Test
    fun the_handshake_matches_the_frozen_abi() {
        val handshake = ChurVault.handshake()
        assertEquals(8, handshake.major)
        assertEquals(4, handshake.minor, "the internal profile exposes ABI 8.4")
        assertEquals(1, handshake.objectFormatMin)
        assertEquals(2, handshake.objectFormatMax)
        assertTrue(handshake.capabilities and 0b0000_0010L != 0L, "the reader is declared")
        assertTrue(
            handshake.capabilities and 0b0001_0000L != 0L,
            "the portable backup surface is declared",
        )
        assertTrue(
            handshake.capabilities and 0b0000_0001L != 0L,
            "the independent decoy identity is declared",
        )
        assertTrue(
            handshake.capabilities and 0b0010_0000L != 0L,
            "the encrypted sync inbox is declared",
        )
        assertTrue(
            handshake.capabilities and 0b1000_0000L != 0L,
            "collection sharing is declared",
        )
        assertTrue(
            handshake.capabilities and 0b1_0000_0000L != 0L,
            "shared object transfer is declared",
        )
        assertTrue(ChurVault.statusIsKnown(ChurStatus.AUTHENTICATION_FAILED.value))
        assertFalse(ChurVault.statusIsKnown(42))
    }

    @Test
    fun a_vault_with_no_revocation_has_nothing_to_reencrypt() {
        val runtime = openRuntime()
        val session = createVault(runtime)
        assertEquals(ReencryptionCounts(pending = 0, failed = 0), ChurVault.reencryptionCounts(session))
        val operation = ChurVault.beginReencryption(session)
        var progress = ChurVault.poll(operation)
        while (!progress.terminal) {
            Thread.sleep(10)
            progress = ChurVault.poll(operation)
        }
        assertEquals(0, progress.status)
        assertEquals(0L, progress.total)
        ChurVault.closeOperation(operation)
        ChurVault.closeSession(session)
    }

    @Test
    fun a_created_vault_unlocks_and_a_wrong_password_does_not() {
        val runtime = openRuntime()
        assertFalse(ChurVault.vaultPresent(runtime))
        val session = createVault(runtime)
        assertTrue(ChurVault.vaultPresent(runtime))
        ChurVault.closeSession(session)

        val reopened = ChurVault.unlockWithPassword(runtime, PASSWORD.encodeToByteArray())
        assertTrue(reopened != 0L)
        ChurVault.closeSession(reopened)

        val failure = assertFailsWith<ChurFailure> {
            ChurVault.unlockWithPassword(runtime, "wrong".encodeToByteArray())
        }
        assertEquals(ChurStatus.AUTHENTICATION_FAILED, failure.status)
        assertTrue(failure.retryable)
    }

    @Test
    fun repeated_password_failures_delay_the_password_but_never_the_recovery_phrase() {
        // PASSWORD_PROFILE.md section 11: five free attempts, then a delay
        // that Rust enforces before any derivation.
        val runtime = openRuntime()
        val creation = ChurVault.beginCreation(runtime, PASSWORD.encodeToByteArray())
        val phrase = ChurVault.creationAddRecoverySlot(creation)
        ChurVault.closeSession(ChurVault.activateCreation(creation))
        repeat(5) {
            val failure = assertFailsWith<ChurFailure> {
                ChurVault.unlockWithPassword(runtime, "wrong".encodeToByteArray())
            }
            assertEquals(ChurStatus.AUTHENTICATION_FAILED, failure.status)
        }
        val delayed = assertFailsWith<ChurFailure> {
            ChurVault.unlockWithPassword(runtime, PASSWORD.encodeToByteArray())
        }
        assertEquals(ChurStatus.UNLOCK_DELAYED, delayed.status)
        assertTrue(delayed.retryable)
        assertTrue(ChurVault.statusIsKnown(ChurStatus.UNLOCK_DELAYED.value))

        val recovered = ChurVault.unlockWithRecovery(runtime, phrase.encodeToByteArray())
        ChurVault.closeSession(recovered)
        // The recovery success reset the count.
        ChurVault.closeSession(ChurVault.unlockWithPassword(runtime, PASSWORD.encodeToByteArray()))
    }

    @Test
    fun the_recovery_slot_offered_during_creation_unlocks_the_vault() {
        val runtime = openRuntime()
        val creation = ChurVault.beginCreation(runtime, PASSWORD.encodeToByteArray())
        val phrase = ChurVault.creationAddRecoverySlot(creation)
        assertEquals(24, phrase.split(" ").size, "RECOVERY.md §2 shows a 24-word phrase")
        val session = ChurVault.activateCreation(creation)
        val slots = ChurVault.slots(session)
        assertEquals(2, slots.size)
        assertTrue(slots.any { it.familyName == "Password" })
        assertTrue(slots.any { it.familyName == "Recovery" })
        assertTrue(slots.all { it.portable })
    }

    @Test
    fun an_imported_object_reads_back_byte_for_byte() {
        val runtime = openRuntime()
        val session = createVault(runtime)
        // Two chunks and a short third, so the canonical chunking is exercised
        // through the whole stack rather than only in Rust.
        val bytes = ByteArray(262_144 * 2 + 1_234) { (it * 31 % 251).toByte() }
        val objectId = import(session, bytes, "Bäckerei.jpg")

        val page = ChurVault.query(session, ObjectQuery())
        assertEquals(1, page.objects.size)
        assertEquals(1L, page.totalCount)
        val row = page.objects.first()
        assertEquals(bytes.size.toLong(), row.plaintextSize)
        assertEquals(4, row.integritySummary, "COMPLETE_VERIFIED")
        assertFalse(row.captureTimeSubstituted)

        val reader = ChurVault.openReader(session, objectId, StreamKind.ORIGINAL)
        assertEquals(bytes.size.toLong(), ChurVault.readerSize(reader))
        val info = ChurVault.readerContentInfo(reader)
        assertEquals("image/jpeg", info.contentType)
        assertTrue(info.complete)
        assertContentEquals(bytes, ChurVault.readRange(reader, 0, bytes.size))
        // A range that crosses a chunk boundary is the case the loop exists for.
        assertContentEquals(
            bytes.copyOfRange(262_100, 262_400),
            ChurVault.readRange(reader, 262_100, 300),
        )
        // The viewer's whole read: each chunk lands after the last in one
        // native buffer, not over the start of it.
        withChurBuffer(bytes.size) { buffer ->
            ChurVault.readInto(reader, buffer)
            assertContentEquals(bytes, buffer.copyOut(bytes.size))
        }
        assertEquals(4, ChurVault.verifyComplete(reader))
        ChurVault.closeReader(reader)
    }

    @Test
    fun the_detail_record_carries_the_private_text_the_projection_does_not() {
        val runtime = openRuntime()
        val session = createVault(runtime)
        val objectId = import(session, ByteArray(4_096) { 7 }, "Bäckerei.jpg")

        val tag = ChurVault.createTag(session, "Sommer")
        ChurVault.setObjectTag(session, tag, objectId, true)

        val detail = ChurVault.detail(session, objectId)
        assertEquals("Bäckerei.jpg", detail.filename)
        assertEquals("image/jpeg", detail.contentType)
        assertEquals(4_096L, detail.plaintextSize)
        assertEquals(1, detail.tags.size)
        assertEquals("Sommer", detail.tags.first().second)
    }

    @Test
    fun removing_album_objects_uses_one_native_transaction_and_keeps_other_memberships() {
        val session = createVault(openRuntime())
        val first = import(session, byteArrayOf(1, 2, 3), "first.jpg")
        import(session, byteArrayOf(4, 5, 6), "second.jpg")
        val objects = ChurVault.query(session, ObjectQuery()).objects.map { it.objectId }
        assertEquals(2, objects.size)
        val source = ChurVault.createAlbum(session, "Source")
        val other = ChurVault.createAlbum(session, "Other")
        ChurVault.placeAlbumObjects(session, source, "", null, null, objects, false)
        ChurVault.placeAlbumObjects(session, other, "", null, null, objects, false)
        val query = ObjectQuery(QueryScope.ALBUM, scopeId = source)
        val before = ChurVault.query(session, query)
        assertEquals(ChurStatus.CONFLICT, assertFailsWith<ChurFailure> {
            ChurVault.removeAlbumObjects(session, source, listOf(first, ByteArray(16) { 99 }))
        }.status)
        assertEquals(before.catalogGeneration, ChurVault.query(session, query).catalogGeneration)
        assertEquals(2L, ChurVault.query(session, query).totalCount)
        ChurVault.removeAlbumObjects(session, source, objects)
        assertEquals(0L, ChurVault.query(session, query).totalCount)
        assertEquals(2L, ChurVault.query(session, ObjectQuery(QueryScope.ALBUM, scopeId = other)).totalCount)
        assertEquals(2L, ChurVault.query(session, ObjectQuery()).totalCount)
        val reader = ChurVault.openReader(session, first, StreamKind.ORIGINAL)
        try { assertContentEquals(byteArrayOf(1, 2, 3), ChurVault.readRange(reader, 0, 3)) }
        finally { ChurVault.closeReader(reader) }
    }

    @Test
    fun the_library_scopes_answer_what_the_destinations_show() {
        val runtime = openRuntime()
        val session = createVault(runtime)
        val objectId = import(session, ByteArray(2_048) { 3 }, "holiday.jpg")

        ChurVault.setFavorite(session, objectId, true)
        assertEquals(1, ChurVault.query(session, ObjectQuery(QueryScope.FAVORITES)).objects.size)

        val album = ChurVault.createAlbum(session, "Holiday")
        ChurVault.setAlbumMembership(session, album, objectId, true)
        val albums = ChurVault.albums(session)
        assertEquals(1, albums.size)
        assertEquals("Holiday", albums.first().name)
        assertEquals(1L, albums.first().memberCount)
        assertEquals(
            1,
            ChurVault.query(session, ObjectQuery(QueryScope.ALBUM, scopeId = album)).objects.size,
        )

        // A move adds the destination before removing the old membership.
        val movedTo = ChurVault.createAlbum(session, "Later")
        ChurVault.setAlbumMembership(session, movedTo, objectId, true)
        ChurVault.setAlbumMembership(session, album, objectId, false)
        assertEquals(0, ChurVault.query(session, ObjectQuery(QueryScope.ALBUM, scopeId = album)).objects.size)
        assertEquals(1, ChurVault.query(session, ObjectQuery(QueryScope.ALBUM, scopeId = movedTo)).objects.size)
        assertEquals(1, ChurVault.query(session, ObjectQuery()).objects.size)

        val tag = ChurVault.createTag(session, "To print")
        assertEquals("To print", ChurVault.tags(session).single().name)
        ChurVault.setObjectTag(session, tag, objectId, true)
        assertEquals(1, ChurVault.query(session, ObjectQuery(QueryScope.TAG, scopeId = tag)).objects.size)

        // §16.4: the tokenizer folds the diacritic and the prefix index answers
        // an as-you-type query.
        assertEquals(
            1,
            ChurVault.query(session, ObjectQuery(QueryScope.SEARCH, terms = "holiday")).objects.size,
        )
        assertEquals(
            0,
            ChurVault.query(session, ObjectQuery(QueryScope.SEARCH, terms = "nothing")).objects.size,
        )
    }

    @Test
    fun a_thumbnail_the_platform_produced_round_trips() {
        val runtime = openRuntime()
        val session = createVault(runtime)
        val objectId = import(session, ByteArray(2_048) { 5 }, "a.jpg")

        val thumbnail = ByteArray(3_000) { (it % 97).toByte() }
        ChurVault.putDerived(session, objectId, StreamKind.THUMBNAIL, 320, 240, thumbnail)
        assertTrue(ChurVault.query(session, ObjectQuery()).objects.first().thumbnailReady)
        assertContentEquals(
            thumbnail,
            ChurVault.readDerived(session, objectId, StreamKind.THUMBNAIL),
        )
    }

    @Test
    fun locking_invalidates_every_handle_the_session_owns() {
        val runtime = openRuntime()
        val session = createVault(runtime)
        val objectId = import(session, ByteArray(2_048) { 9 }, "a.jpg")
        val reader = ChurVault.openReader(session, objectId, StreamKind.ORIGINAL)

        ChurVault.lock(session, LockReason.BACKGROUND)

        assertEquals(
            ChurStatus.SESSION_EXPIRED,
            assertFailsWith<ChurFailure> { ChurVault.readerSize(reader) }.status,
        )
        assertEquals(
            ChurStatus.VAULT_LOCKED,
            assertFailsWith<ChurFailure> { ChurVault.query(session, ObjectQuery()) }.status,
        )
        // §3: close after lock is still success.
        ChurVault.closeReader(reader)
        ChurVault.closeSession(session)
    }

    @Test
    fun trash_hides_restores_and_permanently_deletes_the_object() {
        val runtime = openRuntime()
        val session = createVault(runtime)
        val objectId = import(session, ByteArray(4_096) { 1 }, "a.jpg")
        ChurVault.setFavorite(session, objectId, true)

        ChurVault.deleteObject(session, objectId)

        assertTrue(ChurVault.query(session, ObjectQuery()).objects.isEmpty())
        assertTrue(ChurVault.query(session, ObjectQuery(QueryScope.FAVORITES)).objects.isEmpty())
        assertEquals(1, ChurVault.query(session, ObjectQuery(QueryScope.TRASH)).objects.size)
        ChurVault.detail(session, objectId)
        ChurVault.restoreTrash(session)
        assertEquals(1, ChurVault.query(session, ObjectQuery()).objects.size)
        assertEquals(1, ChurVault.query(session, ObjectQuery(QueryScope.FAVORITES)).objects.size)
        ChurVault.deleteObject(session, objectId)
        ChurVault.emptyTrash(session)
        assertTrue(ChurVault.query(session, ObjectQuery(QueryScope.TRASH)).objects.isEmpty())
        assertEquals(
            ChurStatus.NOT_FOUND,
            assertFailsWith<ChurFailure> { ChurVault.detail(session, objectId) }.status,
        )
    }

    @Test
    fun a_page_cursor_walks_the_scope_without_repeating_a_row() {
        val runtime = openRuntime()
        val session = createVault(runtime)
        repeat(7) { import(session, ByteArray(1_024) { index -> (index + it).toByte() }, "a$it.jpg") }

        val seen = mutableListOf<String>()
        var query = ObjectQuery(limit = 2)
        while (true) {
            val page = ChurVault.query(session, query)
            seen.addAll(page.objects.map { it.id })
            val cursor = page.nextCursor ?: break
            query = query.copy(cursor = cursor)
        }
        assertEquals(7, seen.size)
        assertEquals(7, seen.toSet().size, "a page repeated a row")
    }

    @Test
    fun the_last_portable_slot_cannot_be_removed() {
        val runtime = openRuntime()
        val session = createVault(runtime)
        val password = ChurVault.slots(session).single { it.familyName == "Password" }
        assertEquals(
            ChurStatus.CONFLICT,
            assertFailsWith<ChurFailure> { ChurVault.removeSlot(session, password.slotId) }.status,
        )
        ChurVault.addRecoverySlot(session)
        ChurVault.removeSlot(session, password.slotId)
        assertEquals(1, ChurVault.slots(session).size)
    }

    private companion object {
        const val PASSWORD = "correct horse battery staple"
    }
}
