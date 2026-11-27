package dev.po4yka.chur.sync

import dev.po4yka.chur.core.model.ChurStatus
import dev.po4yka.chur.ffi.*
import java.io.File
import java.io.RandomAccessFile
import java.nio.file.Files
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import kotlin.test.*

/** Real encrypted vaults, JNI, and direct TCP; no service, mock transport, or account. */
class PeerSyncHostTest {
    @Test
    fun paired_devices_transfer_originals_and_album_edits_in_both_directions_and_reconnect() = runBlocking {
        val directory = Files.createTempDirectory("chur-peer-sync-").toFile()
        val source = NativeBoundary(File(directory, "source"))
        val target = NativeBoundary(File(directory, "target"))
        try {
            source.session = ChurVault.activateCreation(ChurVault.beginCreation(source.runtime, PASSWORD.encodeToByteArray()))
            ChurVault.sharingIdentity(source.session)
            val backup = File(directory, "vault.backup")
            RandomAccessFile(backup, "rw").use { terminal(ChurVault.beginBackup(source.session, descriptor(it))) }
            RandomAccessFile(backup, "r").use { terminal(ChurVault.beginRestore(target.runtime, descriptor(it), PASSWORD.encodeToByteArray())) }
            target.session = ChurVault.unlockWithPassword(target.runtime, PASSWORD.encodeToByteArray())
            val left = PeerSyncCoordinator { NOW }.apply { bind(source) }
            val right = PeerSyncCoordinator { NOW }.apply { bind(target) }
            val request = right.prepareDevicePairing()
            val preview = left.inspectDevicePairing(request.request)
            assertFailsWith<ChurFailure> { left.approveDevicePairing(request.request, "wrong fingerprint") }
            right.acceptPairingApproval(left.approveDevicePairing(request.request, preview.fingerprint))
            // Reopen the actual encrypted catalog before any connection; no approval-file replay.
            right.endSession()
            ChurVault.closeSession(target.session)
            target.session = ChurVault.unlockWithPassword(target.runtime, PASSWORD.encodeToByteArray())
            assertFalse(right.refresh())
            val original = ByteArray(800_000) { (it % 251).toByte() }
            val first = import(source.session, directory, original)
            val album = ChurVault.createAlbum(source.session, "From first device")
            ChurVault.setAlbumMembership(source.session, album, first, true)
            connect(left, right)
            assertContentEquals(original, export(target.session, directory, first))
            assertEquals("From first device", ChurVault.albums(target.session).single().name)
            assertFalse(ChurVault.sharingIdentity(source.session).deviceId.contentEquals(ChurVault.sharingIdentity(target.session).deviceId))
            val secondBytes = ByteArray(20_000) { (it % 233).toByte() }
            val second = import(target.session, directory, secondBytes)
            ChurVault.renameAlbum(target.session, album, "From second device")
            connect(left, right)
            assertContentEquals(secondBytes, export(source.session, directory, second))
            assertEquals("From second device", ChurVault.albums(source.session).single().name)
            // A new transport and fresh handshake do not duplicate existing objects.
            connect(left, right)
            assertEquals(2, ChurVault.query(source.session, ObjectQuery()).objects.size)
            assertEquals(2, ChurVault.query(target.session, ObjectQuery()).objects.size)
            val revoked = left.pairedDevices().single { !it.current }
            left.revokePairedDevice(revoked.deviceId, revoked.fingerprint)
            supervisorScope {
                val listening = async(Dispatchers.IO) { runCatching { left.listen("127.0.0.1") } }
                val invitation = withTimeout(10_000) { left.status.first { it.invitation != null }.invitation!! }
                assertFailsWith<Exception> { withContext(Dispatchers.IO) { right.connect(invitation) } }
                assertTrue(listening.await().isFailure)
            }
        } finally {
            source.close(); target.close(); directory.deleteRecursively()
        }
    }
    @Test
    fun locking_a_listening_session_erases_its_invitation_and_closes_its_device_socket(): Unit = runBlocking {
        val directory = Files.createTempDirectory("chur-peer-lock-").toFile()
        val source = NativeBoundary(directory)
        try {
            source.session = ChurVault.activateCreation(ChurVault.beginCreation(source.runtime, PASSWORD.encodeToByteArray()))
            val sync = PeerSyncCoordinator { NOW }.apply { bind(source) }
            supervisorScope {
                val run = async(Dispatchers.IO) { runCatching { sync.listen("127.0.0.1") } }
                val invitation = withTimeout(10_000) { sync.status.first { it.invitation != null }.invitation!! }
                sync.endSession()
                ChurVault.lock(source.session, LockReason.PANIC)
                assertTrue(withTimeout(5_000) { run.await() }.isFailure)
                assertNull(sync.status.value.invitation)
                assertFalse(sync.status.value.busy)
                assertFalse(sync.status.value.canApprove)
                val port = invitation.substringBefore('#').substringAfter(':').toInt()
                assertFailsWith<java.io.IOException> { java.net.Socket("127.0.0.1", port).close() }
                assertFailsWith<ChurFailure> { ChurVault.peerCall(source.session, byteArrayOf(3)) }
            }
        } finally { source.close(); directory.deleteRecursively() }
    }

    private suspend fun connect(left: PeerSyncCoordinator, right: PeerSyncCoordinator) = coroutineScope {
        withTimeout(60_000) {
            val listening = async(Dispatchers.IO) { left.listen("127.0.0.1") }
            val invitation = left.status.first { it.invitation != null }.invitation!!
            withContext(Dispatchers.IO) { right.connect(invitation) }
            listening.await()
            assertEquals("Synced directly with the other device.", left.status.value.message)
            assertEquals(left.status.value.message, right.status.value.message)
            assertNull(left.status.value.invitation)
        }
    }
    private fun import(session: Long, directory: File, bytes: ByteArray): ByteArray {
        val before = ChurVault.query(session, ObjectQuery()).objects.map { it.objectId.toList() }.toSet()
        val file = File(directory, "input.bin").apply { writeBytes(bytes) }
        RandomAccessFile(file, "r").use { terminal(ChurVault.beginImport(session, descriptor(it), ImportRequest(
            contentType = "application/octet-stream", seekable = true, mediaClass = 4,
            knownLength = bytes.size.toLong(), originalFilename = "input.bin",
        ))) }
        return ChurVault.query(session, ObjectQuery()).objects.single { it.objectId.toList() !in before }.objectId
    }
    private fun export(session: Long, directory: File, id: ByteArray): ByteArray {
        val file = File(directory, "output.bin")
        RandomAccessFile(file, "rw").use { it.setLength(0); terminal(ChurVault.beginExport(session, id, descriptor(it))) }
        return file.readBytes()
    }
    private class NativeBoundary(val root: File) : SyncVaultBoundary, AutoCloseable {
        var runtime = ChurVault.openRuntime(root.apply { mkdirs() }.absolutePath)
        var session = 0L
        override suspend fun peerCall(input: ByteArray) = ChurVault.peerCall(session, input)
        override suspend fun identity(): SharingIdentity? = try { ChurVault.sharingIdentity(session) } catch (failure: ChurFailure) {
            if (failure.status == ChurStatus.RECOVERY_REQUIRED) null else throw failure
        }
        override suspend fun acceptedHeads() = ChurVault.syncHeads(session).map { DeviceCursor(it.deviceId, it.sequence) }
        override suspend fun stage(vaultId: ByteArray, kind: SyncRecordKind, stagedAtMs: Long, record: ByteArray) =
            ChurVault.stageSync(runtime, vaultId, kind, stagedAtMs, record)
        override suspend fun process() = ChurVault.processSync(session, 1_700_000_000_000L)
        override suspend fun forkState() = ChurVault.syncForkState(session)
        override suspend fun sourcePage(collectionId: ByteArray, afterObjectId: ByteArray) = ChurVault.sharedSourcePage(session, collectionId, afterObjectId)
        override suspend fun ownSyncCollections() = ChurVault.ownSyncCollections(session)
        override suspend fun ownSyncOperations(after: ULong) = ChurVault.ownSyncOperations(session, after)
        override suspend fun ownSyncPlan(collectionId: ByteArray) = ChurVault.ownSyncPlan(session, collectionId)
        override suspend fun ownSyncAuthor(source: SharedSourceObject) = ChurVault.ownSyncAuthor(session, source)
        override suspend fun prepareDevicePairing() = ChurVault.prepareDevicePairing(session)
        override suspend fun inspectDevicePairing(request: ByteArray) = ChurVault.inspectDevicePairing(session, request)
        override suspend fun approveDevicePairing(request: ByteArray, nowMs: Long) =
            ChurVault.approveDevicePairing(session, request, nowMs)
        override suspend fun startDevicePairing(approval: ByteArray) = ChurVault.startDevicePairing(session, approval)
        override suspend fun finishDevicePairing(nowMs: Long) = ChurVault.finishDevicePairing(session, nowMs)
        override suspend fun currentDeviceCheckpoint(nowMs: Long) = ChurVault.currentDeviceCheckpoint(session, nowMs)
        override suspend fun pairedDevices() = ChurVault.pairedDevices(session)
        override suspend fun prepareDeviceRevocation(deviceId: ByteArray, nowMs: Long) = ChurVault.prepareDeviceRevocation(session, deviceId, nowMs)
        override suspend fun objectKeyRequest(collectionId: ByteArray, objectId: ByteArray) = ChurVault.objectKeyRequest(session, collectionId, objectId)
        override suspend fun objectKeyAccept(packageBytes: ByteArray, grant: ByteArray): Boolean { ChurVault.objectKeyAccept(session, packageBytes, grant); return true }
        override suspend fun sharedDownloadOffset(collectionId: ByteArray, objectId: ByteArray) = ChurVault.sharedDownloadOffset(session, collectionId, objectId)
        override suspend fun appendSharedDownload(collectionId: ByteArray, objectId: ByteArray, offset: ULong, bytes: ByteArray): Boolean {
            ChurVault.appendSharedDownload(session, collectionId, objectId, offset, bytes); return true
        }
        override suspend fun finishSharedDownload(collectionId: ByteArray, objectId: ByteArray, nowMs: Long): Boolean {
            ChurVault.finishSharedDownload(session, collectionId, objectId, nowMs); return true
        }
        override fun close() {
            if (session != 0L) ChurVault.closeSession(session)
            ChurVault.closeRuntime(runtime)
        }
    }


    companion object {
        const val PASSWORD = "correct horse battery staple peer"
        const val NOW = 1_700_000_000_000L
        private fun descriptor(file: RandomAccessFile): Int = file.fd.javaClass.getDeclaredField("fd").apply { isAccessible = true }.getInt(file.fd)
        private fun terminal(operation: Long) {
            val deadline = System.nanoTime() + 30_000_000_000L
            try {
                while (true) {
                    check(System.nanoTime() < deadline)
                    val progress = ChurVault.poll(operation)
                    if (progress.terminal) { assertEquals(0, progress.status); return }
                    Thread.yield()
                }
            } finally { ChurVault.closeOperation(operation) }
        }
    }
}
