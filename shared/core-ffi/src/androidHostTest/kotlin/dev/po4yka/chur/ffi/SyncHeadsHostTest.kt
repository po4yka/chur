package dev.po4yka.chur.ffi

import dev.po4yka.chur.core.model.ChurStatus
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** The production Kotlin decoder consumes actual C ABI bytes through JNI. */
class SyncHeadsHostTest {
    @Test
    fun only_an_unlocked_verified_head_advances_and_rejected_staging_does_not() {
        val root = Files.createTempDirectory("chur-sync-heads-").toFile()
        val runtime = ChurVault.openRuntime(root.absolutePath)
        var session = 0L
        try {
            session = ChurVault.activateCreation(ChurVault.beginCreation(runtime, "head-test-password".encodeToByteArray()))
            val identity = ChurVault.sharingIdentity(session)
            val first = ChurVault.syncHeads(session).single()
            assertContentEquals(identity.deviceId, first.deviceId)
            assertEquals(1uL, first.sequence)

            ChurVault.stageSync(runtime, identity.vaultId, SyncRecordKind.OPERATION, 1, byteArrayOf(1, 2, 3))
            val badPage = byteArrayOf(0, 0, 0, 1, 4, 0, 0, 0, 2, 5)
            val truncated = assertFailsWith<ChurFailure> {
                ChurVault.stageSync(runtime, identity.vaultId, SyncRecordKind.OPERATION_PAGE, 1, badPage)
            }
            assertEquals(ChurStatus.INVALID_INPUT, truncated.status)
            val page = byteArrayOf(0, 0, 0, 1, 4, 0, 0, 0, 1, 5)
            repeat(2) {
                ChurVault.stageSync(runtime, identity.vaultId, SyncRecordKind.OPERATION_PAGE, 1, page)
            }
            val report = ChurVault.processSync(session, 2)
            assertEquals(3L, report.rejected)
            val after = ChurVault.syncHeads(session).single()
            assertContentEquals(first.deviceId, after.deviceId)
            assertEquals(first.sequence, after.sequence)

            ChurVault.lock(session, LockReason.USER)
            val failure = assertFailsWith<ChurFailure> { ChurVault.syncHeads(session) }
            assertEquals(ChurStatus.VAULT_LOCKED, failure.status)
        } finally {
            if (session != 0L) ChurVault.closeSession(session)
            ChurVault.closeRuntime(runtime)
            root.deleteRecursively()
        }
    }
}
