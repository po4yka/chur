package dev.po4yka.chur.ffi

import dev.po4yka.chur.core.model.ChurStatus
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DevicePairingRecordsTest {
    @Test
    fun overview_distinguishes_a_local_retry_from_another_devices_revocation() {
        val local = device(1, "local revoker", retry = 1)
        val remote = device(2, "remote revoker", retry = 0)
        val devices = decodePairedDevices(byteArrayOf(0, 2, 0, 0, 0, 2) + local + remote)
        assertContentEquals(ByteArray(16) { 1 }, devices[0].deviceId)
        assertEquals("local revoker", devices[0].fingerprint)
        assertFalse(devices[0].active)
        assertTrue(devices[0].retryAvailable)
        assertFalse(devices[1].retryAvailable)
        assertFalse(devices[1].current)
    }

    @Test
    fun retry_is_a_canonical_boolean_and_cannot_be_absent_or_followed_by_trailing_data() {
        val prefix = byteArrayOf(0, 2, 0, 0, 0, 1)
        for (record in listOf(device(1, "member", retry = 2), device(1, "member", retry = 1).dropLast(1).toByteArray(),
            device(1, "member", retry = 1) + byteArrayOf(0))) {
            assertFailsWith<ChurFailure> { decodePairedDevices(prefix + record) }
        }
    }

    @Test
    fun an_oversized_member_count_is_rejected_before_allocating_records() {
        val refusal = assertFailsWith<ChurFailure> { decodePairedDevices(byteArrayOf(0, 2, 0, 0, 16, 1)) }
        assertEquals(ChurStatus.RESOURCE_LIMIT_EXCEEDED, refusal.status)
    }

    private fun device(id: Int, fingerprint: String, retry: Int): ByteArray {
        val text = fingerprint.encodeToByteArray()
        return ByteArray(16) { id.toByte() } + byteArrayOf(0, 0, 0, text.size.toByte()) + text +
            byteArrayOf(0, 0, retry.toByte())
    }
}
