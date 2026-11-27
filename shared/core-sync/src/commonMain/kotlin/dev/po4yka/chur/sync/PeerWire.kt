package dev.po4yka.chur.sync

import dev.po4yka.chur.ffi.ChurFailure
import dev.po4yka.chur.core.model.ChurStatus
import kotlinx.serialization.Serializable

@Serializable
internal data class PeerHead(val device: ByteArray, val sequence: String)

@Serializable
internal data class PeerMessage(
    val kind: String,
    val bytes: ByteArray = byteArrayOf(),
    val id: ByteArray = byteArrayOf(),
    val offset: String = "0",
    val records: List<ByteArray> = emptyList(),
    val heads: List<PeerHead> = emptyList(),
    val failure: Int? = null,
)

internal class PeerBytes(private val bytes: ByteArray) {
    private var offset = 0
    fun take(size: Int): ByteArray {
        require(size >= 0 && size <= bytes.size - offset) { "truncated peer record" }
        return bytes.copyOfRange(offset, offset + size).also { offset += size }
    }
    fun number(size: Int): ULong = take(size).fold(0uL) { n, byte -> (n shl 8) or (byte.toInt() and 255).toULong() }
    fun record(): ByteArray {
        val size = number(4)
        require(size <= (4 * 1024 * 1024).toULong())
        return take(size.toInt())
    }
    fun end() { require(offset == bytes.size) { "trailing peer data" } }
}
internal fun number(value: ULong, size: Int): ByteArray = ByteArray(size) { (value shr ((size - it - 1) * 8)).toByte() }
internal fun record(bytes: ByteArray): ByteArray = number(bytes.size.toULong(), 4) + bytes
internal fun ByteArray.hex(): String = joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
internal fun String.unhex(): ByteArray {
    require(length % 2 == 0 && all { it in "0123456789abcdefABCDEF" }) { "invalid peer code" }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
internal fun locked(): Nothing = throw ChurFailure(ChurStatus.VAULT_LOCKED, "the peer vault locked")
