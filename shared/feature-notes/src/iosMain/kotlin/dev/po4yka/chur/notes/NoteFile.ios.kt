@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class, kotlinx.cinterop.BetaInteropApi::class)

package dev.po4yka.chur.notes

import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.usePinned
import platform.Foundation.NSData
import platform.Foundation.create
import platform.Foundation.dataWithContentsOfFile
import platform.Foundation.writeToFile
import platform.posix.ENOENT
import platform.posix.errno
import platform.posix.memcpy
import platform.posix.stat

internal actual fun readNoteFile(path: String): String? {
    return readNoteBlob(path, NoteState.MAX_STORE_BYTES)?.decodeToString(throwOnInvalidSequence = true)
}

/**
 * Writes through Foundation's atomic replacement.
 *
 * `atomically` is the same temporary-then-rename that the Android side does by
 * hand; Foundation already owns it here, so this does not repeat it.
 *
 * The text becomes UTF-8 in Kotlin rather than through `NSString`. The
 * conversion is the same one, and doing it here keeps the encoding a decision
 * this file makes rather than one Foundation makes for it.
 */
internal actual fun writeNoteFile(path: String, text: String) {
    val bytes = text.encodeToByteArray()
    val data = if (bytes.isEmpty()) {
        NSData()
    } else {
        bytes.usePinned { pinned ->
            NSData.create(bytes = pinned.addressOf(0), length = bytes.size.toULong())
        }
    }
    if (!data.writeToFile(path, atomically = true)) {
        error("cannot replace the note file at $path")
    }
}

internal actual fun readNoteBlob(path: String, maxBytes: Int): ByteArray? {
    val size = memScoped {
        val info = alloc<stat>()
        if (stat(path, info.ptr) != 0) {
            if (errno == ENOENT) return null
            error("cannot read note file attributes")
        }
        info.st_size
    }
    require(size in 0..maxBytes.toLong()) { "attachment content is too large" }
    val data = NSData.dataWithContentsOfFile(path) ?: error("cannot read attachment content")
    require(data.length <= maxBytes.toULong()) { "attachment content is too large" }
    val bytes = ByteArray(data.length.toInt())
    if (bytes.isNotEmpty()) bytes.usePinned { pinned -> memcpy(pinned.addressOf(0), data.bytes, data.length) }
    return bytes
}

internal actual fun writeNoteBlob(path: String, bytes: ByteArray) {
    val directory = path.substringBeforeLast('/')
    check(platform.Foundation.NSFileManager.defaultManager.createDirectoryAtPath(directory, true, null, null)) {
        "cannot create attachment directory"
    }
    val data = if (bytes.isEmpty()) NSData() else bytes.usePinned {
        NSData.create(bytes = it.addressOf(0), length = bytes.size.toULong())
    }
    check(data.writeToFile(path, atomically = true)) { "cannot store attachment content" }
}

internal actual fun listNoteDirectory(path: String): List<String> =
    platform.Foundation.NSFileManager.defaultManager.contentsOfDirectoryAtPath(path.ifEmpty { "." }, null)
        ?.mapNotNull { it as? String }.orEmpty()

internal actual fun deleteNoteBlob(path: String) {
    val manager = platform.Foundation.NSFileManager.defaultManager
    check(!manager.fileExistsAtPath(path) || manager.removeItemAtPath(path, null)) { "cannot delete attachment content" }
}
