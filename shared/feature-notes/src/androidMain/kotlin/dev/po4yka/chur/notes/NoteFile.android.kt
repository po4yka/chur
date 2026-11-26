package dev.po4yka.chur.notes

import java.io.File
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.NoSuchFileException
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes

internal actual fun readNoteFile(path: String): String? {
    return readNoteBlob(path, NoteState.MAX_STORE_BYTES)?.decodeToString(throwOnInvalidSequence = true)
}

/**
 * Writes beside the file and renames over it.
 *
 * `rename` within one filesystem replaces the destination in one step, so a
 * reader sees either the previous file or the new one. The directory sync
 * after it makes the rename itself survive a power loss.
 */
internal actual fun writeNoteFile(path: String, text: String) {
    writeNoteBlob(path, text.encodeToByteArray())
}

internal actual fun readNoteBlob(path: String, maxBytes: Int): ByteArray? {
    val file = File(path)
    val attributes = try {
        Files.readAttributes(file.toPath(), BasicFileAttributes::class.java)
    } catch (_: NoSuchFileException) {
        return null
    }
    require(attributes.isRegularFile && attributes.size() <= maxBytes) { "attachment content is too large" }
    return file.inputStream().use { input ->
        val output = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(8192)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            require(output.size().toLong() + count <= maxBytes) { "attachment content is too large" }
            output.write(buffer, 0, count)
        }
        output.toByteArray()
    }
}

internal actual fun writeNoteBlob(path: String, bytes: ByteArray) {
    val file = File(path)
    check(file.parentFile?.let { it.isDirectory || it.mkdirs() } != false) { "cannot create attachment directory" }
    val temporary = File(file.parentFile, "${file.name}.tmp")
    try {
        java.io.FileOutputStream(temporary).use { output ->
            output.write(bytes)
            output.fd.sync()
        }
        check(temporary.renameTo(file)) { "cannot store attachment content" }
    } finally {
        temporary.delete()
    }
    file.parentFile?.let { syncNoteDirectory(it) }
}

/**
 * Flushes the directory entry that a rename changed, and returns whether it
 * did. It never fails the write: the rename already published the new file,
 * and the caller then publishes the same state in memory or keeps the blobs
 * that state names. A failed attempt leaves the write as durable as the
 * rename, and a platform that cannot open a directory offers no sync.
 */
internal fun syncNoteDirectory(directory: File, force: (FileChannel) -> Unit = { it.force(true) }): Boolean = try {
    FileChannel.open(directory.toPath(), StandardOpenOption.READ).use(force)
    true
} catch (_: IOException) {
    false
} catch (_: UnsupportedOperationException) {
    false
} catch (_: SecurityException) {
    false
}

internal actual fun listNoteDirectory(path: String): List<String> =
    File(path.ifEmpty { "." }).list()?.toList().orEmpty()

internal actual fun deleteNoteBlob(path: String) {
    val file = File(path)
    check(!file.exists() || file.delete()) { "cannot delete attachment content" }
}
