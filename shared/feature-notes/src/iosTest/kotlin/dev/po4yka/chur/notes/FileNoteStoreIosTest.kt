@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package dev.po4yka.chur.notes

import kotlinx.coroutines.test.runTest
import platform.Foundation.NSFileManager
import platform.Foundation.NSTemporaryDirectory
import platform.Foundation.NSUUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class FileNoteStoreIosTest {
    @Test
    fun a_failed_file_lookup_retries_before_the_next_write() = runTest {
        val files = NSFileManager.defaultManager
        val root = NSTemporaryDirectory() + NSUUID().UUIDString
        val parent = "$root/public"
        val parked = "$root/parked"
        val path = "$parent/notes.json"
        val original = Note("a", "Saved", "original", 1)
        val next = Note("b", "New", "second", 2)
        assertTrue(files.createDirectoryAtPath(parent, true, null, null))
        try {
            FileNoteStore(path).put(original)
            assertTrue(files.moveItemAtPath(parent, parked, null))
            writeNoteFile(parent, "not a directory")

            val store = FileNoteStore(path)
            assertFailsWith<IllegalStateException> { store.all() }
            assertTrue(files.removeItemAtPath(parent, null))
            assertTrue(files.moveItemAtPath(parked, parent, null))
            store.put(next)
            assertEquals(setOf(original, next), FileNoteStore(path).all().toSet())
        } finally {
            files.removeItemAtPath(root, null)
        }
    }
}
