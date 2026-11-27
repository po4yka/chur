package dev.po4yka.chur.android

import android.content.ContextWrapper
import android.content.Intent
import android.net.Uri
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.po4yka.chur.app.notes.AndroidPublicNoteExport
import java.io.File
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class PublicNoteExportTest {
    @Test
    fun a_recreated_export_owner_delivers_the_original_text_and_releases_cancelled_requests() = runBlocking {
        val app = InstrumentationRegistry.getInstrumentation().targetContext
        val directory = java.nio.file.Files.createTempDirectory(app.cacheDir.toPath(), "note-export-test").toFile()
        val context = object : ContextWrapper(app) {
            override fun getCacheDir(): File = directory
        }
        val requests = mutableListOf<Intent>()
        fun owner(restored: Boolean) = AndroidPublicNoteExport(context, restored) { requests.add(it) }
        try {
            val body = "# Title\r\n" + "Ж".repeat(30_000) + "  \n"
            owner(false).choose("Draft", body, markdown = true)
            assertEquals(Intent.ACTION_CREATE_DOCUMENT, requests.single().action)
            assertEquals("Draft.md", requests.single().getStringExtra(Intent.EXTRA_TITLE))
            val destination = File(directory, "selected")
            val restored = owner(true)
            restored.complete(Uri.fromFile(destination))
            assertEquals(body, destination.readText())

            restored.choose("Cancelled", "not selected", markdown = false)
            owner(true).complete(null)
            restored.choose("Next", "second", markdown = false)
            owner(true).complete(Uri.fromFile(destination))
            assertEquals("Next\n\nsecond", destination.readText())
        } finally { directory.deleteRecursively() }
    }
}
