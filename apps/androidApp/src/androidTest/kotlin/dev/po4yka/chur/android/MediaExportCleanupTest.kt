package dev.po4yka.chur.android

import android.content.ContentResolver
import android.content.ContentValues
import android.content.Context
import android.content.ContextWrapper
import android.content.pm.ProviderInfo
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.Bundle
import android.os.CancellationSignal
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.DocumentsProvider
import android.provider.MediaStore
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.po4yka.chur.app.ExportTarget
import dev.po4yka.chur.imports.AndroidProviderPipe
import java.io.File
import java.io.IOException
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Assert.assertNotNull
import org.junit.Test
import org.junit.runner.RunWith

/** A partial MediaStore export is not left in shared storage after the process dies. */
@RunWith(AndroidJUnit4::class)
class MediaExportCleanupTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val resolver = context.contentResolver

    @Test
    fun aNewProcessDeletesThePendingRowsThatAnEarlierProcessLeft() {
        // An earlier process inserted the row and died before publish or discard.
        val abandoned = requireNotNull(resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, "chur-abandoned-${System.nanoTime()}.bin")
            put(MediaStore.MediaColumns.MIME_TYPE, "application/octet-stream")
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }))
        try {
            resolver.openOutputStream(abandoned)!!.use { it.write(ByteArray(64) { 7 }) }
            assertNotNull(pendingRow(abandoned))
            ExportDestinations(context, {}, {})
            assertEquals(null, pendingRow(abandoned))
        } finally {
            resolver.delete(abandoned, null, null)
        }
    }

    @Test
    fun exhaustedOutputSlotsDiscardNewMediaRows() {
        val sink = ExportDestinations(context, {}, {})
        val files = List(4) { File.createTempFile("provider-slot-", ".bin", context.cacheDir) }
        val outputs = files.map { AndroidProviderPipe.output(ParcelFileDescriptor.open(it, ParcelFileDescriptor.MODE_WRITE_ONLY)) }
        try {
            val name = "chur-output-limit-${System.nanoTime()}.bin"
            exhausted { sink.create(name, "application/octet-stream", ExportTarget.DEFAULT, null, 512) }
            awaitCleanup {
                resolver.query(MediaStore.Downloads.EXTERNAL_CONTENT_URI, arrayOf(MediaStore.MediaColumns._ID), Bundle().apply {
                    putString(android.content.ContentResolver.QUERY_ARG_SQL_SELECTION, "${MediaStore.MediaColumns.DISPLAY_NAME} = ?")
                    putStringArray(android.content.ContentResolver.QUERY_ARG_SQL_SELECTION_ARGS, arrayOf(name))
                    putInt(MediaStore.QUERY_ARG_MATCH_PENDING, MediaStore.MATCH_INCLUDE)
                }, null)?.use { !it.moveToFirst() } == true
            }
        } finally {
            outputs.forEach { it.close(); runCatching { it.finish() } }
            files.forEach { it.delete() }
            sink.cancelPending()
        }
    }

    @Test
    fun exhaustedOutputSlotsDiscardPickedDocumentsThroughTheDocumentsProvider() {
        val picked = PickedDocuments()
        val sink = ExportDestinations(picked.context, {}, {})
        val files = List(4) { File.createTempFile("provider-slot-", ".bin", context.cacheDir) }
        val outputs = files.map { AndroidProviderPipe.output(ParcelFileDescriptor.open(it, ParcelFileDescriptor.MODE_WRITE_ONLY)) }
        try {
            exhausted { sink.create("selected.bin", "application/octet-stream", ExportTarget.FILES, picked.uri("single").toString(), 512) }
            exhausted { sink.createArchive("selected.bin", "application/octet-stream", ExportTarget.FILES, picked.uri("archive").toString(), 512) }
            awaitCleanup { picked.deleted.toList().sorted() == listOf("archive", "single") }
        } finally {
            outputs.forEach { it.close(); runCatching { it.finish() } }
            files.forEach { it.delete() }
            sink.cancelPending()
        }
    }

    @Test
    fun aDiscardedPickedDocumentIsDeletedThroughTheDocumentsProvider() {
        val picked = PickedDocuments()
        val sink = ExportDestinations(picked.context, {}, {})
        try {
            requireNotNull(sink.create("selected.bin", "application/octet-stream", ExportTarget.FILES, picked.uri("plain").toString(), 512)).discard()
            assertEquals(listOf("plain"), picked.deleted.toList())
        } finally { sink.cancelPending() }
    }

    /** A DocumentsProvider rejects ContentResolver.delete, so only DocumentsContract removes a picked document. */
    private inner class PickedDocuments {
        val authority = "dev.po4yka.chur.test.picked-${System.nanoTime()}"
        val deleted = CopyOnWriteArrayList<String>()
        private val resolver: ContentResolver
        val context: Context

        init {
            val provider = object : DocumentsProvider() {
                override fun onCreate() = true
                override fun deleteDocument(documentId: String) { deleted.add(documentId) }
                override fun openDocument(documentId: String, mode: String, signal: CancellationSignal?): ParcelFileDescriptor =
                    ParcelFileDescriptor.open(File.createTempFile("picked-", ".bin", this@MediaExportCleanupTest.context.cacheDir).apply { deleteOnExit() }, ParcelFileDescriptor.MODE_READ_WRITE)
                override fun queryRoots(projection: Array<out String>?): Cursor = MatrixCursor(arrayOf())
                override fun queryDocument(documentId: String, projection: Array<out String>?): Cursor = MatrixCursor(arrayOf())
                override fun queryChildDocuments(parentDocumentId: String, projection: Array<out String>?, sortOrder: String?): Cursor = MatrixCursor(arrayOf())
            }
            provider.attachInfo(this@MediaExportCleanupTest.context, ProviderInfo().apply {
                authority = this@PickedDocuments.authority
                exported = true
                grantUriPermissions = true
                readPermission = android.Manifest.permission.MANAGE_DOCUMENTS
                writePermission = android.Manifest.permission.MANAGE_DOCUMENTS
            })
            resolver = ContentResolver.wrap(provider)
            context = object : ContextWrapper(this@MediaExportCleanupTest.context) {
                override fun getContentResolver() = resolver
            }
        }

        fun uri(id: String): Uri = DocumentsContract.buildDocumentUri(authority, id)
    }

    private fun exhausted(action: () -> Unit) {
        try { action(); fail("the occupied output pool must reject the export") }
        catch (failure: IOException) { assertEquals("Too many provider output workers", failure.message) }
    }

    private fun awaitCleanup(complete: () -> Boolean) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (!complete() && System.nanoTime() < deadline) Thread.sleep(20)
        assertTrue("the unpublished destination was not removed", complete())
    }

    private fun pendingRow(uri: Uri): Long? = resolver.query(uri, arrayOf(MediaStore.MediaColumns.DATE_EXPIRES),
        Bundle().apply { putInt(MediaStore.QUERY_ARG_MATCH_PENDING, MediaStore.MATCH_INCLUDE) }, null,
    )?.use { if (it.moveToFirst()) it.getLong(0) else null }
}
