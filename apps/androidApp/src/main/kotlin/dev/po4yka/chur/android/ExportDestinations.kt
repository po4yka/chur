package dev.po4yka.chur.android

import android.content.ContentResolver
import android.content.ContentUris
import android.content.ContentValues
import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.provider.DocumentsContract
import android.provider.MediaStore
import android.webkit.MimeTypeMap
import androidx.core.content.FileProvider
import dev.po4yka.chur.app.ExportSink
import dev.po4yka.chur.app.ExportDirectory
import dev.po4yka.chur.app.ExportTarget
import dev.po4yka.chur.core.model.ChurStatus
import dev.po4yka.chur.ffi.ChurFailure
import dev.po4yka.chur.imports.AndroidProviderPipe
import java.io.File
import java.io.FileNotFoundException
import java.util.UUID

/** Streams verified originals to a chosen system destination. */
class ExportDestinations(
    private val context: Context,
    private val onShareLaunch: () -> Unit,
    private val onShareEnd: () -> Unit,
    private val scheduleCleanup: (Long, () -> Unit) -> Unit = { delay, cleanup ->
        Handler(Looper.getMainLooper()).postDelayed({ cleanup() }, delay)
    },
) : ExportSink {
    private val resolver: ContentResolver = context.contentResolver
    private val scratch = ExportLeases.scratch(context)
    // The export worker creates and publishes shares; the main thread returns from
    // the share sheet and runs the cleanup timers. Both maps change only under [shares].
    private val shares = Any()
    private val pendingShares = mutableMapOf<Uri, File>()
    private val scratchReservations = mutableMapOf<File, Long>()
    private var generation = 0L
    private val directoryExports = mutableSetOf<DocumentExportDirectory>()
    private val providerOutputs = mutableSetOf<AndroidProviderPipe.Output>()
    private val ciphertextScratch = File(context.cacheDir, "encrypted-transfers")
    private val ciphertextFiles = mutableSetOf<File>()

    init {
        ExportLeases.clearScratch(context) // A previous process cannot have a live share sheet.
        scratch.mkdirs()
        ciphertextScratch.mkdirs()
        ciphertextScratch.listFiles()?.forEach { it.delete() }
        // ChurHost builds this once per process, so no export of this process is
        // in flight yet: every pending row that is still ours is a partial export.
        deleteAbandonedMediaExports()
    }

    /**
     * Delete the pending MediaStore rows that this app owns. A process that dies
     * during a MediaStore export leaves a partial plaintext file in shared storage,
     * and only the owner can see or delete a pending row.
     */
    internal fun deleteAbandonedMediaExports(): Int = MEDIA_COLLECTIONS.sumOf { collection ->
        try {
            deletePendingRows(collection)
        } catch (_: RuntimeException) {
            0 // A volume that is not mounted has no rows to delete; the next start tries again.
        }
    }

    private fun deletePendingRows(collection: Uri): Int {
        val owner = "${MediaStore.MediaColumns.OWNER_PACKAGE_NAME} = ? AND ${MediaStore.MediaColumns.IS_PENDING} = 1"
        val ids = mutableListOf<Long>()
        val cursor = if (Build.VERSION.SDK_INT >= 30) {
            resolver.query(collection, arrayOf(MediaStore.MediaColumns._ID), Bundle().apply {
                putString(ContentResolver.QUERY_ARG_SQL_SELECTION, owner)
                putStringArray(ContentResolver.QUERY_ARG_SQL_SELECTION_ARGS, arrayOf(context.packageName))
                putInt(MediaStore.QUERY_ARG_MATCH_PENDING, MediaStore.MATCH_ONLY)
            }, null)
        } else {
            @Suppress("DEPRECATION")
            resolver.query(MediaStore.setIncludePending(collection), arrayOf(MediaStore.MediaColumns._ID),
                owner, arrayOf(context.packageName), null)
        }
        cursor?.use { while (it.moveToNext()) ids += it.getLong(0) }
        return ids.sumOf { id ->
            val row = ContentUris.withAppendedId(collection, id)
            resolver.delete(row, null, null)
        }
    }

    override fun cancelPending() {
        val directories = synchronized(directoryExports) {
            generation += 1
            directoryExports.toList()
        }
        // Native code may be acquiring a duplicate of an active descriptor. Invalidate
        // now; the operation's finally closes and removes its output after native work ends.
        directories.forEach { it.invalidate() }
        synchronized(providerOutputs) { providerOutputs.toList() }.forEach { it.cancel() }
        synchronized(shares) { pendingShares.toMap() }.forEach { (uri, file) -> releaseShare(uri, file) }
        synchronized(shares) { scratchReservations.clear() }
        ExportLeases.clearScratch(context)
        scratch.mkdirs()
        onShareEnd()
    }

    override fun openDirectory(uri: String): ExportDirectory {
        val startedAt = synchronized(directoryExports) { generation }
        val directory = DocumentExportDirectory.open(resolver, Uri.parse(uri)) { directory ->
            synchronized(directoryExports) { directoryExports.remove(directory) }
        }
        synchronized(directoryExports) {
            if (generation != startedAt) {
                directory.close()
                throw ChurFailure(ChurStatus.CANCELLED, "the folder export was cancelled")
            }
            directoryExports.add(directory)
        }
        return directory
    }

    /** Allow asynchronous recipient opens briefly after the share activity returns. */
    internal fun completePendingShares() {
        expireShares()
        val completed = synchronized(shares) { pendingShares.toMap() }
        if (completed.isNotEmpty()) scheduleCleanup(60_000L) {
            completed.forEach { (uri, file) -> releaseShare(uri, file) }
        }
    }

    /**
     * End every share older than the hold limit by the wall clock. The timer of
     * [scheduleCleanup] counts uptime only and stops in deep sleep.
     */
    internal fun expireShares(now: Long = System.currentTimeMillis()) {
        synchronized(shares) { pendingShares.toMap() }.forEach { (uri, file) ->
            if (ExportLeases.expired(file, now)) releaseShare(uri, file)
        }
    }

    private fun releaseShare(uri: Uri, file: File) {
        synchronized(shares) {
            if (pendingShares[uri] !== file) return
            pendingShares.remove(uri)
        }
        runCatching { context.revokeUriPermission(uri, Intent.FLAG_GRANT_READ_URI_PERMISSION) }
        releaseScratch(file)
    }

    private fun releaseScratch(file: File) {
        ExportLeases.revoke(file)
        synchronized(shares) { scratchReservations.remove(file) }
        file.delete()
    }

    private class Destination(
        private val handle: ParcelFileDescriptor,
        private val publishAction: () -> Unit,
        private val discardAction: () -> Unit,
    ) : ExportSink.Destination {
        private var closed = false
        override val descriptor: Int get() = handle.fd
        override fun publish() {
            close()
            publishAction()
        }
        override fun discard() {
            close()
            discardAction()
        }
        override fun close() {
            if (!closed) { handle.close(); closed = true }
        }
    }

    private inner class ProviderDestination(
        val transfer: AndroidProviderPipe.Output,
        private val uri: Uri,
        private val document: Boolean,
        private val publishAction: () -> Unit,
        private val discardAction: () -> Unit,
    ) : ExportSink.Destination {
        override val descriptor: Int get() = transfer.descriptor
        override fun publish() {
            transfer.finish()
            publishAction()
        }
        override fun discard() { close(); discardAction() }
        fun discardAfterSetupFailure() {
            try { close() } finally { AndroidProviderOpen.discard(resolver, uri, document) }
        }
        override fun close() {
            transfer.close()
            synchronized(providerOutputs) { providerOutputs.remove(transfer) }
        }
    }

    /** Only encrypted backup/archive callers may use this local seekable spool. */
    override fun createArchive(
        displayName: String,
        contentType: String,
        target: ExportTarget,
        uri: String?,
        capacity: Long,
    ): ExportSink.Destination? {
        if (target == ExportTarget.SHARE) return create(displayName, contentType, target, uri, capacity)
        val destination = create(displayName, contentType, target, uri, capacity) as? ProviderDestination ?: return null
        val file = File(ciphertextScratch, UUID.randomUUID().toString())
        try {
            synchronized(ciphertextFiles) {
                if (ciphertextFiles.size >= 4) throw ChurFailure(ChurStatus.RESOURCE_LIMIT_EXCEEDED, "the encrypted transfer budget")
                check(file.createNewFile())
                ciphertextFiles.add(file)
            }
            val handle = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_WRITE)
            return object : ExportSink.Destination {
                private var closed = false
                override val descriptor: Int get() = handle.fd
                override fun publish() {
                    if (closed) throw ChurFailure(ChurStatus.CANCELLED, "the encrypted transfer")
                    handle.close()
                    ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY).use {
                        destination.transfer.copyCiphertext(it)
                    }
                    destination.publish()
                    close()
                }
                override fun discard() { try { destination.discard() } finally { close() } }
                override fun close() {
                    if (closed) return
                    closed = true
                    try { handle.close() } finally {
                        destination.close()
                        file.delete()
                        synchronized(ciphertextFiles) { ciphertextFiles.remove(file) }
                    }
                }
            }
        } catch (failure: Exception) {
            file.delete()
            synchronized(ciphertextFiles) { ciphertextFiles.remove(file) }
            runCatching { destination.discardAfterSetupFailure() }
            throw failure
        }
    }

    override fun archiveCapacity(target: ExportTarget): Long = when (target) {
        ExportTarget.FILES -> Long.MAX_VALUE
        ExportTarget.SHARE -> {
            val singleLimit = 4L * 1024 * 1024 * 1024
            synchronized(shares) {
                if (scratchReservations.size >= 4) 0L
                else minOf(singleLimit, 2 * singleLimit - scratchReservations.values.sum()).coerceAtLeast(0)
            }
        }
        else -> 0L
    }

    override fun create(displayName: String, contentType: String): ExportSink.Destination? =
        create(displayName, contentType, ExportTarget.DEFAULT, null)

    override fun create(
        displayName: String,
        contentType: String,
        target: ExportTarget,
        uri: String?,
    ): ExportSink.Destination? = create(displayName, contentType, target, uri, -1)

    override fun create(
        displayName: String,
        contentType: String,
        target: ExportTarget,
        uri: String?,
        plaintextSize: Long,
    ): ExportSink.Destination? = when (target) {
        ExportTarget.FILES -> {
            val document = uri?.let(Uri::parse) ?: return null
            // A picked document belongs to a DocumentsProvider, which rejects ContentResolver.delete.
            open(document, publish = {}, discard = {
                // A document that is already gone must not mask the failure that led here.
                try {
                    if (!DocumentsContract.deleteDocument(resolver, document)) {
                        throw ChurFailure(ChurStatus.IO_FAILURE, "the partial export could not be removed")
                    }
                } catch (_: FileNotFoundException) { }
            }, document = true)
        }
        ExportTarget.SHARE -> {
            expireShares()
            val singleLimit = 4L * 1024 * 1024 * 1024
            val totalLimit = 2 * singleLimit
            val createdGeneration = synchronized(directoryExports) { generation }
            val extension = MimeTypeMap.getSingleton().getExtensionFromMimeType(contentType)
                ?: displayName.substringAfterLast('.', "bin")
            val safeExtension = extension.takeIf { it.matches(Regex("[A-Za-z0-9]{1,10}")) } ?: "bin"
            val file = File(scratch, "${UUID.randomUUID()}.$safeExtension")
            // The check and the reservation are one step, so two concurrent creates
            // cannot both pass a budget that only one of them fits.
            synchronized(shares) {
                if (plaintextSize < 0 || plaintextSize > singleLimit || scratchReservations.size >= 4 ||
                    scratchReservations.values.sum() > totalLimit - plaintextSize
                ) {
                    throw ChurFailure(ChurStatus.RESOURCE_LIMIT_EXCEEDED, "the share scratch budget")
                }
                check(file.createNewFile()) { "the share file already exists" }
                scratchReservations[file] = plaintextSize
            }
            val handle = try {
                ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_WRITE_ONLY)
            } catch (failure: Exception) {
                releaseScratch(file)
                throw failure
            }
            Destination(handle, publishAction = {
                if (createdGeneration != synchronized(directoryExports) { generation }) {
                    releaseScratch(file)
                    throw ChurFailure(ChurStatus.CANCELLED, "the share was cancelled")
                }
                val contentUri = FileProvider.getUriForFile(
                    context, "${context.packageName}.exports", file, displayName,
                )
                val intent = Intent(Intent.ACTION_SEND).apply {
                    type = contentType
                    putExtra(Intent.EXTRA_STREAM, contentUri)
                    clipData = ClipData.newRawUri("", contentUri)
                    addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
                }
                // The lease starts now: the provider measures the hold limit from this time.
                file.setLastModified(System.currentTimeMillis())
                synchronized(shares) { pendingShares[contentUri] = file }
                ExportLeases.grant(file)
                try {
                    onShareLaunch()
                    context.startActivity(Intent.createChooser(intent, "Share original").apply {
                        clipData = ClipData.newRawUri("", contentUri)
                        addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
                    })
                } catch (failure: Exception) {
                    releaseShare(contentUri, file)
                    onShareEnd()
                    throw failure
                }
                scheduleCleanup(ExportLeases.HOLD_MS) {
                    releaseShare(contentUri, file)
                }
            }, discardAction = { releaseScratch(file) })
        }
        else -> {
            val collection = when (target) {
                ExportTarget.MEDIA_LIBRARY -> when {
                    contentType.startsWith("image/") -> MediaStore.Images.Media.EXTERNAL_CONTENT_URI
                    contentType.startsWith("video/") -> MediaStore.Video.Media.EXTERNAL_CONTENT_URI
                    else -> return null
                }
                else -> MediaStore.Downloads.EXTERNAL_CONTENT_URI
            }
            val values = ContentValues().apply {
                put(MediaStore.MediaColumns.DISPLAY_NAME, displayName)
                put(MediaStore.MediaColumns.MIME_TYPE, contentType)
                put(MediaStore.MediaColumns.IS_PENDING, 1)
            }
            val destination = resolver.insert(collection, values) ?: return null
            open(destination,
                publish = {
                    check(resolver.update(destination, ContentValues().apply {
                        put(MediaStore.MediaColumns.IS_PENDING, 0)
                    }, null, null) == 1) { "the export could not be published" }
                },
                discard = { resolver.delete(destination, null, null) },
            )
        }
    }

    private fun open(uri: Uri, publish: () -> Unit, discard: () -> Unit, document: Boolean = false): ExportSink.Destination? {
        val openedGeneration = synchronized(directoryExports) { generation }
        var openerEntered = false
        val transfer = try {
            AndroidProviderPipe.output {
                openerEntered = true
                AndroidProviderOpen.open(resolver, uri, "w", document) {
                    openedGeneration != synchronized(directoryExports) { generation }
                } ?: throw ChurFailure(ChurStatus.IO_FAILURE, "the export file could not be opened")
            }
        } catch (failure: Exception) {
            // Once entered, the opener owns late-FD cleanup. Before entry, only
            // this path can discard the selected URI or the new MediaStore row.
            if (!openerEntered) AndroidProviderOpen.discard(resolver, uri, document)
            throw failure
        }
        synchronized(providerOutputs) { providerOutputs.add(transfer) }
        return ProviderDestination(transfer, uri, document, publish, discard)
    }
}

private val MEDIA_COLLECTIONS: List<Uri> = listOf(
    MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
    MediaStore.Video.Media.EXTERNAL_CONTENT_URI,
    MediaStore.Downloads.EXTERNAL_CONTENT_URI,
)
