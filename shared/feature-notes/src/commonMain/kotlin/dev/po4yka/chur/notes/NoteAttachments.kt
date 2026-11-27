package dev.po4yka.chur.notes

import kotlin.io.encoding.Base64
import kotlin.uuid.Uuid
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

/** Public descriptors never expose a source URI or a filesystem path. */
@Serializable
data class NoteAttachment(
    val id: String,
    val name: String,
    val mimeType: String,
    val sizeBytes: Int,
    internal val storageId: String = id,
)

object NoteAttachments {
    const val MAX_NAME_BYTES: Int = 240
    const val MAX_FILE_BYTES: Int = 8 * 1024 * 1024
    const val MAX_TOTAL_BYTES: Int = 16 * 1024 * 1024
    const val MAX_ATTACHMENTS: Int = 32
    const val MAX_PACKAGE_BYTES: Int = 24 * 1024 * 1024

    fun validId(id: String): Boolean = id.length == 32 && id.any { it != '0' } && id.all { it in '0'..'9' || it in 'a'..'f' }

    fun validateName(name: String) {
        require(name.isNotBlank() && name != "." && name != "..") { "invalid attachment name" }
        require(name.none { it == '/' || it == '\\' || it == ':' || it.isISOControl() }) {
            "invalid attachment name"
        }
        require(name.encodeToByteArray(throwOnInvalidSequence = true).size <= MAX_NAME_BYTES) { "attachment name is too long" }
    }

    /** MIME comes from content, never from an extension or an untrusted provider. */
    fun validate(name: String, data: ByteArray): String {
        validateName(name)
        require(data.size <= MAX_FILE_BYTES) { "attachment is too large" }
        fun prefix(vararg bytes: Int): Boolean = data.size >= bytes.size &&
            bytes.indices.all { data[it].toInt() and 255 == bytes[it] }
        return when {
            prefix(0x89, 0x50, 0x4e, 0x47, 13, 10, 26, 10) -> "image/png"
            prefix(0xff, 0xd8, 0xff) -> "image/jpeg"
            prefix(71, 73, 70, 56, 55, 97) || prefix(71, 73, 70, 56, 57, 97) -> "image/gif"
            prefix(82, 73, 70, 70) && data.size >= 12 && data.copyOfRange(8, 12).decodeToString() == "WEBP" -> "image/webp"
            prefix(37, 80, 68, 70, 45) -> "application/pdf"
            else -> "application/octet-stream"
        }
    }

    internal fun validateList(attachments: List<NoteAttachment>) {
        require(attachments.size <= MAX_ATTACHMENTS) { "too many attachments" }
        require(attachments.map { it.id }.toSet().size == attachments.size) { "duplicate attachment identifier" }
        var total = 0L
        attachments.forEach {
            require(validId(it.id) && validId(it.storageId)) { "invalid attachment identifier" }
            validateName(it.name)
            require(it.sizeBytes in 0..MAX_FILE_BYTES) { "invalid attachment size" }
            require(it.mimeType in mimeTypes) { "invalid attachment MIME type" }
            total += it.sizeBytes
        }
        require(total <= MAX_TOTAL_BYTES) { "attachments are too large" }
    }

    private val mimeTypes = setOf("image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf", "application/octet-stream")
}

internal fun newAttachmentId(): String = Uuid.random().toString().replace("-", "")

data class NotePackage(val title: String, val body: String, val format: NoteFormat, val attachments: List<NotePackageAttachment>) {
    override fun toString(): String = "NotePackage(<redacted>)"
}

data class NotePackageAttachment(val id: String, val name: String, val mimeType: String, val data: ByteArray) {
    override fun toString(): String = "NotePackageAttachment(<redacted>)"
}

/** Bounded, source-preserving portable format. No paths, extraction, networking or executable HTML. */
object NotePackages {
    private val json = Json { encodeDefaults = true }

    fun encode(note: NotePackage): ByteArray {
        validate(note)
        val encoded = json.encodeToString(
            StoredPackage.serializer(),
            StoredPackage(version = 1, title = note.title, body = note.body, format = note.format, attachments = note.attachments.map {
                StoredAttachment(it.id, it.name, it.mimeType, Base64.encode(it.data))
            }),
        ).encodeToByteArray(throwOnInvalidSequence = true)
        require(encoded.size <= NoteAttachments.MAX_PACKAGE_BYTES) { "note package is too large" }
        return encoded
    }

    fun decode(bytes: ByteArray): NotePackage {
        require(bytes.size <= NoteAttachments.MAX_PACKAGE_BYTES) { "note package is too large" }
        val stored = json.decodeFromString(StoredPackage.serializer(), bytes.decodeToString(throwOnInvalidSequence = true))
        require(stored.version == 1) { "unsupported note package version" }
        require(stored.attachments.size <= NoteAttachments.MAX_ATTACHMENTS) { "too many attachments" }
        val attachments = mutableListOf<NotePackageAttachment>()
        try {
            stored.attachments.forEach {
                require(it.data.length <= ((NoteAttachments.MAX_FILE_BYTES + 2) / 3) * 4) { "attachment is too large" }
                val data = Base64.decode(it.data)
                // Take custody immediately, before canonical encoding and all metadata checks.
                attachments += NotePackageAttachment(it.id, it.name, it.mimeType, data)
                require(Base64.encode(data) == it.data) { "non-canonical attachment encoding" }
            }
            return NotePackage(stored.title, stored.body, stored.format, attachments).also(::validate)
        } catch (cause: Throwable) {
            attachments.forEach { it.data.fill(0) }
            throw cause
        }
    }

    private fun validate(note: NotePackage) {
        require('\u0000' !in note.title && '\u0000' !in note.body) { "notes cannot contain NUL" }
        require(note.title.encodeToByteArray(throwOnInvalidSequence = true).size <= 256) { "note title is too long" }
        require(note.body.encodeToByteArray(throwOnInvalidSequence = true).size <= 256 * 1024) { "note body is too long" }
        NoteAttachments.validateList(note.attachments.map {
            require(NoteAttachments.validate(it.name, it.data) == it.mimeType) { "attachment MIME type does not match content" }
            NoteAttachment(it.id, it.name, it.mimeType, it.data.size)
        })
    }
}

@Serializable
private data class StoredPackage(
    val version: Int,
    val title: String,
    val body: String,
    val format: NoteFormat,
    val attachments: List<StoredAttachment>,
)

@Serializable
private data class StoredAttachment(val id: String, val name: String, val mimeType: String, val data: String)
