package dev.po4yka.chur.ffi

import dev.po4yka.chur.core.model.ChurStatus

/**
 * The canonical boundary records of `docs/interop/FFI_CONTRACT.md` §6.4 and
 * §6.5.
 *
 * Every one is big-endian, which `docs/format/CANONICAL_ENCODING_V1.md` §3
 * fixes for every Chur integer, and every decoder rejects trailing bytes, which
 * the same section requires. These are boundary bytes rather than persisted
 * ones, so a truncated record is [ChurStatus.INVALID_INPUT] rather than a
 * corruption verdict.
 *
 * Nothing here is an encoder for a persisted record. §13 of that document
 * reserves that for Rust, and this file decodes what Rust produced.
 */

/** Length of the identifier of `CANONICAL_ENCODING_V1.md` §8. */
const val ID_LENGTH: Int = 16

/** Length of the page cursor of `CATALOG_SCHEMA_V1.md` §16.2. */
const val CURSOR_LENGTH: Int = 42

/** Length of `ObjectProjectionV1` of `CATALOG_SCHEMA_V1.md` §16.1. */
const val PROJECTION_LENGTH: Int = 79

/** Length of the `ChurPageV1` header of `FFI_CONTRACT.md` §6.4. */
const val PAGE_HEADER_LENGTH: Int = 63

/** Length of the device secret a slot operation hands back, §6.5. */
const val SECRET_LENGTH: Int = 32

/** The 96-bit GCM nonce of `KEY_SLOTS.md` §4. */
const val GCM_NONCE_LENGTH: Int = 12

/** A wrapped 32-byte key and its 16-byte tag. */
const val WRAPPED_KEY_LENGTH: Int = 48

/** Length of an Ed25519 or X25519 public key. */
const val PUBLIC_KEY_LENGTH: Int = 32

private const val SHARING_BUNDLE_BYTES_MAX: Long = 16L * 1024 * 1024
private const val SHARING_RECORDS_MAX: Int = 4_096
private const val SHARING_ISSUERS_MAX: Int = 257

/**
 * The largest recovery phrase, §6.5.
 *
 * Twenty-four words of the BIP-39 English list, whose longest entry is eight
 * characters, plus the separators.
 */
const val RECOVERY_PHRASE_MAX: Int = 24 * 9

/** One row of a library page, §16.1. */
data class ObjectProjection(
    val objectId: ByteArray,
    val primaryStreamId: ByteArray,
    val mediaKind: Int,
    val captureTimeMs: Long,
    val importTimeMs: Long,
    val captureTimeSubstituted: Boolean,
    val plaintextSize: Long,
    val width: Int,
    val height: Int,
    val durationMs: Long,
    val favorite: Boolean,
    val state: Int,
    val integritySummary: Int,
    val thumbnailReady: Boolean,
) {
    /** The identifier as lowercase hexadecimal, for a key in a list. */
    val id: String get() = objectId.toHex()

    override fun equals(other: Any?): Boolean = other is ObjectProjection && id == other.id

    override fun hashCode(): Int = id.hashCode()
}

/** One page of results, §16.2. */
data class ObjectPage(
    val objects: List<ObjectProjection>,
    val totalCount: Long,
    val catalogGeneration: Long,
    val nextCursor: ByteArray?,
) {
    override fun equals(other: Any?): Boolean =
        other is ObjectPage &&
            objects == other.objects &&
            totalCount == other.totalCount &&
            catalogGeneration == other.catalogGeneration

    override fun hashCode(): Int = objects.hashCode() * 31 + catalogGeneration.hashCode()
}

/** One album, §6.5. */
data class AlbumSummary(
    val albumId: ByteArray,
    val memberCount: Long,
    val name: String,
    val parentId: ByteArray? = null,
    val position: Long = 0,
) {
    val id: String get() = albumId.toHex()

    override fun equals(other: Any?): Boolean = other is AlbumSummary &&
        id == other.id && memberCount == other.memberCount && name == other.name &&
            parentId?.toHex() == other.parentId?.toHex() && position == other.position

    override fun hashCode(): Int =
        (((id.hashCode() * 31 + memberCount.hashCode()) * 31 + name.hashCode()) * 31 +
            (parentId?.toHex()?.hashCode() ?: 0)) * 31 + position.hashCode()
}

/** One private tag for the selection picker. */
data class TagSummary(val tagId: ByteArray, val name: String) {
    val id: String get() = tagId.toHex()

    override fun equals(other: Any?): Boolean = other is TagSummary && id == other.id && name == other.name

    override fun hashCode(): Int = id.hashCode() * 31 + name.hashCode()
}

/** One key slot, §6.5. */
data class SlotSummary(val slotId: ByteArray, val slotType: Int, val generation: Long) {
    val id: String get() = slotId.toHex()

    /** The family name `docs/security/KEY_SLOTS.md` §1 uses. */
    val familyName: String
        get() = when (slotType) {
            1 -> "Password"
            2 -> "Android Keystore"
            3 -> "Apple Keychain"
            4 -> "Recovery"
            5 -> "Peer device"
            else -> "Unknown"
        }

    /** Whether the family is portable, which §10 of that document fixes. */
    val portable: Boolean get() = slotType == 1 || slotType == 4

    override fun equals(other: Any?): Boolean = other is SlotSummary && id == other.id

    override fun hashCode(): Int = id.hashCode()
}

/** One object's detail record, §6.5. */
data class ObjectDetail(
    val captureTimeMs: Long,
    val importTimeMs: Long,
    val captureTimeSubstituted: Boolean,
    val width: Int,
    val height: Int,
    val durationMs: Long,
    val plaintextSize: Long,
    val contentType: String,
    val filename: String,
    val caption: String,
    val tags: List<Pair<ByteArray, String>>,
)

/** Public material needed to discover and address one sharing device. */
class SharingIdentity(
    val vaultId: ByteArray,
    val deviceId: ByteArray,
    val signingPublicKey: ByteArray,
    val hpkePublicKey: ByteArray,
    val fingerprint: String,
    val enrollment: ByteArray,
    val initialOperation: ByteArray,
)

/** The current default cryptographic collection and its known recipients. */
class SharingOverview(
    val collectionId: ByteArray,
    val members: List<SharingMember>,
)

/** One current or historical recipient device of the default collection. */
class SharingMember(
    val vaultId: ByteArray,
    val deviceId: ByteArray,
    val fingerprint: String,
    val permissions: SharingPermission,
    val active: Boolean,
    val verified: Boolean,
)

/** Identity authenticated from a self-signed initial enrollment. */
class SharingRecipient(
    val vaultId: ByteArray,
    val deviceId: ByteArray,
    val fingerprint: String,
)

/** One cumulative collection-sharing permission profile. */
enum class SharingPermission(val code: Int) {
    READ(0x01),
    CONTRIBUTE(0x03),
    MANAGE_MEMBERS(0x07),
}

/** Canonical records the sender uploads in dependency order. */
class PreparedShare(
    val membership: ByteArray,
    val membershipOperation: ByteArray,
    val grant: ByteArray,
    val grantOperation: ByteArray,
)

/** One current recipient grant and its authenticated outer operation. */
class PreparedGrant(
    val grant: ByteArray,
    val operation: ByteArray,
)

/** One bounded, resumable forward-only recipient revocation batch. */
class PreparedShareRevocation(
    val membership: ByteArray,
    val membershipOperation: ByteArray,
    val rotationOperations: List<ByteArray>,
    val grants: List<PreparedGrant>,
    val rotationComplete: Boolean,
)

/** Public identity evidence for one issuer of sharing records. */
class SharingIssuerEvidence(
    val membership: List<ByteArray>,
    val operations: List<ByteArray>,
)

/** One collection membership record and its authenticated outer operation. */
class SharingMembershipEvidence(
    val membership: ByteArray,
    val operation: ByteArray,
)

/** Relay evidence consumed atomically by `chur_sharing_accept`. */
class ShareAcceptance(
    val issuers: List<SharingIssuerEvidence>,
    val membership: List<SharingMembershipEvidence>,
    val grant: ByteArray,
    val grantOperation: ByteArray,
)

/** One source object with native-authored collection operations. */
class SharedSourceObject(
    val collectionId: ByteArray,
    val objectId: ByteArray,
    val storeId: ByteArray,
    val length: ULong,
    val fullSha256: ByteArray,
    val createOperation: ByteArray,
    val commitOperation: ByteArray,
)

/** One bounded committed ciphertext range from the source vault. */

/** Decodes a native source publication page without inspecting signed payloads. */
fun decodeSharedSourcePage(
    collectionId: ByteArray,
    bytes: ByteArray,
    length: Int,
): List<SharedSourceObject> {
    require(collectionId.size == ID_LENGTH) { "invalid collection ID" }
    val reader = RecordReader(bytes, length)
    if (reader.short() != 1) {
        throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "the source page version")
    }
    val count = reader.int()
    if (count !in 0..64) {
        throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "the source page count")
    }
    val objects = List(count) {
        val create = reader.bounded()
        val commit = reader.bounded()
        SharedSourceObject(
            collectionId, reader.take(ID_LENGTH), reader.take(ID_LENGTH), reader.long().toULong(),
            reader.take(32), create, commit,
        )
    }
    reader.requireExhausted()
    return objects
}

/** One signed shared object whose ciphertext is still absent locally. */
class SharedDownload(
    val objectId: ByteArray,
    val storeId: ByteArray,
    val length: ULong,
)

/** Native-verifier output for one collection-operation page. */
class SharedReceivePlan(
    val sourceVaultId: ByteArray,
    val collectionId: ByteArray,
    val selector: ByteArray,
    val pendingOperations: Int,
    val downloads: List<SharedDownload>,
)

/** Frames a bounded page without decoding or trusting its encrypted content. */
fun encodeSharedOperationPage(operations: List<ByteArray>): ByteArray {
    require(operations.size <= SHARING_RECORDS_MAX) { "too many shared operations" }
    val size = operations.fold(4L) { total, record -> total + 4 + record.size }
    require(size <= SHARING_BUNDLE_BYTES_MAX) { "shared operation page is too large" }
    val bytes = ByteArray(size.toInt())
    var at = 0
    fun putInt(value: Int) {
        bytes[at++] = (value ushr 24).toByte()
        bytes[at++] = (value ushr 16).toByte()
        bytes[at++] = (value ushr 8).toByte()
        bytes[at++] = value.toByte()
    }
    putInt(operations.size)
    operations.forEach { record ->
        putInt(record.size)
        record.copyInto(bytes, at)
        at += record.size
    }
    return bytes
}

/** Decodes only native-authenticated identifiers and lengths. */
fun decodeSharedReceivePlan(bytes: ByteArray, length: Int): SharedReceivePlan {
    val reader = RecordReader(bytes, length)
    if (reader.short() != 1) {
        throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "the shared plan version")
    }
    val sourceVaultId = reader.take(ID_LENGTH)
    val collectionId = reader.take(ID_LENGTH)
    val selector = reader.take(ID_LENGTH)
    val pending = reader.int()
    val count = reader.int()
    if (pending < 0 || count !in 0..SHARING_RECORDS_MAX) {
        throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "the shared plan count")
    }
    val downloads = List(count) {
        SharedDownload(reader.take(ID_LENGTH), reader.take(ID_LENGTH), reader.long().toULong())
    }
    reader.requireExhausted()
    return SharedReceivePlan(sourceVaultId, collectionId, selector, pending, downloads)
}

/** Encodes one opaque recipient identity-vault history for §6.13. */
fun encodeSharingIssuerEvidence(evidence: SharingIssuerEvidence): ByteArray {
    require(evidence.membership.size <= SHARING_RECORDS_MAX) { "too many issuer memberships" }
    require(evidence.operations.size <= SHARING_RECORDS_MAX) { "too many issuer operations" }
    val records = evidence.membership + evidence.operations
    val size = records.fold(2L + 8) { total, record -> total + 4 + record.size }
    require(size <= SHARING_BUNDLE_BYTES_MAX) { "recipient evidence is too large" }
    val bytes = ByteArray(size.toInt())
    var at = 0
    fun putShort(value: Int) {
        bytes[at++] = (value ushr 8).toByte()
        bytes[at++] = value.toByte()
    }
    fun putInt(value: Int) {
        bytes[at++] = (value ushr 24).toByte()
        bytes[at++] = (value ushr 16).toByte()
        bytes[at++] = (value ushr 8).toByte()
        bytes[at++] = value.toByte()
    }
    fun putRecord(record: ByteArray) {
        putInt(record.size)
        record.copyInto(bytes, at)
        at += record.size
    }
    putShort(1)
    putInt(evidence.membership.size)
    evidence.membership.forEach(::putRecord)
    putInt(evidence.operations.size)
    evidence.operations.forEach(::putRecord)
    return bytes
}

/** One device position that native signature and sequence checks accepted. */
data class SyncDeviceHead(val deviceId: ByteArray, val sequence: ULong)

class DevicePairingRequest(val request: ByteArray, val fingerprint: String)

class DevicePairingPreview(val vaultId: ByteArray, val deviceId: ByteArray, val fingerprint: String)

class PreparedDevicePairing(
    val checkpoint: ByteArray,
    val enrollment: ByteArray,
    val operation: ByteArray,
    val approval: ByteArray,
)

class DevicePairingCredentials(
    val vaultId: ByteArray,
    val deviceId: ByteArray,
    val enrollment: ByteArray,
    val checkpoint: ByteArray,
)

class PairedDevice(
    val deviceId: ByteArray,
    val fingerprint: String,
    val active: Boolean,
    val current: Boolean,
    val retryAvailable: Boolean = false,
)

class PreparedDeviceRevocation(val checkpoint: ByteArray, val revocation: ByteArray, val operation: ByteArray)

fun decodePairedDevices(bytes: ByteArray): List<PairedDevice> {
    val reader = versionedRecordReader(bytes, 2)
    val count = reader.int()
    if (count !in 0..4_096) throw ChurFailure(ChurStatus.RESOURCE_LIMIT_EXCEEDED, "the paired device count")
    val result = List(count) { PairedDevice(reader.take(ID_LENGTH), reader.bounded().decodeToString(), reader.flag(), reader.flag(), reader.flag()) }
    reader.requireExhausted()
    return result
}

fun decodePreparedDeviceRevocation(bytes: ByteArray): PreparedDeviceRevocation {
    val reader = versionedRecordReader(bytes, 2)
    val result = PreparedDeviceRevocation(reader.bounded(), reader.bounded(), reader.bounded())
    reader.requireExhausted()
    return result
}

fun decodeDevicePairingRequest(bytes: ByteArray): DevicePairingRequest {
    val reader = versionedRecordReader(bytes, 2)
    val result = DevicePairingRequest(reader.bounded(), reader.bounded().decodeToString())
    reader.requireExhausted()
    return result
}

fun decodeDevicePairingPreview(bytes: ByteArray): DevicePairingPreview {
    val reader = versionedRecordReader(bytes, 2)
    val result = DevicePairingPreview(reader.take(ID_LENGTH), reader.take(ID_LENGTH), reader.bounded().decodeToString())
    reader.requireExhausted()
    return result
}

fun decodePreparedDevicePairing(bytes: ByteArray): PreparedDevicePairing {
    val reader = versionedRecordReader(bytes, 2)
    val result = PreparedDevicePairing(reader.bounded(), reader.bounded(), reader.bounded(), reader.bounded())
    reader.requireExhausted()
    return result
}

fun decodeDevicePairingCredentials(bytes: ByteArray): DevicePairingCredentials {
    val reader = versionedRecordReader(bytes, 2)
    val result = DevicePairingCredentials(
        reader.take(ID_LENGTH), reader.take(ID_LENGTH), reader.bounded(), reader.bounded(),
    )
    reader.requireExhausted()
    return result
}

fun decodeFinishedDevicePairing(bytes: ByteArray): ByteArray {
    val reader = versionedRecordReader(bytes, 2)
    val result = reader.take(ID_LENGTH)
    reader.requireExhausted()
    return result
}

fun decodeOwnSyncCollections(bytes: ByteArray): List<ByteArray> {
    val reader = versionedRecordReader(bytes, 1)
    val count = reader.int()
    if (count !in 0..4_096) throw ChurFailure(ChurStatus.RESOURCE_LIMIT_EXCEEDED, "the own collection count")
    val result = List(count) { reader.take(ID_LENGTH) }
    reader.requireExhausted()
    return result
}

class OwnSyncOperation(val sequence: ULong, val record: ByteArray)

fun decodeOwnSyncOperations(bytes: ByteArray): List<OwnSyncOperation> {
    val reader = versionedRecordReader(bytes, 1)
    val count = reader.int()
    if (count !in 0..4_096) throw ChurFailure(ChurStatus.RESOURCE_LIMIT_EXCEEDED, "the own operation count")
    val result = List(count) { OwnSyncOperation(reader.long().toULong(), reader.bounded()) }
    reader.requireExhausted()
    return result
}

private fun versionedRecordReader(bytes: ByteArray, version: Int): RecordReader {
    val reader = RecordReader(bytes, bytes.size)
    if (reader.short() != version) throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "the native control record version")
    return reader
}

fun encodeDevicePairingApproval(request: ByteArray, nowMs: Long): ByteArray {
    require(request.size <= 16_384 && nowMs >= 0)
    val encoded = ByteArray(2 + 4 + request.size + 8)
    var offset = 0
    fun unsigned(value: ULong, bytes: Int) {
        repeat(bytes) { index -> encoded[offset++] = (value shr ((bytes - index - 1) * 8)).toByte() }
    }
    fun record(value: ByteArray) {
        unsigned(value.size.toULong(), 4)
        value.copyInto(encoded, offset)
        offset += value.size
    }
    unsigned(2uL, 2)
    record(request)
    unsigned(nowMs.toULong(), 8)
    return encoded
}

fun encodeDevicePairingTime(nowMs: Long): ByteArray {
    require(nowMs >= 0)
    return ByteArray(8) { index -> (nowMs.toULong() shr ((7 - index) * 8)).toByte() }
}

fun decodeSyncHeads(bytes: ByteArray, length: Int): List<SyncDeviceHead> {
    val reader = RecordReader(bytes, length)
    if (reader.short() != 1) throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "the sync head version")
    val count = reader.int()
    if (count !in 0..32) throw ChurFailure(ChurStatus.RESOURCE_LIMIT_EXCEEDED, "the sync head count")
    val heads = List(count) { SyncDeviceHead(reader.take(ID_LENGTH), reader.long().toULong()) }
    reader.requireExhausted()
    return heads
}

/** Decodes the collection-sharing identity record of §6.9. */
fun decodeSharingIdentity(bytes: ByteArray, length: Int): SharingIdentity {
    val reader = RecordReader(bytes, length)
    if (reader.short() != 1) {
        throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "the sharing identity version")
    }
    val identity = SharingIdentity(
        vaultId = reader.take(ID_LENGTH),
        deviceId = reader.take(ID_LENGTH),
        signingPublicKey = reader.take(PUBLIC_KEY_LENGTH),
        hpkePublicKey = reader.take(PUBLIC_KEY_LENGTH),
        fingerprint = reader.bounded().decodeToString(),
        enrollment = reader.bounded(),
        initialOperation = reader.bounded(),
    )
    reader.requireExhausted()
    return identity
}

/** Decodes the active default-collection members of §6.14. */
fun decodeSharingOverview(bytes: ByteArray, length: Int): SharingOverview {
    val reader = RecordReader(bytes, length)
    if (reader.short() != 1) {
        throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "the sharing overview version")
    }
    val collectionId = reader.take(ID_LENGTH)
    val count = reader.int()
    if (count !in 0..SHARING_RECORDS_MAX) {
        throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "the sharing member count")
    }
    val members = List(count) {
        val vaultId = reader.take(ID_LENGTH)
        val deviceId = reader.take(ID_LENGTH)
        val permissionCode = reader.byte()
        val permission = SharingPermission.entries.firstOrNull { it.code == permissionCode }
            ?: throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "the sharing permission")
        val active = reader.flag()
        val verified = reader.flag()
        val fingerprint = reader.bounded().decodeToString()
        SharingMember(vaultId, deviceId, fingerprint, permission, active, verified)
    }
    reader.requireExhausted()
    return SharingOverview(collectionId, members)
}

/** Decodes an authenticated initial enrollment preview of §6.14. */
fun decodeSharingRecipient(bytes: ByteArray, length: Int): SharingRecipient {
    val reader = RecordReader(bytes, length)
    if (reader.short() != 1) {
        throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "the sharing recipient version")
    }
    val recipient = SharingRecipient(reader.take(ID_LENGTH), reader.take(ID_LENGTH),
        reader.bounded().decodeToString())
    reader.requireExhausted()
    return recipient
}

/** Decodes the prepared share record of §6.10. */
fun decodePreparedShare(bytes: ByteArray, length: Int): PreparedShare {
    val reader = RecordReader(bytes, length)
    if (reader.short() != 1) {
        throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "the prepared share version")
    }
    val share = PreparedShare(
        membership = reader.bounded(),
        membershipOperation = reader.bounded(),
        grant = reader.bounded(),
        grantOperation = reader.bounded(),
    )
    reader.requireExhausted()
    return share
}

/** Decodes the prepared recipient revocation record of §6.12. */
fun decodePreparedShareRevocation(bytes: ByteArray, length: Int): PreparedShareRevocation {
    val reader = RecordReader(bytes, length)
    if (reader.short() != 1) {
        throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "the prepared revocation version")
    }
    val membership = reader.bounded()
    val membershipOperation = reader.bounded()
    val rotationCount = reader.int()
    if (rotationCount !in 0..SHARING_RECORDS_MAX) {
        throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "the rotation operation count")
    }
    val rotationOperations = List(rotationCount) { reader.bounded() }
    val grantCount = reader.int()
    if (grantCount !in 0..SHARING_RECORDS_MAX) {
        throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "the current grant count")
    }
    val grants = List(grantCount) { PreparedGrant(reader.bounded(), reader.bounded()) }
    val record = PreparedShareRevocation(
        membership = membership,
        membershipOperation = membershipOperation,
        rotationOperations = rotationOperations,
        grants = grants,
        rotationComplete = reader.flag(),
    )
    reader.requireExhausted()
    return record
}

/** Encodes the bounded share acceptance bundle of §6.11. */
fun encodeShareAcceptance(share: ShareAcceptance): ByteArray {
    require(share.issuers.size <= SHARING_ISSUERS_MAX) { "too many sharing issuers" }
    require(share.membership.size <= SHARING_RECORDS_MAX) { "too many membership records" }
    share.issuers.forEach { issuer ->
        require(issuer.membership.size <= SHARING_RECORDS_MAX) { "too many issuer memberships" }
        require(issuer.operations.size <= SHARING_RECORDS_MAX) { "too many issuer operations" }
    }
    val records = buildList {
        share.issuers.forEach { issuer ->
            addAll(issuer.membership)
            addAll(issuer.operations)
        }
        share.membership.forEach { evidence ->
            add(evidence.membership)
            add(evidence.operation)
        }
        add(share.grant)
        add(share.grantOperation)
    }
    val size = records.fold(2L + 4 + 4 + (share.issuers.size * 8L)) { total, record ->
        total + 4 + record.size
    }
    require(size <= SHARING_BUNDLE_BYTES_MAX) { "sharing acceptance bundle is too large" }
    val bytes = ByteArray(size.toInt())
    var at = 0
    fun putShort(value: Int) {
        bytes[at++] = (value ushr 8).toByte()
        bytes[at++] = value.toByte()
    }
    fun putInt(value: Int) {
        bytes[at++] = (value ushr 24).toByte()
        bytes[at++] = (value ushr 16).toByte()
        bytes[at++] = (value ushr 8).toByte()
        bytes[at++] = value.toByte()
    }
    fun putRecord(record: ByteArray) {
        putInt(record.size)
        record.copyInto(bytes, at)
        at += record.size
    }
    putShort(1)
    putInt(share.issuers.size)
    share.issuers.forEach { issuer ->
        putInt(issuer.membership.size)
        issuer.membership.forEach(::putRecord)
        putInt(issuer.operations.size)
        issuer.operations.forEach(::putRecord)
    }
    putInt(share.membership.size)
    share.membership.forEach { evidence ->
        putRecord(evidence.membership)
        putRecord(evidence.operation)
    }
    putRecord(share.grant)
    putRecord(share.grantOperation)
    return bytes
}

/** Decodes `ChurPageV1`, §6.4. */
fun decodeObjectPage(bytes: ByteArray, length: Int): ObjectPage {
    val reader = RecordReader(bytes, length)
    val total = reader.long()
    val generation = reader.long()
    val count = reader.int()
    val cursorPresent = reader.byte()
    val cursor = reader.take(CURSOR_LENGTH)
    if (cursorPresent != 0 && cursorPresent != 1) {
        throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "the cursor presence byte")
    }
    val objects = ArrayList<ObjectProjection>(count)
    repeat(count) { objects.add(decodeProjection(reader.take(PROJECTION_LENGTH))) }
    reader.requireExhausted()
    return ObjectPage(objects, total, generation, if (cursorPresent == 1) cursor else null)
}

/** Decodes one `ObjectProjectionV1`, §16.1. */
fun decodeProjection(bytes: ByteArray): ObjectProjection {
    val reader = RecordReader(bytes, bytes.size)
    val projection = ObjectProjection(
        objectId = reader.take(ID_LENGTH),
        primaryStreamId = reader.take(ID_LENGTH),
        mediaKind = reader.short(),
        captureTimeMs = reader.long(),
        importTimeMs = reader.long(),
        captureTimeSubstituted = reader.flag(),
        plaintextSize = reader.long(),
        width = reader.int(),
        height = reader.int(),
        durationMs = reader.long(),
        favorite = reader.flag(),
        state = reader.byte(),
        integritySummary = reader.byte(),
        thumbnailReady = reader.flag(),
    )
    reader.requireExhausted()
    return projection
}

/** Decodes `ChurAlbumListV2`, §6.19. */
fun decodeAlbumList(bytes: ByteArray, length: Int): List<AlbumSummary> {
    val reader = RecordReader(bytes, length)
    val count = reader.int()
    val albums = ArrayList<AlbumSummary>(count)
    repeat(count) {
        val id = reader.take(ID_LENGTH)
        val members = reader.long()
        val name = reader.text()
        val parent = reader.take(ID_LENGTH).takeUnless { bytes -> bytes.all { it == 0.toByte() } }
        albums.add(AlbumSummary(id, members, name, parent, reader.long()))
    }
    reader.requireExhausted()
    return albums
}

/** Decodes the bounded private tag list. */
fun decodeTagList(bytes: ByteArray, length: Int): List<TagSummary> {
    val reader = RecordReader(bytes, length)
    val count = reader.int()
    val tags = ArrayList<TagSummary>(count)
    repeat(count) {
        tags.add(TagSummary(reader.take(ID_LENGTH), reader.text()))
    }
    reader.requireExhausted()
    return tags
}

/** Decodes `ChurSlotListV1`, §6.5. */
fun decodeSlotList(bytes: ByteArray, length: Int): List<SlotSummary> {
    val reader = RecordReader(bytes, length)
    val count = reader.int()
    val slots = ArrayList<SlotSummary>(count)
    repeat(count) {
        slots.add(SlotSummary(reader.take(ID_LENGTH), reader.byte(), reader.long()))
    }
    reader.requireExhausted()
    return slots
}

/**
 * What the Android Keystore needs to wrap the root, §6.6.
 *
 * [rootSecret] is the vault root. `KEY_SLOTS.md` §4 puts the AEAD in the
 * Keystore, so the bytes have to reach it; ADR-0041 records the exception and
 * requires the holder to clear the array as soon as the wrap returns.
 */
class KeystoreEnrollment(
    val alias: ByteArray,
    val aad: ByteArray,
    val rootSecret: ByteArray,
)

/** What the Android Keystore needs to unwrap the root, §6.6. Nothing is secret. */
data class KeystoreMaterial(
    val alias: ByteArray,
    val aad: ByteArray,
    val gcmNonce: ByteArray,
    val wrappedRootSecret: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is KeystoreMaterial &&
            alias.contentEquals(other.alias) &&
            aad.contentEquals(other.aad) &&
            gcmNonce.contentEquals(other.gcmNonce) &&
            wrappedRootSecret.contentEquals(other.wrappedRootSecret)

    override fun hashCode(): Int = alias.contentHashCode()
}

/** Decodes the enrollment record of §6.6. */
fun decodeKeystoreEnrollment(bytes: ByteArray, length: Int): KeystoreEnrollment {
    val reader = RecordReader(bytes, length)
    val enrollment = KeystoreEnrollment(
        alias = reader.bounded(),
        aad = reader.bounded(),
        rootSecret = reader.take(SECRET_LENGTH),
    )
    reader.requireExhausted()
    return enrollment
}

/** Decodes the material record of §6.6. */
fun decodeKeystoreMaterial(bytes: ByteArray, length: Int): List<KeystoreMaterial> {
    val reader = RecordReader(bytes, length)
    val count = reader.int()
    val material = ArrayList<KeystoreMaterial>(count)
    repeat(count) {
        material.add(
            KeystoreMaterial(
                alias = reader.bounded(),
                aad = reader.bounded(),
                gcmNonce = reader.take(GCM_NONCE_LENGTH),
                wrappedRootSecret = reader.take(WRAPPED_KEY_LENGTH),
            ),
        )
    }
    reader.requireExhausted()
    return material
}

/** Decodes `ChurObjectMetadataV1`, §6.5. */
fun decodeObjectDetail(bytes: ByteArray, length: Int): ObjectDetail {
    val reader = RecordReader(bytes, length)
    val detail = ObjectDetail(
        captureTimeMs = reader.long(),
        importTimeMs = reader.long(),
        captureTimeSubstituted = reader.flag(),
        width = reader.int(),
        height = reader.int(),
        durationMs = reader.long(),
        plaintextSize = reader.long(),
        contentType = reader.text(),
        filename = reader.text(),
        caption = reader.text(),
        tags = buildList {
            repeat(reader.short()) { add(reader.take(ID_LENGTH) to reader.text()) }
        },
    )
    reader.requireExhausted()
    return detail
}

/** Lowercase hexadecimal, which is how every identifier is shown and keyed. */
fun ByteArray.toHex(): String {
    val digits = "0123456789abcdef"
    val out = StringBuilder(size * 2)
    for (byte in this) {
        val value = byte.toInt() and 0xff
        out.append(digits[value ushr 4])
        out.append(digits[value and 0x0f])
    }
    return out.toString()
}

/** Parses 32 lowercase hexadecimal characters into an identifier. */
fun String.fromHex(): ByteArray {
    require(length % 2 == 0) { "a hexadecimal string has an even length" }
    return ByteArray(length / 2) { index ->
        val high = digitOf(this[index * 2])
        val low = digitOf(this[index * 2 + 1])
        ((high shl 4) or low).toByte()
    }
}

private fun digitOf(character: Char): Int = when (character) {
    in '0'..'9' -> character - '0'
    in 'a'..'f' -> character - 'a' + 10
    in 'A'..'F' -> character - 'A' + 10
    else -> throw IllegalArgumentException("not a hexadecimal digit")
}

/**
 * A big-endian reader over a boundary record.
 *
 * It fails with [ChurFailure] rather than an index exception, so a truncated
 * record reaches the caller as the status the boundary would have used.
 */
private class RecordReader(private val bytes: ByteArray, private val limit: Int) {
    private var at = 0

    fun take(length: Int): ByteArray {
        require(length)
        val slice = bytes.copyOfRange(at, at + length)
        at += length
        return slice
    }

    fun byte(): Int {
        require(1)
        return bytes[at++].toInt() and 0xff
    }

    fun flag(): Boolean = when (val value = byte()) {
        0 -> false
        1 -> true
        else -> throw ChurFailure(
            ChurStatus.NON_CANONICAL_ENCODING,
            "a boolean is neither 0x00 nor 0x01 but $value",
        )
    }

    fun short(): Int {
        require(2)
        var value = 0
        repeat(2) { value = (value shl 8) or (bytes[at++].toInt() and 0xff) }
        return value
    }

    fun int(): Int {
        require(4)
        var value = 0
        repeat(4) { value = (value shl 8) or (bytes[at++].toInt() and 0xff) }
        return value
    }

    fun long(): Long {
        require(8)
        var value = 0L
        repeat(8) { value = (value shl 8) or (bytes[at++].toLong() and 0xff) }
        return value
    }

    fun text(): String {
        val length = short()
        return take(length).decodeToString()
    }

    /** A `u32` length and the bytes it counts. */
    fun bounded(): ByteArray = take(int())

    fun requireExhausted() {
        if (at != limit) {
            throw ChurFailure(
                ChurStatus.NON_CANONICAL_ENCODING,
                "the record carries trailing bytes",
            )
        }
    }

    private fun require(length: Int) {
        if (at + length > limit) {
            throw ChurFailure(ChurStatus.INVALID_INPUT, "the record ends inside a field")
        }
    }
}

/** One verified durable local collection-operation publication. */
class CollectionOutbound(val cursor: ULong, val collectionId: ByteArray, val record: ByteArray)

fun decodeCollectionOutbound(bytes: ByteArray, length: Int): List<CollectionOutbound> {
    val reader = RecordReader(bytes, length)
    require(reader.short() == 1) { "unsupported collection outbox version" }
    val count = reader.int()
    require(count in 0..64) { "invalid collection outbox count" }
    val records = List(count) {
        val cursor = reader.long()
        require(cursor > 0) { "invalid collection outbox cursor" }
        CollectionOutbound(cursor.toULong(), reader.take(16), reader.bounded())
    }
    reader.requireExhausted()
    return records
}
