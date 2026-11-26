package dev.po4yka.chur.ffi

import dev.po4yka.chur.core.model.ChurStatus

/**
 * The vault as a feature calls it.
 *
 * [ChurNative] is the C ABI transliterated; this is the half with Kotlin types,
 * exceptions instead of status codes, and out-parameters turned into return
 * values. Everything below is a thin composition over one export, so a reader
 * comparing this file with `docs/interop/FFI_CONTRACT.md` §6.2 and §6.5 sees
 * the same list.
 *
 * Nothing here is private state. A handle is an opaque `Long` the registry of
 * §3 owns, and this file holds no secret between calls: a recovery secret is
 * returned to the caller that asked for it and never kept.
 *
 * Calls block. §8 makes every native call synchronous, and the caller wraps
 * them on an I/O dispatcher.
 */
object ChurVault {
    // -----------------------------------------------------------------------
    // Handshake, §2
    // -----------------------------------------------------------------------

    /** The ABI the loaded library answers. */
    fun handshake(): NativeHandshake =
        NativeHandshake(
            major = ChurNative.abiVersionMajor(),
            minor = ChurNative.abiVersionMinor(),
            capabilities = ChurNative.capabilities(),
            objectFormatMin = ChurNative.objectFormatMin(),
            objectFormatMax = ChurNative.objectFormatMax(),
            keySlotFormatMin = ChurNative.keySlotFormatMin(),
            keySlotFormatMax = ChurNative.keySlotFormatMax(),
            buildFlavor = ChurNative.buildFlavor(),
        )

    /** Whether a status value is one this build allocates. */
    fun statusIsKnown(value: Int): Boolean = ChurNative.statusIsKnown(value)

    // -----------------------------------------------------------------------
    // Runtime and session
    // -----------------------------------------------------------------------

    /** Opens the one runtime of §14 over a storage root. */
    fun openRuntime(root: String): Long =
        handleOf("runtime open") { out ->
            ChurNative.runtimeOpen(root, out)
        }

    /** Closes the runtime and every handle it owns. */
    fun closeRuntime(runtime: Long) {
        ChurFailure.check(ChurNative.runtimeClose(runtime), "runtime close")
    }

    /** Whether the storage root holds a vault, `PROVISIONING.md` §2. */
    fun vaultPresent(runtime: Long): Boolean {
        val out = ByteArray(1)
        ChurFailure.check(ChurNative.vaultPresent(runtime, out), "vault present")
        return out[0].toInt() == 1
    }

    /** Begins vault creation, `PROVISIONING.md` §3 steps 3 and 4. */
    fun beginCreation(
        runtime: Long,
        password: ByteArray,
    ): Long =
        handleOf("vault create") { out ->
            ChurNative.vaultCreateBegin(runtime, password, 0, 0, 0, out)
        }

    /**
     * Offers the recovery slot, step 5, and returns the phrase.
     *
     * The phrase is the caller's to present and clear. `RECOVERY.md` §2 shows
     * it exactly once, and nothing here keeps a copy: a user who loses it
     * rotates the slot under §8 there rather than asking for it again.
     */
    fun creationAddRecoverySlot(creation: Long): String =
        phraseOf("creation recovery slot") { buffer, written ->
            ChurNative.vaultCreationAddRecoverySlot(creation, buffer, written)
        }

    /** Reaches `ACTIVE` and opens the session, step 6. */
    fun activateCreation(creation: Long): Long =
        handleOf("vault activate") { out ->
            ChurNative.vaultCreationActivate(creation, out)
        }

    /** Abandons a creation, leaving nothing openable. */
    fun abandonCreation(creation: Long) {
        ChurFailure.check(ChurNative.vaultCreationAbandon(creation), "vault abandon")
    }

    /** Unlocks with a password, `KEY_SLOTS.md` §8. */
    fun unlockWithPassword(
        runtime: Long,
        password: ByteArray,
    ): Long = handleOf("unlock") { out -> ChurNative.vaultUnlock(runtime, FACTOR_PASSWORD, password, out) }

    /**
     * Unlocks with a recovery phrase, as UTF-8 bytes.
     *
     * The phrase arrives as bytes so the caller can zero them after the call,
     * which a `String` does not allow.
     */
    fun unlockWithRecovery(
        runtime: Long,
        phrase: ByteArray,
    ): Long =
        handleOf("recover") { out ->
            ChurNative.vaultUnlock(runtime, FACTOR_RECOVERY, phrase, out)
        }

    /** Unlocks with a `DeviceUnlockSecret` the platform keystore returned. */
    fun unlockWithDeviceSecret(
        runtime: Long,
        secret: ByteArray,
    ): Long =
        handleOf("device unlock") { out ->
            ChurNative.vaultUnlock(runtime, FACTOR_DEVICE, secret, out)
        }

    /** Locks a session, `PLAINTEXT_LIFECYCLE.md` §8. */
    fun lock(
        session: Long,
        reason: LockReason,
    ) {
        ChurFailure.check(ChurNative.vaultLock(session, reason.code), "lock")
    }

    /** Closes a session handle. */
    fun closeSession(session: Long) {
        ChurFailure.check(ChurNative.sessionClose(session), "session close")
    }

    /** Provisions or returns this device's public collection-sharing identity. */
    fun sharingIdentity(session: Long): SharingIdentity =
        withChurBuffer(SHARING_IDENTITY_CAPACITY) { buffer ->
            val written = IntArray(1)
            ChurFailure.check(
                ChurNative.sharingIdentity(session, buffer, written),
                "sharing identity",
            )
            decodeSharingIdentity(buffer.copyOut(written[0]), written[0])
        }

    /** Returns the default collection and its current active recipients. */
    fun sharingOverview(session: Long): SharingOverview =
        withChurBuffer(SHARING_OVERVIEW_CAPACITY) { buffer ->
            val written = IntArray(1)
            ChurFailure.check(ChurNative.sharingOverview(session, buffer, written), "sharing overview")
            decodeSharingOverview(buffer.copyOut(written[0]), written[0])
        }

    /** Authenticates and previews a recipient's self-signed initial enrollment. */
    fun inspectEnrollment(enrollment: ByteArray): SharingRecipient =
        withChurBuffer(SHARING_RECIPIENT_CAPACITY) { buffer ->
            val written = IntArray(1)
            ChurFailure.check(
                ChurNative.sharingInspectEnrollment(enrollment, buffer, written),
                "sharing enrollment inspection",
            )
            decodeSharingRecipient(buffer.copyOut(written[0]), written[0])
        }

    /** Prepares the membership and HPKE grant for one recipient device. */
    fun prepareShare(
        session: Long,
        collectionId: ByteArray,
        recipientEnrollment: ByteArray,
        permissions: SharingPermission,
        fingerprintVerified: Boolean,
    ): PreparedShare =
        withChurBuffer(PREPARED_SHARE_CAPACITY) { buffer ->
            val written = IntArray(1)
            ChurFailure.check(
                ChurNative.sharingPrepare(
                    session,
                    collectionId,
                    recipientEnrollment,
                    permissions.code,
                    fingerprintVerified,
                    buffer,
                    written,
                ),
                "sharing prepare",
            )
            decodePreparedShare(buffer.copyOut(written[0]), written[0])
        }

    /** Prepares a grant for one device in an authenticated recipient vault. */
    fun prepareShareForDevice(
        session: Long,
        collectionId: ByteArray,
        recipient: SharingIssuerEvidence,
        recipientDeviceId: ByteArray,
        permissions: SharingPermission,
        fingerprintVerified: Boolean,
    ): PreparedShare {
        val evidence = encodeSharingIssuerEvidence(recipient)
        return withChurBuffer(evidence.size) { evidenceBuffer ->
            evidenceBuffer.copyIn(evidence)
            withChurBuffer(PREPARED_SHARE_CAPACITY) { destination ->
                val written = IntArray(1)
                ChurFailure.check(
                    ChurNative.sharingPrepareDevice(
                        session,
                        collectionId,
                        evidenceBuffer,
                        evidence.size,
                        recipientDeviceId,
                        permissions.code,
                        fingerprintVerified,
                        destination,
                        written,
                    ),
                    "sharing prepare device",
                )
                decodePreparedShare(destination.copyOut(written[0]), written[0])
            }
        }
    }

    /** Authenticates relay evidence and atomically installs one recipient share. */
    fun acceptShare(
        session: Long,
        share: ShareAcceptance,
    ) = acceptSharePackage(session, encodeShareAcceptance(share))

    /** Passes one complete opaque relay package to the native sharing verifier. */
    fun acceptSharePackage(
        session: Long,
        packageBytes: ByteArray,
    ) {
        withChurBuffer(packageBytes.size) { buffer ->
            buffer.copyIn(packageBytes)
            ChurFailure.check(
                ChurNative.sharingAccept(session, buffer, packageBytes.size),
                "sharing accept",
            )
        }
    }

    /** Returns one ordered page of active source objects and stable signed records. */
    fun sharedSourcePage(
        session: Long,
        collectionId: ByteArray,
        afterObjectId: ByteArray = ByteArray(16),
    ): List<SharedSourceObject> {
        require(collectionId.size == 16 && afterObjectId.size == 16) { "invalid source page ID" }
        return withChurBuffer(8 * 1024) { output ->
            val written = IntArray(1)
            ChurFailure.check(
                ChurNative.sharingPublication(session, collectionId, afterObjectId, output, written),
                "sharing publication",
            )
            decodeSharedSourcePage(collectionId, output.copyOut(written[0]), written[0])
        }
    }

    /** Authors one object's stable operations after its ciphertext is uploaded. */
    fun sharedSourceAuthor(session: Long, source: SharedSourceObject): SharedSourceObject {
        require(source.collectionId.size == 16 && source.objectId.size == 16 && source.storeId.size == 16)
        require(source.length <= Long.MAX_VALUE.toULong() && source.fullSha256.size == 32)
        return withChurBuffer(1024 * 1024) { output ->
            val written = IntArray(1)
            ChurFailure.check(
                ChurNative.sharingAuthor(
                    session, source.collectionId, source.objectId, source.storeId,
                    source.length.toLong(), source.fullSha256, output, written,
                ),
                "sharing author",
            )
            val authored = decodeSharedSourcePage(source.collectionId, output.copyOut(written[0]), written[0]).single()
            require(
                authored.objectId.contentEquals(source.objectId) &&
                    authored.storeId.contentEquals(source.storeId) &&
                    authored.length == source.length &&
                    authored.fullSha256.contentEquals(source.fullSha256) &&
                    authored.createOperation.isNotEmpty() && authored.commitOperation.isNotEmpty(),
            ) { "source object changed before operation publication" }
            authored
        }
    }

    /** Returns null if the object key is ready, otherwise its signed one-use request. */
    fun objectKeyRequest(session: Long, collectionId: ByteArray, objectId: ByteArray): ByteArray? {
        require(collectionId.size == 16 && objectId.size == 16)
        val result = objectKeyCall(session, collectionId + objectId, ChurNative::objectKeyRequest)
        require(result.isNotEmpty() && (result[0] == 0.toByte() || result[0] == 1.toByte()))
        if (result[0] == 0.toByte()) { require(result.size == 1); return null }
        require(result.size == 1 + OBJECT_PREKEY_LENGTH)
        return result.copyOfRange(1, result.size)
    }


    fun objectKeyAccept(session: Long, packageBytes: ByteArray, grant: ByteArray) {
        require(packageBytes.size <= SHARING_BUNDLE_CAPACITY - OBJECT_GRANT_LENGTH - 8 && grant.size == OBJECT_GRANT_LENGTH)
        fun length(value: Int) = byteArrayOf((value ushr 24).toByte(), (value ushr 16).toByte(),
            (value ushr 8).toByte(), value.toByte())
        objectKeyCall(session, length(packageBytes.size) + packageBytes + length(grant.size) + grant,
            ChurNative::objectKeyAccept)
    }

    private fun objectKeyCall(
        session: Long, bytes: ByteArray,
        call: (Long, ChurBuffer, Int, ChurBuffer, IntArray) -> Int,
    ): ByteArray = withChurBuffer(bytes.size) { input ->
        input.copyIn(bytes)
        withChurBuffer(maxOf(1 + OBJECT_PREKEY_LENGTH, OBJECT_GRANT_LENGTH)) { output ->
            val written = IntArray(1)
            ChurFailure.check(call(session, input, bytes.size, output, written), "object key delivery")
            output.copyOut(written[0])
        }
    }

    fun outboundCollectionOperations(session: Long, after: ULong): List<CollectionOutbound> {
        require(after <= Long.MAX_VALUE.toULong())
        return withChurBuffer(16 * 1024 * 1024) { output ->
            val written = IntArray(1)
            ChurFailure.check(ChurNative.sharingOutbound(session, after.toLong(), output, written), "collection outbox")
            decodeCollectionOutbound(output.copyOut(written[0]), written[0])
        }
    }

    /** Authenticates one collection-operation page and returns missing objects. */
    fun receiveSharedOperations(
        session: Long,
        packageBytes: ByteArray,
        operations: List<ByteArray>,
    ): SharedReceivePlan {
        val page = encodeSharedOperationPage(operations)
        return withChurBuffer(packageBytes.size) { bundle ->
            bundle.copyIn(packageBytes)
            withChurBuffer(page.size) { records ->
                records.copyIn(page)
                withChurBuffer(256 * 1024) { output ->
                    val written = IntArray(1)
                    ChurFailure.check(
                        ChurNative.sharingReceive(
                            session, bundle, packageBytes.size, records, page.size,
                            output, written,
                        ),
                        "sharing receive",
                    )
                    decodeSharedReceivePlan(output.copyOut(written[0]), written[0])
                }
            }
        }
    }

    /** Returns the durable ciphertext prefix for a signed shared object. */
    fun sharedDownloadOffset(session: Long, collectionId: ByteArray, objectId: ByteArray): ULong {
        require(collectionId.size == 16 && objectId.size == 16) { "invalid shared download ID" }
        requireCurrentAbi()
        val out = LongArray(1)
        ChurFailure.check(
            ChurNative.sharingDownloadOffset(session, collectionId, objectId, out),
            "sharing download offset",
        )
        require(out[0] >= 0) { "shared download offset exceeds the ABI" }
        return out[0].toULong()
    }

    /** Stages one bounded opaque ciphertext range for a signed shared object. */
    fun appendSharedDownload(
        session: Long,
        collectionId: ByteArray,
        objectId: ByteArray,
        offset: ULong,
        bytes: ByteArray,
    ) {
        require(collectionId.size == 16 && objectId.size == 16) { "invalid shared download ID" }
        require(offset <= Long.MAX_VALUE.toULong()) { "shared download offset exceeds the ABI" }
        require(bytes.size in 1..1024 * 1024) { "shared download range exceeds 1 MiB" }
        withChurBuffer(bytes.size) { buffer ->
            buffer.copyIn(bytes)
            ChurFailure.check(
                ChurNative.sharingDownloadAppend(
                    session, collectionId, objectId, offset.toLong(), buffer, bytes.size,
                ),
                "sharing download append",
            )
        }
    }

    /** Verifies the complete container and activates its local catalog row. */
    fun finishSharedDownload(
        session: Long,
        collectionId: ByteArray,
        objectId: ByteArray,
        nowMs: Long,
    ) {
        require(collectionId.size == 16 && objectId.size == 16) { "invalid shared download ID" }
        require(nowMs >= 0) { "shared download time is negative" }
        ChurFailure.check(
            ChurNative.sharingDownloadFinish(session, collectionId, objectId, nowMs),
            "sharing download finish",
        )
    }

    /** Revokes one recipient and returns one resumable rotation batch. */
    fun revokeShare(
        session: Long,
        collectionId: ByteArray,
        recipientVaultId: ByteArray,
        recipientDeviceId: ByteArray,
        acceptedAtMs: Long,
    ): PreparedShareRevocation {
        require(acceptedAtMs >= 0) { "sharing revocation time is negative" }
        return withChurBuffer(SHARING_BUNDLE_CAPACITY) { buffer ->
            val written = IntArray(1)
            ChurFailure.check(
                ChurNative.sharingRevoke(
                    session,
                    collectionId,
                    recipientVaultId,
                    recipientDeviceId,
                    acceptedAtMs,
                    buffer,
                    written,
                ),
                "sharing revoke",
            )
            decodePreparedShareRevocation(buffer.copyOut(written[0]), written[0])
        }
    }

    fun ownSyncCollections(session: Long): List<ByteArray> =
        decodeOwnSyncCollections(pairingCall(session, byteArrayOf(), ChurNative::ownSyncCollections, 65_536))

    fun ownSyncOperations(session: Long, after: ULong): List<OwnSyncOperation> {
        require(after <= Long.MAX_VALUE.toULong())
        return decodeOwnSyncOperations(pairingCall(session, encodeDevicePairingTime(after.toLong()), ChurNative::ownSyncOperations))
    }

    fun ownSyncPlan(session: Long, collectionId: ByteArray): SharedReceivePlan {
        require(collectionId.size == 16)
        val bytes = pairingCall(session, collectionId, ChurNative::ownSyncPlan, 65_536)
        return decodeSharedReceivePlan(bytes, bytes.size)
    }

    fun ownSyncAuthor(session: Long, source: SharedSourceObject): SharedSourceObject {
        require(source.collectionId.size == 16 && source.objectId.size == 16 && source.storeId.size == 16 && source.fullSha256.size == 32)
        require(source.length <= Long.MAX_VALUE.toULong())
        val input = source.collectionId + source.objectId + source.storeId + encodeDevicePairingTime(source.length.toLong()) + source.fullSha256
        val bytes = pairingCall(session, input, ChurNative::ownSyncAuthor)
        return decodeSharedSourcePage(source.collectionId, bytes, bytes.size).single()
    }

    /** Fixed output capacity prevents a mutating IO call from being repeated for sizing. */
    fun peerCall(session: Long, input: ByteArray): ByteArray =
        pairingCall(session, input, ChurNative::peerCall, when (input.firstOrNull()?.toInt()) {
            1 -> 34
            5 -> 4 * 1024 * 1024 + 1
            8 -> 2 * 1024 * 1024
            9 -> 16
            10 -> PAIRING_CREDENTIALS_CAPACITY
            11 -> OBJECT_GRANT_LENGTH
            12 -> 1024 * 1024
            else -> 1
        })

    fun prepareDevicePairing(session: Long): DevicePairingRequest =
        decodeDevicePairingRequest(pairingCall(session, byteArrayOf(), ChurNative::devicePairingPrepare, 8 * 1024))

    fun inspectDevicePairing(session: Long, request: ByteArray): DevicePairingPreview =
        decodeDevicePairingPreview(pairingCall(session, request, ChurNative::devicePairingInspect, 128))

    fun approveDevicePairing(session: Long, request: ByteArray, nowMs: Long): PreparedDevicePairing {
        val encoded = encodeDevicePairingApproval(request, nowMs)
        return try {
            val response = pairingCall(session, encoded, ChurNative::devicePairingApprove)
            try { decodePreparedDevicePairing(response) } finally { response.fill(0) }
        } finally { encoded.fill(0) }
    }

    fun startDevicePairing(session: Long, approval: ByteArray): DevicePairingCredentials {
        val response = pairingCall(session, approval, ChurNative::devicePairingStart, PAIRING_CREDENTIALS_CAPACITY)
        return try { decodeDevicePairingCredentials(response) } finally { response.fill(0) }
    }

    fun finishDevicePairing(session: Long, nowMs: Long): ByteArray =
        decodeFinishedDevicePairing(pairingCall(session, encodeDevicePairingTime(nowMs), ChurNative::devicePairingFinish, 18))

    fun pairedDevices(session: Long): List<PairedDevice> =
        decodePairedDevices(pairingCall(session, byteArrayOf(), ChurNative::devicePairingOverview, 1024 * 1024))

    fun prepareDeviceRevocation(session: Long, deviceId: ByteArray, nowMs: Long): PreparedDeviceRevocation {
        require(deviceId.size == 16)
        return decodePreparedDeviceRevocation(pairingCall(session, deviceId + encodeDevicePairingTime(nowMs), ChurNative::devicePairingRevoke, 65_536))
    }

    fun currentDeviceCheckpoint(session: Long, nowMs: Long): ByteArray =
        pairingCall(session, encodeDevicePairingTime(nowMs), ChurNative::devicePairingCheckpoint, 65_536)

    private fun pairingCall(
        session: Long,
        input: ByteArray,
        call: (Long, ChurBuffer, Int, ChurBuffer, IntArray) -> Int,
        outputCapacity: Int = 16 * 1024 * 1024 + 32 * 1024,
    ): ByteArray {
        require(input.size <= 16 * 1024 * 1024) { "device pairing input is too large" }
        return withChurBuffer(maxOf(1, input.size)) { source ->
            source.copyIn(input)
            withChurBuffer(outputCapacity) { destination ->
                val written = IntArray(1)
                ChurFailure.check(call(session, source, input.size, destination, written), "device pairing")
                destination.copyOut(written[0])
            }
        }
    }

    /** Stages one opaque downloaded record without opening vault keys. */
    fun stageSync(
        runtime: Long,
        vaultId: ByteArray,
        kind: SyncRecordKind,
        stagedAtMs: Long,
        record: ByteArray,
    ) {
        withChurBuffer(record.size) { buffer ->
            buffer.copyIn(record)
            ChurFailure.check(
                ChurNative.syncStage(runtime, vaultId, kind.code, stagedAtMs, buffer, record.size),
                "sync stage",
            )
        }
    }

    /** Validates and applies the retained inbox after unlock. */
    fun syncHeads(session: Long): List<SyncDeviceHead> = withChurBuffer(6 + 32 * 24) { buffer ->
        val written = IntArray(1)
        ChurFailure.check(ChurNative.syncHeads(session, buffer, written), "sync heads")
        decodeSyncHeads(buffer.copyOut(written[0]), written[0])
    }

    /** Validates and applies the retained inbox after unlock. */
    fun processSync(
        session: Long,
        nowMs: Long,
    ): SyncProcessReport {
        val counts = LongArray(4)
        val status = IntArray(1)
        ChurFailure.check(ChurNative.syncProcess(session, nowMs, counts, status), "sync process")
        return SyncProcessReport(counts[0], counts[1], counts[2], counts[3], status[0])
    }

    /**
     * Counts the device chains the open vault holds a fork for, by state.
     *
     * `ROLLBACK_PROTECTION.md` §4 keeps the state in the catalog until it
     * clears, while [processSync] reports a fork only in the pass that found
     * it, so this is what tells the user again after a restart, §6.24 of
     * `docs/interop/FFI_CONTRACT.md`.
     */
    fun syncForkState(session: Long): SyncForkState {
        val counts = LongArray(2)
        ChurFailure.check(ChurNative.syncForkState(session, counts), "sync fork state")
        return SyncForkState(detected = counts[0], acknowledged = counts[1])
    }

    /** Marks every detected fork as seen; each chain stays frozen, §6.24. */
    fun acknowledgeSyncForks(session: Long) {
        ChurFailure.check(ChurNative.syncForkAcknowledge(session), "sync fork acknowledge")
    }

    // -----------------------------------------------------------------------
    // Key slots
    // -----------------------------------------------------------------------

    /** Adds a recovery slot to an active vault and returns the phrase, §8. */
    fun addRecoverySlot(session: Long): String =
        phraseOf("add recovery slot") { buffer, written ->
            ChurNative.vaultAddRecoverySlot(session, buffer, written)
        }

    /**
     * Stages a recovery slot and returns its phrase, `RECOVERY.md` §8.
     *
     * Nothing is committed: [commitRecoverySlot] writes the slot once the user
     * has confirmed the phrase, and a lock or a close before that discards it,
     * §6.23 of `docs/interop/FFI_CONTRACT.md`.
     */
    fun beginRecoverySlot(session: Long): String =
        phraseOf("recovery begin") { buffer, written ->
            ChurNative.vaultRecoveryBegin(session, buffer, written)
        }

    /** Commits the slot [beginRecoverySlot] staged, `KEY_SLOTS.md` §9. */
    fun commitRecoverySlot(session: Long) {
        ChurFailure.check(ChurNative.vaultRecoveryCommit(session), "recovery commit")
    }

    /** Adds the Apple Keychain slot, `KEY_SLOTS.md` §5. */
    fun addDeviceSlot(
        session: Long,
        keychainItemId: ByteArray,
    ): ByteArray =
        secretOf("add device slot") { out ->
            ChurNative.vaultAddDeviceSlot(session, keychainItemId, out)
        }

    /**
     * Begins the Android Keystore enrollment, `KEY_SLOTS.md` §4.
     *
     * The result carries the vault root, because the Keystore performs the
     * AEAD. The caller wraps it, calls [commitKeystoreSlot], and clears the
     * array; ADR-0041 records why the exception exists.
     */
    fun beginKeystoreSlot(session: Long): KeystoreEnrollment =
        withChurBuffer(KEYSTORE_ENROLLMENT_CAPACITY) { buffer ->
            val written = IntArray(1)
            ChurFailure.check(
                ChurNative.vaultKeystoreBegin(session, buffer, written),
                "keystore begin",
            )
            decodeKeystoreEnrollment(buffer.copyOut(written[0]), written[0])
        }

    /** Stores what the Keystore wrap returned, completing the slot. */
    fun commitKeystoreSlot(
        session: Long,
        gcmNonce: ByteArray,
        wrappedRootSecret: ByteArray,
    ) {
        ChurFailure.check(
            ChurNative.vaultKeystoreCommit(session, gcmNonce, wrappedRootSecret),
            "keystore commit",
        )
    }

    /** What every enrolled Keystore slot needs for its unwrap, on a locked runtime. */
    fun keystoreMaterial(runtime: Long): List<KeystoreMaterial> =
        withChurBuffer(KEYSTORE_MATERIAL_CAPACITY) { buffer ->
            val written = IntArray(1)
            ChurFailure.check(
                ChurNative.vaultKeystoreMaterial(runtime, buffer, written),
                "keystore material",
            )
            decodeKeystoreMaterial(buffer.copyOut(written[0]), written[0])
        }

    /** Unlocks with the root an Android Keystore unwrap returned. */
    fun unlockWithKeystoreRoot(
        runtime: Long,
        rootSecret: ByteArray,
    ): Long =
        handleOf("keystore unlock") { out ->
            ChurNative.vaultUnlock(runtime, FACTOR_KEYSTORE, rootSecret, out)
        }

    /** Removes one slot, `KEY_SLOTS.md` §9. */
    fun removeSlot(
        session: Long,
        slotId: ByteArray,
    ) {
        ChurFailure.check(ChurNative.vaultRemoveSlot(session, slotId), "remove slot")
    }

    /** Replaces the password slot. */
    fun changePassword(
        session: Long,
        password: ByteArray,
    ) {
        ChurFailure.check(ChurNative.vaultChangePassword(session, password), "change password")
    }

    /** The slots this vault carries. */
    fun slots(session: Long): List<SlotSummary> =
        withChurBuffer(SLOT_LIST_CAPACITY) { buffer ->
            val written = IntArray(1)
            ChurFailure.check(ChurNative.vaultSlots(session, buffer, written), "slots")
            decodeSlotList(buffer.copyOut(written[0]), written[0])
        }

    /** Public Keychain item ID or Keystore alias for a slot in this session. */
    fun platformSlotIdentifier(session: Long, slotId: ByteArray): ByteArray {
        require(slotId.size == 16) { "invalid slot ID" }
        requireCurrentAbi()
        return withChurBuffer(64) { buffer ->
            val written = IntArray(1)
            ChurFailure.check(
                ChurNative.vaultPlatformSlotIdentifier(session, slotId, buffer, written),
                "platform slot identifier",
            )
            require(written[0] in 16..64) { "invalid platform slot identifier length" }
            buffer.copyOut(written[0])
        }
    }

    // -----------------------------------------------------------------------
    // Library
    // -----------------------------------------------------------------------

    /** Reads local SQLCipher resume state bound to the original's content revision. */
    fun playbackPosition(session: Long, objectId: ByteArray): Long {
        require(objectId.size == ID_LENGTH)
        requirePlaybackPositionAbi()
        val output = LongArray(1)
        ChurFailure.check(ChurNative.playbackPosition(session, objectId, output), "read playback position")
        return output[0]
    }

    /** Saves a bounded native observation; zero clears a saved position. */
    fun savePlaybackPosition(session: Long, objectId: ByteArray, positionMs: Long, durationMs: Long) {
        require(objectId.size == ID_LENGTH && positionMs >= 0 && durationMs in 1..14_400_000L && positionMs <= durationMs)
        requirePlaybackPositionAbi()
        ChurFailure.check(ChurNative.savePlaybackPosition(session, objectId, positionMs, durationMs), "save playback position")
    }

    private fun requirePlaybackPositionAbi() {
        if (ChurNative.abiVersionMajor() != 8 || ChurNative.abiVersionMinor() < 2) {
            throw ChurFailure(ChurStatus.ABI_INCOMPATIBLE, "encrypted playback positions require ABI 8.2")
        }
    }

    /** Reads one page of a scope, `CATALOG_SCHEMA_V1.md` §16.2. */
    fun query(
        session: Long,
        query: ObjectQuery,
    ): ObjectPage {
        val limit = if (query.limit == 0) DEFAULT_PAGE_LIMIT else query.limit
        val capacity = PAGE_HEADER_LENGTH + PROJECTION_LENGTH * limit
        return withChurBuffer(capacity) { buffer ->
            val written = IntArray(1)
            ChurFailure.check(
                ChurNative.catalogQuery(
                    session,
                    query.scope.code,
                    query.sort.code,
                    query.kinds,
                    query.limit,
                    query.scopeId ?: ByteArray(ID_LENGTH),
                    query.cursor,
                    query.terms?.encodeToByteArray(),
                    buffer,
                    written,
                ),
                "catalog query",
            )
            decodeObjectPage(buffer.copyOut(written[0]), written[0])
        }
    }

    /** One object's detail record, §6.5. */
    fun detail(
        session: Long,
        objectId: ByteArray,
    ): ObjectDetail =
        withChurBuffer(DETAIL_CAPACITY) { buffer ->
            val written = IntArray(1)
            ChurFailure.check(
                ChurNative.objectMetadata(session, objectId, buffer, written),
                "object metadata",
            )
            decodeObjectDetail(buffer.copyOut(written[0]), written[0])
        }

    /** Sets or clears the favourite flag. */
    fun setFavorite(
        session: Long,
        objectId: ByteArray,
        favorite: Boolean,
    ) {
        ChurFailure.check(
            ChurNative.objectSetFavorite(session, objectId, favorite),
            "set favourite",
        )
    }

    /** Sets the favourite state of the whole selection atomically. */
    fun setFavorites(session: Long, objectIds: List<ByteArray>, favorite: Boolean) {
        ChurFailure.check(ChurNative.favoritesSet(session, packSelection(objectIds), favorite),
            "set favourites")
    }

    /** Moves an object into the thirty-day trash. */
    fun deleteObject(
        session: Long,
        objectId: ByteArray,
    ) {
        deleteObjects(session, listOf(objectId))
    }

    fun deleteObjects(session: Long, objectIds: List<ByteArray>) {
        ChurFailure.check(ChurNative.trashSet(session, packSelection(objectIds), false), "move to trash")
    }

    fun restoreObjects(session: Long, objectIds: List<ByteArray>) {
        ChurFailure.check(ChurNative.trashSet(session, packSelection(objectIds), true), "restore from trash")
    }

    fun permanentlyDeleteObject(session: Long, objectId: ByteArray) {
        ChurFailure.check(ChurNative.objectDelete(session, objectId), "delete permanently")
    }

    fun deleteDamagedFiles(session: Long) {
        ChurFailure.check(ChurNative.corruptEmpty(session), "delete damaged files")
    }

    fun emptyTrash(session: Long) {
        ChurFailure.check(ChurNative.trashEmpty(session), "empty trash")
    }

    fun restoreTrash(session: Long) {
        ChurFailure.check(ChurNative.trashRestoreAll(session), "restore trash")
    }

    /** Creates an album and returns its identifier. */
    fun createAlbum(
        session: Long,
        name: String,
        requestedId: ByteArray? = null,
    ): ByteArray {
        require(requestedId == null || requestedId.size == ID_LENGTH)
        val out = ByteArray(ID_LENGTH)
        ChurFailure.check(ChurNative.albumCreate(session, name, requestedId, out), "create album")
        return out
    }

    fun renameAlbum(session: Long, albumId: ByteArray, name: String) {
        ChurFailure.check(ChurNative.albumRename(session, albumId, name), "rename album")
    }

    fun deleteAlbum(session: Long, albumId: ByteArray) {
        ChurFailure.check(ChurNative.albumDelete(session, albumId), "delete album")
    }

    fun moveAlbum(session: Long, albumId: ByteArray, parentId: ByteArray?, beforeId: ByteArray?) {
        ChurFailure.check(
            ChurNative.albumMove(session, albumId, parentId ?: ByteArray(ID_LENGTH), beforeId ?: ByteArray(ID_LENGTH)),
            "move album",
        )
    }

    fun moveAlbumMember(session: Long, albumId: ByteArray, objectId: ByteArray, beforeId: ByteArray?) {
        ChurFailure.check(
            ChurNative.albumMoveMember(session, albumId, objectId, beforeId ?: ByteArray(ID_LENGTH)),
            "reorder album",
        )
    }

    /** Adds or removes one album membership. */
    fun setAlbumMembership(
        session: Long,
        albumId: ByteArray,
        objectId: ByteArray,
        member: Boolean,
    ) {
        ChurFailure.check(
            ChurNative.albumSetMembership(session, albumId, objectId, member),
            "album membership",
        )
    }

    /** Removes a nonempty selection from one album in one transaction, retaining the files. */
    fun removeAlbumObjects(session: Long, albumId: ByteArray, objectIds: List<ByteArray>) {
        require(albumId.size == ID_LENGTH)
        require(objectIds.isNotEmpty() && objectIds.size <= 100_000)
        require(objectIds.all { it.size == ID_LENGTH })
        val packed = ByteArray(objectIds.size * ID_LENGTH)
        objectIds.forEachIndexed { index, id -> id.copyInto(packed, index * ID_LENGTH) }
        ChurFailure.check(ChurNative.albumRemoveObjects(session, albumId, packed), "remove album objects")
    }

    /** Places a nonempty selection in one transaction, optionally creating its destination. */
    fun placeAlbumObjects(
        session: Long,
        targetId: ByteArray?,
        newName: String,
        parentId: ByteArray?,
        sourceId: ByteArray?,
        objectIds: List<ByteArray>,
        moveMembers: Boolean,
    ): ByteArray {
        require(objectIds.isNotEmpty() && objectIds.size <= 100_000)
        require(objectIds.all { it.size == ID_LENGTH })
        val packed = ByteArray(objectIds.size * ID_LENGTH)
        objectIds.forEachIndexed { index, id -> id.copyInto(packed, index * ID_LENGTH) }
        val output = ByteArray(ID_LENGTH)
        ChurFailure.check(
            ChurNative.albumPlaceObjects(
                session, targetId ?: ByteArray(ID_LENGTH), newName,
                parentId ?: ByteArray(ID_LENGTH), sourceId ?: ByteArray(ID_LENGTH),
                packed, moveMembers, output,
            ),
            "place album objects",
        )
        return output
    }

    /** Every album, with its membership count. */
    fun albums(session: Long): List<AlbumSummary> {
        var capacity = ALBUM_LIST_CAPACITY
        while (true) {
            val result = withChurBuffer(capacity) { buffer ->
                val written = IntArray(1)
                val status = ChurNative.albumList(session, buffer, written)
                if (status == 0) return@withChurBuffer decodeAlbumList(buffer.copyOut(written[0]), written[0])
                if (status == ChurStatus.RESOURCE_LIMIT_EXCEEDED.value && written[0] > capacity) {
                    capacity = written[0]
                    return@withChurBuffer null
                }
                ChurFailure.check(status, "album list")
                null
            }
            if (result != null) return result
        }
    }

    /**
     * Encrypts external sources into an independent portable archive without a session.
     *
     * The native worker duplicates descriptors before return. The caller retains provider
     * leases and does not seek, close, or reuse the sources until the operation is terminal.
     * The destination must be writable and seekable. Close the operation off the UI thread.
     */
    fun beginExternalArchive(
        runtime: Long,
        files: List<ExternalArchiveFile>,
        password: ByteArray,
        destinationFd: Int,
        maxOutputBytes: Long = Long.MAX_VALUE,
    ): Long {
        requireCurrentAbi()
        require(destinationFd >= 0) { "invalid archive destination" }
        val request = encodeExternalArchiveRequest(files, password, maxOutputBytes)
        return try {
            handleOf("external archive") { out ->
                ChurNative.externalArchiveBegin(runtime, request, files.map { it.descriptor }.toIntArray(), destinationFd, out)
            }
        } finally { request.fill(0) }
    }

    fun beginSelectiveExport(session: Long, objectIds: List<ByteArray>, albumIds: List<ByteArray>, notes: List<PrivateNoteSelection>, password: ByteArray, destinationFd: Int, maxOutputBytes: Long = Long.MAX_VALUE): Long {
        require(password.size in 1..1024 && objectIds.size <= 1000 && albumIds.size <= 1000 && notes.size <= 1000)
        require(objectIds.all { it.size == 16 } && albumIds.all { it.size == 16 } && notes.all { it.noteId.size == 16 && it.revision > 0 })
        val w = PrivateNoteWriter(1 + 4 + password.size + 12 + objectIds.size * 16 + albumIds.size * 16 + notes.size * 24 + 8)
        w.byte(1); w.sized(password)
        w.count(objectIds.size); objectIds.forEach { w.raw(it) }
        w.count(albumIds.size); albumIds.forEach { w.raw(it) }
        w.count(notes.size); notes.forEach { w.raw(it.noteId); w.number(it.revision) }
        require(maxOutputBytes > 0); w.number(maxOutputBytes)
        val out = LongArray(1)
        try { ChurFailure.check(ChurNative.selectiveExportBegin(session, w.bytes, destinationFd, out), "encrypted export") }
        finally { w.bytes.fill(0) }
        return out[0]
    }

    fun beginSelectiveImport(session: Long, sourceFd: Int, password: ByteArray): Long {
        require(password.size in 1..1024)
        val w = PrivateNoteWriter(1 + 4 + password.size)
        w.byte(1); w.sized(password)
        val out = LongArray(1)
        try { ChurFailure.check(ChurNative.selectiveImportBegin(session, w.bytes, sourceFd, out), "encrypted archive import") }
        finally { w.bytes.fill(0) }
        return out[0]
    }

    /** Local derived text stays in the encrypted catalog. The caller owns and clears [text]. */
    fun putContentIndex(session: Long, candidate: ContentIndexCandidate, text: ByteArray, partial: Boolean) {
        require(candidate.objectId.size == ID_LENGTH && candidate.primaryStreamId.size == ID_LENGTH)
        if (text.size > CONTENT_INDEX_TEXT_MAX_BYTES) throw ChurFailure(ChurStatus.RESOURCE_LIMIT_EXCEEDED, "content index text exceeds its bound")
        val writer = PrivateNoteWriter(42 + text.size)
        writer.byte(1); writer.raw(candidate.objectId); writer.raw(candidate.primaryStreamId)
        writer.byte(if (partial) 2 else 1); writer.count(1); writer.sized(text)
        contentIndexControl(session, writer.bytes, ChurNative::contentIndexPut).fill(0)
    }

    fun contentIndexCandidates(session: Long, afterId: ByteArray? = null, rebuild: Boolean = false, limit: Int = 25): List<ContentIndexCandidate> {
        require((afterId == null || afterId.size == ID_LENGTH) && limit in 1..100)
        val writer = PrivateNoteWriter(22)
        writer.byte(1); writer.byte(if (rebuild) 1 else 0); writer.raw(afterId ?: ByteArray(ID_LENGTH)); writer.count(limit)
        val bytes = contentIndexControl(session, writer.bytes, ChurNative::contentIndexCandidates)
        return try { decodeContentIndexCandidates(bytes) } finally { bytes.fill(0) }
    }

    fun clearContentIndex(session: Long) {
        contentIndexControl(session, byteArrayOf(1), ChurNative::contentIndexClear).fill(0)
    }

    private fun contentIndexControl(session: Long, request: ByteArray, call: (Long, ByteArray, ChurBuffer, IntArray) -> Int): ByteArray =
        try { requireCurrentAbi(); withChurBuffer(1_048_576) { buffer ->
            val written = IntArray(1)
            ChurFailure.check(call(session, request, buffer, written), "content index")
            buffer.copyOut(written[0])
        } } finally { request.fill(0) }

    private fun noteControl(session: Long, request: ByteArray, call: (Long, ByteArray, ChurBuffer, IntArray) -> Int): ByteArray =
        try { requireCurrentAbi(); withChurBuffer(1_048_576) { buffer ->
            val written = IntArray(1)
            ChurFailure.check(call(session, request, buffer, written), "private note")
            buffer.copyOut(written[0])
        } } finally { request.fill(0) }

    fun privateNotes(session: Long, terms: String = "", trashed: Boolean = false, limit: Int = 50, cursor: ByteArray? = null): PrivateNotePage {
        val text = terms.encodeToByteArray()
        try {
            require(text.size <= 256 && limit in 1..100 && (cursor == null || cursor.size == 65))
            val writer = PrivateNoteWriter(1 + 8 + 4 + text.size + 4 + (cursor?.size ?: 0))
            writer.byte(if (trashed) 1 else 0); writer.number(limit.toLong()); writer.sized(text); writer.sized(cursor ?: byteArrayOf())
            val bytes = noteControl(session, writer.bytes, ChurNative::privateNotesQuery)
            return try { decodePrivateNotePage(bytes) } finally { bytes.fill(0) }
        } finally { text.fill(0) }
    }

    fun privateNote(session: Long, id: ByteArray): PrivateNote {
        require(id.size == 16)
        val bytes = noteControl(session, id.copyOf(), ChurNative::privateNoteGet)
        return try { decodePrivateNote(bytes) } finally { bytes.fill(0) }
    }

    fun savePrivateNote(session: Long, id: ByteArray? = null, expectedRevision: Long = 0, title: String, body: String, pinned: Boolean = false, format: PrivateNoteFormat = PrivateNoteFormat.PLAIN_TEXT): PrivateNote {
        val titleBytes = title.encodeToByteArray(); val bodyBytes = body.encodeToByteArray()
        try {
            require(id == null || id.size == 16)
            if (titleBytes.size > 256 || bodyBytes.size > 262144) throw ChurFailure(ChurStatus.RESOURCE_LIMIT_EXCEEDED, "private note text exceeds its bound")
            require(expectedRevision >= 0)
            val writer = PrivateNoteWriter(16 + 8 + 2 + 4 + titleBytes.size + 4 + bodyBytes.size)
            writer.raw(id ?: ByteArray(16)); writer.number(expectedRevision); writer.byte(if (pinned) 1 else 0); writer.byte(format.ordinal); writer.sized(titleBytes); writer.sized(bodyBytes)
            val bytes = noteControl(session, writer.bytes, ChurNative::privateNoteSave)
            return try { decodePrivateNote(bytes) } finally { bytes.fill(0) }
        } finally { titleBytes.fill(0); bodyBytes.fill(0) }
    }

    fun changePrivateNote(session: Long, id: ByteArray, expectedRevision: Long, action: PrivateNoteAction): PrivateNote? {
        require(id.size == 16 && expectedRevision > 0)
        val writer = PrivateNoteWriter(25)
        writer.raw(id); writer.number(expectedRevision); writer.byte(action.ordinal + 1)
        val bytes = noteControl(session, writer.bytes, ChurNative::privateNoteChange)
        return try { if (bytes.isEmpty()) null else decodePrivateNote(bytes) } finally { bytes.fill(0) }
    }


    private fun attachmentControl(
        session: Long,
        request: ByteArray,
        capacity: Int = 1_048_576,
    ): ByteArray = try {
        requireCurrentAbi()
        withChurBuffer(capacity) { buffer ->
            val written = IntArray(1)
            ChurFailure.check(
                ChurNative.privateNoteAttachments(session, request, buffer, written),
                "private note attachment",
            )
            buffer.copyOut(written[0])
        }
    } finally {
        request.fill(0)
    }

    fun privateNoteAttachments(session: Long, id: ByteArray): List<PrivateNoteAttachment> {
        require(id.size == 16)
        val request = PrivateNoteWriter(17).apply { byte(1); raw(id) }.bytes
        val bytes = attachmentControl(session, request)
        return try {
            val reader = PrivateNoteReader(bytes)
            val count = reader.count()
            require(count in 0..32)
            List(count) {
                PrivateNoteAttachment(reader.raw(16), reader.text(240), reader.text(128), reader.number())
                    .also { require(it.size in 0..8_388_608) }
            }.also { reader.end() }
        } finally {
            bytes.fill(0)
        }
    }

    fun privateNoteOrganization(session: Long, id: ByteArray): PrivateNoteOrganization {
        require(id.size == 16)
        val bytes = attachmentControl(session, PrivateNoteWriter(17).apply { byte(6); raw(id) }.bytes)
        return try { PrivateNoteReader(bytes).let { r -> r.organization().also { r.end() } } } finally { bytes.fill(0) }
    }

    fun organizePrivateNote(session: Long, id: ByteArray, revision: Long, organization: PrivateNoteOrganization): PrivateNote {
        require(id.size == 16 && revision > 0)
        val labels = (listOf(organization.folder) + organization.tags).map { it.encodeToByteArray() }
        try {
            require(organization.tags.size <= 16 && labels.all { it.size <= 64 })
            val writer = PrivateNoteWriter(25 + 4 + labels[0].size + 4 + labels.drop(1).sumOf { 4 + it.size })
            writer.byte(7); writer.raw(id); writer.number(revision); writer.sized(labels[0]); writer.count(organization.tags.size)
            labels.drop(1).forEach(writer::sized)
            val bytes = attachmentControl(session, writer.bytes)
            return try { decodePrivateNote(bytes) } finally { bytes.fill(0) }
        } finally { labels.forEach { it.fill(0) } }
    }

    fun privateNoteDraft(session: Long): PrivateNoteDraft? {
        val bytes = attachmentControl(session, byteArrayOf(13), 16 + 8 + 2 + 8 + 256 + 262144)
        return try {
            if (bytes.isEmpty()) null else PrivateNoteReader(bytes).let { reader ->
                val id = reader.raw(16).takeUnless { it.all { byte -> byte == 0.toByte() } }
                val revision = reader.number()
                val pin = reader.byte()
                val format = PrivateNoteFormat.entries[reader.byte()]
                require(revision >= 0 && (id == null) == (revision == 0L) && pin in 0..1)
                PrivateNoteDraft(id, revision, reader.text(256), reader.text(262144), pin == 1, format)
                    .also { reader.end() }
            }
        } finally { bytes.fill(0) }
    }

    fun writePrivateNoteDraft(session: Long, draft: PrivateNoteDraft?) {
        if (draft == null) {
            attachmentControl(session, byteArrayOf(15), 1).fill(0)
            return
        }
        val title = draft.title.encodeToByteArray()
        val body = draft.body.encodeToByteArray()
        try {
            require(title.size <= 256 && body.size <= 262144 && (draft.noteId == null || draft.noteId.size == 16))
            val writer = PrivateNoteWriter(1 + 16 + 8 + 2 + 8 + title.size + body.size)
            writer.byte(14)
            writer.raw(draft.noteId ?: ByteArray(16))
            writer.number(draft.revision)
            writer.byte(if (draft.pinned) 1 else 0)
            writer.byte(draft.format.ordinal)
            writer.sized(title)
            writer.sized(body)
            attachmentControl(session, writer.bytes, 1).fill(0)
        } finally { title.fill(0); body.fill(0) }
    }

    fun privateNoteHistory(session: Long, id: ByteArray): List<PrivateNoteRevision> {
        require(id.size == 16)
        val bytes = attachmentControl(session, PrivateNoteWriter(17).apply { byte(8); raw(id) }.bytes)
        return try {
            val r = PrivateNoteReader(bytes); val count = r.count(); require(count in 0..20)
            List(count) {
                val revision = r.number(); val updated = r.number(); val title = r.text(256)
                val format = r.byte(); val attachments = r.count()
                require(revision > 0 && updated >= 0 && format in 0..1 && attachments in 0..32)
                PrivateNoteRevision(revision, updated, title, PrivateNoteFormat.entries[format], attachments)
            }.also { r.end() }
        } finally { bytes.fill(0) }
    }

    fun privateNoteRevision(session: Long, id: ByteArray, revision: Long): PrivateNoteRevisionDetail {
        require(id.size == 16 && revision > 0)
        val bytes = attachmentControl(session, PrivateNoteWriter(25).apply { byte(11); raw(id); number(revision) }.bytes)
        return try { PrivateNoteReader(bytes).let { r ->
            PrivateNoteRevisionDetail(r.note(), r.organization(), r.attachments()).also { r.end() }
        } } finally { bytes.fill(0) }
    }

    fun restorePrivateNoteRevision(session: Long, id: ByteArray, expectedRevision: Long, historicalRevision: Long): PrivateNote {
        require(id.size == 16 && expectedRevision > 0 && historicalRevision > 0)
        val bytes = attachmentControl(session, PrivateNoteWriter(33).apply {
            byte(9); raw(id); number(expectedRevision); number(historicalRevision)
        }.bytes)
        return try { decodePrivateNote(bytes) } finally { bytes.fill(0) }
    }

    fun privateNoteWorkspace(session: Long, terms: String, trashed: Boolean, limit: Int, cursor: ByteArray?,
        folder: String, tag: String): PrivateNoteWorkspacePage {
        val labels = listOf(terms, folder, tag).map { it.encodeToByteArray() }
        try {
            require(labels[0].size <= 256 && labels.drop(1).all { it.size <= 64 } && limit in 1..100 && (cursor == null || cursor.size == 65))
            val writer = PrivateNoteWriter(2 + 8 + labels.sumOf { 4 + it.size } + 4 + (cursor?.size ?: 0))
            writer.byte(12); writer.byte(if (trashed) 1 else 0); writer.number(limit.toLong())
            writer.sized(labels[0]); writer.sized(cursor ?: byteArrayOf()); writer.sized(labels[1]); writer.sized(labels[2])
            val bytes = attachmentControl(session, writer.bytes)
            return try { PrivateNoteReader(bytes).let { r ->
                val page = r.page()
                PrivateNoteWorkspacePage(page, page.notes.associate { it.id to r.organization() }).also { r.end() }
            } } finally { bytes.fill(0) }
        } finally { labels.forEach { it.fill(0) } }
    }

    fun readPrivateNoteAttachment(session: Long, id: ByteArray, attachmentId: ByteArray): ByteArray {
        require(id.size == 16 && attachmentId.size == 16)
        val request = PrivateNoteWriter(33).apply { byte(3); raw(id); raw(attachmentId) }.bytes
        return attachmentControl(session, request, 8_388_608)
    }

    private fun attachmentSize(attachment: PrivateNoteAttachmentData): Int {
        require(attachment.attachmentId.size == 16 && attachment.attachmentId.any { it != 0.toByte() })
        require(attachment.data.size <= 8_388_608)
        val name = attachment.name.encodeToByteArray()
        val mime = attachment.mimeType.encodeToByteArray()
        return try {
            require(name.size in 1..240 && mime.size <= 128)
            16 + 4 + name.size + 4 + mime.size + 4 + attachment.data.size
        } finally {
            name.fill(0)
            mime.fill(0)
        }
    }

    private fun PrivateNoteWriter.attachment(attachment: PrivateNoteAttachmentData) {
        raw(attachment.attachmentId)
        val name = attachment.name.encodeToByteArray()
        val mime = attachment.mimeType.encodeToByteArray()
        try {
            sized(name)
            sized(mime)
            sized(attachment.data)
        } finally {
            name.fill(0)
            mime.fill(0)
        }
    }

    fun putPrivateNoteAttachment(
        session: Long,
        id: ByteArray,
        expectedRevision: Long,
        attachment: PrivateNoteAttachmentData,
    ): PrivateNote {
        require(id.size == 16 && expectedRevision > 0)
        val writer = PrivateNoteWriter(25 + attachmentSize(attachment))
        writer.byte(2)
        writer.raw(id)
        writer.number(expectedRevision)
        writer.attachment(attachment)
        val bytes = attachmentControl(session, writer.bytes)
        return try { decodePrivateNote(bytes) } finally { bytes.fill(0) }
    }

    fun removePrivateNoteAttachment(
        session: Long,
        id: ByteArray,
        expectedRevision: Long,
        attachmentId: ByteArray,
    ): PrivateNote {
        require(id.size == 16 && attachmentId.size == 16 && expectedRevision > 0)
        val writer = PrivateNoteWriter(41)
        writer.byte(4)
        writer.raw(id)
        writer.number(expectedRevision)
        writer.raw(attachmentId)
        val bytes = attachmentControl(session, writer.bytes)
        return try { decodePrivateNote(bytes) } finally { bytes.fill(0) }
    }

    fun importPrivateNotePackage(
        session: Long,
        title: String,
        body: String,
        format: PrivateNoteFormat,
        attachments: List<PrivateNoteAttachmentData>,
    ): PrivateNote {
        val titleBytes = title.encodeToByteArray()
        val bodyBytes = body.encodeToByteArray()
        try {
            require(titleBytes.size <= 256 && bodyBytes.size <= 262144 && attachments.size <= 32)
            require(attachments.sumOf { it.data.size.toLong() } <= 16_777_216)
            val sizes = attachments.map(::attachmentSize)
            val writer = PrivateNoteWriter(2 + 4 + titleBytes.size + 4 + bodyBytes.size + 4 + sizes.sum())
            writer.byte(5)
            writer.byte(format.ordinal)
            writer.sized(titleBytes)
            writer.sized(bodyBytes)
            writer.count(attachments.size)
            attachments.forEach { writer.attachment(it) }
            val bytes = attachmentControl(session, writer.bytes)
            return try { decodePrivateNote(bytes) } finally { bytes.fill(0) }
        } finally {
            titleBytes.fill(0)
            bodyBytes.fill(0)
        }
    }

    private fun requireCurrentAbi() {
        if (ChurNative.abiVersionMajor() != 8) {
            throw ChurFailure(ChurStatus.ABI_INCOMPATIBLE, "native ABI 8 is required")
        }
    }

    fun beginPrivateNoteExport(session: Long, id: ByteArray, expectedRevision: Long, destinationFd: Int): Long {
        requireCurrentAbi()
        require(id.size == 16 && expectedRevision > 0)
        val out = LongArray(1)
        ChurFailure.check(ChurNative.privateNoteExportBegin(session, id, expectedRevision, destinationFd, out), "export private note")
        return out[0]
    }

    fun beginPrivateNoteAttachmentExport(
        session: Long,
        id: ByteArray,
        expectedRevision: Long,
        attachmentId: ByteArray,
        destinationFd: Int,
    ): Long {
        requireCurrentAbi()
        require(id.size == 16 && attachmentId.size == 16 && expectedRevision > 0)
        val out = LongArray(1)
        ChurFailure.check(
            ChurNative.privateNoteAttachmentExportBegin(session, id, expectedRevision, attachmentId, destinationFd, out),
            "export private note attachment",
        )
        return out[0]
    }

    /** Creates a tag and returns its identifier. */
    fun createTag(
        session: Long,
        name: String,
    ): ByteArray {
        val out = ByteArray(ID_LENGTH)
        ChurFailure.check(ChurNative.tagCreate(session, name, out), "create tag")
        return out
    }

    /** Every tag available to the private selection picker. */
    fun tags(session: Long): List<TagSummary> {
        var capacity = TAG_LIST_CAPACITY
        while (true) {
            val result = withChurBuffer(capacity) { buffer ->
                val written = IntArray(1)
                val status = ChurNative.tagList(session, buffer, written)
                if (status == 0) return@withChurBuffer decodeTagList(buffer.copyOut(written[0]), written[0])
                if (status == ChurStatus.RESOURCE_LIMIT_EXCEEDED.value && written[0] > capacity) {
                    capacity = written[0]
                    return@withChurBuffer null
                }
                ChurFailure.check(status, "tag list")
                null
            }
            if (result != null) return result
        }
    }

    /** Applies or removes one tag on one object. */
    fun setObjectTag(
        session: Long,
        tagId: ByteArray,
        objectId: ByteArray,
        tagged: Boolean,
    ) {
        ChurFailure.check(ChurNative.objectSetTag(session, tagId, objectId, tagged), "set tag")
    }

    /** Applies or removes a tag for the whole selection in one transaction. */
    fun applyTagSelection(session: Long, tagId: ByteArray?, newName: String,
                          objectIds: List<ByteArray>, tagged: Boolean): ByteArray {
        val output = ByteArray(ID_LENGTH)
        ChurFailure.check(ChurNative.tagApplySelection(session, tagId ?: ByteArray(ID_LENGTH),
            newName, packSelection(objectIds), tagged, output), "apply tag selection")
        return output
    }

    fun renameTag(session: Long, tagId: ByteArray, name: String) {
        ChurFailure.check(ChurNative.tagRename(session, tagId, name), "rename tag")
    }

    fun deleteTag(session: Long, tagId: ByteArray) {
        ChurFailure.check(ChurNative.tagDelete(session, tagId), "delete tag")
    }

    private fun packSelection(objectIds: List<ByteArray>): ByteArray {
        require(objectIds.isNotEmpty() && objectIds.size <= 1_000_000)
        require(objectIds.all { it.size == ID_LENGTH })
        return ByteArray(objectIds.size * ID_LENGTH).also { packed ->
            objectIds.forEachIndexed { index, id -> id.copyInto(packed, index * ID_LENGTH) }
        }
    }

    // -----------------------------------------------------------------------
    // Derived assets and reading
    // -----------------------------------------------------------------------

    /** Encrypts and records one derived asset the platform produced. */
    fun putDerived(
        session: Long,
        objectId: ByteArray,
        kind: StreamKind,
        width: Int,
        height: Int,
        bytes: ByteArray,
    ) {
        withChurBuffer(bytes.size) { buffer ->
            buffer.copyIn(bytes)
            ChurFailure.check(
                ChurNative.derivedPut(
                    session,
                    objectId,
                    kind.code,
                    width,
                    height,
                    buffer,
                    bytes.size,
                ),
                "put derived asset",
            )
        }
    }

    /** Reads one derived asset, which the timeline does for every visible row. */
    fun readDerived(
        session: Long,
        objectId: ByteArray,
        kind: StreamKind,
    ): ByteArray =
        withChurBuffer(DERIVED_CAPACITY) { buffer ->
            val written = IntArray(1)
            ChurFailure.check(
                ChurNative.derivedRead(session, objectId, kind.code, buffer, written),
                "read derived asset",
            )
            buffer.copyOut(written[0])
        }

    /** Opens a random-access reader on one stream. */
    fun openReader(
        session: Long,
        objectId: ByteArray,
        kind: StreamKind,
    ): Long =
        handleOf("open reader") { out ->
            ChurNative.objectReaderOpen(session, objectId, kind.code, out)
        }

    /** The authenticated plaintext size. */
    fun readerSize(reader: Long): Long {
        val out = LongArray(1)
        ChurFailure.check(ChurNative.objectReaderSize(reader, out), "reader size")
        return out[0]
    }

    /** The content information a player needs before its first range request. */
    fun readerContentInfo(reader: Long): ContentInfo {
        val numbers = LongArray(4)
        val contentType = ByteArray(64)
        ChurFailure.check(
            ChurNative.objectReaderContentInfo(reader, numbers, contentType),
            "content info",
        )
        val terminator = contentType.indexOfFirst { it.toInt() == 0 }
        val length = if (terminator < 0) contentType.size else terminator
        return ContentInfo(
            plaintextSize = numbers[0],
            mediaKind = numbers[1].toInt(),
            byteRangeSupported = numbers[2] == 1L,
            complete = numbers[3] == 1L,
            contentType = contentType.decodeToString(0, length),
        )
    }

    /**
     * Reads a range, looping until it has the bytes or reaches the end.
     *
     * §6.3 permits a short read at any offset, so the loop is the contract
     * rather than a precaution: a caller that read once and trusted the count
     * would silently truncate.
     */
    fun readRange(
        reader: Long,
        offset: Long,
        length: Int,
    ): ByteArray {
        val out = ByteArray(length)
        try {
            fillRange(reader, offset, length, out)
        } catch (failure: Throwable) {
            // A read that fails part way leaves plaintext in `out`, and the
            // caller never receives it to wipe.
            out.fill(0)
            throw failure
        }
        return out
    }

    private fun fillRange(
        reader: Long,
        offset: Long,
        length: Int,
        out: ByteArray,
    ) {
        withChurBuffer(length) { buffer ->
            val written = IntArray(1)
            var at = 0
            while (at < length) {
                ChurFailure.check(
                    ChurNative.objectReaderReadAt(reader, offset + at, buffer, 0, written),
                    "read at",
                )
                if (written[0] == 0) break
                // The reader fills up to the buffer's capacity, which is the
                // whole range rather than what is left of it, so a read that
                // starts part way through returns more than the caller still
                // needs. Taking the surplus would run off the end of `out`; the
                // next iteration re-reads from the authenticated container, so
                // dropping it costs one chunk decrypt on the last step only.
                val take = minOf(written[0], length - at)
                val chunk = buffer.copyOut(take)
                try {
                    chunk.copyInto(out, at)
                } finally {
                    // The intermediate copy is plaintext nothing else holds.
                    chunk.fill(0)
                }
                at += take
            }
            if (at < length) {
                throw ChurFailure(ChurStatus.OBJECT_INCOMPLETE, "the range ended early")
            }
        }
    }

    /**
     * Fills [destination] with the plaintext from its start, looping as
     * [readRange] does.
     *
     * Each read lands where the last one stopped, so the whole object ends up
     * in the one native buffer and never in a Kotlin array: §6 forbids a
     * whole-file `ByteArray`, and §7 lets Rust write straight into a buffer the
     * host owns. The caller sizes the buffer to the object and clears it, which
     * [withChurBuffer] does.
     */
    fun readInto(
        reader: Long,
        destination: ChurBuffer,
        sourceOffset: Long = 0,
    ) {
        require(sourceOffset >= 0 && sourceOffset <= Long.MAX_VALUE - destination.capacityBytes)
        val length = destination.capacityBytes
        val written = IntArray(1)
        var at = 0
        while (at < length) {
            ChurFailure.check(
                ChurNative.objectReaderReadAt(reader, sourceOffset + at, destination, at, written),
                "read at",
            )
            if (written[0] == 0) break
            at += written[0]
        }
        if (at < length) {
            throw ChurFailure(ChurStatus.OBJECT_INCOMPLETE, "the range ended early")
        }
    }

    /** Runs complete verification and returns the state it reached. */
    fun verifyComplete(reader: Long): Int {
        val out = IntArray(1)
        ChurFailure.check(ChurNative.objectReaderVerifyComplete(reader, out), "verify")
        return out[0]
    }

    /** Closes a reader handle. */
    fun closeReader(reader: Long) {
        ChurFailure.check(ChurNative.objectReaderClose(reader), "reader close")
    }

    // -----------------------------------------------------------------------
    // Operations
    // -----------------------------------------------------------------------

    /** Starts an import from a file descriptor the platform opened. */
    fun beginImport(
        session: Long,
        sourceFd: Int,
        request: ImportRequest,
    ): Long {
        require(request.requestedObjectId == null || request.requestedObjectId.size == ID_LENGTH)
        return handleOf("import begin") { out ->
            ChurNative.importBegin(
                session,
                sourceFd,
                request.seekable,
                request.mediaClass,
                request.width,
                request.height,
                request.durationMs,
                request.knownLength ?: -1L,
                request.captureTimeMs ?: -1L,
                request.contentType,
                request.originalFilename,
                request.requestedObjectId,
                out,
            )
        }
    }

    /** Starts an export to a file descriptor the platform opened. */
    fun beginExport(
        session: Long,
        objectId: ByteArray,
        destinationFd: Int,
    ): Long =
        handleOf("export begin") { out ->
            ChurNative.exportBegin(session, objectId, destinationFd, out)
        }

    /**
     * Starts writing a backup package to a descriptor, `FFI_CONTRACT.md` §6.7.
     *
     * The descriptor must be writable and seekable:
     * `docs/format/BACKUP_FORMAT_V1.md` §7 writes the public preamble before
     * the records and learns the record count only after the inventory pass, so
     * a pipe is not a destination. An application that uploads a package writes
     * it to a file and uploads that.
     */
    fun beginBackup(
        session: Long,
        destinationFd: Int,
    ): Long =
        handleOf("backup create") { out ->
            ChurNative.backupCreate(session, destinationFd, out)
        }

    /**
     * Starts restoring a backup package, §6.7.
     *
     * It takes the runtime rather than a session, because a restore installs an
     * identity: at the moment it runs there may be no session and no vault at
     * all, and §8 obtains the credential from the package's own portable
     * descriptor.
     */
    fun beginRestore(
        runtime: Long,
        sourceFd: Int,
        password: ByteArray,
    ): Long =
        handleOf("backup restore") { out ->
            ChurNative.backupRestore(runtime, sourceFd, password, out)
        }

    /** Starts an integrity scan; a null identifier scans every object. */
    fun beginIntegrityScan(
        session: Long,
        objectId: ByteArray?,
    ): Long =
        handleOf("scan begin") { out ->
            ChurNative.integrityScanBegin(session, objectId, out)
        }

    /**
     * Starts one re-encryption pass after a revocation, ADR-0069. The caller
     * polls and cancels it like any operation; a lock cancels it.
     */
    fun beginReencryption(session: Long): Long =
        handleOf("reencryption begin") { out ->
            ChurNative.reencryptionBegin(session, out)
        }

    /** The objects still to re-encrypt and the objects that cannot be re-encrypted now. */
    fun reencryptionCounts(session: Long): ReencryptionCounts {
        val counts = LongArray(2)
        ChurFailure.check(ChurNative.reencryptionCounts(session, counts), "reencryption counts")
        return ReencryptionCounts(pending = counts[0], failed = counts[1])
    }

    /** One progress snapshot, §10. */
    fun poll(operation: Long): OperationProgress {
        val counts = LongArray(2)
        val states = IntArray(4)
        val objectId = ByteArray(16)
        ChurFailure.check(ChurNative.operationPoll(operation, counts, states, objectId), "poll")
        return OperationProgress(
            processed = counts[0],
            total = counts[1],
            kind = states[0],
            stage = states[1],
            terminal = states[2] == 1,
            status = states[3],
            objectId = objectId,
        )
    }

    /** Asks an operation to stop, §9. */
    fun cancel(operation: Long) {
        ChurFailure.check(ChurNative.operationCancel(operation), "cancel")
    }

    /** Closes an operation handle, waiting for its worker. */
    fun closeOperation(operation: Long) {
        ChurFailure.check(ChurNative.operationClose(operation), "operation close")
    }

    // -----------------------------------------------------------------------

    private inline fun handleOf(
        where: String,
        body: (LongArray) -> Int,
    ): Long {
        val out = LongArray(1)
        ChurFailure.check(body(out), where)
        return out[0]
    }

    /**
     * Runs a call whose result is a recovery phrase.
     *
     * The buffer is cleared before it is released, so the phrase exists in
     * native memory only for the call and in the returned string until the
     * caller drops it.
     */
    private inline fun phraseOf(
        where: String,
        body: (ChurBuffer, IntArray) -> Int,
    ): String =
        withChurBuffer(RECOVERY_PHRASE_MAX) { buffer ->
            val written = IntArray(1)
            ChurFailure.check(body(buffer, written), where)
            buffer.copyOut(written[0]).decodeToString()
        }

    private inline fun secretOf(
        where: String,
        body: (ByteArray) -> Int,
    ): ByteArray {
        val out = ByteArray(SECRET_LENGTH)
        val code = body(out)
        if (code != 0) {
            out.fill(0)
            ChurFailure.check(code, where)
        }
        return out
    }

    /** `CHUR_FACTOR_PASSWORD`. */
    private const val FACTOR_PASSWORD = 1

    /** `CHUR_FACTOR_RECOVERY`. */
    private const val FACTOR_RECOVERY = 2

    /** `CHUR_FACTOR_APPLE_KEYCHAIN`. */
    private const val FACTOR_DEVICE = 3

    /** The Android Keystore factor, whose secret is the unwrapped root. */
    private const val FACTOR_KEYSTORE = 4

    /** A length-prefixed alias and AAD and a 32-byte root, §6.6. */
    private const val KEYSTORE_ENROLLMENT_CAPACITY = 4 + 64 + 4 + 160 + 32

    /** A count and two entries, which is every identity the registry admits. */
    private const val KEYSTORE_MATERIAL_CAPACITY = 4 + 2 * (4 + 64 + 4 + 160 + 12 + 48)

    /** The bounded public identity, enrollment, and initial operation record. */
    private const val SHARING_IDENTITY_CAPACITY = 32 * 1024

    /** Four thousand active members with identifiers and fingerprints. */
    private const val SHARING_OVERVIEW_CAPACITY = 512 * 1024

    private const val OBJECT_PREKEY_LENGTH = 4_655
    private const val PAIRING_CREDENTIALS_CAPACITY = 16 * 1024
    private const val OBJECT_GRANT_LENGTH = 4_679

    private const val SHARING_RECIPIENT_CAPACITY = 128

    /** Membership and grant, plus their signed operation records. */
    private const val PREPARED_SHARE_CAPACITY = 64 * 1024

    /** The exact response bound required before a revocation changes state. */
    private const val SHARING_BUNDLE_CAPACITY = 16 * 1024 * 1024

    /** The default page size of §16.2. */
    private const val DEFAULT_PAGE_LIMIT = 200

    /** Sixteen slots at 25 bytes each plus the count, §13 of the descriptor. */
    private const val SLOT_LIST_CAPACITY = 4 + 16 * 25

    /** Ten thousand albums is the §21 bound; the buffer holds a realistic page
     *  of them and a longer list is `RESOURCE_LIMIT_EXCEEDED`, which the caller
     *  surfaces rather than truncating. */
    private const val ALBUM_LIST_CAPACITY = 64 * 1024

    /** The picker reports an explicit limit error instead of truncating a long list. */
    private const val TAG_LIST_CAPACITY = 64 * 1024

    /** A detail record is bounded by §12's metadata bounds. */
    private const val DETAIL_CAPACITY = 96 * 1024

    /** A screen preview at 2048 px is the largest derivative §12 allows. */
    private const val DERIVED_CAPACITY = 8 * 1024 * 1024
}

/** Opaque record families accepted by the locked sync inbox. */
enum class SyncRecordKind(
    internal val code: Int,
) {
    OPERATION(1),
    CHECKPOINT(2),
    OPERATION_PAGE(3),
}

/**
 * Counts from one unlocked inbox pass.
 *
 * [firstRejection] is zero or the status of the first rejected record, except
 * that a fork or rollback verdict replaces an earlier status of another kind
 * (`FFI_CONTRACT.md` §6.8).
 */
data class SyncProcessReport(
    val applied: Long,
    val duplicates: Long,
    val pending: Long,
    val rejected: Long,
    val firstRejection: Int,
)

/**
 * How many device chains the catalog holds a fork for, by the state of
 * `ROLLBACK_PROTECTION.md` §4: [detected] ones the user has not seen yet, and
 * [acknowledged] ones they have. Both stay frozen until the state clears.
 */
data class SyncForkState(
    val detected: Long,
    val acknowledged: Long,
)

/** The handshake facts of §2. */
data class NativeHandshake(
    val major: Int,
    val minor: Int,
    val capabilities: Long,
    val objectFormatMin: Int,
    val objectFormatMax: Int,
    val keySlotFormatMin: Int,
    val keySlotFormatMax: Int,
    val buildFlavor: Int,
)

/** The content information of §6.1. */
data class ContentInfo(
    val plaintextSize: Long,
    val contentType: String,
    val mediaKind: Int,
    val byteRangeSupported: Boolean,
    val complete: Boolean,
)

/**
 * One progress snapshot, §10.
 *
 * [objectId] is the object a terminal successful import activated, and zero
 * for every other kind, stage, and outcome. [importedObjectId] is how a
 * caller reads it, because a zeroed array means "no identifier" and no caller
 * should compare raw bytes against that convention itself.
 */
data class OperationProgress(
    val processed: Long,
    val total: Long,
    val kind: Int,
    val stage: Int,
    val terminal: Boolean,
    val status: Int,
    val objectId: ByteArray = ByteArray(16),
) {
    /** The object a terminal successful import activated, or `null`. */
    fun importedObjectId(): ByteArray? = objectId.takeIf { id -> id.any { byte -> byte != 0.toByte() } }

    override fun equals(other: Any?): Boolean =
        other is OperationProgress &&
            processed == other.processed &&
            total == other.total &&
            kind == other.kind &&
            stage == other.stage &&
            terminal == other.terminal &&
            status == other.status &&
            objectId.contentEquals(other.objectId)

    override fun hashCode(): Int =
        processed.hashCode() * 31 + total.hashCode() * 31 + kind * 31 + stage * 31 +
            terminal.hashCode() * 31 + status * 31 + objectId.contentHashCode()
}

/** The reason a session locked, which reaches no private state. */
enum class LockReason(
    val code: Int,
) {
    /** The user asked. */
    USER(1),

    /** The idle timer expired. */
    TIMEOUT(2),

    /** The application went to the background. */
    BACKGROUND(3),

    /** The panic gesture, `DESIGN.md` §14. */
    PANIC(4),
}

/** The query scopes of §16.2. */
enum class QueryScope(
    val code: Int,
) {
    /** Every listable object. */
    TIMELINE(1),

    /** The members of one album. */
    ALBUM(2),

    /** Every favourite. */
    FAVORITES(3),

    /** Every object carrying one tag. */
    TAG(4),

    /** The FTS5 query of §16.4. */
    SEARCH(5),

    /** The objects §16.2 keeps out of the ordinary library. */
    QUARANTINE(6),
    /** Recoverable deleted media. */
    TRASH(7),
}

/** The sorts of §16.2. */
enum class QuerySort(
    val code: Int,
) {
    /** Capture time descending, the default. */
    CAPTURE_DESC(1),

    /** Capture time ascending. */
    CAPTURE_ASC(2),

    /** Import time descending. */
    IMPORT_DESC(3),
    /** The user-controlled order within one album. */
    ALBUM_MANUAL(4),
}

/** The stream kinds of `CANONICAL_ENCODING_V1.md` §15.4. */
enum class StreamKind(
    val code: Int,
) {
    /** The imported bytes as received. */
    ORIGINAL(1),

    /** The small thumbnail the timeline reads. */
    THUMBNAIL(2),

    /** The grid preview. */
    GRID_PREVIEW(3),

    /** The screen preview the viewer reads. */
    SCREEN_PREVIEW(4),

    /** A video poster frame. */
    VIDEO_POSTER(5),

    /**
     * An audio waveform, `docs/interop/MEDIA_PIPELINE.md` §6.1.
     *
     * Unlike every kind above it, this one is not a picture. Its bytes are the
     * peak-envelope record that section defines, which shared code draws.
     */
    AUDIO_WAVEFORM(6),

    /** Explicit H.264/AAC SDR viewing copy; original export stays unchanged. */
    COMPATIBLE_VIDEO(10),

    /** Twelve seek previews in one encrypted JPEG atlas. */
    VIDEO_STORYBOARD(11),
}

/** One page request. */
data class ObjectQuery(
    val scope: QueryScope = QueryScope.TIMELINE,
    val sort: QuerySort = QuerySort.CAPTURE_DESC,
    val kinds: Int = 0,
    val limit: Int = 0,
    val scopeId: ByteArray? = null,
    val terms: String? = null,
    val cursor: ByteArray? = null,
) {
    override fun equals(other: Any?): Boolean =
        other is ObjectQuery && scope == other.scope && sort == other.sort &&
            kinds == other.kinds && limit == other.limit && terms == other.terms

    override fun hashCode(): Int = scope.hashCode() * 31 + (terms?.hashCode() ?: 0)
}

/** What the platform reports about an import source, `MEDIA_PIPELINE.md` §3. */
data class ImportRequest(
    val contentType: String,
    val seekable: Boolean,
    val mediaClass: Int,
    val width: Int = 0,
    val height: Int = 0,
    val durationMs: Long = 0,
    val knownLength: Long? = null,
    val captureTimeMs: Long? = null,
    val originalFilename: String? = null,
    val requestedObjectId: ByteArray? = null,
)

/** Re-encryption state after a revocation, ADR-0069. */
data class ReencryptionCounts(
    /** Objects still under a key that a removed member may hold. */
    val pending: Long,
    /** Objects that cannot be re-encrypted now. */
    val failed: Long,
)
