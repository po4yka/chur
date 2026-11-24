package dev.po4yka.chur.vault

import dev.po4yka.chur.core.model.ChurStatus
import dev.po4yka.chur.core.platformkeys.DeviceSlot
import dev.po4yka.chur.core.platformkeys.DeviceSlotException
import dev.po4yka.chur.ffi.PrivateNote
import dev.po4yka.chur.ffi.PrivateNoteAttachment
import dev.po4yka.chur.ffi.PrivateNoteAttachmentData
import dev.po4yka.chur.ffi.PrivateNoteFormat
import dev.po4yka.chur.ffi.PrivateNoteSelection
import dev.po4yka.chur.ffi.PrivateNotePage
import dev.po4yka.chur.ffi.PrivateNoteAction
import dev.po4yka.chur.ffi.AlbumSummary
import dev.po4yka.chur.ffi.ChurBuffer
import dev.po4yka.chur.ffi.ChurFailure
import dev.po4yka.chur.ffi.ChurVault
import dev.po4yka.chur.ffi.ContentInfo
import dev.po4yka.chur.ffi.ContentIndexCandidate
import dev.po4yka.chur.ffi.ExternalArchiveFile
import dev.po4yka.chur.ffi.ImportRequest
import dev.po4yka.chur.ffi.KeystoreMaterial
import dev.po4yka.chur.ffi.LockReason
import dev.po4yka.chur.ffi.ObjectDetail
import dev.po4yka.chur.ffi.ObjectPage
import dev.po4yka.chur.ffi.ObjectQuery
import dev.po4yka.chur.ffi.OperationProgress
import dev.po4yka.chur.ffi.SharingIdentity
import dev.po4yka.chur.ffi.SharingOverview
import dev.po4yka.chur.ffi.SharingPermission
import dev.po4yka.chur.ffi.SharingRecipient
import dev.po4yka.chur.ffi.SharedReceivePlan
import dev.po4yka.chur.ffi.SharedSourceObject
import dev.po4yka.chur.ffi.PreparedShare
import dev.po4yka.chur.ffi.PreparedShareRevocation
import dev.po4yka.chur.ffi.SlotSummary
import dev.po4yka.chur.ffi.StreamKind
import dev.po4yka.chur.ffi.TagSummary
import dev.po4yka.chur.ffi.SyncForkState
import dev.po4yka.chur.ffi.SyncProcessReport
import dev.po4yka.chur.ffi.SyncRecordKind
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * The one owner of the runtime and session handles.
 *
 * `docs/interop/FFI_CONTRACT.md` §14 permits one runtime per process and §8.1
 * one process per vault, so this is a single instance held by the composition
 * root. Nothing above it sees a handle: a feature asks for a page or an object
 * and never for the `Long` behind it.
 *
 * Every call is guarded by one mutex. §8.1 already serializes catalog writes
 * inside Rust, so this adds no safety there; what it adds is that a lock cannot
 * interleave with a call that is about to use the session it closed.
 *
 * Calls block, because §8 makes every native call synchronous. The caller runs
 * this on an I/O dispatcher; this class does not choose one for it, so a test
 * can drive it directly.
 */
class VaultRepository(
    private val rootPath: String,
    private val clock: () -> Long,
    private var policy: LockPolicy = LockPolicy(),
    private val destroyPlatformSlot: (ByteArray) -> Unit = { DeviceSlot(it).destroy() },
) {
    private val mutex = Mutex()
    private val _state = MutableStateFlow<VaultState>(VaultState.Starting)
    private var runtime = 0L
    private var session = 0L
    private val panicGeneration = MutableStateFlow<Long?>(null)
    private var generation = 0L
    private var lastUsedMs = 0L

    /**
     * A creation stopped at step 5 of `PROVISIONING.md` §3 while its recovery
     * phrase waits for confirmation.
     *
     * §4 there runs the presentation and confirmation "before the slot
     * commits", so the handle reaches `ACTIVE` only in [confirmRecoveryPhrase].
     * A lock before that abandons it.
     */
    private var creation = 0L

    /**
     * Whether a recovery slot staged on the open session waits for its phrase
     * to be confirmed, `RECOVERY.md` §8. The slot itself is in Rust and goes
     * with the session.
     */
    private var recoveryStaged = false

    /**
     * When the recovery phrase that waits for confirmation was handed out.
     *
     * `DESIGN.md` §17.2 bounds the phrase at ten minutes after it appeared.
     * [lastUsedMs] cannot carry that bound, because [poll] refreshes it while
     * an operation runs.
     */
    private var phraseShownAtMs = 0L

    /** What the application should show. */
    val state: StateFlow<VaultState> = _state.asStateFlow()

    /**
     * Opens the runtime and reports whether a vault exists.
     *
     * A start that finds a session already open is a host whose window was
     * recreated. §8.1 of `docs/interop/FFI_CONTRACT.md` says "there is no
     * per-scene vault state", so the session this finds is the session it
     * keeps: re-deriving the state from the descriptor would publish `Locked`
     * while Rust still holds the session, which puts the unlock screen in
     * front of an unlocked vault and leaves its handles unreachable.
     *
     * A creation that waits for its recovery phrase is kept the same way as an
     * open session. The background sync calls this while the phrase can be on
     * screen, and `NoVault` or `Locked` would stop the idle timer that bounds
     * the phrase, `DESIGN.md` §17.2.
     */
    suspend fun start(): VaultState = mutex.withLock {
        if (runtime == 0L) {
            runtime = ChurVault.openRuntime(rootPath)
        }
        val next = when {
            session != 0L || creation != 0L -> _state.value
            ChurVault.vaultPresent(runtime) -> VaultState.Locked()
            else -> VaultState.NoVault
        }
        _state.value = next
        next
    }

    /**
     * Creates a vault, `PROVISIONING.md` §3.
     *
     * The recovery offer of step 5 happens inside, between the verified
     * password slot and `ACTIVE`, because that is where §3 puts it. The phrase
     * is returned once and this class keeps no copy: `RECOVERY.md` §2 shows it
     * exactly once and §8 there is how a user who loses it gets another.
     *
     * With the offer accepted, the creation stops at step 5 and the state
     * stays [VaultState.Creating]: §4 commits the slot only after the user
     * confirmed the phrase, so `ACTIVE` is reached in [confirmRecoveryPhrase].
     * A lock before that abandons the creation, and no vault is left behind.
     */
    suspend fun create(password: ByteArray, offerRecovery: Boolean): String? =
        mutex.withLock {
            requireRuntime()
            // A second identity is created from an authenticated session,
            // `DECOY_VAULT.md` §3, so a session can be open when this runs. It
            // must not survive: this method replaces `session`, and a handle
            // nothing holds any more is a vault Rust still has unlocked, with
            // its root, its collection keys, and its catalog connection live.
            // §8 of `PLAINTEXT_LIFECYCLE.md` is the transition that ends that,
            // and it runs here rather than being skipped because the caller is
            // busy creating something else.
            endSession(LockReason.USER)
            // A second tap can land before the state reads `Creating`, and a
            // creation already waiting here would otherwise be overwritten
            // with its root and its catalog still live in Rust.
            abandonCreation()
            _state.value = VaultState.Creating
            var pending = 0L
            try {
                pending = ChurVault.beginCreation(runtime, password)
                val secret = if (offerRecovery) ChurVault.creationAddRecoverySlot(pending) else null
                if (secret == null) {
                    activate(pending)
                } else {
                    creation = pending
                    phraseShownAtMs = clock()
                }
                pending = 0L
                secret
            } catch (failure: ChurFailure) {
                // §9 of the descriptor format: a creation that does not reach
                // ACTIVE leaves nothing openable, and abandoning is how.
                if (pending != 0L) {
                    runCatching { ChurVault.abandonCreation(pending) }
                }
                // The failure itself reaches the user as the thrown status.
                _state.value = closedState(failure.status)
                throw failure
            }
        }

    /**
     * Commits what the recovery phrase on screen belongs to, `RECOVERY.md` §8.
     *
     * A creation waiting at step 5 of `PROVISIONING.md` §3 reaches `ACTIVE`,
     * and a slot [beginRecoverySlot] staged is written in place of every
     * earlier recovery slot, so the old phrase stops working. It returns `false`
     * when nothing waits, because a lock already discarded what the phrase
     * belonged to and the phrase opens nothing.
     */
    suspend fun confirmRecoveryPhrase(): Boolean = mutex.withLock {
        when {
            creation != 0L -> {
                val pending = creation
                creation = 0L
                try {
                    activate(pending)
                } catch (failure: ChurFailure) {
                    runCatching { ChurVault.abandonCreation(pending) }
                    _state.value = closedState(failure.status)
                    throw failure
                }
                true
            }
            recoveryStaged && session != 0L -> {
                recoveryStaged = false
                ChurVault.commitRecoverySlot(session)
                touch()
                true
            }
            else -> false
        }
    }

    /** Unlocks with a password, `KEY_SLOTS.md` §8. */
    suspend fun unlock(password: ByteArray) = mutex.withLock {
        requireRuntime()
        openSession { ChurVault.unlockWithPassword(runtime, password) }
    }

    /** Unlocks with the recovery phrase, `RECOVERY.md`. */
    suspend fun unlockWithRecovery(phrase: ByteArray) = mutex.withLock {
        requireRuntime()
        openSession { ChurVault.unlockWithRecovery(runtime, phrase) }
    }

    /** Unlocks with a `DeviceUnlockSecret` the platform keystore returned. */
    suspend fun unlockWithDeviceSecret(secret: ByteArray) = mutex.withLock {
        requireRuntime()
        openSession { ChurVault.unlockWithDeviceSecret(runtime, secret) }
    }

    /** Promote a close already waiting for the editor to a panic close. */
    fun requestPanicLock() {
        panicGeneration.value = (_state.value as? VaultState.Unlocked)?.generation
    }

    /**
     * Locks the session, `PLAINTEXT_LIFECYCLE.md` §8.
     *
     * It is idempotent, because every trigger can fire while another already
     * has: the panic gesture during a background transition is the case the
     * product expects rather than the case it forbids.
     */
    suspend fun lock(reason: LockReason) = mutex.withLock { lockSession(reason) }

    private fun lockSession(reason: LockReason) {
        // `PROVISIONING.md` §4 commits nothing the user has not confirmed. A
        // slot staged on the session closes with it, and a creation waiting
        // for its phrase is abandoned, which §3 says leaves no openable vault.
        // Every lock also clears the phrase from the screen, so no slot
        // outlives the phrase that opens it.
        endSession(reason)
        if (abandonCreation()) {
            _state.value = closedState()
            return
        }
        // `Locked` says a vault exists. Every trigger can fire before the
        // user has created one, and the background lock does on a first run
        // that leaves the application; the vault entry then routes to the
        // unlock screen of a vault that is not there. No vault means nothing
        // to lock, so the state stays what `start` found.
        if (_state.value !is VaultState.NoVault) {
            _state.value = VaultState.Locked()
        }
    }

    /**
     * Locks when the policy says the session has been idle too long.
     *
     * While a recovery phrase waits for confirmation the limit is
     * [LockPolicy.RECOVERY_PHRASE_TIMEOUT_MS] from when it appeared, whatever
     * refreshed the idle clock since: copying it outlasts the default, and
     * `DESIGN.md` §17.2 bounds how long a full credential stays on a screen
     * that is kept awake. A waiting creation holds a root too.
     *
     * Without [beforeClose], the decision, [beforeLock], and the close hold
     * the mutex together. With it, [beforeLock] runs after the decision and
     * [beforeClose] after [beforeLock], both outside the mutex, because
     * [beforeClose] writes through this repository: a save takes the mutex
     * and refreshes the idle clock. The close then keeps the decision when
     * the same session is still open, and it runs whatever [beforeClose]
     * does. The result is `true` when [beforeLock] ran.
     */
    suspend fun lockIfIdle(
        beforeClose: (suspend () -> Unit)? = null,
        beforeLock: suspend () -> Unit = {},
    ): Boolean {
        if (beforeClose != null) {
            val decided = mutex.withLock { if (idleDue()) generation else null } ?: return false
            beforeLock()
            val interrupted = try {
                beforeClose()
                null
            } catch (failure: Throwable) {
                failure
            }
            withContext(NonCancellable) {
                mutex.withLock {
                    if (generation == decided && (session != 0L || creation != 0L)) lockSession(LockReason.TIMEOUT)
                }
            }
            interrupted?.let { throw it }
            return true
        }
        mutex.lock()
        try {
            return idleDue() && lockIdle(beforeLock)
        } finally {
            mutex.unlock()
        }
    }

    private fun idleDue(): Boolean {
        val decision = if (creation != 0L || recoveryStaged) {
            idleDecision(LockPolicy(LockPolicy.RECOVERY_PHRASE_TIMEOUT_MS), phraseShownAtMs, clock())
        } else {
            idleDecision(policy, lastUsedMs, clock())
        }
        return (session != 0L || creation != 0L) && decision == LockDecision.LOCK
    }

    private suspend fun lockIdle(beforeLock: suspend () -> Unit): Boolean {
        if (session == 0L && creation == 0L) return false
        beforeLock()
        lockSession(LockReason.TIMEOUT)
        return true
    }

    /**
     * Replaces the idle limit with the auto-lock choice of `DESIGN.md` §14.4.
     *
     * The choice counts as use, so a shorter limit counts from the choice and
     * does not lock at once a session that sat on the settings screen longer
     * than the new limit.
     */
    suspend fun setIdleTimeout(idleTimeoutMs: Long) = mutex.withLock {
        policy = policy.copy(idleTimeoutMs = idleTimeoutMs)
        if (session != 0L) touch()
    }

    /** Locks when the application leaves the foreground, if the policy says so. */
    suspend fun onBackground() {
        if (policy.lockOnBackground) {
            lock(LockReason.BACKGROUND)
        }
    }

    /** Closes everything, which a process shutdown does. */
    suspend fun shutdown() = mutex.withLock {
        if (runtime != 0L) {
            // A waiting creation's vault directory goes now rather than at
            // the next open, where the runtime sweeps it with the temporary
            // descriptor, `PROVISIONING.md` §9.
            abandonCreation()
            recoveryStaged = false
            runCatching { ChurVault.closeRuntime(runtime) }
            runtime = 0L
            session = 0L
        }
        _state.value = VaultState.Starting
    }

    // -----------------------------------------------------------------------
    // The library, each call guarded and each one refreshing the idle clock
    // -----------------------------------------------------------------------

    /** One page of a scope. */
    suspend fun page(query: ObjectQuery): ObjectPage = withSession { ChurVault.query(it, query) }

    /** One object's detail record. */
    suspend fun detail(objectId: ByteArray): ObjectDetail =
        withSession { ChurVault.detail(it, objectId) }

    /** Sets or clears the favourite flag. */
    suspend fun setFavorite(objectId: ByteArray, favorite: Boolean) =
        withSession { ChurVault.setFavorite(it, objectId, favorite) }

    suspend fun setFavorites(objectIds: List<ByteArray>, favorite: Boolean) =
        withSession { ChurVault.setFavorites(it, objectIds, favorite) }

    /** Moves an object to trash. */
    suspend fun delete(objectId: ByteArray) = withSession { ChurVault.deleteObject(it, objectId) }

    suspend fun deleteAll(objectIds: List<ByteArray>) =
        withSession { ChurVault.deleteObjects(it, objectIds) }

    suspend fun restoreAll(objectIds: List<ByteArray>) =
        withSession { ChurVault.restoreObjects(it, objectIds) }

    suspend fun permanentlyDelete(objectId: ByteArray) =
        withSession { ChurVault.permanentlyDeleteObject(it, objectId) }

    suspend fun deleteDamagedFiles() = withSession { ChurVault.deleteDamagedFiles(it) }

    suspend fun emptyTrash() = withSession { ChurVault.emptyTrash(it) }

    suspend fun restoreTrash() = withSession { ChurVault.restoreTrash(it) }

    suspend fun beginSelectiveExport(generation: Long, objectIds: List<ByteArray>, albumIds: List<ByteArray>, notes: List<PrivateNoteSelection>, password: ByteArray, destinationFd: Int, maxOutputBytes: Long = Long.MAX_VALUE): Long = withNoteSession(generation) { ChurVault.beginSelectiveExport(it, objectIds, albumIds, notes, password, destinationFd, maxOutputBytes) }
    suspend fun beginSelectiveImport(generation: Long, sourceFd: Int, password: ByteArray): Long = withNoteSession(generation) { ChurVault.beginSelectiveImport(it, sourceFd, password) }

    /** A stale editor must not access a later unlocked identity. */
    suspend fun privateNotes(generation: Long, terms: String = "", trashed: Boolean = false, limit: Int = 50, cursor: ByteArray? = null): PrivateNotePage = withNoteSession(generation) { ChurVault.privateNotes(it, terms, trashed, limit, cursor) }
    suspend fun privateNoteDraft(generation: Long) = withNoteSession(generation, noteActivity = false) { ChurVault.privateNoteDraft(it) }
    suspend fun writePrivateNoteDraft(generation: Long, draft: dev.po4yka.chur.ffi.PrivateNoteDraft?) =
        withNoteSession(generation, noteActivity = false) { ChurVault.writePrivateNoteDraft(it, draft) }
    suspend fun privateNote(generation: Long, id: ByteArray): PrivateNote = withNoteSession(generation) { ChurVault.privateNote(it, id) }
    /**
     * A lock-time save passes [proceed]. It is checked under the mutex just
     * before the native call, so a save the lock no longer waits for never
     * starts.
     */
    suspend fun savePrivateNote(generation: Long, id: ByteArray? = null, expectedRevision: Long = 0, title: String, body: String, pinned: Boolean = false, format: PrivateNoteFormat = PrivateNoteFormat.PLAIN_TEXT, proceed: () -> Boolean = { true }, preserveDraft: Boolean = false): PrivateNote = withNoteSession(generation) {
        if (!proceed()) throw ChurFailure(ChurStatus.VAULT_LOCKED, "the lock no longer waits for this save")
        if (preserveDraft) {
            ChurVault.writePrivateNoteDraft(it, dev.po4yka.chur.ffi.PrivateNoteDraft(id, expectedRevision, title, body, pinned, format))
            if (!proceed()) throw ChurFailure(ChurStatus.VAULT_LOCKED, "the lock no longer waits for this save")
        }
        val saved = ChurVault.savePrivateNote(it, id, expectedRevision, title, body, pinned, format)
        if (preserveDraft) ChurVault.writePrivateNoteDraft(it, null)
        saved
    }
    suspend fun changePrivateNote(generation: Long, id: ByteArray, expectedRevision: Long, action: PrivateNoteAction): PrivateNote? = withNoteSession(generation) { ChurVault.changePrivateNote(it, id, expectedRevision, action) }
    suspend fun beginPrivateNoteExport(generation: Long, id: ByteArray, expectedRevision: Long, destinationFd: Int): Long = withNoteSession(generation) { ChurVault.beginPrivateNoteExport(it, id, expectedRevision, destinationFd) }
    suspend fun privateNoteAttachments(generation: Long, id: ByteArray): List<PrivateNoteAttachment> = withNoteSession(generation) { ChurVault.privateNoteAttachments(it,id) }
    suspend fun readPrivateNoteAttachment(generation: Long, id: ByteArray, attachmentId: ByteArray): ByteArray = withNoteSession(generation) { ChurVault.readPrivateNoteAttachment(it,id,attachmentId) }
    suspend fun putPrivateNoteAttachment(generation: Long, id: ByteArray, expectedRevision: Long, attachment: PrivateNoteAttachmentData): PrivateNote = withNoteSession(generation) { ChurVault.putPrivateNoteAttachment(it,id,expectedRevision,attachment) }
    suspend fun removePrivateNoteAttachment(generation: Long, id: ByteArray, expectedRevision: Long, attachmentId: ByteArray): PrivateNote = withNoteSession(generation) { ChurVault.removePrivateNoteAttachment(it,id,expectedRevision,attachmentId) }
    suspend fun importPrivateNotePackage(generation: Long, title: String, body: String, format: PrivateNoteFormat, attachments: List<PrivateNoteAttachmentData>): PrivateNote = withNoteSession(generation) { ChurVault.importPrivateNotePackage(it,title,body,format,attachments) }
    suspend fun beginPrivateNoteAttachmentExport(
        generation: Long,
        id: ByteArray,
        expectedRevision: Long,
        attachmentId: ByteArray,
        destinationFd: Int,
    ): Long = withNoteSession(generation) {
        ChurVault.beginPrivateNoteAttachmentExport(it, id, expectedRevision, attachmentId, destinationFd)
    }
    suspend fun privateNoteActivity(generation: Long) { withNoteSession(generation) { Unit } }

    suspend fun privateNoteOrganization(generation: Long, id: ByteArray): dev.po4yka.chur.ffi.PrivateNoteOrganization =
        withNoteSession(generation) { ChurVault.privateNoteOrganization(it, id) }
    suspend fun organizePrivateNote(generation: Long, id: ByteArray, revision: Long, organization: dev.po4yka.chur.ffi.PrivateNoteOrganization): PrivateNote =
        withNoteSession(generation) { ChurVault.organizePrivateNote(it, id, revision, organization) }
    suspend fun privateNoteHistory(generation: Long, id: ByteArray): List<dev.po4yka.chur.ffi.PrivateNoteRevision> =
        withNoteSession(generation) { ChurVault.privateNoteHistory(it, id) }
    suspend fun privateNoteRevision(generation: Long, id: ByteArray, revision: Long): dev.po4yka.chur.ffi.PrivateNoteRevisionDetail =
        withNoteSession(generation) { ChurVault.privateNoteRevision(it, id, revision) }
    suspend fun restorePrivateNoteRevision(generation: Long, id: ByteArray, expectedRevision: Long, historicalRevision: Long): PrivateNote =
        withNoteSession(generation) { ChurVault.restorePrivateNoteRevision(it, id, expectedRevision, historicalRevision) }
    suspend fun privateNoteWorkspace(generation: Long, terms: String, trashed: Boolean, limit: Int, cursor: ByteArray?, folder: String, tag: String): dev.po4yka.chur.ffi.PrivateNoteWorkspacePage =
        withNoteSession(generation) { ChurVault.privateNoteWorkspace(it, terms, trashed, limit, cursor, folder, tag) }

    /** An old indexing job must never read or write a later unlocked identity. */
    suspend fun contentIndexCandidates(generation: Long, afterId: ByteArray? = null, rebuild: Boolean = false, limit: Int = 25): List<ContentIndexCandidate> =
        withGenerationSession(generation) { ChurVault.contentIndexCandidates(it, afterId, rebuild, limit) }

    suspend fun putContentIndex(generation: Long, candidate: ContentIndexCandidate, text: ByteArray, partial: Boolean) =
        withGenerationSession(generation) { ChurVault.putContentIndex(it, candidate, text, partial) }

    suspend fun clearContentIndex(generation: Long) =
        withGenerationSession(generation) { ChurVault.clearContentIndex(it) }

    /** Rust invalidates this lease on lock; the caller releases it in finally. */
    suspend fun leaseContentIndexReader(generation: Long, objectId: ByteArray): Long =
        withGenerationSession(generation) { ChurVault.openReader(it, objectId, StreamKind.ORIGINAL) }

    /** Every album. */
    suspend fun albums(): List<AlbumSummary> = withSession { ChurVault.albums(it) }

    /** Creates an album. */
    suspend fun createAlbum(name: String, requestedId: ByteArray? = null): ByteArray =
        withSession { ChurVault.createAlbum(it, name, requestedId) }

    suspend fun renameAlbum(albumId: ByteArray, name: String) =
        withSession { ChurVault.renameAlbum(it, albumId, name) }

    suspend fun deleteAlbum(albumId: ByteArray) =
        withSession { ChurVault.deleteAlbum(it, albumId) }

    suspend fun moveAlbum(albumId: ByteArray, parentId: ByteArray?, beforeId: ByteArray?) =
        withSession { ChurVault.moveAlbum(it, albumId, parentId, beforeId) }

    suspend fun moveAlbumMember(albumId: ByteArray, objectId: ByteArray, beforeId: ByteArray?) =
        withSession { ChurVault.moveAlbumMember(it, albumId, objectId, beforeId) }

    /** Adds or removes one album membership. */
    suspend fun setAlbumMembership(albumId: ByteArray, objectId: ByteArray, member: Boolean) =
        withSession { ChurVault.setAlbumMembership(it, albumId, objectId, member) }

    suspend fun removeAlbumObjects(
        albumId: ByteArray,
        objectIds: List<ByteArray>,
        expectedGeneration: Long? = null,
    ) = withSession(expectedGeneration) { ChurVault.removeAlbumObjects(it, albumId, objectIds) }

    suspend fun placeAlbumObjects(
        targetId: ByteArray?,
        newName: String,
        parentId: ByteArray?,
        sourceId: ByteArray?,
        objectIds: List<ByteArray>,
        moveMembers: Boolean,
        expectedGeneration: Long? = null,
    ): ByteArray = withSession(expectedGeneration) {
        ChurVault.placeAlbumObjects(it, targetId, newName, parentId, sourceId, objectIds, moveMembers)
    }

    /** Creates a tag. */
    suspend fun createTag(name: String): ByteArray = withSession { ChurVault.createTag(it, name) }

    /** Every tag available in the private catalog. */
    suspend fun tags(): List<TagSummary> = withSession { ChurVault.tags(it) }

    /** Applies or removes one tag. */
    suspend fun setObjectTag(tagId: ByteArray, objectId: ByteArray, tagged: Boolean) =
        withSession { ChurVault.setObjectTag(it, tagId, objectId, tagged) }

    suspend fun applyTagSelection(tagId: ByteArray?, newName: String,
                                  objectIds: List<ByteArray>, tagged: Boolean): ByteArray =
        withSession { ChurVault.applyTagSelection(it, tagId, newName, objectIds, tagged) }

    suspend fun renameTag(tagId: ByteArray, name: String) =
        withSession { ChurVault.renameTag(it, tagId, name) }

    suspend fun deleteTag(tagId: ByteArray) = withSession { ChurVault.deleteTag(it, tagId) }

    /** The key slots, for the settings screen. */
    suspend fun slots(): List<SlotSummary> = withSession { ChurVault.slots(it) }

    /**
     * Stages a recovery slot and returns the phrase once, `RECOVERY.md` §8.
     *
     * Nothing commits until [confirmRecoveryPhrase]; a lock closes the session
     * and the staged slot with it.
     */
    suspend fun beginRecoverySlot(): String = withSession { current ->
        ChurVault.beginRecoverySlot(current).also {
            recoveryStaged = true
            phraseShownAtMs = clock()
        }
    }

    /** Adds the platform device slot and returns the secret to store. */
    suspend fun addDeviceSlot(keychainItemId: ByteArray): ByteArray =
        withSession { ChurVault.addDeviceSlot(it, keychainItemId) }

    /** Adds a Keychain slot and removes it if the platform cannot keep its secret. */
    suspend fun enrollAppleSlot(
        keychainItemId: ByteArray,
        store: (ByteArray) -> Unit,
    ) = withSession { session ->
        val before = ChurVault.slots(session).map { it.id }.toSet()
        val secret = ChurVault.addDeviceSlot(session, keychainItemId)
        try {
            store(secret)
        } catch (failure: Throwable) {
            ChurVault.slots(session)
                .firstOrNull { it.slotType == 3 && it.id !in before }
                ?.let { slot ->
                    try {
                        // A conflict means this item existed before enrollment.
                        val itemToDelete = if (
                            failure is ChurFailure && failure.status == ChurStatus.CONFLICT
                        ) null else keychainItemId
                        removeSlotInSession(session, slot.slotId, itemToDelete)
                    } catch (cleanup: Throwable) {
                        cleanup.addSuppressed(failure)
                        throw cleanup
                    }
                }
            throw failure
        } finally {
            secret.fill(0)
        }
    }

    /**
     * Enrolls the Android Keystore slot, `KEY_SLOTS.md` §4.
     *
     * The enrollment is one repository call rather than two because the vault
     * must not be left holding a pending enrollment: [wrap] runs between the
     * two boundary calls and a failure in it abandons the enrollment instead of
     * committing half of one.
     *
     * [wrap] receives the AAD and the vault root and returns the nonce and the
     * wrapped bytes the Keystore produced. It must not keep either argument.
     */
    suspend fun enrollKeystoreSlot(
        wrap: suspend (
            alias: ByteArray,
            aad: ByteArray,
            rootSecret: ByteArray,
        ) -> Pair<ByteArray, ByteArray>,
    ) = withSession { session ->
        val enrollment = ChurVault.beginKeystoreSlot(session)
        var platformWrapped = false
        try {
            val (nonce, wrappedRoot) = wrap(enrollment.alias, enrollment.aad, enrollment.rootSecret)
            platformWrapped = true
            ChurVault.commitKeystoreSlot(session, nonce, wrappedRoot)
        } catch (failure: Throwable) {
            if (platformWrapped) {
                try {
                    // A descriptor install can succeed before its relock fails.
                    // Keep a key that a committed slot still references.
                    val committed = ChurVault.slots(session)
                        .filter { it.slotType == 2 }
                        .any { ChurVault.platformSlotIdentifier(session, it.slotId)
                            .contentEquals(enrollment.alias) }
                    if (!committed) deletePlatformSlot(enrollment.alias)
                } catch (cleanup: Throwable) {
                    cleanup.addSuppressed(failure)
                    throw cleanup
                }
            }
            throw failure
        } finally {
            enrollment.rootSecret.fill(0)
        }
    }

    /** What every enrolled Keystore slot needs for its unwrap, while locked. */
    suspend fun keystoreMaterial(): List<KeystoreMaterial> = mutex.withLock {
        requireRuntime()
        ChurVault.keystoreMaterial(runtime)
    }

    /** Unlocks with the root an Android Keystore unwrap returned. */
    suspend fun unlockWithKeystoreRoot(rootSecret: ByteArray) = mutex.withLock {
        requireRuntime()
        try {
            openSession { ChurVault.unlockWithKeystoreRoot(runtime, rootSecret) }
        } finally {
            rootSecret.fill(0)
        }
    }

    /** Removes one slot, then deletes its platform key or secret if it has one. */
    suspend fun removeSlot(slotId: ByteArray) = withSession { session ->
        val family = ChurVault.slots(session)
            .firstOrNull { it.slotId.contentEquals(slotId) }
            ?.slotType
        val identifier = if (family == 2 || family == 3) {
            ChurVault.platformSlotIdentifier(session, slotId)
        } else {
            null
        }
        removeSlotInSession(session, slotId, identifier)
    }

    private fun removeSlotInSession(session: Long, slotId: ByteArray, identifier: ByteArray?) {
        var removalFailure: Throwable? = null
        try {
            ChurVault.removeSlot(session, slotId)
        } catch (failure: Throwable) {
            removalFailure = failure
        }
        val stillPresent = ChurVault.slots(session).any { it.slotId.contentEquals(slotId) }
        if (!stillPresent && identifier != null) {
            try {
                deletePlatformSlot(identifier)
            } catch (cleanup: Throwable) {
                removalFailure?.let(cleanup::addSuppressed)
                throw cleanup
            }
        }
        removalFailure?.let { throw it }
        check(!stillPresent) { "the vault did not remove the slot" }
    }

    private fun deletePlatformSlot(identifier: ByteArray) {
        try {
            destroyPlatformSlot(identifier)
        } catch (failure: DeviceSlotException) {
            throw ChurFailure(failure.status, "platform slot cleanup")
        }
    }

    /** Replaces the password slot. */
    suspend fun changePassword(password: ByteArray) =
        withSession { ChurVault.changePassword(it, password) }

    /** Stores a derivative the platform produced. */
    suspend fun putDerived(
        objectId: ByteArray,
        kind: StreamKind,
        width: Int,
        height: Int,
        bytes: ByteArray,
        expectedGeneration: Long? = null,
    ) = withSession(expectedGeneration) { ChurVault.putDerived(it, objectId, kind, width, height, bytes) }

    /** Reads a derivative, which the timeline does for every visible row. */
    suspend fun readDerived(objectId: ByteArray, kind: StreamKind, expectedGeneration: Long? = null): ByteArray =
        withSession(expectedGeneration) { ChurVault.readDerived(it, objectId, kind) }

    /** Resume state remains inside the generation-bound encrypted catalog. */
    suspend fun playbackPosition(objectId: ByteArray, expectedGeneration: Long): Long =
        withGenerationSession(expectedGeneration) { ChurVault.playbackPosition(it, objectId) }

    suspend fun savePlaybackPosition(objectId: ByteArray, positionMs: Long, durationMs: Long, expectedGeneration: Long) =
        withGenerationSession(expectedGeneration) { ChurVault.savePlaybackPosition(it, objectId, positionMs, durationMs) }

    /** Reads a plaintext range of the original. */
    suspend fun readRange(objectId: ByteArray, offset: Long, length: Int): ByteArray =
        withSession { current ->
            val reader = ChurVault.openReader(current, objectId, StreamKind.ORIGINAL)
            try {
                ChurVault.readRange(reader, offset, length)
            } finally {
                runCatching { ChurVault.closeReader(reader) }
            }
        }

    // -----------------------------------------------------------------------
    // Reader leases, for a player
    // -----------------------------------------------------------------------

    /**
     * Opens a reader a player holds across many seeks, `FFI_CONTRACT.md` §6.3.
     *
     * [readRange] opens and closes one reader per call, which suits a single
     * range and is the wrong shape for playback: a player seeks continuously,
     * and re-authenticating the manifest on every range would serialize every
     * seek against every catalog query on this class's one mutex.
     *
     * A lease is taken under the mutex, because it needs the session handle,
     * and is then used without it. §8's table permits exactly that: a reader
     * handle is callable from any thread including one other than its creator,
     * and it names "a Media3 loader thread and an `AVAssetResourceLoader`
     * queue" as the callers it has in mind.
     *
     * A lease never outlives the session it came from, and this class does not
     * arrange that: `PLAINTEXT_LIFECYCLE.md` §8 step 2 invalidates every session
     * handle on lock, and `chur_vault_lock` does it by draining every handle the
     * session owns, of which a reader is one. Tracking the leases here as well
     * would add a second owner of the same fact and a set mutated from a player
     * thread and a lock at once; the caller [releaseReader]s what it took, and a
     * call on a handle the lock already closed is `SESSION_EXPIRED`.
     */
    suspend fun leaseReader(objectId: ByteArray, kind: StreamKind = StreamKind.ORIGINAL, expectedGeneration: Long? = null): Long =
        withSession(expectedGeneration) { current -> ChurVault.openReader(current, objectId, kind) }

    /**
     * The content information a player needs before its first range request.
     *
     * `FFI_CONTRACT.md` §6.1 forbids attaching a reader on an incomplete object
     * to a player, because a player that has been given a length treats a later
     * failure as a transport error and retries indefinitely. The caller checks
     * [ContentInfo.complete] before it does.
     */
    fun readerContentInfo(reader: Long): ContentInfo = ChurVault.readerContentInfo(reader)

    /**
     * Reads a range through a leased reader, off the mutex.
     *
     * §6.3 permits a short read at any offset, and [ChurVault.readRange]
     * already loops until it has the range or observes zero.
     */
    fun readLeased(reader: Long, offset: Long, length: Int): ByteArray =
        ChurVault.readRange(reader, offset, length)

    /**
     * Fills [destination] with a leased object from its start, off the mutex.
     *
     * For a small object a platform decoder needs whole: the bytes go straight
     * into the caller's native buffer, never a Kotlin array, [ChurVault.readInto].
     */
    fun readLeasedInto(reader: Long, destination: ChurBuffer, sourceOffset: Long = 0) =
        ChurVault.readInto(reader, destination, sourceOffset)

    /**
     * Closes one lease.
     *
     * It takes no lock and swallows the failure, because both of the things
     * that can go wrong here are ordinary: closing a handle twice is idempotent
     * inside Rust, and closing one a lock already invalidated is
     * `SESSION_EXPIRED`. A player releases on a thread of its own choosing and
     * must not block behind a catalog query to do it.
     */
    fun releaseReader(reader: Long) {
        runCatching { ChurVault.closeReader(reader) }
    }

    /** Starts an import from a descriptor the platform opened. */
    suspend fun beginImport(sourceFd: Int, request: ImportRequest, expectedGeneration: Long? = null): Long =
        withSession(expectedGeneration) { ChurVault.beginImport(it, sourceFd, request) }

    /** Starts an export to a descriptor the platform opened. */
    suspend fun beginExport(objectId: ByteArray, destinationFd: Int): Long =
        withSession { ChurVault.beginExport(it, objectId, destinationFd) }

    /**
     * Starts one re-encryption pass after a revocation, ADR-0069. It runs
     * only while the vault is open, and a lock cancels it.
     */
    suspend fun beginReencryption(): Long = withQuietSession { ChurVault.beginReencryption(it) }

    /**
     * The objects still to re-encrypt and the objects that cannot be
     * re-encrypted now. Like the pass itself, the call is background work
     * and does not count as activity for the auto-lock.
     */
    suspend fun reencryptionCounts(): dev.po4yka.chur.ffi.ReencryptionCounts =
        withQuietSession { ChurVault.reencryptionCounts(it) }

    /** Starts an integrity scan; a null identifier scans every object. */
    suspend fun beginIntegrityScan(objectId: ByteArray?): Long =
        withSession { ChurVault.beginIntegrityScan(it, objectId) }

    /**
     * Starts writing a backup package to a descriptor the platform opened,
     * `BACKUP_FORMAT_V1.md` §7.
     */
    suspend fun beginBackup(destinationFd: Int): Long =
        withSession { ChurVault.beginBackup(it, destinationFd) }

    /**
     * Starts restoring a package, §8.
     *
     * It takes no session: a restore installs an identity, so it runs from the
     * runtime and the credential comes from the package's own descriptor.
     */
    suspend fun beginRestore(sourceFd: Int, password: ByteArray): Long = mutex.withLock {
        requireRuntime()
        ChurVault.beginRestore(runtime, sourceFd, password)
    }

    /** Encrypts external files without opening or changing the local vault. */
    suspend fun beginExternalArchive(
        files: List<ExternalArchiveFile>,
        password: ByteArray,
        destinationFd: Int,
        maxOutputBytes: Long = Long.MAX_VALUE,
    ): Long = mutex.withLock {
        requireRuntime()
        ChurVault.beginExternalArchive(runtime, files, password, destinationFd, maxOutputBytes)
    }

    /** One nonblocking snapshot. Set [noteActivity] false for work outside the vault. */
    fun poll(operation: Long, noteActivity: Boolean = true): OperationProgress {
        val progress = ChurVault.poll(operation)
        if (noteActivity && !progress.terminal && mutex.tryLock()) {
            try {
                if (session != 0L) touch()
            } finally {
                mutex.unlock()
            }
        }
        return progress
    }

    /**
     * Counts running work as use, as [poll] does for the part of it in Rust.
     *
     * An operation also has phases on the host that call nothing here: the
     * iOS fetch of an iCloud original, the opening of a picked item, and the
     * making of its previews. The controller calls this while such work runs,
     * so the auto-lock choice of `DESIGN.md` §14.4 does not lock the vault in
     * the middle of it.
     */
    suspend fun noteActivity() = mutex.withLock {
        if (session != 0L) touch()
    }

    /** Asks an operation to stop, §9. Callable at any time, like poll. */
    fun cancel(operation: Long) = ChurVault.cancel(operation)

    /** Closes an operation handle, waiting for its worker. */
    fun closeOperation(operation: Long) = ChurVault.closeOperation(operation)

    // -----------------------------------------------------------------------
    // Sync, `docs/sync/SYNC_PROTOCOL_V1.md` §5 and §7
    // -----------------------------------------------------------------------

    /**
     * Stages one downloaded record into the native locked inbox.
     *
     * Staging needs the runtime and not the session, §7, so this runs while the
     * vault is locked: the background schedule calls it from the sync engine,
     * and the inbox the records land in is native state no Kotlin caller reads.
     */
    suspend fun stageSyncRecord(
        vaultId: ByteArray,
        kind: SyncRecordKind,
        stagedAtMs: Long,
        record: ByteArray,
    ) = mutex.withLock {
        requireRuntime()
        ChurVault.stageSync(runtime, vaultId, kind, stagedAtMs, record)
    }

    /**
     * Validates and applies the retained inbox on the open session.
     *
     * §7: "Decrypted application occurs after explicit unlock", so this is
     * `null` while locked and the caller treats a `null` as "not yet" rather
     * than as a failure. The report carries only counts, which §10 of the FFI
     * contract lets a surface show.
     */
    suspend fun processSync(): SyncProcessReport? = mutex.withLock {
        if (session == 0L) null else ChurVault.processSync(session, clock())
    }

    suspend fun syncHeads(): List<dev.po4yka.chur.ffi.SyncDeviceHead>? = mutex.withLock {
        if (session == 0L) null else ChurVault.syncHeads(session)
    }

    suspend fun ownSyncCollections(): List<ByteArray>? = mutex.withLock {
        if (session == 0L) null else ChurVault.ownSyncCollections(session)
    }

    suspend fun ownSyncOperations(after: ULong): List<dev.po4yka.chur.ffi.OwnSyncOperation>? = mutex.withLock {
        if (session == 0L) null else ChurVault.ownSyncOperations(session, after)
    }

    suspend fun ownSyncPlan(collectionId: ByteArray): SharedReceivePlan? = mutex.withLock {
        if (session == 0L) null else ChurVault.ownSyncPlan(session, collectionId)
    }

    suspend fun ownSyncAuthor(source: SharedSourceObject): SharedSourceObject? = mutex.withLock {
        if (session == 0L) null else ChurVault.ownSyncAuthor(session, source)
    }

    suspend fun peerCall(input: ByteArray): ByteArray = mutex.withLock {
        if (session == 0L) throw dev.po4yka.chur.ffi.ChurFailure(ChurStatus.VAULT_LOCKED, "peer requires an unlocked vault")
        ChurVault.peerCall(session, input)
    }

    suspend fun prepareDevicePairing(): dev.po4yka.chur.ffi.DevicePairingRequest? = mutex.withLock {
        if (session == 0L) null else ChurVault.prepareDevicePairing(session)
    }

    suspend fun inspectDevicePairing(request: ByteArray): dev.po4yka.chur.ffi.DevicePairingPreview? = mutex.withLock {
        if (session == 0L) null else ChurVault.inspectDevicePairing(session, request)
    }

    suspend fun approveDevicePairing(request: ByteArray, nowMs: Long): dev.po4yka.chur.ffi.PreparedDevicePairing? = mutex.withLock {
        if (session == 0L) null else ChurVault.approveDevicePairing(session, request, nowMs)
    }

    suspend fun startDevicePairing(approval: ByteArray): dev.po4yka.chur.ffi.DevicePairingCredentials? = mutex.withLock {
        if (session == 0L) null else ChurVault.startDevicePairing(session, approval)
    }

    suspend fun finishDevicePairing(nowMs: Long): ByteArray? = mutex.withLock {
        if (session == 0L) null else ChurVault.finishDevicePairing(session, nowMs)
    }

    suspend fun currentDeviceCheckpoint(nowMs: Long): ByteArray? = mutex.withLock {
        if (session == 0L) null else ChurVault.currentDeviceCheckpoint(session, nowMs)
    }


    suspend fun pairedDevices(): List<dev.po4yka.chur.ffi.PairedDevice>? = mutex.withLock {
        if (session == 0L) null else ChurVault.pairedDevices(session)
    }

    suspend fun prepareDeviceRevocation(deviceId: ByteArray, nowMs: Long): dev.po4yka.chur.ffi.PreparedDeviceRevocation? = mutex.withLock {
        if (session == 0L) null else ChurVault.prepareDeviceRevocation(session, deviceId, nowMs)
    }


    /**
     * The fork state the open vault's catalog keeps, or `null` while locked.
     *
     * `ROLLBACK_PROTECTION.md` §4 keeps it until it clears, so it outlives the
     * [processSync] pass that found the fork and the process that ran it.
     */
    suspend fun syncForkState(): SyncForkState? = mutex.withLock {
        if (session == 0L) null else ChurVault.syncForkState(session)
    }

    /**
     * Records that the user saw every detected fork, or returns `false` while
     * locked. §4 keeps each chain frozen: this changes what the user is told,
     * not what sync applies.
     */
    suspend fun acknowledgeSyncForks(): Boolean = mutex.withLock {
        if (session == 0L) {
            false
        } else {
            ChurVault.acknowledgeSyncForks(session)
            true
        }
    }

    /**
     * The identity this unlocked vault presents to an enrolled peer, or `null`
     * while locked. Native membership verification governs enrollment.
     */
    suspend fun syncIdentity(): SharingIdentity? = mutex.withLock {
        if (session == 0L) null else ChurVault.sharingIdentity(session)
    }

    suspend fun sharingOverview(): SharingOverview = mutex.withLock {
        require(session != 0L) { "the vault is locked" }
        ChurVault.sharingOverview(session)
    }

    suspend fun inspectEnrollment(enrollment: ByteArray): SharingRecipient =
        ChurVault.inspectEnrollment(enrollment)

    suspend fun prepareShare(
        collectionId: ByteArray,
        enrollment: ByteArray,
        permission: SharingPermission,
    ): PreparedShare = mutex.withLock {
        require(session != 0L) { "the vault is locked" }
        ChurVault.prepareShare(session, collectionId, enrollment, permission, true)
    }

    suspend fun revokeShare(
        collectionId: ByteArray,
        recipientVaultId: ByteArray,
        recipientDeviceId: ByteArray,
    ): PreparedShareRevocation = mutex.withLock {
        require(session != 0L) { "the vault is locked" }
        ChurVault.revokeShare(session, collectionId, recipientVaultId, recipientDeviceId, clock())
    }

    suspend fun acceptSharePackage(packageBytes: ByteArray): Boolean = mutex.withLock {
        if (session == 0L) false else {
            ChurVault.acceptSharePackage(session, packageBytes)
            true
        }
    }

    suspend fun objectKeyRequest(collectionId: ByteArray, objectId: ByteArray): ByteArray? = mutex.withLock {
        require(session != 0L) { "the vault is locked" }
        ChurVault.objectKeyRequest(session, collectionId, objectId)
    }

    suspend fun objectKeyAccept(packageBytes: ByteArray, grant: ByteArray): Boolean = mutex.withLock {
        if (session == 0L) false else {
            ChurVault.objectKeyAccept(session, packageBytes, grant)
            true
        }
    }

    suspend fun outboundCollectionOperations(after: ULong): List<dev.po4yka.chur.ffi.CollectionOutbound>? = mutex.withLock {
        if (session == 0L) null else ChurVault.outboundCollectionOperations(session, after)
    }

    suspend fun receiveSharedOperations(
        packageBytes: ByteArray,
        operations: List<ByteArray>,
    ): SharedReceivePlan? = mutex.withLock {
        if (session == 0L) null else ChurVault.receiveSharedOperations(session, packageBytes, operations)
    }

    suspend fun sourceCollectionId(): ByteArray? = mutex.withLock {
        if (session == 0L) null else ChurVault.sharingOverview(session)
            .takeIf { it.members.isNotEmpty() }?.collectionId
    }

    suspend fun sourcePage(collectionId: ByteArray, afterObjectId: ByteArray): List<SharedSourceObject>? = mutex.withLock {
        if (session == 0L) null else ChurVault.sharedSourcePage(session, collectionId, afterObjectId)
    }

    suspend fun sourceAuthor(source: SharedSourceObject): SharedSourceObject? = mutex.withLock {
        if (session == 0L) null else ChurVault.sharedSourceAuthor(session, source)
    }

    suspend fun sharedDownloadOffset(collectionId: ByteArray, objectId: ByteArray): ULong? = mutex.withLock {
        if (session == 0L) null else ChurVault.sharedDownloadOffset(session, collectionId, objectId)
    }

    suspend fun appendSharedDownload(
        collectionId: ByteArray,
        objectId: ByteArray,
        offset: ULong,
        bytes: ByteArray,
    ): Boolean = mutex.withLock {
        if (session == 0L) false else {
            ChurVault.appendSharedDownload(session, collectionId, objectId, offset, bytes)
            true
        }
    }

    suspend fun finishSharedDownload(
        collectionId: ByteArray,
        objectId: ByteArray,
        nowMs: Long,
    ): Boolean = mutex.withLock {
        if (session == 0L) false else {
            ChurVault.finishSharedDownload(session, collectionId, objectId, nowMs)
            true
        }
    }

    // -----------------------------------------------------------------------

    private fun requireRuntime() {
        if (runtime == 0L) {
            throw ChurFailure(ChurStatus.INTERNAL_FAILURE, "the runtime is not open")
        }
    }

    private inline fun openSession(open: () -> Long) {
        // One runtime shares one session, §8.1 of `docs/interop/FFI_CONTRACT.md`.
        // An unlock can find one open when a host showed the public shell over
        // it, and replacing the handle would leave that session unlocked in
        // Rust, with its root, keys and catalog, beyond every later lock. It
        // is ended first, as `create` ends it; §8 of `PLAINTEXT_LIFECYCLE.md`
        // is that transition. A creation waiting for its phrase is abandoned
        // for the same reason: its activation would assign over this session.
        endSession(LockReason.USER)
        abandonCreation()
        try {
            session = open()
            generation += 1
            touch()
            _state.value = VaultState.Unlocked(generation)
        } catch (failure: ChurFailure) {
            _state.value = VaultState.Locked(failure.status)
            throw failure
        }
    }

    private fun touch() {
        lastUsedMs = clock()
    }

    /**
     * Opens the session a creation reached `ACTIVE` with, step 6 of §3.
     *
     * One runtime shares one session, §8.1 of `docs/interop/FFI_CONTRACT.md`,
     * so a session still open here is ended first rather than assigned over.
     */
    private fun activate(pending: Long) {
        endSession(LockReason.USER)
        session = ChurVault.activateCreation(pending)
        generation += 1
        touch()
        _state.value = VaultState.Unlocked(generation)
    }

    /**
     * Locks and closes the open session, if there is one, and with it the
     * recovery slot staged on it, `PLAINTEXT_LIFECYCLE.md` §8.
     */
    private fun endSession(reason: LockReason) {
        if (session != 0L) {
            val initialReason = if (panicGeneration.value == generation) LockReason.PANIC else reason
            runCatching { ChurVault.lock(session, initialReason) }
            if (initialReason != LockReason.PANIC && panicGeneration.value == generation) {
                runCatching { ChurVault.lock(session, LockReason.PANIC) }
            }
            panicGeneration.compareAndSet(generation, null)
            runCatching { ChurVault.closeSession(session) }
            session = 0L
        }
        recoveryStaged = false
    }

    /**
     * Abandons the creation waiting for its phrase, if there is one.
     *
     * §9 of the descriptor format: a creation that does not reach `ACTIVE`
     * leaves nothing openable, and abandoning is how.
     */
    private fun abandonCreation(): Boolean {
        if (creation == 0L) return false
        runCatching { ChurVault.abandonCreation(creation) }
        creation = 0L
        return true
    }

    /**
     * The state when no session is open.
     *
     * A stopped first creation leaves no vault, and `Locked` would put the
     * unlock screen in front of nothing, as in [lockSession]. The disk decides;
     * a check that cannot answer keeps `Locked`.
     */
    private fun closedState(failure: ChurStatus? = null): VaultState {
        val present = runCatching { ChurVault.vaultPresent(runtime) }.getOrDefault(true)
        return if (present) VaultState.Locked(failure) else VaultState.NoVault
    }

    /**
     * Runs [body] with the open session, refusing when there is none.
     *
     * A caller that reached here while locked gets `VAULT_LOCKED` rather than a
     * handle of zero, which the boundary would refuse with `INVALID_INPUT` and
     * a less useful message.
     */
    private suspend inline fun <T> withSession(expectedGeneration: Long? = null, body: (Long) -> T): T = mutex.withLock {
        if (session == 0L || (expectedGeneration != null &&
                (generation != expectedGeneration || _state.value !is VaultState.Unlocked))) {
            throw ChurFailure(ChurStatus.VAULT_LOCKED, "no session is open")
        }
        val result = body(session)
        touch()
        result
    }
    /** [withSession] for background work, which never resets the idle timer. */
    private suspend inline fun <T> withQuietSession(body: (Long) -> T): T = mutex.withLock {
        if (session == 0L || _state.value !is VaultState.Unlocked) {
            throw ChurFailure(ChurStatus.VAULT_LOCKED, "no session is open")
        }
        body(session)
    }
    private suspend inline fun <T> withGenerationSession(expectedGeneration: Long, body: (Long) -> T): T = mutex.withLock {
        if (session == 0L || generation != expectedGeneration || _state.value !is VaultState.Unlocked) {
            throw ChurFailure(ChurStatus.VAULT_LOCKED, "the content index session has ended")
        }
        val result = body(session)
        touch()
        result
    }
    private suspend inline fun <T> withNoteSession(expectedGeneration: Long, noteActivity: Boolean = true, body: (Long) -> T): T = mutex.withLock {
        if (session == 0L || generation != expectedGeneration || _state.value !is VaultState.Unlocked) {
            throw ChurFailure(ChurStatus.VAULT_LOCKED, "the private note session has ended")
        }
        val result = body(session)
        if (noteActivity) touch()
        result
    }

}
