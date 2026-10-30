package dev.po4yka.chur.app

import dev.po4yka.chur.app.vault.PresentedState
import dev.po4yka.chur.app.vault.ThumbnailCache
import dev.po4yka.chur.app.vault.isAcceptableNewPassword
import dev.po4yka.chur.core.model.ChurStatus
import dev.po4yka.chur.ffi.AlbumSummary
import dev.po4yka.chur.ffi.ChurFailure
import dev.po4yka.chur.ffi.LockReason
import dev.po4yka.chur.ffi.ObjectDetail
import dev.po4yka.chur.ffi.ObjectPage
import dev.po4yka.chur.ffi.ObjectQuery
import dev.po4yka.chur.ffi.OperationProgress
import dev.po4yka.chur.ffi.SharingIdentity
import dev.po4yka.chur.ffi.SharingMember
import dev.po4yka.chur.ffi.SharingOverview
import dev.po4yka.chur.ffi.SharingPermission
import dev.po4yka.chur.ffi.SharingRecipient
import dev.po4yka.chur.ffi.fromHex
import dev.po4yka.chur.ffi.toHex
import dev.po4yka.chur.ffi.QueryScope
import dev.po4yka.chur.ffi.QuerySort
import dev.po4yka.chur.sync.PeerSyncCoordinator
import dev.po4yka.chur.sync.PeerSyncStatus
import dev.po4yka.chur.ffi.SlotSummary
import dev.po4yka.chur.ffi.StreamKind
import dev.po4yka.chur.ffi.TagSummary
import dev.po4yka.chur.notes.InMemoryNoteStore
import dev.po4yka.chur.notes.Note
import dev.po4yka.chur.notes.NoteStore
import dev.po4yka.chur.notes.NoteAttachment
import dev.po4yka.chur.vault.LockPolicy
import dev.po4yka.chur.vault.VaultRepository
import dev.po4yka.chur.vault.VaultState
import dev.po4yka.chur.imports.PickedMedia
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancelChildren
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext

/**
 * The application state machine, shared by both hosts.
 *
 * `docs/ARCHITECTURE.md` §9 puts binding in the composition root, and both
 * hosts have one; what they do not have is a reason to write this twice. The
 * two platform-specific pieces are injected: where an export lands, and the
 * privacy cover, because neither is expressible in common code.
 *
 * `docs/interop/FFI_CONTRACT.md` §14 permits one runtime per process, so a host
 * creates one of these. §8 makes every native call synchronous, so every call
 * below moves to the I/O dispatcher and none blocks the main thread.
 */
class ChurController(
    storageRoot: String,
    private val privacy: PrivacyCover,
    private val exports: ExportSink,
    private val deviceUnlock: DeviceUnlock = NoDeviceUnlock,
    private val appleDeviceUnlock: AppleDeviceUnlock = NoAppleDeviceUnlock,
    /**
     * The per-vault device-slot policy of `KEY_SLOTS.md` §1.
     *
     * A host without a device slot keeps the unset default, and the
     * settings row never appears, because [deviceUnlockAvailable] is
     * false with it.
     */
    private val deviceSlotPolicy: DeviceSlotPolicySetting = DeviceSlotPolicySetting.unset(),
    private val appLockSetting: AppLockSetting = AppLockSetting.unset(),
    private val publicShellSetting: PublicShellSetting = PublicShellSetting.unset(),
    val guide: dev.po4yka.chur.app.onboarding.GuideCoordinator = dev.po4yka.chur.app.onboarding.GuideCoordinator(),
    val publicUtilities: dev.po4yka.chur.app.publicshell.PublicUtilityStore = dev.po4yka.chur.app.publicshell.PublicUtilityStore(),
    /** The auto-lock choice of `DESIGN.md` §14.4, which sets the idle limit. */
    private val autoLockSetting: AutoLockSetting = AutoLockSetting.unset(),
    private val clock: () -> Long,
    private val notes: NoteStore = InMemoryNoteStore(),
    /** The lock policy; [autoLockSetting] replaces its idle limit. */
    private val policy: LockPolicy = LockPolicy(),
    /**
     * The sync engine, when the host binds one.
     *
     * A host that passes none gets no sync surface at all: the settings
     * section reads a `null` status and renders nothing, so an unbound
     * controller is unchanged rather than half-configured.
     */
    private val sync: PeerSyncCoordinator? = null,
    /** iOS presents its local network prompt during the foreground peer connection. */
    private val localNetworkAlert: Boolean = false,
    private val contentExtractor: dev.po4yka.chur.app.vault.ContentTextExtractor? = null,
) {
    /**
     * The last net under every coroutine this controller starts.
     *
     * [guarded] wraps a surface action, but a `launch` of its own re-roots the
     * work on [scope], where the guard around the caller cannot see it, and an
     * `Error` escapes the guard as well. Either one reached the platform
     * default handler, which ends the process — the crash `PLAINTEXT_LIFECYCLE`
     * §8 replaces with an orderly lock. `SupervisorJob` does not help here: it
     * stops the cancellation of a sibling, not the report of a failure.
     */
    private val uncaught = CoroutineExceptionHandler { context, _ ->
        post(userCopy(ChurStatus.INTERNAL_FAILURE), context[RouteVisit]?.number ?: routeVisit)
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main + uncaught)

    /**
     * The parent of the sync runs the open session started: the unlock pull
     * and "Sync now".
     *
     * A run holds the engine through its backoff, about 90 s against a peer
     * that does not answer, and shows this session's peer on every retry.
     * [clearPrivateProjections] cancels it, so the next identity's unlock does
     * not wait behind it or see what it showed, `DECOY_VAULT.md` §6.
     */
    private val sessionSync = SupervisorJob(scope.coroutineContext[Job])
    private val _autoLock = MutableStateFlow(
        runCatching { autoLockSetting.read() }.getOrDefault(AutoLock.DEFAULT),
    )
    private val repository =
        VaultRepository(storageRoot, clock, policy.copy(idleTimeoutMs = _autoLock.value.idleTimeoutMs))

    private val contentIndexer = ContentIndexController(repository.state,
        VaultContentIndexAccess(repository), contentExtractor, scope, changed = { reload() })
    val contentIndex: StateFlow<ContentIndexState> = contentIndexer.state

    /** OCR starts only on an explicit foreground action and remains inside this session. */
    fun indexContent(rebuild: Boolean = false) { contentIndexer.start(rebuild) }
    fun cancelContentIndex() { contentIndexer.cancel() }
    fun clearContentIndex() { contentIndexer.clear() }

    private val initiallyLockWholeApp = runCatching { appLockSetting.read() }.getOrDefault(false)
    private val _route = MutableStateFlow<AppRoute>(
        if (initiallyLockWholeApp) AppRoute.AppUnlock else AppRoute.PublicShell,
    )
    private var pendingLauncherAction: LauncherAction? = null
    private var launcherToken = 0L
    private var launcherNavigationBusy = false
    private var guideNavigationBusy = false
    private var launcherLocking = false
    /** New credential attempts must not overtake an earlier native lock. */
    private var pendingLock: Job? = null
    private var cleanupToken = 0L
    /** The Apple adapter owns one LAContext; password/create never acquire this mutex. */
    private val appleEntryMutex = Mutex()
    private val _launcherRequest = MutableStateFlow<LauncherRequest?>(null)
    val launcherRequest: StateFlow<LauncherRequest?> = _launcherRequest.asStateFlow()
    private val _notes = MutableStateFlow<List<Note>>(emptyList())
    private val _trashedNotes = MutableStateFlow<List<Note>>(emptyList())
    private val _publicNoteWriteFailureId = MutableStateFlow<String?>(null)
    private val publicNoteWrites = kotlinx.coroutines.sync.Mutex()
    /** Late callbacks cannot recreate an identifier purged during this process. */
    private val retiredPublicNoteIds = mutableSetOf<String>()
    private val _disclosureDue = MutableStateFlow(false)
    private val _publicDisclosureRequired = MutableStateFlow(true)
    /** Camera must show the public-data statement before its first file write. */
    val publicDisclosureRequired: StateFlow<Boolean> = _publicDisclosureRequired.asStateFlow()
    private val _page = MutableStateFlow(ObjectPage(emptyList(), 0, 0, null))
    private val _albums = MutableStateFlow<List<AlbumSummary>>(emptyList())
    private val _tags = MutableStateFlow<List<TagSummary>>(emptyList())
    private var currentQuery = ObjectQuery()
    private var queryRevision = 0L
    private val _slots = MutableStateFlow<List<SlotSummary>>(emptyList())
    private val _reencryptionNotice = MutableStateFlow<String?>(null)

    /**
     * A neutral line for Settings when some objects cannot be re-encrypted
     * after a revocation, ADR-0069, and `null` otherwise.
     */
    val reencryptionNotice: StateFlow<String?> = _reencryptionNotice.asStateFlow()
    private var reencryption: Job? = null
    private val _devicePairing = MutableStateFlow(dev.po4yka.chur.app.vault.DevicePairingUiState())
    private val _pairingApproval = MutableStateFlow<ByteArray?>(null)
    private val _notice = MutableStateFlow<Notice?>(null)
    private val _formError = MutableStateFlow<String?>(null)
    private var noticeCount = 0L

    /**
     * How many times the route has changed, which [post] compares.
     *
     * Touched only from the main dispatcher, where every route write runs.
     */
    private var routeVisit = 0L
    private val _activeOperation = MutableStateFlow<ActiveOperation?>(null)
    private var operationToken = 0L
    private val _recoveryPhrase = MutableStateFlow<String?>(null)
    private val _deviceUnlockOffered = MutableStateFlow(false)
    private val _unlocking = MutableStateFlow(false)

    /**
     * The decoded-image cache of `PLAINTEXT_LIFECYCLE.md` §4, which the
     * lock transitions below clear.
     *
     * It lives here rather than in a composition because a lock does not
     * wait for a library screen: the background lock fires while the host
     * is stopped, and a cache owned by composition would keep decoded
     * private pixels in exactly the locked process §8 step 7 is about.
     */
    private val thumbnails = ThumbnailCache()

    /** The cache the library renders from, cleared on every lock. */
    val thumbnailCache: ThumbnailCache get() = thumbnails

    private val _deviceSlotStrict = MutableStateFlow(false)
    private val _appLockEnabled = MutableStateFlow(initiallyLockWholeApp)

    /** Whether the entire app is gated on start and return from background. */
    val appLockEnabled: StateFlow<Boolean> = _appLockEnabled.asStateFlow()

    private val _publicShell = MutableStateFlow(runCatching { publicShellSetting.read() }.getOrDefault(PublicShell.NOTES))
    private val _publicShellError = MutableStateFlow<String?>(null)
    val publicShell: StateFlow<PublicShell> = _publicShell.asStateFlow()
    private val _preferredPublicShell = MutableStateFlow(_publicShell.value)
    val preferredPublicShell = _preferredPublicShell.asStateFlow()
    val publicShellError: StateFlow<String?> = _publicShellError.asStateFlow()
    private val _publicNoteRequest = MutableStateFlow(0L)
    val publicNoteRequest = _publicNoteRequest.asStateFlow()
    fun takePublicNoteRequest(): Note? {
        if (_route.value != AppRoute.PublicShell || _publicShell.value != PublicShell.NOTES || _publicNoteRequest.value == 0L) return null
        _publicNoteRequest.value = 0L
        return Note("note-${clock()}-${kotlin.random.Random.nextLong()}", "", "", clock())
    }

    private var hostBackground = false
    private val _guideObscured = MutableStateFlow(false)
    val guideObscured = _guideObscured.asStateFlow()
    fun foreground() { hostBackground = false; _guideObscured.value = guideNavigationBusy }
    private val _publicInputEpoch = MutableStateFlow(0L)
    val publicInputEpoch = _publicInputEpoch.asStateFlow()

    fun chooseInitialShell(shell: PublicShell) {
        if (!guide.bootstrapAllowed || guide.session.value?.step != dev.po4yka.chur.app.onboarding.GuideStep.CHOOSE ||
            _route.value != AppRoute.PublicShell || publicUtilities.discreet.value) return
        try {
            publicShellSetting.write(shell)
            _publicShell.value = shell
            _preferredPublicShell.value = shell
            guide.offerPetLesson = shell == PublicShell.PET
            guide.event(dev.po4yka.chur.app.onboarding.GuideStep.CHOOSE)
            _publicShellError.value = null
        } catch (_: Exception) { _publicShellError.value = "The public screen could not be changed. Try again." }
    }
    fun startPrivateGuide() {
        if (_route.value == AppRoute.Vault && repository.state.value is VaultState.Unlocked) {
            guide.offerPetLesson = _preferredPublicShell.value == PublicShell.PET
            guide.startPrivate()
        }
    }
    fun startPublicGuide() {
        if (_route.value != AppRoute.PublicSettings) return
        goTo(AppRoute.PublicShell)
        guide.startPublic(_publicShell.value)
    }

    /** A public preference. It never opens or changes a vault. */
    fun setPublicShell(shell: PublicShell) {
        if (_route.value != AppRoute.Vault || repository.state.value !is VaultState.Unlocked) return
        try {
            publicShellSetting.write(shell)
            _publicShell.value = shell
            _preferredPublicShell.value = shell
            refreshPublicPresentation()
            _publicShellError.value = null
        } catch (_: Exception) {
            _publicShellError.value = "The public screen could not be changed. Try again."
        }
    }

    fun refreshPublicPresentation() {
        dev.po4yka.chur.app.publicshell.PublicPresentation.apply?.invoke(publicUtilities.discreet.value, _preferredPublicShell.value.storedValue)
    }
    // A setup trial retains a digest only, and cannot enable the mode before real authentication.
    private var trialDigest: String? = null
    private var trialSubmitted = false
    fun beginDiscreetSetup(code: String) {
        check(_route.value == AppRoute.Vault && repository.state.value is VaultState.Unlocked)
        require(dev.po4yka.chur.app.publicshell.PublicUtilityStore.validCode(code))
        lock()
        trialDigest = dev.po4yka.chur.app.publicshell.publicCodeDigest(code)
        trialSubmitted = false
    }
    fun disableDiscreetMode() {
        check(_route.value == AppRoute.Vault && repository.state.value is VaultState.Unlocked)
        trialDigest = null
        trialSubmitted = false
        publicUtilities.disable()
        refreshPublicPresentation()
    }
    fun matchesPublicCode(code: String): Boolean =
        dev.po4yka.chur.app.publicshell.PublicUtilityStore.validCode(code) &&
            (trialDigest?.let { it == dev.po4yka.chur.app.publicshell.publicCodeDigest(code) } ?: publicUtilities.matches(code))

    fun submitPublicCode(code: String): Boolean {
        if (_route.value != AppRoute.PublicShell || !matchesPublicCode(code)) return false
        val tested = trialDigest != null
        openVaultEntry()
        trialSubmitted = tested
        return true
    }

    /** The external camera is an app-requested activity, like the photo picker. */
    fun beginPublicCameraActivity(): () -> Unit {
        if (_route.value != AppRoute.PublicShell || _publicShell.value != PublicShell.CAMERA) return {}
        val epoch = promptEpoch
        var open = true
        beginHostActivity()
        return {
            if (open) {
                open = false
                if (epoch == promptEpoch) endHostActivity()
            }
        }
    }

    /** How long an idle vault stays open in the foreground, `DESIGN.md` §14.4. */
    val autoLock: StateFlow<AutoLock> = _autoLock.asStateFlow()

    /** Whether the device slot requires biometry only, `KEY_SLOTS.md` §1. */
    val deviceSlotStrict: StateFlow<Boolean> = _deviceSlotStrict.asStateFlow()

    /** Whether this platform can hold a device slot at all. */
    val deviceUnlockAvailable: Boolean get() = deviceUnlock.available || appleDeviceUnlock.available

    /**
     * How many activities the host launched and is still waiting on.
     *
     * Touched only from the main dispatcher, which is where both the surface
     * callbacks and the lifecycle callbacks run, so it needs no synchronization.
     */
    private var hostActivities = 0

    /**
     * How many of the [hostActivities] are [beginPrompt] brackets, which
     * [enteredBackground] and the end of the session end early; the epoch
     * tells a prompt that its bracket was ended for it.
     */
    private var prompts = 0
    private var promptEpoch = 0L
    private var lockEpoch = 0L

    /**
     * Whether a [beginPrompt] bracket was open, and so held the lock off,
     * when [onBackground] last ran.
     *
     * A bracket can end before the application enters the background: a
     * local peer connection ends while the user looks at
     * the app switcher. A user who then leaves still left, so
     * [enteredBackground] locks for that bracket too, `DESIGN.md` §14.4.
     */
    private var promptHeldLock = false

    /**
     * Whether [start] has already run.
     *
     * Touched only from the main dispatcher, which is where a host calls
     * [start], so it needs no synchronization. §14 of
     * `docs/interop/FFI_CONTRACT.md` permits one runtime per process, and a
     * host whose window the platform recreated calls [start] again on this
     * same controller.
     */
    private var started = false

    /** Where the application is, `DESIGN.md` §10.3. */
    val route: StateFlow<AppRoute> = _route.asStateFlow()

    /** The vault state machine. */
    val vaultState: StateFlow<VaultState> = repository.state

    /**
     * Whether the switcher must not show the screen now: [needsPrivacyCover]
     * of the current state.
     *
     * The iOS scene delegate reads it on `sceneWillResignActive` and on
     * `sceneDidEnterBackground`. Kotlin/Native gives Swift a `StateFlow` value
     * only as an untyped object, so the check is made here and not in the host.
     */
    val privacyCoverNeeded: Boolean
        get() = needsPrivacyCover(vaultState.value, route.value, recoveryPhrase.value != null)

    /** The public notes. */
    val notesState: StateFlow<List<Note>> = _notes.asStateFlow()
    val trashedNotesState: StateFlow<List<Note>> = _trashedNotes.asStateFlow()
    val publicNoteWriteFailureId: StateFlow<String?> = _publicNoteWriteFailureId.asStateFlow()

    /** The current library page. */
    val page: StateFlow<ObjectPage> = _page.asStateFlow()

    /** The albums. */
    val albums: StateFlow<List<AlbumSummary>> = _albums.asStateFlow()
    val tags: StateFlow<List<TagSummary>> = _tags.asStateFlow()

    /** The key slots. */
    val slots: StateFlow<List<SlotSummary>> = _slots.asStateFlow()

    val devicePairing: StateFlow<dev.po4yka.chur.app.vault.DevicePairingUiState> = _devicePairing.asStateFlow()
    val pairingApproval: StateFlow<ByteArray?> = _pairingApproval.asStateFlow()

    /**
     * The outcome of the last action on the vault, shown once as the snackbar
     * of `DESIGN.md` §26, or a security notice until the user dismisses it.
     *
     * Its text is [userCopy], a count, or a fixed line, so it
     * carries no private value, `ERROR_MODEL.md` "Safe metadata". Only the
     * vault shell and the viewer read it. A route change clears it, so an
     * outcome never reaches another screen: not the public shell, which must
     * not show a vault outcome (`DECOY_VAULT.md` §10), and not a credential
     * form, where it would read as a refusal.
     */
    val notice: StateFlow<Notice?> = _notice.asStateFlow()

    /**
     * Why the credential form on screen was refused: creation, restore,
     * unlock or recovery.
     *
     * It is separate from [notice] because a form shows its refusal beside
     * its fields for as long as the form is up, and an unlock screen reads
     * any refusal as a failed attempt. A route change clears it.
     */
    val formError: StateFlow<String?> = _formError.asStateFlow()

    /** Marks [notice] [id] as shown, so no screen shows it again. */
    fun consume(id: Long) {
        _notice.update { current -> current?.takeUnless { it.id == id } }
    }

    /** The current user-visible import, export, backup, restore, or scan. */
    val activeOperation: StateFlow<ActiveOperation?> = _activeOperation.asStateFlow()

    /** The recovery phrase, held only until the user acknowledges it. */
    val recoveryPhrase: StateFlow<String?> = _recoveryPhrase.asStateFlow()

    /**
     * The sync engine's state, or a constant `null` when no engine is bound.
     *
     * A settings surface renders the section from this: `null` means the host
     * bound no engine, so the section is absent rather than empty, and a
     * non-null status is already bounded by `PeerSyncStatus`'s contract.
     */
    val syncStatus: StateFlow<PeerSyncStatus?> = sync?.status ?: MutableStateFlow(null)

    /**
     * Whether the unlock screen may offer the device slot.
     *
     * It is false unless the platform has one and the vault enrolled it, which
     * `DESIGN.md` §14.1 requires of every affordance on that screen: an offer
     * that appears when no slot exists would say a slot exists.
     */
    val deviceUnlockOffered: StateFlow<Boolean> = _deviceUnlockOffered.asStateFlow()

    /**
     * Whether an unlock or a recovery is being tried, [attempt].
     *
     * The unlock and recovery forms are busy while it holds: the button says
     * "Opening" and cannot be pressed again, and the error region is blank.
     * The repository keeps an equal `Locked` state after a second refusal, so
     * without the blank a screen reader would hear only the first one,
     * `DESIGN.md` §23.2.
     */
    val unlocking: StateFlow<Boolean> = _unlocking.asStateFlow()

    /** The repository, for a host flow that drives operations itself. */
    val vault: VaultRepository get() = repository

    /** Unsaved private-note text that an ordinary lock saves first, `PRIVATE_NOTES.md`. */
    internal val lockDrafts = LockDrafts()

    /**
     * Opens the runtime, loads the public shell, and starts the idle timer.
     *
     * It runs once. An Android activity is destroyed and recreated for a
     * locale change, a font-scale change, a display-size change and a
     * multi-window resize, and each recreation calls this again. The timer
     * [runIdleTimer] starts lives on [scope], which no host cancels, so a
     * second run would leave a second one-second wakeup over the one session
     * and keep this controller - and the window its cover holds - alive for
     * the life of the process.
     *
     * It runs on [begin] rather than on a scope of the host's, so nothing
     * cancels it part-way. A cancelled start would leave the flag unset with
     * no timer armed, and the next launch would arm a second one.
     */
    suspend fun start() {
        if (started) return
        val initialState = withContext(Dispatchers.Default) { repository.start() }
        if (initialState is VaultState.NoVault && _appLockEnabled.value) {
            withContext(Dispatchers.Default) { appLockSetting.write(false) }
            _appLockEnabled.value = false
            if (pendingLauncherAction == null) setRoute(AppRoute.PublicShell)
        }
        _notes.value = notes.all()
        _publicDisclosureRequired.value = !notes.disclosureAcknowledged()
        _deviceSlotStrict.value =
            withContext(Dispatchers.Default) { deviceSlotPolicy.read() }
        refreshDeviceUnlockOffer()
        guarded { runIdleTimer() }
        started = true
        dispatchLauncherAction()
    }

    /**
     * [start], on this controller's own scope.
     *
     * A host that launched it on a window-bound scope lost it to the next
     * recreation: an Android activity's `lifecycleScope` is cancelled at
     * `onDestroy`, so a start cancelled at one of its two suspension points
     * armed no idle timer and left `started` unset, and the next window armed
     * a second timer over the one session. This scope has the life of the
     * process, which §14 of `docs/interop/FFI_CONTRACT.md` gives the runtime.
     *
     * [guarded] is the second reason. A refused start used to travel out of an
     * uncaught `launch` and end the process, which is the crash
     * `PLAINTEXT_LIFECYCLE.md` §8 replaces with an orderly lock.
     */
    fun begin() = guarded {
        try {
            start()
        } finally {
            if (!started) clearLauncherAction()
        }
    }

    /** Native hosts call this on Main after decoding the closed command set. */
    fun requestLauncherAction(action: LauncherAction): Boolean {
        if (action == LauncherAction.LOCK_AND_HIDE) {
            panic()
            return true
        }
        val gate = _route.value == AppRoute.Unlock || _route.value == AppRoute.AppUnlock
        if (launcherLocking || launcherNavigationBusy || _activeOperation.value != null || _recoveryPhrase.value != null ||
            (hostActivities > 0 && !gate) ||
            _route.value !in setOf(AppRoute.PublicShell, AppRoute.PublicSettings, AppRoute.Vault, AppRoute.Unlock, AppRoute.AppUnlock)
        ) {
            post("Finish or cancel the current action first.")
            return false
        }
        action.publicShell?.let { shell ->
            clearLauncherAction()
            if (_route.value in setOf(AppRoute.Vault, AppRoute.Unlock, AppRoute.AppUnlock)) lock()
            _publicShell.value = shell
            if (action == LauncherAction.PUBLIC_NOTES) _publicNoteRequest.value += 1L
            if (_route.value == AppRoute.PublicSettings || _route.value == AppRoute.Unlock) setRoute(AppRoute.PublicShell)
            return true
        }
        pendingLauncherAction = action
        launcherToken += 1
        _launcherRequest.value = null
        if (started) dispatchLauncherAction()
        return true
    }

    /** Public editors and vault dialogs keep their current work when a shortcut arrives. */
    fun setLauncherNavigationBusy(busy: Boolean) = setVaultNavigationBusy(busy, busy)

    /** A viewer blocks shortcuts, but keeps its return-to-Library lesson visible. */
    fun setVaultNavigationBusy(busy: Boolean, obscureGuide: Boolean) {
        launcherNavigationBusy = busy
        guideNavigationBusy = obscureGuide
        _guideObscured.value = hostBackground || obscureGuide
    }

    fun acknowledgeLauncherAction(token: Long, generation: Long): Boolean {
        val request = _launcherRequest.value ?: return false
        if (request.token != token || request.generation != generation ||
            (repository.state.value as? VaultState.Unlocked)?.generation != generation || _route.value != AppRoute.Vault
        ) return false
        if (launcherLocking || launcherNavigationBusy || _activeOperation.value != null ||
            hostActivities > 0 || _recoveryPhrase.value != null
        ) {
            rejectLauncherAction(token)
            return false
        }
        clearLauncherAction()
        return true
    }

    fun rejectLauncherAction(token: Long) {
        if (_launcherRequest.value?.token != token) return
        clearLauncherAction()
        post("Finish or cancel the current action first.")
    }

    /** An incoming share takes precedence over deferred launcher navigation. */
    fun cancelLauncherAction() = clearLauncherAction()

    private fun clearLauncherAction() {
        pendingLauncherAction = null
        _launcherRequest.value = null
    }

    private fun dispatchLauncherAction() {
        val action = pendingLauncherAction ?: return
        when (val state = repository.state.value) {
            is VaultState.Unlocked -> {
                if (_unlocking.value && _route.value != AppRoute.Vault) return
                privacy.setEnabled(true)
                if (_route.value != AppRoute.Vault) setRoute(AppRoute.Vault)
                _launcherRequest.value = LauncherRequest(launcherToken, action, state.generation)
            }
            is VaultState.NoVault -> {
                clearLauncherAction()
                setRoute(AppRoute.PublicSettings)
                post("Set up Chur before using this action.")
            }
            is VaultState.Locked -> {
                val next = if (_route.value == AppRoute.AppUnlock) AppRoute.AppUnlock else AppRoute.Unlock
                if (_route.value != next) setRoute(next)
            }
            else -> Unit
        }
    }

    /**
     * The timer behind the auto-lock choices of `DESIGN.md` §14.4.
     *
     * It lives here rather than in each host because the rule is the same on
     * both and a timer neither host started is the failure this replaces: the
     * idle check existed and nothing called it, so a timed lock never happened.
     *
     * `collectLatest` cancels the loop as soon as the session is not unlocked,
     * so no wakeup runs while there is nothing to lock. A creation waiting for
     * its recovery phrase to be confirmed counts: it holds a root and shows a
     * full credential, so it times out as a session does.
     */
    private suspend fun runIdleTimer() {
        repository.state.collectLatest { current ->
            if (current !is VaultState.Unlocked && current !is VaultState.Creating) return@collectLatest
            while (true) {
                delay(IDLE_TICK_MS)
                checkIdle()
            }
        }
    }

    /**
     * Whether a request that ends with a recovery phrase on screen is in
     * flight, [create] or [addRecoverySlot].
     *
     * A second request abandons what the first staged while the first phrase
     * can already be on screen, so that phrase opens nothing, and a Continue
     * on it would commit the second before its phrase was ever shown. So a
     * request is ignored while another runs or its phrase is shown. The flag
     * is set on Main before the work starts, because the vault state reads
     * `Creating` only once the work has reached the repository.
     */
    private var phraseRequested = false
    /** Only the newest entry request may change busy state. Lock revokes it synchronously. */
    private var entryRequestToken = 0L
    private val nativeEntries = MutableStateFlow<Set<CompletableDeferred<Unit>>>(emptySet())

    private fun requestPhrase(body: suspend () -> Unit) {
        if (phraseRequested || _unlocking.value || _recoveryPhrase.value != null) return
        phraseRequested = true
        val token = ++entryRequestToken
        val epoch = lockEpoch
        guarded {
            try {
                if (token != entryRequestToken || !awaitLockCleanup(epoch)) return@guarded
                body()
            } finally {
                if (token == entryRequestToken) phraseRequested = false
            }
        }
    }

    /** Creates a vault, `PROVISIONING.md` §3. */
    fun create(password: String, offerRecovery: Boolean) = requestPhrase {
        if (!isAcceptableNewPassword(password)) {
            say(NEW_PASSWORD_RULE)
            return@requestPhrase
        }
        val epoch = endOpenSession()
        if (epoch != lockEpoch) return@requestPhrase
        val target = _route.value
        val bytes = password.encodeToByteArray()
        val phrase = try {
            nativeEntry(epoch) { repository.create(bytes, offerRecovery) }
        } catch (failure: ChurFailure) {
            // One sentence for every reason a creation is refused.
            // `DECOY_VAULT.md` §10 forbids a surface that differs by whether a
            // sibling exists, and the two statuses that reach here differ by
            // exactly that: `RESOURCE_LIMIT_EXCEEDED` means the registry
            // already holds the two identities §11 admits, and `CONFLICT`
            // means this credential already opens one. A message naming either
            // would answer, from inside a decoy session, the question the
            // design refuses to answer. The residual signal that a creation
            // failed at all is structural and is recorded in §5 there.
            say("This vault could not be created. Try a different credential.")
            return@requestPhrase
        } finally {
            bytes.fill(0)
        }
        if (epoch != lockEpoch || _route.value != target) {
            closeStaleSession()
            return@requestPhrase
        }
        guide.event(dev.po4yka.chur.app.onboarding.GuideStep.CREATE)
        if (phrase != null) _recoveryPhrase.value = phrase else enterVault()
    }

    /**
     * Acknowledges the phrase, which is the only way past that screen.
     *
     * The slot commits here and not before: `PROVISIONING.md` §4 runs the
     * presentation and confirmation "before the slot commits", and
     * `RECOVERY.md` §8 confirms before the new descriptor generation. The
     * phrase leaves the screen at the tap, so it is shown once and a second
     * tap does nothing. A lock that reached the repository first already
     * discarded what the phrase belonged to, and the user is told that the
     * phrase they wrote down was not saved.
     *
     * A committed slot is confirmed with a notice, `DESIGN.md` §17.1 step 6.
     * A creation opens the Library of its new session with it. A phrase from
     * Settings belongs to a session that is already open, so its confirmation
     * is not an unlock: [enterVault] would pull again and repeat the unlock's
     * fork notice, which would take the place of this one. So the notice goes
     * to the vault as it stands, and a lock after the commit drops it.
     *
     * An activation that fails reaches the user as a message, as a failed
     * [create] does, and leaves nothing to clear: the repository abandons the
     * creation, and [endOpenSession] cleared the projections of an open
     * session before the creation began.
     */
    fun acknowledgeRecoveryPhrase() {
        if (_recoveryPhrase.value == null) return
        _recoveryPhrase.value = null
        // A creation waits in `Creating` until the phrase is confirmed.
        val creating = vaultState.value is VaultState.Creating
        val epoch = lockEpoch
        phraseRequested = true
        val token = ++entryRequestToken
        guarded {
            try {
                if (token != entryRequestToken || epoch != lockEpoch) return@guarded
                val confirmed = nativeEntry(epoch) { repository.confirmRecoveryPhrase() }
                if (epoch != lockEpoch) {
                    closeStaleSession()
                    return@guarded
                }
                if (confirmed) {
                    guide.event(dev.po4yka.chur.app.onboarding.GuideStep.RECOVERY)
                    if (creating) enterVault(notice = PHRASE_SAVED) else say(PHRASE_SAVED)
                } else {
                    say("This recovery phrase was not saved.")
                }
            } finally {
                if (token == entryRequestToken) phraseRequested = false
            }
        }
    }

    /** Unlocks with a password. */
    fun unlock(password: String) = attempt {
        val epoch = endOpenSession()
        if (epoch != lockEpoch) return@attempt
        val target = _route.value
        val bytes = password.encodeToByteArray()
        try {
            nativeEntry(epoch) { repository.unlock(bytes) }
        } finally {
            bytes.fill(0)
        }
        completeUnlock(target, epoch)
    }

    /** Unlocks with the recovery phrase, and says why a phrase was refused. */
    fun recover(phrase: String) = attempt(::recoveryCopy) {
        val epoch = endOpenSession()
        if (epoch != lockEpoch) return@attempt
        val target = _route.value
        val bytes = phrase.trim().encodeToByteArray()
        try {
            nativeEntry(epoch) { repository.unlockWithRecovery(bytes) }
        } finally {
            bytes.fill(0)
        }
        completeUnlock(target, epoch)
    }

    /**
     * Unlocks through the platform device slot, `KEY_SLOTS.md` §4.
     *
     * The platform performs the unwrap and hands back the root, which the
     * repository clears once the session is open. Every enrolled slot is tried
     * in turn, because the material names no identity.
     */
    fun unlockWithDevice() = attempt {
        val epoch = endOpenSession()
        if (epoch != lockEpoch) return@attempt
        val target = _route.value
        val material = withContext(Dispatchers.Default) { repository.keystoreMaterial() }
        // Not `firstNotNullOfOrNull`: the unwrap suspends now, because the
        // platform asks the user to authorize it first.
        var root: ByteArray? = null
        var worst: ChurFailure? = null
        val hostEpoch = promptEpoch
        beginHostActivity()
        try {
            withContext(Dispatchers.Default) {
                for (entry in material) {
                    // One invalidated or malformed slot must not stop the
                    // others: every entry is tried, and the most severe
                    // failure is reported only when none opened. A cancel is
                    // the user's answer and ends the walk.
                    root = try {
                        deviceUnlock.unwrap(
                            entry.alias,
                            entry.aad,
                            entry.gcmNonce,
                            entry.wrappedRootSecret,
                        )
                    } catch (failure: ChurFailure) {
                        if (failure.status == ChurStatus.CANCELLED) throw failure
                        worst = moreSevere(worst, failure)
                        null
                    }
                    if (root != null) break
                }
            }
        } finally {
            if (hostEpoch == promptEpoch) endHostActivity()
        }
        val opened = root
            ?: throw worst ?: ChurFailure(ChurStatus.AUTHENTICATION_FAILED, "no device slot opened")
        try {
            if (epoch != lockEpoch || _route.value != target) return@attempt
            nativeEntry(epoch) { repository.unlockWithKeystoreRoot(opened) }
        } finally {
            opened.fill(0)
        }
        completeUnlock(target, epoch)
    }

    /** Opens the vault with a Keychain secret released by local authorization. */
    fun unlockWithAppleDevice() = attempt {
        val epoch = endOpenSession()
        if (epoch != lockEpoch) return@attempt
        val target = _route.value
        appleEntryMutex.withLock {
            if (epoch != lockEpoch || _route.value != target) return@attempt
            val hostEpoch = promptEpoch
            var hostActivityHeld = true
            beginHostActivity()
            try {
                withContext(Dispatchers.Default) { appleDeviceUnlock.beginUnlock() }
                try {
                    var opened = false
                    for (itemId in withContext(Dispatchers.Default) { appleDeviceUnlock.itemIds() }) {
                        val secret = withContext(Dispatchers.Default) { appleDeviceUnlock.releaseSecret(itemId) }
                        try {
                            if (epoch != lockEpoch || _route.value != target) return@attempt
                            try {
                                nativeEntry(epoch) { repository.unlockWithDeviceSecret(secret) }
                                opened = true
                                break
                            } catch (failure: ChurFailure) {
                                if (failure.status != ChurStatus.AUTHENTICATION_FAILED) throw failure
                            }
                        } finally {
                            secret.fill(0)
                        }
                    }
                    if (!opened) throw ChurFailure(ChurStatus.AUTHENTICATION_FAILED, "no device slot opened")
                    // The OS prompt is over; platform context disposal must
                    // not suppress background locking of the opened screen.
                    if (hostEpoch == promptEpoch) endHostActivity()
                    hostActivityHeld = false
                    // Authorize/publish on this Main turn before platform
                    // teardown suspends. A late endUnlock must never perform
                    // stale native cleanup against a newer password session.
                    completeUnlock(target, epoch)
                } finally {
                    withContext(NonCancellable + Dispatchers.Default) { appleDeviceUnlock.endUnlock() }
                }
            } finally {
                if (hostActivityHeld && hostEpoch == promptEpoch) endHostActivity()
            }
        }
    }

    /**
     * Enrolls the platform device slot on the open session.
     *
     * The enrolment is bracketed the way an import is: authorizing the platform
     * key can put a system credential screen in front of this one, and the
     * background lock would otherwise close the session the enrolment needs.
     *
     * Rust refuses the enrolment when another identity already holds a device
     * slot, `DECOY_VAULT.md` §10, and [deviceSlotCopy] gives that refusal the
     * sentence of any device unlock that is not available.
     */
    fun enrollDeviceSlot() = guarded(copy = ::deviceSlotCopy) {
        beginHostActivity()
        try {
            // The only guarded action that used to stay on the main dispatcher,
            // and the one that could least afford to: the enrolment generates a
            // Keystore key, runs an interactive prompt and finishes an AEAD.
            // The prompt itself hops back to the main thread on its own, which
            // is where the platform requires it.
            withContext(Dispatchers.Default) { addKeystoreSlot() }
        } finally {
            endHostActivity()
        }
        say("This device can now open the vault.")
        loadSlots()
        refreshDeviceUnlockOffer()
    }

    /** Stores a random Rust device secret under Keychain authorization. */
    fun enrollAppleDeviceSlot() = guarded(copy = ::deviceSlotCopy) {
        beginHostActivity()
        try {
            withContext(Dispatchers.Default) { addAppleSlot() }
        } finally {
            endHostActivity()
        }
        say("This device can now open the vault.")
        loadSlots()
        refreshDeviceUnlockOffer()
    }

    /**
     * Enrolls a Keystore slot under the policy [deviceSlotPolicy] holds now,
     * which the Android binding reads when it generates the key.
     */
    private suspend fun addKeystoreSlot() {
        repository.enrollKeystoreSlot { alias, aad, root ->
            deviceUnlock.wrap(alias, aad, root)
        }
    }

    /** Enrolls a Keychain slot under the policy [deviceSlotPolicy] holds now. */
    private suspend fun addAppleSlot() {
        val itemId = appleDeviceUnlock.newItemId()
        repository.enrollAppleSlot(itemId) { secret ->
            appleDeviceUnlock.storeSecret(itemId, secret, deviceSlotPolicy.read())
        }
    }

    /** Recomputes whether the unlock screen may offer the device slot. */
    private fun refreshDeviceUnlockOffer() {
        if (!deviceUnlockAvailable) {
            _deviceUnlockOffered.value = false
            return
        }
        scope.launch {
            _deviceUnlockOffered.value = runCatching {
                withContext(Dispatchers.Default) {
                    if (appleDeviceUnlock.available) {
                        appleDeviceUnlock.itemIds().isNotEmpty()
                    } else {
                        repository.keystoreMaterial().isNotEmpty()
                    }
                }
            }.getOrDefault(false)
        }
    }

    /**
     * Switches the device-slot policy of `KEY_SLOTS.md` §1 and replaces the
     * device slot the open vault holds under the old one.
     *
     * The platform fixes a slot's authentication when it creates the key or
     * the Keychain item, and the Android unwrap follows the stored key rather
     * than this setting. Writing the setting alone therefore left a convenient
     * slot that the device unlock code still opened after the user chose
     * biometrics only, which is the adversary `THREAT_MODEL.md` A2 names.
     * `ANDROID.md` §9.3 makes a mode change create or replace the platform
     * slot, so this enrolls a slot under the new policy through the path, and
     * the prompt, an enrollment uses. It removes the old slots only after the
     * new one commits, the order of `KEY_SLOTS.md` §9 and `ANDROID.md` §9.4
     * steps 5 and 6. With no slot enrolled, the change is the creation-time
     * choice §1 describes and nothing else happens.
     *
     * [deviceSlotStrict] comes from the slots that survive, not from the
     * request. A cancelled prompt or a failed removal therefore never shows a
     * policy that is not in force. The platform binding reads the new policy
     * through [DeviceSlotPolicySetting.enrollingUnder], so nothing is stored
     * for it. Before the swap the setting is stored as convenient, the weaker
     * of the two policies involved, and only the read-back after the swap
     * stores what is in force. A process that dies inside the swap therefore
     * never shows strict while a convenient slot may exist; at worst it shows
     * convenient over a strict slot, which the next toggle corrects.
     */
    fun toggleDeviceSlotPolicy() = guarded(copy = ::deviceSlotCopy) {
        val previous = _deviceSlotStrict.value
        val next = !previous
        // The slot types [SlotSummary.familyName] gives: 2 is the Android
        // Keystore, 3 the Apple Keychain. The Keychain binding wins when it is
        // bound, the same choice [refreshDeviceUnlockOffer] makes.
        val family = if (appleDeviceUnlock.available) 3 else 2
        beginHostActivity()
        try {
            withContext(Dispatchers.Default) {
                val before = repository.slots().filter { it.slotType == family }
                // One of `previous` and `next` is convenient, and so is the
                // vault while the swap runs.
                deviceSlotPolicy.write(false)
                try {
                    if (before.isNotEmpty()) {
                        deviceSlotPolicy.enrollingUnder(next) {
                            if (family == 3) addAppleSlot() else addKeystoreSlot()
                        }
                        // Every old slot goes even when one fails: a removal
                        // can fail after the descriptor dropped the slot, and
                        // stopping there would keep the next old slot.
                        before.mapNotNull { slot ->
                            runCatching { repository.removeSlot(slot.slotId) }.exceptionOrNull()
                        }.firstOrNull()?.let { throw it }
                    }
                } finally {
                    // A slot listed in `before` holds the old policy and any
                    // other slot holds the new one. A mix of the two always
                    // includes a convenient slot, which the device unlock code
                    // opens. If the vault cannot be read, assume it holds one.
                    val after = runCatching {
                        repository.slots().filter { it.slotType == family }
                    }.getOrNull()
                    val inForce = when {
                        after == null -> false
                        after.none { it in before } -> next
                        else -> previous && after.all { it in before }
                    }
                    deviceSlotPolicy.write(inForce)
                    _deviceSlotStrict.value = inForce
                }
            }
        } finally {
            endHostActivity()
            loadSlots()
            refreshDeviceUnlockOffer()
        }
    }

    /** Selects whether the public shell also needs a vault credential. */
    fun toggleAppLock() = guarded {
        if (repository.state.value !is VaultState.Unlocked) {
            throw ChurFailure(ChurStatus.VAULT_LOCKED, "the vault is locked")
        }
        val next = !_appLockEnabled.value
        withContext(Dispatchers.Default) { appLockSetting.write(next) }
        _appLockEnabled.value = next
    }

    /**
     * Selects how long an idle vault stays open in the foreground, `DESIGN.md`
     * §14.4. Leaving the application still locks at once, whatever the choice.
     */
    fun setAutoLock(choice: AutoLock) = guarded {
        if (repository.state.value !is VaultState.Unlocked) {
            throw ChurFailure(ChurStatus.VAULT_LOCKED, "the vault is locked")
        }
        withContext(Dispatchers.Default) {
            autoLockSetting.write(choice)
            repository.setIdleTimeout(choice.idleTimeoutMs)
        }
        _autoLock.value = choice
    }

    /** Whether the public-shell disclosure is owed to the user right now. */
    val disclosureDue: StateFlow<Boolean> = _disclosureDue.asStateFlow()

    /**
     * Reads one derived asset, or `null` when the object carries none.
     *
     * A derivative that is absent is an ordinary state rather than a failure:
     * `MEDIA_PIPELINE.md` §13 says a codec failure must not commit a catalog
     * entry claiming a derivative exists, so an object imported when the codec
     * could not read it simply has none, and the surface shows what it has.
     */
    suspend fun derivativeOf(objectId: ByteArray, kind: StreamKind): ByteArray? = try {
        withContext(Dispatchers.Default) { repository.readDerived(objectId, kind) }
    } catch (_: ChurFailure) {
        null
    }

    /**
     * Conceals on the caller's UI turn; native cleanup must never delay the
     * public screen. An open private note with unsaved text is captured
     * before the concealment and saved after it, before the native close,
     * within the bound of [LockDrafts]. The panic reason captures nothing
     * and ends the save wait of an earlier lock, so it never waits for a
     * save that has not started, `DISCREET_MODE.md`.
     */
    fun lock(reason: LockReason = LockReason.USER) {
        trialSubmitted = false
        val drafts = if (reason == LockReason.PANIC) {
            lockDrafts.abort()
            emptyList()
        } else {
            lockDrafts.capture()
        }
        concealPrivateSession()
        enablePrivacyCover()
        queueNativeLock(reason, drafts)
    }

    /** The same immediate concealment, recorded by Rust with the panic reason. */
    fun panic() = lock(LockReason.PANIC)

    private fun enablePrivacyCover() {
        try {
            privacy.setEnabled(true)
        } catch (_: Exception) {
            post(userCopy(ChurStatus.INTERNAL_FAILURE))
        }
    }

    private fun concealPrivateSession() {
        guide.conceal()
        _publicInputEpoch.value += 1
        // Rust cancels the operation as the session locks; the poller ends here.
        reencryption?.cancel()
        reencryption = null
        _reencryptionNotice.value = null
        lockEpoch += 1
        entryRequestToken += 1
        phraseRequested = false
        _unlocking.value = false
        clearPrivateProjections()
        launcherLocking = true
        setRoute(if (_appLockEnabled.value) AppRoute.AppUnlock else AppRoute.PublicShell)
    }

    private fun queueNativeLock(reason: LockReason, drafts: List<LockDrafts.Save> = emptyList()) {
        val previous = pendingLock
        val epoch = lockEpoch
        val token = ++cleanupToken
        val entriesBeforeLock = nativeEntries.value
        pendingLock = scope.launch {
            previous?.join()
            // Native calls are synchronous and cannot be cancelled. Their
            // tickets end before teardown; public masking already happened.
            entriesBeforeLock.forEach { it.await() }
            // The session is still open for the captured saves. No save
            // starts after their bound; one native call that started in it
            // ends before the close can take the repository mutex.
            val interrupted = try {
                lockDrafts.save(drafts)
                null
            } catch (failure: Throwable) {
                failure
            }
            // Provider or filesystem revocation can fail. The native session
            // must still close; a failure keeps the cover enabled and is
            // reported by the controller's exception handler. An interrupted
            // save wait still closes, and its failure follows the close.
            if (interrupted == null) {
                closeAfterLockSaves(reason)
            } else {
                withContext(NonCancellable) { closeAfterLockSaves(reason) }
                throw interrupted
            }
            // An earlier cleanup may finish after another lock, but must
            // never remove the newer transition's privacy cover. A failed
            // native cleanup keeps the cover enabled and projections closed.
            if (epoch == lockEpoch && token == cleanupToken) {
                privacy.setEnabled(needsPrivacyCover(repository.state.value, _route.value, _recoveryPhrase.value != null))
                launcherLocking = false
            }
        }
    }

    private suspend fun closeAfterLockSaves(reason: LockReason) {
        try {
            exports.cancelPending()
        } finally {
            closeNativeSession(reason)
        }
    }

    /** Track native opens independently of slow OS prompts and Main result delivery. */
    private suspend fun <T> nativeEntry(expectedEpoch: Long, body: suspend () -> T): T {
        val completed = CompletableDeferred<Unit>()
        nativeEntries.update { it + completed }
        try {
            if (expectedEpoch != lockEpoch) throw CancellationException("entry authorization expired")
            val result = withContext(Dispatchers.Default) { body() }
            if (expectedEpoch != lockEpoch) {
                // Register stale-result teardown before releasing this ticket.
                // It may wait for this ticket, so never join it from here.
                launcherLocking = true
                queueNativeLock(LockReason.BACKGROUND)
                throw CancellationException("entry authorization expired")
            }
            return result
        } finally {
            completed.complete(Unit)
            nativeEntries.update { it - completed }
        }
    }

    /**
     * A joined Job may have failed. A fresh user attempt gets one new teardown
     * attempt; credentials never open native state behind failed cleanup.
     */
    private suspend fun awaitLockCleanup(expectedEpoch: Long): Boolean {
        val previous = awaitPendingLockTail(expectedEpoch)
        if (expectedEpoch != lockEpoch) return false
        if (previous?.isCancelled == true) {
            // One fresh teardown for this explicit user attempt. Waiting for
            // a changing tail above is serialization, not another retry.
            queueNativeLock(LockReason.USER)
            val retry = awaitPendingLockTail(expectedEpoch)
            if (expectedEpoch != lockEpoch) return false
            if (retry?.isCancelled == true || launcherLocking) {
                throw ChurFailure(ChurStatus.INTERNAL_FAILURE, "the previous lock could not finish")
            }
        }
        if (launcherLocking) throw ChurFailure(ChurStatus.INTERNAL_FAILURE, "the lock is still completing")
        return true
    }

    private suspend fun awaitPendingLockTail(expectedEpoch: Long): Job? {
        var joined: Job?
        do {
            joined = pendingLock
            joined?.join()
            if (expectedEpoch != lockEpoch) return null
        } while (joined !== pendingLock)
        return joined
    }

    /**
     * Every teardown records the same barrier, including identity replacement
     * and a late native open. Its failure must remain visible to the next
     * explicit credential attempt, even after native state became Locked.
     */
    private suspend fun closeTrackedSession(reason: LockReason) {
        launcherLocking = true
        queueNativeLock(reason)
        val cleanup = pendingLock ?: return
        cleanup.join()
        if (cleanup.isCancelled) {
            throw ChurFailure(ChurStatus.INTERNAL_FAILURE, "the session cleanup did not finish")
        }
    }

    /** Closes a native open that finished after its UI authorization expired. */
    private suspend fun closeStaleSession() = closeTrackedSession(LockReason.BACKGROUND)

    /** Release cached plaintext even when native or platform cleanup fails. */
    private suspend fun closeNativeSession(reason: LockReason) {
        try {
            withContext(Dispatchers.Default) { repository.lock(reason) }
        } finally {
            withContext(NonCancellable) { thumbnails.clear() }
        }
    }

    /**
     * Marks that the host is running an activity it launched itself.
     *
     * The background lock cannot tell the user leaving from the application
     * asking the platform for something: both stop the activity. The media
     * picker of `ANDROID.md` §14.1 is the case that matters, because the whole
     * import path goes through it — the lock fired as the picker came up, and
     * the result arrived at a locked vault, so no import could ever finish.
     *
     * The cover still goes on, so the switcher entry is covered either way.
     * What is suppressed is the lock alone, and only while the host says a
     * launch of its own is outstanding. The idle timer is untouched and stays
     * the backstop for a user who walks away from an open picker.
     */
    fun beginHostActivity() {
        hostActivities += 1
    }

    /** Ends what [beginHostActivity] began, on the result or on a dismissal. */
    fun endHostActivity() {
        if (hostActivities > 0) hostActivities -= 1
    }

    /**
     * Marks that a system prompt the application asked for is up, and returns
     * the bracket that [endPrompt] takes.
     *
     * A prompt holds the background lock off as [beginHostActivity] does, but
     * it never takes the application out of the foreground by itself: an iOS
     * alert or Local Authentication sheet only makes the scene resign active,
     * and an Android permission dialog, delete confirmation, or, from API 30,
     * device authentication prompt at most pauses the activity. So
     * [enteredBackground] during a prompt means the user left, and the
     * bracket ends there and the vault locks at once, as leaving always does,
     * `DESIGN.md` §14.4. A picker or a credential screen, which can take the
     * whole screen, uses [beginHostActivity] instead.
     */
    fun beginPrompt(): Long {
        prompts += 1
        hostActivities += 1
        return promptEpoch
    }

    /**
     * Ends what [beginPrompt] began, on the answer or on a dismissal.
     *
     * It returns `false` when leaving the application or the end of the
     * session already ended the bracket. The answer then belongs to no screen
     * of the session now open, and the bracket must not end a newer one.
     */
    fun endPrompt(bracket: Long): Boolean {
        if (bracket != promptEpoch || prompts == 0) return false
        prompts -= 1
        endHostActivity()
        return true
    }

    /**
     * The application entered the background: iOS reports it after the scene
     * resigned active and [background] ran, and Android when the activity
     * stops after its pause ran [background].
     *
     * A lock held off by [beginHostActivity] stays off, as the picker needs.
     * The brackets of [beginPrompt] are the exception: a prompt does not take
     * the application out of the foreground, so the user left, and every open
     * prompt ends and the vault locks at once, `DESIGN.md` §14.4 and
     * `PLAINTEXT_LIFECYCLE.md` §7. So does a prompt that held the lock off
     * when the application left the foreground and ended before this call,
     * [promptHeldLock]; a picker still open keeps the lock off, as always.
     * Foreground peer connections end with the unlocked session, `IOS.md` §27.
     */
    fun enteredBackground() {
        if (prompts == 0 && !promptHeldLock) return
        repeat(prompts) { endHostActivity() }
        prompts = 0
        promptEpoch += 1
        background()
    }

    /** The application left the foreground. */
    suspend fun onBackground() {
        if (prepareBackgroundLock()) pendingLock?.join()
    }

    private fun prepareBackgroundLock(): Boolean {
        hostBackground = true
        _guideObscured.value = true
        _publicInputEpoch.value += 1
        contentIndexer.cancel()
        enablePrivacyCover()
        promptHeldLock = prompts > 0
        if (hostActivities > 0) return false
        guide.conceal()
        if (_appLockEnabled.value || policy.lockOnBackground) {
            lock(LockReason.BACKGROUND)
            return true
        }
        // A policy that retains the open session still invalidates an
        // in-flight credential attempt when the host leaves the foreground.
        clearLauncherAction()
        lockEpoch += 1
        return false
    }

    /** Controller-owned cleanup survives the host activity's destruction. */
    fun background() { prepareBackgroundLock() }

    /**
     * The idle check of `DESIGN.md` §14.4, which [runIdleTimer] drives.
     *
     * The lock publishes the new state before this check resumes on Main, and
     * the `collectLatest` of [runIdleTimer] then cancels the check. Without
     * [NonCancellable] the check stopped after the lock and before the
     * clearing: the route stayed in the vault, and a recovery phrase whose
     * slot the lock had discarded stayed on screen with the display awake,
     * against the clearing policy of `DESIGN.md` §17.2.
     *
     * An operation the user has not cancelled counts as use until it ends.
     * Its polls refresh the idle clock only while Rust works, and an import
     * also works on the host: the iOS fetch of an iCloud original, the
     * opening of each picked item, and its previews. Under the 30-second
     * choice such a phase locked the vault and dropped the rest of the pick.
     *
     * Unsaved private-note text is captured after the idle decision, and
     * saved after the concealment and before the close, within the bound of
     * [LockDrafts], as at every ordinary lock.
     */
    suspend fun checkIdle() {
        withContext(NonCancellable) {
            var concealedEpoch: Long? = null
            var concealedRoute: AppRoute? = null
            var drafts = emptyList<LockDrafts.Save>()
            // An open private editor moves the concealment out of the
            // repository mutex, so its save can run after it and before the close.
            val beforeClose: (suspend () -> Unit)? = if (!lockDrafts.active) null else {
                { withContext(NonCancellable + Dispatchers.Main) { lockDrafts.save(drafts) } }
            }
            if (withContext(Dispatchers.Default) {
                if (_activeOperation.value?.let { !it.cancelling && it.name != "external-archive" } == true) repository.noteActivity()
                repository.lockIfIdle(beforeClose) {
                    withContext(NonCancellable + Dispatchers.Main) {
                        drafts = lockDrafts.capture()
                        concealPrivateSession()
                        concealedEpoch = lockEpoch
                        concealedRoute = _route.value
                        // Complete physical cache release before the native
                        // idle close permits another credential operation.
                        thumbnails.clear()
                    }
                }
            }) {
                // The native idle close can finish before its Main continuation.
                // A newer lock or authenticated session owns its own cover.
                val after = repository.state.value
                if (concealedEpoch != lockEpoch || after is VaultState.Unlocked || after is VaultState.Creating) {
                    return@withContext
                }
                exports.cancelPending()
                if (concealedEpoch != lockEpoch || _route.value != concealedRoute) return@withContext
                privacy.setEnabled(needsPrivacyCover(repository.state.value, _route.value, _recoveryPhrase.value != null))
                launcherLocking = false
            }
        }
    }

    /** Moves to a route the public shell offers. */
    fun goTo(next: AppRoute) {
        if (next == AppRoute.PublicShell || next == AppRoute.PublicSettings) trialSubmitted = false
        if (next !in setOf(AppRoute.Unlock, AppRoute.AppUnlock, AppRoute.Recover, AppRoute.AppRecover)) clearLauncherAction()
        setRoute(next)
    }

    /** The route the visible settings entry of §2 leads to. */
    fun openVaultEntry() {
        trialSubmitted = false
        setRoute(if (repository.state.value is VaultState.NoVault) {
            AppRoute.CreateVault
        } else {
            AppRoute.Unlock
        })
    }

    /** Loads one query scope. */
    fun load(query: ObjectQuery) {
        currentQuery = query
        val revision = ++queryRevision
        val guideToken = guide.session.value?.token
        _page.value = ObjectPage(emptyList(), 0, 0, null)
        if (query.scope == QueryScope.SEARCH && query.terms.isNullOrBlank()) return
        guarded(clearMessage = false) {
            val result = withContext(Dispatchers.Default) { repository.page(query) }
            if (revision == queryRevision) {
                _page.value = result
                if (!query.terms.isNullOrBlank()) guide.event(dev.po4yka.chur.app.onboarding.GuideStep.SEARCH, guideToken)
            }
        }
    }

    private var loadingNextPageRevision: Long? = null

    /** Appends one bounded page when the user reaches the end of the grid. */
    fun loadNextPage() = guarded(clearMessage = false) {
        val query = currentQuery
        val revision = queryRevision
        if (loadingNextPageRevision == revision) return@guarded
        val previous = _page.value
        val cursor = previous.nextCursor ?: return@guarded
        loadingNextPageRevision = revision
        try {
            val next = withContext(Dispatchers.Default) { repository.page(query.copy(cursor = cursor)) }
            if (revision != queryRevision) return@guarded
            val result = if (next.catalogGeneration != previous.catalogGeneration) {
                pageThrough(query, previous.objects.size + next.objects.size)
            } else {
                next.copy(objects = previous.objects + next.objects)
            }
            if (revision == queryRevision) _page.value = result
        } finally {
            if (loadingNextPageRevision == revision) loadingNextPageRevision = null
        }
    }

    /** Loads the albums. */
    fun loadAlbums() = guarded(clearMessage = false) {
        publishPrivate(_albums) { repository.albums() }
    }

    /** Loads tags only for the unlocked selection picker. */
    fun loadTags() = guarded {
        publishPrivate(_tags) { repository.tags() }
    }

    /** Refreshes the visible projections after a host command changes the vault. */
    suspend fun refreshExternalChanges(albums: Boolean = false, tags: Boolean = false) {
        val session = privateSession() ?: return
        reload(session.generation)
        if (!session.isCurrent()) return
        if (albums) refreshAlbums(session.generation)
        if (!session.isCurrent()) return
        if (tags) publishPrivate(_tags) { repository.tags() }
    }

    /** Loads the key slots. */
    fun loadSlots() = guarded(clearMessage = false) {
        publishPrivate(_slots) { repository.slots() }
    }

    /** Sets or clears the favourite flag. */
    fun setFavorite(objectId: ByteArray, favorite: Boolean, onSuccess: () -> Unit = {}) = guarded {
        withContext(Dispatchers.Default) { repository.setFavorite(objectId, favorite) }
        reload()
        onSuccess()
    }

    fun setFavoritesForAll(objectIds: List<ByteArray>, favorite: Boolean,
                           onSuccess: () -> Unit = {}) = guarded {
        withContext(Dispatchers.Default) { repository.setFavorites(objectIds, favorite) }
        reload()
        say("Updated ${items(objectIds.size)}.")
        onSuccess()
    }

    /**
     * Moves an object to the recoverable trash.
     *
     * The move is confirmed with a count and an undo, `DESIGN.md` §26: a
     * mis-tap is taken back from the snackbar rather than from Trash. The
     * notice is set before [onSuccess], so a host that closes the viewer
     * there shows it in the shell.
     */
    fun delete(objectId: ByteArray, onSuccess: () -> Unit = {}) = guarded {
        withContext(Dispatchers.Default) { repository.delete(objectId) }
        reload()
        refreshAlbums()
        sayTrashed(listOf(objectId))
        onSuccess()
    }

    /**
     * Moves every selected object to trash in one transaction.
     *
     * One reload rather than one per object: the page is read once at the end,
     * so a selection of two hundred does not redraw the grid two hundred times.
     */
    fun deleteAll(objectIds: List<ByteArray>, onSuccess: () -> Unit = {}) = guarded {
        withContext(Dispatchers.Default) { repository.deleteAll(objectIds) }
        reload()
        refreshAlbums()
        sayTrashed(objectIds)
        onSuccess()
    }

    fun restoreAll(objectIds: List<ByteArray>, onSuccess: () -> Unit = {}) = guarded {
        withContext(Dispatchers.Default) { repository.restoreAll(objectIds) }
        reload()
        refreshAlbums()
        say("Restored ${items(objectIds.size)}.")
        onSuccess()
    }

    fun permanentlyDeleteAll(objectIds: List<ByteArray>, onSuccess: () -> Unit = {}) = guarded {
        try {
            withContext(Dispatchers.Default) { objectIds.forEach { repository.permanentlyDelete(it) } }
        } finally {
            thumbnails.clear()
            reload()
            refreshAlbums()
        }
        say("Deleted permanently.")
        onSuccess()
    }

    fun deleteDamagedFiles() = guarded {
        try {
            withContext(Dispatchers.Default) { repository.deleteDamagedFiles() }
        } finally {
            thumbnails.clear()
            reload()
            refreshAlbums()
        }
        say("Damaged files deleted permanently.")
    }

    fun emptyTrash(onSuccess: () -> Unit = {}) = guarded {
        try {
            withContext(Dispatchers.Default) { repository.emptyTrash() }
        } finally {
            thumbnails.clear()
            reload()
            refreshAlbums()
        }
        say("Deleted permanently.")
        onSuccess()
    }

    fun restoreTrash(onSuccess: () -> Unit = {}) = guarded {
        withContext(Dispatchers.Default) { repository.restoreTrash() }
        reload()
        refreshAlbums()
        // The engine does not return how many it restored.
        say("Restored everything in Trash.")
        onSuccess()
    }

    /**
     * Removes every selected object from one album, §11.4.
     *
     * It is a separate action from [deleteAll]: one changes a membership and
     * the other moves the object out of ordinary library scopes.
     */
    fun removeAllFromAlbum(
        albumId: ByteArray,
        objectIds: List<ByteArray>,
        onSuccess: () -> Unit = {},
    ) = guarded {
        withContext(Dispatchers.Default) {
            repository.removeAlbumObjects(albumId, objectIds)
        }
        reload()
        refreshAlbums()
        say("Removed ${items(objectIds.size)} from the album.")
        onSuccess()
    }

    /**
     * Adds or moves a selection in one catalog transaction.
     *
     * The notice names a count and never the album: `DESIGN.md` §26 keeps
     * private names out of a snackbar. A host that reports its own outcome
     * from [onSuccess], as an import into an album does, replaces it.
     */
    fun placeObjectsInAlbum(
        albumId: ByteArray,
        objectIds: List<ByteArray>,
        fromAlbumId: ByteArray? = null,
        move: Boolean = false,
        expectedGeneration: Long? = null,
        onSuccess: () -> Unit = {},
    ) = guarded {
        withContext(Dispatchers.Default) {
            repository.placeAlbumObjects(albumId, "", null, fromAlbumId.takeIf { move }, objectIds, move, expectedGeneration)
        }
        if (expectedGeneration != null && (repository.state.value as? VaultState.Unlocked)?.generation != expectedGeneration) return@guarded
        reload()
        refreshAlbums()
        sayPlaced(objectIds.size, move)
        onSuccess()
    }

    /** Creates a destination and places the selection atomically. */
    fun createAlbumWithObjects(
        name: String,
        parentId: ByteArray?,
        objectIds: List<ByteArray>,
        fromAlbumId: ByteArray? = null,
        move: Boolean = false,
        onSuccess: () -> Unit = {},
    ) = guarded {
        withContext(Dispatchers.Default) {
            repository.placeAlbumObjects(null, name, parentId, fromAlbumId.takeIf { move }, objectIds, move)
        }
        reload()
        refreshAlbums()
        sayPlaced(objectIds.size, move)
        onSuccess()
    }

    /** Creates an album and reloads the list. */
    fun createAlbum(name: String) = guarded {
        withContext(Dispatchers.Default) { repository.createAlbum(name) }
        refreshAlbums()
    }

    fun renameAlbum(albumId: ByteArray, name: String) = guarded {
        withContext(Dispatchers.Default) { repository.renameAlbum(albumId, name) }
        refreshAlbums()
    }

    fun deleteAlbum(albumId: ByteArray, onSuccess: () -> Unit = {}) = guarded {
        withContext(Dispatchers.Default) { repository.deleteAlbum(albumId) }
        reload()
        refreshAlbums()
        say("Album deleted.")
        onSuccess()
    }

    fun moveAlbum(
        albumId: ByteArray,
        parentId: ByteArray?,
        beforeId: ByteArray?,
        onSuccess: () -> Unit = {},
    ) = guarded {
        withContext(Dispatchers.Default) { repository.moveAlbum(albumId, parentId, beforeId) }
        refreshAlbums()
        onSuccess()
    }

    fun moveAlbumMember(
        albumId: ByteArray,
        objectId: ByteArray,
        beforeId: ByteArray?,
        onSuccess: () -> Unit = {},
    ) = guarded {
        withContext(Dispatchers.Default) { repository.moveAlbumMember(albumId, objectId, beforeId) }
        reload()
        onSuccess()
    }

    /** Applies or removes one tag across the selected objects. */
    fun setTagForAll(
        tagId: ByteArray,
        objectIds: List<ByteArray>,
        tagged: Boolean,
        onSuccess: () -> Unit = {},
    ) = guarded {
        withContext(Dispatchers.Default) {
            repository.applyTagSelection(tagId, "", objectIds, tagged)
        }
        reload()
        say("Updated ${items(objectIds.size)}.")
        onSuccess()
    }

    /** Creates a tag and applies it to the selection. */
    fun createTagWithObjects(name: String, objectIds: List<ByteArray>, onSuccess: () -> Unit = {}) = guarded {
        withContext(Dispatchers.Default) {
            repository.applyTagSelection(null, name, objectIds, true)
        }
        reload()
        publishPrivate(_tags) { repository.tags() }
        say("Updated ${items(objectIds.size)}.")
        onSuccess()
    }

    fun createTag(name: String) = guarded {
        withContext(Dispatchers.Default) { repository.createTag(name) }
        publishPrivate(_tags) { repository.tags() }
    }

    fun renameTag(tagId: ByteArray, name: String) = guarded {
        withContext(Dispatchers.Default) { repository.renameTag(tagId, name) }
        reload()
        publishPrivate(_tags) { repository.tags() }
    }

    fun deleteTag(tagId: ByteArray, onSuccess: () -> Unit = {}) = guarded {
        withContext(Dispatchers.Default) { repository.deleteTag(tagId) }
        reload()
        publishPrivate(_tags) { repository.tags() }
        say("Tag deleted.")
        onSuccess()
    }

    /** Confirms a move to Trash with its count and an undo that restores it. */
    private suspend fun sayTrashed(objectIds: List<ByteArray>) {
        say("Moved ${items(objectIds.size)} to Trash.", action = "Undo" to { restoreAll(objectIds) })
    }

    private suspend fun sayPlaced(count: Int, move: Boolean) {
        say("${if (move) "Moved" else "Added"} ${items(count)} to the album.")
    }

    // Foreground-only peer synchronization. Network state never enters durable storage.
    fun listenForPeer(address: String) = peerAction { it.listen(address) }
    fun connectToPeer(invitation: String) = peerAction { it.connect(invitation) }
    fun stopPeerSync() { sessionSync.cancelChildren() }

    private fun peerAction(action: suspend (PeerSyncCoordinator) -> Unit) = guarded(copy = ::peerCopy, context = sessionSync) {
        val engine = sync ?: return@guarded
        val generation = (repository.state.value as? VaultState.Unlocked)?.generation ?: return@guarded
        val prompt = if (localNetworkAlert) beginPrompt() else null
        try { withSyncCatalogRefresh(generation) { withContext(Dispatchers.Default) { action(engine) } } }
        finally { prompt?.let(::endPrompt) }
    }

    internal suspend fun <T> withSyncCatalogRefresh(generation: Long, operation: suspend () -> T): T =
        try { operation() } finally { refreshAlbums(generation); reload(generation) }

    fun prepareDevicePairing() = pairingAction {
        val request = (sync ?: return@pairingAction).prepareDevicePairing()
        _devicePairing.value = _devicePairing.value.copy(
            requestCode = request.request.toHex().chunked(32).joinToString("\n"),
            requestFingerprint = request.fingerprint,
        )
    }
    fun inspectDevicePairing(requestHex: String) = pairingAction {
        val preview = (sync ?: return@pairingAction).inspectDevicePairing(pairingRequestBytes(requestHex))
        _pairingApproval.value?.fill(0)
        _pairingApproval.value = null
        _devicePairing.value = _devicePairing.value.copy(
            inspectedRequestCode = requestHex, inspectedFingerprint = preview.fingerprint, approvalReady = false,
        )
    }
    fun approveDevicePairing(requestHex: String, expectedFingerprint: String) = pairingAction {
        val engine = sync ?: return@pairingAction
        val preview = _devicePairing.value
        if (preview.inspectedRequestCode != requestHex || preview.inspectedFingerprint != expectedFingerprint)
            throw ChurFailure(ChurStatus.AUTHENTICATION_FAILED, "compare the device fingerprint again")
        val approval = withContext(Dispatchers.Default) { engine.approveDevicePairing(pairingRequestBytes(requestHex), expectedFingerprint) }
        _pairingApproval.value?.fill(0)
        _pairingApproval.value = approval
        _devicePairing.value = _devicePairing.value.copy(approvalReady = true)
        say("Device approved. Save the encrypted approval file and connect directly to finish pairing.")
    }
    fun acceptPairingApproval(approval: ByteArray) {
        if (_devicePairing.value.busy) return
        val captured = approval.copyOf()
        pairingAction {
            try {
                withContext(Dispatchers.Default) { sync?.acceptPairingApproval(captured) }
                say("Approval verified. Connect directly to the approving device to finish pairing.")
            } finally { captured.fill(0) }
        }
    }
    fun loadPairedDevices() = pairingAction {
        _devicePairing.value = _devicePairing.value.copy(devices = sync?.pairedDevices())
    }
    fun revokePairedDevice(peer: dev.po4yka.chur.ffi.PairedDevice) = pairingAction {
        val engine = sync ?: return@pairingAction
        withContext(Dispatchers.Default) { engine.revokePairedDevice(peer.deviceId, peer.fingerprint) }
        _devicePairing.value = _devicePairing.value.copy(devices = engine.pairedDevices())
        say("Device revoked locally. Sync with your other devices to propagate the revocation.")
    }
    private fun pairingAction(body: suspend () -> Unit) {
        if (_devicePairing.value.busy) return
        val epoch = lockEpoch
        _devicePairing.value = _devicePairing.value.copy(busy = true)
        guarded(context = sessionSync) {
            try { body() } finally {
                if (lockEpoch == epoch) _devicePairing.value = _devicePairing.value.copy(busy = false)
            }
        }
    }
    private fun pairingRequestBytes(requestHex: String): ByteArray {
        val compact = requestHex.filterNot(Char::isWhitespace)
        if (compact.length != 420) throw ChurFailure(ChurStatus.INVALID_INPUT, "invalid device request length")
        return try { compact.fromHex() } catch (_: IllegalArgumentException) {
            throw ChurFailure(ChurStatus.INVALID_INPUT, "invalid hexadecimal device request")
        }
    }

    /**
     * Stages a recovery slot and shows the phrase once, after the device
     * authentication of `DESIGN.md` §17.1 step 2. Settings calls it from the
     * confirm of the step 1 explanation, so the explanation comes first.
     *
     * An open vault alone does not prove who holds the device, and a phrase
     * set up here opens the vault from anywhere. So the platform prompt runs
     * first, under the device-slot policy in force: with "Biometrics only" on,
     * the device unlock code does not pass it. A cancel returns quietly, and
     * a device with no factor to ask for gets no phrase until it has one. The
     * Local Authentication sheet only makes the scene resign active, and from
     * API 30 the Android prompt and its device credential are SystemUI
     * windows, so the check is a [beginPrompt]: a user who leaves the app
     * during it is locked out at once, and an answer that comes after that
     * shows nothing. Only where [DeviceUnlock.ownerCheckTakesScreen] says the
     * prompt can hand over to a full-screen credential activity, the API 29
     * device credential, is it bracketed as a picker is. Either bracket ends
     * once, in the `finally` below. [create] asks nothing: the vault
     * credential was entered a moment before.
     *
     * Nothing is committed yet, so the slot list stays as it is:
     * [acknowledgeRecoveryPhrase] commits it, and Settings reloads the slots
     * when it is entered again.
     */
    fun addRecoverySlot() = requestPhrase {
        val session = privateSession() ?: return@requestPhrase
        val strict = _deviceSlotStrict.value
        val android = deviceUnlock.available
        val prompt = if (deviceUnlock.ownerCheckTakesScreen(strict)) {
            beginHostActivity()
            null
        } else {
            beginPrompt()
        }
        var current = true
        val check = try {
            if (android) {
                deviceUnlock.confirmOwner(strict)
            } else {
                appleDeviceUnlock.confirmOwner(strict)
            }
        } catch (_: ChurFailure) {
            // A lockout, or a prompt the platform could not show. The unlock
            // line of [userCopy] would send the user to recovery, which is
            // what they are setting up.
            say("This device could not confirm it's you. Try again.")
            return@requestPhrase
        } finally {
            if (prompt == null) endHostActivity() else current = endPrompt(prompt)
        }
        if (!current || !session.isCurrent()) return@requestPhrase
        when (check) {
            OwnerCheck.CONFIRMED -> Unit
            OwnerCheck.CANCELLED -> return@requestPhrase
            OwnerCheck.NOT_SET_UP -> {
                say(
                    if (strict) {
                        "Set up a fingerprint or face unlock first. With Biometrics only on, " +
                            "Chur asks for it before it shows a recovery phrase."
                    } else {
                        "Set a screen lock on this device first. Chur asks for it before it " +
                            "shows a recovery phrase."
                    },
                )
                return@requestPhrase
            }
        }
        val phrase = nativeEntry(session.epoch) { repository.beginRecoverySlot() }
        if (session.isCurrent()) _recoveryPhrase.value = phrase
    }

    /** Replaces the password slot with a password or a long numeric PIN. */
    fun changePassword(password: String) = guarded {
        if (!isAcceptableNewPassword(password)) {
            say(NEW_PASSWORD_RULE)
            return@guarded
        }
        val bytes = password.encodeToByteArray()
        try {
            withContext(Dispatchers.Default) { repository.changePassword(bytes) }
        } finally {
            bytes.fill(0)
        }
        say("Vault credential changed. Existing backups still use the old credential.")
        publishPrivate(_slots) { repository.slots() }
    }

    /** One object's detail record, §6.5. */
    suspend fun detailOf(objectId: ByteArray): ObjectDetail? {
        val guideToken = guide.session.value?.token
        return try {
            withContext(Dispatchers.Default) { repository.detail(objectId) }.also {
                guide.event(dev.po4yka.chur.app.onboarding.GuideStep.OPEN, guideToken)
            }
        } catch (failure: ChurFailure) {
            say(userCopy(failure.status))
            null
        }
    }

    /**
     * Exports one object, `PLAINTEXT_LIFECYCLE.md` §6.
     *
     * The message says the copy is outside the vault rather than reporting a
     * silent success: §6 makes this the moment the user deliberately leaves the
     * boundary, and recipients, editors, and share extensions persist plaintext
     * under their own policies from here on.
     */
    fun export(objectId: ByteArray, target: ExportTarget = ExportTarget.DEFAULT, uri: String? = null) =
        guarded { tracked("export") { token -> exportOne(objectId, token, target, uri) } }

    /** Records real editor activity without keeping an idle session alive by polling. */
    fun recordPrivateNoteActivity(generation: Long) {
        scope.launch(Dispatchers.Default) {
            try { repository.privateNoteActivity(generation) } catch (_: ChurFailure) {
                // A late input event from a removed private route is discarded.
            }
        }
    }

    /** Exports the selected saved revision after the host's plaintext warning. */
    fun exportPrivateNote(request: PrivateNoteExportRequest, target: ExportTarget, uri: String? = null) = guarded {
        // Own an already-created SAF document even if another operation won
        // the race while the picker was open. A refusal still removes it.
        var destination = if (target == ExportTarget.FILES && uri != null) {
            withContext(Dispatchers.Default) { exports.create("", "", target, uri) }
                ?: throw ChurFailure(ChurStatus.IO_FAILURE, "the export destination")
        } else null
        var published = false
        try {
            tracked("export") { token ->
                fun checkSession() {
                    if ((repository.state.value as? VaultState.Unlocked)?.generation != request.generation) {
                        throw ChurFailure(ChurStatus.SESSION_EXPIRED, "the private note export")
                    }
                    if (cancellationRequested(token)) throw ChurFailure(ChurStatus.CANCELLED, "the private note export")
                }
                checkSession()
                val output = destination ?: withContext(Dispatchers.Default) { exports.create(
                    request.filename, request.contentType, target, uri, request.exportSize,
                ) } ?: throw ChurFailure(ChurStatus.IO_FAILURE, "the export destination")
                destination = output
                checkSession()
                val nativeOperation = withContext(Dispatchers.Default) {
                    val attachmentId = request.attachmentId
                    if (attachmentId == null) repository.beginPrivateNoteExport(request.generation, request.noteId, request.revision, output.descriptor)
                    else repository.beginPrivateNoteAttachmentExport(request.generation, request.noteId, request.revision, attachmentId, output.descriptor)
                }
                val terminal = try { drain(nativeOperation, token) } finally { closeOperation(nativeOperation) }
                if (terminal != 0) throw ChurFailure(ChurStatus.fromValue(terminal), "the private note export")
                checkSession()
                if (!withContext(Dispatchers.Default) { output.publishChecked() }) throw ChurFailure(ChurStatus.IO_FAILURE, "the export destination")
                checkSession()
                published = true
                say("Note exported. The destination may keep an unencrypted copy.")
            }
        } finally {
            try { if (!published) destination?.discard() } finally { destination?.close() }
        }
    }

    private suspend fun exportOne(objectId: ByteArray, token: Long, target: ExportTarget, uri: String?) {
        // A SAF document exists as soon as the picker returns. Own it before
        // reading catalog metadata so even an invalidated object deletes it.
        var destination = if (target == ExportTarget.FILES && uri != null) {
            withContext(Dispatchers.Default) { exports.create("", "", target, uri) }
                ?: throw ChurFailure(ChurStatus.IO_FAILURE, "the export destination")
        } else null
        var published = false
        try {
            val detail = withContext(Dispatchers.Default) { repository.detail(objectId) }
            val output = destination ?: withContext(Dispatchers.Default) { exports.create(
                detail.filename.ifBlank { "chur-export" }, detail.contentType, target, uri, detail.plaintextSize,
            ) } ?: throw ChurFailure(ChurStatus.IO_FAILURE, "the export destination")
            destination = output
            writeVerifiedExport(objectId, output, token)
            published = true
            say("Export prepared. The destination may keep a plaintext copy.")
        } finally {
            try {
                if (!published) destination?.discard()
            } finally {
                destination?.close()
            }
        }
    }

    /** Writes only a complete verified object; the caller owns destination cleanup. */
    private suspend fun writeVerifiedExport(objectId: ByteArray, output: ExportSink.Destination, token: Long) {
        if (cancellationRequested(token)) throw ChurFailure(ChurStatus.CANCELLED, "the export")
        val operation = withContext(Dispatchers.Default) { repository.beginExport(objectId, output.descriptor) }
        val terminal = try { drain(operation, token) } finally { closeOperation(operation) }
        if (terminal != 0) throw ChurFailure(ChurStatus.fromValue(terminal), "the export")
        if (cancellationRequested(token) || repository.state.value !is VaultState.Unlocked) {
            throw ChurFailure(ChurStatus.CANCELLED, "the export")
        }
        // Provider delivery can wait after native keys are released. Keep it off Main.
        if (!withContext(Dispatchers.Default) { output.publishChecked() }) throw ChurFailure(ChurStatus.IO_FAILURE, "the export destination")
        // A lock or cancellation while a provider publishes still owns this file.
        if (cancellationRequested(token) || repository.state.value !is VaultState.Unlocked) {
            throw ChurFailure(ChurStatus.CANCELLED, "the export")
        }
    }

    /** Restores one complete Live Photo into a new folder in the selected directory. */
    fun restoreLivePhoto(objectId: ByteArray, uri: String) {
        val requestedGeneration = (repository.state.value as? VaultState.Unlocked)?.generation
        val requestedObject = objectId.copyOf()
        guarded {
            var root: ExportDirectory? = null
            var child: ExportDirectory? = null
            try {
                tracked("live-photo-export") { token ->
                    withContext(Dispatchers.Default) {
                        // Own the selected grant even if the session changed while
                        // the system folder picker was open.
                        root = exports.openDirectory(uri)
                            ?: throw ChurFailure(ChurStatus.IO_FAILURE, "the Live Photo directory")
                        fun cancelled() = cancellationRequested(token) || requestedGeneration == null ||
                            (repository.state.value as? VaultState.Unlocked)?.generation != requestedGeneration
                        if (cancelled()) throw ChurFailure(ChurStatus.CANCELLED, "the Live Photo export")
                        child = root?.createDirectory("Live Photo")
                            ?: throw ChurFailure(ChurStatus.IO_FAILURE, "the Live Photo directory")
                        val count = restoreLivePhotoResources(repository, requestedObject, requireNotNull(child),
                            cancelled = ::cancelled,
                            onProgress = { item, total ->
                                _activeOperation.update { current -> current?.takeIf { it.id == token }?.copy(
                                    item = item, items = total, processed = 0, total = 0, stage = 1, cancellable = true,
                                ) ?: current }
                            })
                        say("Live Photo restored: $count resources and a portable original. Exported copies are unencrypted.")
                    }
                }
            } finally {
                withContext(NonCancellable + Dispatchers.Default) {
                    try { child?.close() } finally { root?.close() }
                }
            }
        }
    }

    /** Exports the complete album tree, independently of the visible query and loaded page. */
    fun exportAlbum(albumId: ByteArray, uri: String) {
        val requestedGeneration = (repository.state.value as? VaultState.Unlocked)?.generation
        val requestedAlbum = albumId.copyOf()
        guarded {
            // Consume a selected-folder token even if another operation wins
            // the race, so its platform access never waits for the next lock.
            var selectedRoot: ExportDirectory? = null
            var outcome: AlbumExportOutcome? = null
            var cleanupFailed = false
            var rootClosed = false
            suspend fun closeRoot() {
                if (rootClosed) return
                rootClosed = true
                withContext(NonCancellable + Dispatchers.Default) {
                    try { selectedRoot?.close() }
                    catch (cancel: CancellationException) { throw cancel }
                    catch (_: Exception) { cleanupFailed = true }
                }
            }
            try {
                // Assign before resuming the caller: cancellation during the
                // dispatcher handoff must still leave a lease for finally.
                withContext(Dispatchers.Default) {
                    selectedRoot = exports.openDirectory(uri)
                        ?: throw ChurFailure(ChurStatus.IO_FAILURE, "the export directory")
                }
                val root = requireNotNull(selectedRoot)
                outcome = tracked("album-export") { token ->
                    try {
                        withContext(Dispatchers.Default) {
                            fun invalidated() = requestedGeneration == null ||
                                (repository.state.value as? VaultState.Unlocked)?.generation != requestedGeneration
                            if (invalidated()) throw ChurFailure(ChurStatus.CANCELLED, "the album export")
                            // Snapshot before reading the tree as well as its
                            // memberships, so a concurrent album move cannot
                            // disappear between those two catalog reads.
                            val catalogGeneration = repository.page(ObjectQuery(limit = 1)).catalogGeneration
                            exportAlbumTree(
                                albumId = requestedAlbum,
                                albums = repository.albums(),
                                root = root,
                                page = repository::page,
                                expectedGeneration = catalogGeneration,
                                cancelled = { cancellationRequested(token) || invalidated() },
                                onItem = { item, count ->
                                    _activeOperation.update { current -> current?.takeIf { it.id == token }?.copy(
                                        item = item, items = count, processed = 0, total = 0, stage = 1,
                                        cancellable = true,
                                    ) ?: current }
                                },
                                export = { directory, objectId ->
                                    val detail = repository.detail(objectId)
                                    if (invalidated()) throw ChurFailure(ChurStatus.CANCELLED, "the album export")
                                    val destination = directory.createFile(
                                        safeExportName(detail.filename, "chur-export"), detail.contentType, detail.plaintextSize,
                                    ) ?: throw ChurFailure(ChurStatus.IO_FAILURE, "the export destination")
                                    var published = false
                                    try {
                                        writeVerifiedExport(objectId, destination, token)
                                        if (invalidated()) throw ChurFailure(ChurStatus.CANCELLED, "the album export")
                                        published = true
                                    } finally {
                                        try { if (!published) destination.discard() } finally { destination.close() }
                                    }
                                },
                            )
                        }
                    } finally { closeRoot() }
                }
            } finally { closeRoot() }
            outcome?.let {
                val result = if (cleanupFailed) it.copy(status = it.status ?: ChurStatus.IO_FAILURE, cleanupFailed = true) else it
                say(result.summary(), security = result.status in SECURITY_STATUSES)
            }
        }
    }

    /**
     * Exports every selected object, one destination each.
     *
     * A single archive would be a second container format, which
     * `CANONICAL_ENCODING_V1.md` §13 does not admit, so the loop is the design
     * rather than a simplification.
     */
    fun exportAll(
        objectIds: List<ByteArray>,
        target: ExportTarget = ExportTarget.DEFAULT,
        onSuccess: () -> Unit = {},
    ) = guarded {
        var exported = 0
        try {
            tracked("export") { token ->
                objectIds.forEach {
                    if (cancellationRequested(token)) {
                        throw ChurFailure(ChurStatus.CANCELLED, "the export")
                    }
                    exportOne(it, token, target, null)
                    exported += 1
                }
                if (cancellationRequested(token)) {
                    throw ChurFailure(ChurStatus.CANCELLED, "the export")
                }
                onSuccess()
            }
        } catch (failure: ChurFailure) {
            if (failure.status == ChurStatus.CANCELLED && exported > 0) {
                say("Cancelled after exporting $exported. Exported copies remain outside the vault.")
            } else {
                throw failure
            }
        }
    }

    private val archiveCredentials = mutableSetOf<ArchiveCredentialHold>()

    /** Register on the UI thread before starting archive staging or a queued native call. */
    fun retainArchiveCredential(credential: ArchiveCredential): ArchiveCredentialHold =
        ArchiveCredentialHold(credential) { archiveCredentials.remove(it) }.also { archiveCredentials.add(it) }

    private fun clearArchiveCredentials() {
        val pending = archiveCredentials.toList()
        archiveCredentials.clear()
        pending.forEach { it.revoke() }
    }

    private var externalArchiveSecret: ArchiveCredential? = null
    private var externalArchiveBytes: ByteArray? = null
    private fun clearExternalArchiveSecret() {
        externalArchiveSecret?.clear(); externalArchiveSecret = null
        externalArchiveBytes?.fill(0); externalArchiveBytes = null
    }
    private var externalArchiveReturn: AppRoute = AppRoute.PublicSettings
    private var externalArchiveGeneration: Long? = null
    internal val externalArchiveVisit: Long get() = routeVisit
    internal fun externalArchiveCurrent(visit: Long): Boolean =
        _route.value == AppRoute.EncryptFiles && routeVisit == visit

    fun openExternalArchive() {
        if (_route.value != AppRoute.PublicSettings && _route.value != AppRoute.Vault) return
        if (_activeOperation.value != null) { report("Finish the current operation first."); return }
        externalArchiveReturn = _route.value
        externalArchiveGeneration = (repository.state.value as? VaultState.Unlocked)?.generation
        privacy.setEnabled(true)
        setRoute(AppRoute.EncryptFiles)
    }

    fun closeExternalArchive() {
        if (_route.value != AppRoute.EncryptFiles) return
        cancelActiveOperation()
        val sameVault = externalArchiveGeneration != null &&
            (repository.state.value as? VaultState.Unlocked)?.generation == externalArchiveGeneration
        val next = if (externalArchiveReturn == AppRoute.Vault && sameVault) AppRoute.Vault else AppRoute.PublicSettings
        setRoute(next)
        privacy.setEnabled(next == AppRoute.Vault)
    }

    internal fun externalArchiveActivity(visit: Long): (() -> Unit)? {
        if (!externalArchiveCurrent(visit)) return null
        val epoch = promptEpoch
        beginHostActivity()
        var ended = false
        return {
            if (!ended) {
                ended = true
                if (promptEpoch == epoch) endHostActivity()
            }
        }
    }

    /** Encrypts provider inputs into a fresh-key CHURBAK1 without touching the library. */
    fun exportExternalArchive(
        visit: Long,
        selection: ExternalArchiveSelection,
        credential: ArchiveCredential,
        target: ExportTarget,
        uri: String? = null,
    ) = guarded {
        val opened = mutableListOf<dev.po4yka.chur.imports.PickedMedia>()
        var destination: ExportSink.Destination? = null
        var password: ByteArray? = null
        var published = false
        var nativeOperation: Long? = null
        try {
            if (target == ExportTarget.FILES && uri != null) {
                destination = withContext(Dispatchers.Default) { exports.createArchive("", "", target, uri) }
                    ?: throw ChurFailure(ChurStatus.IO_FAILURE, "the archive destination")
            }
            tracked("external-archive") { token ->
                fun checkOwner() {
                    if (!externalArchiveCurrent(visit) || cancellationRequested(token)) {
                        throw ChurFailure(ChurStatus.CANCELLED, "the external archive")
                    }
                }
                checkOwner()
                externalArchiveSecret = credential
                if (selection.count !in 1..32 || target !in listOf(ExportTarget.FILES, ExportTarget.SHARE)) {
                    throw ChurFailure(ChurStatus.INVALID_INPUT, "the external archive")
                }
                val files = mutableListOf<dev.po4yka.chur.ffi.ExternalArchiveFile>()
                var knownTotal = 0L
                for (index in 0 until selection.count) {
                    checkOwner()
                    val source = withContext(Dispatchers.Default) {
                        selection.open(index) { _, _ ->
                            externalArchiveCurrent(visit) && !cancellationRequested(token)
                        }?.also { opened += it }
                    } ?: throw ChurFailure(ChurStatus.IO_FAILURE, "the external file")
                    checkOwner()
                    source.knownLength?.let { size ->
                        if (size < 0 || size > 4L * 1024 * 1024 * 1024 - knownTotal) {
                            throw ChurFailure(ChurStatus.RESOURCE_LIMIT_EXCEEDED, "the external files")
                        }
                        knownTotal += size
                    }
                    files += dev.po4yka.chur.ffi.ExternalArchiveFile(source.nativeDescriptor,
                        source.originalFilename?.takeIf { it.isNotBlank() } ?: "file-${index + 1}", source.contentTypeHint, source.knownLength)
                }
                val capacity = if (destination != null) Long.MAX_VALUE else exports.archiveCapacity(target)
                if (capacity <= 0) throw ChurFailure(ChurStatus.RESOURCE_LIMIT_EXCEEDED, "the archive destination")
                val output = destination ?: withContext(Dispatchers.Default) { exports.createArchive("chur-archive.churbak", "application/octet-stream", target, uri, capacity) }
                    ?: throw ChurFailure(ChurStatus.IO_FAILURE, "the archive destination")
                destination = output
                val bytes = credential.copyBytes()
                password = bytes
                externalArchiveBytes = bytes
                try {
                    withContext(Dispatchers.Default) {
                        nativeOperation = repository.beginExternalArchive(files, bytes, output.descriptor, capacity)
                    }
                } finally { bytes.fill(0); credential.clear() }
                val operation = requireNotNull(nativeOperation)
                val result = drainProgress(operation, token, keepVaultAlive = false)
                closeOperation(operation)
                nativeOperation = null
                if (result.status != 0) throw ChurFailure(ChurStatus.fromValue(result.status), "the external archive")
                checkOwner()
                if (!withContext(Dispatchers.Default) { output.publishChecked() }) throw ChurFailure(ChurStatus.IO_FAILURE, "the archive destination")
                checkOwner()
                published = true
                say("Encrypted archive ready. Use its password to restore it or import fresh copies. The library was not changed.")
            }
        } finally {
            nativeOperation?.let { runCatching { closeOperation(it) } }
            password?.fill(0)
            credential.clear()
            if (externalArchiveSecret === credential) clearExternalArchiveSecret()
            opened.forEach { runCatching { it.close() } }
            runCatching { selection.close() }
            destination?.let { output ->
                try { if (!published) output.discard() } finally { output.close() }
            }
        }
    }

    /** Writes a fresh-key archive; no source credential or unrelated catalog row leaves the vault. */
    fun exportSelectiveArchive(
        request: SelectiveExportRequest,
        credential: ArchiveCredential,
        target: ExportTarget,
        uri: String? = null,
    ) = guarded {
        var bytes: ByteArray? = null
        var destination: ExportSink.Destination? = null
        var published = false
        try {
            // A returned SAF URI already names an empty file, including on a busy refusal.
            if (target == ExportTarget.FILES && uri != null) {
                destination = withContext(Dispatchers.Default) { exports.createArchive("", "", target, uri) }
                    ?: throw ChurFailure(ChurStatus.IO_FAILURE, "the archive destination")
            }
            tracked("archive-export") { token ->
                fun checkSession() {
                    if ((repository.state.value as? VaultState.Unlocked)?.generation != request.generation) {
                        throw ChurFailure(ChurStatus.SESSION_EXPIRED, "the archive export")
                    }
                    if (cancellationRequested(token)) throw ChurFailure(ChurStatus.CANCELLED, "the archive export")
                }
                checkSession()
                if (target != ExportTarget.FILES && target != ExportTarget.SHARE) {
                    throw ChurFailure(ChurStatus.INVALID_INPUT, "the archive destination")
                }
                val capacity = if (destination != null) Long.MAX_VALUE else exports.archiveCapacity(target)
                if (capacity <= 0) throw ChurFailure(ChurStatus.RESOURCE_LIMIT_EXCEEDED, "the archive destination")
                val output = destination ?: withContext(Dispatchers.Default) { exports.createArchive("chur-archive.churbak", "application/octet-stream", target, uri, capacity) }
                    ?: throw ChurFailure(ChurStatus.IO_FAILURE, "the archive destination")
                destination = output
                val password = credential.copyBytes()
                bytes = password
                val nativeOperation = try {
                    withContext(Dispatchers.Default) {
                        repository.beginSelectiveExport(request.generation, request.objectIds, request.albumIds,
                            request.notes, password, output.descriptor, capacity)
                    }
                } finally { password.fill(0); credential.clear() }
                val result = try { drainProgress(nativeOperation, token) } finally { closeOperation(nativeOperation) }
                if (result.status != 0) throw ChurFailure(ChurStatus.fromValue(result.status), "the archive export")
                checkSession()
                if (!withContext(Dispatchers.Default) { output.publishChecked() }) throw ChurFailure(ChurStatus.IO_FAILURE, "the archive destination")
                checkSession()
                published = true
                say("Encrypted archive ready. Open it with its archive password using Restore or Import encrypted archive.")
            }
        } finally {
            bytes?.fill(0)
            credential.clear()
            try { if (!published) destination?.discard() } finally { destination?.close() }
        }
    }

    /** Removes a document returned to a disposed Android picker owner. */
    fun discardArchiveDestination(uri: String) = guarded(clearMessage = false) {
        val destination = withContext(Dispatchers.Default) { exports.create("", "", ExportTarget.FILES, uri) } ?: return@guarded
        try { destination.discard() } finally { destination.close() }
    }

    /** Authenticates the complete archive before the native worker adds fresh copies. */
    fun importSelectiveArchive(generation: Long, sourceFd: Int, credential: ArchiveCredential, close: () -> Unit) {
        val hold = retainArchiveCredential(credential)
        guarded {
            var bytes: ByteArray? = null
            try {
                tracked("archive-import") { token ->
                    if ((repository.state.value as? VaultState.Unlocked)?.generation != generation) {
                        throw ChurFailure(ChurStatus.SESSION_EXPIRED, "the archive import")
                    }
                    val password = credential.copyBytes()
                    bytes = password
                    val operation = try {
                        withContext(Dispatchers.Default) { repository.beginSelectiveImport(generation, sourceFd, password) }
                    } finally { password.fill(0); credential.clear() }
                    val result = try { drainProgress(operation, token) } finally { closeOperation(operation) }
                    if ((repository.state.value as? VaultState.Unlocked)?.generation != generation) return@tracked
                    // A failed refresh must not hide items that the native worker already committed.
                    val revision = queryRevision
                    val query = currentQuery.copy(cursor = null)
                    val refreshed = try {
                        withContext(Dispatchers.Default) {
                            fun checkGeneration() {
                                if ((repository.state.value as? VaultState.Unlocked)?.generation != generation) {
                                    throw ChurFailure(ChurStatus.SESSION_EXPIRED, "the archive import")
                                }
                            }
                            checkGeneration()
                            val importedPage = repository.page(query)
                            checkGeneration()
                            val importedAlbums = repository.albums()
                            checkGeneration()
                            val importedTags = repository.tags()
                            checkGeneration()
                            Triple(importedPage, importedAlbums, importedTags)
                        }
                    } catch (cancelled: CancellationException) { throw cancelled
                    } catch (_: Exception) { null }
                    if ((repository.state.value as? VaultState.Unlocked)?.generation != generation) return@tracked
                    if (refreshed != null) {
                        if (queryRevision == revision) _page.value = refreshed.first
                        _albums.value = refreshed.second
                        _tags.value = refreshed.third
                    }
                    val refreshCopy = if (refreshed == null) " Refresh the library to see the imported items." else ""
                    if (result.status == 0) {
                        say("${result.processed} items imported from the encrypted archive. Existing items were kept." + refreshCopy)
                    } else if (result.processed > 0) {
                        say("${result.processed} items saved. Saved originals and notes remain; tags, previews, or album organization may be incomplete. " +
                            userCopy(ChurStatus.fromValue(result.status)) + refreshCopy)
                    } else {
                        throw ChurFailure(ChurStatus.fromValue(result.status), "the archive import")
                    }
                }
            } finally {
                bytes?.fill(0)
                credential.clear()
                hold.release()
                close()
            }
        }
    }

    /** Restore installs an independent identity and leaves the existing vault locked. */
    fun restoreArchiveAsSeparateVault() = guarded {
        if (_activeOperation.value != null) { say("Finish the current operation first."); return@guarded }
        val epoch = endOpenSession()
        if (epoch != lockEpoch) return@guarded
        privacy.setEnabled(true)
        setRoute(AppRoute.RestoreBackup)
    }

    /**
     * Writes a backup package, `BACKUP_FORMAT_V1.md` §5 and §7.
     *
     * The destination is the host's, exactly as an export's is: the picker and
     * the provider are the platform's and this asks for a descriptor. The
     * package is published only on a terminal success, so an interrupted write
     * leaves nothing that looks complete — §7's "incomplete state remains
     * explicitly marked and is never advertised as complete".
     *
     * The message carries counts and no identity. §9 already tells anyone
     * holding the file its size and its creation time; it does not tell them
     * whose vault it is, and neither does this.
     */
    fun createBackup() = guarded {
        tracked("backup") { token ->
            val destination = withContext(Dispatchers.Default) { exports.createArchive("chur-backup", "application/octet-stream", ExportTarget.DEFAULT, null) }
                ?: throw ChurFailure(ChurStatus.IO_FAILURE, "the backup destination")
            var published = false
            try {
                val operation = withContext(Dispatchers.Default) {
                    repository.beginBackup(destination.descriptor)
                }
                val terminal = try {
                    drain(operation, token)
                } finally {
                    closeOperation(operation)
                }
                if (terminal != 0) {
                    throw ChurFailure(ChurStatus.fromValue(terminal), "the backup")
                }
                if (_activeOperation.value?.id != token) {
                    throw ChurFailure(ChurStatus.CANCELLED, "the backup")
                }
                withContext(Dispatchers.Default) { destination.publish() }
                published = true
                say("Backup written. It opens with the password or phrase you use now.")
            } finally {
                try {
                    if (!published) destination.discard()
                } finally {
                    destination.close()
                }
            }
        }
    }

    /**
     * Restores a backup package, `BACKUP_FORMAT_V1.md` §8.
     *
     * It is [createBackup] read backwards and differs in two things, both of
     * them §8's. The operation runs from the runtime rather than from a
     * session, because a restore installs an identity and there may be no
     * session and no vault when it starts; and the credential is the package's
     * own, taken from its portable descriptor at step 2.
     *
     * The source is the host's rather than the [ExportSink]'s. An export
     * destination is one the application creates; a package is a file the user
     * picks, which is a platform picker and not a call. Rust duplicates the
     * descriptor at the boundary, §13 of the FFI contract, so the host may
     * close its own as soon as this returns; [close] returns it here rather
     * than at the host so one lambda ends the attempt on a refusal exactly as
     * on a success, and a descriptor the application keeps is a file the
     * platform cannot reclaim.
     *
     * The bracket is [enrollDeviceSlot]'s, for a longer reason. A restore is
     * the longest operation here, and a background transition during one would
     * move the shell to the public route and take the restore screen, and the
     * progress it shows, with it.
     *
     * The repository published `NoVault` and nothing has asked it since;
     * `start` is that question, it opens no runtime that is already open, and
     * it is what moves the shell from creation to the unlock gate.
     *
     * `CONFLICT` is the exception: a refused restore is a refused creation and
     * says the creation sentence, `DECOY_VAULT.md` §5. Every other message is
     * the status's [userCopy] and nothing more, as every other
     * boundary failure's is: `docs/ERROR_MODEL.md` "Safe metadata" keeps a
     * private value out of it, and the package's password is one. [close] is
     * told whether the user cancelled, so the route can show that calmly
     * rather than as a failure (principle 4 of the same document) without
     * reading the text, which its "Layer mapping" forbids a branch on.
     */
    fun restoreBackup(sourceFd: Int, password: String, close: (cancelled: Boolean) -> Unit) =
        restoreBackup(sourceFd, ArchiveCredential(password), close)

    fun restoreBackup(sourceFd: Int, credential: ArchiveCredential, close: (cancelled: Boolean) -> Unit) {
        val guideToken = guide.session.value?.token
        val hold = retainArchiveCredential(credential)
        guarded {
            var bytes: ByteArray? = null
            var cancelled = false
            var heldActivity = false
            try {
                val password = credential.copyBytes()
                bytes = password
                beginHostActivity()
                heldActivity = true
                tracked("restore") { token ->
                    val operation = withContext(Dispatchers.Default) {
                        repository.beginRestore(sourceFd, password)
                    }
                    val terminal = try {
                        drain(operation, token)
                    } finally {
                        closeOperation(operation)
                    }
                    if (terminal != 0) {
                        cancelled = terminal == ChurStatus.CANCELLED.value
                        if (terminal == ChurStatus.CONFLICT.value) {
                            // The creation sentence: a refused restore is a
                            // refused creation, `DECOY_VAULT.md` §5, and a
                            // reason would answer what §10 refuses to.
                            say("This vault could not be created. Try a different credential.")
                            return@tracked
                        }
                        throw ChurFailure(ChurStatus.fromValue(terminal), "the restore")
                    }
                    withContext(Dispatchers.Default) { repository.start() }
                    guide.event(dev.po4yka.chur.app.onboarding.GuideStep.RESTORE, guideToken)
                    setRoute(AppRoute.Unlock)
                }
            } finally {
                bytes?.fill(0)
                credential.clear()
                hold.release()
                if (heldActivity) endHostActivity()
                close(cancelled)
            }
        }
    }

    /**
     * Provisions a second vault identity, `DECOY_VAULT.md` §3.
     *
     * It routes to the ordinary creation screen. There is no separate decoy
     * flow, and that is the design rather than an omission: §2 gives feature
     * code an opaque session and no durable `isDecoy`, so a second identity is
     * created the way the first one was, with its own root, its own slots, and
     * its own credential.
     *
     * `vault::create` refuses a credential that already opens an identity here,
     * which is §3's distinct-credential rule and also the reason a second
     * identity under a shared password would be unreachable forever.
     */
    fun createSecondIdentity() {
        setRoute(AppRoute.CreateVault)
    }

    /**
     * Checks every library object and says what the check found, `DESIGN.md` §20.
     *
     * "Verified" is the §20.1 name of one presented state, so the result never
     * uses it for a count: it says how many objects were checked and names each
     * kind of problem. The scan's status carries proven corruption alone,
     * `ERROR_MODEL.md` "Integrity states versus errors", and a `CORRUPT` row is
     * in no `CATALOG_SCHEMA_V1.md` §16.2 scope, so "at least one" is the only
     * count there is for it.
     * The other verdicts are integrity states the catalog records, read back
     * after the scan: the quarantine scope's total and the timeline rows left
     * Incomplete or Unsupported. Both are the catalog's present state rather
     * than a difference from before the scan, so an import or a sync racing the
     * scan cannot turn a problem into "no problems found".
     */
    fun verifyEverything() = guarded {
        tracked("verification") { token ->
            val operation = withContext(Dispatchers.Default) { repository.beginIntegrityScan(null) }
            try {
                val result = drainProgress(operation, token)
                val corrupt = result.status == ChurStatus.OBJECT_CORRUPT.value
                if (result.status == 0 || corrupt) {
                    val quarantined = quarantinedCount()
                    val unverifiable = unverifiableCount()
                    // A problem found is an integrity verdict the user acts
                    // on, so it stays until dismissed, `DESIGN.md` §26.
                    say(
                        verificationSummary(result.processed, corrupt, quarantined, unverifiable),
                        security = corrupt || quarantined > 0 || unverifiable > 0,
                    )
                } else {
                    val status = ChurStatus.fromValue(result.status)
                    say(userCopy(status), security = status in SECURITY_STATUSES)
                }
            } finally {
                closeOperation(operation)
                if (repository.state.value is VaultState.Unlocked) reload()
            }
        }
    }

    /**
     * Writes a public note, stamped with the time of the write.
     *
     * The editor calls this as the user types and again as it closes, so this
     * is where a write is told apart from a repeat. A note equal to the stored
     * one apart from its time is not written again, and neither is a new note
     * the user never wrote in: "Create note" and straight back out is not the
     * first public-shell write `DISCREET_MODE.md` discloses. A blank edit of a
     * stored note is written: this cannot tell a note the user emptied, which
     * stays, from one "Create note" made that was written and erased again.
     * The editor knows which note it created, and removes that one through
     * [removeNote] as it leaves it blank. The comparison reads the store
     * rather than [notesState]: the store's lock places the read after every
     * write queued ahead of it, and the projection is refreshed only once each
     * has finished.
     *
     * The time is this controller's clock rather than the one the note carries,
     * which is when it was opened, so an edited note moves up a list that
     * `Notes.ordered` sorts by it.
     */
    suspend fun updatePublicNotes(selected: List<Note>, pinned: Boolean?) {
        for (note in selected) {
            if (pinned == null) trashPublicNote(note)
            else publicNoteWrites.withLock {
                val latest = notes.all().firstOrNull { it.id == note.id } ?: return@withLock
                persistPublicNote(latest.copy(pinned = pinned))
            }
        }
    }

    fun putNote(note: Note) = guarded {
        publicNoteWrites.withLock {
            try {
                persistPublicNote(note)
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (failure: Exception) {
                _publicNoteWriteFailureId.value = note.id
                throw failure
            }
        }
    }

    /** The store owns attachment membership; queued text saves cannot resurrect deleted files. */
    private suspend fun persistPublicNote(note: Note, allowBlank: Boolean = false) {
        check(note.id !in retiredPublicNoteIds) { "note is no longer editable; reopen it" }
        val all = notes.all()
        val stored = all.firstOrNull { it.id == note.id }
        if (!allowBlank && stored == null && note.title.isBlank() && note.body.isBlank()) return
        val current = note.copy(attachments = stored?.attachments.orEmpty(), folder = stored?.folder, tags = stored?.tags.orEmpty(),
            revision = stored?.revision ?: note.revision)
        if (stored != null && stored.copy(updatedMs = current.updatedMs) == current) {
            _notes.value = all
            if (_publicNoteWriteFailureId.value == current.id) _publicNoteWriteFailureId.value = null
            return
        }
        val first = !notes.disclosureAcknowledged()
        notes.put(current.copy(updatedMs = clock()))
        _notes.value = notes.all()
        if (_publicNoteWriteFailureId.value == current.id) _publicNoteWriteFailureId.value = null
        if (first) _disclosureDue.value = true
    }

    suspend fun addPublicNoteAttachment(note: Note, name: String, data: ByteArray): NoteAttachment =
        withContext(Dispatchers.Default) {
            publicNoteWrites.withLock {
                persistPublicNote(note, allowBlank = true)
                val added = notes.addAttachment(note.id, name, data)
                _notes.value = notes.all()
                added
            }
        }

    suspend fun readPublicNoteAttachment(noteId: String, attachmentId: String): ByteArray =
        withContext(Dispatchers.Default) { notes.readAttachment(noteId, attachmentId) }

    suspend fun removePublicNoteAttachment(noteId: String, attachmentId: String) = withContext(Dispatchers.Default) {
        publicNoteWrites.withLock {
            notes.removeAttachment(noteId, attachmentId)
            _notes.value = notes.all()
        }
    }

    suspend fun exportPublicNotePackage(note: Note): ByteArray = withContext(Dispatchers.Default) {
        publicNoteWrites.withLock {
            persistPublicNote(note, allowBlank = true)
            notes.exportPackage(note.id)
        }
    }

    suspend fun importPublicNotePackage(data: ByteArray, noteId: String): Note = withContext(Dispatchers.Default) {
        publicNoteWrites.withLock {
            val first = !notes.disclosureAcknowledged()
            val imported = notes.importPackage(data, noteId, clock())
            _notes.value = notes.all()
            if (first) _disclosureDue.value = true
            imported
        }
    }

    suspend fun publicNoteHistory(id: String): List<dev.po4yka.chur.notes.NoteRevision> =
        withContext(Dispatchers.Default) { publicNoteWrites.withLock { notes.history(id) } }
    suspend fun organizePublicNote(id: String, folder: String?, tags: List<String>) = withContext(Dispatchers.Default) {
        publicNoteWrites.withLock { withContext(NonCancellable) {
            notes.updateOrganization(id, folder, tags)
            _notes.value = notes.all()
        } }
    }
    suspend fun restorePublicNoteRevision(id: String, revision: String): Note = withContext(Dispatchers.Default) {
        publicNoteWrites.withLock { withContext(NonCancellable) {
            val restored = notes.restoreRevision(id, revision)
            _notes.value = notes.all()
            restored
        } }
    }
    fun refreshPublicTrash() = guarded {
        publicNoteWrites.withLock { _trashedNotes.value = notes.trash() }
    }
    suspend fun restorePublicNote(id: String) = withContext(Dispatchers.Default) {
        publicNoteWrites.withLock { withContext(NonCancellable) {
            notes.restore(id, clock())
            retiredPublicNoteIds.remove(id)
            _notes.value = notes.all(); _trashedNotes.value = notes.trash()
        } }
    }
    suspend fun purgePublicNote(id: String) = withContext(Dispatchers.Default) {
        publicNoteWrites.withLock { withContext(NonCancellable) {
            notes.purge(id)
            retiredPublicNoteIds.add(id)
            _trashedNotes.value = notes.trash()
        } }
    }

    suspend fun trashPublicNote(note: Note) = withContext(Dispatchers.Default) {
        publicNoteWrites.withLock { withContext(NonCancellable) {
            persistPublicNote(note, allowBlank = true)
            notes.remove(note.id)
            retiredPublicNoteIds.add(note.id)
            _notes.value = notes.all(); _trashedNotes.value = notes.trash()
        } }
    }

    /**
     * Records that the public-shell disclosure has been shown.
     *
     * The flag is persisted in public storage, so it survives a process
     * restart: `DISCREET_MODE.md` says once, and once means once.
     */
    fun acknowledgeDisclosure() = guarded {
        notes.acknowledgeDisclosure()
        _disclosureDue.value = false
        _publicDisclosureRequired.value = false
    }

    /**
     * Removes a public note.
     *
     * The editor calls this for Delete, and as it leaves a note that "Create
     * note" made and that is blank. It never calls it for a stored note only
     * because that note is blank: a note the user emptied stays.
     */
    fun removeNote(id: String) = guarded {
        publicNoteWrites.withLock {
            notes.remove(id)
            retiredPublicNoteIds.add(id)
            _notes.value = notes.all()
            _trashedNotes.value = notes.trash()
            if (_publicNoteWriteFailureId.value == id) _publicNoteWriteFailureId.value = null
        }
    }

    /** Reports the outcome of a host-driven import, §13 of the media pipeline. */
    fun reportImport(message: String?, expectedGeneration: Long? = null) = guarded(clearMessage = expectedGeneration == null) {
        if (expectedGeneration != null) {
            if ((repository.state.value as? VaultState.Unlocked)?.generation != expectedGeneration) return@guarded
            say(null)
        }
        // The order is the point: `guarded` clears the message first, so the
        // one this call carries is set after it, not before.
        say(message)
        reload()
    }

    /**
     * Sets the message a host flow produced, or clears it with `null`.
     *
     * A credential form shows it as its [formError], and every other route as
     * its [notice]. A clear leaves a security notice, see [post].
     */
    fun report(message: String?) {
        post(message)
    }

    /** [report], with an [action] beside the text, such as a way to the system settings. */
    fun report(message: String, action: Pair<String, () -> Unit>) {
        post(message, action = action)
    }

    /** Requests cancellation; the worker sends it to Rust before its next poll. */
    fun cancelActiveOperation() {
        val cancelDirectory = _activeOperation.value?.let { it.name == "album-export" && it.cancellable } == true
        if (_activeOperation.value?.name == "external-archive") clearExternalArchiveSecret()
        _activeOperation.update { current ->
            current?.takeIf { it.cancellable }?.copy(cancelling = true) ?: current
        }
        // A provider can be waiting before native polling starts. Signal its
        // directory owner without revoking unrelated export scratch or inputs.
        if (cancelDirectory) exports.cancelDirectoryOperations()
    }

    /**
     * Runs a single import with the same progress and cancellation as other
     * work. It is a pick of one, so its card reads in the `DESIGN.md` §15.2
     * phases, as [importAll] does, and not in bytes.
     */
    suspend fun importMedia(importer: MediaImporter, requestedObjectId: ByteArray? = null, open: () -> PickedMedia?): MediaImporter.Outcome? {
        val generation = (repository.state.value as? VaultState.Unlocked)?.generation ?: return null
        return tracked("import") { token ->
            _activeOperation.update { current ->
                current?.takeIf { it.id == token }?.copy(item = 1, items = 1) ?: current
            }
            importItem(importer, token, generation, requestedObjectId) { open() }
        }
    }

    /**
     * Imports what one picker session returned, as one operation.
     *
     * [expectedGeneration] pins a delayed incoming selection to its confirmed
     * session. Ordinary picker imports bind the session current at this call.
     *
     * A picker hands back many items at once, and each used to need its own
     * round trip through the picker, because a second import was refused
     * while the first ran. Here the items run one after another under one
     * progress card, "Importing item 3 of 12", `DESIGN.md` §15.2 and §23.2.
     * One at a time keeps the bound of `MEDIA_PIPELINE.md` §12 on what is in
     * flight.
     *
     * Each item commits on its own, so a cancel or a lock keeps the items
     * already imported and stops before the next one. An item that cannot be
     * opened or is refused does not stop the rest, unless the refusal is about
     * the vault or the device rather than the item, [PICK_STOPPING_STATUSES]:
     * the rest would meet the same full disk or damaged vault, so none of them
     * opens an import. The imported items go into [albumId] in one placement,
     * and one line then says what happened to the whole pick; no line follows
     * a lock, whose route change drops it anyway.
     *
     * [open] opens the item at an index. The picked items stay with the host,
     * which never keeps them past this call, `ANDROID.md` §14.2. A host that
     * must first fetch the item, as iOS does for an iCloud original, reports
     * the fetch through the callback [open] is given, and the card shows it as
     * the "Preparing" phase of `DESIGN.md` §15.2 with a bar. The callback
     * answers false once the user cancels, and the host then stops the fetch
     * and opens nothing, so the cancel lands before any native import begins,
     * `IOS.md` §15.2.
     */
    suspend fun importAll(
        importer: MediaImporter,
        count: Int,
        albumId: ByteArray?,
        expectedGeneration: Long? = null,
        open: suspend (index: Int, prepare: (processed: Long, total: Long) -> Boolean) -> PickedMedia?,
    ): List<MediaImporter.Outcome> {
        val generation = expectedGeneration ?: (repository.state.value as? VaultState.Unlocked)?.generation ?: return emptyList()
        if ((repository.state.value as? VaultState.Unlocked)?.generation != generation) return emptyList()
        val outcomes = mutableListOf<MediaImporter.Outcome>()
        tracked("import") { token ->
            val prepare = { processed: Long, total: Long ->
                _activeOperation.update { current ->
                    current?.takeIf { it.id == token }?.copy(processed = processed, total = total) ?: current
                }
                !cancellationRequested(token) && (repository.state.value as? VaultState.Unlocked)?.generation == generation
            }
            for (index in 0 until count) {
                if (cancellationRequested(token) || (repository.state.value as? VaultState.Unlocked)?.generation != generation) break
                _activeOperation.update { current ->
                    current?.takeIf { it.id == token }?.copy(
                        processed = 0,
                        total = 0,
                        stage = 1,
                        cancellable = true,
                        item = index + 1,
                        items = count,
                    ) ?: current
                }
                val outcome = importItem(importer, token, generation) { open(index, prepare) }
                outcomes += outcome
                if (outcome is MediaImporter.Outcome.Refused && outcome.status in PICK_STOPPING_STATUSES) break
                if (outcome is MediaImporter.Outcome.Imported &&
                    outcome.previewWarning == MediaImporter.PreviewWarning.DECODER_CLEANUP_FAILED) break
            }
        } ?: return outcomes
        if (outcomes.isEmpty() || (repository.state.value as? VaultState.Unlocked)?.generation != generation) return outcomes
        val summary = importSummary(outcomes, count, intoAlbum = albumId != null)
        val imported = outcomes.filterIsInstance<MediaImporter.Outcome.Imported>().map { it.objectId }
        if (albumId != null && imported.isNotEmpty()) {
            placeObjectsInAlbum(albumId, imported, expectedGeneration = generation) { report(summary) }
        } else {
            reportImport(summary, expectedGeneration = generation)
        }
        return outcomes
    }

    /** Closes the runtime, which a finishing host does. */
    suspend fun shutdown() {
        clearLauncherAction()
        withContext(Dispatchers.Default) { repository.shutdown() }
    }

    private suspend fun <T> tracked(name: String, body: suspend (Long) -> T): T? {
        if (_activeOperation.value != null) {
            say("Finish the current operation first.")
            return null
        }
        val token = ++operationToken
        _activeOperation.value = ActiveOperation(token, name)
        try {
            val result = body(token)
            return result.takeIf { _activeOperation.value?.id == token }
        } finally {
            _activeOperation.update { current -> current?.takeUnless { it.id == token } }
        }
    }

    /** Imports one picked item under the operation that [token] owns. */
    private suspend fun importItem(
        importer: MediaImporter,
        token: Long,
        generation: Long,
        requestedObjectId: ByteArray? = null,
        open: suspend () -> PickedMedia?,
    ): MediaImporter.Outcome {
        val guideToken = guide.session.value?.token
        return try {
            withContext(Dispatchers.Default) {
                importer.import(
                    repository = repository,
                    source = open(),
                    expectedGeneration = generation,
                    requestedObjectId = requestedObjectId,
                    onProgress = { updateOperation(token, it, keepCancellableOnSuccess = true) },
                    cancelRequested = { cancellationRequested(token) },
                )
            }.also { outcome ->
                if (outcome is MediaImporter.Outcome.Imported && (repository.state.value as? VaultState.Unlocked)?.generation == generation)
                    guide.event(dev.po4yka.chur.app.onboarding.GuideStep.IMPORT, guideToken)
            }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (failure: ChurFailure) {
            MediaImporter.Outcome.Refused(failure.status)
        } catch (_: dev.po4yka.chur.imports.LivePhotoBundleException) {
            MediaImporter.Outcome.Refused(ChurStatus.OBJECT_CORRUPT)
        } catch (_: Exception) {
            MediaImporter.Outcome.Refused(ChurStatus.INTERNAL_FAILURE)
        }
    }

    private fun cancellationRequested(token: Long): Boolean =
        _activeOperation.value?.let { it.id != token || it.cancelling } ?: true

    private fun updateOperation(
        token: Long,
        progress: OperationProgress,
        keepCancellableOnSuccess: Boolean = false,
    ) {
        _activeOperation.update { current ->
            current?.takeIf { it.id == token }?.copy(
                processed = progress.processed,
                total = progress.total,
                stage = progress.stage,
                cancellable = !progress.terminal || (keepCancellableOnSuccess && progress.status == 0),
            ) ?: current
        }
    }

    /**
     * Runs one re-encryption pass in the background after unlock, ADR-0069.
     *
     * It starts only after the vault opened, never inside the unlock, and it
     * does nothing in an identity with no completed rotation that it owns.
     * Polling does not count as activity, so the pass never keeps the vault
     * unlocked, and a lock cancels it; the next unlock resumes it.
     */
    private fun startReencryption(epoch: Long) {
        reencryption?.cancel()
        reencryption = scope.launch {
            try {
                val counts = withContext(Dispatchers.Default) { repository.reencryptionCounts() }
                if (counts.pending > 0) {
                    val operation = withContext(Dispatchers.Default) { repository.beginReencryption() }
                    try {
                        while (epoch == lockEpoch) {
                            val progress = withContext(Dispatchers.Default) {
                                repository.poll(operation, noteActivity = false)
                            }
                            if (progress.terminal) break
                            delay(REENCRYPTION_POLL_MS)
                        }
                    } finally {
                        closeOperation(operation)
                    }
                }
                if (epoch != lockEpoch) return@launch
                val after = withContext(Dispatchers.Default) { repository.reencryptionCounts() }
                _reencryptionNotice.value = if (after.failed > 0) REENCRYPTION_FAILED_COPY else null
            } catch (_: ChurFailure) {
                // A lock or a closed session ends the pass. The candidates are
                // catalog state, so the next unlock resumes it.
            }
        }
    }

    private suspend fun closeOperation(operation: Long) {
        withContext(NonCancellable + Dispatchers.Default) {
            try {
                repository.cancel(operation)
            } finally {
                repository.closeOperation(operation)
            }
        }
    }

    /** Every object `CATALOG_SCHEMA_V1.md` §16.2 keeps in the quarantine scope, whichever scan put it there. */
    private suspend fun quarantinedCount(): Long = withContext(Dispatchers.Default) {
        repository.page(ObjectQuery(QueryScope.QUARANTINE, limit = 1)).totalCount
    }

    /**
     * The timeline rows a scan left Incomplete or Unsupported, `DESIGN.md` §20.1.
     *
     * Import time never changes, so under that sort no row moves between two
     * pages and the restart after a `catalog_generation` change that
     * `CATALOG_SCHEMA_V1.md` §16.2 requires is not needed: a concurrent write
     * only adds or removes rows, which a count of the present state should
     * see. 500 is the largest page `CATALOG_SCHEMA_V1.md` §16.2 allows.
     */
    private suspend fun unverifiableCount(): Long {
        var query = ObjectQuery(sort = QuerySort.IMPORT_DESC, limit = 500)
        var count = 0L
        while (true) {
            val page = withContext(Dispatchers.Default) { repository.page(query) }
            count += page.objects.count { projection ->
                when (PresentedState.of(projection)) {
                    PresentedState.INCOMPLETE, PresentedState.UNSUPPORTED -> true
                    else -> false
                }
            }
            query = query.copy(cursor = page.nextCursor ?: return count)
        }
    }

    /**
     * The result line of a whole-vault check, in the voice of `DESIGN.md` §27.
     *
     * Each problem is named by its `DESIGN.md` §20.1 state, the name the
     * library shows on the same item.
     */
    private fun verificationSummary(checked: Long, corrupt: Boolean, quarantined: Long, unverifiable: Long): String {
        val problems = buildList {
            if (corrupt) add("at least 1 corrupt and no longer shown in the library")
            if (quarantined > 0) add("$quarantined quarantined (see Browse > Quarantine)")
            if (unverifiable > 0) add("$unverifiable incomplete or in an unsupported format (marked in the library)")
        }
        val checkedLine = "Checked $checked ${if (checked == 1L) "item" else "items"}."
        return if (problems.isEmpty()) {
            "$checkedLine No problems found."
        } else {
            "$checkedLine Some items could not be verified: ${problems.joinToString("; ")}."
        }
    }

    /** Polls one native operation and forwards its redacted snapshot to the UI. */
    private suspend fun drainProgress(operation: Long, token: Long, keepVaultAlive: Boolean = true): OperationProgress {
        var signalled = false
        while (true) {
            if (!signalled && cancellationRequested(token)) {
                withContext(Dispatchers.Default) { repository.cancel(operation) }
                signalled = true
            }
            val progress =
                withContext(Dispatchers.Default) { repository.poll(operation, noteActivity = keepVaultAlive) }
            updateOperation(token, progress, keepCancellableOnSuccess = _activeOperation.value?.name == "album-export")
            if (progress.terminal) return progress
            delay(POLL_INTERVAL_MS)
        }
    }

    private suspend fun drain(operation: Long, token: Long): Int = drainProgress(operation, token).status

    /**
     * Reads the current query again, as far as the grid had paged it.
     *
     * A reload that read only the first page cut the grid back to it. Past
     * that page the grid lost its place, and the viewer lost the item on
     * screen from its pages, so a swipe did nothing (`DESIGN.md` §13.1).
     */
    private suspend fun reload(expectedGeneration: Long? = null) {
        val session = privateSession() ?: return
        val generation = session.generation
        if (expectedGeneration == null || expectedGeneration == generation) {
            val query = currentQuery
            val revision = queryRevision
            val result = if (query.scope == QueryScope.SEARCH && query.terms.isNullOrBlank()) {
                ObjectPage(emptyList(), 0, 0, null)
            } else pageThrough(query, _page.value.objects.size)
            if (revision == queryRevision && session.isCurrent()) _page.value = result
        }
    }

    /**
     * The first page of [query], and the pages after it until [rows] rows are
     * loaded or the scope ends, `CATALOG_SCHEMA_V1.md` §16.2.
     *
     * A page read at another `catalog_generation` restarts the scope, as §16.2
     * requires, because a row whose sort key changed can be skipped or come
     * twice. That happens once; a second change keeps the rows read at one
     * generation, and the grid pages on from there.
     */
    private suspend fun pageThrough(query: ObjectQuery, rows: Int): ObjectPage =
        withContext(Dispatchers.Default) {
            var result = repository.page(query)
            var restarted = false
            while (result.objects.size < rows) {
                val cursor = result.nextCursor ?: break
                val next = repository.page(query.copy(cursor = cursor))
                if (next.catalogGeneration == result.catalogGeneration) {
                    result = next.copy(objects = result.objects + next.objects)
                } else if (!restarted) {
                    restarted = true
                    result = repository.page(query)
                } else {
                    break
                }
            }
            result
        }

    private suspend fun refreshAlbums(expectedGeneration: Long? = null) {
        val session = privateSession() ?: return
        if (expectedGeneration != null && expectedGeneration != session.generation) return
        val result = withContext(Dispatchers.Default) { repository.albums() }
        if (session.isCurrent()) _albums.value = result
    }

    /**
     * Ends a session a new credential replaces, §8 of `PLAINTEXT_LIFECYCLE.md`.
     *
     * What this controller derived from the session goes with it: its pending
     * work, and step 7's projections and decoded images, which would otherwise
     * show one identity's albums, tags, slots or sharing inside the next until
     * each reloads - the cross-identity surface `DECOY_VAULT.md` §10 forbids.
     *
     * Projections are cleared before waiting for native teardown. Every
     * private read retains its originating epoch and generation, so a late
     * completion cannot refill them. A cancelled device unlock therefore
     * leaves nothing on screen and no preceding session open in Rust.
     *
     * Every entry point calls it before it reads the epoch, and before
     * [beginHostActivity], whose count the clear resets.
     */
    private suspend fun endOpenSession(): Long {
        val previousEpoch = lockEpoch
        if (repository.state.value is VaultState.Unlocked) guide.conceal()
        if (!awaitLockCleanup(previousEpoch) || repository.state.value !is VaultState.Unlocked) return previousEpoch
        lockEpoch += 1
        val epoch = lockEpoch
        clearPrivateProjections()
        closeTrackedSession(LockReason.USER)
        return epoch
    }

    private fun clearPrivateProjections() {
        // Clear pre-native credentials synchronously; never wait for a provider.
        clearArchiveCredentials()
        clearLauncherAction()
        launcherNavigationBusy = false
        guideNavigationBusy = false
        _guideObscured.value = hostBackground
        contentIndexer.reset()
        _activeOperation.value = null
        currentQuery = ObjectQuery()
        queryRevision++
        // §10.3: a lock transition destroys private back-stack projections, and
        // these flows are that projection. §4 of `PLAINTEXT_LIFECYCLE.md` and
        // §8 step 7 add the decoded-image cache, which leaves with them.
        thumbnails.invalidate()
        _page.value = ObjectPage(emptyList(), 0, 0, null)
        _albums.value = emptyList()
        _tags.value = emptyList()
        _slots.value = emptyList()
        _devicePairing.value = dev.po4yka.chur.app.vault.DevicePairingUiState()
        _pairingApproval.value?.fill(0)
        _pairingApproval.value = null
        // The phrase is one of them, and the most valuable: it opens the vault
        // on its own. Both route tables draw it ahead of the route, so leaving
        // it set kept a full credential on screen after the lock had already
        // moved the route to the public shell — and the same transition takes
        // the cover off, which put it in the switcher snapshot too. §8 step 7
        // clears feature projections and step 9 shows a neutral surface; a
        // phrase that survived the lock did neither.
        //
        // Losing an unacknowledged phrase to a lock is still intended, but it
        // no longer strands a slot: the repository's lock discards the slot
        // staged on the session, or abandons the creation waiting for the
        // phrase, so nothing the user did not confirm stays committed.
        // `RECOVERY.md` §2 shows the phrase exactly once, and §8 there is how
        // a user gets another one.
        _recoveryPhrase.value = null
        // Cancel the foreground peer session and erase its invitation before
        // another vault or a public route can display private projections.
        endSessionSync()
        // A launch whose result never arrived belonged to the session that just
        // ended. Carrying its count forward would suppress the background lock
        // of the next session, so the count ends with the session. So do the
        // prompts, and the new epoch keeps a prompt of this session that
        // answers later from ending one of the next.
        hostActivities = 0
        prompts = 0
        promptEpoch += 1
    }

    /** Clears the session's sync projection before any locked/public route can be observed. */
    private fun endSessionSync() {
        sync?.endSession()
        sessionSync.cancelChildren()
    }

    private suspend fun completeUnlock(target: AppRoute, epoch: Long) {
        if (epoch != lockEpoch || _route.value != target) {
            clearPrivateProjections()
            closeTrackedSession(LockReason.BACKGROUND)
            // The user may already be using public Settings or an editor.
            // Closing a stale native result must not replace that navigation.
            return
        }
        if ((target == AppRoute.AppUnlock || target == AppRoute.AppRecover) && pendingLauncherAction == null) {
            closeTrackedSession(LockReason.USER)
            // Native teardown suspends too. A panic or background during it
            // revokes this whole-app authorization before it opens the shell.
            if (epoch != lockEpoch || _route.value != target) return
            setRoute(AppRoute.PublicShell)
            privacy.setEnabled(needsPrivacyCover(repository.state.value, _route.value, _recoveryPhrase.value != null))
        } else {
            val checkedDigest = trialDigest.takeIf { trialSubmitted }
            trialDigest = null
            trialSubmitted = false
            var setupNotice: String? = null
            if (checkedDigest != null) {
                setupNotice = try {
                    publicUtilities.configureDigest(checkedDigest)
                    guide.verifiedEntry()
                    refreshPublicPresentation()
                    "Entry checked. Discreet mode is enabled."
                } catch (_: Exception) { "The entry was checked, but settings could not be saved. Try setup again." }
            }
            enterVault(notice = setupNotice)
        }
    }

    /**
     * Opens the Library of the session that just began.
     *
     * [notice] is posted to the Library's own visit before anything here
     * suspends, so a lock that follows cannot carry it to the screen after
     * the lock. The route change already cleared what the last screen showed,
     * so the sync below does not clear again and leaves [notice] standing.
     */
    private suspend fun enterVault(notice: String? = null) {
        val generation = (repository.state.value as? VaultState.Unlocked)?.generation ?: return
        val epoch = lockEpoch
        val initialQueryRevision = queryRevision
        privacy.setEnabled(true)
        guide.event(dev.po4yka.chur.app.onboarding.GuideStep.RESTORE_UNLOCK)
        guide.event(dev.po4yka.chur.app.onboarding.GuideStep.CREATE)
        guide.event(dev.po4yka.chur.app.onboarding.GuideStep.RECOVERY)
        setRoute(AppRoute.Vault)
        dispatchLauncherAction()
        post(notice)
        val initialPage = withContext(Dispatchers.Default) { repository.page(ObjectQuery()) }
        if (epoch != lockEpoch || (repository.state.value as? VaultState.Unlocked)?.generation != generation) return
        if (queryRevision == initialQueryRevision) _page.value = initialPage
        startReencryption(epoch)
        sync?.let { engine ->
            guarded(clearMessage = false, context = sessionSync) {
                withContext(Dispatchers.Default) { engine.refresh() }
            }
        }
    }

    /**
     * Runs work and turns a boundary failure into a message.
     *
     * `docs/ERROR_MODEL.md` keeps a private value out of a message, and the
     * boundary carries only a status, so the message is [userCopy] of that
     * status: the feature layer's copy of "Layer mapping", never the name of
     * the code.
     *
     * The last catch is the backstop. Every action a surface can invoke goes
     * through here, and a platform adapter that raised something other than a
     * [ChurFailure] would otherwise leave an uncaught exception in a coroutine
     * and take the process with it — a crash that ends the session without the
     * orderly lock `PLAINTEXT_LIFECYCLE.md` §8 describes, reached by tapping an
     * ordinary settings row. `ERROR_MODEL.md` requires a platform layer to
     * normalize before a feature sees it; this says what happens when one did
     * not, and folds the unknown into [ChurStatus.INTERNAL_FAILURE] the same
     * way `fromValue` folds an unrecognized code. `CancellationException` is
     * re-thrown ahead of it, because swallowing it would break the cancellation
     * of the scope itself.
     *
     * The work carries the [routeVisit] it started in, so what it reports
     * reaches the screen it was started from or nothing: see [post]. A
     * [context] with a job, [sessionSync], makes the work that job's child.
     */
    private fun guarded(
        clearMessage: Boolean = true,
        copy: (ChurStatus) -> String = ::userCopy,
        context: CoroutineContext = EmptyCoroutineContext,
        body: suspend () -> Unit,
    ) {
        val session = SessionVisit(lockEpoch, (repository.state.value as? VaultState.Unlocked)?.generation)
        scope.launch(context + RouteVisit(routeVisit) + session) {
            try {
                if (clearMessage) say(null)
                body()
            } catch (cancellation: CancellationException) {
                throw cancellation
            } catch (failure: ChurFailure) {
                say(copy(failure.status), security = failure.status in SECURITY_STATUSES)
            } catch (_: Exception) {
                say(userCopy(ChurStatus.INTERNAL_FAILURE))
            }
        }
    }

    /**
     * Runs an unlock or a recovery as [guarded] does, with [unlocking] set.
     *
     * The flag is set on Main before the work starts, as [requestPhrase]
     * sets its own, so a second tap in the same frame is ignored rather than
     * starting a second key derivation. It clears before [guarded] reports a
     * refusal, so the form shows the refusal once it is no longer busy.
     */
    private fun attempt(copy: (ChurStatus) -> String = ::userCopy, body: suspend () -> Unit) {
        if (_unlocking.value || phraseRequested) return
        _unlocking.value = true
        val token = ++entryRequestToken
        val epoch = lockEpoch
        guarded(copy = copy) {
            try {
                if (token != entryRequestToken || !awaitLockCleanup(epoch)) return@guarded
                body()
            } finally {
                if (token == entryRequestToken) _unlocking.value = false
            }
        }
    }

    /**
     * Moves to [next] and drops what the last screen was showing.
     *
     * Every route write goes through here, so an outcome or a refusal never
     * outlives the screen it was for. A second vault set up from Settings
     * used to open its creation form with the vault's last outcome painted
     * in error red, and an unlock screen read any leftover as a failed
     * attempt.
     */
    private fun setRoute(next: AppRoute) {
        if (next == AppRoute.RestoreBackup) guide.chooseRestore()
        if (next == AppRoute.CreateVault && _route.value == AppRoute.RestoreBackup) guide.returnToCreation()
        if (next != _route.value && (next == AppRoute.PublicShell || next == AppRoute.PublicSettings) &&
            guide.session.value?.publicOnly == false && guide.session.value?.step !in listOf(
                dev.po4yka.chur.app.onboarding.GuideStep.CHOOSE, dev.po4yka.chur.app.onboarding.GuideStep.PRIVACY)) guide.conceal()
        if (next !in setOf(AppRoute.Vault, AppRoute.Unlock, AppRoute.AppUnlock, AppRoute.Recover, AppRoute.AppRecover)) clearLauncherAction()
        if (_route.value == AppRoute.EncryptFiles && next != AppRoute.EncryptFiles) clearExternalArchiveSecret()
        routeVisit += 1
        _notice.value = null
        _formError.value = null
        _route.value = next
        if (next == AppRoute.PublicShell && _publicShell.value == PublicShell.PET) guide.showPendingPetLesson()
    }

    /**
     * Shows [text] on the current screen if it is still the one [visit] was
     * taken on, and drops it otherwise.
     *
     * An action that ends after the user moved on, or after a lock, reports
     * to a screen it was not started from; an export that fails after the
     * lock would otherwise show its outcome on the unlock form as a refused
     * credential. A credential form gets [formError]; every other route gets
     * a [notice].
     *
     * `null` clears the form's refusal and a routine notice, but not a
     * [Notice.security] one: `DESIGN.md` §26 keeps that until the user
     * dismisses it or takes its action, and every [guarded] action and every
     * opened tile clears first. Only a newer notice or a route change, such as
     * a lock, replaces it.
     */
    private fun post(
        text: String?,
        visit: Long = routeVisit,
        security: Boolean = false,
        action: Pair<String, () -> Unit>? = null,
        pointsToSettings: Boolean = false,
    ) {
        if (visit != routeVisit) return
        if (_route.value in FORM_ROUTES) {
            _formError.value = text
        } else if (text != null) {
            _notice.value = Notice(++noticeCount, text, security, action, pointsToSettings)
        } else {
            _notice.update { current -> current?.takeIf { it.security } }
        }
    }

    /** [post], from work that [guarded] started, for the visit it started in. */
    private suspend fun say(
        text: String?,
        security: Boolean = false,
        action: Pair<String, () -> Unit>? = null,
        pointsToSettings: Boolean = false,
    ) {
        post(text, currentCoroutineContext()[RouteVisit]?.number ?: routeVisit, security, action, pointsToSettings)
    }

    /** The identity and UI lifetime that own a private projection. */
    private inner class PrivateSession(val epoch: Long, val generation: Long) {
        fun isCurrent(): Boolean = !launcherLocking && epoch == lockEpoch &&
            (repository.state.value as? VaultState.Unlocked)?.generation == generation
    }

    private suspend fun privateSession(): PrivateSession? {
        val generation = (repository.state.value as? VaultState.Unlocked)?.generation ?: return null
        val action = currentCoroutineContext()[SessionVisit]
        if (action != null && (action.epoch != lockEpoch ||
                (action.generation != null && action.generation != generation))) return null
        return PrivateSession(lockEpoch, generation).takeIf { it.isCurrent() }
    }

    private suspend fun <T> publishPrivate(target: MutableStateFlow<T>, read: suspend () -> T) {
        val session = privateSession() ?: return
        val result = withContext(Dispatchers.Default) { read() }
        if (session.isCurrent()) target.value = result
    }

    private class SessionVisit(val epoch: Long, val generation: Long?) : AbstractCoroutineContextElement(SessionVisit) {
        companion object Key : CoroutineContext.Key<SessionVisit>
    }

    /** The [routeVisit] a piece of guarded work started in. */
    private class RouteVisit(val number: Long) : AbstractCoroutineContextElement(RouteVisit) {
        companion object Key : CoroutineContext.Key<RouteVisit>
    }

    private companion object {
        /** The confirmation of `DESIGN.md` §17.1 step 6. */
        const val PHRASE_SAVED = "Recovery phrase saved."

        /** The rule a new or changed credential meets, `PASSWORD_PROFILE.md` §3. */
        const val NEW_PASSWORD_RULE = "Use at least 12 characters, or a PIN of at least 12 digits."

        /** The routes whose screen is a credential form, which reads [formError]. */
        val FORM_ROUTES: Set<AppRoute> = setOf(
            AppRoute.CreateVault,
            AppRoute.RestoreBackup,
            AppRoute.Unlock,
            AppRoute.AppUnlock,
            AppRoute.Recover,
            AppRoute.AppRecover,
        )

        /**
         * The failures `DESIGN.md` §26 keeps on screen until dismissed.
         *
         * They are the security states of `ERROR_MODEL.md`: the sync verdicts,
         * after which Chur applies nothing more from the one device or shared
         * history they name until the fork state clears while everything else
         * keeps syncing, `ROLLBACK_PROTECTION.md` §4, and the integrity
         * verdicts whose copy tells the user to restore from a backup.
         */
        val SECURITY_STATUSES: Set<ChurStatus> = setOf(
            ChurStatus.SYNC_CHAIN_FORK,
            ChurStatus.SYNC_HEAD_ROLLBACK,
            ChurStatus.VAULT_CORRUPT,
            ChurStatus.CATALOG_CORRUPT,
            ChurStatus.OBJECT_CORRUPT,
        )

        /**
         * The refusals that end a pick in [importAll].
         *
         * `ERROR_MODEL.md` puts their cause in the device or the vault, not in
         * the picked item: protected data the locked device keeps closed, a
         * volume that is full, detached or unwritable, and a vault or a
         * library that failed its integrity check. Every later item would
         * open an import into the same state, and write more to a vault
         * already reported damaged.
         *
         * `IO_FAILURE` is not one of them: a failed read of the picked item
         * itself also maps to it, `ANDROID.md` §27 and `IOS.md` §29, as when
         * a cloud-backed item loses its network. `ANDROID.md` §14.4 has import
         * handle such transient network errors, so that item fails alone and
         * the rest of the pick goes on.
         */
        val PICK_STOPPING_STATUSES: Set<ChurStatus> = setOf(
            ChurStatus.PROTECTED_DATA_UNAVAILABLE,
            ChurStatus.VAULT_CORRUPT,
            ChurStatus.CATALOG_CORRUPT,
            ChurStatus.STORAGE_UNAVAILABLE,
        )

        /** Fast enough to feel immediate, slow enough not to spin a core. */
        const val POLL_INTERVAL_MS = 50L

        /** A background pass reports nothing on screen, so it polls slowly. */
        const val REENCRYPTION_POLL_MS = 500L

        /**
         * The Settings line when objects cannot be re-encrypted after a
         * revocation, ADR-0069. It names no identity and no member.
         */
        const val REENCRYPTION_FAILED_COPY =
            "Some items could not be protected with new keys. A former member may still open copies they already have."

        /** A count of library items for a notice: "1 item", "3 items". */
        fun items(count: Int): String = if (count == 1) "1 item" else "$count items"

        /**
         * The one line an import ends with, `MEDIA_PIPELINE.md` §13.
         *
         * A pick of one item keeps the line it always had. A larger pick
         * counts what its items ended as, "11 imported, 1 could not be
         * opened", and names none of them: `DESIGN.md` §26 keeps file names
         * out of a snackbar. The items a cancel kept from starting count as
         * cancelled, and the ones a [PICK_STOPPING_STATUSES] refusal kept
         * from starting count as skipped.
         *
         * §13 tells storage full, permission denied, an unsupported codec and
         * corruption apart, and the next step differs for each, so a refused
         * item adds the [userCopy] line a pick of one shows. A pick gives one
         * reason: an integrity verdict first, so a damaged vault is not hidden
         * behind a lesser refusal, then the refusal that ended the pick, then
         * the first one.
         */
        fun importSummary(outcomes: List<MediaImporter.Outcome>, requested: Int, intoAlbum: Boolean): String {
            val single = outcomes.singleOrNull()
            if (requested == 1 && single != null) return when (single) {
                is MediaImporter.Outcome.Imported -> when {
                    single.storedAsFile -> "Saved original as a file; a media preview is unavailable on this device."
                    single.previewWarning == MediaImporter.PreviewWarning.DECODING_FAILED && intoAlbum ->
                        "Imported original into album; some previews could not be decoded."
                    single.previewWarning == MediaImporter.PreviewWarning.DECODING_FAILED ->
                        "Imported original; some previews could not be decoded."
                    single.previewWarning == MediaImporter.PreviewWarning.DECODER_CLEANUP_FAILED && intoAlbum ->
                        "Imported original into album; preview processing could not stop safely. Restart Chur before importing more media."
                    single.previewWarning == MediaImporter.PreviewWarning.DECODER_CLEANUP_FAILED ->
                        "Imported original; preview processing could not stop safely. Restart Chur before importing more media."
                    single.previewWarning == MediaImporter.PreviewWarning.STORAGE_FAILED && intoAlbum ->
                        "Imported original into album; some previews could not be saved."
                    single.previewWarning == MediaImporter.PreviewWarning.STORAGE_FAILED ->
                        "Imported original; some previews could not be saved."
                    single.previewWarning == MediaImporter.PreviewWarning.TIMED_OUT && intoAlbum ->
                        "Imported original into album; preview generation timed out."
                    single.previewWarning == MediaImporter.PreviewWarning.TIMED_OUT ->
                        "Imported original; preview generation timed out."
                    single.previewsSkipped && intoAlbum -> "Imported original into album; remaining previews cancelled."
                    single.previewsSkipped -> "Imported original; remaining previews cancelled."
                    intoAlbum -> "Imported into album."
                    else -> "Imported into vault."
                }
                is MediaImporter.Outcome.TooLarge -> single.reason
                MediaImporter.Outcome.Unreadable -> "That file could not be opened."
                is MediaImporter.Outcome.Refused -> userCopy(single.status)
            }
            val imported = outcomes.filterIsInstance<MediaImporter.Outcome.Imported>()
            val unreadable = outcomes.count { it == MediaImporter.Outcome.Unreadable }
            val tooLarge = outcomes.count { it is MediaImporter.Outcome.TooLarge }
            val refused = outcomes.filterIsInstance<MediaImporter.Outcome.Refused>()
            val failed = refused.filter { it.status != ChurStatus.CANCELLED }
            // A stopped decoder keeps its committed original, but no later
            // source may open while the process still owns uncertain resources.
            val decoderStopped = imported.any { it.previewWarning == MediaImporter.PreviewWarning.DECODER_CLEANUP_FAILED }
            val stopped = decoderStopped || failed.lastOrNull()?.status in PICK_STOPPING_STATUSES
            val unopened = requested - outcomes.size
            val skipped = if (stopped) unopened else 0
            val cancelled = refused.size - failed.size + unopened - skipped
            val counts = listOfNotNull(
                "${imported.size} imported",
                "$unreadable could not be opened".takeIf { unreadable > 0 },
                "$tooLarge too large to import".takeIf { tooLarge > 0 },
                "${failed.size} could not be imported".takeIf { failed.isNotEmpty() },
                "$cancelled cancelled".takeIf { cancelled > 0 },
                "$skipped skipped".takeIf { skipped > 0 },
            ).joinToString(", ")
            val previews = listOfNotNull(
                "some originals were saved as files without media previews".takeIf { imported.any { it.storedAsFile } },
                "some previews could not be decoded".takeIf { imported.any {
                    it.previewWarning == MediaImporter.PreviewWarning.DECODING_FAILED && !it.storedAsFile
                } },
                "some previews could not be saved".takeIf { imported.any { it.previewWarning == MediaImporter.PreviewWarning.STORAGE_FAILED } },
                "preview generation timed out".takeIf { imported.any { it.previewWarning == MediaImporter.PreviewWarning.TIMED_OUT } },
                "remaining previews cancelled".takeIf { imported.any { it.previewsSkipped } },
            ).joinToString("; ").let { if (it.isEmpty()) "" else "; $it" }
            val reason = failed.firstOrNull { it.status in SECURITY_STATUSES }
                ?: if (stopped) failed.lastOrNull() else failed.firstOrNull()
            val decoderWarning = if (decoderStopped)
                " Preview processing could not stop safely. Restart Chur before importing more media." else ""
            return "$counts$previews." + reason?.let { " " + userCopy(it.status) }.orEmpty() + decoderWarning
        }

        /**
         * How often the idle timer looks.
         *
         * The shortest choice of §14.4 is 30 seconds, and a vault locks at most
         * one tick after its limit, so a second keeps every choice within about
         * 3 percent of what it says. It is one wakeup a second, and only while
         * a session is unlocked or a creation waits for its phrase.
         */
        const val IDLE_TICK_MS = 1_000L
    }
}

/**
 * Where an export lands, `PLAINTEXT_LIFECYCLE.md` §6.
 *
 * Android streams to MediaStore or a selected document and shares through a
 * temporary FileProvider URI. iOS exports through Photos, Files, or the share
 * sheet. All destinations receive a verified stream and remove incomplete
 * results where the provider permits it.
 */
interface ExportSink {
    /** Reserved upper bound for an archive of unknown encoded length. Native writes enforce it. */
    fun archiveCapacity(target: ExportTarget): Long = 4L * 1024 * 1024 * 1024

    /** Revokes and deletes temporary results still owned by this application. Safe to repeat. */
    fun cancelPending()

    /** Signals directory-provider waits; teardown must not block the caller. */
    fun cancelDirectoryOperations() = Unit

    /** One open destination. */
    interface Destination {
        /** The descriptor Rust writes into; §13 has Rust duplicate it. */
        val descriptor: Int

        /** Makes the result visible once the whole object is written. */
        fun publish()

        /** Returns false if a platform provider could not finish publication. */
        fun publishChecked(): Boolean { publish(); return true }

        /** Removes a destination whose export failed. */
        fun discard()

        /** Closes the descriptor, which the caller owns. */
        fun close()
    }

    /** Opens a transient selected-directory lease. It must never persist [uri]. */
    fun openDirectory(uri: String): ExportDirectory? = null

    /** Creates a destination for one export. */
    fun create(displayName: String, contentType: String): Destination?

    fun create(
        displayName: String,
        contentType: String,
        target: ExportTarget,
        uri: String?,
    ): Destination?

    /** Encrypted archives need a seekable destination before provider delivery. */
    fun createArchive(
        displayName: String,
        contentType: String,
        target: ExportTarget,
        uri: String?,
        capacity: Long = archiveCapacity(target),
    ): Destination? = create(displayName, contentType, target, uri, capacity)

    /** Reserves the known plaintext size before the host opens a scratch file. */
    fun create(
        displayName: String,
        contentType: String,
        target: ExportTarget,
        uri: String?,
        plaintextSize: Long,
    ): Destination? = create(displayName, contentType, target, uri)
}

enum class ExportTarget { DEFAULT, FILES, MEDIA_LIBRARY, SHARE }

/**
 * One outcome message, the snackbar of `DESIGN.md` §26.
 *
 * [id] tells two equal texts apart, so the same outcome twice is shown twice.
 * A [security] notice stays until the user dismisses it or takes its
 * [action]: a clear, an opened item and the viewer's close leave it, and only
 * a newer notice or a route change replaces it. Any other one times out.
 */
data class Notice(
    val id: Long,
    val text: String,
    val security: Boolean = false,
    /** A label and what it does, such as an undo. */
    val action: Pair<String, () -> Unit>? = null,
    /**
     * Whether it only sends the user to a Settings banner that says the same
     * and stays, so Settings drops it once it is on screen rather than show
     * both.
     */
    val pointsToSettings: Boolean = false,
) {
    // A security notice can move between the shell and the viewer. Keep its
    // acknowledgement on the event so a new host does not repeat it.
    private var securityHapticDelivered = false

    /** Called on the UI thread when a host presents this notice. */
    internal fun consumeSecurityHaptic(): Boolean {
        if (!security || securityHapticDelivered) return false
        securityHapticDelivered = true
        return true
    }
}

/**
 * The failure a device unlock reports when no slot opened.
 *
 * An invalidated key needs the user to re-enroll, `ANDROID.md` §9.4, so it
 * outranks a factor that is only unavailable now, which outranks any other
 * refusal. A tag that does not verify ranks last, because it is what every
 * slot that is not the right one answers.
 */
internal fun moreSevere(current: ChurFailure?, next: ChurFailure): ChurFailure {
    if (current == null) return next
    fun rank(failure: ChurFailure): Int = when (failure.status) {
        ChurStatus.PLATFORM_KEY_INVALIDATED -> 3
        ChurStatus.PLATFORM_KEY_UNAVAILABLE -> 2
        ChurStatus.AUTHENTICATION_FAILED -> 0
        else -> 1
    }
    return if (rank(next) > rank(current)) next else current
}
