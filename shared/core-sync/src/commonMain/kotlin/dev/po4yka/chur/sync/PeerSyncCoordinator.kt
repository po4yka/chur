package dev.po4yka.chur.sync

import dev.po4yka.chur.core.model.ChurStatus
import dev.po4yka.chur.ffi.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlin.coroutines.AbstractCoroutineContextElement
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.serialization.json.Json
import kotlin.concurrent.Volatile

/** Only the current foreground session is visible; no network configuration is saved. */
public data class PeerSyncStatus(
    val busy: Boolean = false,
    val canApprove: Boolean = false,
    val invitation: String? = null,
    val message: String? = null,
    val failure: ChurStatus? = null,
    internal val generation: Int = 0,
) {
    override fun toString(): String = "PeerSyncStatus(busy=$busy, canApprove=$canApprove, invitation=${if (invitation == null) "absent" else "redacted"}, failure=$failure)"
}

/** Two unlocked devices exchange native-verified operations and ciphertext directly. */
public class PeerSyncCoordinator(private val clock: () -> Long = { 0L }) {
    private val runMutex = Mutex()
    private val _status = MutableStateFlow(PeerSyncStatus())
    public val status: StateFlow<PeerSyncStatus> = _status.asStateFlow()
    private var boundary: SyncVaultBoundary? = null
    @Volatile private var epoch: Int = 0
    private class PendingPairing(val generation: Int, val credentials: DevicePairingCredentials)
    @Volatile private var pairing: PendingPairing? = null
    private val pendingPairing: DevicePairingCredentials?
        get() = pairing?.takeIf { it.generation == epoch }?.credentials
    public fun bind(boundary: SyncVaultBoundary?) { this.boundary = boundary }
    public fun endSession() { epoch++; pairing = null; _status.value = PeerSyncStatus(generation = epoch) }
    public suspend fun refresh(): Boolean {
        val vault = boundary ?: return false
        val generation = epoch
        val encoded = vault.peerCall(byteArrayOf(10))
        val pending = when (encoded.firstOrNull()?.toInt()) {
            0 -> { require(encoded.size == 1); null }
            1 -> decodeDevicePairingCredentials(encoded.copyOfRange(1, encoded.size))
            else -> throw ChurFailure(ChurStatus.NON_CANONICAL_ENCODING, "invalid pending peer evidence")
        }
        if (generation != epoch) throw CancellationException("peer session ended")
        pairing = pending?.let { PendingPairing(generation, it) }
        val canApprove = try { pending == null && vault.identity() != null && vault.pairedDevices() != null } catch (failure: ChurFailure) {
            if (failure.status != ChurStatus.RECOVERY_REQUIRED) throw failure
            false
        }
        publish(generation) { it.copy(canApprove = canApprove) }
        return canApprove
    }
    public suspend fun prepareDevicePairing(): DevicePairingRequest = boundary?.prepareDevicePairing() ?: locked()
    public suspend fun inspectDevicePairing(request: ByteArray): DevicePairingPreview = boundary?.inspectDevicePairing(request) ?: locked()
    public suspend fun approveDevicePairing(request: ByteArray, fingerprint: String): ByteArray {
        val preview = inspectDevicePairing(request)
        if (preview.fingerprint != fingerprint) throw ChurFailure(ChurStatus.AUTHENTICATION_FAILED, "compare device fingerprints")
        return (boundary?.approveDevicePairing(request, clock()) ?: locked()).approval
    }
    public suspend fun acceptPairingApproval(approval: ByteArray) {
        val generation = epoch
        val credentials = boundary?.startDevicePairing(approval) ?: locked()
        if (generation != epoch) throw CancellationException("pairing session ended")
        pairing = PendingPairing(generation, credentials)
        publish(generation) { it.copy(message = "Approval verified. Connect directly to the approving device to finish pairing.") }
    }
    public suspend fun pairedDevices(): List<PairedDevice> = boundary?.pairedDevices() ?: locked()
    public suspend fun revokePairedDevice(device: ByteArray, fingerprint: String) {
        val peer = pairedDevices().singleOrNull { it.deviceId.contentEquals(device) && it.fingerprint == fingerprint }
            ?: throw ChurFailure(ChurStatus.AUTHENTICATION_FAILED, "device fingerprint changed")
        require(!peer.current)
        boundary?.prepareDeviceRevocation(device, clock()) ?: locked()
    }
    /** Opens a one-use invitation. Caller supplies this device's reachable IP, never a service URL. */
    public suspend fun listen(address: String) = runPeer {
        val octets = address.split('.')
        require(octets.size == 4 && octets.all { part -> part.toIntOrNull()?.let { it in 0..255 && it.toString() == part } == true } && address != "0.0.0.0") { "enter this device's IPv4 address" }
        require(refresh()) { "finish pairing before offering a connection" }
        prepareMedia()
        // Native binds only this interface address, so other interfaces cannot take the invitation.
        val encoded = io(byteArrayOf(1) + record(address.encodeToByteArray()))
        val response = PeerBytes(encoded)
        val port = response.number(2)
        val secret = response.take(32)
        response.end()
        try { publishCurrent { it.copy(invitation = "${INVITATION_PREFIX}$address:$port#${secret.hex()}", message = "Waiting for the other device. Keep both apps open.") } }
        finally { secret.fill(0); encoded.fill(0) }
        awaitReady()
        hello()
        publishCurrent { it.copy(invitation = null, message = "Synchronizing directly…") }
        serve("turn")
        pull()
        send(PeerMessage("complete"))
        require(receive().kind == "complete")
    }
    /** Connects to a device invitation; both directions finish before success is reported. */
    public suspend fun connect(invitation: String) = runPeer {
        val value = invitation.trim()
        if (!value.startsWith(INVITATION_PREFIX)) {
            throw ChurFailure(ChurStatus.UNSUPPORTED_VERSION, "unsupported peer invitation version")
        }
        val parts = value.removePrefix(INVITATION_PREFIX).split('#')
        require(parts.size == 2 && parts[1].length == 64) { "invalid peer invitation" }
        val endpoint = parts[0].split(':')
        require(endpoint.size == 2)
        val port = endpoint[1].toInt()
        require(port in 1..65535)
        refresh()
        val secret = parts[1].unhex()
        val request = byteArrayOf(2) + record(endpoint[0].encodeToByteArray()) + number(port.toULong(), 2) + secret
        try { io(request) } finally { secret.fill(0); request.fill(0) }
        awaitReady()
        hello()
        publishCurrent { it.copy(message = "Synchronizing directly…") }
        pull()
        prepareMedia()
        send(PeerMessage("turn"))
        serve("complete")
        send(PeerMessage("complete"))
    }
    private suspend fun runPeer(block: suspend () -> Unit) {
        if (!runMutex.tryLock()) throw ChurFailure(ChurStatus.CONFLICT, "a peer connection is already active")
        val generation = epoch
        publish(generation) { it.copy(busy = true, failure = null, invitation = null, message = "Preparing direct connection…") }
        try {
            withContext(PeerRun(generation)) { block() }
            val forks = boundary?.forkState()
            publish(generation) {
                if (forks != null && forks.detected > 0) it.copy(message = null, failure = ChurStatus.SYNC_CHAIN_FORK)
                else it.copy(message = "Synced directly with the other device.")
            }
        } catch (cancelled: CancellationException) {
            publish(generation) { it.copy(message = "Connection stopped.") }
            throw cancelled
        }
        catch (failure: ChurFailure) {
            publish(generation) { it.copy(failure = failure.status, message = null) }
            throw failure
        } catch (invalid: IllegalArgumentException) {
            publish(generation) { it.copy(failure = ChurStatus.INVALID_INPUT, message = null) }
            throw ChurFailure(ChurStatus.INVALID_INPUT, "invalid peer invitation or peer record")
        } finally {
            // Lock closes the native socket independently, including a cancelled connection.
            if (generation == epoch) {
                withContext(NonCancellable) { try { io(byteArrayOf(6)) } catch (_: ChurFailure) { } }
                publish(generation) { it.copy(busy = false, invitation = null) }
            }
            runMutex.unlock()
        }
    }
    private fun publish(generation: Int, transform: (PeerSyncStatus) -> PeerSyncStatus) {
        _status.update { if (it.generation == generation) transform(it) else it }
    }
    private suspend fun publishCurrent(transform: (PeerSyncStatus) -> PeerSyncStatus) {
        publish(currentCoroutineContext()[PeerRun]?.epoch ?: epoch, transform)
    }
    private class PeerRun(val epoch: Int) : AbstractCoroutineContextElement(Key) {
        companion object Key : CoroutineContext.Key<PeerRun>
    }
    private suspend fun io(bytes: ByteArray): ByteArray {
        val context = currentCoroutineContext()
        context.ensureActive()
        val generation = context[PeerRun]?.epoch
        if (generation != null && generation != epoch) throw CancellationException("peer session ended")
        val result = boundary?.peerCall(bytes) ?: locked()
        if (generation != null && generation != epoch) throw CancellationException("peer session ended")
        return result
    }
    private suspend fun awaitReady() { while (!io(byteArrayOf(3)).contentEquals(byteArrayOf(1))) delay(20) }
    private suspend fun send(message: PeerMessage) {
        val bytes = Json.encodeToString(PeerMessage.serializer(), message).encodeToByteArray()
        require(bytes.size <= 4 * 1024 * 1024)
        try { io(byteArrayOf(4) + record(bytes)) } finally { bytes.fill(0) }
        while (!io(byteArrayOf(7)).contentEquals(byteArrayOf(1))) delay(20)
    }
    private suspend fun receive(): PeerMessage {
        while (true) {
            val bytes = io(byteArrayOf(5))
            if (bytes.firstOrNull() == 1.toByte()) {
                try {
                    return Json.decodeFromString(PeerMessage.serializer(), bytes.copyOfRange(1, bytes.size).decodeToString()).also {
                        it.failure?.let { code -> throw ChurFailure(ChurStatus.fromValue(code), "peer could not supply the requested data") }
                    }
                } finally { bytes.fill(0) }
            }
            delay(20)
        }
    }
    private suspend fun request(message: PeerMessage): PeerMessage { send(message); return receive().also { require(it.kind == message.kind) } }
    private suspend fun hello() {
        // Native verified the vault and the signed device transcript during the handshake.
        // The remote device ID comes from that verification, never from a peer message.
        val remote = io(byteArrayOf(9))
        require(remote.size == 16) { "peer device is not authenticated" }
    }
    private suspend fun prepareMedia() {
        val vault = boundary ?: locked()
        // Native owns causal ordering and verifies each complete local source before authoring.
        vault.ownSyncOperations(0uL) ?: locked()
        for (collection in vault.ownSyncCollections() ?: locked()) {
            var after = ByteArray(16)
            while (true) {
                val page = vault.sourcePage(collection, after) ?: locked()
                if (page.isEmpty()) break
                for (source in page) vault.ownSyncAuthor(source) ?: locked()
                val next = page.last().objectId
                require(next.hex() > after.hex())
                after = next
            }
        }
    }
    private suspend fun serve(stopKind: String) {
        val vault = boundary ?: locked()
        var checkpoint: ByteArray? = null
        while (true) {
            val request = receive()
            if (request.kind == stopKind) return
            val response = try {
                when (request.kind) {
                    "heads" -> {
                        checkpoint = vault.currentDeviceCheckpoint(clock()) ?: locked()
                        PeerMessage("heads", heads = (vault.acceptedHeads() ?: locked()).map { PeerHead(it.deviceId, it.after.toString()) })
                    }
                    "history" -> {
                        require(request.id.size == 16)
                        val page = io(byteArrayOf(8) + request.id + number(request.offset.toULong(), 8) + request.bytes)
                        PeerMessage("history", history = encodeHistoryPage(page))
                    }
                    "checkpoint" -> PeerMessage("checkpoint", bytes = checkpoint ?: throw ChurFailure(ChurStatus.INVALID_INPUT, "request peer heads first"))
                    // Native issues the grant only to the authenticated peer device and serves
                    // ciphertext only while that device is active.
                    "key" -> PeerMessage("key", bytes = io(byteArrayOf(11) + request.bytes))
                    "range" -> {
                        require(request.id.size == 16)
                        val range = io(byteArrayOf(12) + request.id + number(request.offset.toULong(), 8) + number(256uL * 1024uL, 4))
                        PeerMessage("range", bytes = range)
                    }
                    else -> throw ChurFailure(ChurStatus.INVALID_INPUT, "unexpected peer request")
                }
            } catch (failure: ChurFailure) {
                // Native keeps the connection open after a request-level failure; answer and continue.
                PeerMessage(request.kind, failure = failure.status.value)
            } catch (_: IllegalArgumentException) {
                PeerMessage(request.kind, failure = ChurStatus.INVALID_INPUT.value)
            }
            send(response)
        }
    }
    private suspend fun pull() {
        val vault = boundary ?: locked()
        val vaultId = pendingPairing?.vaultId ?: vault.identity()?.vaultId ?: locked()
        val remoteHeads = request(PeerMessage("heads")).heads
        require(remoteHeads.size <= 32 && remoteHeads.all { it.device.size == 16 && it.sequence.toULong() <= Long.MAX_VALUE.toULong() } && remoteHeads.map { it.device.hex() }.distinct().size == remoteHeads.size)
        val localHeads = (vault.acceptedHeads() ?: locked()).associate { it.deviceId.hex() to it.after }
        for (head in remoteHeads) {
            var after = localHeads[head.device.hex()] ?: 0uL
            val target = head.sequence.toULong()
            while (after < target) {
                val response = request(PeerMessage("history", bytes = number(target, 8), id = head.device, offset = after.toString()))
                val page = decodeHistoryPage(response.history, after, target)
                vault.stage(vaultId, SyncRecordKind.OPERATION_PAGE, clock(), page.stagedBytes)
                checkReport(vault.process() ?: locked())
                // The fetch position is public metadata. Rust advances durable heads after signature verification.
                after = page.lastSequence
            }
        }
        checkReport(vault.process() ?: locked())
        val accepted = (vault.acceptedHeads() ?: locked()).associate { it.deviceId.hex() to it.after }
        require(remoteHeads.all { (accepted[it.device.hex()] ?: 0uL) >= it.sequence.toULong() }) { "signed peer history has missing dependencies" }
        val checkpoint = request(PeerMessage("checkpoint")).bytes
        vault.stage(vaultId, SyncRecordKind.CHECKPOINT, clock(), checkpoint)
        val checkpointReport = vault.process() ?: locked()
        checkReport(checkpointReport)
        require(checkpointReport.pending == 0L) { "peer checkpoint has missing history" }
        io(byteArrayOf(13) + record(checkpoint))
        if (pendingPairing != null) {
            vault.finishDevicePairing(clock()) ?: locked()
            pairing = null
            refresh()
        }
        for (collection in vault.ownSyncCollections() ?: locked()) {
            while (true) {
                val plan = vault.ownSyncPlan(collection) ?: locked()
                require(plan.pendingOperations == 0) { "peer changes have missing dependencies" }
                if (plan.downloads.isEmpty()) break
                for (objectPlan in plan.downloads) {
                    val keyRequest = vault.objectKeyRequest(collection, objectPlan.objectId)
                    if (keyRequest != null) {
                        val grant = request(PeerMessage("key", bytes = keyRequest)).bytes
                        check(vault.objectKeyAccept(byteArrayOf(), grant))
                    }
                    var offset = vault.sharedDownloadOffset(collection, objectPlan.objectId) ?: locked()
                    require(offset <= objectPlan.length)
                    while (offset < objectPlan.length) {
                        val range = request(PeerMessage("range", id = objectPlan.objectId, offset = offset.toString())).bytes
                        require(range.isNotEmpty() && range.size <= 256 * 1024 && range.size.toULong() <= objectPlan.length - offset)
                        check(vault.appendSharedDownload(collection, objectPlan.objectId, offset, range))
                        offset += range.size.toULong()
                    }
                    check(vault.finishSharedDownload(collection, objectPlan.objectId, clock()))
                }
            }
        }
    }
    private fun checkReport(report: SyncProcessReport) {
        if (report.rejected > 0) throw ChurFailure(ChurStatus.fromValue(report.firstRejection), "signed peer history was rejected")
    }
}

private const val INVITATION_PREFIX = "chur-p2p3/"
