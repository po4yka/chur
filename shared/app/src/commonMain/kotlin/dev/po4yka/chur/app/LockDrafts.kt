package dev.po4yka.chur.app

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.concurrent.Volatile
import kotlin.coroutines.CoroutineContext

/** How long a lock lets captured saves start and finish, `PRIVATE_NOTES.md`. */
internal const val LOCK_DRAFT_SAVE_BOUND_MS = 2_000L

/**
 * Unsaved private-note text that an ordinary lock saves as a new revision
 * before the native session closes, `PRIVATE_NOTES.md`.
 *
 * A source captures its text on the lock's UI turn, before concealment
 * disposes the editor; the capture is the editor's last action. The lock
 * conceals first and then runs [save], which waits at most [boundMs].
 *
 * The bound has one limit. A save checks `proceed` while it holds the
 * repository mutex, just before its native call, so no save starts after
 * the bound or after [abort]. A native call that already started cannot be
 * pre-empted, and the native close waits for the mutex. So the close comes
 * at most [boundMs] plus the rest of one bounded note transaction after the
 * lock, the same wait as for any other native call in flight.
 *
 * Panic calls [abort]: the wait of an earlier ordinary lock ends at once,
 * and its saves that have not started never start, `DISCREET_MODE.md`.
 *
 * Only Main calls these members.
 */
internal class LockDrafts(
    private val boundMs: Long = LOCK_DRAFT_SAVE_BOUND_MS,
    saveContext: CoroutineContext = Dispatchers.Default,
) {
    /** A captured save. It must check `proceed` under the repository mutex, just before the native call. */
    fun interface Save {
        suspend fun run(proceed: () -> Boolean)
    }

    /** Returns the save of the text open now, or `null` when nothing is unsaved. */
    fun interface Source {
        fun captureForLock(): Save?
    }

    private class Round {
        @Volatile
        var open = true
        val stop = CompletableDeferred<Unit>()

        fun end() {
            open = false
            stop.complete(Unit)
        }
    }

    private val sources = mutableListOf<Source>()
    private val rounds = mutableListOf<Round>()
    private val saveScope = CoroutineScope(SupervisorJob() + saveContext)

    /**
     * How many captured edits a lock did not save: a save that failed, met
     * a newer revision, did not start within the bound, or did not finish
     * in it. The encrypted draft can still be recovered in the same vault.
     */
    var lost: Int = 0
        private set

    /** Whether an editor that can hold unsaved text is open. */
    val active: Boolean get() = sources.isNotEmpty()

    /** Registers [source] and returns the call that removes it. */
    fun register(source: Source): () -> Unit {
        sources += source
        return { sources -= source }
    }

    fun capture(): List<Save> = sources.mapNotNull { it.captureForLock() }

    /** Ends every running [save] at once and keeps its unstarted saves from starting. */
    fun abort() {
        rounds.toList().forEach { it.end() }
    }

    /**
     * Runs [saves] and returns `true` when each one was saved. It never
     * throws for a save: any failure leaves the revision unchanged.
     */
    @OptIn(ExperimentalCoroutinesApi::class)
    suspend fun save(saves: List<Save>): Boolean {
        if (saves.isEmpty()) return true
        val round = Round()
        rounds += round
        try {
            val saved = saves.map { save ->
                saveScope.async {
                    try {
                        save.run { round.open }
                        true
                    } catch (_: Throwable) {
                        false
                    }
                }
            }
            val all = saveScope.async { saved.awaitAll() }
            withTimeoutOrNull(boundMs) {
                select {
                    all.onAwait {}
                    round.stop.onAwait {}
                }
            }
            round.end()
            all.cancel()
            val missed = saved.count { !it.isCompleted || it.isCancelled || !it.getCompleted() }
            lost += missed
            return missed == 0
        } finally {
            round.end()
            rounds -= round
        }
    }
}
