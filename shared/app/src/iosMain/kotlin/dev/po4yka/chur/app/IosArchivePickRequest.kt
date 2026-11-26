package dev.po4yka.chur.app

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

/** The result of one iOS file picker visit. The host calls these methods on the main thread. */
public class IosArchivePickRequest internal constructor(
    private var answer: ((ArchiveSource?, String?) -> Unit)?,
) {
    private var stopOpening by mutableStateOf<(() -> Unit)?>(null)
    internal val preparing: Boolean get() = stopOpening != null

    public fun beginOpening(cancel: () -> Unit) {
        if (answer == null) cancel() else stopOpening = cancel
    }

    public fun opened(source: ArchiveSource) = finish(source, null)
    public fun cancelled() {
        val stop = stopOpening
        try { finish(null, null) } finally { stop?.invoke() }
    }
    public fun openFailed() = finish(null, "That file could not be opened.")

    private fun finish(source: ArchiveSource?, error: String?) {
        val callback = answer
        answer = null
        stopOpening = null
        if (callback == null) source?.close?.invoke() else callback(source, error)
    }
}
