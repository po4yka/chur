package dev.po4yka.chur.app

/** The result of one iOS file picker visit. The host calls these methods on the main thread. */
public class IosArchivePickRequest internal constructor(
    private var answer: ((ArchiveSource?, String?) -> Unit)?,
) {
    public fun opened(source: ArchiveSource) = finish(source, null)
    public fun cancelled() = finish(null, null)
    public fun openFailed() = finish(null, "That file could not be opened.")

    private fun finish(source: ArchiveSource?, error: String?) {
        val callback = answer
        answer = null
        if (callback == null) source?.close?.invoke() else callback(source, error)
    }
}
