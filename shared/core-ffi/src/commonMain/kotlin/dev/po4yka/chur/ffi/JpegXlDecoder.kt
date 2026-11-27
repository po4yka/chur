package dev.po4yka.chur.ffi

/** Portable JPEG XL decoder. Calls on one decoder must be serialized. */
expect class JpegXlDecoder {
    val width: Int
    val height: Int
    val frameCount: Int
    /** Zero means infinite animation repeats. */
    val loopCount: Int
    /** Returns a bounded oriented RGBA8 sRGB raster with straight alpha. Never upscales. */
    fun renderFrame(index: Int, maxEdge: Int): JpegXlFrame
    /** Releases native state; call when the viewer stops, including on vault lock. */
    fun close()
    companion object {
        /** Borrows a seekable descriptor; reads from zero without changing its offset. */
        fun open(descriptor: Int): JpegXlDecoder
        /** Borrows bytes only during this call. No pointer is retained. */
        fun open(original: ChurBuffer, length: Int = original.capacityBytes): JpegXlDecoder
    }
}

/** A caller-owned raster. Clear and release it after the platform consumes it. */
class JpegXlFrame(val width: Int, val height: Int, val durationMs: Int, val pixels: ChurBuffer) {
    private var closed = false
    fun close() {
        if (closed) return
        closed = true
        pixels.clear()
        pixels.release()
    }
}

internal fun jpegXlDimensions(width: Int, height: Int, maxEdge: Int): Pair<Int, Int> {
    require(maxEdge in 1..4096) { "JPEG XL output edge exceeds limits" }
    val edge = maxOf(width, height)
    return if (edge <= maxEdge) width to height else {
        maxOf(1, (width.toLong() * maxEdge / edge).toInt()) to
            maxOf(1, (height.toLong() * maxEdge / edge).toInt())
    }
}

internal fun requireJpegXlCapability() {
    if (ChurNative.abiVersionMajor() != 7 || ChurNative.abiVersionMinor() < 1 ||
        ChurNative.capabilities() and (1L shl 9) == 0L) {
        throw ChurFailure(dev.po4yka.chur.core.model.ChurStatus.ABI_INCOMPATIBLE, "portable JPEG XL requires ABI 7.1")
    }
}
