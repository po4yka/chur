package dev.po4yka.chur.app.spirit

import kotlin.math.sqrt

/** Public artwork only. Never give a renderer a controller, repository or vault state. */
data class SpiritRenderState(
    val clip: String = "idle_soft",
    val clipSerial: Int = 0,
    val motionSerial: Int = 0,
    val reducedMotion: Boolean = false,
    val dragX: Float = 0f,
    val dragY: Float = 0f,
)

/** Immutable, platform-free interaction reducer. Coordinates are pixels in the safe viewport. */
data class SpiritInteraction(
    val x: Float = 16f,
    val y: Float = 16f,
    val maxX: Float = 0f,
    val maxY: Float = 0f,
    val pressed: Boolean = false,
    val dragging: Boolean = false,
    val downX: Float = 0f,
    val downY: Float = 0f,
    val originX: Float = 0f,
    val originY: Float = 0f,
    val eventMillis: Long = 0L,
    val render: SpiritRenderState = SpiritRenderState(),
) {
    fun bounds(width: Float, height: Float, size: Float): SpiritInteraction {
        val mx = (width - size).coerceAtLeast(0f)
        val my = (height - size).coerceAtLeast(0f)
        return copy(maxX = mx, maxY = my, x = x.coerceIn(0f, mx), y = y.coerceIn(0f, my))
    }

    fun down(px: Float, py: Float, timeMillis: Long = 0L) = copy(
        eventMillis = timeMillis, pressed = true, dragging = false, downX = px, downY = py, originX = x, originY = y,
    )

    fun move(px: Float, py: Float, slop: Float, timeMillis: Long = eventMillis + 16L, sizePixels: Float = 144f): SpiritInteraction {
        if (!pressed || !px.isFinite() || !py.isFinite()) return this
        val dx = px - downX
        val dy = py - downY
        if (!dragging && sqrt(dx * dx + dy * dy) <= slop) return this
        val nx = (originX + dx).coerceIn(0f, maxX)
        val ny = (originY + dy).coerceIn(0f, maxY)
        val elapsed = (timeMillis - eventMillis).coerceAtLeast(1L).toFloat()
        val unit = sizePixels.takeIf { it.isFinite() && it > 0f } ?: 144f
        // Velocity in mascot-widths/second; independent of event rate and display density.
        val gain = 150f / (unit * elapsed)
        return copy(
            eventMillis = timeMillis, x = nx, y = ny, dragging = true,
            render = render.copy(
                clip = "hold_enter", clipSerial = render.clipSerial + if (dragging) 0 else 1,
                motionSerial = render.motionSerial + if (nx != x || ny != y) 1 else 0,
                dragX = if (render.reducedMotion) 0f else ((nx - x) * gain).coerceIn(-1f, 1f),
                dragY = if (render.reducedMotion) 0f else ((ny - y) * gain).coerceIn(-1f, 1f),
            ),
        )
    }

    fun up(cancelled: Boolean = false): SpiritInteraction {
        if (!pressed) return this
        return copy(
            pressed = false, dragging = false,
            render = render.copy(
                clip = if (cancelled) "idle_soft" else if (dragging) "release_settle" else "tap_react",
                clipSerial = render.clipSerial + 1, dragX = 0f, dragY = 0f,
            ),
        )
    }

    fun tap() = copy(render = render.copy(clip = "tap_react", clipSerial = render.clipSerial + 1))
    fun motion(reduced: Boolean) = copy(render = render.copy(reducedMotion = reduced,
        dragX = if (reduced) 0f else render.dragX, dragY = if (reduced) 0f else render.dragY))
}

/** Shared scheduling gate, with host lifecycle observations supplied by native adapters. */
fun shouldScheduleSpiritFrame(attached: Boolean, resumed: Boolean, visible: Boolean,
    dirty: Boolean, reducedMotion: Boolean): Boolean =
    attached && resumed && visible && (dirty || !reducedMotion)

/** Cancel even when primary-up and secondary-down arrive in the same dispatch. */
fun hasSecondarySpiritPointer(primary: Long, pressedIds: List<Long>): Boolean =
    pressedIds.any { it != primary }
