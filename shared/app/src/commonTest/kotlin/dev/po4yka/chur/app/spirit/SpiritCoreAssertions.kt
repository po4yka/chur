package dev.po4yka.chur.app.spirit

import dev.po4yka.chur.app.spirit.*
import kotlin.math.abs

fun runSpiritCoreChecks() {
    fun verify(value: Boolean, name: String) = check(value) { name }
    val initial = SpiritInteraction().bounds(500f, 700f, 144f)
    val pressed = initial.down(40f, 40f)
    verify(pressed.move(43f, 43f, 8f).up().render.clip == "tap_react", "sub-slop tap")
    // Both events use the same committed offset; uncommitted model changes must not
    // enter coordinate conversion. Compose uses LayoutCoordinates.localToRoot.
    val committedX = initial.x
    val eventOne = pressed.move(60f + committedX, 40f, 8f)
    val eventTwo = eventOne.move(70f + committedX, 40f, 8f)
    verify(eventTwo.x == initial.x + (70f + committedX - 40f), "two events before layout commit")
    val dragged = pressed.move(140f, 240f, 8f)
    verify(dragged.dragging && dragged.x == 116f && dragged.y == 216f, "drag translation")
    verify(dragged.render.clip == "hold_enter", "hold transition")
    verify(dragged.move(180f, 280f, 8f).render.clipSerial == dragged.render.clipSerial, "hold not restarted")
    verify(dragged.up().render.clip == "release_settle", "drag release, not tap")
    verify(dragged.up(true).render.clip == "idle_soft", "cancel never reacts")
    verify(dragged.up(true).up().render.clip == "idle_soft", "cancel then up stays cancelled")
    verify(pressed.move(9999f, 9999f, 8f).x == 356f, "right bound")
    verify(pressed.move(-9999f, -9999f, 8f).y == 0f, "top bound")
    verify(dragged.bounds(60f, 60f, 144f).x == 0f, "resize clamp")
    verify(pressed.move(Float.NaN, 3f, 8f) == pressed, "bad pointer ignored")
    verify(pressed.motion(true).move(200f, 200f, 8f).render.dragX == 0f, "reduced motion no lean")
    verify(initial.tap().tap().render.clipSerial == 2, "repeat taps restart reaction")
    verify(SpiritEyes.weights(1f).all { it == 0f }, "open eye basis")
    verify(SpiritEyes.weights(0f)[0] == 1f, "closed surface target")
    for (i in 0..1000) {
        val weights = SpiritEyes.weights(i / 1000f)
        verify(weights.all { it in 0f..1f } && weights.sum() <= 1.00001f, "valid eye interpolation $i")
    }
    verify(SpiritEyes.aperture(SpiritClipSample("idle_soft", 2.72f), false) == 0f, "blink closes")
    verify(SpiritEyes.aperture(SpiritClipSample("idle_soft", 2.72f), true) == 1f, "reduced motion eyes remain open")
    verify(sampleSpiritClip("hold_enter", .4f, false).name == "hold_loop", "hold continuation")
    verify(sampleSpiritClip("tap_react", 1f, false).name == "idle_soft", "reaction finishes")
    verify(sampleSpiritClip("release_settle", .4f, true) == SpiritClipSample("idle_soft", 0f), "reduced static frame")
    for (attached in listOf(false, true)) for (resumed in listOf(false, true))
        for (visible in listOf(false, true)) for (dirty in listOf(false, true))
            for (reduced in listOf(false, true)) {
                val actual = shouldScheduleSpiritFrame(attached, resumed, visible, dirty, reduced)
                verify(actual == (attached && resumed && visible && (dirty || !reduced)), "lifecycle scheduling gate")
            }
    val identity = floatArrayOf(1f,0f,0f,0f,0f,1f,0f,0f,0f,0f,1f,0f,0f,0f,0f,1f)
    val turn = floatArrayOf(0f,1f,0f,0f,-1f,0f,0f,0f,0f,0f,1f,0f,10f,0f,0f,1f)
    val displayed = blendSpiritPose(identity, turn, .5f)
    verify(abs(displayed[0] - .7071068f) < .0001f && abs(displayed[12] - 5f) < .0001f, "TRS rotation and translation")
    verify(blendSpiritPose(displayed, identity, 0f).contentEquals(displayed), "interrupted transition begins at actual pose")
    verify(blendSpiritPose(displayed, identity, 1f).contentEquals(identity), "transition exact endpoint")
    verify(abs(SpiritEyes.aperture(SpiritClipSample("hold_loop", .4f), false) - .84f) < .00001f, "held expression")
    verify(SpiritEyes.aperture(SpiritClipSample("tap_react", .184f), false) < .00001f, "tap-specific blink")
    var tail = FloatArray(8)
    repeat(1000) { frame ->
        tail = advanceSpiritTail(tail, if (frame < 30) 1f else if (frame < 60) -1f else 0f, 1f/60f, false)
        verify(tail.all { it in -1f..1f }, "tail envelope remains bounded")
    }
    verify(tail.all { abs(it) < .0001f }, "tail settles after input stops")
    verify(advanceSpiritTail(FloatArray(8) { 1f }, 1f, .016f, true).all { it == 0f }, "reduced motion immediately clears tail")
    for (sampleName in listOf("idle_soft", "tap_react")) {
        val duration = if (sampleName == "idle_soft") 4f else .8f
        val closed = (0..(duration*30).toInt()).count {
            SpiritEyes.aperture(SpiritClipSample(sampleName, it/30f), false) == 0f
        }
        verify(closed >= 3, "full closed plateau at30fps for $sampleName")
    }
    val moving = pressed.move(100f, 100f, 8f)
    val nextMoving = moving.move(120f, 120f, 8f)
    verify(nextMoving.render.motionSerial == moving.render.motionSerial + 1, "constant-speed input retains motion heartbeat")
    verify(nextMoving.move(120f, 120f, 8f).render.motionSerial == nextMoving.render.motionSerial, "stationary event does not refresh motion")
    // Identical physical velocity at 30/60/120 Hz and 1x/3x density.
    for (hz in listOf(30, 60, 120)) for (density in listOf(1f, 3f)) {
        var input = SpiritInteraction().bounds(3000f*density, 3000f*density, 144f*density).down(0f, 0f, 0L)
        for (frame in 1..hz) {
            val millis = (frame*1000.0/hz).toLong()
            input = input.move(millis*.48f*density, 0f, 0f, millis, 144f*density)
            verify(abs(input.render.dragX-.5f) < .0001f, "event-rate/density normalized velocity $hz/$density/$frame")
        }
    }
    fun tailAt(hz: Int): FloatArray {
        var values = FloatArray(8)
        repeat(hz) { values = advanceSpiritTail(values, 1f, 1f/hz, false) }
        return values
    }
    val referenceTail = tailAt(120)
    for (hz in listOf(30,60)) for (i in 0..7)
        verify(abs(tailAt(hz)[i]-referenceTail[i]) < .005f, "tail timing parity $hz/$i")
    verify(sampleSpiritClip("hold_enter", .25f, false) .let { it.name == "hold_loop" && abs(it.seconds - .05f) < .00001f }, "clip successor preserves residual time")
    verify(hasSecondarySpiritPointer(1L, listOf(2L)), "primary-up plus secondary-down cancels")
    verify(hasSecondarySpiritPointer(1L, listOf(1L,2L)), "second pointer during hold cancels")
    verify(!hasSecondarySpiritPointer(1L, listOf(1L)), "primary pointer remains valid")
    verify(!hasSecondarySpiritPointer(1L, emptyList()), "ordinary up remains valid")
}
