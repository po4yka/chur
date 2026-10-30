package dev.po4yka.chur.app.spirit

/** Generated from the asset manifest's validated-small envelope. Not a device guarantee. */
data class SpiritTailJoint(val name: String, val axis: FloatArray, val maxRadians: Float)
val spiritTailJoints = listOf(
    SpiritTailJoint("Tail_01", floatArrayOf(-0.6625739625133669f, -7.406696641750592e-08f, 0.748996491446609f), 0.0f),
    SpiritTailJoint("Tail_02", floatArrayOf(-0.6139406452393908f, -9.084065704530473e-08f, 0.7893521927017322f), 0.0f),
    SpiritTailJoint("Tail_03", floatArrayOf(-0.3896400771372453f, -1.3761976635958492e-07f, 0.9209672145567738f), 0.004f),
    SpiritTailJoint("Tail_04", floatArrayOf(0.03996804484625962f, -2.1324455056325855e-07f, 0.9992009584618713f), 0.008f),
    SpiritTailJoint("Tail_05", floatArrayOf(0.48564314380859f, -2.6638179395419143e-07f, 0.874157157993709f), 0.012f),
    SpiritTailJoint("Tail_06", floatArrayOf(0.7474095073409063f, -2.7011082288225103e-07f, 0.6643636265904016f), 0.016f),
    SpiritTailJoint("Tail_07", floatArrayOf(0.8320503874746037f, -2.9271955926168636e-07f, 0.5547000565199866f), 0.02f),
    SpiritTailJoint("Tail_08", floatArrayOf(0.9405539039307058f, -2.567438838188141e-07f, 0.33964445203866167f), 0.024f),
 )

fun advanceSpiritTail(previous: FloatArray, input: Float, seconds: Float, reduced: Boolean): FloatArray {
    require(previous.size == spiritTailJoints.size)
    if (reduced) return FloatArray(previous.size)
    val dt = if (seconds.isFinite()) seconds.coerceIn(0f, .25f) else 0f
    val steps = kotlin.math.ceil(dt * 240f).toInt().coerceAtLeast(1)
    val step = dt / steps
    // Non-finite values become 0, as in the C++ boundedInput, so one bad sample cannot poison the tail.
    fun bounded(value: Float) = if (value.isFinite()) value.coerceIn(-1f, 1f) else 0f
    var result = previous.copyOf()
    repeat(steps) {
        val before = result
        result = FloatArray(previous.size) { index ->
            val target = bounded(if (index == 0) input else before[index - 1])
            val blend = 1f - kotlin.math.exp(-step * (12f - index))
            bounded(before[index] + (target - before[index]) * blend)
        }
    }
    return result
}
