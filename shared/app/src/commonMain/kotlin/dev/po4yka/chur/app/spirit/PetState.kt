package dev.po4yka.chur.app.spirit

import kotlin.math.exp

enum class PetActivity { REST, TOY, TREAT, SLEEP }
enum class PetAction { GREET, TREAT, TOY, SLEEP }

/** Session-only public artwork. No clock, score, identity, or persistent progression. */
data class PetState(
    val interaction: SpiritInteraction = SpiritInteraction(),
    val activity: PetActivity = PetActivity.REST,
) {
    fun act(action: PetAction): PetState {
        if (activity == PetActivity.SLEEP && action != PetAction.SLEEP) return this
        val next = when (action) {
            PetAction.GREET -> PetActivity.REST
            PetAction.TREAT -> PetActivity.TREAT
            PetAction.TOY -> if (activity == PetActivity.TOY) PetActivity.REST else PetActivity.TOY
            PetAction.SLEEP -> if (activity == PetActivity.SLEEP) PetActivity.REST else PetActivity.SLEEP
        }
        val clip = when {
            next == PetActivity.SLEEP -> "sleep_enter"
            activity == PetActivity.SLEEP -> "wake"
            action == PetAction.GREET -> "tap_react"
            next == PetActivity.TREAT || next == PetActivity.TOY -> "notice"
            else -> "idle_soft"
        }
        return copy(activity = next, interaction = interaction.up(true).let {
            it.copy(render = it.render.copy(clip = clip, clipSerial = it.render.clipSerial + 1))
        })
    }

    fun settleTreat(): PetState = if (activity == PetActivity.TREAT) act(PetAction.GREET) else this

    /** Toy centre on the far side of the scene, so the pet visibly travels to it. */
    fun toyOffer(size: Float): Pair<Float, Float> {
        val i = interaction
        val half = size / 2
        return if (i.maxX > 0f) Pair((if (i.x <= i.maxX / 2) i.maxX else 0f) + half, i.y + half)
        else Pair(i.x + half, (if (i.y <= i.maxY / 2) i.maxY else 0f) + half)
    }

    fun follow(x: Float, y: Float, seconds: Float): PetState {
        if (activity != PetActivity.TOY || !x.isFinite() || !y.isFinite() || !seconds.isFinite()) return this
        val fraction = if (interaction.render.reducedMotion) 1f else 1f - exp(-seconds.coerceIn(0f, .1f) * 6f)
        val nx = x.coerceIn(0f, interaction.maxX)
        val ny = y.coerceIn(0f, interaction.maxY)
        return copy(interaction = interaction.copy(
            x = interaction.x + (nx - interaction.x) * fraction,
            y = interaction.y + (ny - interaction.y) * fraction,
        ))
    }
}
