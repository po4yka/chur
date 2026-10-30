package dev.po4yka.chur.app.spirit

import kotlin.test.*

class PetStateTest {
    @Test fun reduced_motion_keeps_a_static_sleep_expression() {
        val sleeping = sampleSpiritClip("sleep_enter", .2f, true)
        assertEquals(SpiritClipSample("sleep_loop", 0f), sleeping)
        assertEquals(0f, SpiritEyes.aperture(sleeping, true))
        assertEquals(SpiritClipSample("idle_soft", 0f), sampleSpiritClip("wake", 5f, true))
    }
    @Test fun sleeping_refuses_food_play_and_greeting_until_woken() {
        val asleep = PetState().act(PetAction.SLEEP)
        assertEquals("sleep_enter", asleep.interaction.render.clip)
        for (action in listOf(PetAction.GREET, PetAction.TREAT, PetAction.TOY)) assertEquals(asleep, asleep.act(action))
        val awake = asleep.act(PetAction.SLEEP)
        assertEquals(PetActivity.REST, awake.activity)
        assertEquals("wake", awake.interaction.render.clip)
    }
    @Test fun treats_are_repeatable_and_a_late_completion_cannot_wake_a_sleeping_pet() {
        var pet = PetState()
        repeat(20) { pet = pet.act(PetAction.TREAT).settleTreat() }
        assertEquals(PetActivity.REST, pet.activity)
        val asleep = pet.act(PetAction.TREAT).act(PetAction.SLEEP)
        assertEquals(asleep, asleep.settleTreat())
    }
    @Test fun toy_follow_is_bounded_and_reduced_motion_moves_directly() {
        val pet = PetState(SpiritInteraction().bounds(500f, 700f, 144f)).act(PetAction.TOY)
        assertEquals(pet, pet.follow(Float.NaN, 0f, .033f))
        val direct = pet.copy(interaction = pet.interaction.motion(true)).follow(10000f, -100f, .033f)
        assertEquals(356f, direct.interaction.x)
        assertEquals(0f, direct.interaction.y)
        val smooth = pet.follow(300f, 300f, .033f)
        assertTrue(smooth.interaction.x > pet.interaction.x && smooth.interaction.x < 300f)
        assertEquals(PetActivity.REST, pet.act(PetAction.TOY).activity)
    }
    @Test fun toy_is_offered_away_from_the_pet() {
        val room = SpiritInteraction().bounds(500f, 700f, 144f)
        assertEquals(Pair(428f, 350f), PetState(room.copy(x = 178f, y = 278f)).toyOffer(144f))
        assertEquals(Pair(72f, 72f), PetState(room.copy(x = 300f, y = 0f)).toyOffer(144f))
        val narrow = SpiritInteraction().bounds(144f, 700f, 144f).copy(y = 100f)
        assertEquals(Pair(72f, 628f), PetState(narrow).toyOffer(144f))
    }
    @Test fun ending_a_drag_or_activity_never_persists_a_session() {
        val dragged = PetState(SpiritInteraction().bounds(500f, 700f, 144f).down(0f, 0f).move(100f, 100f, 8f))
        val sleeping = dragged.act(PetAction.SLEEP)
        assertFalse(sleeping.interaction.pressed)
        assertFalse(sleeping.interaction.dragging)
        assertEquals(PetActivity.REST, PetState().activity)
        assertEquals("idle_soft", PetState().interaction.render.clip)
    }
}
