package dev.po4yka.chur.app

import dev.po4yka.chur.core.model.ChurStatus
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The ABI gate a host runs before a vault can be opened.
 *
 * `docs/interop/FFI_CONTRACT.md` §2 fixes what it refuses, and ADR-0037 makes a
 * panicking library return values the gate already refuses. These tests assert
 * both, so a contained panic is a refusal rather than a value the host trusts.
 */
class AbiGateTest {
    private fun handshake(
        major: UInt = 7u,
        minor: UInt = REQUIRED_ABI_MINOR,
        capabilities: ULong = 0u,
        objectMin: UInt = 1u,
        objectMax: UInt = 1u,
        slotMin: UInt = 1u,
        slotMax: UInt = 1u,
        flavor: UInt = FLAVOR_RELEASE,
    ) = NativeHandshake(major, minor, capabilities, objectMin, objectMax, slotMin, slotMax, flavor)

    @Test
    fun a_matching_release_library_is_compatible() {
        val result = gate(handshake(), releaseApplication = true)
        assertIs<GateResult.Compatible>(result)
        assertEquals(0uL, result.capabilities)
    }

    @Test
    fun another_major_version_is_refused_terminally() {
        for (major in listOf(0u, 1u, 2u, 3u, 4u, 5u, 6u, UInt.MAX_VALUE)) {
            val result = gate(handshake(major = major), releaseApplication = true)
            assertIs<GateResult.Incompatible>(result)
            assertEquals(ChurStatus.ABI_INCOMPATIBLE, result.status)
            assertEquals(GateResult.Reason.MAJOR_VERSION, result.reason)
        }
    }

    @Test
    fun a_newer_minor_is_not_a_refusal() {
        assertIs<GateResult.Compatible>(gate(handshake(minor = 9u), releaseApplication = true))
    }

    @Test
    fun an_older_minor_is_refused_before_a_missing_function_is_called() {
        for (minor in 0u until REQUIRED_ABI_MINOR) {
            val result = gate(handshake(minor = minor), releaseApplication = true)
            assertIs<GateResult.Incompatible>(result)
            assertEquals(ChurStatus.ABI_INCOMPATIBLE, result.status)
            assertEquals(GateResult.Reason.MINOR_VERSION, result.reason)
        }
    }

    @Test
    fun the_panic_fallback_of_a_channel_less_export_is_refused() {
        // ADR-0037: a panicking library returns major 0 and the inverted range
        // 0xFFFF..0. The gate refuses it without knowing a panic happened.
        val panicked = handshake(
            major = 0u,
            minor = 0u,
            capabilities = 0u,
            objectMin = 0xffffu,
            objectMax = 0u,
            slotMin = 0xffffu,
            slotMax = 0u,
            flavor = 0u,
        )
        val result = gate(panicked, releaseApplication = true)
        assertIs<GateResult.Incompatible>(result)
        assertEquals(ChurStatus.ABI_INCOMPATIBLE, result.status)
    }

    @Test
    fun an_empty_format_range_is_refused() {
        for (broken in listOf(
            handshake(objectMin = 2u, objectMax = 1u),
            handshake(slotMin = 2u, slotMax = 1u),
        )) {
            val result = gate(broken, releaseApplication = true)
            assertIs<GateResult.Incompatible>(result)
            assertEquals(GateResult.Reason.EMPTY_FORMAT_RANGE, result.reason)
        }
    }

    @Test
    fun a_release_application_refuses_a_debug_or_test_hook_library() {
        for (flavor in listOf(FLAVOR_DEBUG_ASSERTIONS, FLAVOR_RELEASE or FLAVOR_TEST_HOOKS)) {
            val result = gate(handshake(flavor = flavor), releaseApplication = true)
            assertIs<GateResult.Incompatible>(result)
            assertEquals(GateResult.Reason.BUILD_FLAVOR, result.reason)
        }
    }

    @Test
    fun a_debug_application_accepts_a_debug_library() {
        assertIs<GateResult.Compatible>(
            gate(handshake(flavor = FLAVOR_DEBUG_ASSERTIONS), releaseApplication = false),
        )
    }

    @Test
    fun a_flavor_of_neither_or_both_is_refused_by_any_application() {
        for (release in listOf(true, false)) {
            for (flavor in listOf(0u, FLAVOR_RELEASE or FLAVOR_DEBUG_ASSERTIONS)) {
                val result = gate(handshake(flavor = flavor), releaseApplication = release)
                assertIs<GateResult.Incompatible>(result)
                assertEquals(GateResult.Reason.BUILD_FLAVOR, result.reason)
            }
        }
    }

    @Test
    fun an_unknown_capability_bit_never_reaches_the_host() {
        // §2: an unknown set bit is ignored and never enables behaviour.
        val result = gate(
            handshake(capabilities = 0xffff_ffff_ffff_ffffuL),
            releaseApplication = true,
        )
        assertIs<GateResult.Compatible>(result)
        assertEquals(0xffuL, result.capabilities)
    }

    @Test
    fun no_refusal_message_repeats_a_value_the_library_returned() {
        // ERROR_MODEL.md "Safe metadata": raw untrusted input never reaches a
        // user-visible string.
        val summaries = GateResult.Reason.entries.map { reason ->
            gateSummary(GateResult.Incompatible(ChurStatus.ABI_INCOMPATIBLE, reason))
        }
        assertEquals(GateResult.Reason.entries.size, summaries.toSet().size)
        for (summary in summaries) {
            assertTrue(summary.isNotEmpty())
            assertFalse(summary.any { it.isDigit() }, "a refusal message carries no returned value")
        }
    }
}
