package dev.po4yka.chur.app.publicshell

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CalculatorStateTest {
    @Test
    fun decimal_arithmetic_rounds_the_binary_tail_and_repeated_equals_reuses_the_operand() {
        val sum = calculate("0.1", CalculatorKey.ADD, "0.2")
        assertEquals("0.3", sum.display)
        assertEquals("0.5", sum.press(CalculatorKey.EQUALS).display)
        assertEquals("0.7", sum.press(CalculatorKey.EQUALS).press(CalculatorKey.EQUALS).display)
    }

    @Test
    fun operators_chain_left_to_right_and_replace_an_operator_before_an_operand() {
        val replaced = type("8").press(CalculatorKey.ADD).press(CalculatorKey.MULTIPLY)
        assertEquals("16", type("2", replaced).press(CalculatorKey.EQUALS).display)
        val chained = type("2", type("8").press(CalculatorKey.ADD)).press(CalculatorKey.MULTIPLY)
        assertEquals("30", type("3", chained).press(CalculatorKey.EQUALS).display)
    }

    @Test
    fun missing_second_operand_uses_the_first_and_new_input_starts_a_new_calculation() {
        val square = type("3").press(CalculatorKey.MULTIPLY).press(CalculatorKey.EQUALS)
        assertEquals("9", square.display)
        assertEquals("4", type("4", square).press(CalculatorKey.EQUALS).display)
        assertEquals("0", square.press(CalculatorKey.CLEAR).display)
    }

    @Test
    fun inserting_a_number_replaces_the_operand_and_preserves_the_pending_operation() {
        val pending = type("2").press(CalculatorKey.ADD)
        val pasted = assertNotNull(pending.replaceOperand("3"))
        assertEquals("2 + 3", pasted.calculationExpression)
        assertEquals("5", pasted.press(CalculatorKey.EQUALS).display)
        val replacement = assertNotNull(pasted.replaceOperand("01234567"))
        assertEquals("2 +", replacement.pendingExpression)
        assertEquals("1234569", replacement.press(CalculatorKey.EQUALS).display)
        assertNull(pasted.replaceOperand("NaN"))
        val newEntry = assertNotNull(pasted.press(CalculatorKey.EQUALS).replaceOperand("4"))
        assertEquals("4", newEntry.press(CalculatorKey.EQUALS).display)
    }

    @Test
    fun percent_is_relative_for_addition_and_subtraction_and_a_fraction_for_multiplication() {
        val plus = type("10", type("200").press(CalculatorKey.ADD)).press(CalculatorKey.PERCENT)
        assertEquals("20", plus.display)
        assertEquals("220", plus.press(CalculatorKey.EQUALS).display)
        val minus = type("10", type("200").press(CalculatorKey.SUBTRACT)).press(CalculatorKey.PERCENT)
        assertEquals("180", minus.press(CalculatorKey.EQUALS).display)
        val product = type("10", type("200").press(CalculatorKey.MULTIPLY)).press(CalculatorKey.PERCENT)
        assertEquals("20", product.press(CalculatorKey.EQUALS).display)
        assertEquals("0.5", type("50").press(CalculatorKey.PERCENT).display)
    }

    @Test
    fun sign_can_start_a_negative_operand_and_backspace_edits_it() {
        val negative = type("5").press(CalculatorKey.ADD).press(CalculatorKey.SIGN)
        val entered = type("23", negative)
        assertEquals("-23", entered.display)
        assertEquals("3", entered.press(CalculatorKey.BACKSPACE).press(CalculatorKey.EQUALS).display)
        assertEquals("23", entered.press(CalculatorKey.SIGN).display)
    }

    @Test
    fun repeated_decimal_and_leading_zero_input_remain_valid_and_entry_is_bounded() {
        assertEquals("0.2", type("000.2.").display)
        val maximum = type("123456789012345678901234567890")
        assertEquals("123456789012", maximum.display)
        assertTrue(type("0.00000000000000000000000000001").display.length <= 16)
    }

    @Test
    fun divide_by_zero_is_explicit_and_digit_decimal_clear_or_delete_recovers() {
        val failure = calculate("1", CalculatorKey.DIVIDE, "0")
        assertEquals("Cannot divide by zero", failure.error)
        assertEquals(failure, failure.press(CalculatorKey.EQUALS))
        assertEquals("2", type("2", failure).display)
        assertNull(type("2", failure).error)
        assertEquals("0.", failure.press(CalculatorKey.DECIMAL).display)
        assertNull(failure.press(CalculatorKey.CLEAR).error)
        assertNull(failure.press(CalculatorKey.BACKSPACE).error)
    }

    @Test
    fun large_results_use_scientific_notation_and_range_errors_are_recoverable() {
        val large = calculate("999999999999", CalculatorKey.MULTIPLY, "9")
        assertEquals("8.99999999999e12", large.display)
        var result = calculate("999999999999", CalculatorKey.MULTIPLY, "999999999999")
        repeat(12) { result = result.press(CalculatorKey.EQUALS) }
        assertEquals("Result out of range", result.error)
        assertEquals("7", type("7", result).display)
        assertEquals("1e-11", calculate("1", CalculatorKey.DIVIDE, "100000000000").display)
    }

    @Test
    fun saved_state_restores_pending_and_repeated_operations_and_rejects_bad_values() {
        val pending = type("5", type("10").press(CalculatorKey.SUBTRACT))
        val restored = assertNotNull(CalculatorState.restore(pending.save()))
        assertEquals("5", restored.press(CalculatorKey.EQUALS).display)
        val repeated = restored.press(CalculatorKey.EQUALS)
        assertEquals("0", assertNotNull(CalculatorState.restore(repeated.save())).press(CalculatorKey.EQUALS).display)
        assertNull(CalculatorState.restore(listOf("NaN")))
        assertNull(CalculatorState.restore(CalculatorState().save().toMutableList().also { it[0] = "Infinity" }))
        assertNull(CalculatorState.restore(CalculatorState().save().toMutableList().also { it[2] = "1" }))
    }

    private fun calculate(left: String, key: CalculatorKey, right: String): CalculatorState =
        type(right, type(left).press(key)).press(CalculatorKey.EQUALS)

    private fun type(text: String, initial: CalculatorState = CalculatorState()): CalculatorState =
        text.fold(initial) { state, character ->
            state.press(if (character == '.') CalculatorKey.DECIMAL else CalculatorKey.entries.first { it.digit == character.digitToInt() })
        }
}
