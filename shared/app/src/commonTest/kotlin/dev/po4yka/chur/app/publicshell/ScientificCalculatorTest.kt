package dev.po4yka.chur.app.publicshell

import kotlin.test.*

class ScientificCalculatorTest {
    @Test fun signChangesOnlyTheOperandAtTheEndOfTheExpression() {
        for ((input, result) in listOf("2+3" to "-1", "2−3" to "5", "2^3" to "0.125",
            "2+sqrt(4*(2+2))" to "-2", "2+(3+4)" to "-5", "2+50%" to "1.5",
            "2+1e-3" to "1.999", "1,5 + 2,5 " to "-1", "2+pi" to "-1.14159265359")) {
            val toggled = ScientificCalculator.toggleOperandSign(input)
            assertEquals(result, ScientificCalculator.evaluate(toggled, true), input)
            assertEquals(input, ScientificCalculator.toggleOperandSign(toggled), input)
        }
        assertEquals("2+ 3", ScientificCalculator.toggleOperandSign("2+ −3"))
        assertEquals("2+-", ScientificCalculator.toggleOperandSign("2+"))
        assertEquals("", ScientificCalculator.toggleOperandSign("-"))
        val full = "1".padStart(512)
        assertEquals(full, ScientificCalculator.toggleOperandSign(full))
    }
    @Test fun precedenceAndParentheses() {
        assertEquals("14", ScientificCalculator.evaluate("2+3*4", true))
        assertEquals("20", ScientificCalculator.evaluate("(2+3)*4", true))
        assertEquals("512", ScientificCalculator.evaluate("2^3^2", true))
        assertEquals("-4", ScientificCalculator.evaluate("-2^2", true))
        assertEquals("0.25", ScientificCalculator.evaluate("2^-2", true))
        assertEquals("0.3", ScientificCalculator.evaluate("0,1+0,2", true))
    }
    @Test fun percentAppliesToThePrecedingOperandBeforeExponentiation() {
        assertEquals("0.05", ScientificCalculator.evaluate("(2+3)%", true))
        assertEquals("0.03", ScientificCalculator.evaluate("sqrt(9)%", true))
        assertEquals("1", ScientificCalculator.evaluate("sin(π%*50)", false))
        assertEquals("0.25", ScientificCalculator.evaluate("50%^2", true))
        assertFailsWith<IllegalArgumentException> { ScientificCalculator.evaluate("5%%", true) }
    }
    @Test fun scientificFunctionsAndAngleModes() {
        assertEquals("1", ScientificCalculator.evaluate("sin(90)", true))
        assertEquals("1", ScientificCalculator.evaluate("sin(pi/2)", false))
        assertEquals("2", ScientificCalculator.evaluate("log(100)", false))
        assertEquals("1", ScientificCalculator.evaluate("ln(e)", true))
        assertEquals("3", ScientificCalculator.evaluate("sqrt(9)", true))
        assertEquals("0.001", ScientificCalculator.evaluate("1e-3", true))
    }
    @Test fun errorsAreBoundedAndRecoverable() {
        for (text in listOf("1/0", "sqrt(-1)", "ln(0)", "tan(90)", "1e100", "2+", "(2", "eval(2)", "NaN", "Infinity", "(".repeat(80)+"1"+")".repeat(80), "1".repeat(513))) {
            assertFailsWith<IllegalArgumentException>(text) { ScientificCalculator.evaluate(text, true) }
        }
        assertEquals("4", ScientificCalculator.evaluate("2+2", true))
    }
    @Test fun ordinaryCalculatorStillExecutesInEntryOrder() {
        var state = CalculatorState()
        for (key in listOf(CalculatorKey.TWO, CalculatorKey.ADD, CalculatorKey.THREE, CalculatorKey.MULTIPLY, CalculatorKey.FOUR)) state = state.press(key)
        assertEquals("5 × 4", state.calculationExpression)
        assertEquals("20", state.press(CalculatorKey.EQUALS).display)
    }
}
