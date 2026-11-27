package dev.po4yka.chur.app.publicshell

import kotlin.math.abs
import kotlin.math.floor
import kotlin.math.log10
import kotlin.math.pow
import kotlin.math.round

/** A finite, immediate-execution calculator. It does not parse or evaluate text. */
data class CalculatorState private constructor(
    val display: String,
    val error: String?,
    private val stored: String?,
    private val operation: CalculatorKey?,
    private val waiting: Boolean,
    private val freshInput: Boolean,
    private val repeatOperation: CalculatorKey?,
    private val repeatOperand: String?,
) {
    constructor() : this("0", null, null, null, false, false, null, null)

    val pendingExpression: String
        get() = if (stored != null && operation != null) "$stored ${operation.symbol}" else ""

    fun replaceOperand(text: String): CalculatorState? =
        fromNumber(text)?.copy(stored = stored, operation = operation)

    val calculationExpression: String? get() {
        val selected = operation ?: repeatOperation ?: return null
        val right = if (operation != null) { if (waiting) stored!! else display } else repeatOperand!!
        return "${if (operation != null) stored else display} ${selected.symbol} $right"
    }

    fun press(key: CalculatorKey): CalculatorState {
        if (key == CalculatorKey.CLEAR) return CalculatorState()
        if (key.digit != null || key == CalculatorKey.DECIMAL) {
            val start = if (error != null) CalculatorState() else this
            return start.enter(key)
        }
        if (error != null) return if (key == CalculatorKey.BACKSPACE) CalculatorState() else this
        return when (key) {
            CalculatorKey.ADD, CalculatorKey.SUBTRACT, CalculatorKey.MULTIPLY, CalculatorKey.DIVIDE -> {
                val result = if (operation != null && !waiting) calculate(stored!!, operation, display) else display
                if (result == null) failure(operation, display)
                else copy(display = result, stored = result, operation = key, waiting = true,
                    freshInput = true, repeatOperation = null, repeatOperand = null)
            }
            CalculatorKey.EQUALS -> equalsResult()
            CalculatorKey.SIGN -> {
                val input = if (waiting) "0" else display
                copy(display = if (input.startsWith('-')) input.drop(1) else "-$input",
                    waiting = false, freshInput = if (waiting) false else freshInput,
                    repeatOperation = null, repeatOperand = null)
            }
            CalculatorKey.PERCENT -> {
                val value = display.toDouble()
                val base = if (operation == CalculatorKey.ADD || operation == CalculatorKey.SUBTRACT) stored!!.toDouble() else 1.0
                val result = format(base * (value / 100.0))
                if (result == null) failure(null, display)
                else copy(display = result, waiting = false, freshInput = true, repeatOperation = null, repeatOperand = null)
            }
            CalculatorKey.BACKSPACE -> if (waiting) this else copy(
                display = if ('E' in display || 'e' in display) "0" else display.dropLast(1).takeUnless { it.isEmpty() || it == "-" } ?: "0",
                freshInput = false, repeatOperation = null, repeatOperand = null,
            )
            else -> this
        }
    }

    private fun enter(key: CalculatorKey): CalculatorState {
        var input = if (freshInput) "0" else display
        if (key == CalculatorKey.DECIMAL) {
            if ('.' in input) return this
            input += "."
        } else {
            val digit = key.digit!!
            input = when (input) {
                "0" -> digit.toString()
                "-0" -> "-$digit"
                else -> input + digit
            }
            // Input and display work stay bounded even if a button is held down.
            if (input.length > 16 || input.filter { it.isDigit() }.trimStart('0').length > 12) return this
        }
        return copy(display = input, waiting = false, freshInput = false,
            repeatOperation = null, repeatOperand = null)
    }

    private fun equalsResult(): CalculatorState {
        val selected = operation ?: repeatOperation ?: return copy(freshInput = true)
        val operand = if (operation != null) {
            if (waiting) stored!! else display
        } else repeatOperand!!
        val left = if (operation != null) stored!! else display
        val result = calculate(left, selected, operand) ?: return failure(selected, operand)
        return copy(display = result, stored = null, operation = null, waiting = false,
            freshInput = true, repeatOperation = selected, repeatOperand = operand)
    }

    private fun failure(selected: CalculatorKey?, operand: String): CalculatorState = CalculatorState().copy(
        error = if (selected == CalculatorKey.DIVIDE && operand.toDouble() == 0.0) "Cannot divide by zero" else "Result out of range",
    )

    /** Only public calculator values enter platform saved state. No vault state is read. */
    internal fun save(): List<String> = listOf(display, error ?: "", stored ?: "", operation?.name ?: "",
        waiting.toString(), freshInput.toString(), repeatOperation?.name ?: "", repeatOperand ?: "")

    companion object {
        fun fromNumber(text: String): CalculatorState? {
            val value = text.trim().replace(publicDecimalSeparator(), ".").replace(',', '.').toDoubleOrNull()?.takeIf { it.isFinite() } ?: return null
            return format(value)?.let { CalculatorState().copy(display = it, freshInput = true) }
        }
        internal fun restore(values: List<String>): CalculatorState? {
            if (values.size != 8 || values.any { it.length > 64 }) return null
            val display = values[0].takeIf { it.length <= 32 && it.toDoubleOrNull()?.isFinite() == true } ?: return null
            fun number(index: Int): String? = values[index].takeIf { it.isNotEmpty() }
            fun operator(index: Int): CalculatorKey? = CalculatorKey.entries.firstOrNull { it.name == values[index] && it.isOperator }
            val stored = number(2)
            val operation = operator(3)
            val repeat = operator(6)
            val operand = number(7)
            if (listOfNotNull(stored, operand).any { it.toDoubleOrNull()?.isFinite() != true }) return null
            if ((stored == null) != (operation == null) || (repeat == null) != (operand == null)) return null
            if (values[4] !in listOf("true", "false") || values[5] !in listOf("true", "false")) return null
            val error = values[1].takeIf { it.isNotEmpty() }
            if (error != null && error !in listOf("Cannot divide by zero", "Result out of range")) return null
            return CalculatorState(display, error, stored, operation, values[4].toBoolean(), values[5].toBoolean(), repeat, operand)
        }

        private fun calculate(left: String, operation: CalculatorKey, right: String): String? {
            val a = left.toDouble()
            val b = right.toDouble()
            val result = when (operation) {
                CalculatorKey.ADD -> a + b
                CalculatorKey.SUBTRACT -> a - b
                CalculatorKey.MULTIPLY -> a * b
                CalculatorKey.DIVIDE -> if (b == 0.0) return null else a / b
                else -> return null
            }
            return format(result)
        }

        /** Twelve significant digits, with bounded scientific notation for extreme values. */
        internal fun format(value: Double): String? {
            if (!value.isFinite() || abs(value) > 1e99 || (value != 0.0 && abs(value) < 1e-99)) return null
            if (value == 0.0) return "0"
            val magnitude = abs(value)
            var exponent = floor(log10(magnitude)).toInt()
            var significand = round(magnitude / 10.0.pow(exponent) * 1e11).toLong()
            if (significand >= 1_000_000_000_000L) {
                significand /= 10
                exponent++
            }
            val digits = significand.toString().trimEnd('0')
            val number = if (exponent < -6 || exponent >= 12) {
                digits.take(1) + (if (digits.length > 1) ".${digits.drop(1)}" else "") + "e" + exponent
            } else {
                val point = exponent + 1
                when {
                    point <= 0 -> "0." + "0".repeat(-point) + digits
                    point >= digits.length -> digits + "0".repeat(point - digits.length)
                    else -> digits.take(point) + "." + digits.drop(point)
                }
            }
            return if (value < 0.0) "-$number" else number
        }
    }
}

enum class CalculatorKey(val symbol: String, val label: String, val digit: Int? = null) {
    ZERO("0", "0", 0), ONE("1", "1", 1), TWO("2", "2", 2), THREE("3", "3", 3),
    FOUR("4", "4", 4), FIVE("5", "5", 5), SIX("6", "6", 6),
    SEVEN("7", "7", 7), EIGHT("8", "8", 8), NINE("9", "9", 9),
    DECIMAL(".", "Decimal point"), ADD("+", "Add"), SUBTRACT("−", "Subtract"),
    MULTIPLY("×", "Multiply"), DIVIDE("÷", "Divide"), EQUALS("=", "Equals"),
    SIGN("+/−", "Change sign"), PERCENT("%", "Percent"), CLEAR("AC", "Clear all"),
    BACKSPACE("⌫", "Delete last digit");

    val isOperator: Boolean
        get() = this == ADD || this == SUBTRACT || this == MULTIPLY || this == DIVIDE
}
