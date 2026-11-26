package dev.po4yka.chur.app.publicshell

import kotlin.math.*

/** A bounded expression parser. No scripting engine, identifiers or executable input. */
object ScientificCalculator {
    private val trailingAtom = Regex("""(?:[0-9.,]+(?:e[+−-]?[0-9]*)?|[a-zA-Zπ]+)$""")

    internal fun toggleOperandSign(expression: String): String {
        var end = expression.trimEnd().length
        if (expression.getOrNull(end - 1) == '%') end = expression.take(end - 1).trimEnd().length
        val start = if (expression.getOrNull(end - 1) == ')') {
            var depth = 1
            var open = end - 1
            while (open > 0 && depth > 0) {
                when (expression[--open]) {
                    ')' -> depth++
                    '(' -> depth--
                }
            }
            if (depth != 0) return expression
            val prefix = expression.take(open).trimEnd()
            if (prefix.lastOrNull()?.isLetter() == true) prefix.indexOfLast { !it.isLetter() } + 1 else open
        } else {
            val decimal = publicDecimalSeparator().singleOrNull() ?: '.'
            trailingAtom.find(expression.take(end).replace(decimal, '.'))?.range?.first ?: end
        }
        val prefix = expression.take(start).trimEnd()
        if (prefix.endsWith('-') || prefix.endsWith('−')) {
            val beforeMinus = prefix.dropLast(1).trimEnd().lastOrNull()
            if (beforeMinus == null || beforeMinus in "(+-−*/×÷^") {
                return expression.removeRange(prefix.lastIndex, prefix.length)
            }
        }
        return if (expression.length < 512) expression.replaceRange(start, start, "-") else expression
    }

    fun evaluate(expression: String, degrees: Boolean): String {
        require(expression.isNotBlank() && expression.length <= 512) { "Enter an expression" }
        val parser = Parser(expression.replace(publicDecimalSeparator(), ".").replace(',', '.').replace('×', '*').replace('÷', '/').replace('−', '-'), degrees)
        return CalculatorState.format(parser.result()) ?: throw IllegalArgumentException("Result out of range")
    }
    private class Parser(val source: String, val degrees: Boolean) {
        var index = 0
        var depth = 0
        fun result(): Double { val value = sum(); space(); require(index == source.length) { "Check the expression" }; return checked(value) }
        fun space() { while (index < source.length && source[index].isWhitespace()) index++ }
        fun take(c: Char): Boolean { space(); return if (index < source.length && source[index] == c) { index++; true } else false }
        fun checked(value: Double): Double { require(value.isFinite()) { "Result outside the function domain" }; return value }
        fun sum(): Double {
            var value = product()
            while (true) value = when { take('+') -> checked(value + product()); take('-') -> checked(value - product()); else -> return value }
        }
        fun product(): Double {
            var value = unary()
            while (true) value = when {
                take('*') -> checked(value * unary())
                take('/') -> { val divisor = unary(); require(divisor != 0.0) { "Cannot divide by zero" }; checked(value / divisor) }
                else -> return value
            }
        }
        fun unary(): Double {
            require(++depth <= 64) { "Expression is too deeply nested" }
            try { return when { take('+') -> unary(); take('-') -> -unary(); else -> power() } } finally { depth-- }
        }
        fun power(): Double {
            val operand = atom()
            val base = if (take('%')) operand / 100 else operand
            return if (take('^')) checked(base.pow(unary())) else base
        }
        fun atom(): Double {
            if (take('(')) { val value = sum(); require(take(')')) { "Close the parenthesis" }; return value }
            space()
            if (take('π')) return PI
            val start = index
            while (index < source.length && source[index].isLetter()) index++
            if (index > start) {
                val name = source.substring(start, index)
                if (name == "e") return E
                if (name == "pi") return PI
                require(take('(')) { "A function needs parentheses" }
                val value = sum()
                require(take(')')) { "Close the parenthesis" }
                val angle = if (degrees) value * PI / 180 else value
                return checked(when (name) {
                    "sin" -> sin(angle); "cos" -> cos(angle)
                    "tan" -> { require(abs(cos(angle)) > 1e-12) { "Tangent is undefined" }; tan(angle) }
                    "sqrt" -> sqrt(value); "ln" -> ln(value); "log" -> log10(value)
                    "abs" -> abs(value); "exp" -> exp(value)
                    else -> throw IllegalArgumentException("Unknown function")
                })
            }
            while (index < source.length && (source[index].isDigit() || source[index] == '.')) index++
            if (index < source.length && source[index] == 'e') {
                index++
                if (index < source.length && source[index] in "+-") index++
                while (index < source.length && source[index].isDigit()) index++
            }
            val number = source.substring(start, index).toDoubleOrNull() ?: throw IllegalArgumentException("Enter a number")
            return checked(number)
        }
    }
}
