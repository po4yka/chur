package dev.po4yka.chur.app.publicshell

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.focusable
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.key.*
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import dev.po4yka.chur.app.theme.SettingsGlyph

/** Input is intentionally process-local: a partial transition code must never enter saved state. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CalculatorScreen(onOpenSettings: () -> Unit, modifier: Modifier = Modifier, onSubmitCode: (String) -> Boolean = { false },
    showFirstWriteDisclosure: Boolean = false, onAcknowledgeDisclosure: () -> Unit = {}) {
    val store = LocalPublicUtilities.current
    val keyboardFocus = remember { FocusRequester() }
    val clipboard = LocalClipboardManager.current
    var basic by remember { mutableStateOf(CalculatorState()) }
    var scientific by remember { mutableStateOf(false) }
    LaunchedEffect(scientific) { if (!scientific) keyboardFocus.requestFocus() }
    var expression by remember { mutableStateOf("") }
    var scientificResult by remember { mutableStateOf("0") }
    var degrees by remember { mutableStateOf(true) }
    val historyResult = remember { runCatching { store.history() } }
    var history by remember { mutableStateOf(historyResult.getOrDefault(emptyList())) }
    var showingHistory by remember { mutableStateOf(false) }
    var message by remember { mutableStateOf(if (historyResult.isFailure) "History is unavailable. Its saved data has not been changed." else null) }
    var directEntry by remember { mutableStateOf("") }
    var pendingHistory by remember { mutableStateOf<Calculation?>(null) }
    var acceptedDisclosure by remember { mutableStateOf(false) }
    val decimal = publicDecimalSeparator()
    fun record(row: Calculation) {
        if (showFirstWriteDisclosure && !acceptedDisclosure) { pendingHistory = row; return }
        try {
            history = store.appendCalculation(row)
            message = null
        } catch (_: Exception) { message = utilityText("History could not be saved. Your result is still available.", "Не удалось сохранить историю. Результат остаётся на экране.") }
    }
    fun submit() {
        val candidate = if (scientific) expression else directEntry.takeIf {
            basic.pendingExpression.isEmpty() && basic.error == null && basic.display == it.trimStart('0').ifEmpty { "0" }
        }.orEmpty()
        if (onSubmitCode(candidate)) {
            directEntry = ""; expression = ""; scientificResult = "0"; basic = CalculatorState(); showingHistory = false
            return
        }
        directEntry = ""
        if (scientific) {
            try { scientificResult = ScientificCalculator.evaluate(expression, degrees); record(Calculation(expression, scientificResult)) }
            catch (error: IllegalArgumentException) { message = error.message }
        } else {
            val original = basic
            basic = basic.press(CalculatorKey.EQUALS)
            if (basic.error == null) original.calculationExpression?.let { record(Calculation(it, basic.display)) }
        }
    }
    fun press(key: CalculatorKey) {
        message = null
        if (key == CalculatorKey.EQUALS) { submit(); return }
        if (scientific) {
            expression = when (key) {
                CalculatorKey.CLEAR -> ""
                CalculatorKey.BACKSPACE -> expression.dropLast(1)
                CalculatorKey.SIGN -> ScientificCalculator.toggleOperandSign(expression)
                else -> (expression + if (key == CalculatorKey.DECIMAL) decimal else key.symbol).take(512)
            }
        } else {
            directEntry = when {
                key.digit != null -> (directEntry + key.digit).take(16)
                key == CalculatorKey.BACKSPACE -> directEntry.dropLast(1)
                else -> ""
            }
            basic = basic.press(key)
        }
    }
    pendingHistory?.let { row -> AlertDialog(onDismissRequest = { pendingHistory = null },
        title = { Text(utilityText("Data storage", "Хранение данных")) },
        text = { Text(utilityText("Calculation history is not encrypted by this app and can enter system backup.", "История вычислений не зашифрована приложением и может попасть в системную резервную копию.")) },
        confirmButton = { TextButton(onClick = { acceptedDisclosure = true; onAcknowledgeDisclosure(); pendingHistory = null; record(row) }) { Text(utilityText("Got it", "Понятно")) } },
        dismissButton = { TextButton(onClick = { pendingHistory = null }) { Text(utilityText("Cancel", "Отмена")) } }) }
    if (showingHistory) ModalBottomSheet(onDismissRequest = { showingHistory = false }) {
        Row(Modifier.fillMaxWidth().padding(horizontal = 20.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(utilityText("History", "История"), style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            TextButton(enabled = history.isNotEmpty(), onClick = {
                try { store.saveHistory(emptyList()); history = emptyList() } catch (_: Exception) { message = "History could not be cleared." }
            }) { Text(utilityText("Clear", "Очистить")) }
        }
        if (history.isEmpty()) Text(utilityText("Your calculations will appear here.", "Здесь появятся ваши вычисления."), Modifier.padding(20.dp))
        LazyColumn(Modifier.fillMaxWidth().heightIn(max = 480.dp)) {
            itemsIndexed(history) { index, row ->
                ListItem(headlineContent = { Text(row.result) }, supportingContent = { Text(row.expression) }, trailingContent = {
                    Row {
                        TextButton(onClick = {
                            if (scientific) expression = row.result else basic = basic.replaceOperand(row.result) ?: basic
                            directEntry = ""; showingHistory = false
                        }) { Text(utilityText("Use", "Вставить")) }
                        TextButton(onClick = {
                            val next = history.filterIndexed { i, _ -> i != index }
                            try { store.saveHistory(next); history = next } catch (_: Exception) { message = "History could not be saved." }
                        }) { Text(utilityText("Delete", "Удалить")) }
                    }
                })
            }
        }
    }
    Scaffold(modifier = modifier.focusRequester(keyboardFocus).focusable().onPreviewKeyEvent { event ->
        if (event.type != KeyEventType.KeyDown || event.isCtrlPressed || event.isMetaPressed || event.isAltPressed) false
        else {
            val key = when (event.key) {
                Key.Enter, Key.NumPadEnter -> CalculatorKey.EQUALS
                Key.Backspace -> CalculatorKey.BACKSPACE
                Key.Escape -> CalculatorKey.CLEAR
                else -> CalculatorKey.entries.firstOrNull { it.symbol == event.utf16CodePoint.toChar().toString() }
                    ?: when (event.utf16CodePoint.toChar()) { '*' -> CalculatorKey.MULTIPLY; '/' -> CalculatorKey.DIVIDE; '-' -> CalculatorKey.SUBTRACT; ',' -> CalculatorKey.DECIMAL; else -> null }
            }
            if (key != null && !scientific) { press(key); true } else false
        }
    }, topBar = { TopAppBar(title = { Text(utilityText("Calculator", "Калькулятор"), style = MaterialTheme.typography.titleMedium) }, actions = {
        IconButton(onClick = onOpenSettings) { Icon(SettingsGlyph, utilityText("Settings", "Настройки")) }
    }) }) { padding ->
        BoxWithConstraints(Modifier.fillMaxSize().padding(padding)) {
            val wide = maxWidth > 600.dp
            Column(Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp), horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Row(Modifier.widthIn(max = 720.dp).fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.SpaceBetween) {
                    TextButton(onClick = { showingHistory = true }) { Text(utilityText("History", "История")) }
                    FilterChip(selected = scientific, onClick = { scientific = !scientific; directEntry = ""; message = null }, label = { Text(utilityText("Scientific", "Научный")) })
                    if (scientific) TextButton(onClick = { degrees = !degrees }) { Text(if (degrees) "DEG" else "RAD") }
                }
                if (scientific) OutlinedTextField(expression, { expression = it.take(512) }, singleLine = true,
                    label = { Text(utilityText("Expression", "Выражение")) }, modifier = Modifier.widthIn(max = 720.dp).fillMaxWidth(),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Ascii, imeAction = ImeAction.Done), keyboardActions = KeyboardActions(onDone = { submit() }))
                else Text(basic.pendingExpression.ifEmpty { " " }, textAlign = androidx.compose.ui.text.style.TextAlign.End, modifier = Modifier.widthIn(max = 720.dp).fillMaxWidth(), style = MaterialTheme.typography.titleMedium)
                val result = if (scientific) scientificResult else basic.error ?: basic.display
                Text(result.replace('.', decimal.first()), textAlign = androidx.compose.ui.text.style.TextAlign.End, style = MaterialTheme.typography.displayLarge, maxLines = 1,
                    modifier = Modifier.widthIn(max = 720.dp).fillMaxWidth().horizontalScroll(rememberScrollState()).semantics {
                        contentDescription = utilityText("Calculator result: $result", "Результат: $result"); liveRegion = LiveRegionMode.Polite
                    })
                Row(Modifier.widthIn(max = 720.dp).fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                    TextButton(onClick = { clipboard.setText(AnnotatedString(result)) }) { Text(utilityText("Copy", "Копировать")) }
                    TextButton(onClick = {
                        val text = clipboard.getText()?.text.orEmpty().trim()
                        val parsed = basic.replaceOperand(text)
                        if (parsed == null) message = utilityText("Paste a finite number.", "Вставьте конечное число.")
                        else { if (scientific) expression = if (PublicUtilityStore.validCode(text)) text else parsed.display else basic = parsed; directEntry = text.takeIf(PublicUtilityStore::validCode).orEmpty() }
                    }) { Text(utilityText("Paste", "Вставить")) }
                }
                message?.let { Text(it, color = MaterialTheme.colorScheme.error, modifier = Modifier.widthIn(max = 720.dp)) }
                if (scientific) {
                    for (row in listOf(listOf("sin(", "cos(", "tan(", "π", "e"), listOf("sqrt(", "ln(", "log(", "^", "("), listOf(")", "^2", "abs(", "exp(", "1/"))) {
                        Row(Modifier.widthIn(max = 720.dp).fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                            row.forEach { function -> OutlinedButton(onClick = { expression = (expression + function).take(512) }, modifier = Modifier.weight(1f), contentPadding = PaddingValues(2.dp)) { Text(function) } }
                        }
                    }
                }
                for (row in calculatorRows) Row(Modifier.widthIn(max = 720.dp).fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    row.forEach { key ->
                        val active = key.isOperator && basic.pendingExpression.endsWith(key.symbol)
                        FilledTonalButton(onClick = { press(key) }, modifier = Modifier.weight(1f).heightIn(min = if (wide) 56.dp else 64.dp).semantics { contentDescription = key.accessibleLabel() },
                            colors = ButtonDefaults.filledTonalButtonColors(containerColor = when {
                                key == CalculatorKey.EQUALS || active -> MaterialTheme.colorScheme.primary
                                key.isOperator -> MaterialTheme.colorScheme.primaryContainer
                                else -> MaterialTheme.colorScheme.surfaceContainer
                            }, contentColor = if (key == CalculatorKey.EQUALS || active) MaterialTheme.colorScheme.onPrimary else MaterialTheme.colorScheme.onSurface),
                            contentPadding = PaddingValues(4.dp)) { Text(if (key == CalculatorKey.DECIMAL) decimal else key.symbol, style = MaterialTheme.typography.headlineSmall) }
                    }
                }
            }
        }
    }
}
private val calculatorRows = listOf(
    listOf(CalculatorKey.CLEAR, CalculatorKey.BACKSPACE, CalculatorKey.PERCENT, CalculatorKey.DIVIDE),
    listOf(CalculatorKey.SEVEN, CalculatorKey.EIGHT, CalculatorKey.NINE, CalculatorKey.MULTIPLY),
    listOf(CalculatorKey.FOUR, CalculatorKey.FIVE, CalculatorKey.SIX, CalculatorKey.SUBTRACT),
    listOf(CalculatorKey.ONE, CalculatorKey.TWO, CalculatorKey.THREE, CalculatorKey.ADD),
    listOf(CalculatorKey.SIGN, CalculatorKey.ZERO, CalculatorKey.DECIMAL, CalculatorKey.EQUALS),
)

private fun CalculatorKey.accessibleLabel(): String = utilityText(label, when (this) {
    CalculatorKey.DECIMAL -> "Десятичный разделитель"
    CalculatorKey.ADD -> "Прибавить"
    CalculatorKey.SUBTRACT -> "Вычесть"
    CalculatorKey.MULTIPLY -> "Умножить"
    CalculatorKey.DIVIDE -> "Разделить"
    CalculatorKey.EQUALS -> "Равно"
    CalculatorKey.SIGN -> "Сменить знак"
    CalculatorKey.PERCENT -> "Процент"
    CalculatorKey.CLEAR -> "Очистить всё"
    CalculatorKey.BACKSPACE -> "Удалить последнюю цифру"
    else -> label
})
