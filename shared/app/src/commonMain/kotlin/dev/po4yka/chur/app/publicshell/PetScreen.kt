package dev.po4yka.chur.app.publicshell

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.horizontalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.LayoutCoordinates
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.*
import androidx.compose.ui.unit.dp
import dev.po4yka.chur.app.spirit.*
import dev.po4yka.chur.app.onboarding.*
import dev.po4yka.chur.app.theme.LocalChurMotion
import dev.po4yka.chur.app.theme.SettingsGlyph
import kotlinx.coroutines.delay

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PetScreen(onOpenSettings: () -> Unit, onSubmitCode: (String) -> Boolean,
              inputEpoch: Long = 0L, onNavigationBusy: (Boolean) -> Unit = {}) {
    val guide = LocalGuide.current
    val guideToken = guide?.session?.collectAsState()?.value?.token
    val size = 144.dp
    val density = LocalDensity.current
    val sizePx = with(density) { size.toPx() }
    val reduced = LocalChurMotion.current.reducedMotion
    var pet by remember { mutableStateOf(PetState()) }
    var room by remember { mutableStateOf(false) }
    var placed by remember { mutableStateOf(false) }
    var toy by remember { mutableStateOf(Offset.Zero) }
    var treat by remember { mutableFloatStateOf(0f) }
    var treatSerial by remember { mutableIntStateOf(0) }
    var enteringCode by remember(inputEpoch) { mutableStateOf(false) }
    val coordinates = remember { arrayOfNulls<LayoutCoordinates>(1) }
    val sleeping = pet.activity == PetActivity.SLEEP
    val greetLabel = utilityText("Greet Chur", "Погладить Чура")
    val resetLabel = utilityText("Reset position", "Вернуть на место")
    val moveLabel = utilityText("Move Chur", "Переместить Чура")
    val sleepLabel = utilityText(if (sleeping) "Wake" else "Sleep", if (sleeping) "Разбудить" else "Сон")
    // Neutral on purpose: a decoy app must not announce a hidden entry to every screen-reader user.
    val accessLabel = utilityText("More options", "Другие действия")
    fun event(step: GuideStep) { guide?.event(step, guideToken) }
    fun act(action: PetAction) { pet = pet.act(action) }
    DisposableEffect(enteringCode) { onNavigationBusy(enteringCode); onDispose { onNavigationBusy(false) } }
    LaunchedEffect(reduced) { pet = pet.copy(interaction = pet.interaction.motion(reduced)) }
    LaunchedEffect(inputEpoch) { pet = pet.copy(interaction = pet.interaction.up(true)); if (pet.activity == PetActivity.TOY) act(PetAction.TOY) }
    LaunchedEffect(treatSerial) {
        if (treatSerial == 0) return@LaunchedEffect
        treat = 0f
        if (!reduced) repeat(18) { treat = (it + 1) / 18f; delay(33) }
        else { treat = 1f; delay(100) }
        pet = pet.settleTreat()
        event(GuideStep.PET_TREAT)
    }
    LaunchedEffect(pet.activity, toy, reduced) {
        if (pet.activity == PetActivity.TOY) {
            do {
                pet = pet.follow(toy.x - sizePx / 2, toy.y - sizePx / 2, 1f / 30)
                val target = Offset((toy.x - sizePx / 2).coerceIn(0f, pet.interaction.maxX),
                    (toy.y - sizePx / 2).coerceIn(0f, pet.interaction.maxY))
                val delta = Offset(pet.interaction.x, pet.interaction.y) - target
                if (delta.getDistance() < 1f || reduced) break
                delay(33)
            } while (true)
            event(GuideStep.PET_TOY)
        }
    }
    if (enteringCode) AccessCodeDialog(onSubmitCode) { enteringCode = false }
    Scaffold(topBar = { TopAppBar(title = { Text(utilityText("Chur", "Чур")) }, actions = {
        IconButton(onClick = onOpenSettings) { Icon(SettingsGlyph, utilityText("Settings", "Настройки")) }
    }) }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            Box(Modifier.weight(1f).fillMaxWidth().onSizeChanged {
                room = it.width >= sizePx && it.height >= sizePx
                pet = pet.copy(interaction = pet.interaction.bounds(it.width.toFloat(), it.height.toFloat(), sizePx).up(true))
                if (!placed && room) {
                    pet = pet.copy(interaction = pet.interaction.copy(x = pet.interaction.maxX / 2, y = pet.interaction.maxY / 2))
                    toy = Offset(it.width / 2f, it.height / 2f); placed = true
                }
            }.pointerInput(pet.activity, sizePx) {
                if (pet.activity == PetActivity.TOY) awaitEachGesture {
                    val down = awaitFirstDown(); toy = down.position; down.consume()
                    while (true) {
                        val changes = awaitPointerEvent().changes
                        val current = changes.firstOrNull { it.id == down.id } ?: break
                        if (hasSecondarySpiritPointer(down.id.value, changes.filter { it.pressed }.map { it.id.value }) || !current.pressed) break
                        toy = current.position; current.consume()
                    }
                }
            }) {
                if (room) Box(Modifier.absoluteOffset(
                    x = with(density) { pet.interaction.x.toDp() },
                    y = with(density) { pet.interaction.y.toDp() })
                    .size(size).guideTarget("pet").onGloballyPositioned { coordinates[0] = it }
                    .semantics {
                        contentDescription = if (sleeping) utilityText("Chur is sleeping", "Чур спит") else utilityText("Chur companion", "Питомец Чур")
                        // Mirror touch: a tap only reacts, and the pet ignores direct input while it plays with the toy.
                        if (!sleeping && pet.activity != PetActivity.TOY) {
                            onClick(greetLabel) { pet = pet.copy(interaction = pet.interaction.tap()); event(GuideStep.PET_GREET); true }
                            customActions = listOf(
                                CustomAccessibilityAction(resetLabel) { pet = pet.copy(interaction = pet.interaction.up(true).copy(x = pet.interaction.maxX / 2, y = pet.interaction.maxY / 2)); true },
                                CustomAccessibilityAction(moveLabel) { pet = pet.copy(interaction = pet.interaction.copy(x = if (pet.interaction.x < pet.interaction.maxX / 2) pet.interaction.maxX else 0f)); event(GuideStep.PET_MOVE); true })
                        }
                    // guideToken is a key: a running gesture loop otherwise keeps the token it started with.
                    }.pointerInput(sleeping, pet.activity == PetActivity.TOY, sizePx, guideToken) {
                        if (!sleeping && pet.activity != PetActivity.TOY) awaitEachGesture {
                            val down = awaitFirstDown(requireUnconsumed = false)
                            val point = coordinates[0]?.takeIf { it.isAttached }?.localToRoot(down.position) ?: return@awaitEachGesture
                            pet = pet.copy(interaction = pet.interaction.down(point.x, point.y, down.uptimeMillis)); down.consume()
                            try {
                                while (true) {
                                    val changes = awaitPointerEvent().changes
                                    val change = changes.firstOrNull { it.id == down.id }
                                    if (change == null || change.isConsumed || hasSecondarySpiritPointer(down.id.value, changes.filter { it.pressed }.map { it.id.value })) break
                                    if (!change.pressed) {
                                        val moved = pet.interaction.dragging
                                        pet = pet.copy(interaction = pet.interaction.up())
                                        event(if (moved) GuideStep.PET_MOVE else GuideStep.PET_GREET); change.consume(); break
                                    }
                                    val current = coordinates[0]?.takeIf { it.isAttached }?.localToRoot(change.position) ?: break
                                    pet = pet.copy(interaction = pet.interaction.move(current.x, current.y, viewConfiguration.touchSlop, change.uptimeMillis, sizePx))
                                    change.consume()
                                }
                            } finally { pet = pet.copy(interaction = pet.interaction.up(true)) }
                        }
                    }) { SpiritSurface(pet.interaction.render, Modifier.fillMaxSize()) }
                if (pet.activity == PetActivity.TOY || pet.activity == PetActivity.TREAT) Canvas(Modifier.fillMaxSize()) {
                    val end = Offset(pet.interaction.x + sizePx / 2, pet.interaction.y + sizePx / 2)
                    val start = Offset(this.size.width / 2, this.size.height - 24.dp.toPx())
                    val point = if (pet.activity == PetActivity.TOY) toy else start + (end - start) * treat
                    drawCircle(Color(0xFFFFC45C), 9.dp.toPx(), point)
                }
                if (!room) Text(utilityText("More room is needed to show Chur. The controls still work.", "Для Чура нужно больше места. Кнопки по-прежнему работают."), Modifier.padding(16.dp))
            }
            Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(enabled = !sleeping, modifier = Modifier.guideTarget("treat"), onClick = { act(PetAction.TREAT); treatSerial++ }) { Text(utilityText("Treat", "Угостить")) }
                TextButton(enabled = !sleeping, modifier = Modifier.guideTarget("toy"), onClick = {
                    toy = pet.toyOffer(sizePx).let { (x, y) -> Offset(x, y) }
                    act(PetAction.TOY)
                }) { Text(utilityText(if (pet.activity == PetActivity.TOY) "Put toy away" else "Toy", if (pet.activity == PetActivity.TOY) "Убрать игрушку" else "Игрушка")) }
                // TextButton has no long press, so match its role, shape, and text style by hand.
                Row(Modifier.guideTarget("sleep").clip(ButtonDefaults.textShape).combinedClickable(
                    role = Role.Button,
                    onClick = { act(PetAction.SLEEP); event(GuideStep.PET_SLEEP) },
                    onLongClickLabel = accessLabel, onLongClick = { enteringCode = true },
                ).semantics {
                    customActions = listOf(CustomAccessibilityAction(accessLabel) { enteringCode = true; true })
                }.heightIn(min = 48.dp).padding(horizontal = 12.dp), verticalAlignment = Alignment.CenterVertically) {
                    val style = MaterialTheme.typography.labelLarge.copy(color = MaterialTheme.colorScheme.primary)
                    Text("☾ ", Modifier.clearAndSetSemantics {}, style = style)
                    Text(sleepLabel, style = style)
                }
            }
        }
    }
}
