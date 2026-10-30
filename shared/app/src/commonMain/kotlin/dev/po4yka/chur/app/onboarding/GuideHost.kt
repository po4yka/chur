package dev.po4yka.chur.app.onboarding

import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.composed
import androidx.compose.ui.layout.boundsInWindow
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp
import dev.po4yka.chur.app.*
import dev.po4yka.chur.app.publicshell.utilityText
import dev.po4yka.chur.app.spirit.SpiritRenderState
import dev.po4yka.chur.app.spirit.SpiritSurface
import dev.po4yka.chur.app.theme.LocalChurMotion

internal val LocalGuide = staticCompositionLocalOf<GuideCoordinator?> { null }

/** The target owns its border. No full-screen touch interception or coordinate hit testing. */
internal fun Modifier.guideTarget(id: String, enabled: Boolean = true): Modifier = composed {
    val guide = LocalGuide.current
    val owner = remember(guide, id) { Any() }
    val session = guide?.session?.collectAsState()?.value
    var visible by remember { mutableStateOf(false) }
    SideEffect { guide?.target(owner, id, visible && enabled) }
    DisposableEffect(guide, owner) { onDispose { guide?.releaseTargets(owner) } }
    onGloballyPositioned { coordinates ->
        val bounds = coordinates.boundsInWindow()
        visible = coordinates.isAttached && bounds.width >= coordinates.size.width - 1 &&
            bounds.height >= coordinates.size.height - 1 && bounds.width > 0 && bounds.height > 0
    }.then(if (visible && enabled && session?.step?.target == id) Modifier.border(2.dp, MaterialTheme.colorScheme.primary, MaterialTheme.shapes.small) else Modifier)
}

@Composable
fun GuideHost(controller: ChurController, route: AppRoute, onDockHeight: (Float) -> Unit = {}, content: @Composable () -> Unit) {
    val guide = controller.guide
    val session by guide.session.collectAsState()
    val shell by controller.publicShell.collectAsState()
    val discreet by controller.publicUtilities.discreet.collectAsState()
    val obscured by controller.guideObscured.collectAsState()
    val targets by guide.targets.collectAsState()
    val preferenceError by controller.publicShellError.collectAsState()
    val current = session
    val density = LocalDensity.current.density
    // A public route can only show public lessons or the explicit first-launch introduction.
    val publicRoute = route == AppRoute.PublicShell || route == AppRoute.PublicSettings
    val introductory = current?.step in listOf(GuideStep.CHOOSE, GuideStep.PRIVACY)
    val show = !obscured && current != null && (current.publicOnly && publicRoute || !current.publicOnly &&
        ((!publicRoute && route != AppRoute.AppUnlock && route != AppRoute.AppRecover) || introductory && !discreet))
    DisposableEffect(show, route) { if (!show) onDockHeight(0f); onDispose { onDockHeight(0f) } }
    CompositionLocalProvider(LocalGuide provides if (show) guide else null) {
        BoxWithConstraints(Modifier.fillMaxSize()) {
            val guideHeight = (maxHeight * .4f).coerceAtMost(240.dp)
            Column(Modifier.fillMaxSize()) {
                Box(Modifier.weight(1f)) {
                    if (show && current?.step == GuideStep.CHOOSE) {
                        Column(Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState()).padding(20.dp)) {
                            Text(utilityText("Meet Chur", "Знакомьтесь: Чур"), style = MaterialTheme.typography.headlineSmall)
                            SpiritSurface(SpiritRenderState(clip = "notice", reducedMotion = LocalChurMotion.current.reducedMotion), Modifier.size(120.dp))
                            Text(utilityText("Choose your public app. You can use it without a vault.", "Выберите публичное приложение. Им можно пользоваться без хранилища."))
                            preferenceError?.let { Text(it, color = MaterialTheme.colorScheme.error) }
                            PublicShell.entries.forEach { option ->
                                TextButton(onClick = { controller.chooseInitialShell(option) }) { Text(publicShellLabel(option)) }
                            }
                        }
                    } else content()
                }
                if (show && current != null) {
                    val step = current.step
                    val targetVisible = step.target == null || targets[step.target] == true
                    Surface(tonalElevation = 3.dp, modifier = Modifier.onSizeChanged { onDockHeight(it.height / density) }) {
                        Column(Modifier.fillMaxWidth().heightIn(max = guideHeight).navigationBarsPadding()
                            .verticalScroll(rememberScrollState()).padding(12.dp)) {
                            if (step != GuideStep.CHOOSE && !(route == AppRoute.PublicShell && shell == PublicShell.PET)) {
                                SpiritSurface(SpiritRenderState(clip = "notice", clipSerial = current.index,
                                    reducedMotion = LocalChurMotion.current.reducedMotion), Modifier.size(64.dp))
                            }
                            Text(if (step == GuideStep.PUBLIC_APP) publicAppText(shell) else guideText(step), style = MaterialTheme.typography.bodyMedium)
                            if (!targetVisible) Text(utilityText("Open the matching screen or scroll to the control. You can also skip this step.",
                                "Откройте нужный экран или прокрутите к элементу. Этот шаг можно пропустить."), style = MaterialTheme.typography.bodySmall)
                            if (step == GuideStep.PRIVACY) TextButton(onClick = {
                                guide.event(step, current.token); controller.openVaultEntry()
                            }) { Text(utilityText("Set up vault", "Настроить хранилище")) }
                            if (step.informational && step != GuideStep.PRIVACY) TextButton(enabled = targetVisible,
                                onClick = { guide.event(step, current.token) }) { Text(utilityText("Got it", "Понятно")) }
                            FlowRow {
                                TextButton(onClick = {
                                    if (step == GuideStep.CHOOSE) controller.chooseInitialShell(PublicShell.NOTES)
                                    else if (step == GuideStep.PRIVACY) { guide.stop(); if (shell == PublicShell.PET) guide.startPet() }
                                    else guide.skip()
                                }) { Text(utilityText("Skip step", "Пропустить шаг")) }
                                TextButton(onClick = { guide.stop() }) { Text(utilityText("Finish tutorial", "Завершить обучение")) }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun publicShellLabel(shell: PublicShell): String = utilityText(shell.label, when (shell) {
    PublicShell.NOTES -> "Заметки"
    PublicShell.CALCULATOR -> "Калькулятор"
    PublicShell.CAMERA -> "Камера"
    PublicShell.PET -> "Чур"
})

@Composable
private fun guideText(step: GuideStep): String = when (step) {
    GuideStep.PUBLIC_APP -> ""
    GuideStep.CHOOSE -> utilityText("Choose Notes, Calculator, Camera, or your companion. Skipping keeps Notes.", "Выберите заметки, калькулятор, камеру или питомца. При пропуске останутся заметки.")
    GuideStep.PRIVACY -> utilityText("Public apps are not vault-encrypted. A private vault uses a separate password. Let us set one up, or skip to use only the public app.", "Публичные приложения не зашифрованы хранилищем. У приватного хранилища отдельный пароль. Настроим его или пропустим этот шаг.")
    GuideStep.CREATE -> utilityText("Choose a strong password and repeat it. Create the vault, or use Restore from a backup if you already have one.", "Задайте надёжный пароль и повторите его. Создайте хранилище или выберите восстановление из резервной копии.")
    GuideStep.RESTORE -> utilityText("Enter the archive password or backup recovery phrase, then choose the file. Restore runs only after your choice. You can cancel or retry; existing data is not replaced.", "Введите пароль архива или фразу восстановления копии, затем выберите файл. Восстановление начнётся только после выбора. Можно отменить выбор или повторить попытку; существующие данные не заменяются.")
    GuideStep.RESTORE_UNLOCK -> utilityText("The archive is restored. Use normal authentication to open the vault. Restoring a file does not open a private session.", "Архив восстановлен. Пройдите обычную авторизацию, чтобы открыть хранилище. Восстановление файла не открывает приватную сессию.")
    GuideStep.RECOVERY -> utilityText("Keep the recovery words offline, away from this device. Words restore access to an existing vault; they cannot replace a backup or recreate lost files. I cannot read or save them. Complete the screen's confirmation; skipping this tip does not skip that confirmation.", "Храните слова восстановления офлайн, отдельно от устройства. Фраза возвращает доступ к существующему хранилищу; она не заменяет копию и не восстанавливает потерянные файлы. Я не читаю и не сохраняю её. Пройдите подтверждение на экране: пропуск подсказки не отменяет его.")
    GuideStep.IMPORT -> utilityText("In Library, use Import and select a file. This step completes only after it is saved. You can cancel or skip.", "В библиотеке нажмите Import и выберите файл. Шаг завершится после сохранения. Выбор можно отменить, а шаг — пропустить.")
    GuideStep.OPEN -> utilityText("Open an item in Library. Return to Library after viewing it. If it is empty, skip this step.", "Откройте элемент библиотеки, затем вернитесь назад. Если библиотека пуста, пропустите шаг.")
    GuideStep.SEARCH -> utilityText("Return to Library and open Search. Submit a query to search your files; an empty result is also a result.", "Вернитесь в библиотеку и откройте Search. Выполните поиск; отсутствие совпадений тоже считается результатом.")
    GuideStep.LOCK -> utilityText("Tap Lock to close the vault. Hold it for Lock and hide. Both hide private content immediately. Locking also closes this tutorial; restart it from private Settings.", "Нажатие Lock закрывает хранилище; удержание — Lock and hide. Приватное содержимое скрывается сразу. Блокировка также закрывает обучение; повтор доступен в приватных настройках.")
    GuideStep.AUTO_LOCK -> utilityText("Open Settings and find Auto-lock. Choose how long an idle vault may remain open. This guide never changes that choice.", "Откройте Settings и найдите Auto-lock. Здесь задаётся время до блокировки. Проводник не меняет настройку за вас.")
    GuideStep.UNLOCK -> utilityText("In Settings, review Access. A password is portable; device unlock requires a supported, configured device. Recovery needs a previously saved phrase.", "В Settings изучите Access. Пароль переносим; разблокировка устройством требует его поддержки и настройки. Для восстановления нужна ранее сохранённая фраза.")
    GuideStep.BACKUP -> utilityText("Find Write a backup file in Settings. Only an explicit export creates a portable encrypted backup. This guide does not export or restore anything.", "Найдите Write a backup file в Settings. Переносимая зашифрованная копия создаётся только при явном экспорте. Проводник ничего не экспортирует и не восстанавливает.")
    GuideStep.DISCREET -> utilityText("Open Public applications in Settings. Choose an app and a transition code. In Chur, hold the moon to enter it. Test the entry and authenticate. Holding Version in About is the fallback.", "Откройте «Публичные приложения» в Settings. Выберите оболочку и код. В «Чуре» удерживайте луну для ввода. Проверьте переход и пройдите авторизацию. Запасной вход — удержание версии в «О приложении».")
    GuideStep.PET_GREET -> utilityText("Tap Chur to greet. There are no needs, scores, or penalties.", "Коснитесь Чура, чтобы погладить. Здесь нет потребностей, счёта и наказаний.")
    GuideStep.PET_MOVE -> utilityText("Drag Chur to a new place, or use the accessible Move action.", "Перенесите Чура в другое место или используйте доступное действие «Переместить».")
    GuideStep.PET_TREAT -> utilityText("Use Treat to offer a firefly. You never run out of treats.", "Нажмите «Угостить», чтобы предложить огонёк. Угощения не заканчиваются.")
    GuideStep.PET_TOY -> utilityText("Use Toy, then move the firefly. Chur follows it. Press again to put the toy away.", "Нажмите «Игрушка» и двигайте огонёк: Чур следует за ним. Повторное нажатие убирает игрушку.")
    GuideStep.PET_SLEEP -> utilityText("Tap the moon to let Chur sleep. Tap again to wake up. Each new visit starts with an awake companion.", "Нажмите луну, чтобы Чур уснул, и ещё раз, чтобы разбудить. При новом посещении питомец бодрствует.")
}


@Composable
private fun publicAppText(shell: PublicShell): String = when (shell) {
    PublicShell.NOTES -> utilityText("Create a note, search, and use More to organize or import. Notes and attachments are not vault-encrypted.", "Создавайте заметки, ищите их, используйте More для организации и импорта. Заметки и вложения не зашифрованы хранилищем.")
    PublicShell.CALCULATOR -> utilityText("Use the keypad to calculate. Scientific mode has more functions. History lets you reuse or delete results.", "Вводите вычисления на клавиатуре. Научный режим добавляет функции. В истории можно повторить или удалить результат.")
    PublicShell.CAMERA -> utilityText("Choose Photo or Video, then capture. Open the gallery to view, export, or delete. Photos and videos are not vault-encrypted.", "Выберите фото или видео и начните съёмку. В галерее можно просмотреть, экспортировать или удалить файлы. Фото и видео не зашифрованы хранилищем.")
    PublicShell.PET -> ""
}
