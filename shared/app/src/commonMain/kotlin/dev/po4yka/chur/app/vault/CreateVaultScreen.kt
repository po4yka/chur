package dev.po4yka.chur.app.vault

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.CheckboxDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import dev.po4yka.chur.app.ActiveOperation
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.saveable.LocalSaveableStateRegistry
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import dev.po4yka.chur.app.onboarding.guideTarget
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.onFocusChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.isTraversalGroup
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.rememberTextMeasurer
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import dev.po4yka.chur.app.secretKeyboardOptions
import dev.po4yka.chur.app.theme.ChurSpacing
import dev.po4yka.chur.app.theme.LocalChurColors
import dev.po4yka.chur.app.theme.churOutlinedTextFieldColors

/**
 * Vault creation, `docs/security/PROVISIONING.md` §3.
 *
 * The order on screen is §3's order, because §3 is an order and not a list:
 * the explanation comes before the password, the password is checked against
 * the profile before anything is generated, and the recovery offer comes after
 * the slot is verified and before the vault is usable.
 *
 * §8 forbids stating a claim `DISCREET_MODE.md` bars, so the copy says what is
 * true and no more: no server copy exists and no support path can recover it.
 *
 * [onRestore] is null unless the storage root holds no vault. A restore
 * installs an identity, `../format/BACKUP_FORMAT_V1.md` §8, so it is offered
 * where creation is offered and nowhere else: `DECOY_VAULT.md` §8 asks the
 * product to keep a restore away from another identity's descriptors, and §10
 * forbids a surface that differs by whether a second identity exists. With no
 * identity present there is none to overwrite and none to reveal.
 *
 * Next on the keyboard moves from the password to its repeat. The repeat
 * field only closes the keyboard: the §4 offer below it is part of the
 * decision, so the vault is created from the button and never from a key.
 *
 * This form and the two below sit inside the safe area and scroll in the
 * space the keyboard leaves, `DESIGN.md` §25.5.
 */
@Composable
fun CreateVaultScreen(
    busy: Boolean,
    error: String?,
    onCreate: (password: String, offerRecovery: Boolean) -> Unit,
    onCancel: () -> Unit,
    onRestore: (() -> Unit)? = null,
    onHide: (() -> Unit)? = null,
) {
    var password by remember { mutableStateOf("") }
    var confirmation by remember { mutableStateOf("") }
    var usePin by remember { mutableStateOf(false) }
    var offerRecovery by remember { mutableStateOf(true) }
    var confirmationFocused by remember { mutableStateOf(false) }
    var confirmationChecked by remember { mutableStateOf(false) }
    val colors = LocalChurColors.current
    val matching = password.isNotEmpty() && password == confirmation &&
        (if (usePin) isValidVaultPin(password) else isAcceptableNewPassword(password))
    val confirmationMismatch = confirmationChecked && confirmation.isNotEmpty() && password != confirmation
    val confirmationHint = when {
        confirmationMismatch -> if (usePin) "PINs do not match." else "Passwords do not match."
        matching -> if (usePin) "PINs match. Ready to create vault." else "Passwords match. Ready to create vault."
        usePin -> "Enter the same 12–20 digit PIN in both fields to enable Create vault."
        else -> "Enter the same password of at least 12 characters in both fields to enable Create vault."
    }
    Surface(color = colors.canvas, modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState())
                .padding(ChurSpacing.gutter),
            verticalArrangement = Arrangement.spacedBy(ChurSpacing.three),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Column(
                modifier = Modifier.widthIn(max = 420.dp),
                verticalArrangement = Arrangement.spacedBy(ChurSpacing.three),
            ) {
                onHide?.let { hide ->
                    TextButton(onClick = hide) { Text("Lock and hide") }
                }
                // §3 step 1.
                Text("Create a vault", style = MaterialTheme.typography.headlineSmall)
                Text(
                    "A vault keeps photos, video, and audio on this device, encrypted. " +
                        "There is no server copy and no support path: if you lose the " +
                        "${if (usePin) "PIN" else "password"} and the recovery phrase, the contents are gone.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = colors.inkMuted,
                )
                // §3 step 2.
                TextButton(
                    onClick = {
                        usePin = !usePin
                        password = ""
                        confirmation = ""
                        confirmationChecked = false
                    },
                    enabled = !busy,
                ) {
                    Text(if (usePin) "Use a password instead" else "Use a PIN instead")
                }
                if (usePin) {
                    Text(
                        "Choose 12–20 digits. This vault PIN is separate from your device PIN.",
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.inkMuted,
                    )
                }
                OutlinedTextField(
                    colors = churOutlinedTextFieldColors(),
                    value = password,
                    onValueChange = {
                        if (!usePin || (it.length <= 20 && it.all { digit -> digit in '0'..'9' })) {
                            password = it
                        }
                    },
                    singleLine = true,
                    enabled = !busy,
                    label = { Text(if (usePin) "PIN" else "Password") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = secretKeyboardOptions(pin = usePin, imeAction = ImeAction.Next),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    colors = churOutlinedTextFieldColors(),
                    value = confirmation,
                    onValueChange = {
                        if (!usePin || (it.length <= 20 && it.all { digit -> digit in '0'..'9' })) {
                            confirmation = it
                            confirmationChecked = false
                        }
                    },
                    singleLine = true,
                    enabled = !busy,
                    label = { Text(if (usePin) "Repeat PIN" else "Repeat password") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = secretKeyboardOptions(pin = usePin),
                    isError = confirmationMismatch,
                    supportingText = { Text(confirmationHint) },
                    modifier = Modifier.fillMaxWidth().onFocusChanged { focus ->
                        if (confirmationFocused && !focus.isFocused) confirmationChecked = true
                        confirmationFocused = focus.isFocused
                    },
                )
                // §4: the offer, and the consequence of declining it.
                Column(verticalArrangement = Arrangement.spacedBy(ChurSpacing.one)) {
                    Row(
                        modifier = Modifier.fillMaxWidth().heightIn(min = 48.dp)
                            .toggleable(
                                value = offerRecovery,
                                enabled = !busy,
                                role = Role.Checkbox,
                                onValueChange = { offerRecovery = it },
                            ),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Checkbox(
                            checked = offerRecovery,
                            onCheckedChange = null,
                            enabled = !busy,
                            colors = CheckboxDefaults.colors(
                                checkedColor = colors.accent,
                                checkmarkColor = colors.onInk,
                            ),
                        )
                        Text("Create a recovery phrase", style = MaterialTheme.typography.bodyMedium)
                    }
                    Text(
                        text = if (offerRecovery) {
                            "You will see 24 words once. Write them down and keep them offline."
                        } else {
                            "Without a recovery phrase, a forgotten ${if (usePin) "PIN" else "password"} cannot be " +
                                "recovered. You can set one up later in Settings. Chur asks for your " +
                                "screen lock first."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = colors.inkMuted,
                    )
                }
                FormMessage(error)
                Button(
                    onClick = { onCreate(password, offerRecovery) },
                    enabled = !busy && matching,
                    modifier = Modifier.fillMaxWidth().guideTarget("create", !busy && matching),
                ) {
                    Text(if (busy) "Creating" else "Create vault")
                }
                if (onRestore != null) {
                    TextButton(onClick = onRestore, enabled = !busy) {
                        Text("Restore from a backup")
                    }
                }
                TextButton(onClick = onCancel, enabled = !busy) { Text("Not now") }
            }
        }
    }
}

/**
 * The recovery presentation of `RECOVERY.md` §2.3, in the steps of
 * `DESIGN.md` §17.1.
 *
 * - The words appear only after the user asks for them (§17.1 step 3), so
 *   neither a glance nor a screen reader meets them when the screen opens
 *   (§23.2).
 * - [PhraseGrid] shows them numbered under the version marker of
 *   `RECOVERY.md` §2.1. There is no selection container, so they cannot be
 *   copied (§17.2).
 * - The warning is the "not beside an unlocked device" of §2.3. Screenshots
 *   are blocked only where the platform can block them (§17.1 step 4), so the
 *   copy asks the user not to take one and does not say they cannot.
 * - The user confirms by typing three words at random positions again, which
 *   is the re-entry of §2.3 and `PASSWORD_PROFILE.md` §12. Each word is matched
 *   by its first four letters as in §2.2, by [recoveryWordMatches], and a
 *   mismatch names only the position. Continue is the only way on and stays off until all three
 *   match, because the phrase is shown once: `PROVISIONING.md` §4 commits the
 *   slot only after this confirmation.
 * - [onLock] and [onPanic] are the secure exit of §17.1 step 7. A lock
 *   discards the words and commits nothing, as the copy says.
 *
 * All state is `remember`ed and keyed to the phrase: `PASSWORD_PROFILE.md` §2
 * keeps a secret out of saved state, and a step or an answer given for one
 * phrase says nothing about the next.
 */
@Composable
fun RecoveryPhraseScreen(
    phrase: String,
    onAcknowledged: () -> Unit,
    onLock: () -> Unit,
    onPanic: () -> Unit,
) {
    val words = remember(phrase) { phrase.split(" ") }
    var step by remember(phrase) { mutableStateOf(PhraseStep.EXPLAIN) }
    val positions = remember(phrase) { words.indices.shuffled().take(CHECKED_WORDS).sorted() }
    val answers = remember(phrase) { mutableStateListOf(*Array(CHECKED_WORDS) { "" }) }
    val colors = LocalChurColors.current
    Surface(color = colors.canvas, modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState())
                .padding(ChurSpacing.gutter),
            verticalArrangement = Arrangement.spacedBy(ChurSpacing.three),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Column(
                modifier = Modifier.widthIn(max = 480.dp),
                verticalArrangement = Arrangement.spacedBy(ChurSpacing.three),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "Your recovery phrase",
                        style = MaterialTheme.typography.headlineSmall,
                        modifier = Modifier.weight(1f).guideTarget("recovery"),
                    )
                    LockControl(onLock = onLock, onPanic = onPanic)
                }
                Text(
                    "These 24 words open your vault without the password. You see them " +
                        "once, on this screen. Nothing is saved until you confirm them. If " +
                        "the app locks or you leave it before then, the words are discarded.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = colors.inkMuted,
                )
                when (step) {
                    PhraseStep.EXPLAIN, PhraseStep.WORDS -> {
                        Text(
                            "Write the words on paper, in order. Do not keep them on or beside " +
                                "this phone while it is unlocked. Do not take a screenshot or copy them.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        if (step == PhraseStep.EXPLAIN) {
                            Button(onClick = { step = PhraseStep.WORDS }, modifier = Modifier.fillMaxWidth()) {
                                Text("Show words")
                            }
                        } else {
                            PhraseGrid(words)
                            Button(onClick = { step = PhraseStep.CHECK }, modifier = Modifier.fillMaxWidth()) {
                                Text("I have written them down")
                            }
                        }
                    }
                    PhraseStep.CHECK -> {
                        Text(
                            "To check what you wrote, enter these words from your paper.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        positions.forEachIndexed { index, position ->
                            val expected = words[position]
                            val answer = answers[index]
                            // Judged once it is as long as the part §2.2 compares,
                            // so a word being typed is not called wrong.
                            val wrong = answer.trim().length >= expected.take(MATCHED_LETTERS).length &&
                                !recoveryWordMatches(expected, answer)
                            OutlinedTextField(
                                colors = churOutlinedTextFieldColors(),
                                value = answer,
                                onValueChange = { answers[index] = it },
                                singleLine = true,
                                label = { Text("Word ${position + 1}") },
                                isError = wrong,
                                supportingText = if (wrong) {
                                    { Text("Word ${position + 1} does not match.") }
                                } else {
                                    null
                                },
                                keyboardOptions = secretKeyboardOptions(
                                    imeAction = if (index < positions.lastIndex) ImeAction.Next else ImeAction.Done,
                                ),
                                modifier = Modifier.fillMaxWidth(),
                            )
                        }
                        Button(
                            onClick = onAcknowledged,
                            enabled = positions.indices.all { recoveryWordMatches(words[positions[it]], answers[it]) },
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text("Continue")
                        }
                        TextButton(
                            onClick = { step = PhraseStep.WORDS },
                            modifier = Modifier.padding(bottom = 8.dp),
                        ) {
                            Text("Show the words again")
                        }
                    }
                }
            }
        }
    }
}

private enum class PhraseStep { EXPLAIN, WORDS, CHECK }

/** How many words the user types again, `RECOVERY.md` §2.3. */
private const val CHECKED_WORDS = 3

/** The letters a word is matched by, `RECOVERY.md` §2.2. */
private const val MATCHED_LETTERS = 4

/**
 * Whether [typed] is the word [expected] by the rule `RECOVERY.md` §2.2 uses
 * to tell the words apart: trimmed and lowercased, then compared by its first
 * four letters, which are unique across the BIP-39 English list. A correctly
 * remembered word survives a mistyped ending, as it does when the phrase is
 * entered to recover.
 *
 * The NFKD step of §2.2 is not repeated, so a compatibility form that recovery
 * accepts, such as a word in full-width letters, is refused here. That
 * difference is accepted: the check asks whether the paper holds the right
 * word, and the words on the paper were copied from the ASCII list on screen.
 * A refused word names only its position, and the user types it again.
 */
internal fun recoveryWordMatches(expected: String, typed: String): Boolean =
    typed.trim().lowercase().take(MATCHED_LETTERS) == expected.take(MATCHED_LETTERS)

/**
 * The words under the version marker, `RECOVERY.md` §2.1: numbered and read
 * down two columns, 1–12 and then 13–24.
 *
 * The numbers are monospaced and padded to two digits, so the words line up
 * at any font size. `DESIGN.md` §17.2 never truncates, and a cell that wraps
 * breaks the reading order, so where two columns cannot hold the widest cell
 * on one line (a narrow screen at a large font scale) one column holds all 24.
 * Each column is a traversal group, so a screen reader also reads 1–12 before
 * 13–24 and not across the rows.
 */
@Composable
private fun PhraseGrid(words: List<String>) {
    val colors = LocalChurColors.current
    val style = MaterialTheme.typography.bodyLarge
    val cells = remember(words, colors.inkMuted) {
        words.mapIndexed { index, word ->
            buildAnnotatedString {
                withStyle(SpanStyle(fontFamily = FontFamily.Monospace, color = colors.inkMuted)) {
                    append("${index + 1}".padStart(2) + ".")
                }
                append(" $word")
            }
        }
    }
    val measurer = rememberTextMeasurer()
    val widest = remember(cells, style, measurer) {
        cells.maxOf { measurer.measure(it, style, softWrap = false, maxLines = 1).size.width }
    }
    val density = LocalDensity.current
    Surface(
        color = colors.surfaceSunken,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier.fillMaxWidth(),
    ) {
        BoxWithConstraints(modifier = Modifier.padding(ChurSpacing.gutter)) {
            val twoColumns = with(density) { widest.toDp() } * 2 + ChurSpacing.gutter <= maxWidth
            Column(verticalArrangement = Arrangement.spacedBy(ChurSpacing.two)) {
                Text("chur-recovery-v1", style = style.copy(fontFamily = FontFamily.Monospace))
                Row(horizontalArrangement = Arrangement.spacedBy(ChurSpacing.gutter)) {
                    cells.chunked(if (twoColumns) cells.size / 2 else cells.size).forEach { column ->
                        Column(
                            modifier = Modifier.weight(1f).semantics { isTraversalGroup = true },
                            verticalArrangement = Arrangement.spacedBy(ChurSpacing.one),
                        ) {
                            column.forEach { Text(it, style = style) }
                        }
                    }
                }
            }
        }
    }
}

/**
 * The restore route, `docs/format/BACKUP_FORMAT_V1.md` §8.
 *
 * The password comes before the file because §8 does: step 2 obtains the
 * credential from the package's own portable descriptor and step 3
 * authenticates the manifest with it, so a package the credential does not open
 * is refused before any record of it is read.
 *
 * The copy names the package and never this device's vaults.
 * `../security/DECOY_VAULT.md` §10 forbids a surface that differs by whether a
 * second identity exists, and the hosts offer this screen only while the
 * storage root holds no identity at all.
 *
 * [cancelled] comes from the restore's own result rather than from [error]'s
 * text, because `docs/ERROR_MODEL.md` "Layer mapping" forbids branching on
 * copy. A cancellation reads as muted text, not as a failure (principle 4).
 */
@Composable
fun RestoreBackupScreen(
    busy: Boolean,
    preparing: Boolean,
    error: String?,
    cancelled: Boolean,
    operation: ActiveOperation? = null,
    onChoose: (password: String) -> Unit,
    onBack: () -> Unit,
    onCancel: () -> Unit = {},
) {
    CompositionLocalProvider(LocalSaveableStateRegistry provides null) {
        RestoreArchiveContent(busy, preparing, error, cancelled, operation, onChoose, onBack, onCancel)
    }
}

@Composable
private fun RestoreArchiveContent(
    busy: Boolean,
    preparing: Boolean,
    error: String?,
    cancelled: Boolean,
    operation: ActiveOperation?,
    onChoose: (String) -> Unit,
    onBack: () -> Unit,
    onCancel: () -> Unit,
) {
    var password by remember { mutableStateOf("") }
    DisposableEffect(Unit) { onDispose { password = "" } }
    val colors = LocalChurColors.current
    Surface(color = colors.canvas, modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier.fillMaxSize().safeDrawingPadding().verticalScroll(rememberScrollState())
                .padding(ChurSpacing.gutter),
            verticalArrangement = Arrangement.spacedBy(ChurSpacing.three),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Column(
                modifier = Modifier.widthIn(max = 420.dp),
                verticalArrangement = Arrangement.spacedBy(ChurSpacing.three),
            ) {
                Text("Restore a backup or archive", style = MaterialTheme.typography.headlineSmall)
                Text(
                    "Enter the password of the archive, or the password or recovery phrase of the backup. " +
                        "Then choose the file. Restore creates a separate vault and does not replace existing data. " +
                        "If this device cannot add another vault, use an empty installation. " +
                        "To add items to your current vault instead, use Import encrypted archive.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = colors.inkMuted,
                )
                OutlinedTextField(
                    colors = churOutlinedTextFieldColors(),
                    value = password,
                    onValueChange = { password = it },
                    singleLine = true,
                    enabled = !busy,
                    label = { Text("Backup password or recovery phrase") },
                    visualTransformation = PasswordVisualTransformation(),
                    keyboardOptions = secretKeyboardOptions(),
                    modifier = Modifier.fillMaxWidth(),
                )
                FormMessage(error, color = if (cancelled) colors.inkMuted else colors.error)
                Button(
                    onClick = { val entered = password; password = ""; onChoose(entered) },
                    enabled = !busy && password.isNotEmpty(),
                    modifier = Modifier.fillMaxWidth().guideTarget("restore", !busy && password.isNotEmpty()),
                ) {
                    Text(if (preparing) "Opening backup file" else if (busy) "Restoring" else "Choose backup file")
                }
                if (operation != null) {
                    OperationProgressCard(operation, onCancel)
                } else if (preparing) {
                    TextButton(onClick = onCancel) { Text("Cancel") }
                }
                TextButton(onClick = onBack, enabled = !busy) { Text("Back") }
            }
        }
    }
}
