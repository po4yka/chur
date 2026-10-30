package dev.po4yka.chur.app.publicshell

import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import dev.po4yka.chur.app.PrivateTextInput

/** Transition-code entry for public shells. The draft lives only while the dialog is shown. */
@Composable
internal fun AccessCodeDialog(onSubmitCode: (String) -> Boolean, onClose: () -> Unit) = PrivateTextInput(enabled = true) {
    var code by remember { mutableStateOf("") }
    var codeError by remember { mutableStateOf(false) }
    fun submit() { val candidate = code; code = ""; if (onSubmitCode(candidate)) onClose() else codeError = true }
    val errorText = utilityText("Code not recognized.", "Код не распознан.")
    AlertDialog(onDismissRequest = onClose, title = { Text(utilityText("Access code", "Код доступа")) }, text = {
        OutlinedTextField(code, { code = it.filter { c -> c in '0'..'9' }.take(8); codeError = false },
            label = { Text(utilityText("8-digit code", "Код из 8 цифр")) }, singleLine = true, isError = codeError,
            supportingText = if (codeError) {
                { Text(errorText, Modifier.semantics { liveRegion = LiveRegionMode.Polite }) }
            } else null,
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword, imeAction = ImeAction.Done),
            keyboardActions = KeyboardActions(onDone = { if (code.length == 8) submit() }))
    }, confirmButton = { TextButton(enabled = code.length == 8, onClick = ::submit) { Text(utilityText("Continue", "Продолжить")) } },
        dismissButton = { TextButton(onClick = onClose) { Text(utilityText("Cancel", "Отмена")) } })
}
