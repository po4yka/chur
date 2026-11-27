package dev.po4yka.chur.app.vault

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import dev.po4yka.chur.app.rememberSensitiveCopy
import androidx.compose.material3.TextButton
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import dev.po4yka.chur.app.privateKeyboardOptions
import dev.po4yka.chur.app.theme.ChurSpacing
import dev.po4yka.chur.app.theme.churOutlinedTextFieldColors

/** Public pairing codes stay in memory on the protected vault screen. */
data class DevicePairingUiState(
    val devices: List<dev.po4yka.chur.ffi.PairedDevice>? = null,
    val requestCode: String? = null,
    val requestFingerprint: String? = null,
    val inspectedRequestCode: String? = null,
    val inspectedFingerprint: String? = null,
    val approvalReady: Boolean = false,
    val busy: Boolean = false,
)

/** Explicit approval connects a restored vault using signed peer approval. */
@Composable
internal fun DevicePairingCard(
    state: DevicePairingUiState,
    canApprove: Boolean,
    busy: Boolean,
    onPrepare: () -> Unit,
    onInspect: (String) -> Unit,
    onApprove: (String, String) -> Unit,
    onSaveApproval: () -> Unit,
    onOpenApproval: () -> Unit,
    onLoadDevices: () -> Unit,
    onRevokeDevice: (dev.po4yka.chur.ffi.PairedDevice) -> Unit,
    onNavigationBusyChange: (Boolean) -> Unit = {},
) {
    var revoke by remember { mutableStateOf<dev.po4yka.chur.ffi.PairedDevice?>(null) }
    revoke?.let { peer ->
        PrivateAlertDialog(
            onDismissRequest = { revoke = null },
            title = { Text("Revoke this device?") },
            text = { Text("Device fingerprint: ${peer.fingerprint}\n\nThis device loses new object-key access after peers receive the revocation. Copies it already received cannot be recalled.") },
            confirmButton = {
                TextButton(onClick = { revoke = null; onRevokeDevice(peer) }, enabled = !busy) { Text("Revoke device") }
            },
            dismissButton = { TextButton(onClick = { revoke = null }) { Text("Cancel") } },
        )
    }
    var request by remember { mutableStateOf("") }
    val copy = rememberSensitiveCopy()
    var confirmed by remember(request) { mutableStateOf(false) }
    NavigationBusyEffect(request.isNotEmpty() || revoke != null, onNavigationBusyChange)
    val inspectedFingerprint = state.inspectedFingerprint.takeIf {
        request.isNotBlank() && state.inspectedRequestCode == request
    }
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(ChurSpacing.three),
            verticalArrangement = Arrangement.spacedBy(ChurSpacing.two),
        ) {
            Text("Connect another device", style = MaterialTheme.typography.titleMedium)
            Text(
                "Restore an encrypted backup on the new device first. Keep both apps open on a network where they can reach each other. " +
                    "Compare the new device fingerprint on both devices before you approve access to the whole vault.",
                style = MaterialTheme.typography.bodySmall,
            )
            if (!canApprove) {
                Text("On the new device")
                Button(onClick = onPrepare, enabled = !busy) { Text("Create pairing request") }
                state.requestFingerprint?.let { Text("New device fingerprint: $it") }
                state.requestCode?.let { code ->
                    Text("Send this request to your connected device:")
                    Text(code, style = MaterialTheme.typography.bodySmall)
                    TextButton(onClick = { copy("Chur pairing request", code) }) { Text("Copy request") }
                }
                Text("Open the encrypted approval file from your connected device then connect directly to finish pairing.")
                Button(onClick = onOpenApproval, enabled = !busy) {
                    Text("Open approval file")
                }
            } else {
                Text("Paired devices", style = MaterialTheme.typography.titleSmall)
                Button(onClick = onLoadDevices, enabled = !busy) { Text("Refresh devices") }
                state.devices?.forEach { peer ->
                    Text(peer.fingerprint, style = MaterialTheme.typography.bodySmall)
                    Text(if (peer.current) "This device" else if (peer.active) "Access active" else "Access revoked locally")
                    if (!peer.current && peer.active) {
                        Button(onClick = { revoke = peer }, enabled = !busy) {
                            Text("Revoke access")
                        }
                    }
                }
                Text("On the connected device")
                OutlinedTextField(
                    colors = churOutlinedTextFieldColors(),
                    value = request,
                    onValueChange = { request = it.take(PAIRING_CODE_MAX_CHARS) },
                    label = { Text("New device pairing request") },
                    keyboardOptions = privateKeyboardOptions(),
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 2,
                    maxLines = 4,
                )
                Button(onClick = { onInspect(request) }, enabled = request.isNotBlank() && !busy) {
                    Text("Check new device")
                }
                inspectedFingerprint?.let { fingerprint ->
                    Text("New device fingerprint: $fingerprint")
                    Row(modifier = Modifier.fillMaxWidth()) {
                        Checkbox(checked = confirmed, onCheckedChange = { confirmed = it })
                        Text(
                            "I compared this fingerprint with the new device and approve access to the whole vault.",
                            modifier = Modifier.padding(top = ChurSpacing.two),
                        )
                    }
                    Button(onClick = { onApprove(request, fingerprint) }, enabled = confirmed && !busy) {
                        Text("Approve device")
                    }
                }
                if (state.approvalReady && inspectedFingerprint != null) {
                    Text("Save the encrypted approval file and send it to the new device.")
                    Button(onClick = onSaveApproval, enabled = !busy) { Text("Save approval file") }
                }
            }
        }
    }
}

/** Bounds pasted public codes before native canonical decoding. */
internal const val PAIRING_CODE_MAX_CHARS = 1_024
