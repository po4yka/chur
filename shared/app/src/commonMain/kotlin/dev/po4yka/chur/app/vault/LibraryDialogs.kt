package dev.po4yka.chur.app.vault

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import dev.po4yka.chur.app.privateKeyboardOptions
import dev.po4yka.chur.app.theme.DestructiveButton
import dev.po4yka.chur.app.theme.churOutlinedTextFieldColors
import dev.po4yka.chur.ffi.AlbumSummary
import dev.po4yka.chur.ffi.TagSummary

@Composable
fun NewAlbumDialog(onCreate: (String) -> Unit, onDismiss: () -> Unit) {
    var name by remember { mutableStateOf("") }
    PrivateAlertDialog(
        presentation = PrivateModalPresentation.Sheet,
        onDismissRequest = onDismiss,
        title = { Text("New album") },
        text = {
            OutlinedTextField(
                colors = churOutlinedTextFieldColors(),
                value = name,
                onValueChange = { name = it },
                singleLine = true,
                keyboardOptions = privateKeyboardOptions(),
                label = { Text("Album name") },
            )
        },
        confirmButton = {
            TextButton(onClick = privateModalAction { onCreate(name.trim()) }, enabled = name.isNotBlank()) {
                Text("Create")
            }
        },
        dismissButton = { TextButton(onClick = privateModalAction(onDismiss)) { Text("Cancel") } },
    )
}

@Composable
fun MoveAlbumDialog(
    albums: List<AlbumSummary>,
    album: AlbumSummary,
    onChoose: (AlbumSummary?) -> Unit,
    onDismiss: () -> Unit,
) {
    var filter by remember(album.id) { mutableStateOf("") }
    val destinations = remember(albums, album.id) { albumDestinations(albums, album.id) }
    val matches = remember(destinations, filter) {
        destinations.filter { it.path.contains(filter.trim(), ignoreCase = true) }
    }
    PrivateAlertDialog(
        presentation = PrivateModalPresentation.Sheet,
        onDismissRequest = onDismiss,
        title = { Text("Move album") },
        text = {
            Column(modifier = Modifier.heightIn(max = 360.dp)) {
                OutlinedTextField(
                    value = filter, onValueChange = { filter = it }, singleLine = true,
                    label = { Text("Find destination") }, keyboardOptions = privateKeyboardOptions(),
                    colors = churOutlinedTextFieldColors(), modifier = Modifier.fillMaxWidth()
                        .testTag("album-move-filter"),
                )
                LazyColumn(modifier = Modifier.weight(1f, fill = false).fillMaxWidth()
                    .testTag("album-move-destinations")) {
                    item {
                        TextButton(onClick = privateModalAction { onChoose(null) }, modifier = Modifier.fillMaxWidth()
                            .semantics { contentDescription = "Move album to top level" }) {
                            Text("Top level", modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Start)
                        }
                    }
                    items(matches, key = { it.album.id }) { destination ->
                        TextButton(onClick = privateModalAction { onChoose(destination.album) },
                            modifier = Modifier.fillMaxWidth().testTag("album-move-${destination.album.id}")
                                .semantics { contentDescription = "Move album to ${destination.path}" }) {
                            Text(destination.path, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Start)
                        }
                    }
                    if (matches.isEmpty()) item { Text("No matching albums") }
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = privateModalAction(onDismiss)) { Text("Cancel") } },
    )
}

@Composable
fun AlbumPickerDialog(
    albums: List<AlbumSummary>,
    currentAlbum: AlbumSummary?,
    move: Boolean,
    onChoose: (AlbumSummary) -> Unit,
    onCreate: (String, AlbumSummary?) -> Unit,
    onDismiss: () -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf("") }
    var parent by remember(currentAlbum?.id) { mutableStateOf(currentAlbum) }
    var parentExpanded by remember { mutableStateOf(false) }
    val destinations = remember(albums) { albumDestinations(albums) }
    val verb = if (move) "Move" else "Add"
    PrivateAlertDialog(
        presentation = PrivateModalPresentation.Sheet,
        onDismissRequest = onDismiss,
        title = { Text("$verb to album") },
        text = {
            Column(modifier = Modifier.heightIn(max = 360.dp).verticalScroll(rememberScrollState())) {
                OutlinedTextField(
                    value = filter, onValueChange = { filter = it }, singleLine = true,
                    label = { Text("Find destination") }, keyboardOptions = privateKeyboardOptions(),
                    colors = churOutlinedTextFieldColors(), modifier = Modifier.fillMaxWidth(),
                )
                destinations.filter { it.album.id != currentAlbum?.id &&
                    it.path.contains(filter.trim(), ignoreCase = true) }.forEach { destination ->
                    TextButton(
                        onClick = privateModalAction { onChoose(destination.album) },
                        modifier = Modifier.fillMaxWidth().semantics {
                            contentDescription = "$verb to ${destination.path}"
                        },
                    ) { Text(destination.path, modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Start) }
                }
                Text("Create a new destination")
                OutlinedTextField(
                    colors = churOutlinedTextFieldColors(),
                    value = name,
                    onValueChange = { name = it },
                    singleLine = true,
                    keyboardOptions = privateKeyboardOptions(),
                    label = { Text("New album name") },
                )
                Box {
                    TextButton(onClick = { parentExpanded = true }) {
                        Text("Inside: ${destinations.firstOrNull { it.album.id == parent?.id }?.path ?: "Top level"}")
                    }
                    PrivateDropdownMenu(expanded = parentExpanded, onDismissRequest = { parentExpanded = false }) {
                        DropdownMenuItem(text = { Text("Top level") }, onClick = {
                            parent = null; parentExpanded = false
                        })
                        destinations.forEach { destination ->
                            DropdownMenuItem(
                                text = { Text(destination.path) },
                                onClick = { parent = destination.album; parentExpanded = false },
                            )
                        }
                    }
                }
                TextButton(onClick = privateModalAction { onCreate(name.trim(), parent) }, enabled = name.isNotBlank()) {
                    Text("Create and ${verb.lowercase()}")
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = privateModalAction(onDismiss)) { Text("Cancel") } },
    )
}

@Composable
fun TagPickerDialog(
    tags: List<TagSummary>,
    onAdd: (TagSummary) -> Unit,
    onRemove: (TagSummary) -> Unit,
    onCreate: (String) -> Unit,
    onDismiss: () -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf("") }
    val existing = tags.firstOrNull { it.name.equals(name.trim(), ignoreCase = true) }
    PrivateAlertDialog(
        presentation = PrivateModalPresentation.Sheet,
        onDismissRequest = onDismiss,
        title = { Text("Tags") },
        text = {
            Column(modifier = Modifier.heightIn(max = 360.dp)) {
                OutlinedTextField(colors = churOutlinedTextFieldColors(), value = filter,
                    onValueChange = { filter = it }, singleLine = true,
                    keyboardOptions = privateKeyboardOptions(), label = { Text("Find tag") })
                LazyColumn(modifier = Modifier.heightIn(max = 220.dp)) {
                    items(tags.filter { it.name.contains(filter, ignoreCase = true) }, key = { it.id }) { tag ->
                    Column {
                        TextButton(onClick = privateModalAction { onAdd(tag) }) { Text("Add ${tag.name}") }
                        TextButton(onClick = privateModalAction { onRemove(tag) }) { Text("Remove") }
                    }
                    }
                }
                OutlinedTextField(
                    colors = churOutlinedTextFieldColors(),
                    value = name,
                    onValueChange = { name = it },
                    singleLine = true,
                    keyboardOptions = privateKeyboardOptions(),
                    label = { Text("New tag name") },
                )
                TextButton(
                    onClick = privateModalAction { if (existing == null) onCreate(name.trim()) else onAdd(existing) },
                    enabled = name.isNotBlank(),
                ) {
                    Text(if (existing == null) "Create and add" else "Add existing tag")
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = privateModalAction(onDismiss)) { Text("Cancel") } },
    )
}

/** Browses tag scopes and manages their private names and memberships. */
@Composable
fun TagBrowserDialog(
    tags: List<TagSummary>,
    onOpen: (TagSummary) -> Unit,
    onCreate: (String) -> Unit,
    onRename: (TagSummary, String) -> Unit,
    onDelete: (TagSummary) -> Unit,
    onDismiss: () -> Unit,
) {
    var filter by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var editing by remember { mutableStateOf<TagSummary?>(null) }
    var deleting by remember { mutableStateOf<TagSummary?>(null) }
    PrivateAlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Tags") },
        text = {
            Column(modifier = Modifier.heightIn(max = 420.dp)) {
                OutlinedTextField(colors = churOutlinedTextFieldColors(), value = filter,
                    onValueChange = { filter = it }, singleLine = true,
                    keyboardOptions = privateKeyboardOptions(), label = { Text("Find tag") })
                LazyColumn(modifier = Modifier.heightIn(max = 270.dp)) {
                    items(tags.filter { it.name.contains(filter, ignoreCase = true) }, key = { it.id }) { tag ->
                        Column {
                            TextButton(onClick = { onOpen(tag) }) { Text(tag.name) }
                            TextButton(onClick = { editing = tag; name = tag.name }) { Text("Rename ${tag.name}") }
                            TextButton(onClick = { deleting = tag }) { Text("Delete ${tag.name}") }
                        }
                    }
                }
                OutlinedTextField(colors = churOutlinedTextFieldColors(), value = name,
                    onValueChange = { name = it }, singleLine = true,
                    keyboardOptions = privateKeyboardOptions(),
                    label = { Text(if (editing == null) "New tag" else "Rename ${editing?.name}") })
                TextButton(onClick = {
                    val value = name.trim()
                    val tag = editing
                    if (tag == null) onCreate(value) else onRename(tag, value)
                    editing = null
                    name = ""
                }, enabled = name.isNotBlank()) {
                    Text(if (editing == null) "Create tag" else "Save name")
                }
            }
        },
        confirmButton = {},
        dismissButton = { TextButton(onClick = onDismiss) { Text("Close") } },
    )
    deleting?.let { tag ->
        PrivateAlertDialog(onDismissRequest = { deleting = null }, title = { Text("Delete ${tag.name}?") },
            text = { Text("This removes the tag from its media. The media stays in the vault.") },
            confirmButton = { DestructiveButton(onClick = {
                deleting = null
                onDelete(tag)
            }) { Text("Delete tag") } },
            dismissButton = { TextButton(onClick = { deleting = null }) { Text("Cancel") } })
    }
}

/**
 * Confirms a move to Trash or a permanent deletion, in the words of
 * `DESIGN.md` §27.
 *
 * Only the permanent one gets the destructive button of §26: a move to Trash
 * can be taken back, from Trash or from the snackbar's undo.
 */
@Composable
fun DeleteSelectionDialog(count: Int, onDelete: () -> Unit, onDismiss: () -> Unit,
    permanent: Boolean = false, emptyTrash: Boolean = false) {
    PrivateAlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (permanent) "Delete permanently?" else "Move to Trash?") },
        text = { Text(when {
            emptyTrash -> "This removes Chur's local keys and encrypted objects for everything in Trash. " +
                "Copies exported elsewhere are not affected."
            permanent && count == 1 -> "This removes Chur's local key and encrypted object. " +
                "Copies exported elsewhere are not affected."
            permanent -> "This removes Chur's local keys and encrypted objects for these $count items. " +
                "Copies exported elsewhere are not affected."
            count == 1 -> "Chur keeps this item for at least 30 days so you can restore it."
            else -> "Chur keeps these $count items for at least 30 days so you can restore them."
        }) },
        confirmButton = {
            if (permanent) {
                DestructiveButton(onClick = onDelete) { Text(if (emptyTrash) "Empty trash" else "Delete permanently") }
            } else {
                TextButton(onClick = onDelete) { Text("Move to Trash") }
            }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
