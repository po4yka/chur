package dev.po4yka.chur.app.publicshell

import androidx.compose.foundation.*
import androidx.compose.foundation.gestures.rememberTransformableState
import androidx.compose.foundation.gestures.transformable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.grid.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.ImageBitmap
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.contentDescription
import dev.po4yka.chur.app.theme.SettingsGlyph
import dev.po4yka.chur.app.theme.AlbumsGlyph
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

data class PublicCameraLens(val id: String, val label: String)

data class PublicCameraPhoto(val id: String, val label: String, val video: Boolean = false)
const val PUBLIC_CAMERA_DISCLOSURE = "Photos and videos are not encrypted by this app and are copied by the system backup. They are saved in this app. Export to the system library only when you choose."

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CameraScreen(
    preview: ImageBitmap?, hasCapture: Boolean, busy: Boolean, message: String?,
    showFirstWriteDisclosure: Boolean, onAcknowledgeDisclosure: () -> Unit,
    onCapture: () -> Unit, onSave: () -> Unit = {}, onDiscard: () -> Unit = {}, onOpenSettings: () -> Unit,
    modifier: Modifier = Modifier,
    photos: List<PublicCameraPhoto> = emptyList(), selectedPhotoId: String? = null,
    onOpenPhoto: (String) -> Unit = {}, onClosePhoto: () -> Unit = {}, onDeletePhoto: (String) -> Unit = {},
    livePreview: (@Composable () -> Unit)? = null,
    videoContent: (@Composable () -> Unit)? = null,
    thumbnail: suspend (String) -> ImageBitmap? = { null },
    onExport: (List<String>) -> Unit = {},
    onSubmitCode: (String) -> Boolean = { false },
    captureReady: Boolean = true, videoMode: Boolean = false, recording: Boolean = false, elapsedSeconds: Long = 0,
    onVideoMode: (Boolean) -> Unit = {}, onSwitchCamera: () -> Unit = {},
    zoom: Float = 1f, zoomRange: ClosedFloatingPointRange<Float> = 1f..1f, onZoom: (Float) -> Unit = {},
    exposure: Float = 0f, exposureRange: ClosedFloatingPointRange<Float> = 0f..0f, onExposure: (Float) -> Unit = {},
    hasFlash: Boolean = false, flash: Boolean = false, onFlash: () -> Unit = {},
    sound: Boolean = true, onSound: () -> Unit = {},
    onGalleryChange: (Boolean) -> Unit = {},
    lenses: List<PublicCameraLens> = emptyList(), selectedLens: String = "", onLens: (String) -> Unit = {},
    systemBack: @Composable (onBack: () -> Unit) -> Unit = {},
) {
    var gallery by remember { mutableStateOf(false) }
    var selected by remember { mutableStateOf(setOf<String>()) }
    var deleting by remember { mutableStateOf<List<String>>(emptyList()) }
    var enteringCode by remember { mutableStateOf(false) }
    var disclosure by remember { mutableStateOf(false) }
    var grid by remember { mutableStateOf(false) }
    var controls by remember { mutableStateOf(false) }
    var timer by remember { mutableIntStateOf(0) }
    var countdown by remember { mutableIntStateOf(0) }
    val scope = rememberCoroutineScope()
    fun showGallery(value: Boolean) { gallery = value; selected = emptySet(); onGalleryChange(value) }
    fun capture() {
        if (recording) { onCapture(); return }
        if (showFirstWriteDisclosure) { disclosure = true; return }
        scope.launch { for (second in timer downTo 1) { countdown = second; delay(1000) }; countdown = 0; onCapture() }
    }
    if (gallery) systemBack { if (selectedPhotoId != null) onClosePhoto() else showGallery(false) }
    if (disclosure) AlertDialog(onDismissRequest = { disclosure = false },
        title = { Text(utilityText("Data storage", "Хранение данных")) }, text = { Text(utilityText(PUBLIC_CAMERA_DISCLOSURE, "Фото и видео не зашифрованы приложением и входят в системную резервную копию. Они сохраняются внутри приложения. Экспорт в системную галерею выполняется только по вашему действию.")) },
        confirmButton = { TextButton(onClick = { onAcknowledgeDisclosure(); disclosure = false }) { Text(utilityText("Got it", "Понятно")) } },
        dismissButton = { TextButton(onClick = { disclosure = false }) { Text(utilityText("Cancel", "Отмена")) } })
    if (enteringCode) AccessCodeDialog(onSubmitCode) { enteringCode = false }
    if (deleting.isNotEmpty()) AlertDialog(onDismissRequest = { deleting = emptyList() }, title = { Text(utilityText("Delete selected files?", "Удалить выбранные файлы?")) },
        text = { Text(utilityText("This cannot be undone. Export files you want to keep first.", "Это действие нельзя отменить. Сначала экспортируйте файлы, которые хотите сохранить.")) },
        confirmButton = { TextButton(enabled = !busy, onClick = { deleting.forEach(onDeletePhoto); deleting = emptyList(); selected = emptySet() }) { Text(utilityText("Delete", "Удалить")) } },
        dismissButton = { TextButton(onClick = { deleting = emptyList() }) { Text(utilityText("Cancel", "Отмена")) } })
    if (controls) ModalBottomSheet(onDismissRequest = { controls = false }) {
        Column(Modifier.fillMaxWidth().heightIn(max = 420.dp).verticalScroll(rememberScrollState()).padding(16.dp)) {
                    if (lenses.size > 1) Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.Center) {
                        lenses.forEach { lens -> FilterChip(selectedLens == lens.id, onClick = { onLens(lens.id) }, enabled = !busy && !recording && countdown == 0, label = { Text(lens.label) }) }
                    }

                        if (zoomRange.endInclusive > zoomRange.start) { Text(utilityText("Zoom", "Масштаб") + " ${zoom}×"); Slider(zoom.coerceIn(zoomRange), onZoom, valueRange = zoomRange) }
                        if (exposureRange.endInclusive > exposureRange.start) { Text(utilityText("Exposure", "Экспозиция")); Slider(exposure.coerceIn(exposureRange), onExposure, valueRange = exposureRange, enabled = !recording) }
                        Row(Modifier.horizontalScroll(rememberScrollState())) {
                            if (hasFlash) FilterChip(flash, onFlash, label = { Text(utilityText("Flash", "Вспышка")) }, enabled = !recording)
                            FilterChip(grid, { grid = !grid }, label = { Text(utilityText("Grid", "Сетка")) })
                            TextButton(onClick = { timer = when (timer) { 0 -> 3; 3 -> 10; else -> 0 } }, enabled = !recording) { Text(utilityText("Timer", "Таймер") + " $timer") }
                            if (videoMode) FilterChip(sound, onSound, label = { Text(utilityText("Sound", "Звук")) }, enabled = !recording)
                        }

        }
    }
    val selectedPhoto = photos.firstOrNull { it.id == selectedPhotoId }
    Scaffold(modifier, containerColor = if (gallery) MaterialTheme.colorScheme.background else Color.Black,
        topBar = { TopAppBar(title = { Text(if (gallery) utilityText("Gallery", "Галерея") else utilityText("Camera", "Камера")) },
            navigationIcon = { if (gallery) TextButton(onClick = { onClosePhoto(); showGallery(false) }) { Text(utilityText("Camera", "Камера")) } },
            actions = { IconButton(enabled = !recording && countdown == 0, onClick = onOpenSettings) { Icon(SettingsGlyph, utilityText("Settings", "Настройки")) } }) }) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            if (gallery) message?.let { Text(it, maxLines = 2, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis, modifier = Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface).padding(12.dp), color = MaterialTheme.colorScheme.onSurface) }
            if (gallery) {
                if (selectedPhoto != null) {
                    Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())) {
                        TextButton(onClick = onClosePhoto) { Text(utilityText("All photos", "Все снимки")) }
                        TextButton(enabled = !busy, onClick = { onExport(listOf(selectedPhoto.id)) }) { Text(utilityText("Export", "Экспорт")) }
                        TextButton(enabled = !busy, onClick = { deleting = listOf(selectedPhoto.id) }) { Text(utilityText("Delete", "Удалить")) }
                    }
                    if (selectedPhoto.video && videoContent != null) Box(Modifier.weight(1f)) { videoContent() }
                    else if (preview != null) {
                        var scale by remember(selectedPhoto.id) { mutableFloatStateOf(1f) }
                        var offset by remember(selectedPhoto.id) { mutableStateOf(Offset.Zero) }
                        val transform = rememberTransformableState { factor, pan, _ -> scale = (scale * factor).coerceIn(1f, 8f); offset = if (scale == 1f) Offset.Zero else offset + pan }
                        Box(Modifier.weight(1f).fillMaxWidth().background(Color.Black).transformable(transform), contentAlignment = Alignment.Center) {
                            Image(preview, selectedPhoto.label, Modifier.fillMaxSize().graphicsLayer { scaleX = scale; scaleY = scale; translationX = offset.x; translationY = offset.y }, contentScale = ContentScale.Fit)
                        }
                        Row {
                            TextButton(onClick = { scale = (scale + 1).coerceAtMost(8f) }) { Text(utilityText("Zoom in", "Увеличить")) }
                            TextButton(onClick = { scale = 1f; offset = Offset.Zero }) { Text(utilityText("Reset zoom", "Сбросить масштаб")) }
                        }
                    }
                } else {
                    if (selected.isNotEmpty()) Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState())) {
                        TextButton(onClick = { selected = photos.map { it.id }.toSet() }) { Text(utilityText("Select all", "Выбрать все")) }
                        TextButton(enabled = !busy, onClick = { onExport(selected.toList()) }) { Text(utilityText("Export", "Экспорт")) }
                        TextButton(enabled = !busy, onClick = { deleting = selected.toList() }) { Text(utilityText("Delete", "Удалить")) }
                        TextButton(onClick = { selected = emptySet() }) { Text(utilityText("Done", "Готово")) }
                    }
                    if (photos.isEmpty()) Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) { Text(utilityText("No photos or videos yet", "Пока нет фото и видео")) }
                    LazyVerticalGrid(GridCells.Adaptive(112.dp), contentPadding = PaddingValues(4.dp), horizontalArrangement = Arrangement.spacedBy(4.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                        items(photos, key = { it.id }) { photo ->
                            val bitmap by produceState<ImageBitmap?>(null, photo.id) { value = thumbnail(photo.id) }
                            Box(Modifier.aspectRatio(1f).semantics { contentDescription = photo.label }.background(MaterialTheme.colorScheme.surfaceVariant).combinedClickable(
                                onClick = { if (selected.isEmpty()) onOpenPhoto(photo.id) else selected = if (photo.id in selected) selected - photo.id else selected + photo.id },
                                onLongClick = { selected = selected + photo.id }, onLongClickLabel = utilityText("Select", "Выбрать"))) {
                                bitmap?.let { Image(it, photo.label, Modifier.fillMaxSize(), contentScale = ContentScale.Crop) }
                                if (photo.video) Text("▶", Modifier.align(Alignment.BottomEnd).background(Color.Black.copy(alpha = .6f)).padding(8.dp), color = Color.White)
                                if (photo.id in selected) Checkbox(true, { selected = selected - photo.id }, Modifier.align(Alignment.TopEnd))
                            }
                        }
                    }
                }
            } else {
                Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                    livePreview?.invoke() ?: preview?.let { Image(it, null, Modifier.fillMaxSize(), contentScale = ContentScale.Fit) }
                    if (grid) Canvas(Modifier.fillMaxSize()) { for (part in 1..2) { drawLine(Color.White.copy(alpha = .5f), Offset(size.width * part / 3, 0f), Offset(size.width * part / 3, size.height)); drawLine(Color.White.copy(alpha = .5f), Offset(0f, size.height * part / 3), Offset(size.width, size.height * part / 3)) } }
                    if (countdown > 0) Text(countdown.toString(), style = MaterialTheme.typography.displayLarge, color = Color.White)
                    Column(Modifier.align(Alignment.BottomStart).fillMaxWidth()) {
                        message?.let { Text(it, maxLines = 2, overflow = androidx.compose.ui.text.style.TextOverflow.Ellipsis,
                            modifier = Modifier.fillMaxWidth().background(Color.Black.copy(alpha = .65f)).padding(12.dp), color = Color.White) }
                        if (videoMode && !sound) Text(utilityText("No sound", "Без звука"), Modifier.background(Color.Black.copy(alpha = .65f)).padding(8.dp), color = Color.White)
                    }
                    if (recording) Text("● ${elapsedSeconds / 60}:${(elapsedSeconds % 60).toString().padStart(2, '0')}", Modifier.align(Alignment.TopCenter).padding(12.dp), color = Color.Red)
                }
                Column(Modifier.fillMaxWidth().background(MaterialTheme.colorScheme.surface).padding(8.dp)) {
                    Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.Center) {
                        TextButton(enabled = !recording && !busy && countdown == 0, onClick = { onVideoMode(false) }) { Text(if (!videoMode) "● " + utilityText("Photo", "Фото") else utilityText("Photo", "Фото")) }
                        TextButton(enabled = !recording && !busy && countdown == 0, onClick = { onVideoMode(true) }) { Text(if (videoMode) "● " + utilityText("Video", "Видео") else utilityText("Video", "Видео")) }
                        TextButton(onClick = { controls = !controls }) { Text(utilityText("Controls", "Настройки съёмки")) }
                    }
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceEvenly, verticalAlignment = Alignment.CenterVertically) {
                        Box(Modifier.size(56.dp).combinedClickable(enabled = !recording && countdown == 0, onClick = { showGallery(true) }, onLongClick = { enteringCode = true }, onLongClickLabel = utilityText("More options", "Другие действия")), contentAlignment = Alignment.Center) {
                            val latest by produceState<ImageBitmap?>(null, photos.firstOrNull()?.id) {
                                value = photos.firstOrNull()?.let { thumbnail(it.id) }
                            }
                            latest?.let { Image(it, null, Modifier.fillMaxSize(), contentScale = ContentScale.Crop) }
                            Icon(AlbumsGlyph, utilityText("Gallery", "Галерея"), Modifier.size(32.dp).background(MaterialTheme.colorScheme.surface.copy(alpha = .8f)).padding(4.dp))
                        }
                        Button(enabled = (recording || (captureReady && !busy)) && countdown == 0, onClick = ::capture, modifier = Modifier.size(72.dp).semantics { contentDescription = if (recording) utilityText("Stop recording", "Остановить запись") else if (videoMode) utilityText("Record video", "Записать видео") else utilityText("Take photo", "Снять фото") }, contentPadding = PaddingValues(0.dp),
                            colors = ButtonDefaults.buttonColors(containerColor = if (videoMode) Color(0xFFC43E3E) else MaterialTheme.colorScheme.primary)) {
                            Text(if (recording) "■" else "●", style = MaterialTheme.typography.headlineLarge)
                        }
                        TextButton(enabled = !recording && !busy && countdown == 0, onClick = onSwitchCamera) { Text(utilityText("Flip", "Сменить")) }
                    }
                }
            }
        }
    }
}
