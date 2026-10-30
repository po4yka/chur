package dev.po4yka.chur.android

import android.content.Intent
import android.content.res.Configuration
import android.graphics.Bitmap
import android.graphics.Rect
import android.os.SystemClock
import android.view.ContextThemeWrapper
import android.view.View
import android.view.ViewGroup
import android.view.inspector.WindowInspector
import android.widget.FrameLayout
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.ComposeView
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.platform.ViewRootForTest
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsNode
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.semantics.getAllSemanticsNodes
import androidx.compose.ui.semantics.getOrNull
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.unit.Density
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import dev.po4yka.chur.app.PublicShell
import dev.po4yka.chur.app.notes.NotesScreen
import dev.po4yka.chur.app.notes.Disclosure
import dev.po4yka.chur.app.notes.PublicSettingsScreen
import dev.po4yka.chur.app.publicshell.CalculatorScreen
import dev.po4yka.chur.app.publicshell.CameraScreen
import dev.po4yka.chur.app.publicshell.PUBLIC_CAMERA_DISCLOSURE
import dev.po4yka.chur.app.publicshell.PublicCameraPhoto
import dev.po4yka.chur.app.theme.ChurTheme
import java.io.File
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Public fictional state through the shared renderer. Native capture/storage has separate tests. */
@RunWith(AndroidJUnit4::class)
class PublicShellPresentationTest {
    private val instrumentation get() = InstrumentationRegistry.getInstrumentation()

    @Test
    fun pet_native_drag_long_press_and_renderer_lifecycle() {
        val shown = mutableStateOf(true)
        present(scale = 1f, nativeSurface = true, content = { if (shown.value) dev.po4yka.chur.app.publicshell.PetScreen({}, { false }) }) { f ->
            f.assertPetVisible()
            val before = f.bounds("Chur companion")
            f.gesture("Chur companion", 100f, -100f, 250)
            assertTrue(f.await { f.bounds("Chur companion").left > before.left + 50f })
            f.gesture("Sleep", 0f, 0f, 800)
            assertTrue(f.await { f.has("Access code") })
            f.confirm("Cancel")
            assertTrue(f.has("Chur companion"))
            val frames = java.util.concurrent.atomic.AtomicInteger()
            f.observeTextureFrames(frames)
            assertTrue(f.await { frames.get() > 2 })
            val start = frames.get()
            SystemClock.sleep(1100)
            val foregroundFrames = frames.get() - start
            assertTrue("30 fps cap: $foregroundFrames frames in 1.1 seconds", foregroundFrames in 1..34)
            val memory = mutableListOf(android.os.Debug.getPss())
            repeat(6) {
                f.main { shown.value = false }
                assertTrue(f.await { f.textureCount() == 0 })
                f.main { shown.value = true }
                assertTrue(f.await { f.textureCount() == 1 })
                val beforeFrames = frames.get()
                f.observeTextureFrames(frames)
                assertTrue(f.await { frames.get() > beforeFrames + 2 })
                f.assertPetVisible()
                memory += android.os.Debug.getPss()
            }
            f.main { f.activity.moveTaskToBack(true) }
            SystemClock.sleep(400) // Drain frames submitted before the lifecycle transition.
            val backgroundStart = frames.get()
            SystemClock.sleep(1100)
            assertEquals("No native frames in the background", backgroundStart, frames.get())
            File(requireNotNull(f.activity.getExternalFilesDir(null)), "pet-runtime.txt").writeText(
                "foreground_frames_1100ms=$foregroundFrames\nbackground_frames_1100ms=${frames.get() - backgroundStart}\npss_kib_after_open=$memory\n")
            f.main { shown.value = false }
            assertTrue(f.await { f.textureCount() == 0 })
        }
    }

    @Test
    fun pet_sleep_treat_and_toy_remain_accessible_without_progression() {
        present(scale = 1f, nativeSurface = true, content = { dev.po4yka.chur.app.publicshell.PetScreen({}, { false }) }) { f ->
            assertTrue(f.await { f.has("Chur companion") })
            f.assertPetVisible()
            f.click("Treat")
            f.click("Toy")
            assertTrue(f.await { f.has("Put toy away") })
            f.click("Put toy away")
            f.click("Sleep")
            assertTrue(f.await { f.has("Chur is sleeping") })
            f.click("Wake")
            assertTrue(f.await { f.has("Chur companion") })
            f.capture("pet-awake.png")
        }
    }

    @Test
    fun pet_long_press_does_not_sleep_and_background_revokes_code_input() {
        val epoch = mutableStateOf(0L)
        present(scale = 1f, nativeSurface = true, content = { dev.po4yka.chur.app.publicshell.PetScreen({}, { false }, epoch.value) }) { f ->
            f.hold("Sleep")
            assertTrue(f.await { f.has("Access code") })
            f.confirm("Cancel")
            assertTrue(f.await { f.has("Chur companion") })
            assertFalse(f.has("Chur is sleeping"))
            f.hold("Sleep")
            assertTrue(f.await { f.has("Access code") })
            f.main { epoch.value++ }
            assertTrue(f.await { !f.has("Access code") })
        }
    }

    @Test
    fun pet_large_text_keeps_settings_and_actions_available() {
        present(nativeSurface = true, content = { dev.po4yka.chur.app.publicshell.PetScreen({}, { false }) }) { f ->
            f.click("Treat")
            f.assertLabelFits("Treat")
            f.click("Settings")
            f.capture("pet-large-text.png")
        }
    }

    @Test
    fun notes_keep_search_and_settings_without_brand_controls() {
        val query = mutableStateOf("")
        present(content = { NotesScreen(notes = emptyList(), query = query.value, onQueryChange = { query.value = it }, onOpen = {}, onCreate = {}, onOpenSettings = {}, showFirstWriteDisclosure = false) }) { f ->
            assertTrue(f.await { f.has("Search notes") })
            assertFalse(f.has("Show Chur"))
            assertFalse(f.has("Chur companion. Drag to move, activate to greet."))
            f.click("More")
            f.capture("public-notes-320-font2.png")
            f.assertLabelFits("Notes")
        }
    }

    @Test
    fun narrow_double_font_calculator_keeps_keys_history_and_settings_reachable() {
        var settings = 0
        present(content = { CalculatorScreen(onOpenSettings = { settings++ }) }) { f ->
            for (key in listOf("2", "Add", "3", "Equals")) f.click(key)
            assertTrue(f.await { f.has("Calculator result: 5") })
            f.reveal("Calculator result: 5")
            f.capture("public-calculator-result-320-font2.png")
            f.click("Settings")
            assertEquals(1, settings)
            f.assertLabelFits("Calculator")
            f.reveal("Equals")
            f.assertLabelFits("=")
            f.capture("public-calculator-keys-320-font2.png")
            f.click("History")
            assertTrue(f.await { f.has("Use") })
            f.click("Use")
            assertTrue(f.await { f.has("Calculator result: 5") })
        }
    }

    @Test
    fun calculator_consumes_exact_code_only_on_equals_without_history() {
        var entries = 0
        present(content = { CalculatorScreen(onOpenSettings = {}, onSubmitCode = { if (it == "01234567") { entries++; true } else false }) }) { f ->
            f.click("2")
            f.click("Add")
            for (digit in "01234567") f.click(digit.toString())
            f.click("Equals")
            assertEquals(0, entries)
            f.click("Clear all")
            for (digit in "01234567") f.click(digit.toString())
            assertEquals(0, entries)
            f.click("Equals")
            assertEquals(1, entries)
            assertTrue(f.await { f.has("Calculator result: 0") })
            f.click("History")
            assertFalse(f.has("01234567"))
            assertTrue(f.await { f.has("1234569") })
        }
    }

    @Test
    fun discreet_settings_offer_storage_and_accessible_recovery_only() {
        var opens = 0
        var backs = 0
        present(content = { PublicSettingsScreen(onBack = { backs++ }, onOpenVault = { opens++ }, discreet = true) }) { f ->
            assertFalse(f.has(Disclosure.VAULT_ENTRY))
            f.click("About")
            val version = "Version " + dev.po4yka.chur.app.publicshell.PublicPresentation.version
            f.hold(version)
            assertEquals(1, opens)
            f.assertLabelFits(version)
            f.capture("public-settings-320-font2.png")
            f.click("Back")
            assertEquals(1, backs)
        }
    }

    @Test
    fun camera_discloses_before_capture_and_confirms_gallery_deletion() {
        val selected = mutableStateOf<String?>(null)
        val acknowledged = mutableStateOf(false)
        val photos = mutableStateOf(listOf(PublicCameraPhoto("sample", "Public sample photo")))
        val preview = Bitmap.createBitmap(96, 64, Bitmap.Config.ARGB_8888).apply { eraseColor(0xFF2764A5.toInt()) }.asImageBitmap()
        var captures = 0
        var deletes = 0
        present(content = {
            CameraScreen(preview = preview, hasCapture = false, busy = false, message = null,
                showFirstWriteDisclosure = !acknowledged.value, onAcknowledgeDisclosure = { acknowledged.value = true },
                onCapture = { captures++ }, onOpenSettings = {}, photos = photos.value, selectedPhotoId = selected.value,
                thumbnail = { preview }, onOpenPhoto = { selected.value = it }, onClosePhoto = { selected.value = null },
                onDeletePhoto = { deletes++; photos.value = photos.value.filterNot { p -> p.id == it }; selected.value = null })
        }) { f ->
            f.click("Take photo")
            assertTrue(f.await { f.has("Data storage") })
            assertEquals(0, captures)
            f.capture("public-camera-disclosure-320-font2.png", dialogTitle = "Data storage")
            f.click("Cancel")
            assertFalse(acknowledged.value)
            f.click("Take photo")
            f.click("Got it")
            assertTrue(acknowledged.value)
            f.click("Take photo")
            assertTrue(f.await { captures == 1 })
            f.capture("public-camera-320-font2.png")
            f.click("Gallery")
            f.click("Public sample photo")
            assertEquals("sample", selected.value)
            f.click("Delete")
            assertTrue(f.await { f.has("Delete selected files?") })
            f.click("Cancel")
            assertEquals(0, deletes)
            f.click("Delete")
            f.capture("public-camera-delete-320-font2.png", dialogTitle = "Delete selected files?")
            f.confirm("Delete")
            assertEquals(1, deletes)
            assertTrue(photos.value.isEmpty())
        }
    }

    @Test
    fun silent_video_status_does_not_overlap_permission_message() {
        val status = "Microphone access is off. Video will have no sound."
        present(content = {
            CameraScreen(preview = null, hasCapture = false, busy = false, message = status,
                showFirstWriteDisclosure = false, onAcknowledgeDisclosure = {}, onCapture = {},
                onOpenSettings = {}, videoMode = true, sound = false)
        }) { f ->
            assertTrue(f.await { f.has(status) && f.has("No sound") })
            f.assertVerticallySeparated(status, "No sound")
            f.capture("public-camera-microphone-denied-320-font2.png")
        }
    }

    @Test
    fun public_screens_render_in_both_languages_themes_and_adaptive_sizes() {
        val original = java.util.Locale.getDefault()
        val originalList = android.os.LocaleList.getDefault()
        try {
            for (language in listOf("en", "ru")) for (dark in listOf(false, true)) {
                java.util.Locale.setDefault(java.util.Locale.forLanguageTag(language))
                android.os.LocaleList.setDefault(android.os.LocaleList(java.util.Locale.forLanguageTag(language)))
                for ((width, height) in listOf(320 to 640, 640 to 320, 700 to 800)) {
                    val suffix = "$language-${if (dark) "dark" else "light"}-$width-$height"
                    present(width, height, 1f, dark, language, content = { CalculatorScreen(onOpenSettings = {}) }) { f ->
                        f.click("2"); f.click(if (language == "ru") "Прибавить" else "Add")
                        f.capture("matrix-calculator-$suffix.png")
                    }
                    present(width, height, 1f, dark, language, content = { NotesScreen(notes = emptyList(), query = "", onQueryChange = {}, onOpen = {}, onCreate = {}, onOpenSettings = {}) }) { f ->
                        assertTrue(f.await { f.has(if (language == "ru") "Поиск заметок" else "Search notes") })
                        f.capture("matrix-notes-$suffix.png")
                    }
                    present(width, height, 1f, dark, language, content = { CameraScreen(preview = null, hasCapture = false, busy = false, message = null,
                        showFirstWriteDisclosure = false, onAcknowledgeDisclosure = {}, onCapture = {}, onOpenSettings = {}) }) { f ->
                        f.click(if (language == "ru") "Снять фото" else "Take photo")
                        f.capture("matrix-camera-$suffix.png")
                    }
                }
            }
        } finally { java.util.Locale.setDefault(original); android.os.LocaleList.setDefault(originalList) }
    }

    private fun present(width: Int = 320, height: Int = 640, scale: Float = 2f, dark: Boolean = false, language: String = "en", nativeSurface: Boolean = false, content: @Composable () -> Unit, test: (Fixture) -> Unit) {
        val activity = instrumentation.startActivitySync(Intent(instrumentation.targetContext, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as MainActivity
        try {
            val f = Fixture(activity)
            f.main {
                android.os.LocaleList.setDefault(android.os.LocaleList(java.util.Locale.forLanguageTag(language)))
                val density = activity.resources.displayMetrics.density
                val config = Configuration(activity.resources.configuration).apply {
                    screenWidthDp = width; screenHeightDp = height; fontScale = scale; setLocale(java.util.Locale.forLanguageTag(language))
                }
                val context = ContextThemeWrapper(activity, activity.theme).apply { applyOverrideConfiguration(config) }
                f.view = ComposeView(context).apply {
                    // TextureView requires the same hardware composition as the production host.
                    if (!nativeSurface) setLayerType(View.LAYER_TYPE_SOFTWARE, null)
                    setContent {
                        val rememberStore = androidx.compose.runtime.remember { dev.po4yka.chur.app.publicshell.PublicUtilityStore().apply { setAppearance(if (dark) "dark" else "light") } }
                        CompositionLocalProvider(LocalDensity provides Density(density, scale), LocalConfiguration provides config) {
                            dev.po4yka.chur.app.publicshell.PublicUtilityTheme(rememberStore, content)
                        }
                    }
                }
                activity.setContentView(FrameLayout(activity).apply {
                    addView(f.view, FrameLayout.LayoutParams((width * density).toInt(), (height * density).toInt()))
                })
            }
            test(f)
        } finally { instrumentation.runOnMainSync { activity.finish() } }
    }

    private inner class Fixture(val activity: MainActivity) {
        lateinit var view: ComposeView
        fun main(action: () -> Unit) = instrumentation.runOnMainSync(action)
        fun bounds(label: String): androidx.compose.ui.geometry.Rect {
            var result: androidx.compose.ui.geometry.Rect? = null
            main { result = find(label)?.boundsInWindow }
            return requireNotNull(result)
        }
        fun gesture(label: String, dx: Float, dy: Float, duration: Long) {
            val origin = bounds(label).center
            val started = SystemClock.uptimeMillis()
            fun send(action: Int, x: Float, y: Float) {
                val event = android.view.MotionEvent.obtain(started, SystemClock.uptimeMillis(), action, x, y, 0)
                try { instrumentation.sendPointerSync(event) } finally { event.recycle() }
            }
            send(android.view.MotionEvent.ACTION_DOWN, origin.x, origin.y)
            repeat(10) { i ->
                SystemClock.sleep(duration / 10)
                send(android.view.MotionEvent.ACTION_MOVE, origin.x + dx * (i + 1) / 10, origin.y + dy * (i + 1) / 10)
            }
            send(android.view.MotionEvent.ACTION_UP, origin.x + dx, origin.y + dy)
            frames()
        }
        private fun textures(): List<android.view.TextureView> {
            val result = mutableListOf<android.view.TextureView>()
            fun visit(node: View) {
                if (node is android.view.TextureView) result += node
                if (node is ViewGroup) for (i in 0 until node.childCount) visit(node.getChildAt(i))
            }
            visit(view)
            return result
        }
        fun textureCount(): Int { var count = 0; main { count = textures().size }; return count }
        fun observeTextureFrames(count: java.util.concurrent.atomic.AtomicInteger) = main {
            val texture = textures().single()
            val delegate = requireNotNull(texture.surfaceTextureListener)
            texture.surfaceTextureListener = object : android.view.TextureView.SurfaceTextureListener by delegate {
                override fun onSurfaceTextureUpdated(surface: android.graphics.SurfaceTexture) {
                    delegate.onSurfaceTextureUpdated(surface)
                    count.incrementAndGet()
                }
            }
        }
        fun assertPetVisible() {
            assertTrue("Pet must be visible in the composed screen, including its native surface", await {
                var bounds: androidx.compose.ui.geometry.Rect? = null
                main { bounds = find("Chur companion")?.boundsInWindow ?: find("Chur is sleeping")?.boundsInWindow }
                val region = bounds ?: return@await false
                val screen = instrumentation.uiAutomation.takeScreenshot() ?: return@await false
                try {
                    var dark = 0
                    // Ignore the guide border: only count the character inside the target.
                    val inset = region.width * .2f
                    for (y in (region.top + inset).toInt() until (region.bottom - inset).toInt() step 4) {
                        for (x in (region.left + inset).toInt() until (region.right - inset).toInt() step 4) {
                            if (x !in 0 until screen.width || y !in 0 until screen.height) continue
                            val pixel = screen.getPixel(x, y)
                            if (android.graphics.Color.red(pixel) < 120 && android.graphics.Color.green(pixel) < 120 &&
                                android.graphics.Color.blue(pixel) < 120) dark++
                        }
                    }
                    if (dark <= 30) File(requireNotNull(activity.getExternalFilesDir(null)), "pet-not-visible.png").outputStream().use { screen.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it) }
                    dark > 30
                } finally { screen.recycle() }
            })
        }
        fun await(condition: () -> Boolean): Boolean {
            val deadline = SystemClock.uptimeMillis() + 5_000
            while (SystemClock.uptimeMillis() < deadline) {
                instrumentation.waitForIdleSync()
                if (condition()) return true
                SystemClock.sleep(30)
            }
            return condition()
        }
        private fun nodes(merged: Boolean = true) = WindowInspector.getGlobalWindowViews().flatMap { it.roots() }
            .flatMap { it.semanticsOwner.getAllSemanticsNodes(mergingEnabled = merged) }
        private fun find(label: String) = nodes().firstOrNull { label in it.labels }
        fun has(label: String): Boolean { var found = false; main { found = find(label) != null }; return found }
        fun isSelected(label: String): Boolean {
            var selected = false
            main { selected = find(label)?.config?.getOrNull(SemanticsProperties.Selected) == true }
            return selected
        }
        fun reveal(label: String) {
            assertTrue("missing public control: $label", await { has(label) })
            repeat(8) {
                var visible = false
                main {
                    val node = requireNotNull(find(label))
                    val top = node.positionInWindow.y
                    val bottom = top + node.size.height
                    val window = WindowInspector.getGlobalWindowViews().first { root ->
                        root.roots().any { r -> r.semanticsOwner.getAllSemanticsNodes(mergingEnabled = true).any { it.id == node.id } }
                    }
                    val mainWindow = window === activity.window.decorView
                    val position = IntArray(2); view.getLocationInWindow(position)
                    val low = if (mainWindow) position[1] + view.height - 1f else window.height - 1f
                    val high = if (!mainWindow) 0f else position[1] +
                        if (label in listOf("Settings", "Back", "Calculator", "More")) 0f
                        else 64 * view.resources.displayMetrics.density
                    visible = top >= high && bottom <= low && bottom > top
                    if (!visible) {
                        val scroll = nodes().firstOrNull { SemanticsActions.ScrollBy in it.config &&
                            it.config.getOrNull(SemanticsProperties.VerticalScrollAxisRange) != null }
                        val delta = (top + bottom) / 2f - (high + low) / 2f
                        scroll?.config?.getOrNull(SemanticsActions.ScrollBy)?.action?.invoke(0f, delta)
                    }
                }
                if (visible) return
                frames()
            }
            throw AssertionError("public control did not scroll into view: $label")
        }
        fun click(label: String) {
            reveal(label)
            main {
                val node = nodes().first { label in it.labels && SemanticsActions.OnClick in it.config }
                assertTrue(node.config[SemanticsActions.OnClick].action?.invoke() == true)
            }
            frames()
        }
        fun hold(label: String) {
            reveal(label)
            main { assertTrue(requireNotNull(find(label)).config[SemanticsActions.OnLongClick].action?.invoke() == true) }
        }
        fun confirm(label: String) {
            main { val node = nodes().last { label in it.labels && SemanticsActions.OnClick in it.config }; assertTrue(node.config[SemanticsActions.OnClick].action?.invoke() == true) }
        }
        fun assertVerticallySeparated(upper: String, lower: String) = main {
            val first = requireNotNull(find(upper)).boundsInWindow
            val second = requireNotNull(find(lower)).boundsInWindow
            assertTrue("Status labels overlap: $first and $second", first.bottom <= second.top)
        }
        fun assertLabelFits(label: String) = main {
            val node = nodes(false).first { n -> n.config.getOrNull(SemanticsProperties.Text)?.any { it.text == label } == true &&
                SemanticsActions.GetTextLayoutResult in n.config }
            val layouts = mutableListOf<TextLayoutResult>()
            assertTrue(node.config[SemanticsActions.GetTextLayoutResult].action?.invoke(layouts) == true)
            assertTrue(layouts.isNotEmpty())
            for (layout in layouts) {
                val metrics = "label=$label, node=${node.boundsInWindow}, position=${node.positionInWindow}, " +
                    "nodeSize=${node.size}, layout=${layout.size}, constraints=${layout.layoutInput.constraints}, " +
                    "paragraphWidth=${layout.multiParagraph.width}, lines=${layout.lineCount}, " +
                    "widthOverflow=${layout.didOverflowWidth}, heightOverflow=${layout.didOverflowHeight}, " +
                    "font=${layout.layoutInput.style.fontSize}, scale=${layout.layoutInput.density.fontScale}"
                assertEquals("actual font scale; $metrics", 2f, layout.layoutInput.density.fontScale, 0.01f)
                // ui-text can retain a paragraph constraint wider than its wrapped Text node.
                // Compare visible lines and glyphs with the node, as DocumentPresentationTest does.
                assertEquals("every character must remain visible; $metrics", label.length,
                    layout.getLineEnd(layout.lineCount - 1, visibleEnd = true))
                for (line in 0 until layout.lineCount) {
                    assertFalse("the label must not be ellipsized; $metrics", layout.isLineEllipsized(line))
                    assertTrue("line $line must start inside the node; $metrics", layout.getLineLeft(line) >= -1f)
                    assertTrue("line $line must end inside the node; $metrics",
                        layout.getLineRight(line) <= node.boundsInWindow.width + 1f)
                }
                for (offset in label.indices) {
                    val box = layout.getBoundingBox(offset)
                    assertTrue("glyph $offset must fit horizontally: $box; $metrics",
                        box.left >= -1f && box.right <= node.boundsInWindow.width + 1f)
                    assertTrue("glyph $offset must fit vertically: $box; $metrics",
                        box.top >= -1f && box.bottom <= node.boundsInWindow.height + 1f)
                }
                assertFalse("the full height must fit; $metrics", layout.didOverflowHeight)
                assertTrue("the text node must not clip horizontally; $metrics",
                    layout.size.width <= node.boundsInWindow.width + 1f)
                assertTrue("the text node must not clip vertically; $metrics",
                    layout.size.height <= node.boundsInWindow.height + 1f)
            }
        }
        private fun frames() {
            val ready = CountDownLatch(1)
            main { view.postOnAnimation { view.postOnAnimation { ready.countDown() } } }
            assertTrue(ready.await(5, TimeUnit.SECONDS))
            instrumentation.waitForIdleSync()
        }
        fun capture(name: String, dialogTitle: String? = null) {
            val animatedPet = name.startsWith("pet-")
            if (animatedPet) assertPetVisible()
            frames()
            val bounds = Rect()
            main {
                val target = if (dialogTitle == null) view else WindowInspector.getGlobalWindowViews().first { root ->
                    root.roots().flatMap { it.semanticsOwner.getAllSemanticsNodes(mergingEnabled = false) }
                        .any { dialogTitle in it.labels }
                }
                val point = IntArray(2); target.getLocationOnScreen(point)
                bounds.set(point[0], point[1], point[0] + target.width, point[1] + target.height)
            }
            // A dismissed Android dialog can keep its compositor surface during the window
            // animation after Compose is idle. Require stable public pixels, not a fixed delay.
            val deadline = SystemClock.uptimeMillis() + 5_000
            var previous: Bitmap? = null
            var unchangedSince = 0L
            var settled = false
            try {
                while (SystemClock.uptimeMillis() < deadline) {
                    frames()
                    val screen = requireNotNull(instrumentation.uiAutomation.takeScreenshot())
                    val current = try {
                        assertTrue(bounds.intersect(0, 0, screen.width, screen.height))
                        Bitmap.createBitmap(screen, bounds.left, bounds.top, bounds.width(), bounds.height())
                    } catch (error: Throwable) {
                        screen.recycle()
                        throw error
                    }
                    // createBitmap can return the same bitmap for a full-screen crop.
                    if (current !== screen) screen.recycle()
                    val now = SystemClock.uptimeMillis()
                    if (previous?.sameAs(current) == true) {
                        if (unchangedSince == 0L) unchangedSince = now
                    } else unchangedSince = 0L
                    previous?.recycle()
                    previous = current
                    if (animatedPet || unchangedSince != 0L && now - unchangedSince >= 200L) {
                        settled = true
                        break
                    }
                }
                assertTrue("public fixture pixels must finish animating before capture: $name", settled)
                val crop = requireNotNull(previous)
                val colors = mutableSetOf<Int>()
                for (y in 0 until crop.height step 4) for (x in 0 until crop.width step 4) colors += crop.getPixel(x, y)
                assertTrue("public fixture must render", colors.size > 16)
                File(requireNotNull(activity.getExternalFilesDir(null)), name).outputStream().use {
                    assertTrue(crop.compress(Bitmap.CompressFormat.PNG, 100, it))
                }
            } finally { previous?.recycle() }
        }
    }
    private val SemanticsNode.labels get() = config.getOrNull(SemanticsProperties.Text).orEmpty().map { it.text } +
        config.getOrNull(SemanticsProperties.ContentDescription).orEmpty()
    private fun View.roots(): List<ViewRootForTest> = buildList {
        if (this@roots is ViewRootForTest) add(this@roots)
        if (this@roots is ViewGroup) for (index in 0 until childCount) addAll(getChildAt(index).roots())
    }
}
