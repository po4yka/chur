package dev.po4yka.chur.android

import android.content.Intent
import android.os.SystemClock
import android.view.KeyEvent
import android.view.View
import android.view.ViewGroup
import android.view.accessibility.AccessibilityNodeInfo
import android.view.inspector.WindowInspector
import androidx.compose.ui.platform.ViewRootForTest
import androidx.compose.ui.semantics.*
import androidx.compose.ui.text.AnnotatedString
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

/** Real first-launch UI. Run after clearing this synthetic app and seeding Download/onboarding.png. */
@RunWith(AndroidJUnit4::class)
class PrivateOnboardingTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val password = "Onboarding-public-test-2026"

    @Test fun complete_private_tour_and_revoke_manual_replay_on_background() {
        val activity = instrumentation.startActivitySync(Intent(instrumentation.targetContext, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as MainActivity
        try {
            assertTrue("Use a fresh disposable installation", await { has("Meet Chur") })
            click("Chur")
            click("Set up vault", guide = true)
            field("Password", password)
            field("Repeat password", password)
            click("Create vault")
            assertTrue(await { has("Your recovery phrase") })
            click("Show words")
            assertTrue(await { has("chur-recovery-v1") })
            val words = mutableMapOf<Int, String>()
            repeat(5) {
                main { nodes(false).flatMap { it.labels }.forEach { value ->
                    Regex("^\\s*(\\d+)\\. ([a-z]+)$").matchEntire(value)?.let {
                        words[it.groupValues[1].toInt()] = it.groupValues[2]
                    }
                } }
                if (words.size < 24) scroll(true)
            }
            assertEquals(24, words.size)
            click("I have written them down")
            val labels = mutableListOf<String>()
            assertTrue(await {
                main { labels.clear(); labels += nodes().filter { SemanticsActions.SetText in it.config }.flatMap { it.labels }.filter { it.startsWith("Word ") } }
                labels.size == 3
            })
            labels.forEach { field(it, requireNotNull(words[it.substringAfter("Word ").toInt()])) }
            click("Continue")
            lesson("In Library, use Import")
            click("Import")
            click("Media files")
            awaitPackage("com.google.android.documentsui")
            instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
            awaitPackage("dev.po4yka.chur")
            lesson("In Library, use Import")
            click("Import")
            click("Media files")
            awaitPackage("com.google.android.documentsui")
            systemClick("Show roots")
            systemClick("Downloads")
            systemClick("onboarding.png")
            awaitPackage("dev.po4yka.chur")
            assertTrue(await { has("Keep original") || has("onboarding.png") })
            if (has("Keep original")) click("Keep original")
            lesson("Open an item in Library")
            assertTrue(await {
                var ready = false
                main { ready = nodes().any { it.config.getOrNull(SemanticsActions.OnClick)?.label == "Open" } }
                ready
            })
            main {
                val tile = nodes().first { it.config.getOrNull(SemanticsActions.OnClick)?.label == "Open" }
                assertTrue(tile.config[SemanticsActions.OnClick].action?.invoke() == true)
            }
            lesson("Return to Library and open Search")
            instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
            click("Search")
            field("Search", "onboarding")
            var keyboardVisible = false
            main { keyboardVisible = activity.window.decorView.rootWindowInsets.isVisible(android.view.WindowInsets.Type.ime()) }
            if (keyboardVisible) instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
            lesson("Tap Lock to close the vault")
            click("Got it", guide = true)
            click("Settings")
            reveal("Auto-lock")
            click("Got it", guide = true)
            reveal("Access", up = false)
            click("Got it", guide = true)
            reveal("Write a backup file")
            click("Got it", guide = true)
            reveal("Public applications", up = false)
            click("Public applications")
            field("New 8-digit transition code", "01234567")
            field("Try the code again", "01234567")
            click("Test entry and enable")
            assertTrue(await { has("Sleep") })
            assertFalse(has("Finish tutorial"))
            main { assertTrue(find("Sleep")!!.config[SemanticsActions.OnLongClick].action?.invoke() == true) }
            field("8-digit code", "01234567")
            click("Continue")
            assertTrue(await { has("Unlock") })
            field("Password", password)
            click("Unlock")
            assertTrue(await { has("Library") })
            assertFalse(has("Finish tutorial"))
            click("Settings")
            reveal("Public applications", up = false)
            click("Public applications")
            assertTrue(await { has("Disable discreet mode") })
            reveal("Learn with Chur", up = false)
            click("Learn with Chur")
            lesson("In Library, use Import")
            main { activity.moveTaskToBack(true) }
            assertTrue(await { !has("Finish tutorial") })
            instrumentation.targetContext.startActivity(Intent(instrumentation.targetContext, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            awaitPackage("dev.po4yka.chur")
            assertTrue(await {
                var privateHint = false
                main { privateHint = nodes().any { node -> node.labels.any { it.startsWith("In Library, use Import") } } }
                !privateHint
            })
        } finally { main { activity.finish() } }
    }

    /** Seed the CLI-produced restore-onboarding.churbak and truncated.churbak in Downloads. */
    @Test fun restore_archive_cancel_retry_authenticate_and_continue_tour() {
        val activity = instrumentation.startActivitySync(Intent(instrumentation.targetContext, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)) as MainActivity
        try {
            assertTrue("Use a fresh disposable installation", await { has("Meet Chur") })
            click("Chur")
            click("Set up vault", guide = true)
            click("Restore from a backup")
            lesson("Enter the archive password")
            click("Back")
            lesson("Choose a strong password")
            click("Restore from a backup")
            field("Backup password or recovery phrase", password)
            click("Choose backup file")
            awaitPackage("com.google.android.documentsui")
            instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
            awaitPackage("dev.po4yka.chur")
            lesson("Enter the archive password")
            assertRestoreCredentialCleared()
            fun chooseArchive(credential: String, name: String) {
                field("Backup password or recovery phrase", credential)
                click("Choose backup file")
                awaitPackage("com.google.android.documentsui")
                systemClick("Show roots")
                systemClick("Downloads")
                systemClick(name)
                awaitPackage("dev.po4yka.chur")
            }
            chooseArchive("Wrong-public-fixture-password", "restore-onboarding.churbak")
            assertTrue(await { has("Unable to unlock. Try again or use recovery.") })
            lesson("Enter the archive password")
            assertRestoreCredentialCleared()
            assertFalse(has("Library"))
            chooseArchive(password, "truncated.churbak")
            assertTrue(await { has("The vault could not be verified. Restore it from a backup.") })
            lesson("Enter the archive password")
            assertRestoreCredentialCleared()
            assertFalse(has("Library"))
            chooseArchive(password, "restore-onboarding.churbak")
            lesson("The archive is restored")
            assertTrue(has("Unlock"))
            assertFalse(has("Library"))
            field("Password", password)
            click("Unlock")
            lesson("In Library, use Import")
            assertFalse(has("Your recovery phrase"))
            // Restored content is already present. Import is optional in the tour.
            click("Skip step", guide = true)
            lesson("Open an item in Library")
            assertTrue(await {
                var ready = false
                main { ready = nodes().any { it.config.getOrNull(SemanticsActions.OnClick)?.label == "Open" } }
                ready
            })
            main { assertTrue(nodes().first { it.config.getOrNull(SemanticsActions.OnClick)?.label == "Open" }
                .config[SemanticsActions.OnClick].action?.invoke() == true) }
            lesson("Return to Library and open Search")
            assertTrue("Restored image pixels must be decoded", await {
                var ready = false
                main { ready = nodes().any { it.config.getOrNull(SemanticsProperties.StateDescription) == "Zoom 100%" } }
                ready
            })
            assertFalse(has("Preview unavailable"))
            click("Info")
            assertTrue(await { has("restored-onboarding.png") })
            click("Hide info")
            instrumentation.sendKeyDownUpSync(KeyEvent.KEYCODE_BACK)
            click("Search")
            field("Search", "restored-onboarding")
            lesson("Tap Lock to close the vault")
            click("Lock now")
            assertTrue(await { !has("Finish tutorial") })
        } finally { main { activity.finish() } }
    }
    private fun assertRestoreCredentialCleared() {
        main {
            val field = nodes().first { "Backup password or recovery phrase" in it.labels && SemanticsActions.SetText in it.config }
            assertEquals("", field.config[SemanticsProperties.EditableText].text)
            assertTrue(SemanticsProperties.Disabled in find("Choose backup file")!!.config)
        }
    }

    private val SemanticsNode.labels get() = config.getOrNull(SemanticsProperties.Text).orEmpty().map { it.text } +
        config.getOrNull(SemanticsProperties.ContentDescription).orEmpty()
    private fun View.roots(): List<ViewRootForTest> = when (this) {
        is ViewRootForTest -> listOf(this)
        is ViewGroup -> (0 until childCount).flatMap { getChildAt(it).roots() }
        else -> emptyList()
    }
    private fun nodes(merged: Boolean = true) = WindowInspector.getGlobalWindowViews().flatMap { it.roots() }
        .flatMap { it.semanticsOwner.getAllSemanticsNodes(mergingEnabled = merged) }
    private fun find(label: String, contains: Boolean = false) = nodes().firstOrNull { n ->
        n.labels.any { if (contains) it.contains(label) else it == label } }
    private fun main(block: () -> Unit) = instrumentation.runOnMainSync(block)
    private fun settleUi() {
        instrumentation.waitForIdleSync()
        val frames = java.util.concurrent.CountDownLatch(1)
        main { android.view.Choreographer.getInstance().postFrameCallback {
            android.view.Choreographer.getInstance().postFrameCallback { frames.countDown() }
        } }
        assertTrue("Compose frame completed", frames.await(5, java.util.concurrent.TimeUnit.SECONDS))
        instrumentation.waitForIdleSync()
    }
    private fun has(label: String): Boolean { var yes = false; main { yes = find(label) != null }; return yes }
    private fun await(block: () -> Boolean): Boolean {
        val end = SystemClock.uptimeMillis() + 30_000
        while (SystemClock.uptimeMillis() < end) {
            instrumentation.waitForIdleSync()
            if (block()) return true
            SystemClock.sleep(100)
        }
        return block()
    }
    private fun lesson(prefix: String) {
        val present = await { var yes = false; main { yes = nodes().any { it.labels.any { s -> s.startsWith(prefix) } } }; yes }
        if (!present) main { android.util.Log.i("Onboarding", "FAILED STEP UI: " + nodes().flatMap { it.labels }.joinToString(" | ")) }
        assertTrue("Missing guide step: $prefix", present)
        android.util.Log.i("Onboarding", "STEP: $prefix")
    }
    private fun scroll(up: Boolean, guide: Boolean = false) {
        var axis: ScrollAxisRange? = null
        var previous = 0f
        main {
            val candidates = nodes().filter { SemanticsActions.ScrollBy in it.config &&
                it.config.getOrNull(SemanticsProperties.VerticalScrollAxisRange) != null }
            val node = if (guide) candidates.maxByOrNull { it.boundsInWindow.top }
                else candidates.maxByOrNull { it.size.height }
            axis = node?.config?.getOrNull(SemanticsProperties.VerticalScrollAxisRange)
            previous = axis?.value?.invoke() ?: 0f
            node?.config?.getOrNull(SemanticsActions.ScrollBy)?.action?.invoke(0f, if (up) 450f else -450f)
        }
        settleUi()
        assertTrue(await {
            var settled = false
            main { axis?.let { settled = it.value() != previous || (up && it.value() >= it.maxValue()) || (!up && it.value() <= 0f) } ?: run { settled = true } }
            settled
        })
    }
    private fun reveal(label: String, up: Boolean = true, guide: Boolean = false, contains: Boolean = false) {
        repeat(18) {
            var visible = false
            main { find(label, contains)?.let { visible = it.boundsInWindow.height >= it.size.height - 1 && it.boundsInWindow.height > 0 } }
            if (visible) return
            scroll(up, guide)
        }
        assertTrue("Missing control: $label", has(label))
    }
    private fun click(label: String, guide: Boolean = false, contains: Boolean = false) {
        reveal(label, guide = guide, contains = contains)
        assertTrue("Enabled control: $label", await {
            var enabled = false
            main { enabled = find(label, contains)?.let { SemanticsProperties.Disabled !in it.config && SemanticsActions.OnClick in it.config } == true }
            enabled
        })
        main { assertTrue("Control must handle click: $label", find(label, contains)!!.config.getOrNull(SemanticsActions.OnClick)?.action?.invoke() == true) }
        settleUi()
    }
    private fun field(label: String, value: String) {
        reveal(label)
        assertTrue("Missing editable field: $label", await {
            var ready = false
            main { ready = nodes().any { label in it.labels && SemanticsActions.SetText in it.config } }
            ready
        })
        main {
            val node = nodes().first { label in it.labels && SemanticsActions.SetText in it.config }
            assertTrue(node.config[SemanticsActions.SetText].action?.invoke(AnnotatedString(value)) == true)
        }
        settleUi()
    }
    private fun awaitPackage(name: String) {
        assertTrue("Expected foreground package: $name", await { instrumentation.uiAutomation.rootInActiveWindow?.packageName?.toString() == name })
        instrumentation.uiAutomation.waitForIdle(500, 5_000)
    }
    private fun systemClick(label: String) {
        fun descend(node: AccessibilityNodeInfo): AccessibilityNodeInfo? {
            if (node.isVisibleToUser && (node.text?.toString()?.equals(label, ignoreCase = true) == true || node.contentDescription?.toString()?.equals(label, ignoreCase = true) == true)) return node
            for (i in 0 until node.childCount) node.getChild(i)?.let { descend(it)?.let { match -> return match } }
            return null
        }
        instrumentation.uiAutomation.waitForIdle(500, 5_000)
        val clicked = await {
            var found = instrumentation.uiAutomation.rootInActiveWindow?.let(::descend) ?: return@await false
            while (!found.isClickable) found = found.parent ?: return@await false
            found.performAction(AccessibilityNodeInfo.ACTION_CLICK)
        }
        if (!clicked) {
            fun describe(node: AccessibilityNodeInfo) {
                android.util.Log.i("OnboardingPicker", "text=${node.text} description=${node.contentDescription} visible=${node.isVisibleToUser} clickable=${node.isClickable}")
                for (i in 0 until node.childCount) node.getChild(i)?.let(::describe)
            }
            instrumentation.uiAutomation.rootInActiveWindow?.let(::describe)
        }
        assertTrue("Missing system picker control: $label", clicked)
        instrumentation.uiAutomation.waitForIdle(500, 5_000)
    }
}
