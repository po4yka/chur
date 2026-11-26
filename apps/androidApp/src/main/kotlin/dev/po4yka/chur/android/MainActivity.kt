package dev.po4yka.chur.android

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import dev.po4yka.chur.app.notes.AndroidPublicNoteExport
import dev.po4yka.chur.app.notes.PublicNoteExportHost
import dev.po4yka.chur.app.ChurApp
import dev.po4yka.chur.app.LauncherAction
import dev.po4yka.chur.app.GateResult
import dev.po4yka.chur.app.NativeHandshake
import dev.po4yka.chur.app.gate
import dev.po4yka.chur.app.needsPrivacyCover
import dev.po4yka.chur.ffi.ChurVault
import java.io.IOException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.combine

/**
 * The window half of the composition root.
 *
 * `docs/ARCHITECTURE.md` §9 says only the composition root and adapter modules
 * bind implementations. The root is split in two, because its two halves have
 * two lifetimes: [ChurHost] holds what `docs/interop/FFI_CONTRACT.md` §14 makes
 * process-scoped - the runtime, the repository, the controller, the engine -
 * and this holds the window, which the platform destroys and recreates under
 * it. §8.1 has the recreated window share the one session: "there is no
 * per-scene vault state".
 *
 * The gate runs before anything private is composed. §2 of
 * `docs/interop/FFI_CONTRACT.md` makes a failing gate terminal for the process,
 * so the shell says so and composes no vault route rather than degrading.
 */
/*
 * It is a `FragmentActivity` rather than a bare `ComponentActivity` because
 * `BiometricPrompt` requires one, and the device slot of `KEY_SLOTS.md` §4
 * cannot be authorized without it. `FragmentActivity` extends
 * `ComponentActivity`, so everything else here is unchanged.
 */
class MainActivity : FragmentActivity(), PublicNoteExportHost {
    override lateinit var publicNoteExport: AndroidPublicNoteExport
        private set
    private lateinit var host: ChurHost
    private var gateCompatible = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val noteDestination = activityResultRegistry.register("public-note-text-export", this,
            ActivityResultContracts.StartActivityForResult()) { result ->
            val uri = if (result.resultCode == Activity.RESULT_OK) result.data?.data else null
            lifecycleScope.launch(start = CoroutineStart.UNDISPATCHED) {
                try { publicNoteExport.complete(uri) }
                catch (cancelled: CancellationException) { throw cancelled }
                catch (_: Exception) { showNoteExportFailure() }
            }
        }
        publicNoteExport = AndroidPublicNoteExport(applicationContext, savedInstanceState != null, noteDestination::launch)
        enableEdgeToEdge()

        host = ChurHost.of(this)
        host.activity = this
        // Recreation keeps the process inbox. A restored activity never replays
        // the original payload after process death or a completed import.
        val launchIntent = intent
        intent = sanitizedLauncherIntent(this)
        // The window is new and the session it will show may already be open.
        // §1 of `PLAINTEXT_LIFECYCLE.md` puts the switcher snapshot in the
        // forbidden column, and the platform can take one before the collector
        // below has run, so the cover is set from the state here rather than
        // waiting for the first collection.
        host.privacy.setEnabled(host.controller.privacyCoverNeeded)

        val weakActivity = java.lang.ref.WeakReference(this)
        val publicContext = applicationContext
        dev.po4yka.chur.app.publicshell.PublicPresentation.apply = { enabled, shell ->
            PublicLauncherPresentation.apply(publicContext, enabled, shell)
            val label = publicContext.getString(if (!enabled) R.string.app_name else when (shell) {
                "calculator" -> R.string.public_calculator; "camera" -> R.string.public_camera; "pet" -> R.string.public_pet; else -> R.string.public_notes
            })
            val icon = if (!enabled) R.mipmap.ic_launcher else when (shell) {
                "calculator" -> R.drawable.ic_public_calculator; "camera" -> R.drawable.ic_public_camera; "pet" -> R.mipmap.ic_launcher; else -> R.drawable.ic_public_notes
            }
            weakActivity.get()?.let { activity ->
                activity.title = label
                val drawable = androidx.core.content.ContextCompat.getDrawable(publicContext, icon)
                val bitmap = android.graphics.Bitmap.createBitmap(96, 96, android.graphics.Bitmap.Config.ARGB_8888)
                drawable?.setBounds(0, 0, 96, 96)
                drawable?.draw(android.graphics.Canvas(bitmap))
                @Suppress("DEPRECATION")
                activity.setTaskDescription(android.app.ActivityManager.TaskDescription(label, bitmap))
            }
        }
        dev.po4yka.chur.app.publicshell.PublicPresentation.version = packageManager.getPackageInfo(packageName, 0).versionName ?: ""
        host.controller.refreshPublicPresentation()
        val controller = host.controller
        val verdict = runGate(this)
        if (verdict is GateResult.Compatible) {
            // It runs once per process: the controller refuses a second start,
            // because a second one would leave a second idle timer over the one
            // session. It runs on the controller's scope and not on this
            // activity's, because `lifecycleScope` is cancelled at `onDestroy`
            // and a start cancelled part-way arms no timer at all.
            gateCompatible = true
            controller.begin()
            if (savedInstanceState == null) receiveExternalIntent(launchIntent)
        } else {
            host.incomingShares.discard()
        }

        setContent {
            val state by controller.vaultState.collectAsState()
            val route by controller.route.collectAsState()
            ChurApp(gate = verdict, route = route) {
                ChurRoutes(controller = controller, route = route, vaultState = state)
                val codec = remember { dev.po4yka.chur.imports.AndroidMediaCodec(applicationContext) }
                val importer = remember { dev.po4yka.chur.app.MediaImporter(codec) }
                dev.po4yka.chur.app.IncomingSharePrompt(
                    inbox = host.incomingShares,
                    controller = controller,
                    route = route,
                    importer = importer,
                )
            }
        }

        // Observe only while resumed. After onPause enables the cover, a
        // background lock can emit Locked before onStop; a STARTED collector
        // would clear FLAG_SECURE while the window is still visible to recents.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.RESUMED) {
                combine(controller.vaultState, controller.route, controller.recoveryPhrase) { state, route, phrase ->
                    needsPrivacyCover(state, route, phrase != null)
                }.collect { secure ->
                    host.privacy.setEnabled(secure)
                }
            }
        }
        lifecycleScope.launch {
            host.deviceControl.pairing.collect { pairing ->
                if (pairing != null) {
                    window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                } else {
                    window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
                }
            }
        }
    }

    private fun showNoteExportFailure() {
        val message = dev.po4yka.chur.app.publicshell.utilityText(
            "The file could not be exported. Try again.", "Не удалось экспортировать файл. Повторите попытку."
        )
        android.widget.Toast.makeText(applicationContext, message, android.widget.Toast.LENGTH_LONG).show()
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        receiveExternalIntent(intent)
    }

    private fun receiveExternalIntent(incoming: Intent) {
        // Read only an allowlisted action; no extra, URI or saved intent can
        // supply a private query, identity, or replay token. The only extra read
        // is the launcher token: an app other than the launcher cannot supply it,
        // so it cannot force a lock or a private route.
        val action = externalLauncherAction(this, incoming)
        intent = sanitizedLauncherIntent(this)
        if (!gateCompatible) return
        if (incoming.action == Intent.ACTION_SEND || incoming.action == Intent.ACTION_SEND_MULTIPLE) {
            receiveShare(incoming)
            return
        }
        if (action == null) return
        if (action != LauncherAction.LOCK_AND_HIDE && host.incomingShares.state.value != null) {
            android.widget.Toast.makeText(this, R.string.launcher_finish_share, android.widget.Toast.LENGTH_LONG).show()
            return
        }
        host.privacy.setEnabled(true)
        host.controller.requestLauncherAction(action)
        if (action == LauncherAction.LOCK_AND_HIDE) {
            try {
                host.deviceControl.stop()
            } catch (_: IOException) {
                // Session revocation above must complete even if socket close fails.
            }
            window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        }
        host.privacy.setEnabled(host.controller.privacyCoverNeeded)
    }

    private fun receiveShare(incoming: Intent) {
        if (incoming.action != Intent.ACTION_SEND && incoming.action != Intent.ACTION_SEND_MULTIPLE) return
        val payload = incomingSharePayload(this, incoming)
        if (payload == null) {
            android.widget.Toast.makeText(this, "That shared content could not be received. Share up to 100 files or 1 MiB of text.", android.widget.Toast.LENGTH_LONG).show()
            return
        }
        if (host.incomingShares.offer(AndroidIncomingShareSource(applicationContext, payload))) {
            host.controller.cancelLauncherAction()
        } else {
            android.widget.Toast.makeText(this, "Finish or discard the pending share before sending more content.", android.widget.Toast.LENGTH_LONG).show()
        }
    }

    /**
     * The application left the foreground.
     *
     * The cover goes on first and the lock follows, because the snapshot is
     * taken as the activity stops: a lock that ran first would still leave the
     * unlocked frame in the picture if the cover were late.
     *
     * The lock runs on the controller's scope, not on this activity's. A back
     * press runs `onPause` and `onDestroy` in one pass, and `lifecycleScope`
     * dies with the second, so a lock launched here used to be cancelled at its
     * first suspension point and the session stayed open in a process the
     * platform keeps.
     */
    override fun onResume() {
        super.onResume()
        host.controller.foreground()
        host.endShareActivity()
        LauncherShortcuts.refresh(this)
    }

    override fun onPause() {
        host.privacy.setEnabled(true)
        host.deviceControl.stop()
        window.clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)
        super.onPause()
        // A configuration change is not the user leaving. The platform destroys
        // this activity and creates another one in the same task, in the
        // foreground, over the same session - §8.1 says there is no per-scene
        // vault state. Locking here would put the unlock screen in front of an
        // application that never left, which is the same false positive
        // `beginHostActivity` answers for the media picker. The cover above
        // still goes on, so the transition is covered either way.
        if (isChangingConfigurations) return
        host.controller.background()
    }

    override fun onStop() {
        super.onStop()
        // A permission dialog, a delete confirmation, or from API 30 the
        // device authentication prompt holds the lock above off, but it at
        // most pauses this activity. Stopping while one is up means the user
        // left, so every such prompt ends and the vault locks at once,
        // `ANDROID.md` §19.3; a picker or the API 29 credential screen, which
        // stops this activity itself, keeps the lock off.
        if (isChangingConfigurations) return
        host.controller.enteredBackground()
    }

    override fun onDestroy() {
        if (isFinishing) publicNoteExport.discard()
        super.onDestroy()
        // The window goes; the runtime, the repository and the engine stay,
        // because §14 gives them the life of the process and §8.1 has the next
        // activity share the one session. The two adapters that need a window
        // find none until one is attached again.
        if (host.activity === this) {
            host.activity = null
        }
    }
}

/** Run the native gate before either host entry point opens a runtime. */
internal fun runGate(context: Context): GateResult {
    val handshake = ChurVault.handshake()
    return gate(
        NativeHandshake(
            abiVersionMajor = handshake.major.toUInt(),
            abiVersionMinor = handshake.minor.toUInt(),
            capabilities = handshake.capabilities.toULong(),
            objectFormatMin = handshake.objectFormatMin.toUInt(),
            objectFormatMax = handshake.objectFormatMax.toUInt(),
            keySlotFormatMin = handshake.keySlotFormatMin.toUInt(),
            keySlotFormatMax = handshake.keySlotFormatMax.toUInt(),
            buildFlavor = handshake.buildFlavor.toUInt(),
        ),
        releaseApplication = !BuildConfigCompat.debuggable(context),
    )
}

/** Whether this build is debuggable, without generating a `BuildConfig`. */
internal object BuildConfigCompat {
    fun debuggable(context: Context): Boolean =
        context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0
}
