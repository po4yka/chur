package dev.po4yka.chur.app.spirit

import android.app.Activity
import android.content.Context
import android.content.ContextWrapper
import android.opengl.Matrix
import android.view.Choreographer
import android.view.Surface
import android.view.TextureView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.findViewTreeLifecycleOwner
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.viewinterop.AndroidView
import com.google.android.filament.Camera
import com.google.android.filament.Engine
import com.google.android.filament.EntityManager
import com.google.android.filament.LightManager
import com.google.android.filament.Renderer
import com.google.android.filament.SwapChain
import com.google.android.filament.View
import com.google.android.filament.Viewport
import com.google.android.filament.android.UiHelper
import com.google.android.filament.gltfio.AssetLoader
import com.google.android.filament.gltfio.FilamentAsset
import com.google.android.filament.gltfio.Gltfio
import com.google.android.filament.gltfio.ResourceLoader
import com.google.android.filament.gltfio.UbershaderProvider
import com.google.android.filament.Filament
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import kotlin.math.exp

@Composable
internal actual fun SpiritSurface(state: SpiritRenderState, modifier: Modifier) {
    val context = LocalContext.current
    val bytes by produceState<ByteArray?>(null) {
        value = withContext(Dispatchers.IO) {
            runCatching { context.assets.open("chur_interactive.glb").use { it.readBytes() } }.getOrNull()
        }
    }
    var failed by remember { mutableStateOf(false) }
    var ready by remember { mutableStateOf(false) }
    val data = bytes
    Box(modifier) {
        if (data != null && !failed) {
            AndroidView(modifier = Modifier.fillMaxSize(),
                factory = { SpiritTexture(it, data, { shown -> ready = shown }) { failed = true } },
                update = { it.submit(state) },
                onRelease = { it.release() },
            )
        }
        if (data == null || failed || !ready) {
            // Loading/failure stays a usable, accessible public decoration.
            AndroidView(modifier = Modifier.fillMaxSize(), factory = { ctx -> android.widget.ImageView(ctx).apply {
                scaleType = android.widget.ImageView.ScaleType.FIT_CENTER
                runCatching { ctx.assets.open("chur_interactive_fallback.png").use {
                    setImageDrawable(android.graphics.drawable.Drawable.createFromStream(it, null))
                } }
                importantForAccessibility = android.view.View.IMPORTANT_FOR_ACCESSIBILITY_NO
                isClickable = false
            } })
        }
    }
}

/** One native surface/engine; it owns no app state, files beyond bundled art, or network access. */
private class SpiritTexture(context: Context, private val data: ByteArray, private val ready: (Boolean) -> Unit, private val failed: () -> Unit) :
    TextureView(context), Choreographer.FrameCallback {
    private var engine: Engine? = null
    private var helper: UiHelper? = null
    private var renderer: Renderer? = null
    private var view: View? = null
    private var camera: Camera? = null
    private var scene: com.google.android.filament.Scene? = null
    private var swapChain: SwapChain? = null
    private var loader: AssetLoader? = null
    private var resources: ResourceLoader? = null
    private var materials: UbershaderProvider? = null
    private var asset: FilamentAsset? = null
    private var loading = false
    private var light = 0
    private var eyes = intArrayOf()
    private var tails = intArrayOf()
    private var tailSignals = FloatArray(8)
    private var motionInputAge = 0f
    private var state = SpiritRenderState()
    private var clipTime = 0f
    private var animationIndex = emptyMap<String, Int>()
    private var poseInstances = intArrayOf()
    private var restPose = emptyArray<FloatArray>()
    private var authoredPose = emptyArray<FloatArray>()
    private var transitionPose: Array<FloatArray>? = null
    private var authoredReady = false
    private var tailPoseIndex = intArrayOf()
    private var tailInstances = intArrayOf()
    private var eyeInstances = intArrayOf()
    private var rootInstance = 0
    private val leanTransform = FloatArray(16)
    private val tailScratch = FloatArray(16)
    private var transitionTime = 0f
    private var displayedAperture = 1f
    private var transitionAperture = 1f
    private var lastFrame = 0L
    private var running = false
    private var resumed = false
    private var released = false
    private var dirty = true
    private var lean = 0f
    private var visibilityPolling = false
    private val visibleRect = android.graphics.Rect()
    private val visibilityPoll = Runnable { visibilityPolling = false; dirty = true; schedule() }
    private val frameClock = Choreographer.getInstance()
    private val hostActivity = generateSequence(context) { (it as? ContextWrapper)?.baseContext }
        .filterIsInstance<Activity>().firstOrNull()
    private var hostLifecycle: Lifecycle? = null
    private val lifecycleObserver = LifecycleEventObserver { _, event ->
        resumed = hostLifecycle?.currentState?.isAtLeast(Lifecycle.State.RESUMED) == true
        if (event == Lifecycle.Event.ON_DESTROY) release()
        else if (resumed) { dirty = true; schedule() } else stop()
    }

    init { isOpaque = false; isClickable = false; isFocusable = false
        importantForAccessibility = android.view.View.IMPORTANT_FOR_ACCESSIBILITY_NO }

    fun submit(value: SpiritRenderState) {
        if (value.clipSerial != state.clipSerial || value.clip != state.clip || value.reducedMotion != state.reducedMotion) {
            transitionPose = if (authoredReady) Array(authoredPose.size) { authoredPose[it].copyOf() } else null
            transitionTime = 0f
            transitionAperture = displayedAperture
            clipTime = 0f
        }
        if (value.reducedMotion) { lean = 0f; tailSignals.fill(0f); transitionPose = null; displayedAperture = 1f; transitionAperture = 1f }
        if (state != value) dirty = true
        if (value.reducedMotion) motionInputAge = Float.POSITIVE_INFINITY
        else if (value.motionSerial != state.motionSerial) motionInputAge = 0f
        state = value
        schedule()
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        released = false
        hostLifecycle = (findViewTreeLifecycleOwner() ?: hostActivity as? LifecycleOwner)?.lifecycle
        resumed = hostLifecycle?.currentState?.isAtLeast(Lifecycle.State.RESUMED) == true
        hostLifecycle?.addObserver(lifecycleObserver)
        try { createRenderer(); schedule() } catch (_: Exception) { release(); failed() }
        catch (_: LinkageError) { release(); failed() }
    }
    override fun onDetachedFromWindow() { release(); super.onDetachedFromWindow() }
    override fun onWindowVisibilityChanged(visibility: Int) {
        super.onWindowVisibilityChanged(visibility)
        if (engine == null) return
        if (visibility == VISIBLE) { dirty = true; schedule() } else stop()
    }

    override fun onVisibilityChanged(changedView: android.view.View, visibility: Int) {
        super.onVisibilityChanged(changedView, visibility)
        if (engine == null) return
        if (visibility == VISIBLE) { dirty = true; schedule() } else stop()
    }

    private fun createRenderer() {
        // A reattached view builds a new engine; show the poster again until its first frame.
        ready(false)
        Filament.init(); Gltfio.init()
        val e = Engine.create().also { engine = it }
        val r = e.createRenderer().also { renderer = it }
        r.clearOptions = Renderer.ClearOptions().apply { clear = true; clearColor = doubleArrayOf(0.0, 0.0, 0.0, 0.0) }
        val s = e.createScene().also { scene = it }
        val c = e.createCamera(EntityManager.get().create()).also { camera = it }
        c.setExposure(16f, 1f / 125f, 100f)
        c.lookAt(0.0, 0.0, 4.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0)
        val v = e.createView().also { view = it }
        v.scene = s; v.camera = c; v.blendMode = View.BlendMode.TRANSLUCENT
        v.isPostProcessingEnabled = false
        light = EntityManager.get().create()
        LightManager.Builder(LightManager.Type.SUN).color(1f, .96f, .9f).intensity(100_000f)
            .direction(-.4f, -.6f, -1f).castShadows(false).build(e, light)
        s.addEntity(light)
        val provider = UbershaderProvider(e).also { materials = it }
        val al = AssetLoader(e, provider, EntityManager.get()).also { loader = it }
        val a = checkNotNull(al.createAsset(ByteBuffer.allocateDirect(data.size).apply { put(data); flip() }))
        asset = a
        val rl = ResourceLoader(e).also { resources = it }
        // Decode textures on Filament's worker threads; doFrame uploads them as they finish.
        check(rl.asyncBeginLoad(a)) { "Resource load failed" }
        loading = true
        eyes = a.entities.filter { a.getName(it) == "Spirit_Eye_L" || a.getName(it) == "Spirit_Eye_R" }.toIntArray()
        check(eyes.size == 2) { "Eye contract mismatch" }
        eyeInstances = IntArray(2) { e.renderableManager.getInstance(eyes[it]) }
        check(eyeInstances.all { it != 0 && e.renderableManager.getMorphTargetCount(it) == 11 }) { "Eye contract mismatch" }
        check(eyes.all { a.getMorphTargetNames(it).toList() == apertureNames }) { "Eye morph contract mismatch" }
        val animator = a.instance.animator
        animationIndex = (0 until animator.animationCount).associate { animator.getAnimationName(it) to it }
        check(animationIndex.keys.containsAll(requiredClips)) { "Animation contract mismatch" }
        tails = spiritTailJoints.map { joint -> a.entities.firstOrNull { a.getName(it) == joint.name } ?: 0 }.toIntArray()
        check(tails.none { it == 0 }) { "Tail contract mismatch" }
        val tm = e.transformManager
        val poseEntities = a.entities.filter { it != a.root && tm.getInstance(it) != 0 }
        poseInstances = IntArray(poseEntities.size) { tm.getInstance(poseEntities[it]) }
        restPose = Array(poseEntities.size) { tm.getTransform(poseInstances[it], null) }
        authoredPose = Array(poseEntities.size) { FloatArray(16) }
        authoredReady = false; transitionPose = null
        tailPoseIndex = IntArray(tails.size) { poseEntities.indexOf(tails[it]) }
        check(tailPoseIndex.none { it < 0 }) { "Tail contract mismatch" }
        tailInstances = IntArray(tails.size) { tm.getInstance(tails[it]) }
        rootInstance = tm.getInstance(a.root)
        // The small animated mesh must not be culled by imported bind-pose bounds.
        for (entity in a.entities) {
            val renderable = e.renderableManager.getInstance(entity)
            if (renderable != 0) e.renderableManager.setCulling(renderable, false)
        }
        s.addEntities(a.entities)
        val ui = UiHelper(UiHelper.ContextErrorPolicy.DONT_CHECK).also { helper = it }
        ui.isOpaque = false
        ui.renderCallback = object : UiHelper.RendererCallback {
            override fun onNativeWindowChanged(surface: Surface) {
                swapChain?.let { e.destroySwapChain(it) }
                swapChain = e.createSwapChain(surface, SwapChain.CONFIG_TRANSPARENT)
                dirty = true; schedule()
            }
            override fun onDetachedFromSurface() {
                stop(); swapChain?.let { e.destroySwapChain(it) }; swapChain = null; e.flushAndWait()
            }
            override fun onResized(w: Int, h: Int) {
                v.viewport = Viewport(0, 0, w, h)
                val aspect = w.coerceAtLeast(1).toDouble() / h.coerceAtLeast(1)
                val vertical = 1.125 * maxOf(1.0, 1.0 / aspect)
                c.setProjection(Camera.Projection.ORTHO, -vertical * aspect, vertical * aspect, -vertical, vertical, .1, 10.0)
                dirty = true; schedule()
            }
        }
        ui.attachTo(this)
        // Keep the poster until the TextureView has a frame, not merely until
        // Filament has loaded the GLB. GPU initialization can take several frames.
        val delegate = surfaceTextureListener
        surfaceTextureListener = object : SurfaceTextureListener {
            private var delivered = false
            override fun onSurfaceTextureAvailable(texture: android.graphics.SurfaceTexture, width: Int, height: Int) {
                delegate?.onSurfaceTextureAvailable(texture, width, height)
            }
            override fun onSurfaceTextureSizeChanged(texture: android.graphics.SurfaceTexture, width: Int, height: Int) {
                delegate?.onSurfaceTextureSizeChanged(texture, width, height)
            }
            override fun onSurfaceTextureDestroyed(texture: android.graphics.SurfaceTexture): Boolean =
                delegate?.onSurfaceTextureDestroyed(texture) ?: true
            override fun onSurfaceTextureUpdated(texture: android.graphics.SurfaceTexture) {
                delegate?.onSurfaceTextureUpdated(texture)
                if (!delivered && !released) { delivered = true; ready(true) }
            }
        }
    }

    private fun hierarchyVisible(): Boolean {
        var node: android.view.View? = this
        while (node != null) {
            if (node.visibility != VISIBLE || node.alpha <= 0f) return false
            node = node.parent as? android.view.View
        }
        // Compose scrolls or clips an AndroidView without changing its visibility; skip frames nobody can see.
        return isShown && getGlobalVisibleRect(visibleRect)
    }
    private fun schedule() {
        // Ancestor alpha changes have no reliable child callback. Poll only
        // while active+attached and hidden, never keep GPU frames alive.
        if (!released && engine != null && isAttachedToWindow && resumed && windowVisibility == VISIBLE && !hierarchyVisible()) {
            if (!visibilityPolling) { visibilityPolling = true; postDelayed(visibilityPoll, 200L) }
            return
        }
        removeCallbacks(visibilityPoll); visibilityPolling = false
        if (!released && engine != null && swapChain != null && !running && shouldScheduleSpiritFrame(
                isAttachedToWindow, resumed, hierarchyVisible() && windowVisibility == VISIBLE, dirty, state.reducedMotion)) {
            running = true; frameClock.postFrameCallback(this)
        }
    }
    private fun stop() { removeCallbacks(visibilityPoll); visibilityPolling = false; frameClock.removeFrameCallback(this); running = false; lastFrame = 0L; motionInputAge = Float.POSITIVE_INFINITY }

    override fun doFrame(time: Long) {
        running = false
        val e = engine ?: return
        if (!resumed || released || !hierarchyVisible() || windowVisibility != VISIBLE) { lastFrame = 0L; motionInputAge = Float.POSITIVE_INFINITY; schedule(); return }
        val dt = if (lastFrame == 0L) 0f else ((time - lastFrame) / 1e9f).coerceAtLeast(0f)
        // 30fps cap with slack: vsync timestamps jitter, and a strict 33.3ms gate skips every other frame (20fps at 60Hz).
        if (lastFrame != 0L && time - lastFrame < 30_000_000L) { schedule(); return }
        lastFrame = time
        clipTime += dt; transitionTime += dt; motionInputAge += dt
        val a = asset ?: return
        if (loading) {
            val rl = resources ?: return
            rl.asyncUpdateLoad()
            if (rl.asyncGetLoadProgress() < 1f) { schedule(); return }
            loading = false
            a.releaseSourceData()
        }
        val animator = a.instance.animator
        // Export optimizes constant channels out of some clips. Restore rest first,
        // otherwise an interrupted tap can leave MotionRoot rotated during a hold.
        val tm = e.transformManager
        for (i in poseInstances.indices) tm.setTransform(poseInstances[i], restPose[i])
        val sample = sampleSpiritClip(state.clip, clipTime, state.reducedMotion)
        val index = animationIndex[sample.name]
        if (index != null) animator.applyAnimation(index, sample.seconds)
        // Snapshot the actually displayed authored pose, including an interrupted blend.
        // This avoids a snap when a fast drag-release interrupts an earlier transition.
        val alpha = (transitionTime / .12f).coerceIn(0f, 1f).let { it * it * (3f - 2f * it) }
        val previousPose = transitionPose
        for (i in poseInstances.indices) {
            val buffer = authoredPose[i]
            tm.getTransform(poseInstances[i], buffer)
            val previous = previousPose?.get(i)
            if (previous != null && alpha < 1f && !state.reducedMotion) {
                val blended = blendSpiritPose(previous, buffer, alpha)
                if (blended !== buffer) System.arraycopy(blended, 0, buffer, 0, 16)
            }
            tm.setTransform(poseInstances[i], buffer)
        }
        authoredReady = true
        if (alpha >= 1f) transitionPose = null
        val motionSignal = if (state.reducedMotion || motionInputAge > .08f) 0f else state.dragX
        lean += ((-motionSignal * 12f) - lean) * (1f - exp(-dt * 12f))
        Matrix.setIdentityM(leanTransform, 0); Matrix.rotateM(leanTransform, 0, lean, 0f, 0f, 1f)
        tm.setTransform(rootInstance, leanTransform)
        // Eye overrides happen AFTER clip evaluation. No TRS crossfade can corrupt aperture weights.
        val targetAperture = SpiritEyes.aperture(sample, state.reducedMotion)
        displayedAperture = if (state.reducedMotion) targetAperture else
            transitionAperture * (1f - alpha) + targetAperture * alpha
        val weights = SpiritEyes.weights(displayedAperture)
        for (instance in eyeInstances) e.renderableManager.setMorphWeights(instance, weights, 0)
        tailSignals = advanceSpiritTail(tailSignals, -motionSignal, dt, state.reducedMotion)
        for (i in tailInstances.indices) {
            val joint = spiritTailJoints[i]
            val pose = tailScratch
            System.arraycopy(authoredPose[tailPoseIndex[i]], 0, pose, 0, 16)
            Matrix.rotateM(pose, 0, tailSignals[i] * joint.maxRadians * (180f / Math.PI.toFloat()),
                joint.axis[0], joint.axis[1], joint.axis[2])
            tm.setTransform(tailInstances[i], pose)
        }
        animator.updateBoneMatrices()
        val swap = swapChain
        if (swap != null && helper?.isReadyToRender == true) {
            if (renderer!!.beginFrame(swap, time)) { renderer!!.render(view!!); renderer!!.endFrame(); dirty = false }
        }
        // Reduced motion has no continuous render loop after the requested static frame.
        if (!state.reducedMotion || dirty) schedule()
    }

    fun release() {
        if (released) return
        released = true; stop(); hostLifecycle?.removeObserver(lifecycleObserver)
        val e = engine ?: return
        helper?.detach(); helper = null
        if (loading) { resources?.asyncCancelLoad(); loading = false }
        asset?.let { scene?.removeEntities(it.entities); loader?.destroyAsset(it) }; asset = null
        animationIndex = emptyMap(); poseInstances = intArrayOf(); restPose = emptyArray(); authoredPose = emptyArray(); transitionPose = null; authoredReady = false
        tailPoseIndex = intArrayOf(); tailInstances = intArrayOf(); eyeInstances = intArrayOf(); rootInstance = 0
        resources?.destroy(); resources = null
        loader?.destroy(); loader = null
        materials?.destroyMaterials(); materials?.destroy(); materials = null
        if (light != 0) { e.destroyEntity(light); EntityManager.get().destroy(light); light = 0 }
        camera?.let { e.destroyCameraComponent(it.entity); EntityManager.get().destroy(it.entity) }; camera = null
        view?.let { e.destroyView(it) }; view = null
        scene?.let { e.destroyScene(it) }; scene = null
        renderer?.let { e.destroyRenderer(it) }; renderer = null
        e.destroy(); engine = null
    }
}

private val requiredClips: List<String> = listOf("idle_soft", "notice", "tap_react", "hold_enter", "hold_loop",
    "release_settle", "sleep_enter", "sleep_loop", "wake")
private val apertureNames: List<String> = listOf("Aperture_00000", "Aperture_00025", "Aperture_00050", "Aperture_00100",
    "Aperture_00250", "Aperture_00750", "Aperture_01500", "Aperture_03000", "Aperture_05000", "Aperture_07000", "Aperture_08500")
