package dev.po4yka.chur.app.onboarding

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow

enum class GuideStep(val target: String?, val informational: Boolean = false) {
    PUBLIC_APP(null, true), CHOOSE(null), PRIVACY(null, true), CREATE("create"), RESTORE("restore"), RESTORE_UNLOCK("restore-unlock"), RECOVERY("recovery"),
    IMPORT("import"), OPEN("open"), SEARCH("search"), LOCK("lock", true),
    AUTO_LOCK("auto-lock", true), UNLOCK("unlock-method", true), BACKUP("backup", true),
    DISCREET("discreet"), PET_GREET("pet"), PET_MOVE("pet"), PET_TREAT("treat"),
    PET_TOY("toy"), PET_SLEEP("sleep"),
}

data class GuideSession(val token: Long, val steps: List<GuideStep>, val index: Int = 0, val publicOnly: Boolean = false) {
    val step get() = steps[index]
}

/** Versioned completion only. It never stores a route, identity or a credential. */
class GuideStore(private val read: () -> String? = { null }, private val write: (String) -> Unit = {}) {
    fun status(): String? = read()?.also { require(it in setOf("1:seen", "1:complete", "1:skipped")) }
    fun record(value: String) { require(value in setOf("seen", "complete", "skipped")); status(); write("1:$value") }
}

class GuideCoordinator(private val store: GuideStore = GuideStore(), freshInstall: Boolean = false) {
    private val targetOwners = mutableMapOf<Pair<Any, String>, Boolean>()
    private val available = MutableStateFlow<Map<String, Boolean>>(emptyMap())
    val targets = available.asStateFlow()
    fun target(owner: Any, id: String, visible: Boolean) {
        if (targetOwners[owner to id] == visible) return
        targetOwners[owner to id] = visible
        publishTargets()
    }
    fun releaseTargets(owner: Any) {
        targetOwners.keys.filter { it.first === owner }.forEach(targetOwners::remove)
        publishTargets()
    }
    private fun publishTargets() { available.value = targetOwners.entries.groupBy { it.key.second }.mapValues { (_, entries) -> entries.any { it.value } } }
    private var serial = 0L
    var offerPetLesson = false
    var petLessonPending = false
        private set
    private val mutable = MutableStateFlow<GuideSession?>(null)
    val session = mutable.asStateFlow()
    val bootstrapAllowed: Boolean
    init {
        bootstrapAllowed = runCatching {
            val fresh = freshInstall && store.status() == null
            if (store.status() == null) store.record("seen")
            fresh
        }.getOrDefault(false)
        if (bootstrapAllowed) mutable.value = GuideSession(++serial, privateSteps)
    }
    fun chooseRestore() {
        val current = session.value ?: return
        if (current.publicOnly || current.step !in listOf(GuideStep.CREATE, GuideStep.RECOVERY)) return
        mutable.value = GuideSession(++serial, listOf(GuideStep.RESTORE, GuideStep.RESTORE_UNLOCK) + privateSteps.drop(4))
    }
    fun returnToCreation() {
        if (session.value?.step == GuideStep.RESTORE)
            mutable.value = GuideSession(++serial, privateSteps.drop(2))
    }
    fun startPrivate() { mutable.value = GuideSession(++serial, privateSteps.drop(3).filter { it != GuideStep.RECOVERY }) }
    fun startPublic(shell: dev.po4yka.chur.app.PublicShell) {
        if (shell == dev.po4yka.chur.app.PublicShell.PET) startPet()
        else mutable.value = GuideSession(++serial, listOf(GuideStep.PUBLIC_APP), publicOnly = true)
    }
    fun startPet() { mutable.value = GuideSession(++serial, petSteps, publicOnly = true) }
    fun event(step: GuideStep, token: Long? = session.value?.token) {
        val current = session.value ?: return
        if (current.token == token && current.step == step) advance()
    }
    fun skip() = advance()
    // Public lessons are not the private tutorial; they never rewrite its stored status.
    private fun finish(status: String) {
        val public = mutable.value?.publicOnly == true
        mutable.value = null; serial++
        if (!public) runCatching { store.record(status) }
    }
    fun stop() = finish("skipped")
    fun conceal() { mutable.value = null; serial++ }
    fun complete() {
        if (mutable.value?.publicOnly == false && offerPetLesson) petLessonPending = true
        finish("complete")
    }
    fun verifiedEntry() { if (offerPetLesson) petLessonPending = true; complete() }
    fun showPendingPetLesson() { if (petLessonPending) { petLessonPending = false; startPet() } }
    private fun advance() {
        val current = session.value ?: return
        if (current.index == current.steps.lastIndex) complete()
        else mutable.value = current.copy(index = current.index + 1)
    }
    companion object {
        val privateSteps = listOf(GuideStep.CHOOSE, GuideStep.PRIVACY, GuideStep.CREATE, GuideStep.RECOVERY,
            GuideStep.IMPORT, GuideStep.OPEN, GuideStep.SEARCH, GuideStep.LOCK, GuideStep.AUTO_LOCK,
            GuideStep.UNLOCK, GuideStep.BACKUP, GuideStep.DISCREET)
        val petSteps = listOf(GuideStep.PET_GREET, GuideStep.PET_MOVE, GuideStep.PET_TREAT, GuideStep.PET_TOY, GuideStep.PET_SLEEP)
    }
}

/** Must run before creating the runtime or any public store. Errors mean an existing install. */
expect fun platformGuideStore(settingsDirectory: String): GuideStore
