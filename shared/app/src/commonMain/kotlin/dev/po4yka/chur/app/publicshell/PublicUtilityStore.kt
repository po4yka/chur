package dev.po4yka.chur.app.publicshell

import androidx.compose.runtime.staticCompositionLocalOf
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.*

/** Public utility data only. A transition code never authenticates a vault. */
class PublicUtilityStore(
    private val read: (String) -> String? = { null },
    private val write: (String, String) -> Unit = { _, _ -> },
) {
    private val _discreet = MutableStateFlow(runCatching { configuration()["enabled"]?.jsonPrimitive?.boolean == true }.getOrDefault(true))
    val discreet = _discreet.asStateFlow()
    private val _appearance = MutableStateFlow(runCatching { readAppearance() }.getOrDefault("system"))
    private fun readAppearance(): String {
        val raw = read("appearance") ?: return "system"
        val document = Json.parseToJsonElement(raw).jsonObject
        require(document["version"]?.jsonPrimitive?.int == 1) { "Unsupported appearance version" }
        return document.getValue("mode").jsonPrimitive.content.also { require(it in listOf("system", "light", "dark")) }
    }
    val appearance = _appearance.asStateFlow()
    private fun configuration(): JsonObject {
        val raw = read("entry") ?: return buildJsonObject { put("version", 1); put("enabled", false) }
        val value = Json.parseToJsonElement(raw).jsonObject
        require(value["version"]?.jsonPrimitive?.int == 1) { "Unsupported settings version" }
        return value
    }
    fun matches(code: String): Boolean {
        if (!_discreet.value || !validCode(code)) return false
        return runCatching { configuration()["digest"]?.jsonPrimitive?.content == publicCodeDigest(code) }.getOrDefault(false)
    }
    fun configure(code: String) {
        require(validCode(code))
        configureDigest(publicCodeDigest(code))
    }
    internal fun configureDigest(digest: String) {
        require(digest.length == 64 && digest.all { it in "0123456789abcdef" })
        configuration() // Refuse to overwrite an unsupported document.
        write("entry", buildJsonObject { put("version", 1); put("enabled", true); put("digest", digest) }.toString())
        _discreet.value = true
    }
    fun disable() {
        configuration()
        write("entry", "{\"version\":1,\"enabled\":false}")
        _discreet.value = false
    }
    fun setAppearance(value: String) {
        require(value in listOf("system", "light", "dark"))
        readAppearance()
        write("appearance", buildJsonObject { put("version", 1); put("mode", value) }.toString())
        _appearance.value = value
    }
    fun history(): List<Calculation> {
        val raw = read("calculator") ?: return emptyList()
        require(raw.length <= 512 * 1024)
        val document = Json.parseToJsonElement(raw).jsonObject
        require(document["version"]?.jsonPrimitive?.int == 1) { "Unsupported history version" }
        return document.getValue("items").jsonArray.take(500).map {
            val item = it.jsonObject
            Calculation(item.getValue("expression").jsonPrimitive.content, item.getValue("result").jsonPrimitive.content)
                .also { row -> require(row.expression.length <= 512 && row.result.length <= 64) }
        }
    }
    internal fun appendCalculation(row: Calculation): List<Calculation> =
        (listOf(row) + history()).take(500).also(::writeHistory)

    fun saveHistory(items: List<Calculation>) {
        history() // Never overwrite unknown versions or corrupt data.
        writeHistory(items)
    }

    private fun writeHistory(items: List<Calculation>) {
        require(items.size <= 500 && items.all { it.expression.length <= 512 && it.result.length <= 64 })
        val encoded = buildJsonObject {
            put("version", 1)
            putJsonArray("items") { items.forEach { row -> add(buildJsonObject {
                put("expression", row.expression); put("result", row.result)
            }) } }
        }.toString()
        require(encoded.encodeToByteArray().size <= 512 * 1024)
        write("calculator", encoded)
    }
    companion object { fun validCode(value: String) = value.length == 8 && value.all { it in '0'..'9' } }
}

data class Calculation(val expression: String, val result: String)
val LocalPublicUtilities = staticCompositionLocalOf { PublicUtilityStore() }
internal expect fun publicCodeDigest(value: String): String
internal expect fun publicDecimalSeparator(): String
/** Fixed names, bounded reads and atomic writes; entry settings are excluded from backup. */
expect fun publicUtilityStore(publicDirectory: String, settingsDirectory: String): PublicUtilityStore
