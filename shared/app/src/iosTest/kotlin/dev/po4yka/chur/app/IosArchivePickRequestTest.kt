package dev.po4yka.chur.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class IosArchivePickRequestTest {
    @Test
    fun openingFailureAndPickerDismissalHaveDifferentResults() {
        val messages = mutableListOf<String?>()
        fun request() = IosArchivePickRequest { source, error ->
            assertNull(source)
            messages += error
        }
        request().openFailed()
        request().cancelled()
        assertEquals(listOf("That file could not be opened.", null), messages)
    }
}
