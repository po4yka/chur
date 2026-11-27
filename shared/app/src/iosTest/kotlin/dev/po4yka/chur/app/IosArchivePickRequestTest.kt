package dev.po4yka.chur.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
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

    @Test
    fun cancelDuringOpenReleasesTheProviderAndClosesALateSource() {
        val events = mutableListOf<String>()
        val request = IosArchivePickRequest { source, error ->
            assertNull(source)
            assertNull(error)
            events += "cancelled"
        }
        request.beginOpening { events += "provider stopped" }
        assertTrue(request.preparing)
        request.cancelled()
        assertFalse(request.preparing)
        request.opened(ArchiveSource(1) { events += "source closed" })
        request.openFailed()
        request.cancelled()
        assertEquals(listOf("cancelled", "provider stopped", "source closed"), events)
    }
}
