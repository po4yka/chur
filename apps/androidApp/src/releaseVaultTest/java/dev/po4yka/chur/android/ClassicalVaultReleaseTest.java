package dev.po4yka.chur.android;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.*;

import android.app.Activity;
import android.app.Instrumentation;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.os.SystemClock;
import android.view.accessibility.AccessibilityNodeInfo;
import android.content.pm.ApplicationInfo;
import android.util.Log;
import dev.po4yka.chur.ffi.ChurJni;
import java.util.function.Predicate;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Opens the historical vault in the release package's process through its shipped JNI. */
public class ClassicalVaultReleaseTest extends Instrumentation {
    @Override public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        start();
    }

    @Override public void onStart() {
        // Use the framework runner contract. Only the target supplies the release JNI.
        Bundle status = new Bundle();
        status.putString("id", "ClassicalVaultRelease");
        status.putString("class", getClass().getName());
        status.putString("test", "releaseReadsClassicalVaultAndOriginal");
        status.putInt("current", 1);
        status.putInt("numtests", 1);
        sendStatus(1, status);
        try {
            releaseReadsClassicalVaultAndOriginal();
            sendStatus(0, status);
            finish(Activity.RESULT_OK, new Bundle());
        } catch (Throwable error) {
            status.putString("stack", Log.getStackTraceString(error));
            sendStatus(-2, status);
            finish(Activity.RESULT_CANCELED, status);
        }
    }

    private void releaseReadsClassicalVaultAndOriginal() throws Exception {
        Context target = getTargetContext();
        assertEquals("dev.po4yka.chur", target.getPackageName());
        assertEquals(0, target.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE);
        ChurJni jni = ChurJni.INSTANCE;
        assertEquals(7, jni.abiVersionMajor());
        // This is the production storageRoot() of ChurHost. A managed device starts clean.
        Path root = Files.createDirectory(target.getFilesDir().toPath().resolve("chur"));
        long[] runtime = {0}, session = {0}, reader = {0};
        try {
            try (ZipInputStream zip = new ZipInputStream(getContext().getAssets().open("vault.zip"))) {
                for (ZipEntry entry; (entry = zip.getNextEntry()) != null; ) {
                    Path path = root.resolve(entry.getName()).normalize();
                    assertTrue("fixture path outside vault root", path.startsWith(root));
                    if (entry.isDirectory()) {
                        Files.createDirectories(path);
                    } else {
                        Files.createDirectories(path.getParent());
                        Files.copy(zip, path);
                    }
                }
            }
            assertEquals("open", 0, jni.runtimeOpen(root.toString(), runtime));
            byte[] present = {0};
            assertEquals("presence", 0, jni.vaultPresent(runtime[0], present));
            assertEquals(1, present[0]);
            byte[] password = "Chur public compatibility fixture 2026".getBytes(UTF_8);
            assertEquals("unlock", 0, jni.vaultUnlock(runtime[0], 1, password, session));

            int[] written = {0};
            ByteBuffer identity = ByteBuffer.allocateDirect(64 * 1024);
            assertEquals("existing classical identity", 0, jni.sharingIdentity(session[0], identity, written));
            assertTrue(written[0] >= 98);
            assertEquals("identity record version", 1, identity.getShort());
            assertBytes(identity, hex("13425f5e0834ba5f815dfd9758e16e88"));
            assertBytes(identity, hex("286fdccd12d920a874919587d9e54f64"));

            assertBytes(identity, hex("eab1eae044a445f9cb05f8c5b5e7d41f1307c48036429fb4c2fc7299baed82c8"));

            byte[] object = hex("df8bdc3d3cb1a831a21b56f321c39808");
            byte[] proof = "Chur classical vault compatibility fixture\n".getBytes(UTF_8);
            assertEquals("open original", 0, jni.objectReaderOpen(session[0], object, 1, reader));
            long[] size = {0};
            assertEquals("size", 0, jni.objectReaderSize(reader[0], size));
            assertEquals(proof.length, size[0]);
            ByteBuffer original = ByteBuffer.allocateDirect(proof.length);
            assertEquals("read original", 0, jni.objectReaderReadAt(reader[0], 0, original, written));
            assertEquals(proof.length, written[0]);
            assertBytes(original, proof);
            assertEquals("authenticate all chunks", 0, jni.objectReaderVerifyComplete(reader[0], new int[1]));
        } finally {
            if (reader[0] != 0) jni.objectReaderClose(reader[0]);
            if (session[0] != 0) jni.sessionClose(session[0]);
            if (runtime[0] != 0) jni.runtimeClose(runtime[0]);

        }
        verifyReleaseEntry(target);
    }

    private void verifyReleaseEntry(Context target) {
        Instrumentation instrumentation = this;
        Intent launch = target.getPackageManager().getLaunchIntentForPackage(target.getPackageName());
        assertNotNull(launch);
        Activity activity = instrumentation.startActivitySync(launch);
        try {
            click(instrumentation, "Settings");
            click(instrumentation, "Private vault");
            AccessibilityNodeInfo password = await(instrumentation, AccessibilityNodeInfo::isEditable, "password field");
            Bundle value = new Bundle();
            value.putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE,
                    "Chur public compatibility fixture 2026");
            assertTrue("enter historical vault password", password.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, value));
            click(instrumentation, "Unlock");
            await(instrumentation, node -> label(node, "Lock now"), "unlocked vault");
        } finally {
            instrumentation.runOnMainSync(activity::finish);
        }
    }

    private static void click(Instrumentation instrumentation, String text) {
        AccessibilityNodeInfo node = await(instrumentation, item -> label(item, text), text);
        while (node != null && !node.isClickable()) node = node.getParent();
        assertNotNull("clickable control for " + text, node);
        assertTrue("click " + text, node.performAction(AccessibilityNodeInfo.ACTION_CLICK));
    }

    private static boolean label(AccessibilityNodeInfo node, String text) {
        return text.contentEquals(node.getText() == null ? "" : node.getText())
                || text.contentEquals(node.getContentDescription() == null ? "" : node.getContentDescription());
    }

    private static AccessibilityNodeInfo await(Instrumentation instrumentation,
            Predicate<AccessibilityNodeInfo> match, String description) {
        long deadline = SystemClock.uptimeMillis() + 30_000;
        do {
            AccessibilityNodeInfo found = find(instrumentation.getUiAutomation().getRootInActiveWindow(), match);
            if (found != null) return found;
            SystemClock.sleep(100);
        } while (SystemClock.uptimeMillis() < deadline);
        throw new AssertionError("Release UI did not reach " + description);
    }

    private static AccessibilityNodeInfo find(AccessibilityNodeInfo node, Predicate<AccessibilityNodeInfo> match) {
        if (node == null) return null;
        if (match.test(node)) return node;
        for (int i = 0; i < node.getChildCount(); i++) {
            AccessibilityNodeInfo found = find(node.getChild(i), match);
            if (found != null) return found;
        }
        return null;
    }

    private static void assertBytes(ByteBuffer source, byte[] expected) {
        byte[] actual = new byte[expected.length];
        source.get(actual);
        assertArrayEquals(expected, actual);
    }

    private static byte[] hex(String value) {
        byte[] out = new byte[value.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(value.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }
}
