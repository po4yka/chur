package dev.po4yka.chur.android;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.graphics.Bitmap;
import android.graphics.Color;
import android.net.Uri;
import android.os.ParcelFileDescriptor;
import android.provider.OpenableColumns;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

/** Generated public bytes in a separate test APK process, without host dependencies. */
public final class IncomingShareFixtureProvider extends ContentProvider {
    public static final Uri uri = Uri.parse("content://dev.po4yka.chur.test.incoming-share/file");

    @Override public boolean onCreate() { return true; }
    @Override public String getType(Uri source) {
        if ("jpeg-xl".equals(source.getLastPathSegment())) return "image/jpeg";
        if ("image".equals(source.getLastPathSegment())) return "image/png";
        if ("invalid-image".equals(source.getLastPathSegment())) return "image/jpeg";
        return "application/octet-stream";
    }
    @Override public Cursor query(Uri source, String[] projection, String selection, String[] selectionArgs, String sortOrder) {
        MatrixCursor cursor = new MatrixCursor(new String[]{OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE});
        cursor.addRow(new Object[]{"image".equals(source.getLastPathSegment()) ? "shared-image.png" : "../shared-report.bin", sourceBytes(source).length + ("truncated".equals(source.getLastPathSegment()) ? 1 : 0)});
        return cursor;
    }
    @Override public ParcelFileDescriptor openFile(Uri source, String mode) throws FileNotFoundException {
        if (!"r".equals(mode)) throw new FileNotFoundException();
        try {
            ParcelFileDescriptor[] pipe = ParcelFileDescriptor.createPipe();
            new Thread(() -> {
                try (ParcelFileDescriptor.AutoCloseOutputStream output = new ParcelFileDescriptor.AutoCloseOutputStream(pipe[1])) {
                    if ("slow-archive".equals(source.getLastPathSegment())) {
                        output.write("CHURBAK1".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                        for (int i = 0; i < 300; i++) {
                            android.os.SystemClock.sleep(100);
                            output.write(0);
                        }
                    } else {
                        output.write(sourceBytes(source));
                    }
                } catch (IOException ignored) { /* A cancelled reader closes its pipe. */ }
            }).start();
            return pipe[0];
        } catch (IOException failure) { throw new FileNotFoundException(); }
    }
    @Override public Uri insert(Uri source, ContentValues values) { return null; }
    @Override public int delete(Uri source, String selection, String[] selectionArgs) { return 0; }
    @Override public int update(Uri source, ContentValues values, String selection, String[] selectionArgs) { return 0; }

    private byte[] sourceBytes(Uri source) {
        if (!"jpeg-xl".equals(source.getLastPathSegment()) &&
            !"jpeg-xl-generic".equals(source.getLastPathSegment())) return fixtureBytes(source);
        try (java.io.InputStream input = getContext().getAssets().open("jpeg-xl/still-container.jxl")) {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] block = new byte[8192];
            int count;
            while ((count = input.read(block)) >= 0) output.write(block, 0, count);
            return output.toByteArray();
        } catch (IOException failure) { throw new IllegalStateException("JPEG XL test fixture missing", failure); }
    }

    public static byte[] fixtureBytes() { return fixtureBytes(uri); }
    public static byte[] fixtureBytes(Uri source) {
        if (!"image".equals(source.getLastPathSegment())) {
            byte[] bytes = new byte[81923];
            for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) (i % 251);
            return bytes;
        }
        Bitmap bitmap = Bitmap.createBitmap(24, 24, Bitmap.Config.ARGB_8888);
        bitmap.eraseColor(Color.BLUE);
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            bitmap.compress(Bitmap.CompressFormat.PNG, 100, output);
            return output.toByteArray();
        } finally { bitmap.recycle(); }
    }
}
