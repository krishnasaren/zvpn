package elrasseo.syreao.zvpn.net;

import android.util.Log;

import java.util.zip.Deflater;

public class PacketWriter {
    private static final String TAG = "PacketWriter";

    public static byte[] compress(byte[] src, int len) {
        try {
            if (src == null || len <= 0) return null;

            // Upper bound for zlib: original + 0.1% + 12 bytes
            int max = len + (len / 100) + 16;
            byte[] out = new byte[max];

            Deflater def = new Deflater(Deflater.BEST_SPEED, true);

            def.setInput(src, 0, len);
            def.finish();

            int outLen = def.deflate(out);
            def.end();

            // If compression didn't help → skip compress
            if (outLen <= 0 || outLen >= len) {
                return null;    // caller will send RAW
            }

            byte[] finalBuf = new byte[outLen];
            System.arraycopy(out, 0, finalBuf, 0, outLen);
            return finalBuf;

        } catch (Exception e) {
            Log.e(TAG, "compress() failed: " + e.getMessage());
            return null;
        }
    }
}
