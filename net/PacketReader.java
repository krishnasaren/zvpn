package elrasseo.syreao.zvpn.net;

import android.util.Log;

import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

public class PacketReader {
    private static final String TAG = "PacketReader";

    // Max expected frame (TUN MTU)
    private static final int MAX_OUT = 2000;

    public static byte[] decompress(byte[] src, int len) {

        if (src == null || len <= 0) return null;

        Inflater inflater = new Inflater(true); // raw DEFLATE (no zlib header)

        try {
            inflater.setInput(src, 0, len);

            byte[] out = new byte[MAX_OUT];
            int outLen = inflater.inflate(out);

            inflater.end();

            // If inflate produced 0 bytes → not compressed → return RAW
            if (outLen == 0) {
                return rawFallback(src, len);
            }

            // Valid compressed packet
            byte[] finalBuf = new byte[outLen];
            System.arraycopy(out, 0, finalBuf, 0, outLen);
            return finalBuf;

        } catch (DataFormatException e) {
            // Not compressed → RAW packet
            return rawFallback(src, len);

        } catch (Exception e) {
            Log.e(TAG, "decompress error: " + e);
            return null;
        }
    }

    private static byte[] rawFallback(byte[] src, int len) {
        byte[] raw = new byte[len];
        System.arraycopy(src, 0, raw, 0, len);
        return raw;
    }
}
