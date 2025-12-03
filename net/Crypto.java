package elrasseo.syreao.zvpn.net;

import android.util.Log;

import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypto {


    private static final String TAG = "Crypto";
    private static final SecureRandom random = new SecureRandom();

    private static volatile byte[] UDP_KEY = null;

    // ============================================================
    // KEY MANAGEMENT
    // ============================================================

    public static void setUdpKey(byte[] key) {
        if (key == null || key.length != 32) {
            Log.e(TAG, "Invalid UDP key length (must be 32 bytes)");
            UDP_KEY = null;
            return;
        }
        UDP_KEY = key.clone();
        Log.d(TAG, "UDP key set (AES-256-GCM)");
    }

    public static boolean hasUdpKey() {
        return UDP_KEY != null;
    }

    // ============================================================
    // AES-256-GCM ENCRYPTION
    // Packet format: [12-byte IV][ciphertext+tag]
    // ============================================================

    public static byte[] encryptUdp(byte[] plain) {
        try {
            if (UDP_KEY == null) return null;

            // 96-bit IV (recommended for GCM)
            byte[] iv = new byte[12];
            random.nextBytes(iv);

            SecretKeySpec keySpec = new SecretKeySpec(UDP_KEY, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv); // 128-bit tag

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

            byte[] enc = cipher.doFinal(plain);

            byte[] out = new byte[12 + enc.length];
            System.arraycopy(iv, 0, out, 0, 12);
            System.arraycopy(enc, 0, out, 12, enc.length);

            return out;

        } catch (Exception e) {
            Log.e(TAG, "encryptUdp error: " + e);
            return null;
        }
    }

    // ============================================================
    // AES-256-GCM DECRYPTION
    // ============================================================

    public static byte[] decryptUdp(byte[] packet, int len) {
        try {
            if (UDP_KEY == null) return null;
            if (len < 12 + 16) return null; // need IV + tag

            byte[] iv = new byte[12];
            System.arraycopy(packet, 0, iv, 0, 12);

            byte[] ciphertext = new byte[len - 12];
            System.arraycopy(packet, 12, ciphertext, 0, ciphertext.length);

            SecretKeySpec keySpec = new SecretKeySpec(UDP_KEY, "AES");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

            return cipher.doFinal(ciphertext);

        } catch (Exception e) {
            Log.e(TAG, "decryptUdp failed: " + e.getMessage());
            return null; // AEAD authentication failed → drop
        }
    }

}
