package elrasseo.syreao.zvpn.net;

import android.content.Context;
import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Collections;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import elrasseo.syreao.zvpn.util.Prefs;

public class TcpTlsChannel {

    // ============================================================
    // CALLBACKS
    // ============================================================

    public interface Listener {
        // Unified config callback
        void onCfgReceived(String cfgLine, byte[] udpKey);
        void onDisconnected(Exception e);
    }

    public interface PacketHandler {
        void onPacket(byte[] data, int length);
    }

    private static final String TAG = "TcpTlsChannel";

    private final Context context;
    private final String serverIp;
    private final int serverPort;

    private SSLSocket socket;
    private InputStream in;
    private OutputStream out;

    private volatile boolean running = false;
    private Listener listener;

    // ============================================================
    // CONSTRUCTOR
    // ============================================================

    public TcpTlsChannel(Context ctx, String ip, int port) {
        this.context = ctx.getApplicationContext();
        this.serverIp = ip;
        this.serverPort = port;
    }

    public boolean isRunning() {
        return running &&
                socket != null &&
                socket.isConnected() &&
                !socket.isClosed();
    }

    // ============================================================
    // CONNECT
    // ============================================================

    public void connect(Listener listener) throws Exception {
        this.listener = listener;

        SSLContext sslContext = createTrustAllContext();
        SSLSocketFactory factory = sslContext.getSocketFactory();

        socket = (SSLSocket) factory.createSocket();
        socket.setEnableSessionCreation(true);
        socket.setUseClientMode(true);
        socket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});

        // IMPORTANT: no read timeout here, otherwise idle VPN will drop
        socket.setSoTimeout(20000);

        SSLParameters params = socket.getSSLParameters();
        params.setServerNames(Collections.singletonList(new SNIHostName(serverIp)));
        socket.setSSLParameters(params);

        try {
            socket.connect(new InetSocketAddress(serverIp, serverPort), 6000);
            Log.d(TAG, "TLS connected: " + serverIp + ":" + serverPort);
        } catch (Exception e) {
            Log.e(TAG, "TLS connect failed", e);
            safeClose();
            throw e;
        }

        // If you want explicit handshake:
        try {
            socket.startHandshake();
        } catch (IOException e) {
            Log.e(TAG, "TLS handshake failed", e);
            safeClose();
            throw e;
        }

        in = socket.getInputStream();
        out = socket.getOutputStream();

        Log.d(TAG, "Performing AUTH + CFG + UDP key...");
        performHandshakeAndCfg();     // may throw on error

        running = true;
    }

    // ============================================================
    // TRUST ALL CERTS (dev mode)
    // ============================================================

    private SSLContext createTrustAllContext() throws Exception {
        TrustManager[] tm = new TrustManager[]{
                new X509TrustManager() {
                    public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String a) {}
                    public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String a) {}
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return new java.security.cert.X509Certificate[0];
                    }
                }
        };

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tm, new SecureRandom());
        return ctx;
    }

    // ============================================================
    // HANDSHAKE + CFG + UDP KEY
    // Robust against partial TCP reads
    // ============================================================

    private void performHandshakeAndCfg() throws IOException {
        // 1) Wait for "AUTH_REQ"
        readExactToken("AUTH_REQ");
        Log.d(TAG, "AUTH_REQ received");

        // 2) Send token
        String token = Prefs.get(context).getToken();
        if (token == null) token = "";
        out.write((token + "\n").getBytes(StandardCharsets.UTF_8));
        out.flush();

        // 3) Wait for "AUTH_OK"
        readExactToken("AUTH_OK");
        Log.d(TAG, "AUTH_OK received");

        // 4) Read CFG line until '\n'
        String cfgLine = readLine();
        if (cfgLine == null || !cfgLine.startsWith("CFG")) {
            throw new IOException("Expected CFG line, got: " + cfgLine);
        }
        Log.d(TAG, "CFG line: " + cfgLine);

        // 5) Read 32-byte UDP key
        byte[] udpKey = readExactBytes(32);
        Log.d(TAG, "Received UDP key (32 bytes) " + bytesToHex(udpKey));

        // 6) Notify listener
        if (listener != null) {
            listener.onCfgReceived(cfgLine, udpKey);
        }
    }

    // Read exactly token "AUTH_REQ" or "AUTH_OK" from stream in order
    private void readExactToken(String token) throws IOException {
        byte[] pattern = token.getBytes(StandardCharsets.US_ASCII);
        int matched = 0;

        while (matched < pattern.length) {
            int b = in.read();
            if (b < 0) {
                throw new IOException("EOF while waiting for token " + token);
            }

            if (b == pattern[matched]) {
                matched++;
            } else {
                // naive prefix fallback; good enough for short tokens
                matched = (b == pattern[0]) ? 1 : 0;
            }
        }
    }

    // Read a single ASCII line (ending with '\n')
    private String readLine() throws IOException {
        StringBuilder sb = new StringBuilder();
        while (true) {
            int ch = in.read();
            if (ch < 0) {
                if (sb.length() == 0) return null;
                break;
            }
            if (ch == '\n') break;
            if (ch != '\r') sb.append((char) ch);
        }
        return sb.toString().trim();
    }

    // Read exactly N bytes, handling partial reads
    private byte[] readExactBytes(int len) throws IOException {
        byte[] buf = new byte[len];
        int off = 0;
        while (off < len) {
            int r = in.read(buf, off, len - off);
            if (r < 0) throw new IOException("EOF while reading " + len + " bytes");
            off += r;
        }
        return buf;
    }

    private static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte value : b) sb.append(String.format("%02X", value));
        return sb.toString();
    }

    // ============================================================
    // READ LOOP – packets from server → VPNService
    // ============================================================

    public void startReadLoop(PacketHandler handler) {
        new Thread(() -> {
            try {
                byte[] header = new byte[4];
                byte[] buffer = new byte[65535];

                while (running) {
                    // Read full 4 byte header
                    if (!readFully(in, header, 4)) break;

                    int len = ((header[0] & 0xff) << 24) |
                            ((header[1] & 0xff) << 16) |
                            ((header[2] & 0xff) << 8)  |
                            (header[3] & 0xff);

                    if (len <= 0 || len > 65535) break;

                    if (!readFully(in, buffer, len)) break;

                    byte[] raw = new byte[len];
                    System.arraycopy(buffer, 0, raw, 0, len);


                    byte[] decompressed = PacketReader.decompress(raw, len);
                    if (decompressed == null) decompressed = raw;
                    /* =========================================
                    DISCONNECT PACKET FROM SERVER ("DC")
                    ========================================== */
                    if (decompressed.length == 2 &&
                            decompressed[0] == 'D' &&
                            decompressed[1] == 'C') {

                        Log.e(TAG, "Server sent DISCONNECT (DC)");

                        running = false;
                        safeClose();

                        if (listener != null) {
                            listener.onDisconnected(
                                    new Exception("Server closed session")
                            );
                        }
                        return; // stop read loop
                    }

                    /* -------- normal tunneled IP packet -------- */
                    handler.onPacket(decompressed, decompressed.length);

                }

            } catch (Exception e) {
                running = false;
                safeClose();
                if (listener != null) listener.onDisconnected(e);
            }
        }, "TcpTLS-Reader").start();

    }
    private boolean readFully(InputStream in, byte[] buf, int len) throws IOException {
        int off = 0;
        while (off < len) {
            int r = in.read(buf, off, len - off);
            if (r < 0) return false;
            off += r;
        }
        return true;
    }


    // Very small check: first nibble must be 4 or 6 (IPv4 / IPv6)
    private boolean looksLikeIpPacket(byte[] data) {
        if (data.length < 1) return false;
        int version = (data[0] >> 4) & 0xF;
        return (version == 4 || version == 6);
    }

    // ============================================================
    // SEND PACKET TUN → SERVER
    // ============================================================

    public synchronized void sendPacket(byte[] data, int len) {
        if (!isRunning()) return;

        try {
            byte[] compressed = PacketWriter.compress(data, len);
            if (compressed == null) {
                compressed = new byte[len];
                System.arraycopy(data, 0, compressed, 0, len);
            }

            int cLen = compressed.length;

            byte[] framed = new byte[cLen + 4];
            framed[0] = (byte)((cLen >>> 24) & 0xFF);
            framed[1] = (byte)((cLen >>> 16) & 0xFF);
            framed[2] = (byte)((cLen >>>  8) & 0xFF);
            framed[3] = (byte)((cLen       ) & 0xFF);

            System.arraycopy(compressed, 0, framed, 4, cLen);

            out.write(framed);
            out.flush();


        } catch (Exception e) {
            Log.e(TAG, "sendPacket error", e);
            running = false;
            safeClose();
            if (listener != null) {
                listener.onDisconnected(e);
            }
        }
    }

    // ============================================================
    // CLOSE
    // ============================================================

    public void close() {
        running = false;
        safeClose();
    }

    private void safeClose() {
        try { if (in != null) in.close(); } catch (Exception ignored) {}
        try { if (out != null) out.close(); } catch (Exception ignored) {}
        try { if (socket != null) socket.close(); } catch (Exception ignored) {}
    }
}
