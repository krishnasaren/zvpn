package elrasseo.syreao.zvpn.net;

import android.content.Context;
import android.util.Log;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketException;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

public class UdpChannel {
    private static final String TAG = "UdpChannel";

    // Max UDP packet size
    private static final int MAX_PACKET = 65535;

    private static final int HEARTBEAT_INTERVAL_MS = 5000;   // client → server
    private static final int NAT_CHECK_INTERVAL_MS = 2000;   // detect port changes

    public interface Listener {
        void onPacket(byte[] data, int len);
    }

    private Listener listener;

    private final Context context;
    private final String serverIp;
    private final int serverPort;

    private DatagramSocket socket;
    private InetSocketAddress serverSockAddr;
    private volatile InetSocketAddress lastLocalAddr;

    private final AtomicBoolean running = new AtomicBoolean(false);

    private Thread receiverThread;
    private Thread heartbeatThread;
    private Thread natThread;

    // =====================================================================
    // CONSTRUCTOR
    // =====================================================================

    public UdpChannel(Context ctx, String serverIp, int serverPort) throws Exception {
        this.context = ctx.getApplicationContext();
        this.serverIp = serverIp;
        this.serverPort = serverPort;

        InetAddress serverInet = InetAddress.getByName(serverIp);
        this.serverSockAddr = new InetSocketAddress(serverInet, serverPort);

        socket = new DatagramSocket();
        socket.connect(serverSockAddr);

        // No timeout – UDP channel may be idle
        socket.setSoTimeout(0);

        lastLocalAddr = (InetSocketAddress) socket.getLocalSocketAddress();
        Log.d(TAG, "UDP created: local=" + lastLocalAddr);
    }

    // =====================================================================
    // START
    // =====================================================================

    public void startReadLoop(Listener listener) {
        this.listener = listener;
        running.set(true);

        startReceiver();
        startHeartbeat();
        startNatMonitor();

        Log.d(TAG, "UDP channel started");
    }

    // =====================================================================
    // RECEIVER THREAD
    // =====================================================================

    private void startReceiver() {

        receiverThread = new Thread(() -> {

            byte[] recvBuf = new byte[MAX_PACKET];

            while (running.get()) {
                try {
                    DatagramPacket pkt = new DatagramPacket(recvBuf, recvBuf.length);
                    socket.receive(pkt);

                    int len = pkt.getLength();
                    if (len <= 0) continue;

                    // decrypt
                    byte[] dec = Crypto.decryptUdp(recvBuf, len);
                    if (dec == null || dec.length == 0) {
                        continue;
                    }

                    // Control packets (1-byte)
                    if (dec.length == 1) {
                        byte c = dec[0];

                        // 0x7F: server heartbeat → ignore
                        if (c == (byte) 0x7F) {
                            continue;
                        }

                        // 0xFA: server NAT ACK → ignore (we only care server sees us)
                        if (c == (byte) 0xFA) {
                            continue;
                        }
                    }

                    // Check if it's an IP packet (4 or 6)
                    if (!isValidIpPacket(dec)) {
                        continue;
                    }

                    if (listener != null) {
                        listener.onPacket(dec, dec.length);
                    }

                } catch (SocketException e) {
                    if (running.get()) {
                        Log.e(TAG, "UDP socket exception: " + e.getMessage());
                    }
                    break;

                } catch (IOException e) {
                    if (running.get()) {
                        Log.e(TAG, "UDP IO exception: " + e.getMessage());
                    }
                    break;

                } catch (Exception e) {
                    Log.e(TAG, "UDP fatal error", e);
                    break;
                }
            }

            Log.d(TAG, "UDP receiver stopped");

        }, "UDP-Receiver");

        receiverThread.start();
    }

    private boolean isValidIpPacket(byte[] data) {
        if (data.length < 1) return false;
        int version = (data[0] >> 4) & 0xF;
        return version == 4 || version == 6;
    }

    // =====================================================================
    // HEARTBEAT THREAD
    // =====================================================================

    private void startHeartbeat() {
        heartbeatThread = new Thread(() -> {

            while (running.get()) {
                try {
                    Thread.sleep(HEARTBEAT_INTERVAL_MS);

                    if (!Crypto.hasUdpKey()) continue;

                    // 0x7F = client heartbeat control packet
                    byte[] hb = new byte[]{0x7F};
                    byte[] enc = Crypto.encryptUdp(hb);
                    if (enc == null) continue;

                    socket.send(new DatagramPacket(enc, enc.length, serverSockAddr));

                } catch (Exception ignored) {}
            }

        }, "UDP-Heartbeat");

        heartbeatThread.start();
    }

    // =====================================================================
    // NAT REBIND DETECTION
    // =====================================================================

    private void startNatMonitor() {
        natThread = new Thread(() -> {

            while (running.get()) {
                try {
                    Thread.sleep(NAT_CHECK_INTERVAL_MS);

                    InetSocketAddress now = (InetSocketAddress) socket.getLocalSocketAddress();

                    // port OR src IP changed
                    if (!localAddrEqual(lastLocalAddr, now)) {

                        Log.w(TAG, "UDP NAT rebinding detected: " + now);
                        lastLocalAddr = now;

                        sendRebindSignal();
                    }

                } catch (Exception ignored) {}
            }

        }, "UDP-NATMonitor");

        natThread.start();
    }

    private boolean localAddrEqual(InetSocketAddress a, InetSocketAddress b) {
        if (a == null || b == null) return false;
        return a.getPort() == b.getPort() && a.getAddress().equals(b.getAddress());
    }

    private void sendRebindSignal() {
        try {
            // 0xFA = client NAT rebind signal control packet
            byte[] packet = new byte[]{(byte) 0xFA};
            byte[] enc = Crypto.encryptUdp(packet);
            if (enc == null) return;

            socket.send(new DatagramPacket(enc, enc.length, serverSockAddr));
            Log.d(TAG, "Sent UDP REBIND signal");

        } catch (Exception e) {
            Log.e(TAG, "sendRebindSignal failed: " + e.getMessage());
        }
    }

    // =====================================================================
    // SEND PACKET (TUN → SERVER)
    // =====================================================================

    public boolean sendPacket(byte[] data, int len) {
        if (!running.get()) return false;
        if (!Crypto.hasUdpKey()) {
            Log.w(TAG, "UDP key not set → skipping UDP");
            return false;
        }

        try {
            byte[] raw = (data.length == len) ? data : Arrays.copyOf(data, len);
            byte[] enc = Crypto.encryptUdp(raw);
            if (enc == null) return false;

            socket.send(new DatagramPacket(enc, enc.length, serverSockAddr));
            return true;

        } catch (Exception e) {
            Log.e(TAG, "UDP send error: " + e.getMessage());
            return false;
        }
    }

    // =====================================================================
    // CLOSE
    // =====================================================================

    public void close() {
        running.set(false);

        try { if (socket != null) socket.close(); } catch (Exception ignored) {}

        Log.d(TAG, "UDP channel closed");
    }

    // =====================================================================
    // SET UDP KEY
    // =====================================================================

    public void setUdpKey(byte[] key) {
        if (key == null || key.length != 32) {
            Log.e(TAG, "Invalid UDP key length");
            return;
        }

        Crypto.setUdpKey(key);
        Log.d(TAG, "UDP key installed (" + key.length + " bytes)");
    }
}
