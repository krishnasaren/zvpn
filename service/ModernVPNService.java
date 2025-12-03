package elrasseo.syreao.zvpn.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.core.app.NotificationCompat;

import com.airbnb.lottie.L;

import java.io.FileInputStream;
import java.io.FileOutputStream;

import elrasseo.syreao.zvpn.MainActivity;
import elrasseo.syreao.zvpn.R;
import elrasseo.syreao.zvpn.net.TcpTlsChannel;
import elrasseo.syreao.zvpn.net.UdpChannel;
import elrasseo.syreao.zvpn.util.ConnectionTimer;
import elrasseo.syreao.zvpn.util.DataFormatter;
import elrasseo.syreao.zvpn.util.Prefs;

public class ModernVPNService extends VpnService {

    // Action Commands
    public static final String ACTION_START = "MODERN_VPN_START";
    public static final String ACTION_STOP  = "MODERN_VPN_STOP";

    private static final String TAG = "ModernVPNService";
    private static final String CHANNEL_ID = "modernvpn_channel";

    private static final int TCP_PORT = 8888;
    private static final int UDP_PORT = 8889;
    private final Object lifecycleLock = new Object();

    // TUN interface
    private ParcelFileDescriptor tunFd;
    private FileInputStream tunIn;
    private FileOutputStream tunOut;
    private Thread tunThread;

    // Channels
    private TcpTlsChannel tcp;
    private UdpChannel udp;

    // Running
    private volatile boolean running = false;
    private volatile boolean tunActive = false;

    // Stats
    private long upBytes = 0;
    private long downBytes = 0;
    private long lastSpeedAt = 0;
    private long lastUp = 0;
    private long lastDown = 0;

    private final ConnectionTimer timer = new ConnectionTimer();

    // Server config
    private String v4;
    private String gw4;
    private String v6;
    private String gw6;
    private String[] dns4 = new String[0];
    private String[] dns6 = new String[0];
    private int mtu = 1400;
    private String mode = "HYBRID";

    private String serverIp;
    private byte[] udpKey;

    // Event callback
    public interface VpnEventListener {
        void onStateChanged(String state);
        void onStatsUpdated(long up, long down);
        void onSpeedUpdated(String up, String down);
        void onTimeUpdated(String t);
    }
    private static VpnEventListener listener;

    public static void setEventListener(VpnEventListener l) {
        listener = l;
    }

    // ---------------------------------------------------------------------
    // onStartCommand
    // ---------------------------------------------------------------------
    @Override
    public int onStartCommand(Intent i, int flags, int id) {
        if (i == null) return START_NOT_STICKY;

        if (ACTION_STOP.equals(i.getAction())) {
            stopVpnInternal(false);
            stopSelf();
            return START_NOT_STICKY;
        }

        if (ACTION_START.equals(i.getAction())) {
            String ip = Prefs.get(this).getSelectedServerIP();
            if (ip == null || ip.isEmpty()) {
                Log.e(TAG, "No server IP stored");
                return START_NOT_STICKY;
            }
            startVpn(ip);
        }
        return START_STICKY;
    }

    // ---------------------------------------------------------------------
    // START VPN
    // ---------------------------------------------------------------------


    private void startVpn(String ip) {

        synchronized (lifecycleLock) {

            if (running) {
                Log.w(TAG, "Restart requested → stopping previous VPN first");
                stopVpnInternal(false);
                try { Thread.sleep(350); } catch (Exception ignored) {}
            }

            // NOW allow start
            running = true;
        }

        serverIp = ip;

        // Reset stats
        upBytes = downBytes = 0;
        lastSpeedAt = lastUp = lastDown = 0;
        timer.reset();

        sendState("connecting");
        createNotifChannel();
        startForeground(1, notif("Connecting…"));

        new Thread(this::connectTcp, "tcp-connector").start();
    }


    private void connectTcp() {
        try {
            // *** CHANGED: ensure fresh channels each time ***
            if (tcp != null) {
                try { tcp.close(); } catch (Exception ignored) {}
                tcp = null;
            }
            if (udp != null) {
                try { udp.close(); } catch (Exception ignored) {}
                udp = null;
            }

            tcp = new TcpTlsChannel(this, serverIp, TCP_PORT);

            tcp.connect(new TcpTlsChannel.Listener() {

                @Override
                public void onCfgReceived(String cfg, byte[] key) {
                    Log.d(TAG, "CFG: " + cfg);

                    if (!running) return;

                    udpKey = key;
                    parseCfg(cfg);

                    sendState("assigned_ip");
                    updateNotif("Configuring interface…");

                    try {
                        setupTun();
                        startTcpReader();
                        startUdpIfAllowed();
                        startTunReader();

                        timer.start();
                        sendState("connected");
                        updateNotif("Connected");
                    }
                    catch (Exception e) {
                        Log.e(TAG, "TUN/Setup failed", e);
                        stopVpnInternal(true);
                    }
                }

                @Override
                public void onDisconnected(Exception e) {
                    Log.e(TAG, "TCP disconnected: " + e);
                    stopVpnInternal(true);
                }
            });

        } catch (Exception e) {
            Log.e(TAG, "TCP connect exception", e);
            stopVpnInternal(true);
        }
    }

    // ---------------------------------------------------------------------
    // STOP VPN (safe)
    // ---------------------------------------------------------------------
    private void stopVpnInternal(boolean error) {

        synchronized (lifecycleLock) {

            if (!running) return;
            running = false;
        }

        sendState(error ? "error" : "disconnected");
        updateNotif(error ? "Error" : "Disconnected");

        tunActive = false;

        if (tunThread != null) {
            tunThread.interrupt();
            tunThread = null;
        }

        try { if (tcp != null) tcp.close(); } catch (Exception ignored) {}
        try { if (udp != null) udp.close(); } catch (Exception ignored) {}

        try { if (tunIn  != null) tunIn.close(); } catch (Exception ignored) {}
        try { if (tunOut != null) tunOut.close(); } catch (Exception ignored) {}
        try { if (tunFd  != null) tunFd.close(); } catch (Exception ignored) {}

        // Force Android to release last TUN
        try {
            VpnService.Builder b = new VpnService.Builder();
            b.setSession("dummy");
            ParcelFileDescriptor tmp = b.establish();
            if (tmp != null) tmp.close();
        } catch (Exception ignored) {}

        tcp = null;
        udp = null;
        tunFd = null;
        tunIn = null;
        tunOut = null;

        stopForeground(true);

        Log.d(TAG, "VPN fully stopped.");
    }


    // ---------------------------------------------------------------------
    // Parse Config
    // ---------------------------------------------------------------------
    private void parseCfg(String c) {
        try {
            String[] p = c.trim().split("\\s+");
            if (p.length < 9) return;

            v4 = p[1];
            gw4 = p[2];
            v6 = p[3];
            gw6 = p[4];

            dns4 = "-".equals(p[5]) ? new String[0] : p[5].split(",");
            dns6 = "-".equals(p[6]) ? new String[0] : p[6].split(",");

            try {
                int m = Integer.parseInt(p[7]);
                mtu = (m < 1200 || m > 1500) ? 1400 : m;
            } catch (Exception ignore) {}

            mode = p[8].toUpperCase();

        } catch (Exception e) {
            Log.e(TAG, "Bad CFG", e);
        }
    }

    // ---------------------------------------------------------------------
    // Configure & Create TUN
    // ---------------------------------------------------------------------
    private void setupTun() throws Exception {
        if (v4 == null || v4.isEmpty()) {
            throw new Exception("Server CFG missing IPv4");
        }

        VpnService.Builder b = new VpnService.Builder();

        b.setMtu(mtu);
        b.addAddress(v4, 24);
        b.addRoute("0.0.0.0", 0);

        if (v6 != null && !v6.isEmpty() && !"-".equals(v6)) {
            b.addAddress(v6, 64);
            b.addRoute("::", 0);
        }

        for (String d : dns4) {
            if (d != null && !d.isEmpty()) try { b.addDnsServer(d); } catch (Exception ignored) {}
        }
        for (String d : dns6) {
            if (d != null && !d.isEmpty()) try { b.addDnsServer(d); } catch (Exception ignored) {}
        }

        b.setSession("ModernVPN");

        tunFd = b.establish();
        if (tunFd == null) throw new Exception("Failed to create TUN");

        tunIn  = new FileInputStream(tunFd.getFileDescriptor());
        tunOut = new FileOutputStream(tunFd.getFileDescriptor());

        Log.d(TAG, "TUN created (v4=" + v4 + " v6=" + v6 + " mtu=" + mtu + ")");
    }

    // ---------------------------------------------------------------------
    // UDP Start
    // ---------------------------------------------------------------------
    private void startUdpIfAllowed() {
        if ("TCP".equals(mode)) {
            Log.d(TAG, "Skipping UDP (TCP-only)");
            return;
        }
        if (udpKey == null || udpKey.length != 32) {
            Log.d(TAG, "Missing UDP key, skipping");
            return;
        }

        try {
            udp = new UdpChannel(this, serverIp, UDP_PORT);
            udp.setUdpKey(udpKey);

            udp.startReadLoop((data, len) -> {
                if (!running || tunOut == null) return;
                try {
                    tunOut.write(data, 0, len);
                    downBytes += len;
                    updateStats();
                } catch (Exception e) {
                    Log.e(TAG, "UDP->TUN error", e);
                }
            });

            Log.d(TAG, "UDP channel active");

        } catch (Exception e) {
            Log.e(TAG, "UDP init failed", e);
        }
    }

    // ---------------------------------------------------------------------
    // TCP Reader
    // ---------------------------------------------------------------------
    private void startTcpReader() {
        tcp.startReadLoop((data, len) -> {
            if (!running || tunOut == null) return;

            try {
                tunOut.write(data, 0, len);
                downBytes += len;
                updateStats();
            } catch (Exception e) {
                Log.e(TAG, "TCP->TUN write failed", e);
                stopVpnInternal(true);
            }
        });
    }

    // ---------------------------------------------------------------------
    // TUN Reader thread (→ UDP/TCP)
    // ---------------------------------------------------------------------
    private void startTunReader() {
        tunActive = true;

        tunThread = new Thread(() -> {

            byte[] buf = new byte[32767];

            while (running && tunActive && !Thread.interrupted()) {
                try {
                    int n = tunIn.read(buf);
                    if (n > 0) {

                        boolean okUdp = false;

                        if (udp != null && !"TCP".equals(mode)) {
                            okUdp = udp.sendPacket(buf, n);
                        }

                        if (!okUdp && tcp != null) {
                            tcp.sendPacket(buf, n);
                        }

                        upBytes += n;
                        updateStats();

                    } else if (n < 0) {
                        break;
                    }

                } catch (Exception e) {
                    if (running) {
                        Log.e(TAG, "TUN read error", e);
                    }
                    break;
                }
            }

            Log.d(TAG, "TUN thread exit");
        }, "tun-thread");

        tunThread.start();
    }

    // ---------------------------------------------------------------------
    // Stats
    // ---------------------------------------------------------------------
    private void updateStats() {
        long now = System.currentTimeMillis();
        if (now - lastSpeedAt >= 1000) {

            long up = upBytes - lastUp;
            long down = downBytes - lastDown;

            if (listener != null) {
                listener.onStatsUpdated(upBytes, downBytes);
                listener.onSpeedUpdated(
                        DataFormatter.formatSpeed(up),
                        DataFormatter.formatSpeed(down)
                );
                listener.onTimeUpdated(timer.getFormatted());
            }

            lastUp = upBytes;
            lastDown = downBytes;
            lastSpeedAt = now;
        }
    }

    // ---------------------------------------------------------------------
    // Notifications
    // ---------------------------------------------------------------------
    private void sendState(String s) {
        if (listener != null) listener.onStateChanged(s);
    }

    private void createNotifChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel c = new NotificationChannel(
                    CHANNEL_ID, "ModernVPN", NotificationManager.IMPORTANCE_LOW);
            NotificationManager nm = getSystemService(NotificationManager.class);
            nm.createNotificationChannel(c);
        }
    }

    private Notification notif(String text) {
        Intent i = new Intent(this, MainActivity.class);
        PendingIntent pi = PendingIntent.getActivity(
                this, 0, i, PendingIntent.FLAG_IMMUTABLE);

        return new NotificationCompat
                .Builder(this, CHANNEL_ID)
                .setContentTitle("Modern VPN")
                .setContentText(text)
                .setSmallIcon(R.drawable.baseline_vpn_lock_24)
                .setOngoing(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setCategory(NotificationCompat.CATEGORY_SERVICE)
                .setContentIntent(pi)
                .build();
    }

    private void updateNotif(String text) {
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.notify(1, notif(text));
    }

    // Optional: make sure service shutdown also cleans VPN
    @Override
    public void onDestroy() {
        stopVpnInternal(false);
        super.onDestroy();
    }


}
