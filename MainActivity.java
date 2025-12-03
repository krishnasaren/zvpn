package elrasseo.syreao.zvpn;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.view.animation.Animation;
import android.view.animation.RotateAnimation;
import android.view.animation.ScaleAnimation;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.cardview.widget.CardView;
import androidx.core.content.ContextCompat;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.airbnb.lottie.LottieAnimationView;
import com.google.android.material.button.MaterialButton;
import com.google.android.material.textfield.TextInputEditText;

import java.util.Locale;

import elrasseo.syreao.zvpn.net.NetQualityMonitor;
import elrasseo.syreao.zvpn.service.ModernVPNService;
import elrasseo.syreao.zvpn.ui.ServerListActivity;
import elrasseo.syreao.zvpn.ui.SettingsActivity;
import elrasseo.syreao.zvpn.util.DataFormatter;
import elrasseo.syreao.zvpn.util.PingUtils;
import elrasseo.syreao.zvpn.util.Prefs;

public class MainActivity extends AppCompatActivity implements ModernVPNService.VpnEventListener{

    private TextView statusText, statusSubtext, pingText;
    private TextView uploadSpeed, downloadSpeed, connectionTime, totalDataText;
    private MaterialButton connectButton;
    private LottieAnimationView lottieConnect;
    private ImageView connectGlow;
    private TextInputEditText serverIpInput;

    private boolean isConnected = false;
    private Handler pingHandler = new Handler();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initViews();

        ModernVPNService.setEventListener(this);

        connectButton.setOnClickListener(v -> {
            if (!isConnected) requestVpnPermission();
            else stopVPN();
        });
    }

    private void initViews() {
        statusText = findViewById(R.id.statusText);
        statusSubtext = findViewById(R.id.statusSubtext);
        pingText = findViewById(R.id.pingText);

        uploadSpeed = findViewById(R.id.uploadSpeed);
        downloadSpeed = findViewById(R.id.downloadSpeed);
        connectionTime = findViewById(R.id.connectionTime);
        totalDataText = findViewById(R.id.totalDataText);

        connectButton = findViewById(R.id.connectButton);
        lottieConnect = findViewById(R.id.lottieConnect);
        connectGlow = findViewById(R.id.connectGlow);

        serverIpInput = findViewById(R.id.serverIpInput);

        String savedIp = elrasseo.syreao.zvpn.util.Prefs.get(this).getSelectedServerIP();
        if (savedIp != null) serverIpInput.setText(savedIp);
    }

    // ──────────────────────────── VPN Permission ───────────────────────────────

    private void requestVpnPermission() {
        String ip = serverIpInput.getText().toString().trim();

        if (ip.isEmpty()) {
            serverIpInput.setError("Enter server IP");
            return;
        }

        Prefs.get(this).saveSelectedServerIP(ip);

        Intent intent = VpnService.prepare(this);
        if (intent != null) {
            startActivityForResult(intent, 100);
        } else {
            startVPN();
        }
    }

    private void startVPN() {
        Intent intent = new Intent(this, ModernVPNService.class);
        intent.setAction(ModernVPNService.ACTION_START);
        startService(intent);
    }

    private void stopVPN() {
        Intent intent = new Intent(this, ModernVPNService.class);
        intent.setAction(ModernVPNService.ACTION_STOP);
        startService(intent);
    }

    // ───────────────────────── Event Listener From Service ─────────────────────────

    @Override
    public void onStateChanged(String state) {
        runOnUiThread(() -> updateState(state));
    }

    @Override
    public void onStatsUpdated(long up, long down) {
        runOnUiThread(() -> {
            long totalMB = (up + down) / (1024 * 1024);
            totalDataText.setText("Total: " + totalMB + " MB");
        });
    }

    @Override
    public void onSpeedUpdated(String upSpeed, String downSpeed) {
        runOnUiThread(() -> {
            uploadSpeed.setText(upSpeed);
            downloadSpeed.setText(downSpeed);
        });
    }

    @Override
    public void onTimeUpdated(String time) {
        runOnUiThread(() -> connectionTime.setText(time));
    }

    // ───────────────────────── UI State Update ───────────────────────────

    private void updateState(String state) {
        switch (state) {

            case "connecting":
                isConnected = false;
                resetStatsUI();
                statusText.setText("Connecting…");
                statusSubtext.setText("Please wait");

                connectButton.setText("CONNECTING...");
                connectButton.setEnabled(false);

                lottieConnect.setVisibility(View.VISIBLE);
                lottieConnect.playAnimation();
                connectGlow.setVisibility(View.VISIBLE);

                break;

            case "error":
                isConnected = false;
                statusText.setText("Connection Failed");
                statusSubtext.setText("Server unreachable");
                connectButton.setText("CONNECT");
                connectButton.setEnabled(true);
                lottieConnect.setVisibility(View.GONE);
                connectGlow.setVisibility(View.GONE);
                stopPingLoop();
                pingText.setText("Ping: 0 ms");
                break;


            case "assigned_ip":
                statusSubtext.setText("Assigned VPN IP");
                break;

            case "connected":
                isConnected = true;

                statusText.setText("Connected");
                statusSubtext.setText("Secure tunnel active");

                connectButton.setText("DISCONNECT");
                connectButton.setEnabled(true);

                lottieConnect.setVisibility(View.GONE);
                connectGlow.setVisibility(View.GONE);

                startPingLoop();
                break;

            case "disconnected":
            default:
                isConnected = false;

                statusText.setText("Disconnected");
                statusSubtext.setText("Tap connect to start");

                connectButton.setText("CONNECT");
                connectButton.setEnabled(true);

                lottieConnect.setVisibility(View.GONE);
                connectGlow.setVisibility(View.GONE);

                stopPingLoop();
                resetStatsUI();
                break;
        }
    }

    // ─────────────────────────── PING SYSTEM ───────────────────────────────

    private void startPingLoop() {
        pingHandler.postDelayed(pingRunnable, 2000);
    }

    private void stopPingLoop() {
        pingHandler.removeCallbacks(pingRunnable);
    }

    private final Runnable pingRunnable = new Runnable() {
        @Override
        public void run() {
            if (!isConnected) return;

            long start = System.currentTimeMillis();
            new Thread(() -> {
                boolean ok = PingUtils.ping(serverIpInput.getText().toString().trim());
                long ms = System.currentTimeMillis() - start;

                runOnUiThread(() -> {
                    if (ok)
                        pingText.setText("Ping: " + ms + " ms");
                    else
                        pingText.setText("Ping: timeout");
                });

            }).start();

            pingHandler.postDelayed(this, 2000);
        }
    };

    private void resetStatsUI() {
        uploadSpeed.setText("0 KB/s");
        downloadSpeed.setText("0 KB/s");
        connectionTime.setText("00:00:00");
        totalDataText.setText("Total: 0 MB");
        pingText.setText("Ping: 0 ms");
    }
}