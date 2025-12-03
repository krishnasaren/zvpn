package elrasseo.syreao.zvpn.util;

import android.content.Context;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKeys;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

import elrasseo.syreao.zvpn.model.ServerModel;

public class Prefs {
    private static Prefs instance;
    private Context context;
    private android.content.SharedPreferences prefs;

    public static Prefs get(Context ctx) {
        if (instance == null) instance = new Prefs(ctx);
        return instance;
    }

    private Prefs(Context ctx) {
        try {
            context = ctx.getApplicationContext();
            String masterKey = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC);

            prefs = EncryptedSharedPreferences.create(
                    "vpn_secure_prefs",
                    masterKey,
                    context,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );

        } catch (Exception e) {
            throw new RuntimeException("Encrypted prefs error: " + e.getMessage());
        }
    }

    // ---------------------------------------------------------
    // SAVE SERVER LIST
    // ---------------------------------------------------------
    public void saveServers(List<ServerModel> list) {
        if (list == null) {
            prefs.edit().remove("servers").apply();
            return;
        }
        try {
            JSONArray arr = new JSONArray();

            for (ServerModel s : list) {
                JSONObject o = new JSONObject();
                o.put("name", s.getName());
                o.put("ip", s.getIp());
                o.put("ping", s.getLastPing());
                arr.put(o);
            }

            prefs.edit().putString("servers", arr.toString()).apply();

        } catch (Exception ignored) {}
    }

    // ---------------------------------------------------------
    // LOAD SERVER LIST
    // ---------------------------------------------------------
    public List<ServerModel> loadServers() {
        String json = prefs.getString("servers", null);
        List<ServerModel> list = new ArrayList<>();

        try {
            if (json != null) {
                JSONArray arr = new JSONArray(json);

                for (int i = 0; i < arr.length(); i++) {
                    JSONObject o = arr.getJSONObject(i);
                    ServerModel s = new ServerModel(
                            o.getString("name"),
                            o.getString("ip"),
                            o.getInt("ping")
                    );
                    list.add(s);
                }
            }
        } catch (Exception ignored) {}

        return list;
    }

    // Selected Server
    public void saveSelectedServerIP(String ip) {
        prefs.edit().putString("selected_ip", ip).apply();
    }

    public String getSelectedServerIP() {
        return prefs.getString("selected_ip", "");
    }

    // Auto-reconnect setting
    public void setAutoReconnect(boolean enabled) {
        prefs.edit().putBoolean("auto_reconnect", enabled).apply();
    }

    public boolean getAutoReconnect() {
        return prefs.getBoolean("auto_reconnect", true);
    }

    // Token
    public void setToken(String token) {
        prefs.edit().putString("auth_token", token).apply();
    }

    public String getToken() {
        return prefs.getString("auth_token", "MODERNVPN2024");
    }
}
