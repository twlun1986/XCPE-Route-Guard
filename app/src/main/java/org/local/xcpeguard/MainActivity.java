package org.local.xcpeguard;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/** TV-remote-friendly UI. No SDKs, analytics, trackers or remote code. */
public final class MainActivity extends Activity {
    private static final int VPN_REQUEST = 7001;
    private TextView status;
    private EditText addresses;
    private EditText domains;
    private final Handler refreshHandler = new Handler(Looper.getMainLooper());
    private final Runnable refreshLoop = new Runnable() {
        @Override public void run() {
            showStatus();
            refreshHandler.postDelayed(this, 2000);
        }
    };

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        int p = (int) (18 * getResources().getDisplayMetrics().density);
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(p, p, p, p);
        scroll.addView(root);
        TextView heading = label(root, "XCPE Route Guard 0.3.0", 26);
        heading.setFocusable(false);
        label(root, "Author: Nikaido Wei", 15);
        label(root, "LOCAL PROTECTION — works on any router. Published XCPE IPv4 destinations "
                + "are dropped; listed FQDNs and subdomains return NXDOMAIN for standard "
                + "IPv4 UDP DNS. Video packets bypass the local VPN. This does not remove "
                + "firmware malware or stop privileged bypasses, encrypted DNS and IPv6.", 15);
        status = label(root, "Checking protection status...", 17);
        status.setPadding(0, p / 2, 0, p / 2);
        label(root, "Blocked IPv4 addresses (one per line):", 16);
        addresses = new EditText(this);
        addresses.setMinLines(4);
        addresses.setInputType(android.text.InputType.TYPE_CLASS_TEXT |
                android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        addresses.setText(getSharedPreferences(GuardVpnService.PREFS, MODE_PRIVATE)
                .getString(GuardVpnService.KEY_IPS, IpRules.DEFAULT_IPS));
        root.addView(addresses);
        label(root, "Blocked domains (including subdomains, one per line):", 16);
        domains = new EditText(this);
        domains.setMinLines(4);
        domains.setInputType(android.text.InputType.TYPE_CLASS_TEXT |
                android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        domains.setText(getSharedPreferences(GuardVpnService.PREFS, MODE_PRIVATE)
                .getString(GuardVpnService.KEY_DOMAINS, DomainRules.DEFAULT_DOMAINS));
        root.addView(domains);

        button(root, "Save rules").setOnClickListener(v -> saveRules());
        button(root, "Start protection").setOnClickListener(v -> {
            if (saveRules()) requestVpn();
        });
        button(root, "Stop protection").setOnClickListener(v -> {
            // This must call onStartCommand(ACTION_STOP) of the running VPN
            // rather than merely requesting service destruction: Android may
            // keep the VPN service bound and skip onDestroy for some time.
            if (!getSharedPreferences(GuardVpnService.PREFS, MODE_PRIVATE).edit()
                    .putBoolean(GuardVpnService.KEY_ENABLED, false).commit()) {
                Toast.makeText(this, "Unable to save Stop preference", Toast.LENGTH_LONG).show();
                return;
            }
            try {
                startService(new Intent(this, GuardVpnService.class)
                        .setAction(GuardVpnService.ACTION_STOP));
                status.setText("STOP REQUESTED: releasing local VPN...");
                refreshHandler.postDelayed(this::showStatus, 200);
                refreshHandler.postDelayed(this::showStatus, 850);
            } catch (RuntimeException e) {
                Toast.makeText(this, "Stop request failed: " + e.getMessage(),
                        Toast.LENGTH_LONG).show();
                showStatus();
            }
        });
        button(root, "Refresh status").setOnClickListener(v -> showStatus());
        label(root, "AUTO-START: after Start Protection, the app remembers your choice and " +
                "attempts to resume following Android BOOT_COMPLETED, package updates or " +
                "system service restarts. Stop Protection disables this. If the TV firmware " +
                "blocks background startup, check Android VPN Always-on or the box's " +
                "Autostart/Battery restrictions. Never enable Block connections without VPN.", 14);
        label(root, "STATUS ICON: some Android TV launchers hide VPN/notification icons. "
                + "Check ACTIVE above or the persistent notification. Keep 'Block connections "
                + "without VPN' disabled. Only one Android VPN can run at a time.", 14);
        setContentView(scroll);
    }

    private TextView label(LinearLayout root, String value, int size) {
        TextView t = new TextView(this);
        t.setText(value);
        t.setTextSize(size);
        root.addView(t);
        return t;
    }
    private Button button(LinearLayout root, String value) {
        Button b = new Button(this);
        b.setText(value);
        b.setFocusable(true);
        root.addView(b);
        return b;
    }
    private boolean saveRules() {
        String ips = addresses.getText().toString();
        String fqdns = domains.getText().toString();
        try {
            IpRules.parse(ips);
            DomainRules.parse(fqdns);
        } catch (IllegalArgumentException e) {
            Toast.makeText(this, e.getMessage(), Toast.LENGTH_LONG).show();
            return false;
        }
        getSharedPreferences(GuardVpnService.PREFS, MODE_PRIVATE).edit()
                .putString(GuardVpnService.KEY_IPS, ips)
                .putString(GuardVpnService.KEY_DOMAINS, fqdns)
                .apply();
        Toast.makeText(this, "Saved. Stop and start to apply changes.", Toast.LENGTH_SHORT).show();
        return true;
    }
    private void requestVpn() {
        Intent permission = VpnService.prepare(this);
        if (permission != null) startActivityForResult(permission, VPN_REQUEST);
        else startGuard();
    }
    private void startGuard() {
        if (GuardVpnService.active) {
            Toast.makeText(this, "Stop protection first to apply saved rules",
                    Toast.LENGTH_LONG).show();
            return;
        }
        if (!getSharedPreferences(GuardVpnService.PREFS, MODE_PRIVATE).edit()
                .putBoolean(GuardVpnService.KEY_ENABLED, true).commit()) {
            Toast.makeText(this, "Unable to save VPN enable state", Toast.LENGTH_LONG).show();
            return;
        }
        try {
            startForegroundService(new Intent(this, GuardVpnService.class)
                    .setAction(GuardVpnService.ACTION_START));
            status.setText("Starting... select Refresh status");
            new Handler(Looper.getMainLooper()).postDelayed(this::showStatus, 500);
        } catch (RuntimeException e) {
            getSharedPreferences(GuardVpnService.PREFS, MODE_PRIVATE).edit()
                    .putBoolean(GuardVpnService.KEY_ENABLED, false).apply();
            Toast.makeText(this, "Unable to start VPN: " + e.getMessage(), Toast.LENGTH_LONG).show();
            showStatus();
        }
    }
    @Override protected void onActivityResult(int req, int result, Intent data) {
        super.onActivityResult(req, result, data);
        if (req == VPN_REQUEST && result == RESULT_OK) startGuard();
        else if (req == VPN_REQUEST)
            Toast.makeText(this, "VPN permission denied", Toast.LENGTH_LONG).show();
    }
    @Override protected void onResume() {
        super.onResume();
        refreshHandler.removeCallbacks(refreshLoop);
        refreshHandler.post(refreshLoop);
    }
    @Override protected void onPause() {
        refreshHandler.removeCallbacks(refreshLoop);
        super.onPause();
    }
    private void showStatus() {
        String err = getSharedPreferences(GuardVpnService.PREFS, MODE_PRIVATE)
                .getString("error", null);
        long drops = getSharedPreferences(GuardVpnService.PREFS, MODE_PRIVATE)
                .getLong(GuardVpnService.KEY_TOTAL, 0);
        long blocked = getSharedPreferences(GuardVpnService.PREFS, MODE_PRIVATE)
                .getLong(GuardVpnService.KEY_BLOCKED_DNS, 0);
        boolean enabled = getSharedPreferences(GuardVpnService.PREFS, MODE_PRIVATE)
                .getBoolean(GuardVpnService.KEY_ENABLED, false);
        String state = GuardVpnService.active ? "ACTIVE" :
                (enabled ? "WAITING/INACTIVE (auto-start enabled)" : "INACTIVE");
        status.setText(state +
                " | Reboot restart: " + (enabled ? "ON" : "OFF") +
                " | Dropped IP packets: " + drops +
                " | Blocked DNS: " + blocked +
                (err == null ? "" : " | Error: " + err));
    }
}
