package org.local.xcpeguard;

import android.app.Activity;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/** Simple Android TV-friendly UI: D-pad focusable native buttons, no SDKs. */
public final class MainActivity extends Activity {
    private static final int REQUEST_VPN = 7001;
    private TextView status;
    private EditText addresses;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int p = (int) (20 * getResources().getDisplayMetrics().density);
        root.setPadding(p, p, p, p);
        scroll.addView(root);
        TextView heading = new TextView(this);
        heading.setText("XCPE Route Guard");
        heading.setTextSize(26);
        root.addView(heading);
        TextView description = new TextView(this);
        description.setText("Minimal IP-only protection for SVI 10P. " +
                "Normal streaming packets are not routed into this VPN. " +
                "This does NOT remove firmware malware, block domains, " +
                "or stop new C2 addresses.");
        description.setTextSize(16);
        root.addView(description);
        status = new TextView(this);
        status.setTextSize(17);
        status.setPadding(0, p / 2, 0, p / 2);
        root.addView(status);
        TextView label = new TextView(this);
        label.setText("Blocked destinations (public IPv4 only, one per line):");
        root.addView(label);
        addresses = new EditText(this);
        addresses.setMinLines(4);
        addresses.setInputType(android.text.InputType.TYPE_CLASS_TEXT |
                android.text.InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        addresses.setText(getPreferences());
        root.addView(addresses);
        Button save = button("Save IP list", root);
        save.setOnClickListener(v -> saveRules());
        Button start = button("Start blocking", root);
        start.setOnClickListener(v -> {
            if (saveRules()) requestVpn();
        });
        Button stop = button("Stop blocking", root);
        stop.setOnClickListener(v -> {
            Intent cmd = new Intent(this, GuardVpnService.class).setAction(GuardVpnService.ACTION_STOP);
            startService(cmd);
            status.setText("Stopping... reopen to refresh status");
        });
        TextView note = new TextView(this);
        note.setPadding(0, p / 2, 0, p / 2);
        note.setText("IMPORTANT: Keep 'Block connections without VPN' OFF. " +
                "Optional Always-on VPN may restart it after reboot, but your firmware " +
                "can disable this app. Only one Android VPN can run at once. " +
                "Keep the SVI 10P isolated using TP-Link BE400 Device Isolation.");
        root.addView(note);
        setContentView(scroll);
    }

    private Button button(String title, LinearLayout root) {
        Button b = new Button(this);
        b.setText(title);
        b.setFocusable(true);
        root.addView(b);
        return b;
    }

    private String getPreferences() {
        return getSharedPreferences(GuardVpnService.PREFS, MODE_PRIVATE)
                .getString(GuardVpnService.KEY_IPS, IpRules.DEFAULT_IPS);
    }

    private boolean saveRules() {
        String raw = addresses.getText().toString();
        try {
            IpRules.parse(raw);
        } catch (IllegalArgumentException err) {
            Toast.makeText(this, err.getMessage(), Toast.LENGTH_LONG).show();
            return false;
        }
        getSharedPreferences(GuardVpnService.PREFS, MODE_PRIVATE).edit()
                .putString(GuardVpnService.KEY_IPS, raw).apply();
        Toast.makeText(this, "Saved; stop and start guard to apply edits", Toast.LENGTH_SHORT).show();
        return true;
    }

    private void requestVpn() {
        Intent permission = VpnService.prepare(this);
        if (permission != null) startActivityForResult(permission, REQUEST_VPN);
        else startGuard();
    }

    private void startGuard() {
        if (GuardVpnService.active) {
            Toast.makeText(this, "Stop first, then Start to apply changes",
                    Toast.LENGTH_LONG).show();
            return;
        }
        Intent intent = new Intent(this, GuardVpnService.class)
                .setAction(GuardVpnService.ACTION_START);
        startForegroundService(intent);
        status.setText("Starting... return to this screen to check status");
    }

    @Override protected void onActivityResult(int req, int result, Intent data) {
        super.onActivityResult(req, result, data);
        if (req == REQUEST_VPN && result == RESULT_OK) startGuard();
        else if (req == REQUEST_VPN) Toast.makeText(this,
                "VPN permission denied; blocker not running", Toast.LENGTH_LONG).show();
    }

    @Override protected void onResume() {
        super.onResume();
        String err = getSharedPreferences(GuardVpnService.PREFS, MODE_PRIVATE)
                .getString("error", null);
        long n = getSharedPreferences(GuardVpnService.PREFS, MODE_PRIVATE)
                .getLong(GuardVpnService.KEY_TOTAL, 0);
        status.setText((GuardVpnService.active ? "ACTIVE" : "Not active in this process") +
                " | Total intercepted packets: " + n +
                (err == null ? "" : " | Last error: " + err));
    }
}
