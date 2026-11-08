package org.local.xcpeguard;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.List;

/**
 * An IP-only split-tunnel blackhole. Only destination IPs listed with /32
 * routes enter the TUN; packets read from TUN are intentionally discarded.
 * No default route, DNS proxy, sockets, analytics, tracking or remote updates.
 */
public final class GuardVpnService extends VpnService {
    public static final String ACTION_START = "org.local.xcpeguard.START";
    public static final String ACTION_STOP = "org.local.xcpeguard.STOP";
    public static final String PREFS = "guard";
    public static final String KEY_IPS = "ips";
    public static final String KEY_TOTAL = "dropped";
    public static volatile boolean active = false;
    private static final String CHANNEL = "xcpe_guard_status";
    private ParcelFileDescriptor tun;
    private Thread readerThread;
    private volatile boolean stopping;
    private long dropped;

    @Override public synchronized int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            stopSelf();
            return START_NOT_STICKY;
        }
        createChannel();
        Intent ui = new Intent(this, MainActivity.class);
        PendingIntent pending = PendingIntent.getActivity(this, 0, ui,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        Notification notification = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentTitle("XCPE Route Guard")
                .setContentText("Blocking listed XCPE IPs only")
                .setOngoing(true)
                .setContentIntent(pending)
                .build();
        startForeground(1, notification);
        if (tun == null) {
            try {
                startBlocking();
            } catch (Exception error) {
                active = false;
                getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                        .putString("error", error.toString()).apply();
                stopSelf();
                return START_NOT_STICKY;
            }
        }
        return START_STICKY;
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationChannel channel = new NotificationChannel(CHANNEL,
                    "XCPE route blocking", NotificationManager.IMPORTANCE_LOW);
            NotificationManager mgr = getSystemService(NotificationManager.class);
            if (mgr != null) mgr.createNotificationChannel(channel);
        }
    }

    private synchronized void startBlocking() throws IOException {
        if (VpnService.prepare(this) != null)
            throw new SecurityException("VPN permission not granted");
        String saved = getSharedPreferences(PREFS, MODE_PRIVATE)
                .getString(KEY_IPS, IpRules.DEFAULT_IPS);
        List<String> ips = IpRules.parse(saved);
        Builder builder = new Builder()
                .setSession("XCPE Route Guard: IP only")
                .setMtu(1500)
                .setBlocking(true)
                .addAddress("198.18.0.2", 32);
        // IMPORTANT: no IPv6 routes. Explicitly allow IPv6 to continue using
        // the underlying network rather than blocking all IPv6 applications.
        builder.allowFamily(OsConstants.AF_INET6);
        // Only these /32 IPs are intercepted. Ordinary video traffic bypasses.
        for (String ip : ips) builder.addRoute(ip, 32);
        tun = builder.establish();
        if (tun == null) throw new SecurityException("VPN permission revoked");
        dropped = getSharedPreferences(PREFS, MODE_PRIVATE).getLong(KEY_TOTAL, 0);
        stopping = false;
        active = true;
        final ParcelFileDescriptor interfaceFd = tun;
        readerThread = new Thread(() -> drain(interfaceFd), "xcpe-dropper");
        readerThread.start();
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().remove("error").apply();
    }

    private void drain(ParcelFileDescriptor fd) {
        byte[] packet = new byte[32768];
        try (FileInputStream stream = new FileInputStream(fd.getFileDescriptor())) {
            while (!stopping && !Thread.currentThread().isInterrupted()) {
                int len = stream.read(packet);
                if (len < 0) break;
                if (len == 0) continue;
                // Never forward packets; consume and discard only the /32 routes.
                dropped++;
                if ((dropped & 63) == 0) persistCount();
            }
        } catch (IOException ignored) {
            // Closing the TUN on stop normally interrupts this blocking read.
        } finally {
            persistCount();
            active = false;
        }
    }

    private void persistCount() {
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().putLong(KEY_TOTAL, dropped).apply();
    }

    @Override public synchronized void onDestroy() {
        stopping = true;
        active = false;
        ParcelFileDescriptor old = tun;
        tun = null;
        if (old != null) try { old.close(); } catch (IOException ignored) { }
        readerThread = null;
        super.onDestroy();
    }

    @Override public void onRevoke() { stopSelf(); }
    @Override public IBinder onBind(Intent intent) { return super.onBind(intent); }
}
