package org.local.xcpeguard;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Build;
import android.os.IBinder;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.List;

/**
 * Offline, device-local VPN:
 *  (1) intercept and discard four specified IPv4 /32 destinations;
 *  (2) intercept only the Android system's IPv4 UDP DNS to a local resolver;
 *  (3) answer listed domains with NXDOMAIN and relay other DNS to the
 *      currently connected physical network's configured DNS server.
 * Never proxies video/web packets; no telemetry, callbacks or updates.
 */
public final class GuardVpnService extends VpnService {
    public static final String ACTION_START = "org.local.xcpeguard.START";
    public static final String ACTION_STOP = "org.local.xcpeguard.STOP";
    public static final String ACTION_BOOT = "org.local.xcpeguard.BOOT";
    public static final String PREFS = "guard";
    public static final String KEY_IPS = "ips";
    public static final String KEY_DOMAINS = "domains";
    public static final String KEY_TOTAL = "dropped";
    public static final String KEY_BLOCKED_DNS = "blocked_dns";
    public static final String KEY_ENABLED = "protection_enabled";
    public static volatile boolean active = false;
    private static final String CHANNEL = "xcpe_guard_status_v3";
    private static final long NETWORK_RETRY_MS = 12000L;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private Runnable pendingRetry;
    private ParcelFileDescriptor tun;
    private volatile boolean stopping;
    private Thread readerThread;
    private long dropped;
    private long blockedDns;
    private List<String> domainRules;

    @Override public synchronized int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            // Android can keep a VpnService bound after stopSelf().
            // Close the actual TUN interface here, not only in onDestroy().
            getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                    .putBoolean(KEY_ENABLED, false).commit();
            shutdownProtection();
            stopSelf();
            return START_NOT_STICKY;
        }
        // A sticky restart, boot or OS always-on start is allowed ONLY
        // after the person explicitly pressed Start Protection.
        if (!getSharedPreferences(PREFS, MODE_PRIVATE)
                .getBoolean(KEY_ENABLED, false)) {
            shutdownProtection();
            stopSelf();
            return START_NOT_STICKY;
        }
        stopping = false;
        createChannel();
        startForeground(1, notification("STARTING: preparing IP + DNS protection"));
        if (tun == null && pendingRetry == null) connectOrRetry();
        return START_STICKY;
    }

    private Notification notification(String state) {
        PendingIntent openUi = PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        return new Notification.Builder(this, CHANNEL)
                .setSmallIcon(R.drawable.ic_guard_status)
                .setContentTitle("XCPE Route Guard by Nikaido Wei")
                .setContentText(state)
                .setContentIntent(openUi)
                .setOngoing(true)
                .setOnlyAlertOnce(true)
                .build();
    }

    private void updateNotification(String state) {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) manager.notify(1, notification(state));
    }

    private synchronized void connectOrRetry() {
        pendingRetry = null;
        if (stopping || tun != null || !getSharedPreferences(PREFS, MODE_PRIVATE)
                .getBoolean(KEY_ENABLED, false)) return;
        try {
            if (VpnService.prepare(this) != null) {
                getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                        .putString("error", "VPN permission missing: open the app to approve").apply();
                shutdownProtection();
                stopSelf();
                return;
            }
            if (selectUpstream() == null) {
                updateNotification("WAITING: physical network DNS not ready");
                scheduleNetworkRetry();
                return;
            }
            startProtection();
            updateNotification("ACTIVE: IP and local DNS blocking");
        } catch (Exception e) {
            active = false;
            // An unsuccessful VPN setup must not retain a partial tunnel.
            ParcelFileDescriptor failed = tun;
            tun = null;
            if (failed != null) try { failed.close(); } catch (IOException ignored) {}
            getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                    .putString("error", e.getClass().getSimpleName() +
                            ": " + e.getMessage()).apply();
            updateNotification("WAITING: retrying VPN and network setup");
            scheduleNetworkRetry();
        }
    }

    private synchronized void scheduleNetworkRetry() {
        if (stopping || pendingRetry != null || !getSharedPreferences(PREFS, MODE_PRIVATE)
                .getBoolean(KEY_ENABLED, false)) return;
        pendingRetry = this::connectOrRetry;
        mainHandler.postDelayed(pendingRetry, NETWORK_RETRY_MS);
    }

    private void createChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) manager.createNotificationChannel(new NotificationChannel(
                    CHANNEL, "XCPE protection status", NotificationManager.IMPORTANCE_LOW));
        }
    }

    private synchronized void startProtection() throws IOException {
        if (VpnService.prepare(this) != null) throw new SecurityException("VPN approval missing");
        String ipText = getSharedPreferences(PREFS, MODE_PRIVATE).getString(KEY_IPS, IpRules.DEFAULT_IPS);
        String domains = getSharedPreferences(PREFS, MODE_PRIVATE).getString(KEY_DOMAINS, DomainRules.DEFAULT_DOMAINS);
        List<String> ips = IpRules.parse(ipText);
        domainRules = DomainRules.parse(domains);
        if (selectUpstream() == null) throw new IOException(
                "No physical-network IPv4 DNS found; connect Wi-Fi/Ethernet and restart");
        Builder vpn = new Builder()
                .setSession("XCPE Route Guard by Nikaido Wei")
                .setMtu(1500)
                .setBlocking(true)
                .addAddress("198.18.0.2", 32)
                .addDnsServer(DnsPacket.LOCAL_DNS);
        vpn.allowFamily(OsConstants.AF_INET6); // never force all IPv6 video traffic through VPN
        vpn.addRoute(DnsPacket.LOCAL_DNS, 32);
        for (String ip : ips) vpn.addRoute(ip, 32);
        tun = vpn.establish();
        if (tun == null) throw new SecurityException("VPN establishment was denied");
        dropped = getSharedPreferences(PREFS, MODE_PRIVATE).getLong(KEY_TOTAL, 0);
        blockedDns = getSharedPreferences(PREFS, MODE_PRIVATE).getLong(KEY_BLOCKED_DNS, 0);
        stopping = false;
        active = true;
        final ParcelFileDescriptor descriptor = tun;
        readerThread = new Thread(() -> processPackets(descriptor), "xcpe-local-dns");
        readerThread.start();
        getSharedPreferences(PREFS, MODE_PRIVATE).edit().remove("error").apply();
    }

    private static final class Upstream {
        final Network network;
        final InetAddress dns;
        Upstream(Network network, InetAddress dns) { this.network = network; this.dns = dns; }
    }

    /** Uses the connected network's own DNS; never a hardcoded tracking resolver. */
    private Upstream selectUpstream() {
        ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) return null;
        Network[] all = cm.getAllNetworks();
        for (Network network : all) {
            NetworkCapabilities nc = cm.getNetworkCapabilities(network);
            if (nc == null || nc.hasTransport(NetworkCapabilities.TRANSPORT_VPN) ||
                    !nc.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
            LinkProperties lp = cm.getLinkProperties(network);
            if (lp == null) continue;
            for (InetAddress dns : lp.getDnsServers()) {
                if (dns instanceof Inet4Address) return new Upstream(network, dns);
            }
        }
        return null;
    }

    private void processPackets(ParcelFileDescriptor descriptor) {
        byte[] input = new byte[32768];
        try (FileInputStream in = new FileInputStream(descriptor.getFileDescriptor());
             FileOutputStream out = new FileOutputStream(descriptor.getFileDescriptor())) {
            while (!stopping) {
                int len = in.read(input);
                if (len < 0) break;
                if (len == 0) continue;
                DnsPacket.Query request = DnsPacket.decode(input, len);
                if (request == null) {
                    dropped++;
                    if ((dropped & 63) == 0) persist();
                    continue;
                }
                byte[] reply;
                if (DomainRules.matches(domainRules, request.name)) {
                    reply = DnsPacket.errorReply(request.payload, 3); // NXDOMAIN
                    blockedDns++;
                } else {
                    reply = resolveByPhysicalNetwork(request.payload);
                    if (reply == null) reply = DnsPacket.errorReply(request.payload, 2);
                }
                if (reply != null) out.write(DnsPacket.wrapReply(request, reply));
                if (((blockedDns + dropped) & 31) == 0) persist();
            }
        } catch (Exception e) {
            if (!stopping) getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                    .putString("error", e.toString()).apply();
        } finally {
            persist();
            if (!stopping && readerThread == Thread.currentThread()) {
                active = false;
                readerThread = null;
                ParcelFileDescriptor fd = tun;
                tun = null;
                if (fd != null) try { fd.close(); } catch (IOException ignored) {}
                mainHandler.post(() -> {
                    if (getSharedPreferences(PREFS, MODE_PRIVATE)
                            .getBoolean(KEY_ENABLED, false)) {
                        updateNotification("WAITING: restoring the local VPN");
                        scheduleNetworkRetry();
                    }
                });
            }
        }
    }

    /** Only outbound operation permitted: UDP/53 to physical-network DNS. */
    private byte[] resolveByPhysicalNetwork(byte[] question) {
        Upstream upstream = selectUpstream(); // also follows Wi-Fi/Ethernet changes
        if (upstream == null) return null;
        try (DatagramSocket socket = new DatagramSocket()) {
            if (!protect(socket)) return null;
            upstream.network.bindSocket(socket);
            socket.connect(upstream.dns, 53);
            socket.setSoTimeout(1500);
            socket.send(new DatagramPacket(question, question.length, upstream.dns, 53));
            byte[] data = new byte[4096];
            DatagramPacket answer = new DatagramPacket(data, data.length);
            socket.receive(answer);
            byte[] reply = new byte[answer.getLength()];
            System.arraycopy(data, 0, reply, 0, reply.length);
            return DnsPacket.validUpstreamResponse(question, reply) ? reply : null;
        } catch (IOException | RuntimeException ignored) {
            return null; // SERVFAIL on upstream failure: never silently allow a blocked domain
        }
    }

    private void persist() {
        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .putLong(KEY_TOTAL, dropped)
                .putLong(KEY_BLOCKED_DNS, blockedDns).apply();
    }

    /** Release the actual VPN interface, even when the service remains bound. */
    private synchronized void shutdownProtection() {
        stopping = true;
        active = false;
        if (pendingRetry != null) {
            mainHandler.removeCallbacks(pendingRetry);
            pendingRetry = null;
        }
        Thread oldReader = readerThread;
        readerThread = null;
        ParcelFileDescriptor fd = tun;
        tun = null;
        if (fd != null) try { fd.close(); } catch (IOException ignored) {}
        if (oldReader != null) oldReader.interrupt();
        stopForeground(STOP_FOREGROUND_REMOVE);
    }

    @Override public synchronized void onDestroy() {
        shutdownProtection();
        super.onDestroy();
    }

    @Override public void onRevoke() {
        getSharedPreferences(PREFS, MODE_PRIVATE).edit()
                .putBoolean(KEY_ENABLED, false).apply();
        shutdownProtection();
        stopSelf();
    }
    @Override public IBinder onBind(Intent intent) { return super.onBind(intent); }
}
