# XCPE Route Guard v0.2.1 — offline IP + DNS containment

**Author: Nikaido Wei**

This source builds a **device-local** Android TV VPN utility for the SVI 10P and other compatible Android devices (Android 8+). It does not rely on an ASUS/TP-Link/OpenWrt router, and does not require root or ADB. It is **containment, not malware removal**.

## Blocklists (locally bundled; editable within the app)

From Google Threat Intelligence Group, **2 November 2026**, "Shutting the Door on the XCPE Botnet":
https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet

IPv4:
- 219.134.163.210 (MQTT broker cited in the text)
- 219.134.163.211 (MQTT broker)
- 23.94.49.57 (operator hosting/C2)
- 38.145.197.135 (operator hosting/C2)

Domains (each applies to the apex and **all** subdomains):
- anyevonline.com
- szbboys.com (including mqtt.szbboys.com and ott.szbboys.com)
- intermedia-arts.tv
- yokatvonline.com (YokaTV fallback, may affect YokaTV-related features)

Do **not** add `github.com` to the DNS list just because Google's report identifies operator-controlled GitHub release URL *paths*. DNS cannot distinguish paths such as `github.com/Aviciiii/` and would disable all of GitHub. Likewise `ip-api.com` and Google STUN infrastructure are shared legitimate infrastructure and are not included.

## Architecture

- Android `VpnService` with only **specific /32 IPv4 routes** for the known IPs and the local DNS address `198.18.0.1`.
- Android standard IPv4 **UDP DNS queries** to the local resolver are inspected.
- Blocked domain suffixes return **NXDOMAIN**, without an upstream query.
- Unblocked DNS queries are forwarded over UDP/53 only to the current physical network's configured IPv4 DNS server, with a short timeout.
- Other video/web traffic stays on the original network and is not routed through the app.
- No telemetry, automatic updates, remote management, remote code, file downloads or boot-start permissions.

### Limitations

- Not guaranteed against firmware-privileged malware that disables/bypasses Android's VPN.
- Does not intercept direct DNS to a hardcoded external resolver, DNS-over-HTTPS, DNS-over-TLS, TCP DNS, or IPv6 DNS/traffic.
- No IPv6-only DNS support; requires a physical network with an IPv4 DNS server.
- Does not block brand-new botnet C2 infrastructure or endpoint IP addresses absent from the list.
- Each device can have only one Android VPN at a time.
- Leave Android **Block connections without VPN** OFF. This app intentionally uses selective routes.
- Some Android TV launchers conceal VPN icons and notifications. Use the in-app **ACTIVE** status and counters.
- Changing networks is supported for new DNS queries, if the new network has an IPv4 resolver; a VPN restart may still be needed on unusual TV firmware.

## Installing / updating

1. GitHub Actions → **Build Android APK** → select the successful run → download `XCPE-Route-Guard-APK`.
2. Extract `app-debug.apk` and upload it through Emotn Store → Remote Push.
3. The initial build and this new debug build may have **different debug signing certificates**. If Android says the update is incompatible, **uninstall the old XCPE Route Guard**, then install this version. Note this resets custom rules and counters.
4. Launch, review the IP/domain lists, choose **Start protection**, and approve Android VPN permission.
5. Use **Refresh status** to confirm ACTIVE. Test streaming and non-blocked DNS.
6. If internet access breaks, use **Stop protection** and review the network's DNS configuration.

The GitHub workflow performs source pattern checks, local rule/DNS unit tests, APK compilation, and an APK permission inspection. Those checks do not replace device testing, independent security assessment or a full firmware cleanup.

## Stop protection reliably (v0.2.1)

- Tap **Stop protection**. The app now calls Android `stopService()` directly rather than sending a new start command with a STOP action.
- The service shuts down its TUN descriptor, removes the foreground notification and sets its in-process status to INACTIVE. The on-screen status automatically refreshes.
- An explicit user-enabled flag guards against unwanted `START_STICKY` restarts; the service now returns `START_NOT_STICKY`.
- If the device reactivates a VPN due to firmware-specific Always-on settings, go to Android **Settings → Network & Internet → VPN** and turn off Always-on VPN / disconnect. On stripped-down TV firmware, **Settings → Apps → XCPE Route Guard → Force Stop** will terminate the old service.
- This version contains source-level lifecycle checks in the CI pipeline. Stopping/starting on the physical SVI 10P has not been verified in a hardware test.
