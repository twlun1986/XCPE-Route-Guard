# XCPE Route Guard v0.3.0 — offline IP + DNS containment

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
- No telemetry, automatic updates, remote management, remote code or file downloads. A BOOT_COMPLETED receiver is included strictly for a user-enabled restart.

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


## User-controlled Always-on behavior (v0.3.0)

- **Start Protection** saves a local boolean preference `protection_enabled=true` and starts the local VPN. If Android kills the process, `START_STICKY` allows it to recover while enabled.
- **Stop Protection** saves `false` and sends an explicit `ACTION_STOP` to the running VPN service. The service **immediately closes the TUN file descriptor**, drops the active state, cancels retry jobs, removes the foreground notification and then calls `stopSelf()`. This works even when Android's VPN binding delays `onDestroy()`.
- A non-exported **BOOT_COMPLETED** and **MY_PACKAGE_REPLACED** receiver starts the foreground service *only* if the preference was previously enabled by the user.
- If Wi-Fi/Ethernet is not ready after reboot, the visible service waits and retries every 12 seconds. It does not route traffic through a default VPN gateway and does not contact a cloud service.
- If the Android VPN authorization was revoked or Android firmware blocks background start, open the app and approve the VPN again. Some TV-box firmware suppresses boot receivers or kills background apps.
- The Android system **Always-on VPN** option, if available in Android Settings, provides stronger OS-enforced restart and can be used too. When configured, it may require disabling the system Always-on switch to stop the VPN permanently.
- Keep **Block connections without VPN OFF**, because this selective-route VPN deliberately passes normal streaming traffic outside the tunnel.
- Installing a debug-signed APK built on a new GitHub runner can fail signature verification. Back up custom rules and reinstall if Android rejects an upgrade.

## Test sequence

1. Install/upgrade to v0.3.0 through Emotn Remote Push.
2. Tap **Start Protection**; verify **ACTIVE** and **Reboot restart: ON**.
3. Tap **Stop Protection**; the screen should show **INACTIVE** and **Reboot restart: OFF**.
4. Reopen the app and verify still INACTIVE. Reboot the TV box; verify it remains INACTIVE.
5. Tap **Start Protection** again, verify ACTIVE, reboot, allow network initialization, then verify ACTIVE again.
6. If the boot restart fails, inspect any firmware-specific **Autostart / Battery optimization** controls and Android's built-in VPN settings. Android TV firmware support varies.

Only static logic checks and compilation are performed automatically; the SVI 10P's real OS/service behavior must still be verified on-device.
