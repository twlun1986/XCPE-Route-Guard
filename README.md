# XCPE Route Guard — SVI 10P lightweight, IP-only Android application

**Status: Android Studio / Gradle source project, not a compiled APK.**

This project creates a small no-root Android VPN blocker that installs through **Emotn Store → Remote Push** once it has been compiled into an APK. It was designed for Android 12 and the SVI 10P use case. The platform's physical behavior has **not** been tested on a SVI 10P. This is a containment aid, not a cure.

## What the app actually blocks

On startup it installs *only* four IPv4 destination routes (`/32`) into a local Android `VpnService` tunnel:

```
219.134.163.210
219.134.163.211
23.94.49.57
38.145.197.135
```

Sources: Google Threat Intelligence Group, 2 Nov 2026, https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet and Synthient https://github.com/synthient/public-research/blob/main/2026/11/Videostrong/README.md

Packets matching these destination IPs enter the VPN and are deliberately discarded. **No default route is configured**, so unrelated streaming flows are meant to stay on the normal network. IPv6 is explicitly allowed to bypass instead of being accidentally disabled. The app does not create any network sockets, require `INTERNET`, send logs, fetch updates or capture full video traffic.

**Not blocked:** other IPs, domain names / `*.anyevonline.com` / `*.szbboys.com`, IPv6 destinations, general TCP 3885–3887 by port, malicious traffic from privileged apps that bypass or disable the VPN, and any malware using new infrastructure. Android per-app VPN bypass, firmware changes and network-stack differences can invalidate this design. Don't treat the box as clean.

For known malicious domains, keep TP-Link Archer BE400 HomeShield domain blocking enabled. For other compromised-network destinations, an **external gateway firewall** is needed for reliable enforcement. Prefer replacing or disconnecting compromised hardware.

## Build a signed-for-testing APK (requires Android SDK)

### Option A: Android Studio (Windows/macOS/Linux)

1. Unzip the project and open the folder containing `settings.gradle` in Android Studio.
2. Allow Android Studio to download SDK Platform 35, Android Gradle Plugin and Gradle as requested.
3. Select **Build → Build APK(s)** (or run `gradle :app:assembleDebug`).
4. Find `app/build/outputs/apk/debug/app-debug.apk`.
5. Transfer that APK using **Emotn Store → Remote Push**.

This is a standard **debug-signed** APK for local testing. It is not a Play Store release and each different debug signing key changes the app identity for upgrades.

### Option B: GitHub Actions (no local Android SDK)

1. Create your own **private GitHub repository** and upload the unzipped folder's contents, including `.github/workflows/build-apk.yml`.
2. In that repository, open **Actions → Build Android APK → Run workflow** (or push to `main`).
3. After the successful run, download the **XCPE-Route-Guard-APK** artifact and extract `app-debug.apk`.
4. Remote Push the APK to your SVI 10P.

The workflow uses the Android SDK and JDK 17 on GitHub-hosted runners; it may require adjustment if SDK/Gradle versions change. The output is a local testing APK, not a security-certified solution.

## Install / run on SVI 10P

1. Open Emotn → Remote Push, and from another device on the same reachable LAN upload `app-debug.apk`.
2. Accept installation from that source. If device isolation blocks transfer, perform setup on a **temporary trusted setup network** rather than disabling home-network protection permanently.
3. Launch **XCPE Route Guard** on the TV using remote control.
4. Check the default four IPv4 addresses; press **Start blocking**.
5. Approve Android's VPN permission prompt. Confirm the VPN indicator and the app's **ACTIVE** state (reopen app).
6. Keep **Settings → VPN → Block connections without VPN = OFF**; a route-selective blocker is **not** a full-tunnel VPN and lockdown may disrupt all other internet connectivity.
7. Optional: Set **Always-on VPN** for the app *if your firmware supports it*, but keep lockdown OFF. Verify it actually reconnects after reboot. Android can revoke/kill VPNs; verify after restarts.
8. Play a stream and verify quality. If anything breaks, open the app and click **Stop blocking**, or revoke/remove its VPN in Android settings. After changes to the IP list, **Stop**, then **Start** to apply them.
9. Keep TP-Link BE400 Device Isolation on for this box. This application alone is not enough to protect your home network.

A zero drop count is possible after botnet infrastructure takedowns and does **not** mean your firmware is safe. Beware of other VPN apps: Android normally permits only one active VPN.

## Permissions / design

- `android.permission.FOREGROUND_SERVICE` — keep Android VPN worker alive while playing video.
- VPN user consent via Android `VpnService` — required; no ADB, root, camera, accessibility or storage permissions.
- No `INTERNET` permission, no tracking SDK, no background remote-control endpoint, no external dependencies except the Android Gradle build plugin.
- One daemon thread blocking on TUN reads; traffic routed into TUN is dropped. All other traffic is excluded by specific `/32` routes.
- App does **not** read system apps or inspect files; it has no ability to remove the XCPE firmware backdoor.

## Risks and security limitations

This application runs *inside potentially compromised firmware*. An `android.uid.system` XCPE component may stop it, revoke the VPN, exploit other network access, or use an entirely different destination. An IP-based list is a narrow historical filter, not reliable enterprise containment. The device may still be a residential proxy even with these specific IPs blocked. Keep it isolated from the normal LAN and consider replacement.

## Verification performed here

- The pure-Java IPv4 list parser passed local positive/negative JDK tests (`tests/RuleValidationTest.java`).
- Full Android compilation, APK signature validation and actual device/network behavior **could not be tested** in the creation environment because the Android SDK and build tools were not available. **No installable APK is included in this ZIP.**
