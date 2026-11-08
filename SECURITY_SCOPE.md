# XCPE Route Guard — security scope and limitations

**Author: Nikaido Wei**

## Permitted operations
- `VpnService`: selectively divert /32 IPv4 malicious destinations plus the locally designated UDP DNS resolver.
- `INTERNET`: **only** to relay ordinary DNS questions to the connected physical network's own DNS server over UDP port 53. No fixed third-party resolver.
- `ACCESS_NETWORK_STATE`: read DNS addresses from Android's active Wi-Fi/Ethernet network.
- `FOREGROUND_SERVICE`: show active protection where Android TV firmware supports notification icons.
- Editable, locally stored IP/domain rules and local packet counters.

## Explicitly absent
- No telemetry, cloud control plane, periodic rule update, account registration, proxy network or remote access.
- No APK downloader, script execution, shell commands, root/ADB interactions, dynamic code loading, accessibility automation, or silent package installs.
- No attempt to intercept or proxy ordinary streaming media packets.
- No blanket GitHub/filemail/ip-api/Google STUN blocking: shared legitimate infrastructure could be disrupted.
- No DoH/DoT support.

## Network protections are incomplete
- Blocking is indicator-specific and constrained by Android OS VPN routing semantics.
- A preinstalled system-privileged backdoor can bypass/disrupt a user app.
- Direct IPv6, nonstandard DNS, external DNS resolvers, encrypted DNS and unknown malicious networks may escape filtering.
- An infected device should remain segregated from sensitive LAN equipment if possible.
- Most reliable permanent mitigation is a verified clean firmware replacing all infected partitions, or replacing the device.

## Build/review boundary
- Sources are plain Java and Android vector XML, no third-party SDKs.
- The workflow rejects known dangerous permissions and obvious dynamic-execution network patterns; this is a guardrail, **not a formal code audit**.
- APK permission output and SHA-256 accompany each GitHub Actions artifact.

## Explicitly user-enabled reboot persistence (v0.3.0)

- The Android manifest declares `RECEIVE_BOOT_COMPLETED` only to restore the protective service after the user has previously pressed Start Protection.
- The non-exported `BootReceiver` is limited to `BOOT_COMPLETED` and `MY_PACKAGE_REPLACED` and validates `StartupPolicy.mayAutoStart(enabled, action)`.
- Pressing Stop flips that saved flag OFF; the service closes its VPN interface immediately and cannot restart protection without a new manual Start.
- The service is foreground and observable; it has no auto-update, remote command, data exfiltration, shell execution or permission escalation.
- Android TV vendor firmware may independently prevent or force-restart system VPNs. This user-space app is not a substitute for a verified clean firmware.
