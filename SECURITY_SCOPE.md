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
- No APK downloader, script execution, shell commands, root/ADB interactions, dynamic code loading, accessibility automation, boot receiver, or silent package installs.
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
