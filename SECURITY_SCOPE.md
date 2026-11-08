# Security scope and assumptions

The package is designed to enforce four **historical XCPE IPv4 indicators** with selective /32 routes. It does not do port-specific filtering, host-name filtering, packet-forwarding, TLS interception, proxy detection, malware cleanup, or remote IOC updates.

Google research identifies `x.cpe` / `com.oemservice` as privileged firmware malware and `com.abc.nexus` as a module loader. If malware has the ability to run as a system UID, it can render any third-party app ineffective; it cannot be defended against by an APK alone.

Source: https://cloud.google.com/blog/topics/threat-intelligence/shutting-the-door-on-the-xcpe-botnet

Android `VpnService.Builder.addRoute()` only sends selected routes to the tunnel. `allowFamily(AF_INET6)` is essential because IPv6 could otherwise be blocked by the VPN when no IPv6 address/route is configured. `Block connections without VPN` must not be enabled because this is a split-tunnel blocker.

Sources: https://developer.android.com/reference/android/net/VpnService.Builder , https://developer.android.com/develop/connectivity/vpn
