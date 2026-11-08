package org.local.xcpeguard;

/** Pure Java policy: no boot restart without a previously saved user choice. */
public final class StartupPolicy {
    private StartupPolicy() {}
    public static boolean mayAutoStart(boolean enabled, String broadcastAction) {
        return enabled && (
                "android.intent.action.BOOT_COMPLETED".equals(broadcastAction)
                || "android.intent.action.MY_PACKAGE_REPLACED".equals(broadcastAction)
        );
    }
}
