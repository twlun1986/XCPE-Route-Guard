package org.local.xcpeguard;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;

/**
 * User-consented boot restart only. The receiver has no network access,
 * no background commands and no functionality beyond restarting the
 * visible local VPN service when the user previously pressed Start.
 */
public final class BootReceiver extends BroadcastReceiver {
    @Override public void onReceive(Context context, Intent intent) {
        if (intent == null) return;
        // Important: default OFF. Explicit Stop writes false; boot never
        // turns protection back on without the user's saved consent.
        boolean enabled = context.getSharedPreferences(GuardVpnService.PREFS,
                Context.MODE_PRIVATE).getBoolean(GuardVpnService.KEY_ENABLED, false);
        if (!StartupPolicy.mayAutoStart(enabled, intent.getAction())) return;
        try {
            context.startForegroundService(new Intent(context, GuardVpnService.class)
                    .setAction(GuardVpnService.ACTION_BOOT));
        } catch (RuntimeException error) {
            context.getSharedPreferences(GuardVpnService.PREFS, Context.MODE_PRIVATE)
                    .edit().putString("error", "Boot restart blocked: " +
                            error.getClass().getSimpleName()).apply();
        }
    }
}
