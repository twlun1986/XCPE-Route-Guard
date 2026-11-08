package org.local.xcpeguard;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;

/** Pure Java, independent of Android so the validation can be unit-tested. */
public final class IpRules {
    private IpRules() {}

    // Historical XCPE indicators, from Google Threat Intelligence, 2026-11-02.
    public static final String DEFAULT_IPS =
            "219.134.163.210\n" +
            "219.134.163.211\n" +
            "23.94.49.57\n" +
            "38.145.197.135";

    /** Only individually specified public IPv4 addresses are supported. */
    public static List<String> parse(String input) {
        if (input == null) throw new IllegalArgumentException("IP list is missing");
        LinkedHashSet<String> ips = new LinkedHashSet<>();
        for (String raw : input.split("\\r?\\n")) {
            String line = raw.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (!line.matches("[0-9.]+"))
                throw new IllegalArgumentException("Expected IPv4 address: " + line);
            String[] parts = line.split("\\.", -1);
            if (parts.length != 4) throw new IllegalArgumentException("Invalid IPv4: " + line);
            int[] octets = new int[4];
            for (int i = 0; i < 4; i++) {
                if (parts[i].isEmpty() || parts[i].length() > 3)
                    throw new IllegalArgumentException("Invalid IPv4: " + line);
                // Canonical decimal form: never interpret leading zero as octal.
                octets[i] = Integer.parseInt(parts[i]);
                if (octets[i] > 255 || (parts[i].length() > 1 && parts[i].charAt(0) == '0'))
                    throw new IllegalArgumentException("Invalid IPv4: " + line);
            }
            int a = octets[0], b = octets[1], c = octets[2];
            if (a == 0 || a == 10 || a == 127 || a >= 224 ||
                    (a == 100 && b >= 64 && b <= 127) ||
                    (a == 169 && b == 254) ||
                    (a == 172 && b >= 16 && b <= 31) ||
                    (a == 192 && (b == 168 || (b == 0 && c == 2))) ||
                    (a == 198 && ((b >= 18 && b <= 19) || (b == 51 && c == 100))) ||
                    (a == 203 && b == 0 && c == 113))
                throw new IllegalArgumentException("Only public IPv4 supported: " + line);
            ips.add(line);
            if (ips.size() > 128) throw new IllegalArgumentException("Maximum 128 IPs");
        }
        if (ips.isEmpty()) throw new IllegalArgumentException("Add at least one IP");
        return Collections.unmodifiableList(new ArrayList<>(ips));
    }
}
