package org.local.xcpeguard;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;

/** Exact-domain and subdomain DNS deny rules. Bundled locally; no remote list. */
public final class DomainRules {
    private DomainRules() {}
    // Google Threat Intelligence, 2 Nov 2026. YokaTV is a documented fallback.
    public static final String DEFAULT_DOMAINS =
            "anyevonline.com\n" +
            "szbboys.com\n" +
            "intermedia-arts.tv\n" +
            "yokatvonline.com";

    public static List<String> parse(String input) {
        if (input == null) throw new IllegalArgumentException("Domain list missing");
        LinkedHashSet<String> result = new LinkedHashSet<>();
        for (String raw : input.split("\\r?\\n")) {
            String host = raw.trim().toLowerCase(Locale.ROOT);
            if (host.isEmpty() || host.startsWith("#")) continue;
            if (host.startsWith("*.")) host = host.substring(2);
            if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
            if (host.length() > 253 || !host.matches("[a-z0-9.-]+") ||
                    !host.contains(".") || host.startsWith(".") ||
                    host.endsWith(".") || host.contains(".."))
                throw new IllegalArgumentException("Invalid domain: " + raw);
            for (String label : host.split("\\.")) {
                if (label.length() == 0 || label.length() > 63 ||
                        label.startsWith("-") || label.endsWith("-"))
                    throw new IllegalArgumentException("Invalid domain: " + raw);
            }
            result.add(host);
            if (result.size() > 256) throw new IllegalArgumentException("Maximum 256 domains");
        }
        if (result.isEmpty()) throw new IllegalArgumentException("Enter at least one domain");
        return Collections.unmodifiableList(new ArrayList<>(result));
    }

    public static boolean matches(List<String> rules, String name) {
        if (name == null) return false;
        String host = name.toLowerCase(Locale.ROOT);
        if (host.endsWith(".")) host = host.substring(0, host.length() - 1);
        for (String rule : rules) {
            if (host.equals(rule) || host.endsWith("." + rule)) return true;
        }
        return false;
    }
}
