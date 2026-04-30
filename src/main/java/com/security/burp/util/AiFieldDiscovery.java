package com.security.burp.util;

import burp.api.montoya.MontoyaApi;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Asks the AI to suggest contextually privileged JSON field names for
 * mass-assignment testing. Augments the hardcoded SENSITIVE_FIELDS list
 * with names the model thinks the server might accept given the observed
 * request shape (e.g. accountTier, organizationRole, billingPlan).
 *
 * Cached per (host + path + method + body-keys-hash). Returns at most 8
 * candidates; empty list if AI unavailable.
 */
public class AiFieldDiscovery {

    private static final int MAX_FIELDS = 8;
    private static final int MAX_NAME_LEN = 40;
    private static final int CACHE_LIMIT = 256;
    private static final Pattern KEY_PATTERN = Pattern.compile("\"([A-Za-z_][A-Za-z0-9_]*)\"\\s*:");
    private static final Pattern NAME_CHAR = Pattern.compile("[^A-Za-z0-9_]");

    private final MontoyaApi api;
    private final AiClient ai;
    private final ConcurrentMap<String, List<String>> cache = new ConcurrentHashMap<>();
    private final boolean disabled;

    public AiFieldDiscovery(MontoyaApi api, AiClient ai) {
        this.api = api;
        this.ai = ai;
        this.disabled = Boolean.getBoolean("com.security.burp.ai.discovery.disabled");
    }

    public boolean isAvailable() {
        return !disabled && ai.isAvailable();
    }

    public List<String> suggestFields(String host, String path, String method, String jsonBody) {
        if (!isAvailable()) return Collections.emptyList();
        String existingKeys = extractKeys(jsonBody);
        String cacheKey = host + "|" + path + "|" + method + "|" + Integer.toHexString(existingKeys.hashCode());
        List<String> cached = cache.get(cacheKey);
        if (cached != null) return cached;

        String system =
                "You suggest privileged JSON field names that a server might accept via mass " +
                "assignment but that are NOT already present in the user's request body. " +
                "Reply with ONLY a comma-separated list of field names (camelCase or snake_case). " +
                "Up to " + MAX_FIELDS + " names. No prose, no quotes, no explanation.";

        String user =
                "Endpoint: " + method + " " + path + "\n" +
                "Existing body fields: " + existingKeys + "\n" +
                "Suggest privileged or sensitive fields the server might accept that aren't already present.";

        String reply = ai.ask(system, user);
        List<String> out = parseList(reply, existingKeys);
        if (cache.size() < CACHE_LIMIT) cache.put(cacheKey, out);
        if (!out.isEmpty()) {
            api.logging().logToOutput("[AI Field Discovery] " + path + " -> " + out);
        }
        return out;
    }

    private static String extractKeys(String json) {
        if (json == null) return "";
        Set<String> keys = new LinkedHashSet<>();
        Matcher m = KEY_PATTERN.matcher(json);
        while (m.find()) keys.add(m.group(1));
        return String.join(", ", keys);
    }

    private static List<String> parseList(String reply, String existingKeys) {
        if (reply == null || reply.isBlank()) return Collections.emptyList();
        String firstLine = reply.split("\\r?\\n")[0];
        String[] parts = firstLine.split("[,;]");
        Set<String> existing = new LinkedHashSet<>();
        for (String e : existingKeys.split(",\\s*")) existing.add(e.toLowerCase());
        List<String> out = new ArrayList<>();
        for (String p : parts) {
            String n = NAME_CHAR.matcher(p.trim()).replaceAll("");
            if (n.isEmpty() || n.length() > MAX_NAME_LEN) continue;
            if (existing.contains(n.toLowerCase())) continue;
            if (!out.contains(n)) out.add(n);
            if (out.size() >= MAX_FIELDS) break;
        }
        return out;
    }
}
