package com.security.burp.scanner;

import com.security.burp.utils.ApiEndpoint;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe registry of discovered API endpoints. Replaces the legacy
 * ApiScanner discovery state. Read by the UI tab; written by passive checks.
 */
public class EndpointRegistry {

    private final Map<String, ApiEndpoint> endpoints = new ConcurrentHashMap<>();

    public void record(String host, String path, String method) {
        if (path == null) return;
        String key = normalizeEndpoint(path);
        ApiEndpoint endpoint = endpoints.computeIfAbsent(key, k -> new ApiEndpoint(k, host));
        endpoint.addMethod(method == null ? "GET" : method);
    }

    public Map<String, ApiEndpoint> snapshot() {
        return new HashMap<>(endpoints);
    }

    public static boolean isApiEndpoint(String path) {
        if (path == null) return false;
        String lowerPath = path.toLowerCase();
        return lowerPath.contains("/api/") ||
               lowerPath.matches(".*/v\\d+/.*") ||
               lowerPath.endsWith(".json") ||
               lowerPath.endsWith("/graphql");
    }

    public static String normalizeEndpoint(String path) {
        // Replace numeric IDs and UUIDs with placeholders for grouping.
        return path.replaceAll("/\\d+", "/{id}")
                   .replaceAll("/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "/{uuid}")
                   .replaceAll("/[a-f0-9]{24}", "/{id}"); // MongoDB ObjectID
    }
}
