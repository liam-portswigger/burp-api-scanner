package com.security.burp.util;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.List;
import java.util.Locale;

/**
 * Stateless helpers for inspecting HTTP messages. No business logic — just
 * the small predicates we'd otherwise duplicate across every check.
 */
public final class HttpUtils {

    private HttpUtils() {}

    /**
     * Phrases that indicate the server <em>rejected</em> the input rather than
     * acting on it. Active checks use this to avoid treating a 2xx validation
     * error (e.g. {@code {"error":"Field 'isAdmin' is not allowed"}}) as
     * evidence that a privileged action succeeded. Kept deliberately specific
     * — broad words like "error"/"invalid" alone would suppress true positives.
     */
    private static final List<String> REJECTION_MARKERS = List.of(
            "not allowed", "not permitted", "is not a valid", "isn't a valid",
            "unknown field", "unexpected field", "unrecognized field",
            "unrecognised field", "rejected", "validation failed",
            "forbidden", "access denied", "permission denied",
            "not found", "does not exist", "doesn't exist", "unauthorized",
            "unauthorised");

    public static boolean isJson(HttpRequest request) {
        return contentTypeContains(request, "application/json");
    }

    public static boolean isJson(HttpResponse response) {
        return contentTypeContains(response, "application/json");
    }

    /**
     * True if {@code marker} already appears in the baseline (unmutated)
     * response. Active checks use this to discard markers that were present
     * before any payload was sent — e.g. {@code root:x:0:0} in API
     * documentation, or an IMDS hostname mentioned in static content. Without
     * this guard, marker-presence alone produces false positives (SSRF,
     * command injection, etc.).
     */
    public static boolean baselineContains(HttpRequestResponse base, String marker) {
        if (base == null || marker == null || !base.hasResponse()) return false;
        String body = base.response().bodyToString();
        return body != null && body.contains(marker);
    }

    /** True if the response body contains a recognised rejection/validation phrase. */
    public static boolean looksRejected(HttpResponse response) {
        if (response == null) return false;
        String body = response.bodyToString();
        if (body == null) return false;
        String lower = body.toLowerCase(Locale.ROOT);
        for (String marker : REJECTION_MARKERS) {
            if (lower.contains(marker)) return true;
        }
        return false;
    }

    /** True if the request carries any common authentication header. */
    public static boolean hasAuthHeader(HttpRequest request) {
        for (HttpHeader header : request.headers()) {
            String name = header.name();
            if (name == null) continue;
            switch (name.toLowerCase(Locale.ROOT)) {
                case "authorization", "cookie", "x-api-key", "api-key",
                        "apikey", "x-auth-token", "x-access-token" -> {
                    return true;
                }
                default -> { }
            }
        }
        return false;
    }

    /** True if the host is a loopback address (no network intermediary in path). */
    public static boolean isLoopbackHost(String host) {
        if (host == null) return false;
        String h = host.toLowerCase(Locale.ROOT);
        return h.equals("localhost") || h.equals("127.0.0.1") || h.equals("::1")
                || h.equals("[::1]") || h.startsWith("127.");
    }

    public static boolean isApiPath(String path) {
        if (path == null) return false;
        String lower = path.toLowerCase(Locale.ROOT);
        return lower.contains("/api/")
                || lower.matches(".*/v\\d+/.*")
                || lower.endsWith("/graphql")
                || lower.endsWith(".json");
    }

    public static boolean isModifyingMethod(String method) {
        return "POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method);
    }

    /**
     * True if the request targets a GraphQL endpoint — either the path
     * contains {@code graphql}, or it is a JSON request whose body carries a
     * GraphQL operation (a {@code "query"} field wrapping a selection set).
     * Used to gate the GraphQL-specific active checks so they only probe real
     * GraphQL endpoints.
     */
    public static boolean isGraphQlRequest(HttpRequest request) {
        if (request == null) return false;
        String path = request.pathWithoutQuery();
        if (path != null && path.toLowerCase(Locale.ROOT).contains("graphql")) return true;
        if (isJson(request)) {
            String body = request.bodyToString();
            return body != null && body.contains("\"query\"") && body.contains("{");
        }
        return false;
    }

    private static boolean contentTypeContains(HttpRequest request, String needle) {
        for (HttpHeader header : request.headers()) {
            if ("content-type".equalsIgnoreCase(header.name())) {
                return header.value() != null
                        && header.value().toLowerCase(Locale.ROOT).contains(needle);
            }
        }
        return false;
    }

    private static boolean contentTypeContains(HttpResponse response, String needle) {
        for (HttpHeader header : response.headers()) {
            if ("content-type".equalsIgnoreCase(header.name())) {
                return header.value() != null
                        && header.value().toLowerCase(Locale.ROOT).contains(needle);
            }
        }
        return false;
    }
}
