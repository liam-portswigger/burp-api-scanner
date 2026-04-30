package com.security.burp.util;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Shared helpers used by all Montoya scan checks.
 * Centralises legacy-string-severity mapping and AuditIssue construction so the
 * per-check translations stay close to their original shape.
 */
public final class MontoyaUtils {

    private MontoyaUtils() {}

    public static AuditIssueSeverity severity(String legacy) {
        if (legacy == null) return AuditIssueSeverity.INFORMATION;
        switch (legacy.trim().toLowerCase()) {
            // Montoya has no Critical level - map to HIGH (Burp's highest standard severity).
            case "critical":
            case "high":
                return AuditIssueSeverity.HIGH;
            case "medium":
                return AuditIssueSeverity.MEDIUM;
            case "low":
                return AuditIssueSeverity.LOW;
            case "information":
            case "info":
            default:
                return AuditIssueSeverity.INFORMATION;
        }
    }

    public static AuditIssueConfidence confidence(String legacy) {
        if (legacy == null) return AuditIssueConfidence.TENTATIVE;
        switch (legacy.trim().toLowerCase()) {
            case "certain":
                return AuditIssueConfidence.CERTAIN;
            case "firm":
                return AuditIssueConfidence.FIRM;
            case "tentative":
            default:
                return AuditIssueConfidence.TENTATIVE;
        }
    }

    /**
     * Build an AuditIssue mirroring the legacy CustomScanIssue construction shape.
     * Remediation text is left empty (legacy CustomScanIssue always returned null).
     */
    public static AuditIssue makeIssue(String name,
                                       String detail,
                                       String background,
                                       String severity,
                                       String confidence,
                                       String baseUrl,
                                       List<HttpRequestResponse> evidence) {
        AuditIssueSeverity sev = severity(severity);
        return AuditIssue.auditIssue(
                name,
                detail,
                /* remediation */ "",
                baseUrl,
                sev,
                confidence(confidence),
                background,
                /* remediationBackground */ "",
                /* typicalSeverity */ sev,
                evidence
        );
    }

    public static AuditIssue makeIssue(String name,
                                       String detail,
                                       String background,
                                       String severity,
                                       String confidence,
                                       HttpRequestResponse base,
                                       HttpRequestResponse... evidence) {
        List<HttpRequestResponse> list = new ArrayList<>();
        if (evidence != null && evidence.length > 0) {
            for (HttpRequestResponse rr : evidence) {
                if (rr != null) list.add(rr);
            }
        } else if (base != null) {
            list.add(base);
        }
        String baseUrl;
        if (base != null && base.request() != null) {
            baseUrl = base.request().url();
        } else if (!list.isEmpty() && list.get(0).request() != null) {
            baseUrl = list.get(0).request().url();
        } else {
            baseUrl = "";
        }
        return makeIssue(name, detail, background, severity, confidence, baseUrl, list);
    }

    // ---------- Header helpers ----------

    public static String headerValue(HttpRequest request, String name) {
        for (HttpHeader h : request.headers()) {
            if (h.name().equalsIgnoreCase(name)) return h.value();
        }
        return null;
    }

    public static String headerValue(HttpResponse response, String name) {
        for (HttpHeader h : response.headers()) {
            if (h.name().equalsIgnoreCase(name)) return h.value();
        }
        return null;
    }

    public static boolean hasHeaderStartingWith(HttpRequest request, String prefixLower) {
        for (HttpHeader h : request.headers()) {
            if ((h.name() + ": " + h.value()).toLowerCase().startsWith(prefixLower.toLowerCase())) return true;
        }
        return false;
    }

    public static List<String> headerLines(HttpRequest request) {
        List<String> lines = new ArrayList<>();
        for (HttpHeader h : request.headers()) {
            lines.add(h.name() + ": " + h.value());
        }
        return lines;
    }

    public static List<String> headerLines(HttpResponse response) {
        List<String> lines = new ArrayList<>();
        for (HttpHeader h : response.headers()) {
            lines.add(h.name() + ": " + h.value());
        }
        return lines;
    }

    public static String contentType(HttpRequest request) {
        String v = headerValue(request, "Content-Type");
        return v == null ? null : v.toLowerCase();
    }

    public static String contentType(HttpResponse response) {
        String v = headerValue(response, "Content-Type");
        return v == null ? null : v.toLowerCase();
    }

    /** url-path of a HttpRequest, lowercased, never null. */
    public static String pathLower(HttpRequest request) {
        try {
            return request.pathWithoutQuery() == null ? "" : request.pathWithoutQuery().toLowerCase();
        } catch (Exception e) {
            return "";
        }
    }

    /**
     * Replace path of an HTTP request, preserving query string by using withPath.
     * (HttpRequest.path() includes query, withPath replaces it.)
     */
    public static HttpRequest withReplacedPath(HttpRequest request, String newPath) {
        return request.withPath(newPath);
    }

    public static byte[] bodyBytes(HttpRequest req) {
        ByteArray b = req.body();
        return b == null ? new byte[0] : b.getBytes();
    }

    public static byte[] bodyBytes(HttpResponse resp) {
        ByteArray b = resp.body();
        return b == null ? new byte[0] : b.getBytes();
    }

    public static String bodyString(HttpResponse resp) {
        return resp == null ? "" : resp.bodyToString();
    }

    public static List<String> empty() {
        return new ArrayList<>();
    }

    public static byte[] copyBodyTail(byte[] full, int offset) {
        if (full == null || offset >= full.length) return new byte[0];
        return Arrays.copyOfRange(full, offset, full.length);
    }
}
