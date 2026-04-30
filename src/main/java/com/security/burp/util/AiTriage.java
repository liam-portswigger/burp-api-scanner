package com.security.burp.util;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;

import java.util.ArrayList;
import java.util.List;

/**
 * Pre-report triage for passive findings. Asks the AI whether each finding
 * is meaningful in context; suppresses obvious false positives, keeps
 * everything else.
 *
 * Conservative by design: any prompt failure, ambiguous response, or AI
 * unavailability keeps the original issue. The detector is the source of
 * truth; AI only filters out noise on findings that are technically present
 * but not exploitable in this context (e.g. missing X-Frame-Options on a
 * JSON-only API endpoint).
 */
public class AiTriage {

    private final MontoyaApi api;
    private final AiClient ai;
    private final boolean disabled;

    public AiTriage(MontoyaApi api, AiClient ai) {
        this.api = api;
        this.ai = ai;
        this.disabled = Boolean.getBoolean("com.security.burp.ai.triage.disabled");
    }

    public List<AuditIssue> filter(List<AuditIssue> issues, HttpRequestResponse rr) {
        if (disabled || issues.isEmpty() || !ai.isAvailable()) return issues;
        List<AuditIssue> kept = new ArrayList<>(issues.size());
        for (AuditIssue issue : issues) {
            if (shouldSuppress(issue, rr)) {
                api.logging().logToOutput("[AI Triage] Suppressed: " + issue.name());
            } else {
                kept.add(issue);
            }
        }
        return kept;
    }

    private boolean shouldSuppress(AuditIssue issue, HttpRequestResponse rr) {
        try {
            String system =
                    "You triage Burp Suite passive scan findings. Reply with EXACTLY one word: " +
                    "KEEP or SUPPRESS, optionally followed by a colon and a one-sentence reason. " +
                    "SUPPRESS only if the finding is clearly not exploitable in this specific " +
                    "context (e.g. missing X-Frame-Options on a JSON-only API response, missing " +
                    "CSP on an API that never returns HTML). When in doubt, KEEP.";

            String url = safe(rr.request().url(), 200);
            String reqHeaders = safe(rr.request().headers().toString(), 500);
            String respHeaders = rr.hasResponse() ? safe(rr.response().headers().toString(), 500) : "(no response)";
            String respSnippet = rr.hasResponse() ? safe(rr.response().bodyToString(), 400) : "";

            String user = "Finding: " + issue.name() + "\n" +
                    "Severity: " + issue.severity() + "\n" +
                    "URL: " + url + "\n" +
                    "Request headers: " + reqHeaders + "\n" +
                    "Response headers: " + respHeaders + "\n" +
                    "Response body excerpt: " + respSnippet;

            String reply = ai.ask(system, user);
            if (reply == null) return false;
            return reply.toUpperCase().startsWith("SUPPRESS");
        } catch (Throwable t) {
            return false;
        }
    }

    private static String safe(String s, int max) {
        if (s == null) return "";
        s = s.replace('\n', ' ').replace('\r', ' ');
        return s.length() > max ? s.substring(0, max) + "..." : s;
    }
}
