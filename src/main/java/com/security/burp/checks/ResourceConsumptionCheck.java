package com.security.burp.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import com.security.burp.scanner.EndpointRegistry;
import com.security.burp.util.MontoyaUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * OWASP API4:2023 - Unrestricted Resource Consumption
 */
public class ResourceConsumptionCheck implements PassiveScanCheck {

    private final MontoyaApi api;
    private final EndpointRegistry registry;

    public ResourceConsumptionCheck(MontoyaApi api, EndpointRegistry registry) {
        this.api = api;
        this.registry = registry;
    }

    @Override
    public String checkName() {
        return "API4:2023 Unrestricted Resource Consumption";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse rr) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            HttpRequest request = rr.request();
            try {
                registry.record(request.httpService().host(), request.pathWithoutQuery(), request.method());
            } catch (Exception ignored) {}

            if (!rr.hasResponse()) return AuditResult.auditResult(issues);
            HttpResponse response = rr.response();

            boolean hasRateLimitHeader = false;
            for (HttpHeader h : response.headers()) {
                String n = h.name().toLowerCase();
                if (n.startsWith("x-ratelimit-") || n.startsWith("x-rate-limit-") || n.startsWith("ratelimit-")) {
                    hasRateLimitHeader = true;
                    break;
                }
            }

            int responseSize = response.toByteArray().length();
            if (responseSize > 5000000) {
                api.logging().logToOutput("[Resource Check] Large response detected: " + responseSize + " bytes");
                issues.add(createLargeResponseIssue(rr, responseSize));
            }

            String path = MontoyaUtils.pathLower(request);
            if (!hasRateLimitHeader && isResourceIntensiveEndpoint(path)) {
                api.logging().logToOutput("[Resource Check] Resource-intensive endpoint without rate limiting: " + path);
                issues.add(createMissingRateLimitIssue(rr, path));
            }
        } catch (Exception e) {
            api.logging().logToError("[Resource Check] " + e.getMessage());
        }
        return AuditResult.auditResult(issues);
    }

    private boolean isResourceIntensiveEndpoint(String path) {
        return path.contains("/search") ||
               path.contains("/export") ||
               path.contains("/report") ||
               path.contains("/download") ||
               path.contains("/bulk") ||
               path.contains("/batch") ||
               path.contains("/query");
    }

    private static final String API4_BACKGROUND =
            "API4:2023 - Unrestricted Resource Consumption<br><br>" +
            "Satisfying API requests requires resources such as network bandwidth, CPU, memory, and " +
            "storage. Other resources such as emails/SMS/phone calls or biometrics validation are made " +
            "available by service providers via API integrations, and paid for per request. Successful " +
            "attacks can lead to Denial of Service or an increase of operational costs.";

    private AuditIssue createLargeResponseIssue(HttpRequestResponse rr, int size) {
        String detail = "The API returned a very large response (" + (size / 1024) + " KB).<br><br>" +
                "Large responses can lead to:<br>" +
                "- Client-side memory exhaustion<br>" +
                "- Network bandwidth consumption<br>" +
                "- Denial of Service<br><br>" +
                "Recommendation: Implement pagination, response size limits, and streaming for large datasets.";
        return MontoyaUtils.makeIssue(
                "API4:2023 - Unrestricted Resource Consumption (Large Response)",
                detail, API4_BACKGROUND, "Medium", "Certain", rr);
    }

    private AuditIssue createMissingRateLimitIssue(HttpRequestResponse rr, String path) {
        String detail = "The API endpoint appears to perform resource-intensive operations but lacks " +
                "rate limiting headers.<br><br>" +
                "Endpoint: " + path + "<br><br>" +
                "Without rate limiting, attackers can:<br>" +
                "- Execute denial of service attacks<br>" +
                "- Exhaust API quotas<br>" +
                "- Increase operational costs<br>" +
                "- Degrade service for legitimate users<br><br>" +
                "Recommendation: Implement rate limiting with headers like X-RateLimit-Limit, " +
                "X-RateLimit-Remaining, and X-RateLimit-Reset.";
        return MontoyaUtils.makeIssue(
                "API4:2023 - Unrestricted Resource Consumption (Missing Rate Limiting)",
                detail, API4_BACKGROUND, "Low", "Tentative", rr);
    }
}
