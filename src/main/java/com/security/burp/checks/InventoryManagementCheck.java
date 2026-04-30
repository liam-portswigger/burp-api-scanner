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
import com.security.burp.util.AiTriage;
import com.security.burp.util.MontoyaUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * OWASP API9:2023 - Improper Inventory Management
 */
public class InventoryManagementCheck implements PassiveScanCheck {

    private final MontoyaApi api;
    private final EndpointRegistry registry;
    private final AiTriage triage;

    public InventoryManagementCheck(MontoyaApi api, EndpointRegistry registry, AiTriage triage) {
        this.api = api;
        this.registry = registry;
        this.triage = triage;
    }

    @Override
    public String checkName() {
        return "API9:2023 Improper Inventory Management";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse rr) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            HttpRequest request = rr.request();
            try {
                registry.record(request.httpService().host(), request.pathWithoutQuery(), request.method());
            } catch (Exception ignored) {}

            if (!rr.hasResponse()) return AuditResult.auditResult(triage.filter(issues, rr));
            HttpResponse response = rr.response();
            String path = request.pathWithoutQuery();

            if (isDeprecatedApiVersion(path)) {
                api.logging().logToOutput("[Inventory Check] Deprecated API version detected: " + path);
                issues.add(createDeprecatedVersionIssue(rr, path));
            }
            if (isDebugEndpoint(path)) {
                api.logging().logToOutput("[Inventory Check] Debug endpoint exposed: " + path);
                issues.add(createDebugEndpointIssue(rr, path));
            }
            for (HttpHeader h : response.headers()) {
                String name = h.name().toLowerCase();
                if (name.equals("x-api-version") || name.equals("api-version")) {
                    String version = h.value().trim();
                    api.logging().logToOutput("[Inventory Check] API version disclosed in header: " + version);
                    issues.add(createVersionDisclosureIssue(rr, version));
                    break;
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Inventory Check] " + e.getMessage());
        }
        return AuditResult.auditResult(triage.filter(issues, rr));
    }

    private boolean isDeprecatedApiVersion(String path) {
        if (path == null) return false;
        String p = path.toLowerCase();
        return p.matches(".*/v0/.*") ||
               p.matches(".*/v1/.*") ||
               p.contains("/deprecated/") ||
               p.contains("/legacy/") ||
               p.contains("/old/") ||
               p.contains("-old") ||
               p.contains("-v1") ||
               p.contains("-deprecated");
    }

    private boolean isDebugEndpoint(String path) {
        if (path == null) return false;
        String p = path.toLowerCase();
        return p.contains("/debug") || p.contains("/test") || p.contains("/dev") ||
               p.contains("/staging") || p.contains("/_debug") || p.contains("/internal") ||
               p.contains("/admin") || p.contains("/actuator") || p.contains("/metrics") ||
               p.contains("/health") || p.contains("/status") || p.contains("/swagger") ||
               p.contains("/api-docs") || p.contains("/openapi");
    }

    private static final String API9_BACKGROUND =
            "API9:2023 - Improper Inventory Management<br><br>" +
            "APIs tend to expose more endpoints than traditional web applications, making proper and " +
            "updated documentation highly important. A proper inventory of hosts and deployed API versions " +
            "also are important to mitigate issues such as deprecated API versions and exposed debug endpoints.";

    private AuditIssue createDeprecatedVersionIssue(HttpRequestResponse rr, String path) {
        String detail = "The API endpoint appears to use a deprecated or old API version.<br><br>" +
                "Endpoint: " + path + "<br><br>" +
                "Deprecated API versions can:<br>" +
                "- Contain unpatched security vulnerabilities<br>" +
                "- Lack current security controls<br>" +
                "- Increase attack surface<br>" +
                "- Lead to inconsistent security posture<br><br>" +
                "Recommendation: Migrate to current API version, deprecate old versions with proper " +
                "sunset periods, maintain proper API inventory documentation.";
        return MontoyaUtils.makeIssue(
                "API9:2023 - Improper Inventory Management (Deprecated API Version)",
                detail, API9_BACKGROUND, "Medium", "Tentative", rr);
    }

    private AuditIssue createDebugEndpointIssue(HttpRequestResponse rr, String path) {
        String detail = "The API exposes what appears to be a debug, test, or internal endpoint.<br><br>" +
                "Endpoint: " + path + "<br><br>" +
                "Exposed debug endpoints can:<br>" +
                "- Reveal sensitive system information<br>" +
                "- Provide administrative access<br>" +
                "- Expose internal API documentation<br>" +
                "- Allow unauthorized operations<br><br>" +
                "Recommendation: Remove debug endpoints from production, implement proper access controls, " +
                "maintain inventory of all deployed endpoints.";
        return MontoyaUtils.makeIssue(
                "API9:2023 - Improper Inventory Management (Debug Endpoint Exposed)",
                detail, API9_BACKGROUND, "Medium", "Certain", rr);
    }

    private AuditIssue createVersionDisclosureIssue(HttpRequestResponse rr, String version) {
        String detail = "The API discloses version information in response headers.<br><br>" +
                "Disclosed version: " + version + "<br><br>" +
                "While not directly exploitable, version disclosure:<br>" +
                "- Aids attackers in identifying vulnerable versions<br>" +
                "- Reveals information about API architecture<br>" +
                "- Can indicate poor inventory management practices<br><br>" +
                "Recommendation: Remove version headers or ensure disclosed versions are current and documented.";
        return MontoyaUtils.makeIssue(
                "API9:2023 - Improper Inventory Management (API Version Disclosure)",
                detail, API9_BACKGROUND, "Information", "Certain", rr);
    }
}
