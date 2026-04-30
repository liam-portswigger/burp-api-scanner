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
 * OWASP API6:2023 - Unrestricted Access to Sensitive Business Flows
 */
public class BusinessFlowCheck implements PassiveScanCheck {

    private final MontoyaApi api;
    private final EndpointRegistry registry;

    public BusinessFlowCheck(MontoyaApi api, EndpointRegistry registry) {
        this.api = api;
        this.registry = registry;
    }

    @Override
    public String checkName() {
        return "API6:2023 Unrestricted Access to Sensitive Business Flows";
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
            String path = request.pathWithoutQuery();
            if (isSensitiveBusinessEndpoint(path) && !hasAntiAutomationMechanisms(response)) {
                api.logging().logToOutput("[Business Flow] Sensitive endpoint without anti-automation: " + path);
                issues.add(createBusinessFlowIssue(rr, path));
            }
        } catch (Exception e) {
            api.logging().logToError("[Business Flow] " + e.getMessage());
        }
        return AuditResult.auditResult(issues);
    }

    private boolean isSensitiveBusinessEndpoint(String path) {
        if (path == null) return false;
        String p = path.toLowerCase();
        return p.contains("/purchase") || p.contains("/order") || p.contains("/payment") ||
               p.contains("/checkout") || p.contains("/book") || p.contains("/reserve") ||
               p.contains("/ticket") || p.contains("/vote") || p.contains("/transfer") ||
               p.contains("/withdraw") || p.contains("/comment") || p.contains("/review") ||
               p.contains("/submit") || p.contains("/create");
    }

    private boolean hasAntiAutomationMechanisms(HttpResponse response) {
        for (HttpHeader h : response.headers()) {
            String s = (h.name() + ": " + h.value()).toLowerCase();
            if (s.contains("x-captcha") || s.contains("recaptcha") || s.contains("hcaptcha") ||
                s.contains("x-csrf-token") || s.contains("x-xsrf-token")) {
                return true;
            }
        }
        return false;
    }

    private AuditIssue createBusinessFlowIssue(HttpRequestResponse rr, String path) {
        String detail = "The API endpoint performs sensitive business operations but lacks visible " +
                "anti-automation protections.<br><br>" +
                "Endpoint: " + path + "<br><br>" +
                "Without proper protections, attackers can:<br>" +
                "- Automate purchases/bookings to scalp items<br>" +
                "- Mass submit spam comments/reviews<br>" +
                "- Manipulate voting or rating systems<br>" +
                "- Exhaust inventory through automated orders<br>" +
                "- Perform financial fraud through automation<br><br>" +
                "Recommendation: Implement CAPTCHA, rate limiting with progressive delays, " +
                "device fingerprinting, behavioral analysis, or transaction value thresholds.";
        String background = "API6:2023 - Unrestricted Access to Sensitive Business Flows<br><br>" +
                "APIs vulnerable to this risk expose a business flow - such as buying a ticket, or posting " +
                "a comment - without compensating for how the functionality could harm the business if used " +
                "excessively in an automated manner. This doesn't necessarily come from implementation bugs.";
        return MontoyaUtils.makeIssue(
                "API6:2023 - Unrestricted Access to Sensitive Business Flows",
                detail, background, "Medium", "Tentative", rr);
    }
}
