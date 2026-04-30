package com.security.burp.checks;

import burp.api.montoya.MontoyaApi;
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
 * OWASP API10:2023 - Unsafe Consumption of APIs
 */
public class UnsafeApiConsumptionCheck implements PassiveScanCheck {

    private static final String[] THIRD_PARTY_APIS = {
        "googleapis.com", "github.com", "stripe.com", "twilio.com",
        "sendgrid.com", "amazonaws.com", "azure.com", "cloudflare.com",
        "slack.com", "api.twitter.com", "graph.facebook.com"
    };

    private final MontoyaApi api;
    private final EndpointRegistry registry;

    public UnsafeApiConsumptionCheck(MontoyaApi api, EndpointRegistry registry) {
        this.api = api;
        this.registry = registry;
    }

    @Override
    public String checkName() {
        return "API10:2023 Unsafe Consumption of APIs";
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

            String responseBody = response.bodyToString();
            if (responseBody.isEmpty()) {
                // Still allow webhook endpoint check below.
            }

            for (String thirdPartyApi : THIRD_PARTY_APIS) {
                if (responseBody.contains(thirdPartyApi)) {
                    api.logging().logToOutput("[API Consumption] Third-party API reference found: " + thirdPartyApi);
                    if (!hasValidationIndicators(responseBody)) {
                        issues.add(createUnsafeConsumptionIssue(rr, thirdPartyApi));
                        break;
                    }
                }
            }

            String path = MontoyaUtils.pathLower(request);
            if (isWebhookEndpoint(path)) {
                api.logging().logToOutput("[API Consumption] Webhook endpoint detected: " + path);
                issues.add(createWebhookIssue(rr, path));
            }
        } catch (Exception e) {
            api.logging().logToError("[API Consumption] " + e.getMessage());
        }
        return AuditResult.auditResult(issues);
    }

    private boolean hasValidationIndicators(String responseBody) {
        return responseBody.contains("\"validated\"") ||
               responseBody.contains("\"sanitized\"") ||
               responseBody.contains("\"verified\"");
    }

    private boolean isWebhookEndpoint(String path) {
        return path.contains("/webhook") ||
               path.contains("/callback") ||
               path.contains("/notify") ||
               path.contains("/event") ||
               path.contains("/integration");
    }

    private static final String API10_BACKGROUND =
            "API10:2023 - Unsafe Consumption of APIs<br><br>" +
            "Developers tend to trust data received from third-party APIs more than user input, and so " +
            "tend to adopt weaker security standards. In order to compromise APIs, attackers go after " +
            "integrated third-party services instead of trying to compromise the target API directly.";

    private AuditIssue createUnsafeConsumptionIssue(HttpRequestResponse rr, String thirdPartyApi) {
        String detail = "The API appears to consume data from third-party APIs without visible validation.<br><br>" +
                "Third-party API detected: " + thirdPartyApi + "<br><br>" +
                "Unsafe consumption of third-party APIs can lead to:<br>" +
                "- Injection attacks through untrusted data<br>" +
                "- Data integrity issues<br>" +
                "- Business logic bypass<br>" +
                "- Supply chain attacks<br><br>" +
                "Recommendation: Always validate and sanitize data from third-party APIs. Don't blindly " +
                "trust external sources. Implement schema validation, input sanitization, and rate limiting " +
                "for third-party API consumption.";
        return MontoyaUtils.makeIssue(
                "API10:2023 - Unsafe Consumption of APIs (Third-Party API Integration)",
                detail, API10_BACKGROUND, "Medium", "Tentative", rr);
    }

    private AuditIssue createWebhookIssue(HttpRequestResponse rr, String path) {
        String detail = "The API exposes a webhook endpoint that receives data from external sources.<br><br>" +
                "Webhook endpoint: " + path + "<br><br>" +
                "Webhooks are particularly vulnerable to unsafe API consumption because:<br>" +
                "- They accept unsolicited data from external sources<br>" +
                "- Data validation is often insufficient<br>" +
                "- Signature verification may be missing<br>" +
                "- Rate limiting is frequently absent<br><br>" +
                "Recommendation: Implement strict webhook signature verification (HMAC), validate all " +
                "incoming data against a schema, use allowlists for webhook sources, implement rate limiting, " +
                "and never trust webhook data without validation.";
        return MontoyaUtils.makeIssue(
                "API10:2023 - Unsafe Consumption of APIs (Webhook Endpoint)",
                detail, API10_BACKGROUND, "Medium", "Tentative", rr);
    }
}
