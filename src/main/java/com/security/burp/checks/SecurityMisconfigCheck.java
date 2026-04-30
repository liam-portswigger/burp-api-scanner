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

import java.util.*;

/**
 * Security Misconfiguration Check
 * OWASP API8:2023 - Security Misconfiguration
 */
public class SecurityMisconfigCheck implements PassiveScanCheck {

    private static final Map<String, String> RECOMMENDED_HEADERS = new LinkedHashMap<>();
    static {
        RECOMMENDED_HEADERS.put("X-Content-Type-Options", "nosniff");
        RECOMMENDED_HEADERS.put("X-Frame-Options", "DENY or SAMEORIGIN");
        RECOMMENDED_HEADERS.put("Content-Security-Policy", "restrictive policy");
        RECOMMENDED_HEADERS.put("Strict-Transport-Security", "max-age value");
    }

    private static final String[] DISCLOSURE_HEADERS = {
        "Server", "X-Powered-By", "X-AspNet-Version",
        "X-AspNetMvc-Version", "X-Runtime"
    };

    private final MontoyaApi api;
    private final EndpointRegistry registry;
    private final AiTriage triage;

    public SecurityMisconfigCheck(MontoyaApi api, EndpointRegistry registry, AiTriage triage) {
        this.api = api;
        this.registry = registry;
        this.triage = triage;
    }

    @Override
    public String checkName() {
        return "API8:2023 Security Misconfiguration";
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

            issues.addAll(checkMissingSecurityHeaders(rr, response));
            issues.addAll(checkDisclosureHeaders(rr, response));
            issues.addAll(checkCORSMisconfig(rr, request, response));
            issues.addAll(checkInsecureProtocol(rr, request));
            issues.addAll(checkVerboseErrors(rr, response));
        } catch (Exception e) {
            api.logging().logToError("[Misconfig Check] " + e.getMessage());
        }
        return AuditResult.auditResult(triage.filter(issues, rr));
    }

    private List<AuditIssue> checkMissingSecurityHeaders(HttpRequestResponse rr, HttpResponse response) {
        List<AuditIssue> issues = new ArrayList<>();
        Map<String, String> headerMap = new HashMap<>();
        for (HttpHeader h : response.headers()) {
            headerMap.put(h.name().toLowerCase(), h.value());
        }
        List<String> missing = new ArrayList<>();
        for (String name : RECOMMENDED_HEADERS.keySet()) {
            if (!headerMap.containsKey(name.toLowerCase())) missing.add(name);
        }
        if (!missing.isEmpty()) {
            api.logging().logToOutput("[Misconfig Check] Missing security headers: " + missing);
            issues.add(createMissingHeadersIssue(rr, missing));
        }
        return issues;
    }

    private List<AuditIssue> checkDisclosureHeaders(HttpRequestResponse rr, HttpResponse response) {
        List<AuditIssue> issues = new ArrayList<>();
        List<String> found = new ArrayList<>();
        for (HttpHeader h : response.headers()) {
            for (String disc : DISCLOSURE_HEADERS) {
                if (h.name().equalsIgnoreCase(disc)) {
                    found.add(h.name() + ": " + h.value());
                    break;
                }
            }
        }
        if (!found.isEmpty()) {
            api.logging().logToOutput("[Misconfig Check] Information disclosure headers: " + found);
            issues.add(createDisclosureHeadersIssue(rr, found));
        }
        return issues;
    }

    private List<AuditIssue> checkCORSMisconfig(HttpRequestResponse rr, HttpRequest request, HttpResponse response) {
        List<AuditIssue> issues = new ArrayList<>();
        String acao = MontoyaUtils.headerValue(response, "Access-Control-Allow-Origin");
        if (acao == null) return issues;
        acao = acao.trim();
        if (acao.equals("*")) {
            String acac = MontoyaUtils.headerValue(response, "Access-Control-Allow-Credentials");
            boolean hasCreds = acac != null && acac.trim().equalsIgnoreCase("true");
            if (hasCreds) {
                api.logging().logToOutput("[Misconfig Check] CORS: wildcard origin with credentials!");
                issues.add(createCORSCredentialsIssue(rr));
            } else {
                api.logging().logToOutput("[Misconfig Check] CORS: wildcard origin (potential issue)");
                issues.add(createCORSWildcardIssue(rr));
            }
        }
        String origin = MontoyaUtils.headerValue(request, "Origin");
        if (origin != null && acao.equals(origin)) {
            api.logging().logToOutput("[Misconfig Check] CORS: reflected origin!");
            issues.add(createCORSReflectedIssue(rr, origin));
        }
        return issues;
    }

    private List<AuditIssue> checkInsecureProtocol(HttpRequestResponse rr, HttpRequest request) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            if (!request.httpService().secure()) {
                api.logging().logToOutput("[Misconfig Check] API using HTTP (insecure)");
                issues.add(createInsecureProtocolIssue(rr));
            }
        } catch (Exception ignored) {}
        return issues;
    }

    private List<AuditIssue> checkVerboseErrors(HttpRequestResponse rr, HttpResponse response) {
        List<AuditIssue> issues = new ArrayList<>();
        int statusCode = response.statusCode();
        if (statusCode < 400) return issues;
        String body = response.bodyToString().toLowerCase();
        if (body.contains("stack trace") ||
            body.contains("at line") ||
            body.contains("exception") ||
            body.contains("error message") ||
            body.contains("stacktrace") ||
            body.contains("traceback")) {
            api.logging().logToOutput("[Misconfig Check] Verbose error messages detected");
            issues.add(createVerboseErrorIssue(rr));
        }
        return issues;
    }

    private static final String API8_BACKGROUND =
            "API8:2023 - Security Misconfiguration<br><br>" +
            "APIs and the systems supporting them typically contain complex configurations, meant to " +
            "make the APIs more customizable. Software and DevOps engineers can miss these configurations, " +
            "or don't follow security best practices when it comes to configuration, opening the door for " +
            "different types of attacks.";

    private AuditIssue createMissingHeadersIssue(HttpRequestResponse rr, List<String> missing) {
        StringBuilder list = new StringBuilder();
        for (String name : missing) {
            list.append("- ").append(name).append(": ").append(RECOMMENDED_HEADERS.get(name)).append("<br>");
        }
        String detail = "The API response is missing important security headers:<br><br>" +
                list + "<br>" +
                "These headers help protect against various attacks including XSS, " +
                "clickjacking, and MIME type confusion.";
        return MontoyaUtils.makeIssue(
                "API8:2023 - Security Misconfiguration (Missing Security Headers)",
                detail, API8_BACKGROUND, "Information", "Certain", rr);
    }

    private AuditIssue createDisclosureHeadersIssue(HttpRequestResponse rr, List<String> headers) {
        StringBuilder list = new StringBuilder();
        for (String h : headers) list.append("- ").append(h).append("<br>");
        String detail = "The API response contains headers that disclose server information:<br><br>" +
                list + "<br>" +
                "These headers reveal technology stack details that can help attackers " +
                "identify specific vulnerabilities to exploit.";
        return MontoyaUtils.makeIssue(
                "API8:2023 - Security Misconfiguration (Information Disclosure via Headers)",
                detail, API8_BACKGROUND, "Information", "Certain", rr);
    }

    private AuditIssue createCORSWildcardIssue(HttpRequestResponse rr) {
        String detail = "The API uses 'Access-Control-Allow-Origin: *' which allows any website to read " +
                "the API response. While this doesn't allow credential-based attacks, it may expose " +
                "public API data to unauthorized origins.<br><br>" +
                "Recommendation: Use specific allowed origins instead of wildcard.";
        return MontoyaUtils.makeIssue(
                "API8:2023 - Security Misconfiguration (CORS Wildcard Origin)",
                detail, API8_BACKGROUND, "Low", "Certain", rr);
    }

    private AuditIssue createCORSCredentialsIssue(HttpRequestResponse rr) {
        String detail = "The API uses 'Access-Control-Allow-Origin: *' together with " +
                "'Access-Control-Allow-Credentials: true'. This is invalid and blocked by browsers, " +
                "but indicates a severe misconfiguration.<br><br>" +
                "This configuration would allow any website to make authenticated requests to the API.";
        return MontoyaUtils.makeIssue(
                "API8:2023 - Security Misconfiguration (CORS Wildcard with Credentials)",
                detail, API8_BACKGROUND, "High", "Certain", rr);
    }

    private AuditIssue createCORSReflectedIssue(HttpRequestResponse rr, String origin) {
        String detail = "The API reflects the Origin header in Access-Control-Allow-Origin without validation. " +
                "This allows any website to read API responses.<br><br>" +
                "Origin sent: " + origin + "<br>" +
                "Origin reflected in response<br><br>" +
                "If credentials are allowed, this enables full cross-origin attacks.";
        return MontoyaUtils.makeIssue(
                "API8:2023 - Security Misconfiguration (CORS Reflected Origin)",
                detail, API8_BACKGROUND, "High", "Firm", rr);
    }

    private AuditIssue createInsecureProtocolIssue(HttpRequestResponse rr) {
        String detail = "The API is accessible over unencrypted HTTP. All data including authentication " +
                "tokens, credentials, and sensitive information is transmitted in cleartext and " +
                "can be intercepted by attackers.<br><br>" +
                "Recommendation: Use HTTPS exclusively for all API communications.";
        return MontoyaUtils.makeIssue(
                "API8:2023 - Security Misconfiguration (API Using HTTP - Insecure)",
                detail, API8_BACKGROUND, "High", "Certain", rr);
    }

    private AuditIssue createVerboseErrorIssue(HttpRequestResponse rr) {
        String detail = "The API returns detailed error messages including stack traces or internal details. " +
                "This information can help attackers understand the internal structure and identify " +
                "specific vulnerabilities.<br><br>" +
                "Recommendation: Return generic error messages to clients and log detailed errors server-side.";
        return MontoyaUtils.makeIssue(
                "API8:2023 - Security Misconfiguration (Verbose Error Messages)",
                detail, API8_BACKGROUND, "Low", "Firm", rr);
    }
}
