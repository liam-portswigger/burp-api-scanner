package com.security.burp.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import com.security.burp.util.MontoyaUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * OWASP API7:2023 - Server Side Request Forgery
 */
public class SsrfCheck implements ActiveScanCheck {

    private static final String[] SSRF_PAYLOADS = {
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",
        "http://[::1]",
        "http://0.0.0.0",
        "file:///etc/passwd",
        "http://internal.local"
    };

    private static final String[] SSRF_INDICATORS = {
        "ami-id", "instance-id", "local-ipv4",
        "root:", "daemon:", "/bin/bash",
        "kube-env", "attributes/"
    };

    private final MontoyaApi api;
    private final boolean isEnterprise;

    public SsrfCheck(MontoyaApi api, boolean isEnterprise) {
        this.api = api;
        this.isEnterprise = isEnterprise;
    }

    @Override
    public String checkName() {
        return "API7:2023 SSRF";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            String name = ip.name() == null ? "" : ip.name().toLowerCase();
            if (!isUrlParameter(name)) return AuditResult.auditResult(issues);
            api.logging().logToOutput("[SSRF Check] Testing parameter: " + ip.name());

            for (String payload : SSRF_PAYLOADS) {
                HttpRequest mutated = ip.buildHttpRequestWithPayload(ByteArray.byteArray(payload));
                HttpRequestResponse testResponse = http.sendRequest(mutated);
                if (testResponse == null || !testResponse.hasResponse()) continue;
                int sc = testResponse.response().statusCode();
                String body = testResponse.response().bodyToString();

                boolean indicatorFound = false;
                for (String indicator : SSRF_INDICATORS) {
                    if (body.contains(indicator)) {
                        api.logging().logToOutput("[SSRF Check] SSRF vulnerability confirmed!");
                        issues.add(createSSRFIssue(rr, testResponse, ip, payload, indicator, "High"));
                        indicatorFound = true;
                        break;
                    }
                }
                if (indicatorFound) return AuditResult.auditResult(issues);

                if (sc == 200 && (payload.contains("127.0.0.1") ||
                        payload.contains("localhost") || payload.contains("169.254.169.254"))) {
                    api.logging().logToOutput("[SSRF Check] Potential SSRF - internal URL accessible");
                    issues.add(createSSRFIssue(rr, testResponse, ip, payload, "200 OK response", "Medium"));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[SSRF Check] " + e.getMessage());
        }
        return AuditResult.auditResult(issues);
    }

    private boolean isUrlParameter(String paramName) {
        return paramName.contains("url") || paramName.contains("uri") ||
                paramName.contains("link") || paramName.contains("redirect") ||
                paramName.contains("callback") || paramName.contains("webhook") ||
                paramName.contains("destination") || paramName.contains("target") ||
                paramName.contains("next") || paramName.contains("proxy") ||
                paramName.contains("host") || paramName.contains("domain") ||
                paramName.contains("path");
    }

    private AuditIssue createSSRFIssue(HttpRequestResponse original, HttpRequestResponse attack,
                                       AuditInsertionPoint ip, String payload, String indicator, String severity) {
        String detail = "SSRF vulnerability detected - the API makes requests to attacker-controlled URLs.<br><br>" +
                "Insertion point: " + ip.name() + "<br>" +
                "Payload: " + payload + "<br>" +
                "Indicator: " + indicator + "<br><br>" +
                "SSRF vulnerabilities allow attackers to:<br>" +
                "- Access internal services and metadata endpoints<br>" +
                "- Bypass firewalls and access controls<br>" +
                "- Steal cloud credentials (AWS, GCP, Azure metadata)<br>" +
                "- Port scan internal networks<br>" +
                "- Read local files<br>" +
                "- Perform attacks on behalf of the server";
        String background = "API7:2023 - Server Side Request Forgery<br><br>" +
                "Server-Side Request Forgery (SSRF) flaws can occur when an API is fetching a remote " +
                "resource without validating the user-supplied URI. This enables an attacker to coerce " +
                "the application to send a crafted request to an unexpected destination, even when " +
                "protected by a firewall or a VPN.";
        return MontoyaUtils.makeIssue("API7:2023 - Server Side Request Forgery",
                detail, background, severity, "Firm", original, original, attack);
    }
}
