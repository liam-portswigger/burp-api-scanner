package com.security.burp.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.ActiveScanCheck;
import com.security.burp.util.MontoyaUtils;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * OWASP API5:2023 - HTTP Method Fuzzing
 */
public class MethodFuzzingCheck implements ActiveScanCheck {

    private static final String[] HTTP_METHODS = {
        "GET", "POST", "PUT", "DELETE", "PATCH",
        "HEAD", "OPTIONS", "TRACE", "CONNECT"
    };

    private static final String[] DAST_HTTP_METHODS = {
        "GET", "POST", "PUT", "DELETE", "PATCH"
    };

    private final MontoyaApi api;
    private final boolean isEnterprise;

    public MethodFuzzingCheck(MontoyaApi api, boolean isEnterprise) {
        this.api = api;
        this.isEnterprise = isEnterprise;
    }

    @Override
    public String checkName() {
        return "API5:2023 HTTP Method Fuzzing";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            HttpRequest request = rr.request();
            String originalMethod = request.method();
            String[] methodsToTest = HTTP_METHODS;
            api.logging().logToOutput("[Method Fuzzing] Testing " + methodsToTest.length +
                    " HTTP methods on: " + request.pathWithoutQuery());
            api.logging().logToOutput("[Method Fuzzing] Original method: " + originalMethod);

            Map<String, MethodTestResult> results = new HashMap<>();

            for (String method : methodsToTest) {
                if (method.equals(originalMethod)) continue;
                MethodTestResult result = testMethod(http, request, method);
                results.put(method, result);

                if (result.successful) {
                    api.logging().logToOutput("[Method Fuzzing] Method " + method +
                            " returned " + result.statusCode + " (may be unintended)");
                    if (isDangerousMethod(method) && result.statusCode < 400) {
                        issues.add(createMethodIssue(rr, method, result, "High", originalMethod));
                    } else if (result.statusCode >= 200 && result.statusCode < 300) {
                        issues.add(createMethodIssue(rr, method, result, "Medium", originalMethod));
                    } else if (result.statusCode != 405) {
                        issues.add(createMethodIssue(rr, method, result, "Information", originalMethod));
                    }
                }
            }

            MethodTestResult optionsResult = results.get("OPTIONS");
            if (optionsResult != null && optionsResult.allowHeader != null) {
                issues.add(createOptionsIssue(rr, optionsResult));
            }
            MethodTestResult traceResult = results.get("TRACE");
            if (traceResult != null && traceResult.successful && traceResult.statusCode == 200) {
                issues.add(createTraceIssue(rr, traceResult));
            }
        } catch (Exception e) {
            api.logging().logToError("[Method Fuzzing] " + e.getMessage());
        }
        return AuditResult.auditResult(issues);
    }

    private MethodTestResult testMethod(Http http, HttpRequest baseRequest, String method) {
        try {
            HttpRequest mutated = baseRequest.withMethod(method);
            if (!shouldHaveBody(method)) {
                mutated = mutated.withBody(ByteArray.byteArray(new byte[0]));
            }
            HttpRequestResponse response = http.sendRequest(mutated);
            if (response == null || !response.hasResponse()) {
                return new MethodTestResult(false, 0, null, response);
            }
            HttpResponse resp = response.response();
            int statusCode = resp.statusCode();
            String allowHeader = null;
            for (HttpHeader h : resp.headers()) {
                if (h.name().equalsIgnoreCase("Allow")) {
                    allowHeader = h.value();
                    break;
                }
            }
            return new MethodTestResult(true, statusCode, allowHeader, response);
        } catch (Exception e) {
            return new MethodTestResult(false, 0, null, null);
        }
    }

    private boolean shouldHaveBody(String method) {
        return method.equals("POST") || method.equals("PUT") ||
                method.equals("PATCH") || method.equals("DELETE");
    }

    private boolean isDangerousMethod(String method) {
        return method.equals("PUT") || method.equals("DELETE") ||
                method.equals("PATCH") || method.equals("TRACE");
    }

    private AuditIssue createMethodIssue(HttpRequestResponse base, String method,
                                         MethodTestResult result, String severity, String originalMethod) {
        String issueName = "API5:2023 - Broken Function Level Authorization (Unexpected HTTP Method: " + method + ")";
        String detail = "The API endpoint responded to HTTP " + method +
                " method with status code " + result.statusCode + ".<br><br>" +
                "Original method documented: " + originalMethod + "<br>" +
                "Method tested: " + method + "<br><br>" +
                "This may indicate:<br>" +
                "- Incomplete API specification/documentation<br>" +
                "- Missing HTTP method restrictions<br>" +
                "- Potential for unauthorized operations<br>" +
                "- Broken Function Level Authorization<br><br>" +
                "Recommendation: Implement proper HTTP method whitelisting and ensure only " +
                "intended methods are allowed.";
        String background = "API5:2023 - Broken Function Level Authorization<br><br>" +
                "Complex access control policies with different hierarchies, group roles, and an unclear " +
                "separation between administrative and regular functions, tend to lead to authorization flaws. " +
                "By exploiting these issues, attackers can gain access to other users' resources and/or " +
                "administrative functions.";
        return MontoyaUtils.makeIssue(issueName, detail, background, severity, "Firm", base, base, result.response);
    }

    private AuditIssue createOptionsIssue(HttpRequestResponse base, MethodTestResult result) {
        String detail = "The API endpoint responds to HTTP OPTIONS requests and discloses " +
                "allowed methods via the Allow header: " + result.allowHeader + "<br><br>" +
                "This information disclosure can help attackers identify all available " +
                "HTTP methods for further testing.";
        String background = "API8:2023 - Security Misconfiguration<br><br>" +
                "APIs and the systems supporting them typically contain complex configurations, meant to " +
                "make the APIs more customizable. Software and DevOps engineers can miss these configurations, " +
                "or don't follow security best practices when it comes to configuration, opening the door for " +
                "different types of attacks.";
        return MontoyaUtils.makeIssue("API8:2023 - Security Misconfiguration (OPTIONS Method Disclosure)",
                detail, background, "Information", "Certain", base, base, result.response);
    }

    private AuditIssue createTraceIssue(HttpRequestResponse base, MethodTestResult result) {
        String detail = "The API endpoint responds to HTTP TRACE requests. This can be " +
                "exploited for Cross-Site Tracing (XST) attacks to bypass HTTPOnly " +
                "cookie protections and steal sensitive headers.<br><br>" +
                "TRACE method should be disabled on production systems.";
        String background = "API8:2023 - Security Misconfiguration<br><br>" +
                "APIs and the systems supporting them typically contain complex configurations, meant to " +
                "make the APIs more customizable. Software and DevOps engineers can miss these configurations, " +
                "or don't follow security best practices when it comes to configuration, opening the door for " +
                "different types of attacks.";
        return MontoyaUtils.makeIssue("API8:2023 - Security Misconfiguration (TRACE Method Enabled - XST Risk)",
                detail, background, "Medium", "Certain", base, base, result.response);
    }

    private static class MethodTestResult {
        final boolean successful;
        final int statusCode;
        final String allowHeader;
        final HttpRequestResponse response;
        MethodTestResult(boolean successful, int statusCode, String allowHeader, HttpRequestResponse response) {
            this.successful = successful;
            this.statusCode = statusCode;
            this.allowHeader = allowHeader;
            this.response = response;
        }
    }
}
