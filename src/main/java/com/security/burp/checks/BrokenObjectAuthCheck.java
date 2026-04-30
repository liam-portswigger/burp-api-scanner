package com.security.burp.checks;

import burp.api.montoya.MontoyaApi;
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
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * OWASP API1:2023 - Broken Object Level Authorization (BOLA)
 */
public class BrokenObjectAuthCheck implements ActiveScanCheck {

    private static final Pattern[] ID_PATTERNS = {
        Pattern.compile("/\\d+(?:/|$)"),
        Pattern.compile("/[a-f0-9]{24}(?:/|$)"),
        Pattern.compile("/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(?:/|$)"),
        Pattern.compile("[?&]id=\\d+"),
        Pattern.compile("[?&]user_?id=\\d+"),
        Pattern.compile("[?&]account_?id=\\d+")
    };

    private final MontoyaApi api;
    private final boolean isEnterprise;

    public BrokenObjectAuthCheck(MontoyaApi api, boolean isEnterprise) {
        this.api = api;
        this.isEnterprise = isEnterprise;
    }

    @Override
    public String checkName() {
        return "API1:2023 Broken Object Level Authorization";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            HttpRequest request = rr.request();
            String url = request.url();
            if (!containsObjectIdentifier(url)) return AuditResult.auditResult(issues);
            api.logging().logToOutput("[BOLA Check] Testing endpoint: " + url);

            issues.addAll(testIdManipulation(rr, http));

            if (!isEnterprise) {
                api.logging().logToOutput("[BOLA Check] Testing unauthenticated access");
                issues.addAll(testUnauthenticatedAccess(rr, http));
            } else {
                api.logging().logToOutput("[BOLA Check] Skipping unauthenticated access test (Enterprise mode)");
            }

            issues.addAll(testIdEnumeration(rr, http));
        } catch (Exception e) {
            api.logging().logToError("[BOLA Check] " + e.getMessage());
        }
        return AuditResult.auditResult(issues);
    }

    private boolean containsObjectIdentifier(String url) {
        for (Pattern p : ID_PATTERNS) {
            if (p.matcher(url).find()) return true;
        }
        return false;
    }

    private List<AuditIssue> testIdManipulation(HttpRequestResponse rr, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            HttpRequest original = rr.request();
            String originalUrl = original.url();
            List<String> modifiedPaths = generateModifiedPaths(original.path());
            for (String modifiedPath : modifiedPaths) {
                HttpRequest mutated = original.withPath(modifiedPath);
                HttpRequestResponse testResponse = http.sendRequest(mutated);
                if (testResponse != null && testResponse.hasResponse()) {
                    int statusCode = testResponse.response().statusCode();
                    if (statusCode >= 200 && statusCode < 300) {
                        api.logging().logToOutput("[BOLA Check] Vulnerable! Modified ID returned " + statusCode);
                        issues.add(createBOLAIssue(rr, testResponse, originalUrl, modifiedPath));
                        break;
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[BOLA Check] ID manipulation test error: " + e.getMessage());
        }
        return issues;
    }

    private List<AuditIssue> testUnauthenticatedAccess(HttpRequestResponse rr, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            HttpRequest original = rr.request();
            HttpRequest stripped = original;
            for (HttpHeader h : original.headers()) {
                String n = h.name().toLowerCase();
                if (n.equals("authorization") || n.equals("cookie") ||
                    n.equals("x-api-key") || n.equals("x-auth-token")) {
                    stripped = stripped.withRemovedHeader(h.name());
                }
            }
            HttpRequestResponse testResponse = http.sendRequest(stripped);
            if (testResponse != null && testResponse.hasResponse()) {
                int statusCode = testResponse.response().statusCode();
                if (statusCode >= 200 && statusCode < 300) {
                    api.logging().logToOutput("[BOLA Check] Accessible without authentication!");
                    issues.add(createUnauthAccessIssue(rr, testResponse));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[BOLA Check] Unauth access test error: " + e.getMessage());
        }
        return issues;
    }

    private List<AuditIssue> testIdEnumeration(HttpRequestResponse rr, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            HttpRequest original = rr.request();
            String url = original.url();
            Pattern numericPattern = Pattern.compile("/(\\d+)(?:/|$)");
            Matcher matcher = numericPattern.matcher(url);
            if (matcher.find()) {
                int originalId = Integer.parseInt(matcher.group(1));
                int successCount = 0;
                String originalPath = original.path();
                for (int offset : new int[]{-1, -2, 1, 2}) {
                    int testId = originalId + offset;
                    if (testId <= 0) continue;
                    String testPath = originalPath.replaceFirst("/" + originalId + "(?=/|$)", "/" + testId);
                    HttpRequestResponse testResponse = http.sendRequest(original.withPath(testPath));
                    if (testResponse != null && testResponse.hasResponse()) {
                        int sc = testResponse.response().statusCode();
                        if (sc >= 200 && sc < 300) successCount++;
                    }
                }
                if (successCount >= 2) {
                    api.logging().logToOutput("[BOLA Check] Sequential ID enumeration possible!");
                    issues.add(createEnumerationIssue(rr));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[BOLA Check] ID enumeration test error: " + e.getMessage());
        }
        return issues;
    }

    private List<String> generateModifiedPaths(String path) {
        List<String> paths = new ArrayList<>();
        Pattern numericPattern = Pattern.compile("/(\\d+)(?:/|$)");
        Matcher matcher = numericPattern.matcher(path);
        if (matcher.find()) {
            int originalId = Integer.parseInt(matcher.group(1));
            for (int testId : new int[]{1, 2, 100, 999, originalId + 1, originalId - 1}) {
                if (testId != originalId && testId > 0) {
                    paths.add(path.replaceFirst("/" + originalId + "(?=/|$)", "/" + testId));
                }
            }
        }
        return paths;
    }

    private AuditIssue createBOLAIssue(HttpRequestResponse original, HttpRequestResponse modified,
                                       String originalUrl, String modifiedUrl) {
        String detail = "<b>Broken Object Level Authorization Vulnerability Detected</b><br><br>" +
                "The API endpoint is vulnerable to BOLA - the #1 OWASP API Security vulnerability. " +
                "An attacker can access objects belonging to other users by manipulating object identifiers.<br><br>" +
                "<b>Original URL:</b> " + originalUrl + "<br>" +
                "<b>Modified URL:</b> " + modifiedUrl + "<br><br>" +
                "The modified request returned a <b>successful response</b>, indicating insufficient " +
                "authorization checks at the object level.<br><br>" +
                "<b>Impact:</b><br>" +
                "- Unauthorized access to sensitive user data<br>" +
                "- Privacy violations and data breaches<br>" +
                "- Compliance violations (GDPR, CCPA, HIPAA)<br>" +
                "- Account takeover potential<br>" +
                "- Mass data enumeration and extraction<br><br>" +
                "<b>Exploitation:</b><br>" +
                "An attacker can iterate through IDs (1, 2, 3...) to access all users' data without authorization.<br><br>" +
                "<b>Remediation:</b><br>" +
                "- Implement object-level authorization checks<br>" +
                "- Verify user ownership before returning resources<br>" +
                "- Use indirect reference maps instead of direct IDs<br>" +
                "- Example: <code>if (resource.userId !== currentUser.id) return 403;</code>";
        String background = "API1:2023 - Broken Object Level Authorization<br><br>" +
                "APIs tend to expose endpoints that handle object identifiers, creating a wide " +
                "attack surface of Object Level Access Control issues. Object level authorization " +
                "checks should be considered in every function that accesses a data source using " +
                "an ID from the user. This is the #1 most common and impactful API vulnerability.";
        return MontoyaUtils.makeIssue("API1:2023 - Broken Object Level Authorization (BOLA)",
                detail, background, "Critical", "Firm", original, original, modified);
    }

    private AuditIssue createUnauthAccessIssue(HttpRequestResponse original, HttpRequestResponse unauth) {
        String detail = "<b>Unauthenticated Access to Protected Resources</b><br><br>" +
                "The API endpoint returned a <b>successful response</b> without any authentication " +
                "credentials, indicating missing authorization controls.<br><br>" +
                "The request was sent <b>without</b>:<br>" +
                "- Authorization headers<br>" +
                "- Session cookies<br>" +
                "- API keys<br>" +
                "- Any authentication mechanism<br><br>" +
                "Yet the endpoint still returned <b>200 OK</b> with sensitive data.<br><br>" +
                "<b>Impact:</b><br>" +
                "- <b>Complete bypass of authentication</b><br>" +
                "- Public access to private user data<br>" +
                "- Data breach and privacy violations<br>" +
                "- No audit trail of unauthorized access<br><br>" +
                "<b>Remediation:</b><br>" +
                "- Implement authentication checks on ALL endpoints<br>" +
                "- Use middleware to enforce authentication<br>" +
                "- Return 401 Unauthorized for missing credentials<br>" +
                "- Never skip authentication for any API endpoint";
        String background = "API1:2023 - Broken Object Level Authorization<br><br>" +
                "While this appears to be a missing authentication issue, it falls under BOLA because " +
                "the endpoint should be checking both authentication (who you are) and authorization " +
                "(what you can access). Complete absence of checks is the most severe form of BOLA.";
        return MontoyaUtils.makeIssue(
                "API1:2023 - Broken Object Level Authorization (Unauthenticated Access)",
                detail, background, "Critical", "Certain", original, original, unauth);
    }

    private AuditIssue createEnumerationIssue(HttpRequestResponse base) {
        String detail = "The API allows sequential ID enumeration. Multiple sequential object IDs " +
                "returned successful responses, indicating an attacker could iterate through " +
                "IDs to discover all objects in the system.<br><br>" +
                "Combined with BOLA, this enables mass data extraction.";
        String background = "API1:2023 - Broken Object Level Authorization<br><br>" +
                "APIs tend to expose endpoints that handle object identifiers, creating a wide " +
                "attack surface of Object Level Access Control issues. Object level authorization " +
                "checks should be considered in every function that accesses a data source using " +
                "an ID from the user.";
        return MontoyaUtils.makeIssue("API1:2023 - Broken Object Level Authorization (ID Enumeration)",
                detail, background, "Medium", "Firm", base);
    }
}
