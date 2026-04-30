package com.security.burp.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpHeader;
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
 * OWASP API5:2023 - Broken Function Level Authorization
 */
public class FunctionLevelAuthCheck implements ActiveScanCheck {

    private static final String[] ADMIN_KEYWORDS = {
        "admin", "administrator", "superuser", "root",
        "delete", "remove", "destroy", "drop",
        "create", "add", "new",
        "update", "modify", "edit", "change",
        "approve", "reject", "verify",
        "config", "configuration", "settings",
        "logs", "audit", "monitor",
        "users", "accounts", "permissions", "roles"
    };

    private static final String[] PRIVILEGED_METHODS = {
        "DELETE", "PUT", "PATCH"
    };

    private final MontoyaApi api;
    private final boolean isEnterprise;

    public FunctionLevelAuthCheck(MontoyaApi api, boolean isEnterprise) {
        this.api = api;
        this.isEnterprise = isEnterprise;
    }

    @Override
    public String checkName() {
        return "API5:2023 Broken Function Level Authorization";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            HttpRequest request = rr.request();
            String path = MontoyaUtils.pathLower(request);
            String method = request.method();
            if (!isPrivilegedEndpoint(path, method)) return AuditResult.auditResult(issues);

            api.logging().logToOutput("[Function Level Auth] Testing privileged endpoint: " + method + " " + path);
            issues.addAll(testWithoutAuth(rr, http));
            issues.addAll(testWithLowPrivilegeRole(rr, http));
        } catch (Exception e) {
            api.logging().logToError("[Function Level Auth] " + e.getMessage());
        }
        return AuditResult.auditResult(issues);
    }

    private boolean isPrivilegedEndpoint(String path, String method) {
        for (String keyword : ADMIN_KEYWORDS) {
            if (path.contains(keyword)) return true;
        }
        for (String pm : PRIVILEGED_METHODS) {
            if (method.equals(pm)) return true;
        }
        return false;
    }

    private List<AuditIssue> testWithoutAuth(HttpRequestResponse rr, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            HttpRequest original = rr.request();
            boolean hasAuth = false;
            for (HttpHeader h : original.headers()) {
                if (h.name().equalsIgnoreCase("Authorization")) {
                    hasAuth = true; break;
                }
            }
            if (!hasAuth) return issues;

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
                int sc = testResponse.response().statusCode();
                if (sc >= 200 && sc < 300) {
                    api.logging().logToOutput("[Function Level Auth] Privileged endpoint accessible without authentication!");
                    issues.add(createIssue(rr, testResponse, "no authentication required"));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Function Level Auth] Test without auth error: " + e.getMessage());
        }
        return issues;
    }

    private List<AuditIssue> testWithLowPrivilegeRole(HttpRequestResponse rr, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            HttpRequest original = rr.request();
            // Replace any role headers, then add a final user-role header.
            HttpRequest mutated = original;
            for (HttpHeader h : original.headers()) {
                String n = h.name().toLowerCase();
                if (n.equals("x-user-role") || n.equals("x-role") || n.equals("role")) {
                    mutated = mutated.withRemovedHeader(h.name());
                }
            }
            mutated = mutated.withAddedHeader("X-User-Role", "user");

            HttpRequestResponse testResponse = http.sendRequest(mutated);
            if (testResponse != null && testResponse.hasResponse()) {
                int sc = testResponse.response().statusCode();
                if (sc >= 200 && sc < 300) {
                    api.logging().logToOutput("[Function Level Auth] Privileged endpoint accessible with user role!");
                    issues.add(createIssue(rr, testResponse,
                            "accessible with low-privilege role (X-User-Role: user)"));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Function Level Auth] Test with role error: " + e.getMessage());
        }
        return issues;
    }

    private AuditIssue createIssue(HttpRequestResponse original, HttpRequestResponse attack, String testCondition) {
        HttpRequest req = original.request();
        String method = req.method();
        String path = req.pathWithoutQuery();
        StringBuilder detail = new StringBuilder();
        detail.append("<b>Privileged Endpoint Accessible Without Proper Authorization!</b><br><br>")
              .append("<b>Endpoint:</b> ").append(method).append(" ").append(path).append("<br>")
              .append("<b>Test Condition:</b> ").append(testCondition).append("<br><br>")
              .append("This <b>privileged administrative endpoint</b> should only be accessible to administrators, ")
              .append("but it can be accessed by <b>regular users or without authentication</b>.<br><br>")
              .append("<b>Why This Endpoint is Considered Privileged:</b><br>");

        String pathLower = path.toLowerCase();
        for (String keyword : ADMIN_KEYWORDS) {
            if (pathLower.contains(keyword)) {
                detail.append("- Path contains privileged keyword: '<b>").append(keyword).append("</b>'<br>");
            }
        }
        for (String pm : PRIVILEGED_METHODS) {
            if (method.equals(pm)) {
                detail.append("- Uses privileged HTTP method: <b>").append(pm).append("</b><br>");
            }
        }
        detail.append("<br><b>Impact:</b><br>")
              .append("- <b>Regular users can perform administrative actions</b><br>")
              .append("- Unauthorized data deletion or modification<br>")
              .append("- Access to sensitive administrative functions<br>")
              .append("- View confidential logs and system information<br>")
              .append("- Modify system configuration<br>")
              .append("- Create/delete user accounts<br>")
              .append("- <b>Potential complete system compromise</b><br><br>")
              .append("<b>Common Vulnerable Scenarios:</b><br>")
              .append("- Admin endpoints: /api/admin/*, /api/admin-panel/*<br>")
              .append("- DELETE endpoints for critical resources<br>")
              .append("- Configuration/settings endpoints<br>")
              .append("- User management endpoints<br>")
              .append("- Audit log access<br><br>")
              .append("<b>Exploitation:</b><br>")
              .append("An attacker with a regular user account (or no account at all) can:<br>")
              .append("1. Access admin-only endpoints directly<br>")
              .append("2. Delete other users' data<br>")
              .append("3. View system logs and sensitive information<br>")
              .append("4. Modify critical system settings<br><br>")
              .append("<b>Remediation:</b><br>")
              .append("- Implement role-based access control (RBAC)<br>")
              .append("- Check user roles/permissions for EVERY privileged function<br>")
              .append("- Use middleware/decorators to enforce admin-only access<br>")
              .append("- Deny by default - explicitly whitelist allowed actions");
        String background = "API5:2023 - Broken Function Level Authorization<br><br>" +
                "Complex access control policies with different hierarchies, groups, and roles, and " +
                "an unclear separation between administrative and regular functions, tend to lead to " +
                "authorization flaws.";
        return MontoyaUtils.makeIssue("API5:2023 - Broken Function Level Authorization",
                detail.toString(), background, "Critical", "Firm", original, original, attack);
    }
}
