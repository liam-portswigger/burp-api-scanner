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
import com.google.gson.*;
import com.security.burp.util.AiFieldDiscovery;
import com.security.burp.util.MontoyaUtils;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OWASP API3:2023 - Mass Assignment / Broken Object Property Level Authorization
 */
public class MassAssignmentCheck implements ActiveScanCheck {

    private static final String[] SENSITIVE_FIELDS = {
        "isAdmin", "is_admin", "admin", "role", "roles",
        "permissions", "is_verified", "isVerified", "verified",
        "is_active", "isActive", "active", "status",
        "password", "email_verified", "emailVerified",
        "balance", "credit", "credits", "premium", "isPremium"
    };

    private final MontoyaApi api;
    private final boolean isEnterprise;
    private final AiFieldDiscovery aiDiscovery;
    // Dedupe: per-host scan check would still re-run, but PER_INSERTION_POINT
    // means many invocations for one request. We only need to do mass-assignment
    // once per (host+path+method+body-hash) base request.
    private final Set<String> processed = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public MassAssignmentCheck(MontoyaApi api, boolean isEnterprise, AiFieldDiscovery aiDiscovery) {
        this.api = api;
        this.isEnterprise = isEnterprise;
        this.aiDiscovery = aiDiscovery;
    }

    @Override
    public String checkName() {
        return "API3:2023 Mass Assignment";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            HttpRequest request = rr.request();
            if (!isModifyingRequest(request.method())) return AuditResult.auditResult(issues);

            String contentType = MontoyaUtils.contentType(request);
            if (contentType == null || !contentType.contains("application/json")) {
                return AuditResult.auditResult(issues);
            }

            String key = request.httpService().host() + "|" + request.method() + "|" +
                    request.pathWithoutQuery() + "|" + request.bodyToString().hashCode();
            if (!processed.add(key)) return AuditResult.auditResult(issues);

            api.logging().logToOutput("[Mass Assignment] Testing endpoint: " + request.pathWithoutQuery());

            String body = request.bodyToString();
            if (body == null || body.isEmpty()) return AuditResult.auditResult(issues);

            JsonElement jsonElement;
            try {
                jsonElement = JsonParser.parseString(body);
            } catch (JsonSyntaxException e) {
                api.logging().logToOutput("[Mass Assignment] Invalid JSON body");
                return AuditResult.auditResult(issues);
            }
            if (!jsonElement.isJsonObject()) return AuditResult.auditResult(issues);
            JsonObject originalJson = jsonElement.getAsJsonObject();

            // Hardcoded list first.
            Set<String> fields = new LinkedHashSet<>();
            for (String f : SENSITIVE_FIELDS) fields.add(f);

            // AI-suggested contextual fields (e.g. accountTier, organizationRole)
            // augment the hardcoded list when Burp AI is available.
            if (aiDiscovery != null && aiDiscovery.isAvailable()) {
                List<String> aiFields = aiDiscovery.suggestFields(
                        request.httpService().host(),
                        request.pathWithoutQuery(),
                        request.method(),
                        body);
                fields.addAll(aiFields);
            }

            for (String field : fields) {
                List<AuditIssue> found = testSensitiveField(rr, http, originalJson, field);
                issues.addAll(found);
            }
            issues.addAll(testMultipleSensitiveFields(rr, http, originalJson));
        } catch (Exception e) {
            api.logging().logToError("[Mass Assignment] " + e.getMessage());
        }
        return AuditResult.auditResult(issues);
    }

    private boolean isModifyingRequest(String method) {
        return method.equals("POST") || method.equals("PUT") || method.equals("PATCH");
    }

    private List<AuditIssue> testSensitiveField(HttpRequestResponse rr, Http http,
                                                JsonObject originalJson, String field) {
        List<AuditIssue> issues = new ArrayList<>();
        if (originalJson.has(field)) return issues;
        try {
            Object[] testValues = getTestValuesForField(field);
            for (Object testValue : testValues) {
                JsonObject modifiedJson = originalJson.deepCopy();
                if (testValue instanceof Boolean) modifiedJson.addProperty(field, (Boolean) testValue);
                else if (testValue instanceof Number) modifiedJson.addProperty(field, (Number) testValue);
                else modifiedJson.addProperty(field, testValue.toString());

                HttpRequest mutated = rr.request().withBody(modifiedJson.toString());
                HttpRequestResponse testResponse = http.sendRequest(mutated);
                if (testResponse != null && testResponse.hasResponse()) {
                    int sc = testResponse.response().statusCode();
                    if (sc >= 200 && sc < 300) {
                        String responseBody = testResponse.response().bodyToString();
                        if (responseBody.contains("\"" + field + "\"")) {
                            boolean isPrivEsc = field.toLowerCase().contains("role") ||
                                    field.toLowerCase().contains("admin") ||
                                    field.toLowerCase().contains("permission");
                            api.logging().logToOutput("[Mass Assignment] Sensitive field '" + field +
                                    "' accepted (priv-esc=" + isPrivEsc + ")");
                            issues.add(createMassAssignmentIssue(rr, testResponse, field,
                                    testValue.toString(), isPrivEsc));
                            return issues;
                        }
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Mass Assignment] Field test error: " + e.getMessage());
        }
        return issues;
    }

    private List<AuditIssue> testMultipleSensitiveFields(HttpRequestResponse rr, Http http,
                                                         JsonObject originalJson) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            JsonObject modifiedJson = originalJson.deepCopy();
            modifiedJson.addProperty("isAdmin", true);
            modifiedJson.addProperty("role", "admin");
            modifiedJson.addProperty("verified", true);
            modifiedJson.addProperty("premium", true);
            HttpRequest mutated = rr.request().withBody(modifiedJson.toString());
            HttpRequestResponse testResponse = http.sendRequest(mutated);
            if (testResponse != null && testResponse.hasResponse()) {
                int sc = testResponse.response().statusCode();
                if (sc >= 200 && sc < 300) {
                    String responseBody = testResponse.response().bodyToString();
                    List<String> accepted = new ArrayList<>();
                    for (String field : new String[]{"isAdmin", "role", "verified", "premium"}) {
                        if (responseBody.contains("\"" + field + "\"")) accepted.add(field);
                    }
                    if (!accepted.isEmpty()) {
                        api.logging().logToOutput("[Mass Assignment] Multiple sensitive fields accepted: " + accepted);
                        issues.add(createMultiFieldMassAssignmentIssue(rr, testResponse, accepted));
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Mass Assignment] Multi-field test error: " + e.getMessage());
        }
        return issues;
    }

    private Object[] getTestValuesForField(String field) {
        String l = field.toLowerCase();
        if (l.contains("admin")) return new Object[]{true};
        if (l.contains("role")) return new Object[]{"admin", "administrator", "superuser"};
        if (l.contains("verified") || l.contains("active")) return new Object[]{true};
        if (l.contains("balance") || l.contains("credit")) return new Object[]{999999, 1000000};
        if (l.contains("premium")) return new Object[]{true};
        if (l.contains("status")) return new Object[]{"active", "approved", "verified"};
        return new Object[]{true, "admin", 1};
    }

    private static final String API3_BACKGROUND =
            "API3:2023 - Broken Object Property Level Authorization<br><br>" +
            "This category combines API3:2019 Excessive Data Exposure and API6:2019 - Mass Assignment, " +
            "focusing on the root cause: the lack of or improper authorization validation at the object " +
            "property level. This leads to information exposure or manipulation by unauthorized parties.";

    private AuditIssue createMassAssignmentIssue(HttpRequestResponse original, HttpRequestResponse modified,
                                                 String field, String value, boolean isPrivilegeEscalation) {
        String issueName;
        String issueDetail;
        String severity;
        if (isPrivilegeEscalation) {
            issueName = "API3:2023 - Mass Assignment Privilege Escalation";
            issueDetail = "<b>CRITICAL: Privilege Escalation via Mass Assignment!</b><br><br>" +
                    "The API endpoint allows modification of the privileged field '<b>" + field + "</b>' " +
                    "through mass assignment.<br><br>" +
                    "<b>Exploit Example:</b> " + field + " = \"" + value + "\"<br><br>" +
                    "<b>Attack Scenario:</b><br>" +
                    "An attacker can escalate their privileges by simply adding this field to API requests:<br>" +
                    "- Regular user -> Admin user<br>" +
                    "- Limited permissions -> Full access<br>" +
                    "- Unverified account -> Verified status<br><br>" +
                    "<b>Proof of Concept:</b><br>" +
                    "Send a PUT/PATCH request with the body including:<br>" +
                    "<code>{\"" + field + "\": \"" + value + "\"}</code><br><br>" +
                    "<b>Impact:</b><br>" +
                    "- Complete account takeover<br>" +
                    "- Unauthorized administrative access<br>" +
                    "- Bypass of access controls<br>" +
                    "- Potential system-wide compromise<br><br>" +
                    "<b>Remediation:</b><br>" +
                    "- Implement a whitelist of allowed fields for each API endpoint<br>" +
                    "- Never allow role/admin/permission fields to be set via user input<br>" +
                    "- Use separate admin-only endpoints for privilege modifications<br>" +
                    "- Validate and authorize every field modification";
            severity = "Critical";
        } else {
            issueName = "API3:2023 - Broken Object Property Level Authorization (Mass Assignment)";
            issueDetail = "The API endpoint accepts and processes the sensitive field '<b>" + field +
                    "</b>' in the request body, even though it was not originally present.<br><br>" +
                    "<b>Test value:</b> " + field + " = " + value + "<br><br>" +
                    "This indicates a mass assignment vulnerability where an attacker could modify " +
                    "sensitive fields by including them in API requests. This can lead to unauthorized " +
                    "data manipulation or access.<br><br>" +
                    "<b>Remediation:</b><br>" +
                    "- Implement field-level authorization checks<br>" +
                    "- Use Data Transfer Objects (DTOs) with explicit field whitelisting<br>" +
                    "- Validate that users can only modify fields they're authorized to change";
            severity = "High";
        }
        return MontoyaUtils.makeIssue(issueName, issueDetail, API3_BACKGROUND,
                severity, "Firm", original, original, modified);
    }

    private AuditIssue createMultiFieldMassAssignmentIssue(HttpRequestResponse original,
                                                           HttpRequestResponse modified,
                                                           List<String> acceptedFields) {
        String issueDetail = "<b>SEVERE: Multiple Sensitive Fields Vulnerable to Mass Assignment</b><br><br>" +
                "The API endpoint accepts <b>multiple sensitive fields</b> in the request body:<br><br>" +
                "<b>Accepted Fields:</b> " + String.join(", ", acceptedFields) + "<br><br>" +
                "This is a <b>severe mass assignment vulnerability</b> that allows attackers to modify " +
                "multiple sensitive properties simultaneously.<br><br>" +
                "<b>Impact:</b><br>" +
                "- <b>Complete account takeover</b><br>" +
                "- Simultaneous privilege escalation and verification bypass<br>" +
                "- Administrative access without authorization<br>" +
                "- Mass manipulation of user attributes<br>" +
                "- System-wide compromise potential<br><br>" +
                "<b>Attack Scenario:</b><br>" +
                "An attacker can send a single request with all privileged fields:<br>" +
                "<code>{\"isAdmin\": true, \"role\": \"admin\", \"verified\": true, \"premium\": true}</code><br><br>" +
                "<b>Remediation:</b><br>" +
                "- <b>URGENT:</b> Implement strict field-level authorization<br>" +
                "- Use explicit whitelists of allowed fields per endpoint<br>" +
                "- Separate admin-only modification endpoints<br>" +
                "- Validate every single field modification";
        return MontoyaUtils.makeIssue(
                "API3:2023 - Broken Object Property Level Authorization (Multiple Field Mass Assignment)",
                issueDetail, API3_BACKGROUND, "Critical", "Certain", original, original, modified);
    }
}
