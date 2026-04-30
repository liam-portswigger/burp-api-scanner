package com.security.burp.checks;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import com.google.gson.*;
import com.security.burp.scanner.EndpointRegistry;
import com.security.burp.util.MontoyaUtils;

import java.util.*;

/**
 * Excessive Data Exposure Check
 * OWASP API3:2023 - Broken Object Property Level Authorization
 */
public class ExcessiveDataExposureCheck implements PassiveScanCheck {

    private static final String[] SENSITIVE_FIELDS = {
        "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
        "private_key", "privatekey", "ssn", "social_security", "credit_card",
        "cvv", "pin", "salt", "hash", "internal_id", "internal"
    };

    private final MontoyaApi api;
    private final EndpointRegistry registry;

    public ExcessiveDataExposureCheck(MontoyaApi api, EndpointRegistry registry) {
        this.api = api;
        this.registry = registry;
    }

    @Override
    public String checkName() {
        return "API3:2023 Excessive Data Exposure";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse rr) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            HttpRequest request = rr.request();
            // Endpoint discovery (passive recording).
            try {
                registry.record(request.httpService().host(), request.pathWithoutQuery(), request.method());
                if (EndpointRegistry.isApiEndpoint(request.pathWithoutQuery())) {
                    api.logging().logToOutput("[API Discovery] " + request.method() + " " + request.pathWithoutQuery());
                }
            } catch (Exception ignored) {}

            if (!rr.hasResponse()) return AuditResult.auditResult(issues);
            HttpResponse response = rr.response();

            String contentType = MontoyaUtils.contentType(response);
            if (contentType == null || !contentType.contains("application/json")) {
                return AuditResult.auditResult(issues);
            }

            String responseBody = response.bodyToString();
            if (responseBody.isEmpty()) return AuditResult.auditResult(issues);

            try {
                JsonElement jsonElement = JsonParser.parseString(responseBody);

                List<String> foundSensitiveFields = findSensitiveFields(jsonElement, "");
                if (!foundSensitiveFields.isEmpty()) {
                    api.logging().logToOutput("[Data Exposure] Sensitive fields found: " + foundSensitiveFields);
                    issues.add(createSensitiveDataIssue(rr, foundSensitiveFields));
                }

                if (jsonElement.isJsonArray()) {
                    JsonArray array = jsonElement.getAsJsonArray();
                    if (array.size() > 100) {
                        api.logging().logToOutput("[Data Exposure] Large array response: " + array.size() + " items");
                        issues.add(createLargeResponseIssue(rr, array.size()));
                    }
                    if (array.size() > 0 && array.get(0).isJsonObject()) {
                        Set<String> allFields = getAllFields(array);
                        if (allFields.size() > 20) {
                            api.logging().logToOutput("[Data Exposure] Response contains " + allFields.size() + " fields");
                            issues.add(createExcessiveFieldsIssue(rr, allFields));
                        }
                    }
                }
            } catch (JsonSyntaxException e) {
                // Not JSON, skip.
            }
        } catch (Exception e) {
            api.logging().logToError("[Data Exposure] " + e.getMessage());
        }
        return AuditResult.auditResult(issues);
    }

    private List<String> findSensitiveFields(JsonElement element, String path) {
        List<String> found = new ArrayList<>();
        if (element.isJsonObject()) {
            JsonObject obj = element.getAsJsonObject();
            for (Map.Entry<String, JsonElement> entry : obj.entrySet()) {
                String fieldName = entry.getKey().toLowerCase();
                String fullPath = path.isEmpty() ? entry.getKey() : path + "." + entry.getKey();
                for (String sensitiveField : SENSITIVE_FIELDS) {
                    if (fieldName.contains(sensitiveField)) {
                        if (!entry.getValue().isJsonNull() &&
                            !(entry.getValue().isJsonPrimitive() && entry.getValue().getAsString().isEmpty())) {
                            found.add(fullPath);
                            break;
                        }
                    }
                }
                if (entry.getValue().isJsonObject() || entry.getValue().isJsonArray()) {
                    found.addAll(findSensitiveFields(entry.getValue(), fullPath));
                }
            }
        } else if (element.isJsonArray()) {
            JsonArray array = element.getAsJsonArray();
            for (int i = 0; i < Math.min(array.size(), 10); i++) {
                found.addAll(findSensitiveFields(array.get(i), path + "[" + i + "]"));
            }
        }
        return found;
    }

    private Set<String> getAllFields(JsonArray array) {
        Set<String> all = new HashSet<>();
        for (int i = 0; i < Math.min(array.size(), 10); i++) {
            if (array.get(i).isJsonObject()) {
                all.addAll(array.get(i).getAsJsonObject().keySet());
            }
        }
        return all;
    }

    private static final String API3_BACKGROUND =
            "API3:2023 - Broken Object Property Level Authorization<br><br>" +
            "This category combines API3:2019 Excessive Data Exposure and API6:2019 - Mass Assignment, " +
            "focusing on the root cause: the lack of or improper authorization validation at the object " +
            "property level. This leads to information exposure or manipulation by unauthorized parties.";

    private AuditIssue createSensitiveDataIssue(HttpRequestResponse rr, List<String> sensitiveFields) {
        StringBuilder fieldList = new StringBuilder();
        for (String field : sensitiveFields) fieldList.append("- ").append(field).append("<br>");
        String detail = "The API response contains sensitive fields that should not be exposed:<br><br>" +
                fieldList + "<br>" +
                "These fields may contain passwords, tokens, internal IDs, or other sensitive " +
                "information. APIs should filter response data to only include necessary fields.";
        return MontoyaUtils.makeIssue(
                "API3:2023 - Broken Object Property Level Authorization (Sensitive Data Exposure)",
                detail, API3_BACKGROUND, "Medium", "Firm", rr);
    }

    private AuditIssue createLargeResponseIssue(HttpRequestResponse rr, int itemCount) {
        String detail = "The API returned " + itemCount + " items in a single response without " +
                "apparent pagination limits. This can lead to:<br><br>" +
                "- Performance issues<br>" +
                "- Information disclosure (exposing entire datasets)<br>" +
                "- Resource exhaustion<br>" +
                "- Denial of service<br><br>" +
                "Recommendation: Implement pagination with reasonable default limits (e.g., 10-100 items).";
        return MontoyaUtils.makeIssue(
                "API3:2023 - Broken Object Property Level Authorization (Large Unbounded Response)",
                detail, API3_BACKGROUND, "Low", "Firm", rr);
    }

    private AuditIssue createExcessiveFieldsIssue(HttpRequestResponse rr, Set<String> fields) {
        String detail = "The API response contains " + fields.size() + " different fields. " +
                "This may indicate that complete internal objects are being returned without " +
                "proper filtering.<br><br>" +
                "Fields should be limited to only what the client needs. Consider implementing " +
                "field filtering (e.g., ?fields=id,name,email) or using DTOs (Data Transfer Objects).";
        return MontoyaUtils.makeIssue(
                "API3:2023 - Broken Object Property Level Authorization (Excessive Fields)",
                detail, API3_BACKGROUND, "Information", "Firm", rr);
    }
}
