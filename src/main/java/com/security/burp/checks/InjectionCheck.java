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
import com.security.burp.util.MontoyaUtils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * OWASP API2:2023 / API8:2023 - Injection vulnerabilities
 */
public class InjectionCheck implements ActiveScanCheck {

    private static final String[] SQL_PAYLOADS = {
        "' OR '1'='1", "' OR 1=1--", "1' OR '1'='1' --",
        "' UNION SELECT NULL--", "'; DROP TABLE users--",
        "\" OR \"1\"=\"1", "admin' --", "admin' #",
        "' OR 'a'='a", "') OR ('1'='1"
    };
    private static final String[] NOSQL_PAYLOADS = {
        "{\"$gt\":\"\"}", "{\"$ne\":null}", "{\"$ne\":\"\"}"
    };
    private static final String[] CMD_PAYLOADS = {
        "; ls", "| whoami", "`whoami`", "$(whoami)", "&& dir"
    };
    private static final String[] XSS_PAYLOADS = {
        "<script>alert(1)</script>", "\"><script>alert(1)</script>",
        "javascript:alert(1)", "<img src=x onerror=alert(1)>"
    };
    private static final String[] SQL_ERROR_PATTERNS = {
        "sql syntax", "mysql", "postgresql", "ora-", "sqlite",
        "unclosed quotation", "syntax error"
    };
    private static final String[] NOSQL_ERROR_PATTERNS = {
        "mongodb", "mongo", "casterror", "validationerror"
    };

    private final MontoyaApi api;
    private final boolean isEnterprise;
    // Auth-bypass test runs once per (host+path) since it doesn't depend on insertion point.
    private final Set<String> authBypassDone = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public InjectionCheck(MontoyaApi api, boolean isEnterprise) {
        this.api = api;
        this.isEnterprise = isEnterprise;
    }

    @Override
    public String checkName() {
        return "API2:2023/API8:2023 Injection";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            HttpRequest request = rr.request();
            String path = MontoyaUtils.pathLower(request);

            if (isAuthenticationEndpoint(path) && request.method().equals("POST")) {
                String key = request.httpService().host() + "|" + request.pathWithoutQuery();
                if (authBypassDone.add(key)) {
                    api.logging().logToOutput("[Injection Check] Detected authentication endpoint - running targeted SQL injection tests");
                    List<AuditIssue> authIssues = testAuthenticationSQLInjection(rr, http);
                    issues.addAll(authIssues);
                    if (!authIssues.isEmpty()) return AuditResult.auditResult(issues);
                }
            }

            api.logging().logToOutput("[Injection Check] Testing insertion point: " + ip.name());

            issues.addAll(testSQLInjection(rr, ip, http));
            issues.addAll(testNoSQLInjection(rr, ip, http));
            issues.addAll(testCommandInjection(rr, ip, http));
            issues.addAll(testXSS(rr, ip, http));
        } catch (Exception e) {
            api.logging().logToError("[Injection Check] " + e.getMessage());
        }
        return AuditResult.auditResult(issues);
    }

    private List<AuditIssue> testAuthenticationSQLInjection(HttpRequestResponse rr, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            HttpRequest request = rr.request();
            String body = request.bodyToString();
            if (body == null || body.isEmpty()) return issues;
            api.logging().logToOutput("[Injection Check] Authentication endpoint body: " + body);

            JsonElement el;
            try { el = JsonParser.parseString(body); }
            catch (JsonSyntaxException e) {
                api.logging().logToOutput("[Injection Check] Not JSON body, skipping auth SQL injection test");
                return issues;
            }
            if (!el.isJsonObject()) return issues;
            JsonObject originalJson = el.getAsJsonObject();

            String[] usernameFields = {"username", "user", "email", "login", "account"};
            String[] passwordFields = {"password", "pass", "pwd", "secret", "credentials"};
            String usernameField = null, passwordField = null;
            for (String f : usernameFields) if (originalJson.has(f)) { usernameField = f; break; }
            for (String f : passwordFields) if (originalJson.has(f)) { passwordField = f; break; }
            if (usernameField == null || passwordField == null) {
                api.logging().logToOutput("[Injection Check] Could not identify username/password fields");
                return issues;
            }
            api.logging().logToOutput("[Injection Check] Found auth fields: " + usernameField + "/" + passwordField);

            for (String sqlPayload : SQL_PAYLOADS) {
                JsonObject attackJson = originalJson.deepCopy();
                attackJson.addProperty(usernameField, "admin");
                attackJson.addProperty(passwordField, sqlPayload);
                HttpRequestResponse attack = http.sendRequest(request.withBody(attackJson.toString()));
                if (attack == null || !attack.hasResponse()) continue;
                int sc = attack.response().statusCode();
                String responseBody = attack.response().bodyToString().toLowerCase();
                api.logging().logToOutput("[Injection Check] SQL payload test: '" + sqlPayload + "' => " + sc);
                if (sc == 200 && (responseBody.contains("token") ||
                        responseBody.contains("\"success\":true") ||
                        responseBody.contains("\"user\"") ||
                        responseBody.contains("logged") ||
                        responseBody.contains("authenticated"))) {
                    api.logging().logToOutput("[Injection Check] CRITICAL: SQL INJECTION AUTHENTICATION BYPASS!");
                    issues.add(createAuthBypassIssue(rr, attack, passwordField, sqlPayload, responseBody));
                    return issues;
                }
                if (responseBody.contains("sql") || responseBody.contains("syntax") ||
                    responseBody.contains("mysql") || responseBody.contains("sqlite") ||
                    responseBody.contains("postgres") || responseBody.contains("query")) {
                    api.logging().logToOutput("[Injection Check] SQL ERROR MESSAGE DETECTED!");
                    issues.add(createSQLErrorAuthIssue(rr, attack, passwordField, sqlPayload, responseBody));
                    return issues;
                }
            }
            for (String sqlPayload : SQL_PAYLOADS) {
                JsonObject attackJson = originalJson.deepCopy();
                attackJson.addProperty(usernameField, sqlPayload);
                attackJson.addProperty(passwordField, "password");
                HttpRequestResponse attack = http.sendRequest(request.withBody(attackJson.toString()));
                if (attack == null || !attack.hasResponse()) continue;
                int sc = attack.response().statusCode();
                String responseBody = attack.response().bodyToString().toLowerCase();
                if (sc == 200 && (responseBody.contains("token") || responseBody.contains("success"))) {
                    api.logging().logToOutput("[Injection Check] CRITICAL: SQL INJECTION IN USERNAME FIELD!");
                    issues.add(createAuthBypassIssue(rr, attack, usernameField, sqlPayload, responseBody));
                    return issues;
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Injection Check] Auth SQL injection test error: " + e.getMessage());
        }
        return issues;
    }

    private boolean isAuthenticationEndpoint(String path) {
        return path.contains("/login") || path.contains("/auth") ||
               path.contains("/signin") || path.contains("/authenticate") ||
               path.contains("/token");
    }

    private List<AuditIssue> testSQLInjection(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            for (String payload : SQL_PAYLOADS) {
                HttpRequest mutated = ip.buildHttpRequestWithPayload(ByteArray.byteArray(payload));
                HttpRequestResponse attack = http.sendRequest(mutated);
                if (attack == null || !attack.hasResponse()) continue;
                String body = attack.response().bodyToString().toLowerCase();
                for (String pattern : SQL_ERROR_PATTERNS) {
                    if (body.contains(pattern)) {
                        api.logging().logToOutput("[Injection Check] SQL Injection vulnerability found!");
                        issues.add(createSQLInjectionIssue(rr, attack, ip, payload, pattern));
                        return issues;
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Injection Check] SQL test error: " + e.getMessage());
        }
        return issues;
    }

    private List<AuditIssue> testNoSQLInjection(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            String contentType = MontoyaUtils.contentType(rr.request());
            if (contentType == null || !contentType.contains("application/json")) return issues;

            for (String payload : NOSQL_PAYLOADS) {
                HttpRequest mutated = ip.buildHttpRequestWithPayload(ByteArray.byteArray(payload));
                HttpRequestResponse attack = http.sendRequest(mutated);
                if (attack == null || !attack.hasResponse()) continue;
                String body = attack.response().bodyToString().toLowerCase();
                int sc = attack.response().statusCode();
                for (String pattern : NOSQL_ERROR_PATTERNS) {
                    if (body.contains(pattern)) {
                        api.logging().logToOutput("[Injection Check] NoSQL Injection vulnerability found!");
                        issues.add(createNoSQLInjectionIssue(rr, attack, ip, payload, pattern));
                        return issues;
                    }
                }
                if (sc == 200 && payload.contains("$ne")) {
                    issues.add(createNoSQLInjectionIssue(rr, attack, ip, payload, "potential bypass"));
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Injection Check] NoSQL test error: " + e.getMessage());
        }
        return issues;
    }

    private List<AuditIssue> testCommandInjection(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            for (String payload : CMD_PAYLOADS) {
                HttpRequest mutated = ip.buildHttpRequestWithPayload(ByteArray.byteArray(payload));
                HttpRequestResponse attack = http.sendRequest(mutated);
                if (attack == null || !attack.hasResponse()) continue;
                String body = attack.response().bodyToString();
                if (body.contains("root:") || body.contains("/bin/") ||
                    body.contains("Windows") || body.contains("Administrator")) {
                    api.logging().logToOutput("[Injection Check] Command Injection vulnerability found!");
                    issues.add(createCommandInjectionIssue(rr, attack, ip, payload));
                    return issues;
                }
                String lb = body.toLowerCase();
                if (lb.contains("command not found") || lb.contains("is not recognized")) {
                    api.logging().logToOutput("[Injection Check] Command Injection attempted!");
                    issues.add(createCommandInjectionIssue(rr, attack, ip, payload));
                    return issues;
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Injection Check] Command injection test error: " + e.getMessage());
        }
        return issues;
    }

    private List<AuditIssue> testXSS(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            for (String payload : XSS_PAYLOADS) {
                HttpRequest mutated = ip.buildHttpRequestWithPayload(ByteArray.byteArray(payload));
                HttpRequestResponse attack = http.sendRequest(mutated);
                if (attack == null || !attack.hasResponse()) continue;
                String body = attack.response().bodyToString();
                if (body.contains(payload)) {
                    api.logging().logToOutput("[Injection Check] Reflected XSS in API response!");
                    issues.add(createXSSIssue(rr, attack, ip, payload));
                    return issues;
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Injection Check] XSS test error: " + e.getMessage());
        }
        return issues;
    }

    private static String urlEnc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private AuditIssue createSQLInjectionIssue(HttpRequestResponse original, HttpRequestResponse attack,
                                               AuditInsertionPoint ip, String payload, String pattern) {
        String detail = "<b>SQL Injection Vulnerability Detected</b><br><br>" +
                "<b>Insertion Point:</b> " + ip.name() + "<br>" +
                "<b>Payload:</b> <code>" + urlEnc(payload) + "</code><br>" +
                "<b>Error Pattern Found:</b> " + pattern + "<br><br>" +
                "<b>Impact:</b><br>" +
                "- Unauthorized data access and exfiltration<br>" +
                "- Data modification or deletion<br>" +
                "- Authentication bypass (if in auth endpoints)<br>" +
                "- Complete database compromise<br>" +
                "- Privilege escalation<br><br>" +
                "<b>Remediation:</b><br>" +
                "- Use parameterized queries (prepared statements)<br>" +
                "- Never concatenate user input into SQL queries<br>" +
                "- Use ORM frameworks with proper escaping<br>" +
                "- Implement input validation and sanitization";
        String background = "API2:2023 - Broken Authentication<br><br>" +
                "Authentication mechanisms are often implemented incorrectly, allowing attackers to " +
                "compromise authentication tokens or exploit implementation flaws. SQL injection in API " +
                "parameters can lead to authentication bypass and unauthorized access.";
        return MontoyaUtils.makeIssue("API2:2023 - Broken Authentication (SQL Injection)",
                detail, background, "Critical", "Firm", original, original, attack);
    }

    private AuditIssue createNoSQLInjectionIssue(HttpRequestResponse original, HttpRequestResponse attack,
                                                 AuditInsertionPoint ip, String payload, String indicator) {
        String detail = "<b>NoSQL Injection Vulnerability Detected</b><br><br>" +
                "<b>Insertion Point:</b> " + ip.name() + "<br>" +
                "<b>Payload:</b> <code>" + payload + "</code><br>" +
                "<b>Indicator:</b> " + indicator + "<br><br>" +
                "<b>Impact:</b><br>" +
                "- Authentication bypass<br>" +
                "- Unauthorized data extraction<br>" +
                "- Denial of service attacks<br>" +
                "- Query manipulation<br>" +
                "- Potential code execution (in some MongoDB configurations)<br><br>" +
                "<b>Remediation:</b><br>" +
                "- Validate and sanitize all user input<br>" +
                "- Use parameterized queries or ORM methods<br>" +
                "- Avoid using $where operator with user input<br>" +
                "- Implement strict input type checking";
        String background = "API2:2023 - Broken Authentication<br><br>" +
                "NoSQL databases like MongoDB are vulnerable to injection attacks when user input is " +
                "not properly validated. NoSQL injection in authentication mechanisms can lead to " +
                "complete authentication bypass and unauthorized access.";
        return MontoyaUtils.makeIssue("API2:2023 - Broken Authentication (NoSQL Injection)",
                detail, background, "Critical", "Firm", original, original, attack);
    }

    private AuditIssue createCommandInjectionIssue(HttpRequestResponse original, HttpRequestResponse attack,
                                                   AuditInsertionPoint ip, String payload) {
        String detail = "<b>CRITICAL: OS Command Injection Vulnerability Detected</b><br><br>" +
                "<b>Insertion Point:</b> " + ip.name() + "<br>" +
                "<b>Payload:</b> <code>" + payload + "</code><br><br>" +
                "<b>Impact:</b><br>" +
                "- <b>Complete server compromise</b><br>" +
                "- Arbitrary command execution with application privileges<br>" +
                "- Data exfiltration and database access<br>" +
                "- Lateral movement to other systems<br>" +
                "- Denial of service<br>" +
                "- Installation of backdoors and malware<br><br>" +
                "<b>Remediation:</b><br>" +
                "- <b>Never</b> pass user input to system commands<br>" +
                "- Use language-specific APIs instead of shell commands<br>" +
                "- If shell execution is unavoidable, use strict whitelisting<br>" +
                "- Run application with minimal privileges<br>" +
                "- Implement input validation and sanitization";
        String background = "API8:2023 - Security Misconfiguration<br><br>" +
                "OS Command Injection occurs when an application passes unsafe user input to system " +
                "shell commands. This is one of the most severe vulnerabilities as it allows complete " +
                "server compromise.";
        return MontoyaUtils.makeIssue("API8:2023 - Security Misconfiguration (OS Command Injection)",
                detail, background, "Critical", "Certain", original, original, attack);
    }

    private AuditIssue createXSSIssue(HttpRequestResponse original, HttpRequestResponse attack,
                                      AuditInsertionPoint ip, String payload) {
        String detail = "<b>Reflected Cross-Site Scripting in API Response</b><br><br>" +
                "<b>Insertion Point:</b> " + ip.name() + "<br>" +
                "<b>Payload:</b> <code>" + urlEnc(payload) + "</code><br><br>" +
                "The API reflects user input without proper encoding, allowing XSS attacks.<br><br>" +
                "<b>Impact:</b><br>" +
                "- Session hijacking if API responses are rendered in browsers<br>" +
                "- Credential theft<br>" +
                "- Phishing attacks<br>" +
                "- Client-side code execution<br><br>" +
                "<b>Remediation:</b><br>" +
                "- Encode all user-controlled data in API responses<br>" +
                "- Use Content-Security-Policy headers<br>" +
                "- Set Content-Type to application/json explicitly<br>" +
                "- Implement input validation";
        String background = "API8:2023 - Security Misconfiguration<br><br>" +
                "Reflecting user input without proper encoding represents a security misconfiguration. " +
                "While XSS is traditionally a web application issue, APIs that reflect unencoded input " +
                "create vulnerabilities in consuming applications.";
        return MontoyaUtils.makeIssue("API8:2023 - Security Misconfiguration (Reflected XSS in API Response)",
                detail, background, "Medium", "Firm", original, original, attack);
    }

    private AuditIssue createAuthBypassIssue(HttpRequestResponse original, HttpRequestResponse attack,
                                             String field, String payload, String responseBody) {
        String detail = "<b>CRITICAL: SQL Injection Authentication Bypass Detected!</b><br><br>" +
                "The authentication endpoint is vulnerable to SQL injection, allowing complete authentication bypass.<br><br>" +
                "<b>Vulnerable Field:</b> " + field + "<br>" +
                "<b>Payload Used:</b> <code>" + payload.replace("<", "&lt;").replace(">", "&gt;") + "</code><br>" +
                "<b>Status Code:</b> 200 OK (Authentication Successful)<br><br>" +
                "<b>Impact:</b><br>" +
                "- Complete authentication bypass - no credentials needed<br>" +
                "- Unauthorized access to any user account<br>" +
                "- Potential database compromise and data exfiltration<br>" +
                "- Privilege escalation to admin accounts<br>" +
                "- Complete application takeover<br><br>" +
                "<b>Response Evidence (first 500 chars):</b><br>" +
                "<pre>" + responseBody.substring(0, Math.min(500, responseBody.length())).replace("<", "&lt;").replace(">", "&gt;") + "</pre><br>" +
                "<b>Remediation:</b><br>" +
                "- Use parameterized queries/prepared statements (NEVER string concatenation)<br>" +
                "- Use ORM frameworks with proper escaping<br>" +
                "- Implement input validation and sanitization<br>" +
                "- Use stored procedures with parameters<br>" +
                "- Apply principle of least privilege to database accounts";
        String background = "API2:2023 - Broken Authentication<br><br>" +
                "Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise " +
                "authentication tokens or to exploit implementation flaws to assume other users' identities. " +
                "SQL Injection in authentication endpoints is one of the most critical vulnerabilities.";
        return MontoyaUtils.makeIssue(
                "API2:2023 - Broken Authentication (SQL Injection Authentication Bypass)",
                detail, background, "Critical", "Certain", original, original, attack);
    }

    private AuditIssue createSQLErrorAuthIssue(HttpRequestResponse original, HttpRequestResponse attack,
                                               String field, String payload, String responseBody) {
        String detail = "<b>SQL Injection Detected in Authentication Endpoint!</b><br><br>" +
                "The authentication endpoint returns SQL error messages, confirming SQL injection vulnerability.<br><br>" +
                "<b>Vulnerable Field:</b> " + field + "<br>" +
                "<b>Payload Used:</b> <code>" + payload.replace("<", "&lt;").replace(">", "&gt;") + "</code><br><br>" +
                "<b>SQL Error Evidence (first 500 chars):</b><br>" +
                "<pre>" + responseBody.substring(0, Math.min(500, responseBody.length())).replace("<", "&lt;").replace(">", "&gt;") + "</pre><br>" +
                "<b>Impact:</b><br>" +
                "- Potential authentication bypass<br>" +
                "- Database information disclosure<br>" +
                "- Unauthorized data access<br>" +
                "- Database structure enumeration<br><br>" +
                "<b>Remediation:</b><br>" +
                "- Use parameterized queries/prepared statements<br>" +
                "- Implement generic error messages (don't expose SQL errors)<br>" +
                "- Use proper input validation<br>" +
                "- Implement rate limiting on login attempts";
        String background = "API2:2023 - Broken Authentication<br><br>" +
                "SQL Injection in authentication endpoints can lead to authentication bypass and " +
                "unauthorized access to the application.";
        return MontoyaUtils.makeIssue(
                "API2:2023 - Broken Authentication (SQL Injection - Error-Based)",
                detail, background, "High", "Certain", original, original, attack);
    }
}
