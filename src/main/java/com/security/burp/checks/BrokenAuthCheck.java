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
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.security.burp.util.MontoyaUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * OWASP API2:2023 - Broken Authentication
 * Per Hannah's note this runs as a per-host active check, but performs no
 * outbound traffic - it inspects credentials present on the base request.
 */
public class BrokenAuthCheck implements ActiveScanCheck {

    private final MontoyaApi api;
    private final boolean isEnterprise;

    public BrokenAuthCheck(MontoyaApi api, boolean isEnterprise) {
        this.api = api;
        this.isEnterprise = isEnterprise;
    }

    @Override
    public String checkName() {
        return "API2:2023 Broken Authentication";
    }

    @Override
    public AuditResult doCheck(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            api.logging().logToOutput("[Auth Check] Analyzing authentication mechanisms");
            HttpRequest request = rr.request();
            issues.addAll(checkJWTVulnerabilities(rr, request));
            issues.addAll(checkWeakAuthentication(rr, request));
        } catch (Exception e) {
            api.logging().logToError("[Auth Check] " + e.getMessage());
        }
        return AuditResult.auditResult(issues);
    }

    private List<AuditIssue> checkJWTVulnerabilities(HttpRequestResponse rr, HttpRequest request) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            for (HttpHeader header : request.headers()) {
                if (header.name().equalsIgnoreCase("Authorization")) {
                    String value = header.value();
                    if (value != null && value.toLowerCase().startsWith("bearer ")) {
                        String token = value.substring("bearer ".length()).trim();
                        try {
                            DecodedJWT jwt = JWT.decode(token);
                            api.logging().logToOutput("[Auth Check] JWT found, analyzing...");

                            if ("none".equalsIgnoreCase(jwt.getAlgorithm())) {
                                api.logging().logToOutput("[Auth Check] JWT uses 'none' algorithm!");
                                issues.add(createJWTNoneAlgIssue(rr, token));
                            }
                            String alg = jwt.getAlgorithm();
                            if ("HS256".equalsIgnoreCase(alg) || "HS384".equalsIgnoreCase(alg) ||
                                "HS512".equalsIgnoreCase(alg)) {
                                api.logging().logToOutput("[Auth Check] JWT uses symmetric algorithm (HMAC)");
                                issues.add(createWeakJWTAlgIssue(rr, alg));
                            }
                            if (jwt.getExpiresAt() == null) {
                                api.logging().logToOutput("[Auth Check] JWT has no expiration!");
                                issues.add(createJWTNoExpirationIssue(rr));
                            } else {
                                long expiresIn = jwt.getExpiresAt().getTime() - System.currentTimeMillis();
                                long hoursUntilExpiry = expiresIn / (1000 * 60 * 60);
                                if (hoursUntilExpiry > 24) {
                                    api.logging().logToOutput("[Auth Check] JWT expires in " + hoursUntilExpiry + " hours");
                                    issues.add(createJWTLongExpirationIssue(rr, hoursUntilExpiry));
                                }
                            }
                        } catch (Exception e) {
                            api.logging().logToOutput("[Auth Check] Could not decode JWT: " + e.getMessage());
                        }
                    }
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Auth Check] JWT check error: " + e.getMessage());
        }
        return issues;
    }

    private List<AuditIssue> checkWeakAuthentication(HttpRequestResponse rr, HttpRequest request) {
        List<AuditIssue> issues = new ArrayList<>();
        try {
            for (HttpHeader header : request.headers()) {
                String name = header.name().toLowerCase();
                String value = header.value() == null ? "" : header.value();
                if (name.equals("authorization") && value.toLowerCase().startsWith("basic ")) {
                    api.logging().logToOutput("[Auth Check] Basic authentication detected");
                    issues.add(createBasicAuthIssue(rr));
                }
                if (name.equals("x-api-key") || name.equals("api-key") || name.equals("apikey")) {
                    api.logging().logToOutput("[Auth Check] API key authentication detected");
                    try {
                        if (!request.httpService().secure()) {
                            issues.add(createInsecureApiKeyIssue(rr));
                        }
                    } catch (Exception ignored) {}
                }
            }
        } catch (Exception e) {
            api.logging().logToError("[Auth Check] Weak auth check error: " + e.getMessage());
        }
        return issues;
    }

    private static final String API2_BACKGROUND =
            "API2:2023 - Broken Authentication<br><br>" +
            "Authentication mechanisms are often implemented incorrectly, allowing attackers " +
            "to compromise authentication tokens or to exploit implementation flaws to assume " +
            "other user's identities temporarily or permanently. Compromising a system's ability " +
            "to identify the client/user, compromises API security overall.";

    private AuditIssue createJWTNoneAlgIssue(HttpRequestResponse rr, String token) {
        String detail = "The API accepts JWT tokens with algorithm 'none', which means no signature verification. " +
                "An attacker can forge arbitrary tokens by setting the algorithm to 'none' and removing the signature.<br><br>" +
                "Token: " + token.substring(0, Math.min(50, token.length())) + "...<br><br>" +
                "This completely bypasses authentication and is a critical vulnerability.";
        return MontoyaUtils.makeIssue("API2:2023 - Broken Authentication (JWT 'none' Algorithm)",
                detail, API2_BACKGROUND, "Critical", "Certain", rr);
    }

    private AuditIssue createWeakJWTAlgIssue(HttpRequestResponse rr, String algorithm) {
        String detail = "The API uses a symmetric HMAC algorithm (" + algorithm + ") for JWT signatures. " +
                "This is weaker than asymmetric algorithms (RS256, ES256) and requires the same secret " +
                "to be shared between multiple services, increasing the attack surface.<br><br>" +
                "Recommendation: Use RS256 (RSA) or ES256 (ECDSA) instead.";
        return MontoyaUtils.makeIssue("API2:2023 - Broken Authentication (Weak JWT Algorithm: " + algorithm + ")",
                detail, API2_BACKGROUND, "Low", "Certain", rr);
    }

    private AuditIssue createJWTNoExpirationIssue(HttpRequestResponse rr) {
        String detail = "The JWT token does not contain an 'exp' (expiration) claim. This means the token " +
                "never expires and can be used indefinitely if compromised.<br><br>" +
                "Recommendation: Always set expiration times on JWTs (e.g., 1-24 hours).";
        return MontoyaUtils.makeIssue("API2:2023 - Broken Authentication (JWT Without Expiration)",
                detail, API2_BACKGROUND, "Medium", "Certain", rr);
    }

    private AuditIssue createJWTLongExpirationIssue(HttpRequestResponse rr, long hours) {
        String detail = "The JWT token expires in " + hours + " hours. Long-lived tokens increase the " +
                "window of opportunity for attackers if the token is compromised.<br><br>" +
                "Recommendation: Use shorter expiration times (e.g., 1-24 hours) and implement refresh tokens.";
        return MontoyaUtils.makeIssue("API2:2023 - Broken Authentication (Long JWT Expiration)",
                detail, API2_BACKGROUND, "Low", "Certain", rr);
    }

    private AuditIssue createBasicAuthIssue(HttpRequestResponse rr) {
        String detail = "The API uses HTTP Basic Authentication, which transmits credentials in Base64 encoding " +
                "(easily decoded). While acceptable over HTTPS, this is weaker than modern token-based " +
                "authentication and requires sending credentials with every request.<br><br>" +
                "Recommendation: Use OAuth 2.0, JWT, or other token-based authentication.";
        return MontoyaUtils.makeIssue("API2:2023 - Broken Authentication (HTTP Basic Authentication)",
                detail, API2_BACKGROUND, "Information", "Certain", rr);
    }

    private AuditIssue createInsecureApiKeyIssue(HttpRequestResponse rr) {
        String detail = "The API key is being transmitted over unencrypted HTTP. API keys transmitted in " +
                "cleartext can be intercepted by attackers through man-in-the-middle attacks.<br><br>" +
                "Recommendation: Always use HTTPS for API communications.";
        return MontoyaUtils.makeIssue("API2:2023 - Broken Authentication (API Key Over HTTP)",
                detail, API2_BACKGROUND, "High", "Certain", rr);
    }
}
