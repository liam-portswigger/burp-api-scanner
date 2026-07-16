package com.security.burp.checks.active;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.Http;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.security.burp.checks.AbstractActiveCheck;
import com.security.burp.util.HttpUtils;
import com.security.burp.util.IssueBuilder;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * GraphQL-specific weaknesses that Burp's native scanner does not check.
 *
 * <p>Native coverage already reports GraphQL endpoint discovery and
 * introspection; this check adds two things it does not:
 * <ol>
 *   <li><b>Field-suggestion leakage</b> (API9) — even with introspection
 *       disabled, many servers answer an unknown-field query with a
 *       "Did you mean …" hint, letting an attacker recover the schema field
 *       by field;</li>
 *   <li><b>Array query batching</b> (API4) — accepting a JSON array of
 *       operations in one request enables amplification and per-request
 *       rate-limit bypass (batched/aliased brute force).</li>
 * </ol>
 *
 * <p>Registered {@code PER_HOST}; deduped per (host + path). Both probes are
 * <b>read-only</b> — they query {@code __typename} (or a misspelled variant),
 * so they never mutate server state.
 */
public final class GraphQlCheck extends AbstractActiveCheck {

    /** Misspelled meta-field: a server with suggestions replies "Did you mean __typename". */
    private static final String SUGGESTION_PROBE = "{\"query\":\"{ __typenaem }\"}";

    /** Two-operation array batch; a server that runs both returns a 2-element array. */
    private static final String BATCH_PROBE =
            "[{\"query\":\"{ __typename }\"},{\"query\":\"{ __typename }\"}]";

    private static final String BACKGROUND_API9 =
            "API9:2023 - Improper Inventory Management<br><br>" +
            "GraphQL serves a whole typed schema from one endpoint. When the server leaks " +
            "schema detail, an attacker can map the full API surface — including fields never " +
            "meant to be public — without any documentation.";

    private static final String BACKGROUND_API4 =
            "API4:2023 - Unrestricted Resource Consumption<br><br>" +
            "GraphQL lets a client request many operations in a single call. Without limits " +
            "this multiplies server work per request and can be used to bypass controls that " +
            "count HTTP requests rather than operations.";

    /** Cross-reference to Burp's native GraphQL scan checks. */
    private static final String RELATED_INTROSPECTION =
            "<br><br><b>Related Burp Scanner checks:</b> for further detail refer to the native " +
            "<a href=\"https://portswigger.net/kb/issues/00200512_graphql-introspection-enabled\">GraphQL introspection enabled</a> and " +
            "<a href=\"https://portswigger.net/kb/issues/00200510_graphql-endpoint-found\">GraphQL endpoint found</a> checks.";

    private final Set<String> dedupe = Collections.newSetFromMap(new ConcurrentHashMap<>());

    public GraphQlCheck(MontoyaApi api) {
        super(api);
    }

    @Override
    public String checkName() {
        return "GraphQL weaknesses (field suggestions, batching)";
    }

    @Override
    protected List<AuditIssue> audit(HttpRequestResponse rr, AuditInsertionPoint ip, Http http) {
        if (!shouldRunOnce(rr)) return List.of();
        if (!HttpUtils.isGraphQlRequest(rr.request())) return List.of();

        List<AuditIssue> issues = new ArrayList<>();
        AuditIssue suggestions = trySuggestions(rr, http);
        if (suggestions != null) issues.add(suggestions);
        AuditIssue batching = tryBatching(rr, http);
        if (batching != null) issues.add(batching);
        return issues;
    }

    private boolean shouldRunOnce(HttpRequestResponse rr) {
        String key = rr.request().httpService().host() + "|" + rr.request().pathWithoutQuery();
        return dedupe.add(key);
    }

    // ---- Probes -------------------------------------------------------------

    /**
     * Fire only when the server returns a GraphQL field suggestion for a
     * deliberately-misspelled meta-field. The response literally naming a
     * "Did you mean" hint <em>is</em> the leak; requiring the reply to read as
     * a GraphQL error as well keeps a generic "did you mean" from some other
     * handler out.
     */
    private AuditIssue trySuggestions(HttpRequestResponse rr, Http http) {
        HttpRequestResponse evidence = sendGraphQl(rr, http, SUGGESTION_PROBE);
        if (evidence == null) return null;
        String body = evidence.response().bodyToString();
        if (body == null) return null;
        String lower = body.toLowerCase(Locale.ROOT);
        boolean leaks = lower.contains("did you mean")
                && (lower.contains("cannot query field") || lower.contains("\"errors\""));
        return leaks ? buildSuggestionsIssue(rr, evidence) : null;
    }

    /**
     * Fire only when the server executes a two-operation JSON array batch and
     * returns a matching 2-element array of results — proof array batching is
     * enabled. This is not the GraphQL default; many servers reject an array
     * body, so a genuine 2-element result array is a real configuration signal.
     */
    private AuditIssue tryBatching(HttpRequestResponse rr, Http http) {
        HttpRequestResponse evidence = sendGraphQl(rr, http, BATCH_PROBE);
        if (evidence == null) return null;
        return batchExecuted(evidence.response().bodyToString())
                ? buildBatchingIssue(rr, evidence)
                : null;
    }

    private static boolean batchExecuted(String body) {
        if (body == null) return false;
        try {
            JsonElement root = JsonParser.parseString(body);
            if (!root.isJsonArray()) return false;
            JsonArray array = root.getAsJsonArray();
            // Both operations must have been processed — each element a GraphQL
            // result object (carrying data or errors).
            return array.size() >= 2 && isGraphQlResult(array.get(0)) && isGraphQlResult(array.get(1));
        } catch (JsonSyntaxException e) {
            return false;
        }
    }

    private static boolean isGraphQlResult(JsonElement element) {
        if (!element.isJsonObject()) return false;
        JsonObject object = element.getAsJsonObject();
        return object.has("data") || object.has("errors");
    }

    // ---- HTTP ---------------------------------------------------------------

    private HttpRequestResponse sendGraphQl(HttpRequestResponse rr, Http http, String jsonBody) {
        try {
            HttpRequest probe = rr.request().withMethod("POST").withBody(jsonBody);
            // Reuse the original request (keeps auth cookies/headers). Only add a
            // JSON Content-Type when it isn't already JSON, to avoid a duplicate
            // header on the common application/json GraphQL request.
            if (!HttpUtils.isJson(probe)) {
                probe = probe.withAddedHeader("Content-Type", "application/json");
            }
            HttpRequestResponse response = http.sendRequest(probe);
            return (response != null && response.hasResponse()) ? response : null;
        } catch (Exception e) {
            api.logging().logToError("[GraphQL] probe send failed: " + e.getMessage());
            return null;
        }
    }

    // ---- Issues -------------------------------------------------------------

    private AuditIssue buildSuggestionsIssue(HttpRequestResponse base, HttpRequestResponse evidence) {
        String detail =
                "The GraphQL endpoint returns field <b>suggestions</b> when a query references an " +
                "unknown field. Sending the misspelled meta-field <code>__typenaem</code> produced " +
                "a \"Did you mean …\" hint in the response.<br><br>" +
                "Even with introspection disabled, an attacker can recover the schema field by " +
                "field by iterating unknown-field errors and reading the suggestions — defeating " +
                "the point of hiding it." +
                RELATED_INTROSPECTION;
        return IssueBuilder.issue(base)
                .name("API9:2023 - Improper Inventory Management (GraphQL Field Suggestions Enabled)")
                .detail(detail)
                .remediation("Strip field suggestions from error responses in production — e.g. a " +
                        "custom validation rule or error formatter that removes \"Did you mean\" " +
                        "hints — the same way you disable introspection.")
                .background(BACKGROUND_API9)
                .severity("Low")
                .confidence("Firm")
                .evidence(base, evidence)
                .build();
    }

    private AuditIssue buildBatchingIssue(HttpRequestResponse base, HttpRequestResponse evidence) {
        String detail =
                "The GraphQL endpoint accepts <b>array-batched</b> requests: a JSON array of two " +
                "operations was sent in one request and the server executed both, returning a " +
                "two-element result array.<br><br>" +
                "Batching — and field aliasing — let a client pack many operations into a single " +
                "request. Combined with a sensitive operation such as login or OTP verification, " +
                "this multiplies attempts per request and can bypass rate limiting that counts " +
                "HTTP requests (a brute-force amplification primitive). Whether it is exploitable " +
                "depends on what operations the endpoint exposes.";
        return IssueBuilder.issue(base)
                .name("API4:2023 - Unrestricted Resource Consumption (GraphQL Query Batching Enabled)")
                .detail(detail)
                .remediation("Disable array-based batching if it is not needed, cap the number of " +
                        "operations and aliases per request, and rate-limit on operations rather " +
                        "than on HTTP requests alone.")
                .background(BACKGROUND_API4)
                .severity("Low")
                .confidence("Firm")
                .evidence(base, evidence)
                .build();
    }
}
