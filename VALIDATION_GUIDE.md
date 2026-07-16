# Validation Guide

How to validate findings reported by this extension. Organised by
Montoya's confidence levels (`CERTAIN` / `FIRM` / `TENTATIVE`) — the
higher the confidence, the less manual validation is required.

> **Overlap with the native scanner.** Several categories here (injection,
> SSRF, JWT/auth, CORS/CSP/misconfig, TRACE) overlap Burp's native
> scanner, which detects the same classes at higher confidence. Each such
> issue carries a "Related Burp Scanner checks" line linking to the native
> check — cross-check it during validation.

## Severity mapping note

The extension uses Montoya's four-level severity (`HIGH`, `MEDIUM`,
`LOW`, `INFORMATION`). Legacy "Critical" findings are reported as
`HIGH` with `CERTAIN` confidence — Montoya has no Critical level. The
combination of `HIGH` + `CERTAIN` is the practical equivalent.

## AI triage note

When Burp AI is enabled, the [passive triage layer](BURP_DAST_GUIDE.md#burp-ai-features)
has already filtered findings the model considered clear false
positives in context. Anything that reaches the Issues tab is at least
a "the model thinks this is worth looking at" finding — but it can
still benefit from manual validation per the guidance below. Triage is
conservative (KEEP-when-in-doubt), not authoritative.

---

## CERTAIN — exploit proven by the request/response itself

These findings carry their own proof of exploitability. The validation
question is rarely "is this real?" but "is this in scope / worth
fixing?". Triage if needed, then prioritise.

| Finding | Why it's CERTAIN |
|---|---|
| **JWT `alg: none`** | Token verification is bypassed — any forged token is accepted. |
| **SQL injection (error-based)** | A SQL engine error string *not present in the baseline* appeared after the payload — input reached the SQL parser. |
| **Command injection** | Command output (`root:`, `/bin/`, …) *new vs the baseline* appeared after the payload — the OS executed it. |
| **SSRF to cloud IMDS** | Cloud-metadata content appeared in a 2xx response and was absent from the baseline — the server fetched the attacker URL. |
| **TRACE method enabled** | TRACE returned 200 **and echoed our marker header back** — Cross-Site Tracing is confirmed, not just assumed. |
| **API version disclosed in header** | The header value is itself the disclosure. |

For these: no manual validation needed. Confirm scope ownership, then
fix.

> **Note on baseline diffing (v2.1.0+).** The injection and SSRF checks
> now only fire when the marker is *new versus the unmutated baseline
> response* — a marker that already appears in docs, error pages, or
> static content no longer triggers a finding. This removes a class of
> false positive that earlier versions produced.

A few findings that look "certain" are deliberately reported a notch
lower because a single response can't fully prove exploitability:

- **Reflected XSS** — reported **Firm**, and only when the response
  Content-Type is HTML. A JSON API echoing the payload as a string
  value is not exploitable, so it is no longer flagged.
- **API over HTTP** — reported **Firm**, and only on a 2xx cleartext
  response. A 3xx redirect to the `https://` equivalent is correct
  enforcement and is suppressed.

---

## FIRM — strong evidence, context-dependent

These findings have substantive evidence (a 2xx where one wasn't
expected, a field appearing in a response that didn't ask for it), but
the *meaning* of that evidence depends on context. Walk through the
checklist before reporting.

### API1:2023 — BOLA / ID manipulation

**Finding:** changing an object ID in the URL returned a *different
object* than the original request (the response body differs from the
baseline — a 2xx alone does not fire this check).

**Questions to answer:**
1. Is the authenticated user *supposed* to see that other ID?
2. Are these public profiles (Twitter / LinkedIn shape)?
3. Is the user an admin / same-org member with legitimate access?

**How to validate:**
- Compare with the application's documented role model.
- Re-test as a different (non-admin) user.
- Confirm the returned data is genuinely cross-tenant or cross-user.

**True positive indicators:** private user data accessible across
tenants; PII accessible without explicit access grant.
**False positive scenarios:** public profile endpoints; legitimate
admin access; shared / collaborative resources.

### API1:2023 — Sequential ID enumeration

**Finding:** multiple adjacent numeric IDs each return a *distinct
object* (different response bodies), suggesting an enumerable namespace.

**Questions to answer:** Is the namespace meant to be enumerable
(public articles, public products)? Or is this leaking the existence
of private records?

**How to validate:** check whether the returned objects contain any
sensitive data, or whether the act of enumeration itself violates a
property (e.g. unlisted resources).

### API2:2023 — SQL injection auth bypass

**Finding:** a SQL payload in the password field returned a 200 with
session/token markers.

**Questions to answer:**
1. Did the response actually issue a valid session?
2. Or did the API just return a generic 200 with no real credentials?

**How to validate:**
- Capture any session token / JWT in the response.
- Use it on a follow-up authenticated endpoint. If it works, this is
  a confirmed bypass; if it doesn't, the 200 was a placebo.

### API2:2023 — Long-lived JWT (>24h)

**Finding:** `exp` claim is more than 24 hours in the future.

**Questions to answer:** Is the long lifetime an explicit business
choice (e.g. service-to-service tokens), or an oversight on user
sessions?

**How to validate:** check the token's `sub` / role — service tokens
legitimately live long; user-session tokens should not.

### API3:2023 — Mass assignment

**Finding:** the extension injected `isAdmin: true` (or an AI-suggested
contextual field like `priceOverride`) and the field was echoed in the
response.

**Questions to answer:**
1. Was the field actually saved server-side, or just echoed?
2. Does the field grant real privileges, or is it cosmetic?

**How to validate:**
- Re-fetch the modified record without the injection. Does the field
  persist?
- Attempt a privileged operation that should now succeed if the field
  was honoured (e.g. an admin-only endpoint).
- For AI-suggested fields (`priceOverride`, etc.), perform the
  business action and verify the price / state actually changed.

**False positive scenarios:** API echoes input but doesn't persist it;
field is validated and silently ignored.
**True positive indicators:** field persists across requests; the
user can now perform actions they previously couldn't.

### API3:2023 — Excessive data exposure (response shape)

**Finding:** the response is an **unbounded array** (100+ items with no
pagination signal) or its items carry an **excessive number of distinct
fields** (over-broad projection). Note: the check flags response *shape*,
not fields by sensitive-sounding name — specific value leaks are Burp's
native "Password returned in later response", "Credit card numbers
disclosed", etc. (linked from the issue).

**Questions to answer:**
1. Is the large/wide response intended (a legitimate bulk export)?
2. Does the client actually consume every field, or is the back-end
   model being serialised wholesale?

**How to validate:**
- Check for a pagination mechanism the check might have missed
  (cursor in body, non-standard header).
- Inspect the field set for back-end-only properties leaking through.

### API8:2023 — CORS reflected origin

**Finding:** the response `Access-Control-Allow-Origin` mirrors the
request `Origin` header.

**How to validate:**
- Test with an arbitrary `Origin` value — does it still reflect?
- Is `Access-Control-Allow-Credentials: true` also present? That's
  the combination that enables cross-origin attacks with credentials.

**False positive scenarios:** the server only reflects from an
allow-list and the request happened to hit a permitted origin.

### API9:2023 — Deprecated version reachable

**Finding:** the current path was `/v3/...` and an older `/v(N-1)/...`
returned 2xx on the same host. (Note: `/v1/` is no longer treated as
deprecated on its own — it is the current version on most APIs.)

**Questions to answer:**
1. Is the old version officially supported (long deprecation window)?
2. Or is it actually meant to be off?

**How to validate:**
- Diff the responses — does the old version expose endpoints or
  fields that the new version intentionally removed?
- Check whether the old version misses security fixes documented for
  the new version.

### API9:2023 — GraphQL field suggestions enabled

**Finding:** a query for the misspelled meta-field `__typenaem` returned
a "Did you mean …" hint, so the server leaks field names on unknown-field
errors — schema recovery is possible even with introspection disabled.

**Questions to answer:** Is introspection also on (then this is moot —
the schema is already public)? If introspection is off, this defeats that
control.

**How to validate:** in Repeater, send `{ __typenaem }` and confirm the
suggestion; then query another misspelled field name and observe the
server hinting real field names. Cross-check Burp's native *GraphQL
introspection enabled* issue for the same endpoint.

### API4:2023 — GraphQL query batching enabled

**Finding:** a JSON array of two operations was accepted and both were
executed (a two-element result array returned).

**Questions to answer:** Does the endpoint expose a sensitive operation
(login, OTP, password reset) that batching/aliasing could amplify past a
per-request rate limit?

**How to validate:** in Repeater, batch (or alias) a sensitive mutation N
times in one request and check whether all N attempts are processed and
whether rate limiting counts operations or only HTTP requests. Batching
alone is only impactful when paired with such an operation.

---

## TENTATIVE — heuristic, high false-positive rate

These findings come from heuristics with no direct exploit proof.
They're worth knowing about but should never be reported as
confirmed without manual validation.

### API4:2023 — Missing rate limiting (Information)

**Finding:** no `X-RateLimit-*` / `RateLimit-*` headers on a
resource-intensive endpoint path (search, export, report, …). Reported
at Information/Tentative — header absence is weak evidence.

**How to validate:**
- Send a burst of requests (e.g. 200 in 30 seconds).
- Watch for 429 / 503 / 502 responses, increased latency, or IP
  blocks.
- Confirm with the WAF / CDN config if accessible — rate limiting may
  exist at a layer that doesn't surface response headers.

**False positive scenarios:** WAF / Cloudflare handles rate limiting
without surfacing headers; legitimate low-value endpoint that doesn't
need limiting.

### API6:2023 — Missing anti-automation on sensitive flow

**Finding:** a sensitive-keyword path (`/checkout`, `/transfer`,
`/withdraw`, …) lacks anti-automation indicators (CAPTCHA tokens,
rate-limit headers).

**How to validate:**
- Attempt to drive the endpoint at scale (10–100x normal use).
- Confirm whether the underlying business action repeats unimpeded.
- Consider whether the action has business impact at scale (financial
  loss, account creation flood, ticket scalping).

### API8:2023 — NoSQL injection (bypass behaviour)

**Finding:** the endpoint returned 200 OK to a payload containing a
Mongo operator (`{"$ne": null}` etc.) without surfacing a NoSQL
error.

**How to validate:**
- Diff the response between the operator payload and a benign
  payload. If both produce identical 200s, the server is silently
  accepting the operator — investigate whether it reached the query
  layer.
- Try operator combinations that should be semantically distinct
  (`$ne` vs `$gt` vs `$exists`) and look for behavioural differences
  in the response.
- If you have access to the back-end, check whether the input is
  cast to a string before query construction.

**False positive scenarios:** the server treats the object as a
string and stores it verbatim; no Mongo query is involved.

### API9:2023 — Debug / management endpoint exposed

**Finding:** path looks like `/debug`, `/actuator`, `/metrics`,
`/internal`, etc. (Documentation paths like `/swagger` and `/openapi`
are no longer flagged — intentional published artefacts.)

**How to validate:**
- Is the endpoint intentionally public (e.g. a public health probe)?
- Does it leak runtime configuration or grant administrative
  actions?
- Is access restricted by network controls (mTLS, allow-list)?

### API10:2023 — HTTP Parameter Pollution

**Finding:** sending the same parameter twice (once with the original
value, once with a marker) produced a response that differs from the
single-parameter baseline.

**How to validate:**
- Reproduce the request in Repeater with the polluted parameter.
- Try several pollution-value variants: empty string, a value the
  application is likely to treat specially (`admin`, `1`, `0`,
  `true`), and the marker the scanner used. Different frameworks
  pick different values from the duplicate set — knowing *which* the
  server picks is part of the exploit.
- If the parameter participates in authorisation (e.g.
  `?user_id=123&user_id=456` returns user 456's data), this is a
  direct access-control bypass.
- If the parameter participates in filtering (e.g. WAF reads first
  value, app reads last), the inconsistency is exploitable across
  the security boundary.

> **On a `200 → 400` result:** do **not** dismiss it as the framework
> safely rejecting a duplicate. If polluting with the marker flips a 200
> to a 400, the server is reading the *last* value (the marker) and
> discarding the legitimate first one — that is the override primitive HPP
> exploits. A reviewer confirmed one such case as a genuine auth-relevant
> HPP, so the check fires on any status change (Tentative).

**False positive scenarios:** the response varies for unrelated reasons
(timestamps, caching) — the jitter guard suppresses most of these, but
verify in Repeater.

**True positive indicators:** the polluted response reveals different
data than the baseline; the security control (WAF, framework router)
treats the parameter set differently than the application code.

### API10:2023 — Webhook receiver (Information)

**Finding:** path matches a webhook pattern (`/webhook`,
`/inbound-webhook`, …). A pointer for manual review, not a confirmed
flaw — the check has no evidence the handler is actually unsafe. (Broad
terms like `/callback` were removed as too noisy.)

**How to validate:**
- Send a synthetic payload from an unrelated source. Does the
  endpoint accept it?
- If the upstream provider documents a signing scheme (HMAC, etc.),
  check whether the application implements verification.

---

## Reporting tips

- **Treat `CERTAIN + HIGH` as the equivalent of legacy `Critical`** —
  these findings should be the headline of any report.
- **Always include the request/response evidence** that fired the
  finding — Burp captures it automatically; make sure it's exported
  with the report.
- **For AI-augmented findings** (mass assignment via field discovery,
  triage-survived findings), note in the report which payloads /
  fields the AI proposed. The reviewer should see the model's
  contribution so they can sanity-check it.
- **For TENTATIVE findings** — never report without manual
  validation. False positives erode trust in the whole report.
