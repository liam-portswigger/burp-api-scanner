# Burp Suite DAST Integration Guide

This document only covers what's specific to running this extension on
**Burp Suite DAST** (headless / automated scanning). For general DAST
configuration — scope, scheduling, scan-speed tuning, OpenAPI import,
CI/CD integration — see the [official DAST documentation](https://portswigger.net/burp/documentation/dast).

The extension also runs unchanged in **Burp Suite Professional**; the
edition is detected at load time and the UI tab is skipped under DAST.

## Loading the extension

The extension is shipped as a single fat JAR. Build with:

```bash
mvn clean package -DskipTests
```

Output: `target/burp-api-scanner-2.3.2.jar`.

In DAST:

1. **Settings → Extensions → Add extension**
2. Upload `burp-api-scanner-2.3.2.jar`
3. Enable the extension

There is no per-DAST configuration — once loaded and enabled, the
extension's checks run as part of any scan that uses Active and/or
Passive audit.

## Verifying the load

DAST runs headless — there is **no interactive Output tab** to read the
startup banner in (that surface only exists in Professional / Community).
Verify the extension in DAST like this:

1. Open the scan's **Settings** tab and confirm the extension is listed
   under **Extensions** (e.g. `burp-api-scanner-2.3.2.jar`). This proves
   it loaded and was applied to the scan.
2. After the scan runs, open the **Issues** tab and confirm findings
   labelled `APIx:2023` are present — this confirms the extension's
   checks actually executed against the site.

The banner (extension name, edition via `BurpSuiteEdition.displayName()`,
and AI-features state) is still emitted to the extension's output stream
in every edition — it is just not viewable in an interactive tab under
DAST. If AI features report `disabled` when you expect them on, the most
common cause is that Burp AI isn't enabled at the suite level, not an
extension fault.

In **Professional / Community**, the banner is visible directly in the
extension's Output tab and reads:

```
====================================
OWASP API Security Top 10 Scanner v2.3.2
OWASP API Security Top 10 (2023) coverage
Edition: Burp Suite Professional
AI features: enabled       (or "disabled" if Burp AI is off)
====================================
```

## OWASP API Top 10 coverage

Complete OWASP API Security Top 10 (2023) coverage — 15 checks. Several
checks overlap Burp's native scanner; that overlap is intentional (one
extension, all ten categories, OWASP-labelled) and each overlapping issue
links to the native check in its detail. Run the native scanner alongside
this extension for the deepest results.

| Category | Detection | Related native check(s) |
|---|---|---|
| **API1:2023** — Broken Object Level Authorization | Active | Broken access control |
| **API2:2023** — Broken Authentication | Active | JWT signature not verified; JWT *none* algorithm; JWT weak HMAC secret; JSON Web Key Set disclosed; Cleartext submission of password |
| **API3:2023** — Broken Object Property Level Authorization | Active + Passive | Password returned in later response; Credit card numbers disclosed; Private key disclosed |
| **API4:2023** — Unrestricted Resource Consumption | Passive | — (API-specific) |
| **API5:2023** — Broken Function Level Authorization | Active | Broken access control |
| **API6:2023** — Unrestricted Access to Sensitive Business Flows | Passive | — (API-specific) |
| **API7:2023** — Server-Side Request Forgery | Active | Out-of-band resource load (HTTP); External service interaction; File path traversal |
| **API8:2023** — Security Misconfiguration | Active + Passive | CORS; Content security policy; Strict transport security not enforced; Frameable response; Unencrypted communications; Source code disclosure; HTTP TRACE method is enabled |
| **API9:2023** — Improper Inventory Management | Active + Passive | — (API-specific) |
| **API10:2023** — Unsafe Consumption of APIs | Active + Passive | — (API-specific) |

Each overlapping issue carries a **"Related Burp Scanner checks"** line in
its detail that deep-links to the specific native issue definition(s) under
[portswigger.net/kb/issues](https://portswigger.net/kb/issues) — not just
the generic vulnerabilities list.

All findings use Montoya's four-level severity (`HIGH`, `MEDIUM`, `LOW`,
`INFORMATION`). Legacy `Critical` findings are reported as `HIGH` with
`CERTAIN` confidence — Montoya has no Critical level.

**Parameter Pollution note:** the HPP check fires on *any* status change
between the baseline and the polluted request, in either direction
(reported Tentative). A `200 → 400` is **not** treated as safe rejection
here: if our duplicate marker flips a 200 to a 400, the server is reading
the last value and discarding the legitimate first one — a genuine
override primitive. Confirm exploitability manually.

**Parameter Pollution note:** the HPP check fires on *any* status change
between the baseline and the polluted request, in either direction
(reported Tentative). A `200 → 400` is **not** treated as safe rejection
here: if our duplicate marker flips a 200 to a 400, the server is reading
the last value and discarding the legitimate first one — a genuine
override primitive. Confirm exploitability manually.

## Burp AI features

Two AI integrations run automatically when `api.ai().isEnabled()` is
true:

- **Passive triage** — each passive finding is sent to the model with
  the request/response context. The model returns `KEEP` or
  `SUPPRESS`. Findings tagged `SUPPRESS` are dropped before they reach
  the Issues tab. Conservative: any failure or ambiguous reply keeps
  the issue.
- **Contextual mass-assignment field discovery** — for JSON request
  bodies, the model proposes domain-specific privileged fields
  (`priceOverride`, `organizationRole`, etc.) in addition to the
  hardcoded list, and the existing test logic injects each one.

Each AI call has a 2-second hard timeout. AI errors are logged but
never fail a scan.

Kill switches (JVM system properties on the DAST process):

- `-Dcom.security.burp.ai.disabled=true` — turn off everything
- `-Dcom.security.burp.ai.triage.disabled=true` — keep field discovery,
  disable triage
- `-Dcom.security.burp.ai.discovery.disabled=true` — keep triage,
  disable field discovery

## Verification checklist

Before running production scans:

- [ ] Extension JAR listed under the scan's **Settings → Extensions**
- [ ] After a test scan, `APIx:2023` findings appear in the **Issues**
      tab (confirms the checks executed)
- [ ] Scan configuration includes Active + Passive audit (passive-only
      will not surface the active findings — injection, SSRF, BOLA,
      mass assignment, TRACE, version probing, parameter pollution)
- [ ] Burp's **native scanner is also enabled** — the overlapping
      categories detect the same classes at higher confidence, and the
      issues here link to those native checks (see coverage table)
- [ ] API endpoints are in scan scope
- [ ] Authentication credentials configured if the API requires them
      (authorization checks need an authenticated baseline to test
      against)

## Troubleshooting

| Symptom | First thing to check |
|---|---|
| Extension fails to load | Errors tab on the extension. JDK 17+ is required (Montoya API requirement). |
| `AI features: disabled` when Burp AI is on | The extension declares `EnhancedCapability.AI_FEATURES`; if `isEnabled()` is still false, confirm the user account has been granted AI access. |
| No findings at all | Confirm Active audit is enabled — the active findings (injection, SSRF, BOLA, mass assignment, TRACE, version probe, parameter pollution) require it. |
| Findings missing only on URL-rebuild checks (BOLA, version probe) | Some servers reject duplicate Host headers — this is handled in v2, but worth checking the Errors tab for `4xx` responses on probe requests. |

## Reference

- [Burp Suite DAST documentation](https://portswigger.net/burp/documentation/dast)
- [Extension authoring](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/index.html)
- [CLAUDE.md](CLAUDE.md) — architecture, conventions, gotchas
- [README.md](README.md) — overview and quick-start
