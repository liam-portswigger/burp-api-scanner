# `full` branch — complete build (NOT for BApp Store)

This branch preserves the **complete 15-check** version of the extension
as it stood at **v2.1.2**.

It intentionally includes scan checks that **re-detect issues Burp's
native scanner already reports** (SQL injection, OS command injection,
reflected XSS, SSRF, TRACE/PUT, JWT flaws, CORS/CSP/HSTS, etc.), framed
under the OWASP API Security Top 10. That redundancy is **by design**
here — this branch is for users who want a single consolidated
OWASP-API-Top-10 view across both native and API-specific findings.

## This branch is NOT the BApp Store submission

The BApp Store build lives on `main`. Per BApp acceptance criteria and
PortSwigger review feedback, `main` removes the checks that duplicate
the native scanner and instead cross-references them, keeping only the
API-specific checks native Burp lacks. **Do not submit this branch.**

| | `main` | `full` (here) |
|---|---|---|
| Audience | BApp Store | internal / consolidated-report users |
| Duplicate-of-native checks | removed, cross-referenced | kept |
| OWASP Top 10 mapping | docs + "Related Burp checks" detail lines | live re-detection |

Build identically: `mvn clean package` → `target/burp-api-scanner-<version>.jar`.
