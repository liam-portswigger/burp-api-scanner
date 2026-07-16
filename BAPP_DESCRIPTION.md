# BApp Store description

Source of truth for the extension's BApp Store listing text. Keep this in
sync with the store page when either changes.

**Extension name:** OWASP API Security Top 10 Scanner

---

This extension provides coverage of all ten OWASP API Security Top 10 (2023) categories through active and passive scan checks. It reports findings labelled by OWASP API category so that scan output maps directly to the framework. Where checks overlap with native scanner coverage, issue details include references linking to the corresponding native issue definitions.

## Features

* All ten OWASP API Security Top 10 (2023) categories in a single extension, with every finding labelled by category so scan output maps straight onto the framework for reporting.
* Coverage of the four API-specific risks that native scanning does not address: unrestricted resource consumption, unrestricted access to sensitive business flows, improper inventory management, and unsafe consumption of APIs.
* Active discovery of deprecated API versions left reachable in production, by probing earlier versions of any `/vN/` path.
* GraphQL-specific checks that native scanning does not perform: field-suggestion leakage ("Did you mean …", which lets an attacker recover the schema even when introspection is disabled) and array query batching (a rate-limit-bypass and brute-force amplification primitive).
* Detection tuned to keep noise down: broken object level authorization fires only when a manipulated identifier returns a materially different object, and parameter pollution measures an endpoint's natural response variation before reporting length-based differences.
* Optional AI assistance that filters false positives on noise-prone passive checks and suggests context-specific mass-assignment fields to test.

## Usage

1. Confirm the extension has loaded:
   * **Burp Suite Professional / Community:** check the extension's Output tab for the startup banner, which shows the detected edition and whether AI features are active.
   * **Burp Suite DAST:** there is no interactive Output tab. Open the scan's **Settings** tab and confirm the extension is listed under **Extensions**, then check the **Issues** tab for findings labelled `APIx:2023` to confirm it is running against the site.
2. Browse or proxy API traffic as normal. Passive checks run against proxy traffic when live passive auditing is enabled, and as part of any audit; discovered endpoints appear in the extension's tab under Professional.
3. Run an active audit against your API:
   * **Professional:** start a scan from the **Dashboard → New scan** wizard (or right-click a request and choose **Scan**).
   * **DAST:** launch a scan against the site in the usual way.

   The audit exercises the active checks — broken object- and function-level authorization, injection, SSRF, mass assignment, parameter pollution, TRACE, and version enumeration on any `/vN/` path — and runs the passive checks against the responses, so between them all ten OWASP API categories are covered.
4. Review findings in the Issues view, where each is labelled with its OWASP API category. For checks that overlap native coverage, follow the Related Burp Scanner checks reference in the issue detail to compare with native findings.
5. If AI features are enabled, passive findings on noise-prone checks will be automatically triaged before reporting, and mass-assignment payloads will include domain-specific field suggestions derived from the observed request body.
