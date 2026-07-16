# OWASP API Security Top 10 Scanner

**📦 Available on the [Burp Suite BApp Store](https://portswigger.net/bappstore/4894a4ba29ec4303990196a6bbc5d67b)** — install directly from **Extensions → BApp Store** in Burp.

A Burp Suite extension providing complete OWASP API Security Top 10
(2023) coverage in one place, built on the
[Montoya API](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions).

**Compatible with:**
- Burp Suite Professional (with UI tab)
- Burp Suite DAST (headless / automated scanning)

The extension auto-detects the edition at load time; the UI tab is
registered only under Professional.

> **On overlap with the native scanner.** Some checks here (injection,
> SSRF, HTTP method abuse, JWT/authentication, CORS/CSP/security-
> misconfiguration) intentionally overlap Burp's native scanner. That
> overlap is deliberate: the goal is a single extension that reports
> findings **labelled against all ten OWASP API categories**, so a report
> organised by the OWASP API Top 10 comes straight out of the tool. Where
> a check overlaps native coverage, its issue detail carries a
> **"Related Burp Scanner checks"** line that **deep-links to the specific
> native issue definition(s)** (e.g. [SQL injection](https://portswigger.net/kb/issues/00100200_sql-injection),
> [Broken access control](https://portswigger.net/kb/issues/00100850_broken-access-control))
> — the native scanner detects the same class at higher confidence. Run it
> alongside this extension for the deepest results.

## Quick start

**Most users:** install from the [BApp Store](https://portswigger.net/bappstore/4894a4ba29ec4303990196a6bbc5d67b) via **Extensions → BApp Store** in Burp — no build required.

**Building from source** (development):

```bash
mvn clean package -DskipTests
```

Produces `target/burp-api-scanner-2.3.2.jar`. Load via **Extensions →
Installed → Add → Java**.

Requires JDK 17+ (Montoya API requirement) and Maven 3.6+.

The banner in the extension's Output tab will look like:

```
====================================
OWASP API Security Top 10 Scanner v2.3.2
OWASP API Security Top 10 (2023) coverage
Edition: Burp Suite Professional
AI features: enabled
====================================
```

## Coverage

Full OWASP API Security Top 10 (2023), 15 checks:

| OWASP category | Detection | Related native check(s) |
|---|---|---|
| API1:2023 — Broken Object Level Authorization | Active | Broken access control |
| API2:2023 — Broken Authentication | Active | JWT signature not verified · JWT none algorithm · JWT weak HMAC secret · JSON Web Key Set disclosed · Cleartext submission of password |
| API3:2023 — Broken Object Property Level Authorization | Active + passive | Password returned in later response · Credit card numbers disclosed · Private key disclosed |
| API4:2023 — Unrestricted Resource Consumption | Passive | — (API-specific) |
| API5:2023 — Broken Function Level Authorization | Active | Broken access control |
| API6:2023 — Unrestricted Access to Sensitive Business Flows | Passive | — (API-specific) |
| API7:2023 — Server-Side Request Forgery | Active | Out-of-band resource load (HTTP) · External service interaction · File path traversal |
| API8:2023 — Security Misconfiguration | Active + passive | CORS · Content security policy · Strict transport security not enforced · Frameable response · Unencrypted communications · Source code disclosure · HTTP TRACE method is enabled |
| API9:2023 — Improper Inventory Management | Active + passive | — (API-specific) |
| API10:2023 — Unsafe Consumption of APIs | Active + passive | — (API-specific) |

Every issue in the overlapping categories links to its native
counterpart in its detail section (see the note above). The four
API-specific categories (API4, API6, API9, API10) have no native
equivalent — they are the unique coverage this extension adds.

## Distinguishing features

- **Active version probing** — when the path matches `/vN/`, the
  extension actively probes `/v(N-1)/`, `/v(N-2)/`, … on the same host
  and reports each version that returns 2xx. Catches deprecated API
  versions that survive into production.
- **Content-compared BOLA** — the object-level-authorization check fires
  only when a manipulated identifier returns a *materially different
  object* than the baseline, not merely a 2xx.
- **HTTP Parameter Pollution** — fires on any response change (in either
  direction) when a parameter is duplicated; a marker-induced `200 → 400`
  is treated as a real override primitive, not safe rejection.
- **Burp AI integration** (optional) — when `api.ai().isEnabled()` is
  true, two extra features activate automatically:
  - **Passive triage**: false-positive filter on noise-prone passive
    checks. Attacker-controlled HTTP content is wrapped in structural
    delimiters and treated as data; the model's reply is parsed with
    safe-failure semantics (ambiguous → keep the finding).
  - **Contextual mass-assignment field discovery**: in addition to the
    hardcoded `isAdmin`/`role`/etc. payloads, the model proposes
    domain-specific privileged fields (`priceOverride`,
    `organizationRole`, …) given the observed JSON body.
  Both features have JVM-property kill switches and time out at 2
  seconds per prompt on a bounded daemon thread pool.

## Documentation

- [CLAUDE.md](CLAUDE.md) — architecture, conventions, gotchas. Read
  this before contributing.
- [BURP_DAST_GUIDE.md](BURP_DAST_GUIDE.md) — DAST-specific load,
  banner, coverage, troubleshooting.
- [VALIDATION_GUIDE.md](VALIDATION_GUIDE.md) — how to validate
  findings by confidence level.

## Architecture (high level)

```
com.security.burp/
├── BurpExtender.java        # entry; declares AI capability, registers everything
├── ai/                      # AI client + triage + field discovery
├── checks/
│   ├── AbstractPassiveCheck #   base classes — exception handling, triage
│   ├── AbstractActiveCheck
│   ├── passive/             # 6 passive checks
│   └── active/              # 9 active checks
│       └── injection/       #   InjectionCheck helpers (payloads, auth-bypass tester)
├── scanner/EndpointRegistry # shared state for the UI tab
├── ui/ScannerTab            # Swing tab listing discovered endpoints
└── util/IssueBuilder        # fluent AuditIssue construction
```

15 scan checks total, registered individually with the appropriate
`ScanCheckType` (`PER_INSERTION_POINT`, `PER_HOST`, or `PER_REQUEST`).
See [CLAUDE.md](CLAUDE.md) for the full breakdown.

## Contributing

The patterns established during the v2 rewrite are documented in
[CLAUDE.md](CLAUDE.md). When adding a new check, extend
`AbstractPassiveCheck` or `AbstractActiveCheck`, build issues via
`IssueBuilder`, keep constants at the top of the class. If a new check
overlaps native scanner coverage, add a "Related Burp Scanner checks"
line to its issue detail linking to the vulnerabilities list.

Ideas worth picking up:
- GraphQL-specific testing (introspection, depth, batching)
- Out-of-band detection via Burp Collaborator integration

## Disclaimer

For authorized security testing only. Obtain proper authorization
before testing any API or application you don't own.

## License

MIT — see [LICENSE](LICENSE).
