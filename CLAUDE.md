# CLAUDE.md

Guidance for Claude (and any human reviewer) working in this repository.

This is a Burp Suite extension implementing OWASP API Security Top 10
(2023) coverage. It is built on the Montoya API and targets Burp Suite
Professional and Burp Suite DAST.

> **Coverage note.** `main` is the **full build** (16 checks) — complete
> OWASP API Top 10 (2023) coverage in one extension, and this is what we
> submit to the BApp Store (renamed **"OWASP API Security Top 10 Scanner"**).
> Several checks intentionally overlap Burp's native scanner (injection,
> SSRF, TRACE, JWT/auth, CORS/CSP/misconfig). Per Hannah's guidance, the
> overlap is kept — not removed — so the extension gives complete,
> OWASP-labelled coverage; each overlapping issue instead carries a
> **"Related Burp Scanner checks"** line in its detail linking to the
> native check in the [vulnerabilities list](https://portswigger.net/burp/documentation/scanner/vulnerabilities-list).
>
> History: v2.2.0 (on the `full` branch and `v2.1.2` tag) briefly went the
> other way — a *lean* build that removed the duplicating checks. That was
> reversed in v2.3.0 after re-consulting Hannah: keep-and-cross-reference,
> don't remove. The confidence/severity recalibrations from the lean pass
> were kept.

## Architecture

```
src/main/java/com/security/burp/
├── BurpExtender.java              # Entry point. Declares EnhancedCapability.AI_FEATURES,
│                                  # registers checks, wires the unloading handler.
├── ai/                            # AI integration layer (optional, gates on api.ai().isEnabled())
│   ├── AiClient.java              #   wrapper around api.ai(): bounded thread pool + 2s timeout + cache
│   ├── AiTriage.java              #   passive-finding KEEP/SUPPRESS filter
│   └── AiFieldDiscovery.java      #   contextual privileged-field suggestions for mass assignment
├── checks/
│   ├── AbstractPassiveCheck.java  # Base class. Centralises endpoint recording, exception
│   │                              # handling (with stack-trace logging), AI triage.
│   ├── AbstractActiveCheck.java   # Same, for active checks.
│   ├── passive/                   # 6 passive checks, all extend AbstractPassiveCheck
│   │                              #   (BusinessFlow, ExcessiveDataExposure,
│   │                              #   InventoryManagement, ResourceConsumption,
│   │                              #   SecurityMisconfig, UnsafeApiConsumption)
│   └── active/                    # 10 active checks, all extend AbstractActiveCheck
│       └── injection/             #   (BrokenObjectAuth, BrokenAuth, DeprecatedVersionProbe,
│                                  #   FunctionLevelAuth, GraphQl, Injection, MassAssignment,
│                                  #   MethodFuzzing, ParameterPollution, Ssrf).
│                                  #   InjectionCheck splits into injection/{AuthBypassTester,
│                                  #   InjectionPayloads}.
├── scanner/
│   └── EndpointRegistry.java      # Bounded thread-safe state shared with the UI tab.
│                                  # Cleared on unload.
├── ui/
│   └── ScannerTab.java            # Swing JPanel + JTable backed by EndpointRegistry.
│                                  # dispose() stops the refresh timer.
└── util/
    ├── HttpUtils.java             # content-type / API-path / modifying-method helpers
    └── IssueBuilder.java          # fluent AuditIssue construction (replaces legacy
                                   # CustomScanIssue). Maps "Critical" -> Montoya HIGH.
```

## Build commands

```bash
export JAVA_HOME=/opt/homebrew/opt/openjdk        # or any JDK 17+
export PATH="$JAVA_HOME/bin:$PATH"
mvn clean package -DskipTests
```

Output: `target/burp-api-scanner-2.4.0.jar` (~370 KB fat JAR).

Load in Burp via **Extensions → Installed → Add → Java**.

## Conventions

These are the patterns established across all 16 checks. Stick to them
when adding new ones — Hannah's review feedback was the catalyst for the
v2 rewrite, and breaking these breaks the property she cared about
(reviewable code).

- **Each check extends `AbstractPassiveCheck` or `AbstractActiveCheck`.**
  Subclasses implement one method (`audit(...)`) and don't worry about
  exception handling, endpoint recording, or AI triage.
- **Constants at the top of the class.** Path keywords, payload tables,
  HTML strings for issue descriptions — pull them up.
- **Methods under ~50 LOC**, classes under ~250 LOC. The largest current
  file is `SecurityMisconfigCheck.java` (~360 LOC) because it has several
  sub-checks; further splitting would just add ceremony.
- **Overlapping checks cross-reference native.** If a check detects a
  class Burp's native scanner also covers (injection, SSRF, TRACE,
  JWT/auth, CORS/CSP/misconfig), append a `RELATED_CHECKS`-style constant
  to the issue detail that **deep-links each named native check to its
  specific `/kb/issues/<code>_<slug>` definition** (not the generic
  vulnerabilities-list page). This is how we keep full OWASP coverage
  without pretending we detect these better than native does.
- **No swallowed exceptions.** The base classes log uncaught throwables
  with a full stack trace via `api.logging().logToError(...)`. If you
  catch yourself, log the same way.
- **Issues built via `IssueBuilder`.** Don't call `AuditIssue.auditIssue(...)`
  directly — the builder centralises the legacy "Critical" → Montoya
  HIGH mapping (Montoya has no Critical level).
- **Detection logic is the source of truth.** AI is a *filter* (triage
  drops false positives) or an *augmentation* (field discovery adds
  contextual payloads). It never invents findings on its own.

## Gotchas (real things that bit us)

1. **`EnhancedCapability.AI_FEATURES` must be declared.** Without this
   override on `BurpExtension`, `api.ai().isEnabled()` returns false even
   when Burp AI is on at the suite level. The banner will say
   "AI features: disabled" and you will lose an afternoon trying to
   figure out why. See `BurpExtender.enhancedCapabilities()`.

2. **`HttpRequest.httpRequestFromUrl(...)` already sets a Host header.**
   Adding `withAddedHeaders(rr.request().headers())` on top duplicates
   it, and many servers reject duplicate Host with a 4xx — silently
   masking real findings (BOLA, version-probe). Re-attach all original
   headers EXCEPT Host. See `BrokenObjectAuthCheck.sendWithReplacedId`
   and `DeprecatedVersionProbeCheck.rebuildAtVersion` for the right shape.

3. **AI calls must time out AND run on a multi-worker pool.**
   `api.ai().prompt().execute(...)` is synchronous and can block
   indefinitely. `AiClient` runs prompts on a bounded daemon thread
   pool (4 workers) with a 2s hard timeout. The pool must have several
   workers, not one: with a single worker, concurrent scan threads
   queue and can time out while still *waiting in the queue* rather
   than during the actual call. PortSwigger BApp criterion #5.

4. **Use `edition.displayName()`, not the raw enum.** The Montoya enum
   constant is `BurpSuiteEdition.ENTERPRISE_EDITION` for backward
   compatibility, but customers know the product as "Burp Suite DAST".
   `displayName()` returns the current product name.

5. **UI tabs need `applyThemeToComponent()`.** Without it, the tab uses
   Swing defaults — looks wrong against a dark Burp. Call it on the
   component before `registerSuiteTab`.

6. **The unloading handler must release everything.** Executors, timers,
   registries, UI references. PortSwigger BApp criterion #6. See
   `BurpExtender.registerUnloadingHandler` for the canonical shape.

7. **JSON-format AI prompts are more reliable than free-text.** The AI
   integration uses structured prompts that ask for JSON (e.g.
   `{"verdict": "KEEP" | "SUPPRESS"}`) and parses with Gson. Free-text
   parsing produces flaky results on the long tail of model outputs.

8. **Don't bulk-rewrite via a sub-agent without reviewing the output.**
   The first Montoya migration (closed PR #2) compiled cleanly but
   produced unreviewable code (one 666-LOC check, swallowed exceptions,
   dense logic). The v2 rewrite was hand-written file by file with
   the patterns above. "Compile-clean" ≠ "good code".

## Adding a new check

1. Decide passive (no outbound traffic) or active (sends payloads).
2. Create the class under `checks/passive/` or `checks/active/` and
   extend the corresponding `Abstract*Check` base class.
3. Add constants at the top, helpers private, single `audit(...)` body.
4. Build issues via `IssueBuilder.issue(rr).name(...).detail(...).build()`.
5. Register in `BurpExtender.registerScanChecks(...)` with the right
   `ScanCheckType`:
   - `PER_INSERTION_POINT` for parameter-mutating checks
   - `PER_HOST` for endpoint/method-level checks
   - `PER_REQUEST` for passive checks
6. Run `mvn clean package` — the build will fail loudly on style /
   import / typing problems before the JAR is produced.

## Detection-logic discipline (the #1 false-positive source)

Every false positive this extension has shipped came from one mistake:
**firing on a signal without confirming it actually indicates the
vulnerability.** Before adding or changing any check, walk this
checklist — every row is a bug we actually shipped and had to fix.

| Ask yourself | Why | Real example |
|---|---|---|
| Does a 2xx actually mean success? | A `200` with `{"error":"not found"}` is the server refusing access with a sloppy status code. Inspect the body (`HttpUtils.looksRejected`). | BOLA fired Critical on a 200-with-error-body; FunctionLevelAuth too. |
| Did my payload cause the marker, or was it already there? | A marker in static content (docs, error page, cached response) proves nothing. Diff against the baseline `rr.response()` (`HttpUtils.baselineContains`). | SSRF fired on `root:x:0:0` in API docs; command injection on `/bin/bash` in a config dump. |
| Does a *difference* between responses prove a vuln, or just a different input being handled? | Judge by **mechanism, not status direction**. For a *single mutated value*, a `2xx → 4xx` is usually the server correctly rejecting bad input — not a bypass. **But duplicate-parameter pollution is the documented exception:** if polluting with our marker flips `200 → 400`, the server is reading the *last* value and discarding the legitimate first one — a real HPP override primitive. So ParameterPollution fires on *any* status change. | Two opposite FPs: an injection check firing on a `200 → 400` rejection; **and** HPP wrongly *suppressing* a real `200 → 400` override (over-correction — a reviewer confirmed the suppressed case was genuine). |
| Is the value reflected, or actually processed? | An echoed `redirect_uri` in a validation error is input reflection, not SSRF. A request field echoed for audit logging isn't mass assignment. | SSRF on OAuth reject-echo; MassAssignment on request-echo. |
| Is enforcement being mistaken for the flaw? | A `308` to `https://` is correct HTTPS enforcement, not "API over HTTP". | API-over-HTTP fired on every redirect. |
| Does my confidence match my proof? | Keyword / path / header-presence heuristics are **Tentative**, not Certain. Reserve Certain for self-proving evidence (a SQL error *new vs baseline*, TRACE echoing a planted marker). | Several passive checks were Certain on path-keyword matches. |
| On an ambiguous or unparseable signal, do I fail toward NOT firing? | Suppressing a finding (or asserting one) on doubt erodes trust. Default to keep-the-finding / don't-fire. | `AiTriage` now KEEPs on any non-clean verdict. |

**The one-line rule:** a check may only fire when the evidence would
convince a skeptical pentester that the *specific* vulnerability is
present — not merely that "something is different" or "a keyword
appeared". When in doubt, don't fire.

## Reference

- [Montoya API Javadoc](https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/MontoyaApi.html)
- [Montoya API examples](https://github.com/PortSwigger/burp-extensions-montoya-api-examples)
- [BApp Store acceptance criteria](https://portswigger.net/burp/documentation/desktop/extend-burp/extensions/bapp-store-acceptance-criteria)
- [Extension template project](https://github.com/PortSwigger/extension-template-project) — the upstream
  CLAUDE.md and `docs/*` define PortSwigger's official conventions.
- See [BURP_DAST_GUIDE.md](BURP_DAST_GUIDE.md) for headless / DAST
  loading guidance.
