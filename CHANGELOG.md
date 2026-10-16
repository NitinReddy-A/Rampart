# Changelog

All notable changes to Rampart are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Finding-driven escalation (`--deep`).** A *confirmed* finding now deterministically spawns
  bounded, deduped, oracle-proven follow-up tests — the other injection classes on a parameter
  proven to be a live sink (the initial sweep only proposes SSRF/CMDI/traversal/redirect when the
  parameter *name* matches a hint, so an oddly-named sink is otherwise never deep-tested), and
  sibling endpoints returning an object type proven to have a broken ownership check. The control
  flow is fixed code, never an LLM; it is level-synchronous and admits follow-ups in a
  completion-order-independent order, so a parallel run escalates to exactly the same set as a
  serial one. Hard caps (`--deep` uses depth ≤ 2, ≤ 24 total, ≤ 6 per finding) plus dedup by
  investigation identity make runaway fan-out structurally impossible, and the counts admitted
  and dropped by each cap are recorded in the report. Escalation only ever targets classes whose
  oracle proves the class with a negative control, so it can never amplify an oracle's
  false-positive mode — it finds *more*, never noisier. Available as `--deep` on the CLI and
  `Rampart(..., deep=True)` in the SDK.
- **Capability/coverage manifest** ([docs/COVERAGE.md](docs/COVERAGE.md)): an authoritative,
  code-verified statement of exactly what Rampart does — every runtime class by evidence tier
  (oracle-proven / single-reproduction / observation / static / indicator), the four LLM probe
  families, the white-box scanners' limits, and an explicit "not covered" section — so no reader
  can infer more than is implemented.
- **JS / single-page-app route discovery.** With `--browser`, Rampart now renders the target with
  the optional headless engine and discovers routes and API calls from the post-JS DOM and the
  page's `fetch`/XHR traffic, feeding them into the application model so the oracles test endpoints
  a static GET-only crawl never sees. Scope-gated by the same admission predicate — out-of-scope
  links/requests are never collected or sent.
- **Outbound findings notifications** ([docs/NOTIFICATIONS.md](docs/NOTIFICATIONS.md)): post
  *confirmed* findings to a signed generic webhook (`X-Rampart-Signature: sha256=…`, HMAC over the
  raw body) and/or a Slack incoming webhook. Opt-in (`--notify-webhook` / `--notify-slack` + env),
  idempotent (never re-notifies a finding), secret-safe, and failure-safe (a sink error never
  breaks a scan). A Jira/Linear sink is a drop-in subclass.
- **Multi-app benchmark program.** `benchmarks/corpus_runner.py` now reports per-class
  precision/recall/F1, a **coverage manifest** (`tested+confirmed` / `tested+missed` / `not-tested`
  — so "no findings" is never read as "fully tested"), variance across `--runs` with a determinism
  flag, and inconclusive/error signals; ships Juice Shop fixtures alongside VAmPI.
- **MCP parity:** the `rampart_scan` tool now exposes the deeper read-only stages the CLI offers
  (`deep`, `authz`, `bizlogic`, `api_scan`, `exploit`, `oob`, `active`) — every new field optional
  and still fully subject to the policy pipeline (`active` writes still require policy approval).

### Fixed
- **Evidence blobs hash to their own names on Windows.** The evidence store wrote in text mode, so
  every LF became CRLF on disk and an external `sha256sum` of a blob no longer matched its
  content-addressed file name. Blobs are now written and read byte-exact (`newline=""`).
- **Source correlation needs evidence, not just a shared CWE.** A runtime finding was linked to the
  first SAST hit with the same CWE anywhere in the repo, so a confirmed command injection on
  `/api/ping` could point at an unrelated line (and SARIF reported that location). A sink is now
  linked only when its code ties it to the endpoint (the route literal in its file, or the
  endpoint's parameter or path name in the enclosing function); the best-evidenced sink wins and
  the reason is recorded. With no evidence the finding stays uncorrelated.
- **Reproduction steps are the requests the oracle actually sent.** Confirmed findings used to
  carry generic steps ("Send GET /api/me with a crafted '' value … see proof below"). The
  validator now rewrites them from the recorded evidence: the exact probe, the benign control,
  the reproduction count and the evidence references. Parameter-less classes (JWT, BFLA, Host
  header, mass assignment, GraphQL) get an accurate description before validation too.
- **`retest` re-checks misconfiguration and exposed-file findings.** They have no replayable
  hypothesis, so they were reported "not retestable". `retest` now runs the built-in header,
  misconfiguration and sensitive-file checks once more and marks each finding `Fixed`,
  `still-vulnerable`, `Regression` or `inconclusive` (target down or unhealthy).
- **"Endpoints tested" counts endpoints.** The report tile and SDK metric counted hypotheses (the
  demo showed `79/22`); they now count distinct endpoints, including for reports regenerated from
  an older run. An LLM scan counts its one chat endpoint, not its probes.
- **`python scripts/demo.py --llm` works without PyYAML.** The demo wrote its scope as a multi-line
  flow mapping, which the strict built-in parser refuses, so the LLM demo crashed on a plain
  `pip install -e .`. The scope is now block-style YAML.
- **CLI output.** Multi-line refusals (an expired or invalid scope) keep their line breaks; `init`
  aligns its labels (`authorized by:` had no space); `features` columns line up on a colour
  terminal; the summary's source-code count is labelled `SAST/secrets` so it no longer reads as a
  contradiction of the static-exposure total; white-box runs say the audit chain is not
  applicable instead of a warning-coloured "no events"; and a run that tested nothing no longer
  claims "every candidate was dropped".
- **The weekly VAmPI corpus benchmark tests VAmPI.** It ran with no spec, accounts or seed, and a
  crawl of VAmPI's JSON root finds no links, so Rampart mapped 0 endpoints and scored recall 0.
  `benchmarks/vampi_setup.py` now populates VAmPI's database, creates a known book per test
  account, and saves the live spec and the account secrets; the scope seeds VAmPI's `name1` /
  `name2` users and excludes `/createdb` (a GET that drops the database mid-scan); and
  `corpus_runner.py` takes `--login-path` / `--token-path`. The ground truth's BOLA moves to
  `/books/v1/{book_title}`, where VAmPI documents it. Result: BOLA and excessive data exposure
  confirmed, mass assignment tested but missed (VAmPI's register response does not echo the
  injected field, so the canary oracle cannot prove it): recall 0.67.
- **SARIF is accepted by GitHub code scanning.** A runtime finding put its endpoint URL
  (`http://host/path`) — or, for infra/TLS findings, a bare `host:443`, which parses as scheme
  `host` — straight into `artifactLocation.uri`, and code scanning rejects the *whole* upload when
  any location is an absolute URI whose scheme isn't the checkout's (`SARIF URI scheme "http" did
  not match the checkout URI scheme "file"`). Every result now has exactly one relative,
  scheme-less location: the repo file for a source-mapped finding, otherwise a percent-encoded
  virtual path (`127.0.0.1%3A8080/api/users`, displayed as `127.0.0.1:8080/api/users`) that can't
  climb out of the repo root, with the exact URL kept as a logical location and a stable
  `primaryLocationLineHash` so alerts track across scans. Verified against GitHub's SARIF
  processor; the test that asserted the old behaviour now asserts code scanning's constraints.
- **Scope contract: an integer field with a control character now refuses cleanly.** Found by the
  new fuzzer on its first CI run: `\s` in the integer guard accepts `\x1c`–`\x1f` but `int()`
  doesn't, so e.g. `max_total_requests: 5000\x1f` escaped as a bare `ValueError` — a traceback
  from the CLI and MCP server instead of the fail-closed `ScopeError` refusal (nothing ran either
  way). The input is now part of the fuzz seed corpus.
- **SCA: hash-locked requirements are pinned — and CVE-matched.** In a pip-compile / `uv
  --generate-hashes` lock, the `--hash=` options follow the specifier, which failed the exact-pin
  match: every such dependency was reported as *unpinned* and, worse, never matched against OSV, so
  a vulnerable package in a hash-locked file was silently missed. Only lines with an environment
  marker survived (the marker split also dropped the hashes). pip's per-requirement options
  (`--hash`, `--config-settings`/`-C`, `--global-option`) are now stripped before parsing. Found by
  running Rampart's own white-box scan on this repository: 47 of its 80 locked packages were
  affected.
- **Content-proof oracles for CMDI, SSRF, path traversal, and BFLA** — they now prove the flaw from
  real response content instead of a marker the bundled demo emits, removing both false positives
  (a reflecting endpoint wrongly confirmed) and false negatives (a real app missed for lacking the
  demo's magic string). CMDI injects `; echo $((A*B))` with a fresh random product each round and
  requires that computed product (which the payload never contains literally) in the response and
  absent from a benign control; SSRF matches cloud-metadata/IMDS content (`AccessKeyId`, `iam-role`,
  `computeMetadata`, …); path traversal matches a real `/etc/passwd` root line or a Windows
  `boot.ini`/`win.ini` banner; BFLA confirms structurally — a low-privilege principal gets a 200
  privileged aggregate while an unauthenticated request is rejected. With the CMDI oracle now
  requiring computed proof, `CMDI` is re-enabled as a `--deep` escalation target (it could not
  previously be one without amplifying input-reflection into false findings).
- **Fail closed when a configured Postgres store is unreachable.** A `postgres://`/`postgresql://`
  `--store` URL with no `psycopg` driver (or a failed connection) used to silently fall back to a
  local SQLite file, so evidence landed somewhere other than configured. It now aborts with a clear
  error (exit 2); an explicit `?on_error=sqlite-fallback` opts into the old behaviour, loudly, and
  the fallback is recorded in `scan.json` (`store_warnings`).
- **Sensitive-file check no longer fires on soft-404 pages.** A catch-all page that returns 200
  with signature-matching content for every path is now caught by a non-existent-sibling negative
  control and dropped, instead of being reported as an exposed file.

### Changed
- **New logo and README hero.** The logo is a crenellated rampart-shield with a terminal prompt
  and a "proven"-green cursor. The README opens on a terminal window showing the unedited output of
  `rampart test --repo . --deep` against the demo app, scrolled to the results (22 confirmed, 66
  dropped by the false-positive gate). It is rendered from a captured run by
  `scripts/render_terminal_svg.py`, which keeps the CLI's own colours and wraps lines the way a
  terminal does, so the image can be regenerated whenever the output changes. The rows print in
  one at a time behind a block cursor and the final frame stays (static for
  `prefers-reduced-motion`). The HTML-report
  screenshot moved to "Reports and compliance".
- **README badges no longer depend on shields.io.** GitHub loads README images through its camo
  proxy, which gives up after ~4s, and shields' badges were regularly slower than that — the
  Scorecard and Release badges rendered broken (so did the same badges on far busier repos). The
  live ones (Scorecard score, latest release) are now rendered by `scripts/render_badges.py` in a
  `Badges` workflow after every Scorecard run and release, published to a `badges` branch, and
  served from raw.githubusercontent.com, which GitHub doesn't proxy; the fixed-text ones are
  committed SVGs.
- **The demo's insecure-by-design IaC fixtures moved to `examples/demo_target/testdata/iac/`.**
  `testdata/` is where tools such as OpenSSF Scorecard expect test input, so the deliberately
  unpinned fixture Dockerfile is no longer reported as an unpinned dependency of this repository.
- **Corrected documentation overclaims** flagged by a competitive review, so the docs match the
  implementation exactly: the LLM testing is described as **4 of the OWASP LLM Top 10 categories**
  (LLM01/05/07/02), not all ten; the "every class has a negative control and 2+ reproductions"
  claim now spells out the honest exceptions (OOB/gRPC single reproduction; misconfiguration /
  sensitive-file single authoritative observation); and "one choke-point" is restated as **one
  admission contract enforced at every egress point** (the HTTP policy pipeline, plus a shared
  admission guard for the browser/gRPC/infra engines that open their own connections).

### Security
- **Scope glob matching can no longer be made to hang (ReDoS).** Path globs (`paths_include` /
  `paths_exclude`) and host globs (`hosts_exclude`) were compiled to `.*` / `[^/]*` regexes, which
  backtrack exponentially on wildcard-heavy patterns — while the path or host being matched comes
  from the target (the crawler matched raw crawled paths). `/**/**/**/**/x` against an 800-character
  path, or `*a*a*a*a*a*a*a*a*b` against a long host, ran for seconds to minutes. Globs are now
  matched in linear time by tracking reachable positions; a differential test pins the exact
  regex semantics (450k randomized cases, including case-folding and newline edge cases, agree).
  Found by the scope-contract fuzzer; the input joins the seed corpus.
- **Hash-pinned build and CI supply chain.** Every `pip install` in CI, the release, the Docker
  image, and the composite action now installs from hash-locked files (`requirements/*.txt`,
  `--require-hashes`, compiled from `requirements/*.in` with `make lock`) or installs Rampart
  itself with `--no-deps`; builds run without isolation so the pinned setuptools is the backend
  actually used. Docker base images are pinned by multi-arch digest. `requirements-dev.txt` is now
  a hash-pinned lock, which also moves the dev toolchain off `filelock` < 3.20.3 (CVE-2025-68146,
  CVE-2026-22701) and `pygments` < 2.20.0.
- **Continuous fuzzing.** A new CI job runs coverage-guided Atheris fuzzers (`fuzz/`) against the
  scope-contract parser and gate matchers (must fail closed on any input) and the SARIF location
  builder (must stay a relative, scheme-less uri-reference).

## [1.2.0] — 2026-10-09

This release comes out of a full end-to-end review: seven parallel reviewers tested every
surface against live targets and reproduced each issue before it was fixed. Every fix has a
regression test (the suite grew from 197 to 661 tests).

### Security
- **Scope enforcement now covers every path out.** The target's port and scheme are checked at
  startup (previously only the host was). Test-account logins, the headless browser, the
  infrastructure scan, and gRPC now go through the same scope checks and audit log as every other
  request, instead of touching ports and origins the contract didn't authorize.
- `--infra` only probes ports the scope authorizes for the host (it used to connect to ~22
  well-known ports regardless of scope).
- The headless browser blocks sub-resources, redirects, and navigations outside the authorized
  origin and excluded paths, and every browser request is audited.
- `paths_exclude` can no longer be bypassed with encoded or non-canonical paths (`%61dmin`, `//`,
  `/./`, `..`, `;params`, case changes, trailing slashes).
- The built-in YAML parser fails closed on anything it doesn't fully understand (tabs, anchors,
  block scalars, trailing junk). Previously several of these silently dropped scope exclusions.
  Scope fields are strictly typed.
- `tier2_requires_approval` is always honoured, even when `default_tier_ceiling` is 2.
- The destructive-action classifier now inspects query keys, headers, and decoded bodies, and
  normalises SQL comments, so `DROP/**/TABLE`-style evasions are caught.
- Budgets are enforced: `budget_usd` and `max_tokens` cap LLM spend, a `KILL` file in the work
  dir (or Ctrl-C) stops a run, and a low rate limit now throttles instead of silently skipping.
- Audit logs are anchored, so truncation and deleted events are detected; corrupt logs no longer
  crash `verify-audit`.
- The local dashboard rejects cross-site requests (CSRF token) and foreign `Host` headers
  (DNS rebinding), and sends strict security headers.
- Reports (Markdown, compliance, SOC 2), PR comments, and console output escape
  target-controlled text, so a hostile target can't inject HTML, mentions, or terminal escapes.
- The PR-comment poster only edits its own comment.
- The GitHub Action and workflows pass inputs through environment variables (no shell
  injection), and every action is pinned to a commit SHA.
- Hard IP blocking covers IPv4-mapped/NAT64 forms of cloud metadata addresses and more providers.

### Fixed
- **Results you can trust:** a target that is down, or a scan where every request was blocked,
  now ends `incomplete` with exit code 2, even with `--ci`. It used to pass the gate.
- Boolean SQL injection no longer confirms on responses that merely change over time.
- HTTPS targets with a hostname work (TLS used the IP for SNI and certificate checks).
- Requests have a wall-clock deadline and a response size cap; stored evidence is capped.
- DOM-based XSS through `innerHTML` is detected, and reflected XSS is no longer double-counted.
- GraphQL batching, gRPC read-method detection, and authz template paths no longer produce
  false findings.
- SAST: precise sink matching (82 → 18 findings on Rampart's own code, all explained), import
  aliases, UTF-8 BOM / latin-1 files, and no crash on deeply nested expressions.
- Secrets: catches `SECRET_KEY`, `DB_PASSWORD`, `client_secret`, unquoted `.env` values; skips
  binaries.
- SCA: never recommends a downgrade; KEV/EPSS look at every advisory; PyPI names are normalised;
  route handlers count as reachable; more manifest formats; OSV batch queries (no 400-package cap).
- IaC: fewer false positives (egress rules, comments, non-CloudFormation YAML) and new checks
  (multi-line CIDRs, CronJobs, final-stage `USER root`, untagged base images).
- `llm-test`: an endpoint that echoes its input, returns errors, or can't be parsed is no longer
  reported as a pass or a vulnerability; outcomes are `confirmed`, `not-vulnerable`, `blocked`,
  `error`, `inconclusive`, or `skipped`. OWASP 2025 labels corrected (system-prompt leak is LLM07).
- MCP server: JSON-RPC notifications never trigger tools, `ping` is supported, arguments are
  validated against each tool's schema, UTF-8 and LF framing on Windows.
- `retest` replays every class with an oracle (not just IDOR), never marks a finding fixed when
  the target is unhealthy, and no longer needs `--target`.
- Findings marked Fixed by retest no longer count as confirmed anywhere.
- `--config` precedence (CLI flags now win), unknown report formats, severities, and malformed
  inputs give clear errors instead of tracebacks.
- SARIF: repo-relative file locations (`%SRCROOT%`), valid regions, and rule descriptions.
- The weekly VAmPI corpus workflow, the GitLab template, and docker-compose (dashboard on
  loopback only) work as documented.

### Changed
- `rampart pipeline` and the SDK's full mode **no longer enable write probes** by default; pass
  `--active` explicitly.
- `rampart test --repo X` runs SAST, secrets, and SCA (and IaC with `--iac`), as documented.
- `sast`, `sca`, and `iac` never contact a target and no longer require `--target`.
- New flags: `--fail-on-static`, `--oob-collaborator-url`; `llm-test` gains `--ci`/`--fail-on`.
- A scope without `test_accounts` no longer needs a `secrets.json`.
- Release artifacts include an SPDX SBOM and signed attestations; releases are immutable.
- Added CodeQL and OpenSSF Scorecard; CODEOWNERS and branch protection on `main`.

### Known issues
- The OS command injection oracle can confirm an endpoint that echoes its input back.
- The sensitive-file check can be fooled by "soft 404" pages that return 200 for every path.
- The path traversal, SSRF, and BFLA oracles recognise response signatures produced by the
  bundled demo, so they can miss these flaws on other applications.

## [1.1.0] — 2026-10-09

### Added
- **Release pipeline** (`.github/workflows/release.yml`): pushing a `vX.Y.Z` tag builds and
  smoke-tests the wheel + sdist, attaches them to a GitHub Release with `SHA256SUMS` and signed
  build-provenance attestations, publishes a multi-arch Docker image to
  `ghcr.io/nitinreddy-a/rampart`, moves the floating `v1` tag for the GitHub Action, and (once
  enabled) publishes to PyPI via trusted publishing.
- CI now builds and smoke-tests the Docker image on every push. Dependabot keeps actions, pip
  tooling, and the base image current.
- **Python SDK** (`from rampart import Rampart`): `Rampart(...).scan()` returns a `ScanResult` with
  `.confirmed`, `.failed(on=...)`, `by_severity()`, and in-memory report renderers. A thin wrapper
  over the `Engagement` facade, so it produces identical results to the CLI. See `docs/SDK.md`.
- **PR-comment reporter** (`rampart pr-comment`) and a GitHub poster that keeps one sticky comment
  per pull request. Wired into the composite Action via a `comment-pr` input.
- `docs/SDK.md` and `docs/MCP.md`.

### Changed
- Renamed the authorization/scope contract from `SECURITY.md` to `rampart.scope.yaml`, freeing
  `SECURITY.md` for the standard GitHub vulnerability-disclosure policy.
- Productized the repository for open-source contribution: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`,
  issue/PR templates, `CHANGELOG.md`, `NOTICE`, ruff lint/format config, pre-commit, and an
  `ARCHITECTURE.md`. Rewrote the README around a clear getting-started and LLM-integration flow.
- Rewrote the README again around every way to use Rampart (CLI, SDK, GitHub Action, GitLab CI,
  Docker, MCP, dashboard), with a real report preview, an architecture diagram, and an FAQ.
- Install instructions and CI templates now point at versioned GitHub releases.
- Packaging uses an SPDX license expression (`license = "Apache-2.0"`), ahead of setuptools
  dropping the table form.

### Fixed
- CI lint failure: ruff is now pinned to one version (0.16.10) in CI, the `dev` extra, and
  pre-commit, so a new ruff release can't silently change formatting rules.

## [1.0.0] — 2026-10-08

### Added
- **Call-graph reachability** for SCA: a static Python call graph decides whether a vulnerable
  dependency's symbol is actually reachable from an entrypoint (`function-reachable` … `unreachable`).
- **Per-RPC gRPC**: method enumeration, plaintext-transport detection, and (under `--active`,
  read-ish methods only) unauthenticated-method-invocation confirmation.
- **Eight-framework compliance mapping** (`--report compliance`): SOC 2, ISO 27001:2022, PCI DSS
  v4.0, NIST 800-53 Rev5 (FedRAMP), HIPAA, GDPR, OWASP ASVS, CIS Controls v8.
- **SCA exploit intelligence**: EPSS + CISA KEV + reachability folded into an adjusted P0–P3 priority.
- **Live infrastructure scan** (`--infra`), **deep auth** (`--authz`, weak JWT secret),
  **deterministic business logic** (`--bizlogic`, economic/parameter tampering), and
  **API depth** (`--api-scan`, HTTP verb tampering + GraphQL depth).

## [0.9.0] — 2026-10-08

### Added
- **Graph orchestrator**: a DAG scheduled across a bounded thread pool, with runtime subagent
  spawning, so independent hypotheses are tested and validated in parallel (`--parallel N`).
- **Full SCA** against OSV.dev with concrete upgrade remediation; **IaC** scanning (Terraform /
  CloudFormation / Kubernetes / Dockerfile); **gRPC** server-reflection exposure.

### Changed
- Thread-safety for parallel runs (session manager, evidence store); parallel runs produce
  byte-identical findings to sequential ones.

## [0.8.0] — 2026-10-08

### Added
- Blind XXE over the OOB collaborator, stored-XSS write-half via the headless browser, a passive
  request-smuggling indicator, a multi-tenant SQL store, diff-aware SAST (`--since`), and an
  external-corpus benchmark runner.

## [0.6.0 – 0.7.0] — 2026-10-08

### Added
- Product scan modes (`recon` / `dast` / `api` / `sast` / `sca` / `agents` / `pipeline`).
- White-box **SAST/SCA** with SAST↔DAST correlation; a hardened multi-agent reasoning harness;
  host-header injection, mass assignment, GraphQL, and partial CSRF classes.

## [0.4.0] — 2026-10-08

### Added
- Multi-step **live exploitation** (bounded, non-destructive proof of impact), five more oracle
  classes (SSTI, JWT alg=none, sensitive-file exposure, clickjacking, insecure cookies), and a
  **SOC 2 evidence** report.

## [0.3.0] — 2026-10-07

### Added
- Recon crawler, attack-chain correlation with a risk score, and product surfaces: the one-shot
  `pipeline`, a zero-dependency web dashboard (`serve`), and an MCP server (`mcp`).

## [0.2.0] — 2026-10-06

### Added
- Expanded from the single BOLA/IDOR slice to multiple web/API classes plus the OWASP LLM Top 10,
  each behind an independent oracle, with external OSS scanner adapters.

## [0.1.0] — 2026-10-01

### Added
- First release: the BOLA/IDOR vertical slice carried end-to-end — scope gate → app model →
  hypothesis → controlled probe → independent validation → finding → advisory patch → retest.

[Unreleased]: https://github.com/NitinReddy-A/Rampart/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/NitinReddy-A/Rampart/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/NitinReddy-A/Rampart/releases/tag/v1.1.0
