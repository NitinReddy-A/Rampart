<div align="center">

<img src="docs/assets/rampart-mark.svg" alt="Rampart" width="96" />

# Rampart

### Find it. Prove it. Fix it.

The open-source, self-hosted security agent for web apps, APIs, and LLM endpoints.<br />
It reports only the vulnerabilities it can **prove**, each with the evidence to reproduce it.

[![Website](docs/assets/badges/website.svg)](https://rampart.dpdns.org)
[![CI](https://github.com/NitinReddy-A/Rampart/actions/workflows/ci.yml/badge.svg)](https://github.com/NitinReddy-A/Rampart/actions/workflows/ci.yml)
[![CodeQL](https://github.com/NitinReddy-A/Rampart/actions/workflows/codeql.yml/badge.svg)](https://github.com/NitinReddy-A/Rampart/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://raw.githubusercontent.com/NitinReddy-A/Rampart/badges/scorecard.svg)](https://scorecard.dev/viewer/?uri=github.com/NitinReddy-A/Rampart)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15386/badge)](https://www.bestpractices.dev/projects/15386)
[![Release](https://raw.githubusercontent.com/NitinReddy-A/Rampart/badges/release.svg)](https://github.com/NitinReddy-A/Rampart/releases/latest)
[![Python](docs/assets/badges/python.svg)](pyproject.toml)
[![Runtime deps](docs/assets/badges/runtime-deps.svg)](pyproject.toml)
[![Benchmark](docs/assets/badges/benchmark.svg)](#benchmark)
[![License](docs/assets/badges/license.svg)](LICENSE)

**[Website](https://rampart.dpdns.org)** ·
**[Try it in 60 seconds](#try-it-in-60-seconds)** ·
[How it works](#how-it-works) ·
[What it tests](#what-it-tests) ·
[Scan your app](#scan-your-own-app) ·
[Use it anywhere](#use-it-anywhere) ·
[FAQ](#faq) ·
[Docs](#documentation)

<img src="docs/assets/rampart-console.svg" alt="Terminal output of rampart test against the bundled demo app, scrolled to the results: 22 findings confirmed with reproducible proof, each candidate the independent validator could not reproduce listed as dropped (66 in all), then the confirmed CRITICAL and HIGH findings" width="900" />

<sub>Unedited output of <code>rampart test --repo . --deep</code> against the bundled demo app, scrolled to the results. <code>--deep</code> is on <code>main</code> and not yet in the v1.2.0 release.</sub>

</div>

<br />

<table>
<tr>
<td width="33%" valign="top">

### 🔬 It proves, then reports

A hit is only a *candidate*. An independent oracle re-proves it from a clean state, with a negative control and two reproductions, before it becomes a finding. The oracle is deterministic code, never an LLM.

</td>
<td width="33%" valign="top">

### 🗑️ It shows what it threw away

Candidates the oracle couldn't reproduce are dropped **and listed**, so you can see the noise Rampart filtered out instead of trusting that it did.

</td>
<td width="33%" valign="top">

### 🧱 It stays inside the lines

No valid, unexpired scope contract, no request. Every request crosses one admission gate, and every action lands in a tamper-evident audit log.

</td>
</tr>
</table>

Runs on your machine or in your CI · **zero runtime dependencies** (pure standard-library Python) · **no LLM required**: free, offline and deterministic by default.

> [!IMPORTANT]
> Rampart is for **authorized testing only**: assets you own or have written permission to test.
> It enforces this. It won't send a single request without a valid, unexpired scope contract that
> covers the target.

## Try it in 60 seconds

Rampart ships an intentionally vulnerable demo app. Everything runs on `127.0.0.1`, and nothing
touches the internet.

```bash
git clone https://github.com/NitinReddy-A/Rampart.git
cd Rampart
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
python scripts/demo.py
```

The demo starts the target, runs a full assessment, and opens an HTML report:

```text
    [CRITICAL] OS command injection via 'host' on GET /api/ping  (CONFIRMED)
    [CRITICAL] JWT accepted without signature verification (alg=none) on GET /api/me  (CONFIRMED)
    [  HIGH] SQL injection in 'id' on GET /api/products  (CONFIRMED)
    [  HIGH] Broken function-level authorization on GET /api/reports/orders  (CONFIRMED)
    [  HIGH] SQL injection in 'q' on GET /api/search  (Dropped)
    [MEDIUM] Reflected cross-site scripting (XSS) in 'id' on GET /api/products  (Dropped)
    ...
  audit chain: intact · 476 events · cost $0.0
```

**22 confirmed findings, 45 candidates dropped, 7 multi-step attack chains.** The **Dropped** rows
are the point: broad enumeration also guessed SQLi on `q` and XSS on `id`, the oracle couldn't
reproduce them, so they're discarded. Run `python scripts/demo.py --fixed` against the patched
build and Rampart confirms nothing at all.

## Why Rampart

Application security usually forces a bad trade. Scanners are cheap and self-hosted but bury you in
unvalidated "possible" issues. Hosted AI-pentest services prove what they find, but your code and
targets go to a vendor. Rampart takes the third path.

| | Typical scanner | Hosted "AI pentest" service | **Rampart** |
| --- | :---: | :---: | :---: |
| Every finding re-proved by an independent oracle | ✗ | varies | **✓** |
| False positives shown, not just hidden | ✗ | ✗ | **✓** |
| Runs fully on your infrastructure | ✓ | ✗ | **✓** |
| Works with no LLM (free, offline, reproducible) | ✓ | ✗ | **✓** |
| Optional LLM reasoning (Claude Code, OpenAI-compatible, Ollama) | ✗ | ✓ | **✓** |
| Hard scope enforcement on every request | partial | varies | **✓** |
| Tamper-evident audit log of everything it did | ✗ | varies | **✓** |
| Findings mapped to 8 compliance frameworks | rarely | varies | **✓** |
| Open source, Apache-2.0 | some | ✗ | **✓** |

**Built for**

| | |
| --- | --- |
| **Developers** | a security gate in CI that doesn't cry wolf |
| **AppSec teams** | evidence, not a 400-row spreadsheet of "possible" issues |
| **Pentesters** | the repetitive 80% automated and audited, so you can spend time on the hard 20% |
| **Audit prep** | control evidence for SOC 2, ISO 27001, PCI DSS and five more frameworks, mapped to findings |

## How it works

Scope goes in; a proven report comes out. Each stage is gated, and only the **prove** stage may mark
a finding confirmed.

<div align="center">
<img src="docs/assets/iso-flow.svg" alt="Isometric view of the scan: a scope block, then the app model, then the one amber admission gate every request crosses, then the prove stage (an unproven candidate is dropped, a reproved one is confirmed), then the report" width="880" />
</div>

| | Stage | What happens |
| :---: | --- | --- |
| **1** | **Scope** | A short YAML contract says who owns the target, who authorized the test, what's in scope, and when the permission expires. No valid contract, no run. |
| **2** | **Map** | Rampart builds a model of the app: endpoints and parameters from crawling, an OpenAPI spec, a headless browser, test accounts, and object ownership. |
| **3** | **Hypothesize** | For every endpoint and parameter it proposes the attack classes that could apply. Deterministic rules by default; an LLM may suggest more. |
| **4** | **Prove** | Each candidate goes to an independent oracle: the probe, a benign negative control, and the same signal reproduced twice from a clean state. Otherwise it's dropped. |
| **5** | **Report** | Confirmed findings with CWE, CVSS 4.0 and compliance mappings, the exact requests that prove them, attack chains, and an advisory patch, never applied for you. |

<details>
<summary><b>The exact flow, with every fail-closed edge</b></summary>

<br />

```mermaid
flowchart TD
    S([rampart.scope.yaml]):::doc --> G{Authorization gate}:::gate
    G -- invalid / out of scope --> X([Refuse to run]):::stop
    G -- valid --> M[Build the app model]:::step
    M --> H[Generate hypotheses]:::step
    H --> P{{Policy pipeline}}:::choke
    P -- denied --> B([Blocked &amp; audited]):::stop
    P -- allowed --> T[(Your target)]:::target
    T --> O{Independent oracle}:::gate
    O -- re-proven --> C([Confirmed finding]):::good
    O -- not re-proven --> D([Dropped]):::drop
    C -->|"with --deep"| H
    C --> R[Correlate, score, report]:::step

    classDef doc stroke:#94a3b8,stroke-width:1.5px
    classDef step stroke:#3b82f6,stroke-width:1.5px
    classDef gate stroke:#eab308,stroke-width:2px
    classDef choke stroke:#ef4444,stroke-width:3px
    classDef target stroke:#38bdf8,stroke-width:2px
    classDef good stroke:#22c55e,stroke-width:2px
    classDef drop stroke:#78716c,stroke-width:1.5px,stroke-dasharray:5 3
    classDef stop stroke:#ef4444,stroke-width:1.5px,stroke-dasharray:5 3
```

<sub>Amber diamonds are decision gates · the red hexagon is the **one admission choke-point** every
request passes (scope · resolved-IP · risk tier · budget · audit) · dashed red = fail-closed ·
green = oracle-proven · the `--deep` arrow is finding-driven escalation. Full detail:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).</sub>

</details>

Two rules make the results trustworthy:

1. **One admission contract, enforced at every egress point.** Every HTTP probe goes through one
   choke-point, the policy pipeline (`rampart/policy/pipeline.py`): scope, resolved-IP allowlist,
   risk tier, policy, and budget are checked on each request, fail-closed. The engines that open
   their own connections (headless browser, gRPC, infra) check the same scope and resolved-IP
   allowlist themselves and go through a shared admission guard (`rampart/infra/sidechannel.py`)
   with the same budget, kill switch, and audit. No agent, scanner, or LLM output can route around
   it; a prompt-injected model can at most propose requests the policy engine rejects.
2. **Nothing is "confirmed" without independent proof.** The oracle that confirms a finding is
   deterministic code, never an LLM, and it re-derives the result from scratch with a negative
   control. LLM-reasoned issues that can't be proven are labelled `agent-assessed`.

<details>
<summary><b>Architecture at a glance</b></summary>

<br />

Every way of running Rampart (CLI, Python SDK, MCP server, GitHub Action) enters through **one
engagement** and produces identical results, and every layer rests on a **safety core** that no
scanner, agent, or model output can route around.

<div align="center">
<img src="docs/assets/iso-layers.svg" alt="Isometric stack of Rampart's layers: surfaces on top, then the engagement facade, discover and confirm, the checks, reason and report, all resting on the safety core at the bottom, with every request passing down into that core" width="560" />
</div>

Full map: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

</details>

## What it tests

Most runtime classes have an independent oracle (a probe, a negative control, and 2+ reproductions
from a clean state) before anything is called *confirmed*. Two honest exceptions: out-of-band blind
SSRF/XXE and gRPC server reflection confirm on one reproduction plus a negative control, and the
misconfiguration, security-header, and sensitive-file checks are single observations re-checked on a
second request. Every class's evidence tier is in [docs/COVERAGE.md](docs/COVERAGE.md). The built-in
checks need no external tools.

| Area | Checks | Turn on with |
| --- | --- | --- |
| **Web & API** | IDOR/BOLA, broken function-level authz, SQL injection, XSS, SSTI, SSRF, OS command injection, path traversal, open redirect, host-header injection, JWT `alg=none`, excessive data exposure, mass assignment, GraphQL introspection | default (`--active` for write probes) |
| **Misconfiguration** | security headers, permissive CORS, cookie flags, clickjacking, exposed files (`.env`, `.git`, backups), version disclosure | default |
| **Deep auth** | weak JWT signing secrets, expiry not enforced | `--authz` |
| **API depth** | HTTP verb tampering, GraphQL depth abuse | `--api-scan` |
| **Business logic** | price, quantity, and parameter tampering | `--bizlogic` |
| **Blind bugs** | blind SSRF and XXE via a self-hosted out-of-band collaborator | `--oob` |
| **Browser** | JS/SPA route discovery (DOM + fetch/XHR), DOM and stored XSS in real headless Chromium | `--browser` |
| **gRPC** | reflection exposure, plaintext transport, unauthenticated RPCs | `--grpc` |
| **Infrastructure** | exposed services on in-scope hosts | `--infra` |
| **Source code** | Python AST source scanner, hard-coded secrets | `--repo` |
| **Infrastructure as code** | Terraform, CloudFormation, Kubernetes, Dockerfile | `--iac` |
| **Dependencies (SCA)** | OSV.dev matches, ranked by EPSS, CISA KEV, and call-graph reachability | `--sca-online` |
| **LLM apps** | OWASP LLM Top 10 probes for 4 of the risk categories: LLM01 prompt injection + jailbreak, LLM05 improper output handling, LLM07/LLM02 system-prompt and sensitive-info leakage | `rampart llm-test` |
| **External tools** | Nuclei, Nmap, Semgrep, Trivy, testssl.sh, imported as *unvalidated leads* | `--scanners` |

Run `rampart features` for every capability and how to run it, and `rampart tools` to see which
external scanners are installed.

## Install

Every method runs the same engine. Requires **Python 3.10+**.

| Method | Command |
| --- | --- |
| **pipx** (recommended for the CLI) | `pipx install https://github.com/NitinReddy-A/Rampart/releases/download/v1.2.0/rampart_appsec-1.2.0-py3-none-any.whl` |
| **pip** (CLI + Python SDK) | `pip install https://github.com/NitinReddy-A/Rampart/releases/download/v1.2.0/rampart_appsec-1.2.0-py3-none-any.whl` |
| **Docker** | `docker pull ghcr.io/nitinreddy-a/rampart:1.2.0` |
| **From source** | `git clone https://github.com/NitinReddy-A/Rampart.git && pip install -e ".[dev]"` |

The release wheel URL needs no git and works in slim CI images. Every release is on the
[Releases](https://github.com/NitinReddy-A/Rampart/releases/latest) page.

<details>
<summary><b>Optional extras</b></summary>

<br />

Extras add features but never change the core:

```bash
pip install "rampart-appsec[browser] @ https://github.com/NitinReddy-A/Rampart/releases/download/v1.2.0/rampart_appsec-1.2.0-py3-none-any.whl"
python -m playwright install chromium    # DOM / stored XSS in a real headless browser
```

| Extra | Adds |
| --- | --- |
| `yaml` | PyYAML for scope parsing (a strict built-in parser is used otherwise) |
| `browser` | Playwright for DOM and stored XSS |
| `grpc` | gRPC reflection and per-RPC checks |
| `all` | everything above |

</details>

<details>
<summary><b>Verifying a release</b></summary>

<br />

Every release is built by this repository's [release workflow](.github/workflows/release.yml), not
on anyone's laptop, and published as an [immutable release](https://docs.github.com/repositories/releasing-projects-on-github/about-releases)
(its files and tag can never be changed afterwards). Each one ships the wheel, the sdist,
`SHA256SUMS`, an SPDX SBOM, and [Sigstore](https://www.sigstore.dev/)-signed build-provenance
attestations for both the Python packages and the Docker image:

```bash
gh release download v1.2.0 --repo NitinReddy-A/Rampart
sha256sum -c SHA256SUMS
gh attestation verify rampart_appsec-1.2.0-py3-none-any.whl --repo NitinReddy-A/Rampart
gh attestation verify oci://ghcr.io/nitinreddy-a/rampart:1.2.0 --repo NitinReddy-A/Rampart
```

</details>

## Scan your own app

Three steps: describe what you're allowed to test, check it, scan.

**1 · Write the scope contract.** Copy the example and fill it in:

```bash
curl -fsSLo rampart.scope.yaml \
  https://raw.githubusercontent.com/NitinReddy-A/Rampart/main/rampart.scope.example.yaml
```

```yaml
apiVersion: security-agent/v1
kind: EngagementScope
authorization:
  owner: "team-payments@acme.example"       # who is accountable
  authorized_by: "ciso@acme.example"         # who granted permission
  attestation: "Acme owns staging.acme.internal and authorizes this test."
  expires: "2026-12-31T23:59:59Z"            # the contract expires, and Rampart stops
scope:
  in_scope:
    - host: "staging.acme.internal"
      ports: [443]
      paths_include: ["/api/**"]
  resolved_ip_allowlist: ["10.20.0.0/24"]    # checked against the resolved IP on every request
```

**2 · Check it.** This validates the contract without sending anything to the target:

```bash
rampart init --scope-file rampart.scope.yaml
```

**3 · Scan.**

```bash
rampart test \
  --scope-file rampart.scope.yaml \
  --target https://staging.acme.internal \
  --crawl \
  --report html,json,sarif
```

Open `.rampart/reports/report.html`. That's it.

<details>
<summary><b>Give it more context, find more: grey-box and white-box inputs</b></summary>

<br />

Rampart works black-box with just a URL. Give it more and it finds more:

| Add | Flag | What you get |
| --- | --- | --- |
| An OpenAPI spec | `--openapi openapi.json` | every endpoint and parameter, without crawling |
| A single-page app | `--browser` | JS/SPA routes and API calls discovered from the rendered DOM + fetch/XHR, fed to the oracles (static crawling cannot see these) |
| Test accounts | `test_accounts` in the scope file + `--secrets secrets.json` | authenticated testing, IDOR/BOLA across users |
| Object ownership | `--appmodel-seed seed.json` | precise cross-tenant access checks |
| Your source code | `--repo .` | SAST, secrets, SCA, IaC, and runtime↔source correlation |

Test-account credentials are never written in the scope file. It holds a reference
(`secret_ref: "vault://eng/user_a"`), resolved from a local `secrets.json` or your secrets manager.
See [`examples/demo_target`](examples/demo_target) for a complete grey-box setup.

</details>

### Go deeper with `--deep`

Add `--deep` and a *confirmed* finding drives the scan harder, the way an assessor would: the other
injection classes on a parameter proven to be a live sink, and sibling endpoints that return an
object type proven to have a broken ownership check.

```bash
rampart pipeline --target … --scope-file … --deep     # the full, result-driven deep scan
```

- **Proven, never noisier.** Every follow-up is re-proven by the same independent oracle, so
  `--deep` can only add *proven* findings.
- **Can't run away.** The fan-out is deterministic and hard-capped (depth, total, and per-finding),
  with duplicates removed, and the counts admitted and dropped are in the report.
- **Honest on the demo.** Its 21 follow-ups were all re-tested and correctly dropped (the demo's
  other parameters aren't vulnerable), and 27 more were cut by the caps.

> [!NOTE]
> `--deep` is on `main` and not in the v1.2.0 release yet. Until the next release, install from
> source (`pip install -e .` in a clone) or `pipx install git+https://github.com/NitinReddy-A/Rampart.git`.

## Use it anywhere

Every surface goes through the same engine and the same safety checks, so a scan from the CLI, your
code, your CI, or an AI agent produces identical findings. Open the one you need:

<details>
<summary><b>⌨️ CLI</b>: running scans by hand or in a script</summary>

<br />

Run everything with `test`, or one capability on its own:

```bash
rampart test     --target … --scope-file …   # the full assessment (start here)
rampart pipeline --target … --repo .         # everything, correlated across runtime and source
rampart recon    --target …                  # map the attack surface only
rampart dast     --target …                  # black-box web/API checks
rampart api      --target … --openapi …      # API-focused, grey-box
rampart sast     --repo .                    # source + secrets (offline; never contacts a target)
rampart sca      --repo . --sca-online       # dependencies vs OSV.dev, EPSS, CISA KEV
rampart iac      --repo .                    # Terraform, CloudFormation, Kubernetes, Dockerfile
rampart llm-test --target … --chat-path /chat --canary …   # OWASP LLM Top 10 probes (4 categories: LLM01/05/07/02)
rampart retest   --work-dir .rampart         # replay confirmed findings against a patched build
rampart features                             # list every capability and how to run it
```

`sast`, `sca`, and `iac` still require a valid scope contract, but never send a request.

**In CI**, gate the build with `--ci --fail-on high` (confirmed runtime findings) and, optionally,
`--fail-on-static high` (source, dependency, and IaC findings, which are evidence-backed but not
exploit-proven). Exit codes are stable:

| Exit | Meaning |
| :---: | --- |
| `0` | completed; nothing at or above the gate |
| `1` | completed; a finding breached the gate (or `retest` found something still vulnerable) |
| `2` | refused or incomplete: invalid/expired scope, target out of scope, target unreachable, every request blocked, or invalid input |

A scan that couldn't actually test anything always exits `2`, so it can never pass a gate by
accident.

</details>

<details>
<summary><b>🐍 Python SDK</b>: scans inside tests, notebooks, or your own tooling</summary>

<br />

```python
from rampart import Rampart

result = Rampart(
    scope="rampart.scope.yaml",
    target="https://staging.acme.internal",
    openapi="openapi.json",  # or crawl=True; with neither, only the built-in misconfiguration checks run
).scan()

print(result.summary())
# on the bundled demo app (grey-box, with its seed and test accounts):
# "22 confirmed (3 critical, 9 high, 9 medium, 1 low), 45 dropped by the false-positive gate"
for finding in result.confirmed:
    print(finding.severity, finding.title)

result.save(["html", "sarif"])  # or result.to_json(), to_markdown(), to_compliance() …
```

A security gate is one assertion in your test suite:

```python
def test_staging_has_no_high_severity_vulnerabilities():
    result = Rampart(scope="rampart.scope.yaml", target=STAGING_URL, openapi="openapi.json").scan()
    assert not result.failed(on="high"), result.summary()
```

Full API: [docs/SDK.md](docs/SDK.md).

</details>

<details>
<summary><b>✅ GitHub Action</b>: a security gate and a findings comment on every pull request</summary>

<br />

```yaml
# .github/workflows/security.yml
name: Security
on: [pull_request]

permissions:
  contents: read
  pull-requests: write          # only needed for comment-pr

jobs:
  rampart:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      # …deploy or start the app you're testing…

      - uses: NitinReddy-A/Rampart@v1
        with:
          target: https://staging.acme.internal
          scope-file: rampart.scope.yaml
          openapi: openapi.json      # optional; without it the site is crawled
          fail-on: high              # fail the check on a confirmed high or critical
          comment-pr: true           # sticky findings summary on the PR

      - uses: actions/upload-artifact@v6
        if: always()
        with:
          name: rampart-report
          path: .rampart/reports/
```

| Input | Default | Description |
| --- | --- | --- |
| `target` | (required) | Authorized base URL to test |
| `scope-file` | `rampart.scope.yaml` | The authorization contract |
| `openapi` | | OpenAPI spec for grey-box testing |
| `crawl` | `true` | Discover endpoints by crawling |
| `secrets` | | `secrets.json` for the scope's test accounts |
| `fail-on` | `high` | `low` · `medium` · `high` · `critical` |
| `report` | `sarif,html` | Any of `html,md,json,sarif,compliance,soc2` (`json` is always added) |
| `scanners` | | Optional external tools: `nuclei,semgrep,…` or `all` |
| `args` | | Extra `rampart test` flags, e.g. `--authz --api-scan` |
| `comment-pr` | `false` | Post or update one summary comment on the PR |
| `work-dir` | `.rampart` | Where the audit log, evidence, and reports go |

`@v1` tracks the latest 1.x release. Pin to an exact tag such as `@v1.2.0`, or a full commit SHA, for
fully reproducible builds. Inputs reach the shell only through environment variables, so a value
can't inject commands. The job fails (exit 2) if the target is unreachable or every request was
blocked by your scope, so a broken deploy can never pass the security check by accident.

</details>

<details>
<summary><b>🦊 GitLab CI</b>: your pipelines live in GitLab</summary>

<br />

```yaml
rampart:
  image: python:3.12-slim
  script:
    - pip install https://github.com/NitinReddy-A/Rampart/releases/download/v1.2.0/rampart_appsec-1.2.0-py3-none-any.whl
    - rampart test --scope-file rampart.scope.yaml --target "$STAGING_URL"
        --crawl --report sarif,html,json --ci --fail-on high
  artifacts:
    when: always
    paths: [.rampart/reports/]
```

A fuller template is in [`.gitlab-ci.yml`](.gitlab-ci.yml).

</details>

<details>
<summary><b>🐳 Docker</b>: no Python on the host, or Kubernetes and CI runners</summary>

<br />

```bash
docker run --rm \
  --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" \
  ghcr.io/nitinreddy-a/rampart:latest \
  test --scope-file rampart.scope.yaml --target https://staging.acme.internal --report html,sarif
```

The image is multi-arch (`amd64`, `arm64`), runs as a non-root user, and is tagged `latest`,
`1.2`, and `1.2.0`. To scan something on your host, add `--network host` on Linux or target
`host.docker.internal` on macOS and Windows. See [`docker-compose.yml`](docker-compose.yml) for a
ready-made setup.

</details>

<details>
<summary><b>🤖 MCP server</b>: Claude Code, Cursor, or another agent runs scoped scans for you</summary>

<br />

Rampart ships an [MCP](https://modelcontextprotocol.io) server, so an AI agent can validate scope,
run scans, and read reports, always inside your scope contract.

```bash
claude mcp add rampart -- rampart mcp
```

For Cursor, Claude Desktop, or any other MCP client, add this to its MCP config:

```json
{
  "mcpServers": {
    "rampart": { "command": "rampart", "args": ["mcp"] }
  }
}
```

Then just ask: *"Check my scope file, scan http://127.0.0.1:8080, and summarize the confirmed
findings."* Tools and details: [docs/MCP.md](docs/MCP.md).

</details>

<details>
<summary><b>📊 Local dashboard</b>: browse runs and findings in a browser</summary>

<br />

```bash
rampart serve --work-dir .rampart      # http://127.0.0.1:8787, zero dependencies
```

</details>

## Bring your own LLM (optional)

The LLM only **suggests** where to look. Everything it suggests is re-checked by the deterministic
pipeline and the oracles.

| `--intel` | Uses | Cost | Setup |
| --- | --- | --- | --- |
| `deterministic` *(default)* | built-in rules | free | none |
| `claude-code` | your local `claude` CLI | your Claude plan | `claude` on your `PATH` |
| `openai-compat` | OpenAI, OpenRouter, Groq, Together, LiteLLM, Ollama… | your key, or free locally | 2–3 env vars |

```bash
export RAMPART_LLM_BASE_URL="http://localhost:11434/v1"   # e.g. a local Ollama
export RAMPART_LLM_MODEL="llama3.1"
export RAMPART_LLM_API_KEY="..."                          # or OPENAI_API_KEY; not needed for Ollama
rampart test --intel openai-compat --agents --scope-file rampart.scope.yaml --target …
```

Keys are read from the environment, never from command-line flags. Model suggestions:
[docs/LLM_AND_API_KEYS.md](docs/LLM_AND_API_KEYS.md).

## Safety model

<div align="center">
<img src="docs/assets/iso-choke.svg" alt="Isometric view: the crawler, oracles, logins, and the browser, gRPC and infra engines all converge through one admission gate before reaching the target; an out-of-scope request bounces off the gate" width="560" />
<br />
<sub>One gate, no side doors. An out-of-scope request bounces off.</sub>
</div>

<br />

| | |
| --- | --- |
| **Authorization gate** | No valid, unexpired, in-scope `rampart.scope.yaml` with an accountable owner means no run. |
| **One admission contract on every egress** | HTTP requests (crawler, oracles, test-account logins) are checked against the scope's host, port, and canonicalised path, and the *resolved* IP to stop DNS rebinding. The browser, gRPC, and infra engines enforce the same scope and resolved-IP allowlist and share one admission guard for budget, kill switch, and audit. All fail-closed. |
| **Fail-closed scope parsing** | The built-in YAML parser rejects anything it doesn't fully understand instead of guessing, so a typo can't silently widen your scope. |
| **LLM containment, tested** | A regression test drives the agent layer with a model that tries other hosts, ports, excluded paths, cloud metadata, and `file://` URLs, and asserts nothing out of scope is ever contacted. |
| **Non-destructive by default** | Write probes need `--active`; state changes beyond that need human approval; destructive actions and denial of service are always denied. |
| **Tamper-evident audit log** | Append-only, hash-chained, and anchored; `rampart verify-audit` detects edits, deletions, reordering, and truncation. |
| **Target output is data** | Never instructions, which prevents indirect prompt injection. |
| **Budgets and a kill switch** | Request rate, total requests, and LLM spend are capped. |
| **Advisory fixes only** | Patch suggestions are written as files; Rampart never applies or merges them. |

## Reports and compliance

<p align="center">
  <img src="docs/assets/report-preview.png" alt="Rampart HTML report: 22 confirmed findings, 45 false positives dropped, $0 LLM cost" width="820" />
</p>

Choose any combination with `--report`:

| Format | For |
| --- | --- |
| `html` | a self-contained, shareable report (light and dark) |
| `md` | pull requests, wikis, tickets |
| `json` | your own tooling; the stable schema the SDK reads |
| `sarif` | GitHub code scanning (`github/codeql-action/upload-sarif`), other SARIF tools, IDEs |
| `compliance` / `soc2` | auditors |

The compliance report maps each finding by CWE to the controls it evidences across **SOC 2,
ISO 27001:2022, PCI DSS v4.0, NIST 800-53 Rev5 (FedRAMP), HIPAA, GDPR, OWASP ASVS, and CIS
Controls v8**. It's evidence for your auditor, not a certification. Pair it with the hash-chained
audit log (`rampart verify-audit`) and the evidence bundle.

## Benchmark

Most tools self-report their false-positive rate. Rampart ships the benchmark so you can check:

```bash
python benchmarks/run_benchmark.py --runs 5
```

It scans the demo target in **vulnerable** and **fixed** modes and scores confirmed findings
against ground truth. CI runs it on every push and fails the build on any false positive or false
negative.

| True positives | False positives | False negatives | Precision | Recall | Cost |
| :---: | :---: | :---: | :---: | :---: | :---: |
| 15 | 0 | 0 | 100% | 100% | $0 |

A separate weekly job scores Rampart against the external
[OWASP VAmPI](https://github.com/erev0s/VAmPI) corpus ([`corpus.yml`](.github/workflows/corpus.yml)).

> [!NOTE]
> The benchmark target ships with Rampart, so a perfect score there is a regression guarantee, not
> a claim about every application. Known gaps on other targets are listed under
> [Limitations](#limitations), and we track them openly.

## FAQ

<details>
<summary><b>Is it legal to run this?</b></summary>
<br />
On systems you own or have written permission to test, yes. That's what the scope contract
records: who authorized the test, what's in scope, and when the permission expires. Running any
security scanner against systems without permission is illegal in most countries.
</details>

<details>
<summary><b>Does my code or data leave my machine?</b></summary>
<br />
Not by default. Rampart's default mode makes no external calls besides the requests to your
in-scope target. Two features are opt-in: <code>--sca-online</code> sends dependency names and
versions to OSV.dev and fetches public EPSS and CISA KEV data, and an LLM provider receives prompts
if you configure one. Use Ollama to keep LLM reasoning local too.
</details>

<details>
<summary><b>Will it break my staging environment?</b></summary>
<br />
It's built not to. By default it only sends read requests and controlled validation probes. Write
probes require <code>--active</code>, state-changing actions require human approval, and
destructive or denial-of-service actions are always blocked. Rate and request budgets come from
your scope file. Still, test against staging rather than production.
</details>

<details>
<summary><b>How is this different from OWASP ZAP or Nuclei?</b></summary>
<br />
Those are excellent at finding <i>candidates</i>. Rampart's focus is proving them: each finding is
reproduced by an independent oracle with a negative control, and unproven candidates are dropped
and listed. Rampart can also run Nuclei, Nmap, Semgrep, Trivy, and testssl.sh as lead sources via
<code>--scanners</code>, then label their output as unvalidated.
</details>

<details>
<summary><b>Do I need an LLM or an API key?</b></summary>
<br />
No. Everything in "What it tests" works deterministically with no LLM. The optional reasoning layer
(<code>--agents</code>) helps with business-logic and multi-step auth flows.
</details>

<details>
<summary><b>What does "agent-assessed" mean?</b></summary>
<br />
An issue the LLM reasoned about but no oracle could prove. Rampart shows it separately so a human
can review it, and never counts it as confirmed or uses it to fail a build.
</details>

<details>
<summary><b>Can I add my own checks?</b></summary>
<br />
Yes. A new vulnerability class is a probe plus an oracle. <a href="CONTRIBUTING.md">CONTRIBUTING.md</a>
walks through it step by step.
</details>

## Limitations

Rampart is a strong, low-noise first pass and a continuous regression gate. It isn't a replacement
for a human pentest.

- Novel logic flaws and deep design issues still need a person. That's why LLM-only findings are labelled `agent-assessed` and never promoted automatically.
- No mobile app testing, and gRPC coverage stops at reachable unauthenticated checks (no deep fuzzing).
- No hosted service. You run it yourself.
- Compliance output is evidence of control effectiveness, not an attestation.

## Documentation

| Guide | |
| --- | --- |
| [Python SDK](docs/SDK.md) | run scans from code, gate tests |
| [MCP / Claude Code](docs/MCP.md) | let an AI agent run scoped scans |
| [LLMs and API keys](docs/LLM_AND_API_KEYS.md) | providers, models, free options |
| [LLM security testing](docs/LLM_SECURITY_TESTING.md) | the 4 OWASP LLM Top 10 categories `llm-test` covers (LLM01/05/07/02) |
| [Coverage manifest](docs/COVERAGE.md) | exactly what Rampart does, by evidence tier: the single source of truth |
| [Notifications](docs/NOTIFICATIONS.md) | post confirmed findings to a signed webhook or Slack |
| [External tools](docs/EXTERNAL_TOOLS.md) | optional Nuclei/Semgrep/Trivy/… adapters (unvalidated leads) |
| [Architecture](docs/ARCHITECTURE.md) | how the code is organized |
| [Benchmark fixtures](docs/BENCHMARK_FIXTURES.md) | the multi-app benchmark program and ground truth |
| [Changelog](CHANGELOG.md) | what changed in each release |

## Contributing

New checks, integrations, docs, and bug reports are all welcome. Start with
[CONTRIBUTING.md](CONTRIBUTING.md) for setup and the rules that keep findings trustworthy.

```bash
git clone https://github.com/NitinReddy-A/Rampart.git && cd Rampart
pip install -e ".[dev]" && pre-commit install
make check          # lint, format, tests, and the benchmark, exactly as CI runs them
```

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md). Found a vulnerability
*in Rampart itself*? Please report it privately via [SECURITY.md](SECURITY.md).

## Contributors

Thanks to everyone who has made Rampart better.

<table>
  <tr>
    <td align="center" width="140" valign="top">
      <a href="https://github.com/NitinReddy-A"><img src="https://avatars.githubusercontent.com/u/114919978?v=4&s=160" width="80" alt="Nitin" /><br /><b>Nitin</b></a><br />
      <sub>@NitinReddy-A</sub><br />
      <sub>Creator &amp; maintainer</sub>
    </td>
    <td align="center" width="140" valign="top">
      <a href="https://github.com/pkr2805"><img src="https://avatars.githubusercontent.com/u/137922268?v=4&s=160" width="80" alt="Priyanshu Kumar" /><br /><b>Priyanshu Kumar</b></a><br />
      <sub>@pkr2805</sub><br />
      <sub>Maintainer</sub>
    </td>
  </tr>
</table>

Want to see your face here? Pick an [open issue](https://github.com/NitinReddy-A/Rampart/issues)
or propose a new check.

## License

[Apache-2.0](LICENSE). GPL/AGPL external scanners are invoked as separate processes, never linked.
See [NOTICE](NOTICE).

<div align="center">
<br />
<sub>If Rampart saved you time, a ⭐ helps others find it.</sub>
</div>
