# Rampart — positioning & the funding story

*Written for: prospective investors and design partners.*

## One line

**The open-source, self-hostable AppSec agent that finds, _proves_, and helps _fix_ web/API
vulnerabilities in your own authorized apps — combining source + runtime + independent validation
in your CI, without shipping your code or targets to a SaaS.**

## The problem

Application security today forces a bad trade:

- **Scanners (DAST/SAST)** are cheap and self-hostable but drown teams in unvalidated noise, and
  even AI pentesters ship a share of non-actionable reports that someone has to triage.
- **Autonomous AI pentest platforms** (Parameter, XBOW, Horizon3, Pentera) sell *proof-of-exploit*
  instead of CVSS lists — a genuinely better product — but they are **closed-source SaaS**. You ship
  your code and production targets to a vendor. That is a non-starter for regulated, security-conscious,
  and air-gapped buyers, and it means the tool can never live natively in your own CI.

No incumbent is **open, self-hostable, AND evidence-first**. That's the wedge.

## The wedge (four properties no incumbent occupies together)

1. **Open + self-hostable** — data never leaves your infra.
2. **Validation + evidence** — an independent component re-derives every finding from a clean state before it's "confirmed"; false positives are dropped, not shipped.
3. **Runtime ↔ source correlation + fix loop** — links a runtime-proven bug to the source sink its code ties to the endpoint, and proposes a minimal, advisory patch.
4. **Developer-first** — one CLI, SARIF for CI, auditor-ready evidence — not a security-team console.

## Why it's defensible (and safe enough to trust with autonomy)

Two invariants, enforced in code, not prompts:

- **The LLM proposes; deterministic code disposes.** Every action passes one admission contract
  (`allowlist → scope → resolved-IP → risk → policy → sandbox → audit`) — the HTTP policy pipeline,
  and a shared admission guard that applies the same scope/IP/budget/audit to the engines that open
  their own connections — fail-closed. Prompt injection against naive security agents is a
  demonstrated attack; here a prompt-injected model can at worst emit requests the policy engine
  rejects. Safety is a property of the architecture.
- **Evidence over alerts.** A separate validator re-derives proof with a deterministic oracle, 2+
  reproductions, and negative controls. This is the same separation-of-duties move XBOW and Horizon3
  call the most important stage of their pipelines — but ours is open and independently benchmarkable.

## What's built today (v1.2.0, plus `main`)

- The full safety choke-point + append-only, hash-chained, tamper-evident audit log, with a shared
  admission guard for the engines that open their own connections.
- 14 oracle-validated runtime classes (IDOR/BOLA, BFLA, SQLi, XSS, SSTI, SSRF, command injection,
  path traversal, open redirect, host-header injection, JWT `alg=none`, excessive data exposure,
  mass assignment, GraphQL introspection), each end-to-end: scope gate → app model → hypothesis →
  controlled probe → independent validation → schema-valid finding (CWE + CVSS 4.0 + evidence
  bundle) → advisory patch (never auto-merged) → retest → `Fixed`/`Regression`.
- Built-in misconfiguration, header and sensitive-file checks; deep auth, API-depth,
  business-logic, out-of-band, headless-browser, gRPC and infra stages.
- White-box: a Python AST source scanner, secrets, SCA against OSV.dev, IaC, and runtime ↔ source
  correlation that links a sink only when its code ties it to the endpoint.
- OWASP LLM Top 10 probes for 4 of the 10 categories.
- On `main`: finding-driven escalation (`--deep`), bounded and deterministic.
- Three intelligence backends: free deterministic default, Claude Code, and bring-your-own-key
  (any OpenAI-compatible provider, incl. fully-local Ollama).
- Surfaces: CLI, Python SDK, GitHub Action, GitLab CI template, Docker image, MCP server, local
  dashboard.
- Reports: HTML, Markdown, JSON, SARIF (GitHub code scanning), compliance mapping across 8
  frameworks, SOC 2 evidence.
- **Its own reproducible benchmark**: 15/0/0 (100% precision and recall) on the shipped
  vulnerable/fixed corpus, gated in CI, plus a weekly run against OWASP VAmPI and Juice Shop fixtures.
- A test suite of 750+ tests, including the A1–A8 acceptance suite, and coverage-guided fuzzing of
  the scope parser and gate matchers.

BOLA/IDOR was built end-to-end first: broken object-level authorization is the leading risk in
the OWASP API Security Top 10, and one class proven honestly beats twenty shallow scanners.

## Market context

Autonomous AI pentesting is a validated, well-funded category (XBOW, Horizon3, RunSybil, Terra,
Parameter, Pentera) — and it is almost entirely closed SaaS. Open-core + self-host is the
un-served segment (regulated enterprises, defense, anyone who won't send code to a vendor).

## Business model

Apache-2.0 open core (adoption + contribution + trust), open-core commercial layer for teams
(hosted control plane, SSO/RBAC, multi-tenant orchestration, managed scanner fleet, support/SLA).
GPL/AGPL scanners are integrated as separate processes, never linked — clean licensing for a
commercial offering.

## Roadmap

Shipped from the original roadmap: external scanner adapters (as unvalidated leads), the web
injection and misconfiguration workers, the GitHub Action and MCP server, the local dashboard, the
Postgres store, and the corpus benchmark program.

Still open: a stateful business-logic and race-condition engine, native SAST beyond Python,
broader OWASP LLM coverage, more external corpora in the published benchmark, and — as the
commercial layer, not the open core — a hosted, multi-user control plane.

## The honest guardrail (a feature, not a hedge)

Rampart **augments, does not replace, expert human pentesters**, and generates *evidence of control
effectiveness*, not compliance attestation. Being honest about the ceiling is exactly what earns
trust with security buyers — and it's the credibility the market's self-reported FP claims lack.
