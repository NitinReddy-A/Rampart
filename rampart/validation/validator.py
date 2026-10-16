"""The independent false-positive gate (blueprint sections 4, 21).

Separation of duties: the Validator is a DIFFERENT component from the worker that proposed
the candidate. It receives only the structured hypothesis facts (which endpoint, which
seeded principals/objects/parameter) — never the worker's reasoning — looks up the oracle
for the finding's class in the registry, and re-derives the proof itself from a clean state.
Only the Validator may set ``confidence = confirmed``; a class with no registered oracle can
never be confirmed (fail-closed).
"""

from __future__ import annotations

import ast
import http.client

from ..executor.session import SessionError
from ..runner import ProbeRunner
from ..schemas.finding import Finding, State, Verification
from ..util import now_iso
from .registry import get_oracle


def _request_line(stored: str) -> tuple[str, str]:
    """('GET /path?k=v', session) from a stored http_request evidence blob (see
    EvidenceStore.put_request); ('', '') if it doesn't look like one."""
    lines = stored.splitlines()
    if not lines or " HTTP/" not in lines[0]:
        return "", ""
    method, path = lines[0].split(" ")[:2]
    session, query, body = "", {}, ""
    for i, line in enumerate(lines[1:], start=1):
        if line.startswith("(session: "):
            value = line[len("(session: ") :].split(",", 1)[0].strip()
            session = "" if value in ("None", "") else value
        elif line.startswith("Query: "):
            parsed = ast.literal_eval(line[len("Query: ") :])
            if isinstance(parsed, dict):
                query = parsed
        elif line == "" and i + 1 < len(lines):
            body = "\n".join(lines[i + 1 :]).strip()
            break
    out = f"{method} {path}"
    if query:
        out += "?" + "&".join(f"{k}={v}" for k, v in query.items())
    if body:
        out += f" with body {body[:160]}{'…' if len(body) > 160 else ''}"
    return out, session


class Validator:
    def __init__(self, pipeline, evidence_store, session_manager, host, port, scheme="http"):
        self.pipeline = pipeline
        self.evidence = evidence_store
        self.sessions = session_manager
        self.host = host
        self.port = port
        self.scheme = scheme

    def _runner(self, phase: str, profile: str = "validator") -> ProbeRunner:
        return ProbeRunner(
            self.pipeline,
            self.evidence,
            self.pipeline.engagement_id,
            self.host,
            self.port,
            self.scheme,
            actor_role="validator",
            actor_profile=profile,
            phase=phase,
        )

    def validate(self, finding: Finding, hyp: dict, reproductions: int = 2) -> bool:
        oracle = get_oracle(finding.vuln_class)
        if oracle is None:
            # No independent oracle for this class — cannot confirm (fail-closed).
            finding.state = State.DROPPED
            finding.status = "dropped"
            finding.confidence = "tentative"
            finding.verification = Verification(
                method="no-oracle",
                validated=False,
                validated_at=now_iso(),
                validator="validator",
                false_positive_checks=[f"no oracle registered for {finding.vuln_class!r}"],
                confidence_score=0.0,
            )
            finding.assert_consistent()
            return False

        runner = self._runner("validate", profile=finding.vuln_class)
        verdict = oracle(runner, self.sessions, hyp, reproductions)
        finding.evidence.extend(verdict.evidence)

        if verdict.validated:
            self._concrete_reproduction(finding, verdict.evidence, verdict.reproductions)
            finding.state = State.VALIDATED
            finding.confidence = "confirmed"
            finding.status = "open"
            finding.verification = Verification(
                method="active-exploit-replay",
                validated=True,
                validated_at=now_iso(),
                validator="validator",  # a component distinct from the discoverer
                independent_reproduction=True,
                reproductions=verdict.reproductions,
                false_positive_checks=verdict.reasons + verdict.false_positive_checks,
                confidence_score=0.95,
                last_retest={"result": "still-vulnerable", "at": now_iso()},
            )
        else:
            finding.state = State.DROPPED
            finding.confidence = "tentative"
            finding.status = "dropped"
            finding.verification = Verification(
                method="active-exploit-replay",
                validated=False,
                validated_at=now_iso(),
                validator="validator",
                independent_reproduction=False,
                reproductions=verdict.reproductions,
                false_positive_checks=verdict.reasons + verdict.false_positive_checks,
                confidence_score=0.0,
            )
        finding.assert_consistent()
        return verdict.validated

    # ----------------------------------------------------------- reproduction
    def _concrete_reproduction(self, finding: Finding, evidence: list, reproductions: int) -> None:
        """Replace the worker's generic steps with the requests the oracle actually sent: the
        probe, the benign control, and where the exact exchange is stored. Best effort: any
        problem reading the evidence leaves the generic steps in place."""
        try:
            reqs = [e for e in evidence if getattr(e, "type", "") == "http_request"]
            if not reqs or self.evidence is None:
                return
            is_control = lambda e: any(
                w in (e.summary or "").lower() for w in ("control", "baseline", "negative")
            )  # noqa: E731
            probe = next((e for e in reqs if not is_control(e)), None)
            control = next((e for e in reqs if is_control(e)), None)
            if probe is None:
                return
            p_line, p_session = _request_line(self.evidence.read(probe.storage_uri))
            if not p_line:
                return
            original = (finding.reproduction.steps or [""])[0]
            if "?" not in p_line and " with body " not in p_line and original.startswith("Send "):
                # what the probe changed isn't in the request line (a forged header, a different
                # principal), so keep the worker's description of it
                p_line = original[len("Send ") :]
            steps = [f"Send the probe: {p_line}"]
            if control is not None:
                c_line, _ = _request_line(self.evidence.read(control.storage_uri))
                if c_line:
                    steps.append(f"Send the benign control: {c_line}; the oracle signal must be absent")
            steps.append(
                f"Repeat from a clean state: the oracle reproduced the signal {reproductions} time(s) "
                "with fresh values each run"
            )
            refs = ", ".join(e.storage_uri for e in (probe, control) if e is not None)
            steps.append(f"The exact requests and responses are in the evidence store: {refs}")
            finding.reproduction.steps = steps
            if p_session:
                finding.reproduction.prerequisites = [
                    f"Authenticated as the scope's test account '{p_session}'"
                ]
        except (OSError, ValueError, SyntaxError, AttributeError):
            return

    def retest(self, finding: Finding, hyp: dict, reproductions: int = 2) -> str:
        """Replay the stored reproduction against the (possibly patched) target.

        Returns 'Fixed' only when the oracle no longer fires AND its controls were healthy and the
        probe was a real denial; 'inconclusive' when the target could not give a meaningful answer
        (down, erroring, sessions failing) — the finding's state is then left unchanged;
        'Regression'/'still-vulnerable' otherwise.
        """
        oracle = get_oracle(finding.vuln_class)
        if oracle is None:
            return "still-vulnerable"
        runner = self._runner("retest", profile=finding.vuln_class)
        try:
            verdict = oracle(runner, self.sessions, hyp, reproductions)
        except (OSError, SessionError, http.client.HTTPException) as exc:
            finding.verification.last_retest = {
                "result": "inconclusive",
                "at": now_iso(),
                "error": f"{type(exc).__name__}: {exc}",
            }
            return "inconclusive"
        if not verdict.validated and (verdict.inconclusive or not verdict.controls_ok):
            finding.verification.last_retest = {
                "result": "inconclusive",
                "at": now_iso(),
                "reproductions": verdict.reproductions,
                "controls": verdict.controls,
            }
            return "inconclusive"
        finding.verification.last_retest = {
            "result": "still-vulnerable" if verdict.validated else "fixed",
            "at": now_iso(),
            "reproductions": verdict.reproductions,
            "controls": verdict.controls,
        }
        if not verdict.validated:
            finding.state = State.FIXED
            finding.status = "fixed"
            return "Fixed"
        if finding.state == State.FIXED:
            finding.state = State.REGRESSION
            finding.status = "open"
            return "Regression"
        finding.state = State.VALIDATED
        return "still-vulnerable"
