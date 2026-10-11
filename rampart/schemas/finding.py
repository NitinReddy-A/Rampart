"""The machine-readable finding — a SARIF-exportable superset (blueprint section 14).

``confidence == "confirmed"`` REQUIRES ``verification.validated is True`` with independent
replay evidence. That coupling is the trust primitive separating this from a raw scanner
alert. The finding lifecycle (section 21) is enforced by the states below.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from ..util import gen_id, now_iso


class State:
    CANDIDATE = "Candidate"  # LLM hypothesis exists; no evidence
    INVESTIGATING = "Investigating"  # worker running Tier 0/1 probes
    EVIDENCE_FOUND = "EvidenceFound"  # a deterministic oracle fired; bundle assembled
    VALIDATED = "Validated"  # GATE passed: independent re-derivation from clean state
    REPORTED = "Reported"
    FIX_PROPOSED = "FixProposed"
    RETEST = "Retest"
    FIXED = "Fixed"
    REGRESSION = "Regression"
    DROPPED = "Dropped"  # gate failed / demoted


SEVERITIES = ("info", "low", "medium", "high", "critical")
CONFIDENCES = ("tentative", "firm", "confirmed")


@dataclass
class Evidence:
    type: str  # http_request|http_response|response_diff|screenshot|note
    summary: str
    storage_uri: str = ""
    sha256: str = ""
    redacted: bool = True


@dataclass
class CVSS:
    version: str = "4.0"
    base_score: float = 0.0
    vector: str = ""
    severity: str = "info"
    v31_fallback: dict = field(default_factory=dict)


@dataclass
class Reproduction:
    prerequisites: list = field(default_factory=list)
    steps: list = field(default_factory=list)
    deterministic: bool = True


@dataclass
class AffectedCode:
    detected_by: str = ""
    repo: str = ""
    file: str = ""
    start_line: int = 0
    end_line: int = 0
    snippet: str = ""
    commit: str = ""


@dataclass
class Remediation:
    summary: str = ""
    type: str = "code_patch"
    guidance: str = ""
    proposed_diff: str = ""  # advisory only — never auto-applied (R7)
    effort: str = "low"
    fix_status: str = "proposed"  # proposed|applied
    tests_run: bool = False
    tests_passed: bool | None = None
    pr_ref: str = ""


@dataclass
class Verification:
    method: str = ""  # e.g. active-exploit-replay
    validated: bool = False
    validated_at: str = ""
    validator: str = ""  # a component DIFFERENT from the discoverer (separation of duties)
    independent_reproduction: bool = False
    reproductions: int = 0
    false_positive_checks: list = field(default_factory=list)
    confidence_score: float = 0.0
    last_retest: dict = field(default_factory=dict)


@dataclass
class Finding:
    engagement_id: str
    title: str
    vuln_class: str = ""
    severity: str = "info"
    severity_source: str = "cvss"
    confidence: str = "tentative"
    status: str = "open"
    state: str = State.CANDIDATE
    cwe: list = field(default_factory=list)
    owasp: dict = field(default_factory=dict)
    asvs: dict = field(default_factory=dict)
    cvss: CVSS = field(default_factory=CVSS)
    asset: dict = field(default_factory=dict)
    endpoint: dict = field(default_factory=dict)
    description: str = ""
    impact: str = ""
    evidence: list = field(default_factory=list)
    reproduction: Reproduction = field(default_factory=Reproduction)
    affected_code: AffectedCode | None = None
    root_cause: str = ""
    remediation: Remediation = field(default_factory=Remediation)
    references: list = field(default_factory=list)
    compliance_control_refs: list = field(default_factory=list)
    verification: Verification = field(default_factory=Verification)
    dedupe_key: str = ""
    first_seen: str = field(default_factory=now_iso)
    tags: list = field(default_factory=list)
    # SCA exploit-intelligence context: {epss, epss_percentile, kev, reachable, adjusted_severity,
    # priority, rationale}. Empty for non-SCA findings.
    exploit_intel: dict = field(default_factory=dict)
    id: str = ""
    schema_version: str = "1.0.0"

    def __post_init__(self):
        if not self.id:
            self.id = gen_id("fnd")

    # ------------------------------------------------------------- invariant
    def assert_consistent(self) -> None:
        """The trust primitive: 'confirmed' is only legal with independent validation."""
        if self.confidence == "confirmed" and not self.verification.validated:
            raise ValueError(
                f"finding {self.id}: confidence=confirmed requires verification.validated=True "
                "(evidence over alerts — section 21)"
            )

    def to_dict(self) -> dict:
        d = asdict(self)
        d["$schema"] = "https://rampart.dev/schemas/finding/v1.json"
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        d = {k: v for k, v in d.items() if not k.startswith("$")}

        def _sub(klass, val, default):
            if val is None:
                return default
            if isinstance(val, klass):
                return val
            return klass(**{k: v for k, v in val.items() if k in klass.__annotations__})

        d["cvss"] = _sub(CVSS, d.get("cvss"), CVSS())
        d["reproduction"] = _sub(Reproduction, d.get("reproduction"), Reproduction())
        d["remediation"] = _sub(Remediation, d.get("remediation"), Remediation())
        d["verification"] = _sub(Verification, d.get("verification"), Verification())
        if d.get("affected_code"):
            d["affected_code"] = _sub(AffectedCode, d.get("affected_code"), None)
        d["evidence"] = [_sub(Evidence, e, None) for e in (d.get("evidence") or [])]
        known = {k: v for k, v in d.items() if k in cls.__annotations__}
        return cls(**known)

    # --------------------------------------------------------------- SARIF
    def to_sarif_result(self, repo_root: str = "") -> dict:
        """One SARIF 2.1.0 ``result``.

        Every result gets exactly ONE physical location whose uri is relative and scheme-less,
        because GitHub code scanning rejects the WHOLE upload when any artifactLocation is an
        absolute URI whose scheme is not the checkout's (``file``). A finding with
        ``affected_code.file`` points at the source file, repo-relative under ``uriBaseId:
        %SRCROOT%`` (relativised against ``repo_root`` when given; never an absolute local path),
        with a 1-based region when the line is known. A runtime finding gets a virtual
        ``<host>[:port]/<path>`` path (:func:`sarif_endpoint_uri`), keeps its exact endpoint URL as
        a logical location, and carries its own ``primaryLocationLineHash`` — there is no file for
        the uploader to fingerprint."""
        import hashlib

        from ..reporting.status import norm_severity

        level = {
            "critical": "error",
            "high": "error",
            "medium": "warning",
            "low": "note",
            "info": "note",
        }[norm_severity(self.severity)]
        rule_id = (self.cwe[0] if self.cwe else self.vuln_class) or "finding"
        target = self.asset.get("target", "") or ""
        code_file = self.affected_code.file if self.affected_code and self.affected_code.file else ""
        fingerprints = {"dedupeKey/v1": self.dedupe_key or self.id}
        if code_file:
            phys = {
                "artifactLocation": {
                    "uri": sarif_relative_uri(code_file, repo_root),
                    "uriBaseId": "%SRCROOT%",
                }
            }
            start = self.affected_code.start_line or 0
            if isinstance(start, int) and start >= 1:  # SARIF regions are 1-based; omit when unknown
                end_line = self.affected_code.end_line or 0
                phys["region"] = {
                    "startLine": start,
                    "endLine": max(start, end_line if isinstance(end_line, int) else 0),
                }
            locations = [{"physicalLocation": phys}]
        else:
            # Never the endpoint itself as the uri: "http://host/x" — and a bare "host:443", which
            # parses as scheme "host" — would get the whole SARIF upload rejected by code scanning.
            endpoint = self.endpoint.get("url") or (target if "://" in target else "")
            if endpoint:
                uri = sarif_endpoint_uri(endpoint)
            elif self.asset.get("type") == "dependency" and target:
                uri = sarif_virtual_path(target.split(":", 1))  # "PyPI:flask" -> "PyPI/flask"
            else:
                uri = sarif_virtual_path([rule_id])
            uri = uri or "finding"
            loc = {"physicalLocation": {"artifactLocation": {"uri": uri}}}
            if endpoint:
                loc["logicalLocations"] = [{"fullyQualifiedName": endpoint, "kind": "resource"}]
            locations = [loc]
            identity = f"{rule_id}|{self.dedupe_key or uri}"
            fingerprints["primaryLocationLineHash"] = (
                hashlib.sha256(identity.encode()).hexdigest()[:16] + ":1"
            )
        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{self.title} — {self.description}"},
            "locations": locations,
            "partialFingerprints": fingerprints,
            "properties": {
                "vuln_class": self.vuln_class,
                "confidence": self.confidence,
                "state": self.state,
                "cwe": self.cwe,
                "owasp": self.owasp,
                "cvss": asdict(self.cvss),
                "validated": self.verification.validated,
                "reproductions": self.verification.reproductions,
                "compliance_control_refs": self.compliance_control_refs,
            },
        }
        if self.asset.get("type") == "dependency" and target:
            eco, _, pkg = target.partition(":")
            result["properties"]["package"] = {"ecosystem": eco, "name": pkg or target}
            logical = {"name": pkg or target, "fullyQualifiedName": target, "kind": "package"}
            loc = result["locations"][0]
            loc["logicalLocations"] = [logical, *loc.get("logicalLocations", [])]
        return result


def sarif_endpoint_uri(endpoint: str) -> str:
    """A scheme-less virtual path (``<host>[:port]/<path>``) standing in for a runtime endpoint in
    a SARIF ``artifactLocation``.

    Code scanning reads a relative uri as repo-relative and accepts it even when no such file
    exists; an absolute one must use the checkout's ``file`` scheme or the upload is rejected.
    So the scheme, userinfo, query and fragment are dropped and every reserved character —
    ':' included, so ``host:443`` can't parse as a scheme — is percent-encoded. The exact
    endpoint is reported separately as a logical location."""
    from urllib.parse import unquote, urlsplit

    s = str(endpoint or "").strip().replace("\\", "/")
    if "://" not in s and not s.startswith("/"):
        s = "//" + s  # "host:port[/path]" — parse the host as an authority, not a scheme
    try:
        parts = urlsplit(s)
        host = parts.hostname or ""
        authority = f"[{host}]" if ":" in host else host
        if parts.port is not None:
            authority += f":{parts.port}"
        path = parts.path
    except ValueError:  # malformed port / IPv6 literal: keep the raw text as path segments
        authority, path = "", s
    return sarif_virtual_path([authority, *(unquote(p) for p in path.split("/"))]) or "endpoint"


def sarif_virtual_path(segments) -> str:
    """Join ``segments`` into a relative, scheme-less SARIF uri: each one percent-encoded down to
    RFC 3986 unreserved characters, and empty / ``.`` / ``..`` segments dropped so the path can
    never climb out of the repository root."""
    from urllib.parse import quote

    return "/".join(quote(str(s), safe="-._~") for s in segments if s not in ("", ".", ".."))


def sarif_relative_uri(path: str, repo_root: str = "") -> str:
    """A repo-relative, forward-slash URI for a SARIF ``artifactLocation`` (``%SRCROOT%`` based).

    Relativised against ``repo_root`` when the file lies inside it; otherwise any drive letter /
    UNC prefix / leading slash is dropped so an absolute local path is never emitted."""
    import ntpath
    import posixpath
    from urllib.parse import quote

    p = str(path or "").replace("\\", "/")
    root = str(repo_root or "").replace("\\", "/").rstrip("/")
    if root:
        ci = bool(ntpath.splitdrive(root)[0])  # Windows paths compare case-insensitively
        pl, rl = (p.lower(), root.lower()) if ci else (p, root)
        if pl == rl:
            p = posixpath.basename(p)
        elif pl.startswith(rl + "/"):
            p = p[len(root) + 1 :]
    drive, rest = ntpath.splitdrive(p)
    if drive:
        p = rest.replace("\\", "/")
    p = p.lstrip("/")
    parts = [seg for seg in p.split("/") if seg not in ("", ".")]
    while parts and parts[0] == "..":
        parts.pop(0)
    return quote("/".join(parts), safe="/-._~")
