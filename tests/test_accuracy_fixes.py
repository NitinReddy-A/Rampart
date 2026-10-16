"""Regression tests for accuracy fixes: evidence hashes that match on Windows, the LLM demo's
scope under the strict built-in parser, CLI output, report metrics, concrete reproduction
steps, evidence-based source correlation and observation-tier retest."""

from __future__ import annotations

import hashlib
import importlib.util
import os
import re

import pytest
from conftest import PLATFORM, make_engagement, write_engagement

from rampart import cli
from rampart.evidence import EvidenceStore
from rampart.reporting import ReportBuilder
from rampart.schemas.scope import EngagementScope
from rampart.yaml_lite import _load_lite

DEMO = os.path.join(PLATFORM, "examples", "demo_target")
ANSI = re.compile(r"\x1b\[[0-9;]*m")


# ------------------------------------------------------------------ evidence store
def test_evidence_blob_bytes_hash_to_their_own_name(tmp_path):
    store = EvidenceStore(str(tmp_path))
    text = "HTTP 200\nServer: x\n\nfirst line\r\nsecond line\n"
    ev = store.put_text("http_response", "probe", text)
    blob = tmp_path / ev.sha256[:2] / ev.sha256
    # the bytes on disk are exactly what was hashed, on every OS (text mode wrote CRLF on Windows)
    assert hashlib.sha256(blob.read_bytes()).hexdigest() == ev.sha256
    # and a CRLF inside a captured body survives the round trip
    assert store.read(ev.storage_uri) == text


# ------------------------------------------------------------------ LLM demo scope
def test_llm_demo_scope_parses_without_pyyaml():
    spec = importlib.util.spec_from_file_location("demo_script", os.path.join(PLATFORM, "scripts", "demo.py"))
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    path = demo._llm_scope(9090)
    with open(path, encoding="utf-8") as fh:
        data = _load_lite(fh.read())  # the strict fallback parser, as in a clean install
    scope = EngagementScope.from_dict(data)
    assert scope.validate() == []
    assert scope.in_scope[0].ports == [9090]


# ------------------------------------------------------------------ CLI output
def test_err_keeps_line_breaks_but_cleans_each_line(capsys):
    cli._err("refused to run: invalid scope:\n   - expires is in the past\x1b[2Jboom")
    out = capsys.readouterr().out
    lines = ANSI.sub("", out).splitlines()
    assert lines[0].startswith("✗ refused to run: invalid scope:")
    assert lines[1].strip().startswith("- expires is in the past")
    assert "\x1b[2J" not in out  # a control sequence inside a line is still neutralised


def test_init_labels_are_aligned(tmp_path, capsys):
    scope = write_engagement(tmp_path, 18123)
    assert cli.main(["init", "--scope-file", scope]) == 0
    rows = [
        ln for ln in ANSI.sub("", capsys.readouterr().out).splitlines() if ln.startswith("  ") and ":" in ln
    ]
    labels = {ln.split(":")[0].strip(): ln for ln in rows}
    assert {"authorized by", "test accounts"} <= set(labels)
    # every value starts in the same column, after a space
    starts = {len(ln) - len(ln.split(":", 1)[1].lstrip()) for ln in rows}
    assert len(starts) == 1, rows
    assert "authorized by:" in labels["authorized by"] and "by: " in labels["authorized by"]


def test_features_columns_line_up_in_colour(capsys, monkeypatch):
    monkeypatch.setattr(cli, "_USE_COLOR", True)
    cli.main(["features"])
    plain = ANSI.sub("", capsys.readouterr().out).splitlines()
    names = {"recon", "dast", "sast", "pipeline", "mcp"}
    cols = {ln.index(ln.split()[1]) for ln in plain if ln.split() and ln.split()[0] in names}
    assert len(cols) == 1, cols  # descriptions start in one column even with colour codes


# ------------------------------------------------------------------ report metrics
def test_endpoints_tested_counts_distinct_endpoints():
    hyps = [
        {"endpoint_id": "ep_a_get", "endpoint_method": "GET", "endpoint_path": "/a"},
        {"endpoint_id": "ep_a_get", "endpoint_method": "GET", "endpoint_path": "/a"},
        # an escalated follow-up carries no endpoint_id but is the same endpoint
        {"endpoint_method": "get", "endpoint_path": "/a"},
        {"endpoint_id": "ep_b_get", "endpoint_method": "GET", "endpoint_path": "/b"},
    ]
    rb = ReportBuilder([], None, None, {"hypotheses": hyps, "endpoints_tested": 79}, {}, audit_events=0)
    assert rb.metrics()["endpoints_tested"] == 2


def test_summary_does_not_claim_a_gate_ran_when_nothing_was_tested():
    rb = ReportBuilder([], None, None, {"hypotheses": []}, {}, audit_events=0)
    text = rb.executive_summary()
    assert "Every candidate" not in text and "All 0" not in text
    assert "no runtime candidates were tested" in text


# ------------------------------------------------------------------ against the demo app
def test_confirmed_findings_carry_concrete_steps_and_honest_correlation(tmp_path, vuln_server):
    from rampart.engagement import Engagement, EngagementConfig

    scope = write_engagement(tmp_path, vuln_server.port)
    eng = Engagement(
        EngagementConfig(
            scope_file=scope,
            target=f"http://127.0.0.1:{vuln_server.port}",
            work_dir=str(tmp_path / ".rampart"),
            openapi=str(tmp_path / "openapi.json"),
            appmodel_seed=str(tmp_path / "seed.json"),
            application="demo-shop-api",
            repo=DEMO,
            do_sast=True,
        )
    )
    findings = eng.run_scan().findings
    by_title = {f.title: f for f in findings}

    cmdi = by_title["OS command injection via 'host' on GET /api/ping"]
    assert cmdi.verification.validated
    steps = cmdi.reproduction.steps
    assert steps[0].startswith("Send the probe: GET /api/ping?host=") and "echo $((" in steps[0]
    assert any(s.startswith("Send the benign control: GET /api/ping?host=") for s in steps)
    assert any("evidence://" in s for s in steps)
    assert not any("see proof below" in s for s in steps)

    # a probe whose forged part is a header keeps a description of it
    jwt = by_title["JWT accepted without signature verification (alg=none) on GET /api/me"]
    assert jwt.reproduction.steps[0] == (
        "Send the probe: GET /api/me with an unsigned token (alg=none) in the Authorization header"
    )

    # correlated to the sink that takes the same parameter, with the reason recorded
    assert "source-correlated" in cmdi.tags
    assert (cmdi.affected_code.file, cmdi.affected_code.start_line) == ("src/vulnerable_code.py", 19)
    assert any("parameter 'host'" in c for c in cmdi.verification.false_positive_checks)

    # a same-CWE sink with no tie to the endpoint is not claimed
    sqli = by_title["SQL injection in 'id' on GET /api/products"]
    assert sqli.verification.validated and "source-correlated" not in sqli.tags

    m = eng.report_builder().metrics()
    assert 0 < m["endpoints_tested"] <= m["endpoints_discovered"]


def test_retest_rechecks_misconfiguration_findings(tmp_path, vuln_server):
    from rampart.engagement import Engagement

    eng = make_engagement(tmp_path, vuln_server.port)
    eng.run_scan()
    results = eng.retest()
    rechecked = {(f.title, o) for f, o in results if f.vuln_class in Engagement.RECHECKABLE}
    assert rechecked, "the demo app has misconfiguration and exposed-file findings"
    # still present on the vulnerable build, so still vulnerable, never "not retestable"
    assert {o for _t, o in rechecked} == {"still-vulnerable"}


@pytest.mark.parametrize("cls", sorted({"security-misconfiguration", "sensitive-file-exposure"}))
def test_recheckable_classes_are_the_observation_tier(cls):
    from rampart.engagement import Engagement

    assert cls in Engagement.RECHECKABLE
