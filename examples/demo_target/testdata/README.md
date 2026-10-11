# Test data — intentionally insecure, never build or deploy

Fixtures here are deliberately misconfigured so Rampart's scanners have something real to find;
the tests assert specific findings at specific lines, so don't "fix" them.

They live under `testdata/` because that is the conventional home for fixtures that tools should
treat as test input rather than as the project's own configuration — OpenSSF Scorecard, for one,
skips `testdata/` paths, so an insecure-by-design Dockerfile here isn't reported as an unpinned
dependency of this repository. Put any new insecure-by-design fixture here too.

- `iac/` — Dockerfile, Kubernetes, and Terraform misconfigurations for the IaC scanner
  (`tests/test_iac.py`, `tests/test_iac_precision.py`).
