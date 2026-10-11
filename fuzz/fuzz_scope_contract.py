"""Atheris fuzz target: the rampart.scope.yaml authorization contract.

The contract gates every scan, so it must fail closed on ANY input: the built-in YAML parser
raises only YamlError, parsing a contract either succeeds or raises ScopeError (never another
exception), and on a parsed contract the gate's matchers never raise and never admit a path
that cannot be reasoned about.

    python fuzz/fuzz_scope_contract.py -max_total_time=60 <corpus-dir>
"""

import sys

import atheris

with atheris.instrument_imports():
    from rampart import yaml_lite
    from rampart.schemas.scope import EngagementScope, PathError, ScopeError, path_forms

# Request paths that probe normalisation: traversal, encoding, case, NUL, empty, not origin-form.
_PATHS = (
    "/",
    "/api/users/1",
    "/api/admin/x",
    "/API/Admin/",
    "/%2e%2e/admin",
    "/a/../admin",
    "/a%00b",
    "",
    "x",
)
_HOSTS = ("127.0.0.1", "LOCALHOST", "example.com.", "")


def _malformed(path: str) -> bool:
    try:
        forms = path_forms(path)
    except PathError:
        return True
    assert forms and all(isinstance(f, str) for f in forms), forms
    return False


def TestOneInput(data: bytes) -> None:
    text = data.decode("utf-8", errors="replace")
    try:
        # The strict built-in parser (PyYAML is not installed in the fuzz job).
        yaml_lite._load_lite(text)
    except yaml_lite.YamlError:
        pass
    try:
        scope = EngagementScope.from_text(text)
    except ScopeError:
        return  # refused: the fail-closed outcome for a malformed contract
    assert isinstance(scope.validate(), list)
    assert isinstance(scope.is_expired(), bool)
    line = text.splitlines()[0][:256] if text else ""
    for path in (*_PATHS, line):
        malformed = _malformed(path)
        excluded = scope.path_excluded(path)
        assert excluded is True or excluded is False, excluded
        assert excluded or not malformed, f"malformed path not excluded: {path!r}"
        for hs in scope.in_scope:
            included = scope.path_included(hs, path)
            assert included is None or isinstance(included, str), included
            assert included is None or not malformed, f"malformed path included: {path!r}"
    for host in (*_HOSTS, line[:64]):
        scope.host_scope(host)
        assert isinstance(scope.ip_allowed(host), bool)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
