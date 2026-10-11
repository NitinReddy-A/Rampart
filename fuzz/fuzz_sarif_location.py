"""Atheris fuzz target: the SARIF locations GitHub code scanning ingests.

Code scanning rejects a WHOLE upload when any artifactLocation is an absolute URI whose scheme
isn't the checkout's ("file"). Whatever endpoint, target or rule id a finding carries — text
that targets and external tools control — its single SARIF location must stay a relative,
scheme-less, valid uri-reference that cannot climb out of the repository root, with a stable
fingerprint.

    python fuzz/fuzz_sarif_location.py -max_total_time=60 <corpus-dir>
"""

import re
import string
import sys
from urllib.parse import unquote, urlsplit

import atheris

with atheris.instrument_imports():
    from rampart.schemas.finding import Finding

# RFC 3986 unreserved characters, percent-encoding, and the segment separator — nothing else.
_URI_CHARS = frozenset(string.ascii_letters + string.digits + "-._~%/")
_ASSETS = ("web", "infrastructure", "dependency", "grpc")


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    asset_type = _ASSETS[fdp.ConsumeIntInRange(0, len(_ASSETS) - 1)]
    use_endpoint = fdp.ConsumeBool()
    rule = fdp.ConsumeUnicodeNoSurrogates(64)
    text = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
    f = Finding(engagement_id="fuzz", title="t", vuln_class=rule, severity="high")
    f.asset = {"type": asset_type, "target": text}
    if use_endpoint:
        f.endpoint = {"url": text}

    res = f.to_sarif_result()
    (loc,) = res["locations"]
    uri = loc["physicalLocation"]["artifactLocation"]["uri"]
    assert uri and set(uri) <= _URI_CHARS, uri
    assert urlsplit(uri).scheme == "" and not uri.startswith("/"), uri
    assert all(unquote(seg) not in ("", ".", "..") for seg in uri.split("/")), uri
    assert re.fullmatch(r"[0-9a-f]{16}:1", res["partialFingerprints"]["primaryLocationLineHash"])
    assert f.to_sarif_result()["partialFingerprints"] == res["partialFingerprints"]


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
