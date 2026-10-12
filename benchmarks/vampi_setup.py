"""Prepare a running OWASP VAmPI container for ``corpus_runner.py``.

VAmPI ships with an empty database and random book titles, so a scan against a fresh container
has no endpoints mapped, no accounts to log in as, and no known objects to prove BOLA with. This
script, run once before the scan:

1. waits for the target and populates its database (``GET /createdb`` — retried, because VAmPI
   seeds random ``bookTitle<0-99>`` titles that occasionally collide on its unique constraint);
2. logs in as each seeded account and creates the book listed for it in the app-model seed
   (title = object id, secret = signature), so the BOLA oracle has a known cross-account object;
3. saves the live OpenAPI spec (``/openapi.json``) and a secrets file for the test accounts.

    python benchmarks/vampi_setup.py --target http://127.0.0.1:5000 --out-dir "$RUNNER_TEMP/vampi"

Stdlib only. The credentials are VAmPI's own built-in dummy users on a local container.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SEED = os.path.join(HERE, "fixtures", "vampi-appmodel-seed.json")

# VAmPI's built-in users (models/user_model.py: init_db_users).
ACCOUNTS = {"name1": "pass1", "name2": "pass2"}


def _request(method: str, url: str, body: dict | None = None, token: str = "") -> tuple[int, str]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _retry(what: str, method: str, url: str, body: dict | None = None, attempts: int = 3, delay: float = 1):
    """Send the request until it returns 200; exit with the last error after ``attempts`` tries."""
    last = None
    for _ in range(attempts):
        try:
            status, text = _request(method, url, body)
            if status == 200:
                return text
            last = f"HTTP {status}: {text[:200]}"
        except OSError as exc:
            last = str(exc)
        time.sleep(delay)
    raise SystemExit(f"vampi_setup: {what} failed after {attempts} attempts ({last})")


def setup(target: str, out_dir: str, seed_path: str = DEFAULT_SEED) -> dict:
    target = target.rstrip("/")
    _retry("waiting for the target", "GET", f"{target}/", attempts=30, delay=2)
    _retry("populating the database", "GET", f"{target}/createdb", attempts=5)

    with open(seed_path, encoding="utf-8") as fh:
        seed = json.load(fh)
    for obj in seed.get("objects", []):
        owner = obj["owner_principal"]
        creds = {"username": owner, "password": ACCOUNTS[owner]}
        login = _retry(f"login as {owner}", "POST", f"{target}/users/v1/login", creds)
        token = json.loads(login).get("auth_token", "")
        if not token:
            raise SystemExit(f"vampi_setup: login as {owner} returned no auth_token: {login[:200]}")
        status, body = _request(
            "POST", f"{target}/books/v1", {"book_title": obj["id"], "secret": obj["signature"]}, token
        )
        if status != 200:
            raise SystemExit(f"vampi_setup: creating book {obj['id']!r} failed: HTTP {status}: {body[:200]}")

    spec = _retry("fetching /openapi.json", "GET", f"{target}/openapi.json")
    os.makedirs(out_dir, exist_ok=True)
    paths = {
        "openapi": os.path.join(out_dir, "vampi-openapi.json"),
        "secrets": os.path.join(out_dir, "vampi-secrets.json"),
    }
    with open(paths["openapi"], "w", encoding="utf-8") as fh:
        fh.write(spec)
    with open(paths["secrets"], "w", encoding="utf-8") as fh:
        json.dump({f"vampi/{u}": {"username": u, "password": p} for u, p in ACCOUNTS.items()}, fh)
    return paths


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="http://127.0.0.1:5000")
    ap.add_argument("--out-dir", required=True, help="where to write the spec and secrets file")
    ap.add_argument("--seed", default=DEFAULT_SEED)
    args = ap.parse_args(argv)
    paths = setup(args.target, args.out_dir, args.seed)
    print(json.dumps(paths))
    return 0


if __name__ == "__main__":
    sys.exit(main())
