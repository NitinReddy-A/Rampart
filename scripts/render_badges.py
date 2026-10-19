"""Render the README's live badges (OpenSSF Scorecard score, latest release) as flat SVGs.

Why not shields.io: GitHub fetches README images through its camo proxy, which gives up after
~4s, and shields' dynamic badges are often slower than that — the Scorecard and release badges
(the same as on far busier repos) rendered as broken images. These SVGs are published to the
`badges` branch by .github/workflows/badges.yml and served from raw.githubusercontent.com, which
GitHub does not proxy. Stdlib only.

    python scripts/render_badges.py <out-dir> [--repo owner/name]
    python scripts/render_badges.py docs/assets/badges --static   # the fixed-text badges
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.request
from xml.sax.saxutils import escape

# Approximate advance widths of Verdana 11px (what shields' flat style is drawn in), so the
# badge is sized like the shields one it replaces.
_NARROW, _WIDE = set("fijlrt.,:;!|'()[]{} "), set("mwMW@%")


def _text_width(s: str) -> int:
    return round(sum(3.8 if c in _NARROW else 9.6 if c in _WIDE else 6.6 for c in s)) + 10


def score_color(score: float) -> str:
    """shields' colour ladder for the OpenSSF Scorecard score (brightgreen only at 10)."""
    for floor, color in ((10, "#44BB00"), (8, "#67AC09"), (5, "#95991A"), (2, "#D8B800")):
        if score >= floor:
            return color
    return "#DD4343"


def badge(label: str, value: str, color: str) -> str:
    """A shields-style "flat" badge: grey label, coloured value."""
    lw, vw = _text_width(label), _text_width(value)
    total = lw + vw
    label, value = escape(label, {'"': "&quot;"}), escape(value, {'"': "&quot;"})  # used in an attribute too
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" '
        f'aria-label="{label}: {value}"><title>{label}: {value}</title>'
        '<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/>'
        '<stop offset="1" stop-opacity=".1"/></linearGradient>'
        f'<clipPath id="r"><rect width="{total}" height="20" rx="3" fill="#fff"/></clipPath>'
        f'<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#555"/>'
        f'<rect x="{lw}" width="{vw}" height="20" fill="{color}"/>'
        f'<rect width="{total}" height="20" fill="url(#s)"/></g>'
        '<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" '
        'text-rendering="geometricPrecision" font-size="11">'
        f'<text x="{lw / 2}" y="15" fill="#010101" fill-opacity=".3">{label}</text>'
        f'<text x="{lw / 2}" y="14">{label}</text>'
        f'<text x="{lw + vw / 2}" y="15" fill="#010101" fill-opacity=".3">{value}</text>'
        f'<text x="{lw + vw / 2}" y="14">{value}</text></g></svg>\n'
    )


def _get_json(url: str, token: str = "") -> dict:
    headers = {"Accept": "application/json", "User-Agent": "rampart-badges"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as resp:
        return json.load(resp)


# Badges whose text only changes with the code; committed under docs/assets/badges/.
STATIC = {
    "python.svg": ("python", "3.10 – 3.13", "#3776AB"),
    "runtime-deps.svg": ("runtime deps", "0", "#2EA44F"),
    "benchmark.svg": ("benchmark", "100% precision · 100% recall", "#2EA44F"),
    "license.svg": ("license", "Apache-2.0", "#007EC6"),
    "website.svg": ("website", "rampart.dpdns.org", "#0284C7"),
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("out_dir")
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", "NitinReddy-A/Rampart"))
    ap.add_argument("--static", action="store_true", help="render the fixed-text badges instead")
    args = ap.parse_args()

    if args.static:
        rendered = {name: badge(*spec) for name, spec in STATIC.items()}
        summary = ", ".join(STATIC)
    else:
        token = os.environ.get("GH_TOKEN", "")
        score = float(_get_json(f"https://api.scorecard.dev/projects/github.com/{args.repo}")["score"])
        tag = str(_get_json(f"https://api.github.com/repos/{args.repo}/releases/latest", token)["tag_name"])
        rendered = {
            "scorecard.svg": badge("openssf scorecard", f"{score:.1f}", score_color(score)),
            "release.svg": badge("release", tag, "#4F46E5"),
        }
        summary = f"scorecard {score:.1f}, release {tag}"

    os.makedirs(args.out_dir, exist_ok=True)
    for name, svg in rendered.items():
        with open(os.path.join(args.out_dir, name), "w", encoding="utf-8", newline="\n") as fh:
            fh.write(svg)
    print(f"{summary} -> {args.out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
