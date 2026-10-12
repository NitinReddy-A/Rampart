"""Render captured terminal output (with ANSI colours) as an SVG terminal window.

Used for the README hero, docs/assets/rampart-console.svg: it is real `rampart test` output
from the bundled demo app, not a mock-up. To regenerate it after the CLI output changes:

    python examples/demo_target/vulnerable_app.py --port 8080 &
    cd examples/demo_target
    python -c "import sys, rampart.cli as c; c._USE_COLOR = True; sys.exit(c.main(sys.argv[1:]))" \\
        test --scope-file rampart.scope.yaml --target http://127.0.0.1:8080 --openapi openapi.json \\
        --appmodel-seed appmodel_seed.json --secrets secrets.json --repo . --deep \\
        --report html,sarif > /tmp/rampart.ansi
    python scripts/render_terminal_svg.py /tmp/rampart.ansi docs/assets/rampart-console.svg \\
        --from "  Results" --before 2 --rows 39 --animate

The window shows a contiguous slice of the output, the way a terminal scrolled back to it would
(`--from` is the first line that matches, `--before` lines of context above it, `--rows` screen
rows after wrapping at `--cols`). Nothing is rewritten: every character comes from the capture.
With `--animate` the rows print in one at a time behind a block cursor, as the CLI writes them,
then the final frame stays; without CSS animation (or with prefers-reduced-motion) the SVG is
simply that final frame. Stdlib only.
"""

from __future__ import annotations

import argparse
import re
from xml.sax.saxutils import escape

# One Dark — a common terminal theme (bg, fg, and the ANSI colours the CLI uses).
BG = "#282c34"
FG = "#abb2bf"
TITLE_BG = "#21252b"
ANSI = {
    30: "#3f4451",
    31: "#e06c75",
    32: "#98c379",
    33: "#e5c07b",
    34: "#61afef",
    35: "#c678dd",
    36: "#56b6c2",
    37: "#d7dae0",
}

FONT = "ui-monospace, 'SF Mono', Menlo, Monaco, 'Cascadia Mono', Consolas, 'DejaVu Sans Mono', monospace"
UI_FONT = "-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif"
FONT_SIZE = 12.5
CHAR_W = FONT_SIZE * 0.602  # Menlo / SF Mono / DejaVu advance; Consolas is narrower, so it still fits
LINE_H = 17
PAD_X, PAD_Y = 14, 10
TITLE_H = 28
MARGIN = 28  # room for the window shadow

# --animate pacing (seconds): when the first row prints, the gap between rows (dim rows, such as
# dropped candidates, print faster), and the pause before a blank row (the CLI writing reports).
START, STEP, STEP_DIM, PAUSE = 0.5, 0.07, 0.035, 0.8

_SGR = re.compile(r"\x1b\[([0-9;]*)m")


def _mix(a: str, b: str, t: float) -> str:
    """Blend colour ``a`` toward ``b`` by ``t`` (how terminals render SGR 2 'dim')."""
    ca = [int(a[i : i + 2], 16) for i in (1, 3, 5)]
    cb = [int(b[i : i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(ca, cb))


def parse(line: str) -> list[tuple[str, dict]]:
    """Split one line into (text, style) runs following its SGR escape codes."""
    runs, style, pos = [], {}, 0
    for m in _SGR.finditer(line):
        if m.start() > pos:
            runs.append((line[pos : m.start()], dict(style)))
        for code in [int(c) for c in (m.group(1) or "0").split(";") if c] or [0]:
            if code == 0:
                style = {}
            elif code == 1:
                style["bold"] = True
            elif code == 2:
                style["dim"] = True
            elif code in ANSI:
                style["fg"] = ANSI[code]
        pos = m.end()
    if pos < len(line):
        runs.append((line[pos:], dict(style)))
    return runs


def wrap(runs: list[tuple[str, dict]], cols: int) -> list[list[tuple[str, dict]]]:
    """Hard-wrap at ``cols`` characters, as the terminal does."""
    rows, row, width = [], [], 0
    for text, style in runs:
        while text:
            take = text[: cols - width]
            row.append((take, style))
            width += len(take)
            text = text[len(take) :]
            if width == cols and text:
                rows.append(row)
                row, width = [], 0
    rows.append(row)
    return rows


def _tspan(text: str, style: dict) -> str:
    fill = style.get("fg", FG)
    if style.get("dim"):
        fill = _mix(fill, BG, 0.45)
    attrs = f' fill="{fill}"' if fill != FG else ""
    if style.get("bold"):
        attrs += ' font-weight="700"'
    # no-break spaces: SVG collapses runs of ordinary spaces, and the CLI's indentation is columnar
    body = escape(text).replace(" ", " ")
    return f"<tspan{attrs}>{body}</tspan>" if attrs else body


def schedule(screen) -> list[float]:
    """When each row prints. Rows wrapped from one line print together, as a terminal shows them."""
    times, t, prev = [], START, None
    for i, (line, row) in enumerate(screen):
        if i and line != prev:
            text = "".join(x for x, _ in row).strip()
            if not text:
                t += PAUSE
            else:
                t += STEP_DIM if all(st.get("dim") for x, st in row if x.strip()) else STEP
        times.append(round(t, 3))
        prev = line
    return times


def _animation(screen, times) -> list[str]:
    """CSS for --animate: each row is hidden until its print time; a block cursor marks the next row."""
    end = times[-1] + STEP
    frames = ["0% { transform: translateY(0px); opacity: 1; }"]
    for r, t in enumerate(times):
        if r + 1 < len(screen) and screen[r + 1][0] == screen[r][0]:
            continue  # the cursor lands after the last row of a wrapped line
        frames.append(f"{100 * t / end:.2f}% {{ transform: translateY({(r + 1) * LINE_H}px); }}")
    frames.append("100% { opacity: 0; }")
    return [
        "<style>",
        ".p { animation: p 1ms backwards; }",
        "@keyframes p { from { opacity: 0; } }",
        f".cur {{ animation: cur {end:.2f}s step-end forwards; }}",
        "@keyframes cur { " + " ".join(frames) + " }",
        "@media (prefers-reduced-motion: reduce) { .p, .cur { animation: none; } }",
        "</style>",
    ]


def render(screen, cols, title, total_rows, first_row, label, animate=False) -> str:
    rows = len(screen)
    times = schedule(screen) if animate else []
    win_w = round(PAD_X * 2 + cols * CHAR_W)
    win_h = TITLE_H + PAD_Y * 2 + rows * LINE_H
    w, h = win_w + MARGIN * 2, win_h + MARGIN * 2
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" '
        f'role="img" aria-label="{escape(label)}">',
        f"<title>{escape(label)}</title>",
        "<defs>",
        '<filter id="shadow" x="-10%" y="-10%" width="120%" height="125%">'
        '<feDropShadow dx="0" dy="8" stdDeviation="11" flood-color="#000" flood-opacity="0.35"/></filter>',
        f'<clipPath id="win"><rect width="{win_w}" height="{win_h}" rx="10"/></clipPath>',
        "</defs>",
        *(_animation(screen, times) if animate else []),
        f'<g transform="translate({MARGIN} {MARGIN - 6})">',
        f'<rect width="{win_w}" height="{win_h}" rx="10" fill="{BG}" filter="url(#shadow)"/>',
        '<g clip-path="url(#win)">',
        f'<rect width="{win_w}" height="{TITLE_H}" fill="{TITLE_BG}"/>',
        f'<rect y="{TITLE_H}" width="{win_w}" height="1" fill="#000" fill-opacity="0.35"/>',
    ]
    for i, (fill, stroke) in enumerate(
        (("#ff5f57", "#e0443e"), ("#febc2e", "#dea123"), ("#28c840", "#1aab29"))
    ):
        out.append(
            f'<circle cx="{18 + i * 20}" cy="{TITLE_H / 2}" r="6" fill="{fill}" stroke="{stroke}" stroke-width="0.5"/>'
        )
    out.append(
        f'<text x="{win_w / 2}" y="{TITLE_H / 2 + 4.5}" text-anchor="middle" font-family="{UI_FONT}" '
        f'font-size="12.5" font-weight="600" fill="#8b919c">{escape(title)}</text>'
    )
    # scrolled-back position, as an overlay scrollbar thumb
    track_y, track_h = TITLE_H + 4, win_h - TITLE_H - 8
    thumb_h = max(18, track_h * rows / total_rows)
    thumb_y = track_y + (track_h - thumb_h) * first_row / max(1, total_rows - rows)
    out.append(
        f'<rect x="{win_w - 9}" y="{thumb_y:.1f}" width="5" height="{thumb_h:.1f}" rx="2.5" '
        'fill="#fff" fill-opacity="0.22"/>'
    )
    out.append(f'<g font-family="{FONT}" font-size="{FONT_SIZE}" fill="{FG}">')
    for r, (_line, row) in enumerate(screen):
        y = TITLE_H + PAD_Y + (r + 1) * LINE_H - 4.5
        body = "".join(_tspan(t, s) for t, s in row if t)
        if not body:
            continue
        anim = f' class="p" style="animation-delay:{times[r]}s"' if animate else ""
        out.append(f'<text x="{PAD_X}"{anim} y="{y}">{body}</text>')
    out.append("</g>")
    if animate:
        # hidden unless animating, so a static render never shows a stray cursor
        out.append(
            f'<rect class="cur" x="{PAD_X}" y="{TITLE_H + PAD_Y + 1}" width="{CHAR_W:.2f}" '
            f'height="{LINE_H - 2}" fill="{FG}" opacity="0"/>'
        )
    out += ["</g>", "</g>", "</svg>"]
    return "\n".join(out) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", help="terminal output with ANSI colour codes")
    ap.add_argument("out", help="SVG to write")
    ap.add_argument("--from", dest="start", required=True, help="first line of the slice (prefix match)")
    ap.add_argument("--before", type=int, default=0, help="lines of context above --from")
    ap.add_argument("--rows", type=int, default=36, help="screen rows")
    ap.add_argument("--cols", type=int, default=110, help="screen columns")
    ap.add_argument("--title", default="demo_target — -zsh — {cols}×{rows}")
    ap.add_argument("--label", default="Rampart terminal output")
    ap.add_argument("--animate", action="store_true", help="print the rows in one at a time")
    args = ap.parse_args(argv)

    with open(args.capture, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    plain = [_SGR.sub("", ln) for ln in lines]
    start = next(i for i, ln in enumerate(plain) if ln.startswith(args.start))
    start = max(0, start - args.before)
    screen_rows = [(i, row) for i, ln in enumerate(lines) for row in wrap(parse(ln), args.cols)]
    first_row = sum(len(wrap(parse(ln), args.cols)) for ln in lines[:start])
    screen = screen_rows[first_row : first_row + args.rows]
    title = args.title.format(cols=args.cols, rows=args.rows)
    svg = render(screen, args.cols, title, len(screen_rows), first_row, args.label, args.animate)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(svg)
    print(f"{args.out}: rows {first_row}-{first_row + len(screen)} of {len(screen_rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
