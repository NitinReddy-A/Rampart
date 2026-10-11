"""The README's self-rendered badges (scripts/render_badges.py): valid SVG, escaped text, and
shields' colour ladder for the Scorecard score."""

import importlib.util
import os
import xml.dom.minidom

_PATH = os.path.join(os.path.dirname(__file__), "..", "scripts", "render_badges.py")
_spec = importlib.util.spec_from_file_location("render_badges", _PATH)
render_badges = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(render_badges)


def test_badge_is_well_formed_svg_with_escaped_text():
    svg = render_badges.badge("release", 'v1.2.0<script>&"', "#4F46E5")
    doc = xml.dom.minidom.parseString(svg)
    assert doc.documentElement.tagName == "svg"
    assert "<script>" not in svg and "&lt;script&gt;" in svg
    assert doc.documentElement.getAttribute("height") == "20"


def test_scorecard_colour_ladder_matches_shields():
    color = render_badges.score_color
    assert color(10) == "#44BB00" and color(8.2) == "#67AC09" and color(5) == "#95991A"
    assert color(2.5) == "#D8B800" and color(0) == "#DD4343"


def test_wider_text_gives_a_wider_badge():
    narrow = xml.dom.minidom.parseString(render_badges.badge("a", "1", "#000")).documentElement
    wide = xml.dom.minidom.parseString(
        render_badges.badge("openssf scorecard", "8.2", "#000")
    ).documentElement
    assert int(wide.getAttribute("width")) > int(narrow.getAttribute("width"))
