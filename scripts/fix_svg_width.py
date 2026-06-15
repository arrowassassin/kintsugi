#!/usr/bin/env python3
"""Widen gen_svg.py terminal-frame SVGs so no line clips on the right.

gen_svg.py sized frames at CHARW=8.6 px/glyph, but the fallback monospace fonts
(DejaVu Sans Mono ≈9.03 px at font-size 15) advance wider, so the longest line —
and the TUI risk gauge — overflowed the frame. This recomputes each frame's width
from its actual glyph count at a safe advance and rewrites the width/viewBox and
the three full-width background rects. Content (text, colors) is untouched.

Usage: fix_svg_width.py <file.svg> [<file.svg> ...]
"""
import re
import sys

PADX = 18
CHARW = 9.1  # monospace cell width at font-size 15 (close to the real advance)

# Body lines are the font-size 15 <text> rows (the title is font-size 11).
TEXT_BODY = re.compile(r'<text [^>]*font-size="15"[^>]*>(.*?)</text>', re.DOTALL)
BODY_ELEM = re.compile(r'(<text [^>]*font-size="15"[^>]*)>(.*?)</text>', re.DOTALL)
TSPAN = re.compile(r"<tspan[^>]*>(.*?)</tspan>", re.DOTALL)


def grid_x(n: int) -> str:
    return " ".join(f"{PADX + k * CHARW:.1f}" for k in range(n)) if n else str(PADX)


def glyphs(inner: str) -> int:
    """Count rendered glyphs in the tspans of one <text> line."""
    total = 0
    for body in TSPAN.findall(inner):
        # &#160; (nbsp) and &amp;/&lt;/&gt; each render as one glyph.
        s = body.replace("&#160;", " ")
        s = s.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        total += len(s)
    return total


def is_frame(svg: str) -> bool:
    # The title-bar squaring rect is unique to gen_svg.py output.
    return '<rect x="1" y="20"' in svg


def inject_grid(svg: str) -> str:
    """Pin every body line to an explicit per-glyph x list, drop xml:space=
    "preserve" (visible spaces are already &#160;), and strip whitespace
    around/between tspans inside each <text>. Under preserve mode, Chrome
    treats every newline between <text>/<tspan>/</tspan>/</text> as a real
    character that eats a slot from the x list, which shifted every later
    colored span right — that's the drift we kept seeing in the browser even
    after pinning the grid."""

    inter_tspan = re.compile(r"</tspan>\s+<tspan")

    def repl(m: "re.Match[str]") -> str:
        tag = re.sub(r'\s+(?:textLength|lengthAdjust|xml:space)="[^"]*"', "", m.group(1))
        # Strip the leading/trailing whitespace between <text> and its first
        # tspan and between the last tspan and </text>, plus any whitespace
        # between adjacent tspans. Each of these is a real character under
        # xml:space="preserve" that consumes a slot from the x grid.
        inner = inter_tspan.sub("</tspan><tspan", m.group(2)).strip()
        tag = re.sub(r'\bx="[^"]*"', f'x="{grid_x(glyphs(inner))}"', tag, count=1)
        return f"{tag}>{inner}</text>"

    return BODY_ELEM.sub(repl, svg)


def fix(path: str) -> bool:
    svg = open(path, encoding="utf-8").read()
    if not is_frame(svg):
        print(f"skip   {path} (not a terminal-frame SVG)")
        return False
    orig = svg

    max_glyphs = max((glyphs(m) for m in TEXT_BODY.findall(svg)), default=0)
    if max_glyphs == 0:
        # A frame with no text body lines (e.g. the flow diagram) — leave it alone.
        print(f"skip   {path} (no text rows)")
        return False
    # Width = grid span + a right margin matching the left pad. Always set it
    # (grow or shrink) so the frame fits the pinned grid exactly.
    new_w = int(PADX + max_glyphs * CHARW + PADX + 0.999)
    m = re.search(r'<svg[^>]*\bwidth="(\d+)"', svg)
    old_w = int(m.group(1))
    if new_w != old_w:
        svg = re.sub(r'(<svg[^>]*\bwidth=")\d+(")', rf"\g<1>{new_w}\g<2>", svg, count=1)
        svg = re.sub(r'(viewBox="0 0 )\d+( \d+")', rf"\g<1>{new_w}\g<2>", svg, count=1)
        svg = svg.replace(f'width="{old_w - 2}"', f'width="{new_w - 2}"')

    svg = inject_grid(svg)

    if svg == orig:
        print(f"ok     {path} ({old_w}px, {max_glyphs} glyphs)")
        return False
    open(path, "w", encoding="utf-8").write(svg)
    print(f"fixed  {path}: width {old_w}->{new_w}, grid pinned ({max_glyphs} glyphs)")
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: fix_svg_width.py <file.svg> [...]")
    for p in sys.argv[1:]:
        fix(p)
