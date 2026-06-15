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
CHARW = 9.3  # safe upper bound on real monospace advance at font-size 15

TEXT_BODY = re.compile(r'<text x="18"[^>]*>(.*?)</text>', re.DOTALL)
TSPAN = re.compile(r"<tspan[^>]*>(.*?)</tspan>", re.DOTALL)


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


def fix(path: str) -> bool:
    svg = open(path, encoding="utf-8").read()
    if not is_frame(svg):
        print(f"skip   {path} (not a terminal-frame SVG)")
        return False

    max_glyphs = max((glyphs(m) for m in TEXT_BODY.findall(svg)), default=0)
    new_w = int(PADX * 2 + max_glyphs * CHARW + 0.999)

    m = re.search(r'<svg[^>]*\bwidth="(\d+)"', svg)
    old_w = int(m.group(1))
    if new_w <= old_w:
        print(f"ok     {path} (width {old_w} already fits {max_glyphs} glyphs)")
        return False

    # width="..." and viewBox="0 0 W H" on the root <svg>.
    svg = re.sub(r'(<svg[^>]*\bwidth=")\d+(")', rf"\g<1>{new_w}\g<2>", svg, count=1)
    svg = re.sub(r'(viewBox="0 0 )\d+( \d+")', rf"\g<1>{new_w}\g<2>", svg, count=1)
    # The three full-width background rects use width="OLD-2".
    svg = svg.replace(f'width="{old_w - 2}"', f'width="{new_w - 2}"')

    open(path, "w", encoding="utf-8").write(svg)
    print(f"widen  {path}: {old_w} -> {new_w} (longest line {max_glyphs} glyphs)")
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: fix_svg_width.py <file.svg> [...]")
    for p in sys.argv[1:]:
        fix(p)
