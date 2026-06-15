#!/usr/bin/env python3
"""Render a captured terminal frame (plain text) into a styled 8-bit SVG.

Deterministic, dependency-free. Each SVG is a "terminal window" card matching the
Aegis site theme, so docs and the website show real captured output as images.

Usage: gen_svg.py <in.txt> <out.svg> "<title>" [tokenrule ...]
  tokenrule = SUBSTRING=COLORKEY   (colorkey: red|amber|green|cyan|dim|bold)
"""
import sys, html

PAL = {
    "bg": "#070a11", "barbg": "#141c30", "line": "#283557", "ink": "#cdd6e6",
    "red": "#ff5d5d", "amber": "#ffd866", "green": "#5af78e", "cyan": "#6bd6ff",
    "dim": "#8b95ad", "bold": "#ffffff",
}
# CHARW is a safe upper bound on the real monospace advance at FS=15 (DejaVu Sans
# Mono ≈9.03px); undersizing it clips the longest line and the TUI risk gauge.
CHARW, LINEH, FS = 9.1, 20, 15
PADX, TOP = 18, 44  # title bar height ~36 + gap

def grid_x(n):
    """Explicit x position for each of n glyphs on the monospace grid."""
    return " ".join(f"{PADX + k * CHARW:.1f}" for k in range(n)) if n else str(PADX)

def colorize(line, rules):
    """Split a line into (text,color) segments by non-overlapping token rules."""
    segs, i, n = [], 0, len(line)
    while i < n:
        hit = None
        for tok, col in rules:
            if tok and line.startswith(tok, i):
                if hit is None or len(tok) > len(hit[0]):
                    hit = (tok, col)
        if hit:
            segs.append((hit[0], PAL[hit[1]])); i += len(hit[0])
        else:
            j = i
            while j < n:
                if any(tok and line.startswith(tok, j) for tok, _ in rules):
                    break
                j += 1
            segs.append((line[i:j], PAL["ink"])); i = j
    return segs or [("", PAL["ink"])]

def main():
    src, out, title = sys.argv[1], sys.argv[2], sys.argv[3]
    rules = []
    for a in sys.argv[4:]:
        k, _, v = a.partition("=")
        rules.append((k, v))
    rules.sort(key=lambda r: -len(r[0]))
    lines = open(src, encoding="utf-8").read().rstrip("\n").split("\n")
    cols = max((len(l) for l in lines), default=20)
    W = int(PADX * 2 + cols * CHARW)
    H = int(TOP + len(lines) * LINEH + 16)

    p = []
    p.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" '
             f'viewBox="0 0 {W} {H}" font-family="ui-monospace,DejaVu Sans Mono,Consolas,monospace">')
    p.append(f'<rect x="1" y="1" width="{W-2}" height="{H-2}" rx="8" fill="{PAL["bg"]}" '
             f'stroke="{PAL["line"]}" stroke-width="3"/>')
    p.append(f'<rect x="1" y="1" width="{W-2}" height="34" rx="8" fill="{PAL["barbg"]}"/>')
    p.append(f'<rect x="1" y="20" width="{W-2}" height="15" fill="{PAL["barbg"]}"/>')
    for k, cx in (("red", 18), ("amber", 36), ("green", 54)):
        p.append(f'<rect x="{cx}" y="12" width="11" height="11" fill="{PAL[k]}"/>')
    p.append(f'<text x="74" y="22" font-size="11" fill="{PAL["dim"]}">{html.escape(title)}</text>')

    y = TOP + 4
    for line in lines:
        # Pin every glyph to an explicit x = PADX + col*CHARW so box-drawing
        # chars (│ ─ ╭) can't drift the columns, regardless of how the fallback
        # monospace font advances them. Critically, emit the whole <text> on a
        # single line — with xml:space="preserve", newlines between </tspan> and
        # the next <tspan> become real characters that consume positions from
        # the x list, shifting every later tspan right (this is exactly what
        # Chrome was doing while Firefox/Safari collapsed it).
        xs = grid_x(len(line))
        tspans = "".join(
            f'<tspan fill="{col}">{html.escape(txt).replace(" ", "&#160;")}</tspan>'
            for txt, col in colorize(line, rules)
            if txt
        )
        # Note: no xml:space="preserve". Visible spaces are already &#160; (nbsp),
        # so we don't need preserve mode — and dropping it means newlines around
        # tspans inside this <text> are default-collapsed and can't consume x
        # slots from the grid list.
        p.append(f'<text x="{xs}" y="{y}" font-size="{FS}">{tspans}</text>')
        y += LINEH
    p.append("</svg>")
    open(out, "w", encoding="utf-8").write("\n".join(p))
    print("wrote", out, f"({W}x{H})")

if __name__ == "__main__":
    main()
