#!/usr/bin/env python3
"""Compose several real terminal-frame SVGs into one autoplaying "cast".

Each input SVG is already real captured Kintsugi output (see gen_svg.py). This
stacks them on one dark canvas and cycles through them with SMIL `<animate>`
(calcMode=discrete), so the result loops on its own and animates even when used
as an <img> (site and GitHub README). No external tools, fully deterministic.

Usage: gen_cast_svg.py <out.svg> <dwell_seconds> <in1.svg> [in2.svg ...]
"""
import re
import sys

BG = "#070a11"
PAD = 22
CAPTION_H = 30
CAP = "#8b95ad"
FRAMES_CAP = [
    "an agent proposes a destructive command — Kintsugi holds it before it runs",
    "you deny it; the attempt lands on the tamper-evident timeline",
    "the live TUI: cross-agent timeline, detail, and a risk meter",
]

DIM = re.compile(r'<svg[^>]*\bwidth="(\d+)"[^>]*\bheight="(\d+)"', re.DOTALL)


def parts(path):
    """Return (inner_svg_markup, width, height) for one frame SVG."""
    svg = open(path, encoding="utf-8").read()
    m = DIM.search(svg)
    w, h = int(m.group(1)), int(m.group(2))
    inner = svg[svg.index(">", m.start()) + 1 : svg.rindex("</svg>")]
    return inner, w, h


def main():
    out, dwell, ins = sys.argv[1], float(sys.argv[2]), sys.argv[3:]
    frames = [parts(p) for p in ins]
    n = len(frames)
    body_w = max(w for _, w, _ in frames)
    body_h = max(h for _, _, h in frames)
    canvas_w = body_w + PAD * 2
    canvas_h = body_h + PAD * 2 + CAPTION_H
    total = dwell * n

    # keyTimes for N discrete slots: N+1 boundaries 0..1.
    kt = ";".join(f"{i / n:.4f}" for i in range(n + 1))

    p = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{canvas_w}" height="{canvas_h}" '
        f'viewBox="0 0 {canvas_w} {canvas_h}" '
        f'font-family="ui-monospace,DejaVu Sans Mono,Consolas,monospace">',
        f'<rect width="{canvas_w}" height="{canvas_h}" rx="10" fill="{BG}"/>',
    ]

    for i, (inner, w, h) in enumerate(frames):
        dx = PAD + (body_w - w) // 2
        dy = PAD + (body_h - h) // 2
        # opacity is 1 only during this frame's slot; discrete switch, looping.
        vals = ";".join("1" if k == i else "0" for k in range(n + 1))
        p.append(f'<g opacity="0" transform="translate({dx},{dy})">')
        p.append(
            f'<animate attributeName="opacity" calcMode="discrete" '
            f'dur="{total:g}s" repeatCount="indefinite" keyTimes="{kt}" values="{vals}"/>'
        )
        p.append(inner)
        p.append("</g>")

        # Caption for this frame (same cycle), centered under the body.
        cap = FRAMES_CAP[i] if i < len(FRAMES_CAP) else ""
        cy = PAD * 2 + body_h + 4
        p.append(
            f'<text x="{canvas_w / 2:.0f}" y="{cy}" font-size="14" fill="{CAP}" '
            f'text-anchor="middle" opacity="0">'
            f'<animate attributeName="opacity" calcMode="discrete" dur="{total:g}s" '
            f'repeatCount="indefinite" keyTimes="{kt}" values="{vals}"/>{cap}</text>'
        )

    p.append("</svg>")
    open(out, "w", encoding="utf-8").write("\n".join(p))
    print(f"wrote {out} ({canvas_w}x{canvas_h}, {n} frames, {total:g}s loop)")


if __name__ == "__main__":
    main()
