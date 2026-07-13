#!/usr/bin/env python3
"""Generate ADRS byte-layout diagrams for SHRINCS.

Produces, for the stateless (SL_*) and stateful (SF_*) ADRS type families,
a proportional 22-byte strip per type:

    stateless: layer (1B)       | tree_address (8B) | type (1B) | payload (12B, per-type split)
    stateful:  node_height (1B) | node_index (8B)   | type (1B) | payload (12B, per-type split)

Outputs (next to this script):
    adrs-stateless.svg / .drawio
    adrs-stateful.svg  / .drawio

Style follows img/wots-diagram-generic.svg: Arial, light-gray rounded boxes
(#e0e0e0), thin strokes, purple accent (#633FD6).

Data source: SHRINCS.md "ADRS Format / Types / Payloads" tables.
"""

import os
import html

# ---------------------------------------------------------------------------
# Data model. Each entry: (name, type_value, [(field_label, n_bytes, kind), ...])
# kind in {"active", "pad"} describes the 12-byte payload subfields.
# ---------------------------------------------------------------------------

STATELESS = [
    ("SL_WOTS_TW_HASH", 0,  [("key pair index", 4, "active"), ("chain index", 4, "active"), ("hash index", 4, "active")]),
    ("SL_WOTS_TW_PK",   1,  [("key pair index", 4, "active"), ("zero padding", 8, "pad")]),
    ("SL_XMSS_TREE",    2,  [("zero padding", 4, "pad"), ("tree height", 4, "active"), ("tree index", 4, "active")]),
    ("SL_FORS_TREE",    3,  [("key pair index", 4, "active"), ("tree height", 4, "active"), ("tree index", 4, "active")]),
    ("SL_FORS_ROOTS",   4,  [("key pair index", 4, "active"), ("zero padding", 8, "pad")]),
    ("SL_WOTS_TW_PRF",  5,  [("key pair index", 4, "active"), ("chain index", 4, "active"), ("zero padding", 4, "pad")]),
    ("SL_FORS_PRF",     6,  [("key pair index", 4, "active"), ("zero padding", 4, "pad"), ("tree index", 4, "active")]),
]

STATEFUL = [
    ("SF_WOTS_C_HASH",  16, [("zero padding", 4, "pad"), ("chain index", 4, "active"), ("hash index", 4, "active")]),
    ("SF_WOTS_C_PK",    17, [("zero padding", 12, "pad")]),
    ("SF_FXMSS_TREE",   18, [("zero padding", 12, "pad")]),
    ("SF_WOTS_C_PRF",   21, [("zero padding", 4, "pad"), ("chain index", 4, "active"), ("zero padding", 4, "pad")]),
    ("SF_WOTS_C_GRIND", 22, [("zero padding", 12, "pad")]),
]

# Common-header field names: (1-byte field, 8-byte field), per ADRS family.
STATELESS_HEADER = ("layer", "tree_address")
STATEFUL_HEADER = ("node_height", "node_index")

# ---------------------------------------------------------------------------
# Layout constants
# ---------------------------------------------------------------------------
FONT = "Arial, Helvetica, sans-serif"
C_BG            = "#141414"   # page background (dark theme)
C_HEADER_FILL   = "#3a3a3e"   # layer / tree_address (schema header)
C_HEADER_STROKE = "#5c5c62"
C_MUTED_FILL    = "#242426"   # layer / tree_address inside per-type rows
C_MUTED_STROKE  = "#3c3c40"
C_MUTED_TEXT    = "#9a9ea3"
C_TYPE_FILL     = "#7c5cff"   # the discriminating `type` byte
C_TYPE_TEXT     = "#ffffff"
C_ACTIVE_FILL   = "#33285f"   # meaningful payload fields
C_ACTIVE_STROKE = "#8b6fff"
C_ACTIVE_TEXT   = "#ffffff"
C_PAD_FILL      = "#1f1f21"   # zero padding
C_PAD_STROKE    = "#3a3a3e"
C_PAD_TEXT      = "#8a8e92"
C_GRID          = "#3a3a3e"
C_TEXT          = "#f2f2f2"
C_TICK          = "#8a8e92"

BW   = 24      # byte width (px) -> proportional strips
BOXH = 44
PITCH = 70
LABELW = 196
LEFT = 20
RIGHT = 24
STRIPX = LEFT + LABELW
STRIPW = 22 * BW
WIDTH = STRIPX + STRIPW + RIGHT

TITLE_Y = 34
NOTE_Y = 54
RULER_Y = 86          # baseline for byte-offset numbers
SCHEMA_Y = 94         # top of schema header boxes
ROWS_Y = SCHEMA_Y + BOXH + 42  # top of first per-type row


def esc(s):
    return html.escape(s, quote=True)


def wrap_label(label, box_w, base_fs=11):
    """Return (lines, font_size) fitting the label into box_w."""
    words = label.split()
    fs = base_fs
    if box_w < 50:
        fs = 9
    elif box_w < 80:
        fs = 10

    def fits(text, f):
        return len(text) * 0.56 * f <= box_w - 6

    if fits(label, fs):
        return [label], fs
    # a single snake_case word may wrap after its last underscore
    if len(words) == 1 and "_" in label[1:-1]:
        i = label.rindex("_", 1, -1)
        words = [label[:i + 1], label[i + 1:]]
    # try a two-line balanced split
    if len(words) >= 2:
        best = None
        for i in range(1, len(words)):
            a = " ".join(words[:i])
            b = " ".join(words[i:])
            cost = abs(len(a) - len(b))
            if best is None or cost < best[0]:
                best = (cost, a, b)
        a, b = best[1], best[2]
        while not (fits(a, fs) and fits(b, fs)) and fs > 8:
            fs -= 1
        return [a, b], fs
    if fs > 8:
        fs = 8
    return [label], fs


# ---------------------------------------------------------------------------
# SVG generation
# ---------------------------------------------------------------------------

def svg_box(x, w, fill, stroke, label_lines, fs, text_color, italic=False,
            byte_count=None, weight="400"):
    out = []
    out.append(f'<rect x="{x:.1f}" y="0" width="{w:.1f}" height="{BOXH}" rx="3" '
               f'fill="{fill}" stroke="{stroke}" stroke-width="1"/>')
    # internal byte gridlines
    nb = int(round(w / BW))
    for k in range(1, nb):
        gx = x + k * BW
        out.append(f'<line x1="{gx:.1f}" y1="2" x2="{gx:.1f}" y2="{BOXH-2}" '
                   f'stroke="{C_GRID}" stroke-width="0.75"/>')
    cx = x + w / 2
    n = len(label_lines)
    # vertical centering; leave room for byte-count annotation
    has_bc = byte_count is not None
    block_h = n * (fs + 2)
    cy = (BOXH - (block_h + (12 if has_bc else 0))) / 2 + fs
    style = f'font-family:{FONT};font-size:{fs}px;font-weight:{weight};fill:{text_color}'
    if italic:
        style += ';font-style:italic'
    for i, ln in enumerate(label_lines):
        ly = cy + i * (fs + 2)
        out.append(f'<text x="{cx:.1f}" y="{ly:.1f}" text-anchor="middle" '
                   f'style="{style}">{esc(ln)}</text>')
    if has_bc:
        by = cy + (n - 1) * (fs + 2) + 12
        out.append(f'<text x="{cx:.1f}" y="{by:.1f}" text-anchor="middle" '
                   f'style="font-family:{FONT};font-size:8px;fill:{text_color};opacity:0.7">'
                   f'{byte_count} B</text>')
    return out


def svg_strip_group(y, fields, muted_header):
    """fields: list of (label, n_bytes, kind, special). Returns svg string at given y."""
    parts = [f'<g transform="translate({STRIPX},{y})">']
    x = 0.0
    for (label, nb, kind, special) in fields:
        w = nb * BW
        if kind == "header":
            fill, stroke, tc, it, wt = (C_MUTED_FILL, C_MUTED_STROKE, C_MUTED_TEXT, False, "400") \
                if muted_header else (C_HEADER_FILL, C_HEADER_STROKE, C_TEXT, False, "400")
        elif kind == "type":
            fill, stroke, tc, it, wt = C_TYPE_FILL, C_TYPE_FILL, C_TYPE_TEXT, False, "700"
        elif kind == "active":
            fill, stroke, tc, it, wt = C_ACTIVE_FILL, C_ACTIVE_STROKE, C_ACTIVE_TEXT, False, "400"
        else:  # pad
            fill, stroke, tc, it, wt = C_PAD_FILL, C_PAD_STROKE, C_PAD_TEXT, True, "400"
        lines, fs = wrap_label(label, w)
        parts += svg_box(x, w, fill, stroke, lines, fs, tc, italic=it,
                         byte_count=nb if special != "noBC" else None, weight=wt)
        x += w
    parts.append('</g>')
    return "\n".join(parts)


def build_svg(title, rows, header):
    hdr1, hdr8 = header
    n = len(rows)
    height = ROWS_Y + (n - 1) * PITCH + BOXH + 64  # + legend
    s = []
    s.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height}" '
             f'viewBox="0 0 {WIDTH} {height}" font-family="{FONT}">')
    s.append(f'<rect x="0" y="0" width="{WIDTH}" height="{height}" fill="{C_BG}"/>')
    # title + note
    s.append(f'<text x="{LEFT}" y="{TITLE_Y}" style="font-family:{FONT};font-size:18px;'
             f'font-weight:700;fill:{C_TEXT}">{esc(title)}</text>')
    s.append(f'<text x="{LEFT}" y="{NOTE_Y}" style="font-family:{FONT};font-size:11px;'
             f'fill:{C_MUTED_TEXT}">22-byte address &#183; '
             f'{esc(hdr1)} (1) &#183; {esc(hdr8)} (8) &#183; type (1) &#183; payload (12). '
             f'Byte offsets shown above.</text>')

    # byte-offset ruler (0..22 at byte boundaries)
    for i in range(0, 23):
        gx = STRIPX + i * BW
        s.append(f'<line x1="{gx:.1f}" y1="{RULER_Y-6}" x2="{gx:.1f}" y2="{RULER_Y-1}" '
                 f'stroke="{C_TICK}" stroke-width="0.75"/>')
        s.append(f'<text x="{gx:.1f}" y="{RULER_Y-8:.1f}" text-anchor="middle" '
                 f'style="font-family:{FONT};font-size:7.5px;fill:{C_TICK}">{i}</text>')

    # schema header row
    schema = [
        (hdr1, 1, "header", None),
        (hdr8, 8, "header", None),
        ("type", 1, "header", None),
        ("payload", 12, "header", None),
    ]
    s.append(svg_strip_group(SCHEMA_Y, schema, muted_header=False))

    # per-type rows
    for idx, (name, val, payload) in enumerate(rows):
        y = ROWS_Y + idx * PITCH
        fields = [
            (hdr1, 1, "header", None),
            (hdr8, 8, "header", None),
            (str(val), 1, "type", None),
        ]
        for (lab, nb, kind) in payload:
            fields.append((lab, nb, kind, None))
        # left label: type name + value
        s.append(f'<text x="{LEFT}" y="{y+18:.1f}" style="font-family:{FONT};font-size:13px;'
                 f'font-weight:700;fill:{C_TEXT}">{esc(name)}</text>')
        s.append(f'<text x="{LEFT}" y="{y+34:.1f}" style="font-family:{FONT};font-size:10.5px;'
                 f'fill:{C_MUTED_TEXT}">type = {val}</text>')
        s.append(svg_strip_group(y, fields, muted_header=True))

    # legend
    ly = ROWS_Y + (n - 1) * PITCH + BOXH + 34
    legend = [
        (C_TYPE_FILL, C_TYPE_FILL, "type byte"),
        (C_ACTIVE_FILL, C_ACTIVE_STROKE, "active payload field"),
        (C_PAD_FILL, C_PAD_STROKE, "zero padding"),
        (C_MUTED_FILL, C_MUTED_STROKE, f"common header ({hdr1} / {hdr8})"),
    ]
    lx = LEFT
    for fill, stroke, lab in legend:
        s.append(f'<rect x="{lx}" y="{ly-11}" width="16" height="13" rx="2" '
                 f'fill="{fill}" stroke="{stroke}" stroke-width="1"/>')
        s.append(f'<text x="{lx+22}" y="{ly:.1f}" style="font-family:{FONT};font-size:10px;'
                 f'fill:{C_TEXT}">{esc(lab)}</text>')
        lx += 28 + len(lab) * 6.0 + 18
    s.append('</svg>')
    return "\n".join(s)


# ---------------------------------------------------------------------------
# draw.io generation (mxGraphModel)
# ---------------------------------------------------------------------------

def drawio_style(kind, muted):
    base = "rounded=1;arcSize=8;whiteSpace=wrap;html=1;fontFamily=Arial;fontSize=11;"
    if kind == "header":
        if muted:
            return base + f"fillColor={C_MUTED_FILL};strokeColor={C_MUTED_STROKE};fontColor={C_MUTED_TEXT};"
        return base + f"fillColor={C_HEADER_FILL};strokeColor={C_HEADER_STROKE};fontColor={C_TEXT};"
    if kind == "type":
        return base + f"fillColor={C_TYPE_FILL};strokeColor={C_TYPE_FILL};fontColor={C_TYPE_TEXT};fontStyle=1;"
    if kind == "active":
        return base + f"fillColor={C_ACTIVE_FILL};strokeColor={C_ACTIVE_STROKE};fontColor={C_ACTIVE_TEXT};"
    return base + f"fillColor={C_PAD_FILL};strokeColor={C_PAD_STROKE};fontColor={C_PAD_TEXT};fontStyle=2;"


def build_drawio(title, rows, header):
    hdr1, hdr8 = header
    cells = []
    cid = [1]

    def add(value, style, x, y, w, h):
        cid[0] += 1
        i = cid[0]
        v = esc(value)
        cells.append(f'<mxCell id="{i}" value="{v}" style="{style}" vertex="1" parent="1">'
                     f'<mxGeometry x="{x:.1f}" y="{y:.1f}" width="{w:.1f}" height="{h:.1f}" as="geometry"/></mxCell>')

    def add_text(value, x, y, w, h, fs=11, bold=False, color=C_TEXT):
        st = (f"text;html=1;align=left;verticalAlign=middle;fontFamily=Arial;fontSize={fs};"
              f"fontColor={color};" + ("fontStyle=1;" if bold else ""))
        add(value, st, x, y, w, h)

    add_text(title, LEFT, 8, 600, 24, fs=18, bold=True)
    add_text(f"22-byte address: {hdr1} (1) | {hdr8} (8) | type (1) | payload (12)",
             LEFT, 34, 600, 18, fs=11, color=C_MUTED_TEXT)

    # schema header
    schema = [(hdr1, 1, "header"), (hdr8, 8, "header"),
              ("type", 1, "header"), ("payload", 12, "header")]
    sx = STRIPX
    for lab, nb, kind in schema:
        add(f"{lab}\n({nb} B)", drawio_style(kind, False), sx, SCHEMA_Y, nb * BW, BOXH)
        sx += nb * BW

    for idx, (name, val, payload) in enumerate(rows):
        y = ROWS_Y + idx * PITCH
        add_text(name, LEFT, y, LABELW - 8, 18, fs=13, bold=True)
        add_text(f"type = {val}", LEFT, y + 18, LABELW - 8, 16, fs=10, color=C_MUTED_TEXT)
        fields = [(hdr1, 1, "header"), (hdr8, 8, "header"), (str(val), 1, "type")]
        fields += [(lab, nb, kind) for (lab, nb, kind) in payload]
        x = STRIPX
        for lab, nb, kind in fields:
            txt = lab if kind == "type" else f"{lab}\n({nb} B)"
            add(txt, drawio_style(kind, muted=(kind == "header")), x, y, nb * BW, BOXH)
            x += nb * BW

    body = "\n".join(cells)
    return (
        '<mxfile host="app.diagrams.net">\n'
        f'<diagram name="{esc(title)}">\n'
        '<mxGraphModel dx="800" dy="600" grid="0" gridSize="10" guides="1" tooltips="1" '
        f'connect="1" arrows="1" fold="1" page="1" pageScale="1" math="0" shadow="0" background="{C_BG}">\n'
        '<root>\n'
        '<mxCell id="0"/>\n<mxCell id="1" parent="0"/>\n'
        f'{body}\n'
        '</root>\n</mxGraphModel>\n</diagram>\n</mxfile>\n'
    )


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    targets = [
        ("Stateless ADRS types", STATELESS, STATELESS_HEADER, "adrs-stateless"),
        ("Stateful ADRS types", STATEFUL, STATEFUL_HEADER, "adrs-stateful"),
    ]
    for title, rows, header, base in targets:
        with open(os.path.join(here, base + ".svg"), "w", encoding="utf-8") as f:
            f.write(build_svg(title, rows, header))
        with open(os.path.join(here, base + ".drawio"), "w", encoding="utf-8") as f:
            f.write(build_drawio(title, rows, header))
        print("wrote", base + ".svg", "and", base + ".drawio")


if __name__ == "__main__":
    main()
