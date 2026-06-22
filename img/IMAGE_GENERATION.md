# Generating diagrams with Claude

This note records the workflow Claude uses to produce and verify the figures in
this repo (e.g. `adrs-stateless.svg`, `adrs-stateful.svg`). It is written for a
future Claude session so the approach is reproducible.

> **Important:** Claude cannot *paint* images. There is no image-generation model
> in this environment. Claude builds diagrams by **writing code/markup that
> renders deterministically** (SVG, draw.io XML, TikZ, Mermaid, matplotlib, …)
> and then **renders that to a raster to look at it**. This is the right approach
> for technical/spec diagrams anyway: they are exact, diffable, and editable.

## The loop

1. **Model the data, not the pixels.** Capture the figure's content as a small
   data structure (the byte-field tables, node lists, etc.). Keep it as the
   single source of truth.
2. **Write a generator** that turns that data into the output format(s). A short
   Python script is the most maintainable choice — see `gen_adrs_diagrams.py`.
3. **Render to PNG and actually look at it.** SVG/draw.io won't show up in the
   `Read` tool directly, so rasterize first (see below), then `Read` the PNG.
4. **Iterate** on spacing, wrapping, and color until it reads well.
5. **Clean up** temporary preview PNGs; commit only the source + final assets.

## Output formats used here

- **SVG** — the asset embedded in the Markdown spec. Hand-written/generated SVG
  is small, crisp at any zoom, and diffable in git.
- **`.drawio`** — an editable source (draw.io / diagrams.net) generated from the
  same data, so a human can open and tweak the figure visually and re-export.

Generate both from one script so they never drift apart.

## Rendering to PNG (to verify)

There is no `cairosvg`/`inkscape`/ImageMagick in this environment, but **Edge
runs headless** on Windows and screenshots SVG (or HTML) reliably:

```powershell
$edge = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
if (-not (Test-Path $edge)) { $edge = "C:\Program Files\Microsoft\Edge\Application\msedge.exe" }
& $edge --headless=new --disable-gpu --hide-scrollbars `
  --force-device-scale-factor=2 --window-size=800,730 `
  --screenshot="img\_preview.png" "img\my-diagram.svg" | Out-Null
```

Notes:
- Use `--headless=new` (the old `--headless` flag may silently produce no file).
- `--force-device-scale-factor=2` gives a sharp 2x screenshot.
- `--window-size=W,H` is the capture viewport — set it a little larger than the
  SVG's `width`/`height` so nothing is clipped, then `Read` the PNG to inspect.
- Prefix preview files with `_` and delete them when done.

To render a `.drawio` headlessly, export it via the draw.io desktop CLI if
installed; otherwise just render the matching `.svg` (they share the same data).

## Styling conventions (match the existing figures)

Follow `wots-diagram-generic.svg` so new figures look native to the spec:

- Font: `Arial, Helvetica, sans-serif`; sizes ~7.5–18px.
- Light theme palette: light-gray rounded boxes (`#e0e0e0`), thin 1px strokes,
  purple accent (`#633fd6`). Dark theme variant: `#141414` background, white
  text (`#f2f2f2`), brighter purple accents (`#7c5cff` / `#8b6fff`).
- Rounded rects (`rx≈3`), proportional widths when depicting byte/field layouts,
  a byte-offset ruler, and a small legend.
- All color constants live at the top of the generator — change the theme there
  and rerun, don't hand-edit the emitted SVG.

## Regenerating

```powershell
py img\gen_adrs_diagrams.py
```

This rewrites `adrs-stateless.{svg,drawio}` and `adrs-stateful.{svg,drawio}`.
The Markdown embeds reference the SVGs by filename, so no doc edits are needed
after a regeneration.

## When NOT to use this workflow

- If the user wants a *photograph* or *artistic* image, say plainly that this
  environment has no image-generation model; offer a diagram instead.
- For one-off math/plot figures, matplotlib (if available) or TikZ in the LaTeX
  spec may be a better fit than hand-rolled SVG.
