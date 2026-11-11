#!/usr/bin/env python3
"""
make_fig_perf.py - the performance figure (paper Fig. 8) drawn from measured data only.

  python3 scripts/make_fig_perf.py results/<tag>/results.json  Fig8_Performance.png

Reads results.json written by analyze.py (perf -> scheme -> gen/tx/proc/e2e with mean and ci95).
Stacked bars: T_gen (measured), T_tx (calculated from frame size), T_proc (measured).
No improvement percentage is drawn: the figure shows the components and lets the numbers speak.
Without a results.json it draws the recorded baseline numbers (BASELINE_RESULTS.md) and marks
the proposed scheme as pending.
"""
import json, sys
from PIL import Image, ImageDraw, ImageFont

FB, FR = "C:/Windows/Fonts/arialbd.ttf", "C:/Windows/Fonts/arial.ttf"
f = lambda p, s: ImageFont.truetype(p, s)
INK, GREY = (20, 20, 30), (90, 90, 100)
COL = {"gen": (30, 90, 200), "tx": (150, 155, 165), "proc": (205, 110, 10)}
NAME = {"none": "No security (stock)", "banerjee": "Prior design (Banerjee-style)", "proposed": "Proposed scheme"}
ORDER = ["none", "banerjee", "proposed"]

# recorded baseline run (BASELINE_RESULTS.md): T_gen, T_tx, T_proc, T_E2E, CI95 of T_E2E
FALLBACK = {"none": dict(gen=5.765, tx=16.240, proc=2.992, ci=None),
            "banerjee": dict(gen=8.686, tx=20.960, proc=5.570, ci=0.017)}


def load(path):
    out = {}
    if path:
        res = json.load(open(path))
        for s, v in res["perf"].items():
            out[s] = dict(gen=v["gen"]["mean"], tx=v["tx"]["mean"], proc=v["proc"]["mean"], ci=v["e2e"].get("ci95"))
    else:
        out = dict(FALLBACK)
    return out


def main():
    src = sys.argv[1] if len(sys.argv) > 1 and sys.argv[1].endswith(".json") else None
    outp = sys.argv[2] if len(sys.argv) > 2 else (sys.argv[1] if len(sys.argv) > 1 and not src else "Fig8_Performance.png")
    data = load(src)
    W, H = 2400, 1000
    img = Image.new("RGB", (W, H), "white")
    d = ImageDraw.Draw(img)
    X0, X1 = 880, 1990
    rows = [s for s in ORDER if s in data or s == "proposed"]
    vmax = max(sum(data[s][k] for k in ("gen", "tx", "proc")) for s in data)
    scale = (X1 - X0) / (vmax * 1.12)
    d.text((W // 2, 40), "End-to-end latency, Raspberry Pi 4 Model B", font=f(FB, 54), fill=INK, anchor="mm")
    y = 130
    for s in rows:
        d.text((X0 - 30, y + 70), NAME[s], font=f(FB, 42), fill=INK, anchor="rm")
        if s not in data:
            d.rounded_rectangle((X0, y + 10, X0 + 700, y + 130), radius=10, outline=GREY, width=4)
            d.text((X0 + 350, y + 70), "pending Pi run", font=f(FR, 44), fill=GREY, anchor="mm")
            y += 190
            continue
        x = X0
        for k in ("gen", "tx", "proc"):
            w = data[s][k] * scale
            d.rectangle((x, y + 10, x + w, y + 130), fill=COL[k])
            d.text((x + w / 2, y + 70), f"{data[s][k]:.1f}", font=f(FB, 44), fill="white", anchor="mm")
            x += w
        tot = sum(data[s][k] for k in ("gen", "tx", "proc"))
        ci = data[s]["ci"]
        label = f"{tot:.1f} \u00b5s" + (f"  (\u00b1{ci:.2f})" if ci else "")
        d.text((x + 24, y + 70), label, font=f(FB, 46), fill=INK, anchor="lm")
        y += 190
    # legend
    lx = X0
    for k, lab in [("gen", "T_gen (measured)"), ("tx", "T_tx (calculated from frame size)"), ("proc", "T_proc (measured)")]:
        d.rectangle((lx, y + 30, lx + 44, y + 74), fill=COL[k])
        d.text((lx + 60, y + 52), lab, font=f(FR, 38), fill=INK, anchor="lm")
        lx += 60 + int(f(FR, 38).getlength(lab)) + 60
    d.text((W // 2, y + 130), "values in \u00b5s; bar total = T_E2E = T_gen + T_tx + T_proc; \u00b1 = 95% CI over runs",
           font=f(FR, 34), fill=GREY, anchor="mm")
    img.crop((0, 0, W, y + 175)).save(outp, dpi=(343, 343))
    print(outp)


main()
