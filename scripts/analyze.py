#!/usr/bin/env python3
"""analyze.py - build every number in the paper from the raw CSV files.

    python3 scripts/analyze.py results/<tag>

Reads
    perf_<scheme>_r<k>.pub.csv / .sub.csv      (run_matrix.sh)
    sec_<scenario>_<config>.pub/.sub.csv       (run_security.sh)
    bench_<host>_<variant>.txt                 (ascon_bench)
Writes <dir>/results.json and <dir>/results.md. Nothing is typed in by hand:
copy tables from results.md, not from terminal output.

Definitions (identical for every scheme):
    T_gen  = mean over measured frames of the publish() call time        [publisher CSV]
    T_tx   = mean of frame_len*8/100e6 (calculated, not measured)        [publisher CSV]
    T_proc = mean over delivered, post-warm-up frames                    [subscriber CSV]
    T_E2E  = T_gen + T_tx + T_proc   (sum of three means; the two hosts' clocks are
             not synchronised, so a true one-way delay is not available)
Run-to-run spread is reported over the per-run means, never over pooled frames.
"""
import csv, glob, json, math, os, re, statistics, sys
from collections import defaultdict

# two-sided 95 % Student-t critical values, df = 1..30
T95 = [12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
       2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086,
       2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042]

# Banerjee & Banerjee, FNWF 2025, Tables I and II (Raspberry Pi 5) - CONTEXT ONLY
PAPER = {
    "none":     dict(frame=202, gen=26.68, tx=16.16, proc=5.52,  e2e=48.36),
    "banerjee": dict(frame=261, gen=40.74, tx=20.88, proc=22.53, e2e=84.15),
}


def tcrit(n):
    df = max(1, n - 1)
    return T95[min(df, 30) - 1]


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def mean(v):
    return sum(v) / len(v) if v else float("nan")


def sd(v):
    return statistics.stdev(v) if len(v) > 1 else 0.0


def pct(v, p):
    s = sorted(v)
    return s[min(len(s) - 1, int(len(s) * p))] if s else float("nan")


def summarize(v):
    return dict(n=len(v), mean=mean(v), median=statistics.median(v) if v else float("nan"),
                std=sd(v), p99=pct(v, 0.99), max=max(v) if v else float("nan"))


# ---------------------------------------------------------------------------
def perf(d):
    runs = defaultdict(dict)       # scheme -> run -> dict
    for pubf in sorted(glob.glob(os.path.join(d, "perf_*_r*.pub.csv"))):
        m = re.match(r"perf_(.+)_r(\d+)\.pub\.csv", os.path.basename(pubf))
        if not m:
            continue
        scheme, run = m.group(1), int(m.group(2))
        subf = pubf.replace(".pub.csv", ".sub.csv")
        if not os.path.exists(subf):
            continue
        pub = [r for r in read_csv(pubf) if r["warmup"] == "0" and int(r["frame_len"]) > 0]
        sub = [r for r in read_csv(subf) if r["verdict"] == "0" and r["warmup"] == "0"]
        if not pub or not sub:
            continue
        gen = [float(r["t_gen_us"]) for r in pub]
        tx = [float(r["t_tx_us"]) for r in pub]
        proc = [float(r["t_proc_us"]) for r in sub]
        lens = [int(r["frame_len"]) for r in pub]
        allsub = read_csv(subf)
        runs[scheme][run] = dict(
            gen=summarize(gen), tx=mean(tx), proc=summarize(proc),
            frame=max(set(lens), key=lens.count),
            e2e=mean(gen) + mean(tx) + mean(proc),
            delivered=len([r for r in allsub if r["verdict"] == "0" and r["warmup"] == "0"]),
            published=len(pub),
            rejected=len([r for r in allsub if r["verdict"] != "0"]),
        )
    return runs


def agg(runs, key):
    vals = []
    for r in runs.values():
        x = r[key]
        vals.append(x["mean"] if isinstance(x, dict) else x)
    n = len(vals)
    m = mean(vals)
    s = sd(vals)
    return dict(n=n, mean=m, std=s, ci95=(tcrit(n) * s / math.sqrt(n)) if n > 1 else float("nan"),
                min=min(vals), max=max(vals))


def paired(runs_a, runs_b, key):
    """b - a, matched by run number."""
    diffs = []
    for k in sorted(set(runs_a) & set(runs_b)):
        xa, xb = runs_a[k][key], runs_b[k][key]
        xa = xa["mean"] if isinstance(xa, dict) else xa
        xb = xb["mean"] if isinstance(xb, dict) else xb
        diffs.append(xb - xa)
    n = len(diffs)
    if n == 0:
        return None
    s = sd(diffs)
    ci = tcrit(n) * s / math.sqrt(n) if n > 1 else float("nan")
    return dict(n=n, mean=mean(diffs), std=s, ci95=ci,
                significant=(n > 1 and abs(mean(diffs)) > ci))


# ---------------------------------------------------------------------------
def security(d):
    rows = []
    for subf in sorted(glob.glob(os.path.join(d, "sec_*.sub.csv"))):
        m = re.match(r"sec_([a-z]+)_(.+)\.sub\.csv", os.path.basename(subf))
        if not m:
            continue
        scen, cfg = m.group(1), m.group(2)
        pubf = subf.replace(".sub.csv", ".pub.csv")
        published = len([r for r in read_csv(pubf) if int(r["frame_len"]) > 0]) if os.path.exists(pubf) else 0
        sub = read_csv(subf)
        cnt = defaultdict(int)
        cost = defaultdict(list)
        for r in sub:
            cnt[r["verdict"]] += 1
            cost[r["verdict"]].append(float(r["t_proc_us"]))
        delivered = cnt["0"]
        delivered_rows = [r for r in sub if r["verdict"] == "0"]
        distinct = len(set((r["stNum"], r["sqNum"]) for r in delivered_rows))
        duplicates = delivered - distinct      # frames delivered a 2nd or later time = accepted replays
        rows.append(dict(
            scenario=scen, config=cfg, published=published, delivered=delivered,
            distinct=distinct,
            injected_delivered=duplicates,
            legit_lost=max(0, published - distinct),
            rej_auth=cnt["1"], rej_replay=cnt["2"], rej_parse=cnt["3"],
            cost_replay_us=mean(cost["2"]) if cost["2"] else None,
            cost_auth_us=mean(cost["1"]) if cost["1"] else None,
            tproc_delivered_p99_us=pct(cost["0"], 0.99) if cost["0"] else None,
        ))
    return rows


def bench(d):
    out = {}
    for f in sorted(glob.glob(os.path.join(d, "bench_*.txt"))):
        out[os.path.basename(f)[6:-4]] = open(f).read()
    return out


# ---------------------------------------------------------------------------
def components(d):
    """Per-component breakdown from the component-timing build (COMPONENTS=1 bash build.sh).

    The CSVs of that build carry extra columns: publisher t_nonce_us, t_crypto_us, t_send_us and
    subscriber t_window_us, t_crypto_us. Every row is a mean over measured frames, then a mean of the
    per-run means (the same rule as the totals). The two 'remainder' rows are NOT measured directly:
        frame serialise + sendto = T_gen  - nonce - encrypt
        parse + rebuild + rest   = T_proc - window - decrypt
    so that the rows add up to the totals of the same run set, exactly as in a breakdown table.
    Returns {scheme: dict} or {} if the CSVs were produced by the normal build."""
    per = defaultdict(list)
    for pubf in sorted(glob.glob(os.path.join(d, "perf_*_r*.pub.csv"))):
        m = re.match(r"perf_(.+)_r(\d+)\.pub\.csv", os.path.basename(pubf))
        subf = pubf.replace(".pub.csv", ".sub.csv")
        if not m or not os.path.exists(subf):
            continue
        prows, srows = read_csv(pubf), read_csv(subf)
        if not prows or not srows or "t_nonce_us" not in prows[0] or "t_window_us" not in srows[0]:
            continue
        pub = [r for r in prows if r["warmup"] == "0" and int(r["frame_len"]) > 0]
        sub = [r for r in srows if r["verdict"] == "0" and r["warmup"] == "0"]
        if not pub or not sub:
            continue
        lens = [int(r["frame_len"]) for r in pub]
        timer_ns = None
        logf = pubf.replace(".pub.csv", ".pub.log")
        if os.path.exists(logf):
            mm = re.search(r"timer_cost_ns=([0-9.]+)", open(logf, errors="replace").read())
            timer_ns = float(mm.group(1)) if mm else None
        col = lambda rows, k: mean([float(r[k]) for r in rows])
        per[m.group(1)].append(dict(
            frame=max(set(lens), key=lens.count),
            gen=col(pub, "t_gen_us"), nonce=col(pub, "t_nonce_us"), enc=col(pub, "t_crypto_us"),
            send=col(pub, "t_send_us"), tx=col(pub, "t_tx_us"),
            proc=col(sub, "t_proc_us"), win=col(sub, "t_window_us"), dec=col(sub, "t_crypto_us"),
            timer_ns=timer_ns))
    out = {}
    for scheme, rs in per.items():
        m_ = lambda k: mean([r[k] for r in rs])
        gen, nonce, enc, send, tx = m_("gen"), m_("nonce"), m_("enc"), m_("send"), m_("tx")
        proc, win, dec = m_("proc"), m_("win"), m_("dec")
        timers = [r["timer_ns"] for r in rs if r["timer_ns"] is not None]
        out[scheme] = dict(
            runs=len(rs), frame=max(set(r["frame"] for r in rs)), gen=gen, nonce=nonce, enc=enc, send=send,
            serialise=gen - nonce - enc, tx=tx, proc=proc, win=win, dec=dec, parse=proc - win - dec,
            e2e=gen + tx + proc, timer_ns=mean(timers) if timers else None)
    return out


NOTES = {   # scheme -> row -> note
    "banerjee": dict(nonce="BER(stNum) BER(sqNum) t, zero padded (assumed; the original paper does not specify it)",
                     enc="whole PDU value", dec="whole PDU value, before any parsing"),
    "proposed": dict(nonce="stNum || sqNum || t, fixed width, 16 B",
                     enc="allData value only; header fields are AAD", dec="allData value only"),
}


def component_table(scheme, c):
    """Markdown table in the layout Stage | Component | Mean latency | % of T_E2E | Notes."""
    e2e = c["e2e"]
    p = lambda x: f"{100.0 * x / e2e:.2f}%"
    n = NOTES.get(scheme, {})
    rows = [("Stage", "Component", "Mean Latency (us)", "% of T_E2E", "Notes")]
    secured = scheme in ("banerjee", "proposed")
    stage = "Publisher (T_gen)"
    if secured:
        rows.append((stage, "Nonce construction (gs_nonce_*)", f(c["nonce"]), p(c["nonce"]), n.get("nonce", "")))
        rows.append(("", "ASCON-AEAD128 encrypt (crypto_aead_encrypt)", f(c["enc"]), p(c["enc"]), n.get("enc", "")))
        stage = ""
    rows.append((stage, "Frame serialise + sendto() (rest of GoosePublisher_publish)", f(c["serialise"]),
                 p(c["serialise"]), f"remainder of T_gen; of which sendto() = {f(c['send'])} us"))
    rows.append(("", "Total T_gen", f(c["gen"]), p(c["gen"]), ""))
    rows.append(("Transmission (T_tx)", f"Ethernet link ({c['frame']} B @ 100 Mbps)", f(c["tx"]), p(c["tx"]),
                 "calculated: frame bytes x 8 / 100e6, not measured"))
    rows.append(("Subscriber (T_proc)", "BER parse + nonce/AAD reconstruction (rest of receive path)",
                 f(c["parse"]), p(c["parse"]),
                 "remainder of T_proc: recv, header and extension parse, PDU walk, nonce/AAD rebuild, callback"))
    if scheme == "proposed":
        rows.append(("", "RFC 6479 replay window check", f(c["win"]), p(c["win"]), "peek + commit, 64-slot bitmap"))
    if secured:
        rows.append(("", "ASCON-AEAD128 decrypt", f(c["dec"]), p(c["dec"]), n.get("dec", "")))
    rows.append(("", "Total T_proc", f(c["proc"]), p(c["proc"]), ""))
    note = f"mean of {c['runs']} run(s)"
    if c["timer_ns"] is not None:
        note += f"; one timer costs about {c['timer_ns']:.0f} ns (not subtracted)"
    rows.append(("End-to-End", "T_E2E = T_gen + T_tx + T_proc", f(e2e), "100.00%", note))
    w = [max(len(r[i]) for r in rows) for i in range(5)]
    line = lambda r: "| " + " | ".join(r[i].ljust(w[i]) for i in range(5)) + " |"
    return [line(rows[0]), "|" + "|".join("-" * (w[i] + 2) for i in range(5)) + "|"] + [line(r) for r in rows[1:]]


# ---------------------------------------------------------------------------
def f(x, nd=3):
    return "n/a" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:.{nd}f}"


def main(d):
    runs = perf(d)
    res = dict(perf={}, paired={}, security=security(d), bench=bench(d))
    md = [f"# Results ({os.path.basename(os.path.normpath(d))})", ""]

    if runs:
        md += ["## Latency per stage (mean of per-run means, microseconds)", "",
               "| scheme | runs | frame B | T_gen | T_tx (calc.) | T_proc | **T_E2E** | T_E2E run-to-run std |",
               "|---|---|---|---|---|---|---|---|"]
        for s in ["none", "banerjee", "proposed"]:
            if s not in runs:
                continue
            g, t, p, e = (agg(runs[s], "gen"), agg(runs[s], "tx"), agg(runs[s], "proc"), agg(runs[s], "e2e"))
            fr = max(set(r["frame"] for r in runs[s].values()))
            res["perf"][s] = dict(runs=len(runs[s]), frame=fr, gen=g, tx=t, proc=p, e2e=e)
            md.append(f"| {s} | {g['n']} | {fr} | {f(g['mean'])} | {f(t['mean'])} | {f(p['mean'])} | "
                      f"**{f(e['mean'])}** | {f(e['std'])} |")
        md += ["", "Frame sizes must match Banerjee Table II for a faithful baseline (none 202 B, Ascon-AEAD 261 B); "
                   "if they do not, say so in the paper and explain why.", ""]

        md += ["## Scheme comparison on identical hardware (paired by run)", "",
               "| comparison | stage | difference (us) | std over runs | 95 % CI half-width | significant? |",
               "|---|---|---|---|---|---|"]
        for a, b in [("none", "banerjee"), ("none", "proposed"), ("banerjee", "proposed")]:
            if a in runs and b in runs:
                for key, label in [("gen", "T_gen"), ("tx", "T_tx"), ("proc", "T_proc"), ("e2e", "T_E2E")]:
                    p_ = paired(runs[a], runs[b], key)
                    if p_:
                        res["paired"][f"{b}-{a}:{key}"] = p_
                        md.append(f"| {b} - {a} | {label} | {f(p_['mean'])} | {f(p_['std'])} | "
                                  f"{f(p_['ci95'])} | {'yes' if p_['significant'] else 'no'} |")
        md.append("")

        md += ["## Overhead above no security (the platform-independent view)", "",
               "| scheme | extra T_gen | extra T_tx | extra T_proc | extra T_E2E |", "|---|---|---|---|---|"]
        for s in ["banerjee", "proposed"]:
            if s in runs and "none" in runs:
                cells = []
                for key in ["gen", "tx", "proc", "e2e"]:
                    p_ = paired(runs["none"], runs[s], key)
                    cells.append(f(p_["mean"]) if p_ else "n/a")
                md.append(f"| {s} | " + " | ".join(cells) + " |")
        md.append("")

        md += ["## Reference only: Banerjee & Banerjee, Raspberry Pi 5 (NOT comparable with the Pi 4B rows above)", "",
               "| row | frame B | T_gen | T_tx | T_proc | T_E2E |", "|---|---|---|---|---|---|"]
        for k, v in PAPER.items():
            md.append(f"| paper, {k} | {v['frame']} | {v['gen']} | {v['tx']} | {v['proc']} | {v['e2e']} |")
        md.append("")

        md += ["## Per-run detail", "",
               "| scheme | run | frames published | delivered | rejected | T_gen mean | T_proc mean | T_proc p99 | T_E2E |",
               "|---|---|---|---|---|---|---|---|---|"]
        for s in ["none", "banerjee", "proposed"]:
            for k in sorted(runs.get(s, {})):
                r = runs[s][k]
                md.append(f"| {s} | {k} | {r['published']} | {r['delivered']} | {r['rejected']} | "
                          f"{f(r['gen']['mean'])} | {f(r['proc']['mean'])} | {f(r['proc']['p99'])} | {f(r['e2e'])} |")
        md.append("")

    comp = components(d)
    if comp:
        res["components"] = comp
        md += ["## Per-component breakdown (component-timing build)", "",
               "Each measured row is a timer around one step inside GoosePublisher_publish() / parseGooseMessage(). "
               "The two 'remainder' rows are computed so that the rows add up to the totals (see `components()` in "
               "analyze.py). Run this build separately from the normal matrix and take the T_gen / T_proc totals "
               "from the normal run: the timers add a few clock reads.", ""]
        for s in ["none", "banerjee", "proposed"]:
            if s in comp:
                md += [f"### {s}", ""] + component_table(s, comp[s]) + [""]

    if res["security"]:
        md += ["## Security tests (measured)", "",
               "| scenario | config | published | delivered (all) | distinct frames delivered | replays accepted (duplicate deliveries) | legit frames lost | "
               "rej auth | rej replay | rej parse | cost of replay reject (us) | cost of auth reject (us) |",
               "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for r in res["security"]:
            md.append(f"| {r['scenario']} | {r['config']} | {r['published']} | {r['delivered']} | "
                      f"{r['distinct']} | {r['injected_delivered']} | {r['legit_lost']} | {r['rej_auth']} | "
                      f"{r['rej_replay']} | {r['rej_parse']} | {f(r['cost_replay_us'])} | {f(r['cost_auth_us'])} |")
        md.append("")

    if res["bench"]:
        md += ["## Pure cipher cost per Ascon variant (ascon_bench)", ""]
        for k, txt in res["bench"].items():
            md += [f"### {k}", "```", txt.strip(), "```", ""]

    json.dump(res, open(os.path.join(d, "results.json"), "w"), indent=2, default=str)
    open(os.path.join(d, "results.md"), "w").write("\n".join(md) + "\n")
    print("\n".join(md))

    try:                                         # optional figure
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        order = [s for s in ["none", "banerjee", "proposed"] if s in res["perf"]]
        if order:
            fig, ax = plt.subplots(figsize=(5.2, 3.4))
            bottom = [0.0] * len(order)
            for key, label in [("gen", "T_gen"), ("tx", "T_tx (calc.)"), ("proc", "T_proc")]:
                vals = [res["perf"][s][key]["mean"] for s in order]
                ax.bar(order, vals, bottom=bottom, label=label)
                bottom = [b + v for b, v in zip(bottom, vals)]
            for i, s in enumerate(order):
                e = res["perf"][s]["e2e"]
                ax.errorbar(i, e["mean"], yerr=e["std"], color="k", capsize=3)
                ax.text(i, e["mean"] + 1, f"{e['mean']:.1f}", ha="center", fontsize=8)
            ax.set_ylabel("microseconds")
            ax.set_title("Per-stage latency, Raspberry Pi 4B (same harness)")
            ax.legend(fontsize=8)
            fig.tight_layout()
            fig.savefig(os.path.join(d, "latency_stages.png"), dpi=200)
    except Exception as e:                       # matplotlib is optional
        print("(figure skipped:", e, ")")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: analyze.py <results-dir>")
    main(sys.argv[1])
