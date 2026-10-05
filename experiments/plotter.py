"""Render evaluation charts (mean +/- stdev) from the experiment JSON results.

    python3 -m experiments.plotter [--data experiments/data] [--out experiments/plots]

Every figure is written as PNG plus a CSV table view of the plotted values.
Style: validated categorical slots in fixed order (blue, orange, aqua; <= 3 series
per chart), 2px lines, ringed >= 8px markers with distinct shapes as secondary
encoding, hairline solid grid, one y-axis per panel (no dual axes), text in ink
tokens rather than series colours.
"""

from __future__ import annotations

import argparse
import json
import os

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import matplotlib.ticker  # noqa: E402,F401
import pandas as pd  # noqa: E402

from experiments.harness import DATA_DIR  # noqa: E402

PLOTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "plots")
SURFACE = "#fcfcfb"
TEXT_PRIMARY = "#0b0b0b"
TEXT_SECONDARY = "#52514e"
GRID = "#e6e5e1"
SERIES = ["#2a78d6", "#eb6834", "#1baf7a"]  # validated light-mode slots 1-3
MARKERS = ["o", "s", "^"]


def _style() -> None:
    plt.rcParams.update(
        {
            "figure.facecolor": SURFACE,
            "axes.facecolor": SURFACE,
            "savefig.facecolor": SURFACE,
            "axes.edgecolor": GRID,
            "axes.labelcolor": TEXT_SECONDARY,
            "axes.titlecolor": TEXT_PRIMARY,
            "axes.titlesize": 11,
            "axes.titleweight": "bold",
            "axes.labelsize": 9,
            "axes.grid": True,
            "grid.color": GRID,
            "grid.linewidth": 0.8,
            "grid.linestyle": "-",
            "xtick.color": TEXT_SECONDARY,
            "ytick.color": TEXT_SECONDARY,
            "xtick.labelsize": 8,
            "ytick.labelsize": 8,
            "legend.frameon": False,
            "legend.fontsize": 8,
            "axes.spines.top": False,
            "axes.spines.right": False,
            "font.family": "DejaVu Sans",
        }
    )


def _load(data_dir: str, name: str) -> dict | None:
    path = os.path.join(data_dir, name)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _line(ax, xs, means, stds, idx: int, label: str, end_label: bool = True, log: bool = False) -> None:
    color = SERIES[idx % len(SERIES)]
    # On a log axis a lower bar below zero is undefined: clip it inside the positive range.
    yerr = [[min(s, m * 0.9) for m, s in zip(means, stds)], stds] if log else stds
    ax.errorbar(
        xs, means, yerr=yerr, color=color, linewidth=2, marker=MARKERS[idx % len(MARKERS)], markersize=7,
        markeredgecolor=SURFACE, markeredgewidth=2, capsize=3, elinewidth=1, label=label, solid_capstyle="round",
    )  # fmt: skip
    if end_label and len(xs):
        ax.annotate(label, (xs[-1], means[-1]), xytext=(6, 0), textcoords="offset points", va="center",
                    fontsize=8, color=TEXT_SECONDARY)  # fmt: skip


def _pad_top(ax, frac: float = 0.12) -> None:
    """Zero baseline plus headroom so top markers are never clipped."""
    top = ax.get_ylim()[1]
    ax.set_ylim(0, top * (1 + frac))


def _samples(ax, xs: list[float], values: list[list[float]], idx: int) -> None:
    """Faint individual repetitions behind the mean line (shows skew N=5..10 hides)."""
    for x, vals in zip(xs, values):
        vals = [v for v in vals if v is not None]
        ax.scatter([x] * len(vals), vals, s=10, color=SERIES[idx % len(SERIES)], alpha=0.25, linewidths=0, zorder=1)


def _save(fig, out_dir: str, name: str, table: pd.DataFrame) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    png = os.path.join(out_dir, f"{name}.png")
    csv = os.path.join(out_dir, f"{name}.csv")
    fig.tight_layout()
    fig.savefig(png, dpi=150)
    plt.close(fig)
    table.to_csv(csv, index=False)
    return [png, csv]


def _note(fig, meta: dict | None) -> None:
    if meta:
        backend = meta.get("impairment_backend") or "none"
        fig.text(0.01, 0.005, f"kernel {meta.get('kernel', '?')} · impairment backend {backend} · mean ± stdev",
                 fontsize=7, color=TEXT_SECONDARY)  # fmt: skip


def plot_convergence(data: dict, out_dir: str) -> list[str]:
    rows = [
        {
            "topology": r["topology"],
            "loss_pct": r["loss_pct"],
            "t90_mean_s": r["t90"]["mean"],
            "t90_std_s": r["t90"]["stdev"],
            "t100_mean_s": r["t100"]["mean"],
            "t100_std_s": r["t100"]["stdev"],
            "timeouts": r["timeouts"],
            "n": r["t100"]["n"],
        }
        for r in data["loss_sweep"]
    ]
    df = pd.DataFrame(rows)
    raw = {(r["topology"], r["loss_pct"]): r["samples"] for r in data["loss_sweep"]}
    receivers = data["loss_sweep"][0]["samples"][0]["receivers"] if data["loss_sweep"] else 0
    fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharey=True)
    for ax, metric, title in ((axes[0], "t90", "≥90% of receivers"), (axes[1], "t100", "100% of receivers")):
        for idx, (topology, group) in enumerate(df.groupby("topology", sort=False)):
            group = group.sort_values("loss_pct")
            xs = group["loss_pct"].tolist()
            _samples(ax, xs, [[s[metric] * 1000 if s[metric] is not None else None for s in raw[(topology, x)]] for x in xs], idx)
            _line(ax, xs, (group[f"{metric}_mean_s"] * 1000).tolist(),
                  (group[f"{metric}_std_s"].fillna(0) * 1000).tolist(), idx, topology, log=True)  # fmt: skip
        ax.set_title(f"Convergence time to {title}")
        ax.set_xlabel("per-link packet loss (%)")
        ax.set_xticks(sorted(df["loss_pct"].unique()))
        ax.set_yscale("log")  # latencies span ~10 ms (rumor) to seconds (TCP RTO backoff / anti-entropy)
        ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:g}"))
    axes[0].set_ylabel(f"ms after admin commit, log scale ({receivers} receivers)")
    axes[0].legend(loc="upper left")
    _note(fig, data.get("meta"))
    out = _save(fig, out_dir, "convergence_vs_loss", df)

    if data.get("fanout_sweep"):
        fdf = pd.DataFrame(
            [
                {
                    "fanout": r["fanout"],
                    "mean_degree": r["mean_degree"],
                    "duplicates_mean": r["duplicates"]["mean"],
                    "duplicates_std": r["duplicates"]["stdev"],
                    "t100_mean_s": r["t100"]["mean"],
                    "t100_std_s": r["t100"]["stdev"],
                }
                for r in data["fanout_sweep"]
            ]
        ).sort_values("fanout")
        fig, axes = plt.subplots(1, 2, figsize=(10, 4))
        _line(axes[0], fdf["fanout"].tolist(), fdf["duplicates_mean"].tolist(), fdf["duplicates_std"].fillna(0).tolist(), 0, "duplicates", False)
        axes[0].set_title("Duplicate GROUP_UPDATE deliveries per transition")
        axes[0].set_xlabel("fanout k")
        axes[0].set_ylabel("duplicates dropped (cluster total)")
        axes[0].set_ylim(bottom=0)
        _line(axes[1], fdf["fanout"].tolist(), (fdf["t100_mean_s"] * 1000).tolist(), (fdf["t100_std_s"].fillna(0) * 1000).tolist(), 0, "t100", False)
        axes[1].set_title("Time to 100% of receivers")
        axes[1].set_xlabel("fanout k")
        axes[1].set_ylabel("ms after admin commit")
        axes[1].set_ylim(bottom=0)
        for ax in axes:
            ax.set_xticks(fdf["fanout"].tolist())
        _note(fig, data.get("meta"))
        out += _save(fig, out_dir, "fanout_overhead", fdf)
    return out


def _hbars(ax, labels: list[str], means: list[float], stds: list[float], annotations: list[str]) -> None:
    ys = list(range(len(labels)))
    ax.barh(ys, means, xerr=stds, height=0.5, color=SERIES[0], error_kw={"elinewidth": 1, "capsize": 3, "ecolor": TEXT_SECONDARY})
    ax.set_yticks(ys)
    ax.set_yticklabels(labels)
    ax.invert_yaxis()
    ax.grid(axis="y", visible=False)
    span = max([m + s for m, s in zip(means, stds)] + [1e-9])
    for y, m, s, note in zip(ys, means, stds, annotations):
        ax.text(m + s + span * 0.02, y, note, va="center", fontsize=8, color=TEXT_SECONDARY)
    ax.set_xlim(0, span * 1.35)


def plot_attacks(data: dict, out_dir: str) -> list[str]:
    attacks = {k: v for k, v in data["attacks"].items() if k != "telemetry"}
    df = pd.DataFrame(
        [
            {
                "attack": name,
                "detection_rate": v["detection_rate"],
                "ttd_mean_ms": (v["time_to_detect"]["mean"] or 0) * 1000,
                "ttd_std_ms": (v["time_to_detect"]["stdev"] or 0) * 1000,
                "n": v["time_to_detect"]["n"],
            }
            for name, v in attacks.items()
        ]
    )
    fig, ax = plt.subplots(figsize=(8, 4))
    _hbars(ax, df["attack"].tolist(), df["ttd_mean_ms"].tolist(), df["ttd_std_ms"].tolist(),
           [f"{m:.1f} ms · detected {r:.0%}" for m, r in zip(df["ttd_mean_ms"], df["detection_rate"])])  # fmt: skip
    ax.set_title("Time to detect, by attack (target node log)")
    ax.set_xlabel("ms from injection to detection event")
    _note(fig, data.get("meta"))
    return _save(fig, out_dir, "attack_detection", df)


def plot_partition(data: dict, out_dir: str) -> list[str]:
    rows = [{"scenario": "rumor (baseline)", "mean_s": data["baseline"]["t100"]["mean"], "std_s": data["baseline"]["t100"]["stdev"]},
            {"scenario": "anti-entropy only (suppressed relay)", "mean_s": data["suppression"]["t100"]["mean"], "std_s": data["suppression"]["t100"]["stdev"]}]  # fmt: skip
    for item in data["partition_heal"]:
        rows.append({"scenario": f"after heal, {item['hold']:g}s partition", "mean_s": item["recovery"]["mean"], "std_s": item["recovery"]["stdev"]})
    df = pd.DataFrame(rows).fillna(0)
    fig, ax = plt.subplots(figsize=(8, 3.6))
    _hbars(ax, df["scenario"].tolist(), (df["mean_s"] * 1000).tolist(), (df["std_s"] * 1000).tolist(),
           [f"{m * 1000:.0f} ms" for m in df["mean_s"]])  # fmt: skip
    ax.set_title("Recovery time: rumor vs anti-entropy vs partition heal")
    ax.set_xlabel(f"ms to 100% of affected members (T_a = {data['meta'].get('anti_entropy_interval', 2.0)} s)")
    _note(fig, data.get("meta"))
    return _save(fig, out_dir, "partition_recovery", df)


def plot_churn(data: dict, out_dir: str) -> list[str]:
    df = pd.DataFrame(
        [
            {
                "churn_rate_per_s": r["churn_rate_per_s"],
                "delivery_ratio_mean": r["delivery_ratio"]["mean"],
                "delivery_ratio_std": r["delivery_ratio"]["stdev"],
                "throughput_mean": r["throughput"]["mean"],
                "throughput_std": r["throughput"]["stdev"],
                "latency_mean_s": r["transition_latency"]["mean"],
                "latency_std_s": r["transition_latency"]["stdev"],
            }
            for r in data["churn"]
        ]
    ).sort_values("churn_rate_per_s")
    fig, axes = plt.subplots(1, 3, figsize=(12, 3.8))
    x = df["churn_rate_per_s"].tolist()
    _line(axes[0], x, df["delivery_ratio_mean"].tolist(), df["delivery_ratio_std"].fillna(0).tolist(), 0, "delivery", False)
    axes[0].set_title("Group message delivery ratio")
    axes[0].set_ylim(0, 1.1)
    _line(axes[1], x, df["throughput_mean"].tolist(), df["throughput_std"].fillna(0).tolist(), 0, "throughput", False)
    axes[1].set_title("Deliveries per second")
    _pad_top(axes[1])
    _line(axes[2], x, (df["latency_mean_s"] * 1000).tolist(), (df["latency_std_s"].fillna(0) * 1000).tolist(), 0, "latency", False)
    axes[2].set_title("Epoch transition latency (ms)")
    _pad_top(axes[2])
    for ax in axes:
        ax.set_xlabel("membership changes per second")
    _note(fig, data.get("meta"))
    return _save(fig, out_dir, "churn_resilience", df)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data", default=DATA_DIR)
    parser.add_argument("--out", default=PLOTS_DIR)
    args = parser.parse_args(argv)
    _style()
    written: list[str] = []
    for name, fn in (
        ("convergence_results.json", plot_convergence),
        ("attack_results.json", plot_attacks),
        ("partition_results.json", plot_partition),
        ("churn_results.json", plot_churn),
    ):
        data = _load(args.data, name)
        if data is None:
            print(f"skip: {name} not found in {args.data}")
            continue
        written += fn(data, args.out)
    for path in written:
        print(f"wrote {path}")
    return 0 if written else 1


if __name__ == "__main__":
    raise SystemExit(main())
