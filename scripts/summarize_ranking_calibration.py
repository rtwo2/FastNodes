#!/usr/bin/env python3
"""Render sample-aware notes from the collector's ranking calibration summary.

This is analysis only. It never edits ranking weights or subscription output.
"""
from __future__ import annotations

import argparse
import csv
import pathlib
import sys

REQUIRED = {
    "previous_score_band", "retested_nodes", "current_roundtrip_successes",
    "current_roundtrip_failures", "current_success_rate_percent",
    "previous_roundtrip_successes", "previous_successes_persisted", "persistence_rate_percent",
}


class CalibrationError(Exception):
    pass


def integer(row: dict, key: str) -> int:
    try:
        return max(0, int(row.get(key, 0) or 0))
    except (TypeError, ValueError):
        return 0


def percent(row: dict, key: str, *, success_key: str, total_key: str) -> float | None:
    total = integer(row, total_key)
    if total == 0:
        return None
    return integer(row, success_key) * 100.0 / total


def render(path: pathlib.Path, min_sample: int = 50) -> str:
    if min_sample < 1:
        raise CalibrationError("minimum sample size must be at least 1")
    if not path.is_file():
        raise CalibrationError(f"ranking calibration summary does not exist: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = set(reader.fieldnames or [])
        if not REQUIRED.issubset(fields):
            raise CalibrationError("ranking summary is missing columns: " + ", ".join(sorted(REQUIRED - fields)))
        rows = list(reader)

    lines = [
        "# Ranking calibration review",
        "",
        f"- Minimum sample size for interpreting a score band: **{min_sample} retested nodes**",
        f"- Score bands present: **{len(rows)}**",
        "- This report is advisory only. It does not change ranking weights or rewrite generated subscriptions.",
        "",
        "## Score-band outcomes",
        "",
        "| Previous score band | Retested | Current roundtrip success | Current roundtrip failure | Prior successes persisted | Interpretation |",
        "|---|---:|---:|---:|---:|---|",
    ]
    reliable_rates: list[tuple[str, float]] = []
    for row in rows:
        band = row.get("previous_score_band", "(unknown)")
        retested = integer(row, "retested_nodes")
        successes = integer(row, "current_roundtrip_successes")
        failures = integer(row, "current_roundtrip_failures")
        prior = integer(row, "previous_roundtrip_successes")
        persisted = integer(row, "previous_successes_persisted")
        current_rate = percent(row, "current_success_rate_percent",
                               success_key="current_roundtrip_successes", total_key="retested_nodes")
        persistence_rate = percent(row, "persistence_rate_percent",
                                   success_key="previous_successes_persisted", total_key="previous_roundtrip_successes")
        # Avoid interpreting small cohorts or an absent denominator as evidence.
        if retested >= min_sample and current_rate is not None:
            reliable_rates.append((band, current_rate))
            outcome = f"{current_rate:.1f}% current success"
        elif retested == 0:
            outcome = "No current retest sample"
        else:
            outcome = f"Small sample ({retested}/{min_sample})"
        persistence = "—" if prior == 0 or persistence_rate is None else f"{persisted:,}/{prior:,} ({persistence_rate:.1f}%)"
        lines.append(f"| {band} | {retested:,} | {successes:,} ({'—' if current_rate is None else f'{current_rate:.1f}%'}) | "
                     f"{failures:,} | {persistence} | {outcome} |")

    lines += ["", "## Review guidance", ""]
    if len(reliable_rates) < 2:
        lines.append(
            f"Fewer than two score bands meet the {min_sample}-node sample threshold. "
            "Collect additional runs before making score-weight changes."
        )
    else:
        # Keep published rows' score-band order and look for large non-monotonic drops.
        drops = []
        for (lower_band, lower_rate), (higher_band, higher_rate) in zip(reliable_rates, reliable_rates[1:]):
            if higher_rate + 15.0 < lower_rate:
                drops.append((lower_band, lower_rate, higher_band, higher_rate))
        if drops:
            for lower_band, lower_rate, higher_band, higher_rate in drops:
                lines.append(
                    f"- Investigate non-monotonic outcomes: score band **{higher_band}** "
                    f"had {higher_rate:.1f}% current success versus {lower_rate:.1f}% in **{lower_band}**."
                )
            lines.append("These differences are review signals, not automatic instructions to change weights.")
        else:
            lines.append(
                f"{len(reliable_rates)} score bands meet the sample threshold. No adjacent drop greater than "
                "15 percentage points was detected; preserve current weights until repeated runs support a change."
            )
    lines += [
        "",
        "Current-roundtrip success and historical-success persistence are different metrics. "
        "A prior score can reflect verification evidence from an earlier run, so this report is a persistence/calibration check, "
        "not a causal benchmark. Compare multiple successful collection runs before changing weights.",
        "",
    ]
    return "\n".join(lines)


def self_test() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "ranking-calibration-summary.csv"
        path.write_text(
            "previous_score_band,retested_nodes,current_roundtrip_successes,current_roundtrip_failures,current_success_rate_percent,previous_roundtrip_successes,previous_successes_persisted,persistence_rate_percent\n"
            "0-19,4,1,3,25,0,0,\n"
            "20-39,100,90,10,90,80,70,87.5\n"
            "40-59,100,60,40,60,80,50,62.5\n",
            encoding="utf-8",
        )
        report = render(path, min_sample=50)
        assert "Small sample (4/50)" in report
        assert "90.0% current success" in report
        assert "non-monotonic outcomes" in report
        assert "does not change ranking weights" in report
        print("Ranking calibration self-tests passed: sample threshold and non-monotonic outcomes.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="sub/diagnostics/ranking-calibration-summary.csv")
    parser.add_argument("--output")
    parser.add_argument("--min-sample", type=int, default=50)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        report = render(pathlib.Path(args.input), args.min_sample)
        if args.output:
            output = pathlib.Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            temporary = output.with_name(output.name + ".tmp")
            temporary.write_text(report, encoding="utf-8")
            temporary.replace(output)
            print(f"Ranking calibration notes written to {output}.")
        else:
            print(report)
        return 0
    except (OSError, CalibrationError) as exc:
        print(f"Could not analyze ranking calibration: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
