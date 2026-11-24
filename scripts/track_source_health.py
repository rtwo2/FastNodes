#!/usr/bin/env python3
"""Track bounded per-source health across full collection runs.

The trend file is diagnostic only: it never disables/removes a feed or changes ranking.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import pathlib
import sys
from datetime import datetime, timezone

SCHEMA_VERSION = 1
REQUIRED = {
    "url", "fetch_successes", "raw_bytes", "extracted_lines", "parsed", "unique", "status"
}
NUMERIC_FIELDS = (
    "fetch_successes", "raw_bytes", "raw_lines", "extracted_lines", "parsed", "unique",
    "provider_successes", "provider_failures", "fetch_elapsed_ms", "parse_elapsed_ms",
)
OUTPUT_FIELDS = (
    "url", "snapshots_seen", "fetch_success_runs", "fetch_failed_runs", "parse_success_runs",
    "unparsed_runs", "parsed_zero_unique_runs", "latest_status", "latest_parsed", "latest_unique",
    "average_parsed", "average_unique", "latest_fetch_elapsed_ms", "max_fetch_elapsed_ms",
    "latest_parse_elapsed_ms", "classification",
)


class TrendError(Exception):
    pass


def now_utc() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_source_csv(path: pathlib.Path) -> dict[str, dict]:
    if not path.is_file():
        raise TrendError(f"source-health CSV does not exist: {path}")
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = set(reader.fieldnames or [])
        missing = REQUIRED - fields
        if missing:
            raise TrendError("source-health CSV is missing columns: " + ", ".join(sorted(missing)))
        result: dict[str, dict] = {}
        for row in reader:
            url = (row.get("url") or "").strip()
            if not url:
                continue
            normalized = {}
            for key in NUMERIC_FIELDS:
                try:
                    normalized[key] = max(0, int(row.get(key, 0) or 0))
                except (ValueError, TypeError):
                    normalized[key] = 0
            normalized["status"] = (row.get("status") or "unknown").strip() or "unknown"
            # Duplicate URLs in the same CSV should not distort trends. Keep the last
            # deterministic row, matching the final source-health report.
            result[url] = normalized
    if not result:
        raise TrendError("source-health CSV contains no source rows")
    return result


def load_history(path: pathlib.Path) -> dict:
    if not path.exists():
        return {"schema_version": SCHEMA_VERSION, "snapshots": []}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrendError(f"could not read source-health history {path}: {exc}") from exc
    if not isinstance(value, dict) or value.get("schema_version") != SCHEMA_VERSION or not isinstance(value.get("snapshots"), list):
        raise TrendError(f"source-health history has an unsupported schema: {path}")
    for snapshot in value["snapshots"]:
        if not isinstance(snapshot, dict) or not isinstance(snapshot.get("sources"), dict):
            raise TrendError(f"source-health history contains a malformed snapshot: {path}")
    return value


def classify(values: list[dict], latest: dict, fetch_failures: int, parse_successes: int,
             unparsed: int, parsed_zero_unique: int) -> str:
    seen = len(values)
    recurring_threshold = max(2, math.ceil(seen * 0.30))
    if unparsed >= 2 and latest["status"] in {"fetched-but-unparsed", "extracted-but-rejected"}:
        return "recurring-parser-gap"
    if fetch_failures >= recurring_threshold:
        return "recurring-fetch-failure"
    if parse_successes >= 3 and parsed_zero_unique >= max(3, math.ceil(seen * 0.75)):
        return "repeated-zero-unique"
    if latest["unique"] > 0:
        return "contributing"
    if parse_successes > 0:
        return "intermittent-no-unique"
    return "monitor"


def render_trends(snapshots: list[dict]) -> str:
    urls = sorted({url for snapshot in snapshots for url in snapshot["sources"]})
    rows = []
    for url in urls:
        values = [snapshot["sources"][url] for snapshot in snapshots if url in snapshot["sources"]]
        latest = values[-1]
        fetch_successes = sum(v["fetch_successes"] > 0 for v in values)
        fetch_failures = sum(v["status"] == "fetch-failed" for v in values)
        parse_successes = sum(v["parsed"] > 0 for v in values)
        unparsed = sum(v["status"] in {"fetched-but-unparsed", "extracted-but-rejected"} for v in values)
        parsed_zero_unique = sum(v["parsed"] > 0 and v["unique"] == 0 for v in values)
        classification = classify(values, latest, fetch_failures, parse_successes, unparsed, parsed_zero_unique)
        rows.append({
            "url": url,
            "snapshots_seen": len(values),
            "fetch_success_runs": fetch_successes,
            "fetch_failed_runs": fetch_failures,
            "parse_success_runs": parse_successes,
            "unparsed_runs": unparsed,
            "parsed_zero_unique_runs": parsed_zero_unique,
            "latest_status": latest["status"],
            "latest_parsed": latest["parsed"],
            "latest_unique": latest["unique"],
            "average_parsed": round(sum(v["parsed"] for v in values) / len(values), 2),
            "average_unique": round(sum(v["unique"] for v in values) / len(values), 2),
            "latest_fetch_elapsed_ms": latest.get("fetch_elapsed_ms", 0),
            "max_fetch_elapsed_ms": max(v.get("fetch_elapsed_ms", 0) for v in values),
            "latest_parse_elapsed_ms": latest.get("parse_elapsed_ms", 0),
            "classification": classification,
        })
    priority = {
        "recurring-parser-gap": 0,
        "recurring-fetch-failure": 1,
        "repeated-zero-unique": 2,
        "intermittent-no-unique": 3,
        "monitor": 4,
        "contributing": 5,
    }
    rows.sort(key=lambda row: (
        priority.get(row["classification"], 99),
        -row["unparsed_runs"],
        -row["fetch_failed_runs"],
        -row["parsed_zero_unique_runs"],
        row["url"],
    ))
    import io
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=OUTPUT_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return buffer.getvalue()


def write_atomic(path: pathlib.Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def process(input_csv: pathlib.Path, history_path: pathlib.Path, output_csv: pathlib.Path,
            max_snapshots: int = 14, captured_at: str | None = None) -> dict:
    if max_snapshots < 1:
        raise TrendError("max-snapshots must be at least 1")
    sources = read_source_csv(input_csv)
    history = load_history(history_path)
    snapshots = list(history["snapshots"])
    snapshots.append({"captured_at_utc": captured_at or now_utc(), "sources": sources})
    snapshots = snapshots[-max_snapshots:]
    history = {"schema_version": SCHEMA_VERSION, "snapshots": snapshots}
    # Write the bounded history first, then the derived report. Both are replaced
    # atomically so interrupted runs never leave truncated JSON/CSV.
    write_atomic(history_path, json.dumps(history, ensure_ascii=False, indent=2) + "\n")
    write_atomic(output_csv, render_trends(snapshots))
    return {"snapshot_count": len(snapshots), "source_count": len(sources)}


def self_test() -> None:
    import tempfile

    def create_csv(path: pathlib.Path, rows: list[tuple]) -> None:
        fields = [
            "url", "fetch_successes", "raw_bytes", "raw_lines", "extracted_lines", "parsed",
            "unique", "provider_successes", "provider_failures", "fetch_elapsed_ms",
            "parse_elapsed_ms", "status",
        ]
        with path.open("w", encoding="utf-8", newline="") as stream:
            writer = csv.writer(stream)
            writer.writerow(fields)
            writer.writerows(rows)

    parser_gap = "https://example.test/unsupported.yaml"
    redundant = "https://example.test/duplicate.txt"
    contributor = "https://example.test/useful.txt"
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        history = root / "state" / "source-health-history.json"
        output = root / "sub" / "diagnostics" / "source-health-trends.csv"
        for idx in range(3):
            source_csv = root / f"source-health-{idx}.csv"
            create_csv(source_csv, [
                (parser_gap, 1, 1000, 20, 0, 0, 0, 0, 0, 100 + idx, 0, "fetched-but-unparsed"),
                (redundant, 1, 1000, 20, 15, 10, 0, 0, 0, 200 + idx, 20, "healthy"),
                (contributor, 1, 1000, 20, 10, 10, 4, 0, 0, 50 + idx, 10, "healthy"),
            ])
            process(source_csv, history, output, captured_at=f"2026-01-0{idx + 1}T00:00:00Z")
        with output.open("r", encoding="utf-8", newline="") as stream:
            rows = {r["url"]: r for r in csv.DictReader(stream)}
        assert rows[parser_gap]["classification"] == "recurring-parser-gap", rows[parser_gap]
        assert rows[redundant]["classification"] == "repeated-zero-unique", rows[redundant]
        assert rows[contributor]["classification"] == "contributing", rows[contributor]
        persisted = json.loads(history.read_text(encoding="utf-8"))
        assert len(persisted["snapshots"]) == 3
        print("Source-health trend self-tests passed: recurring parser gap, repeated zero contribution, useful source.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="sub/diagnostics/source-health.csv")
    parser.add_argument("--history", default="state/source-health-history.json")
    parser.add_argument("--output", default="sub/diagnostics/source-health-trends.csv")
    parser.add_argument("--max-snapshots", type=int, default=14)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        stats = process(pathlib.Path(args.input), pathlib.Path(args.history),
                        pathlib.Path(args.output), args.max_snapshots)
        print(f"Tracked {stats['source_count']} sources across {stats['snapshot_count']} recent runs; wrote {args.output}.")
        print("Trend classifications are review hints only; no sources are automatically removed.")
        return 0
    except (OSError, ValueError, TrendError) as exc:
        print(f"Could not update source-health history: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
