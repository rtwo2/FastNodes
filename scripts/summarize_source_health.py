#!/usr/bin/env python3
"""Summarize per-source fetch, parse, and unique contribution diagnostics."""
from __future__ import annotations
import argparse, csv, pathlib, sys
from collections import Counter, defaultdict
from urllib.parse import urlsplit

REQUIRED = {"url", "fetch_successes", "raw_bytes", "raw_lines", "extracted_lines",
            "parsed", "unique", "provider_successes", "provider_failures", "status"}
BAD = {"fetch-failed", "empty-body", "fetched-but-unparsed", "provider-failed-or-unparsed",
       "extracted-but-rejected", "healthy-with-provider-errors"}

def number(row: dict, key: str) -> int:
    try: return int(row.get(key, 0) or 0)
    except (TypeError, ValueError): return 0

def group_source(url: str) -> str:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        parts = [p for p in parsed.path.split("/") if p]
        if host in {"raw.githubusercontent.com", "github.com"} and len(parts) >= 2:
            return f"github.com/{parts[0]}/{parts[1].removesuffix('.git')}"
        if host == "cdn.jsdelivr.net" and len(parts) >= 3 and parts[0] == "gh":
            return f"github.com/{parts[1]}/{parts[2].split('@', 1)[0].removesuffix('.git')}"
        return host or "(invalid source URL)"
    except ValueError:
        return "(invalid source URL)"

def cell(value: str) -> str:
    return str(value).replace("|", r"\|").replace("\n", " ").replace("\r", " ").replace(chr(96), "'")

def render(csv_path: pathlib.Path) -> str:
    if not csv_path.is_file():
        return ("# Source health summary\n\nSource-health CSV was not produced: "
                f"{csv_path}. Check the collector step and log artifact.\n")
    with csv_path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        fields = set(reader.fieldnames or [])
        if not REQUIRED.issubset(fields):
            return ("# Source health summary\n\nIncomplete CSV schema; missing columns: "
                    + ", ".join(sorted(REQUIRED - fields)) + ".\n")
        rows = list(reader)
    statuses = Counter((r.get("status") or "unknown").strip() or "unknown" for r in rows)
    total_bytes = sum(number(r, "raw_bytes") for r in rows)
    extracted = sum(number(r, "extracted_lines") for r in rows)
    parsed = sum(number(r, "parsed") for r in rows)
    unique = sum(number(r, "unique") for r in rows)
    provider_ok = sum(number(r, "provider_successes") for r in rows)
    provider_bad = sum(number(r, "provider_failures") for r in rows)
    yielded = sum(number(r, "parsed") > 0 for r in rows)
    failed = sum((r.get("status") or "").strip() == "fetch-failed" for r in rows)
    fetched_unparsed = [r for r in rows if (r.get("status") or "").strip() == "fetched-but-unparsed"]
    parsed_zero_unique = [r for r in rows if number(r, "parsed") > 0 and number(r, "unique") == 0]
    slow_fetch = sorted((r for r in rows if number(r, "fetch_elapsed_ms") > 0),
                        key=lambda r: (-number(r, "fetch_elapsed_ms"), r.get("url", "")))[:10]
    slow_parse = sorted((r for r in rows if number(r, "parse_elapsed_ms") > 0),
                        key=lambda r: (-number(r, "parse_elapsed_ms"), r.get("url", "")))[:10]
    lines = [
        "# Source health summary", "",
        f"- Sources listed: **{len(rows):,}**",
        f"- Sources yielding parsed configurations: **{yielded:,}** ({yielded / len(rows):.1%})" if rows else "- Sources yielding parsed configurations: **0**",
        f"- Fetch failures: **{failed:,}**",
        f"- Downloaded bytes: **{total_bytes / (1024 * 1024):,.1f} MiB**",
        f"- Extracted proxy-like lines: **{extracted:,}**",
        f"- Parsed configurations before global deduplication/filtering: **{parsed:,}**",
        f"- First-contributor unique count: **{unique:,}**",
        f"- Nested provider fetches: **{provider_ok:,} succeeded / {provider_bad:,} failed after retry**",
        f"- Fetched but unparsed sources: **{len(fetched_unparsed):,}**",
        f"- Parsed sources adding no first-contributor nodes this run: **{len(parsed_zero_unique):,}**",
        "", "First-contributor counts follow deterministic source priority, but change as feeds change. A zero-unique source is not automatically redundant or safe to remove; compare multiple runs first.",
        "", "## Status counts", "", "| Status | Sources |", "|---|---:|"
    ]
    for name, count in sorted(statuses.items(), key=lambda x: (-x[1], x[0])):
        lines.append(f"| {cell(name)} | {count:,} |")
    rank = sorted(rows, key=lambda r: (-number(r, "unique"), -number(r, "parsed"), r.get("url", "")))
    lines += ["", "## Highest unique contribution", "", "| Unique | Parsed | Extracted | Status | Source |", "|---:|---:|---:|---|---|"]
    positive = [r for r in rank if number(r, "unique") > 0][:15]
    if not positive: lines.append("| — | — | — | — | No positive unique contributions |")
    for r in positive:
        lines.append(f"| {number(r, 'unique'):,} | {number(r, 'parsed'):,} | {number(r, 'extracted_lines'):,} | "
                     f"{cell(r.get('status', ''))} | {cell(r.get('url', ''))} |")
    groups = defaultdict(lambda: {"sources": 0, "parsed": 0, "unique": 0, "failures": 0})
    for r in rows:
        x = groups[group_source(r.get("url", ""))]
        x["sources"] += 1
        x["parsed"] += number(r, "parsed")
        x["unique"] += number(r, "unique")
        x["failures"] += int((r.get("status") or "").strip() == "fetch-failed")
    lines += ["", "## Repository/host contribution", "", "| Unique | Parsed | Feeds | Fetch failures | Source group |", "|---:|---:|---:|---:|---|"]
    for name, x in sorted(groups.items(), key=lambda kv: (-kv[1]["unique"], -kv[1]["parsed"], kv[0]))[:15]:
        lines.append(f"| {x['unique']:,} | {x['parsed']:,} | {x['sources']:,} | {x['failures']:,} | {cell(name)} |")
    bad = [r for r in rows if (r.get("status") or "").strip() in BAD]
    order = {"fetch-failed": 0, "empty-body": 1, "fetched-but-unparsed": 2,
             "provider-failed-or-unparsed": 3, "extracted-but-rejected": 4,
             "healthy-with-provider-errors": 5}
    bad.sort(key=lambda r: (order.get((r.get("status") or "").strip(), 99), -number(r, "raw_bytes"), r.get("url", "")))
    lines += ["", "## Sources to review", "", "| Status | Parsed | Extracted | Bytes | Source |", "|---|---:|---:|---:|---|"]
    for r in bad[:25]:
        lines.append(f"| {cell(r.get('status', ''))} | {number(r, 'parsed'):,} | {number(r, 'extracted_lines'):,} | "
                     f"{number(r, 'raw_bytes'):,} | {cell(r.get('url', ''))} |")
    if not bad: lines.append("| — | — | — | — | No source status requires review |")
    if slow_fetch:
        lines += ["", "## Slowest source fetch/provider processing", "", "| Time (ms) | Parsed | Unique | Status | Source |", "|---:|---:|---:|---|---|"]
        for r in slow_fetch:
            lines.append(f"| {number(r, 'fetch_elapsed_ms'):,} | {number(r, 'parsed'):,} | {number(r, 'unique'):,} | {cell(r.get('status', ''))} | {cell(r.get('url', ''))} |")
    if slow_parse:
        lines += ["", "## Slowest source parsing/deduplication", "", "| Time (ms) | Parsed | Unique | Status | Source |", "|---:|---:|---:|---|---|"]
        for r in slow_parse:
            lines.append(f"| {number(r, 'parse_elapsed_ms'):,} | {number(r, 'parsed'):,} | {number(r, 'unique'):,} | {cell(r.get('status', ''))} | {cell(r.get('url', ''))} |")
    return "\n".join(lines) + "\n"

def self_test() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = pathlib.Path(tmp) / "source-health.csv"
        path.write_text(
            "url,fetch_successes,raw_bytes,raw_lines,extracted_lines,parsed,unique,provider_successes,provider_failures,fetch_elapsed_ms,parse_elapsed_ms,status\n"
            '"https://raw.githubusercontent.com/alpha/repo/main/a.txt",1,1000,100,40,35,20,2,0,100,20,healthy\n'
            '"https://raw.githubusercontent.com/alpha/repo/main/b.txt",1,500,50,20,20,0,0,1,300,80,healthy-with-provider-errors\n'
            '"https://example.test/feed",0,0,0,0,0,0,0,0,10,0,fetch-failed\n', encoding="utf-8")
        report = render(path)
        assert "Sources listed: **3**" in report
        assert "github.com/alpha/repo" in report
        assert "Highest unique contribution" in report
        assert "fetch-failed" in report and "20" in report
        assert "Parsed sources adding no first-contributor nodes this run: **1**" in report
        assert "Slowest source fetch/provider processing" in report
        assert "Slowest source parsing/deduplication" in report
        print("Source-health summary self-tests passed.")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="sub/diagnostics/source-health.csv")
    parser.add_argument("--output")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        report = render(pathlib.Path(args.input))
        if args.output:
            out = pathlib.Path(args.output)
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(report, encoding="utf-8")
        else:
            print(report)
        if "was not produced" in report or "Incomplete CSV schema" in report:
            print("WARNING: source-health summary is incomplete.", file=sys.stderr)
        else:
            print(f"Source-health summary generated from {args.input}.", file=sys.stderr)
        return 0
    except (OSError, csv.Error) as exc:
        print(f"Could not summarize source health: {exc}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
