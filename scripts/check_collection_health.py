#!/usr/bin/env python3
"""Baseline-aware output regression and file-size checks for FastNodes."""
from __future__ import annotations
import argparse, json, math, pathlib, sys
from datetime import datetime, timezone

MIB = 1024 * 1024
MAX_FILE_BYTES = 90 * MIB  # Below GitHub's 100 MiB per-file hard limit.
MIN_EVERYTHING_LINES = 10_000
MIN_TOP_LINES = 100
MIN_RETAINED = 0.30
KEY_OUTPUTS = ("everything.txt", "top.txt", "verified.txt", "stable.txt",
               "ipv4_only.txt", "ipv6_only.txt", "top_ipv6.txt",
               "verified_tls.txt", "curated.txt")

class HealthError(Exception):
    pass

def count_lines(path: pathlib.Path) -> int:
    size = path.stat().st_size
    if not size: return 0
    count, last = 0, b""
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block: break
            count += block.count(b"\n")
            last = block[-1:]
    return count + int(last != b"\n")

def inspect_tree(root: pathlib.Path) -> dict:
    if not root.is_dir(): raise HealthError(f"output directory does not exist: {root}")
    files = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file(): continue
        rel = path.relative_to(root).as_posix()
        item = {"bytes": path.stat().st_size}
        if path.suffix.lower() == ".txt": item["lines"] = count_lines(path)
        files[rel] = item
    return {"total_files": len(files), "total_bytes": sum(v["bytes"] for v in files.values()), "files": files}

def capture_baseline(root: pathlib.Path, output: pathlib.Path) -> dict:
    tree = inspect_tree(root)
    value = {"schema_version": 1, "captured_at": datetime.now(timezone.utc).isoformat(),
             "total_files": tree["total_files"], "total_bytes": tree["total_bytes"], "files": tree["files"]}
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    print(f"Captured previous output baseline: {tree['total_files']} files, {tree['total_bytes'] / MIB:.1f} MiB")
    return value

def over_limit_files(files: dict, maximum: int = MAX_FILE_BYTES) -> list[tuple[str, int]]:
    return sorted(((name, int(row["bytes"])) for name, row in files.items()
                   if int(row.get("bytes", 0)) > maximum), key=lambda pair: pair[1], reverse=True)

def evaluate(root: pathlib.Path, baseline: dict | None = None,
             maximum: int = MAX_FILE_BYTES) -> tuple[dict, list[str]]:
    current = inspect_tree(root)
    files = current["files"]
    previous = (baseline or {}).get("files", {})
    errors, warnings = [], []
    for name, size in over_limit_files(files, maximum):
        errors.append(f"{name} is {size / MIB:.1f} MiB, over {maximum / MIB:.1f} MiB file ceiling")

    everything = files.get("everything.txt")
    top = files.get("top.txt")
    everything_count = int((everything or {}).get("lines", 0))
    if everything is None:
        errors.append("everything.txt is missing")
    elif everything_count < MIN_EVERYTHING_LINES:
        errors.append(f"everything.txt has {everything_count:,} lines; minimum is {MIN_EVERYTHING_LINES:,}")
    if top is None:
        errors.append("top.txt is missing")
    elif int(top.get("lines", 0)) < MIN_TOP_LINES:
        errors.append(f"top.txt has {top.get('lines', 0):,} lines; minimum is {MIN_TOP_LINES}")

    old_count = int(previous.get("everything.txt", {}).get("lines", 0) or 0)
    required = max(MIN_EVERYTHING_LINES, math.ceil(old_count * MIN_RETAINED))
    if old_count >= MIN_EVERYTHING_LINES and everything_count < required:
        errors.append(f"catastrophic everything.txt regression: {old_count:,} -> {everything_count:,} lines "
                      f"({everything_count / old_count:.1%} retained; need at least {required:,})")

    old_total = int((baseline or {}).get("total_bytes", 0) or 0)
    if old_total and current["total_bytes"] > old_total * 1.5 and current["total_bytes"] - old_total > 100 * MIB:
        warnings.append(f"output tree grew sharply: {old_total / MIB:.1f} -> "
                        f"{current['total_bytes'] / MIB:.1f} MiB; check source duplication")

    deltas = []
    for name, item in files.items():
        old = previous.get(name)
        if old is None: continue
        change = int(item["bytes"]) - int(old.get("bytes", 0))
        if not change: continue
        deltas.append({"path": name, "previous_bytes": int(old.get("bytes", 0)),
                       "current_bytes": int(item["bytes"]), "delta_bytes": change,
                       "previous_lines": old.get("lines"), "current_lines": item.get("lines"),
                       "delta_lines": (int(item["lines"]) - int(old["lines"])
                                       if item.get("lines") is not None and old.get("lines") is not None else None)})
    growth = sorted((x for x in deltas if x["delta_bytes"] > 0), key=lambda x: x["delta_bytes"], reverse=True)[:10]
    shrink = sorted((x for x in deltas if x["delta_bytes"] < 0), key=lambda x: x["delta_bytes"])[:10]
    largest = sorted(({"path": k, "bytes": int(v["bytes"])} for k, v in files.items()),
                     key=lambda x: x["bytes"], reverse=True)[:10]
    keys = {}
    for name in KEY_OUTPUTS:
        now, old = files.get(name), previous.get(name)
        keys[name] = ({"present": False} if now is None else
                      {"present": True, "lines": now.get("lines"), "bytes": now["bytes"],
                       "previous_lines": old.get("lines") if old else None,
                       "previous_bytes": old.get("bytes") if old else None})
    report = {
        "schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(),
        "baseline_captured_at": (baseline or {}).get("captured_at"),
        "limits": {"max_file_bytes": maximum, "min_everything_lines": MIN_EVERYTHING_LINES,
                   "min_top_lines": MIN_TOP_LINES, "minimum_everything_retained_fraction": MIN_RETAINED},
        "current": {"total_files": current["total_files"], "total_bytes": current["total_bytes"],
                    "total_mib": round(current["total_bytes"] / MIB, 2), "largest_files": largest},
        "outputs": keys, "largest_growth_by_bytes": growth, "largest_shrink_by_bytes": shrink,
        "warnings": warnings, "errors": errors
    }
    return report, errors

def self_test() -> None:
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp) / "sub"
        root.mkdir()
        (root / "everything.txt").write_text("n\n" * 20_000, encoding="utf-8")
        (root / "top.txt").write_text("n\n" * 100, encoding="utf-8")
        (root / "verified.txt").write_text("n\n" * 100, encoding="utf-8")
        snap = inspect_tree(root)
        baseline = {"captured_at": "test", "total_bytes": snap["total_bytes"], "files": dict(snap["files"])}
        baseline["files"]["everything.txt"] = {"bytes": snap["files"]["everything.txt"]["bytes"] * 2, "lines": 50_000}
        report, errors = evaluate(root, baseline)
        assert not errors, errors
        assert report["outputs"]["everything.txt"]["lines"] == 20_000
        (root / "everything.txt").write_text("n\n" * 12_000, encoding="utf-8")
        _, errors = evaluate(root, baseline)
        assert any("catastrophic everything.txt regression" in x for x in errors), errors
        assert over_limit_files({"large.bin": {"bytes": 11}}, 10) == [("large.bin", 11)]
        print("Collection-health self-tests passed: baseline, catastrophic drop, and size ceiling.")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    sub = parser.add_subparsers(dest="command")
    capture = sub.add_parser("capture")
    capture.add_argument("--root", default="sub")
    capture.add_argument("--output", required=True)
    check = sub.add_parser("check")
    check.add_argument("--root", default="sub")
    check.add_argument("--baseline")
    check.add_argument("--report")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        if args.command == "capture":
            capture_baseline(pathlib.Path(args.root), pathlib.Path(args.output))
            return 0
        if args.command == "check":
            baseline = None
            if args.baseline:
                with pathlib.Path(args.baseline).open(encoding="utf-8") as stream: baseline = json.load(stream)
                if baseline.get("schema_version") != 1 or not isinstance(baseline.get("files"), dict):
                    raise HealthError("output baseline has an unsupported schema")
            report, errors = evaluate(pathlib.Path(args.root), baseline)
            if args.report:
                dest = pathlib.Path(args.report)
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            print(f"Output health: {report['current']['total_files']} files, {report['current']['total_mib']:.1f} MiB; "
                  f"everything.txt={report['outputs'].get('everything.txt', {}).get('lines', 0):,} lines")
            for item in report["warnings"]: print(f"WARNING: {item}")
            for item in report["largest_growth_by_bytes"][:5]:
                print(f"Growth: {item['path']} +{item['delta_bytes'] / MIB:.1f} MiB")
            for item in errors: print(f"ERROR: {item}", file=sys.stderr)
            if errors: return 1
            print("Collection-health checks passed.")
            return 0
    except (OSError, ValueError, json.JSONDecodeError, HealthError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    parser.error("choose capture or check, or pass --self-test")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
