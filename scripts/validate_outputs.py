#!/usr/bin/env python3
"""Structural validation for generated FastNodes subscription text files."""
from __future__ import annotations

import argparse
import pathlib
import re
import sys
from collections import Counter

SCHEMES = (
    "vmess", "vless", "trojan", "ss", "shadowsocks", "ssr", "hysteria",
    "hysteria2", "hy2", "tuic", "naive", "anytls", "brook", "snell",
    "juicity", "mieru", "wireguard", "wg", "socks5", "socks4", "socks",
)
SCHEME_PATTERN = "|".join(sorted((re.escape(s) for s in SCHEMES), key=len, reverse=True))
URI_RE = re.compile(rf"^(?:{SCHEME_PATTERN})://\S+", re.IGNORECASE)
REQUIRED = ("top.txt", "verified.txt", "everything.txt")
MAX_TOP_LINES = 1000


class ValidationError(Exception):
    pass


def validate_lines(path: pathlib.Path) -> tuple[int, int]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValidationError(f"{path}: cannot read as UTF-8: {exc}") from exc

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    malformed = [
        (i, line[:120])
        for i, line in enumerate(text.splitlines(), 1)
        if line.strip() and not URI_RE.match(line.strip())
    ]
    if malformed:
        sample = "; ".join(f"line {i}: {value!r}" for i, value in malformed[:5])
        raise ValidationError(
            f"{path}: {len(malformed)} malformed subscription line(s): {sample}"
        )

    counts = Counter(lines)
    duplicates = sum(n - 1 for n in counts.values() if n > 1)
    return len(lines), duplicates


def validate_tree(root: pathlib.Path) -> list[str]:
    if not root.is_dir():
        raise ValidationError(f"output directory does not exist: {root}")

    for name in REQUIRED:
        path = root / name
        if not path.is_file() or path.stat().st_size == 0:
            raise ValidationError(f"required subscription is missing or empty: {path}")

    report: list[str] = []
    counts: dict[str, int] = {}
    for path in sorted(root.rglob("*.txt")):
        count, duplicates = validate_lines(path)
        rel = path.relative_to(root).as_posix()
        counts[rel] = count
        if duplicates:
            report.append(f"WARNING {rel}: {duplicates} duplicate line(s)")
        if path.stat().st_size > 50 * 1024 * 1024:
            report.append(f"WARNING {rel}: file exceeds 50 MiB ({path.stat().st_size} bytes)")

    if counts.get("top.txt", 0) > MAX_TOP_LINES:
        raise ValidationError(
            f"top.txt has {counts['top.txt']} lines; maximum is {MAX_TOP_LINES}"
        )
    for name in ("verified.txt", "everything.txt"):
        if counts.get(name, 0) == 0:
            raise ValidationError(f"{name} is empty; refusing to publish")

    report.insert(0, "Validated subscriptions: " + " ".join(
        f"{name}={counts.get(name, 0)}" for name in REQUIRED
    ))
    report.append(f"Validated {len(counts)} generated .txt file(s).")
    return report


def self_test() -> None:
    import tempfile

    good = [
        "vless://uuid@example.com:443?security=tls",
        "vmess://eyJhZGQiOiIxOTIuMC4yLjEifQ==",
        "ss://method:password@example.net:8388",
        "wireguard://example.net:51820",
        "vless://uuid@[2001:db8::1]:443?security=tls",
    ]
    for line in good:
        if not URI_RE.match(line):
            raise ValidationError(f"self-test rejected valid URI: {line}")
    for line in ("https://example.com/subscription", "not a proxy URI", "<html>oops</html>"):
        if URI_RE.match(line):
            raise ValidationError(f"self-test accepted invalid subscription line: {line}")

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "top.txt").write_text(good[0] + "\n", encoding="utf-8")
        (root / "verified.txt").write_text(good[0] + "\n", encoding="utf-8")
        (root / "everything.txt").write_text("\n".join(good) + "\n", encoding="utf-8")
        (root / "ipv6_only.txt").write_text(good[4] + "\n", encoding="utf-8")
        validate_tree(root)
        (root / "protocols").mkdir()
        (root / "protocols" / "vless.txt").write_text("not a proxy URI\n", encoding="utf-8")
        try:
            validate_tree(root)
        except ValidationError:
            pass
        else:
            raise ValidationError("self-test failed to catch malformed nested output")

    print("Output-validator self-tests passed.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=pathlib.Path, help="generated subscription directory")
    parser.add_argument("--self-test", action="store_true", help="run built-in tests without output files")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        if args.root is None:
            parser.error("provide output directory or --self-test")
        for line in validate_tree(args.root):
            print(line)
        return 0
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
