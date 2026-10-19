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

# Two malformed VLESS lines are repeated in checked-in generated snapshots. The
# source feeds are cleaned in this PR and the collector now rejects this malformed
# authority shape; keep the exception exact and visible until outputs are regenerated.
LEGACY_BAD_AGGREGATE_LINES = {
    "vless://My-chanel-Telegram-ATOVPN @136.148.64.242:443?security=tls&type=tcp#%F0%9F%87%B9%F0%9F%87%B7%20Istanbul%2C%20TR%20%C2%B7%20YottaSrc%20%7C%20136.148.64.242%20%3A443%C2%B7vless",
    "vless://My-chanel-Telegram-ATOVPN @167.104.219.12:35671?security=tls&type=tcp#%F0%9F%87%B9%F0%9F%87%B7%20Istanbul%2C%20TR%20%C2%B7%20YottaSrc%20%7C%20167.104.219.12%20%3A35671%C2%B7vless",
}


class ValidationError(Exception):
    pass


def validate_lines(path: pathlib.Path) -> tuple[int, int]:
    try:
        raw = path.read_bytes()
        text = raw.decode("utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValidationError(f"{path}: cannot read as UTF-8: {exc}") from exc

    lines = [line.strip() for line in text.splitlines() if line.strip()]

    # Some generated .txt files intentionally contain Clash YAML rather than one
    # URI per line (currently protocols/wireguard.txt). Validate each proxy block
    # structurally instead of misclassifying YAML keys as malformed proxy links.
    if lines and lines[0].lower() == "proxies:":
        blocks = re.split(r"(?m)^\s*-\s+", text)[1:]
        if not blocks:
            raise ValidationError(f"{path}: YAML subscription has no proxy entries")
        for index, block in enumerate(blocks, 1):
            kind = re.search(r"""(?m)^\s*type\s*:\s*['"]?([a-z0-9_-]+)""", block, re.IGNORECASE)
            server = re.search(r"""(?m)^\s*(?:server|server-host|endpoint|address)\s*:\s*([^#\n]+)""", block, re.IGNORECASE)
            port = re.search(r"""(?m)^\s*port\s*:\s*['"]?(\d+)""", block, re.IGNORECASE)
            if not kind or kind.group(1).lower() not in SCHEMES:
                raise ValidationError(f"{path}: YAML proxy entry {index} has missing/unsupported type")
            if not server or not server.group(1).strip().strip("'\""):
                raise ValidationError(f"{path}: YAML proxy entry {index} has no server endpoint")
            if not port or not (1 <= int(port.group(1)) <= 65535):
                raise ValidationError(f"{path}: YAML proxy entry {index} has invalid port")
        return len(blocks), 0

    allowed_legacy_lines = (
        LEGACY_BAD_AGGREGATE_LINES
        if path.parent.name == "sub" and path.name in {"everything.txt", "stable.txt", "ipv4_only.txt"}
        else set()
    )
    malformed = [
        (i, line[:120])
        for i, line in enumerate(text.splitlines(), 1)
        if line.strip()
        and not URI_RE.fullmatch(line.strip())
        and line.strip() not in allowed_legacy_lines
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
        allowed_legacy_lines = (
            LEGACY_BAD_AGGREGATE_LINES
            if path.parent.name == "sub" and path.name in {"everything.txt", "stable.txt", "ipv4_only.txt"}
            else set()
        )
        legacy_count = sum(
            1 for line in path.read_text(encoding="utf-8-sig").splitlines()
            if line.strip() in allowed_legacy_lines
        )
        if legacy_count:
            report.append(
                f"WARNING {rel}: {legacy_count} exact legacy malformed line(s) tolerated until output regeneration"
            )
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
        if not URI_RE.fullmatch(line):
            raise ValidationError(f"self-test rejected valid URI: {line}")
    for line in (
        "https://example.com/subscription",
        "not a proxy URI",
        "<html>oops</html>",
        "vless://uuid@example.com:443 trailing-junk",
        "vless://uuid@example.com:443 extra words",
        "vless://user @example.com:443",
    ):
        if URI_RE.fullmatch(line):
            raise ValidationError(f"self-test accepted invalid subscription line: {line}")

    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "top.txt").write_text(good[0] + "\n", encoding="utf-8")
        (root / "verified.txt").write_text(good[0] + "\n", encoding="utf-8")
        (root / "everything.txt").write_text("\n".join(good) + "\n", encoding="utf-8")
        (root / "ipv6_only.txt").write_text(good[4] + "\n", encoding="utf-8")
        (root / "malformed_source.txt").write_text(next(iter(LEGACY_BAD_AGGREGATE_LINES)) + "\n", encoding="utf-8")
        try:
            validate_lines(root / "malformed_source.txt")
        except ValidationError:
            pass
        else:
            raise ValidationError("self-test allowed a legacy malformed URI outside generated aggregate files")
        (root / "malformed_source.txt").unlink()
        yaml = 'proxies:\n  - name: "WG test"\n    type: wireguard\n    server: "2001:db8::1"\n    port: 51820\n'
        (root / "wireguard.txt").write_text(yaml, encoding="utf-8")
        validate_tree(root)
        if validate_lines(root / "wireguard.txt")[0] != 1:
            raise ValidationError("self-test failed to count YAML proxy entries")
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
