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
EXPECTED_FILES = ("top_ipv6.txt", "ipv4_only.txt", "ipv6_only.txt")
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

    # Some generated .txt files intentionally contain Clash YAML rather than one
    # URI per line (currently protocols/wireguard.txt). Validate each proxy block
    # structurally instead of misclassifying YAML keys as malformed proxy links.
    if lines and lines[0].lower() == "proxies:":
        # Split only on top-level list items. WireGuard nodes can contain a nested
        # "reserved" sequence; treating its indented "- 0" entries as proxy boundaries
        # produced the reported false "entry 2 has missing type" validation failure.
        # Capture the first list indentation and ignore deeper list items.
        blocks: list[str] = []
        current: list[str] = []
        item_indent: str | None = None
        for line in text.splitlines():
            marker = re.match(r"^(?P<indent>[ \t]*)-[ \t]+", line)
            if marker and (item_indent is None or marker.group("indent") == item_indent):
                if item_indent is None:
                    item_indent = marker.group("indent")
                if current:
                    blocks.append("\n".join(current))
                current = [line]
            elif current:
                current.append(line)
        if current:
            blocks.append("\n".join(current))
        if not blocks:
            raise ValidationError(f"{path}: YAML subscription has no proxy entries")

        for index, block in enumerate(blocks, 1):
            kind = re.search(r"""(?m)^[ \t]*type[ \t]*:[ \t]*['"]?([a-z0-9_-]+)""", block, re.IGNORECASE)
            server = re.search(r"""(?m)^[ \t]*(?:server|server-host|endpoint|address)[ \t]*:[ \t]*([^#\n]+)""", block, re.IGNORECASE)
            port = re.search(r"""(?m)^[ \t]*port[ \t]*:[ \t]*['"]?(\d+)""", block, re.IGNORECASE)
            actual_type = kind.group(1).lower() if kind else "<missing>"
            if not kind or actual_type not in SCHEMES:
                raise ValidationError(
                    f"{path}: YAML proxy entry {index} has missing/unsupported type {actual_type!r}"
                )
            if not server or not server.group(1).strip().strip("'\""):
                raise ValidationError(f"{path}: YAML proxy entry {index} has no server endpoint")
            if not port or not (1 <= int(port.group(1)) <= 65535):
                raise ValidationError(f"{path}: YAML proxy entry {index} has invalid port")
        return len(blocks), 0

    malformed = [
        (i, line[:120])
        for i, line in enumerate(text.splitlines(), 1)
        if line.strip()
        and not URI_RE.fullmatch(line.strip())
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

    # The IPv6 shortlist may be empty if no eligible candidates exist, but the
    # generator must always publish the file so consumers have a stable URL.
    for name in EXPECTED_FILES:
        path = root / name
        if not path.is_file():
            raise ValidationError(f"expected subscription file is missing: {path}")

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

    for name in ("top.txt", "top_ipv6.txt"):
        if counts.get(name, 0) > MAX_TOP_LINES:
            raise ValidationError(
                f"{name} has {counts[name]} lines; maximum is {MAX_TOP_LINES}"
            )
        # Ranked shortlists are curated selections; duplicate entries waste slots
        # and make ranking/diversity guarantees unreliable.
        if counts.get(name, 0):
            lines = [
                line.strip()
                for line in (root / name).read_text(encoding="utf-8-sig").splitlines()
                if line.strip()
            ]
            if len(lines) != len(set(lines)):
                raise ValidationError(f"{name} contains duplicate entries")
    for name in ("top.txt", "verified.txt", "everything.txt"):
        if counts.get(name, 0) == 0:
            raise ValidationError(f"{name} is empty; refusing to publish")

    # The ranked IPv6 shortlist is generated directly from ipv6_only.txt's
    # candidate pool. Every top_ipv6 entry must therefore exist in the family
    # feed; catch accidental truncation or mismatched output publication.
    top_ipv6_path = root / "top_ipv6.txt"
    ipv6_only_path = root / "ipv6_only.txt"
    top_ipv6_links = {
        line.strip() for line in top_ipv6_path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    }
    ipv6_links = {
        line.strip() for line in ipv6_only_path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    }
    missing_ipv6_links = top_ipv6_links - ipv6_links
    if missing_ipv6_links:
        sample = next(iter(missing_ipv6_links))[:120]
        raise ValidationError(
            f"top_ipv6.txt contains {len(missing_ipv6_links)} node(s) missing from "
            f"ipv6_only.txt; sample: {sample!r}"
        )

    # These feeds are all derived from the current-run final proxy pool. Unlike
    # verified.txt, which may intentionally use a last-good snapshot, none of them
    # should contain a link absent from everything.txt.
    everything_links = {
        line.strip() for line in (root / "everything.txt").read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    }
    for name in ("top.txt", "ipv4_only.txt", "ipv6_only.txt"):
        path = root / name
        links = {
            line.strip() for line in path.read_text(encoding="utf-8-sig").splitlines()
            if line.strip()
        }
        missing = links - everything_links
        if missing:
            sample = next(iter(missing))[:120]
            raise ValidationError(
                f"{name} contains {len(missing)} node(s) missing from everything.txt; "
                f"sample: {sample!r}"
            )

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
        (root / "top_ipv6.txt").write_text(good[4] + "\n", encoding="utf-8")
        (root / "verified.txt").write_text(good[0] + "\n", encoding="utf-8")
        (root / "everything.txt").write_text("\n".join(good) + "\n", encoding="utf-8")
        (root / "ipv4_only.txt").write_text(good[0] + "\n", encoding="utf-8")
        (root / "ipv6_only.txt").write_text(good[4] + "\n", encoding="utf-8")
        yaml = ('proxies:\n'
                '  - name: "WG test 1"\n    type: wireguard\n    server: "2001:db8::1"\n    port: 51820\n    reserved:\n      - 0\n      - 0\n      - 0\n'
                '  - name: "WG test 2"\n    type: wireguard\n    server: "198.51.100.2"\n    port: 123\n')
        (root / "wireguard.txt").write_text(yaml, encoding="utf-8")
        validate_tree(root)

        rogue_link = "vless://rogue@example.net:443?security=tls"
        for name in ("top.txt", "ipv4_only.txt", "ipv6_only.txt"):
            path = root / name
            original = path.read_text(encoding="utf-8")
            path.write_text(original + rogue_link + "\n", encoding="utf-8")
            try:
                validate_tree(root)
            except ValidationError as exc:
                if f"{name} contains " not in str(exc) or "missing from everything.txt" not in str(exc):
                    raise
            else:
                raise ValidationError(f"self-test failed to catch {name} entries missing from everything.txt")
            finally:
                path.write_text(original, encoding="utf-8")

        original_top = (root / "top.txt").read_text(encoding="utf-8")
        (root / "top.txt").write_text("\n  \n", encoding="utf-8")
        try:
            validate_tree(root)
        except ValidationError as exc:
            if "top.txt is empty" not in str(exc):
                raise
        else:
            raise ValidationError("self-test failed to catch a blank-only top.txt")
        finally:
            (root / "top.txt").write_text(original_top, encoding="utf-8")

        (root / "ipv6_only.txt").write_text(good[0] + "\n", encoding="utf-8")
        try:
            validate_tree(root)
        except ValidationError as exc:
            if "missing from ipv6_only.txt" not in str(exc):
                raise
        else:
            raise ValidationError("self-test failed to catch top_ipv6.txt entries missing from ipv6_only.txt")
        (root / "ipv6_only.txt").write_text(good[4] + "\n", encoding="utf-8")
        (root / "top.txt").write_text(good[0] + "\n" + good[0] + "\n", encoding="utf-8")
        try:
            validate_tree(root)
        except ValidationError as exc:
            if "top.txt contains duplicate entries" not in str(exc):
                raise
        else:
            raise ValidationError("self-test failed to catch duplicate ranked entries")
        (root / "top.txt").write_text(good[0] + "\n", encoding="utf-8")
        (root / "top_ipv6.txt").unlink()
        try:
            validate_tree(root)
        except ValidationError:
            pass
        else:
            raise ValidationError("self-test failed to catch a missing top_ipv6.txt")
        (root / "top_ipv6.txt").write_text(good[4] + "\n", encoding="utf-8")
        if validate_lines(root / "wireguard.txt")[0] != 2:
            raise ValidationError("self-test failed to count multiple YAML proxy entries")
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
