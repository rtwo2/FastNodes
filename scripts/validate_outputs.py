#!/usr/bin/env python3
"""Structural validation for generated FastNodes subscription text files."""
from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import pathlib
import re
import sys
from collections import Counter
from urllib.parse import parse_qsl, unquote, urlsplit

SCHEMES = (
    "vmess", "vless", "trojan", "ss", "shadowsocks", "ssr", "hysteria",
    "hysteria2", "hy2", "tuic", "naive", "anytls", "brook", "snell",
    "juicity", "mierus", "wireguard", "wg", "socks5", "socks4", "socks",
)
SCHEME_PATTERN = "|".join(sorted((re.escape(s) for s in SCHEMES), key=len, reverse=True))
URI_RE = re.compile(rf"^(?:{SCHEME_PATTERN})://\S+", re.IGNORECASE)
REQUIRED = ("top.txt", "everything.txt")
# The committed public snapshot predates the historical-feed split. The
# collection workflow independently requires verified_last_good.txt after a
# fresh run, while this validator allows legacy checked-in snapshots to migrate.
EXPECTED_FILES = (
    "top_ipv6.txt", "ipv4_only.txt", "ipv6_only.txt",
    "verified.txt",
)
MAX_TOP_LINES = 1000
MAX_PART_BYTES = 50 * 1024 * 1024

class ValidationError(Exception):
    pass


def _normalize_identity_host(host: str) -> str:
    value = (host or "").strip().strip("[]").rstrip(".")
    if not value:
        return ""
    try:
        address = ipaddress.ip_address(value)
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return address.compressed.lower()
    except ValueError:
        return value.encode("idna").decode("ascii").lower()


def _decode_urlsafe_base64(value: str) -> str:
    token = value.strip().replace("-", "+").replace("_", "/")
    token += "=" * ((4 - len(token) % 4) % 4)
    return base64.b64decode(token, validate=False).decode("utf-8")


def _normalize_uuid_credential(value: str) -> str:
    if re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        value,
    ):
        return value.lower()
    return value


def _normalize_wireguard_key(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    try:
        token = raw.replace("-", "+").replace("_", "/")
        token += "=" * ((4 - len(token) % 4) % 4)
        decoded = base64.b64decode(token, validate=True)
        if len(decoded) == 32:
            return base64.b64encode(decoded).decode("ascii")
    except (ValueError, base64.binascii.Error):
        pass
    return raw


def _normalize_reality_key(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return ""
    try:
        token = raw.replace("-", "+").replace("_", "/")
        token += "=" * ((4 - len(token) % 4) % 4)
        decoded = base64.b64decode(token, validate=True)
        if len(decoded) == 32:
            return base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    except (ValueError, base64.binascii.Error):
        pass
    return raw


def _wireguard_conf_identity(decoded: str) -> tuple | None:
    section = ""
    directives: dict[str, dict[str, str]] = {}
    for raw in decoded.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            directives.setdefault(section, {})
            continue
        if section and "=" in line:
            key, value = (part.strip() for part in line.split("=", 1))
            directives[section][key.lower()] = value

    interface = directives.get("interface", {})
    peer = directives.get("peer", {})
    endpoint = peer.get("endpoint", "")
    if not endpoint:
        return None
    if endpoint.startswith("["):
        close = endpoint.find("]")
        if close <= 1 or endpoint[close + 1:close + 2] != ":":
            return None
        host, port_text = endpoint[1:close], endpoint[close + 2:]
    else:
        host, separator, port_text = endpoint.rpartition(":")
        if not separator or ":" in host:
            return None
    try:
        port = int(port_text)
        if not 1 <= port <= 65535:
            return None
    except ValueError:
        return None
    return (
        _normalize_identity_host(host), port, "",
        _normalize_wireguard_key(interface.get("privatekey", "")),
        _normalize_wireguard_key(peer.get("publickey", "")),
        _normalize_wireguard_key(peer.get("presharedkey", "")),
        "", "", "", 0,
    )


def wireguard_uri_identity(line: str) -> tuple | None:
    """WireGuard public identity is endpoint + port + peer authentication."""
    if not re.match(r"(?i)^wireguard://|^wg://", line.strip()):
        return None
    try:
        rest = line.strip().split("://", 1)[1].split("#", 1)[0]
        if "@" not in rest and "?" not in rest:
            try:
                decoded = _decode_urlsafe_base64(rest)
                if "[Interface]" in decoded and "[Peer]" in decoded:
                    identity = _wireguard_conf_identity(decoded)
                    if identity is not None:
                        return identity
            except (ValueError, UnicodeError):
                pass

        parsed = urlsplit(line.strip())
        if not parsed.hostname:
            return None
        params = {
            key.lower(): value
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        }
        private_key = unquote(parsed.username or params.get(
            "privatekey", params.get("private_key", "")
        ))
        public_key = params.get("pk", params.get(
            "publickey", params.get("server_publickey", "")
        ))
        preshared_key = params.get("psk", params.get("presharedkey", ""))
        return (
            _normalize_identity_host(parsed.hostname),
            parsed.port or 51820,
            "",
            _normalize_wireguard_key(private_key),
            _normalize_wireguard_key(public_key),
            _normalize_wireguard_key(preshared_key),
            "", "", "", 0,
        )
    except (ValueError, UnicodeError):
        return None


def _vmess_json_identity(line: str) -> tuple | None:
    try:
        payload = _decode_urlsafe_base64(line.split("://", 1)[1].split("#", 1)[0])
        root = json.loads(payload)
        if not isinstance(root, dict):
            return None
        host = _normalize_identity_host(str(root.get("add", "")))
        if not host:
            return None
        port = int(root.get("port", 443) or 443)
        security = str(root.get("tls", "") or "").strip().lower()
        sni_value = str(root.get("sni", "") or "").strip()
        sni = _normalize_identity_host(sni_value) if sni_value else (
            host if security not in {"", "none", "false", "0"} else ""
        )
        credential = _normalize_uuid_credential(str(root.get("id", "") or ""))
        aid = int(root.get("aid", 0) or 0)
        return host, port, sni, credential, "", "", "", "", "", aid
    except (ValueError, UnicodeError, json.JSONDecodeError):
        return None


def _ss_identity(line: str) -> tuple | None:
    """Parse both SIP002 and legacy base64 Shadowsocks links."""
    try:
        rest = line.split("://", 1)[1].split("#", 1)[0]
        if "@" in rest:
            user_part, host_part = rest.split("@", 1)
            host_port, _separator, query = host_part.partition("?")
            try:
                decoded_credential = _decode_urlsafe_base64(user_part)
            except (ValueError, UnicodeError):
                decoded_credential = unquote(user_part)
        else:
            decoded = _decode_urlsafe_base64(rest)
            main, marker, query = decoded.partition("/?")
            if "@" not in main:
                return None
            decoded_credential, host_port = main.split("@", 1)
            if not marker:
                query = ""
        if ":" not in decoded_credential:
            decoded_credential = unquote(decoded_credential)
        if ":" not in decoded_credential:
            return None
        cipher, password = decoded_credential.split(":", 1)
        credential = cipher.lower() + ":" + password

        if host_port.startswith("["):
            close = host_port.find("]")
            if close <= 1 or host_port[close + 1:close + 2] != ":":
                return None
            host = host_port[1:close]
            port_text = host_port[close + 2:]
        else:
            host, separator, port_text = host_port.rpartition(":")
            if not separator or ":" in host:
                return None
        host = _normalize_identity_host(host)
        port = int(port_text)
        params = {key.lower(): value for key, value in parse_qsl(query, keep_blank_values=True)}
        sni = _normalize_identity_host(params.get("host", "")) if params.get("host") else ""
        return host, port, sni, credential, "", "", "", "", "", 0
    except (ValueError, UnicodeError):
        return None


def _ssr_identity(line: str) -> tuple | None:
    try:
        decoded = _decode_urlsafe_base64(line.split("://", 1)[1].split("#", 1)[0])
        main, _marker, query = decoded.partition("/?")
        if main.startswith("["):
            close = main.index("]")
            host = main[1:close]
            values = main[close + 2:].split(":")
        else:
            values = main.split(":")
            host, values = values[0], values[1:]
        if len(values) != 5:
            return None
        port = int(values[0])
        _protocol, method, obfs, encoded_password = values[1:]
        obfs = obfs.strip().lower()
        params = {key.lower(): value for key, value in parse_qsl(query, keep_blank_values=True)}
        obfs_parameter = params.get("obfsparam", "")
        sni = _normalize_identity_host(obfs_parameter) if obfs.startswith("tls") and obfs_parameter else ""
        password = _decode_urlsafe_base64(encoded_password)
        credential = method.lower() + ":" + password
        return _normalize_identity_host(host), port, sni, credential, "", "", "", "", "", 0
    except (ValueError, UnicodeError, IndexError):
        return None


def semantic_subscription_identity(line: str) -> tuple | None:
    """Public identity: canonical host + port + effective SNI + authentication."""
    value = line.strip()
    if not URI_RE.fullmatch(value):
        return None
    scheme = value.split("://", 1)[0].lower()
    scheme = {
        "hy2": "hysteria2", "shadowsocks": "ss",
        "wg": "wireguard", "mierus": "mieru",
    }.get(scheme, scheme)

    if scheme == "wireguard":
        return wireguard_uri_identity(value)
    if scheme == "vmess" and "@" not in value.split("://", 1)[1].split("#", 1)[0]:
        identity = _vmess_json_identity(value)
        if identity is not None:
            return identity
    if scheme == "ss":
        return _ss_identity(value)
    if scheme == "ssr":
        return _ssr_identity(value)

    try:
        parsed = urlsplit(value)
        if not parsed.hostname:
            return None
        host = _normalize_identity_host(parsed.hostname)
        params = {key.lower(): item for key, item in parse_qsl(parsed.query, keep_blank_values=True)}

        if scheme == "mieru":
            binding = params.get("port", "")
            range_parts = binding.split("-", 1)
            first_port = int(range_parts[0])
            port = (
                f"{first_port}-{int(range_parts[1])}"
                if len(range_parts) == 2 else first_port
            )
        else:
            defaults = {
                "socks": 1080, "socks4": 1080, "socks5": 1080,
                "brook": 9999, "snell": 61825,
            }
            port = parsed.port or defaults.get(scheme, 443)

        sni_value = params.get("sni", "").strip()
        if scheme in {"mieru"}:
            sni = ""
        elif scheme == "ss":
            sni = _normalize_identity_host(params.get("host", "")) if params.get("host") else ""
        else:
            security = params.get("security", "").strip().lower()
            protocol_uses_tls_security = scheme in {"vless", "vmess"}
            implicit_tls = (
                (protocol_uses_tls_security and security not in {"", "none", "false", "0"}) or
                scheme in {"trojan", "hysteria", "hysteria2", "tuic", "juicity", "anytls", "naive"}
            )
            sni = _normalize_identity_host(sni_value) if sni_value else (host if implicit_tls else "")

        credential = unquote(parsed.username or "")
        if parsed.password is not None:
            credential += ":" + unquote(parsed.password)
        if scheme == "hysteria" and not credential:
            credential = params.get("auth", "")
        credential = _normalize_uuid_credential(credential) if scheme in {"vless", "vmess"} else credential

        public_key = _normalize_reality_key(params.get("pbk", ""))
        preshared_key = params.get("psk", params.get("presharedkey", "")).strip()
        short_id = params.get("sid", "").strip().lower()
        flow = params.get("flow", "").strip().lower()
        obfs_password = params.get("obfs-password", "")
        aid = int(params.get("aid", "0") or "0")
        return (
            host, port, sni, credential, public_key, preshared_key,
            short_id, flow, obfs_password, aid
        )
    except (ValueError, UnicodeError):
        return None


def duplicate_examples(path: pathlib.Path, limit: int = 3) -> list[str]:
    """Return concrete exact/semantic duplicate pairs for actionable CI diagnostics."""
    try:
        lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8-sig").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeDecodeError):
        return []

    examples: list[str] = []
    exact_seen: set[str] = set()
    semantic_seen: dict[tuple, str] = {}
    for line in lines:
        if line in exact_seen:
            examples.append(f"exact duplicate: {line[:180]!r}")
        else:
            exact_seen.add(line)

        identity = semantic_subscription_identity(line)
        if identity is None:
            continue
        previous = semantic_seen.get(identity)
        if previous is not None and previous != line:
            examples.append(
                f"same endpoint/SNI/auth identity: {previous[:140]!r} <> {line[:140]!r}"
            )
        else:
            semantic_seen[identity] = line
        if len(examples) >= limit:
            break
    return examples


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

        seen_wireguard: dict[tuple, int] = {}
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

            # The generated Clash WireGuard feed can contain many YAML blocks, so
            # validate semantic uniqueness there as well as in the paired .conf files.
            if actual_type == "wireguard":
                def scalar(name: str) -> str:
                    match = re.search(
                        rf"""(?m)^[ \t]*{re.escape(name)}[ \t]*:[ \t]*(?:"([^"]*)"|'([^']*)'|([^#\n]+))""",
                        block, re.IGNORECASE
                    )
                    if not match:
                        return ""
                    return next((value.strip() for value in match.groups() if value is not None), "")

                private_key = scalar("private-key")
                public_key = scalar("public-key")
                preshared_key = scalar("preshared-key")
                # Legacy/non-WireGuard YAML fixtures may omit keys; structural
                # validation remains compatible, but only complete auth tuples can
                # be compared as semantic public identities.
                if private_key and public_key:
                    identity = (
                        _normalize_identity_host(server.group(1).strip().strip("'\"")),
                        int(port.group(1)),
                        _normalize_wireguard_key(private_key),
                        _normalize_wireguard_key(public_key),
                        _normalize_wireguard_key(preshared_key),
                    )
                    if identity in seen_wireguard:
                        raise ValidationError(
                            f"{path}: YAML WireGuard entry {index} duplicates authenticated endpoint entry "
                            f"{seen_wireguard[identity]} (same server, port, private/public/PSK keys)"
                        )
                    seen_wireguard[identity] = index

            has_keepalive = re.search(
                r"(?m)^[ \t]*persistent-keepalive[ \t]*:", block, re.IGNORECASE
            )
            keepalive = re.search(
                r"""(?m)^[ \t]*persistent-keepalive[ \t]*:[ \t]*['"]?(\d+)['"]?[ \t]*(?:#.*)?$""",
                block, re.IGNORECASE
            )
            if has_keepalive and (not keepalive or int(keepalive.group(1)) > 65535):
                raise ValidationError(
                    f"{path}: YAML proxy entry {index} has invalid persistent-keepalive"
                )
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

    # Catch different URI spellings that still describe one public service profile.
    # This applies to every supported scheme, not only to WireGuard.
    semantic_seen: dict[tuple, str] = {}
    semantic_duplicates = 0
    for line in dict.fromkeys(lines):
        identity = semantic_subscription_identity(line)
        if identity is None:
            continue
        if identity in semantic_seen and semantic_seen[identity] != line:
            semantic_duplicates += 1
        else:
            semantic_seen[identity] = line

    return len(lines), duplicates + semantic_duplicates


def _validate_wireguard_key(value: str, label: str, path: pathlib.Path) -> None:
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise ValidationError(f"{path}: invalid WireGuard {label} encoding") from exc
    if len(decoded) != 32:
        raise ValidationError(f"{path}: WireGuard {label} must decode to exactly 32 bytes")


def _validate_wireguard_host(host: str, path: pathlib.Path) -> None:
    if not host or any(ch.isspace() or ord(ch) < 32 for ch in host):
        raise ValidationError(f"{path}: WireGuard endpoint host is empty or contains whitespace")
    try:
        ipaddress.ip_address(host)
        return
    except ValueError:
        pass
    if len(host) > 253:
        raise ValidationError(f"{path}: WireGuard endpoint hostname is too long")
    labels = host.rstrip(".").split(".")
    if not labels or any(
        not label or len(label) > 63 or
        not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in labels
    ):
        raise ValidationError(f"{path}: invalid WireGuard endpoint hostname {host!r}")


def _normalize_wireguard_ip_list(value: str, *, interface_addresses: bool) -> tuple[str, ...]:
    values = [item.strip() for item in value.split(",")]
    if not values or any(not item for item in values):
        raise ValueError("empty IP list entry")
    parsed = [
        ipaddress.ip_interface(item) if interface_addresses
        else ipaddress.ip_network(item, strict=False)
        for item in values
    ]
    return tuple(sorted(str(item) for item in parsed))


def validate_wireguard_conf(path: pathlib.Path) -> tuple:
    try:
        content = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValidationError(f"{path}: cannot read WireGuard config as UTF-8: {exc}") from exc

    sections: list[str] = []
    values: dict[str, dict[str, str]] = {}
    current: str | None = None
    for line_number, raw in enumerate(content.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            if section not in {"Interface", "Peer"} or section in sections:
                raise ValidationError(f"{path}:{line_number}: unsupported or duplicate section {section!r}")
            sections.append(section)
            values[section] = {}
            current = section
            continue
        if current is None or "=" not in line:
            raise ValidationError(f"{path}:{line_number}: directive appears outside a section or lacks '='")
        key, value = (part.strip() for part in line.split("=", 1))
        normalized_key = key.lower()
        if not normalized_key or not value:
            raise ValidationError(f"{path}:{line_number}: empty WireGuard key or value")
        if normalized_key in values[current]:
            raise ValidationError(f"{path}:{line_number}: duplicate {key} directive")
        values[current][normalized_key] = value

    if sections != ["Interface", "Peer"]:
        raise ValidationError(f"{path}: expected exactly one [Interface] followed by one [Peer] section")

    interface = values["Interface"]
    peer = values["Peer"]
    for key in ("privatekey", "address"):
        if key not in interface:
            raise ValidationError(f"{path}: [Interface] is missing {key}")
    for key in ("publickey", "endpoint", "allowedips"):
        if key not in peer:
            raise ValidationError(f"{path}: [Peer] is missing {key}")

    _validate_wireguard_key(interface["privatekey"], "PrivateKey", path)
    _validate_wireguard_key(peer["publickey"], "PublicKey", path)
    if "presharedkey" in peer:
        _validate_wireguard_key(peer["presharedkey"], "PresharedKey", path)

    try:
        addresses = _normalize_wireguard_ip_list(interface["address"], interface_addresses=True)
    except ValueError as exc:
        raise ValidationError(f"{path}: invalid [Interface] Address: {exc}") from exc

    dns = interface.get("dns", "")
    if dns:
        try:
            entries = [item.strip() for item in dns.split(",")]
            if not entries or any(not item for item in entries):
                raise ValueError("empty DNS entry")
            for item in entries:
                ipaddress.ip_address(item)
        except ValueError as exc:
            raise ValidationError(f"{path}: invalid [Interface] DNS: {exc}") from exc

    try:
        allowed_ips = _normalize_wireguard_ip_list(peer["allowedips"], interface_addresses=False)
    except ValueError as exc:
        raise ValidationError(f"{path}: invalid [Peer] AllowedIPs: {exc}") from exc

    endpoint = peer["endpoint"]
    if endpoint.startswith("["):
        close = endpoint.find("]")
        if close <= 1 or not endpoint[close + 1:].startswith(":"):
            raise ValidationError(f"{path}: invalid bracketed WireGuard endpoint {endpoint!r}")
        host, port_text = endpoint[1:close], endpoint[close + 2:]
    else:
        host, separator, port_text = endpoint.rpartition(":")
        if not separator or ":" in host:
            raise ValidationError(f"{path}: IPv6 WireGuard endpoints must be bracketed")
    _validate_wireguard_host(host, path)
    if not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
        raise ValidationError(f"{path}: invalid WireGuard endpoint port {port_text!r}")

    keepalive = peer.get("persistentkeepalive")
    if keepalive is not None and (not keepalive.isdigit() or int(keepalive) > 65535):
        raise ValidationError(f"{path}: invalid PersistentKeepalive value")

    reserved = tuple(item.strip() for item in peer.get("reserved", "").split(",") if item.strip())
    if reserved and (len(reserved) != 3 or any(not item.isdigit() or int(item) > 255 for item in reserved)):
        raise ValidationError(f"{path}: invalid WireGuard Reserved bytes")

    try:
        normalized_host = ipaddress.ip_address(host).compressed
    except ValueError:
        normalized_host = host.rstrip(".").encode("idna").decode("ascii").lower()

    # Public-feed policy keeps one representative per endpoint + port + peer
    # authentication. Client-side interface addresses/routes, DNS, MTU and keepalive
    # are not authentication and do not create another copy.
    return (
        normalized_host,
        int(port_text),
        interface["privatekey"].strip(),
        peer["publickey"].strip(),
        peer.get("presharedkey", "").strip(),
    )

def validate_wireguard_confs(root: pathlib.Path) -> int:
    directory = root / "wireguard"
    if not directory.exists():
        return 0
    paths = sorted(directory.rglob("*.conf"))
    if not paths:
        # The collector may create this directory before discovering that every
        # candidate has invalid key material. An empty directory is valid only when
        # no WireGuard YAML feed was published alongside it.
        clash_output = root / "protocols" / "wireguard.txt"
        if clash_output.is_file():
            raise ValidationError(
                f"{directory}: WireGuard YAML exists but no matching .conf files were generated"
            )
        return 0
    seen: dict[tuple, pathlib.Path] = {}
    for path in paths:
        identity = validate_wireguard_conf(path)
        if identity in seen:
            raise ValidationError(
                f"{path}: duplicate WireGuard tunnel config already emitted as {seen[identity]} "
                "(DNS/MTU differences do not create a distinct node)"
            )
        seen[identity] = path
    return len(paths)


def validate_tree(root: pathlib.Path, allow_legacy_oversized: bool = False) -> list[str]:
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
            examples = duplicate_examples(path)
            detail = f"; examples: {' | '.join(examples)}" if examples else ""
            raise ValidationError(
                f"{rel} contains {duplicates} duplicate line(s); generated subscription entries must be unique{detail}"
            )
        size = path.stat().st_size
        if size > MAX_PART_BYTES:
            message = (
                f"{rel} is {size / (1024 * 1024):.1f} MiB; generated text files must not exceed 50 MiB per part"
            )
            if allow_legacy_oversized:
                report.append(f"WARNING legacy committed output: {message}")
            else:
                raise ValidationError(message)

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
    for name in ("top.txt", "everything.txt"):
        if counts.get(name, 0) == 0:
            raise ValidationError(f"{name} is empty; refusing to publish")
    # verified.txt is a current-run result and may legitimately be empty when no
    # full Xray round-trip succeeds. The historical fallback has its own feed.

    # Every _partN file must have a stable base file and a gap-free sequence
    # beginning at part 2. This also protects protocol/country/continent chunks.
    split_groups: dict[pathlib.Path, list[tuple[int, pathlib.Path]]] = {}
    for path in root.rglob("*_part*.txt"):
        match = re.fullmatch(r"(.+)_part([0-9]+)\.txt", path.name)
        if not match or int(match.group(2)) < 2:
            raise ValidationError(f"invalid subscription part filename: {path.relative_to(root).as_posix()}")
        base_path = path.with_name(match.group(1) + ".txt")
        if not base_path.is_file():
            raise ValidationError(f"{path.relative_to(root).as_posix()} has no base file {base_path.name}")
        rel = path.relative_to(root).as_posix()
        if counts.get(rel, 0) == 0:
            raise ValidationError(f"{rel} is empty; remove empty trailing subscription parts")
        split_groups.setdefault(base_path, []).append((int(match.group(2)), path))

    for base_path, parts in split_groups.items():
        ordered = sorted(parts, key=lambda item: item[0])
        expected = list(range(2, len(ordered) + 2))
        if [number for number, _ in ordered] != expected:
            rel = base_path.relative_to(root).as_posix()
            raise ValidationError(f"{rel} parts must be contiguous and numbered from _part2.txt")

    def all_parts(base_path: pathlib.Path) -> list[pathlib.Path]:
        ordered = sorted(split_groups.get(base_path, []), key=lambda item: item[0])
        return [base_path] + [path for _, path in ordered]

    # Per-file checks above cannot see duplicates split across two numbered parts.
    # Run the same semantic identity check over each complete part family.
    for base_path in split_groups:
        seen_profiles: dict[tuple, str] = {}
        for part_path in all_parts(base_path):
            for line in (
                line.strip()
                for line in part_path.read_text(encoding="utf-8-sig").splitlines()
                if line.strip()
            ):
                identity = semantic_subscription_identity(line)
                if identity is None:
                    continue
                if identity in seen_profiles and seen_profiles[identity] != line:
                    rel = base_path.relative_to(root).as_posix()
                    raise ValidationError(
                        f"{rel} contains semantically duplicate profiles across split parts: "
                        f"{seen_profiles[identity][:100]!r} and {line[:100]!r}"
                    )
                seen_profiles[identity] = line

    # The ranked IPv6 shortlist is generated directly from ipv6_only.txt's
    # candidate pool. Every top_ipv6 entry must therefore exist in the family
    # feed; catch accidental truncation or mismatched output publication.
    top_ipv6_path = root / "top_ipv6.txt"
    ipv6_only_path = root / "ipv6_only.txt"
    top_ipv6_links = {
        line.strip()
        for path in all_parts(top_ipv6_path)
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    }
    ipv6_links = {
        line.strip()
        for path in all_parts(ipv6_only_path)
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    }
    missing_ipv6_links = top_ipv6_links - ipv6_links
    if missing_ipv6_links:
        sample = next(iter(missing_ipv6_links))[:120]
        raise ValidationError(
            f"top_ipv6.txt contains {len(missing_ipv6_links)} node(s) missing from "
            f"ipv6_only.txt; sample: {sample!r}"
        )

    # Every current-run URI feed, including verified.txt, must be a subset of
    # everything.txt. The historical verified_last_good.txt feed is the only
    # intentional exception: it represents a previously successful snapshot.
    # everything.txt is the stable first part. Large collections continue in
    # everything_part2.txt, everything_part3.txt, ...; validate the sequence and
    # use every part when checking that the other feeds are subsets of the master list.
    # Ranked shortlists can also be byte-split in the rare case of unusually
    # long entries. Keep the 1,000-node limit and duplicate check across all parts.
    for name in ("top.txt", "top_ipv6.txt"):
        entries = [
            line.strip()
            for path in all_parts(root / name)
            for line in path.read_text(encoding="utf-8-sig").splitlines()
            if line.strip()
        ]
        counts[name] = len(entries)
        if len(entries) > MAX_TOP_LINES:
            raise ValidationError(f"{name} has {len(entries)} lines across all parts; maximum is {MAX_TOP_LINES}")
        if len(entries) != len(set(entries)):
            raise ValidationError(f"{name} contains duplicate entries across its parts")

    everything_paths = all_parts(root / "everything.txt")
    everything_links: set[str] = set()
    everything_total_lines = 0
    for path in everything_paths:
        part_lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8-sig").splitlines()
            if line.strip()
        ]
        everything_total_lines += len(part_lines)
        everything_links.update(part_lines)
    counts["everything.txt"] = everything_total_lines
    for path in sorted(root.rglob("*.txt")):
        rel = path.relative_to(root).as_posix()
        if rel == "verified_last_good.txt" or path in everything_paths[1:] or path in all_parts(root / "verified_last_good.txt")[1:]:
            continue
        lines = [
            line.strip()
            for line in path.read_text(encoding="utf-8-sig").splitlines()
            if line.strip()
        ]
        # WireGuard is deliberately published as Clash YAML, not URI-per-line.
        if lines and lines[0].lower() == "proxies:":
            continue
        missing = set(lines) - everything_links
        if missing:
            sample = next(iter(missing))[:120]
            raise ValidationError(
                f"{rel} contains {len(missing)} node(s) missing from everything.txt; "
                f"sample: {sample!r}"
            )

    wireguard_conf_count = validate_wireguard_confs(root)
    report.insert(0, "Validated subscriptions: " + " ".join(
        f"{name}={counts.get(name, 0)}" for name in REQUIRED
    ) + f" verified_current={counts.get('verified.txt', 0)}"
      + f" verified_last_good={counts.get('verified_last_good.txt', 0)}")
    report.append(f"Validated {len(counts)} generated .txt file(s).")
    if wireguard_conf_count:
        report.append(f"Validated {wireguard_conf_count} WireGuard .conf file(s).")
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

    wg_uri_a = "wireguard://private@wg.example.net:51820?pk=server&ip=10.0.0.2%2F32&dns=1.1.1.1&mtu=1280"
    wg_uri_b = "wireguard://private@wg.example.net:51820?mtu=1420&ip=10.0.0.3%2F32&pk=server&dns=8.8.8.8"
    if semantic_subscription_identity(wg_uri_a) != semantic_subscription_identity(wg_uri_b):
        raise ValidationError("self-test failed to collapse WireGuard local-preference variants")
    wg_uri_different_key = "wireguard://another-private@wg.example.net:51820?pk=server&ip=10.0.0.2%2F32"
    if semantic_subscription_identity(wg_uri_a) == semantic_subscription_identity(wg_uri_different_key):
        raise ValidationError("self-test incorrectly collapsed WireGuard private-key alternatives")
    wg_uri_other_port = "wireguard://private@wg.example.net:51821?pk=server&ip=10.0.0.2%2F32"
    if semantic_subscription_identity(wg_uri_a) == semantic_subscription_identity(wg_uri_other_port):
        raise ValidationError("self-test incorrectly collapsed different WireGuard ports")

    vless_a = "vless://same-secret@same.example.net:443?security=tls&type=ws&sni=front.example.net&path=%2Fedge&fp=chrome&dns=1.1.1.1&mtu=1280&name=source-a"
    vless_b = "trojan://same-secret@same.example.net:443?sni=front.example.net&mtu=1420&name=source-b&dns=8.8.8.8"
    if semantic_subscription_identity(vless_a) != semantic_subscription_identity(vless_b):
        raise ValidationError("self-test failed to collapse same-auth cross-protocol/local-metadata variants")
    vless_other_port = vless_b.replace(":443", ":8443")
    if semantic_subscription_identity(vless_a) == semantic_subscription_identity(vless_other_port):
        raise ValidationError("self-test incorrectly collapsed different endpoint ports")
    vless_other_sni = vless_b.replace("front.example.net", "other-front.example.net")
    if semantic_subscription_identity(vless_a) == semantic_subscription_identity(vless_other_sni):
        raise ValidationError("self-test incorrectly collapsed different SNI values")
    vless_other_password = vless_b.replace("same-secret", "different-secret")
    if semantic_subscription_identity(vless_a) == semantic_subscription_identity(vless_other_password):
        raise ValidationError("self-test incorrectly collapsed different authentication credentials")

    custom_id_a = "vless://CustomId@custom.example.net:443?security=tls"
    custom_id_b = "vless://customid@custom.example.net:443?security=tls"
    if semantic_subscription_identity(custom_id_a) == semantic_subscription_identity(custom_id_b):
        raise ValidationError("self-test incorrectly case-folded a custom VLESS authentication ID")

    ss_a = "ss://YWVzLTEyOC1nY206cHc=@same.example.net:8388?dns=1.1.1.1&mtu=1280"
    ss_b = "ss://YWVzLTEyOC1nY206cHc=@same.example.net:8388?mtu=1420&dns=8.8.8.8"
    if semantic_subscription_identity(ss_a) != semantic_subscription_identity(ss_b):
        raise ValidationError("self-test failed to collapse same-password Shadowsocks local-preference variants")
    ss_other_password = "ss://YWVzLTEyOC1nY206b3RoZXI=@same.example.net:8388"
    if semantic_subscription_identity(ss_a) == semantic_subscription_identity(ss_other_password):
        raise ValidationError("self-test incorrectly collapsed different Shadowsocks passwords")

    mieru_a = "mierus://user:pass@same.example.net?profile=home&port=6666&protocol=UDP&mtu=1280&dns=1.1.1.1"
    mieru_b = "mierus://user:pass@same.example.net?profile=travel&port=6666&protocol=udp&mtu=1400&dns=8.8.8.8"
    if semantic_subscription_identity(mieru_a) != semantic_subscription_identity(mieru_b):
        raise ValidationError("self-test failed to collapse same-auth Mieru endpoint variants")
    mieru_other_password = "mierus://user:other@same.example.net?profile=home&port=6666&protocol=UDP"
    if semantic_subscription_identity(mieru_a) == semantic_subscription_identity(mieru_other_password):
        raise ValidationError("self-test incorrectly collapsed different Mieru passwords")

    ssr_password = base64.urlsafe_b64encode(b"secret").decode("ascii").rstrip("=")
    ssr_tls_a = "ssr://" + base64.urlsafe_b64encode(
        f"same.example.net:8388:origin:aes-128-gcm:tls1.2_ticket_auth:{ssr_password}/?obfsparam=front.example.net".encode()
    ).decode("ascii").rstrip("=")
    ssr_tls_b = "ssr://" + base64.urlsafe_b64encode(
        f"same.example.net:8388:origin:aes-128-gcm:tls1.2_ticket_auth:{ssr_password}/?obfsparam=other-front.example.net".encode()
    ).decode("ascii").rstrip("=")
    if semantic_subscription_identity(ssr_tls_a) == semantic_subscription_identity(ssr_tls_b):
        raise ValidationError("self-test incorrectly collapsed SSR TLS obfs links with different SNI")
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
        (root / "verified_last_good.txt").write_text(
            "vless://historical@example.org:443?security=tls\n", encoding="utf-8")
        (root / "everything.txt").write_text("\n".join(good[:3]) + "\n", encoding="utf-8")
        (root / "everything_part2.txt").write_text("\n".join(good[3:]) + "\n", encoding="utf-8")
        (root / "ipv4_only.txt").write_text(good[0] + "\n", encoding="utf-8")
        (root / "ipv6_only.txt").write_text(good[0] + "\n", encoding="utf-8")
        (root / "ipv6_only_part2.txt").write_text(good[4] + "\n", encoding="utf-8")
        (root / "stable.txt").write_text(good[0] + "\n", encoding="utf-8")
        (root / "verified_tls.txt").write_text(good[1] + "\n", encoding="utf-8")
        (root / "curated.txt").write_text(good[2] + "\n", encoding="utf-8")
        (root / "protocols").mkdir()
        (root / "protocols" / "vless.txt").write_text(good[0] + "\n", encoding="utf-8")
        (root / "countries").mkdir()
        (root / "countries" / "DE.txt").write_text(good[0] + "\n", encoding="utf-8")
        (root / "continents").mkdir()
        (root / "continents" / "Europe.txt").write_text(good[1] + "\n", encoding="utf-8")
        yaml = ('proxies:\n'
                '  - name: "WG test 1"\n    type: wireguard\n    server: "2001:db8::1"\n    port: 51820\n    persistent-keepalive: 0\n    reserved:\n      - 0\n      - 0\n      - 0\n'
                '  - name: "WG test 2"\n    type: wireguard\n    server: "198.51.100.2"\n    port: 123\n')

        wg_dir = root / "wireguard"
        wg_dir.mkdir()
        valid_key_1 = base64.b64encode(bytes(range(32))).decode("ascii")
        valid_key_2 = base64.b64encode(bytes(range(32, 64))).decode("ascii")
        yaml = yaml.replace(
            "    port: 51820\n",
            f"    port: 51820\n    private-key: {valid_key_1}\n    public-key: {valid_key_2}\n",
            1,
        )
        (root / "protocols" / "wireguard.txt").write_text(yaml, encoding="utf-8")
        valid_conf = (
            "[Interface]\n"
            f"PrivateKey = {valid_key_1}\n"
            "Address = 10.0.0.2/32, fd00::2/128\n"
            "DNS = 1.1.1.1, 2606:4700:4700::1111\n\n"
            "[Peer]\n"
            f"PublicKey = {valid_key_2}\n"
            f"PresharedKey = {valid_key_1}\n"
            "Endpoint = [2001:4860:4860::8888]:51820\n"
            "AllowedIPs = 0.0.0.0/0, ::/0\n"
            "PersistentKeepalive = 25\n"
            "MTU = 1380\n"
        )
        # Duplicate the first authenticated peer in Clash YAML: this must be
        # rejected even though the block name is different.
        duplicate_yaml = yaml + (
            '  - name: "WG duplicate auth"\n'
            '    type: wireguard\n'
            '    server: "2001:db8::1"\n'
            '    port: 51820\n'
            f'    private-key: {valid_key_1}\n'
            f'    public-key: {valid_key_2}\n'
        )
        duplicate_yaml_path = root / "duplicate-wireguard.yaml"
        duplicate_yaml_path.write_text(duplicate_yaml, encoding="utf-8")
        try:
            validate_lines(duplicate_yaml_path)
        except ValidationError as exc:
            if "duplicates authenticated endpoint entry" not in str(exc):
                raise
        else:
            raise ValidationError("self-test failed to reject duplicate authenticated WireGuard Clash YAML peers")
        finally:
            duplicate_yaml_path.unlink(missing_ok=True)

        wg_conf_path = wg_dir / "valid.conf"
        wg_conf_path.write_text(valid_conf, encoding="utf-8")
        report = validate_tree(root)
        if not any("Validated 1 WireGuard .conf file(s)." in line for line in report):
            raise ValidationError("self-test failed to report validated WireGuard .conf output")

        duplicate_conf = valid_conf.replace(
            "DNS = 1.1.1.1, 2606:4700:4700::1111",
            "DNS = 8.8.8.8"
        ).replace("MTU = 1380", "MTU = 1280")
        duplicate_path = wg_dir / "duplicate-local-preferences.conf"
        duplicate_path.write_text(duplicate_conf, encoding="utf-8")
        try:
            validate_wireguard_confs(root)
        except ValidationError as exc:
            if "duplicate WireGuard tunnel config" not in str(exc):
                raise
        else:
            raise ValidationError("self-test failed to reject a WireGuard duplicate differing only in DNS/MTU")
        finally:
            duplicate_path.unlink(missing_ok=True)

        # Under authenticated endpoint dedup, a different client-side interface
        # address alone does not create another public node when peer keys match.
        different_address = valid_conf.replace(
            "Address = 10.0.0.2/32, fd00::2/128",
            "Address = 10.0.0.3/32, fd00::2/128"
        )
        different_address_path = wg_dir / "different-interface-address.conf"
        different_address_path.write_text(different_address, encoding="utf-8")
        try:
            validate_wireguard_confs(root)
        except ValidationError as exc:
            if "duplicate WireGuard tunnel config" not in str(exc):
                raise
        else:
            raise ValidationError(
                "self-test failed to reject a second WireGuard config at the same endpoint/port"
            )
        finally:
            different_address_path.unlink(missing_ok=True)

        # A different private key is a different authenticated WireGuard peer and
        # must remain a separate downloadable configuration at the same endpoint.
        different_key = valid_conf.replace(
            f"PrivateKey = {valid_key_1}",
            "PrivateKey = " + base64.b64encode(bytes([7]) * 32).decode("ascii")
        )
        different_key_path = wg_dir / "different-auth.conf"
        different_key_path.write_text(different_key, encoding="utf-8")
        try:
            if validate_wireguard_confs(root) != 2:
                raise ValidationError(
                    "self-test incorrectly collapsed different WireGuard authentication keys"
                )
        finally:
            different_key_path.unlink(missing_ok=True)

        invalid_keepalive_yaml = yaml.replace("persistent-keepalive: 0", "persistent-keepalive: 65536")
        (root / "protocols" / "wireguard.txt").write_text(invalid_keepalive_yaml, encoding="utf-8")
        try:
            validate_lines(root / "protocols" / "wireguard.txt")
        except ValidationError as exc:
            if "persistent-keepalive" not in str(exc):
                raise
        else:
            raise ValidationError("self-test failed to reject out-of-range WireGuard YAML keepalive")
        finally:
            (root / "protocols" / "wireguard.txt").write_text(yaml, encoding="utf-8")

        # Empty current-run verification is valid; the historical snapshot is separate.
        verified_path = root / "verified.txt"
        original_verified = verified_path.read_text(encoding="utf-8")
        verified_path.write_text("", encoding="utf-8")
        try:
            validate_tree(root)
        except ValidationError as exc:
            raise ValidationError(f"self-test rejected empty current-run verified.txt: {exc}") from exc
        finally:
            verified_path.write_text(original_verified, encoding="utf-8")

        original_conf = wg_conf_path.read_text(encoding="utf-8")
        wg_conf_path.write_text(original_conf.replace(f"PrivateKey = {valid_key_1}", "PrivateKey = invalid"), encoding="utf-8")
        try:
            validate_tree(root)
        except ValidationError as exc:
            if "PrivateKey" not in str(exc):
                raise
        else:
            raise ValidationError("self-test failed to reject invalid WireGuard private-key material")
        finally:
            wg_conf_path.write_text(original_conf, encoding="utf-8")

        # The collector may discover WireGuard candidates but reject every one before
        # writing a .conf or Clash YAML file. Its pre-created empty directory is valid.
        wg_conf_path.unlink()
        try:
            validate_tree(root)
        except ValidationError as exc:
            if "no matching .conf files" not in str(exc):
                raise
        else:
            raise ValidationError("self-test failed to require .conf files alongside WireGuard YAML")
        wireguard_yaml_path = root / "protocols" / "wireguard.txt"
        original_yaml = wireguard_yaml_path.read_text(encoding="utf-8")
        wireguard_yaml_path.unlink()
        try:
            validate_tree(root)
        finally:
            wg_conf_path.write_text(original_conf, encoding="utf-8")
            wireguard_yaml_path.write_text(original_yaml, encoding="utf-8")

        everything_path = root / "everything.txt"
        original_everything = everything_path.read_text(encoding="utf-8")
        everything_path.write_text(original_everything + good[0] + "\n", encoding="utf-8")
        try:
            validate_tree(root)
        except ValidationError as exc:
            if "everything.txt contains" not in str(exc) or "duplicate" not in str(exc):
                raise
        else:
            raise ValidationError("self-test failed to reject duplicate master-list entries")
        finally:
            everything_path.write_text(original_everything, encoding="utf-8")

        part2_path = root / "everything_part2.txt"
        original_part2 = part2_path.read_text(encoding="utf-8")
        (root / "everything_part4.txt").write_text(good[4] + "\n", encoding="utf-8")
        try:
            validate_tree(root)
        except ValidationError as exc:
            if "parts must be contiguous" not in str(exc):
                raise
        else:
            raise ValidationError("self-test failed to catch a missing everything_part3.txt")
        finally:
            (root / "everything_part4.txt").unlink(missing_ok=True)

        rogue_link = "vless://rogue@example.net:443?security=tls"
        for rel in (
            "stable.txt", "verified.txt", "verified_tls.txt", "curated.txt",
            "protocols/vless.txt", "countries/DE.txt", "continents/Europe.txt"
        ):
            path = root / rel
            original = path.read_text(encoding="utf-8")
            path.write_text(original + rogue_link + "\n", encoding="utf-8")
            try:
                validate_tree(root)
            except ValidationError as exc:
                if f"{rel} contains " not in str(exc) or "missing from everything.txt" not in str(exc):
                    raise
            else:
                raise ValidationError(f"self-test failed to catch {rel} entries missing from everything.txt")
            finally:
                path.write_text(original, encoding="utf-8")
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

        ipv6_part2_path = root / "ipv6_only_part2.txt"
        original_ipv6_part2 = ipv6_part2_path.read_text(encoding="utf-8")
        ipv6_part2_path.unlink()
        (root / "ipv6_only.txt").write_text(good[0] + "\n", encoding="utf-8")
        try:
            validate_tree(root)
        except ValidationError as exc:
            if "missing from ipv6_only.txt" not in str(exc):
                raise
        else:
            raise ValidationError("self-test failed to catch top_ipv6.txt entries missing from ipv6_only.txt")
        finally:
            ipv6_part2_path.write_text(original_ipv6_part2, encoding="utf-8")
        (root / "top.txt").write_text(good[0] + "\n" + good[0] + "\n", encoding="utf-8")
        try:
            validate_tree(root)
        except ValidationError as exc:
            if "top.txt contains" not in str(exc) or "duplicate" not in str(exc):
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
        if validate_lines(root / "protocols" / "wireguard.txt")[0] != 2:
            raise ValidationError("self-test failed to count multiple YAML proxy entries")
        (root / "protocols").mkdir(exist_ok=True)
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
    parser.add_argument(
        "--allow-legacy-oversized",
        action="store_true",
        help="warn instead of failing for oversized files in the existing committed snapshot; never use for newly generated output"
    )
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        if args.root is None:
            parser.error("provide output directory or --self-test")
        for line in validate_tree(args.root, allow_legacy_oversized=args.allow_legacy_oversized):
            print(line)
        return 0
    except ValidationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
