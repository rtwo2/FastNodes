#!/usr/bin/env python3
"""Endpoint-aware Cloudflare/WARP audit for generated FastNodes subscriptions."""
import base64, html, ipaddress, json, pathlib, re, sys
from urllib.parse import unquote, urlsplit

URI_RE = re.compile(r"(?i)\b(vless|vmess|trojan|ss|shadowsocks|ssr|hysteria2?|hy2|tuic|naive|anytls|brook|snell|juicity|mieru|socks5?|socks4?|wireguard|wg)://([^\s<>\"']+)")
WARP_RE = re.compile(r"(?i)(?<![a-z0-9])warp(?:\+)?(?![a-z0-9])")
TRANSPORT_RE = re.compile(r"(?i)(?:^|[?&;])\s*(host|sni|server_name|servername|authority)\s*=\s*([^&;#\s]+)")
KV_RE = re.compile(r"(?i)^\s*(server|server-host|server_host|endpoint|address|remote|host|sni|server_name|servername|authority)\s*[:=]\s*(.*?)\s*$")
ENDPOINT_DOMAINS = ("cloudflare.com", "cloudflareclient.com", "workers.dev", "pages.dev", "trycloudflare.com")
TRANSPORT_SERVICE_DOMAINS = ("cloudflareclient.com", "workers.dev", "pages.dev", "trycloudflare.com")

def decode_text(value):
    value = html.unescape(str(value or ""))
    for _ in range(2):
        newer = unquote(value)
        if newer == value:
            break
        value = newer
    return value

def domain_or_subdomain(host, domain):
    return host == domain or host.endswith("." + domain)

def normalize_host(value):
    value = decode_text(value).strip().strip("\"'").rstrip(",;")
    if not value:
        return ""
    try:
        parsed = urlsplit(value if "://" in value else "//" + value)
        if parsed.hostname:
            return parsed.hostname.strip("[]").rstrip(".").lower()
    except ValueError:
        pass
    if value.startswith("[") and "]" in value:
        value = value[1:value.index("]")]
    elif value.count(":") == 1:
        host, _, port = value.rpartition(":")
        if port.isdigit():
            value = host
    return value.strip("[]").rstrip(".").lower()

def in_cloudflare_ranges(value, ranges):
    candidate = str(value or "").strip().strip("\"'").rstrip(",;")
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1:candidate.index("]")]
    elif candidate.count(":") == 1:
        host, _, port = candidate.rpartition(":")
        if port.isdigit():
            candidate = host
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return any(address.version == net.version and address in net for net in ranges)

def endpoint_is_forbidden(value, ranges):
    if in_cloudflare_ranges(value, ranges):
        return True
    host = normalize_host(value)
    try:
        ipaddress.ip_address(host)
        return in_cloudflare_ranges(host, ranges)
    except ValueError:
        pass
    if any(domain_or_subdomain(host, domain) for domain in ENDPOINT_DOMAINS):
        return True
    return "cloudflare" in host and not domain_or_subdomain(host, "cloudflare.com")

def transport_host_is_forbidden(value):
    host = normalize_host(value)
    if not host:
        return False
    if any(domain_or_subdomain(host, domain) for domain in TRANSPORT_SERVICE_DOMAINS):
        return True
    if "cloudflare" in host and not domain_or_subdomain(host, "cloudflare.com"):
        return True
    return bool(WARP_RE.search(host))

def decode_vmess(raw):
    try:
        token = raw.split("#", 1)[0].split("?", 1)[0].replace("-", "+").replace("_", "/")
        token += "=" * ((4 - len(token) % 4) % 4)
        value = json.loads(base64.b64decode(token).decode("utf-8", "ignore"))
        return value if isinstance(value, dict) else None
    except Exception:
        return None

def label_is_forbidden(value):
    decoded = decode_text(value)
    return "cloudflare" in decoded.lower() or bool(WARP_RE.search(decoded))

def is_forbidden_label(line):
    if re.search(r"(?i)\bwarp://", line):
        return True
    name = re.search(r"(?i)^\s*(?:-\s*)?(?:\{\s*)?name\s*[:=]\s*([^,}\r\n]+)", line)
    if name and label_is_forbidden(name.group(1)):
        return True
    vmess = re.match(r"(?i)^\s*vmess://([^\s]+)", line)
    if vmess:
        obj = decode_vmess(vmess.group(1))
        if obj and label_is_forbidden(obj.get("ps", "")):
            return True
    if "#" in line and "://" in line and label_is_forbidden(line.split("#", 1)[1]):
        return True
    return False

def has_forbidden_transport_host(line):
    vmess = re.match(r"(?i)^\s*vmess://([^\s]+)", line)
    if vmess:
        obj = decode_vmess(vmess.group(1))
        if obj:
            for key in ("host", "sni", "server_name", "servername", "authority"):
                if transport_host_is_forbidden(obj.get(key, "")):
                    return True
    match = URI_RE.search(line)
    if match:
        raw = match.group(2).split("#", 1)[0]
        query = raw.split("?", 1)[1] if "?" in raw else ""
        for _, value in TRANSPORT_RE.findall("?" + decode_text(query)):
            if transport_host_is_forbidden(value):
                return True
    key_value = KV_RE.match(line)
    if key_value and key_value.group(1).lower() not in ("server", "server-host", "server_host", "endpoint", "address", "remote"):
        return transport_host_is_forbidden(key_value.group(2))
    return False

def uri_endpoints(line):
    match = URI_RE.search(line)
    if not match:
        return []
    scheme, raw = match.group(1).lower(), match.group(2).rstrip("),;")
    if scheme == "vmess":
        obj = decode_vmess(raw)
        return [str(obj.get("add", ""))] if obj and obj.get("add") else []
    try:
        host = urlsplit(scheme + "://" + raw).hostname
        return [host] if host else []
    except ValueError:
        return []

def read_ranges(ipv4_path, ipv6_path):
    ranges = []
    for path in (ipv4_path, ipv6_path):
        for line in pathlib.Path(path).read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                ranges.append(ipaddress.ip_network(line, strict=False))
    if not any(net.version == 4 for net in ranges) or not any(net.version == 6 for net in ranges):
        raise ValueError("Official Cloudflare IPv4 and IPv6 range lists must both be non-empty")
    return ranges

def self_test():
    ranges = [ipaddress.ip_network("203.0.113.0/24"), ipaddress.ip_network("2001:db8::/32")]
    assert endpoint_is_forbidden("203.0.113.3", ranges)
    assert endpoint_is_forbidden("[2001:db8::3]:51820", ranges)
    assert endpoint_is_forbidden("api.pages.dev", ranges)
    assert endpoint_is_forbidden("foo.cloudflare.com.attacker.test", ranges)
    assert not endpoint_is_forbidden("example.com:443", ranges)
    assert not endpoint_is_forbidden("198.51.100.4", ranges)
    assert is_forbidden_label("vless://uuid@example.net:443#WARP+")
    assert is_forbidden_label('name: "Cloudflare WARP"')
    assert is_forbidden_label("- name: Cloudflare WARP")
    assert is_forbidden_label("- {name: Cloudflare, type: wireguard}")
    assert not is_forbidden_label("vless://uuid@example.net:443#warpath")
    assert not is_forbidden_label("vless://uuid@example.net:443?sni=www.cloudflare.com#US")
    assert not has_forbidden_transport_host("vless://uuid@example.net:443?sni=www.cloudflare.com&host=www.cloudflare.com#US")
    assert has_forbidden_transport_host("ss://auth@example.net:443?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dedge.pages.dev#US")
    assert has_forbidden_transport_host("vless://uuid@example.net:443?host=www.speedtest.net.ns.cloudflare.com.try.cloudflare.com.attacker.test#US")
    assert not has_forbidden_transport_host("vless://uuid@example.net:443?ech=cloudflare-ech.com#US")
    for scheme in ("naive", "anytls", "brook", "snell", "juicity", "mieru", "socks", "socks4"):
        assert uri_endpoints(f"{scheme}://user@example.net:443") == ["example.net"]
    vmess = base64.b64encode(json.dumps({"add": "example.net", "ps": "Cloudflare node"}).encode()).decode()
    assert is_forbidden_label("vmess://" + vmess)
    print("Cloudflare/WARP audit self-tests passed.")

def audit(output_dir, ranges):
    hits = []
    for path in sorted(pathlib.Path(output_dir).rglob("*")):
        if not path.is_file() or path.name.lower() == "source-health.csv":
            continue
        if "cloudflare" in path.name.lower():
            hits.append("%s: Cloudflare-labelled output filename" % path)
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, 1):
            if is_forbidden_label(line):
                hits.append("%s:%d: Cloudflare/WARP display metadata" % (path, line_no))
            if has_forbidden_transport_host(line):
                hits.append("%s:%d: Cloudflare/WARP transport host" % (path, line_no))
            endpoints = uri_endpoints(line)
            key_value = KV_RE.match(line)
            if not endpoints and key_value and key_value.group(1).lower() in ("server", "server-host", "server_host", "endpoint", "address", "remote"):
                raw_endpoint = key_value.group(2).strip().strip("\"',;")
                endpoints = [raw_endpoint.split()[0]] if raw_endpoint else []
            for endpoint in endpoints:
                if endpoint_is_forbidden(endpoint, ranges):
                    hits.append("%s:%d: Cloudflare endpoint %s" % (path, line_no, endpoint))
    return hits

def main():
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        self_test()
        return 0
    if len(sys.argv) != 4:
        print("Usage: audit_cloudflare_warp.py --self-test | OUTPUT_DIR IPV4_RANGES IPV6_RANGES", file=sys.stderr)
        return 2
    try:
        ranges = read_ranges(sys.argv[2], sys.argv[3])
    except (OSError, ValueError) as exc:
        print("::error::Unable to load official Cloudflare ranges: %s" % exc, file=sys.stderr)
        return 1
    hits = audit(sys.argv[1], ranges)
    if hits:
        for hit in hits[:100]:
            print("::error::" + hit)
        print("Refusing to publish: %d Cloudflare/WARP issue(s) detected." % len(hits), file=sys.stderr)
        return 1
    print("Cloudflare/WARP audit passed: no Cloudflare endpoints or labelled/service-host metadata.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
