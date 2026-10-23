<div align="center">

# FastNodes

**Free public proxy subscriptions · Automatically collected and refreshed**

[![Workflow](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml/badge.svg)](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml)
![Protocols](https://img.shields.io/badge/protocols-VLESS%20·%20VMess%20·%20Trojan%20·%20SS%20·%20Hysteria2%20·%20WireGuard-5965f2)
![License](https://img.shields.io/badge/license-MIT-555)

A global collection of public V2Ray/Xray-compatible configurations.  
**Pick a subscription, copy the URL, and import it into your client.**

Generated node names use `flag Country - City | host:port`. IPv6 literals are bracketed, and duplicate visible names receive a trailing `2`, `3`, and so on.

[Subscriptions](#subscriptions) · [Choose a list](#which-list-should-i-use) · [Import guide](#import) · [All outputs](#more-subscriptions)

</div>

---

## Subscriptions

These are the main links most people need. Copy the URL inside the code block, then paste it into your client as a subscription URL.

### Top ranked

A globally ranked shortlist of up to 1,000 candidates. Best starting point for most users.

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top.txt
```

[Open top.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top.txt)

### Top IPv6-capable

A ranked shortlist of up to 1,000 IPv6-capable nodes with positive quality evidence.

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top_ipv6.txt
```

[Open top_ipv6.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top_ipv6.txt)

### Xray verified

Nodes that passed the project's end-to-end Xray verification when the list was generated. Availability can change.

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/verified.txt
```

[Open verified.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/verified.txt)

### All collected nodes

The broad, global list of surviving configurations. Larger list; not every entry will work from every network.

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.txt
```

[Open everything.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.txt)

### IPv6-capable

Includes nodes whose resolved addresses support native IPv6. Dual-stack hostnames may also appear in the IPv4 feed.

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/ipv6_only.txt
```

[Open ipv6_only.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/ipv6_only.txt)

### IPv4-capable

Includes nodes whose resolved addresses support IPv4. Dual-stack hostnames may appear in both family feeds.

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/ipv4_only.txt
```

[Open ipv4_only.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/ipv4_only.txt)

### WireGuard

For compatible clients that support the project's WireGuard/Clash YAML output.

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/wireguard.txt
```

[Open wireguard.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/wireguard.txt)

---

## Which list should I use?

| If you want… | Use |
|---|---|
| A simple starting point | `top.txt` |
| Ranked IPv6-capable shortlist | `top_ipv6.txt` |
| Nodes that passed an Xray round-trip check | `verified.txt` |
| The largest global collection | `everything.txt` |
| IPv6-capable candidates | `ipv6_only.txt` |
| IPv4-capable candidates | `ipv4_only.txt` |
| WireGuard-compatible output | `protocols/wireguard.txt` |

Verification results are snapshots, not guarantees of current availability. `verified.txt` normally refreshes from nodes that passed a full Xray round-trip in the current run; when too few nodes pass, it retains the last-good snapshot only after filtering malformed links, placeholder credentials/hosts, private or reserved addresses, known blacklist ranges, and Cloudflare/WARP-related entries. If neither the current run nor the sanitized snapshot provides a safe entry, publication fails rather than replacing the last published output tree with an unsafe or empty verified list. `stable.txt` tracks nodes seen across consecutive runs, while `verified_tls.txt` and `curated.txt` represent different evidence tiers. Your ISP, location, client, and protocol support affect whether a node connects.

## Diagnostics and maintenance

Each full collection publishes machine-readable source-health data under `sub/diagnostics/`.
- `source-health.csv` reports per-feed fetch, parse, unique contribution, provider outcomes, and elapsed time.
- `source-health-trends.csv` compares each feed across the latest 14 full runs and flags recurring parser gaps, repeated zero-contribution runs, and recurring fetch failures for review.
- `ranking-calibration-summary.csv` records score-band outcomes; `ranking-calibration-notes.md` applies a minimum sample threshold and highlights non-monotonic outcomes worth investigating.

These reports are diagnostic only. No source is automatically removed, and ranking weights are not automatically modified. Review recurring issues across multiple successful runs before changing source priority or scoring.

## Import

1. Copy one of the subscription URLs above.
2. Open your client and choose **Add subscription**, **Import from URL**, or the equivalent option.
3. Paste the URL and update the subscription.
4. If the list does not work well, try `verified.txt` or another list. No public node is guaranteed to work on every network.

Common compatible clients include Hiddify, v2rayNG, NekoBox, v2rayN, Streisand, Shadowrocket, and other V2Ray/Xray clients. Supported protocols vary by client.

## More subscriptions

All URLs below use the same base path:

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/
```

### Quality and history

| File | Purpose | Copyable URL |
|---|---|---|
| `top.txt` | Globally ranked shortlist | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top.txt` |
| `top_ipv6.txt` | Ranked IPv6-capable shortlist | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top_ipv6.txt` |
| `verified.txt` | Xray-verified list | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/verified.txt` |
| `verified_tls.txt` | TLS-verified candidates | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/verified_tls.txt` |
| `stable.txt` | Nodes seen across consecutive runs | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/stable.txt` |
| `curated.txt` | Additional curated candidates | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/curated.txt` |
| `everything.txt` | Full surviving global list | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.txt` |

### By IP family

| List | Copyable URL |
|---|---|
| IPv4-capable | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/ipv4_only.txt` |
| IPv6-capable | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/ipv6_only.txt` |

### By protocol

Base URL:

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/
```

Replace `<protocol>.txt` with a protocol name, for example `vless.txt`, `vmess.txt`, `trojan.txt`, `ss.txt`, `hysteria2.txt`, or `wireguard.txt`.

Example:

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vless.txt
```

Large protocol lists may be split into parts such as `vless_part2.txt`. The first file contains the first chunk; check the repository's [`sub/protocols/`](https://github.com/rtwo2/FastNodes/tree/main/sub/protocols) directory for available parts.

### By country and continent

Country lists:

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/
```

Continent lists:

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/
```

For example, a country file uses a two-letter country code:

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/DE.txt
```

Browse the [`sub/countries/`](https://github.com/rtwo2/FastNodes/tree/main/sub/countries) or [`sub/continents/`](https://github.com/rtwo2/FastNodes/tree/main/sub/continents) directory to see which files currently exist.

## How it works

FastNodes automatically collects public configurations, parses supported formats, removes duplicates and unusable entries, applies verification and ranking signals, then publishes subscription files through GitHub.

- **Global collection:** outputs are not limited to one country or region.
- **Multiple quality signals:** ranking and verification files have different purposes; a successful check is not a permanent guarantee.
- **IPv4 and IPv6:** family feeds include dual-stack hostnames in both lists when DNS returns both address families.
- **Cloudflare exclusion:** Cloudflare-hosted/fronted nodes are intended to be excluded from published outputs.
- **Automatic updates:** follow the [Actions workflow](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml) to see run status and logs.
- **Diagnostics:** `sub/diagnostics/source-health.csv` records per-source fetch, parse, and unique-contribution evidence. Workflow artifacts include a readable source summary and an output-regression/size report.

## Notes

- This project aggregates public configurations; it does not operate the proxy servers.
- Public nodes may be slow, overloaded, offline, or unsuitable for a particular network.
- Only use configurations and services in ways that comply with local laws and applicable rules.
- Do not put private credentials or personal subscription URLs into public issues.

## Contributing

Source quality matters more than raw source count. If you know a maintained public source, open an issue or pull request with the URL and evidence that it provides usable configurations.

---

<div align="center">

**FastNodes** · Open source · [Repository](https://github.com/rtwo2/FastNodes) · [Workflow status](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml)

</div>
