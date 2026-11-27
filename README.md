<div align="center">

# ✦ FastNodes

### A little less hunting. A lot more connecting. ♡

**A global, automatically refreshed collection of public proxy configurations — carefully filtered, honestly tested, and neatly organized.**

[![CI](https://github.com/rtwo2/FastNodes/actions/workflows/ci.yml/badge.svg)](https://github.com/rtwo2/FastNodes/actions/workflows/ci.yml)
[![Collection](https://img.shields.io/github/actions/workflow/status/rtwo2/FastNodes/collect.yml?label=collection&logo=githubactions)](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml)
[![Stars](https://img.shields.io/github/stars/rtwo2/FastNodes?style=flat&logo=github)](https://github.com/rtwo2/FastNodes/stargazers)
[![License](https://img.shields.io/badge/code-MIT-8b7cf6.svg)](LICENSE)
[![Refresh](https://img.shields.io/badge/refresh-automatic-38a169.svg)](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml)

<br>

**Pick a feed&nbsp; → &nbsp;Copy its URL&nbsp; → &nbsp;Import&nbsp; → &nbsp;Enjoy**

[Get started](#-get-started) · [Featured feeds](#-the-good-stuff) · [Verification](#-what-does-verified-mean) · [All subscriptions](#-the-full-collection) · [How it works](#-under-the-hood)

</div>

---

## ♡ Get started

No account, token, or setup wizard needed.

1. Choose a subscription below. **Top ranked** is a good place to start.
2. Copy the raw URL (or open the file and copy its address).
3. In your client, select **Add subscription** / **Import from URL**, paste it, and update.

Works with compatible V2Ray / Xray clients. Individual protocol support depends on your app.

Generated subscriptions are published on the [`outputs` branch](https://github.com/rtwo2/FastNodes/tree/outputs); source code, tests and CI stay on `main`.

## ✨ The good stuff

A few useful feeds, without making you dig through the whole collection.

| Feed | A good choice when you want… | Open |
|:--|:--|:--:|
| ⚡ **Top ranked** | A balanced shortlist ranked using current test evidence, source quality, and diversity | [top.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/outputs/sub/top.txt) |
| 🛡️ **Xray verified** | Nodes that completed a full Xray proxy round-trip in the latest collection | [verified.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/outputs/sub/verified.txt) |
| 🌐 **Top IPv6** | A ranked shortlist of IPv6-capable candidates | [top_ipv6.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/outputs/sub/top_ipv6.txt) |
| 📦 **Everything** | The broad collection after parsing and safety filters | [everything.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/outputs/sub/everything.txt) |

<details>
<summary><strong>♡ Show copy-and-paste subscription URLs</strong></summary>

**Top ranked**
```text
https://raw.githubusercontent.com/rtwo2/FastNodes/outputs/sub/top.txt
```

**Xray verified**
```text
https://raw.githubusercontent.com/rtwo2/FastNodes/outputs/sub/verified.txt
```

**Top IPv6**
```text
https://raw.githubusercontent.com/rtwo2/FastNodes/outputs/sub/top_ipv6.txt
```

**Everything**
```text
https://raw.githubusercontent.com/rtwo2/FastNodes/outputs/sub/everything.txt
```
</details>

> **Tiny tip:** Start with Top ranked. If you need a wider pool, try Everything. If you specifically need IPv6, use Top IPv6.

## 🔎 What does “verified” mean?

We keep different kinds of evidence separate. A TLS handshake is useful, but it is **not** the same as proving that proxy traffic works.

| Feed | What the label actually means |
|:--|:--|
| `verified.txt` | Full Xray proxy round-trip completed, including the expected **HTTP 204** response, during the current run. It may be empty when nothing passes. |
| `verified_tls.txt` | TLS handshake succeeded during the current run. This is partial connectivity evidence, not a full proxy test. |
| `top.txt` | Global shortlist using 55% full-roundtrip, 30% partial-connectivity, and 15% source/stability evidence lanes, with an IPv6 reservation and diversity caps. |
| `top_ipv6.txt` | IPv6-capable shortlist using the same 55/30/15 evidence mix and source/provider/hostname/transport/protocol diversity controls. |
| `stable.txt` | The selected credential variant has appeared in at least three consecutive collection runs. Stability history is tracked per exact configuration; other credentials collapsed into the same service profile do not inherit that status. Persistence is not a promise of reachability. |
| `curated.txt` | Trusted-source candidates, or candidates that are both stable and TLS-verified. |
| `everything.txt` | One best representative per distinct service profile that survives parsing and safety filters. Many entries are not individually verified. |

### How the ranking stays balanced

Both top feeds use the same evidence mix:

- **55% — Full round-trip:** the strongest available live evidence.
- **30% — Partial connectivity:** useful TLS/connectivity signals, without pretending they prove a working tunnel.
- **15% — Source and stability:** source quality and persistence, including candidates a remote runner cannot currently reach.

The selector collapses credential-only duplicates for the same service profile while preserving connection-affecting differences such as SNI, transport, path, REALITY keys, obfuscation options, Shadowsocks cipher modes, and WireGuard tunnel keys. Source, provider, hostname, transport, and protocol caps help prevent one large feed or host family from taking over. Hostname grouping uses the Public Suffix List, including wildcard and exception rules, with the previous heuristic retained as a fallback if the list cannot be loaded. A reserved share also keeps source-backed QUIC and native-tunnel candidates in consideration when the current TCP/Xray probes cannot test them.

The global feed also reserves its configured IPv6 share. When one evidence lane or diversity group cannot fill its allocation, other lanes can backfill available slots without turning off diversity controls.

**A test result is a snapshot, not a promise.** Reachability can change after collection, and results depend on the runner's network location. A node that fails from the runner may still work from your ISP or country.

The Cloudflare edge check sends each target's effective TLS SNI separately from its endpoint hostname. A custom-SNI result is credited only when the Worker applies and echoes the exact requested SNI; legacy host-only responses remain valid only when endpoint hostname and SNI are identical. See [the Worker contract](docs/EDGE-WORKER-CONTRACT.md) before updating the external Worker.

### Protocol note: Mieru

FastNodes supports Mieru's human-readable `mierus://` simple-share format, including repeated port/protocol bindings expanded into separate TCP or UDP nodes. Supported sing-box and Clash Mieru definitions are also converted. Binary protobuf shares preserve MTU, multiplexing, handshake mode and traffic-pattern settings when converting to the official simple-share format. Profiles that require the optional proxy dialer are skipped rather than silently converted into direct connections.


## 🗂️ The full collection

WireGuard `.conf` and Clash/Mihomo YAML exports preserve source MTU and persistent-keepalive values when supplied. AmneziaWG `reserved` bytes are retained in the Clash YAML feed; the standard WireGuard `.conf` format has no equivalent directive.

All generated subscriptions live in:

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/outputs/sub/
```

### Quality & history

| File | What's inside |
|:--|:--|
| `top.txt` | Globally ranked shortlist |
| `top_ipv6.txt` | Ranked IPv6-capable shortlist |
| `verified.txt` | Current-run full Xray round-trip results; may be empty |
| `verified_last_good.txt` | Sanitized historical snapshot; not a current verification claim |
| `verified_tls.txt` | TLS-handshake results |
| `stable.txt` | Profiles present across consecutive runs |
| `curated.txt` | Trusted-source or stable-plus-TLS candidates |
| `everything.txt` | Broad collection; see the part-file note below |

### IPv4 & IPv6

| File | What's inside |
|:--|:--|
| [`ipv4_only.txt`](https://raw.githubusercontent.com/rtwo2/FastNodes/outputs/sub/ipv4_only.txt) | Profiles with at least one resolved IPv4 address |
| [`ipv6_only.txt`](https://raw.githubusercontent.com/rtwo2/FastNodes/outputs/sub/ipv6_only.txt) | Profiles with at least one resolved IPv6 address; broader than the 1,000-entry Top IPv6 shortlist |

Dual-stack hostnames can appear in both. These lists describe DNS address-family support, not guaranteed proxy connectivity over that family.

### By protocol

Browse the [protocol directory](https://github.com/rtwo2/FastNodes/tree/outputs/sub/protocols).

**VLESS · VMess · Trojan · Shadowsocks · ShadowsocksR · Hysteria · Hysteria2 · TUIC · Naive · AnyTLS · Brook · Snell · Juicity · Mieru · SOCKS · WireGuard**

Example:

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/outputs/sub/protocols/vless.txt
```

WireGuard also has two additional exports:

- [Clash-compatible YAML](https://raw.githubusercontent.com/rtwo2/FastNodes/outputs/sub/protocols/wireguard.txt)
- [Individual WireGuard configuration files](https://github.com/rtwo2/FastNodes/tree/outputs/sub/wireguard), for compatible WireGuard clients

### By country & continent

- [Country feeds](https://github.com/rtwo2/FastNodes/tree/outputs/sub/countries) use two-letter country codes, such as `countries/DE.txt`.
- [Continent feeds](https://github.com/rtwo2/FastNodes/tree/outputs/sub/continents) group candidates by GeoIP-estimated continent.

GeoIP labels are best-effort estimates, not proof of a server's physical location.

### Big feeds, little pieces

GitHub has file-size limits, so large subscriptions are split automatically:

- Global feeds use files such as `everything.txt`, `everything_part2.txt`, and `everything_part3.txt`. Each part is capped at **50 MiB**.
- Large history feeds, such as `stable.txt`, may also have numbered parts.
- Protocol, country, and continent feeds are split when they exceed **1,000 entries**.

The base file contains only its first part. To import the **complete** feed, add every matching part separately in your client. The [subscription directory](https://github.com/rtwo2/FastNodes/tree/outputs/sub) shows which parts currently exist.

## 📱 Compatible clients

Some popular options:

| Platform | Examples |
|:--|:--|
| Android | NekoBox, v2rayNG, Hiddify |
| Windows | v2rayN, NekoRay, other compatible V2Ray/Xray clients |
| iOS | Streisand, Shadowrocket, other compatible clients |

Client support varies by app and version. A client may not understand every protocol in a mixed subscription.

## ⚙️ Under the hood

The collection workflow runs automatically on a schedule and can also be triggered by collector-code changes.

```text
Public sources
     ↓
Fetch & expand provider feeds
     ↓
Decode & parse supported formats
     ↓
Normalize, deduplicate & apply safety filters
     ↓
DNS / TCP / TLS / Xray / available edge checks
     ↓
Rank, diversify, validate & publish
```

In practice, the collector:

1. **Collects** public subscriptions and nested proxy-provider feeds.
2. **Decodes** supported share links, Base64 subscriptions, JSON, Clash YAML, sing-box formats, and WireGuard configurations.
3. **Normalizes** service profiles and filters malformed, placeholder, private/reserved, blacklisted, and detected Cloudflare/WARP endpoints.
4. **Verifies** DNS/TCP safety, TLS handshakes, Xray end-to-end behavior, and available second-vantage edge checks.
5. **Ranks and publishes** categorized feeds with evidence-aware scoring and diversity controls.

The pipeline uses bounded source fetching, vetted destination addresses, dual-stack connection handling, staged output generation, and validation before publication.

## 📊 Transparency & diagnostics

You can follow each collection in the [Actions workflow](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml). Machine-readable reports are published in [`sub/diagnostics/`](https://github.com/rtwo2/FastNodes/tree/outputs/sub/diagnostics).

| Report | What it tells you |
|:--|:--|
| [`source-health.csv`](https://github.com/rtwo2/FastNodes/blob/outputs/sub/diagnostics/source-health.csv) | Fetching, parsing, contribution, and provider outcomes per source |
| [`source-health-trends.csv`](https://github.com/rtwo2/FastNodes/blob/outputs/sub/diagnostics/source-health-trends.csv) | Source health across recent collection runs |
| [`ranking-calibration-summary.csv`](https://github.com/rtwo2/FastNodes/blob/outputs/sub/diagnostics/ranking-calibration-summary.csv) | How previous score bands performed in later Xray checks |
| [`verification-status.csv.gz`](https://raw.githubusercontent.com/rtwo2/FastNodes/outputs/sub/diagnostics/verification-status.csv.gz) | Candidate-level evidence, test status, and ranking details |

Diagnostics help with manual review. A flagged source is not automatically removed, and ranking weights are not automatically changed just because a report finds an anomaly.

## ⚠️ A few important things

- FastNodes aggregates public configurations. **It does not own, operate, or control the proxy servers.**
- Public nodes are shared infrastructure. They may be slow, overloaded, modified, monitored by their operators, or taken offline at any time.
- Avoid using unknown public nodes for sensitive accounts, private credentials, confidential activity, or traffic you would not trust to an independent operator.
- A successful test only describes the tested endpoint at that time. It does not establish the operator's identity, privacy practices, or future behavior.
- Detected Cloudflare/WARP endpoints are excluded from published outputs. DNS can change after collection, so no static audit can guarantee future endpoint behavior.
- Use configurations and services in compliance with local laws and applicable rules.

## 🧡 Contributing

Good sources matter more than a huge source count. Want to suggest one? Open an [issue](https://github.com/rtwo2/FastNodes/issues) or pull request with:

- The direct subscription URL.
- The format or protocol it provides.
- Evidence that it is maintained and contributes usable configurations.

Please don't post private subscription URLs, credentials, or personal access tokens.

## 📄 License & data terms

The original FastNodes source code and associated documentation are licensed under the [MIT License](LICENSE).

Generated subscription lists and files under `sub/` are subject to [`DATA-TERMS.md`](DATA-TERMS.md), to the extent FastNodes has the rights or legal authority to impose those terms. Third-party content remains subject to its own applicable licenses and terms.

---

<div align="center">

### Thanks for stopping by ✦

**FastNodes** · [Repository](https://github.com/rtwo2/FastNodes) · [Subscriptions](https://github.com/rtwo2/FastNodes/tree/outputs/sub) · [Latest collection](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml)

*Collected globally. Verified honestly. Shared openly.* ♡

</div>
