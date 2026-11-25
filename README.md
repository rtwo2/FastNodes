<div align="center">

# FastNodes

### Public proxy configurations. Collected globally. Ranked with evidence.

A free, automatically refreshed collection of V2Ray / Xray-compatible proxy configurations.

[![Collection workflow](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml/badge.svg)](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml)
[![Stars](https://img.shields.io/github/stars/rtwo2/FastNodes?style=flat&logo=github)](https://github.com/rtwo2/FastNodes/stargazers)
[![Forks](https://img.shields.io/github/forks/rtwo2/FastNodes?style=flat&logo=github)](https://github.com/rtwo2/FastNodes/forks)
[![License](https://img.shields.io/badge/source%20license-MIT-blue.svg)](LICENSE)
[![Refresh](https://img.shields.io/badge/collection-hourly-16a34a.svg)](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml)

**Choose a list · Copy its URL · Import it into your client**

[Quick start](#quick-start) · [Subscriptions](#featured-subscriptions) · [How verification works](#honest-verification) · [All feeds](#the-full-catalog) · [How it works](#how-fastnodes-works)

</div>

---

## Quick start

1. Pick **Top ranked** for a balanced starting point, or **Xray verified** for nodes that passed a full proxy round-trip check.
2. Copy the subscription URL.
3. In your client, choose **Add subscription** or **Import from URL**, paste the link, and update it.

No account or API key is needed to access the public lists.

## Featured subscriptions

These are the four links most visitors need. Each URL points directly to the current file on GitHub.

| List | Best for | Subscription |
|---|---|---|
| **⚡ Top ranked** | An evidence-stratified shortlist of up to 1,000 distinct connection profiles, with source, provider, domain, protocol and IPv6 diversity | [Open top.txt ↗](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top.txt) |
| **✅ Xray verified** | Nodes that completed a full proxy round-trip through Xray when the list was generated | [Open verified.txt ↗](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/verified.txt) |
| **🌐 Top IPv6** | A ranked shortlist of IPv6-capable candidates | [Open top_ipv6.txt ↗](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top_ipv6.txt) |
| **📚 Everything** | The broad collection of configurations that survive parsing and safety filters | [Open everything.txt ↗](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.txt) |

<details>
<summary><strong>Show copyable URLs</strong></summary>

**Top ranked**
```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top.txt
```

**Xray verified**
```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/verified.txt
```

**Top IPv6**
```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top_ipv6.txt
```

**Everything**
```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.txt
```

</details>

## Honest verification

FastNodes keeps different kinds of evidence separate. A TLS handshake is not the same thing as a working proxy, and a node appearing in a public feed is not proof that it is online.

| Feed | What it means |
|---|---|
| `verified.txt` | Only nodes that completed a full Xray proxy round-trip, including the expected **204** response, during the current collection run. It can be empty if no node passes. |
| `verified_tls.txt` | One best configuration per endpoint profile with a TLS handshake in the current run. This is partial connectivity evidence, not a full proxy test. |
| `top.txt` | Evidence-stratified candidates: target mix of full Xray round trips, partial TLS/edge passes, and source-tested or persistent nodes. It also reserves up to 10% for stable/source-backed QUIC or native-tunnel protocols that the current TCP/Xray probes do not cover. |
| `top_ipv6.txt` | Up to 1,000 IPv6-capable connection profiles, ranked with the same 55/30/15 evidence lanes as the global shortlist. |
| `stable.txt` | Best representative per connection profile present across at least three consecutive collection runs. Stability measures persistence in sources, not guaranteed reachability. |
| `curated.txt` | Trusted source-tested candidates or nodes that are both stable and TLS-verified. |
| `everything.txt` | Every distinct connection configuration that survives parsing and safety filters. Different credentials or transport options remain separate; equivalent URI spellings and exact semantic duplicates are collapsed. Many entries are not individually verified. |

The top selector aims for a **55% full-roundtrip / 30% partial-connectivity / 15% source-and-stability mix**. It redistributes unused capacity when a lane is short, collapses credential-only duplicates for the same protocol/endpoint/SNI/transport profile while preserving REALITY keys, obfuscation settings, VMess/SS options and other connection-affecting fields, and enforces source, provider, hostname, transport and protocol caps. Stable or multi-source candidates are not automatically discarded because a remote runner cannot reach them: they remain in the lower source/stability lane, with failed probes still labelled **tested-failed** and scored below successful checks. A native-transport reserve helps keep supported QUIC/UDP and tunnel protocols visible when they have stable or trusted-source evidence. The selector never upgrades those entries to a verified status: diagnostics continue to show them as **not tested** when no compatible full-proxy probe ran.

**A verification result is a snapshot, not a promise.** Availability can change between collection and import. Results also depend on the runner's network vantage; some nodes may work from your ISP or country even when a remote runner cannot reach them.

The optional Cloudflare edge check currently supports targets whose effective TLS SNI matches the endpoint hostname. Targets that explicitly require a different SNI are skipped by that check, but remain eligible for the other feeds and verification stages.

## The full catalog

All subscriptions are published under:

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/
```

### Quality and history

| File | Description |
|---|---|
| `top.txt` | Globally ranked shortlist |
| `top_ipv6.txt` | Ranked IPv6-capable shortlist |
| `verified.txt` | Current-run full Xray round-trip results only; may be empty |
| `verified_last_good.txt` | Sanitized historical snapshot from a previous successful run; not a current verification claim |
| `verified_tls.txt` | TLS-handshake results |
| `stable.txt` | Nodes present across consecutive runs |
| `curated.txt` | Trusted-source or stable-plus-TLS candidates |
| `everything.txt` | Broad collection; see part files below |

### By IP family

| File | Description |
|---|---|
| [`ipv4_only.txt`](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/ipv4_only.txt) | Nodes with at least one resolved IPv4 address |
| [`ipv6_only.txt`](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/ipv6_only.txt) | One best representative per connection profile with at least one resolved IPv6 address; includes candidates beyond the 1,000-node `top_ipv6.txt` shortlist |

Dual-stack hostnames can appear in both lists. These feeds classify DNS address-family support; they do not guarantee that a proxy handshake or full traffic round-trip succeeds over that family.

### By protocol

Browse the [protocol directory](https://github.com/rtwo2/FastNodes/tree/main/sub/protocols). Files are generated for the protocols available in the current collection, including:

**VLESS · VMess · Trojan · Shadowsocks · ShadowsocksR · Hysteria · Hysteria2 · TUIC · Naive · AnyTLS · Brook · Snell · Juicity · Mieru · SOCKS · WireGuard**

Example subscription:

```text
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vless.txt
```

WireGuard has two additional export formats:

- [Clash-compatible YAML](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/wireguard.txt), suitable for clients that support Clash-style WireGuard proxies.
- [Individual WireGuard configuration files](https://github.com/rtwo2/FastNodes/tree/main/sub/wireguard), suitable for importing into the official WireGuard app.

### By country and continent

- [Country subscriptions](https://github.com/rtwo2/FastNodes/tree/main/sub/countries) use two-letter country codes, for example `countries/DE.txt`.
- [Continent subscriptions](https://github.com/rtwo2/FastNodes/tree/main/sub/continents) group nodes by their GeoIP-estimated continent.

GeoIP labels are best-effort estimates, not proof of a server's physical location.

### Large-list parts

GitHub has per-file size limits, so large feeds are split automatically:

- Large global lists use files such as `everything.txt`, `everything_part2.txt`, and `everything_part3.txt`. Each part is capped at 50 MiB.
- Large history lists such as `stable.txt` may also have numbered parts.
- Protocol, country, and continent feeds are split into numbered parts when they exceed 1,000 entries.

The base file contains only its first part. **To import the complete feed, add every matching part separately** in your client. The [subscription directory](https://github.com/rtwo2/FastNodes/tree/main/sub) shows which parts currently exist.

## Compatible clients

Common clients include:

- **Android:** NekoBox, v2rayNG, Hiddify
- **Windows:** v2rayN, NekoRay and other compatible V2Ray/Xray clients
- **iOS:** Streisand, Shadowrocket and other compatible clients

Client support differs by protocol and version. A client may not support every configuration in a mixed subscription.

## How FastNodes works

The collection workflow runs on a schedule and can also be triggered by collector-code changes.

1. **Collect** — retrieve public subscriptions and nested proxy-provider feeds.
2. **Decode and parse** — handle supported share links, Base64 subscriptions, JSON, Clash YAML, sing-box formats and WireGuard configurations.
3. **Normalize and filter** — deduplicate connection variants and exclude malformed, placeholder, private/reserved, blacklisted and detected Cloudflare/WARP endpoints.
4. **Verify** — run DNS/TCP safety checks, TLS handshakes, Xray end-to-end probes and the available second-vantage edge checks.
5. **Rank and publish** — prioritize current evidence, preserve source/provider/hostname/transport diversity, and publish categorized subscriptions.

The collector uses bounded source fetching, vetted destination addresses, dual-stack connection handling, staged output generation and validation before publication.

## Transparency and diagnostics

The [collection workflow](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml) exposes run status and logs. Machine-readable reports are published in [`sub/diagnostics/`](https://github.com/rtwo2/FastNodes/tree/main/sub/diagnostics):

| Report | What it shows |
|---|---|
| [`source-health.csv`](https://github.com/rtwo2/FastNodes/blob/main/sub/diagnostics/source-health.csv) | Per-source fetching, parsing, contribution and provider outcomes |
| [`source-health-trends.csv`](https://github.com/rtwo2/FastNodes/blob/main/sub/diagnostics/source-health-trends.csv) | Feed health across recent collection runs |
| [`ranking-calibration-summary.csv`](https://github.com/rtwo2/FastNodes/blob/main/sub/diagnostics/ranking-calibration-summary.csv) | How previous score bands performed on later Xray checks |
| [`verification-status.csv.gz`](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/diagnostics/verification-status.csv.gz) | Candidate-level evidence, test status and ranking details |

These reports support manual review. Sources are not automatically removed and ranking weights are not automatically changed just because a diagnostic flags an anomaly.

## Important notes

- FastNodes aggregates public configurations; **it does not own, operate or control the proxy servers**.
- Public nodes are shared infrastructure. They may be slow, overloaded, modified, monitored by their operators, or taken offline without notice.
- Do not use unknown public nodes for sensitive accounts, private credentials, confidential activity or traffic you would not trust to an independent operator.
- A successful test only describes the tested endpoint and time. It does not establish the operator's identity, privacy practices or future behavior.
- FastNodes excludes detected Cloudflare/WARP endpoints from published outputs. DNS can change after a collection run, so no static audit can guarantee future endpoint behavior.
- Use configurations and services in compliance with local laws and applicable rules.

## Contributing

Useful, maintained sources matter more than raw source count. To suggest a source, open an [issue](https://github.com/rtwo2/FastNodes/issues) or pull request and include:

- The direct subscription URL.
- The format or protocol it provides.
- Evidence that it is maintained and contributes usable configurations.

Please do not post private subscription URLs, credentials or personal access tokens.

## License and data terms

The original FastNodes source code and associated documentation are licensed under the [MIT License](LICENSE).

Generated subscription lists and files under `sub/` are subject to [`DATA-TERMS.md`](DATA-TERMS.md), to the extent FastNodes has the rights or legal authority to impose those terms. Third-party content remains subject to its own applicable licenses and terms.

---

<div align="center">

**FastNodes** · Open source · [Repository](https://github.com/rtwo2/FastNodes) · [Subscriptions](https://github.com/rtwo2/FastNodes/tree/main/sub) · [Latest workflow](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml)

*Collected globally. Verified honestly. Updated automatically.*

</div>
