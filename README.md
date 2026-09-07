<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f0c29,50:302b63,100:24243e&height=200&section=header&text=FastNodes&fontSize=80&fontColor=ffffff&fontAlignY=38&desc=The%20World%27s%20Smartest%20Free%20V2Ray%20Collector&descAlignY=58&descSize=18" width="100%"/>

<br/>

[![Update Status](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml/badge.svg)](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml)
![Protocol](https://img.shields.io/badge/Protocols-VLESS%20%7C%20VMess%20%7C%20Trojan%20%7C%20SS%20%7C%20Hy2%20%7C%20WG-blueviolet?style=flat-square)
![Update](https://img.shields.io/badge/Auto%20Update-Hourly-brightgreen?style=flat-square)
![Sources](https://img.shields.io/badge/Sources-642%20(GitHub%20%2B%20Telegram%20%2B%20Web)-blue?style=flat-square)
![Xray](https://img.shields.io/badge/Deep%20Check-Xray%20Core%20Roundtrip-success?style=flat-square)
![CF Edge](https://img.shields.io/badge/Edge%20Verify-Cloudflare%20Worker-orange?style=flat-square)
![Region](https://img.shields.io/badge/Top%20%26%20Verified-Europe%20%2B%20Iran%20%2B%20Neighbors-9cf?style=flat-square)
![Version](https://img.shields.io/badge/Version-v6.20-purple?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-orange?style=flat-square)
![Built With](https://img.shields.io/badge/Built%20with-C%23%20.NET%209-purple?style=flat-square)

<br/>

**Collects · Filters · Deduplicates · Deep-Checks · Ranks · Publishes**
*Fully automated. No ads. No login. No BS.*

<br/>

[🚀 Quick Start](#-quick-start) · [📊 Live Snapshot](#-live-snapshot) · [🏆 Quality Tiers](#-quality-tiers) · [🌍 Region Policy](#-region-policy--multi-signal-ranking) · [📁 All Subscriptions](#-subscription-links) · [⚙️ How It Works](#️-how-it-works) · [📱 Clients](#-compatible-clients)

---

## ✨ What Is FastNodes?

FastNodes is a fully automated, multi-vantage V2Ray/Xray proxy aggregator. Every hour, it fetches configs from **642 sources** — public GitHub repositories, Telegram channels, and standalone websites. It doesn't just list them; it runs them through a gauntlet of filters, deduplicates them by full config identity, and performs **deep liveness checks** using Xray-core, Cloudflare Workers, and Azure TLS probes.

**The headline files are tuned for real-world usability:** `top.txt` and `verified.txt` contain **only Europe, Iran, and Iran-neighbor nodes** — the regions that empirically work. Everything else stays fully available in the global files.

---

## 📊 Live Snapshot

Numbers from the latest full run (updated hourly — typical values, not guarantees):

### The Pyramid of Trust

```text
642 sources ──► 1,817,641 raw lines ──► 239,689 unique configs
                                              │
                              ┌───────────────┴───────────────┐
                              │   Dead-node & alias filters    │
                              │  (NXDOMAIN · TCP-RST · bogon)  │
                              └───────────────┬───────────────┘
                                              ▼
                                    192,413 alive nodes
                                              │
                          ┌───────────────────┼───────────────────┐
                          ▼                   ▼                   ▼
                   34,123 TLS-verified      734 Xray-verified   276 Edge-verified
                   (CF-fronted excluded)    (FULL roundtrip,    (CF 2nd vantage,
                                             Europe/IR only)    preferred regions)
                                              │                   │
                                     └─────────┴───────────────────┘
                                                ▼
                                top.txt + verified.txt
                          (Europe + Iran + neighbors ONLY)
```

### Protocol Distribution (~192,000 nodes)

```text
vless       ████████████████████████████████████████  145,240  (75.5%)
trojan      █████                                       18,168  ( 9.4%)
vmess       ████                                        13,442  ( 7.0%)
ss          ███                                          10,460  ( 5.4%)
hysteria2   █                                             3,879  ( 2.0%)
wireguard   ▏                                              626  ( 0.3%)
ssr/tuic/socks/anytls/hysteria/socks5                              598  ( 0.3%)
```

### Geographic Distribution (~192,000 nodes)

```text
Europe        ████████████████████████████████████████   75,684  (39.3%)
North America █████████████████                           31,067  (16.1%)
Asia          █████████████                               26,098  (13.6%)
Africa        ██                                            2,922  ( 1.5%)
Oceania       ▏                                               942  ( 0.5%)
South America ▏                                               777  ( 0.4%)
```

### Run Statistics

| Metric | Value |
|--------|-------|
| Total runtime | ~21 minutes (of a 50-minute budget) |
| Raw lines parsed per run | ~1.82 million |
| Nodes dropped as provably dead | ~47,000 (NXDOMAIN + TCP-RST + bogons) |
| Xray deep check | 734/2,682 roundtrips completed in 161s — 0 skipped by budget |
| Sources healthy / dead | 629 / 13 |
| History tracked (cross-run) | ~195,000 nodes |
| Nodes marked stable (3+ runs) | ~189,700 |

---

## 🚀 Quick Start

The fastest way to get working proxies. Just copy a link and paste it into your client (Hiddify, v2rayNG, NekoBox, etc.):

| What | Link |
|------|------|
| **🏆 Top 1000 Ranked** | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top.txt` |
| **🛰️ Xray Verified (Europe + IR region)** | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/verified.txt` |
| **🌍 Everything (all regions)** | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.txt` |
| **🔒 WireGuard (NekoBox)** | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/wireguard.txt` |

> **`top.txt` and `verified.txt` contain only Europe + Iran + Iran-neighbor nodes** (🇪🇺🇮🇷🇹🇷🇦🇪 and neighbors). This matches empirical performance: European and Iranian-region servers connect reliably; US/Asia/CF-fronted free nodes rarely do. All other regions remain fully available in the global files below.

---

## 🏆 Quality Tiers

| File | Typical size | What it is |
|------|--------------|------------|
| `sub/top.txt` | 1,000 | **The precision file.** Europe + IR + neighbors only, ranked by composite score (observed range 117–187). Gate: at least one affirmative current signal. |
| `sub/verified.txt` | ~730 | **The strongest life signal.** Europe + IR + neighbor nodes that proxied a real HTTP `generate_204` request end-to-end through `xray-core` this run. The entire roundtrip budget is spent exclusively on these regions. Never ships empty — falls back to the last successful set if the check stage ever fails. |
| `sub/verified_tls.txt` | ~34,000 | Nodes that completed a TLS handshake with their real SNI from a clean vantage. **CF-fronted hosts are excluded** (~32K per run) — an edge handshake terminates at Cloudflare and proves nothing about the backend behind it. |
| `sub/curated.txt` | ~45,000 | Nodes from explicitly Iran-tested sources, PLUS nodes that are both stable and TLS-verified. |
| `sub/stable.txt` | ~190,000 | Nodes that have survived 3+ consecutive hourly runs without being dropped. |
| `sub/everything.txt` | ~192,000 | The full, uncapped list of all surviving nodes — all regions. Never split. |
| `sub/protocols/wireguard.txt` | ~40 | WireGuard nodes as **Clash YAML** — keys strictly validated (32-byte, base64-normalized), **NekoBox imports this directly**. |
| `sub/wireguard/*.conf` | ~40 files | Individual sanitized `.conf` files — **WireGuard app imports these directly**. |

---

## 🌍 Region Policy & Multi-Signal Ranking

**One simple rule:** `top.txt` and `verified.txt` admit **only Europe, Iran, and Iran-neighbor countries** (TR, AE, IQ, AM, AZ, TM, AF, PK, QA, KW, BH, OM, SA, GE, KZ). Every other output file remains global.

The Xray roundtrip budget and the Cloudflare Edge budget are spent **exclusively** on preferred-region nodes — a verified US or Asian node would earn points it can never spend, so the budget goes where it pays. Within the region, nodes are ordered by a composite score:

| Signal | Points | What it proves |
|--------|--------|----------------|
| Xray roundtrip | +35 | A real HTTP request was proxied **through** this node, end-to-end |
| Iran-tested source | +30 | Delegated validation: a maintainer tested this node from inside Iran |
| CF Edge verified | +20 | Alive from a **second** vantage class (Cloudflare edge) |
| TLS verified | +20 | Completed a TLS handshake with the node's real SNI |
| Region weight | up to +27 | Europe-first ordering within the allowed set |
| Presence streak | up to +20 | Survived N consecutive hourly runs of all drop filters |
| Xray streak | up to +15 | Roundtrip-verified N runs in a row |
| Multi-source | up to +10 | Published by 2+ independent sources (ecosystem consensus) |

### The three verification vantages

| | Azure TLS probe | 🛰️ Xray deep check | 🌐 CF Edge Worker |
|---|---|---|---|
| **Depth** | TLS handshake only | Full proxy roundtrip (real traffic) | TCP + TLS handshake |
| **Region focus** | Global | **Europe + IR + neighbors only** | **Europe + IR + neighbors only** |
| **CF-fronted nodes** | **Skipped — edge handshakes prove nothing** | ✅ Only valid judge of CF nodes | Skipped (platform restriction) |
| **Drops on fail?** | Never | Never | Never |

> **Why skip CF-fronted hosts in TLS?** A TLS handshake with a Cloudflare edge server **always succeeds** — even when the proxy hiding behind it is dead, because the handshake terminates at the edge and never reaches the origin. That fake "+20 verified" signal was flooding `top.txt` with CF nodes that never work. CF nodes can now only prove life through a genuine Xray roundtrip.

> **Why is verified.txt never empty?** If the Xray stage ever fails to run (stage failure, binary issue), the last successful set is shipped from `state/verified_last.txt` instead of an empty subscription. Stale beats empty for a live subscription.

---

## 📁 Subscription Links

All output is plain raw URI lists (`.txt`) — one config per line, works in every V2Ray/Xray client. Output files are sorted alphabetically (Host → Protocol) for stability.

### 📦 Large lists are split into parts
`everything.txt` and the quality tiers are never split. Every other category (protocols, countries, continents) caps at 1000 lines per file. The first 1000 always stay in `xx.txt` — that link never changes — and everything beyond that spills into `xx_part2.txt`, `xx_part3.txt`, etc.

```text
sub/protocols/vless.txt          ← first 1000
sub/protocols/vless_part2.txt    ← next 1000
```

### 🔢 By IP family

Nodes are classified by their **resolved IP family** (hostname nodes are included based on their DNS lookup).

| URL |
|-----|
| `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/ipv4_only.txt` |
| `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/ipv6_only.txt` |

### 🔧 By Protocol

Base path: `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/`

Recognized protocols: `vmess, vless, trojan, ss, ssr, hysteria, hysteria2 (+ hy2 alias), tuic, wireguard, socks, socks5`. Each gets its own file if at least one alive node uses it:

| Protocol | Nodes | File |
|----------|-------|------|
| 🔵 VLESS | ~145K | [vless.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vless.txt) |
| 🟣 Trojan | ~18K | [trojan.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/trojan.txt) |
| 🟠 VMess | ~13K | [vmess.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vmess.txt) |
| ⚫ Shadowsocks | ~10K | [ss.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/ss.txt) |
| ⚡ Hysteria2 | ~4K | [hysteria2.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/hysteria2.txt) |
| 🔒 WireGuard | ~40 | [wireguard.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/wireguard.txt) — Clash YAML for NekoBox |

> **WireGuard users:** The `wireguard.txt` file is a Clash YAML config (NekoBox imports it directly). Individual `.conf` files for the official WireGuard app are in the `sub/wireguard/` directory. All keys are strictly validated — nodes with malformed keys are dropped rather than crashing your client.

### 🌍 By Continent & Country

Base paths:
- `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/`
- `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/`

**Popular countries:**

| | Country | Nodes | File |
|-|---------|-------|------|
| 🇮🇷 | Iran | ~6.8K | [IR.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/IR.txt) |
| 🇩🇪 | Germany | ~17K | [DE.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/DE.txt) |
| 🇺🇸 | United States | ~29K | [US.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/US.txt) |
| 🇷🇺 | Russia | ~20K | [RU.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/RU.txt) |
| 🇬🇧 | United Kingdom | ~5.8K | [GB.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/GB.txt) |
| 🇫🇷 | France | ~6.4K | [FR.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/FR.txt) |
| 🇳🇱 | Netherlands | ~6.5K | [NL.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/NL.txt) |

> Around 90 countries are typically available. Just swap the country code in the URL pattern.

---

## 📱 Compatible Clients

Every output file is a plain raw URI list — works in virtually every V2Ray/Xray client:

| Client | Platform | How to import |
|--------|----------|---------------|
| **Hiddify** | Android / iOS / Desktop / Windows | Add Profile → URL → paste `.txt` link |
| **v2rayNG** | Android | Subscription → Add → paste `.txt` link |
| **NekoBox / NB4A+** | Android | Profile → New → paste `.txt` link |
| **NekoBox (WireGuard)** | Android | Profile → New → paste `wireguard.txt` link — imports Clash YAML |
| **Shadowrocket** | iOS | Add → Type: Subscribe → paste link |
| **Streisand** | iOS | Add Config → paste link |
| **v2rayN** | Windows | Subscription Group → Add → paste `.txt` link |
| **Nekoray** | Windows / Linux | Preferences → Subscription → paste link |
| **WireGuard app** | Android / iOS / Windows | Import `.conf` files from `sub/wireguard/` directory |

> **Raw URI lists work everywhere and load faster.** For WireGuard, a Clash YAML config is provided specifically for NekoBox compatibility.

---

## ⚙️ How It Works

FastNodes runs a 5-stage pipeline every hour, with multiple fail-soft verification layers. Every stage is designed to never kill the pipeline if a third-party service crashes.

```text
642 Sources (GitHub · Telegram · web, fetched in parallel)
        ↓  ~1.82M raw lines → 240K unique configs
🧹 Step 1: Decode & Smart Dedup (full config identity + alias collapse)
        ↓
🌍 Step 2: GeoIP Lookup (106K unique hosts — City · Org · Country, DNS cached)
        ↓
💀 Step 3: Dead-Node Filters (~47K dropped: NXDOMAIN · TCP-RST · bad IPs)
          (Timeouts NEVER drop a node; circuit breakers protect against mass-drops)
        ↓
🔐 Step 4: Multi-Vantage Promotion (Fail-Soft)
   ├─ TLS Verification — ~34K promoted (CF-fronted hosts SKIPPED: ~32K per run)
   ├─ 🛰️ Xray Deep Check — REAL proxy roundtrip via xray-core, candidates drawn
   │     EXCLUSIVELY from Europe/IR/neighbors (2,682 candidates, 734 verified,
   │     161s — xray's output pipes are drained live to prevent startup freezes)
   ├─ 🌐 Edge Verification — Cloudflare Worker 2nd vantage, pools drawn
   │     EXCLUSIVELY from preferred regions (~276 promoted; catches nodes that
   │     geo-block US datacenters)
   └─ 📚 Stability Tracking (195K nodes in state/history.json)
        ↓
💾 Step 5: Region Gate + Composite Score & Publish
          top.txt + verified.txt → Europe/IR/neighbors ONLY
          all other files → global, alphabetical
```

---

## 🧠 Smart Deduplication

Most collectors dedup on `host:port` only, which silently drops configs with different UUIDs on the same server. FastNodes deduplicates on the **full config identity**:

```text
protocol + host + port + credential + transport + security + SNI
         + path + REALITY pbk/sid + flow + obfs-password
```

If a server hosts multiple VLESS configurations (common with Xray setups), all of them are kept. On top of the identity key, an alias-collapse pass re-keys every node on its **resolved IP** and merges spelling-variants — `vless://uuid@1.2.3.4:443` and `vless://uuid@server.com:443` ship as one node, keeping the hostname form (which survives IP rotation).

---

## 🏷️ How Nodes Are Named

Each remark is **geo info + server address**. When multiple nodes share the same server, each gets a port suffix so you can tell the inbounds apart:

```text
🇩🇪 Frankfurt, DE · Hetzner | example.com          ← only node on this server
🇩🇪 Frankfurt, DE · Hetzner | example.com :8443    ← 2nd node, port 8443
🇩🇪 Frankfurt, DE · Hetzner | example.com :8443·vless  ← same port, different protocol
```

The suffix is **stable across runs** — the input list is sorted (host → port → protocol) before naming, so the same server:port always gets the same suffix.

---

## 📂 Repository Structure

```text
FastNodes/
├── .github/workflows/collect.yml       # Hourly run, Xray setup, drives everything
├── ProxyCollector/
│   ├── Collector/ProxyCollector.cs     # Core engine — fetch→parse→verify→rank
│   ├── Configuration/CollectorConfig.cs# Source list loading & normalization
│   ├── Services/IPToCountryResolver.cs# GeoIP + bounded DNS, shared cache
│   └── Models/                         # CityInfo, CountryInfo
├── state/
│   ├── history.json                    # Hashed cross-run streak tracking (~195K nodes)
│   └── verified_last.txt               # Last successful verified.txt set (empty-file fallback)
└── sub/
    ├── everything.txt                  # All surviving nodes — never split
    ├── top.txt                         # Top 1000 — Europe + IR + neighbors ONLY
    ├── verified.txt                    # Full Xray roundtrip — Europe + IR + neighbors ONLY
    ├── verified_tls.txt                # Azure TLS successes (CF-fronted excluded)
    ├── curated.txt                     # Iran-tested or stable+TLS-verified
    ├── stable.txt                      # 3+ consecutive hourly runs
    ├── ipv4_only.txt / ipv6_only.txt   # By resolved IP family
    ├── protocols/                      # Per-protocol .txt, chunked at 1000
    │   ├── vless.txt                   # ← first 1000 vless nodes
    │   ├── vless_part2.txt            # ← overflow
    │   ├── wireguard.txt              # ← Clash YAML config (NekoBox-importable!)
    │   └── ...
    ├── wireguard/                      # Individual .conf files (WireGuard app)
    │   ├── 001 Cloudflare 162.159.192.0.conf
    │   └── ...
    ├── countries/                       # Per-country .txt, same chunking
    └── continents/                     # Per-continent .txt, same chunking
```

---

## ⚠️ Honest Notes

**Filtered on affirmative death only:** NXDOMAIN, TCP-refused, bad resolved-IPs, alias duplicates. A node that merely times out from GitHub is kept — it may work fine from your location.

**Location labels come from resolved IPs**, not source remarks: free-proxy channels routinely label dead US servers "🇩🇪 Germany". FastNodes shows the physical location of the IP you connect to. CF-fronted nodes will show the edge's country, not the backend's.

**This project does not:**
- Host or operate any proxy servers
- Guarantee any node is online or reachable
- Guarantee any node works in your specific location or ISP
- Collect any user data whatsoever

All configs are sourced from publicly available GitHub repositories, Telegram channels, and public subscription sites. Credit goes to all the original collectors and server operators.

---

## 🙏 Sources

FastNodes aggregates from **642 public sources** (GitHub repositories, Telegram channels, and standalone sites). Major contributors include: AvenCores, morpheusadam, MatinGhanbari, barry-far, Epodonios, Surfboardv2ray, 10ium, NiREvil, F0rc3Run, mahdibland, 4n0nymou3, sakha1370, wuqb2i4f, V2RayRoot, sevcator, igareck, youfoundamin, HosseinKoofi, Argh94, Mahdi0024, liketolivefree, AzadNetCH, Leon406, roosterkid, ebrasha, Danialsamadi, LalatinaHub, Farid-Karimi, 0xRadikal, Diversan313, Au1rxx, MustafaBaqer, MahanKenway, SoliSpirit, Delta-Kronecker, and many others.

---

<div align="center">

**If FastNodes helps you, a ⭐ means a lot**

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:24243e,50:302b63,100:0f0c29&height=120&section=footer" width="100%"/>

*Auto-updated every hour · Built with C# .NET 9 · Powered by GitHub Actions & Cloudflare Workers*
