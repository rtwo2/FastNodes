<img src="https://capsule-render.vercel.app/api?type=waving&color=0:0f0c29,50:302b63,100:24243e&height=200&section=header&text=FastNodes&fontSize=80&fontColor=ffffff&fontAlignY=38&desc=The%20World%27s%20Smartest%20Free%20V2Ray%20Collector&descAlignY=58&descSize=18" width="100%"/>

<br/>

[![وضعیت به‌روزرسانی](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml/badge.svg)](https://github.com/rtwo2/FastNodes/actions/workflows/collect.yml)
![Protocol](https://img.shields.io/badge/Protocols-VLESS%20%7C%20VMess%20%7C%20Trojan%20%7C%20SS%20%7C%20Hy2%20%7C%20WG-blueviolet?style=flat-square)
![Update](https://img.shields.io/badge/Auto%20Update-Hourly-brightgreen?style=flat-square)
![Sources](https://img.shields.io/badge/Sources-750+%20(GitHub%20%2B%20Telegram%20%2B%20Web)-blue?style=flat-square)
![Xray](https://img.shields.io/badge/Deep%20Check-Xray%20Core%20Roundtrip-success?style=flat-square)
![CF Edge](https://img.shields.io/badge/Edge%20Verify-Cloudflare%20Worker-orange?style=flat-square)
![Region](https://img.shields.io/badge/Top%20%26%20Verified-Europe%20%2B%20Iran%20%2B%20Neighbors-9cf?style=flat-square)
![Version](https://img.shields.io/badge/Version-v6.20-purple?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-orange?style=flat-square)
![ساخته‌شده با](https://img.shields.io/badge/Built%20with-C%23%20.NET%209-purple?style=flat-square)

<br/>

**جمع‌آوری · فیلترکردن · حذف موارد تکراری · بررسی عمیق · رتبه‌بندی · انتشار**
*کاملاً خودکار؛ بدون تبلیغات، بدون نیاز به ورود، بدون دردسر.*

<br/>

[🚀 شروع سریع](#-quick-start) · [📊 نمای زنده](#-live-snapshot) · [🏆 سطوح کیفیت](#-quality-tiers) · [🌍 سیاست منطقه‌ای](#-region-policy--multi-signal-ranking) · [📁 همهٔ لینک‌های اشتراک](#-subscription-links) · [⚙️ نحوهٔ کار](#️-how-it-works) · [📱 Clients](#-compatible-clients)

---

## ✨ FastNodes چیست؟

FastNodes یک گردآورندهٔ کاملاً خودکار پروکسی‌های V2Ray/Xray است که نودها را از چند مسیر مختلف بررسی می‌کند. این ابزار هر ساعت کانفیگ‌ها را از **بیش از ۷۵۰ منبع** شامل مخزن‌های عمومی GitHub، کانال‌های تلگرام و وب‌سایت‌های مستقل دریافت می‌کند. کار آن فقط فهرست‌کردن نیست؛ کانفیگ‌ها از چندین مرحلهٔ فیلتر عبور می‌کنند، موارد تکراری بر اساس هویت کامل کانفیگ حذف می‌شوند و **زنده‌بودن نودها به‌صورت عمیق** با Xray-core، ‏Cloudflare Workers و بررسی‌های TLS در Azure سنجیده می‌شود.

**فایل‌های اصلی برای استفادهٔ عملی بهینه شده‌اند:** فایل‌های `top.txt` و `verified.txt` **فقط نودهای اروپا، ایران و کشورهای همسایهٔ ایران** را شامل می‌شوند؛ مناطقی که طبق تجربه عملکرد بهتری دارند. تمام نودهای دیگر همچنان در فایل‌های سراسری در دسترس‌اند.

---

## 📊 نمای زنده

آمار آخرین اجرای کامل (به‌روزرسانی ساعتی؛ این اعداد معمول‌اند و تضمین‌شده نیستند):

### هرم اعتماد

```text
750+ sources ──► 1,817,641 raw lines ──► 239,689 unique configs
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

### توزیع پروتکل‌ها (حدود ۱۹۲ هزار نود)

```text
vless       ████████████████████████████████████████  145,240  (75.5%)
trojan      █████                                       18,168  ( 9.4%)
vmess       ████                                        13,442  ( 7.0%)
ss          ███                                          10,460  ( 5.4%)
hysteria2   █                                             3,879  ( 2.0%)
wireguard   ▏                                              626  ( 0.3%)
ssr/tuic/socks/anytls/hysteria/socks5                              598  ( 0.3%)
```

### توزیع جغرافیایی (حدود ۱۹۲ هزار نود)

```text
Europe        ████████████████████████████████████████   75,684  (39.3%)
North America █████████████████                           31,067  (16.1%)
Asia          █████████████                               26,098  (13.6%)
Africa        ██                                            2,922  ( 1.5%)
Oceania       ▏                                               942  ( 0.5%)
South America ▏                                               777  ( 0.4%)
```

### آمار اجرا

| شاخص | مقدار |
|--------|-------|
| Total runtime | ~21 minutes (of a 50-minute budget) |
| Raw lines parsed per run | ~1.82 million |
| Nodes dropped as provably dead | ~47,000 (NXDOMAIN + TCP-RST + bogons) |
| Xray deep check | 734/2,682 roundtrips completed in 161s — 0 skipped by budget |
| Sources healthy / dead | 629 / 13 |
| History tracked (cross-run) | ~195,000 nodes |
| Nodes marked stable (3+ runs) | ~189,700 |

---

## 🚀 شروع سریع

سریع‌ترین راه برای دریافت پروکسی‌ها: لینک موردنظر را کپی کنید و در کلاینت خود (مانند Hiddify، ‏v2rayNG یا NekoBox) وارد کنید:

| What | Link |
|------|------|
| **🏆 Top 1000 Ranked** | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/top.txt` |
| **🛰️ Xray Verified (Europe + IR region)** | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/verified.txt` |
| **🌍 Everything (all regions)** | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.txt` |
| **🔒 WireGuard (NekoBox)** | `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/wireguard.txt` |

> **`top.txt` and `verified.txt` contain only Europe + Iran + Iran-neighbor nodes** (🇪🇺🇮🇷🇹🇷🇦🇪 and neighbors). This matches empirical performance: European and Iranian-region servers connect reliably; US/Asia/CF-fronted free nodes rarely do. All other regions remain fully available in the global files below.

---

## 🏆 سطوح کیفیت

| فایل | اندازهٔ معمول | توضیحات |
|------|--------------|------------|
| `sub/top.txt` | 1,000 | **فایل دقیق و گزینش‌شده.** Europe + IR + neighbors only, ranked by composite score (observed range 117–187). Gate: at least one affirmative current signal. |
| `sub/verified.txt` | ~730 | **قوی‌ترین نشانهٔ زنده‌بودن.** Europe + IR + neighbor nodes that proxied a real HTTP `generate_204` request end-to-end through `xray-core` this run. The entire roundtrip budget is spent exclusively on these regions. Never ships empty — falls back to the last successful set if the check stage ever fails. |
| `sub/verified_tls.txt` | ~34,000 | نودهایی که از یک نقطهٔ بررسی مستقل، با SNI واقعی خود دست‌دهی TLS موفقی داشته‌اند. **CF-fronted hosts are excluded** (~32K per run) — an edge handshake terminates at Cloudflare and proves nothing about the backend behind it. |
| `sub/curated.txt` | ~45,000 | نودهای منابعی که صراحتاً داخل ایران آزمایش شده‌اند، به‌علاوهٔ نودهایی که هم پایدارند و هم تأیید TLS شده‌اند. |
| `sub/stable.txt` | ~190,000 | نودهایی که در دست‌کم سه اجرای ساعتی پیاپی حذف نشده‌اند. |
| `sub/everything.txt` | ~192,000 | فهرست کامل و بدون محدودیت همهٔ نودهای باقی‌مانده از تمام مناطق؛ هرگز به چند فایل تقسیم نمی‌شود. |
| `sub/protocols/wireguard.txt` | ~40 | WireGuard nodes as **Clash YAML** — keys strictly validated (32-byte, base64-normalized), **NekoBox imports this directly**. |
| `sub/wireguard/*.conf` | ~40 files | فایل‌های `.conf` پاک‌سازی‌شده به‌صورت جداگانه؛ **اپلیکیشن WireGuard می‌تواند آن‌ها را مستقیماً وارد کند**. |

---

## 🌍 سیاست منطقه‌ای & Multi-Signal Ranking

**یک قانون ساده:** `top.txt` and `verified.txt` admit **only Europe, Iran, and Iran-neighbor countries** (TR, AE, IQ, AM, AZ, TM, AF, PK, QA, KW, BH, OM, SA, GE, KZ). Every other output file remains global.

The Xray roundtrip budget and the Cloudflare Edge budget are spent **exclusively** on preferred-region nodes — a verified US or Asian node would earn points it can never spend, so the budget goes where it pays. Within the region, nodes are ordered by a composite score:

| سیگنال | امتیاز | چه چیزی را نشان می‌دهد |
|--------|--------|----------------|
| Xray roundtrip | +35 | A real HTTP request was proxied **through** this node, end-to-end |
| Iran-tested source | +30 | Delegated validation: a maintainer tested this node from inside Iran |
| CF Edge verified | +20 | Alive from a **second** vantage class (Cloudflare edge) |
| TLS verified | +20 | Completed a TLS handshake with the node's real SNI |
| Region weight | up to +27 | Europe-first ordering within the allowed set |
| Presence streak | up to +20 | Survived N consecutive hourly runs of all drop filters |
| Xray streak | up to +15 | Roundtrip-verified N runs in a row |
| Multi-source | up to +10 | Published by 2+ independent sources (ecosystem consensus) |

### سه مسیر بررسی و تأیید

| | Azure TLS probe | 🛰️ Xray deep check | 🌐 CF Edge Worker |
|---|---|---|---|
| **Depth** | TLS handshake only | Full proxy roundtrip (real traffic) | TCP + TLS handshake |
| **Region focus** | Global | **Europe + IR + neighbors only** | **Europe + IR + neighbors only** |
| **CF-fronted nodes** | **Skipped — edge handshakes prove nothing** | ✅ Only valid judge of CF nodes | Skipped (platform restriction) |
| **Drops on fail?** | Never | Never | Never |

> **چرا میزبان‌های پشت Cloudflare در بررسی TLS کنار گذاشته می‌شوند؟** دست‌دهی TLS با سرور لبهٔ Cloudflare ممکن است **حتی وقتی پروکسی پشت آن از کار افتاده موفق شود**؛ چون ارتباط TLS در همان سرور لبه پایان می‌یابد و به سرور اصلی نمی‌رسد. این نشانهٔ گمراه‌کنندهٔ «۲۰ امتیاز تأیید» باعث می‌شد `top.txt` پر از نودهای Cloudflare شود که عملاً کار نمی‌کردند. از این پس، نودهای Cloudflare فقط با یک رفت‌وبرگشت واقعی از طریق Xray می‌توانند زنده‌بودن خود را ثابت کنند.

> **چرا فایل verified.txt هیچ‌وقت خالی نمی‌ماند؟** اگر مرحلهٔ Xray اجرا نشود یا با خطا مواجه شود (خرابی مرحله یا مشکل فایل اجرایی)، آخرین مجموعهٔ موفق از `state/verified_last.txt` منتشر می‌شود تا اشتراک خالی نباشد. برای اشتراکی که باید قابل استفاده بماند، دادهٔ قدیمی بهتر از فایل خالی است.

---

## 📁 لینک‌های اشتراک

تمام خروجی‌ها فهرست خام URI با پسوند `.txt` هستند؛ هر خط یک کانفیگ دارد و با کلاینت‌های V2Ray/Xray سازگار است. برای پایداری، فایل‌های خروجی بر اساس میزبان و سپس پروتکل مرتب می‌شوند.

### 📦 فهرست‌های بزرگ به چند بخش تقسیم می‌شوند
`everything.txt` and the quality tiers are never split. Every other category (protocols, countries, continents) caps at 1000 lines per file. The first 1000 always stay in `xx.txt` — that link never changes — and everything beyond that spills into `xx_part2.txt`, `xx_part3.txt`, etc.

```text
sub/protocols/vless.txt          ← first 1000
sub/protocols/vless_part2.txt    ← next 1000
```

### 🔢 بر اساس خانوادهٔ IP

نودها بر اساس **خانوادهٔ IP به‌دست‌آمده از DNS** دسته‌بندی می‌شوند؛ نودهایی که نام میزبان دارند نیز بر اساس نتیجهٔ جست‌وجوی DNS طبقه‌بندی می‌شوند.

| URL |
|-----|
| `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/ipv4_only.txt` |
| `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/ipv6_only.txt` |

### 🔧 بر اساس پروتکل

Base path: `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/`

Recognized protocols: `vmess, vless, trojan, ss, ssr, hysteria, hysteria2 (+ hy2 alias), tuic, wireguard, socks, socks5`. Each gets its own file if at least one alive node uses it:

| پروتکل | تعداد نودها | فایل |
|----------|-------|------|
| 🔵 VLESS | ~145K | [vless.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vless.txt) |
| 🟣 Trojan | ~18K | [trojan.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/trojan.txt) |
| 🟠 VMess | ~13K | [vmess.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vmess.txt) |
| ⚫ Shadowsocks | ~10K | [ss.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/ss.txt) |
| ⚡ Hysteria2 | ~4K | [hysteria2.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/hysteria2.txt) |
| 🔒 WireGuard | ~40 | [wireguard.txt](https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/wireguard.txt) — Clash YAML for NekoBox |

> **کاربران WireGuard:** The `wireguard.txt` file is a Clash YAML config (NekoBox imports it directly). Individual `.conf` files for the official WireGuard app are in the `sub/wireguard/` directory. All keys are strictly validated — nodes with malformed keys are dropped rather than crashing your client.

### 🌍 بر اساس قاره و کشور

Base paths:
- `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/continents/`
- `https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/`

**کشورهای پرکاربرد:**

| | کشور | تعداد نودها | فایل |
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

## 📱 کلاینت‌های سازگار

تمام فایل‌های خروجی فهرست خام URI هستند و تقریباً با همهٔ کلاینت‌های V2Ray/Xray سازگاری دارند:

| کلاینت | پلتفرم | روش واردکردن |
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

> **فهرست‌های خام URI تقریباً همه‌جا کار می‌کنند و سریع‌تر بارگذاری می‌شوند.** For WireGuard, a Clash YAML config is provided specifically for NekoBox compatibility.

---

## ⚙️ نحوهٔ کار

FastNodes هر ساعت یک فرایند پنج‌مرحله‌ای اجرا می‌کند که چند لایهٔ بررسی مقاوم در برابر خطا دارد. اگر سرویس شخص ثالثی از کار بیفتد، طراحی مراحل به‌گونه‌ای است که کل فرایند متوقف نشود.

```text
750+ Sources (GitHub · Telegram · web, fetched in parallel)
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
   ├─ 🛰️ Xray بررسی عمیق — REAL proxy roundtrip via xray-core, candidates drawn
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

## 🧠 حذف هوشمند موارد تکراری

بیشتر گردآورنده‌ها فقط بر اساس `host:port` موارد تکراری را حذف می‌کنند و ممکن است کانفیگ‌هایی با UUID متفاوت روی یک سرور را ناخواسته کنار بگذارند. FastNodes از **هویت کامل کانفیگ** برای حذف موارد تکراری استفاده می‌کند:

```text
protocol + host + port + credential + transport + security + SNI
         + path + REALITY pbk/sid + flow + obfs-password
```

اگر یک سرور چند کانفیگ VLESS داشته باشد (که در تنظیمات Xray رایج است)، همهٔ آن‌ها حفظ می‌شوند. علاوه بر کلید هویت، مرحله‌ای برای ادغام نام‌های مستعار، هر نود را بر اساس **IP resolve‌شده** بررسی و موارد همسان را ادغام می‌کند؛ برای مثال، `vless://uuid@1.2.3.4:443` و `vless://uuid@server.com:443` به‌عنوان یک نود منتشر می‌شوند و شکل دارای نام میزبان حفظ می‌شود تا با تغییر IP نیز قابل استفاده باشد.

---

## 🏷️ نحوهٔ نام‌گذاری نودها

نام توضیحی هر نود از **اطلاعات جغرافیایی + نشانی سرور** تشکیل می‌شود. اگر چند نود روی یک سرور باشند، شمارهٔ پورت به نامشان افزوده می‌شود تا بتوان آن‌ها را از هم تشخیص داد:

```text
🇩🇪 Frankfurt, DE · Hetzner | example.com          ← only node on this server
🇩🇪 Frankfurt, DE · Hetzner | example.com :8443    ← 2nd node, port 8443
🇩🇪 Frankfurt, DE · Hetzner | example.com :8443·vless  ← same port, different protocol
```

پسوند نام‌ها **در اجراهای مختلف ثابت می‌ماند**؛ فهرست ورودی پیش از نام‌گذاری بر اساس میزبان، پورت و پروتکل مرتب می‌شود تا ترکیب یکسان سرور و پورت همیشه پسوند یکسانی بگیرد.

---

## 📂 ساختار مخزن

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

## ⚠️ نکات شفاف

**نودها فقط با نشانه‌های قطعی ازکارافتادگی حذف می‌شوند:** NXDOMAIN، ردشدن اتصال TCP، IPهای نامعتبر و نام‌های مستعار تکراری. نودی که صرفاً از سمت GitHub تایم‌اوت می‌شود حفظ خواهد شد؛ چون ممکن است از موقعیت شما به‌خوبی کار کند.

**برچسب موقعیت جغرافیایی از IP به‌دست‌آمده تعیین می‌شود**، نه از توضیحات منبع؛ کانال‌های پروکسی رایگان گاهی سرورهای ازکارافتادهٔ آمریکا را «🇩🇪 آلمان» معرفی می‌کنند. FastNodes موقعیت IPای را نشان می‌دهد که به آن وصل می‌شوید. برای نودهای پشت Cloudflare، کشور سرور لبه نمایش داده می‌شود، نه کشور سرور اصلی.

**این پروژه:**
- هیچ سرور پروکسی‌ای را میزبانی یا اداره نمی‌کند
- آنلاین یا در دسترس بودن هیچ نودی را تضمین نمی‌کند
- کارکردن نودها را در موقعیت جغرافیایی یا اینترنت‌دهندهٔ مشخص شما تضمین نمی‌کند
- هیچ‌گونه اطلاعاتی از کاربران جمع‌آوری نمی‌کند

تمام کانفیگ‌ها از مخزن‌های عمومی GitHub، کانال‌های تلگرام و وب‌سایت‌های عمومی اشتراک جمع‌آوری می‌شوند. اعتبار این کار متعلق به گردآورندگان اولیه و گردانندگان سرورهاست.

---

## 🙏 منابع

FastNodes aggregates from **750+ public sources** (GitHub repositories, Telegram channels, and standalone sites). Major contributors include: AvenCores, morpheusadam, MatinGhanbari, barry-far, Epodonios, Surfboardv2ray, 10ium, NiREvil, F0rc3Run, mahdibland, 4n0nymou3, sakha1370, wuqb2i4f, V2RayRoot, sevcator, igareck, youfoundamin, HosseinKoofi, Argh94, Mahdi0024, liketolivefree, AzadNetCH, Leon406, roosterkid, ebrasha, Danialsamadi, LalatinaHub, Farid-Karimi, 0xRadikal, Diversan313, Au1rxx, MustafaBaqer, MahanKenway, SoliSpirit, Delta-Kronecker, and many others.

---

<div align="center">

**اگر FastNodes برایتان مفید است، گذاشتن یک ⭐ برای ما ارزش زیادی دارد**

<img src="https://capsule-render.vercel.app/api?type=waving&color=0:24243e,50:302b63,100:0f0c29&height=120&section=footer" width="100%"/>

*به‌روزرسانی خودکار هر ساعت · ساخته‌شده با C# .NET 9 · اجراشده با GitHub Actions و Cloudflare Workers*
