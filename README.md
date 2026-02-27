# FastNodes – Free & Fast Proxy Subscription Collector

**Last updated:** February 27, 2026  
**Total unique proxies:** ~21,700–22,000 (after deduplication & cleaning)  
**Main protocols:** VLESS (~68%), Shadowsocks, Trojan, Hysteria2 (~200+ configs), VMess  
**Update frequency:** Every 30 minutes (GitHub Actions)

This repository automatically collects, parses, deduplicates, tests latency, filters out dead/blacklisted proxies, and generates clean subscription links in multiple formats.

### Why use these subscriptions?

- Very large pool (hundreds of sources aggregated daily)
- Strict deduplication + invalid removal
- Latency-tested & sorted (top 500 fastest proxies saved separately)
- GeoIP country splitting (`sub/countries/`)
- Protocol splitting (`sub/protocols/`)
- Hysteria2 improved significantly (200+ configs)
- Clean base64 & plain text formats
- No ads, no trackers, no telemetry

### Subscription Links (copy-paste ready)

**Full mixed subscription (recommended – all protocols)**  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.txt  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything_base64.txt (base64 version)

**Top 500 fastest proxies (very low latency – best for daily use)**  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/Best-Results/top500.txt  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/Best-Results/top500_base64.txt

**Top 300 / 200 / 100 (smaller & faster subsets)**  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/Best-Results/top300.txt  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/Best-Results/top200.txt  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/Best-Results/top100.txt

**Protocol-specific subscriptions**  
VLESS only: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vless.txt  
Shadowsocks only: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/ss.txt  
Trojan only: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/trojan.txt  
Hysteria2 only: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/hysteria2.txt  
VMess only: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vmess.txt

**Country-specific subscriptions** (examples – more in /sub/countries/)  
United States: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/US.txt  
Germany: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/DE.txt  
Netherlands: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/NL.txt  
United Kingdom: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/GB.txt  
Russia: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/RU.txt  
Iran (local): https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/IR.txt

### How to use

1. Copy any link above
2. Paste into your client:
   - Clash / Clash Meta / Clash Verge → use as Clash subscription URL
   - v2rayNG / v2rayN → import from clipboard or URL
   - Hiddify / Sing-box / Nekobox → add as subscription
   - Shadowrocket / Shadowrocket-like → base64 links work best

### Recommended clients (2026)

- **Clash family**: Clash Verge Rev, Clash Meta for Android, FlClash
- **Sing-box based**: Hiddify Next, SFA, NekoBox for Android
- **iOS**: Shadowrocket, Stash, Shadowrocket-alike apps
- **Windows/macOS**: v2rayN, Nekoray, Clash Verge Rev

### Notes

- Proxies are tested with real connectivity checks (sing-box core)
- Blacklisted IPs (FireHOL Level 2 + bogons) are removed
- Very long filenames / invalid formats are filtered
- Hysteria2 configs are prioritized and growing
- If a link stops working → wait 30 min or check next commit

Star ⭐ the repo if it helps you!

Questions / suggestions? Open an issue.
