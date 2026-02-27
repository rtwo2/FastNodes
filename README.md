# FastNodes – Automatic Free V2Ray / Xray Proxy Collector & Tester

**FastNodes** is an automated GitHub Actions-based pipeline that:

- Collects thousands of free V2Ray / Xray / VMess / VLESS / Trojan / Shadowsocks configurations from public sources
- Removes duplicates, filters out blacklisted IPs, adds country flags & clean names
- Tests proxy latency (Cloudflare 1.1.1.1 reachability)
- Generates ranked **top 100 → top 500** fastest proxies
- Saves results in multiple formats: plain text, Clash Meta / Sing-box compatible JSON
- Automatically commits & pushes fresh lists every 6 hours

→ https://github.com/rtwo2/FastNodes

## Features

- **30+ high-quality public sources** (AvenCores, Proxify, MatinGhanbari, roosterkid, Epodonios, barry-far, …)
- Strict deduplication (by protocol + IP:port + normalized remark)
- IP blacklist filtering (FireHOL Level 2 – ~19k lines → ~450–500 real CIDRs)
- Country detection & emoji flags (MaxMind GeoLite2)
- Real latency testing (parallel, 20 threads, 5s timeout)
- Clean protocol folders: `vless.txt`, `vmess.txt`, `trojan.txt`, `ss.txt`, …
- Country folders: `US.txt`, `RU.txt`, `DE.txt`, …
- Ranked best proxies: `sub/Best-Results/top{100,200,300,400,500}.{txt,json}`
- Clash Meta / Sing-box ready JSON configs with auto group (`url-test`)
- Fully automatic – runs every 6 hours via GitHub Actions

## Folder Structure
FastNodes/
├── ProxyCollector/                 # .NET 9 source code
│   ├── Country.mmdb                # GeoLite2 country database
│   └── blacklist.netset            # FireHOL Level 2 IP blacklist
├── sub/
│   ├── everything.txt              # all working proxies (~20–30k lines)
│   ├── everything.json             # Clash / Sing-box compatible
│   ├── protocols/
│   │   ├── vless.txt
│   │   ├── vmess.txt
│   │   ├── trojan.txt
│   │   ├── ss.txt
│   │   └── …
│   ├── countries/
│   │   ├── US.txt
│   │   ├── RU.txt
│   │   ├── IR.txt
│   │   └── …
│   ├── temp/
│   │   └── temp_everything.txt     # raw collected lines before filtering
│   └── Best-Results/
│       ├── top100.txt / .json
│       ├── top200.txt / .json
│       ├── top300.txt / .json
│       ├── top400.txt / .json
│       └── top500.txt / .json      # fastest proxies (real latency tested)
└── .github/workflows/
└── collector-main.yml          # the automation pipeline


## How to Use

### Option 1 – Subscribe directly (easiest)

Copy one of these links and import it into your client (v2rayNG, Nekobox, Hiddify, Clash Meta, etc.):

**All proxies** (~20–30k)  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.txt

**Fastest 500** (recommended)  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/Best-Results/top500.txt

**Fastest 100** (very low ping)  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/Best-Results/top100.txt

**Clash Meta / Sing-box JSON** (auto url-test group)  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/Best-Results/top500.json

### Option 2 – Self-host or fork

1. Fork this repository
2. Go to **Settings → Actions → General → Workflow permissions** → choose **Read and write permissions**
3. The workflow will run automatically every 6 hours
4. Your own fresh lists will appear in your fork

## Technical Stack

- **Language**: C# / .NET 9
- **Runner**: ubuntu-latest (GitHub Actions)
- **Proxy testing**: HTTP HEAD to `http://cp.cloudflare.com/generate_204` (real connectivity + latency)
- **GeoIP**: MaxMind GeoLite2 Country.mmdb (updated on every run)
- **Blacklist**: FireHOL Level 2 (~450–500 active CIDRs after parsing)
- **Parallelism**: 20 concurrent latency tests
- **Output formats**: plain base64/text + Clash Meta / Sing-box JSON

## How to Contribute

- Found a good public source? → open issue or PR with the link
- Want better latency testing (sing-box real dial)? → discuss in issues
- Want base64 subscription files for top100/top500? → open feature request

## License

MIT License – feel free to fork, modify, self-host.

Made with ❤️ for the open proxy community.

Last auto-update: <!-- GitHub will show commit date automatically -->




# FastNodes – جمع‌آوری و تست خودکار کانفیگ‌های رایگان V2Ray / Xray

**FastNodes** یک پروژه کاملاً خودکار بر پایه GitHub Actions است که:

- روزانه هزاران کانفیگ رایگان V2Ray / Xray / VMess / VLESS / Trojan / Shadowsocks را از منابع عمومی جمع‌آوری می‌کند
- تکراری‌ها را حذف می‌کند، آی‌پی‌های سیاه‌لیست را فیلتر می‌کند، نام‌های تمیز + پرچم کشور اضافه می‌کند
- پینگ واقعی (latency) تا Cloudflare را تست می‌کند
- ۱۰۰ تا ۵۰۰ تا از سریع‌ترین پروکسی‌ها را رتبه‌بندی می‌کند
- خروجی را در فرمت‌های متنی و JSON سازگار با Clash Meta / Sing-box ذخیره می‌کند
- هر ۶ ساعت به‌صورت خودکار آپدیت و کامیت می‌کند

→ https://github.com/rtwo2/FastNodes

## امکانات

- **بیش از ۳۰ منبع معتبر** (AvenCores، Proxify، MatinGhanbari، roosterkid و …)
- حذف دقیق تکراری‌ها (بر اساس پروتکل + آی‌پی:پورت + ریمارک نرمال‌شده)
- فیلتر آی‌پی‌های خطرناک (FireHOL Level 2 – حدود ۴۵۰–۵۰۰ بلاک واقعی)
- تشخیص کشور و اضافه کردن ایموجی پرچم (با GeoLite2)
- تست پینگ واقعی (۲۰ تست همزمان، تایم‌اوت ۵ ثانیه)
- پوشه‌های مرتب پروتکل: `vless.txt`، `vmess.txt`، `trojan.txt`، `ss.txt` و …
- پوشه‌های کشورها: `US.txt`، `RU.txt`، `IR.txt` و …
- سریع‌ترین‌ها: `sub/Best-Results/top{100,200,300,400,500}.{txt,json}`
- خروجی JSON آماده برای Clash Meta و Sing-box (با گروه url-test خودکار)


## نحوه استفاده

### ساده‌ترین روش – سابسکریب مستقیم

لینک زیر را کپی کنید و در کلاینت خود (v2rayNG، Nekobox، Hiddify، Clash Meta و …) اضافه کنید:

**همه کانفیگ‌ها** (~۲۰–۳۰ هزار)  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.txt

**۵۰۰ تا سریع‌ترین** (پیشنهادی)  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/Best-Results/top500.txt

**۱۰۰ تا سریع‌ترین** (پینگ خیلی پایین)  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/Best-Results/top100.txt

**JSON آماده Clash Meta / Sing-box**  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/Best-Results/top500.json

### روش پیشرفته – فورک و خودمیزبانی

1. این ریپازیتوری را فورک کنید
2. به **Settings → Actions → General → Workflow permissions** بروید  
   گزینه **Read and write permissions** را فعال کنید
3. workflow هر ۶ ساعت خودکار اجرا می‌شود
4. لیست‌های تازه در فورک شما ظاهر می‌شوند

## تکنولوژی استفاده شده

- زبان: **C# / .NET 9**
- اجرا: **ubuntu-latest** در GitHub Actions
- تست پینگ: درخواست HTTP به `http://cp.cloudflare.com/generate_204`
- GeoIP: **MaxMind GeoLite2** (هر بار آپدیت می‌شود)
- بلک‌لیست: **FireHOL Level 2** (~۴۵۰–۵۰۰ بلاک فعال)
- موازی‌سازی: ۲۰ تست همزمان
- خروجی: متن ساده + JSON سازگار با Clash Meta و Sing-box

## مشارکت

- منبع خوب پیدا کردید؟ → issue باز کنید یا PR بزنید
- می‌خواهید تست پینگ دقیق‌تر (با sing-box واقعی) باشد؟ → در issues بحث کنید
- خروجی base64 برای top100/top500 می‌خواهید؟ → درخواست بدهید

## لایسنس

MIT License – آزاد برای فورک، تغییر و میزبانی شخصی.

با عشق برای جامعه پروکسی‌های آزاد ساخته شده است.  
آخرین آپدیت خودکار: <!-- تاریخ کامیت به صورت خودکار نمایش داده می‌شود -->
