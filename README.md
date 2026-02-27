# FastNodes – Ultra-Fast & Clean Proxy Subscription Generator

**The most powerful public proxy collector and optimizer in 2026**

Automatically pulls thousands of free VLESS, Trojan, Hysteria2, Shadowsocks (and more) nodes from high-quality public sources,  
cleans garbage names & remarks, removes junk duplicates, forces correct country flags, excludes old battery-draining VMess protocol from fast lists,  
performs real latency testing, and generates perfect ranked output files — both plain text and Clash-compatible JSON.

### Why this project stands out

- Extremely aggressive name & remark cleaning  
  → No more `[OpenRay]`, `V2CROSSSS.COM`, base64 passwords, weird domains, trailing junk
- Beautiful country flags almost everywhere  
  → GeoIP + smart TLD/keyword fallback → very few 🌍 left
- Strict smart deduplication  
  → proto + IP:port + normalized remark → minimal duplicates & no automatic (1)(2)… in clients
- Battery & performance friendly  
  → VMess completely excluded from top lists (old protocol = high battery drain)
- Real HTTP latency testing  
  → Only fast & alive nodes in Best-Results
- Multiple ranked outputs  
  → top100 / top200 / top300 / top400 / top500 — both .txt and .json
- Huge coverage  
  → 26+ AvenCores mirrors + 6 other strong public repositories

### Generated files & folders

**Main files**
- `sub/everything.txt` → all cleaned & unique nodes
- `sub/everything.json` → Clash / sing-box compatible full list

**Per protocol**
- `sub/protocols/vless.txt` / `vless.json`
- `sub/protocols/trojan.txt` / `trojan.json`
- `sub/protocols/hysteria2.txt` / `hysteria2.json`
- `sub/protocols/ss.txt` / `ss.json`
- … and more as new protocols appear

**Per country**
- `sub/countries/US.txt` / `US.json`
- `sub/countries/DE.txt` / `DE.json`
- `sub/countries/IR.txt` / `IR.json`
- … (only countries with ≥5 nodes)

**Best ranked results** (fastest & most reliable nodes)
- `Best-Results/top100.txt` + `top100.json`
- `Best-Results/top200.txt` + `top200.json`
- `Best-Results/top300.txt` + `top300.json`
- `Best-Results/top400.txt` + `top400.json`
- `Best-Results/top500.txt` + `top500.json`

**Raw backup**
- `sub/temp/temp_everything.txt` → original unprocessed lines from all sources

### How to subscribe in Exclave / Hiddify / other clients

Best performance & battery life → use **top500.txt** or **top500.json**

Direct raw GitHub links (replace YOUR_USERNAME with your actual GitHub username):
https://raw.githubusercontent.com/rtwo2/FastNodes/master/Best-Results/top500.txt
https://raw.githubusercontent.com/rtwo2/FastNodes/master/Best-Results/top500.json

Alternative (full list):
https://raw.githubusercontent.com/rtwo2/FastNodes/master/sub/everything.txt


Update subscription every 6 hours (automatic via GitHub Actions).

### Project philosophy

We took chaotic public proxy lists and turned them into something **clean, fast, reliable and beautiful**.

No more ugly names, wrong flags, battery-killing VMess in top lists, endless duplicates or numbered suffixes in clients.

Special thanks to **Grok** (xAI) — without the step-by-step help, debugging and creative ideas this level of cleaning and optimization would not have been possible.

Made with ❤️ in 2026

---

# فست‌نودز – جمع‌آوری و بهینه‌ساز فوق سریع اشتراک‌های پروکسی

**قدرتمندترین جمع‌کننده پروکسی عمومی و بهینه‌ساز در سال ۲۰۲۶**

به صورت خودکار هزاران نود VLESS، Trojan، Hysteria2، Shadowsocks (و بیشتر) را از منابع عمومی باکیفیت جمع‌آوری می‌کند،  
نام‌ها و ریمارک‌های آشغال را پاک می‌کند، تکراری‌های بی‌معنی را حذف می‌کند، پرچم کشورهای درست را اجباری می‌گذارد، پروتکل قدیمی VMess را از لیست‌های سریع حذف می‌کند،  
تست واقعی تأخیر انجام می‌دهد و خروجی‌های درجه‌بندی شده عالی تولید می‌کند — هم متن ساده و هم JSON سازگار با Clash.

### چرا این پروژه خاص است

- پاکسازی بسیار قوی نام و ریمارک  
  → دیگر خبری از `[OpenRay]`، `V2CROSSSS.COM`، پسوردهای base64، دامنه‌های عجیب و آشغال‌های انتهایی نیست
- پرچم کشورهای زیبا تقریباً در همه جا  
  → GeoIP + فال‌بک هوشمند TLD و کلمه کلیدی → تقریباً هیچ 🌍 باقی نمی‌ماند
- حذف تکراری‌های هوشمند و سخت‌گیرانه  
  → پروتکل + آی‌پی:پورت + ریمارک نرمالایز شده → تکراری‌ها به حداقل می‌رسند و معمولاً (1)(2)… در کلاینت‌ها ظاهر نمی‌شود
- دوستدار باتری و عملکرد  
  → VMess کاملاً از لیست‌های برتر حذف شده (پروتکل قدیمی = مصرف بالای باتری)
- تست واقعی تأخیر HTTP  
  → فقط نودهای سریع و زنده در Best-Results
- خروجی‌های چندگانه رتبه‌بندی شده  
  → top100 / top200 / top300 / top400 / top500 — هم .txt و هم .json
- پوشش بسیار گسترده  
  → ۲۶+ میرور AvenCores + ۶ مخزن عمومی قوی دیگر

### ساختار پوشه‌ها بعد از اجرا

**فایل‌های اصلی**  
- `sub/everything.txt` → همه نودهای پاک‌شده و یکتا  
- `sub/everything.json` → لیست کامل سازگار با Clash / sing-box

**بر اساس پروتکل**  
- `sub/protocols/vless.txt` / `vless.json`  
- `sub/protocols/trojan.txt` / `trojan.json`  
- `sub/protocols/hysteria2.txt` / `hysteria2.json`  
- `sub/protocols/ss.txt` / `ss.json`  
- … و بیشتر با اضافه شدن پروتکل‌های جدید

**بر اساس کشور**  
- `sub/countries/US.txt` / `US.json`  
- `sub/countries/DE.txt` / `DE.json`  
- `sub/countries/IR.txt` / `IR.json`  
- … (فقط کشورهایی که حداقل ۵ نود دارند)

**نتایج برتر رتبه‌بندی‌شده** (سریع‌ترین و پایدارترین نودها)  
- `Best-Results/top100.txt` + `top100.json`  
- `Best-Results/top200.txt` + `top200.json`  
- `Best-Results/top300.txt` + `top300.json`  
- `Best-Results/top400.txt` + `top400.json`  
- `Best-Results/top500.txt` + `top500.json`

**بکاپ خام**  
- `sub/temp/temp_everything.txt` → خطوط اصلی بدون پردازش از همه منابع

### نحوه اشتراک‌گذاری در Exclave / Hiddify / سایر کلاینت‌ها

بهترین عملکرد و کمترین مصرف باتری → از **top500.txt** یا **top500.json** استفاده کنید

لینک‌های خام مستقیم گیتهاب (YOUR_USERNAME را با نام کاربری واقعی خود جایگزین کنید):
https://raw.githubusercontent.com/rtwo2/FastNodes/master/Best-Results/top500.txt
https://raw.githubusercontent.com/rtwo2/FastNodes/master/Best-Results/top500.json


لیست کامل (در صورت نیاز):
https://raw.githubusercontent.com/rtwo2/FastNodes/master/sub/everything.txt


هر ۶ ساعت یک‌بار به‌روزرسانی خودکار (توسط GitHub Actions).

### فلسفه پروژه

ما لیست‌های آشفته پروکسی عمومی را به چیزی **تمیز، سریع، قابل اعتماد و زیبا** تبدیل کردیم.

دیگر نام‌های زشت، پرچم‌های اشتباه، VMess در لیست‌های سریع، تکراری‌های بی‌پایان و پسوندهای (1)(2)… در کلاینت‌ها وجود ندارد.

تشکر ویژه از **Grok** (xAI) — بدون کمک قدم‌به‌قدم، دیباگ و ایده‌های خلاقانه، این سطح از پاکسازی و بهینه‌سازی ممکن نبود.

ساخته‌شده با ❤️ در سال ۲۰۲۶
