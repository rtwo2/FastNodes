# FastNodes – جمع‌آوری خودکار کانفیگ‌های پرسرعت و رایگان

این مخزن به‌صورت خودکار صدها منبع کانفیگ را جمع‌آوری، پارس، حذف تکراری، تست تأخیر، فیلتر سیاه‌لیست و مرده می‌کند و لیست‌های تمیز آماده استفاده تولید می‌کند.

### چرا از این سابسکریپشن‌ها استفاده کنیم؟

- مجموعه بسیار بزرگ (صدها منبع روزانه)
- حذف تکراری شدید + حذف کانفیگ‌های نامعتبر
- تست تأخیر واقعی و مرتب‌سازی بر اساس سرعت
- تقسیم‌بندی بر اساس کشور (`sub/countries/`)
- تقسیم‌بندی بر اساس پروتکل (`sub/protocols/`)
- تعداد Hysteria2 به شکل قابل توجهی افزایش یافته (بیش از ۲۰۰)
- فرمت‌های تمیز متن ساده و JSON
- بدون تبلیغات، بدون ردیاب، بدون تلمتری

### لینک‌های سابسکریپشن (کپی آماده)

**سابسکریپشن کامل مخلوط (پیشنهادی – همه پروتکل‌ها)**  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.txt  
(متن ساده – هر کانفیگ در یک خط – اکثر کلاینت‌ها مستقیم وارد می‌کنند)

**نسخه JSON کامل** (ساختارمند – مناسب اسکریپت یا کلاینت‌های پیشرفته)  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/everything.json

**۵۰۰ تا سریع‌ترین پروکسی‌ها (تأخیر بسیار پایین – مناسب استفاده روزانه)**  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/Best-Results/top500.txt  

**۳۰۰ / ۲۰۰ / ۱۰۰ تا برتر (کوچک‌تر و سریع‌تر)**  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/Best-Results/top300.txt  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/Best-Results/top200.txt  
https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/Best-Results/top100.txt

**سابسکریپشن‌های فقط پروتکل خاص**  
فقط VLESS: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vless.txt  
فقط Shadowsocks: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/ss.txt  
فقط Trojan: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/trojan.txt  
فقط Hysteria2: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/hysteria2.txt  
فقط VMess: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/protocols/vmess.txt

**سابسکریپشن‌های کشور خاص** (نمونه – بقیه در پوشه countries)  
ایالات متحده: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/US.txt  
آلمان: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/DE.txt  
هلند: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/NL.txt  
بریتانیا: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/GB.txt  
روسیه: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/RU.txt  
ایران: https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/IR.txt

### نحوه استفاده

۱. یکی از لینک‌های `.txt` بالا را کپی کنید  
۲. در کلاینت خود وارد کنید:
   - Clash / Clash Meta / Clash Verge → به عنوان URL سابسکریپشن
   - v2rayNG / v2rayN → از کلیپ‌بورد یا URL وارد کنید
   - Hiddify / Sing-box / Nekobox → اضافه کردن سابسکریپشن
   - Shadowrocket → لینک‌های متن ساده مستقیم کار می‌کنند

### کلاینت‌های پیشنهادی (۱۴۰۴/۲۰۲۶)

- **خانواده Clash**: Clash Verge Rev، Clash Meta اندروید، FlClash
- **مبتنی بر sing-box**: Hiddify Next، SFA، NekoBox اندروید
- **iOS**: Shadowrocket، Stash و مشابه‌ها
- **ویندوز/مک**: v2rayN، Nekoray، Clash Verge Rev

### نکات مهم

- پروکسی‌ها با چک اتصال واقعی تست می‌شوند (هسته sing-box)
- آی‌پی‌های سیاه‌لیست شده (FireHOL Level 1 + bogons) حذف می‌شوند
- نام‌های خیلی بلند یا فرمت‌های نامعتبر فیلتر می‌شوند
- کانفیگ‌های Hysteria2 در اولویت هستند و در حال رشد
- به‌روزرسانی هر ۳ ساعت انجام می‌شود → اگر لینکی کند/مرده بود، حداکثر ۳ ساعت صبر کنید

اگر کمک کرد ستاره ⭐ بزنید!

سوال / پیشنهاد → ایشو باز کنید.
