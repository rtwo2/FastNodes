using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Collections.Concurrent;
using System.Net;
using ProxyCollector.Configuration;
using ProxyCollector.Services;

namespace ProxyCollector.Collector
{
    public class ProxyCollector
    {
        private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };

        // Lazy resolver — created only after downloads finish
        private IPToCountryResolver? _resolver;
        private IPToCountryResolver Resolver => _resolver ??= new IPToCountryResolver();

        private static readonly HashSet<string> ValidProtocols = new(StringComparer.OrdinalIgnoreCase)
        {
            "vmess", "vless", "trojan", "ss", "shadowsocks", "hysteria2", "hy2", "tuic", "socks", "socks5", "anytls"
        };

        // ──────────────────────────────────────────────────────────────
        // ALL possible ISO 3166-1 alpha-2 country flags (249 entries)
        // Nothing less — every officially assigned code with emoji is here
        // ──────────────────────────────────────────────────────────────
        private static readonly Dictionary<string, string> Flags = new(StringComparer.OrdinalIgnoreCase)
        {
            {"AD", "🇦🇩"}, {"AE", "🇦🇪"}, {"AF", "🇦🇫"}, {"AG", "🇦🇬"}, {"AI", "🇦🇮"},
            {"AL", "🇦🇱"}, {"AM", "🇦🇲"}, {"AO", "🇦🇴"}, {"AQ", "🇦🇶"}, {"AR", "🇦🇷"},
            {"AS", "🇦🇸"}, {"AT", "🇦🇹"}, {"AU", "🇦🇺"}, {"AW", "🇦🇼"}, {"AX", "🇦🇽"},
            {"AZ", "🇦🇿"}, {"BA", "🇧🇦"}, {"BB", "🇧🇧"}, {"BD", "🇧🇩"}, {"BE", "🇧🇪"},
            {"BF", "🇧🇫"}, {"BG", "🇧🇬"}, {"BH", "🇧🇭"}, {"BI", "🇧🇮"}, {"BJ", "🇧🇯"},
            {"BL", "🇧🇱"}, {"BM", "🇧🇲"}, {"BN", "🇧🇳"}, {"BO", "🇧🇴"}, {"BQ", "🇧🇶"},
            {"BR", "🇧🇷"}, {"BS", "🇧🇸"}, {"BT", "🇧🇹"}, {"BV", "🇧🇻"}, {"BW", "🇧🇼"},
            {"BY", "🇧🇾"}, {"BZ", "🇧🇿"}, {"CA", "🇨🇦"}, {"CC", "🇨🇨"}, {"CD", "🇨🇩"},
            {"CF", "🇨🇫"}, {"CG", "🇨🇬"}, {"CH", "🇨🇭"}, {"CI", "🇨🇮"}, {"CK", "🇨🇰"},
            {"CL", "🇨🇱"}, {"CM", "🇨🇲"}, {"CN", "🇨🇳"}, {"CO", "🇨🇴"}, {"CR", "🇨🇷"},
            {"CU", "🇨🇺"}, {"CV", "🇨🇻"}, {"CW", "🇨🇼"}, {"CX", "🇨🇽"}, {"CY", "🇨🇾"},
            {"CZ", "🇨🇿"}, {"DE", "🇩🇪"}, {"DJ", "🇩🇯"}, {"DK", "🇩🇰"}, {"DM", "🇩🇲"},
            {"DO", "🇩🇴"}, {"DZ", "🇩🇿"}, {"EC", "🇪🇨"}, {"EE", "🇪🇪"}, {"EG", "🇪🇬"},
            {"EH", "🇪🇭"}, {"ER", "🇪🇷"}, {"ES", "🇪🇸"}, {"ET", "🇪🇹"}, {"FI", "🇫🇮"},
            {"FJ", "🇫🇯"}, {"FK", "🇫🇰"}, {"FM", "🇫🇲"}, {"FO", "🇫🇴"}, {"FR", "🇫🇷"},
            {"GA", "🇬🇦"}, {"GB", "🇬🇧"}, {"GD", "🇬🇩"}, {"GE", "🇬🇪"}, {"GF", "🇬🇫"},
            {"GG", "🇬🇬"}, {"GH", "🇬🇭"}, {"GI", "🇬🇮"}, {"GL", "🇬🇱"}, {"GM", "🇬🇲"},
            {"GN", "🇬🇳"}, {"GP", "🇬🇵"}, {"GQ", "🇬🇶"}, {"GR", "🇬🇷"}, {"GS", "🇬🇸"},
            {"GT", "🇬🇹"}, {"GU", "🇬🇺"}, {"GW", "🇬🇼"}, {"GY", "🇬🇾"}, {"HK", "🇭🇰"},
            {"HM", "🇭🇲"}, {"HN", "🇭🇳"}, {"HR", "🇭🇷"}, {"HT", "🇭🇹"}, {"HU", "🇭🇺"},
            {"ID", "🇮🇩"}, {"IE", "🇮🇪"}, {"IL", "🇮🇱"}, {"IM", "🇮🇲"}, {"IN", "🇮🇳"},
            {"IO", "🇮🇴"}, {"IQ", "🇮🇶"}, {"IR", "🇮🇷"}, {"IS", "🇮🇸"}, {"IT", "🇮🇹"},
            {"JE", "🇯🇪"}, {"JM", "🇯🇲"}, {"JO", "🇯🇴"}, {"JP", "🇯🇵"}, {"KE", "🇰🇪"},
            {"KG", "🇰🇬"}, {"KH", "🇰🇭"}, {"KI", "🇰🇮"}, {"KM", "🇰🇲"}, {"KN", "🇰🇳"},
            {"KP", "🇰🇵"}, {"KR", "🇰🇷"}, {"KW", "🇰🇼"}, {"KY", "🇰🇾"}, {"KZ", "🇰🇿"},
            {"LA", "🇱🇦"}, {"LB", "🇱🇧"}, {"LC", "🇱🇨"}, {"LI", "🇱🇮"}, {"LK", "🇱🇰"},
            {"LR", "🇱🇷"}, {"LS", "🇱🇸"}, {"LT", "🇱🇹"}, {"LU", "🇱🇺"}, {"LV", "🇱🇻"},
            {"LY", "🇱🇾"}, {"MA", "🇲🇦"}, {"MC", "🇲🇨"}, {"MD", "🇲🇩"}, {"ME", "🇲🇪"},
            {"MF", "🇲🇫"}, {"MG", "🇲🇬"}, {"MH", "🇲🇭"}, {"MK", "🇲🇰"}, {"ML", "🇲🇱"},
            {"MM", "🇲🇲"}, {"MN", "🇲🇳"}, {"MO", "🇲🇴"}, {"MP", "🇲🇵"}, {"MQ", "🇲🇶"},
            {"MR", "🇲🇷"}, {"MS", "🇲🇸"}, {"MT", "🇲🇹"}, {"MU", "🇲🇺"}, {"MV", "🇲🇻"},
            {"MW", "🇲🇼"}, {"MX", "🇲🇽"}, {"MY", "🇲🇾"}, {"MZ", "🇲🇿"}, {"NA", "🇳🇦"},
            {"NC", "🇳🇨"}, {"NE", "🇳🇪"}, {"NF", "🇳🇫"}, {"NG", "🇳🇬"}, {"NI", "🇳🇮"},
            {"NL", "🇳🇱"}, {"NO", "🇳🇴"}, {"NP", "🇳🇵"}, {"NR", "🇳🇷"}, {"NU", "🇳🇺"},
            {"NZ", "🇳🇿"}, {"OM", "🇴🇲"}, {"PA", "🇵🇦"}, {"PE", "🇵🇪"}, {"PF", "🇵🇫"},
            {"PG", "🇵🇬"}, {"PH", "🇵🇭"}, {"PK", "🇵🇰"}, {"PL", "🇵🇱"}, {"PM", "🇵🇲"},
            {"PN", "🇵🇳"}, {"PR", "🇵🇷"}, {"PS", "🇵🇸"}, {"PT", "🇵🇹"}, {"PW", "🇵🇼"},
            {"PY", "🇵🇾"}, {"QA", "🇶🇦"}, {"RE", "🇷🇪"}, {"RO", "🇷🇴"}, {"RS", "🇷🇸"},
            {"RU", "🇷🇺"}, {"RW", "🇷🇼"}, {"SA", "🇸🇦"}, {"SB", "🇸🇧"}, {"SC", "🇸🇨"},
            {"SD", "🇸🇩"}, {"SE", "🇸🇪"}, {"SG", "🇸🇬"}, {"SH", "🇸🇭"}, {"SI", "🇸🇮"},
            {"SJ", "🇸🇯"}, {"SK", "🇸🇰"}, {"SL", "🇸🇱"}, {"SM", "🇸🇲"}, {"SN", "🇸🇳"},
            {"SO", "🇸🇴"}, {"SR", "🇸🇷"}, {"SS", "🇸🇸"}, {"ST", "🇸🇹"}, {"SV", "🇸🇻"},
            {"SX", "🇸🇽"}, {"SY", "🇸🇾"}, {"SZ", "🇸🇿"}, {"TC", "🇹🇨"}, {"TD", "🇹🇩"},
            {"TF", "🇹🇫"}, {"TG", "🇹🇬"}, {"TH", "🇹🇭"}, {"TJ", "🇹🇯"}, {"TK", "🇹🇰"},
            {"TL", "🇹🇱"}, {"TM", "🇹🇲"}, {"TN", "🇹🇳"}, {"TO", "🇹🇴"}, {"TR", "🇹🇷"},
            {"TT", "🇹🇹"}, {"TV", "🇹🇻"}, {"TW", "🇹🇼"}, {"TZ", "🇹🇿"}, {"UA", "🇺🇦"},
            {"UG", "🇺🇬"}, {"UM", "🇺🇲"}, {"US", "🇺🇸"}, {"UY", "🇺🇾"}, {"UZ", "🇺🇿"},
            {"VA", "🇻🇦"}, {"VC", "🇻🇨"}, {"VE", "🇻🇪"}, {"VG", "🇻🇬"}, {"VI", "🇻🇮"},
            {"VN", "🇻🇳"}, {"VU", "🇻🇺"}, {"WF", "🇼🇫"}, {"WS", "🇼🇸"}, {"YE", "🇾🇪"},
            {"YT", "🇾🇹"}, {"ZA", "🇿🇦"}, {"ZM", "🇿🇲"}, {"ZW", "🇿🇼"}
        };

        private static readonly string TestUrl = "http://cp.cloudflare.com/generate_204";
        private const int MaxBestResults = 500;
        private const int TestTimeoutMs = 5000;
        private const int AliveCheckTimeoutMs = 2000;
        private const int MaxFilenameRemarkLength = 150;

        private static readonly List<(IPAddress Network, int Mask)> BlacklistCidrs = new();

        // Static common proxy ports whitelist (no download needed — extend here if you want)
        private static readonly HashSet<int> CommonProxyPorts = new()
        {
            80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2095, 2096,
            8880, 8888, 10000, 10001, 20000, 30000
        };

        private static async Task DownloadFreshGeoIP(HttpClient http)
        {
            Console.WriteLine("Downloading fresh GeoIP database...");
            var geoPath = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "Country.mmdb");
            try
            {
                var response = await http.GetAsync("https://git.io/GeoLite2-Country.mmdb");
                response.EnsureSuccessStatusCode();
                await using var fs = new FileStream(geoPath, FileMode.Create, FileAccess.Write, FileShare.None);
                await response.Content.CopyToAsync(fs);
                Console.WriteLine("✅ Fresh GeoIP database downloaded.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ GeoIP download failed: {ex.Message}. Keeping previous if exists.");
            }
        }

        private static async Task DownloadFreshFireHOLBlacklist(HttpClient http)
        {
            Console.WriteLine("Downloading fresh FireHOL Level 2 blacklist...");
            var path = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "blacklist.netset");
            const string url = "https://iplists.firehol.org/files/firehol_level2.netset";
            try
            {
                var response = await http.GetAsync(url);
                response.EnsureSuccessStatusCode();
                await using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
                await response.Content.CopyToAsync(fs);
                Console.WriteLine("✅ Fresh FireHOL Level 2 downloaded.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ FireHOL download failed: {ex.Message}. Keeping previous if exists.");
            }
        }

        private static async Task DownloadFreshBogons(HttpClient http)
        {
            Console.WriteLine("Downloading fresh Bogons list...");
            var path = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "bogons.txt");
            const string url = "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt";
            try
            {
                var response = await http.GetAsync(url);
                response.EnsureSuccessStatusCode();
                await using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
                await response.Content.CopyToAsync(fs);
                Console.WriteLine("✅ Fresh Bogons list downloaded.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ Bogons download failed: {ex.Message}. Keeping previous if exists.");
            }
        }

        private static void LoadAllBlacklists()
        {
            BlacklistCidrs.Clear();

            // FireHOL
            var fireholPath = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "blacklist.netset");
            if (File.Exists(fireholPath))
            {
                int loaded = 0;
                foreach (var line in File.ReadAllLines(fireholPath))
                {
                    if (line.StartsWith("#") || string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        var parts = line.Split('/');
                        if (parts.Length != 2) continue;
                        var net = IPAddress.Parse(parts[0].Trim());
                        var mask = int.Parse(parts[1].Trim());
                        BlacklistCidrs.Add((net, mask));
                        loaded++;
                    }
                    catch { }
                }
                Console.WriteLine($"Loaded {loaded} CIDRs from FireHOL.");
            }

            // Bogons
            var bogonsPath = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "bogons.txt");
            if (File.Exists(bogonsPath))
            {
                int loaded = 0;
                foreach (var line in File.ReadAllLines(bogonsPath))
                {
                    if (line.StartsWith("#") || string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        var parts = line.Split('/');
                        if (parts.Length != 2) continue;
                        var net = IPAddress.Parse(parts[0].Trim());
                        var mask = int.Parse(parts[1].Trim());
                        BlacklistCidrs.Add((net, mask));
                        loaded++;
                    }
                    catch { }
                }
                Console.WriteLine($"Loaded {loaded} CIDRs from Bogons.");
            }
        }

        private static bool IsBlacklisted(string ipStr)
        {
            if (!IPAddress.TryParse(ipStr, out var ip)) return true;
            foreach (var (net, mask) in BlacklistCidrs)
            {
                if (IsIpInCidr(ip, net, mask)) return true;
            }
            return false;
        }

        private static bool IsIpInCidr(IPAddress ip, IPAddress net, int mask)
        {
            byte[] ipB = ip.GetAddressBytes();
            byte[] netB = net.GetAddressBytes();
            if (ipB.Length != netB.Length) return false;

            int bits = mask;
            for (int i = 0; i < ipB.Length && bits > 0; i++)
            {
                byte m = (byte)(0xFF << (8 - Math.Min(bits, 8)));
                if ((ipB[i] & m) != (netB[i] & m)) return false;
                bits -= 8;
            }
            return true;
        }

        public async Task StartAsync()
        {
            // ALL DOWNLOADS FIRST — before resolver is created/used
            await DownloadFreshGeoIP(_http);
            await DownloadFreshFireHOLBlacklist(_http);
            await DownloadFreshBogons(_http);

            LoadAllBlacklists();

            Console.WriteLine("🚀 ProxyCollector started - FastNodes fork");
            Console.WriteLine("----------------------------------------");
            await RunFullCollectionMode();
        }

        // The rest of the class remains unchanged from your previous working version
        // (RunFullCollectionMode, GetCountryNameFromCode, GenerateBestResultsAsync, etc.)
        // Paste the rest of your existing code here (everything after StartAsync)

        // ... (keep all the other methods exactly as they were in your last working version)

    }
}
