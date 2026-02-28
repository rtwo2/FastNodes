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
using System.Diagnostics;
using System.Threading;
using ProxyCollector.Configuration;
using ProxyCollector.Services;

namespace ProxyCollector.Collector
{
    public class ProxyCollector
    {
        private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };
        private IPToCountryResolver? _resolver;
        private IPToCountryResolver Resolver => _resolver ??= new IPToCountryResolver();

        private static int _basePort = 20000; // much higher base to avoid conflicts

        private static readonly HashSet<string> ValidProtocols = new(StringComparer.OrdinalIgnoreCase)
        {
            "vmess", "vless", "trojan", "ss", "shadowsocks", "http", "socks", "socks5", "ssr",
            "hysteria", "hysteria2", "hy2", "tuic", "snell", "anytls", "shadowtls",
            "websocket", "ws", "wss", "grpc", "mkcp", "quic", "xtls"
        };

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

        private static readonly string[] TestUrls = {
            "http://aparat.com/generate_204",
            "http://varzesh3.com/generate_204",
            "http://www.google.com/generate_204"
        };

        private const int TargetGoodNodes = 200;
        private const int MaxFullAttempts = 2000;
        private const int TestTimeoutMs = 15000;
        private const int AliveCheckTimeoutMs = 3000;     // slightly longer
        private const int FullTestTimeoutSeconds = 20;    // increased from 10s
        private const int ParallelFullTests = 20;
        private const int ProgressReportEvery = 20;

        private static readonly List<(IPAddress Network, int Mask)> BlacklistCidrs = new();

        // ────────────────────────────────────────────────────────────────
        // Download + blacklist methods (unchanged)
        // ────────────────────────────────────────────────────────────────

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
            Console.WriteLine("Downloading fresh FireHOL Level 1 blacklist...");
            var path = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "blacklist.netset");
            const string url = "https://iplists.firehol.org/files/firehol_level1.netset";
            try
            {
                var response = await http.GetAsync(url);
                response.EnsureSuccessStatusCode();
                await using var fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None);
                await response.Content.CopyToAsync(fs);
                Console.WriteLine("✅ Fresh FireHOL Level 1 downloaded.");
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
                int shift = Math.Min(bits, 8);
                byte m = (byte)(0xFF << (8 - shift));
                if ((ipB[i] & m) != (netB[i] & m)) return false;
                bits -= shift;
            }
            return true;
        }

        private string GetCountryNameFromCode(string code)
        {
            return code switch
            {
                "TW" => "Taiwan",
                "LV" => "Latvia",
                "HK" => "Hong Kong",
                "SG" => "Singapore",
                "JP" => "Japan",
                "KR" => "South Korea",
                "US" => "United States",
                "GB" => "United Kingdom",
                "DE" => "Germany",
                "FR" => "France",
                "RU" => "Russia",
                "CA" => "Canada",
                "NL" => "Netherlands",
                "AU" => "Australia",
                "IN" => "India",
                "MD" => "Moldova",
                "CY" => "Cyprus",
                "IR" => "Iran",
                _ => "Unknown"
            };
        }

        public async Task StartAsync()
        {
            await DownloadFreshGeoIP(_http);
            await DownloadFreshFireHOLBlacklist(_http);
            await DownloadFreshBogons(_http);
            LoadAllBlacklists();
            Console.WriteLine("🚀 ProxyCollector started - FastNodes fork");
            Console.WriteLine("----------------------------------------");
            await RunFullCollectionMode();
        }

        private async Task RunFullCollectionMode()
        {
            var urls = CollectorConfig.Instance.Sources;
            var rawLines = new List<string>();
            Console.WriteLine("🔍 Fetching proxy lists from sources...");
            foreach (var url in urls)
            {
                try
                {
                    Console.WriteLine($"Fetching: {url}");
                    var text = await _http.GetStringAsync(url);
                    string content = text;
                    try { content = Encoding.UTF8.GetString(Convert.FromBase64String(text.Trim())); } catch { }
                    var lines = content.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);
                    rawLines.AddRange(lines);
                    Console.WriteLine($" → Found {lines.Length} lines");
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Failed to fetch {url}: {ex.Message}");
                }
            }
            Console.WriteLine($"\n📊 Total raw lines collected: {rawLines.Count}");
            var tempDir = Path.Combine(Directory.GetCurrentDirectory(), "sub", "temp");
            Directory.CreateDirectory(tempDir);
            var tempPath = Path.Combine(tempDir, "temp_everything.txt");
            await File.WriteAllLinesAsync(tempPath, rawLines);
            Console.WriteLine($"💾 Saved raw → {tempPath} ({rawLines.Count} lines)");

            var renamedProxies = new List<(string Link, string Proto, string CountryCode, string ServerPort, string Remark, object? ClashProxy)>();
            var seenNormalized = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int skippedNumbered = 0, parseFail = 0, skippedLongFilename = 0, skippedBlacklisted = 0;
            Console.WriteLine("\n🧹 Parsing + strict deduplicating + forced clean renaming...");
            int processed = 0;
            foreach (var line in rawLines)
            {
                processed++;
                if (processed % 5000 == 0)
                    Console.WriteLine($" {processed}/{rawLines.Count} ({Math.Round((double)processed / rawLines.Count * 100, 1)}%)");
                var trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;
                if (Regex.IsMatch(trimmed, @"\s*\(\d{2,}\)\s*$"))
                {
                    skippedNumbered++;
                    continue;
                }
                var (proto, serverPort, _) = ParseProxyLine(trimmed);
                if (string.IsNullOrEmpty(serverPort) || !serverPort.Contains(":"))
                {
                    parseFail++;
                    continue;
                }
                var parts = serverPort.Split(':', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                string ipOrHost = parts[0];
                string portStr = parts[1];
                if (!int.TryParse(portStr, out int port))
                {
                    parseFail++;
                    continue;
                }
                if (IsBlacklisted(ipOrHost))
                {
                    skippedBlacklisted++;
                    continue;
                }
                string countryCode = "XX";
                var info = Resolver.GetCountry(ipOrHost);
                countryCode = info?.CountryCode?.ToUpperInvariant() ?? "XX";
                string lowerHost = ipOrHost.ToLowerInvariant();
                if (countryCode == "XX")
                {
                    countryCode = lowerHost switch
                    {
                        var h when h.EndsWith(".ir") || h.Contains("iran") => "IR",
                        var h when h.EndsWith(".tw") || h.Contains("taiwan") => "TW",
                        var h when h.EndsWith(".lv") || h.Contains("latvia") => "LV",
                        var h when h.EndsWith(".hk") || h.Contains("hongkong") => "HK",
                        var h when h.EndsWith(".sg") || h.Contains("singapore") => "SG",
                        var h when h.EndsWith(".jp") || h.Contains("japan") => "JP",
                        var h when h.EndsWith(".kr") || h.Contains("korea") => "KR",
                        var h when h.EndsWith(".us") || h.Contains("usa") || h.Contains("unitedstates") => "US",
                        var h when h.EndsWith(".gb") || h.Contains("uk") || h.Contains("unitedkingdom") => "GB",
                        var h when h.EndsWith(".de") || h.Contains("germany") => "DE",
                        var h when h.EndsWith(".fr") || h.Contains("france") => "FR",
                        var h when h.EndsWith(".ru") || h.Contains("russia") => "RU",
                        var h when h.EndsWith(".ca") || h.Contains("canada") => "CA",
                        var h when h.EndsWith(".nl") || h.Contains("netherlands") => "NL",
                        var h when h.EndsWith(".au") || h.Contains("australia") => "AU",
                        var h when h.EndsWith(".in") || h.Contains("india") => "IN",
                        var h when h.EndsWith(".md") || h.Contains("moldova") => "MD",
                        var h when h.EndsWith(".cy") || h.Contains("cyprus") => "CY",
                        _ => "XX"
                    };
                }
                string flag = Flags.TryGetValue(countryCode, out var f) ? f : "🌍";
                string countryDisplay = info?.CountryName ?? GetCountryNameFromCode(countryCode) ?? "Unknown";
                string cleanRemark = $"{flag} {countryDisplay} - {proto.ToUpperInvariant()} {ipOrHost}:{portStr}";
                var renamedLink = RenameRemarkInLink(trimmed, cleanRemark, proto);
                string dedupKey = $"{proto.ToLowerInvariant()}:{serverPort}#{cleanRemark.Replace(" ", "").ToLowerInvariant()}";
                if (seenNormalized.Add(dedupKey))
                {
                    object? clashProxy = GenerateClashProxy(proto, serverPort, trimmed, cleanRemark);
                    renamedProxies.Add((renamedLink, proto, countryCode, serverPort, cleanRemark, clashProxy));
                }
            }
            Console.WriteLine($"Finished → {renamedProxies.Count} unique (dupes: {parseFail}, numbered: {skippedNumbered}, blacklisted: {skippedBlacklisted}, long fn: {skippedLongFilename})");

            var sub = Path.Combine(Directory.GetCurrentDirectory(), "sub");
            var protocolsDir = Path.Combine(sub, "protocols");
            var countriesDir = Path.Combine(sub, "countries");
            var bestDir = Path.Combine(sub, "Best-Results");
            Directory.CreateDirectory(sub);
            Directory.CreateDirectory(protocolsDir);
            Directory.CreateDirectory(countriesDir);
            Directory.CreateDirectory(bestDir);

            var allPath = Path.Combine(sub, "everything.txt");
            await File.WriteAllLinesAsync(allPath, renamedProxies.Select(x => x.Link));
            Console.WriteLine($"Saved everything.txt ({renamedProxies.Count})");
            await SaveClashJson(Path.Combine(sub, "everything.json"), renamedProxies, "FastNodes Everything");
            Console.WriteLine("Saved everything.json");

            Console.WriteLine("By protocol...");
            foreach (var g in renamedProxies.GroupBy(x => NormalizeProto(x.Proto)))
            {
                var key = g.Key.ToLowerInvariant();
                if (key == "unknown" && g.Count() < 10) continue;
                string safeKey = key switch
                {
                    var k when k.Contains("vmess") => "vmess",
                    var k when k.Contains("vless") => "vless",
                    var k when k.Contains("trojan") => "trojan",
                    var k when k.Contains("ss") => "ss",
                    var k when k.Contains("hysteria") || k == "hy2" || k == "hy" => "hysteria2",
                    var k when k.Contains("tuic") => "tuic",
                    _ => key.Length > 20 ? key.Substring(0, 20) : key
                };
                var txt = Path.Combine(protocolsDir, $"{safeKey}.txt");
                try
                {
                    await File.WriteAllLinesAsync(txt, g.Select(x => x.Link));
                    Console.WriteLine($" → {txt} ({g.Count()})");
                }
                catch (PathTooLongException)
                {
                    skippedLongFilename++;
                    Console.WriteLine($"Skipped long filename: {key} ({g.Count()})");
                }
                var json = Path.Combine(protocolsDir, $"{safeKey}.json");
                await SaveClashJson(json, g.ToList(), $"FastNodes {safeKey.ToUpper()}");
            }

            Console.WriteLine("By country...");
            foreach (var g in renamedProxies.GroupBy(x => x.CountryCode))
            {
                if (string.IsNullOrEmpty(g.Key) || g.Key == "XX" || g.Count() < 5) continue;
                var txt = Path.Combine(countriesDir, $"{g.Key}.txt");
                await File.WriteAllLinesAsync(txt, g.Select(x => x.Link));
                Console.WriteLine($" → {txt} ({g.Count()})");
                var json = Path.Combine(countriesDir, $"{g.Key}.json");
                await SaveClashJson(json, g.ToList(), $"FastNodes {g.Key}");
            }

            var unknowns = renamedProxies.Where(p => !ValidProtocols.Contains(p.Proto)).ToList();
            if (unknowns.Any())
            {
                var unknownPath = Path.Combine(protocolsDir, "unknown.txt");
                await File.WriteAllLinesAsync(unknownPath, unknowns.Select(p => p.Link));
                Console.WriteLine($" → {unknownPath} ({unknowns.Count})");
                var unknownJson = Path.Combine(protocolsDir, "unknown.json");
                await SaveClashJson(unknownJson, unknowns, "FastNodes Unknown");
            }

            await GenerateBestResultsAsync(renamedProxies);
            Console.WriteLine("\n🎉 Done!");
        }

        private async Task GenerateBestResultsAsync(List<(string Link, string Proto, string CountryCode, string ServerPort, string Remark, object? ClashProxy)> proxies)
        {
            if (proxies.Count == 0)
            {
                Console.WriteLine("No proxies to test.");
                return;
            }

            Console.WriteLine($"\n🏆 Quick raw latency testing all {proxies.Count} proxies (require 2/3 success)...");
            var quickResults = new ConcurrentBag<(string Link, int Latency, string Proto, object? ClashProxy)>();

            await Parallel.ForEachAsync(proxies, new ParallelOptions { MaxDegreeOfParallelism = 80 }, async (p, ct) =>
            {
                int latency = await QuickRawLatencyAsync(p.Link);
                if (latency > 0 && latency < 1500)
                    quickResults.Add((p.Link, latency, p.Proto, p.ClashProxy));
            });

            var sortedByPing = quickResults.OrderBy(x => x.Latency).ToList();
            Console.WriteLine($"Quick test finished → {sortedByPing.Count} nodes passed (strict 2/3 success filter)");

            Console.WriteLine($"\nStarting parallel full tunnel test → goal: {TargetGoodNodes} good nodes (max {MaxFullAttempts} attempts, {ParallelFullTests} parallel, {FullTestTimeoutSeconds}s timeout each)");

            var fullResults = new ConcurrentBag<(string Link, int Latency, object? ClashProxy)>();
            int goodCount = 0;
            int testedCount = 0;

            var semaphore = new SemaphoreSlim(ParallelFullTests);
            var tasks = new List<Task>();

            foreach (var candidate in sortedByPing.Take(MaxFullAttempts))
            {
                if (goodCount >= TargetGoodNodes) break;

                await semaphore.WaitAsync();
                testedCount++;
                if (testedCount % ProgressReportEvery == 0)
                {
                    Console.WriteLine($"Progress: tested {testedCount}/{MaxFullAttempts} | good: {goodCount}/{TargetGoodNodes}");
                }

                tasks.Add(Task.Run(async () =>
                {
                    try
                    {
                        var cts = new CancellationTokenSource(TimeSpan.FromSeconds(FullTestTimeoutSeconds));

                        bool alive = await IsProxyAliveFullAsync(candidate.Link, candidate.Proto, cts.Token);

                        if (alive)
                        {
                            int fullLatency = await TestProxyLatencyFullAsync(candidate.Link, candidate.Proto, cts.Token);
                            if (fullLatency > 0)
                            {
                                fullResults.Add((candidate.Link, fullLatency, candidate.ClashProxy));
                                Interlocked.Increment(ref goodCount);
                                Console.WriteLine($"Good #{goodCount}/{TargetGoodNodes} | {fullLatency}ms | {candidate.Link}");
                            }
                        }
                    }
                    catch (OperationCanceledException) { /* silent timeout */ }
                    catch (Exception ex)
                    {
                        Console.WriteLine($"Error on {candidate.Link}: {ex.Message}");
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }));
            }

            await Task.WhenAll(tasks);

            var finalSorted = fullResults.OrderBy(x => x.Latency).ToList();
            Console.WriteLine($"Full test finished → {finalSorted.Count} good proxies (tested {testedCount} candidates, target was {TargetGoodNodes})");

            // Fallback if zero good
            if (finalSorted.Count == 0)
            {
                Console.WriteLine("WARNING: 0 good proxies from full test → falling back to quick-ping ranking");
                finalSorted = sortedByPing.Select(p => (p.Link, p.Latency, p.ClashProxy)).ToList();
            }

            var bestDir = Path.Combine(Directory.GetCurrentDirectory(), "sub", "Best-Results");
            Directory.CreateDirectory(bestDir);

            var limits = new[] { 50, 100, 150, 200 };
            foreach (var limit in limits)
            {
                var topN = finalSorted.Take(limit).ToList();
                var txtPath = Path.Combine(bestDir, $"top{limit}.txt");
                await File.WriteAllLinesAsync(txtPath, topN.Select(t => $"{t.Link} # latency={t.Latency}ms"));
                Console.WriteLine($"Saved top{limit}.txt ({topN.Count})");

                var jsonProxies = topN.Select(t => t.ClashProxy).Where(p => p != null).ToList();
                var jsonConfig = new
                {
                    name = $"FastNodes Top {limit} (Iran optimized)",
                    proxies = jsonProxies,
                    proxy_groups = new[]
                    {
                        new
                        {
                            name = "AUTO",
                            type = "url-test",
                            proxies = topN.Select(t => ((dynamic?)t.ClashProxy)?.name ?? "Unnamed").ToList(),
                            url = "http://cp.cloudflare.com/generate_204",
                            interval = 300,
                            tolerance = 50
                        }
                    },
                    rules = new[] { "MATCH,AUTO" }
                };

                var jsonPath = Path.Combine(bestDir, $"top{limit}.json");
                var options = new JsonSerializerOptions { WriteIndented = true };
                await File.WriteAllTextAsync(jsonPath, JsonSerializer.Serialize(jsonConfig, options));
                Console.WriteLine($"Saved top{limit}.json ({topN.Count})");
            }
        }

        private async Task<int> QuickRawLatencyAsync(string link)
        {
            int total = 0;
            int success = 0;
            foreach (var url in TestUrls)
            {
                try
                {
                    using var client = new HttpClient { Timeout = TimeSpan.FromMilliseconds(AliveCheckTimeoutMs) };
                    var start = DateTime.UtcNow;
                    var resp = await client.GetAsync(url);
                    if (resp.IsSuccessStatusCode)
                    {
                        total += (int)(DateTime.UtcNow - start).TotalMilliseconds;
                        success++;
                    }
                }
                catch { }
            }
            return (success >= 2) ? total / success : -1; // require at least 2 successes
        }

        private async Task<bool> IsProxyAliveFullAsync(string link, string proto, CancellationToken token)
        {
            string configPath = Path.GetTempFileName() + ".json";
            int port = Interlocked.Increment(ref _basePort) % 10000 + 20000; // wide range: 20000-29999
            string socksAddr = $"127.0.0.1:{port}";
            var config = GenerateSingBoxConfig(link, proto, port);
            if (config == null)
            {
                Console.WriteLine($"[CONFIG FAIL] Cannot generate sing-box config for: {link}");
                return false;
            }
            await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }), token);
            using var process = StartSingBox(configPath);
            await Task.Delay(1200, token); // give sing-box more time to start
            bool alive = false;
            try
            {
                var proxy = new WebProxy(socksAddr);
                using var client = new HttpClient(new HttpClientHandler { Proxy = proxy }) { Timeout = TimeSpan.FromMilliseconds(AliveCheckTimeoutMs) };
                foreach (var url in TestUrls)
                {
                    try
                    {
                        var resp = await client.GetAsync(url, token);
                        if (resp.IsSuccessStatusCode)
                        {
                            alive = true;
                            break; // one success is enough now
                        }
                    }
                    catch { }
                }
            }
            catch { }
            process.Kill(true);
            try { File.Delete(configPath); } catch { }
            return alive;
        }

        private async Task<int> TestProxyLatencyFullAsync(string link, string proto, CancellationToken token)
        {
            string configPath = Path.GetTempFileName() + ".json";
            int port = Interlocked.Increment(ref _basePort) % 10000 + 20000;
            string socksAddr = $"127.0.0.1:{port}";
            var config = GenerateSingBoxConfig(link, proto, port);
            if (config == null) return -1;
            await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(config, new JsonSerializerOptions { WriteIndented = true }), token);
            using var process = StartSingBox(configPath);
            await Task.Delay(1200, token);
            int total = 0;
            int count = 0;
            try
            {
                var proxy = new WebProxy(socksAddr);
                using var client = new HttpClient(new HttpClientHandler { Proxy = proxy }) { Timeout = TimeSpan.FromMilliseconds(TestTimeoutMs) };
                foreach (var url in TestUrls)
                {
                    try
                    {
                        var start = DateTime.UtcNow;
                        var resp = await client.GetAsync(url, token);
                        if (resp.IsSuccessStatusCode)
                        {
                            total += (int)(DateTime.UtcNow - start).TotalMilliseconds;
                            count++;
                        }
                    }
                    catch { }
                }
            }
            catch { }
            process.Kill(true);
            try { File.Delete(configPath); } catch { }
            return count > 0 ? total / count : -1;
        }

        private Process StartSingBox(string configPath)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "sing-box",
                    Arguments = $"run -c \"{configPath}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            process.Start();
            return process;
        }

        private object? GenerateSingBoxConfig(string link, string proto, int localPort)
        {
            var (protocol, serverPort, _) = ParseProxyLine(link);
            var parts = serverPort.Split(':');
            if (parts.Length < 2) return null;
            string server = parts[0];
            if (!int.TryParse(parts[1], out int port)) return null;

            string uuid = "";
            string password = "";
            string flow = "";
            string security = "auto";
            int alterId = 0;

            switch (protocol.ToLowerInvariant())
            {
                case "vless":
                    var vlessParts = link.Split('@');
                    if (vlessParts.Length > 1) uuid = vlessParts[0].Split("://")[1].Split('#')[0];
                    flow = Regex.Match(link, @"flow=([^&]+)").Groups[1].Value;
                    break;
                case "trojan":
                    var trojanParts = link.Split('@');
                    if (trojanParts.Length > 1) password = trojanParts[0].Split("://")[1].Split('#')[0];
                    break;
                case "ss":
                    string ssDecoded = DecodeBase64(link.Substring(5).Split('#')[0]);
                    var ssAuth = ssDecoded.Split('@')[0].Split(':');
                    if (ssAuth.Length > 1)
                    {
                        security = ssAuth[0];
                        password = ssAuth[1];
                    }
                    break;
                case "vmess":
                    string vmB64 = link.Substring(8).Split('#')[0];
                    string vmDecoded = DecodeBase64(vmB64);
                    if (!string.IsNullOrEmpty(vmDecoded))
                    {
                        var vmObj = JsonDocument.Parse(vmDecoded).RootElement;
                        uuid = vmObj.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? "" : "";
                        alterId = vmObj.TryGetProperty("aid", out var aidProp) ? aidProp.GetInt32() : 0;
                        security = vmObj.TryGetProperty("scy", out var scyProp) ? scyProp.GetString() ?? "auto" : "auto";
                    }
                    break;
                default:
                    return null;
            }

            object outbound = protocol.ToLowerInvariant() switch
            {
                "vless" => new { type = "vless", server, server_port = port, uuid, tls = new { enabled = true }, flow = flow ?? "" },
                "trojan" => new { type = "trojan", server, server_port = port, password, tls = new { enabled = true } },
                "ss" => new { type = "shadowsocks", server, server_port = port, method = security, password },
                "vmess" => new { type = "vmess", server, server_port = port, uuid, alter_id = alterId, security, tls = new { enabled = true } },
                _ => null!
            };

            if (outbound == null)
            {
                Console.WriteLine($"[CONFIG FAIL] Unsupported or malformed link: {link}");
                return null;
            }

            return new
            {
                log = new { level = "error" },
                inbounds = new object[] { new { type = "socks", listen = "127.0.0.1", listen_port = localPort } },
                outbounds = new object[] { outbound, new { type = "direct", tag = "direct" } },
                route = new { rules = new object[] { new { outbound = protocol } } }
            };
        }

        private string NormalizeProto(string proto)
        {
            if (string.IsNullOrEmpty(proto)) return "unknown";
            proto = proto.ToLowerInvariant();
            if (proto.Contains("hysteria") || proto == "hy2" || proto == "hy") return "hysteria2";
            if (proto == "ssr") return "ssr";
            if (proto == "ss") return "ss";
            if (proto == "vmess") return "vmess";
            if (proto == "vless") return "vless";
            if (proto == "trojan") return "trojan";
            if (proto == "tuic") return "tuic";
            return proto;
        }

        private async Task SaveClashJson(string filePath, List<(string Link, string Proto, string CountryCode, string ServerPort, string Remark, object? ClashProxy)> proxies, string configName)
        {
            var clashProxies = proxies.Select(x => x.ClashProxy).Where(p => p != null).ToList();
            var proxyNames = proxies.Select(x => x.Remark).ToList();

            var clashConfig = new
            {
                name = configName,
                port = 7890,
                socks_port = 7891,
                allow_lan = true,
                mode = "Rule",
                log_level = "info",
                external_controller = "127.0.0.1:9090",
                proxies = clashProxies,
                proxy_groups = new[]
                {
                    new
                    {
                        name = "AUTO",
                        type = "url-test",
                        proxies = proxyNames,
                        url = "http://cp.cloudflare.com/generate_204",
                        interval = 300,
                        tolerance = 50
                    }
                },
                rules = new[] { "MATCH,AUTO" }
            };

            var options = new JsonSerializerOptions { WriteIndented = true };
            await File.WriteAllTextAsync(filePath, JsonSerializer.Serialize(clashConfig, options));
        }

        private object? GenerateClashProxy(string proto, string serverPort, string originalLine, string name)
        {
            string server = "unknown";
            int port = 443;
            if (!string.IsNullOrEmpty(serverPort) && serverPort.Contains(":"))
            {
                var parts = serverPort.Split(':');
                server = parts[0] ?? "unknown";
                if (parts.Length > 1 && int.TryParse(parts[1], out int p)) port = p;
            }

            string? uuid = null;
            string? password = null;
            string? flow = null;
            int alterId = 0;
            string cipher = "auto";
            bool tls = true;

            try
            {
                switch (proto.ToLowerInvariant())
                {
                    case "vmess":
                        string b64 = originalLine?.Substring(8)?.Split('#')?[0]?.Trim() ?? "";
                        string decoded = DecodeBase64(b64);
                        if (!string.IsNullOrEmpty(decoded))
                        {
                            var obj = JsonDocument.Parse(decoded).RootElement;
                            uuid = obj.TryGetProperty("id", out var idProp) ? idProp.GetString() : null;
                            alterId = obj.TryGetProperty("aid", out var aidProp) ? aidProp.GetInt32() : 0;
                            cipher = obj.TryGetProperty("scy", out var scyProp) ? scyProp.GetString() ?? "auto" : "auto";
                            tls = obj.TryGetProperty("tls", out var tlsProp) && tlsProp.GetString() == "tls";
                        }
                        break;
                    case "vless":
                        uuid = originalLine?.Split('@')?[0]?.Split("://")?[1];
                        flow = Regex.Match(originalLine ?? "", "flow=([^&]+)").Groups[1].Value;
                        break;
                    case "trojan":
                        password = originalLine?.Split('@')?[0]?.Split("://")?[1];
                        break;
                    case "ss":
                        string ssDecoded = DecodeBase64(originalLine?.Substring(5)?.Split('#')?[0] ?? "");
                        if (ssDecoded.Contains("@"))
                        {
                            var authParts = ssDecoded.Split('@')[0].Split(':');
                            cipher = authParts.Length > 0 ? authParts[0] : "aes-256-gcm";
                            password = authParts.Length > 1 ? authParts[1] : null;
                        }
                        break;
                }
            }
            catch { }

            return proto.ToLowerInvariant() switch
            {
                "vmess" => new { name, type = "vmess", server, port, uuid = uuid ?? "", alterId, cipher, tls },
                "vless" => new { name, type = "vless", server, port, uuid = uuid ?? "", tls, flow = flow ?? "" },
                "trojan" => new { name, type = "trojan", server, port, password = password ?? "", tls },
                "ss" => new { name, type = "ss", server, port, cipher, password = password ?? "" },
                _ => null
            };
        }

        private string RenameRemarkInLink(string original, string newRemark, string proto)
        {
            string baseLink = original.Split('#')[0].TrimEnd();
            baseLink = Regex.Replace(baseLink,
                @"Dynamic-\d+|-ok\d{5,}|-\d{4,}$",
                "", RegexOptions.IgnoreCase | RegexOptions.Multiline).Trim();
            if (proto.ToLowerInvariant() == "vmess" && baseLink.StartsWith("vmess://"))
            {
                try
                {
                    string b64 = baseLink.Substring(8).Trim();
                    string decoded = DecodeBase64(b64);
                    if (string.IsNullOrEmpty(decoded)) return baseLink + "#" + Uri.EscapeDataString(newRemark);
                    string trimmedDecoded = decoded.TrimStart();
                    if (!trimmedDecoded.StartsWith("{") ||
                        (!trimmedDecoded.Contains("\"add\"") && !trimmedDecoded.Contains("\"port\"")))
                    {
                        return baseLink + "#" + Uri.EscapeDataString(newRemark);
                    }
                    var jsonDoc = JsonDocument.Parse(decoded);
                    var root = jsonDoc.RootElement;
                    var props = new Dictionary<string, object?>();
                    foreach (var prop in root.EnumerateObject())
                    {
                        props[prop.Name] = prop.Value.ValueKind == JsonValueKind.Null
                            ? null
                            : JsonSerializer.Deserialize<object>(prop.Value.GetRawText());
                    }
                    props["ps"] = newRemark;
                    string newJson = JsonSerializer.Serialize(props);
                    string newB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(newJson))
                        .Replace("+", "-").Replace("/", "_").TrimEnd('=');
                    baseLink = "vmess://" + newB64;
                }
                catch { }
            }
            string escaped = Uri.EscapeDataString(newRemark);
            return baseLink + "#" + escaped;
        }

        private (string protocol, string serverPort, string remark) ParseProxyLine(string line)
        {
            line = line.Trim();
            if (string.IsNullOrEmpty(line) || line.Length < 20) return ("unknown", "", "");
            string basePart = line.Split('#')[0].Trim();
            string remark = line.Contains('#') ? Uri.UnescapeDataString(line.Split('#')[1].Trim()) : "";
            try
            {
                var uri = new Uri(basePart);
                string scheme = uri.Scheme.ToLowerInvariant();
                if (ValidProtocols.Contains(scheme))
                {
                    string server = uri.Host;
                    int port = uri.Port > 0 ? uri.Port : 443;
                    return (scheme, $"{server}:{port}", remark);
                }
            }
            catch { }
            string lowerClean = line.ToLowerInvariant();
            string guessedProto = "unknown";
            if (lowerClean.Contains("vless://")) guessedProto = "vless";
            else if (lowerClean.Contains("vmess://")) guessedProto = "vmess";
            else if (lowerClean.Contains("ss://")) guessedProto = "ss";
            else if (lowerClean.Contains("trojan://")) guessedProto = "trojan";
            else if (lowerClean.Contains("hysteria2://") || lowerClean.Contains("hy2://")) guessedProto = "hysteria2";
            if (guessedProto == "unknown" && (line.Contains("eyJhZGQiOi") || line.Contains("\"add\":") || (line.Contains("id") && line.Contains("port"))))
            {
                if (line.Contains("reality") || line.Contains("pbk=") || line.Contains("flow=") || line.Contains("xtls") || line.Contains("grpc") || line.Contains("kcp") || line.Contains("sid="))
                    guessedProto = "vless";
                else if (line.Contains("net") || line.Contains("scy") || line.Contains("aid") || line.Contains("ps"))
                    guessedProto = "vmess";
            }
            var ipPortMatch = Regex.Match(line, @"(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?::\d{1,5})?");
            if (ipPortMatch.Success && guessedProto == "unknown")
            {
                string found = ipPortMatch.Value;
                string port = found.Contains(":") ? found.Split(':')[1] : "443";
                if (port == "443" || port == "8443" || port == "2053" || port == "2096" || port == "2083" || port == "2086")
                    guessedProto = "vless";
                else if (port == "80" || port == "8080" || port == "8888")
                    guessedProto = "ss";
                else if (port == "1080" || port == "7890")
                    guessedProto = "socks";
            }
            if (guessedProto != "unknown" && ipPortMatch.Success)
                return (guessedProto, ipPortMatch.Value, remark);
            return ("unknown", "", "");
        }

        private string DecodeBase64(string b64)
        {
            try
            {
                b64 = b64.Replace("-", "+").Replace("_", "/").Replace(" ", "").Trim();
                int mod = b64.Length % 4;
                if (mod > 0) b64 += new string('=', 4 - mod);
                return Encoding.UTF8.GetString(Convert.FromBase64String(b64));
            }
            catch
            {
                return "";
            }
        }
    }
}
