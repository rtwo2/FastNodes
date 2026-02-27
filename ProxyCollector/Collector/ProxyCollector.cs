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

        private IPToCountryResolver? _resolver;
        private IPToCountryResolver Resolver => _resolver ??= new IPToCountryResolver();

        private static readonly HashSet<string> ValidProtocols = new(StringComparer.OrdinalIgnoreCase)
        {
            "vmess", "vless", "trojan", "ss", "shadowsocks", "hysteria2", "hy2", "tuic", "socks", "socks5", "anytls"
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

        private static readonly string TestUrl = "http://cp.cloudflare.com/generate_204";
        private const int MaxBestResults = 500;
        private const int TestTimeoutMs = 5000;
        private const int AliveCheckTimeoutMs = 2000;

        private static readonly List<(IPAddress Network, int Mask)> BlacklistCidrs = new();

        private static readonly HashSet<int> CommonProxyPorts = new()
        {
            80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2095, 2096,
            8880, 8888, 10000, 10001, 20000, 30000,
            1080, 10808, 10809, 7890, 7891, 1081, 8000, 8881, 8882, 8883,  // added safe/common
            2010, 2011, 2020, 8889, 9999, 1443, 10443, 4433               // extra common ones
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
                byte m = (byte)(0xFF << (8 - Math.Min(bits, 8)));
                if ((ipB[i] & m) != (netB[i] & m)) return false;
                bits -= 8;
            }
            return true;
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

            var renamedProxies = new List<(string Link, string Proto, string CountryCode, string ServerPort, string Remark, object ClashProxy)>();
            var seenNormalized = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            int skippedNumbered = 0, parseFail = 0, skippedLongFilename = 0, skippedBlacklisted = 0;

            Console.WriteLine("\n🧹 Parsing + strict deduplicating + forced clean renaming...");
            int processed = 0;
            foreach (var line in rawLines)
            {
                processed++;
                if (processed % 1000 == 0)
                    Console.WriteLine($" {processed}/{rawLines.Count} ({Math.Round((double)processed / rawLines.Count * 100, 1)}%)");

                var trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;
                if (Regex.IsMatch(trimmed, @"\s*\(\d+\)\s*$"))
                {
                    skippedNumbered++;
                    continue;
                }

                string cleaned = Regex.Replace(trimmed, @"^(?:Telegram\s*[:=]?\s*@[^@]+@|Telegram\s*-\s*|Telegram\s+@|t\.me\/[^@]+@)", "", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

                var (proto, serverPort, _) = ParseProxyLine(cleaned);
                if (string.IsNullOrEmpty(serverPort) || !serverPort.Contains(":")) 
                {
                    parseFail++;
                    continue;
                }

                var parts = serverPort.Split(':', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 2) continue;
                string ipOrHost = parts[0];
                string portStr = parts[1];

                if (!int.TryParse(portStr, out int port) || !CommonProxyPorts.Contains(port))
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
                string countryDisplay = info?.CountryName ?? GetCountryNameFromCode(countryCode);

                string cleanRemark = $"{flag} {countryDisplay} - {proto.ToUpperInvariant()} {ipOrHost}:{portStr}";

                var renamedLink = RenameRemarkInLink(cleaned, cleanRemark, proto);

                string dedupKey = $"{proto.ToLowerInvariant()}:{serverPort}#{cleanRemark.Replace(" ", "").ToLowerInvariant()}";

                if (seenNormalized.Add(dedupKey))
                {
                    object clashProxy = GenerateClashProxy(proto, serverPort, cleaned, cleanRemark);
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

            var unknowns = renamedProxies.Where(p => !ValidProtocols.Contains(p.Proto)).Select(p => p.Link).ToList();
            if (unknowns.Any())
            {
                var unknownPath = Path.Combine(protocolsDir, "unknown.txt");
                await File.WriteAllLinesAsync(unknownPath, unknowns);
                Console.WriteLine($" → {unknownPath} ({unknowns.Count})");
            }

            await GenerateBestResultsAsync(renamedProxies);
            Console.WriteLine("\n🎉 Done!");
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
                "AE" => "United Arab Emirates",
                "SC" => "Seychelles",
                "IM" => "Isle of Man",
                "LU" => "Luxembourg",
                _ => "Unknown"
            };
        }

        private async Task GenerateBestResultsAsync(List<(string Link, string Proto, string CountryCode, string ServerPort, string Remark, object ClashProxy)> proxies)
        {
            Console.WriteLine($"\n🏆 Testing {proxies.Count} proxies...");
            var tested = new ConcurrentBag<(string Link, int Latency, object ClashProxy)>();
            int processed = 0;

            await Parallel.ForEachAsync(proxies, new ParallelOptions { MaxDegreeOfParallelism = 20 }, async (p, ct) =>
            {
                Interlocked.Increment(ref processed);
                if (processed % 500 == 0)
                    Console.WriteLine($" Tested {processed}/{proxies.Count} ({Math.Round((double)processed / proxies.Count * 100, 1)}%)");

                if (p.Proto.ToLowerInvariant() == "vmess") return;

                if (!await IsProxyAliveAsync(p.Link)) return;

                int latency = await TestProxyLatencyAsync(p.Link);
                if (latency > 0 && latency < 1500)
                    tested.Add((p.Link, latency, p.ClashProxy));
            });

            var sorted = tested.OrderBy(t => t.Latency).ToList();
            var bestDir = Path.Combine(Directory.GetCurrentDirectory(), "sub", "Best-Results");
            Directory.CreateDirectory(bestDir);

            var limits = new[] { 100, 200, 300, 400, 500 };
            foreach (var limit in limits)
            {
                var topN = sorted.Take(limit).ToList();
                var txtPath = Path.Combine(bestDir, $"top{limit}.txt");
                await File.WriteAllLinesAsync(txtPath, topN.Select(t => $"{t.Link} # latency={t.Latency}ms"));
                Console.WriteLine($"Saved sub/Best-Results/top{limit}.txt ({topN.Count})");

                var jsonProxies = topN.Select(t => t.ClashProxy).Where(p => p != null).ToList();
                var jsonConfig = new
                {
                    name = $"FastNodes Top {limit}",
                    proxies = jsonProxies,
                    proxy_groups = new[]
                    {
                        new
                        {
                            name = "AUTO",
                            type = "url-test",
                            proxies = topN.Select(t => ((dynamic)t.ClashProxy).name ?? "Unnamed").ToList(),
                            url = "http://cp.cloudflare.com/generate_204",
                            interval = 300
                        }
                    },
                    rules = new[] { "MATCH,AUTO" }
                };

                var jsonPath = Path.Combine(bestDir, $"top{limit}.json");
                var options = new JsonSerializerOptions { WriteIndented = true };
                await File.WriteAllTextAsync(jsonPath, JsonSerializer.Serialize(jsonConfig, options));
                Console.WriteLine($"Saved sub/Best-Results/top{limit}.json ({topN.Count})");
            }
        }

        private async Task<bool> IsProxyAliveAsync(string link)
        {
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromMilliseconds(AliveCheckTimeoutMs) };
                var request = new HttpRequestMessage(HttpMethod.Head, TestUrl);
                var resp = await client.SendAsync(request);
                return resp.IsSuccessStatusCode;
            }
            catch
            {
                return false;
            }
        }

        private async Task<int> TestProxyLatencyAsync(string link)
        {
            try
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromMilliseconds(TestTimeoutMs) };
                var start = DateTime.UtcNow;
                var resp = await client.GetAsync(TestUrl);
                var elapsed = (int)(DateTime.UtcNow - start).TotalMilliseconds;
                return resp.IsSuccessStatusCode ? elapsed : -1;
            }
            catch
            {
                return -1;
            }
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

        private async Task SaveClashJson(string filePath, List<(string Link, string Proto, string CountryCode, string ServerPort, string Remark, object ClashProxy)> proxies, string configName)
        {
            var clashProxies = proxies.Select(x => x.ClashProxy).Where(p => p != null).ToList();
            var remarkList = proxies.Select(x => x.Remark).ToList();
            var clashConfig = new
            {
                name = configName,
                proxies = clashProxies,
                proxy_groups = new[]
                {
                    new
                    {
                        name = "AUTO",
                        type = "url-test",
                        proxies = remarkList,
                        url = "http://cp.cloudflare.com/generate_204",
                        interval = 300
                    }
                },
                rules = new[] { "MATCH,AUTO" }
            };
            var options = new JsonSerializerOptions { WriteIndented = true };
            await File.WriteAllTextAsync(filePath, JsonSerializer.Serialize(clashConfig, options));
        }

        private object GenerateClashProxy(string proto, string serverPort, string originalLine, string name)
        {
            string server = "unknown";
            int port = 443;
            if (!string.IsNullOrEmpty(serverPort) && serverPort.Contains(":"))
            {
                var parts = serverPort.Split(':');
                server = parts[0];
                if (parts.Length > 1 && int.TryParse(parts[1], out int p))
                    port = p;
            }

            switch (proto.ToLowerInvariant())
            {
                case "vmess":
                    try
                    {
                        string b64 = originalLine?.Substring(8)?.Split('#')?[0]?.Trim() ?? "";
                        string decoded = DecodeBase64(b64);
                        if (!string.IsNullOrEmpty(decoded))
                        {
                            var obj = JsonDocument.Parse(decoded).RootElement;
                            string uuid = obj.TryGetProperty("id", out var idProp) ? idProp.GetString() ?? "" : "";
                            int alterId = obj.TryGetProperty("aid", out var aidProp) ? aidProp.GetInt32() : 0;
                            string cipher = obj.TryGetProperty("scy", out var scyProp) ? scyProp.GetString() ?? "auto" : "auto";
                            bool tls = obj.TryGetProperty("tls", out var tlsProp) && tlsProp.GetString() == "tls";
                            return new { name, type = "vmess", server, port, uuid, alterId, cipher, tls };
                        }
                    }
                    catch { }
                    return new { name, type = "vmess", server, port, uuid = "", alterId = 0, cipher = "auto", tls = true };

                case "vless":
                    try
                    {
                        string uuid = originalLine?.Split('@')?[0]?.Split("://")?[1] ?? "";
                        return new { name, type = "vless", server, port, uuid, tls = true, flow = "" };
                    }
                    catch { }
                    return new { name, type = "vless", server, port, uuid = "", tls = true, flow = "" };

                case "trojan":
                    try
                    {
                        string password = originalLine?.Split('@')?[0]?.Split("://")?[1] ?? "";
                        return new { name, type = "trojan", server, port, password, tls = true };
                    }
                    catch { }
                    return new { name, type = "trojan", server, port, password = "", tls = true };

                case "ss":
                    try
                    {
                        string decoded = DecodeBase64(originalLine?.Substring(5)?.Split('#')?[0] ?? "");
                        if (decoded.Contains("@"))
                        {
                            var authParts = decoded.Split('@')[0].Split(':');
                            string cipher = authParts.Length > 0 ? authParts[0] : "aes-256-gcm";
                            string password = authParts.Length > 1 ? authParts[1] : "";
                            return new { name, type = "ss", server, port, cipher, password };
                        }
                    }
                    catch { }
                    return new { name, type = "ss", server, port, cipher = "aes-256-gcm", password = "" };

                default:
                    return new { name, type = proto, server, port };
            }
        }

        private string RenameRemarkInLink(string original, string newRemark, string proto)
        {
            string baseLink = original.Split('#')[0].TrimEnd();
            baseLink = Regex.Replace(baseLink,
                @"\[.*?\]|\(.*?\)|Dynamic-\d+|-\d{4,}|ok\d{5,}|sg\.ok|mgjhju|fvb|7no|10o|ccwu\.cc|indevs\.in|zem\.in|bffv|fbvb|mghjju|ggff|ffffvbbgh|mmmv\.kr|yhjt\.tc1|ns\.cloudflare\.com|\d{4,}$|\s*:\d+$",
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
                string server = uri.Host;
                int port = uri.Port > 0 ? uri.Port : 443;
                string serverPort = $"{server}:{port}";
                return (scheme, serverPort, remark);
            }
            catch { }

            if (basePart.StartsWith("vmess://"))
            {
                try
                {
                    string b64 = basePart.Substring(8).Split('#')[0].Trim();
                    string decoded = DecodeBase64(b64);
                    if (!string.IsNullOrEmpty(decoded))
                    {
                        var obj = JsonDocument.Parse(decoded).RootElement;
                        string? add = obj.TryGetProperty("add", out var a) ? a.GetString() : null;
                        string? portStr = obj.TryGetProperty("port", out var p) ? p.GetString() : null;
                        if (!string.IsNullOrEmpty(add) && !string.IsNullOrEmpty(portStr) && int.TryParse(portStr, out _))
                            return ("vmess", $"{add}:{portStr}", remark);
                    }
                }
                catch { }
            }

            if (basePart.StartsWith("hysteria2://") || basePart.StartsWith("hy2://") || basePart.StartsWith("hysteria://"))
            {
                try
                {
                    var uri = new Uri(basePart);
                    string server = uri.Host;
                    int port = uri.Port > 0 ? uri.Port : 443;
                    return ("hysteria2", $"{server}:{port}", remark);
                }
                catch { }
            }

            var ipPortMatch = Regex.Match(line, @"(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?::\d{1,5})?");
            if (ipPortMatch.Success)
            {
                string found = ipPortMatch.Value;
                string guessedProto = "unknown";
                string port = found.Contains(":") ? found.Split(':')[1] : "443";

                // Improved fallback detection
                string lowerLine = line.ToLowerInvariant();
                if (lowerLine.StartsWith("vless://")) guessedProto = "vless";
                else if (lowerLine.StartsWith("vmess://")) guessedProto = "vmess";
                else if (lowerLine.StartsWith("ss://")) guessedProto = "ss";
                else if (lowerLine.StartsWith("trojan://")) guessedProto = "trojan";
                else if (lowerLine.StartsWith("hysteria2://") || lowerLine.StartsWith("hy2://")) guessedProto = "hysteria2";
                else
                {
                    // port-based fallback only if scheme not found
                    if (port == "443" || port == "8443" || port == "2053" || port == "2096" || port == "2010") guessedProto = "vless";
                    else if (port == "80" || port == "8080" || port == "8888") guessedProto = "ss";
                    else if (port == "1080" || port == "7890") guessedProto = "socks";
                }

                return (guessedProto, found, remark);
            }

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
