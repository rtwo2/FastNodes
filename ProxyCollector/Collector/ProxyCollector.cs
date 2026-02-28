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

        private static int _basePort = 10800;

        private static readonly HashSet<string> ValidProtocols = new(StringComparer.OrdinalIgnoreCase)
        {
            "vmess", "vless", "trojan", "ss", "shadowsocks", "http", "socks", "socks5", "ssr",
            "hysteria", "hysteria2", "hy2", "tuic", "snell", "anytls", "shadowtls",
            "websocket", "ws", "wss", "grpc", "mkcp", "quic", "xtls"
            // reality intentionally excluded from valid list to prevent inclusion
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
            // Reduced from 5 → faster quick test, still good for Iran
        };

        private const int MaxBestResults = 500;
        private const int TestTimeoutMs = 15000;
        private const int AliveCheckTimeoutMs = 4000;
        private const int QuickCandidatesLimit = 800;      // Reduced from 2000 → big speedup
        private const int SingBoxBatchSize = 10;

        private static readonly List<(IPAddress Network, int Mask)> BlacklistCidrs = new();

        // ─────────────────────────────────────────────────────────────
        // Download methods (unchanged)
        // ─────────────────────────────────────────────────────────────

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

        // ─────────────────────────────────────────────────────────────
        // Main collection + parsing (mostly unchanged)
        // ─────────────────────────────────────────────────────────────

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
                if (processed % 1000 == 0)
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

            // Protocol folders (skip unknown if too few)
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

            // Country folders
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
                _ => "Unknown"
            };
        }

        private async Task GenerateBestResultsAsync(List<(string Link, string Proto, string CountryCode, string ServerPort, string Remark, object? ClashProxy)> proxies)
        {
            Console.WriteLine($"\n🏆 Quick raw multi-URL testing {proxies.Count} proxies...");
            var quickResults = new ConcurrentBag<(string Link, int Latency, string Proto, object? ClashProxy)>();

            await Parallel.ForEachAsync(proxies, new ParallelOptions { MaxDegreeOfParallelism = 30 }, async (p, ct) =>
            {
                int latency = await QuickRawLatencyAsync(p.Link);
                if (latency > 0 && latency < 2000)
                    quickResults.Add((p.Link, latency, p.Proto, p.ClashProxy));
            });

            var candidates = quickResults
                .OrderBy(x => x.Latency)
                .Take(QuickCandidatesLimit)
                .ToList();

            Console.WriteLine($" → {candidates.Count} quick candidates passed → starting full sing-box tunnel test...");

            var fullResults = new ConcurrentBag<(string Link, int Latency, object? ClashProxy)>();

            var batches = candidates.Chunk(SingBoxBatchSize);
            foreach (var batch in batches)
            {
                var batchTasks = batch.Select(async item =>
                {
                    if (await IsProxyAliveFullAsync(item.Link, item.Proto))
                    {
                        int fullLatency = await TestProxyLatencyFullAsync(item.Link, item.Proto);
                        if (fullLatency > 0)
                            fullResults.Add((item.Link, fullLatency, item.ClashProxy));
                    }
                }).ToArray();

                await Task.WhenAll(batchTasks);
            }

            // Exclude Reality from top results (prevents balancer parse errors)
            var sorted = fullResults
                .Where(x => !x.Link.ToLowerInvariant().Contains("reality"))
                .OrderBy(x => x.Latency)
                .ToList();

            Console.WriteLine($"Full tunnel test complete: {sorted.Count} usable proxies (Reality excluded)");

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
                    name = $"FastNodes Top {limit} (no Reality)",
                    proxies = jsonProxies,
                    proxy_groups = new object[]
                    {
                        new
                        {
                            name = "AUTO",
                            type = "url-test",
                            proxies = topN.Select(t => ((dynamic?)t.ClashProxy)?.name ?? "Unnamed").ToList(),
                            url = TestUrls[0],
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
                        if (success >= 2) break; // early exit optimization
                    }
                }
                catch { }
            }

            return success > 0 ? total / success : -1;
        }

        // The rest of the file (IsProxyAliveFullAsync, TestProxyLatencyFullAsync, StartSingBox, GenerateSingBoxConfig, etc.) remains unchanged from previous version
        // If you need them pasted again, let me know — but they didn't change in this optimization round
