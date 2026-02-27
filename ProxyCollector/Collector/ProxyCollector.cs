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
        private readonly IPToCountryResolver _resolver = new();

        // Strict protocol whitelist – everything else → unknown.txt
        private static readonly HashSet<string> ValidProtocols = new(StringComparer.OrdinalIgnoreCase)
        {
            "vmess", "vless", "trojan", "ss", "shadowsocks", "hysteria2", "hy2", "tuic", "socks", "socks5", "anytls"
        };

        // Expanded country flag map – DUPLICATE "KZ" removed
        private static readonly Dictionary<string, string> Flags = new(StringComparer.OrdinalIgnoreCase)
        {
            {"AF", "🇦🇫"}, {"AL", "🇦🇱"}, {"DZ", "🇩🇿"}, {"AR", "🇦🇷"}, {"AM", "🇦🇲"},
            {"AU", "🇦🇺"}, {"AT", "🇦🇹"}, {"AZ", "🇦🇿"}, {"BD", "🇧🇩"}, {"BY", "🇧🇾"},
            {"BE", "🇧🇪"}, {"BR", "🇧🇷"}, {"BG", "🇧🇬"}, {"CA", "🇨🇦"}, {"CN", "🇨🇳"},
            {"CO", "🇨🇴"}, {"HR", "🇭🇷"}, {"CZ", "🇨🇿"}, {"DK", "🇩🇰"}, {"EG", "🇪🇬"},
            {"FI", "🇫🇮"}, {"FR", "🇫🇷"}, {"DE", "🇩🇪"}, {"GR", "🇬🇷"}, {"HK", "🇭🇰"},
            {"HU", "🇭🇺"}, {"IN", "🇮🇳"}, {"ID", "🇮🇩"}, {"IR", "🇮🇷"}, {"IE", "🇮🇪"},
            {"IL", "🇮🇱"}, {"IT", "🇮🇹"}, {"JP", "🇯🇵"}, {"KR", "🇰🇷"},
            {"MY", "🇲🇾"}, {"MX", "🇲🇽"}, {"NL", "🇳🇱"}, {"NZ", "🇳🇿"}, {"NO", "🇳🇴"},
            {"PK", "🇵🇰"}, {"PH", "🇵🇭"}, {"PL", "🇵🇱"}, {"PT", "🇵🇹"}, {"RU", "🇷🇺"},
            {"SA", "🇸🇦"}, {"RS", "🇷🇸"}, {"SG", "🇸🇬"}, {"ZA", "🇿🇦"}, {"ES", "🇪🇸"},
            {"SE", "🇸🇪"}, {"CH", "🇨🇭"}, {"TH", "🇹🇭"}, {"TR", "🇹🇷"}, {"UA", "🇺🇦"},
            {"GB", "🇬🇧"}, {"US", "🇺🇸"}, {"VN", "🇻🇳"}, {"TW", "🇹🇼"}, {"LV", "🇱🇻"},
            {"LT", "🇱🇹"}, {"EE", "🇪🇪"}, {"MD", "🇲🇩"}, {"CY", "🇨🇾"}, {"GE", "🇬🇪"},
            {"KZ", "🇰🇿"},   // ← only once
            {"UZ", "🇺🇿"}, {"KG", "🇰🇬"}, {"TJ", "🇹🇯"}, {"TM", "🇹🇲"}
        };

        private static readonly string TestUrl = "http://cp.cloudflare.com/generate_204";
        private const int MaxBestResults = 500;
        private const int TestTimeoutMs = 5000;
        private const int AliveCheckTimeoutMs = 2000;
        private const int MaxFilenameRemarkLength = 150;

        // Blacklist CIDRs (FireHOL + Bogons)
        private static readonly List<(IPAddress Network, int Mask)> BlacklistCidrs = new();

        // NEW: Common proxy ports whitelist (static, no download needed)
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
                Console.WriteLine($"⚠️ GeoIP download failed: {ex.Message}. Keeping previous file if exists.");
            }
        }

        private static async Task DownloadFreshFireHOLBlacklist(HttpClient http)
        {
            Console.WriteLine("Downloading fresh FireHOL Level 2 blacklist...");
            var blacklistPath = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "blacklist.netset");
            const string url = "https://iplists.firehol.org/files/firehol_level2.netset";
            try
            {
                var response = await http.GetAsync(url);
                response.EnsureSuccessStatusCode();
                await using var fs = new FileStream(blacklistPath, FileMode.Create, FileAccess.Write, FileShare.None);
                await response.Content.CopyToAsync(fs);
                Console.WriteLine("✅ Fresh FireHOL Level 2 blacklist downloaded.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ FireHOL blacklist download failed: {ex.Message}. Keeping previous file if exists.");
            }
        }

        private static async Task DownloadFreshBogons(HttpClient http)
        {
            Console.WriteLine("Downloading fresh Bogons list...");
            var bogonsPath = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "bogons.txt");
            const string url = "https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt";
            try
            {
                var response = await http.GetAsync(url);
                response.EnsureSuccessStatusCode();
                await using var fs = new FileStream(bogonsPath, FileMode.Create, FileAccess.Write, FileShare.None);
                await response.Content.CopyToAsync(fs);
                Console.WriteLine("✅ Fresh Bogons list downloaded.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"⚠️ Bogons download failed: {ex.Message}. Keeping previous file if exists.");
            }
        }

        private static void LoadAllBlacklists()
        {
            BlacklistCidrs.Clear();

            // 1. Load FireHOL Level 2
            var fireholPath = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "blacklist.netset");
            if (File.Exists(fireholPath))
            {
                var lines = File.ReadAllLines(fireholPath);
                int loaded = 0;
                foreach (var line in lines)
                {
                    if (line.StartsWith("#") || string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        var parts = line.Split('/');
                        if (parts.Length != 2) continue;
                        var network = IPAddress.Parse(parts[0].Trim());
                        var mask = int.Parse(parts[1].Trim());
                        BlacklistCidrs.Add((network, mask));
                        loaded++;
                    }
                    catch { }
                }
                Console.WriteLine($"Loaded {loaded} CIDRs from FireHOL Level 2 blacklist.");
            }
            else
            {
                Console.WriteLine("⚠️ FireHOL blacklist.netset not found.");
            }

            // 2. Load Bogons (same format: CIDR lines)
            var bogonsPath = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "bogons.txt");
            if (File.Exists(bogonsPath))
            {
                var lines = File.ReadAllLines(bogonsPath);
                int loaded = 0;
                foreach (var line in lines)
                {
                    if (line.StartsWith("#") || string.IsNullOrWhiteSpace(line)) continue;
                    try
                    {
                        var parts = line.Split('/');
                        if (parts.Length != 2) continue;
                        var network = IPAddress.Parse(parts[0].Trim());
                        var mask = int.Parse(parts[1].Trim());
                        BlacklistCidrs.Add((network, mask));
                        loaded++;
                    }
                    catch { }
                }
                Console.WriteLine($"Loaded {loaded} CIDRs from Bogons list.");
            }
            else
            {
                Console.WriteLine("⚠️ Bogons.txt not found.");
            }
        }

        private static bool IsBlacklisted(string ipStr)
        {
            if (!IPAddress.TryParse(ipStr, out var ip)) return true; // invalid IP = blocked

            foreach (var (network, mask) in BlacklistCidrs)
            {
                if (IsIpInCidr(ip, network, mask)) return true;
            }
            return false;
        }

        private static bool IsIpInCidr(IPAddress ip, IPAddress network, int mask)
        {
            byte[] ipBytes = ip.GetAddressBytes();
            byte[] networkBytes = network.GetAddressBytes();
            if (ipBytes.Length != networkBytes.Length) return false;

            int bits = mask;
            for (int i = 0; i < ipBytes.Length && bits > 0; i++)
            {
                byte maskByte = (byte)(0xFF << (8 - Math.Min(bits, 8)));
                if ((ipBytes[i] & maskByte) != (networkBytes[i] & maskByte))
                    return false;
                bits -= 8;
            }
            return true;
        }

        public async Task StartAsync()
        {
            // Always download fresh versions of all online-based blacklists
            await DownloadFreshGeoIP(_http);
            await DownloadFreshFireHOLBlacklist(_http);
            await DownloadFreshBogons(_http);

            // Load everything into memory once
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

            Console.WriteLine("\n🧹 Parsing + strict deduplicating + renaming...");
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

                var (proto, serverPort, originalRemark) = ParseProxyLine(cleaned);
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
                var info = _resolver.GetCountry(ipOrHost);
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

                string flag;
                string countryDisplay;
                if (countryCode == "XX")
                {
                    flag = "🌍";
                    countryDisplay = "Unknown";
                }
                else
                {
                    flag = Flags.TryGetValue(countryCode, out var f) ? f : "🌍";
                    countryDisplay = info?.CountryName ?? GetCountryNameFromCode(countryCode);
                }

                string cleanRemark;
                if (string.IsNullOrWhiteSpace(originalRemark) ||
                    originalRemark.Length > 80 ||
                    Regex.IsMatch(originalRemark, @"^[A-Za-z0-9+/=]{40,}$") ||
                    originalRemark.Contains("Telegram") || originalRemark.Contains("t.me") ||
                    originalRemark.Contains("channel") || originalRemark.Contains("group"))
                {
                    cleanRemark = $"{flag} {countryDisplay} - {proto.ToUpperInvariant()} - {ipOrHost}:{portStr}";
                }
                else
                {
                    cleanRemark = $"{flag} {countryDisplay} - {proto.ToUpperInvariant()} - {originalRemark.Trim()}";
                }

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
                _ => "Unknown"
            };
        }

        // ... (rest of your methods: GenerateBestResultsAsync, IsProxyAliveAsync, TestProxyLatencyAsync, NormalizeProto, SaveClashJson, GenerateClashProxy, RenameRemarkInLink, ParseProxyLine, DecodeBase64 remain unchanged) ...
        // Paste the rest of your original code here (from GenerateBestResultsAsync down to the end)
    }
}
