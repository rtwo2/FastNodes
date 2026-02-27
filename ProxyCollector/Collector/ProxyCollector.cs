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
using ProxyCollector.Configuration;
using ProxyCollector.Services;
using ProxyCollector.Models;
using System.Net; // for IPAddress & CIDR check

namespace ProxyCollector.Collector
{
    public class ProxyCollector
    {
        private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };
        private readonly IPToCountryResolver _resolver = new();

        private static readonly Dictionary<string, string> Flags = new()
        {
            {"AF", "🇦🇫"}, {"AL", "🇦🇱"}, {"DZ", "🇩🇿"}, {"AR", "🇦🇷"}, {"AM", "🇦🇲"},
            {"AU", "🇦🇺"}, {"AT", "🇦🇹"}, {"AZ", "🇦🇿"}, {"BD", "🇧🇩"}, {"BY", "🇧🇾"},
            {"BE", "🇧🇪"}, {"BR", "🇧🇷"}, {"BG", "🇧🇬"}, {"CA", "🇨🇦"}, {"CN", "🇨🇳"},
            {"CO", "🇨🇴"}, {"HR", "🇭🇷"}, {"CZ", "🇨🇿"}, {"DK", "🇩🇰"}, {"EG", "🇪🇬"},
            {"FI", "🇫🇮"}, {"FR", "🇫🇷"}, {"DE", "🇩🇪"}, {"GR", "🇬🇷"}, {"HK", "🇭🇰"},
            {"HU", "🇭🇺"}, {"IN", "🇮🇳"}, {"ID", "🇮🇩"}, {"IR", "🇮🇷"}, {"IE", "🇮🇪"},
            {"IL", "🇮🇱"}, {"IT", "🇮🇹"}, {"JP", "🇯🇵"}, {"KZ", "🇰🇿"}, {"KR", "🇰🇷"},
            {"MY", "🇲🇾"}, {"MX", "🇲🇽"}, {"NL", "🇳🇱"}, {"NZ", "🇳🇿"}, {"NO", "🇳🇴"},
            {"PK", "🇵🇰"}, {"PH", "🇵🇭"}, {"PL", "🇵🇱"}, {"PT", "🇵🇹"}, {"RU", "🇷🇺"},
            {"SA", "🇸🇦"}, {"RS", "🇷🇸"}, {"SG", "🇸🇬"}, {"ZA", "🇿🇦"}, {"ES", "🇪🇸"},
            {"SE", "🇸🇪"}, {"CH", "🇨🇭"}, {"TH", "🇹🇭"}, {"TR", "🇹🇷"}, {"UA", "🇺🇦"},
            {"GB", "🇬🇧"}, {"US", "🇺🇸"}, {"VN", "🇻🇳"},
            {"TW", "🇹🇼"}, {"LV", "🇱🇻"}
        };

        private static readonly string TestUrl = "http://cp.cloudflare.com/generate_204";
        private const int MaxBestResults = 500;
        private const int TestTimeoutMs = 5000;
        private const int AliveCheckTimeoutMs = 2000;
        private const int MaxFilenameRemarkLength = 150;

        // ────────────────────────────────────────────────
        // Blacklist: loaded once at startup
        // ────────────────────────────────────────────────
        private static readonly List<(IPAddress Network, int Mask)> BlacklistCidrs = new();

        private static void LoadBlacklist()
        {
            var blacklistPath = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "blacklist.netset");
            if (!File.Exists(blacklistPath))
            {
                Console.WriteLine("⚠️ No blacklist.netset found - skipping IP blacklist check");
                return;
            }

            var lines = File.ReadAllLines(blacklistPath);
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
                catch { /* invalid line - skip silently */ }
            }
            Console.WriteLine($"Loaded {loaded} blacklist CIDRs from {blacklistPath}");
        }

        private static bool IsBlacklisted(string ipStr)
        {
            if (!IPAddress.TryParse(ipStr, out var ip)) return false;

            foreach (var (network, mask) in BlacklistCidrs)
            {
                if (IsIpInCidr(ip, network, mask)) return true;
            }
            return false;
        }

        private static bool IsIpInCidr(IPAddress ip, IPAddress network, int mask)
        {
            uint ipInt = BitConverter.ToUInt32(ip.GetAddressBytes().Reverse().ToArray(), 0);
            uint networkInt = BitConverter.ToUInt32(network.GetAddressBytes().Reverse().ToArray(), 0);
            uint subnetMask = ~((uint)0 >> mask);

            return (ipInt & subnetMask) == (networkInt & subnetMask);
        }

        public async Task StartAsync()
        {
            LoadBlacklist(); // Load once at startup
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
            int skippedNumbered = 0;
            int parseFail = 0;
            int skippedLongFilename = 0;
            int skippedBlacklisted = 0; // NEW: counter for blacklisted IPs

            Console.WriteLine("\n🧹 Parsing + strict deduplicating + renaming...");
            int processed = 0;
            foreach (var line in rawLines)
            {
                processed++;
                if (processed % 1000 == 0)
                    Console.WriteLine($"  {processed}/{rawLines.Count} ({Math.Round((double)processed / rawLines.Count * 100, 1)}%)");

                var trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed)) continue;

                if (Regex.IsMatch(trimmed, @"\s*\(\d+\)\s*$"))
                {
                    skippedNumbered++;
                    continue;
                }

                var (proto, serverPort, originalRemark) = ParseProxyLine(line);

                if (string.IsNullOrEmpty(serverPort) || !serverPort.Contains(":")) continue;

                var parts = serverPort.Split(':');
                string ipOrHost = parts[0];
                string portStr = parts.Length > 1 ? parts[1] : "443";

                // NEW: Block dangerous/blacklisted IPs
                if (IsBlacklisted(ipOrHost))
                {
                    skippedBlacklisted++;
                    continue;
                }

                string cleanRemark;
                string countryCode = "XX";

                var info = _resolver.GetCountry(ipOrHost);
                countryCode = info.CountryCode?.ToUpperInvariant() ?? "XX";

                if (countryCode == "XX")
                {
                    string lowerHost = ipOrHost.ToLowerInvariant();
                    if (lowerHost.EndsWith(".tw") || lowerHost.Contains("taiwan")) countryCode = "TW";
                    else if (lowerHost.EndsWith(".lv") || lowerHost.Contains("latvia")) countryCode = "LV";
                    else if (lowerHost.EndsWith(".hk") || lowerHost.Contains("hongkong")) countryCode = "HK";
                    else if (lowerHost.EndsWith(".sg") || lowerHost.Contains("singapore")) countryCode = "SG";
                    else if (lowerHost.EndsWith(".jp") || lowerHost.Contains("japan")) countryCode = "JP";
                    else if (lowerHost.EndsWith(".kr") || lowerHost.Contains("korea")) countryCode = "KR";
                    else if (lowerHost.EndsWith(".us") || lowerHost.Contains("unitedstates") || lowerHost.Contains("usa")) countryCode = "US";
                    else if (lowerHost.EndsWith(".gb") || lowerHost.Contains("uk") || lowerHost.Contains("unitedkingdom")) countryCode = "GB";
                    else if (lowerHost.EndsWith(".de") || lowerHost.Contains("germany")) countryCode = "DE";
                    else if (lowerHost.EndsWith(".fr") || lowerHost.Contains("france")) countryCode = "FR";
                    else if (lowerHost.EndsWith(".ru") || lowerHost.Contains("russia")) countryCode = "RU";
                    else if (lowerHost.EndsWith(".ca") || lowerHost.Contains("canada")) countryCode = "CA";
                    else if (lowerHost.EndsWith(".nl") || lowerHost.Contains("netherlands")) countryCode = "NL";
                    else if (lowerHost.EndsWith(".au") || lowerHost.Contains("australia")) countryCode = "AU";
                    else if (lowerHost.EndsWith(".in") || lowerHost.Contains("india")) countryCode = "IN";
                }

                var flag = Flags.TryGetValue(countryCode, out var f) ? f : "🌍";
                string countryName = info.CountryName ?? GetCountryNameFromCode(countryCode);

                cleanRemark = $"{flag} {countryName} - {proto.ToUpper()} - {ipOrHost}:{portStr}";

                if (proto.ToLowerInvariant() == "ss" &&
                    (originalRemark.Length > 30 ||
                     Regex.IsMatch(originalRemark, @"^[a-zA-Z0-9+/=]{20,}$") ||
                     originalRemark.Contains("==") || originalRemark.Contains("/")))
                {
                    cleanRemark = $"{flag} {countryName} - SS - {ipOrHost}:{portStr}";
                }

                var renamedLink = RenameRemarkInLink(line, cleanRemark, proto);

                string dedupKey = $"{proto.ToLowerInvariant()}:{serverPort}#{cleanRemark.Replace(" ", "").ToLowerInvariant()}";

                if (seenNormalized.Add(dedupKey))
                {
                    object clashProxy = GenerateClashProxy(proto, serverPort, line, cleanRemark);
                    renamedProxies.Add((renamedLink, proto, countryCode, serverPort, cleanRemark, clashProxy));
                }
                else
                {
                    parseFail++;
                }
            }

            Console.WriteLine($"Finished → {renamedProxies.Count} unique (dupes skipped: {parseFail}, numbered junk skipped: {skippedNumbered}, blacklisted skipped: {skippedBlacklisted}, long filenames skipped: {skippedLongFilename})");

            var sub = Path.Combine(Directory.GetCurrentDirectory(), "sub");
            var protocolsDir = Path.Combine(sub, "protocols");
            var countriesDir = Path.Combine(sub, "countries");
            Directory.CreateDirectory(sub);
            Directory.CreateDirectory(protocolsDir);
            Directory.CreateDirectory(countriesDir);

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

                string safeKey = key.Length > MaxFilenameRemarkLength
                    ? key.Substring(0, MaxFilenameRemarkLength - 10) + "-" + key.GetHashCode().ToString("x8")
                    : key;

                safeKey = Regex.Replace(safeKey, @"[^a-zA-Z0-9-]", "-");

                var txt = Path.Combine(protocolsDir, $"{safeKey}.txt");
                try
                {
                    await File.WriteAllLinesAsync(txt, g.Select(x => x.Link));
                    Console.WriteLine($" → {txt} ({g.Count()})");
                }
                catch (PathTooLongException)
                {
                    skippedLongFilename++;
                    Console.WriteLine($"Skipped long filename protocol: {key} ({g.Count()} nodes)");
                }

                var json = Path.Combine(protocolsDir, $"{safeKey}.json");
                try
                {
                    await SaveClashJson(json, g.ToList(), $"FastNodes {g.Key.ToUpper()}");
                }
                catch { /* silent */ }
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
                if (p.Proto.ToLowerInvariant() == "vmess") return;

                Interlocked.Increment(ref processed);
                if (processed % 500 == 0)
                    Console.WriteLine($"  Tested {processed}/{proxies.Count} ({Math.Round((double)processed / proxies.Count * 100, 1)}%)");

                if (!await IsProxyAliveAsync(p.Link)) return;

                int latency = await TestProxyLatencyAsync(p.Link);
                if (latency > 0 && latency < 1500)
                    tested.Add((p.Link, latency, p.ClashProxy));
            });

            var sorted = tested.OrderBy(t => t.Latency).ToList();

            var bestDir = Path.Combine(Directory.GetCurrentDirectory(), "Best-Results");
            Directory.CreateDirectory(bestDir);

            var limits = new[] { 100, 200, 300, 400, 500 };
            foreach (var limit in limits)
            {
                var topN = sorted.Take(limit).ToList();

                var txtPath = Path.Combine(bestDir, $"top{limit}.txt");
                await File.WriteAllLinesAsync(txtPath, topN.Select(t => $"{t.Link} # latency={t.Latency}ms"));
                Console.WriteLine($"Saved Best-Results/top{limit}.txt ({topN.Count})");

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
                Console.WriteLine($"Saved Best-Results/top{limit}.json ({topN.Count})");
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
                            string uuid = obj.TryGetProperty("id", out var idProp) && idProp.ValueKind != JsonValueKind.Null
                                ? idProp.GetString() ?? ""
                                : "";
                            int alterId = obj.TryGetProperty("aid", out var aidProp) && aidProp.ValueKind != JsonValueKind.Null
                                ? aidProp.GetInt32()
                                : 0;
                            string cipher = obj.TryGetProperty("scy", out var scyProp) && scyProp.ValueKind != JsonValueKind.Null
                                ? scyProp.GetString() ?? "auto"
                                : "auto";
                            bool tls = obj.TryGetProperty("tls", out var tlsProp) && tlsProp.ValueKind != JsonValueKind.Null
                                && tlsProp.GetString() == "tls";
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

                    if (string.IsNullOrWhiteSpace(decoded))
                        return baseLink + "#" + Uri.EscapeDataString(newRemark);

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
                catch
                {
                    // Silent - no spam
                }
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
                if (port == "443" || port == "8443" || port == "2053") guessedProto = "vless";
                else if (port == "80" || port == "8080") guessedProto = "ss";
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
