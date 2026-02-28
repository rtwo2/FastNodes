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

        private static int _basePort = 10800; // for batch sing-box ports

        private static readonly HashSet<string> ValidProtocols = new(StringComparer.OrdinalIgnoreCase)
        {
            "vmess", "vless", "trojan", "ss", "shadowsocks", "hysteria2", "hy2", "tuic", "socks", "socks5", "anytls"
        };

        private static readonly Dictionary<string, string> Flags = new(StringComparer.OrdinalIgnoreCase)
        {
            {"AD", "🇦🇩"}, {"AE", "🇦🇪"}, /* ... full dictionary as in your original code ... */ {"ZW", "🇿🇼"}
        };

        private static readonly string[] TestUrls = {
            "http://aparat.com/generate_204",
            "http://varzesh3.com/generate_204",
            "http://www.google.com/generate_204",
            "http://cp.cloudflare.com/generate_204",
            "http://twitter.com/generate_204"
        };

        private const int MaxBestResults = 500;
        private const int TestTimeoutMs = 15000;
        private const int AliveCheckTimeoutMs = 4000;
        private const int QuickCandidatesLimit = 2000;
        private const int SingBoxBatchSize = 10;

        private static readonly List<(IPAddress Network, int Mask)> BlacklistCidrs = new();

        // ... DownloadFreshGeoIP, DownloadFreshFireHOLBlacklist, DownloadFreshBogons, LoadAllBlacklists (keep as is)

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
            await RunFullCollectionMode();
        }

        private async Task RunFullCollectionMode()
        {
            // Keep your existing fetching + parsing logic here
            // Assume it populates List<(string Link, string Proto, ...)> renamedProxies
            // Then call:
            await GenerateBestResultsAsync(renamedProxies);
            // ... save everything.txt, protocols/*.txt, countries/*.txt, etc.
        }

        private async Task GenerateBestResultsAsync(List<(string Link, string Proto, string CountryCode, string ServerPort, string Remark, object ClashProxy)> proxies)
        {
            Console.WriteLine($"\n🏆 Quick raw multi-URL testing {proxies.Count} proxies...");
            var quickResults = new ConcurrentBag<(string Link, int Latency, string Proto, object ClashProxy)>();

            await Parallel.ForEachAsync(proxies, new ParallelOptions { MaxDegreeOfParallelism = 30 }, async (p, ct) =>
            {
                int latency = await QuickRawLatencyAsync(p.Link);
                if (latency > 0 && latency < 2000)
                    quickResults.Add((p.Link, latency, p.Proto, p.ClashProxy));
            });

            var candidates = quickResults.OrderBy(x => x.Latency).Take(QuickCandidatesLimit).ToList();
            Console.WriteLine($" → {candidates.Count} quick candidates passed → starting full sing-box tunnel test...");

            var fullResults = new ConcurrentBag<(string Link, int Latency, object ClashProxy)>();

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

            var sorted = fullResults.OrderBy(x => x.Latency).ToList();
            Console.WriteLine($"Full tunnel test complete: {sorted.Count} usable proxies");

            // Save top N files (keep your existing save logic)
            var bestDir = Path.Combine(Directory.GetCurrentDirectory(), "sub", "Best-Results");
            Directory.CreateDirectory(bestDir);

            foreach (var limit in new[] { 100, 200, 300, 400, 500 })
            {
                var top = sorted.Take(limit).ToList();
                await File.WriteAllLinesAsync(
                    Path.Combine(bestDir, $"top{limit}.txt"),
                    top.Select(t => $"{t.Link} # latency={t.Latency}ms")
                );
                // ... json save as before
            }
        }

        private async Task<int> QuickRawLatencyAsync(string link)
        {
            int total = 0, success = 0;
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
            return success > 0 ? total / success : -1;
        }

        private async Task<bool> IsProxyAliveFullAsync(string link, string proto)
        {
            string configPath = Path.GetTempFileName() + ".json";
            int localPort = Interlocked.Increment(ref _basePort) % SingBoxBatchSize + 10800;
            string socksAddr = $"127.0.0.1:{localPort}";

            var config = GenerateSingBoxConfig(link, proto, localPort);
            if (config == null) return false;

            await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(config));

            using var process = StartSingBox(configPath);
            await Task.Delay(1200); // give time to start

            bool alive = false;
            try
            {
                var handler = new HttpClientHandler { Proxy = new WebProxy(socksAddr) };
                using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(AliveCheckTimeoutMs) };
                var resp = await client.GetAsync(TestUrls[0]);
                alive = resp.IsSuccessStatusCode;
            }
            catch { }

            process.Kill(true);
            try { File.Delete(configPath); } catch { }
            return alive;
        }

        private async Task<int> TestProxyLatencyFullAsync(string link, string proto)
        {
            string configPath = Path.GetTempFileName() + ".json";
            int localPort = Interlocked.Increment(ref _basePort) % SingBoxBatchSize + 10800;
            string socksAddr = $"127.0.0.1:{localPort}";

            var config = GenerateSingBoxConfig(link, proto, localPort);
            if (config == null) return -1;

            await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(config));

            using var process = StartSingBox(configPath);
            await Task.Delay(1200);

            int total = 0, success = 0;
            foreach (var url in TestUrls)
            {
                try
                {
                    var handler = new HttpClientHandler { Proxy = new WebProxy(socksAddr) };
                    using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMilliseconds(TestTimeoutMs) };
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

            process.Kill(true);
            try { File.Delete(configPath); } catch { }

            return success > 0 ? total / success : -1;
        }

        private Process StartSingBox(string configPath)
        {
            var psi = new ProcessStartInfo
            {
                FileName = "sing-box",
                Arguments = $"run -c \"{configPath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            var p = new Process { StartInfo = psi };
            p.Start();
            return p;
        }

        private object? GenerateSingBoxConfig(string link, string proto, int localPort)
        {
            // Very basic skeleton — expand this per protocol!
            // You need to parse uuid, password, flow, etc. from link
            // For now returning null on unknown to skip

            string server = "unknown";
            int port = 443;
            string uuidOrPass = "";

            try
            {
                var uri = new Uri(link);
                server = uri.Host;
                port = uri.Port > 0 ? uri.Port : 443;
                if (proto == "vless" || proto == "vmess")
                    uuidOrPass = uri.UserInfo; // rough
            }
            catch { return null; }

            var outbound = proto.ToLowerInvariant() switch
            {
                "vless" => new { type = "vless", server, server_port = port, uuid = uuidOrPass, tls = new { enabled = true } },
                "vmess" => new { type = "vmess", server, server_port = port, uuid = uuidOrPass, alter_id = 0, security = "auto", tls = new { enabled = true } },
                "ss" => new { type = "shadowsocks", server, server_port = port, method = "aes-256-gcm", password = uuidOrPass },
                "trojan" => new { type = "trojan", server, server_port = port, password = uuidOrPass, tls = new { enabled = true } },
                _ => null
            };

            if (outbound == null) return null;

            return new
            {
                log = new { level = "fatal" },
                inbounds = new[]
                {
                    new { type = "socks", tag = "socks-in", listen = "127.0.0.1", listen_port = localPort }
                },
                outbounds = new[] { outbound, new { type = "direct", tag = "direct" } },
                route = new
                {
                    rules = new[]
                    {
                        new { outbound = outbound.type }
                    }
                }
            };
        }

        // Keep all your other methods: ParseProxyLine, RenameRemarkInLink, GenerateClashProxy, etc.
    }
}
