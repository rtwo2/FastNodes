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
using System.Diagnostics;  // For Process
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
            // ... (full flags dict as before)
        };

        private static readonly string[] TestUrls = {
            "http://aparat.com/generate_204",
            "http://varzesh3.com/generate_204",
            "http://www.google.com/generate_204",
            "http://cp.cloudflare.com/generate_204",
            "http://twitter.com/generate_204"
        };

        private const int MaxBestResults = 500;
        private const int TestTimeoutMs = 15000;  // Raised for Iran
        private const int AliveCheckTimeoutMs = 4000;
        private const int QuickCandidates = 2000;  // Top N for full test
        private const int BatchSize = 10;  // Parallel sing-box instances

        private static readonly List<(IPAddress Network, int Mask)> BlacklistCidrs = new();

        private static async Task DownloadFreshGeoIP(HttpClient http)
        {
            // ... (same as before)
        }

        private static async Task DownloadFreshFireHOLBlacklist(HttpClient http)
        {
            // ... (same as before)
        }

        private static async Task DownloadFreshBogons(HttpClient http)
        {
            // ... (same as before)
        }

        private static void LoadAllBlacklists()
        {
            // ... (same as before)
        }

        private static bool IsBlacklisted(string ipStr)
        {
            // ... (same as before)
        }

        private static bool IsIpInCidr(IPAddress ip, IPAddress net, int mask)
        {
            // ... (same as before)
        }

        public async Task StartAsync()
        {
            // ... (same as before)
        }

        private async Task RunFullCollectionMode()
        {
            // ... (same fetching, parsing loop as your lighter version)
        }

        private string GetCountryNameFromCode(string code)
        {
            // ... (same as before)
        }

        private async Task GenerateBestResultsAsync(List<(string Link, string Proto, string CountryCode, string ServerPort, string Remark, object ClashProxy)> proxies)
        {
            Console.WriteLine($"\n🏆 Quick raw testing {proxies.Count} proxies for candidates...");
            var quickTested = new ConcurrentBag<(string Link, int Latency, string Proto, object ClashProxy)>();
            await Parallel.ForEachAsync(proxies, new ParallelOptions { MaxDegreeOfParallelism = 20 }, async (p, ct) =>
            {
                int latency = await QuickRawLatencyAsync(p.Link);
                if (latency > 0 && latency < 1500)
                    quickTested.Add((p.Link, latency, p.Proto, p.ClashProxy));
            });

            var candidates = quickTested.OrderBy(t => t.Latency).Take(QuickCandidates).ToList();
            Console.WriteLine($"Found {candidates.Count} quick candidates — now full tunneling test...");

            var fullTested = new ConcurrentBag<(string Link, int Latency, object ClashProxy)>();
            var batches = candidates.Chunk(BatchSize);
            foreach (var batch in batches)
            {
                var tasks = batch.Select(async c =>
                {
                    if (await IsProxyAliveFullAsync(c.Link, c.Proto))
                    {
                        int latency = await TestProxyLatencyFullAsync(c.Link, c.Proto);
                        if (latency > 0) fullTested.Add((c.Link, latency, c.ClashProxy));
                    }
                });
                await Task.WhenAll(tasks);
            }

            var sorted = fullTested.OrderBy(t => t.Latency).ToList();
            // ... (save top100/200/etc as before)
        }

        private async Task<int> QuickRawLatencyAsync(string link)
        {
            // Simple raw test (your original, multiple URLs average)
            int total = 0;
            int count = 0;
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
                        count++;
                    }
                }
                catch { }
            }
            return count > 0 ? total / count : -1;
        }

        private async Task<bool> IsProxyAliveFullAsync(string link, string proto)
        {
            string configPath = $"temp_sing_{Guid.NewGuid().ToString("N")}.json";
            int port = Interlocked.Increment(ref _basePort) % 10 + 10800;  // Unique port 10800-10809
            string localSocks = $"127.0.0.1:{port}";

            var config = GenerateSingBoxConfig(link, proto, localSocks);
            await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(config));

            var process = StartSingBox(configPath);
            await Task.Delay(1000);  // Startup wait

            bool alive = false;
            try
            {
                var proxy = new WebProxy(localSocks);
                using var client = new HttpClient(new HttpClientHandler { Proxy = proxy }) { Timeout = TimeSpan.FromMilliseconds(AliveCheckTimeoutMs) };
                var resp = await client.GetAsync(TestUrls[0]);
                alive = resp.IsSuccessStatusCode;
            }
            catch { }

            process.Kill();
            File.Delete(configPath);
            return alive;
        }

        private async Task<int> TestProxyLatencyFullAsync(string link, string proto)
        {
            string configPath = $"temp_sing_{Guid.NewGuid().ToString("N")}.json";
            int port = Interlocked.Increment(ref _basePort) % 10 + 10800;
            string localSocks = $"127.0.0.1:{port}";

            var config = GenerateSingBoxConfig(link, proto, localSocks);
            await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(config));

            var process = StartSingBox(configPath);
            await Task.Delay(1000);

            int total = 0;
            int count = 0;
            foreach (var url in TestUrls)
            {
                try
                {
                    var proxy = new WebProxy(localSocks);
                    using var client = new HttpClient(new HttpClientHandler { Proxy = proxy }) { Timeout = TimeSpan.FromMilliseconds(TestTimeoutMs) };
                    var start = DateTime.UtcNow;
                    var resp = await client.GetAsync(url);
                    if (resp.IsSuccessStatusCode)
                    {
                        total += (int)(DateTime.UtcNow - start).TotalMilliseconds;
                        count++;
                    }
                }
                catch { }
            }

            process.Kill();
            File.Delete(configPath);
            return count > 0 ? total / count : -1;
        }

        private Process StartSingBox(string configPath)
        {
            var process = new Process
            {
                StartInfo = new ProcessStartInfo
                {
                    FileName = "sing-box",
                    Arguments = $"run -c {configPath}",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                }
            };
            process.Start();
            return process;
        }

        private object GenerateSingBoxConfig(string link, string proto, string localSocks)
        {
            // Parse link (use your ParseProxyLine + more)
            var (protocol, serverPort, remark) = ParseProxyLine(link);
            var parts = serverPort.Split(':');
            string server = parts[0];
            int port = int.Parse(parts[1]);
            string uuid = "";  // Extract from link (adapt for each proto)
            // For simplicity, pseudo-parse (expand per proto)
            var outbound = new { type = protocol, server, port, uuid /* etc */ };

            return new
            {
                log = new { level = "error" },
                inbounds = new[] { new { type = "socks", listen = "127.0.0.1", listen_port = int.Parse(localSocks.Split(':')[1]) } },
                outbounds = new[] { outbound, new { type = "direct", tag = "direct" } },
                route = new { rules = new[] { new { outbound = outbound.type } } }
            };
        }

        // ... (rest of your class: NormalizeProto, SaveClashJson, GenerateClashProxy, RenameRemarkInLink, ParseProxyLine, DecodeBase64)
    }
}
