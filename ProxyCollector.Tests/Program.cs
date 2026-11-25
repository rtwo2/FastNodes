using System.Net;
using System.IO;
using System.IO.Compression;
using System.Threading;
using ProxyCollector.Services;
using YamlDotNet.RepresentationModel;
using System.Text;
using System.Text.Json;
using CollectorType = ProxyCollector.Collector.ProxyCollector;

internal static class Program
{
    private static void Main()
    {
        Checks.Equal(3, ProxyCollector.Configuration.CollectorConfig.ApplySourceLimit(new[] { "a", "b", "c" }, 0).Length,
            "zero source limit preserves full production source list");

        Checks.Equal(0, CollectorType.CountRawLines(""),
            "empty source bodies contain zero raw lines");
        Checks.Equal(1, CollectorType.CountRawLines("one\n"),
            "a trailing newline does not create a phantom raw line");
        Checks.Equal(2, CollectorType.CountRawLines("one\r\ntwo\r\n"),
            "CRLF-terminated source bodies count physical lines correctly");
        Checks.Equal(2, CollectorType.CountRawLines("one\ntwo"),
            "a non-terminated final source line is still counted");

        var untouchedHistory = new ProxyCollector.Collector.NodeHistory { TlsOk = 7, XrayOk = 8 };
        var untestedNode = new ProxyCollector.Collector.ParsedProxy();
        CollectorType.UpdateVerificationStreaks(untouchedHistory, untestedNode);
        Checks.Equal(7, untouchedHistory.TlsOk,
            "an untested TLS node retains its previous success streak");
        Checks.Equal(8, untouchedHistory.XrayOk,
            "an untested Xray node retains its previous success streak");
        Checks.Equal(7, untestedNode.VerifiedStreak,
            "the current proxy carries forward its untouched TLS streak");
        Checks.Equal(8, untestedNode.XrayStreak,
            "the current proxy carries forward its untouched Xray streak");

        var failedProbeNode = new ProxyCollector.Collector.ParsedProxy
        {
            TlsTested = true, XrayTested = true
        };
        CollectorType.UpdateVerificationStreaks(untouchedHistory, failedProbeNode);
        Checks.Equal(6, untouchedHistory.TlsOk,
            "an attempted TLS failure decays the TLS streak by one");
        Checks.Equal(7, untouchedHistory.XrayOk,
            "an attempted Xray failure decays the Xray streak by one");

        var passedProbeNode = new ProxyCollector.Collector.ParsedProxy
        {
            TlsTested = true, TlsVerified = true,
            XrayTested = true, XrayVerified = true
        };
        CollectorType.UpdateVerificationStreaks(untouchedHistory, passedProbeNode);
        Checks.Equal(7, untouchedHistory.TlsOk,
            "a successful TLS probe increments the TLS streak");
        Checks.Equal(8, untouchedHistory.XrayOk,
            "a successful Xray probe increments the Xray streak");

        var interleavedFamilies = HappyEyeballsConnector.OrderAddresses(new[]
        {
            IPAddress.Parse("192.0.2.1"), IPAddress.Parse("192.0.2.2"),
            IPAddress.Parse("2001:db8::1"), IPAddress.Parse("2001:db8::2")
        });
        Checks.That(interleavedFamilies.SequenceEqual(new[]
            {
                IPAddress.Parse("192.0.2.1"), IPAddress.Parse("2001:db8::1"),
                IPAddress.Parse("192.0.2.2"), IPAddress.Parse("2001:db8::2")
            }),
            "Happy Eyeballs interleaves IPv4 and IPv6 while preserving each resolver family order");

        Checks.Equal(1024, SourceFetchBudget.GetReservationBytes(1024, false, 8192),
            "uncompressed source responses reserve their declared working-set size");
        Checks.Equal(8192, SourceFetchBudget.GetReservationBytes(1024, true, 8192),
            "compressed source responses reserve their decompressed maximum, not compressed Content-Length");
        Checks.Equal(8192, SourceFetchBudget.GetReservationBytes(null, false, 8192),
            "unknown-length source responses reserve the configured maximum");
        Checks.Equal(8192, SourceFetchBudget.GetReservationBytes(16384, false, 8192),
            "declared source lengths above the hard cap reserve the full bounded ceiling");

        var memoryBudget = new SourceFetchBudget(4L * 1024 * 1024, 4L * 1024 * 1024);
        {
            var firstReservation = memoryBudget.AcquireSourceAsync(1024 * 1024, CancellationToken.None)
                .GetAwaiter().GetResult();
            var waitingReservation = memoryBudget.AcquireSourceAsync(1024 * 1024, CancellationToken.None).AsTask();
            Thread.Sleep(30);
            Checks.That(!waitingReservation.IsCompleted,
                "source fetch memory reservations apply backpressure at the configured process budget");
            firstReservation.Dispose();
            using var secondReservation = waitingReservation.GetAwaiter().GetResult();
        }

        using (var spool = new SourceSpoolStore())
        {
            spool.WriteSourceAsync(1, new[] { "later-source-line" }, CancellationToken.None).GetAwaiter().GetResult();
            spool.WriteSourceAsync(0, new[] { "priority-first-line" }, CancellationToken.None).GetAwaiter().GetResult();
            spool.AppendSourceAsync(0, new[] { "provider-appended-line" }, CancellationToken.None).GetAwaiter().GetResult();
            Checks.That(spool.ReadSourceLines(0).SequenceEqual(new[] { "priority-first-line", "provider-appended-line" }),
                "source spool appends provider lines after root lines without changing per-source order");
            Checks.That(spool.ReadSourceLines(1).SequenceEqual(new[] { "later-source-line" }),
                "source spool keeps independently fetched feeds separate");
        }

        var sourcePriority = new Dictionary<string, int>(StringComparer.Ordinal)
        {
            ["priority-a"] = 0,
            ["priority-b"] = 1
        };
        var unorderedSourceLines = new[]
        {
            (Url: "priority-b", LineIndex: 1, Line: "b-second"),
            (Url: "priority-a", LineIndex: 1, Line: "a-second"),
            (Url: "priority-b", LineIndex: 0, Line: "b-first"),
            (Url: "priority-a", LineIndex: 0, Line: "a-first")
        };
        var orderedSourceLines = CollectorType.OrderSourceLines(unorderedSourceLines, sourcePriority);
        Checks.That(orderedSourceLines.SequenceEqual(new (string Url, string Line)[]
            {
                ("priority-a", "a-first"),
                ("priority-a", "a-second"),
                ("priority-b", "b-first"),
                ("priority-b", "b-second")
            }),
            "parallel source fetch completion order cannot change first-contributor attribution");

        var distinctProviderUrls = CollectorType.DeduplicateProviderUrls(new[]
        {
            "https://example.net/Main.txt",
            "https://example.net/main.txt",
            "https://example.net/Main.txt"
        });
        Checks.Equal(2, distinctProviderUrls.Count,
            "provider URL dedup preserves case-sensitive paths while collapsing exact repeats");

        var expectedEdgeBatchIds = new HashSet<int> { 10, 11 };
        Checks.That(CollectorType.IsValidEdgeResultId(10, expectedEdgeBatchIds, 25),
            "a result ID inside the current Worker batch is accepted");
        Checks.That(!CollectorType.IsValidEdgeResultId(12, expectedEdgeBatchIds, 25),
            "a result ID belonging to another Worker batch is rejected");
        Checks.That(!CollectorType.IsValidEdgeResultId(-1, expectedEdgeBatchIds, 25),
            "a negative Worker result ID is rejected");
        Checks.That(!CollectorType.IsValidEdgeResultId(25, expectedEdgeBatchIds, 25),
            "an out-of-range Worker result ID is rejected");
        Checks.That(CollectorType.IsValidEdgeSniEcho("tls.example.net", "TLS.EXAMPLE.NET", "endpoint.example.net"),
            "edge verification accepts a case-insensitive echo of the requested TLS SNI");
        Checks.That(CollectorType.IsValidEdgeSniEcho("endpoint.example.net", null, "endpoint.example.net"),
            "legacy edge results remain usable when endpoint hostname is also the intended SNI");
        Checks.That(!CollectorType.IsValidEdgeSniEcho("tls.example.net", null, "endpoint.example.net"),
            "edge verification does not credit a legacy host-only result for a different explicit SNI");
        Checks.That(!CollectorType.IsValidEdgeSniEcho("tls.example.net", "other.example.net", "endpoint.example.net"),
            "edge verification rejects a result for a different TLS SNI");
        Checks.That(CollectorType.IsEdgeProbeSniSupported("endpoint.example.net", null),
            "the current edge Worker supports an implicit endpoint-hostname SNI");
        Checks.That(CollectorType.IsEdgeProbeSniSupported("endpoint.example.net", "ENDPOINT.EXAMPLE.NET"),
            "the current edge Worker supports an explicit SNI matching the endpoint hostname case-insensitively");
        Checks.That(!CollectorType.IsEdgeProbeSniSupported("endpoint.example.net", "tls.example.net"),
            "the current edge Worker skips custom SNI rather than falsely verifying it");
        Checks.That(ProxyCollector.Configuration.CollectorConfig.ApplySourceLimit(new[] { "a", "b", "c", "d" }, 2)
                .SequenceEqual(new[] { "a", "b" }),
            "positive source limit selects only the first N sources in priority order");
        Checks.Equal(3, ProxyCollector.Configuration.CollectorConfig.ApplySourceLimit(new[] { "a", "b", "c" }, 10).Length,
            "source limit larger than the list keeps all available sources");
        var distinctSources = ProxyCollector.Configuration.CollectorConfig.NormalizeAndDeduplicateSources(new[]
        {
            "https://EXAMPLE.com/Main.txt?channel=ABC",
            "https://example.com/Main.txt?channel=ABC",
            "https://example.com/main.txt?channel=ABC",
            "https://example.com/Main.txt?channel=abc",
            "https://github.com/Owner/Repo/raw/main/Feed.txt",
            "https://RAW.githubusercontent.com/Owner/Repo/main/Feed.txt"
        });
        Checks.Equal(4, distinctSources.Length,
            "source dedup normalizes host case and equivalent GitHub raw URLs without folding path or query-value case");

        var rawRepoSource = "https://raw.githubusercontent.com/alpha/repo/main/nodes.txt";
        var cdnRepoSource = "https://cdn.jsdelivr.net/gh/alpha/repo@main/other/nodes.txt";
        Checks.Equal(CollectorType.GetSourceDiversityGroup(rawRepoSource),
            CollectorType.GetSourceDiversityGroup(cdnRepoSource),
            "raw GitHub and jsDelivr feeds from one repository share one consensus identity");
        Checks.That(CollectorType.GetSourceDiversityGroup(rawRepoSource) !=
                    CollectorType.GetSourceDiversityGroup("https://raw.githubusercontent.com/alpha/another-repo/main/nodes.txt"),
            "different upstream repositories retain separate consensus identities");
        Checks.That(CollectorType.IsIranTestedSource(
            "https://raw.githubusercontent.com/F0rc3Run/F0rc3Run/refs/heads/main/Best-Results/proxies.txt"),
            "explicitly trusted tested-source repository/path receives the delegated evidence signal");
        Checks.That(!CollectorType.IsIranTestedSource(
            "https://raw.githubusercontent.com/random-owner/random-repo/main/HighSpeed.txt"),
            "a generic HighSpeed filename cannot grant trusted source evidence");
        Checks.That(!CollectorType.IsIranTestedSource(
            "https://raw.githubusercontent.com/10Dream/sub-mod/main/sub/base64/F0rc3Run_vless"),
            "an aggregator mirror mentioning F0rc3Run is not mistaken for the original tested source");
        Checks.That(!CollectorType.IsIranTestedSource(
            "https://raw.githubusercontent.com/hamedcode/port-based-v2ray-configs/main/sub/top100.txt"),
            "an unrelated top100 feed does not inherit the trusted source signal");

        Checks.Equal(256 * 1024 * 1024,
            CollectorType.GetSourceResponseByteLimit("https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vl.txt"),
            "the known oversized sevcator VLESS feed gets the larger response cap");
        Checks.Equal(64 * 1024 * 1024,
            CollectorType.GetSourceResponseByteLimit("https://raw.githubusercontent.com/example/proxies/main/list.txt"),
            "ordinary source feeds retain the default 64 MiB response cap");
        Checks.Equal(64 * 1024 * 1024,
            CollectorType.GetSourceResponseByteLimit("https://raw.githubusercontent.com/sevcator/5ubscrpt10n/main/protocols/vmess.txt"),
            "the larger response cap does not apply to unrelated files in the same repository");

        using (var exactContent = new ByteArrayContent(Encoding.UTF8.GetBytes("12345678")))
        {
            Checks.Equal("12345678",
                SourceFetcher.ReadContentLimitedAsync(exactContent, 8, CancellationToken.None).GetAwaiter().GetResult(),
                "bounded HTTP reader accepts a body exactly at its byte limit");
        }
        var oversizedContent = new ByteArrayContent(Encoding.UTF8.GetBytes("123456789"));
        bool oversizedBodyRejected = false;
        try
        {
            _ = SourceFetcher.ReadContentLimitedAsync(oversizedContent, 8, CancellationToken.None)
                .GetAwaiter().GetResult();
        }
        catch (InvalidDataException) { oversizedBodyRejected = true; }
        finally { oversizedContent.Dispose(); }
        Checks.That(oversizedBodyRejected,
            "bounded HTTP reader rejects bodies larger than its byte limit");

        string splitTestRoot = Path.Combine(Path.GetTempPath(), "FastNodes-split-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(splitTestRoot);
        try
        {
            int byteSplitParts = CollectorType.WriteSubscriptionPartsAsync(
                Path.Combine(splitTestRoot, "everything"),
                new[] { "abc", "éé", "x" },
                maxBytes: 6).GetAwaiter().GetResult();
            Checks.Equal(3, byteSplitParts,
                "subscription feeds split at the byte ceiling even when the line count is small");
            Checks.Equal("abc\n", File.ReadAllText(Path.Combine(splitTestRoot, "everything.txt")),
                "the first byte-limited chunk keeps the stable base filename");
            Checks.Equal("éé\n", File.ReadAllText(Path.Combine(splitTestRoot, "everything_part2.txt")),
                "UTF-8 byte accounting creates the second chunk with the established _part2 suffix");
            Checks.Equal("x\n", File.ReadAllText(Path.Combine(splitTestRoot, "everything_part3.txt")),
                "additional byte overflow continues with monotonically numbered part files");
            Checks.That(Directory.GetFiles(splitTestRoot, "everything*.txt")
                    .All(file => new FileInfo(file).Length <= 6),
                "every generated subscription part stays within its configured byte ceiling");

            int lineSplitParts = CollectorType.WriteSubscriptionPartsAsync(
                Path.Combine(splitTestRoot, "protocols-vless"),
                new[] { "one", "two", "three" },
                maxBytes: 100,
                maxLinesPerPart: 2).GetAwaiter().GetResult();
            Checks.Equal(2, lineSplitParts,
                "the existing category node-count chunking remains active alongside the byte ceiling");
            Checks.Equal("one\ntwo\n", File.ReadAllText(Path.Combine(splitTestRoot, "protocols-vless.txt")),
                "category part one retains its first 1,000-node-style chunk contract");
            Checks.Equal("three\n", File.ReadAllText(Path.Combine(splitTestRoot, "protocols-vless_part2.txt")),
                "category overflow retains the established _part2 filename");

            bool singleOversizedLineRejected = false;
            try
            {
                CollectorType.WriteSubscriptionPartsAsync(
                    Path.Combine(splitTestRoot, "oversized"),
                    new[] { "123456" },
                    maxBytes: 6).GetAwaiter().GetResult();
            }
            catch (InvalidDataException) { singleOversizedLineRejected = true; }
            Checks.That(singleOversizedLineRejected,
                "a single entry larger than the part limit fails instead of creating an oversized file");
        }
        finally
        {
            if (Directory.Exists(splitTestRoot))
                Directory.Delete(splitTestRoot, recursive: true);
        }

        var invalidDatabasePath = Path.Combine(Path.GetTempPath(), $"fastnodes-invalid-{Guid.NewGuid():N}.mmdb");
        try
        {
            File.WriteAllText(invalidDatabasePath, "interrupted download or HTML error body");
            Checks.That(!CollectorType.IsValidGeoIpDatabase(invalidDatabasePath),
                "a non-empty invalid GeoIP file must not be treated as a valid cached database");
        }
        finally
        {
            if (File.Exists(invalidDatabasePath)) File.Delete(invalidDatabasePath);
        }


        Checks.That(CollectorType.IsPrivateOrReservedIp(IPAddress.IPv6Any),
            "IPv6 unspecified address is rejected as a public proxy endpoint");
        Checks.That(CollectorType.IsPrivateOrReservedIp(IPAddress.Parse("ff02::1")),
            "IPv6 multicast address is rejected as a public proxy endpoint");
        Checks.That(CollectorType.IsPlaceholderCredential("ss", "aes-128-gcm:password123"),
            "placeholder Shadowsocks password is detected after the cipher separator");
        Checks.That(CollectorType.IsPlaceholderCredential("tuic", "123e4567-e89b-12d3-a456-426614174000:123456"),
            "placeholder TUIC password is detected after the UUID separator");
        Checks.That(CollectorType.IsPlaceholderCredential("socks5", "user:your-password"),
            "placeholder SOCKS password is detected after the username separator");
        Checks.That(CollectorType.IsPlaceholderCredential("trojan", "password%31%32%33"),
            "percent-encoded placeholder credentials are detected after URI decoding");
        Checks.That(CollectorType.IsPlaceholderCredential("ss", "aes-128-gcm:password%31%32%33"),
            "percent-encoded placeholder passwords are detected inside composite credentials");
        Checks.That(!CollectorType.IsPlaceholderCredential("ss", "aes-128-gcm:real-secret"),
            "valid composite Shadowsocks credentials are not rejected");

        Checks.That(!CollectorType.IsPrivateOrReservedIp(IPAddress.Parse("2001:4860:4860::8888")),
            "public IPv6 unicast address remains eligible");
        Checks.That(!CollectorType.IsPrivateOrReservedIp(IPAddress.Parse("2001:4860:4860:4860:4860:ffff:a00:1")),
            "a global IPv6 address containing an ffff hextet is not mistaken for IPv4-mapped private space");
        Checks.Equal("[2001:db8::1]:51820", CollectorType.FormatWireguardEndpoint("2001:db8::1", 51820),
            "WireGuard .conf endpoint formatting brackets IPv6 literals");
        Checks.Equal("192.0.2.1:51820", CollectorType.FormatWireguardEndpoint("192.0.2.1", 51820),
            "WireGuard .conf endpoint formatting leaves IPv4 literals unbracketed");
        Checks.That(CollectorType.IsValidWireguardIpList("10.0.0.2/32, fd00::2/128", false),
            "WireGuard interface address validation accepts valid IPv4 and IPv6 CIDRs");
        Checks.That(!CollectorType.IsValidWireguardIpList("10.0.0.2/32\nPostUp=touch /tmp/pwned", false),
            "WireGuard interface addresses reject newline directive injection");
        Checks.That(!CollectorType.IsValidWireguardDns("1.1.1.1\nPostUp=touch /tmp/pwned"),
            "WireGuard DNS settings reject newline directive injection");
        Checks.That(!CollectorType.IsValidWireguardIpList("0.0.0.0/0, :::/0", true),
            "WireGuard AllowedIPs validation rejects malformed CIDRs");
        Checks.That(!CollectorType.IsValidWireguardOutputFields("example.com", 0, "10.0.0.2/32", "1.1.1.1", "0.0.0.0/0"),
            "WireGuard output field validation rejects port zero");
        Checks.That(!CollectorType.IsValidWireguardOutputFields("example.com\nPostUp=bad", 51820, "10.0.0.2/32", "1.1.1.1", "0.0.0.0/0"),
            "WireGuard output field validation rejects directive injection in endpoint host");
        Checks.That(!CollectorType.IsValidWireguardOutputFields("example.com", 51820, "10.0.0.2/32", "1.1.1.1", "0.0.0.0/0", new[] { "1", "2", "300" }),
            "WireGuard reserved bytes must be three values in byte range");
        var hostileName = "node\"\n  - type: trojan\n    server: injected.example";
        var safeYaml = CollectorType.SerializeWireguardClashYaml(new[]
        {
            new Dictionary<string, object?>
            {
                ["name"] = hostileName, ["type"] = "wireguard", ["server"] = "example.com",
                ["port"] = 51820, ["ip"] = "10.0.0.2/32", ["allowed-ips"] = "0.0.0.0/0, ::/0"
            }
        });

        var manyWireguardNodes = Enumerable.Range(0, 1001)
            .Select(index => new Dictionary<string, object?>
            {
                ["name"] = $"wg-{index:D4}", ["type"] = "wireguard", ["server"] = "wg.example.net",
                ["port"] = 51820, ["ip"] = "10.0.0.2/32",
                ["public-key"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                ["private-key"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                ["allowed-ips"] = "0.0.0.0/0, ::/0"
            }).ToList();
        var wireguardYamlParts = CollectorType.SerializeWireguardClashYamlParts(manyWireguardNodes);
        Checks.Equal(2, wireguardYamlParts.Count,
            "large WireGuard protocol feeds are split into valid YAML parts rather than raw URI overflow files");
        var firstWireguardPart = new YamlStream();
        firstWireguardPart.Load(new StringReader(wireguardYamlParts[0]));
        var firstWireguardRoot = (YamlMappingNode)firstWireguardPart.Documents[0].RootNode;
        var firstWireguardEntries = (YamlSequenceNode)firstWireguardRoot.Children[new YamlScalarNode("proxies")];
        Checks.Equal(1000, firstWireguardEntries.Children.Count,
            "the first WireGuard YAML part respects the 1000-node part cap");
        var secondWireguardPart = new YamlStream();
        secondWireguardPart.Load(new StringReader(wireguardYamlParts[1]));
        var secondWireguardRoot = (YamlMappingNode)secondWireguardPart.Documents[0].RootNode;
        var secondWireguardEntries = (YamlSequenceNode)secondWireguardRoot.Children[new YamlScalarNode("proxies")];
        Checks.Equal(1, secondWireguardEntries.Children.Count,
            "the final WireGuard YAML part contains only its remaining proxy");
        var rawProtocolGroups = CollectorType.GetRawProtocolGroups(new[]
        {
            new ProxyCollector.Collector.FinalProxy { Proto = "wireguard" },
            new ProxyCollector.Collector.FinalProxy { Proto = "vless" }
        });
        Checks.Equal(1, rawProtocolGroups.Count,
            "WireGuard is excluded from raw URI-per-line protocol feeds");
        Checks.Equal("vless", rawProtocolGroups[0].Key,
            "ordinary protocols remain in URI-per-line protocol feeds");
        var caseSensitiveFallbackLinks = CollectorType.DeduplicateFallbackLinks(new[]
        {
            "vless://ABC@example.net:443?type=ws&path=%2FCase",
            "vless://abc@example.net:443?type=ws&path=%2Fcase"
        });
        Checks.Equal(2, caseSensitiveFallbackLinks.Count,
            "last-good fallback deduplication preserves case-sensitive credentials and paths");

        string verificationReportPath = Path.Combine(
            Path.GetTempPath(), "fastnodes-verification-report-" + Guid.NewGuid().ToString("N") + ".csv.gz");
        try
        {
            var reportNode = new ProxyCollector.Collector.FinalProxy
            {
                Link = "vless://test@example.net:443",
                NodeId = "verification-node",
                Proto = "vless",
                Host = "example.net",
                Port = "443"
            };
            CollectorType.WriteVerificationReportAsync(
                verificationReportPath,
                new[] { reportNode },
                new[] { reportNode },
                Array.Empty<ProxyCollector.Collector.FinalProxy>())
                .GetAwaiter().GetResult();

            using var compressedReport = File.OpenRead(verificationReportPath);
            using var gzipReport = new GZipStream(compressedReport, CompressionMode.Decompress);
            using var reportReader = new StreamReader(gzipReport);
            string? reportHeader = reportReader.ReadLine();
            string? reportRow = reportReader.ReadLine();
            Checks.That(reportHeader?.StartsWith("diagnostic_rank,node_id,host,port", StringComparison.Ordinal) == true,
                "verification diagnostics are written as a readable gzip-compressed CSV");
            Checks.That(reportRow?.Contains("\"verification-node\"", StringComparison.Ordinal) == true,
                "compressed verification diagnostics preserve candidate rows");
        }
        finally
        {
            if (File.Exists(verificationReportPath)) File.Delete(verificationReportPath);
        }
        var yamlDocument = new YamlStream();
        yamlDocument.Load(new StringReader(safeYaml));
        var yamlRoot = (YamlMappingNode)yamlDocument.Documents[0].RootNode;
        var yamlNodes = (YamlSequenceNode)yamlRoot.Children[new YamlScalarNode("proxies")];
        Checks.Equal(1, yamlNodes.Children.Count,
            "untrusted WireGuard YAML scalars cannot inject extra proxy nodes");
        var yamlNode = (YamlMappingNode)yamlNodes.Children[0];
        Checks.Equal(hostileName, ((YamlScalarNode)yamlNode.Children[new YamlScalarNode("name")]).Value,
            "safe YAML serialization preserves the original display name");
        foreach (var address in new[]
        {
            "0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.1.1",
            "172.16.0.1", "192.168.1.1", "192.0.0.8", "192.0.0.170", "192.0.0.171",
            "192.0.2.1", "192.88.99.1", "192.88.99.2",
            "198.18.0.1", "198.51.100.1",
            "203.0.113.1", "224.0.0.1", "::", "::1", "fc00::1", "fe80::1",
            "2001:db8::1", "::ffff:127.0.0.1"
        })
            Checks.That(CollectorType.IsPrivateOrReservedIp(IPAddress.Parse(address)),
                $"non-public/reserved address {address} is rejected");
        foreach (var address in new[]
        {
            "100::1", "100:0:0:1::1", "64:ff9b:1::1", "2001:2::1",
            "2001:10::1", "3fff::1", "5f00::1",
            "2001:100::1", "2001:1ff::1", "2001::1", "2001:1::4",
            "2002:0102:0304::1"
        })
            Checks.That(CollectorType.IsPrivateOrReservedIp(IPAddress.Parse(address)),
                $"IANA non-global IPv6 prefix {address} is rejected");
        foreach (var address in new[]
        {
            "1.1.1.1", "8.8.8.8", "192.0.0.9", "192.0.0.10",
            "192.31.196.1", "192.52.193.1", "192.175.48.1",
            "2001:4860:4860::8888",
            "2001:1::1", "2001:1::2", "2001:1::3",
            "2001:3::1", "2001:4:112::1", "2001:20::1", "2001:30::1",
            "2001:200::1", "2620:4f:8000::1", "64:ff9b::1"
        })
            Checks.That(!CollectorType.IsPrivateOrReservedIp(IPAddress.Parse(address)),
                $"public or globally reachable address {address} remains eligible");

        Checks.That(CollectorType.HasPlausibleCloudflareRangeCounts(15, 7),
            "complete official Cloudflare IPv4/IPv6 range lists pass the integrity threshold");
        Checks.That(!CollectorType.HasPlausibleCloudflareRangeCounts(9, 7),
            "an obviously truncated Cloudflare IPv4 list fails closed");
        Checks.That(!CollectorType.HasPlausibleCloudflareRangeCounts(15, 4),
            "an obviously truncated Cloudflare IPv6 list fails closed");
        Checks.That(!CollectorType.HasUnsafeResolvedAddress(new[]
            { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("2001:4860:4860::8888") }),
            "a hostname resolving only to public addresses remains eligible");
        Checks.That(CollectorType.HasUnsafeResolvedAddress(new[]
            { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("10.0.0.1") }),
            "a mixed public/private DNS answer is rejected if any address is unsafe");
        Checks.That(CollectorType.IsSafeDnsCanaryAnswer(new[] { IPAddress.Parse("1.1.1.1") }),
            "a DNS health canary with a public address is considered healthy");
        Checks.That(!CollectorType.IsSafeDnsCanaryAnswer(new[] { IPAddress.Parse("127.0.0.1") }),
            "a DNS sinkhole canary resolving to loopback is not considered healthy");
        Checks.That(!CollectorType.IsSafeDnsCanaryAnswer(Array.Empty<IPAddress>()),
            "a DNS health canary with no answers is not considered healthy");
        Checks.That(!CollectorType.ResolvedIpFilterExceedsWarningThreshold(80, 100),
            "the unsafe-answer warning threshold allows exactly the configured maximum without warning");
        Checks.That(CollectorType.ResolvedIpFilterExceedsWarningThreshold(81, 100),
            "widespread unsafe DNS answers trigger a warning while unsafe hosts are still removed");

        Checks.That(CollectorType.HasUnsafeResolvedAddress(new[]
            { IPAddress.Parse("2001:4860:4860::8888"), IPAddress.Parse("::ffff:127.0.0.1") }),
            "an IPv4-mapped private answer is rejected alongside a public IPv6 answer");
        var refusedEndpoints = new HashSet<(string Ip, int Port)>
        {
            ("198.51.100.7", 443)
        };
        var dualStackEndpoints = new[]
        {
            IPAddress.Parse("198.51.100.7"),
            IPAddress.Parse("2001:db8::7")
        };
        Checks.That(!CollectorType.AllResolvedEndpointsRefused(dualStackEndpoints, 443, refusedEndpoints),
            "one refused DNS answer does not mark a multi-address host dead");
        refusedEndpoints.Add(("2001:db8::7", 443));
        Checks.That(CollectorType.AllResolvedEndpointsRefused(dualStackEndpoints, 443, refusedEndpoints),
            "a multi-address host is dead only when every resolved endpoint refuses");
        Checks.That(!CollectorType.AllResolvedEndpointsRefused(Array.Empty<IPAddress>(), 443, refusedEndpoints),
            "an empty DNS answer is inconclusive, not evidence of a refused endpoint");

        Checks.That(!CollectorType.IsValidWireguardLink(
                "wireguard://privatekey@wg.example.net:51820?pk=not-a-key"),
            "WireGuard links with invalid key material are rejected before entering output feeds");
        string validWgPrivateKey = Convert.ToBase64String(Enumerable.Range(1, 32).Select(i => (byte)i).ToArray());
        string validWgPublicKey = Convert.ToBase64String(Enumerable.Range(33, 32).Select(i => (byte)i).ToArray());
        string validWgLink = $"wireguard://{Uri.EscapeDataString(validWgPrivateKey)}@wg.example.net:51820?pk={Uri.EscapeDataString(validWgPublicKey)}&ip=10.0.0.2%2F32";
        Checks.That(CollectorType.IsValidWireguardLink(validWgLink),
            "valid WireGuard key material remains eligible for output feeds");

        string fullWireguardConf =
            "[Interface]\r\n" +
            $"PrivateKey = {validWgPrivateKey}\r\n" +
            "Address = 10.0.0.2/32, fd00::2/128 # keep both interface addresses\r\n" +
            "DNS = 1.1.1.1, 2606:4700:4700::1111\r\n" +
            "\r\n[Peer]\r\n" +
            $"PublicKey = {validWgPublicKey}\r\n" +
            "Endpoint = [2001:4860:4860::8888]:51820\r\n" +
            "AllowedIPs = 0.0.0.0/0, ::/0\r\n" +
            "PersistentKeepalive = 17\r\n";
        string fullWireguardLink = "wireguard://" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes(fullWireguardConf));
        var parsedFullWireguardConf = CollectorType.TryParseWireguardInfo(fullWireguardLink);
        Checks.That(parsedFullWireguardConf is not null,
            "a base64-encoded full WireGuard conf is parsed");
        Checks.Equal("10.0.0.2/32, fd00::2/128", parsedFullWireguardConf!.Address,
            "full WireGuard conf parsing preserves every comma-separated interface address");
        Checks.Equal("1.1.1.1, 2606:4700:4700::1111", parsedFullWireguardConf.Dns,
            "full WireGuard conf parsing preserves every comma-separated DNS server");
        Checks.Equal(17, parsedFullWireguardConf.PersistentKeepalive,
            "full WireGuard conf parsing preserves the source PersistentKeepalive value");
        string rebuiltWireguardConf = CollectorType.BuildWireguardConf(parsedFullWireguardConf);
        Checks.That(rebuiltWireguardConf.Contains("Address = 10.0.0.2/32, fd00::2/128") &&
                    rebuiltWireguardConf.Contains("DNS = 1.1.1.1, 2606:4700:4700::1111") &&
                    rebuiltWireguardConf.Contains("PersistentKeepalive = 17"),
            "rebuilt WireGuard conf retains the original multi-value fields and keepalive");

        string multiplePeerConf = fullWireguardConf +
            $"\r\n[Peer]\r\nPublicKey = {validWgPublicKey}\r\n" +
            "Endpoint = 192.0.2.10:51820\r\nAllowedIPs = 10.0.0.0/8\r\n";
        string multiplePeerLink = "wireguard://" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes(multiplePeerConf));
        Checks.That(CollectorType.TryParseWireguardInfo(multiplePeerLink) is null,
            "multi-peer WireGuard profiles are rejected instead of silently truncating later peers");

        var wireguardDefaultPort = CollectorType.ParseProxyLine(
            "wireguard://privatekey@wg.example.net?pk=serverpub");
        Checks.That(wireguardDefaultPort is not null, "portless WireGuard URI parses");
        Checks.Equal("51820", wireguardDefaultPort!.Port,
            "portless WireGuard URI uses the protocol default rather than generic TLS port 443");
        var wgAliasDefaultPort = CollectorType.ParseProxyLine(
            "wg://privatekey@wg.example.net?pk=serverpub");
        Checks.That(wgAliasDefaultPort is not null, "portless wg alias parses");
        Checks.Equal("51820", wgAliasDefaultPort!.Port,
            "portless wg alias uses the WireGuard protocol default");

        string ssrPasswordB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes("secret"))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        string ssrIpv6Payload = $"[2001:4860:4860::8888]:443:origin:aes-128-cfb:plain:{ssrPasswordB64}/?remarks=ssr-v6";
        string ssrIpv6Link = "ssr://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(ssrIpv6Payload))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        var ssrIpv6 = CollectorType.ParseProxyLine(ssrIpv6Link);
        Checks.That(ssrIpv6 is not null, "SSR link with a bracketed IPv6 endpoint parses");
        Checks.Equal("2001:4860:4860::8888", ssrIpv6!.Host,
            "SSR IPv6 endpoint is normalized without brackets");
        Checks.Equal("443", ssrIpv6.Port, "SSR IPv6 endpoint port is preserved");
        string ssrEmptyPasswordPayload = "edge.example.net:443:origin:aes-128-cfb:plain:";
        string ssrEmptyPasswordLink = "ssr://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(ssrEmptyPasswordPayload))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');
        Checks.That(CollectorType.ParseProxyLine(ssrEmptyPasswordLink) is null,
            "SSR links without a password are rejected instead of entering output feeds");

        var validVlessUuid = "123e4567-e89b-12d3-a456-426614174000";
        Checks.That(CollectorType.ParseProxyLine(
            $"vless://{validVlessUuid}@valid-uuid.example.net:443?security=tls") is not null,
            "canonical VLESS UUID credentials remain accepted");
        Checks.That(CollectorType.ParseProxyLine(
            "vless://custom-vless-user@custom-id.example.net:443?security=tls") is not null,
            "short custom VLESS IDs remain valid as documented by Xray");
        Checks.That(CollectorType.ParseProxyLine(
            "vless://123456789012345678901234567890@bad-vless.example.net:443?security=tls") is null,
            "non-UUID VLESS custom IDs of 30 UTF-8 bytes or more are rejected");
        const string encodedCustomVlessId = "Telegram🇨🇳 @WangCai2";
        var encodedCustomVlessNode = CollectorType.ParseProxyLine(
            "vless://Telegram%F0%9F%87%A8%F0%9F%87%B3%20%40WangCai2@custom-id.example.net:443?security=tls");
        Checks.That(encodedCustomVlessNode is not null,
            "percent-encoded custom VLESS IDs are decoded before the byte-length check");
        Checks.Equal(encodedCustomVlessId, encodedCustomVlessNode!.Credential,
            "percent-encoded custom VLESS ID is preserved exactly after URI parsing");
        var encodedCustomVlessOutbound = CollectorType.BuildXrayOutbound(
            encodedCustomVlessNode, "encoded-custom-vless")!;
        var encodedVlessSettings = (Dictionary<string, object?>)encodedCustomVlessOutbound["settings"]!;
        var encodedVlessVnext = (List<object>)encodedVlessSettings["vnext"]!;
        var encodedVlessEndpoint = (Dictionary<string, object?>)encodedVlessVnext[0];
        var encodedVlessUsers = (List<object>)encodedVlessEndpoint["users"]!;
        var encodedVlessUser = (Dictionary<string, object?>)encodedVlessUsers[0];
        Checks.Equal(encodedCustomVlessId, (string)encodedVlessUser["id"]!,
            "decoded custom VLESS ID reaches the generated Xray outbound unchanged");
        Checks.That(CollectorType.ParseProxyLine(
            "vmess://not-a-uuid@valid-vmess.example.net:443?security=tls") is not null,
            "short custom VMess IDs remain valid as documented by Xray");
        Checks.That(CollectorType.ParseProxyLine(
            "vmess://this-is-a-deliberately-invalid-vmess-credential-over-30@example.net:443?security=tls") is null,
            "VMess custom IDs of 30 UTF-8 bytes or more are rejected unless they are UUIDs");
        var shortCustomVmessJson = """{"add":"custom-vmess.example.net","port":"443","id":"Telegram @channel","net":"tcp","tls":"tls"}""";
        Checks.That(CollectorType.ParseProxyLine(
            "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(shortCustomVmessJson))) is not null,
            "short custom IDs in Base64-JSON VMess profiles remain valid");
        var malformedVmessJson = """{"add":"bad-vmess.example.net","port":"443","id":"this-is-a-deliberately-invalid-vmess-credential-over-30","net":"tcp","tls":"tls"}""";
        Checks.That(CollectorType.ParseProxyLine(
            "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(malformedVmessJson))) is null,
            "overlength non-UUID Base64-JSON VMess IDs are rejected");
        var invalidXrayVless = new ProxyCollector.Collector.ParsedProxy
        {
            Protocol = "vless", Host = "bad-xray.example.net", Port = "443",
            Credential = "123456789012345678901234567890"
        };
        Checks.That(CollectorType.BuildXrayOutbound(invalidXrayVless, "invalid-vless-uuid") is null,
            "Xray builder independently rejects overlength VLESS IDs even if a ParsedProxy bypasses parsing");
        var invalidXrayVmess = new ProxyCollector.Collector.ParsedProxy
        {
            Protocol = "vmess", Host = "bad-vmess.example.net", Port = "443",
            Credential = "this-is-a-deliberately-invalid-vmess-credential-over-30"
        };
        Checks.That(CollectorType.BuildXrayOutbound(invalidXrayVmess, "invalid-vmess-id") is null,
            "Xray builder independently rejects overlength VMess IDs");
        var invalidVlessFlow = new ProxyCollector.Collector.ParsedProxy
        {
            Protocol = "vless", Host = "invalid-flow.example.net", Port = "443",
            Credential = validVlessUuid, Flow = "not-a-real-flow", Security = "tls"
        };
        Checks.That(CollectorType.BuildXrayOutbound(invalidVlessFlow, "invalid-vless-flow") is null,
            "Xray builder skips unsupported VLESS flow values instead of invalidating the full batch");
        var uppercaseVlessFlow = new ProxyCollector.Collector.ParsedProxy
        {
            Protocol = "vless", Host = "uppercase-flow.example.net", Port = "443",
            Credential = validVlessUuid, Flow = "XTLS-RPRX-VISION", Security = "tls"
        };
        var uppercaseFlowOutbound = CollectorType.BuildXrayOutbound(uppercaseVlessFlow, "uppercase-vless-flow")!;
        var uppercaseFlowSettings = (Dictionary<string, object?>)uppercaseFlowOutbound["settings"]!;
        var uppercaseFlowVnext = (List<object>)uppercaseFlowSettings["vnext"]!;
        var uppercaseFlowEndpoint = (Dictionary<string, object?>)uppercaseFlowVnext[0];
        var uppercaseFlowUsers = (List<object>)uppercaseFlowEndpoint["users"]!;
        var uppercaseFlowUser = (Dictionary<string, object?>)uppercaseFlowUsers[0];
        Checks.Equal("xtls-rprx-vision", (string)uppercaseFlowUser["flow"]!,
            "Xray VLESS flow values are canonicalized before the batch config is emitted");

        var uppercaseSsNode = new ProxyCollector.Collector.ParsedProxy
        {
            Protocol = "ss", Host = "ss.example.net", Port = "8388",
            Credential = "AES-256-GCM:secret"
        };
        var uppercaseSsOutbound = CollectorType.BuildXrayOutbound(uppercaseSsNode, "uppercase-ss-cipher")!;
        var uppercaseSsSettings = (Dictionary<string, object?>)uppercaseSsOutbound["settings"]!;
        var uppercaseSsServers = (List<object>)uppercaseSsSettings["servers"]!;
        var uppercaseSsServer = (Dictionary<string, object?>)uppercaseSsServers[0];
        Checks.Equal("aes-256-gcm", (string)uppercaseSsServer["method"]!,
            "Xray Shadowsocks cipher names are normalized to canonical lowercase labels");
        foreach (string unsupportedSsCipher in new[] { "none", "plain", "2022-blake3-chacha8-poly1305" })
        {
            var unsupportedSs = new ProxyCollector.Collector.ParsedProxy
            {
                Protocol = "ss", Host = "ss.example.net", Port = "8388",
                Credential = unsupportedSsCipher + ":secret"
            };
            Checks.That(CollectorType.BuildXrayOutbound(unsupportedSs, "unsupported-ss-" + unsupportedSsCipher) is null,
                "undocumented Xray Shadowsocks cipher is skipped: " + unsupportedSsCipher);
        }

        const string validRealityPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        const string normalizedRealityPublicKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        Checks.That(CollectorType.IsValidRealityPublicKey(validRealityPublicKey),
            "padded Base64 REALITY public keys are accepted as input");
        Checks.That(CollectorType.TryNormalizeRealityPublicKey(
                validRealityPublicKey, out string normalizedRealityKey) &&
                    normalizedRealityKey == normalizedRealityPublicKey,
            "REALITY public keys are normalized to 32-byte unpadded Base64URL for Xray");
        Checks.That(CollectorType.IsValidRealityPublicKey(normalizedRealityPublicKey),
            "already-normalized Base64URL REALITY public keys are accepted");
        Checks.That(!CollectorType.IsValidRealityPublicKey("AAAA AAAA"),
            "whitespace in REALITY public keys is rejected");
        Checks.That(!CollectorType.IsValidRealityPublicKey("abc"),
            "malformed REALITY public keys are rejected");
        Checks.That(CollectorType.IsValidRealityShortId("0123") &&
                    CollectorType.IsValidRealityShortId(""),
            "REALITY short IDs accept empty or even-length hexadecimal values");
        Checks.That(!CollectorType.IsValidRealityShortId("abc") &&
                    !CollectorType.IsValidRealityShortId("0123456789abcdef00"),
            "REALITY short IDs reject odd-length and over-16-character values");
        var validRealityNode = new ProxyCollector.Collector.ParsedProxy
        {
            Protocol = "vless", Host = "reality.example.net", Port = "443",
            Credential = validVlessUuid, Network = "tcp", Security = "reality",
            Pbk = validRealityPublicKey, Sid = "0123"
        };
        var validRealityOutbound = CollectorType.BuildXrayOutbound(validRealityNode, "valid-reality")!;
        var realityStream = (Dictionary<string, object?>)validRealityOutbound["streamSettings"]!;
        var realitySettings = (Dictionary<string, object?>)realityStream["realitySettings"]!;
        Checks.Equal(normalizedRealityPublicKey, (string)realitySettings["password"]!,
            "current Xray REALITY config uses normalized unpadded Base64URL password");
        Checks.That(!realitySettings.ContainsKey("publicKey"),
            "Xray REALITY outbound no longer emits the legacy publicKey property");
        var invalidRealityNode = new ProxyCollector.Collector.ParsedProxy
        {
            Protocol = "vless", Host = "reality.example.net", Port = "443",
            Credential = validVlessUuid, Network = "tcp", Security = "reality",
            Pbk = "abc", Sid = "0123"
        };
        Checks.That(CollectorType.BuildXrayOutbound(invalidRealityNode, "invalid-reality-key") is null,
            "malformed REALITY material is skipped rather than poisoning the entire Xray batch");
        var validUdp443Flow = new ProxyCollector.Collector.ParsedProxy
        {
            Protocol = "vless", Host = "udp443-flow.example.net", Port = "443",
            Credential = "custom-vless-user", Flow = "xtls-rprx-vision-udp443", Security = "tls"
        };
        Checks.That(CollectorType.BuildXrayOutbound(validUdp443Flow, "valid-vless-udp443-flow") is not null,
            "Xray builder accepts the documented VLESS Vision UDP443 flow");
        var invalidVmessSecurityJson = """{"add":"bad-security.example.net","port":"443","id":"123e4567-e89b-12d3-a456-426614174000","net":"tcp","tls":"tls","scy":"not-a-security"}""";
        var invalidVmessSecurity = CollectorType.ParseProxyLine(
            "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(invalidVmessSecurityJson)))!;
        Checks.That(CollectorType.BuildXrayOutbound(invalidVmessSecurity, "invalid-vmess-security") is null,
            "Xray builder skips unsupported VMess security values");
        foreach (string obsoleteSecurity in new[] { "none", "zero" })
        {
            var obsoleteVmessSecurityJson = "{\"add\":\"legacy-security.example.net\",\"port\":\"443\",\"id\":\"123e4567-e89b-12d3-a456-426614174000\",\"net\":\"tcp\",\"tls\":\"tls\",\"scy\":\"" + obsoleteSecurity + "\"}";
            var obsoleteVmessSecurity = CollectorType.ParseProxyLine(
                "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(obsoleteVmessSecurityJson)))!;
            Checks.That(CollectorType.BuildXrayOutbound(
                obsoleteVmessSecurity, "obsolete-vmess-security-" + obsoleteSecurity) is null,
                "unsupported legacy VMess security labels are rejected: " + obsoleteSecurity);
        }

        var ipv6 = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@[2001:4860:4860::8888]:443?security=reality&type=tcp&sni=example.com&flow=xtls-rprx-vision&pbk=abc&sid=01#ipv6");
        Checks.That(ipv6 is not null, "VLESS IPv6 link parses");
        Checks.Equal("2001:4860:4860::8888", ipv6!.Host, "IPv6 host is normalized without brackets");
        Checks.Equal("443", ipv6.Port, "VLESS port");
        Checks.Equal("example.com", ipv6.Sni, "VLESS SNI");
        Checks.Equal("xtls-rprx-vision", ipv6.Flow, "VLESS flow");

        Checks.That(XrayConnectivityProbe.IsExpectedConnectivityStatusLine("HTTP/1.1 204 No Content"),
            "Xray's connectivity probe accepts the expected generate_204 response");
        Checks.That(!XrayConnectivityProbe.IsExpectedConnectivityStatusLine("HTTP/1.1 200 OK"),
            "Xray's connectivity probe does not accept an intercepted 200 response");
        Checks.That(!XrayConnectivityProbe.IsExpectedConnectivityStatusLine("HTTP/1.1 302 Found"),
            "Xray's connectivity probe does not accept redirects as successful roundtrips");
        Checks.That(!XrayConnectivityProbe.IsExpectedConnectivityStatusLine("not-http 204"),
            "Xray's connectivity probe rejects malformed HTTP status lines");

        var vlessWsHost = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@edge.example.net:443?security=tls&type=ws&host=ws.example.net&path=%2Fentry")!;
        Checks.Equal("", vlessWsHost.Sni,
            "generic URI parser does not mistake WebSocket Host for an explicit TLS SNI");
        var vlessWsOutbound = CollectorType.BuildXrayOutbound(vlessWsHost, "vless-ws-host-test")!;
        var vlessWsStream = (Dictionary<string, object?>)vlessWsOutbound["streamSettings"]!;
        var vlessWsSettings = (Dictionary<string, object?>)vlessWsStream["wsSettings"]!;
        var vlessWsHeaders = (Dictionary<string, object?>)vlessWsSettings["headers"]!;
        Checks.Equal("ws.example.net", (string)vlessWsHeaders["Host"]!,
            "Xray VLESS WebSocket outbound preserves the independent HTTP Host header");
        var vlessWsTls = (Dictionary<string, object?>)vlessWsStream["tlsSettings"]!;
        Checks.Equal("edge.example.net", (string)vlessWsTls["serverName"]!,
            "Xray VLESS TLS SNI falls back to the endpoint, not the WebSocket Host");
        var uriVmessHost = CollectorType.ParseProxyLine(
            "vmess://01234567-89ab-cdef-0123-456789abcdef@uri-vmess.example.net:443?security=tls&type=ws&host=ws-uri.example.net&path=%2Fsocket&fp=chrome&alpn=h2")!;
        Checks.Equal("", uriVmessHost.Sni,
            "URI-form VMess does not promote the WebSocket Host into TLS SNI");
        var uriVmessOutbound = CollectorType.BuildXrayOutbound(uriVmessHost, "uri-vmess-test")!;
        var uriVmessStream = (Dictionary<string, object?>)uriVmessOutbound["streamSettings"]!;
        var uriVmessWs = (Dictionary<string, object?>)uriVmessStream["wsSettings"]!;
        var uriVmessHeaders = (Dictionary<string, object?>)uriVmessWs["headers"]!;
        Checks.Equal("ws-uri.example.net", (string)uriVmessHeaders["Host"]!,
            "URI-form VMess preserves its WebSocket Host query option");
        var uriVmessTls = (Dictionary<string, object?>)uriVmessStream["tlsSettings"]!;
        Checks.Equal("uri-vmess.example.net", (string)uriVmessTls["serverName"]!,
            "URI-form VMess TLS SNI defaults to the endpoint hostname");
        Checks.Equal("chrome", (string)uriVmessTls["fingerprint"]!,
            "URI-form VMess preserves its query-string uTLS fingerprint");

        var pinnedVlessOutbound = CollectorType.BuildXrayOutbound(
            vlessWsHost, "vless-pinned-test", "203.0.113.10")!;
        var pinnedVlessSettings = (Dictionary<string, object?>)pinnedVlessOutbound["settings"]!;
        var pinnedVlessVnext = (List<object>)pinnedVlessSettings["vnext"]!;
        var pinnedVlessEndpoint = (Dictionary<string, object?>)pinnedVlessVnext[0];
        Checks.Equal("203.0.113.10", (string)pinnedVlessEndpoint["address"]!,
            "Xray outbound can pin the socket destination to a vetted IP address");
        var pinnedVlessStream = (Dictionary<string, object?>)pinnedVlessOutbound["streamSettings"]!;
        var pinnedVlessTls = (Dictionary<string, object?>)pinnedVlessStream["tlsSettings"]!;
        Checks.Equal("edge.example.net", (string)pinnedVlessTls["serverName"]!,
            "pinning the socket destination preserves the original TLS SNI");

        var vlessH2Host = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@h2.example.net:443?security=tls&type=h2&host=authority.example.net&sni=tls.example.net&path=%2Fh2")!;
        var vlessH2Outbound = CollectorType.BuildXrayOutbound(vlessH2Host, "vless-h2-host-test")!;
        var vlessH2Stream = (Dictionary<string, object?>)vlessH2Outbound["streamSettings"]!;
        var vlessH2Settings = (Dictionary<string, object?>)vlessH2Stream["h2Settings"]!;
        Checks.Equal("authority.example.net",
            ((List<string>)vlessH2Settings["host"]!).Single(),
            "Xray HTTP/2 authority uses the transport Host override independently of TLS SNI");
        var vlessH2Tls = (Dictionary<string, object?>)vlessH2Stream["tlsSettings"]!;
        Checks.Equal("tls.example.net", (string)vlessH2Tls["serverName"]!,
            "Xray HTTP/2 TLS uses the explicit SNI independently of the authority");

        var vmessGrpcJson = """{"add":"grpc.example.net","port":"443","id":"01234567-89ab-cdef-0123-456789abcdef","net":"grpc","tls":"tls","sni":"grpc-tls.example.net","path":"grpc-service","aid":0}""";
        var vmessGrpc = CollectorType.ParseProxyLine("vmess://" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes(vmessGrpcJson)))!;
        var vmessGrpcOutbound = CollectorType.BuildXrayOutbound(vmessGrpc, "vmess-grpc-test")!;
        var vmessGrpcStream = (Dictionary<string, object?>)vmessGrpcOutbound["streamSettings"]!;
        var vmessGrpcSettings = (Dictionary<string, object?>)vmessGrpcStream["grpcSettings"]!;
        Checks.Equal("grpc-service", (string)vmessGrpcSettings["serviceName"]!,
            "Xray VMess gRPC outbound preserves the Base64 JSON service name");

        var vmessJson = """{"add":"vmess.example.com","port":"8443","id":"01234567-89ab-cdef-0123-456789abcdef","net":"ws","tls":"tls","host":"ws.example.com","sni":"tls.example.com","path":"/ws","aid":"1","scy":"chacha20-poly1305","fp":"chrome","alpn":["h2","http/1.1"]}""";
        var vmessWithFastCrypto = """{"add":"vmess.example.com","port":"8443","id":"01234567-89ab-cdef-0123-456789abcdef","net":"ws","tls":"tls","host":"sni.example.com","path":"/ws","aid":0,"scy":"auto","fp":"chrome","ps":"name A"}""";
        var vmessWithDifferentCrypto = """{"add":"vmess.example.com","port":"8443","id":"01234567-89ab-cdef-0123-456789abcdef","net":"ws","tls":"tls","host":"sni.example.com","path":"/ws","aid":0,"scy":"chacha20-poly1305","fp":"chrome","ps":"name B"}""";
        var vmessExtraA = CollectorType.ParseProxyLine("vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(vmessWithFastCrypto)));
        var vmessExtraB = CollectorType.ParseProxyLine("vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(vmessWithDifferentCrypto)));
        Checks.That(vmessExtraA is not null && vmessExtraB is not null &&
                    vmessExtraA.DeduplicationKey != vmessExtraB.DeduplicationKey,
            "VMess connection options not modeled by the collector remain distinct during deduplication");
        var vmessDifferentRemark = """{"add":"vmess.example.com","port":"8443","id":"01234567-89ab-cdef-0123-456789abcdef","net":"ws","tls":"tls","host":"sni.example.com","path":"/ws","aid":0,"scy":"auto","fp":"chrome","ps":"name C"}""";
        var vmessRemarkVariant = CollectorType.ParseProxyLine("vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(vmessDifferentRemark)));
        Checks.That(vmessExtraA is not null && vmessRemarkVariant is not null &&
                    vmessExtraA.DeduplicationKey == vmessRemarkVariant.DeduplicationKey,
            "VMess display remark alone does not split otherwise identical connection entries");
        var vmessPayload = Convert.ToBase64String(Encoding.UTF8.GetBytes(vmessJson));
        var vmess = CollectorType.ParseProxyLine("vmess://" + vmessPayload + "#vmess");
        Checks.That(vmess is not null, "VMess base64 JSON link parses");
        Checks.Equal("vmess.example.com", vmess!.Host, "VMess endpoint");
        Checks.Equal("8443", vmess.Port, "VMess port");
        Checks.Equal("ws", vmess.Network, "VMess transport");
        Checks.Equal("tls.example.com", vmess.Sni, "VMess explicit TLS SNI is kept separate from its WebSocket Host");
        Checks.Equal(1, vmess.Aid, "VMess string-valued alterId is parsed");
        var vmessOutbound = CollectorType.BuildXrayOutbound(vmess, "vmess-test")!;
        var vmessStream = (Dictionary<string, object?>)vmessOutbound["streamSettings"]!;
        var vmessWs = (Dictionary<string, object?>)vmessStream["wsSettings"]!;
        var vmessHeaders = (Dictionary<string, object?>)vmessWs["headers"]!;
        Checks.Equal("ws.example.com", (string)vmessHeaders["Host"]!,
            "Xray VMess outbound preserves the original WebSocket Host header");
        var vmessTls = (Dictionary<string, object?>)vmessStream["tlsSettings"]!;
        Checks.Equal("tls.example.com", (string)vmessTls["serverName"]!,
            "Xray VMess outbound uses the explicit SNI, not the WebSocket Host header");
        Checks.Equal("chrome", (string)vmessTls["fingerprint"]!,
            "Xray VMess outbound preserves the uTLS fingerprint");
        Checks.That(((string[])vmessTls["alpn"]!).SequenceEqual(new[] { "h2", "http/1.1" }),
            "Xray VMess outbound preserves the ALPN list");
        var vmessSettings = (Dictionary<string, object?>)vmessOutbound["settings"]!;
        var vmessVnext = (List<object>)vmessSettings["vnext"]!;
        var vmessEndpoint = (Dictionary<string, object?>)vmessVnext[0];
        var vmessUsers = (List<object>)vmessEndpoint["users"]!;
        var vmessUser = (Dictionary<string, object?>)vmessUsers[0];
        Checks.Equal("chacha20-poly1305", (string)vmessUser["security"]!,
            "Xray VMess outbound preserves the source cipher");
        Checks.Equal(1, (int)vmessUser["alterId"]!,
            "Xray VMess outbound preserves the source alterId");
        var vmessNoSniPayload = """{"add":"vmess.example.net","port":"443","id":"01234567-89ab-cdef-0123-456789abcdef","net":"ws","tls":"tls","host":"ws-only.example.net","path":"/ws","aid":0}""";
        var vmessNoSni = CollectorType.ParseProxyLine("vmess://" +
            Convert.ToBase64String(Encoding.UTF8.GetBytes(vmessNoSniPayload)))!;
        Checks.Equal("", vmessNoSni.Sni,
            "VMess WS Host is not silently promoted to explicit TLS SNI when SNI is absent");

        var singboxJson = """
        {
          "outbounds": [
            {
              "type": "vmess", "tag": "vmess-options", "server": "vmess.example.net",
              "server_port": 443, "uuid": "01234567-89ab-cdef-0123-456789abcdef",
              "security": "aes-128-gcm",
              "tls": {
                "enabled": true, "server_name": "tls.example.net",
                "alpn": ["h2", "http/1.1"],
                "utls": { "enabled": true, "fingerprint": "chrome" }
              },
              "transport": {
                "type": "ws", "path": "/socket",
                "headers": { "Host": "ws.example.net" }
              }
            },
            {
              "type": "vless", "tag": "vless-options", "server": "vless.example.net",
              "server_port": 443, "uuid": "01234567-89ab-cdef-0123-456789abcdef",
              "flow": "xtls-rprx-vision",
              "tls": {
                "enabled": true, "server_name": "tls-vless.example.net", "insecure": true,
                "alpn": ["h2"],
                "utls": { "enabled": true, "fingerprint": "chrome" },
                "reality": { "enabled": true, "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "short_id": "01" }
              },
              "transport": {
                "type": "ws", "path": "/entry",
                "headers": { "Host": "ws-vless.example.net" }
              }
            },
            {
              "type": "hysteria2", "tag": "hy2-options", "server": "hy2.example.net",
              "server_port": 8443, "password": "hy2-secret",
              "obfs": { "type": "salamander", "password": "obfs-secret" },
              "up_mbps": 30, "down_mbps": 50,
              "tls": {
                "enabled": true, "server_name": "hy2-tls.example.net", "insecure": true,
                "alpn": ["h3"],
                "utls": { "enabled": true, "fingerprint": "chrome" }
              }
            },
            {
              "type": "shadowsocks", "tag": "ss-plugin", "server": "ss.example.net",
              "server_port": 8388, "method": "aes-128-gcm", "password": "secret",
              "plugin": "obfs-local", "plugin_opts": "obfs=http;obfs-host=example.org"
            },
            {
              "type": "socks", "tag": "socks-auth", "server": "socks.example.net",
              "server_port": 1080, "username": "user", "password": "p@ss"
            },
            {
              "type": "socks", "tag": "socks-open", "server": "open-socks.example.net",
              "server_port": 1081
            },
            {
              "type": "socks", "tag": "socks4-user", "server": "socks4.example.net",
              "server_port": 1082, "version": "4", "username": "legacy-user"
            },
            {
              "type": "socks", "tag": "socks-v6", "server": "2001:4860:4860::8888",
              "server_port": 1083
            }
          ]
        }
        """;
        var convertedSingbox = CollectorType.DecodeAndExtractLines(
            singboxJson, "https://example.net/config.json");
        Checks.Equal(8, convertedSingbox.Count,
            "sing-box conversion preserves VMess, VLESS, Hysteria2, plugin-based Shadowsocks, SOCKS4 and SOCKS5 outbounds including IPv6");
        string convertedVmess = convertedSingbox.Single(x => x.StartsWith("vmess://", StringComparison.Ordinal));
        string convertedVmessJson = Encoding.UTF8.GetString(Convert.FromBase64String(convertedVmess["vmess://".Length..]));
        using (var convertedVmessDoc = JsonDocument.Parse(convertedVmessJson))
        {
            var root = convertedVmessDoc.RootElement;
            Checks.Equal("ws.example.net", root.GetProperty("host").GetString(),
                "VMess WebSocket Host header survives conversion separately");
            Checks.Equal("tls.example.net", root.GetProperty("sni").GetString(),
                "VMess TLS SNI survives conversion separately from WebSocket Host");
            Checks.Equal("chrome", root.GetProperty("fp").GetString(),
                "VMess uTLS fingerprint survives structured conversion");
            Checks.Equal("h2,http/1.1", root.GetProperty("alpn").GetString(),
                "VMess ALPN list survives structured conversion");
            Checks.Equal("aes-128-gcm", root.GetProperty("scy").GetString(),
                "VMess cipher/security method survives structured conversion");
        }
        var convertedVmessParsed = CollectorType.ParseProxyLine(convertedVmess);
        Checks.That(convertedVmessParsed is not null, "converted VMess link remains parseable");
        Checks.Equal("tls.example.net", convertedVmessParsed!.Sni,
            "VMess parser reads the separate SNI field rather than the WebSocket Host");
        string convertedSs = convertedSingbox.Single(x => x.StartsWith("ss://", StringComparison.Ordinal));
        Checks.That(convertedSs.Contains("plugin=obfs-local", StringComparison.Ordinal) &&
                    convertedSs.Contains("obfs%3Dhttp", StringComparison.Ordinal) &&
                    convertedSs.Contains("obfs-host%3Dexample.org", StringComparison.Ordinal),
            "Shadowsocks SIP002 plugin and plugin options survive sing-box conversion");
        Checks.That(CollectorType.ParseProxyLine(convertedSs) is not null,
            "converted plugin-based Shadowsocks link remains parseable");
        string convertedSocksAuth = convertedSingbox.Single(x => x.StartsWith("socks5://user:p%40ss@", StringComparison.Ordinal));
        Checks.That(CollectorType.ParseProxyLine(convertedSocksAuth) is not null &&
                    convertedSocksAuth.Contains("socks.example.net:1080", StringComparison.Ordinal),
            "sing-box authenticated SOCKS outbound preserves credentials and endpoint");
        string convertedSocksOpen = convertedSingbox.Single(x => x.StartsWith("socks5://open-socks.example.net:1081", StringComparison.Ordinal));
        Checks.That(CollectorType.ParseProxyLine(convertedSocksOpen) is not null,
            "sing-box credential-less SOCKS outbound remains supported");
        string convertedSocks4 = convertedSingbox.Single(x => x.StartsWith("socks4://legacy-user@socks4.example.net:1082", StringComparison.Ordinal));
        Checks.That(CollectorType.ParseProxyLine(convertedSocks4) is not null,
            "sing-box version-4 SOCKS outbound retains SOCKS4 semantics and user ID");
        string convertedSocksV6 = convertedSingbox.Single(x => x.StartsWith("socks5://[2001:4860:4860::8888]:1083", StringComparison.Ordinal));
        Checks.That(CollectorType.ParseProxyLine(convertedSocksV6) is not null,
            "sing-box SOCKS conversion brackets IPv6 endpoints so the generated URI remains parseable");
        string convertedVless = convertedSingbox.Single(x => x.StartsWith("vless://", StringComparison.Ordinal));
        Checks.That(convertedVless.Contains("host=ws-vless.example.net", StringComparison.Ordinal) &&
                    convertedVless.Contains("fp=chrome", StringComparison.Ordinal) &&
                    convertedVless.Contains("alpn=h2", StringComparison.Ordinal) &&
                    convertedVless.Contains("pbk=AAAAAAAA", StringComparison.Ordinal) &&
                    convertedVless.Contains("sid=01", StringComparison.Ordinal) &&
                    convertedVless.Contains("allowInsecure=1", StringComparison.Ordinal) &&
                    convertedVless.Contains("flow=xtls-rprx-vision", StringComparison.Ordinal),
            "sing-box VLESS conversion retains WS Host, fingerprint, ALPN, REALITY keys and flow");
        var convertedVlessParsed = CollectorType.ParseProxyLine(convertedVless);
        Checks.That(convertedVlessParsed is not null, "converted VLESS link remains parseable");
        Checks.Equal("tls-vless.example.net", convertedVlessParsed!.Sni,
            "converted VLESS retains the configured TLS SNI");
        string convertedHy2 = convertedSingbox.Single(x => x.StartsWith("hysteria2://", StringComparison.Ordinal));
        Checks.That(convertedHy2.Contains("obfs=salamander", StringComparison.Ordinal) &&
                    convertedHy2.Contains("obfs-password=obfs-secret", StringComparison.Ordinal) &&
                    convertedHy2.Contains("upmbps=30", StringComparison.Ordinal) &&
                    convertedHy2.Contains("downmbps=50", StringComparison.Ordinal) &&
                    convertedHy2.Contains("alpn=h3", StringComparison.Ordinal) &&
                    convertedHy2.Contains("insecure=1", StringComparison.Ordinal),
            "sing-box Hysteria2 conversion retains obfuscation, ALPN and bandwidth options");

        const string arrayOutboundsJson = """
        [
          {
            "type": "vless", "tag": "array-export", "server": "array.example.net",
            "server_port": 443, "uuid": "01234567-89ab-cdef-0123-456789abcdef",
            "tls": { "enabled": true, "server_name": "tls.array.example.net" }
          },
          { "type": "selector", "tag": "unsupported-selector", "outbounds": ["array-export"] }
        ]
        """;
        var arrayOutbounds = CollectorType.DecodeAndExtractLines(
            arrayOutboundsJson, "https://example.net/all_sources_nekobox.json");
        Checks.Equal(1, arrayOutbounds.Count,
            "root-level arrays of sing-box outbounds extract supported nodes and skip group entries");
        Checks.That(CollectorType.ParseProxyLine(arrayOutbounds.Single()) is not null,
            "root-array outbound conversion produces a valid common share link");

        const string rawEntriesJson = """
        {
          "total": 1,
          "entries": [
            {
              "protocol": "vless",
              "raw": "vless://01234567-89ab-cdef-0123-456789abcdef@raw.example.net:443?security=tls&type=tcp&sni=tls.raw.example.net#raw-entry"
            }
          ]
        }
        """;
        var rawEntries = CollectorType.DecodeAndExtractLines(
            rawEntriesJson, "https://example.net/all_sources.json");
        Checks.Equal(1, rawEntries.Count,
            "wrapper JSON entries.raw share links are recovered without rebuilding their options");
        Checks.That(CollectorType.ParseProxyLine(rawEntries.Single()) is not null,
            "recovered entries.raw URI is accepted by the common parser");

        const string mobileJson = """
        {
          "count": 2,
          "MOBILE": [
            "vless://01234567-89ab-cdef-0123-456789abcdef@mobile.example.net:443?security=tls&type=tcp#mobile",
            "not-a-proxy"
          ]
        }
        """;
        var mobileLinks = CollectorType.DecodeAndExtractLines(
            mobileJson, "https://example.net/mobile.json");
        Checks.Equal(1, mobileLinks.Count,
            "MOBILE string arrays contribute only valid share-link-shaped values");

        const string simpleSingboxProfile = """
        {
          "outbounds": [
            {
              "type": "vless", "tag": "profile-header", "server": "profile.example.net",
              "server_port": 443, "uuid": "01234567-89ab-cdef-0123-456789abcdef",
              "tls": { "enabled": true, "server_name": "tls.profile.example.net" }
            }
          ]
        }
        """;
        var hashHeaderProfile = CollectorType.DecodeAndExtractLines(
            "#profile-title: base64:VGVzdA==\n#profile-update-interval: 1\n" + simpleSingboxProfile,
            "https://example.net/profile.json");
        Checks.Equal(1, hashHeaderProfile.Count,
            "sing-box JSON with #profile metadata headers is parsed");
        var subscriptionMetadataProfile = CollectorType.DecodeAndExtractLines(
            "#profile-title: base64:VGVzdA==\n" +
            "#profile-update-interval: 1\n" +
            "#subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531\n" +
            "#support-url: https://example.net/support\n" +
            "#profile-web-page-url: https://example.net/profile\n" +
            simpleSingboxProfile,
            "https://example.net/subscription.json");
        Checks.Equal(1, subscriptionMetadataProfile.Count,
            "sing-box JSON with subscription-userinfo and support-url metadata headers is parsed");
        var slashSubscriptionMetadataProfile = CollectorType.DecodeAndExtractLines(
            "//profile-title: base64:VGVzdA==\n" +
            "//profile-update-interval: 48\n" +
            "//subscription-userinfo: upload=0; download=0; total=10737418240000000; expire=2546249531\n" +
            "//support-url: https://example.net/support\n" +
            "//profile-web-page-url: https://example.net/profile\n" +
            simpleSingboxProfile,
            "https://example.net/subscription.json");
        Checks.Equal(1, slashSubscriptionMetadataProfile.Count,
            "sing-box JSON with slash-prefixed subscription metadata headers is parsed");
        var slashHeaderProfile = CollectorType.DecodeAndExtractLines(
            "//profile-title: base64:VGVzdA==\n//profile-update-interval: 48\n" + simpleSingboxProfile,
            "https://example.net/profile-feed");
        Checks.Equal(1, slashHeaderProfile.Count,
            "extensionless sing-box JSON with //profile metadata headers is parsed");
        const string singboxEndpointWireguard = """
        {
          "endpoints": [
            {
              "type": "wireguard", "tag": "modern-wg",
              "address": "10.0.0.2/32",
              "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
              "peers": [
                {
                  "address": "wg.example.net", "port": 51820,
                  "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                  "pre_shared_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                  "allowed_ips": "0.0.0.0/0, ::/0",
                  "persistent_keepalive_interval": 25,
                  "reserved": "AQID"
                }
              ]
            }
          ]
        }
        """;
        var modernEndpointWireguard = CollectorType.DecodeAndExtractLines(
            singboxEndpointWireguard, "https://example.net/singbox-endpoint.json");
        Checks.Equal(1, modernEndpointWireguard.Count,
            "sing-box 1.11+ WireGuard endpoints are converted to share links");
        Checks.That(CollectorType.IsValidWireguardLink(modernEndpointWireguard.Single()),
            "modern sing-box WireGuard endpoint conversion preserves scalar address/allowed IPs and base64 reserved bytes");
        Checks.That(modernEndpointWireguard.Single().Contains("reserved=1%2C2%2C3", StringComparison.Ordinal),
            "base64 sing-box reserved bytes are converted to three numeric reserved bytes");
        Checks.That(modernEndpointWireguard.Single().Contains("keepalive=25", StringComparison.Ordinal),
            "modern sing-box WireGuard peer keepalive is preserved");
        const string singboxScalarEndpointWireguard = """
        {
          "endpoints": [
            {
              "type": "wireguard", "tag": "modern-wg-scalar",
              "address": "10.0.0.2/32",
              "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
              "peers": {
                "address": "wg.example.net", "port": 51820,
                "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "allowed_ips": "0.0.0.0/0",
                "reserved": []
              }
            }
          ]
        }
        """;
        var scalarEndpointWireguard = CollectorType.DecodeAndExtractLines(
            singboxScalarEndpointWireguard, "https://example.net/singbox-endpoint-scalar.json");
        Checks.Equal(1, scalarEndpointWireguard.Count,
            "sing-box single-item endpoint peer arrays may be represented by scalar objects/strings");
        Checks.That(CollectorType.IsValidWireguardLink(scalarEndpointWireguard.Single()),
            "scalar single-item WireGuard fields still produce a valid link");
        string encodedModernEndpoint = Convert.ToBase64String(
            Encoding.UTF8.GetBytes(singboxEndpointWireguard));
        var base64ModernEndpoint = CollectorType.DecodeAndExtractLines(
            encodedModernEndpoint, "https://example.net/singbox-endpoint.txt");
        Checks.Equal(1, base64ModernEndpoint.Count,
            "base64-encoded modern sing-box endpoint documents are decoded before format dispatch");
        var base64ModernEndpointWithMetadata = CollectorType.DecodeAndExtractLines(
            "#subscription-userinfo: upload=0; download=0; total=1073741824; expire=2546249531\n" +
            "#support-url: https://example.net/support\n" + encodedModernEndpoint,
            "https://example.net/singbox-endpoint.txt");
        Checks.Equal(1, base64ModernEndpointWithMetadata.Count,
            "metadata-prefixed base64 sing-box endpoints are decoded after stripping metadata headers");

        const string singboxLegacyWireguard = """
        {
          "outbounds": [
            {
              "type": "wireguard", "tag": "legacy-wg",
              "server": "wg.example.net", "server_port": 51820,
              "local_address": ["10.0.0.2/32"],
              "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
              "peer_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
              "pre_shared_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
              "allowed_ips": ["0.0.0.0/0"], "reserved": [1, 2, 3]
            }
          ]
        }
        """;
        var legacyOutboundWireguard = CollectorType.DecodeAndExtractLines(
            singboxLegacyWireguard, "https://example.net/singbox-outbound.json");
        Checks.Equal(1, legacyOutboundWireguard.Count,
            "deprecated sing-box WireGuard outbounds are still converted");
        Checks.That(CollectorType.IsValidWireguardLink(legacyOutboundWireguard.Single()),
            "legacy sing-box WireGuard outbound preserves endpoint and key material");
        const string singboxMultiPeerWireguard = """
        {
          "outbounds": [
            {
              "type": "wireguard", "tag": "multi-wg",
              "server": "ignored-root.example.net", "server_port": 51999,
              "local_address": ["10.0.0.2/32"],
              "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
              "peer_public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
              "pre_shared_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
              "reserved": [1, 2, 3],
              "peers": [
                {
                  "server": "peer-one.example.net", "server_port": 51820,
                  "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                  "allowed_ips": ["0.0.0.0/0"], "reserved": []
                },
                {
                  "server": "peer-two.example.net", "server_port": 51821,
                  "public_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                  "allowed_ips": ["0.0.0.0/0"]
                }
              ]
            }
          ]
        }
        """;
        var multiPeerWireguard = CollectorType.DecodeAndExtractLines(
            singboxMultiPeerWireguard, "https://example.net/singbox-multi-peer.json");
        Checks.Equal(2, multiPeerWireguard.Count,
            "sing-box multi-peer WireGuard outbounds produce one node per peer");
        Checks.That(multiPeerWireguard.Any(link => link.Contains("@peer-one.example.net:51820", StringComparison.Ordinal)) &&
                    multiPeerWireguard.Any(link => link.Contains("@peer-two.example.net:51821", StringComparison.Ordinal)),
            "multi-peer conversion uses each peer's own endpoint rather than ignored root fields");
        Checks.That(multiPeerWireguard.All(link => !link.Contains("psk=", StringComparison.Ordinal)),
            "root-level pre-shared keys are not incorrectly copied into multi-peer configurations");
        Checks.That(multiPeerWireguard.All(link => link.Contains("reserved=1%2C2%2C3", StringComparison.Ordinal)),
            "empty or omitted per-peer reserved arrays inherit the sing-box outbound-level reserved bytes");

        const string amneziaSingboxWireguard = """
        {
          "outbounds": [
            {
              "type": "wireguard", "tag": "amnezia-wg",
              "server": "wg.example.net", "server_port": 51820,
              "local_address": ["10.0.0.2/32"],
              "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
              "peer_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
              "allowed_ips": ["0.0.0.0/0"], "fake_packets": "1-10"
            }
          ]
        }
        """;
        Checks.Equal(0, CollectorType.DecodeAndExtractLines(
            amneziaSingboxWireguard, "https://example.net/amnezia-singbox.json").Count,
            "Amnezia-specific WireGuard JSON is rejected rather than downgraded");

        var malformedTrailingJson = CollectorType.DecodeAndExtractLines(
            "//profile-title: test\n" + simpleSingboxProfile + "\n1",
            "https://example.net/malformed-profile");
        Checks.Equal(0, malformedTrailingJson.Count,
            "profile parsing does not discard arbitrary trailing data after JSON");
        var incompleteOutbound = CollectorType.DecodeAndExtractLines(
            """{"outbounds":[{"type":"vless","tag":"incomplete","server":"incomplete.example.net"}]}""",
            "https://example.net/incomplete.json");
        Checks.Equal(0, incompleteOutbound.Count,
            "incomplete JSON outbounds without a valid port and credentials are not fabricated");



        var vmessIpv6 = CollectorType.ParseProxyLine(
            "vmess://01234567-89ab-cdef-0123-456789abcdef@[2001:4860:4860::8888]:443?security=tls");
        Checks.That(vmessIpv6 is not null, "VMess URI-form IPv6 link parses");
        Checks.Equal("2001:4860:4860::8888", vmessIpv6!.Host,
            "VMess URI-form IPv6 host is normalized without brackets");
        Checks.That(CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:0?security=tls") is null,
            "port zero is rejected instead of being rewritten to a protocol default");
        Checks.That(CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:65536?security=tls") is null,
            "out-of-range proxy ports are rejected");
        Checks.That(CollectorType.ParseProxyLine(
            "vmess://123e4567-e89b-12d3-a456-426614174000@example.com:0?security=tls") is null,
            "VMess URI-form port zero is rejected");
        var encodedInvalidSs = Convert.ToBase64String(Encoding.UTF8.GetBytes("aes-128-gcm:pw"));
        Checks.That(CollectorType.ParseProxyLine($"ss://{encodedInvalidSs}@example.com:0") is null,
            "Shadowsocks port zero is rejected by common port validation");
        var socksDefault = CollectorType.ParseProxyLine("socks5://example.com");
        Checks.That(socksDefault is not null && socksDefault.Port == "1080",
            "a valid omitted SOCKS port still receives its protocol default");

        var ssUser = Convert.ToBase64String(Encoding.UTF8.GetBytes("aes-128-gcm:CaseSensitive"));
        var ss = CollectorType.ParseProxyLine($"ss://{ssUser}@[2001:4860:4860::8888]:8388#ss");
        Checks.That(ss is not null, "Shadowsocks SIP002 IPv6 link parses");
        Checks.Equal("2001:4860:4860::8888", ss!.Host, "Shadowsocks IPv6 host");
        Checks.Equal("8388", ss.Port, "Shadowsocks port");
        Checks.Equal("aes-128-gcm:CaseSensitive", ss.Credential, "Shadowsocks credentials");

        var flowA = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=reality&flow=xtls-rprx-vision");
        var flowB = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=reality");
        Checks.That(flowA is not null && flowB is not null, "VLESS flow variants parse");
        Checks.That(flowA!.DeduplicationKey != flowB!.DeduplicationKey,
            "Deduplication preserves materially different VLESS flow values");
        var pluginA = CollectorType.ParseProxyLine("ss://YWVzLTEyOC1nY206cHc=@example.com:8388?plugin=obfs-local");
        var pluginB = CollectorType.ParseProxyLine("ss://YWVzLTEyOC1nY206cHc=@example.com:8388?plugin=obfs-simple");
        Checks.That(pluginA is not null && pluginB is not null &&
                    pluginA.DeduplicationKey != pluginB.DeduplicationKey,
            "unmodeled Shadowsocks plugin options remain distinct during deduplication");
        var unknownOptionA = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls&custom-mode=alpha");
        var unknownOptionB = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls&custom-mode=beta");
        Checks.That(unknownOptionA is not null && unknownOptionB is not null &&
                    unknownOptionA.DeduplicationKey != unknownOptionB.DeduplicationKey,
            "unmodeled URI options remain distinct instead of being lost to deduplication");
        var repeatedOptionsA = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls&mode=alpha&mode=beta");
        var repeatedOptionsB = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=tls&mode=beta&mode=alpha");
        Checks.That(repeatedOptionsA is not null && repeatedOptionsB is not null &&
                    repeatedOptionsA.DeduplicationKey != repeatedOptionsB.DeduplicationKey,
            "repeated query options preserve value ordering in the deduplication identity");
        var upperPath = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=reality&type=ws&path=%2FABC&pbk=AbCd");
        var lowerPath = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=reality&type=ws&path=%2Fabc&pbk=AbCd");
        Checks.That(upperPath is not null && lowerPath is not null &&
                    upperPath.DeduplicationKey != lowerPath.DeduplicationKey &&
                    upperPath.EndpointKey("203.0.113.10") != lowerPath.EndpointKey("203.0.113.10"),
            "Deduplication preserves case-sensitive transport paths");
        var upperPbk = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=reality&pbk=AbCd");
        var lowerPbk = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=reality&pbk=abcd");
        Checks.That(upperPbk is not null && lowerPbk is not null &&
                    upperPbk.DeduplicationKey != lowerPbk.DeduplicationKey &&
                    upperPbk.EndpointKey("203.0.113.10") != lowerPbk.EndpointKey("203.0.113.10"),
            "Deduplication preserves case-sensitive REALITY public keys");
        Checks.That(CollectorType.HasWarpRemark("vless://uuid@example.com:443#WARP+"),
            "WARP-labelled subscription remarks are detected during fallback sanitization");
        Checks.That(!CollectorType.HasWarpRemark("vless://uuid@example.com:443#warpath"),
            "ordinary words containing warp are not treated as WARP labels");
        Checks.That(!CollectorType.IsCloudflareFinal(new ProxyCollector.Collector.FinalProxy
            { Host = "example.com", Link = "vless://uuid@example.com:443?sni=cloudflare.com", Remark = "🇺🇸 Germany" }),
            "Cloudflare camouflage SNI alone does not exclude a non-Cloudflare endpoint");

        Checks.That(!CollectorType.IsCloudflareFinal(new ProxyCollector.Collector.FinalProxy
            { Host = "example.com", Link = "vless://uuid@example.com:443?sni=www.cloudflare.com&host=www.cloudflare.com#US", Remark = "US" }),
            "valid Cloudflare host and SNI camouflage remain usable");
        Checks.That(CollectorType.IsCloudflareFinal(new ProxyCollector.Collector.FinalProxy
            { Host = "example.com", Link = "ss://auth@example.com:443?plugin=v2ray-plugin%3Bmode%3Dwebsocket%3Bhost%3Dedge.pages.dev#US", Remark = "US" }),
            "Cloudflare Pages transport host metadata is excluded even when nested in SS plugin options");
        Checks.That(CollectorType.IsCloudflareFinal(new ProxyCollector.Collector.FinalProxy
            { Host = "example.com", Link = "vless://uuid@example.com:443?host=www.speedtest.net.ns.cloudflare.com.try.cloudflare.com.attacker.test#US", Remark = "US" }),
            "lookalike Cloudflare host metadata is excluded");
        Checks.That(!CollectorType.IsCloudflareFinal(new ProxyCollector.Collector.FinalProxy
            { Host = "example.com", Link = "vless://uuid@example.com:443?ech=cloudflare-ech.com#US", Remark = "US" }),
            "ECH resolver references are not mistaken for Cloudflare proxy endpoints");
        Checks.That(CollectorType.IsCloudflareFinal(new ProxyCollector.Collector.FinalProxy
            { Host = "foo.cloudflare.com.attacker.test", Link = "vless://uuid@example.com:443#US", Remark = "US" }),
            "Cloudflare lookalike endpoint names are rejected");
        Checks.That(CollectorType.IsCloudflareFinal(new ProxyCollector.Collector.FinalProxy
            { Host = "example.com", Link = "vless://uuid@example.com:443#Cloudflare", Remark = "Cloudflare" }),
            "Cloudflare-labelled proxy remarks remain excluded");

        var passwordA = CollectorType.ParseProxyLine("trojan://CaseSensitive@example.com:443?sni=example.com");
        var passwordB = CollectorType.ParseProxyLine("trojan://casesensitive@example.com:443?sni=example.com");
        Checks.That(passwordA is not null && passwordB is not null, "Trojan password variants parse");
        Checks.That(passwordA!.DeduplicationKey != passwordB!.DeduplicationKey,
            "Deduplication preserves case-sensitive Trojan passwords");

        Checks.That(CollectorType.ParseProxyLine("not a proxy URI") is null,
            "Malformed non-proxy input is rejected");
        Checks.That(CollectorType.ParseProxyLine(
            "vless://My-chanel-Telegram-ATOVPN @167.104.219.12:35671?security=tls&type=tcp#bad") is null,
            "Literal whitespace inside a proxy URI is rejected");

        var malformedSubscription = "vless://My-chanel-Telegram-ATOVPN @167.104.219.12:35671?security=tls&type=tcp#bad";
        Checks.Equal(0, CollectorType.DecodeAndExtractLines(malformedSubscription, "https://example.com/sub").Count,
            "Line extraction does not salvage a malformed URI prefix before whitespace-at");
        Checks.Equal(0, CollectorType.DecodeAndExtractLines(
            "<a href=\"vless://My-chanel-Telegram-ATOVPN @167.104.219.12:35671#bad\">proxy</a>",
            "https://example.com/page.html").Count,
            "HTML extraction does not salvage a malformed URI prefix before whitespace-at");
        Checks.Equal(1, CollectorType.DecodeAndExtractLines(
            "<a href=\"vless://123e4567-e89b-12d3-a456-426614174000@[2001:4860:4860::8888]:443?security=tls#ipv6\">proxy</a>",
            "https://example.com/page.html").Count,
            "HTML extraction preserves bracketed IPv6 proxy endpoints");
        Checks.Equal(1, CollectorType.DecodeAndExtractLines(
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443#good", "https://example.com/sub").Count,
            "Valid subscription URI extraction remains enabled");

        var aliasMetadataKept = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@192.0.2.1:443?security=tls")!;
        var aliasMetadataDuplicate = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@node.example.net:443?security=tls")!;
        aliasMetadataKept.SourceCount = 1;
        aliasMetadataDuplicate.SourceCount = 1;
        aliasMetadataDuplicate.IranTested = true;
        CollectorType.MergeAliasMetadata(aliasMetadataKept, aliasMetadataDuplicate,
            new[] { "source-a", "source-b", "source-a" });
        Checks.Equal(2, aliasMetadataKept.SourceCount,
            "alias collapse retains distinct-source consensus without double-counting overlapping sources");
        Checks.That(aliasMetadataKept.IranTested,
            "alias collapse preserves source-tested evidence from either spelling");

        var implicitSniA = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@one.example.net:443?security=tls")!;
        var implicitSniB = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@two.example.net:443?security=tls")!;
        Checks.That(implicitSniA.EndpointKey("192.0.2.1") != implicitSniB.EndpointKey("192.0.2.1"),
            "alias identity preserves different implicit TLS SNI hostnames sharing one resolved IP");
        var explicitSniA = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@one.example.net:443?security=tls&sni=front.example.net")!;
        var explicitSniB = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@two.example.net:443?security=tls&sni=front.example.net")!;
        Checks.Equal(explicitSniA.EndpointKey("192.0.2.1"), explicitSniB.EndpointKey("192.0.2.1"),
            "aliases with the same explicit TLS SNI remain eligible for collapse");
        var nonTlsAliasA = CollectorType.ParseProxyLine("socks5://one.example.net:1080")!;
        var nonTlsAliasB = CollectorType.ParseProxyLine("socks5://two.example.net:1080")!;
        Checks.Equal(nonTlsAliasA.EndpointKey("192.0.2.1"), nonTlsAliasB.EndpointKey("192.0.2.1"),
            "non-TLS aliases remain eligible for collapse when their resolved endpoint matches");

        var wsImplicitHostA = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@one.example.net:443?security=tls&type=ws&sni=front.example.net&path=%2Fws")!;
        var wsImplicitHostB = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@two.example.net:443?security=tls&type=ws&sni=front.example.net&path=%2Fws")!;
        Checks.That(wsImplicitHostA.EndpointKey("192.0.2.1") != wsImplicitHostB.EndpointKey("192.0.2.1"),
            "different implicit WebSocket Host values remain distinct even with the same explicit TLS SNI");
        var h2ImplicitHostA = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@one.example.net:443?type=h2&path=%2F")!;
        var h2ImplicitHostB = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@two.example.net:443?type=h2&path=%2F")!;
        Checks.That(h2ImplicitHostA.EndpointKey("192.0.2.1") != h2ImplicitHostB.EndpointKey("192.0.2.1"),
            "different implicit H2 host values remain distinct when SNI is omitted");
        var upgradeImplicitHostA = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@one.example.net:443?type=httpupgrade&path=%2F")!;
        var upgradeImplicitHostB = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@two.example.net:443?type=httpupgrade&path=%2F")!;
        Checks.That(upgradeImplicitHostA.EndpointKey("192.0.2.1") != upgradeImplicitHostB.EndpointKey("192.0.2.1"),
            "different implicit HTTP-upgrade Host values remain distinct");

        var dualStack = new[]
        {
            System.Net.IPAddress.Parse("198.51.100.7"),
            System.Net.IPAddress.Parse("2001:db8::7")
        };
        Checks.That(CollectorType.HasAddressFamily(dualStack, System.Net.Sockets.AddressFamily.InterNetwork),
            "Dual-stack host is included in IPv4-capable outputs");
        Checks.That(CollectorType.HasAddressFamily(dualStack, System.Net.Sockets.AddressFamily.InterNetworkV6),
            "Dual-stack host is included in IPv6-capable outputs");
        Checks.That(!CollectorType.HasAddressFamily(new[] { System.Net.IPAddress.Parse("198.51.100.7") },
                System.Net.Sockets.AddressFamily.InterNetworkV6),
            "IPv4-only host is not included in IPv6-capable outputs");

        var singleAliasAddress = System.Net.IPAddress.Parse("192.0.2.1");
        string singleAliasKey = CollectorType.BuildAliasCanonicalHost(
            "single.example.net", new[] { singleAliasAddress });
        string literalAliasKey = CollectorType.BuildAliasCanonicalHost(
            "192.0.2.1", new[] { singleAliasAddress });
        Checks.Equal(literalAliasKey, singleAliasKey,
            "a single-address hostname and its IP literal remain eligible for alias collapse");
        var dualStackAliasAddresses = new[]
        {
            System.Net.IPAddress.Parse("192.0.2.1"),
            System.Net.IPAddress.Parse("2001:db8::1")
        };
        string dualStackAliasKey = CollectorType.BuildAliasCanonicalHost(
            "dual.example.net", dualStackAliasAddresses);
        Checks.That(dualStackAliasKey != literalAliasKey,
            "a multi-homed hostname is not collapsed into a literal that matches only one of its addresses");
        Checks.Equal(dualStackAliasKey, CollectorType.BuildAliasCanonicalHost(
                "another-dual.example.net", dualStackAliasAddresses.Reverse()),
            "multi-homed alias identity is stable regardless of DNS answer ordering");

        var mappedV4 = System.Net.IPAddress.Parse("::ffff:65.109.219.162");
        Checks.That(CollectorType.HasAddressFamily(new[] { mappedV4 },
                System.Net.Sockets.AddressFamily.InterNetwork),
            "IPv4-mapped IPv6 literal is included in IPv4-capable outputs");
        Checks.That(!CollectorType.HasAddressFamily(new[] { mappedV4 },
                System.Net.Sockets.AddressFamily.InterNetworkV6),
            "IPv4-mapped IPv6 literal is not misclassified as native IPv6");

        var ranked = Enumerable.Range(0, 1200)
            .Select(i => new ProxyCollector.Collector.FinalProxy
            {
                Link = $"vless://node{i}@node{i}.example.net:443",
                Host = $"node{i}.example.net", Port = "443",
                Remark = $"node{i}",
                Score = 1200 - i,
                TlsVerified = true
            })
            .ToList();
        var ipv6Links = ranked.Skip(1000).Select(x => x.Link).ToHashSet(StringComparer.Ordinal);
        var ipv6AwareTop = CollectorType.SelectTopWithIpv6Diversity(ranked, ipv6Links);
        Checks.Equal(1000, ipv6AwareTop.Count, "IPv6-aware shortlist preserves the 1000-node contract");
        Checks.Equal(200, ipv6AwareTop.Count(x => ipv6Links.Contains(x.Link)),
            "IPv6-aware shortlist reserves 20% for native-IPv6-capable nodes when enough exist");
        Checks.That(ipv6AwareTop.Any(x => x.Link == ranked[1199].Link),
            "IPv6-aware shortlist can promote lower-ranked IPv6-capable nodes into the shortlist");
        Checks.That(ipv6AwareTop.Zip(ipv6AwareTop.Skip(1), (a, b) => a.Score >= b.Score).All(x => x),
            "IPv6-aware shortlist remains score-ordered after family balancing");
        Checks.Equal(0, CollectorType.SelectTopWithIpv6Diversity(ranked, ipv6Links, maxCount: 0).Count,
            "IPv6-aware shortlist handles a zero-size request");

        var tied = new[]
        {
            new ProxyCollector.Collector.FinalProxy { Link = "vless://c@c.example.net:443", Host = "c.example.net", Port = "443", Remark = "tie", Score = 10, TlsVerified = true },
            new ProxyCollector.Collector.FinalProxy { Link = "vless://a@a.example.net:443", Host = "a.example.net", Port = "443", Remark = "tie", Score = 10, TlsVerified = true },
            new ProxyCollector.Collector.FinalProxy { Link = "vless://b@b.example.net:443", Host = "b.example.net", Port = "443", Remark = "tie", Score = 10, TlsVerified = true }
        };
        var tiedTop = CollectorType.SelectTopWithIpv6Diversity(tied, new HashSet<string>(StringComparer.Ordinal));
        Checks.That(tiedTop.Select(x => x.Link).SequenceEqual(tied.Select(x => x.Link).OrderBy(x => x, StringComparer.Ordinal)),
            "ranked shortlist uses URI as a stable final tie-breaker");

        var strongRoundtrip = new ProxyCollector.Collector.FinalProxy
        {
            Link = "vless://roundtrip@example.net:443", XrayVerified = true, XrayTested = true, Score = 100
        };
        var tlsOnlyHighScore = new ProxyCollector.Collector.FinalProxy
        {
            Link = "vless://tls-only@example.net:443", TlsVerified = true, TlsTested = true, Score = 999
        };
        var evidenceRanked = CollectorType.RankTopCandidates(new[] { tlsOnlyHighScore, strongRoundtrip });
        Checks.Equal(strongRoundtrip.Link, evidenceRanked[0].Link,
            "a current full Xray roundtrip outranks TLS-only nodes even if the weaker node has a higher raw score");
        Checks.Equal(3, CollectorType.GetEvidenceTier(strongRoundtrip),
            "a full Xray roundtrip maps to the strongest evidence tier");
        Checks.Equal("full-roundtrip-passed", CollectorType.GetVerificationStatus(strongRoundtrip),
            "full proxy success is exposed distinctly from partial connectivity");
        Checks.Equal("partial-connectivity-passed", CollectorType.GetVerificationStatus(tlsOnlyHighScore),
            "a TLS handshake is labelled partial connectivity, not a full proxy pass");
        Checks.Equal("not-tested", CollectorType.GetVerificationStatus(new ProxyCollector.Collector.FinalProxy
            { IranTested = true }),
            "upstream tested-feed provenance is separate from current-run testing status");
        Checks.Equal("tested-failed", CollectorType.GetVerificationStatus(new ProxyCollector.Collector.FinalProxy
            { XrayTested = true }),
            "an attempted Xray probe without a pass is distinguishable from not tested");
        Checks.Equal("failed", CollectorType.GetTestStatus(true, false),
            "per-test status reports a real failed attempt");
        Checks.Equal("not-tested", CollectorType.GetTestStatus(false, false),
            "per-test status does not confuse an omitted check with failure");

        var remoteVantageFailure = new ProxyCollector.Collector.FinalProxy
        {
            Link = "vless://history@remote-failure.example.net:443",
            Host = "remote-failure.example.net", Port = "443", Proto = "vless",
            IsStable = true, Streak = 8, SourceCount = 4,
            TlsTested = true, XrayTested = true, EdgeTested = true,
            Score = 40
        };
        var singleSourceFailure = new ProxyCollector.Collector.FinalProxy
        {
            Link = "vless://single@single-failure.example.net:443",
            Host = "single-failure.example.net", Port = "443", Proto = "vless",
            TlsTested = true, XrayTested = true, EdgeTested = true,
            Score = 40
        };
        var sourceBackedAfterFailure = CollectorType.RankTopCandidates(
            new[] { remoteVantageFailure, singleSourceFailure });
        Checks.That(sourceBackedAfterFailure.Any(x => x.Link == remoteVantageFailure.Link),
            "stable multi-source candidates remain in the source/stability lane after remote-vantage probe failures");
        Checks.Equal("tested-failed", CollectorType.GetVerificationStatus(remoteVantageFailure),
            "source/stability retention never mislabels remote-vantage failures as passing");
        Checks.Equal("stable-and-multi-source", CollectorType.GetEvidenceLevel(remoteVantageFailure),
            "diagnostics describe stable, corroborated candidates even when the current probe failed");
        Checks.Equal("multi-source-corroborated", CollectorType.GetEvidenceLevel(
            new ProxyCollector.Collector.FinalProxy { SourceCount = 3 }),
            "diagnostics expose multi-source corroboration as positive selection evidence");
        Checks.That(sourceBackedAfterFailure.All(x => x.Link != singleSourceFailure.Link),
            "unverified single-source candidates without stability do not enter the top shortlist");

        var staleVeteran = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@veteran.example.net:443?security=tls")!;
        staleVeteran.IranTested = true;
        staleVeteran.SourceCount = 5;
        staleVeteran.Streak = 24;
        staleVeteran.VerifiedStreak = 24;
        staleVeteran.XrayStreak = 24;
        var freshTls = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@fresh.example.net:443?security=tls")!;
        freshTls.TlsVerified = true;
        freshTls.Streak = 1;
        Checks.That(CollectorType.CalculateRankingScore(freshTls, "XX") >
                    CollectorType.CalculateRankingScore(staleVeteran, "XX"),
            "a freshly TLS-verified node outranks stale history without a current successful check");
        var freshRoundtrip = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@xray2.example.net:443?security=tls")!;
        freshRoundtrip.XrayVerified = true;
        Checks.That(CollectorType.CalculateRankingScore(freshRoundtrip, "XX") >
                    CollectorType.CalculateRankingScore(staleVeteran, "XX"),
            "a current full roundtrip scores above history-only/source-only evidence");

        var diversityCandidates = new List<ProxyCollector.Collector.FinalProxy>();
        for (int i = 0; i < 70; i++)
            diversityCandidates.Add(new ProxyCollector.Collector.FinalProxy
            {
                Link = $"vless://source-a-{i}@a{i}.example.com:443", Host = $"a{i}.example.com",
                HostGroup = "example.com", ProviderGroup = "provider-a", SourceGroup = "source-a",
                TlsVerified = true, Score = 1000 - i, SourceCount = 1
            });
        foreach (string source in new[] { "source-b", "source-c", "source-d" })
            for (int i = 0; i < 10; i++)
                diversityCandidates.Add(new ProxyCollector.Collector.FinalProxy
                {
                    Link = $"vless://{source}-{i}@{source}{i}.{source}.net:443",
                    Host = $"{source}{i}.{source}.net", HostGroup = $"{source}.net",
                    ProviderGroup = $"provider-{source[^1]}", SourceGroup = source,
                    TlsVerified = true, Score = 900 - (source[7] - 'b') * 100 - i, SourceCount = 2
                });
        var diverseTop = CollectorType.SelectTopWithIpv6Diversity(
            CollectorType.RankTopCandidates(diversityCandidates),
            new HashSet<string>(StringComparer.Ordinal), maxCount: 40, ipv6SharePercent: 0);
        Checks.Equal(40, diverseTop.Count, "diversity-aware selection fills the requested shortlist size");
        Checks.Equal(4, diverseTop.Select(x => x.SourceGroup).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            "top shortlist preserves choice across source groups instead of one feed dominating");
        Checks.That(diverseTop.GroupBy(x => x.SourceGroup, StringComparer.OrdinalIgnoreCase).All(g => g.Count() <= 10),
            "source-group caps prevent one feed family from taking over an otherwise diverse top shortlist");

        var duplicateProfiles = new[]
        {
            new ProxyCollector.Collector.FinalProxy
            {
                Link = "vless://credential-a@shared.example.net:443?security=reality&type=tcp&flow=xtls-rprx-vision&sni=cdn.example.net",
                Host = "shared.example.net", Port = "443", Proto = "vless", Sni = "cdn.example.net",
                Network = "tcp", Security = "reality", Flow = "xtls-rprx-vision",
                XrayVerified = true, Score = 80, SourceGroup = "repo-a", HostGroup = "shared.example.net"
            },
            new ProxyCollector.Collector.FinalProxy
            {
                Link = "vless://credential-b@shared.example.net:443?security=reality&type=tcp&flow=xtls-rprx-vision&sni=cdn.example.net",
                Host = "shared.example.net", Port = "443", Proto = "vless", Sni = "cdn.example.net",
                Network = "tcp", Security = "reality", Flow = "xtls-rprx-vision",
                XrayVerified = true, Score = 120, SourceGroup = "repo-b", HostGroup = "shared.example.net"
            },
            new ProxyCollector.Collector.FinalProxy
            {
                Link = "vless://credential-c@shared.example.net:443?security=reality&type=tcp&flow=xtls-rprx-vision&sni=other.example.net",
                Host = "shared.example.net", Port = "443", Proto = "vless", Sni = "other.example.net",
                Network = "tcp", Security = "reality", Flow = "xtls-rprx-vision",
                XrayVerified = true, Score = 100, SourceGroup = "repo-c", HostGroup = "shared.example.net"
            }
        };
        var deduplicatedProfiles = CollectorType.SelectTopWithIpv6Diversity(
            duplicateProfiles, new HashSet<string>(StringComparer.Ordinal), maxCount: 10, ipv6SharePercent: 0);
        Checks.Equal(2, deduplicatedProfiles.Count,
            "top selection collapses credential-only duplicates at the same connection profile");
        Checks.That(deduplicatedProfiles.Any(x => x.Link.Contains("credential-b", StringComparison.Ordinal)),
            "duplicate profile keeps the strongest-scored usable credential");
        Checks.That(deduplicatedProfiles.Any(x => x.Link.Contains("credential-c", StringComparison.Ordinal)),
            "same endpoint with a different SNI is preserved as a distinct virtual-host profile");

        var stratifiedCandidates = new List<ProxyCollector.Collector.FinalProxy>();
        for (int i = 0; i < 700; i++)
        {
            stratifiedCandidates.Add(new ProxyCollector.Collector.FinalProxy
            {
                Link = $"vless://xray{i}@xray{i}.example.net:443", Host = $"xray{i}.example.net",
                Port = "443", Proto = "vless", Network = "tcp", Security = "reality",
                XrayTested = true, XrayVerified = true, Score = 1000 - i,
                HostGroup = $"xray{i}.example.net"
            });
            stratifiedCandidates.Add(new ProxyCollector.Collector.FinalProxy
            {
                Link = $"trojan://tls{i}@tls{i}.example.org:443", Host = $"tls{i}.example.org",
                Port = "443", Proto = "trojan", Network = "tcp", Security = "tls",
                TlsTested = true, TlsVerified = true, Score = 800 - i,
                HostGroup = $"tls{i}.example.org"
            });
            stratifiedCandidates.Add(new ProxyCollector.Collector.FinalProxy
            {
                Link = $"hysteria2://modern{i}@modern{i}.example.com:443", Host = $"modern{i}.example.com",
                Port = "443", Proto = "hysteria2", Network = "udp", Security = "tls",
                IsStable = true, Streak = 4, SourceCount = 2, Score = 60 - i,
                HostGroup = $"modern{i}.example.com"
            });
        }
        var stratifiedRanked = CollectorType.RankTopCandidates(stratifiedCandidates);
        var stratifiedTop = CollectorType.SelectTopWithIpv6Diversity(
            stratifiedRanked, new HashSet<string>(StringComparer.Ordinal), maxCount: 1000, ipv6SharePercent: 0);
        Checks.Equal(1000, stratifiedTop.Count,
            "stratified shortlist fills the requested size from independent evidence lanes");
        Checks.Equal(550, stratifiedTop.Count(x => x.XrayVerified),
            "full Xray successes use the target 55 percent lane rather than monopolizing the list");
        Checks.Equal(300, stratifiedTop.Count(x => x.TlsVerified),
            "TLS/edge successes retain their target 30 percent lane");
        Checks.That(stratifiedTop.Count(CollectorType.IsTopProbeLimitedProtocol) >= 100,
            "modern QUIC/native-tunnel protocols receive a reserved share when stable/source-backed candidates exist");
        Checks.That(stratifiedTop.Any(x => x.IsStable && !x.XrayVerified && !x.TlsVerified &&
                                           x.VerificationStatus == "not-tested"),
            "stable nodes outside current probe coverage remain eligible without being mislabeled as verified");
        Checks.Equal(stratifiedTop.Count,
            stratifiedTop.Select(CollectorType.GetTopEndpointProfileKey)
                .Distinct(StringComparer.OrdinalIgnoreCase).Count(),
            "top output contains one entry per endpoint connection profile");

        var stratifiedIpv6Links = stratifiedCandidates.Select(x => x.Link)
            .ToHashSet(StringComparer.Ordinal);
        var stratifiedIpv6Top = CollectorType.SelectTopWithIpv6Diversity(
            stratifiedRanked, stratifiedIpv6Links, maxCount: 1000, ipv6SharePercent: 100);
        Checks.Equal(550, stratifiedIpv6Top.Count(x => x.XrayVerified),
            "top_ipv6 keeps the full-roundtrip lane target instead of being filled entirely by Xray nodes");
        Checks.Equal(300, stratifiedIpv6Top.Count(x => x.TlsVerified),
            "top_ipv6 also preserves its partial-connectivity lane");
        Checks.That(stratifiedIpv6Top.All(x => stratifiedIpv6Links.Contains(x.Link)),
            "top_ipv6 contains only IPv6-capable candidates");
        var partialIpv6Links = stratifiedCandidates
            .Where(x => x.Proto != "hysteria2")
            .Select(x => x.Link)
            .ToHashSet(StringComparer.Ordinal);
        var partialIpv6Top = CollectorType.SelectTopWithIpv6Diversity(
            stratifiedRanked, partialIpv6Links, maxCount: 1000, ipv6SharePercent: 100);
        Checks.That(partialIpv6Top.All(x => partialIpv6Links.Contains(x.Link)),
            "top_ipv6 never leaks unfiltered native-protocol candidates from its reserve lane");

        Checks.That(CollectorType.IsTlsCandidate(new ProxyCollector.Collector.ParsedProxy { Protocol = "anytls" }),
            "AnyTLS is included in TCP/TLS handshake candidate selection");
        Checks.That(CollectorType.IsTlsCandidate(new ProxyCollector.Collector.ParsedProxy { Protocol = "naive" }),
            "NaiveProxy is included in TCP/TLS handshake candidate selection");
        Checks.That(!CollectorType.IsTlsCandidate(new ProxyCollector.Collector.ParsedProxy { Protocol = "hysteria2" }),
            "Hysteria2 is not incorrectly tested with a TCP/TLS handshake");
        Checks.That(!CollectorType.IsTlsCandidate(new ProxyCollector.Collector.ParsedProxy { Protocol = "tuic" }),
            "TUIC is not incorrectly tested with a TCP/TLS handshake");

        var optionsVariantA = new ProxyCollector.Collector.FinalProxy
        {
            Link = "vmess://a@same.example.net:443", Proto = "vmess",
            Host = "same.example.net", Port = "443", Network = "tcp",
            Security = "tls", ConnectionOptionsKey = "fp=chrome;alpn=h2"
        };
        var optionsVariantB = new ProxyCollector.Collector.FinalProxy
        {
            Link = "vmess://b@same.example.net:443", Proto = "vmess",
            Host = "same.example.net", Port = "443", Network = "tcp",
            Security = "tls", ConnectionOptionsKey = "fp=firefox;alpn=http/1.1"
        };
        Checks.That(CollectorType.GetTopEndpointProfileKey(optionsVariantA) !=
                    CollectorType.GetTopEndpointProfileKey(optionsVariantB),
            "deduplication preserves VMess/SS variants with different connection-affecting options");

        var protocolVariant = new ProxyCollector.Collector.FinalProxy
        {
            Link = "trojan://a@same.example.net:443", Proto = "trojan",
            Host = "same.example.net", Port = "443", Network = "tcp",
            Security = "tls"
        };
        Checks.That(CollectorType.GetTopEndpointProfileKey(optionsVariantA) !=
                    CollectorType.GetTopEndpointProfileKey(protocolVariant),
            "different proxy protocols at the same host and port remain distinct profiles");
        var realityVariant = new ProxyCollector.Collector.FinalProxy
        {
            Link = "vless://c@same.example.net:443", Proto = "vless",
            Host = "same.example.net", Port = "443", Network = "tcp",
            Security = "reality", Pbk = "different-public-key", Sid = "abcd"
        };
        var realityBase = new ProxyCollector.Collector.FinalProxy
        {
            Link = "vless://d@same.example.net:443", Proto = "vless",
            Host = "same.example.net", Port = "443", Network = "tcp",
            Security = "reality", Pbk = "another-public-key", Sid = "abcd"
        };
        Checks.That(CollectorType.GetTopEndpointProfileKey(realityVariant) !=
                    CollectorType.GetTopEndpointProfileKey(realityBase),
            "distinct REALITY public keys remain separate endpoint profiles");
        var obfsVariant = new ProxyCollector.Collector.FinalProxy
        {
            Link = "hysteria2://a@same.example.net:443", Proto = "hysteria2",
            Host = "same.example.net", Port = "443", Network = "udp",
            Security = "tls", ObfsPassword = "different-obfs"
        };
        var obfsBase = new ProxyCollector.Collector.FinalProxy
        {
            Link = "hysteria2://b@same.example.net:443", Proto = "hysteria2",
            Host = "same.example.net", Port = "443", Network = "udp",
            Security = "tls", ObfsPassword = "another-obfs"
        };
        Checks.That(CollectorType.GetTopEndpointProfileKey(obfsVariant) !=
                    CollectorType.GetTopEndpointProfileKey(obfsBase),
            "different Hysteria2 obfuscation secrets remain separate endpoint profiles");

        var nearbySingleSource = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@nearby.example.net:443?security=tls")!;
        nearbySingleSource.TlsVerified = true;
        nearbySingleSource.SourceCount = 1;
        var distantMultiSource = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@distant.example.net:443?security=tls")!;
        distantMultiSource.TlsVerified = true;
        distantMultiSource.SourceCount = 5;
        var xrayCountryCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["nearby.example.net"] = "IR",
            ["distant.example.net"] = "US"
        };
        var xrayRanked = CollectorType.RankXrayCandidates(
            new[] { nearbySingleSource, distantMultiSource }, xrayCountryCache, maxCount: 1);
        Checks.That(xrayRanked.Count == 1 && xrayRanked[0].Host == "distant.example.net",
            "Xray verification pool prioritizes distinct-source consensus before geography");

        Checks.Equal("DE", CollectorType.CombineGeoCountryCodes("DE", "DE"),
            "Matching City and Country databases agree on the ISO code");
        Checks.Equal("DE", CollectorType.CombineGeoCountryCodes("DE", "XX"),
            "A missing country-database result does not erase a valid city-database code");
        Checks.Equal("XX", CollectorType.CombineGeoCountryCodes("DE", "FR"),
            "Conflicting City and Country database codes are withheld");

        var singleGeo = new[]
        {
            new CollectorType.GeoLocationCandidate("DE", "Germany", "Frankfurt am Main", "Hetzner Online GmbH")
        };
        var singleLabel = CollectorType.BuildGeoLocationLabel(singleGeo);
        Checks.Equal("🇩🇪 Frankfurt am Main, DE · Hetzner Online", singleLabel.Location,
            "GeoIP location naming uses the matching flag and preserves trusted city casing");
        Checks.Equal("DE", singleLabel.CountryCode, "GeoIP returns normalized ISO country codes");

        var germanNodeName = CollectorType.BuildClientNodeName(
            "DE", "🇩🇪 Frankfurt am Main, DE · Hetzner Online", "edge-01.example.net", "443");
        var usNodeName = CollectorType.BuildClientNodeName(
            "US", "🇺🇸 San Francisco, US · Example ASN", "a-much-longer-node-name.example.org", "8443");
        Checks.Equal("🇩🇪 Germany - Frankfurt am Main | edge-01.example.net:443", germanNodeName,
            "client labels follow flag country - city | host:port format without ISO code");
        Checks.Equal("🇺🇸 United States - San Francisco | a-much-longer-node-name.example.org:8443", usNodeName,
            "client labels use full country names and retain the complete endpoint");
        Checks.Equal(germanNodeName, CollectorType.BuildClientNodeName(
            "DE", "🇩🇪 Frankfurt am Main, DE · Hetzner Online", "edge-01.example.net", "443"),
            "client labels are stable between runs for the same endpoint");
        var alternateEndpointName = CollectorType.BuildClientNodeName(
            "DE", "🇩🇪 Frankfurt am Main, DE · Hetzner Online", "edge-02.example.net", "443");
        Checks.That(alternateEndpointName != germanNodeName,
            "different endpoints remain distinguishable before duplicate suffixing");
        Checks.Equal(germanNodeName + " 2", CollectorType.ApplyDuplicateNameSuffix(germanNodeName, 2),
            "second similarly named node gets suffix 2");
        Checks.Equal(germanNodeName + " 3", CollectorType.ApplyDuplicateNameSuffix(germanNodeName, 3),
            "third similarly named node gets suffix 3");
        Checks.Equal(germanNodeName, CollectorType.ApplyDuplicateNameSuffix(germanNodeName, 1),
            "first occurrence has no numeric suffix");
        Checks.Equal("🌐 Unknown - Unknown | [2001:4860:4860::8888]:443",
            CollectorType.BuildClientNodeName("XX", "🌐 Unknown", "2001:4860:4860::8888", "443"),
            "unknown GeoIP labels and IPv6 endpoints remain well-formed");
        Checks.Equal("🇩🇪 Germany - Frankfurt am Main | edge.example.net:443",
            CollectorType.BuildFallbackNodeName("🇩🇪 Frankfurt am Main, DE · Hetzner Online · abc123",
                "edge.example.net", "443"),
            "legacy verified snapshot remarks migrate to the new country-city-endpoint format");
        Checks.Equal("🇩🇪 Germany - Unknown | edge.example.net:443",
            CollectorType.BuildFallbackNodeName("🇩🇪 Germany · Hetzner Online",
                "edge.example.net", "443"),
            "country-level legacy remarks do not invent a city");
        Checks.Equal("🇩🇪 Germany - Frankfurt am Main | edge.example.net:443",
            CollectorType.BuildFallbackNodeName("🇩🇪 Germany (DE) - Frankfurt am Main | old.example.net:8443",
                "edge.example.net", "443"),
            "already-renamed fallback remarks are normalized to the current endpoint");
        Checks.Equal("🌐 Unknown - Unknown | edge.example.net:443",
            CollectorType.BuildFallbackNodeName("🌐 Unknown (XX) - Unknown | old.example.net:8443",
                "edge.example.net", "443"),
            "already-renamed unknown-country fallback remarks remain well-formed");
        Checks.Equal("🇩🇪 Germany - Frankfurt (Main) | edge.example.net:443",
            CollectorType.BuildFallbackNodeName("🇩🇪 Germany (DE) - Frankfurt (Main) | old.example.net:8443",
                "edge.example.net", "443"),
            "parenthesized city names remain intact when migrating fallback remarks");


        var multiCityGeo = new[]
        {
            new CollectorType.GeoLocationCandidate("DE", "Germany", "Frankfurt", "Hetzner GmbH"),
            new CollectorType.GeoLocationCandidate("DE", "Germany", "Berlin", "Hetzner GmbH")
        };
        var multiCityLabel = CollectorType.BuildGeoLocationLabel(multiCityGeo);
        Checks.Equal("🇩🇪 Germany · Hetzner", multiCityLabel.Location,
            "DNS answers in the same country but different cities use country-level naming");
        Checks.Equal("🇩🇪 Germany · Hetzner", CollectorType.BuildGeoLocationLabel(multiCityGeo.Reverse().ToArray()).Location,
            "GeoIP label is independent of DNS answer ordering");

        var conflictingGeo = new[]
        {
            new CollectorType.GeoLocationCandidate("DE", "Germany", "Frankfurt", "Hetzner GmbH"),
            new CollectorType.GeoLocationCandidate("NL", "Netherlands", "Amsterdam", "OVH SAS")
        };
        var conflictingLabel = CollectorType.BuildGeoLocationLabel(conflictingGeo);
        Checks.Equal("🌐 Unknown", conflictingLabel.Location,
            "Conflicting country/provider signals do not produce a misleading flag or country");
        Checks.Equal("XX", conflictingLabel.CountryCode,
            "Conflicting country signals do not bias continent and proximity ranking");

        var conflictingCountrySameOrg = new[]
        {
            new CollectorType.GeoLocationCandidate("DE", "Germany", "Frankfurt", "Hetzner GmbH"),
            new CollectorType.GeoLocationCandidate("NL", "Netherlands", "Amsterdam", "Hetzner GmbH")
        };
        Checks.Equal("🌐 Hetzner", CollectorType.BuildGeoLocationLabel(conflictingCountrySameOrg).Location,
            "When country disagrees, a unanimous provider may be shown without a country claim");

        var invalidGeo = new[]
        {
            new CollectorType.GeoLocationCandidate("", "Unknown", "Frankfurt", "")
        };
        Checks.Equal("🌐 Unknown", CollectorType.BuildGeoLocationLabel(invalidGeo).Location,
            "Missing country code never creates a malformed or incorrect city flag");
        Checks.Equal("XX", CollectorType.BuildGeoLocationLabel(invalidGeo).CountryCode,
            "Missing country metadata normalizes to XX");
        
        var properCaseGeo = new[]
        {
            new CollectorType.GeoLocationCandidate("US", "United States", "McLean", "")
        };
        Checks.Equal("🇺🇸 McLean, US", CollectorType.BuildGeoLocationLabel(properCaseGeo).Location,
            "GeoIP city names preserve meaningful internal capitalization");


        string publishRoot = Path.Combine(Path.GetTempPath(), "FastNodes-publish-test-" + Guid.NewGuid().ToString("N"));
        string finalTree = Path.Combine(publishRoot, "sub");
        string stagingTree = Path.Combine(publishRoot, "sub.staging");
        string backupTree = Path.Combine(publishRoot, "sub.previous");
        Directory.CreateDirectory(finalTree);
        Directory.CreateDirectory(stagingTree);
        try
        {
            File.WriteAllText(Path.Combine(finalTree, "marker.txt"), "previous-complete-tree");
            File.WriteAllText(Path.Combine(stagingTree, "marker.txt"), "new-tree");
            bool failStageMoveOnce = true;
            try
            {
                CollectorType.PublishStagedDirectory(finalTree, stagingTree, backupTree, (source, destination) =>
                {
                    if (failStageMoveOnce && source == stagingTree)
                    {
                        failStageMoveOnce = false;
                        throw new IOException("injected stage publication failure");
                    }
                    Directory.Move(source, destination);
                });
                Checks.That(false, "failed staged publication must propagate its failure");
            }
            catch (IOException ex) when (ex.Message == "injected stage publication failure")
            {
                // The old output is restored before the exception escapes.
            }
            Checks.Equal("previous-complete-tree", File.ReadAllText(Path.Combine(finalTree, "marker.txt")),
                "failed staged publication restores the last complete output tree");
            Checks.That(!Directory.Exists(backupTree),
                "rollback leaves no stranded backup directory after restoring the prior tree");
        }
        finally
        {
            if (Directory.Exists(publishRoot)) Directory.Delete(publishRoot, recursive: true);
        }


        var flatClash = """
        proxies:
          - {name: flow-vmess, type: vmess, server: vmess.example.net, port: 443, uuid: 01234567-89ab-cdef-0123-456789abcdef, network: ws, tls: true, skip-cert-verify: true, sni: tls.example.net, ws-path: /socket, ws-host: ws.example.net, client-fingerprint: chrome, alpn: h2, cipher: chacha20-poly1305}
          - {name: flow-ss, type: ss, server: ss.example.net, port: 8388, cipher: aes-128-gcm, password: secret, plugin: obfs-local, plugin-opts: "obfs=http;obfs-host=example.org"}
          - {name: custom-vless-id, type: vless, server: custom.example.net, port: 443, uuid: "Telegram🇨🇳 @WangCai2", tls: true, sni: tls.custom.example.net}
        """;
        var convertedFlatClash = CollectorType.DecodeAndExtractLines(flatClash, "https://example.net/config.yaml");
        Checks.Equal(3, convertedFlatClash.Count,
            "flow-style Clash YAML routes all supported proxy entries to the unified structured converter");
        string flatVmess = convertedFlatClash.Single(x => x.StartsWith("vmess://", StringComparison.Ordinal));
        string flatVmessJson = Encoding.UTF8.GetString(Convert.FromBase64String(flatVmess["vmess://".Length..]));
        using (var flatVmessDoc = JsonDocument.Parse(flatVmessJson))
        {
            var root = flatVmessDoc.RootElement;
            Checks.Equal("ws.example.net", root.GetProperty("host").GetString(),
                "flow-style Clash VMess keeps the WebSocket Host header");
            Checks.Equal("tls.example.net", root.GetProperty("sni").GetString(),
                "flow-style Clash VMess keeps SNI distinct");
            Checks.Equal("chrome", root.GetProperty("fp").GetString(),
                "flow-style Clash VMess keeps client fingerprint");
            Checks.Equal("chacha20-poly1305", root.GetProperty("scy").GetString(),
                "flow-style Clash VMess keeps cipher choice");
            Checks.That(root.GetProperty("allowInsecure").GetBoolean(),
                "flow-style Clash VMess keeps the certificate-verification policy");
        }
        string flatSs = convertedFlatClash.Single(x => x.StartsWith("ss://", StringComparison.Ordinal));
        Checks.That(flatSs.Contains("plugin=obfs-local", StringComparison.Ordinal) &&
                    flatSs.Contains("obfs%3Dhttp", StringComparison.Ordinal) &&
                    flatSs.Contains("obfs-host%3Dexample.org", StringComparison.Ordinal),
            "flow-style Clash Shadowsocks keeps plugin options");
        string flatCustomVless = convertedFlatClash.Single(x => x.StartsWith("vless://", StringComparison.Ordinal));
        var flatCustomVlessNode = CollectorType.ParseProxyLine(flatCustomVless);
        Checks.That(flatCustomVlessNode is not null,
            "Clash YAML custom VLESS IDs containing spaces, Unicode and @ remain parseable");
        Checks.Equal("Telegram🇨🇳 @WangCai2", flatCustomVlessNode!.Credential,
            "Clash YAML custom VLESS ID survives URI escaping and decoding without truncation");

        var wireguardClash = $"""
        proxies:
          - name: block-wireguard
            type: wireguard
            server: wg.example.net
            port: 51820
            ip: 10.0.0.2/32
            private-key: {validWgPrivateKey}
            public-key: {validWgPublicKey}
            dns:
              - 1.1.1.1
            allowed-ips:
              - 0.0.0.0/0
              - "::/0"
            reserved: [1, 2, 3]
        """;
        var convertedWireguard = CollectorType.DecodeAndExtractLines(
            wireguardClash, "https://example.net/wireguard.yaml");
        Checks.Equal(1, convertedWireguard.Count,
            "block-style Clash WireGuard entries are converted instead of silently skipped");
        Checks.That(convertedWireguard.Single().StartsWith("wireguard://", StringComparison.Ordinal) &&
                    CollectorType.IsValidWireguardLink(convertedWireguard.Single()),
            "converted Clash WireGuard URI preserves valid keys, endpoint, addresses, allowed IPs, and reserved bytes");

        var amneziaWireguardClash = wireguardClash.Replace(
            "reserved: [1, 2, 3]", "reserved: [1, 2, 3]\n    amnezia-wg-option: 4");
        var convertedAmneziaWireguard = CollectorType.DecodeAndExtractLines(
            amneziaWireguardClash, "https://example.net/amnezia-wireguard.yaml");
        Checks.Equal(0, convertedAmneziaWireguard.Count,
            "AmneziaWG entries are not downgraded when the exporter cannot preserve their extra options");

        var allAddressAttempts = CollectorType.GetProbeAddressAttempts(new[]
        {
            IPAddress.Parse("192.0.2.10"), IPAddress.Parse("192.0.2.11"),
            IPAddress.Parse("2001:db8::10"), IPAddress.Parse("2001:db8::11")
        });
        Checks.That(allAddressAttempts.SequenceEqual(new[]
            {
                IPAddress.Parse("192.0.2.10"), IPAddress.Parse("2001:db8::10"),
                IPAddress.Parse("192.0.2.11"), IPAddress.Parse("2001:db8::11")
            }),
            "TLS/Xray verification attempts every vetted IPv4 and IPv6 address in interleaved order");

        TestSourceFetcherMixedProvidersAndLineCap();
        TestSourceFetcherRetryBehavior();

        Console.WriteLine($"Parser regression tests passed ({Checks.Count} assertions).");
    }

    private static void TestSourceFetcherMixedProvidersAndLineCap()
    {
        const string rootUrl = "https://root.example.net/config.yaml";
        const string providerUrl = "https://provider.example.net/nodes.txt";
        const string rootBody =
            "proxies:\n  - name: inline-node\nproxy-providers:\n  remote:\n    url: " + providerUrl;
        string providerBody = string.Join("\n",
            Enumerable.Range(0, SourceFetcher.MaxNestedLinesPerSource + 5)
                .Select(index => $"provider-node-{index}"));

        using var http = new HttpClient(new StubHttpMessageHandler(request =>
        {
            string requestUrl = request.RequestUri?.AbsoluteUri ?? "";
            if (requestUrl == rootUrl)
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(rootBody) };
            if (requestUrl == providerUrl)
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(providerBody) };
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        }));

        var fetcher = new SourceFetcher(
            http,
            new SourceFetchBudget(8L * 1024 * 1024, 8L * 1024 * 1024));
        using var result = fetcher.FetchAsync(
            new[] { rootUrl },
            _ => 1024 * 1024,
            (text, url) => url == rootUrl
                ? new List<string> { "inline-node" }
                : text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).ToList(),
            text => text.Contains("proxy-providers:", StringComparison.OrdinalIgnoreCase)
                ? new List<string> { providerUrl }
                : new List<string>(),
            url => new List<string> { url },
            text => text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Length,
            _ => { },
            _ => { }).GetAwaiter().GetResult();

        var extracted = result.Spool.ReadSourceLines(0).ToList();
        Checks.That(extracted.Contains("inline-node"),
            "a Clash parent keeps inline proxies while recursively fetching its nested proxy providers");
        Checks.Equal(SourceFetcher.MaxNestedLinesPerSource + 1, extracted.Count,
            "nested provider writes are capped before append even when one provider exceeds the remaining allowance");
        Checks.Equal($"provider-node-{SourceFetcher.MaxNestedLinesPerSource - 1}", extracted[^1],
            "the nested-provider cap preserves the first configured number of provider entries");
    }

    private static void TestSourceFetcherRetryBehavior()
    {
        const string retryUrl = "https://retry.example.net/nodes.txt";
        int retryCalls = 0;
        using (var retryHttp = new HttpClient(new StubHttpMessageHandler(_ =>
        {
            retryCalls++;
            if (retryCalls == 1)
            {
                var limited = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
                limited.Headers.RetryAfter = new System.Net.Http.Headers.RetryConditionHeaderValue(TimeSpan.FromMilliseconds(20));
                return limited;
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("recovered-node")
            };
        })))
        {
            var fetcher = new SourceFetcher(
                retryHttp,
                new SourceFetchBudget(8L * 1024 * 1024, 8L * 1024 * 1024));
            using var result = fetcher.FetchAsync(
                new[] { retryUrl },
                _ => 1024 * 1024,
                (body, _) => body.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).ToList(),
                _ => new List<string>(),
                url => new List<string> { url },
                body => body.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Length,
                _ => { },
                _ => { }).GetAwaiter().GetResult();

            Checks.Equal(2, retryCalls,
                "HTTP 429 is retried after the server-provided Retry-After interval");
            Checks.That(result.Spool.ReadSourceLines(0).SequenceEqual(new[] { "recovered-node" }),
                "a source that recovers after HTTP 429 contributes its extracted data");
        }

        const string missingUrl = "https://missing.example.net/nodes.txt";
        int missingCalls = 0;
        var permanentErrors = new List<string>();
        using (var missingHttp = new HttpClient(new StubHttpMessageHandler(_ =>
        {
            missingCalls++;
            return new HttpResponseMessage(HttpStatusCode.NotFound);
        })))
        {
            var fetcher = new SourceFetcher(
                missingHttp,
                new SourceFetchBudget(8L * 1024 * 1024, 8L * 1024 * 1024));
            using var result = fetcher.FetchAsync(
                new[] { missingUrl },
                _ => 1024 * 1024,
                (body, _) => new List<string>(),
                _ => new List<string>(),
                url => new List<string> { url },
                _ => 0,
                permanentErrors.Add,
                _ => { }).GetAwaiter().GetResult();
        }

        Checks.Equal(1, missingCalls,
            "permanent HTTP 404 responses are not pointlessly retried");
        Checks.That(permanentErrors.Any(message => message.Contains("HTTP 404", StringComparison.Ordinal)),
            "permanent source failures are logged with their HTTP status");
    }

    private sealed class StubHttpMessageHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;

        public StubHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> respond)
            => _respond = respond;

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request, CancellationToken cancellationToken)
            => Task.FromResult(_respond(request));
    }
}

internal static class Checks
{
    public static int Count { get; private set; }

    public static void That(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException("FAIL: " + message);
        Count++;
    }

    public static void Equal<T>(T expected, T actual, string message)
        => That(EqualityComparer<T>.Default.Equals(expected, actual),
            $"{message}; expected={expected}, actual={actual}");
}
