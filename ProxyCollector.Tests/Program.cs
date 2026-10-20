using System.Net;
using System.Text;
using CollectorType = ProxyCollector.Collector.ProxyCollector;

internal static class Program
{
    private static void Main()
    {
        Checks.Equal(3, ProxyCollector.Configuration.CollectorConfig.ApplySourceLimit(new[] { "a", "b", "c" }, 0).Length,
            "zero source limit preserves full production source list");
        Checks.That(ProxyCollector.Configuration.CollectorConfig.ApplySourceLimit(new[] { "a", "b", "c", "d" }, 2)
                .SequenceEqual(new[] { "a", "b" }),
            "positive source limit selects only the first N sources in priority order");
        Checks.Equal(3, ProxyCollector.Configuration.CollectorConfig.ApplySourceLimit(new[] { "a", "b", "c" }, 10).Length,
            "source limit larger than the list keeps all available sources");

        Checks.That(CollectorType.IsPrivateOrReservedIp(IPAddress.IPv6Any),
            "IPv6 unspecified address is rejected as a public proxy endpoint");
        Checks.That(CollectorType.IsPrivateOrReservedIp(IPAddress.Parse("ff02::1")),
            "IPv6 multicast address is rejected as a public proxy endpoint");
        Checks.That(!CollectorType.IsPrivateOrReservedIp(IPAddress.Parse("2001:4860:4860::8888")),
            "public IPv6 unicast address remains eligible");
        foreach (var address in new[]
        {
            "0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "169.254.1.1",
            "172.16.0.1", "192.168.1.1", "192.0.2.1", "198.18.0.1", "198.51.100.1",
            "203.0.113.1", "224.0.0.1", "::", "::1", "fc00::1", "fe80::1",
            "2001:db8::1", "::ffff:127.0.0.1"
        })
            Checks.That(CollectorType.IsPrivateOrReservedIp(IPAddress.Parse(address)),
                $"non-public/reserved address {address} is rejected");
        foreach (var address in new[] { "1.1.1.1", "8.8.8.8", "2001:4860:4860::8888" })
            Checks.That(!CollectorType.IsPrivateOrReservedIp(IPAddress.Parse(address)),
                $"public address {address} remains eligible");
        Checks.That(!CollectorType.HasUnsafeResolvedAddress(new[]
            { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("2001:4860:4860::8888") }),
            "a hostname resolving only to public addresses remains eligible");
        Checks.That(CollectorType.HasUnsafeResolvedAddress(new[]
            { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("10.0.0.1") }),
            "a mixed public/private DNS answer is rejected if any address is unsafe");
        Checks.That(CollectorType.HasUnsafeResolvedAddress(new[]
            { IPAddress.Parse("2001:4860:4860::8888"), IPAddress.Parse("::ffff:127.0.0.1") }),
            "an IPv4-mapped private answer is rejected alongside a public IPv6 answer");

        var ipv6 = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@[2001:4860:4860::8888]:443?security=reality&type=tcp&sni=example.com&flow=xtls-rprx-vision&pbk=abc&sid=01#ipv6");
        Checks.That(ipv6 is not null, "VLESS IPv6 link parses");
        Checks.Equal("2001:4860:4860::8888", ipv6!.Host, "IPv6 host is normalized without brackets");
        Checks.Equal("443", ipv6.Port, "VLESS port");
        Checks.Equal("example.com", ipv6.Sni, "VLESS SNI");
        Checks.Equal("xtls-rprx-vision", ipv6.Flow, "VLESS flow");

        var vmessJson = """{"add":"vmess.example.com","port":"8443","id":"01234567-89ab-cdef-0123-456789abcdef","net":"ws","tls":"tls","host":"sni.example.com","path":"/ws","aid":"0"}""";
        var vmessPayload = Convert.ToBase64String(Encoding.UTF8.GetBytes(vmessJson));
        var vmess = CollectorType.ParseProxyLine("vmess://" + vmessPayload + "#vmess");
        Checks.That(vmess is not null, "VMess base64 JSON link parses");
        Checks.Equal("vmess.example.com", vmess!.Host, "VMess endpoint");
        Checks.Equal("8443", vmess.Port, "VMess port");
        Checks.Equal("ws", vmess.Network, "VMess transport");
        Checks.Equal("sni.example.com", vmess.Sni, "VMess SNI");

        var vmessIpv6 = CollectorType.ParseProxyLine(
            "vmess://01234567-89ab-cdef-0123-456789abcdef@[2001:4860:4860::8888]:443?security=tls");
        Checks.That(vmessIpv6 is not null, "VMess URI-form IPv6 link parses");
        Checks.Equal("2001:4860:4860::8888", vmessIpv6!.Host,
            "VMess URI-form IPv6 host is normalized without brackets");

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
            "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443#good", "https://example.com/sub").Count,
            "Valid subscription URI extraction remains enabled");

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
                Link = $"vless://node{i}@example.com:443",
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
            new ProxyCollector.Collector.FinalProxy { Link = "vless://c@example.com:443", Remark = "tie", Score = 10, TlsVerified = true },
            new ProxyCollector.Collector.FinalProxy { Link = "vless://a@example.com:443", Remark = "tie", Score = 10, TlsVerified = true },
            new ProxyCollector.Collector.FinalProxy { Link = "vless://b@example.com:443", Remark = "tie", Score = 10, TlsVerified = true }
        };
        var tiedTop = CollectorType.SelectTopWithIpv6Diversity(tied, new HashSet<string>(StringComparer.Ordinal));
        Checks.That(tiedTop.Select(x => x.Link).SequenceEqual(tied.Select(x => x.Link).OrderBy(x => x, StringComparer.Ordinal)),
            "ranked shortlist uses URI as a stable final tie-breaker");

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

        Console.WriteLine($"Parser regression tests passed ({Checks.Count} assertions).");
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
