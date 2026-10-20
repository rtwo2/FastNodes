using System.Net;
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

        using (var exactContent = new ByteArrayContent(Encoding.UTF8.GetBytes("12345678")))
        {
            Checks.Equal("12345678",
                CollectorType.ReadContentLimitedAsync(exactContent, 8, CancellationToken.None).GetAwaiter().GetResult(),
                "bounded HTTP reader accepts a body exactly at its byte limit");
        }
        var oversizedContent = new ByteArrayContent(Encoding.UTF8.GetBytes("123456789"));
        bool oversizedBodyRejected = false;
        try
        {
            _ = CollectorType.ReadContentLimitedAsync(oversizedContent, 8, CancellationToken.None)
                .GetAwaiter().GetResult();
        }
        catch (InvalidDataException) { oversizedBodyRejected = true; }
        finally { oversizedContent.Dispose(); }
        Checks.That(oversizedBodyRejected,
            "bounded HTTP reader rejects bodies larger than its byte limit");

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

        var ipv6 = CollectorType.ParseProxyLine(
            "vless://123e4567-e89b-12d3-a456-426614174000@[2001:4860:4860::8888]:443?security=reality&type=tcp&sni=example.com&flow=xtls-rprx-vision&pbk=abc&sid=01#ipv6");
        Checks.That(ipv6 is not null, "VLESS IPv6 link parses");
        Checks.Equal("2001:4860:4860::8888", ipv6!.Host, "IPv6 host is normalized without brackets");
        Checks.Equal("443", ipv6.Port, "VLESS port");
        Checks.Equal("example.com", ipv6.Sni, "VLESS SNI");
        Checks.Equal("xtls-rprx-vision", ipv6.Flow, "VLESS flow");

        var vmessJson = """{"add":"vmess.example.com","port":"8443","id":"01234567-89ab-cdef-0123-456789abcdef","net":"ws","tls":"tls","host":"sni.example.com","path":"/ws","aid":"0"}""";
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
        Checks.Equal("sni.example.com", vmess.Sni, "VMess SNI");

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
        Checks.Equal("🇩🇪 Germany (DE) - Frankfurt am Main | edge-01.example.net:443", germanNodeName,
            "client labels follow flag country ISO - city | host:port format");
        Checks.Equal("🇺🇸 United States (US) - San Francisco | a-much-longer-node-name.example.org:8443", usNodeName,
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
        Checks.Equal("🌐 Unknown (XX) - Unknown | [2001:4860:4860::8888]:443",
            CollectorType.BuildClientNodeName("XX", "🌐 Unknown", "2001:4860:4860::8888", "443"),
            "unknown GeoIP labels and IPv6 endpoints remain well-formed");
        Checks.Equal("🇩🇪 Germany (DE) - Frankfurt am Main | edge.example.net:443",
            CollectorType.BuildFallbackNodeName("🇩🇪 Frankfurt am Main, DE · Hetzner Online · abc123",
                "edge.example.net", "443"),
            "legacy verified snapshot remarks migrate to the new country-city-endpoint format");
        Checks.Equal("🇩🇪 Germany (DE) - Unknown | edge.example.net:443",
            CollectorType.BuildFallbackNodeName("🇩🇪 Germany · Hetzner Online",
                "edge.example.net", "443"),
            "country-level legacy remarks do not invent a city");
        Checks.Equal("🇩🇪 Germany (DE) - Frankfurt am Main | edge.example.net:443",
            CollectorType.BuildFallbackNodeName("🇩🇪 Germany (DE) - Frankfurt am Main | old.example.net:8443",
                "edge.example.net", "443"),
            "already-renamed fallback remarks are normalized to the current endpoint");
        Checks.Equal("🌐 Unknown (XX) - Unknown | edge.example.net:443",
            CollectorType.BuildFallbackNodeName("🌐 Unknown (XX) - Unknown | old.example.net:8443",
                "edge.example.net", "443"),
            "already-renamed unknown-country fallback remarks remain well-formed");
        Checks.Equal("🇩🇪 Germany (DE) - Frankfurt (Main) | edge.example.net:443",
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
        """;
        var convertedFlatClash = CollectorType.DecodeAndExtractLines(flatClash, "https://example.net/config.yaml");
        Checks.Equal(2, convertedFlatClash.Count,
            "flow-style Clash YAML routes to the unified structured converter");
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
