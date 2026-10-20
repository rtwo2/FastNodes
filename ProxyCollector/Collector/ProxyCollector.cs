using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using MaxMind.GeoIP2;
using ProxyCollector.Configuration;
using ProxyCollector.Services;
using YamlDotNet.Serialization;

namespace ProxyCollector.Collector
{
    public partial class ProxyCollector
    {
        private readonly HttpClient _http = new(new SocketsHttpHandler
        {
            // Some non-GitHub sources always serve gzip regardless of Accept-Encoding;
            // without this the body arrives as raw gzip bytes containing no "://" —
            // the source yields zero nodes, silently.
            AutomaticDecompression = DecompressionMethods.All,
            // Source lists and nested proxy-provider URLs are data from public feeds.
            // Disable ambient proxies so the callback sees the destination itself, and
            // validate every resolved address at connection time (including redirects).
            UseProxy = false,
            ConnectCallback = ConnectToPublicAddressAsync
        })
        {
            Timeout = TimeSpan.FromSeconds(40),
            DefaultRequestHeaders = { { "User-Agent", "FastNodes/6.21 (+https://github.com/rtwo2/FastNodes)" } }
        };
        private static async ValueTask<Stream> ConnectToPublicAddressAsync(
            SocketsHttpConnectionContext context, CancellationToken cancellationToken)
        {
            var endpoint = context.DnsEndPoint;
            IPAddress[] addresses = IPAddress.TryParse(endpoint.Host, out var literal)
                ? new[] { literal }
                : await Dns.GetHostAddressesAsync(endpoint.Host, cancellationToken);

            if (addresses.Length == 0)
                throw new HttpRequestException($"Destination host has no addresses: {endpoint.Host}");

            // Reject mixed answers rather than silently selecting only the public one.
            // Connect to the exact validated IP below to avoid a second DNS lookup (and
            // DNS-rebinding between validation and connection).
            var unsafeAddress = addresses.FirstOrDefault(IsPrivateOrReservedIp);
            if (unsafeAddress is not null)
                throw new HttpRequestException(
                    $"Blocked non-public HTTP destination {endpoint.Host} → {unsafeAddress}");

            Exception? lastError = null;
            foreach (var address in addresses)
            {
                var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
                {
                    NoDelay = true
                };
                try
                {
                    await socket.ConnectAsync(new IPEndPoint(address, endpoint.Port), cancellationToken);
                    return new NetworkStream(socket, ownsSocket: true);
                }
                catch (OperationCanceledException)
                {
                    socket.Dispose();
                    throw;
                }
                catch (Exception ex)
                {
                    socket.Dispose();
                    lastError = ex;
                }
            }

            throw new HttpRequestException(
                $"Could not connect to any public address for {endpoint.Host}:{endpoint.Port}", lastError);
        }

        private readonly Lazy<IPToCountryResolver> _resolverLazy = new(() => new IPToCountryResolver());
        private IPToCountryResolver Resolver => _resolverLazy.Value;

        // Explicit protocol whitelist — expanded to cover more real-world proxy schemes,
        // not just the original short list. A completely open "accept any scheme" approach
        // was tried and reverted: it let junk/non-proxy scheme fragments through as if they
        // were real protocols, which isn't worth the marginal coverage gain.
        private static readonly HashSet<string> ValidProtocols = new(StringComparer.OrdinalIgnoreCase)
        {
            "vmess", "vless", "trojan", "ss", "shadowsocks", "ssr",
            "hysteria", "hysteria2", "hy2", "tuic",
            "naive", "anytls", "brook", "snell", "juicity", "mieru",
            "wireguard", "wg", "socks5", "socks4", "socks"
        };

        // One source of truth for scheme matching — previously the same alternation was
        // copy-pasted into three separate regex literals, so adding a protocol meant
        // editing four places (whitelist + 3 regexes) that could silently drift apart.
        // Sorted length-descending so a short scheme can't shadow a longer one that
        // starts with it. The lookbehind stops mid-word matches ("ss://" inside "wss://").
        private static readonly string SchemeAlternation =
            string.Join("|", ValidProtocols.OrderByDescending(s => s.Length));

        private static readonly Regex SchemeLineRegex = new(
            $@"(?<![a-zA-Z])({SchemeAlternation})://(?>\S+)(?!\s*@)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex SchemeHtmlRegex = new(
            $@"(?<![a-zA-Z])({SchemeAlternation})://(?>[^\s""'<>]+)(?!\s*@)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // ====================== HOST FILTER (EXACT/SUFFIX ONLY) ======================
        // The Cloudflare/WARP exclusion is applied as a separate, explicit pipeline stage
        // after DNS is warmed and again at the final-output boundary. Keep this comment
        // limited to the unrelated generic host checks below so the two policies cannot
        // accidentally be confused or silently drift apart.
        private static readonly HashSet<string> CdnIpExact = new()
        {
            "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
        };

        private static readonly HashSet<string> SuspiciousHostSuffixes = new(StringComparer.OrdinalIgnoreCase)
        {
            "ngrok.io", "ngrok-free.app", "loca.lt", "serveo.net",
        };

        // Placeholder/template domains left in example configs — these are never real
        // servers, just tutorial/documentation filler that occasionally leaks into a
        // source verbatim.
        private static readonly HashSet<string> PlaceholderHosts = new(StringComparer.OrdinalIgnoreCase)
        {
            "example.com", "example.org", "example.net", "yourdomain.com", "your-domain.com",
            "yourserver.com", "your-server.com", "domain.com", "server.com", "test.com",
            "changeme.com", "host.com", "mydomain.com", "myserver.com", "placeholder.com",
        };

        // RFC 2606 — TLDs reserved specifically for documentation/testing, never delegated
        // for real use.
        private static readonly string[] ReservedTlds = { ".test", ".example", ".invalid", ".localhost" };

        // Placeholder credentials (UUID/password) left in example configs — all-zero or
        // all-same-char UUIDs, "xxxx"-style templates, and literal "change this" style
        // strings. Deliberately narrow: only matches obvious template values.
        private static readonly Regex PlaceholderCredentialPattern = new(
            @"^(0{8}-0{4}-0{4}-0{4}-0{12}$" +                    // all-zero UUID
            @"|[0-9a-fx]{8}-x{4}-x{4}-x{4}-x{12}$" +             // xxxx-style UUID template
            @"|([0-9a-f])\1{7}-\1{3}-\1{3}-\1{3}-\1{11}$" +      // all-same-char UUID (11111111-1111-...)
            @"|your[-_]?(uuid|password|pass|id|key|token)" +    // "your-uuid", "your_password", ...
            @"|change[-_]?(me|this)" +                           // "changeme", "change-this"
            @"|placeholder|password123|123456|00000000)",
            RegexOptions.IgnoreCase);

        // Protocols that cannot authenticate without a credential — a node without one
        // can never connect, no matter how healthy the server is. socks/socks4/socks5
        // are deliberately absent: public SOCKS proxies legitimately run credential-less.
        private static readonly HashSet<string> CredentialRequiredProtocols = new(StringComparer.OrdinalIgnoreCase)
        { "vless", "vmess", "trojan", "ss", "ssr", "hysteria", "hysteria2", "tuic",
          "naive", "anytls", "brook", "snell", "juicity" };

        // Private/reserved IP ranges can never be reachable as a public proxy from outside
        // that network — these only ever show up as leftover example/template values.
        // Hardened: IPv4-mapped IPv6 (::ffff:10.0.0.1) previously slipped past every
        // check by parsing as IPv6; TEST-NETs (the IP equivalent of example.com),
        // 198.18.0.0/15, 192.0.0.0/24, the entire multicast/reserved block (224+), and
        // 2001:db8::/32 (documentation) are now covered too.
        internal static bool IsPrivateOrReservedIp(IPAddress ip)
        {
            var b = ip.GetAddressBytes();

            // Only the actual ::ffff:0:0/96 IPv4-mapped range should be mapped.
            // Checking bytes 10–11 alone misclassifies unrelated global IPv6 addresses
            // whose sixth hextet happens to be ffff.
            if (ip.IsIPv4MappedToIPv6)
                return IsPrivateOrReservedIp(ip.MapToIPv4());

            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                if (b[0] == 0 || b[0] == 10 || b[0] == 127) return true;                // 0/8, 10/8, 127/8
                if (b[0] == 172 && b[1] is >= 16 and <= 31) return true;                // 172.16.0.0/12
                if (b[0] == 192 && b[1] == 168) return true;                            // 192.168.0.0/16
                if (b[0] == 169 && b[1] == 254) return true;                            // 169.254.0.0/16 link-local
                if (b[0] == 100 && b[1] is >= 64 and <= 127) return true;               // 100.64.0.0/10 CGNAT
                if (b[0] >= 224) return true;                                           // multicast + reserved + broadcast
                if (b[0] == 192 && b[1] == 0 && (b[2] == 0 || b[2] == 2)) return true;  // 192.0.0.0/24, TEST-NET-1
                if (b[0] == 198 && (b[1] == 18 || b[1] == 19)) return true;             // 198.18.0.0/15 benchmark
                if (b[0] == 198 && b[1] == 51 && b[2] == 100) return true;              // TEST-NET-2
                if (b[0] == 203 && b[1] == 0 && b[2] == 113) return true;               // TEST-NET-3
                return false;
            }
            if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            {
                // ::/96 (except mapped IPv4, handled above) is unspecified, loopback,
                // or deprecated IPv4-compatible space, none of which is a public endpoint.
                if (b.Take(12).All(value => value == 0)) return true;
                if (b[0] == 0xFF) return true;                                          // ff00::/8 multicast
                if (IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal) return true;
                if ((b[0] & 0xFE) == 0xFC) return true;                                 // fc00::/7 unique local
                if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) return true; // 2001:db8::/32 docs
            }
            return false;
        }

        // DNS names can return several A/AAAA records. A host is unsafe if ANY
        // answer is private/reserved or on the loaded IPv4 blacklist; checking only the
        // representative address can let a mixed public/private DNS answer through.
        internal static bool HasUnsafeResolvedAddress(IEnumerable<IPAddress> addresses)
            => addresses.Any(ip => IsPrivateOrReservedIp(ip) || IsFireholBlacklisted(ip));

        internal static bool IsSafeDnsCanaryAnswer(IEnumerable<IPAddress> addresses)
        {
            var materialized = addresses.ToArray();
            return materialized.Length > 0 && !HasUnsafeResolvedAddress(materialized);
        }

        private static bool IsPlaceholderCredential(string credential)
        {
            if (string.IsNullOrEmpty(credential)) return false;
            string normalized = credential.Trim();
            try { normalized = Uri.UnescapeDataString(normalized); }
            catch { /* malformed escapes remain subject to the ordinary pattern check */ }
            return PlaceholderCredentialPattern.IsMatch(normalized);
        }

        internal static bool IsPlaceholderCredential(string protocol, string credential)
        {
            if (IsPlaceholderCredential(credential)) return true;

            // Several share-link formats store two fields in Credential. Checking only
            // the beginning misses placeholder passwords after the separator (for
            // example "aes-128-gcm:password123" or "uuid:123456").
            string proto = NormalizeProto(protocol);
            if (proto is not ("ss" or "ssr" or "tuic" or "juicity" or "naive" or "socks" or "socks4" or "socks5"))
                return false;

            int separator = credential.IndexOf(':');
            return separator >= 0 &&
                (IsPlaceholderCredential(credential[..separator]) ||
                 IsPlaceholderCredential(credential[(separator + 1)..]));
        }

        private static readonly Dictionary<string, string> Flags = new(StringComparer.OrdinalIgnoreCase)
        {
            {"AD","🇦🇩"},{"AE","🇦🇪"},{"AF","🇦🇫"},{"AG","🇦🇬"},{"AI","🇦🇮"},{"AL","🇦🇱"},{"AM","🇦🇲"},
            {"AO","🇦🇴"},{"AQ","🇦🇶"},{"AR","🇦🇷"},{"AS","🇦🇸"},{"AT","🇦🇹"},{"AU","🇦🇺"},{"AW","🇦🇼"},
            {"AX","🇦🇽"},{"AZ","🇦🇿"},{"BA","🇧🇦"},{"BB","🇧🇧"},{"BD","🇧🇩"},{"BE","🇧🇪"},{"BF","🇧🇫"},
            {"BG","🇧🇬"},{"BH","🇧🇭"},{"BI","🇧🇮"},{"BJ","🇧🇯"},{"BL","🇧🇱"},{"BM","🇧🇲"},{"BN","🇧🇳"},
            {"BO","🇧🇴"},{"BQ","🇧🇶"},{"BR","🇧🇷"},{"BS","🇧🇸"},{"BT","🇧🇹"},{"BV","🇧🇻"},{"BW","🇧🇼"},
            {"BY","🇧🇾"},{"BZ","🇧🇿"},{"CA","🇨🇦"},{"CC","🇨🇨"},{"CD","🇨🇩"},{"CF","🇨🇫"},{"CG","🇨🇬"},
            {"CH","🇨🇭"},{"CI","🇨🇮"},{"CK","🇨🇰"},{"CL","🇨🇱"},{"CM","🇨🇲"},{"CN","🇨🇳"},{"CO","🇨🇴"},
            {"CR","🇨🇷"},{"CU","🇨🇺"},{"CV","🇨🇻"},{"CW","🇨🇼"},{"CX","🇨🇽"},{"CY","🇨🇾"},{"CZ","🇨🇿"},
            {"DE","🇩🇪"},{"DJ","🇩🇯"},{"DK","🇩🇰"},{"DM","🇩🇲"},{"DO","🇩🇴"},{"DZ","🇩🇿"},{"EC","🇪🇨"},
            {"EE","🇪🇪"},{"EG","🇪🇬"},{"EH","🇪🇭"},{"ER","🇪🇷"},{"ES","🇪🇸"},{"ET","🇪🇹"},{"FI","🇫🇮"},
            {"FJ","🇫🇯"},{"FK","🇫🇰"},{"FM","🇫🇲"},{"FO","🇫🇴"},{"FR","🇫🇷"},{"GA","🇬🇦"},{"GB","🇬🇧"},
            {"GD","🇬🇩"},{"GE","🇬🇪"},{"GF","🇬🇫"},{"GG","🇬🇬"},{"GH","🇬🇭"},{"GI","🇬🇮"},{"GL","🇬🇱"},
            {"GM","🇬🇲"},{"GN","🇬🇳"},{"GP","🇬🇵"},{"GQ","🇬🇶"},{"GR","🇬🇷"},{"GS","🇬🇸"},{"GT","🇬🇹"},
            {"GU","🇬🇺"},{"GW","🇬🇼"},{"GY","🇬🇾"},{"HK","🇭🇰"},{"HM","🇭🇲"},{"HN","🇭🇳"},{"HR","🇭🇷"},
            {"HT","🇭🇹"},{"HU","🇭🇺"},{"ID","🇮🇩"},{"IE","🇮🇪"},{"IL","🇮🇱"},{"IM","🇮🇲"},{"IN","🇮🇳"},
            {"IO","🇮🇴"},{"IQ","🇮🇶"},{"IR","🇮🇷"},{"IS","🇮🇸"},{"IT","🇮🇹"},{"JE","🇯🇪"},{"JM","🇯🇲"},
            {"JO","🇯🇴"},{"JP","🇯🇵"},{"KE","🇰🇪"},{"KG","🇰🇬"},{"KH","🇰🇭"},{"KI","🇰🇮"},{"KM","🇰🇲"},
            {"KN","🇰🇳"},{"KP","🇰🇵"},{"KR","🇰🇷"},{"KW","🇰🇼"},{"KY","🇰🇾"},{"KZ","🇰🇿"},{"LA","🇱🇦"},
            {"LB","🇱🇧"},{"LC","🇱🇨"},{"LI","🇱🇮"},{"LK","🇱🇰"},{"LR","🇱🇷"},{"LS","🇱🇸"},{"LT","🇱🇹"},
            {"LU","🇱🇺"},{"LV","🇱🇻"},{"LY","🇱🇾"},{"MA","🇲🇦"},{"MC","🇲🇨"},{"MD","🇲🇩"},{"ME","🇲🇪"},
            {"MF","🇲🇫"},{"MG","🇲🇬"},{"MH","🇲🇭"},{"MK","🇲🇰"},{"ML","🇲🇱"},{"MM","🇲🇲"},{"MN","🇲🇳"},
            {"MO","🇲🇴"},{"MP","🇲🇵"},{"MQ","🇲🇶"},{"MR","🇲🇷"},{"MS","🇲🇸"},{"MT","🇲🇹"},{"MU","🇲🇺"},
            {"MV","🇲🇻"},{"MW","🇲🇼"},{"MX","🇲🇽"},{"MY","🇲🇾"},{"MZ","🇲🇿"},{"NA","🇳🇦"},{"NC","🇳🇨"},
            {"NE","🇳🇪"},{"NF","🇳🇫"},{"NG","🇳🇬"},{"NI","🇳🇮"},{"NL","🇳🇱"},{"NO","🇳🇴"},{"NP","🇳🇵"},
            {"NR","🇳🇷"},{"NU","🇳🇺"},{"NZ","🇳🇿"},{"OM","🇴🇲"},{"PA","🇵🇦"},{"PE","🇵🇪"},{"PF","🇵🇫"},
            {"PG","🇵🇬"},{"PH","🇵🇭"},{"PK","🇵🇰"},{"PL","🇵🇱"},{"PM","🇵🇲"},{"PN","🇵🇳"},{"PR","🇵🇷"},
            {"PS","🇵🇸"},{"PT","🇵🇹"},{"PW","🇵🇼"},{"PY","🇵🇾"},{"QA","🇶🇦"},{"RE","🇷🇪"},{"RO","🇷🇴"},
            {"RS","🇷🇸"},{"RU","🇷🇺"},{"RW","🇷🇼"},{"SA","🇸🇦"},{"SB","🇸🇧"},{"SC","🇸🇨"},{"SD","🇸🇩"},
            {"SE","🇸🇪"},{"SG","🇸🇬"},{"SH","🇸🇭"},{"SI","🇸🇮"},{"SJ","🇸🇯"},{"SK","🇸🇰"},{"SL","🇸🇱"},
            {"SM","🇸🇲"},{"SN","🇸🇳"},{"SO","🇸🇴"},{"SR","🇸🇷"},{"SS","🇸🇸"},{"ST","🇸🇹"},{"SV","🇸🇻"},
            {"SX","🇸🇽"},{"SY","🇸🇾"},{"SZ","🇸🇿"},{"TC","🇹🇨"},{"TD","🇹🇩"},{"TF","🇹🇫"},{"TG","🇹🇬"},
            {"TH","🇹🇭"},{"TJ","🇹🇯"},{"TK","🇹🇰"},{"TL","🇹🇱"},{"TM","🇹🇲"},{"TN","🇹🇳"},{"TO","🇹🇴"},
            {"TR","🇹🇷"},{"TT","🇹🇹"},{"TV","🇹🇻"},{"TW","🇹🇼"},{"TZ","🇹🇿"},{"UA","🇺🇦"},{"UG","🇺🇬"},
			{"US","🇺🇸"},{"UY","🇺🇾"},{"UZ","🇺🇿"},{"VA","🇻🇦"},{"VC","🇻🇨"},{"VE","🇻🇪"},
            {"VG","🇻🇬"},{"VI","🇻🇮"},{"VN","🇻🇳"},{"VU","🇻🇺"},{"WF","🇼🇫"},{"WS","🇼🇸"},{"YE","🇾🇪"},
            {"YT","🇾🇹"},{"ZA","🇿🇦"},{"ZM","🇿🇲"},{"ZW","🇿🇼"},{"XK","🇽🇰"},
            {"EU","🇪🇺"},{"UM","🇺🇲"}
        };

        private static readonly Dictionary<string, string> CountryToContinent = new(StringComparer.OrdinalIgnoreCase)
        {
            // Territories with a flag but no obvious continent from the code alone —
            // added so a node here isn't silently excluded from every continents/ file.
            {"AQ","Antarctica"},{"AS","Oceania"},{"AX","Europe"},{"BQ","NorthAmerica"},
            {"BV","Antarctica"},{"CC","Asia"},{"CX","Asia"},{"FO","Europe"},{"GS","Antarctica"},
            {"HM","Antarctica"},{"IO","Asia"},{"PN","Oceania"},{"SH","Africa"},{"SJ","Europe"},
            {"SX","NorthAmerica"},{"TF","Antarctica"},{"UM","Oceania"},
            {"EU","Europe"},
            {"AD","Europe"},{"AL","Europe"},{"AM","Europe"},{"AT","Europe"},{"AZ","Europe"},
            {"BA","Europe"},{"BE","Europe"},{"BG","Europe"},{"BY","Europe"},{"CH","Europe"},
            {"CY","Europe"},{"CZ","Europe"},{"DE","Europe"},{"DK","Europe"},{"EE","Europe"},
            {"ES","Europe"},{"FI","Europe"},{"FR","Europe"},{"GB","Europe"},{"GE","Europe"},
            {"GG","Europe"},{"GI","Europe"},{"GR","Europe"},{"HR","Europe"},{"HU","Europe"},
            {"IE","Europe"},{"IM","Europe"},{"IS","Europe"},{"IT","Europe"},{"JE","Europe"},
            {"LI","Europe"},{"LT","Europe"},{"LU","Europe"},{"LV","Europe"},{"MC","Europe"},
            {"MD","Europe"},{"ME","Europe"},{"MK","Europe"},{"MT","Europe"},{"NL","Europe"},
            {"NO","Europe"},{"PL","Europe"},{"PT","Europe"},{"RO","Europe"},{"RS","Europe"},
            {"RU","Europe"},{"SE","Europe"},{"SI","Europe"},{"SK","Europe"},{"SM","Europe"},
            {"TR","Europe"},{"UA","Europe"},{"VA","Europe"},{"XK","Europe"},
            {"AE","Asia"},{"AF","Asia"},{"BD","Asia"},{"BH","Asia"},{"BN","Asia"},
            {"BT","Asia"},{"CN","Asia"},{"HK","Asia"},{"ID","Asia"},{"IL","Asia"},
            {"IN","Asia"},{"IQ","Asia"},{"IR","Asia"},{"JO","Asia"},{"JP","Asia"},
            {"KG","Asia"},{"KH","Asia"},{"KP","Asia"},{"KR","Asia"},{"KW","Asia"},
            {"KZ","Asia"},{"LA","Asia"},{"LB","Asia"},{"LK","Asia"},{"MM","Asia"},
            {"MN","Asia"},{"MO","Asia"},{"MV","Asia"},{"MY","Asia"},{"NP","Asia"},
            {"OM","Asia"},{"PH","Asia"},{"PK","Asia"},{"PS","Asia"},{"QA","Asia"},
            {"SA","Asia"},{"SG","Asia"},{"SY","Asia"},{"TH","Asia"},{"TJ","Asia"},
            {"TL","Asia"},{"TM","Asia"},{"TW","Asia"},{"UZ","Asia"},{"VN","Asia"},{"YE","Asia"},
            {"AG","NorthAmerica"},{"AI","NorthAmerica"},{"AW","NorthAmerica"},{"BB","NorthAmerica"},
            {"BL","NorthAmerica"},{"BM","NorthAmerica"},{"BS","NorthAmerica"},{"BZ","NorthAmerica"},
            {"CA","NorthAmerica"},{"CR","NorthAmerica"},{"CU","NorthAmerica"},{"CW","NorthAmerica"},
            {"DM","NorthAmerica"},{"DO","NorthAmerica"},{"GD","NorthAmerica"},{"GL","NorthAmerica"},
            {"GP","NorthAmerica"},{"GT","NorthAmerica"},{"HN","NorthAmerica"},{"HT","NorthAmerica"},
            {"JM","NorthAmerica"},{"KN","NorthAmerica"},{"KY","NorthAmerica"},{"LC","NorthAmerica"},
            {"MF","NorthAmerica"},{"MQ","NorthAmerica"},{"MS","NorthAmerica"},{"MX","NorthAmerica"},
            {"NI","NorthAmerica"},{"PA","NorthAmerica"},{"PM","NorthAmerica"},{"PR","NorthAmerica"},
            {"SV","NorthAmerica"},{"TC","NorthAmerica"},{"TT","NorthAmerica"},{"US","NorthAmerica"},
            {"VC","NorthAmerica"},{"VG","NorthAmerica"},{"VI","NorthAmerica"},
            {"AR","SouthAmerica"},{"BO","SouthAmerica"},{"BR","SouthAmerica"},{"CL","SouthAmerica"},
            {"CO","SouthAmerica"},{"EC","SouthAmerica"},{"FK","SouthAmerica"},{"GF","SouthAmerica"},
            {"GY","SouthAmerica"},{"PE","SouthAmerica"},{"PY","SouthAmerica"},{"SR","SouthAmerica"},
            {"UY","SouthAmerica"},{"VE","SouthAmerica"},
            {"AO","Africa"},{"BF","Africa"},{"BI","Africa"},{"BJ","Africa"},{"BW","Africa"},
            {"CD","Africa"},{"CF","Africa"},{"CG","Africa"},{"CI","Africa"},{"CM","Africa"},
            {"CV","Africa"},{"DJ","Africa"},{"DZ","Africa"},{"EG","Africa"},{"EH","Africa"},
            {"ER","Africa"},{"ET","Africa"},{"GA","Africa"},{"GH","Africa"},{"GM","Africa"},
            {"GN","Africa"},{"GQ","Africa"},{"GW","Africa"},{"KE","Africa"},{"KM","Africa"},
            {"LR","Africa"},{"LS","Africa"},{"LY","Africa"},{"MA","Africa"},{"MG","Africa"},
            {"ML","Africa"},{"MR","Africa"},{"MU","Africa"},{"MW","Africa"},{"MZ","Africa"},
            {"NA","Africa"},{"NE","Africa"},{"NG","Africa"},{"RE","Africa"},{"RW","Africa"},
            {"SC","Africa"},{"SD","Africa"},{"SL","Africa"},{"SN","Africa"},{"SO","Africa"},
            {"SS","Africa"},{"ST","Africa"},{"SZ","Africa"},{"TD","Africa"},{"TG","Africa"},
            {"TN","Africa"},{"TZ","Africa"},{"UG","Africa"},{"YT","Africa"},{"ZA","Africa"},
            {"ZM","Africa"},{"ZW","Africa"},
            {"AU","Oceania"},{"CK","Oceania"},{"FJ","Oceania"},{"FM","Oceania"},{"GU","Oceania"},
            {"KI","Oceania"},{"MH","Oceania"},{"MP","Oceania"},{"NC","Oceania"},{"NF","Oceania"},
            {"NR","Oceania"},{"NU","Oceania"},{"NZ","Oceania"},{"PF","Oceania"},{"PG","Oceania"},
            {"PW","Oceania"},{"SB","Oceania"},{"TK","Oceania"},{"TO","Oceania"},{"TV","Oceania"},
            {"VU","Oceania"},{"WF","Oceania"},{"WS","Oceania"},
        };

        // RESTORED: proximity feeds the composite SCORE and probe-budget priority
        // (which nodes get Xray/TLS attention first) — NOT the output file ordering,
        // which stays alphabetical by Host. Without it, US/CF nodes dominate every
        // Azure-vantage signal and flood top.txt.
        private static readonly HashSet<string> NearIranCodes = new(StringComparer.OrdinalIgnoreCase)
        {
            "TR", "IQ", "AE", "AM", "AZ", "TM", "AF", "PK", "QA", "KW", "BH", "OM", "SA", "GE", "KZ"
        };

        // v6.18: EMPIRICAL region ladder (user feedback): Europe performs best,
        // IR+neighbors next, US/CA partially, Asia & CF-fronted rarely. Feeds the
        // composite score AND probe-budget priority. Output order stays alphabetical.
        // Tier 2 deliberately skipped to widen the Europe↔NorthAmerica gap.
        // Geography is a ranking prior only, never a hard eligibility gate for the
        // international top/verified outputs. Keep these helpers for modest scoring
        // and probe ordering, not exclusion.
        private static bool IsPreferredRegion(string cc)
        {
            if (string.IsNullOrEmpty(cc) || cc == "XX") return false;
            if (cc.Equals("IR", StringComparison.OrdinalIgnoreCase)) return true;
            if (NearIranCodes.Contains(cc)) return true;
            return CountryToContinent.TryGetValue(cc, out var cont) && cont == "Europe";
        }

        private static int ProximityTier(string cc)
        {
            if (string.IsNullOrEmpty(cc) || cc == "XX") return 9;
            if (cc.Equals("IR", StringComparison.OrdinalIgnoreCase) || NearIranCodes.Contains(cc)) return 1;

            if (CountryToContinent.TryGetValue(cc, out var cont))
            {
                return cont switch
                {
                    "Europe" => 0,        // empirical best performers
                    "NorthAmerica" => 3,  // US/CA: some work
                    "Africa" => 4,
                    "Asia" => 5,          // empirically weak from this vantage
                    "SouthAmerica" => 6,
                    "Oceania" => 7,
                    _ => 8
                };
            }
            return 8;
        }
		
        // Per-source yield accounting. Lines = extracted lines after decode (0 means the
        // fetch failed / body was empty / response wasn't recognizable). Parsed = lines
        // ParseProxyLine accepted. Unique = nodes this source was FIRST to contribute —
        // the only metric that ranks a source's real value, since a source that only
        // re-publishes other sources' nodes contributes nothing new.
        // Fields (not properties) so Interlocked works on them in the parallel fetch loop.
        private sealed class SourceStat
        {
            public int FetchSuccesses;
            public int RawBytes;
            public int RawLines;
            public int Lines; // proxy-like lines extracted by the decoder
            public int Parsed;
            public int Unique;
            public int ProviderSuccesses;
            public int ProviderFailures;
        }

        // ====================== LOGGING ======================
        private static void Log(string msg, ConsoleColor color = ConsoleColor.White)
        { Console.ForegroundColor = color; Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {msg}"); Console.ResetColor(); }
        private static void LogSuccess(string msg) => Log("✅ " + msg, ConsoleColor.Green);
        private static void LogError(string msg)   => Log("❌ " + msg, ConsoleColor.Red);
        private static void LogInfo(string msg)    => Log("ℹ️  " + msg, ConsoleColor.Cyan);
        private static void LogWarning(string msg) => Log("⚠️  " + msg, ConsoleColor.Yellow);

        // GitHub Actions workflow commands — render each pipeline stage as a collapsible
        // section in the Actions log viewer (with a chevron to expand/collapse), instead of
        // one long flat wall of text. These are plain stdout lines GH's runner intercepts;
        // they're a no-op (just printed literally) anywhere else.
        private static void GroupStart(string title) => Console.WriteLine($"::group::{title}");
        private static void GroupEnd() => Console.WriteLine("::endgroup::");

        private static void Banner(string version)
        {
            const int w = 56;
            void Center(string s)
            {
                int pad = Math.Max(0, (w - s.Length) / 2);
                Console.WriteLine("\u2551" + new string(' ', pad) + s + new string(' ', w - s.Length - pad) + "\u2551");
            }
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("\u2554" + new string('\u2550', w) + "\u2557");
            Center($"🚀 FastNodes {version}");
            Center("The World's Smartest Free V2Ray Collector");
            Console.WriteLine("\u255A" + new string('\u2550', w) + "\u255D");
            Console.ResetColor();
        }

        private static void SummaryTable(List<FinalProxy> proxies, TimeSpan elapsed, int sourceCount, int rawLineCount)
        {
            const int w = 56;
            void Row(string label, string value)
            {
                string line = $" {label,-28}{value,26} ";
                Console.WriteLine("\u2502" + line + "\u2502");
            }
            void Divider(char l, char mid, char r) => Console.WriteLine(l + new string(mid, w) + r);

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Green;
            Divider('\u250C', '\u2500', '\u2510');
            Console.WriteLine("\u2502" + " RUN SUMMARY".PadRight(w) + "\u2502");
            Divider('\u251C', '\u2500', '\u2524');
            Console.ResetColor();

            Row("Sources", sourceCount.ToString("N0"));
            Row("Raw lines fetched", rawLineCount.ToString("N0"));
            Row("Total proxies", proxies.Count.ToString("N0"));
            Row("Elapsed", $"{elapsed:hh\\:mm\\:ss}");

            Console.ForegroundColor = ConsoleColor.Green;
            Divider('\u251C', '\u2500', '\u2524');
            Console.ResetColor();

            foreach (var g in proxies.GroupBy(p => p.Proto).OrderByDescending(g => g.Count()))
                Row(g.Key, g.Count().ToString("N0") + " nodes");

            Console.ForegroundColor = ConsoleColor.Green;
            Divider('\u251C', '\u2500', '\u2524');
            Console.ResetColor();

            foreach (var g in proxies.GroupBy(p => p.Continent).Where(g => g.Key != "Unknown").OrderByDescending(g => g.Count()))
                Row(g.Key, g.Count().ToString("N0") + " nodes");

            Console.ForegroundColor = ConsoleColor.Green;
            Divider('\u2514', '\u2500', '\u2518');
            Console.ResetColor();
            Console.WriteLine();
        }

        // ====================== GEOIP DOWNLOAD ======================
        // Rewritten: one loop instead of three copy-pasted blocks. Skips files that
        // already exist (pairs with the workflow's actions/cache step). REQUIRED
        // databases now fail the run loudly — a green run with no City/Country DB
        // silently published everything as 🌐 Unknown and dropped all country/continent
        // files, which is worse than a red run. ASN stays optional.
        internal static bool IsValidGeoIpDatabase(string path)
        {
            if (!File.Exists(path) || new FileInfo(path).Length == 0) return false;
            try
            {
                // Opening the reader validates the MaxMind database header/metadata. A
                // non-empty HTTP error page or interrupted download is not a usable cache.
                using var reader = new DatabaseReader(path);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static async Task DownloadGeoIPDatabases(HttpClient http)
        {
            var dbs = new (string File, string Label, bool Required)[]
            {
                ("ProxyCollector/GeoLite2-City.mmdb",    "GeoLite2-City.mmdb",    true),
                ("ProxyCollector/GeoLite2-Country.mmdb", "GeoLite2-Country.mmdb", true),
                ("ProxyCollector/GeoLite2-ASN.mmdb",     "GeoLite2-ASN.mmdb",     false),
            };
            var failed = new List<string>();

            foreach (var (file, label, required) in dbs)
            {
                if (IsValidGeoIpDatabase(file))
                {
                    LogInfo($"{label} present and valid (cache), skipping.");
                    continue;
                }

                if (File.Exists(file))
                    LogWarning($"{label} cache is empty or invalid; attempting a fresh download.");

                LogInfo($"Downloading {label}...");
                bool ok = false;
                string tempFile = file + ".download.tmp";
                try { Directory.CreateDirectory(Path.GetDirectoryName(file)!); }
                catch (Exception ex)
                {
                    LogWarning($"Cannot prepare directory for {label}: {ex.Message}");
                    if (required) failed.Add(label);
                    continue;
                }

                foreach (var host in new[]
                {
                    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/",
                    "https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/"
                })
                {
                    try
                    {
                        if (File.Exists(tempFile)) File.Delete(tempFile);
                        // ResponseHeadersRead ends HttpClient's timeout when headers arrive.
                        // This per-mirror token must also cover the streamed database body,
                        // otherwise a stalled CDN can hang the workflow indefinitely.
                        using var mirrorCts = new CancellationTokenSource(TimeSpan.FromSeconds(90));
                        using var resp = await http.GetAsync(
                            host + label, HttpCompletionOption.ResponseHeadersRead, mirrorCts.Token);
                        resp.EnsureSuccessStatusCode();
                        await using (var fs = new FileStream(
                            tempFile, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                        {
                            await resp.Content.CopyToAsync(fs, mirrorCts.Token);
                            await fs.FlushAsync(mirrorCts.Token);
                        }

                        if (!IsValidGeoIpDatabase(tempFile))
                            throw new InvalidDataException($"{label} response is not a valid MaxMind database.");

                        // Only replace the published/cache file after the full download
                        // has been written and verified. A failed mirror never leaves a
                        // truncated final file that the next run will mistake for a cache.
                        File.Move(tempFile, file, overwrite: true);
                        LogSuccess($"{label} downloaded and validated.");
                        ok = true;
                        break;
                    }
                    catch (Exception ex)
                    {
                        LogWarning($"{label} mirror failed: {ex.Message}");
                        try { if (File.Exists(tempFile)) File.Delete(tempFile); } catch { }
                    }
                }

                if (!ok && required) failed.Add(label);
                if (!ok && !required)
                    LogWarning($"Optional {label} is unavailable; continuing without ASN metadata.");
            }

            if (failed.Count > 0)
                throw new InvalidOperationException(
                    $"Required GeoIP DB unavailable or invalid: {string.Join(", ", failed)}");
        }

        // ====================== HOST FILTERING ======================
        // ====================== FIREHOL BLACKLIST ======================
        // Re-added as a purely static signal — with no network liveness check anymore,
        // this catches known-bad/bogon IP ranges that static filtering alone can't. Loaded
        // once at startup; sorted by range start so a lookup is a binary search (O(log n))
        // rather than a linear scan, since this runs on every parsed proxy — a linear scan
        // over several thousand ranges times hundreds of thousands of candidates would be
        // a real slowdown. IPv4 only (level1 netset is IPv4). Fails open (empty list, never
        // blocks anything) if the download fails — non-fatal, same as the GeoIP databases.
        private static (uint Net, uint Mask)[] FireholCidrs = Array.Empty<(uint, uint)>();

        private static async Task LoadFireholBlacklist(HttpClient http)
        {
            try
            {
                var text = await http.GetStringAsync(
                    "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset");

                var list = new List<(uint Net, uint Mask)>();
                foreach (var raw in text.Split('\n'))
                {
                    var l = raw.Trim();
                    if (l.Length == 0 || l.StartsWith("#")) continue;

                    int slash = l.IndexOf('/');
                    if (slash < 0) continue;
                    if (!IPAddress.TryParse(l[..slash], out var netIp)) continue;
                    if (netIp.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (!int.TryParse(l[(slash + 1)..], out int bits) || bits < 0 || bits > 32) continue;

                    var b = netIp.GetAddressBytes();
                    uint net = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
                    uint mask = bits == 0 ? 0 : 0xFFFFFFFFu << (32 - bits);
                    list.Add((net & mask, mask));
                }

                FireholCidrs = list.OrderBy(x => x.Net).ToArray();
                LogSuccess($"FireHOL blacklist loaded ({FireholCidrs.Length} ranges).");
            }
            catch (Exception ex) { LogWarning($"FireHOL blacklist failed to load (non-fatal): {ex.Message}"); }
        }

        private static bool IsFireholBlacklisted(IPAddress ip)
        {
            // Normalize mapped IPv4 literals before consulting the IPv4-only blacklist.
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            if (ip.AddressFamily != AddressFamily.InterNetwork || FireholCidrs.Length == 0)
                return false;

            var b = ip.GetAddressBytes();
            uint addr = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];

            // Binary search for the last range whose start is <= addr, then verify addr
            // actually falls inside it. Correct as long as ranges don't overlap, which
            // holds for FireHOL's aggregated netset.
            int lo = 0, hi = FireholCidrs.Length - 1, idx = -1;
            while (lo <= hi)
            {
                int mid = (lo + hi) / 2;
                if (FireholCidrs[mid].Net <= addr) { idx = mid; lo = mid + 1; }
                else hi = mid - 1;
            }
            if (idx < 0) return false;

            var (net, mask) = FireholCidrs[idx];
            return (addr & mask) == net;
        }

        // ====================== CLOUDFLARE IP RANGES (v6.16) ======================
        // Workers TCP sockets cannot connect to Cloudflare IPs (platform restriction,
        // prevents Worker→CF loops). A large share of free nodes are CF-fronted — the
        // same property that makes them reachable from censored networks. The Edge
        // stage therefore skips CF-resolved hosts: unprovable by construction, and
        // every skipped probe frees budget for hosts this vantage CAN judge.
        // The output exclusion is fail-closed for known CF literals/metadata, and
        // fail-open for unresolved hostnames so one DNS failure never kills a run.
        private static (uint Net, uint Mask)[] CfCidrs = Array.Empty<(uint, uint)>();
        private static (byte[] Net, int Prefix)[] CfCidrsV6 = Array.Empty<(byte[], int)>();

        private static async Task LoadCloudflareRanges(HttpClient http)
        {
            // Load the official IPv4 and IPv6 lists independently. A failure on one
            // endpoint must not prevent the other address family from being filtered.
            try
            {
                var text = await http.GetStringAsync("https://www.cloudflare.com/ips-v4");
                var list = new List<(uint, uint)>();
                foreach (var raw in text.Split('\n'))
                {
                    var l = raw.Trim();
                    if (l.Length == 0) continue;
                    int slash = l.IndexOf('/');
                    if (slash < 0 || !IPAddress.TryParse(l[..slash], out var ip) ||
                        ip.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (!int.TryParse(l[(slash + 1)..], out int bits) || bits < 0 || bits > 32) continue;
                    var b = ip.GetAddressBytes();
                    uint addr = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
                    uint mask = bits == 0 ? 0 : 0xFFFFFFFFu << (32 - bits);
                    list.Add((addr & mask, mask));
                }
                CfCidrs = list.OrderBy(x => x.Item1).ToArray();
            }
            catch (Exception ex) { LogWarning($"Cloudflare IPv4 ranges unavailable: {ex.Message}"); }

            try
            {
                var text = await http.GetStringAsync("https://www.cloudflare.com/ips-v6");
                var list = new List<(byte[] Net, int Prefix)>();
                foreach (var raw in text.Split('\n'))
                {
                    var l = raw.Trim();
                    int slash = l.IndexOf('/');
                    if (slash < 0 || !IPAddress.TryParse(l[..slash], out var ip) ||
                        ip.AddressFamily != AddressFamily.InterNetworkV6) continue;
                    if (!int.TryParse(l[(slash + 1)..], out int bits) || bits < 0 || bits > 128) continue;
                    var bytes = ip.GetAddressBytes();
                    int full = bits / 8, rem = bits % 8;
                    if (rem > 0 && full < bytes.Length) bytes[full] = (byte)(bytes[full] & (0xFF << (8 - rem)));
                    for (int i = full + (rem > 0 ? 1 : 0); i < bytes.Length; i++) bytes[i] = 0;
                    list.Add((bytes, bits));
                }
                CfCidrsV6 = list.ToArray();
            }
            catch (Exception ex) { LogWarning($"Cloudflare IPv6 ranges unavailable: {ex.Message}"); }

            // The project explicitly promises that no Cloudflare nodes are published.
            // If either official list failed to load, continuing would silently weaken that
            // guarantee for one address family. Fail the run instead of publishing uncertain output.
            if (CfCidrs.Length == 0 || CfCidrsV6.Length == 0)
                throw new InvalidOperationException($"Cloudflare range data incomplete (IPv4={CfCidrs.Length}, IPv6={CfCidrsV6.Length}); refusing to generate outputs under the no-Cloudflare policy.");

            LogSuccess($"Cloudflare ranges loaded: IPv4={CfCidrs.Length}, IPv6={CfCidrsV6.Length} CIDRs; all matching proxy nodes will be excluded from published outputs.");
        }

        private static bool IsCloudflareIp(IPAddress ip)
        {
            // IPv4-mapped IPv6 is still an IPv4 endpoint; normalize before CIDR checks
            // so a mapped Cloudflare IPv4 address cannot bypass the official IPv4 ranges.
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            var b = ip.GetAddressBytes();
            if (ip.AddressFamily == AddressFamily.InterNetwork)
            {
                if (CfCidrs.Length == 0) return false;
                uint addr = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
                int lo = 0, hi = CfCidrs.Length - 1, idx = -1;
                while (lo <= hi)
                {
                    int mid = (lo + hi) / 2;
                    if (CfCidrs[mid].Net <= addr) { idx = mid; lo = mid + 1; }
                    else hi = mid - 1;
                }
                if (idx < 0) return false;
                var (net, mask) = CfCidrs[idx];
                return (addr & mask) == net;
            }
            if (ip.AddressFamily != AddressFamily.InterNetworkV6 || CfCidrsV6.Length == 0) return false;
            foreach (var (net, prefix) in CfCidrsV6)
            {
                int full = prefix / 8, rem = prefix % 8;
                bool match = true;
                for (int i = 0; i < full; i++) if (b[i] != net[i]) { match = false; break; }
                if (match && rem > 0)
                {
                    int mask = 0xFF << (8 - rem);
                    match = (b[full] & mask) == (net[full] & mask);
                }
                if (match) return true;
            }
            return false;
        }

        private static bool IsWarpMetadata(string value)
        {
            try { value = Uri.UnescapeDataString(value ?? ""); }
            catch { }
            // Match WARP/WARP+ as a distinct label, not ordinary words such as "warpath".
            return Regex.IsMatch(value, @"(?<![a-z0-9])warp(?:\+)?(?![a-z0-9])", RegexOptions.IgnoreCase);
        }

        internal static bool HasWarpRemark(string link)
        {
            string safeLink = link ?? "";
            int hash = safeLink.IndexOf('#');
            return hash >= 0 && IsWarpMetadata(safeLink[(hash + 1)..]);
        }

        private static bool IsSuspiciousCloudflareTransportHost(string value)
        {
            string decoded = value ?? "";
            try
            {
                decoded = Uri.UnescapeDataString(decoded);
                decoded = Uri.UnescapeDataString(decoded);
            }
            catch { }

            decoded = decoded.Trim().Trim('"').Trim((char)39);
            if (Uri.TryCreate(decoded, UriKind.Absolute, out var absolute) &&
                !string.IsNullOrEmpty(absolute.Host))
                decoded = absolute.Host;
            else if (Uri.TryCreate("https://" + decoded, UriKind.Absolute, out var parsed))
                decoded = parsed.Host;

            string host = decoded.Trim('[', ']').TrimEnd('.');
            if (host.Length == 0 || IPAddress.TryParse(host, out _)) return false;

            static bool MatchesDomain(string h, string domain) =>
                h.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                h.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);

            if (MatchesDomain(host, "workers.dev") ||
                MatchesDomain(host, "pages.dev") ||
                MatchesDomain(host, "trycloudflare.com") ||
                MatchesDomain(host, "cloudflareclient.com"))
                return true;

            // A genuine *.cloudflare.com SNI is allowed as camouflage. Catch
            // deceptive names that embed the word across unrelated DNS labels.
            return (host.Contains("cloudflare", StringComparison.OrdinalIgnoreCase) &&
                    !MatchesDomain(host, "cloudflare.com")) || IsWarpMetadata(host);
        }

        private static bool HasSuspiciousCloudflareTransportReference(string link)
        {
            string safeLink = link ?? "";
            int hash = safeLink.IndexOf('#');
            if (hash >= 0) safeLink = safeLink[..hash];
            safeLink = safeLink.Replace("&amp;", "&", StringComparison.OrdinalIgnoreCase);

            if (safeLink.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    string token = safeLink["vmess://".Length..].Replace('-', '+').Replace('_', '/');
                    int pad = token.Length % 4;
                    if (pad > 0) token += new string('=', 4 - pad);
                    using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(token)));
                    foreach (string key in new[] { "host", "sni", "server_name", "servername", "authority" })
                    {
                        if (doc.RootElement.TryGetProperty(key, out var field) &&
                            field.ValueKind == JsonValueKind.String &&
                            IsSuspiciousCloudflareTransportHost(field.GetString() ?? ""))
                            return true;
                    }
                }
                catch { }
            }

            string decoded = safeLink;
            try
            {
                decoded = Uri.UnescapeDataString(decoded);
                decoded = Uri.UnescapeDataString(decoded);
            }
            catch { }
            foreach (Match match in Regex.Matches(decoded,
                @"(?i)(?:[?&;])\s*(?:host|sni|server_name|servername|authority)\s*=\s*([^&;#\s]+)"))
            {
                if (IsSuspiciousCloudflareTransportHost(match.Groups[1].Value))
                    return true;
            }
            return false;
        }

        private static bool IsCloudflareMetadata(ParsedProxy p)
        {
            static bool IsCfDomain(string value)
            {
                var h = value.Trim().Trim('[', ']').TrimEnd('.');
                return h.Equals("cloudflare.com", StringComparison.OrdinalIgnoreCase) ||
                       h.EndsWith(".cloudflare.com", StringComparison.OrdinalIgnoreCase) ||
                       h.EndsWith(".cloudflareclient.com", StringComparison.OrdinalIgnoreCase) ||
                       h.EndsWith(".workers.dev", StringComparison.OrdinalIgnoreCase) ||
                       h.EndsWith(".pages.dev", StringComparison.OrdinalIgnoreCase) ||
                       h.EndsWith(".trycloudflare.com", StringComparison.OrdinalIgnoreCase) ||
                       (h.Contains("cloudflare", StringComparison.OrdinalIgnoreCase) &&
                        !h.Equals("cloudflare.com", StringComparison.OrdinalIgnoreCase) &&
                        !h.EndsWith(".cloudflare.com", StringComparison.OrdinalIgnoreCase));
            }

            if (IsCfDomain(p.Host)) return true;
            // SNI alone can be camouflage (e.g. a healthy server using a popular SNI),
            // so only treat Cloudflare-hosted service domains as decisive here.
            string sni = p.Sni.Trim().TrimEnd('.');
            if (sni.EndsWith(".workers.dev", StringComparison.OrdinalIgnoreCase) ||
                sni.EndsWith(".pages.dev", StringComparison.OrdinalIgnoreCase) ||
                sni.EndsWith(".trycloudflare.com", StringComparison.OrdinalIgnoreCase) ||
                sni.EndsWith(".cloudflareclient.com", StringComparison.OrdinalIgnoreCase)) return true;
            if (IPAddress.TryParse(p.Host.Trim('[', ']'), out var literal) && IsCloudflareIp(literal)) return true;
            string link = p.BaseLink ?? "";
            if (HasSuspiciousCloudflareTransportReference(link)) return true;
            string remark = "";
            int hash = link.IndexOf('#');
            if (hash >= 0) remark = link[(hash + 1)..];
            else if (link.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
            {
                // VMess stores the display name inside base64 JSON rather than after #.
                try
                {
                    string b64 = link["vmess://".Length..].Replace('-', '+').Replace('_', '/');
                    int pad = b64.Length % 4; if (pad > 0) b64 += new string('=', 4 - pad);
                    using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(b64)));
                    if (doc.RootElement.TryGetProperty("ps", out var ps)) remark = ps.GetString() ?? "";
                }
                catch { }
            }
            if (remark.Contains("cloudflare", StringComparison.OrdinalIgnoreCase)) return true;
            if (IsWarpMetadata(remark)) return true;
            return NormalizeProto(p.Protocol) == "wireguard" &&
                   link.Contains("cloudflareclient", StringComparison.OrdinalIgnoreCase);
        }

        internal static bool IsCloudflareFinal(FinalProxy p)
        {
            string host = (p.Host ?? "").Trim().Trim('[', ']');
            if (IPAddress.TryParse(host, out var ip) && IsCloudflareIp(ip)) return true;

            static bool IsServiceDomain(string host, string domain) =>
                host.Equals(domain, StringComparison.OrdinalIgnoreCase) ||
                host.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase);

            if (IsServiceDomain(host, "cloudflare.com") ||
                IsServiceDomain(host, "cloudflareclient.com") ||
                IsServiceDomain(host, "workers.dev") ||
                IsServiceDomain(host, "pages.dev") ||
                IsServiceDomain(host, "trycloudflare.com") ||
                (host.Contains("cloudflare", StringComparison.OrdinalIgnoreCase) &&
                 !IsServiceDomain(host, "cloudflare.com")))
                return true;

            // Metadata policy applies to the display label, not arbitrary SNI/query text:
            // a legitimate origin may use cloudflare.com as its TLS camouflage SNI.
            if (HasSuspiciousCloudflareTransportReference(p.Link ?? "")) return true;
            string remark = p.Remark ?? "";
            return remark.Contains("cloudflare", StringComparison.OrdinalIgnoreCase) ||
                   IsWarpMetadata(remark);
        }

        private async Task<List<ParsedProxy>> DropCloudflareNodesAsync(List<ParsedProxy> proxies)
        {
            var resolved = new ConcurrentDictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            await Parallel.ForEachAsync(proxies.Select(p => p.Host).Distinct(StringComparer.OrdinalIgnoreCase),
                new ParallelOptions { MaxDegreeOfParallelism = 100 }, async (host, _) =>
                {
                    if (IPAddress.TryParse(host.Trim('[', ']'), out var literal))
                        resolved[host] = IsCloudflareIp(literal);
                    else
                    {
                        try
                        {
                            // A hostname may have both public and Cloudflare A/AAAA
                            // answers. Exclude it if ANY address is in an official CF range.
                            var addresses = await Resolver.ResolveAllAsync(host);
                            resolved[host] = addresses.Any(IsCloudflareIp);
                        }
                        catch { resolved[host] = false; }
                    }
                });

            int metadata = 0, resolvedCf = 0;
            var kept = new List<ParsedProxy>(proxies.Count);
            foreach (var p in proxies)
            {
                if (IsCloudflareMetadata(p)) { metadata++; continue; }
                if (resolved.TryGetValue(p.Host, out var cf) && cf) { resolvedCf++; continue; }
                kept.Add(p);
            }
            int dropped = metadata + resolvedCf;
            if (dropped > 0)
                LogWarning($"Cloudflare exclusion: dropped {dropped} nodes before output generation ({metadata} matched Cloudflare domain/name/URI, {resolvedCf} resolved into official Cloudflare IPv4/IPv6 ranges).");
            else
                LogInfo("Cloudflare exclusion: no Cloudflare nodes found in the publishable pool.");
            return kept;
        }

        private static bool IsBadHost(string host)
        {
            if (string.IsNullOrEmpty(host)) return true;
            if (CdnIpExact.Contains(host)) return true;
            if (PlaceholderHosts.Contains(host)) return true;

            foreach (var s in SuspiciousHostSuffixes)
                if (host.EndsWith(s, StringComparison.OrdinalIgnoreCase)) return true;

            // RFC 2606 reserved TLDs — set aside specifically for documentation/examples,
            // never valid for a real public server.
            foreach (var tld in ReservedTlds)
                if (host.EndsWith(tld, StringComparison.OrdinalIgnoreCase)) return true;

            if (IPAddress.TryParse(host, out var ip))
            {
                if (IsPrivateOrReservedIp(ip)) return true;
                if (IsFireholBlacklisted(ip)) return true;
            }
            else if (!host.Contains('.'))
            {
                // Single-label, non-IP hostname (e.g. "myserver", "test") — can't resolve
                // as a public FQDN, so it's a broken or template value, not a real endpoint.
                return true;
            }

            return false;
        }

        // ====================== LOCATION ======================
        // Geolocation is a best-effort IP-database estimate, not proof of a server's
        // physical location. For hostnames with multiple A/AAAA answers, only display
        // a city when every public answer agrees on both country and city. If country
        // answers conflict, withhold the flag/country rather than confidently mislabel it.
        internal sealed record GeoLocationCandidate(
            string? CountryCode, string? CountryName, string? CityName, string? Organization);

        private static string NormalizeGeoText(string? value)
            => string.Join(" ", (value ?? "").Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));

        private static string NormalizeGeoCountryCode(string? value)
        {
            string code = (value ?? "").Trim().ToUpperInvariant();
            return code.Length == 2 && code.All(c => c is >= 'A' and <= 'Z') && Flags.ContainsKey(code)
                ? code
                : "XX";
        }

        internal static string CombineGeoCountryCodes(string? cityCountryCode, string? countryCountryCode)
        {
            string cityCode = NormalizeGeoCountryCode(cityCountryCode);
            string countryCode = NormalizeGeoCountryCode(countryCountryCode);
            // The City and Country databases are independent datasets. When both contain a
            // country and disagree, suppress the country claim rather than pick one at random.
            if (cityCode != "XX" && countryCode != "XX" && cityCode != countryCode)
                return "XX";
            return countryCode != "XX" ? countryCode : cityCode;
        }

        internal static (string Location, string CountryCode) BuildGeoLocationLabel(
            IReadOnlyList<GeoLocationCandidate> candidates)
        {
            if (candidates is null || candidates.Count == 0)
                return ("🌐 Unknown", "XX");

            // Provider names are shown only when every resolved address reports the same
            // non-empty ASN organization. CDN/round-robin hostnames can span providers;
            // choosing whichever IP happened to resolve first would make names misleading.
            var organizations = candidates
                .Select(c => ShortenOrg(NormalizeGeoText(c.Organization)))
                .ToArray();
            string org = organizations.Length > 0 &&
                         organizations.All(o => !string.IsNullOrWhiteSpace(o)) &&
                         organizations.Distinct(StringComparer.OrdinalIgnoreCase).Count() == 1
                ? organizations.OrderBy(o => o, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(o => o, StringComparer.Ordinal).First()
                : "";
            string orgSuffix = org.Length > 0 ? $" · {org}" : "";

            var countryCodes = candidates.Select(c => NormalizeGeoCountryCode(c.CountryCode)).ToArray();
            if (countryCodes.Any(cc => cc == "XX") ||
                countryCodes.Distinct(StringComparer.Ordinal).Count() != 1)
            {
                return (org.Length > 0 ? $"🌐 {org}" : "🌐 Unknown", "XX");
            }

            string cc = countryCodes[0];
            string flag = Flags.TryGetValue(cc, out var foundFlag) ? foundFlag : "🌍";

            // Preserve GeoIP's original city casing. Lowercasing before TitleCase damaged
            // proper names such as McLean and other names with meaningful internal capitals.
            var cityNames = candidates.Select(c => NormalizeGeoText(c.CityName)).ToArray();
            if (cityNames.All(city => city.Length > 0) &&
                cityNames.Distinct(StringComparer.OrdinalIgnoreCase).Count() == 1)
            {
                string cityName = cityNames
                    .OrderBy(city => city, StringComparer.OrdinalIgnoreCase)
                    .ThenBy(city => city, StringComparer.Ordinal)
                    .First();
                return ($"{flag} {cityName}, {cc}{orgSuffix}", cc);
            }

            // Country names must agree too. If a dataset gives inconsistent names for the
            // same code, use the unambiguous ISO code instead of printing a possibly wrong name.
            var countryNames = candidates
                .Select(c => NormalizeGeoText(c.CountryName))
                .Where(name => name.Length > 0 && !name.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            string countryName = countryNames.Length == 1 ? countryNames[0] : cc;
            return ($"{flag} {countryName}{orgSuffix}", cc);
        }

        // Client labels use the requested readable format. Repeated base names are
        // disambiguated in the output loop with a trailing " 2", " 3", etc.
        internal static string BuildClientNodeName(
            string countryCode, string location, string host, string port)
        {
            string cc = NormalizeGeoCountryCode(countryCode);
            string flag = Flags.TryGetValue(cc, out var foundFlag) ? foundFlag : "🌐";
            string countryName = "Unknown";
            if (cc != "XX")
            {
                try { countryName = new RegionInfo(cc).EnglishName; }
                catch { countryName = cc; }
            }

            string city = "Unknown";
            string sourceLocation = NormalizeGeoText(location);
            if (sourceLocation.StartsWith(flag, StringComparison.Ordinal))
            {
                string candidate = sourceLocation[flag.Length..].Trim();
                int providerAt = candidate.IndexOf(" · ", StringComparison.Ordinal);
                if (providerAt >= 0) candidate = candidate[..providerAt].Trim();
                string countrySuffix = ", " + cc;
                if (candidate.EndsWith(countrySuffix, StringComparison.OrdinalIgnoreCase))
                    candidate = candidate[..^countrySuffix.Length].Trim();

                // Country-level GeoIP agreement has no reliable city to display.
                if (candidate.Length > 0 &&
                    !candidate.Equals(countryName, StringComparison.OrdinalIgnoreCase) &&
                    !candidate.Equals(cc, StringComparison.OrdinalIgnoreCase) &&
                    !candidate.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
                    city = candidate;
            }

            string cleanHost = (host ?? "").Trim().Trim('[', ']');
            if (IPAddress.TryParse(cleanHost, out var ip) &&
                ip.AddressFamily == AddressFamily.InterNetworkV6)
                cleanHost = "[" + ip + "]";
            string endpoint = $"{cleanHost}:{port}";
            return $"{flag} {countryName} ({cc}) - {city} | {endpoint}";
        }

        internal static string ApplyDuplicateNameSuffix(string baseName, int occurrence)
            => occurrence <= 1 ? baseName : $"{baseName} {occurrence}";

        private async Task<(string Location, string CountryCode)> GetLocationAndCountryAsync(string host)
        {
            try
            {
                // Resolve and examine all public A/AAAA answers, not just the resolver's
                // first IPv4-preferred address. Sort addresses so cache/wire order can never
                // decide which flag, city, or provider appears in a node's remark.
                var addresses = (await Resolver.ResolveAllAsync(host))
                    .Where(ip => !IsPrivateOrReservedIp(ip))
                    .Distinct()
                    .OrderBy(ip => ip.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
                    .ThenBy(ip => ip.ToString(), StringComparer.Ordinal)
                    .ToArray();

                var candidates = new List<GeoLocationCandidate>(addresses.Length);
                foreach (var ip in addresses)
                {
                    string address = ip.ToString();
                    var city = await Resolver.GetCityAsync(address);
                    var country = await Resolver.GetCountryAsync(address);
                    string cityCode = NormalizeGeoCountryCode(city?.CountryCode);
                    string countryDbCode = NormalizeGeoCountryCode(country?.CountryCode);
                    string countryCode = CombineGeoCountryCodes(city?.CountryCode, country?.CountryCode);

                    // Prefer the dedicated Country database's English label when it agrees.
                    // A city name is eligible only when the City database also agrees on the code.
                    string countryName = "";
                    if (countryCode != "XX")
                    {
                        if (countryDbCode == countryCode &&
                            !string.IsNullOrWhiteSpace(country?.CountryName) &&
                            !country.CountryName.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
                            countryName = country.CountryName;
                        else if (cityCode == countryCode &&
                                 !string.IsNullOrWhiteSpace(city?.CountryName) &&
                                 !city.CountryName.Equals("Unknown", StringComparison.OrdinalIgnoreCase))
                            countryName = city.CountryName;
                    }
                    string cityName = cityCode != "XX" && cityCode == countryCode
                        ? city?.CityName ?? ""
                        : "";

                    string organization = await Resolver.GetOrgAsync(address) ?? "";
                    candidates.Add(new GeoLocationCandidate(
                        countryCode, countryName, cityName, organization));
                }

                return BuildGeoLocationLabel(candidates);
            }
            catch
            {
                return ("🌐 Unknown", "XX");
            }
        }

        // MaxMind's org strings often carry legal suffixes ("Hetzner Online GmbH",
        // "DigitalOcean, LLC") that add noise to a short remark — trim the common ones.
        // Truncates at a word boundary with an ellipsis rather than a hard character cut,
        // and returns "" (not a mangled fragment) if stripping leaves nothing usable.
        private static string ShortenOrg(string org)
        {
            org = Regex.Replace(org, @",?\s*(LLC|Inc\.?|GmbH|S\.A\.?|Ltd\.?|Co\.?|Corp\.?|SAS|B\.V\.?)\.?$",
                "", RegexOptions.IgnoreCase).Trim();

            if (org.Length <= 24) return org;

            int cut = org.LastIndexOf(' ', 24);
            string shortened = (cut > 8 ? org[..cut] : org[..24]).TrimEnd();
            return shortened.Length > 0 ? shortened + "…" : "";
        }

        private static string GetContinent(string cc)
            => CountryToContinent.TryGetValue(cc ?? "", out var c) ? c : "Unknown";

        private const int MaxSourceResponseBytes = 64 * 1024 * 1024;
        private const int MaxLargeSourceResponseBytes = 256 * 1024 * 1024;
        private const int MaxProviderResponseBytes = 16 * 1024 * 1024;

        // One high-volume source has legitimately grown beyond the ordinary 64 MiB
        // cap. Keep the higher allowance narrowly scoped to that exact repository/feed
        // so the general source limit still protects the other hundreds of URLs.
        internal static int GetSourceResponseByteLimit(string url)
        {
            if (Uri.TryCreate(url, UriKind.Absolute, out var uri) &&
                uri.Host.Equals("raw.githubusercontent.com", StringComparison.OrdinalIgnoreCase) &&
                uri.AbsolutePath.Equals("/sevcator/5ubscrpt10n/main/protocols/vl.txt", StringComparison.OrdinalIgnoreCase))
                return MaxLargeSourceResponseBytes;

            return MaxSourceResponseBytes;
        }

        internal static async Task<string> ReadContentLimitedAsync(
            HttpContent content, int maxBytes, CancellationToken cancellationToken)
        {
            if (maxBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maxBytes));
            long? declaredLength = content.Headers.ContentLength;
            if (declaredLength.HasValue && declaredLength.Value > maxBytes)
                throw new InvalidDataException(
                    $"HTTP response declares {declaredLength.Value} bytes, above the {maxBytes}-byte limit.");

            await using var stream = await content.ReadAsStreamAsync(cancellationToken);
            using var buffer = new MemoryStream();
            var chunk = new byte[81920];
            while (true)
            {
                int read = await stream.ReadAsync(chunk.AsMemory(0, chunk.Length), cancellationToken);
                if (read == 0) break;
                if (buffer.Length + read > maxBytes)
                    throw new InvalidDataException(
                        $"HTTP response exceeded the {maxBytes}-byte limit while streaming.");
                await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
            }

            return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, checked((int)buffer.Length));
        }

        // ====================== ENTRY POINT ======================
        public async Task StartAsync()
        {
            const string version = "v6.21";
            Banner(version);
            GroupStart("📦 GeoIP database + blacklist setup");
            await DownloadGeoIPDatabases(_http);
            await LoadFireholBlacklist(_http);
            await LoadCloudflareRanges(_http);
            // Force the resolver's construction NOW. Its ctor is the fail-loud check for
            // corrupt GeoIP DBs — but it's Lazy, so without this the first touch happens
            // inside GetLocationAndCountryAsync, whose catch-all swallows the throw and
            // the run continues green with every node misclassified as 🌐 Unknown.
            _ = Resolver;
            GroupEnd();
            LogSuccess($"🚀 FastNodes {version} - Starting collection...");
            await RunFullCollectionMode();
        }
		
        // ====================== MAIN PIPELINE ======================
        private async Task RunFullCollectionMode()
        {
            var runStopwatch = Stopwatch.StartNew();
            var urls = CollectorConfig.Instance.Sources;
            LogInfo($"🔍 Fetching from {urls.Length} sources (parallel)...");

            GroupStart("🔍 Step 1/5 — Fetching sources");
            // STEP 1: parallel fetch — one retry on failure. With 500+ independent sources,
            // a transient timeout or blip is common; a single failed attempt shouldn't
            // permanently drop that whole source for the run.
            var rawLinesBag = new ConcurrentBag<(string Url, string Line)>();
            var sourceStats = new ConcurrentDictionary<string, SourceStat>();
            await Parallel.ForEachAsync(urls, new ParallelOptions { MaxDegreeOfParallelism = 30 },
                async (url, _) =>
                {
                    var st = sourceStats.GetOrAdd(url, _ => new SourceStat());
                    for (int attempt = 1; attempt <= 2; attempt++)
                    {
                        try
                        {
                            // Per-request 25s timeout — one slow domain (freenode was
                            // burning 40+1.5+40 ≈ 82s) can no longer define the whole
                            // fetch stage's duration.
                            using var reqCts = new CancellationTokenSource(TimeSpan.FromSeconds(25));
                            using var sourceResponse = await _http.GetAsync(
                                url, HttpCompletionOption.ResponseHeadersRead, reqCts.Token);
                            sourceResponse.EnsureSuccessStatusCode();
                            var text = await ReadContentLimitedAsync(
                                sourceResponse.Content, GetSourceResponseByteLimit(url), reqCts.Token);
                            Interlocked.Increment(ref st.FetchSuccesses);
                            Interlocked.Add(ref st.RawBytes, Encoding.UTF8.GetByteCount(text));
                            if (!string.IsNullOrEmpty(text))
                                Interlocked.Add(ref st.RawLines, 1 + text.Count(ch => ch == '\n'));
                            var lines = DecodeAndExtractLines(text, url);

                            // Full Mihomo profiles often contain only proxy-providers URLs,
                            // not a root `proxies:` list. Treating every ordinary https://
                            // rule/provider URL as a proxy used to create FORMAT GAP spam.
                            // Follow the actual proxy-provider URLs once and parse the
                            // provider payloads, attributing their yield to this parent feed.
                            if (lines.Count == 0 && text.Contains("proxy-providers:", StringComparison.OrdinalIgnoreCase))
                            {
                                // Cap fan-out and use a short retry: aggregator profiles can
                                // contain many provider URLs, and one 522/slow endpoint must
                                // not stall the entire collection run. Failures are counted
                                // separately from ordinary source zero-yield statistics.
                                foreach (var providerUrl in ExtractClashProviderUrls(text).Take(8))
                                {
                                    // Some profiles wrap a perfectly ordinary subscription in
                                    // a third-party converter URL (often 400/522 when the
                                    // converter is overloaded). Try the underlying URL first,
                                    // then fall back to the original provider endpoint.
                                    foreach (var fetchUrl in GetProviderFetchCandidates(providerUrl))
                                    {
                                        bool yielded = false;
                                        for (int providerAttempt = 1; providerAttempt <= 2; providerAttempt++)
                                        {
                                            try
                                            {
                                                using var providerCts = new CancellationTokenSource(TimeSpan.FromSeconds(12));
                                                using var providerResponse = await _http.GetAsync(fetchUrl, HttpCompletionOption.ResponseHeadersRead, providerCts.Token);
                                                providerResponse.EnsureSuccessStatusCode();
                                                var providerText = await ReadContentLimitedAsync(
                                                    providerResponse.Content, MaxProviderResponseBytes, providerCts.Token);
                                                Interlocked.Increment(ref st.ProviderSuccesses);
                                                var providerLines = DecodeAndExtractLines(providerText, fetchUrl);
                                                if (providerLines.Count > 0)
                                                {
                                                    lines.AddRange(providerLines);
                                                    yielded = true;
                                                }
                                                break;
                                            }
                                            catch (Exception providerEx)
                                            {
                                                if (providerAttempt == 2)
                                                {
                                                    Interlocked.Increment(ref st.ProviderFailures);
                                                    LogWarning($"  provider fetch failed (after retry) for {url} → {fetchUrl}: {providerEx.Message}");
                                                }
                                                else
                                                {
                                                    await Task.Delay(700);
                                                }
                                            }
                                        }
                                        // A direct underlying subscription is preferred only
                                        // when it actually yields proxy links. If it returned
                                        // successfully but had an unsupported format, let the
                                        // original converter try to normalize it.
                                        if (yielded) break;
                                    }
                                    if (lines.Count >= 20000) break; // one profile cannot monopolize memory
                                }
                            }

                            Interlocked.Add(ref st.Lines, lines.Count);
                            foreach (var l in lines) rawLinesBag.Add((url, l));
                            return;
                        }
                        catch (Exception ex)
                        {
                            if (attempt == 2) { LogError($"Failed {url}: {ex.Message}"); return; }
                            await Task.Delay(1500);
                        }
                    }
                });

            var rawLines = rawLinesBag.ToList();
            LogInfo($"Total raw lines: {rawLines.Count}");
            GroupEnd();

            GroupStart("🧹 Step 2/5 — Parsing & smart dedup");
            LogInfo("🧹 Parsing & smart dedup...");
            // Identity keys normalize only fields that are semantically case-insensitive.
            // Ordinal comparison is required to preserve case-sensitive credentials, paths,
            // and REALITY public keys.
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var uniqueProxies = new List<ParsedProxy>();
            int processed = 0, badHostFiltered = 0, placeholderFiltered = 0, emptyCredFiltered = 0, invalidWireguardFiltered = 0;

            // v6.13: byKey maps dedup key → kept node, so a DUPLICATE arriving from an
            // explicitly Iran-tested source can upgrade the kept node's trust flag.
            // (Which source's line wins the dedup race is bag-order nondeterminism —
            // this makes trust "ANY tested source contributed it", not "the winner".)
            var byKey = new Dictionary<string, ParsedProxy>(StringComparer.Ordinal);
            var keySources = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
            var testedSrcCache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            bool SrcTested(string u)
            {
                if (testedSrcCache.TryGetValue(u, out var t)) return t;
                t = IsIranTestedSource(u);
                testedSrcCache[u] = t;
                return t;
            }

            foreach (var (url, line) in rawLines)
            {
                processed++;
                if (processed % 100000 == 0) LogInfo($"  {processed}/{rawLines.Count} parsed...");

                var t = line.Trim();
                if (string.IsNullOrWhiteSpace(t) || t.StartsWith("#")) continue;
                if (Regex.IsMatch(t, @"^\s*-\s+name:")) continue;

                var p = ParseProxyLine(t);
                if (p == null) continue;
                sourceStats[url].Parsed++;   // sequential loop — no Interlocked needed

                if (IsBadHost(p.Host)) { badHostFiltered++; continue; }
                if (IsPlaceholderCredential(p.Protocol, p.Credential)) { placeholderFiltered++; continue; }
                if (CredentialRequiredProtocols.Contains(NormalizeProto(p.Protocol)) &&
                    string.IsNullOrEmpty(p.Credential)) { emptyCredFiltered++; continue; }
                if (!int.TryParse(p.Port, out int portNum) || portNum <= 0 || portNum > 65535) { badHostFiltered++; continue; }
                if (NormalizeProto(p.Protocol) == "wireguard" && !IsValidWireguardLink(p.BaseLink))
                {
                    invalidWireguardFiltered++;
                    continue;
                }

                string key = p.DeduplicationKey;
                if (seen.Add(key))
                {
                    p.IranTested = SrcTested(url);
                    p.SourceCount = 1;
                    keySources[key] = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { url };
                    uniqueProxies.Add(p);
                    byKey[key] = p;
                    sourceStats[url].Unique++;
                }
                else
                {
                    // v6.14: count DISTINCT sources publishing this node — ecosystem
                    // consensus it's real. (Weighted low in the score on purpose:
                    // aggregators republish each other, so sources aren't fully
                    // independent.)
                    if (keySources.TryGetValue(key, out var srcs) && srcs.Add(url))
                        if (byKey.TryGetValue(key, out var keptSrc))
                            keptSrc.SourceCount = srcs.Count;

                    if (SrcTested(url) && byKey.TryGetValue(key, out var keptTrust) && !keptTrust.IranTested)
                        keptTrust.IranTested = true;   // duplicate from a tested source — trust upgrades the kept node
                }
            }
            LogInfo($"After smart dedup: {uniqueProxies.Count} unique ({badHostFiltered} bad host/port, {placeholderFiltered} placeholder credential, {emptyCredFiltered} empty credential, {invalidWireguardFiltered} invalid WireGuard filtered)");
            GroupEnd();

            // v6.12: source yield report. Turns source-list maintenance from guesswork
            // into data:
            //   zero Lines                 → dead / empty / blocked from the RUNNER's
            //                                vantage point (Azure US, not your machine)
            //   Lines > 0 but Parsed == 0  → FORMAT GAP: the fetch worked but no parser
            //                                recognized the content — exactly how the
            //                                block-style Clash YAML hole stayed invisible
            //   Unique                     → ranks sources by nodes only THEY contributed
            GroupStart("📊 Source yield report");
            foreach (var kv in sourceStats.OrderByDescending(k => k.Value.Unique).Take(20))
                LogInfo($"  {kv.Value.Unique,6} uniq {kv.Value.Parsed,7} parsed  {kv.Key}");
            int fetchFailed = 0, emptyBody = 0, unparsedContent = 0, parseGap = 0, healthyCount = 0;
            foreach (var kv in sourceStats.OrderBy(k => k.Key))
            {
                var st = kv.Value;
                int fetchSuccesses = Volatile.Read(ref st.FetchSuccesses);
                int rawBytes = Volatile.Read(ref st.RawBytes);
                int sourceRawLineCount = Volatile.Read(ref st.RawLines);
                int extractedLines = Volatile.Read(ref st.Lines);
                int parsed = Volatile.Read(ref st.Parsed);
                if (fetchSuccesses == 0)
                {
                    fetchFailed++;
                    LogWarning($"  fetch-failed (both attempts): {kv.Key}");
                }
                else if (rawBytes == 0)
                {
                    emptyBody++;
                    LogWarning($"  empty-body (HTTP fetch succeeded): {kv.Key}");
                }
                else if (extractedLines == 0)
                {
                    unparsedContent++;
                    LogWarning($"  unparsed-content ({rawBytes} bytes, {sourceRawLineCount} raw lines, 0 proxy lines; may be unsupported format or provider-only profile): {kv.Key}");
                }
                else if (parsed == 0)
                {
                    parseGap++;
                    LogWarning($"  PARSE GAP ({extractedLines} extracted proxy lines, 0 accepted): {kv.Key}");
                }
                else healthyCount++;
            }
            int providerFailures = sourceStats.Values.Sum(st => Volatile.Read(ref st.ProviderFailures));
            int providerSuccesses = sourceStats.Values.Sum(st => Volatile.Read(ref st.ProviderSuccesses));
            LogInfo($"Source health: {sourceStats.Count} sources — {healthyCount} yielded parsed proxies, {fetchFailed} fetch-failed, {emptyBody} empty-body, {unparsedContent} fetched-but-unparsed, {parseGap} extracted-but-rejected; nested provider fetches succeeded={providerSuccesses}, failed-after-retry={providerFailures}.");

            // Publish a machine-readable source audit alongside generated subscriptions.
            // This separates network reachability from parser yield and unique contribution.
            string Csv(string value) => "\"" + (value ?? "").Replace("\"", "\"\"") + "\"";
            var sourceReport = new StringBuilder("url,fetch_successes,raw_bytes,raw_lines,extracted_lines,parsed,unique,provider_successes,provider_failures,status\n");
            foreach (var kv in sourceStats.OrderBy(k => k.Key, StringComparer.OrdinalIgnoreCase))
            {
                var st = kv.Value;
                int fetchSuccesses = Volatile.Read(ref st.FetchSuccesses);
                int rawBytes = Volatile.Read(ref st.RawBytes);
                int sourceRawLineCount = Volatile.Read(ref st.RawLines);
                int extractedLines = Volatile.Read(ref st.Lines);
                int parsed = Volatile.Read(ref st.Parsed);
                int providerSuccessCount = Volatile.Read(ref st.ProviderSuccesses);
                int providerFailureCount = Volatile.Read(ref st.ProviderFailures);
                string status = fetchSuccesses == 0 ? "fetch-failed" : rawBytes == 0 ? "empty-body" : extractedLines == 0 ? (providerFailureCount > 0 ? "provider-failed-or-unparsed" : "fetched-but-unparsed") : parsed == 0 ? "extracted-but-rejected" : providerFailureCount > 0 ? "healthy-with-provider-errors" : "healthy";
                sourceReport.Append(Csv(kv.Key)).Append(',')
                    .Append(fetchSuccesses).Append(',').Append(rawBytes).Append(',').Append(sourceRawLineCount).Append(',')
                    .Append(extractedLines).Append(',').Append(parsed).Append(',')
                    .Append(Volatile.Read(ref st.Unique)).Append(',')
                    .Append(providerSuccessCount).Append(',').Append(providerFailureCount).Append(',')
                    .Append(status).Append('\n');
            }
            // Save the CSV text now, but write it only after SaveAllCategories: that
            // method deliberately recreates `sub/` from scratch and would otherwise erase it.
            string sourceReportCsv = sourceReport.ToString();
            GroupEnd();

            // Sort deterministically before remark numbering — without this, duplicate
            // suffixes (#1, #2, ...) would get reassigned to different physical servers on
            // every run even when the underlying node set hadn't changed at all. The
            // filters below preserve this order (Where() keeps list order).
            var alive = uniqueProxies
                .OrderBy(p => p.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(p => int.TryParse(p.Port, out var pn) ? pn : 0)
                .ThenBy(p => p.Protocol, StringComparer.OrdinalIgnoreCase)
                // Same host/port/protocol may still describe different credentials or
                // transports. The full canonical key makes remark suffix assignment stable.
                .ThenBy(p => p.DeduplicationKey, StringComparer.Ordinal)
                .ToList();
            LogSuccess($"Total proxies: {alive.Count}");

            GroupStart("🌍 Step 3/5 — GeoIP lookup");
            // STEP 3: resolve every unique host exactly once (DNS bounded to 3s per
            // lookup, cached inside the resolver). The warm DNS cache produced here is
            // what makes the step-4 DNS filter nearly free — it only ever re-attempts
            // hosts that already failed once during this pass.
            var uniqueHosts = alive.Select(x => x.Host)
                .Distinct(StringComparer.OrdinalIgnoreCase).ToList();   // v6.13: "Server.com"/"server.com" were two DNS lookups
            LogInfo($"  Resolving geo info for {uniqueHosts.Count} unique hosts...");

            var locationCache = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var countryCache = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            await Parallel.ForEachAsync(uniqueHosts, new ParallelOptions { MaxDegreeOfParallelism = 100 },
                async (host, _) =>
                {
                    var (loc, cc) = await GetLocationAndCountryAsync(host);
                    locationCache[host] = loc;
                    countryCache[host] = cc;
                });
            GroupEnd();

            // User policy: publish no Cloudflare/WARP nodes in ANY output. Filter after
            // DNS has been warmed so hostname aliases resolving into Cloudflare IPv4 or
            // IPv6 ranges are caught too; every downstream file is built from this pool.
            alive = await DropCloudflareNodesAsync(alive);

            GroupStart("💀 Step 4/5 — Dead-node & alias filters");
            // Order is deliberate: DNS filter removes the dead first, then the resolved-IP
            // filter and alias collapse both run on the warm resolver cache (pure cache
            // hits, ~free), and the TCP filter runs LAST so it probes the smallest
            // possible set — alias-merged spelling variants never get probed twice.
            alive = await DropDnsDeadHostsAsync(alive);
            alive = await DropBadResolvedIpsAsync(alive);
            alive = await CollapseHostAliasesAsync(alive, keySources);
            alive = await DropTcpRefusedAsync(alive);
            LogInfo($"After dead-node & alias filters: {alive.Count} remain");
            GroupEnd();

            // v6.13: promotion-only life check — completed TLS handshakes with the node's
            // real SNI. Runs AFTER all drop filters so it probes the smallest set.
            // Fail-soft by design: a promotion feature must never kill a publishing run.
            GroupStart("🔐 TLS verification (clean-vantage life check — promotion only)");
            try { await TlsVerifyAsync(alive, countryCache); }
            catch (Exception ex) { LogWarning($"TLS verification failed (non-fatal — proceeding unverified): {ex.Message}"); }
            GroupEnd();

            // v6.15: xray-core deep check — a REAL proxy roundtrip (fetch generate_204
            // THROUGH the node) on the current top candidates. Runs BEFORE stability so
            // streak tracking sees current-run truth. Promotion-only, as always.
            GroupStart("🛰️ Xray deep check (top-N roundtrip — promotion only)");
            try { await XrayVerifyAsync(alive, countryCache); }
            catch (Exception ex) { LogWarning($"Xray deep check failed (non-fatal): {ex.Message}"); }
            GroupEnd();

            // v6.15: second vantage via Cloudflare Worker — dormant (one log line)
            // until WORKER_URL/WORKER_AUTH secrets exist. Fork-safe by construction.
            GroupStart("🌐 Edge verification (Cloudflare vantage — promotion only)");
            try { await EdgeVerifyAsync(alive, countryCache); }
            catch (Exception ex) { LogWarning($"Edge verification failed (non-fatal): {ex.Message}"); }
            GroupEnd();

            // v6.13: cross-run stability. state/history.json is committed by this run's
            // orphan commit; the next run's checkout of main IS the restore.
            GroupStart("📚 Stability tracking (state/history.json)");
            try
            {
                var history = LoadHistory();
                UpdateStreaks(history, alive);
                SaveHistory(history);
            }
            catch (Exception ex) { LogWarning($"Stability tracking failed (non-fatal): {ex.Message}"); }
            GroupEnd();

            GroupStart("💾 Step 5/5 — Name + save output files");
            string Loc(string h) => locationCache.TryGetValue(h, out var l) ? l : "🌐 Unknown";
            string Cc(string h) => countryCache.TryGetValue(h, out var c) ? c : "XX";

            var finalProxies = new List<FinalProxy>();

            // Preserve the requested human-readable endpoint label. If different
            // connections would have the same visible name, suffix them 2, 3, ... .
            var nameOccurrences = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in alive)
            {
                string proto = NormalizeProto(p.Protocol);
                string cc = Cc(p.Host);
                string baseRemark = BuildClientNodeName(cc, Loc(p.Host), p.Host, p.Port);
                nameOccurrences.TryGetValue(baseRemark, out int occurrence);
                occurrence++;
                nameOccurrences[baseRemark] = occurrence;
                string remark = ApplyDuplicateNameSuffix(baseRemark, occurrence);
                string cleanLink = BuildCleanLink(p, remark);
                string continent = GetContinent(cc);

                // v6.14 composite score — the /top ranking. Only signals whose vantage
                // bias is known: Iran-side trust (delegated), clean-vantage liveness
                // (this hour), consistency streaks, ecosystem persistence, proximity.
                // No single signal can carry a node to the top — convergence across
                // vantage classes is what the score rewards.
                int score = 0;
                if (p.IranTested) score += 15;                      // delegated source test (useful signal, not a dominant region bias)
                if (p.TlsVerified) score += 20;                     // clean-vantage liveness, this hour
                if (p.XrayVerified) score += 35;                    // Increased weight: full proxy roundtrip
                if (p.EdgeVerified) score += 20;                    // Increased weight: second-vantage TLS (CF edge)
                score += Math.Min(p.VerifiedStreak, 5) * 2;         // up to +10 — verified N runs in a row
                if (p.XrayStreak >= 2) score += Math.Min(p.XrayStreak, 5) * 3;  // up to +15 — roundtrip-verified N runs in a row (>=2 gate: the first run already paid via XrayVerified)
                score += Math.Min(p.Streak, 20);                    // up to +20 — survived N hourly runs
                score += Math.Max(0, (8 - ProximityTier(cc)) * 2); // up to +16 — modest region prior, never a region gate
                if (p.SourceCount >= 2) score += Math.Min(p.SourceCount, 5) * 2;  // up to +10 — multi-source consensus

                finalProxies.Add(new FinalProxy
                {
                    Link = cleanLink, Proto = proto, CountryCode = cc,
                    Continent = continent, Remark = remark, Host = p.Host,
                    IranTested = p.IranTested, IsStable = p.IsStable, TlsVerified = p.TlsVerified,
                    XrayVerified = p.XrayVerified, EdgeVerified = p.EdgeVerified,
                    Score = score
                });
            }

            // Defense in depth: the earlier ParsedProxy filter is the primary policy,
            // but the final output boundary also rejects Cloudflare/WARP-labelled entries.
            // This catches converted YAML/WireGuard entries whose source metadata was not
            // represented identically by the initial URI parser. All output files, including
            // per-protocol files and both WireGuard export formats, are built from this list.
            int finalCloudflareDropped = finalProxies.RemoveAll(IsCloudflareFinal);
            if (finalCloudflareDropped > 0)
                LogWarning($"Final-output Cloudflare/WARP safety filter dropped {finalCloudflareDropped} converted entries before any files were written.");

            // Sort deterministically by Host -> Protocol.
            finalProxies = finalProxies
                .OrderBy(p => p.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(p => p.Proto, StringComparer.OrdinalIgnoreCase)
                .ToList();

            await SaveAllCategories(finalProxies, sourceReportCsv);
            GroupEnd();

            runStopwatch.Stop();
            LogSuccess("🎉 Done!");
            SummaryTable(finalProxies, runStopwatch.Elapsed, urls.Length, rawLines.Count);
        }
		
        // ====================== DEAD-NODE FILTERS ======================
        // The whole point of v6.11: drop ONLY on affirmative, location-independent
        // evidence of death. Never drop on silence.
        //
        //   DNS failure (×2)  → the hostname doesn't exist for anyone on the internet
        //   TCP RST (refused) → the server itself answered "nothing listens on this port"
        //
        // A timeout from GitHub means dead / firewalled / datacenter-blocked / geo-fenced
        // to Iran — indistinguishable — so it always KEEPS the node. MaxDropFraction is
        // a circuit breaker: if a filter would ever drop more than that fraction in one
        // run, the signal itself is suspect (resolver outage, network flake) and the
        // filter no-ops instead of mass-dropping. False drops self-heal next run since
        // output is rebuilt from scratch.

        private const double MaxDropFraction = 0.20;

        private static readonly HashSet<string> UdpProtocols = new(StringComparer.OrdinalIgnoreCase)
        { "hysteria", "hysteria2", "hy2", "tuic", "juicity", "wireguard", "wg", "mieru" };

        // DNS verdicts are asymmetric: only a fresh, explicit NXDOMAIN is evidence
        // that a hostname does not exist. Timeouts, SERVFAIL, throttling and other
        // inconclusive results always keep the node. A resolver-health canary runs
        // before mass filtering so a local DNS outage/sinkhole cannot mass-delete nodes.
        // The high-rate breaker is a last-resort guard, not the normal 50% threshold:
        // expired proxy domains can legitimately exceed half of the observed hostnames.
        private const double MaxDnsDropFraction = 0.80;
        private const int DnsCanaryMinimumSuccesses = 3;
        private static readonly string[] DnsHealthCanaries =
        {
            "iana.org", "github.com", "microsoft.com", "wikipedia.org", "cloudflare.com"
        };

        private async Task<bool> IsDnsResolverHealthyAsync()
        {
            int resolved = 0;
            await Parallel.ForEachAsync(DnsHealthCanaries,
                new ParallelOptions { MaxDegreeOfParallelism = DnsHealthCanaries.Length },
                async (host, _) =>
                {
                    try
                    {
                        var addresses = await Resolver.ResolveAllAsync(host);
                        if (IsSafeDnsCanaryAnswer(addresses))
                            Interlocked.Increment(ref resolved);
                    }
                    catch
                    {
                        // A failed canary is a failed canary, never evidence against proxy hosts.
                    }
                });

            if (resolved < DnsCanaryMinimumSuccesses)
            {
                LogWarning($"DNS filter skipped: resolver health check passed only {resolved}/{DnsHealthCanaries.Length} canaries (need {DnsCanaryMinimumSuccesses}); retaining all hostname nodes.");
                return false;
            }

            LogInfo($"DNS resolver health check passed ({resolved}/{DnsHealthCanaries.Length} canaries).");
            return true;
        }

        private async Task<List<ParsedProxy>> DropDnsDeadHostsAsync(List<ParsedProxy> proxies)
        {
            var hosts = proxies.Select(p => p.Host)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Where(h => !IPAddress.TryParse(h, out _))
                .ToList();
            if (hosts.Count == 0) return proxies;
            if (!await IsDnsResolverHealthyAsync())
            {
                // Continuing would let later resolved-IP/TCP/Xray stages act on an
                // untrustworthy DNS view. Abort before active probes; the workflow keeps
                // the last committed publication instead of publishing a mass-filtered or
                // potentially unsafe snapshot.
                LogWarning("DNS resolver health check failed; aborting before active endpoint probes to preserve the last publication.");
                throw new InvalidOperationException(
                    "DNS resolver health check failed; refusing to probe or publish this run.");
            }

            var dead = new ConcurrentBag<string>();
            await Parallel.ForEachAsync(hosts, new ParallelOptions { MaxDegreeOfParallelism = 100 },
                async (host, _) =>
                {
                    if (await Resolver.ResolveAsync(host) != null) return;                        // attempt 1 — cached
                    if (await Resolver.ResolveVerdictUncachedAsync(host) == DnsVerdict.NxDomain) // attempt 2 — fresh
                        dead.Add(host);
                    // Resolved → keep. Inconclusive (timeout/throttle) → keep.
                });

            if (dead.IsEmpty) return proxies;

            var deadSet = dead.ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (deadSet.Count > hosts.Count * MaxDnsDropFraction)
            {
                LogWarning($"DNS filter: {deadSet.Count}/{hosts.Count} explicit NXDOMAINs exceed the {MaxDnsDropFraction:P0} emergency breaker despite healthy canaries; retaining all hostname nodes as a final safety measure.");
                return proxies;
            }

            int before = proxies.Count;
            var result = proxies.Where(p => !deadSet.Contains(p.Host)).ToList();
            LogWarning($"DNS-dead: dropped {deadSet.Count} confirmed NXDOMAIN hosts ({before - result.Count} nodes); inconclusive DNS results were retained.");
            return result;
        }

        // ====================== RESOLVED-IP FILTER ======================
        // IsBadHost's FireHOL/reserved-IP checks only ran for IP-LITERAL hosts — a
        // hostname that RESOLVES into a private range or a FireHOL bogon slipped
        // through untouched. This closes that gap: every surviving hostname's
        // resolved IP (already cached from the GeoIP stage) goes through the same
        // two checks. Affirmative by definition — an endpoint inside 10/8 or a
        // hijacked range can never be a public proxy, whatever it's called.
        internal static bool ResolvedIpFilterExceedsWarningThreshold(int badHostCount, int totalHostCount)
            => totalHostCount > 0 && badHostCount > totalHostCount * MaxDnsDropFraction;

        private async Task<List<ParsedProxy>> DropBadResolvedIpsAsync(List<ParsedProxy> proxies)
        {
            var hosts = proxies.Select(p => p.Host)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Where(h => !IPAddress.TryParse(h, out _))     // literals already checked in IsBadHost
                .ToList();
            if (hosts.Count == 0) return proxies;

            var bad = new ConcurrentBag<string>();
            await Parallel.ForEachAsync(hosts, new ParallelOptions { MaxDegreeOfParallelism = 100 },
                async (host, _) =>
                {
                    var addresses = await Resolver.ResolveAllAsync(host); // cached full A/AAAA set
                    if (addresses.Length == 0) return;            // unresolvable = DNS filter's territory
                    // Reject mixed answers too: clients may select any returned address.
                    if (HasUnsafeResolvedAddress(addresses))
                        bad.Add(host);
                });

            if (bad.IsEmpty) return proxies;

            var badSet = bad.ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (ResolvedIpFilterExceedsWarningThreshold(badSet.Count, hosts.Count))
            {
                // This threshold is diagnostic only. Unlike NXDOMAIN, a private/reserved/
                // blacklisted IP is affirmative unsafe evidence, so never bypass this filter
                // or allow the following TCP/Xray stages to probe those hosts.
                LogWarning($"Resolved-IP filter: {badSet.Count}/{hosts.Count} hostnames resolved to unsafe addresses (over {MaxDnsDropFraction:P0}); dropping unsafe hosts and continuing only with safe endpoints.");
            }

            int before = proxies.Count;
            var result = proxies.Where(p => !badSet.Contains(p.Host)).ToList();
            LogWarning($"Resolved-IP: dropped {badSet.Count} hosts ({before - result.Count} nodes) — private/bogon/blacklisted target.");
            return result;
        }

        // ====================== ALIAS COLLAPSE ======================
        // The primary dedup key uses the host AS WRITTEN — so "vless://uuid@1.2.3.4:443"
        // and "vless://uuid@server.com:443" (server.com → 1.2.3.4) are two keys for ONE
        // endpoint, and both shipped. This pass re-keys every node on its RESOLVED IP
        // (the GeoIP stage already warmed the resolver cache, so this is ~zero-cost)
        // and merges spelling-variants — preferring the hostname form, which survives
        // IP rotation where a bare literal does not.
        //
        // Deliberately NOT merged (genuinely different connections):
        //   - different ports on one host (separate inbounds; one may survive when
        //     the censor blocks the other)
        //   - different credentials on one host:port (different access)
        //   - different effective SNI or implicit WS/H2 Host values, paths, or REALITY keys
        internal static string BuildAliasCanonicalHost(
            string host, IEnumerable<IPAddress> resolvedAddresses)
        {
            static string NormalizeAddress(IPAddress address) =>
                address.IsIPv4MappedToIPv6 ? address.MapToIPv4().ToString() : address.ToString();

            if (IPAddress.TryParse(host, out var literal))
                return NormalizeAddress(literal);

            // Only treat a hostname as an alias of a literal when its complete resolved
            // address set contains exactly that one address. Sharing just one A/AAAA
            // record is not enough: multi-homed hosts may lead to different backends.
            var addresses = resolvedAddresses
                .Select(NormalizeAddress)
                .Distinct(StringComparer.Ordinal)
                .OrderBy(address => address, StringComparer.Ordinal)
                .ToArray();
            if (addresses.Length == 0)
                return "unresolved|" + (host ?? "").Trim().ToLowerInvariant();
            if (addresses.Length == 1)
                return addresses[0];
            return "multi[" + string.Join(",", addresses) + "]";
        }

        internal static void MergeAliasMetadata(
            ParsedProxy kept, ParsedProxy duplicate, IEnumerable<string> combinedSources)
        {
            int distinctSources = combinedSources.Distinct(StringComparer.OrdinalIgnoreCase).Count();
            kept.SourceCount = Math.Max(Math.Max(kept.SourceCount, duplicate.SourceCount), distinctSources);
            kept.IranTested |= duplicate.IranTested;
        }

        private async Task<List<ParsedProxy>> CollapseHostAliasesAsync(
            List<ParsedProxy> proxies,
            IReadOnlyDictionary<string, HashSet<string>> keySources)
        {
            var index = new Dictionary<string, int>(StringComparer.Ordinal);
            var aliasSources = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
            var kept = new List<ParsedProxy>();
            int collapsed = 0;

            foreach (var p in proxies)   // input is deterministically sorted
            {
                IPAddress[] addresses = IPAddress.TryParse(p.Host, out var literal)
                    ? new[] { literal }
                    : await Resolver.ResolveAllAsync(p.Host); // full cached A/AAAA set
                string canonical = BuildAliasCanonicalHost(p.Host, addresses);

                string key = p.EndpointKey(canonical);
                if (index.TryGetValue(key, out var pos))
                {
                    collapsed++;
                    if (!aliasSources.TryGetValue(key, out var sources))
                        aliasSources[key] = sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    if (keySources.TryGetValue(p.DeduplicationKey, out var duplicateSources))
                        sources.UnionWith(duplicateSources);

                    // Alias collapse must preserve metadata gathered before DNS canonicalization:
                    // otherwise source consensus and source-tested evidence disappear with the
                    // discarded spelling variant. Union exact source URLs to avoid double counts.
                    var keptProxy = kept[pos];
                    if (IPAddress.TryParse(keptProxy.Host, out _) && !IPAddress.TryParse(p.Host, out _))
                    {
                        MergeAliasMetadata(p, keptProxy, sources);
                        kept[pos] = p;
                    }
                    else
                    {
                        MergeAliasMetadata(keptProxy, p, sources);
                    }
                }
                else
                {
                    index[key] = kept.Count;
                    kept.Add(p);
                    var sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    if (keySources.TryGetValue(p.DeduplicationKey, out var nodeSources))
                        sources.UnionWith(nodeSources);
                    aliasSources[key] = sources;
                    p.SourceCount = Math.Max(p.SourceCount, sources.Count);
                }
            }

            if (collapsed > 0)
                LogInfo($"Alias collapse: {collapsed} spelling-variants merged (same endpoint, IP/hostname forms).");
            return kept;
        }

        private async Task<List<ParsedProxy>> DropTcpRefusedAsync(List<ParsedProxy> proxies)
        {
            // RST on connect = the server's own TCP stack saying nothing listens on that
            // port. A timeout or other error is inconclusive and always keeps the node.
            var candidates = proxies
                .Where(p => !UdpProtocols.Contains(p.Protocol) && int.TryParse(p.Port, out _))
                .ToList();
            if (candidates.Count == 0) return proxies;

            // Probe every resolved address for each hostname. A multi-address hostname is
            // dead only if every answer explicitly refuses the port; one refused A record
            // must not discard a node whose AAAA/other A record can still serve clients.
            var endpointSet = new Dictionary<(string Ip, int Port), byte>();
            var nodeEndpoints = new List<(ParsedProxy Node, IPAddress[] Addresses, int Port)>(candidates.Count);
            foreach (var p in candidates)
            {
                var addresses = (await Resolver.ResolveAllAsync(p.Host))
                    .Distinct()
                    .ToArray();
                if (addresses.Length == 0) continue; // unresolvable = DNS filter's territory
                int port = int.Parse(p.Port);
                foreach (var ip in addresses)
                    endpointSet.TryAdd((ip.ToString(), port), 0);
                nodeEndpoints.Add((p, addresses, port));
            }
            if (endpointSet.Count == 0) return proxies;

            var deadEndpoints = new ConcurrentBag<(string Ip, int Port)>();
            await Parallel.ForEachAsync(endpointSet.Keys, new ParallelOptions { MaxDegreeOfParallelism = 500 },
                async (ep, ct) =>
                {
                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeoutCts.CancelAfter(TimeSpan.FromSeconds(3));
                    try
                    {
                        using var tcp = new TcpClient();
                        await tcp.ConnectAsync(IPAddress.Parse(ep.Ip), ep.Port, timeoutCts.Token);
                        // Connected — this endpoint is alive (we deliberately send nothing).
                    }
                    catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionRefused)
                    {
                        deadEndpoints.Add(ep); // affirmative death for this address only
                    }
                    catch (OperationCanceledException) { /* timeout — inconclusive, keep */ }
                    catch { /* unreachable / no-v6-route / anything else — keep */ }
                });

            if (deadEndpoints.IsEmpty) return proxies;

            var deadSet = deadEndpoints.ToHashSet();
            int droppedNodes = nodeEndpoints.Count(ne =>
                AllResolvedEndpointsRefused(ne.Addresses, ne.Port, deadSet));
            if (droppedNodes > candidates.Count * MaxDropFraction)
            {
                LogWarning($"TCP filter: {deadSet.Count} refused endpoints ({droppedNodes}/{candidates.Count} nodes) — over {MaxDropFraction:P0} circuit breaker, keeping all.");
                return proxies;
            }

            var deadNodeKeys = nodeEndpoints
                .Where(ne => AllResolvedEndpointsRefused(ne.Addresses, ne.Port, deadSet))
                .Select(ne => ne.Node.DeduplicationKey)
                .ToHashSet(StringComparer.Ordinal);
            var result = proxies.Where(p => !deadNodeKeys.Contains(p.DeduplicationKey)).ToList();
            LogWarning($"TCP-refused: dropped {proxies.Count - result.Count} nodes across {deadSet.Count} refused endpoints (all resolved addresses refused).");
            return result;
        }

        internal static bool AllResolvedEndpointsRefused(
            IEnumerable<IPAddress> addresses,
            int port,
            ISet<(string Ip, int Port)> refusedEndpoints)
        {
            var unique = addresses.Select(ip => ip.ToString())
                .Distinct(StringComparer.Ordinal)
                .ToArray();
            return unique.Length > 0 && unique.All(ip => refusedEndpoints.Contains((ip, port)));
        }

        // ====================== XRAY DEEP CHECK (v6.15) ======================
        // The strongest life signal that exists without a machine in Iran: run the REAL
        // xray-core binary with one socks-inbound + one outbound per candidate, and
        // fetch generate_204 THROUGH each node. Success = full protocol handshake +
        // authentication + end-to-end proxy of real traffic. Promotion-only: an
        // Azure-vantage failure says nothing about Iran, so failures never drop.
        private const int XrayTopN = 3000;   // v6.20: back to the proven size — ~2600 outbounds started fine on Aug 25; startup output scales with outbound count, and 50 parallel probes fit ~3000 in the budget anyway
        private static readonly TimeSpan XrayStageBudget = TimeSpan.FromMinutes(8); // 8 min hard budget prevents time-wasting

        private static bool IsXrayCandidate(ParsedProxy p) =>
            NormalizeProto(p.Protocol) is "vless" or "vmess" or "trojan" or "ss";   // xray-supported only (no QUIC)

        internal static List<ParsedProxy> RankXrayCandidates(
            IEnumerable<ParsedProxy> proxies,
            IReadOnlyDictionary<string, string> countryCache,
            int maxCount = XrayTopN)
        {
            if (maxCount <= 0) return new List<ParsedProxy>();

            // Evidence first: current liveness evidence, then distinct-source consensus.
            // Geography is only a tie-breaker, so a nearby single-source node cannot
            // outrank a far-away node supported by substantially more distinct feeds.
            return proxies
                .Where(p => IsXrayCandidate(p) && int.TryParse(p.Port, out _))
                .OrderByDescending(p => p.TlsVerified)
                .ThenByDescending(p => p.IranTested)
                .ThenByDescending(p => p.SourceCount)
                .ThenBy(p => countryCache.TryGetValue(p.Host, out var cc) ? ProximityTier(cc) : 9)
                .Take(maxCount)
                .ToList();
        }

        private async Task XrayVerifyAsync(List<ParsedProxy> proxies,
            ConcurrentDictionary<string, string> countryCache)
        {
            string? xrayBin = Environment.GetEnvironmentVariable("XRAY_BIN");
            if (string.IsNullOrEmpty(xrayBin) || !File.Exists(xrayBin))
            {
                LogInfo("Xray deep check: XRAY_BIN unset or binary missing — stage skipped (fail-soft).");
                return;
            }

            // v6.19: roundtrip budget spent ONLY on nodes that can enter top.txt/verified.txt
            // Keep the probe pool international. Prefer current independent liveness
            // evidence and source consensus first; geography is only a tie-breaker.
            // Streaks are updated after this stage, so do not rank this pool by stale or
            // not-yet-computed streak fields. Runner success is not the user's own test.
            var candidates = RankXrayCandidates(proxies, countryCache, XrayTopN);
            if (candidates.Count == 0) { LogInfo("Xray deep check: no candidates."); return; }

            // ---- build one config: inbound[i] socks on port 21000+i → outbound ob{port} ----
            const int basePort = 21000;
            var inbounds = new List<object>();
            var outbounds = new List<object>
                { new Dictionary<string, object?> { ["tag"] = "direct", ["protocol"] = "freedom" } };
            var rules = new List<object>();
            var portMap = new Dictionary<int, ParsedProxy>();

            foreach (var p in candidates)
            {
                int localPort = basePort + portMap.Count;
                var ob = BuildXrayOutbound(p, $"ob{localPort}");
                if (ob == null) continue;   // unconvertible node — just not deep-checked
                inbounds.Add(new Dictionary<string, object?>
                {
                    ["tag"] = $"ib{localPort}", ["listen"] = "127.0.0.1", ["port"] = localPort,
                    ["protocol"] = "socks",
                    ["settings"] = new Dictionary<string, object?> { ["auth"] = "noauth", ["udp"] = false }
                });
                outbounds.Add(ob);
                rules.Add(new Dictionary<string, object?>
                {
                    ["type"] = "field",
                    ["inboundTag"] = new List<string> { $"ib{localPort}" },
                    ["outboundTag"] = $"ob{localPort}"
                });
                portMap[localPort] = p;
            }
            if (portMap.Count == 0) { LogInfo("Xray deep check: no convertible candidates."); return; }

            var config = new Dictionary<string, object?>
            {
                // "error", not "warning": xray emits a deprecation Warning PER ws/grpc
                // outbound (~thousands at TopN=3000). Nobody drains stdout while xray
                // runs, so the pipe buffer (~64KB) fills and the process FREEZES
                // mid-probe. "error" silences the flood; fatal startup errors
                // ("Failed to start: ...") are printed by main regardless of loglevel
                // and still land in our crash diagnostics.
                ["log"] = new Dictionary<string, object?> { ["loglevel"] = "error" },
                ["inbounds"] = inbounds,
                ["outbounds"] = outbounds,
                ["routing"] = new Dictionary<string, object?> { ["rules"] = rules }
            };
            string cfgPath = Path.Combine(Path.GetTempPath(), "fastnodes-xray.json");
            await File.WriteAllTextAsync(cfgPath, JsonSerializer.Serialize(config));

            Process? proc = null;
            int verified = 0, probed = 0;
            var stageSw = Stopwatch.StartNew();
            try
            {
                proc = Process.Start(new ProcessStartInfo
                {
                    FileName = xrayBin, Arguments = $"run -c {cfgPath}",
                    UseShellExecute = false, CreateNoWindow = true,
                    RedirectStandardOutput = true, RedirectStandardError = true
                });
                if (proc == null) { LogWarning("Xray deep check: failed to start process."); return; }

                // v6.20: drain BOTH pipes from the instant xray starts. xray emits
                // per-outbound startup output — at ~4000+ outbounds that overflows the
                // ~64KB OS pipe buffer and xray BLOCKS on its next write before binding
                // a single inbound: process alive ("running") but frozen forever. Both
                // the 15s and 90s readiness windows died on exactly this. The captured
                // tasks double as crash diagnostics below (a crashed xray closes its
                // pipes, completing the drains with the error text).
                Task<string> drainOut = proc.StandardOutput.ReadToEndAsync();
                Task<string> drainErr = proc.StandardError.ReadToEndAsync();

                // 90s: startup may need to bind up to 3000 inbound/outbound pairs.
                // Keep the readiness window generous; killing a healthy process too early
                // would erase this run's verified evidence.
                bool ready = false;
                for (int i = 0; i < 900 && !ready; i++)
                {
                    if (proc.HasExited) break; // xray crashed on startup
                    await Task.Delay(100);
                    try
                    {
                        using var t = new TcpClient();
                        await t.ConnectAsync(IPAddress.Loopback, basePort, CancellationToken.None);
                        using var t2 = new TcpClient();
                        await t2.ConnectAsync(IPAddress.Loopback, basePort + portMap.Count - 1, CancellationToken.None);
                        ready = true;
                    }
                    catch { }
                }
                
                if (!ready) 
                { 
                    string errOut = "", stdOut = "";
                    if (proc.HasExited)
                    {
                        await Task.WhenAny(Task.WhenAll(drainOut, drainErr), Task.Delay(2000));   // let drains finish reading the closed pipes
                        errOut = drainErr.IsCompletedSuccessfully ? drainErr.Result : "";
                        stdOut = drainOut.IsCompletedSuccessfully ? drainOut.Result : "";
                    }
                    LogWarning($"Xray deep check: didn't open its inbounds in 90s. Xray status: {(proc.HasExited ? "crashed" : "running")}. Error output: {errOut}. Std output: {stdOut}");
                    return; 
                }

                await Parallel.ForEachAsync(portMap.Keys, new ParallelOptions { MaxDegreeOfParallelism = 50 },
                    async (localPort, ct) =>
                    {
                        if (stageSw.Elapsed > XrayStageBudget) return;   // budget cut lands in the tail
                        Interlocked.Increment(ref probed);
                        if (await ProbeViaSocksAsync(localPort, ct))
                        {
                            portMap[localPort].XrayVerified = true;
                            Interlocked.Increment(ref verified);
                        }
                    });

                LogInfo($"Xray deep check: {verified}/{probed} nodes completed a FULL proxy roundtrip " +
                        $"({stageSw.Elapsed.TotalSeconds:0}s; {portMap.Count - probed} skipped by budget). Failures are not drops.");
            }
            finally
            {
                try { if (proc is { HasExited: false }) proc.Kill(true); } catch { }
                proc?.Dispose();
                try { File.Delete(cfgPath); } catch { }
            }
        }

        // Full roundtrip probe: socks5 handshake (no auth) → CONNECT www.gstatic.com:80 →
        // minimal HTTP/1.1 GET /generate_204 → any 2xx status = affirmative life.
        private static async Task<bool> ProbeViaSocksAsync(int localPort, CancellationToken ct)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(8));
                using var tcp = new TcpClient();
                await tcp.ConnectAsync(IPAddress.Loopback, localPort, cts.Token);
                var s = tcp.GetStream();

                // greeting: VER=5, 1 method, NO AUTH
                await s.WriteAsync(new byte[] { 5, 1, 0 }, cts.Token);
                var g = new byte[2];
                await ReadExactAsync(s, g, cts.Token);
                if (g[0] != 5 || g[1] != 0) return false;

                // CONNECT request by domain
                var host = Encoding.ASCII.GetBytes("www.gstatic.com");
                var req = new byte[7 + host.Length];
                req[0] = 5; req[1] = 1; req[2] = 0; req[3] = 3; req[4] = (byte)host.Length;
                Array.Copy(host, 0, req, 5, host.Length);
                req[5 + host.Length] = (byte)(80 >> 8);
                req[6 + host.Length] = (byte)(80 & 0xFF);
                await s.WriteAsync(req, cts.Token);

                // response: VER REP RSV ATYP + bound addr + port
                var head = new byte[4];
                await ReadExactAsync(s, head, cts.Token);
                if (head[1] != 0) return false;                     // REP != 0 — connect failed
                int addrLen = head[3] switch { 1 => 4, 4 => 16, 3 => 0, _ => -1 };
                if (addrLen == -1) return false;
                if (addrLen == 0)                                  // domain: 1 length byte first
                {
                    var l = new byte[1];
                    await ReadExactAsync(s, l, cts.Token);
                    addrLen = l[0];
                }
                var skip = new byte[addrLen + 2];
                await ReadExactAsync(s, skip, cts.Token);

                // the moment of truth: an HTTP request THROUGH the node
                var http = Encoding.ASCII.GetBytes(
                    "GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nUser-Agent: FastNodes-probe\r\nConnection: close\r\n\r\n");
                await s.WriteAsync(http, cts.Token);
                var status = new byte[12];
                await ReadExactAsync(s, status, cts.Token);
                string line = Encoding.ASCII.GetString(status);     // "HTTP/1.1 204"
                int sp = line.IndexOf(' ');
                return sp >= 0 && sp + 1 < line.Length && line[sp + 1] == '2';
            }
            catch { return false; }
        }

        private static async Task ReadExactAsync(NetworkStream s, byte[] buf, CancellationToken ct)
        {
            int off = 0;
            while (off < buf.Length)
            {
                int n = await s.ReadAsync(buf.AsMemory(off, buf.Length - off), ct);
                if (n == 0) throw new IOException("socks5: stream closed");
                off += n;
            }
        }

        // Safe-list of Shadowsocks ciphers that xray-core actually supports.
        // Feeding it an unsupported cipher (like aes-256-cfb) crashes Xray on startup.
        private static readonly HashSet<string> XraySupportedSsCiphers = new(StringComparer.OrdinalIgnoreCase)
        {
            "aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
            "2022-blake3-aes-256-gcm", "2022-blake3-aes-128-gcm",
            "2022-blake3-chacha20-poly1305", "2022-blake3-chacha8-poly1305",
            "none", "plain"
        };

        // Link → xray outbound. Option B (locked at design): fp / serviceName / ws Host
        // header are re-read from the source link's query string — no model fields, no
        // dedup changes. Unconvertible → null (node simply isn't deep-checked).
        private static Dictionary<string, object?>? BuildXrayOutbound(ParsedProxy p, string tag)
        {
            string proto = NormalizeProto(p.Protocol);
            var q = QueryFromBaseLink(p);

            var stream = new Dictionary<string, object?>();
            string network = string.IsNullOrEmpty(p.Network) ? "tcp" : p.Network.ToLowerInvariant();
            bool reality = !string.IsNullOrEmpty(p.Pbk) || p.Security.Equals("reality", StringComparison.OrdinalIgnoreCase);
            bool tls = reality || p.Security.Equals("tls", StringComparison.OrdinalIgnoreCase) || proto == "trojan";

            // Xray-core rejects REALITY on WebSocket and HTTP/2 transports. One such
            // outbound makes the entire generated config fail at startup, wiping this
            // run's Xray evidence. Skip only the unsupported probe; keep the node in the
            // ordinary pool because a failed probe conversion is not proof of death.
            if (reality && network is not ("tcp" or "grpc")) return null;

            switch (network)
            {
                case "tcp":
                    stream["network"] = "tcp"; break;
                case "ws":
                    stream["network"] = "ws";
                    var ws = new Dictionary<string, object?> { ["path"] = string.IsNullOrEmpty(p.Path) ? "/" : p.Path };
                    string wsHost = q.GetValueOrDefault("host", "");
                    if (!string.IsNullOrEmpty(wsHost))
                        ws["headers"] = new Dictionary<string, object?> { ["Host"] = wsHost };
                    stream["wsSettings"] = ws;
                    break;
                case "grpc":
                    stream["network"] = "grpc";
                    stream["grpcSettings"] = new Dictionary<string, object?>
                    {
                        ["serviceName"] = q.GetValueOrDefault("serviceName", ""),
                        ["multiMode"] = q.GetValueOrDefault("mode", "") == "multi"
                    };
                    break;
                case "h2":
                    stream["network"] = "h2";
                    stream["h2Settings"] = new Dictionary<string, object?>
                    {
                        ["host"] = new List<string> { string.IsNullOrEmpty(p.Sni) ? p.Host : p.Sni },
                        ["path"] = string.IsNullOrEmpty(p.Path) ? "/" : p.Path
                    };
                    break;
                default:
                    return null;   // unknown transport — don't guess
            }

            if (tls)
            {
                string sni = string.IsNullOrEmpty(p.Sni) ? p.Host : p.Sni;
                string fp = q.GetValueOrDefault("fp", "");
                if (string.IsNullOrEmpty(fp) && reality) fp = "chrome";   // REALITY requires a uTLS fingerprint
                if (reality)
                {
                    // Xray crashes if REALITY is enabled but publicKey is empty
                    if (string.IsNullOrEmpty(p.Pbk)) return null;
                    stream["security"] = "reality";
                    stream["realitySettings"] = new Dictionary<string, object?>
                    {
                        ["serverName"] = sni, ["fingerprint"] = fp,
                        ["publicKey"] = p.Pbk, ["shortId"] = p.Sid, ["spiderX"] = "/"
                    };
                }
                else
                {
                    stream["security"] = "tls";
                    stream["tlsSettings"] = new Dictionary<string, object?>
                    {
                        ["serverName"] = sni
                        // "allowInsecure" was removed in Xray 26.x. 
                        // Xray will now strictly verify TLS certs for the deep check.
                    };
                }
            }

            object settings;
            switch (proto)
            {
                case "vless":
                {
                    if (string.IsNullOrEmpty(p.Credential)) return null;
                    var user = new Dictionary<string, object?> { ["id"] = p.Credential, ["encryption"] = "none" };
                    if (!string.IsNullOrEmpty(p.Flow))
                    {
                        // Xray crashes if flow=xtls-rprx-vision is set without TLS/REALITY
                        if (!tls && !reality) return null;
                        user["flow"] = p.Flow;
                    }
                    settings = new Dictionary<string, object?>
                    {
                        ["vnext"] = new List<object> { new Dictionary<string, object?>
                            { ["address"] = p.Host, ["port"] = int.Parse(p.Port),
                              ["users"] = new List<object> { user } } }
                    };
                    break;
                }
                case "vmess":
                {
                    if (string.IsNullOrEmpty(p.Credential)) return null;
                    settings = new Dictionary<string, object?>
                    {
                        ["vnext"] = new List<object> { new Dictionary<string, object?>
                            { ["address"] = p.Host, ["port"] = int.Parse(p.Port),
                              ["users"] = new List<object> { new Dictionary<string, object?>
                                  { ["id"] = p.Credential, ["alterId"] = p.Aid, ["security"] = "auto" } } } }
                    };
                    break;
                }
                case "trojan":
                {
                    if (string.IsNullOrEmpty(p.Credential)) return null;
                    settings = new Dictionary<string, object?>
                    {
                        ["servers"] = new List<object> { new Dictionary<string, object?>
                            { ["address"] = p.Host, ["port"] = int.Parse(p.Port), ["password"] = p.Credential } }
                    };
                    break;
                }
                case "ss":
                {
                    int colon = p.Credential.IndexOf(':');
                    if (colon <= 0) return null;
                    string method = p.Credential[..colon];
                    // Xray panics on startup if it encounters an unsupported/legacy SS cipher
                    if (!XraySupportedSsCiphers.Contains(method)) return null;
                    settings = new Dictionary<string, object?>
                    {
                        ["servers"] = new List<object> { new Dictionary<string, object?>
                            { ["address"] = p.Host, ["port"] = int.Parse(p.Port),
                              ["method"] = method,
                              ["password"] = p.Credential[(colon + 1)..] } }
                    };
                    break;
                }
                default:
                    return null;
            }

            return new Dictionary<string, object?>
            {
                ["tag"] = tag,
                ["protocol"] = proto == "ss" ? "shadowsocks" : proto,
                ["settings"] = settings,
                ["streamSettings"] = stream
            };
        }

        // Option B helper: re-read the query string from the ORIGINAL link. vmess base64
        // links have no query → empty dict (vmess never needs fp/serviceName anyway).
        private static Dictionary<string, string> QueryFromBaseLink(ParsedProxy p)
        {
            try { return ParseQuery(new Uri(p.BaseLink).Query); }
            catch { return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase); }
        }

        // ====================== EDGE VERIFICATION (v6.15) ======================
        // Second vantage via the Cloudflare Worker. Priority pool: TLS-capable nodes
        // Azure could NOT verify — the "second opinion" — capped at 2000 endpoints.
        // Hostnames are sent as-is so CF resolves DNS from its own vantage too.
        // Promotion-only; dormant (one log line) until both secrets exist.
        private const int EdgeMaxEndpoints = 5000; // Increased to rely more on CF edge
        private const int EdgeBatchSize = 25;

        private async Task EdgeVerifyAsync(List<ParsedProxy> proxies,
            ConcurrentDictionary<string, string> countryCache)
        {
            string? url = Environment.GetEnvironmentVariable("WORKER_URL");
            string? auth = Environment.GetEnvironmentVariable("WORKER_AUTH");
            if (string.IsNullOrEmpty(url) || string.IsNullOrEmpty(auth))
            {
                LogInfo("Edge verification: WORKER_URL/WORKER_AUTH unset — stage skipped (fail-soft).");
                return;
            }

            var pool = new List<ParsedProxy>();
            // No comparer: value tuples use structural equality, and both string
            // components are already lowercased below before being added.
            var seen = new HashSet<(string, int, string)>();
            int cfSkipped = 0;
            async Task AddToPoolAsync(ParsedProxy p)
            {
                // CF-fronted hosts are unprovable from a Worker (CF blocks Worker→CF
                // connects) — skip them and spend the budget on hosts this vantage
                // can actually judge. Resolver cache is warm (GeoIP resolved every
                // alive host), so this is a dictionary hit. Unresolvable hosts pass
                // through — they'll fail at the Worker as timeouts, correct outcome.
                if (CfCidrs.Length > 0)
                {
                    var addresses = IPAddress.TryParse(p.Host, out var literal)
                        ? new[] { literal }
                        : await Resolver.ResolveAllAsync(p.Host);
                    if (addresses.Any(IsCloudflareIp)) { cfSkipped++; return; }
                }
                string sni = string.IsNullOrEmpty(p.Sni) ? p.Host : p.Sni;
                if (seen.Add((p.Host.Trim().ToLowerInvariant(), int.Parse(p.Port), sni.Trim().ToLowerInvariant())))
                    pool.Add(p);
            }

            // Pool 1 (half the budget): cross-vantage CONFIRMATION — nodes Azure already
            // TLS-verified. High pass rate; every pass earns the +10 convergence bonus,
            // so top.txt starts preferring nodes alive from BOTH vantage classes.
            // (The stale comment about "Azure could NOT verify" above this class no
            //  longer describes the pool design — two-pool since the refresh.)
            foreach (var p in proxies
                .Where(p => p.TlsVerified && int.TryParse(p.Port, out _) && IsTlsCandidate(p))
                .OrderByDescending(p => p.IranTested)
                .ThenBy(p => countryCache.TryGetValue(p.Host, out var cc) ? ProximityTier(cc) : 9))
            {
                // (no Streak sort: streaks load in UpdateStreaks, which runs AFTER
                //  this stage — every Streak is still 1 here, the key sorts nothing)
                if (seen.Count >= EdgeMaxEndpoints / 2) break;
                await AddToPoolAsync(p);
            }

            // Pool 2 (rest): second opinion on Azure TLS-FAILURES — the hidden gems
            // that geo-block datacenter IPs but answer from Cloudflare's edge.
            foreach (var p in proxies
                .Where(p => !p.TlsVerified && int.TryParse(p.Port, out _) && IsTlsCandidate(p))
                .OrderByDescending(p => p.IranTested))
            {
                if (seen.Count >= EdgeMaxEndpoints) break;
                await AddToPoolAsync(p);
            }
            if (cfSkipped > 0)
                LogInfo($"Edge pool: skipped {cfSkipped} CF-fronted hosts (unprovable from a Worker vantage).");
            if (pool.Count == 0) { LogInfo("Edge verification: no candidates."); return; }

            int ok = 0, cfBlocked = 0, refused = 0, timeouts = 0, errors = 0, dnsFails = 0, tlsFails = 0;
            var edgeReasons = new ConcurrentDictionary<string, int>();
            var batches = pool.Select((p, i) => (Node: p, Idx: i))
                .GroupBy(x => x.Idx / EdgeBatchSize).ToList();

            using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(6)); // Increased budget for 5000 endpoints
            try
            {
                await Parallel.ForEachAsync(batches,
                    new ParallelOptions { MaxDegreeOfParallelism = 3, CancellationToken = cts.Token },
                    async (batch, ct) =>
                    {
                        var payload = JsonSerializer.Serialize(new
                        {
                            targets = batch.Select(b => new
                            {
                                id = b.Idx, host = b.Node.Host, port = int.Parse(b.Node.Port), tls = true
                            }).ToList()
                        });
                        using var req = new HttpRequestMessage(HttpMethod.Post, url)
                        {
                            Content = new StringContent(payload, Encoding.UTF8, "application/json")
                        };
                        req.Headers.Add("x-auth", auth);

                        try
                        {
                            using var resp = await _http.SendAsync(req, ct);
                            resp.EnsureSuccessStatusCode();
                            using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
                            foreach (var r in doc.RootElement.GetProperty("results").EnumerateArray())
                            {
                                int id = r.GetProperty("id").GetInt32();
                                string tcp = r.GetProperty("tcp").GetString() ?? "error";
                                string? tlsR = r.TryGetProperty("tls", out var t) && t.ValueKind == JsonValueKind.String
                                    ? t.GetString() : null;
                                if (tcp == "ok" && tlsR == "ok")
                                {
                                    pool[id].EdgeVerified = true;
                                    Interlocked.Increment(ref ok);
                                }
                                else
                                {
                                    // raw reason evidence for every failure — top ones logged below
                                    if (r.TryGetProperty("reason", out var re) && re.ValueKind == JsonValueKind.String)
                                    {
                                        string raw = re.GetString() ?? "";
                                        if (raw.Length > 0)
                                            edgeReasons.AddOrUpdate(raw, 1, (_, c) => c + 1);
                                    }
                                    if (tcp == "cf-blocked") Interlocked.Increment(ref cfBlocked);
                                    else if (tcp == "refused") Interlocked.Increment(ref refused);
                                    else if (tcp == "timeout") Interlocked.Increment(ref timeouts);
                                    else if (tcp == "dns") Interlocked.Increment(ref dnsFails);
                                    else if (tcp == "tls-failed") Interlocked.Increment(ref tlsFails);
                                    else Interlocked.Increment(ref errors);
                                }
                            }
                        }
                        catch (Exception ex) { LogWarning($"Edge batch failed: {ex.Message}"); }
                    });
            }
            catch (OperationCanceledException)
            {
                LogWarning("Edge verification: 6-minute budget exhausted — remaining unverified (not dropped).");
            }

            LogInfo($"Edge verification: {ok}/{pool.Count} endpoints TLS-verified from the CF edge → " +
                    $"nodes promoted (+20). [cf-blocked {cfBlocked}, refused {refused}, timeout {timeouts}, dns {dnsFails}, tls-failed {tlsFails}, err {errors}] Failures are not drops.");
            // v2: raw Worker error messages, top 8 by frequency — this is what tells us
            // WHY the edge check fails (cert verification? SNI rejection? CF→CF blocks?).
            foreach (var kv in edgeReasons.OrderByDescending(k => k.Value).Take(8))
                LogWarning($"  Edge fail reason: {kv.Key} × {kv.Value}");
        }

        // ====================== IRAN-TESTED SOURCES (v6.13) ======================
        // Sources that EXPLICITLY test nodes before publishing (best-results lists,
        // checked lists, speed-tested lists, checker output) — overwhelmingly Iranian
        // maintainers testing from Iran. A node they publish carries Iran-side
        // validation an Azure runner can never measure. That's the vantage problem
        // converted into a ranking signal.
        private static readonly string[] IranTestedMarkers =
        {
            "F0rc3Run",            // entire repo publishes tested results
            "iran_top100_checked", // sakha1370/OpenRay — explicitly checked, Iran-focused
            "Sub_Checker_Creator", // hamedp-71 — checker output
            "HighSpeed",           // 10ium/free-config — speed-tested
            "speed.txt",           // ndsphonemy/proxy-sub — speed-tested
            "Eternity",            // mahdibland SSAggregator — liveness-checked aggregate (incl. EternityAir)
            "kobabi",              // liketolivefree — hand-curated Iranian channel
            "verified/configs",    // 0xRadikal — explicitly verified node lists
            "top100.txt",          // 0xRadikal — top-100 tested list
            "fast/configs",        // 0xRadikal — speed-tested list
            "alive_full",          // Diversan313/apex-parser — alive-checked output
        };

        private static bool IsIranTestedSource(string url)
        {
            foreach (var m in IranTestedMarkers)
                if (url.Contains(m, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        // ====================== STABILITY TRACKING (v6.13) ======================
        // The hourly schedule itself is a distributed liveness test — computed every
        // run, results thrown away. A node present N consecutive runs survived N
        // rounds of NXDOMAIN/RST/bogon filtering AND persisted in the (largely
        // Iranian) source ecosystem's rotation.
        //
        // Semantics: streak = consecutive runs present, grace of ONE missed run (a
        // source repo that 502s for an hour shouldn't erase months of streak); a
        // second consecutive miss deletes the entry.

        private const int StableMinRuns = 3;     // ≥3 consecutive hourly runs ⇒ "stable"
        private const int MaxStreak = 24;        // cap — veteran is veteran; keeps JSON bounded
        private const int GraceMisses = 1;

        private static string HistoryPath =>
            Path.Combine(Directory.GetCurrentDirectory(), "state", "history.json");

        // 8-byte truncated SHA-256 of the dedup key — raw keys (~100 chars × 170K)
        // would be ~17 MB of JSON committed hourly; hashed it's ~5 MB. Collision odds
        // at this scale ≈ 10⁻⁹, negligible.
        private static string HistKey(string dedupKey) =>
            Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(dedupKey)), 0, 8);

        private static Dictionary<string, NodeHistory> LoadHistory()
        {
            try
            {
                if (File.Exists(HistoryPath))
                    return JsonSerializer.Deserialize<Dictionary<string, NodeHistory>>(
                               File.ReadAllText(HistoryPath)) ?? new Dictionary<string, NodeHistory>();
            }
            catch (Exception ex) { LogWarning($"history.json unreadable — starting fresh (non-fatal): {ex.Message}"); }
            return new Dictionary<string, NodeHistory>();
        }

        private static void UpdateStreaks(Dictionary<string, NodeHistory> history, List<ParsedProxy> alive)
        {
            var seenNow = new HashSet<string>();
            foreach (var p in alive)
            {
                string k = HistKey(p.DeduplicationKey);
                seenNow.Add(k);
                if (history.TryGetValue(k, out var h))
                {
                    h.Streak = Math.Min(h.Streak + 1, MaxStreak);
                    h.Misses = 0;                       // returning from probation resumes its streak
                }
                else
                {
                    h = history[k] = new NodeHistory { Streak = 1, Misses = 0 };
                }

                // v6.14: consecutive-runs-TLS-verified — verified 5 runs in a row is a
                // far stronger life signal than verified once. This stage runs AFTER
                // the TLS stage, so p.TlsVerified is current-run truth.
                // v6.16: decay, not reset — one missed verification (Azure blip, 4s
                // probe timeout) costs 1, not the whole streak. Same spirit as the
                // presence streak's one-run grace.
                h.TlsOk = p.TlsVerified ? Math.Min(h.TlsOk + 1, MaxStreak) : Math.Max(h.TlsOk - 1, 0);
                p.VerifiedStreak = h.TlsOk;
                h.XrayOk = p.XrayVerified ? Math.Min(h.XrayOk + 1, MaxStreak) : Math.Max(h.XrayOk - 1, 0);
                p.XrayStreak = h.XrayOk;   // v6.16: now scored

                p.Streak = h.Streak;
                p.IsStable = h.Streak >= StableMinRuns;
            }

            int pruned = 0;
            foreach (var k in history.Keys.ToList())
            {
                if (seenNow.Contains(k)) continue;
                var h = history[k];
                h.Misses++;
                if (h.Misses > GraceMisses) { history.Remove(k); pruned++; }
            }
            LogInfo($"History: {history.Count} tracked, {pruned} pruned, " +
                    $"{alive.Count(x => x.IsStable)} stable (≥{StableMinRuns} runs).");
        }

        private static void SaveHistory(Dictionary<string, NodeHistory> history)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(HistoryPath)!);
                File.WriteAllText(HistoryPath, JsonSerializer.Serialize(history));
            }
            catch (Exception ex) { LogWarning($"history.json save failed (non-fatal — stability resets next run): {ex.Message}"); }
        }

        // ====================== TLS VERIFICATION (v6.13) ======================
        // Affirmative-LIFE, promotion only — the mirror of the drop filters. A
        // completed handshake with the node's REAL SNI proves a live TLS endpoint
        // (for REALITY it's near-full validity: the handshake is designed to succeed
        // for any client). Catches what TCP-connect can't: ports that accept SYNs
        // but speak no TLS — recycled ports, HTTP stubs, SSH endpoints.
        //
        // Vantage honesty: FAILURE means nothing from Azure (node may geo-block
        // datacenter IPs while working fine from Iran) — so failure never drops and
        // never demotes. verified_tls.txt = "TLS-alive from a clean vantage" — a
        // strict subset of the truly alive, never a claim about the rest.

        private static readonly TimeSpan TlsBudget = TimeSpan.FromMinutes(8);
        private static readonly TimeSpan TlsProbeTimeout = TimeSpan.FromSeconds(4);

        private static bool IsTlsCandidate(ParsedProxy p)
        {
            if (UdpProtocols.Contains(p.Protocol)) return false;      // QUIC: no TLS-over-TCP to probe
            if (NormalizeProto(p.Protocol) == "trojan") return true;  // trojan is TLS by definition
            return p.Security.Equals("tls", StringComparison.OrdinalIgnoreCase)
                || p.Security.Equals("reality", StringComparison.OrdinalIgnoreCase)
                || !string.IsNullOrEmpty(p.Pbk);
        }

        private async Task TlsVerifyAsync(List<ParsedProxy> proxies,
            ConcurrentDictionary<string, string> countryCache)
        {
            var candidates = proxies
                .Where(p => int.TryParse(p.Port, out _) && IsTlsCandidate(p))
                .OrderBy(p => countryCache.TryGetValue(p.Host, out var cc) ? ProximityTier(cc) : 9)
                .ToList();
            if (candidates.Count == 0) { LogInfo("TLS verify: no candidates."); return; }

            // Endpoint dedup — handshake outcome belongs to (IP, port, SNI), not the
            // credential. Same pattern as the TCP filter.
            var endpoints = new List<(string Ip, int Port, string Sni, IPAddress Addr)>();
            var endpointIndex = new HashSet<(string, int, string)>();
            var nodeEndpoints = new List<(ParsedProxy Node, string Ip, int Port, string Sni)>();
            int cfSkippedTls = 0;
            foreach (var p in candidates)
            {
                var addresses = await Resolver.ResolveAllAsync(p.Host); // warm full A/AAAA cache
                if (addresses.Length == 0) continue;
                var ip = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork) ?? addresses[0];
                // CF-fronted hosts: a TLS handshake with ANY Cloudflare answer can succeed
                // at the edge without proving the proxy origin. Exclude the whole hostname
                // if any A/AAAA answer is in an official Cloudflare range.
                if (CfCidrs.Length > 0 && addresses.Any(IsCloudflareIp)) { cfSkippedTls++; continue; }
                int port = int.Parse(p.Port);
                string sni = string.IsNullOrEmpty(p.Sni) ? p.Host : p.Sni;
                string ipStr = ip.ToString();
                if (endpointIndex.Add((ipStr, port, sni)))
                    endpoints.Add((ipStr, port, sni, ip));
                nodeEndpoints.Add((p, ipStr, port, sni));
            }
            if (cfSkippedTls > 0)
                LogInfo($"TLS verify: skipped {cfSkippedTls} CF-fronted hosts — edge handshake is uninformative; Xray roundtrip is their only valid life signal.");

            int probed = 0;
            var verified = new ConcurrentDictionary<(string, int, string), byte>();
            var failStats = new ConcurrentDictionary<string, int>();
            var failSamples = new ConcurrentBag<string>();
            using var budgetCts = new CancellationTokenSource(TlsBudget);
            try
            {
                await Parallel.ForEachAsync(endpoints, new ParallelOptions
                {
                    MaxDegreeOfParallelism = 500,
                    CancellationToken = budgetCts.Token
                }, async (ep, ct) =>
                {
                    Interlocked.Increment(ref probed);
                    if (await TlsProbeAsync(ep.Addr, ep.Port, ep.Sni, ct, failStats, failSamples))
                        verified.TryAdd((ep.Ip, ep.Port, ep.Sni), 0);
                });
            }
            catch (OperationCanceledException)
            {
                LogWarning($"TLS verify: {TlsBudget.TotalMinutes:0}-minute budget exhausted — " +
                           $"{endpoints.Count - probed} endpoints left unverified (NOT dropped).");
            }

            foreach (var (node, ipStr, port, sni) in nodeEndpoints)
                if (verified.ContainsKey((ipStr, port, sni)))
                    node.TlsVerified = true;

            int verifiedNodes = nodeEndpoints.Count(ne => verified.ContainsKey((ne.Ip, ne.Port, ne.Sni)));
            LogInfo($"TLS verify: {verified.Count}/{endpoints.Count} endpoints completed a handshake → " +
                    $"{verifiedNodes} nodes promoted. Failures are not drops.");
            // v6.13.1: failure breakdown — makes the next log self-diagnosing.
            foreach (var kv in failStats.OrderByDescending(k => k.Value))
                LogWarning($"  TLS fail: {kv.Key} × {kv.Value}");
            foreach (var s in failSamples)
                LogWarning($"  TLS fail sample: {s}");
        }

        // v6.13.1: returns false on failure as before, but now CATEGORIZES every failure
        // and keeps sample messages — the bare catch{} deleted the evidence needed to
        // debug the 0/67,935 result. Cert callback now set ONLY in the auth options
        // (was duplicated in the SslStream ctor too — redundant, and a suspect).
        private static async Task<bool> TlsProbeAsync(IPAddress ip, int port, string sni, CancellationToken ct,
            ConcurrentDictionary<string, int> failStats, ConcurrentBag<string> failSamples)
        {
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TlsProbeTimeout);
                using var tcp = new TcpClient();
                await tcp.ConnectAsync(ip, port, cts.Token);
                using var ssl = new SslStream(tcp.GetStream(), false);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    // Reachability, not identity — free nodes present self-signed certs
                    // constantly. Any completed handshake is affirmative life.
                    TargetHost = string.IsNullOrEmpty(sni) ? ip.ToString() : sni,
                    RemoteCertificateValidationCallback = (_, _, _, _) => true
                }, cts.Token);
                return true;
            }
            catch (Exception ex)
            {
                string cat = ex switch
                {
                    OperationCanceledException => "probe-timeout(4s)",
                    SocketException se when se.SocketErrorCode == SocketError.ConnectionRefused => "connect-refused",
                    SocketException se when se.SocketErrorCode == SocketError.TimedOut => "connect-timeout",
                    SocketException se => $"connect-{se.SocketErrorCode}",
                    AuthenticationException => "handshake-rejected",
                    IOException => "io-after-connect",
                    _ => ex.GetType().Name
                };
                failStats.AddOrUpdate(cat, 1, (_, c) => c + 1);
                if (failSamples.Count < 10)
                    failSamples.Add($"[{cat}] {ex.GetType().Name}: {ex.Message}");
                return false;   // inconclusive from this vantage: keep, unverified
            }
        }

        // ====================== BUILD CLEAN LINK ======================
        private static string BuildCleanLink(ParsedProxy p, string remark)
        {
            string encoded = Uri.EscapeDataString(remark);
            try
            {
                if (NormalizeProto(p.Protocol) == "vmess")
                {
                    // Rewrite ONLY the "ps" field inside the ORIGINAL base64 JSON. The old
                    // code rebuilt the whole object from the parsed field set, silently
                    // dropping every field it didn't model (scy, fp, alpn, ...). Mutating
                    // the source's own JSON preserves every field the source had. Falls
                    // through to the plain #remark append if the blob somehow doesn't
                    // parse — keeping the original link intact beats dropping it.
                    string b64 = p.BaseLink["vmess://".Length..];
                    b64 = b64.Replace('-', '+').Replace('_', '/');   // tolerate URL-safe base64
                    int pad = b64.Length % 4; if (pad > 0) b64 += new string('=', 4 - pad);
                    var node = JsonNode.Parse(Encoding.UTF8.GetString(Convert.FromBase64String(b64)));
                    if (node != null)
                    {
                        node["ps"] = remark;
                        return "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(node.ToJsonString()));
                    }
                }

                if (NormalizeProto(p.Protocol) == "ssr")
                    return BuildSsrLink(p, remark);
            }
            catch { }
            return p.BaseLink.TrimEnd() + "#" + encoded;
        }

        // vmess share links are base64(JSON), NEVER "vmess://uuid@host:port?..." — but
        // that's exactly what the Clash/sing-box extractors used to emit, and
        // ParseProxyLine then failed to base64-decode it and silently dropped every one
        // of those nodes. This helper is now the single way any code path builds a vmess link.
        private static string BuildVmessLink(
            string host, string port, string uuid, string net,
            string tls, string sni, string path, string aid, string remark,
            string hostHeader = "", string fingerprint = "", string alpn = "",
            string cipher = "auto", string serviceName = "", int earlyData = 0,
            string earlyDataHeaderName = "", bool allowInsecure = false)
        {
            string actualNet = string.IsNullOrEmpty(net) ? "tcp" : net;
            string actualPath = actualNet.Equals("grpc", StringComparison.OrdinalIgnoreCase) &&
                                !string.IsNullOrEmpty(serviceName)
                ? serviceName : path ?? "";
            var obj = new Dictionary<string, object?>
            {
                ["v"] = "2", ["ps"] = remark, ["add"] = host, ["port"] = port, ["id"] = uuid,
                ["aid"] = string.IsNullOrEmpty(aid) ? "0" : aid,
                ["net"] = actualNet,
                ["type"] = "none",
                // "host" is the HTTP/WebSocket Host header. Keep SNI separate if available;
                // using SNI as host remains a backward-compatible fallback for old clients.
                ["host"] = string.IsNullOrEmpty(hostHeader) ? sni ?? "" : hostHeader,
                ["path"] = actualPath,
                ["tls"] = tls == "tls" ? "tls" : "",
                ["scy"] = string.IsNullOrWhiteSpace(cipher) ? "auto" : cipher
            };
            if (!string.IsNullOrEmpty(sni)) obj["sni"] = sni;
            if (!string.IsNullOrEmpty(fingerprint)) obj["fp"] = fingerprint;
            if (!string.IsNullOrEmpty(alpn)) obj["alpn"] = alpn;
            if (earlyData > 0) obj["ed"] = earlyData;
            if (!string.IsNullOrEmpty(earlyDataHeaderName)) obj["eh"] = earlyDataHeaderName;
            if (allowInsecure) obj["allowInsecure"] = true;
            return "vmess://" + Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(obj)));
        }

        // SSR's display name lives inside the base64 blob's "remarks=" field, same as
        // vmess's "ps" field — a trailing #remark on the outside is ignored by SSR
        // clients, so this reconstructs the whole blob with the new remark baked in.
        private static string BuildSsrLink(ParsedProxy p, string remark)
        {
            var credParts = (p.Credential ?? "").Split(':', 2);
            string method = credParts.Length > 0 ? credParts[0] : "";
            string password = credParts.Length > 1 ? credParts[1] : "";

            // p.Path carries obfsparam/protoparam EXACTLY as they appeared in the
            // source link — which for SSR means they are ALREADY URL-safe base64
            // (ParseQuery only percent-unescapes, a no-op on base64url). Encoding
            // them again would double-encode and corrupt the node: the client would
            // decode the literal string "YWJj" instead of "abc". Only the remark —
            // our own plain text — gets an encode.
            var pathParts = (p.Path ?? "").Split('|', 2);
            string obfsparam = pathParts.Length > 0 ? pathParts[0] : "";
            string protoparam = pathParts.Length > 1 ? pathParts[1] : "";

            string passwordB64 = Base64UrlEncode(password);
            string main = $"{p.Host}:{p.Port}:{p.Network}:{method}:{p.Security}:{passwordB64}";
            string query = $"obfsparam={obfsparam}&protoparam={protoparam}&remarks={Base64UrlEncode(remark)}";
            return "ssr://" + Base64UrlEncode($"{main}/?{query}");
        }

        private static string Base64UrlEncode(string s) =>
            Convert.ToBase64String(Encoding.UTF8.GetBytes(s)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
			
        // Extract only the `url` fields under root proxy-providers. Full Mihomo
        // profiles also contain hundreds of rule-provider URLs; those are NOT proxy
        // subscriptions and must never be recursively fetched as if they were nodes.
        private static List<string> ExtractClashProviderUrls(string text)
        {
            var urls = new List<string>();
            try
            {
                var deserializer = new DeserializerBuilder().Build();
                using var reader = new StringReader(text);
                if (deserializer.Deserialize<Dictionary<object, object>>(reader) is not { } root ||
                    !root.TryGetValue("proxy-providers", out var rawProviders) ||
                    rawProviders is not Dictionary<object, object> providers) return urls;

                foreach (var provider in providers.Values.OfType<Dictionary<object, object>>())
                {
                    if (!provider.TryGetValue("url", out var rawUrl)) continue;
                    string candidate = rawUrl?.ToString()?.Trim() ?? "";
                    if (Uri.TryCreate(candidate, UriKind.Absolute, out var uri) &&
                        (uri.Scheme == Uri.UriSchemeHttps || uri.Scheme == Uri.UriSchemeHttp))
                        urls.Add(uri.AbsoluteUri);
                }
            }
            catch { }
            return urls.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        // For common subscription-converter wrappers, recover the original source URL
        // from `?url=https%3A...` or from the first bare query token (`?https://...&target=clash`).
        // This bypasses a flaky converter when the underlying payload is already a format
        // the collector can decode, while retaining the wrapper as a fallback candidate.
        private static List<string> GetProviderFetchCandidates(string providerUrl)
        {
            var candidates = new List<string>();
            if (Uri.TryCreate(providerUrl, UriKind.Absolute, out var uri))
            {
                string query = uri.Query.TrimStart('?');
                foreach (var part in query.Split('&', StringSplitOptions.RemoveEmptyEntries))
                {
                    string candidate = part;
                    int equals = part.IndexOf('=');
                    if (equals >= 0 && part[..equals].Equals("url", StringComparison.OrdinalIgnoreCase))
                        candidate = part[(equals + 1)..];
                    else if (equals >= 0)
                        continue;
                    candidate = Uri.UnescapeDataString(candidate.Trim());
                    if (Uri.TryCreate(candidate, UriKind.Absolute, out var sourceUri) &&
                        (sourceUri.Scheme == Uri.UriSchemeHttps || sourceUri.Scheme == Uri.UriSchemeHttp) &&
                        !sourceUri.Host.Equals(uri.Host, StringComparison.OrdinalIgnoreCase))
                        candidates.Add(sourceUri.AbsoluteUri);
                }
            }
            candidates.Add(providerUrl);
            return candidates.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        // ====================== SOURCE DECODING ======================
        internal static List<string> DecodeAndExtractLines(string text, string url)
        {
            var results = new List<string>();
            bool isYaml = url.EndsWith(".yaml") || url.EndsWith(".yml");
            bool isJson = url.EndsWith(".json");
            bool isHtml = url.EndsWith(".html") || url.EndsWith(".htm")
                       || url.Contains("t.me/s/", StringComparison.OrdinalIgnoreCase);
                       
            // Base64 peel FIRST, before any format dispatch. A source serving
            // base64-of-a-Clash-YAML or base64-of-sing-box-JSON has no "://",
            // "proxies:", or "outbounds" in its raw form, so every branch below used
            // to miss it entirely — 0 nodes from that source, silently. Peeling first
            // (and recursing) fixes that, and also handles double-encoded subs.
            // URL-safe base64 is normalized too — Convert.FromBase64String rejects
            // '-' and '_'.
            if (!text.Contains("://") && !text.Contains("proxies:") && !text.Contains("\"outbounds\""))
            {
                try
                {
                    string trim = text.Trim().Replace('-', '+').Replace('_', '/');
                    int pad = trim.Length % 4; if (pad > 0) trim += new string('=', 4 - pad);
                    var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(trim));
                    if (decoded.Contains("://") || decoded.Contains("proxies:") || decoded.Contains("\"outbounds\""))
                        return DecodeAndExtractLines(decoded, url);
                }
                catch { }
            }

            if (isHtml)
            {
                // HTML sources carry "&" in query strings HTML-escaped as "&amp;" —
                // extracted raw, a REALITY link would end up with key "amp;pbk" and be
                // broken downstream. Unescape after extraction. The char class still
                // doesn't stop at '&' — real links legitimately contain it.
                foreach (Match m in SchemeHtmlRegex.Matches(text))
                    results.Add(CleanExtracted(m.Value.Replace("&amp;", "&")));
                return results;
            }

            // sing-box config JSON ({"outbounds": [{"type":"vless","server":...}, ...]}) has
            // no literal "scheme://" text anywhere in it — it's structured JSON, so the plain
            // line scan below would silently find nothing at all. Parse it for real.
            if (isJson || (text.TrimStart().StartsWith("{") && text.Contains("\"outbounds\"")))
            {
                var fromJson = ExtractFromSingboxJson(text);
                if (fromJson.Count > 0) return fromJson;
                if (isJson) return results; // was declared JSON but didn't parse — don't fall through to line scanning garbage
            }

            if (isYaml || text.Contains("proxies:"))
            {
                // Structured Clash proxy entries (flow-style: "- {name: x, type: vless, ...}")
                // also have no literal "scheme://" text — only the (less common) case of a
                // literal URI embedded as a string value gets caught by the line scan below.
                // Try structured extraction first; the line scan still runs afterward to catch
                // any embedded literal links a structured parse would miss.
                results.AddRange(ExtractFromClashYaml(text));       // block-style (common)
                results.AddRange(ExtractFromClashFlowYaml(text));   // flow-style (rare)

                foreach (var line in text.Split('\n', '\r'))
                {
                    var t = line.Trim();
                    if (t.StartsWith("#")) continue;
                    // YAML often contains ordinary https:// provider URLs. They are not
                    // proxy nodes and were incorrectly reported as FORMAT GAP entries.
                    var m = SchemeLineRegex.Match(t);
                    if (m.Success) results.Add(CleanExtracted(m.Value));
                }
                // Both YAML extractors may recognize a flow-style node. Preserve each
                // unique generated link only once before source-level scoring/deduplication.
                return results.Distinct(StringComparer.Ordinal).ToList();
            }

            foreach (var rawLine in text.Split('\n', '\r'))
            {
                var t = rawLine.Trim();
                if (string.IsNullOrEmpty(t) || t.StartsWith("#")) continue;

                if (t.Contains("://"))
                {
                    var m = SchemeLineRegex.Match(t);
                    // The old "else results.Add(t)" fed whitelist-rejected lines into
                    // ParseProxyLine — which applies the SAME whitelist, so they could
                    // never parse. Dead code; removed.
                    if (m.Success) results.Add(CleanExtracted(m.Value));
                }
                else if (t.Length > 20)
                {
                    // Per-line base64 blobs — URL-safe variant tolerated here too.
                    try
                    {
                        string padded = t.Replace('-', '+').Replace('_', '/');
                        int pad = padded.Length % 4;
                        if (pad > 0) padded += new string('=', 4 - pad);
                        var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(padded));
                        if (decoded.Contains("://"))
                            foreach (var dl in decoded.Split('\n', '\r'))
                            {
                                var dm = SchemeLineRegex.Match(dl.Trim());
                                if (dm.Success) results.Add(CleanExtracted(dm.Value));
                            }
                    }
                    catch { }
                }
            }

            return results;
        }

        // Parses sing-box's outbound JSON array via real JSON parsing (System.Text.Json) —
        // much more reliable than hand-rolled text scanning since the format is genuinely
        // structured. Reconstructs a normal scheme:// link per outbound so it flows through
        // the same downstream parser as everything else. Best-effort: an outbound type or
        // shape it doesn't recognize is just skipped, not an error for the whole file.
        private static List<string> ExtractFromSingboxJson(string text)
        {
            var results = new List<string>();
            try
            {
                using var doc = JsonDocument.Parse(text);
                if (!doc.RootElement.TryGetProperty("outbounds", out var outbounds) ||
                    outbounds.ValueKind != JsonValueKind.Array) return results;

                foreach (var ob in outbounds.EnumerateArray())
                {
                    try
                    {
                        if (!ob.TryGetProperty("type", out var typeEl)) continue;
                        string type = typeEl.GetString()?.ToLowerInvariant() ?? "";
                        if (!ob.TryGetProperty("server", out var serverEl)) continue;
                        string server = serverEl.GetString() ?? "";
                        int port = ob.TryGetProperty("server_port", out var portEl) &&
                                   portEl.ValueKind == JsonValueKind.Number
                            ? portEl.GetInt32() : 0;
                        if (string.IsNullOrEmpty(server) || port is < 1 or > 65535) continue;
                        string uriServer = FormatUriHost(server);

                        string uuid = ob.TryGetProperty("uuid", out var u) ? u.GetString() ?? "" : "";
                        string password = ob.TryGetProperty("password", out var pw) ? pw.GetString() ?? "" : "";
                        if (type == "hysteria" && string.IsNullOrEmpty(password))
                            password = GetJsonString(ob, "auth");
                        string name = ob.TryGetProperty("tag", out var tag) ? tag.GetString() ?? "" : "";
                        string remark = Uri.EscapeDataString(name);

                        string sni = "";
                        bool tls = false;
                        bool allowInsecure = false;
                        string alpn = "", fingerprint = "";
                        string realityPbk = "", realitySid = "";
                        if (ob.TryGetProperty("tls", out var tlsEl) && tlsEl.ValueKind == JsonValueKind.Object)
                        {
                            if (tlsEl.TryGetProperty("enabled", out var en) && en.ValueKind == JsonValueKind.True) tls = true;
                            if (tlsEl.TryGetProperty("server_name", out var sn)) sni = sn.GetString() ?? "";
                            if (tlsEl.TryGetProperty("insecure", out var insecure) && insecure.ValueKind == JsonValueKind.True)
                                allowInsecure = true;
                            if (tlsEl.TryGetProperty("alpn", out var alpnEl))
                            {
                                if (alpnEl.ValueKind == JsonValueKind.Array)
                                    alpn = string.Join(",", alpnEl.EnumerateArray()
                                        .Where(v => v.ValueKind == JsonValueKind.String)
                                        .Select(v => v.GetString() ?? ""));
                                else if (alpnEl.ValueKind == JsonValueKind.String)
                                    alpn = alpnEl.GetString() ?? "";
                            }
                            if (tlsEl.TryGetProperty("utls", out var utls) && utls.ValueKind == JsonValueKind.Object &&
                                utls.TryGetProperty("fingerprint", out var fpEl))
                                fingerprint = fpEl.GetString() ?? "";
                            // sing-box nests REALITY under tls.reality.
                            if (tlsEl.TryGetProperty("reality", out var re) && re.ValueKind == JsonValueKind.Object)
                            {
                                realityPbk = re.TryGetProperty("public_key", out var pk) ? pk.GetString() ?? "" : "";
                                realitySid = re.TryGetProperty("short_id", out var si) ? si.GetString() ?? "" : "";
                            }
                        }

                        string flow = ob.TryGetProperty("flow", out var fl) ? fl.GetString() ?? "" : "";
                        string transport = "tcp", path = "", hostHeader = "", serviceName = "", earlyDataHeaderName = "";
                        string obfsType = "", obfsPassword = "", upMpbs = "", downMpbs = "";
                        bool zeroRttHandshake = false;
                        int earlyData = 0;

                        string Query(params (string Key, string Value)[] options) =>
                            string.Join("&", options.Where(x => !string.IsNullOrEmpty(x.Value))
                                .Select(x => x.Key + "=" + Uri.EscapeDataString(x.Value)));
                        string OptionalQuery(params (string Key, string Value)[] options)
                        {
                            string query = Query(options);
                            return query.Length == 0 ? "" : "?" + query;
                        }

                        if (ob.TryGetProperty("obfs", out var obfsEl))
                        {
                            if (obfsEl.ValueKind == JsonValueKind.Object)
                            {
                                if (obfsEl.TryGetProperty("type", out var obfsTypeEl)) obfsType = obfsTypeEl.GetString() ?? "";
                                if (obfsEl.TryGetProperty("password", out var obfsPasswordEl)) obfsPassword = obfsPasswordEl.GetString() ?? "";
                            }
                            else if (obfsEl.ValueKind == JsonValueKind.String)
                            {
                                obfsType = obfsEl.GetString() ?? "";
                            }
                        }
                        if (ob.TryGetProperty("up_mbps", out var upEl)) upMpbs = upEl.ToString();
                        if (ob.TryGetProperty("down_mbps", out var downEl)) downMpbs = downEl.ToString();
                        if (ob.TryGetProperty("zero_rtt_handshake", out var zrt) && zrt.ValueKind == JsonValueKind.True)
                            zeroRttHandshake = true;
                        if (ob.TryGetProperty("transport", out var tEl) && tEl.ValueKind == JsonValueKind.Object)
                        {
                            if (tEl.TryGetProperty("type", out var ttEl)) transport = ttEl.GetString() ?? "tcp";
                            if (tEl.TryGetProperty("path", out var pEl)) path = pEl.GetString() ?? "";
                            if (tEl.TryGetProperty("service_name", out var serviceEl)) serviceName = serviceEl.GetString() ?? "";
                            if (tEl.TryGetProperty("max_early_data", out var edEl) && edEl.TryGetInt32(out int ed) && ed > 0)
                                earlyData = ed;
                            if (tEl.TryGetProperty("early_data_header_name", out var ehEl))
                                earlyDataHeaderName = ehEl.GetString() ?? "";
                            if (tEl.TryGetProperty("headers", out var headers) && headers.ValueKind == JsonValueKind.Object)
                                foreach (var header in headers.EnumerateObject())
                                    if (header.Name.Equals("Host", StringComparison.OrdinalIgnoreCase) &&
                                        header.Value.ValueKind == JsonValueKind.String)
                                    {
                                        hostHeader = header.Value.GetString() ?? "";
                                        break;
                                    }
                        }

                        string vmessCipher = ob.TryGetProperty("security", out var cipherEl) &&
                                             cipherEl.ValueKind == JsonValueKind.String
                            ? cipherEl.GetString() ?? "auto" : "auto";
                        string alterId = ob.TryGetProperty("alter_id", out var alterEl) &&
                                         alterEl.ValueKind == JsonValueKind.Number
                            ? alterEl.GetInt32().ToString() : "0";

                        string? link = type switch
                        {
                            "vmess" when !string.IsNullOrEmpty(uuid) =>
                                BuildVmessLink(server, port.ToString(), uuid, transport,
                                    tls ? "tls" : "", sni, path, alterId, name,
                                    hostHeader, fingerprint, alpn, vmessCipher,
                                    serviceName, earlyData, earlyDataHeaderName, allowInsecure),
                            "vless" when !string.IsNullOrEmpty(uuid) =>
                                $"vless://{Uri.EscapeDataString(uuid)}@{uriServer}:{port}?{Query(("security", realityPbk.Length > 0 ? "reality" : tls ? "tls" : "none"), ("type", transport), ("sni", sni), ("path", path), ("host", hostHeader), ("flow", flow), ("fp", fingerprint), ("alpn", alpn), ("pbk", realityPbk), ("sid", realitySid), ("serviceName", serviceName), ("allowInsecure", allowInsecure ? "1" : ""))}#{remark}",
                            "trojan" when !string.IsNullOrEmpty(password) =>
                                $"trojan://{Uri.EscapeDataString(password)}@{uriServer}:{port}?{Query(("security", realityPbk.Length > 0 ? "reality" : tls ? "tls" : "none"), ("sni", sni), ("type", transport), ("path", path), ("host", hostHeader), ("fp", fingerprint), ("alpn", alpn), ("pbk", realityPbk), ("sid", realitySid), ("serviceName", serviceName), ("allowInsecure", allowInsecure ? "1" : ""))}#{remark}",
                            "hysteria2" or "hy2" when !string.IsNullOrEmpty(password) =>
                                $"hysteria2://{Uri.EscapeDataString(password)}@{uriServer}:{port}{OptionalQuery(("sni", sni), ("obfs", obfsType), ("obfs-password", obfsPassword), ("alpn", alpn), ("fp", fingerprint), ("upmbps", upMpbs), ("downmbps", downMpbs), ("insecure", allowInsecure ? "1" : ""))}#{remark}",
                            "hysteria" when !string.IsNullOrEmpty(password) =>
                                $"hysteria://{Uri.EscapeDataString(password)}@{uriServer}:{port}{OptionalQuery(("peer", sni), ("sni", sni), ("alpn", alpn), ("obfs", obfsType), ("obfs-password", obfsPassword), ("upmbps", upMpbs), ("downmbps", downMpbs), ("insecure", allowInsecure ? "1" : ""))}#{remark}",
                            "tuic" when !string.IsNullOrEmpty(uuid) && !string.IsNullOrEmpty(password) =>
                                $"tuic://{Uri.EscapeDataString(uuid)}:{Uri.EscapeDataString(password)}@{uriServer}:{port}{OptionalQuery(("congestion_control", GetJsonString(ob, "congestion_control", "bbr")), ("udp_relay_mode", GetJsonString(ob, "udp_relay_mode", "native")), ("alpn", alpn), ("sni", sni), ("allowInsecure", allowInsecure ? "1" : ""), ("zero_rtt_handshake", zeroRttHandshake ? "1" : ""))}#{remark}",
                            "shadowsocks" => BuildSsLinkFromJson(ob, uriServer, port, remark),
                            "socks" => BuildSocksLinkFromJson(ob, uriServer, port, remark),
                            _ => null
                        };
                        if (link != null) results.Add(link);
                    }
                    catch { } // one malformed outbound entry shouldn't sink the rest of the file
                }
            }
            catch { }
            return results;
        }

        private static string GetJsonString(JsonElement element, string property, string fallback = "")
        {
            if (!element.TryGetProperty(property, out var value)) return fallback;
            return value.ValueKind switch
            {
                JsonValueKind.String => value.GetString() ?? fallback,
                JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False => value.ToString(),
                _ => fallback
            };
        }

        // sing-box represents SOCKS outbounds as structured fields rather than a URI.
        // Convert them to the collector's accepted socks5:// form, preserving optional
        // authentication and the outbound tag. A credential-less SOCKS proxy is valid.
        private static string? BuildSocksLinkFromJson(JsonElement ob, string server, int port, string remark)
        {
            // sing-box defaults SOCKS to version 5, but version 4 is also supported.
            // Preserve that distinction; a SOCKS4 URI must not silently become SOCKS5.
            string version = GetJsonString(ob, "version", "5").Trim();
            string scheme = version switch { "4" => "socks4", "5" => "socks5", _ => "" };
            if (scheme.Length == 0) return null;

            string username = GetJsonString(ob, "username");
            string password = GetJsonString(ob, "password");
            string auth;
            if (scheme == "socks4")
            {
                // SOCKS4 supports a user ID, not a password. Do not emit a broken or
                // semantically altered link if the source supplies an unsupported password.
                if (password.Length > 0) return null;
                auth = username.Length == 0 ? "" : Uri.EscapeDataString(username) + "@";
            }
            else
            {
                // SOCKS5 username/password authentication requires the pair.
                if ((username.Length == 0) != (password.Length == 0)) return null;
                auth = username.Length == 0
                    ? ""
                    : Uri.EscapeDataString(username) + ":" + Uri.EscapeDataString(password) + "@";
            }

            return $"{scheme}://{auth}{server}:{port}#{remark}";
        }

        // SIP002 plugin options must be preserved. Omitting them produces a syntactically
        // valid but unusable link whenever the source Shadowsocks outbound requires a plugin.
        private static string? BuildSsLinkFromJson(JsonElement ob, string server, int port, string remark)
        {
            string method = ob.TryGetProperty("method", out var m) ? m.GetString() ?? "" : "";
            string password = ob.TryGetProperty("password", out var p) ? p.GetString() ?? "" : "";
            if (string.IsNullOrEmpty(method) || string.IsNullOrEmpty(password)) return null;

            string userinfo = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{method}:{password}"));
            string plugin = ob.TryGetProperty("plugin", out var pluginEl) &&
                            pluginEl.ValueKind == JsonValueKind.String ? pluginEl.GetString() ?? "" : "";
            string pluginOptions = ob.TryGetProperty("plugin_opts", out var optionsEl) &&
                                   optionsEl.ValueKind == JsonValueKind.String ? optionsEl.GetString() ?? "" : "";
            string pluginQuery = "";
            if (!string.IsNullOrWhiteSpace(plugin))
            {
                string pluginValue = plugin.Trim();
                if (!string.IsNullOrWhiteSpace(pluginOptions))
                    pluginValue += ";" + pluginOptions.Trim().TrimStart(';');
                pluginQuery = "?plugin=" + Uri.EscapeDataString(pluginValue);
            }
            return $"ss://{userinfo}@{server}:{port}{pluginQuery}#{remark}";
        }

        // Parses flow-style Clash proxy entries: "- {name: x, type: vless, server: 1.2.3.4,
        // port: 443, uuid: ..., ...}" — this is the common machine-generated Clash YAML shape
        // used by most of the aggregator repos in the source list. Deliberately does NOT
        // attempt full block-style (multi-line, nested "ws-opts:"/"reality-opts:" sub-maps)
        // parsing — that needs a real YAML parser to do correctly, and a hand-rolled nested
        // parser risks silently mis-parsing rather than just missing a source, which is worse.
        // Block-style YAML still gets whatever the plain line scan can find (rare, but some
        // files embed a literal link as a comment/string).
        private static List<string> ExtractFromClashFlowYaml(string text)
        {
            var results = new List<string>();
            foreach (Match m in Regex.Matches(text, @"-\s*\{([^{}]+)\}"))
            {
                try
                {
                    var fields = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    foreach (Match kv in Regex.Matches(m.Groups[1].Value, @"([\w-]+)\s*:\s*(?:""([^""]*)""|'([^']*)'|([^,}]+))"))
                    {
                        string key = kv.Groups[1].Value.Trim();
                        string val = (kv.Groups[2].Success ? kv.Groups[2].Value
                                    : kv.Groups[3].Success ? kv.Groups[3].Value
                                    : kv.Groups[4].Value).Trim();
                        fields[key] = val;
                    }

                    // Reuse the complete converter for flow-style YAML as well; normalize
                    // its legacy flat aliases so VMess and Shadowsocks don't lose options.
                    if (fields.TryGetValue("ws-path", out var legacyWsPath) &&
                        !fields.ContainsKey("ws-opts.path"))
                        fields["ws-opts.path"] = legacyWsPath;
                    if (fields.TryGetValue("ws-host", out var legacyWsHost) &&
                        !fields.ContainsKey("ws-opts.headers.Host"))
                        fields["ws-opts.headers.Host"] = legacyWsHost;
                    var link = ClashFieldsToLinkV2(fields);
                    if (link != null) results.Add(link);
                }
                catch { }
            }
            return results;
        }

        // Strips trailing JSON/YAML/markdown punctuation the \S+ regexes swallow along
        // with the link ("vmess://eyJ...", or (vless://...)). A trailing quote or comma
        // breaks base64 decoding downstream and the node is silently dropped. None of
        // these characters can legitimately end a proxy link (base64, UUIDs, hostnames
        // and query strings don't contain them).
        private static string CleanExtracted(string s) =>
            s.Trim().TrimEnd('"', '\'', '`', ',', ';', ')', ']', '}', '>', '.');

        // Block-style Clash YAML — the shape the overwhelming majority of Clash configs
        // actually use ("proxies:\n  - name: x\n    type: vless\n    server: ...\n
        // reality-opts:\n      public-key: ..."). Parsed with a real YAML parser rather
        // than hand-rolled scanning: nested option maps are flattened to dotted keys
        // ("ws-opts.path") and mapped to share-link query params. Malformed YAML just
        // returns whatever parsed before the error — the line scan in the caller still
        // runs as a catch-all.
        private static List<string> ExtractFromClashYaml(string text)
        {
            var results = new List<string>();
            try
            {
                var deserializer = new DeserializerBuilder().Build();
                using var reader = new StringReader(text);
                if (deserializer.Deserialize<Dictionary<object, object>>(reader) is not { } root) return results;
                if (root.GetValueOrDefault("proxies") is not List<object> proxies) return results;

                foreach (var entry in proxies.OfType<Dictionary<object, object>>())
                {
                    var f = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    FlattenClashEntry(entry, "", f);
                    var link = ClashFieldsToLinkV2(f);
                    if (link != null) results.Add(link);
                }
            }
            catch { }
            return results;
        }

        private static void FlattenClashEntry(Dictionary<object, object> src, string prefix, Dictionary<string, string> dst)
        {
            foreach (var kv in src)
            {
                string key = prefix + kv.Key;
                switch (kv.Value)
                {
                    case Dictionary<object, object> nested:
                        FlattenClashEntry(nested, key + ".", dst);
                        break;
                    case List<object> list:
                        dst[key] = string.Join(",", list);
                        break;
                    default:
                        dst[key] = kv.Value?.ToString() ?? "";
                        break;
                }
            }
        }

        // Maps flattened block-style Clash fields to a share link. Covers the fields
        // that actually differentiate connections: REALITY (pbk/sid), flow
        // (xtls-rprx-vision), ws path + Host header, grpc service name, hy2 obfs.
        // Field names per the Clash.Meta/mihomo spec; unrecognized types return null.
        private static string FormatUriHost(string host)
        {
            host = host.Trim();
            if (host.StartsWith("[") && host.EndsWith("]")) return host;
            if (IPAddress.TryParse(host, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6)
                return $"[{host}]";
            return host;
        }

        private static string? ClashFieldsToLinkV2(Dictionary<string, string> f)
        {
            if (!f.TryGetValue("type", out var type)) return null;
            if (!f.TryGetValue("server", out var server) || !f.TryGetValue("port", out var port)) return null;
            type = type.ToLowerInvariant();
            if (string.IsNullOrEmpty(server) || string.IsNullOrEmpty(port)) return null;
            string uriServer = FormatUriHost(server);

            string remark = Uri.EscapeDataString(f.GetValueOrDefault("name", ""));
            bool tls = f.GetValueOrDefault("tls", "").Equals("true", StringComparison.OrdinalIgnoreCase);
            string sni     = f.GetValueOrDefault("servername", f.GetValueOrDefault("sni", ""));
            string network = f.GetValueOrDefault("network", "tcp");
            string path    = f.GetValueOrDefault("ws-opts.path",
                f.GetValueOrDefault("h2-opts.path", f.GetValueOrDefault("ws-path", f.GetValueOrDefault("path", ""))));
            string hostHdr = f.GetValueOrDefault("ws-opts.headers.Host",
                f.GetValueOrDefault("ws-host", f.GetValueOrDefault("host", "")));
            string flow    = f.GetValueOrDefault("flow", "");
            string fp      = f.GetValueOrDefault("client-fingerprint", "");
            string pbk     = f.GetValueOrDefault("reality-opts.public-key", "");
            string sid     = f.GetValueOrDefault("reality-opts.short-id", "");
            string grpc    = f.GetValueOrDefault("grpc-opts.grpc-service-name", "");
            string alpn    = f.GetValueOrDefault("alpn", "");
            bool allowInsecure = f.GetValueOrDefault("skip-cert-verify", "false")
                .Equals("true", StringComparison.OrdinalIgnoreCase);
            int.TryParse(f.GetValueOrDefault("ws-opts.max-early-data", "0"), out int earlyData);
            string earlyDataHeaderName = f.GetValueOrDefault("ws-opts.early-data-header-name", "");
            string cipher = f.GetValueOrDefault("cipher", "auto");

            var q = new List<string>();
            void Q(string k, string v) { if (!string.IsNullOrEmpty(v)) q.Add($"{k}={Uri.EscapeDataString(v)}"); }

            switch (type)
            {
                case "vless" when f.ContainsKey("uuid"):
                {
                    // REALITY detection: pbk present ⇒ security=reality (tls flag may be
                    // false in the source even for REALITY outbounds in mihomo configs).
                    q.Add($"security={(pbk.Length > 0 ? "reality" : tls ? "tls" : "none")}");
                    Q("type", network); Q("sni", sni); Q("path", path); Q("host", hostHdr);
                    Q("flow", flow); Q("fp", fp); Q("pbk", pbk); Q("sid", sid);
                    Q("serviceName", grpc); Q("alpn", alpn);
                    Q("allowInsecure", allowInsecure ? "1" : "");
                    return $"vless://{f["uuid"]}@{uriServer}:{port}?{string.Join("&", q)}#{remark}";
                }
                case "trojan" when f.ContainsKey("password"):
                {
                    q.Add($"security={(pbk.Length > 0 ? "reality" : tls ? "tls" : "none")}");
                    Q("type", network); Q("sni", sni); Q("flow", flow); Q("fp", fp);
                    Q("pbk", pbk); Q("sid", sid); Q("serviceName", grpc);
                    Q("allowInsecure", allowInsecure ? "1" : "");
                    return $"trojan://{Uri.EscapeDataString(f["password"])}@{uriServer}:{port}?{string.Join("&", q)}#{remark}";
                }
                case "hysteria2" or "hy2" when f.ContainsKey("password"):
                {
                    Q("sni", sni); Q("obfs", f.GetValueOrDefault("obfs", ""));
                    Q("obfs-password", f.GetValueOrDefault("obfs-password", ""));
                    Q("alpn", alpn); Q("fp", fp);
                    Q("insecure", allowInsecure ? "1" : "");
                    Q("upmbps", f.GetValueOrDefault("up", f.GetValueOrDefault("upmbps", "")));
                    Q("downmbps", f.GetValueOrDefault("down", f.GetValueOrDefault("downmbps", "")));
                    return $"hysteria2://{Uri.EscapeDataString(f["password"])}@{uriServer}:{port}?{string.Join("&", q)}#{remark}";
                }
                case "vmess" when f.ContainsKey("uuid"):
                    return BuildVmessLink(server, port, f["uuid"], network, tls ? "tls" : "",
                        sni, path, f.GetValueOrDefault("alterId", f.GetValueOrDefault("aid", "0")),
                        f.GetValueOrDefault("name", ""), hostHdr, fp, alpn, cipher,
                        grpc, earlyData, earlyDataHeaderName,
                        f.GetValueOrDefault("skip-cert-verify", "").Equals("true", StringComparison.OrdinalIgnoreCase));
                case "tuic" when f.ContainsKey("uuid") && f.ContainsKey("password"):
                {
                    Q("congestion_control", f.GetValueOrDefault("congestion-controller", f.GetValueOrDefault("congestion_control", "bbr")));
                    Q("udp_relay_mode", f.GetValueOrDefault("udp-relay-mode", f.GetValueOrDefault("udp_relay_mode", "native")));
                    Q("alpn", alpn); Q("sni", sni);
                    Q("allowInsecure", allowInsecure ? "1" : "");
                    return $"tuic://{Uri.EscapeDataString(f["uuid"])}:{Uri.EscapeDataString(f["password"])}@{uriServer}:{port}?{string.Join("&", q)}#{remark}";
                }
                case "hysteria" when f.ContainsKey("password") || f.ContainsKey("auth"):
                {
                    string auth = f.GetValueOrDefault("password", f.GetValueOrDefault("auth", ""));
                    Q("peer", sni); Q("sni", sni); Q("alpn", alpn);
                    Q("insecure", allowInsecure ? "1" : "");
                    Q("obfs", f.GetValueOrDefault("obfs", ""));
                    Q("upmbps", f.GetValueOrDefault("up", f.GetValueOrDefault("upmbps", "")));
                    Q("downmbps", f.GetValueOrDefault("down", f.GetValueOrDefault("downmbps", "")));
                    return $"hysteria://{Uri.EscapeDataString(auth)}@{uriServer}:{port}?{string.Join("&", q)}#{remark}";
                }
                case "anytls" when f.ContainsKey("password"):
                {
                    q.Add($"security={(tls ? "tls" : "none")}"); Q("sni", sni); Q("fp", fp); Q("alpn", alpn);
                    Q("insecure", allowInsecure ? "1" : "");
                    return $"anytls://{Uri.EscapeDataString(f["password"])}@{uriServer}:{port}?{string.Join("&", q)}#{remark}";
                }
                case "socks5" or "socks" or "socks4":
                {
                    string user = f.GetValueOrDefault("username", "");
                    string pass = f.GetValueOrDefault("password", "");
                    string auth = user.Length > 0 ? Uri.EscapeDataString(user) + (pass.Length > 0 ? ":" + Uri.EscapeDataString(pass) : "") + "@" : "";
                    return $"{type}://{auth}{uriServer}:{port}#{remark}";
                }
                case "ss" or "shadowsocks" when f.ContainsKey("cipher") && f.ContainsKey("password"):
                {
                    // SIP002: standard base64 userinfo (NOT URL-safe — the parser
                    // couldn't decode URL-safe base64 for nearly all payloads).
                    return BuildSsLinkFromClashFields(f["cipher"], f["password"], uriServer, port, remark,
                        BuildClashShadowsocksPlugin(f));
                }
                default:
                    return null;
            }
        }

        private static string BuildSsLinkFromClashFields(
            string cipher, string password, string server, string port, string remark, string pluginValue = "")
        {
            string userinfo = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{cipher}:{password}"));
            string pluginQuery = string.IsNullOrWhiteSpace(pluginValue)
                ? "" : "?plugin=" + Uri.EscapeDataString(pluginValue);
            return $"ss://{userinfo}@{server}:{port}{pluginQuery}#{remark}";
        }

        private static string BuildClashShadowsocksPlugin(Dictionary<string, string> fields)
        {
            string plugin = fields.GetValueOrDefault("plugin", "");
            if (string.IsNullOrWhiteSpace(plugin)) return "";
            string options = fields.GetValueOrDefault("plugin-opts", fields.GetValueOrDefault("plugin_opts", ""));
            if (string.IsNullOrWhiteSpace(options))
            {
                var optionPairs = fields
                    .Where(kv => kv.Key.StartsWith("plugin-opts.", StringComparison.OrdinalIgnoreCase))
                    .OrderBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
                    .Select(kv => kv.Key[(kv.Key.IndexOf('.') + 1)..] + "=" + kv.Value)
                    .ToArray();
                options = string.Join(";", optionPairs);
            }
            return string.IsNullOrWhiteSpace(options)
                ? plugin.Trim()
                : plugin.Trim() + ";" + options.Trim().TrimStart(';');
        }

        // ====================== SAVE OUTPUTS ======================
        // everything.txt is always a single, full, uncapped file — never chunked.
        // Every other category's <name>.txt holds the first ChunkSize lines (this
        // filename never changes), overflow beyond that goes to <name>_part2.txt,
        // _part3.txt, ...
        private const int ChunkSize = 1000;


    }

    // ====================== DATA MODELS ======================
    public class ParsedProxy
    {
        public string Protocol    { get; set; } = "";
        public string Host        { get; set; } = "";
        public string Port        { get; set; } = "";
        public string Credential  { get; set; } = "";
        public string Network     { get; set; } = "tcp";
        public string Security    { get; set; } = "";
        public string Sni         { get; set; } = "";
        public string Path        { get; set; } = "";
        public string Pbk         { get; set; } = ""; // REALITY public key
        public string Sid         { get; set; } = ""; // REALITY short id
        public string Flow        { get; set; } = ""; // xtls-rprx-vision etc. — changes the handshake
        public string ObfsPassword{ get; set; } = ""; // hysteria2 obfs (salamander) password
        public int    Aid         { get; set; } = 0;

        // v6.13 quality signals (set during the pipeline, consumed by ranking/output)
        public bool   IranTested  { get; set; }  // source explicitly tests nodes (Iran-side validation)
        public int    Streak      { get; set; } = 1;  // consecutive runs present (state/history.json)
        public bool   IsStable    { get; set; }  // streak >= StableMinRuns
        public bool   TlsVerified { get; set; }  // completed TLS handshake w/ real SNI (clean vantage)
        public int    SourceCount    { get; set; } = 1;  // distinct sources publishing this node
        public int    VerifiedStreak { get; set; }       // consecutive runs TLS-verified (history.json)
        public int    XrayStreak     { get; set; }       // consecutive runs roundtrip-verified (history.json)
        public bool   XrayVerified   { get; set; }       // full proxy roundtrip completed (this run)
        public bool   EdgeVerified   { get; set; }       // TLS verified from the CF edge vantage (this run)
        public string BaseLink    { get; set; } = "";

        // Canonical signature of connection-affecting options not represented by the
        // normalized fields above (for example VMess scy/fp/alpn and SS plugin options).
        // Omitting these lets different functional links collapse as identical nodes.
        public string ConnectionOptionsKey { get; set; } = "";

        public string DeduplicationKey
        {
            get
            {
                string hostKey = Host.Trim().ToLowerInvariant();
                string portKey = int.TryParse(Port, out int pn) ? pn.ToString() : Port.Trim();
                string sniKey  = string.IsNullOrEmpty(Sni) ? hostKey : Sni.Trim().ToLowerInvariant();
                // v6.12: Flow and ObfsPassword appended — see ParseProxyLine. Without them,
                // "vless://u@h:443?flow=xtls-rprx-vision" and "vless://u@h:443" collapsed
                // into one key and one variant was silently lost.
                return $"{NP(Protocol)}:{hostKey}:{portKey}:{CredKey(Protocol, Credential)}:{Network.ToLowerInvariant()}:{Security.ToLowerInvariant()}:{sniKey}:{Path}:{Pbk}:{Sid.ToLowerInvariant()}:{Flow.Trim().ToLowerInvariant()}:{ObfsPassword}:{ConnectionOptionsKey}";
            }
        }
		
        // Same identity as DeduplicationKey, but with the host component replaced by a
        // caller-supplied canonical form (the resolved IP) — used by alias collapse to
        // merge IP-literal vs hostname spellings of one endpoint.
        public string EndpointKey(string canonicalHost)
        {
            string portKey = int.TryParse(Port, out int pn) ? pn.ToString() : Port.Trim();
            string protocol = NP(Protocol);
            bool implicitTlsSni = !string.IsNullOrEmpty(Security) ||
                protocol is "trojan" or "hysteria" or "hysteria2" or "tuic" or "juicity" or "anytls" or "naive";
            // When TLS is enabled and SNI is omitted, clients use the original host as
            // the effective SNI. Do not merge different TLS hostnames just because they
            // resolve to the same IP; that can silently discard a working TLS virtual host.
            string sniKey = !string.IsNullOrEmpty(Sni)
                ? Sni.Trim().ToLowerInvariant()
                : implicitTlsSni ? Host.Trim().ToLowerInvariant() : canonicalHost;
            // WebSocket/HTTP-upgrade Host defaults to the endpoint hostname; H2 also
            // uses it when SNI/host is omitted. Keep those implicit host identities distinct
            // to avoid merging different virtual hosts. For WS/HTTP-upgrade this is
            // conservative even when an explicit Host override is present.
            bool implicitTransportHost =
                Network.Equals("ws", StringComparison.OrdinalIgnoreCase) ||
                Network.Equals("httpupgrade", StringComparison.OrdinalIgnoreCase) ||
                (Network.Equals("h2", StringComparison.OrdinalIgnoreCase) && string.IsNullOrEmpty(Sni));
            string endpointKeyHost = implicitTransportHost
                ? Host.Trim().ToLowerInvariant()
                : canonicalHost.ToLowerInvariant();
            return $"{protocol}:{endpointKeyHost}:{portKey}:{CredKey(Protocol, Credential)}:{Network.ToLowerInvariant()}:{Security.ToLowerInvariant()}:{sniKey}:{Path}:{Pbk}:{Sid.ToLowerInvariant()}:{Flow.Trim().ToLowerInvariant()}:{ObfsPassword}:{ConnectionOptionsKey}";
        }

        // Case handling in the credential part of the dedup key. The old blanket
        // Credential.ToLowerInvariant() was right for UUIDs (hex, case-insensitive) but
        // WRONG for trojan/ss/hysteria2 passwords, where "Abc" and "abc" are different
        // credentials — two genuinely distinct nodes were silently collapsed into one.
        // ss/ssr credentials are "method:password": cipher names are case-insensitive,
        // passwords are not.
        private static string CredKey(string proto, string cred)
        {
            proto = NP(proto);
            if (proto is "vmess" or "vless" or "tuic" or "juicity")
                return cred.Trim().ToLowerInvariant();
            if ((proto == "ss" || proto == "ssr") && cred.Contains(':'))
            {
                int c = cred.IndexOf(':');
                return cred[..c].ToLowerInvariant() + cred[c..];
            }
            return cred;   // trojan, hysteria2, naive, ... — case-sensitive passwords
        }

        private static string NP(string p)
        {
            if (string.IsNullOrEmpty(p)) return "unknown";
            p = p.ToLowerInvariant();
            if (p == "hy2") return "hysteria2"; // alias only — "hysteria" (v1) stays separate, see NormalizeProto
            if (p == "shadowsocks") return "ss";
            if (p == "wg") return "wireguard";
            return p;
        }
    }

    public class FinalProxy
    {
        public string  Link             { get; set; } = "";
        public string  Proto            { get; set; } = "";
        public string  CountryCode      { get; set; } = "XX";
        public string  Continent        { get; set; } = "Unknown";
        public string  Remark           { get; set; } = "";
        public string  Host             { get; set; } = "";
        public bool    IranTested       { get; set; }
        public bool    IsStable         { get; set; }
        public bool    TlsVerified      { get; set; }
        public bool    XrayVerified     { get; set; }   // v6.15: full roundtrip via xray-core
        public bool    EdgeVerified     { get; set; }   // v6.15: TLS verified from CF edge vantage
        public int     Score            { get; set; }   // composite (0–187 since v6.18: 30 Iran + 20 TLS + 35 Xray + 20 Edge + 10 TLS-streak + 15 Xray-streak + 20 presence + 27 region + 10 source)
    }

    public class NodeHistory
    {
        public int Streak { get; set; }
        public int Misses { get; set; }
        public int TlsOk { get; set; }   // consecutive runs TLS-verified
        public int XrayOk { get; set; }  // consecutive runs roundtrip-verified (v6.15)
    }
}
