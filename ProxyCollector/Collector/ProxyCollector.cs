using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
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
using ProxyCollector.Configuration;
using ProxyCollector.Services;
using YamlDotNet.Serialization;

namespace ProxyCollector.Collector
{
    public class ProxyCollector
    {
        private readonly HttpClient _http = new(new SocketsHttpHandler
        {
            // Some non-GitHub sources always serve gzip regardless of Accept-Encoding;
            // without this the body arrives as raw gzip bytes containing no "://" —
            // the source yields zero nodes, silently.
            AutomaticDecompression = DecompressionMethods.All
        })
        {
            Timeout = TimeSpan.FromSeconds(40),
            DefaultRequestHeaders = { { "User-Agent", "FastNodes/6.20 (+https://github.com/rtwo2/FastNodes)" } }
        };
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
            $@"(?<![a-zA-Z])({SchemeAlternation})://\S+",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static readonly Regex SchemeHtmlRegex = new(
            $@"(?<![a-zA-Z])({SchemeAlternation})://[^\s""'<>\[\]]+",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        // ====================== HOST FILTER (EXACT/SUFFIX ONLY) ======================
        // No IP-range/CDN filtering anymore. The previous Cloudflare CIDR filter blocked
        // any host whose IP fell in Cloudflare's ranges — but fronting a proxy through
        // Cloudflare (a bare Cloudflare IP, or a workers.dev/pages.dev endpoint) is a
        // deliberate and common way to make a proxy reachable from a censored network.
        // That filter was removing a large share of exactly the nodes most likely to work.
        // All that's left is a short list of things that are never a real proxy server:
        // bare public DNS resolver IPs, and dev-tunnel domains.
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
        private static bool IsPrivateOrReservedIp(IPAddress ip)
        {
            var b = ip.GetAddressBytes();

            // IPv4-mapped IPv6 (::ffff:a.b.c.d): bytes [10] and [11] are both 0xFF,
            // with the embedded IPv4 in bytes [12..16]. Detected manually (IPAddress
            // has no IsIPv4MappedIPv6 property) and re-checked as plain IPv4 —
            // otherwise ::ffff:192.168.1.1 parses as IPv6 and slips past every
            // IPv4 range check below.
            if (ip.AddressFamily == AddressFamily.InterNetworkV6 && b.Length == 16
                && b[10] == 0xFF && b[11] == 0xFF)
            {
                return IsPrivateOrReservedIp(ip.MapToIPv4());
            }

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
                if (IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal) return true;
                if ((b[0] & 0xFE) == 0xFC) return true;                                 // fc00::/7 unique local
                if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8) return true; // 2001:db8::/32 docs
            }
            return false;
        }

        private static bool IsPlaceholderCredential(string credential)
            => !string.IsNullOrEmpty(credential) && PlaceholderCredentialPattern.IsMatch(credential.Trim());

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
        // v6.19: the ONLY region decision for top.txt / verified.txt. User's actual
        // usage: Europe + Iran + neighbors — everything else works too rarely to rank.
        // All other output files stay global and untouched.
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
            public int Lines;
            public int Parsed;
            public int Unique;
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
                if (File.Exists(file) && new FileInfo(file).Length > 0)
                {
                    LogInfo($"{label} present (cache), skipping.");
                    continue;
                }

                LogInfo($"Downloading {label}...");
                bool ok = false;
                foreach (var host in new[]
                {
                    "https://github.com/P3TERX/GeoLite.mmdb/raw/download/",
                    "https://cdn.jsdelivr.net/gh/P3TERX/GeoLite.mmdb@download/"
                })
                {
                    try
                    {
                        var resp = await http.GetAsync(host + label);
                        resp.EnsureSuccessStatusCode();
                        await using var fs = new FileStream(file, FileMode.Create);
                        await resp.Content.CopyToAsync(fs);
                        LogSuccess($"{label} downloaded.");
                        ok = true;
                        break;
                    }
                    catch (Exception ex) { LogWarning($"{label} mirror failed: {ex.Message}"); }
                }
                if (!ok && required) failed.Add(label);
            }

            if (failed.Count > 0)
                throw new InvalidOperationException(
                    $"Required GeoIP DB unavailable: {string.Join(", ", failed)}");
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
        // Fail-open, same discipline as FireHOL: download fails → filter off →
        // Edge probes everything exactly as before.
        private static (uint Net, uint Mask)[] CfCidrs = Array.Empty<(uint, uint)>();

        private static async Task LoadCloudflareRanges(HttpClient http)
        {
            try
            {
                var text = await http.GetStringAsync("https://www.cloudflare.com/ips-v4");
                var list = new List<(uint, uint)>();
                foreach (var raw in text.Split('\n'))
                {
                    var l = raw.Trim();
                    if (l.Length == 0) continue;
                    int slash = l.IndexOf('/');
                    if (slash < 0) continue;
                    if (!IPAddress.TryParse(l[..slash], out var ip)) continue;
                    if (ip.AddressFamily != AddressFamily.InterNetwork) continue;
                    if (!int.TryParse(l[(slash + 1)..], out int bits) || bits < 0 || bits > 32) continue;
                    var b = ip.GetAddressBytes();
                    uint net = ((uint)b[0] << 24) | ((uint)b[1] << 16) | ((uint)b[2] << 8) | b[3];
                    uint mask = bits == 0 ? 0 : 0xFFFFFFFFu << (32 - bits);
                    list.Add((net & mask, mask));
                }
                CfCidrs = list.OrderBy(x => x.Item1).ToArray();
                LogSuccess($"Cloudflare ranges loaded ({CfCidrs.Length} CIDRs) — Edge stage will skip CF-fronted hosts.");
            }
            catch (Exception ex) { LogWarning($"Cloudflare ranges failed to load (non-fatal — Edge probes everything): {ex.Message}"); }
        }

        private static bool IsCloudflareIp(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork || CfCidrs.Length == 0)
                return false;
            var b = ip.GetAddressBytes();
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
        // Resolves both the display string and the raw country code in one shot, so we
        // never need a second DNS lookup for the same host later just to get its ISO code.
        // Fallback chain: city (+ org if available) -> country + org -> country only ->
        // org only -> Unknown. Org is shown alongside city too, not just as a fallback
        // for when city is missing — knowing the hosting provider is useful even when
        // the city is known (e.g. distinguishing a Hetzner box from an OVH box in the
        // same city).
        private async Task<(string Location, string CountryCode)> GetLocationAndCountryAsync(string host)
        {
            try
            {
                string? org = await Resolver.GetOrgAsync(host);
                string shortOrgTop = string.IsNullOrEmpty(org) ? "" : ShortenOrg(org);
                string orgSuffix = !string.IsNullOrEmpty(shortOrgTop) ? $" · {shortOrgTop}" : "";

                var city = await Resolver.GetCityAsync(host);
                if (!string.IsNullOrEmpty(city?.CityName))
                {
                    string cityCc = city.CountryCode?.ToUpper() ?? "XX";
                    string flag = Flags.TryGetValue(cityCc, out var f) ? f : "🌍";
                    string cityName = System.Globalization.CultureInfo.InvariantCulture.TextInfo
                        .ToTitleCase(city.CityName.Trim().ToLowerInvariant());
                    return ($"{flag} {cityName}, {cityCc}{orgSuffix}", cityCc);
                }

                var country = await Resolver.GetCountryAsync(host);
                string cc = country?.CountryCode?.ToUpper() ?? "XX";
                if (!string.IsNullOrEmpty(cc) && cc != "XX")
                {
                    string flagC = Flags.TryGetValue(cc, out var fc) ? fc : "🌍";
                    string name = !string.IsNullOrEmpty(country?.CountryName) && country.CountryName != "Unknown"
                        ? country.CountryName : cc;
                    return ($"{flagC} {name}{orgSuffix}", cc);
                }

                // Neither city nor country resolved — the ASN db is a separate lookup and
                // may still have an org name even in this case, so try it before giving up.
                string shortOrg = string.IsNullOrEmpty(org) ? "" : ShortenOrg(org);
                if (!string.IsNullOrEmpty(shortOrg))
                    return ($"🌐 {shortOrg}", "XX");

                return ("🌐 Unknown", "XX");
            }
            catch { return ("🌐 Unknown", "XX"); }
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

        // ====================== ENTRY POINT ======================
        public async Task StartAsync()
        {
            const string version = "v6.20";
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
                            var text = await _http.GetStringAsync(url, reqCts.Token);
                            var lines = DecodeAndExtractLines(text, url);
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
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var uniqueProxies = new List<ParsedProxy>();
            int processed = 0, badHostFiltered = 0, placeholderFiltered = 0, emptyCredFiltered = 0;

            // v6.13: byKey maps dedup key → kept node, so a DUPLICATE arriving from an
            // explicitly Iran-tested source can upgrade the kept node's trust flag.
            // (Which source's line wins the dedup race is bag-order nondeterminism —
            // this makes trust "ANY tested source contributed it", not "the winner".)
            var byKey = new Dictionary<string, ParsedProxy>(StringComparer.OrdinalIgnoreCase);
            var keySources = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
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
                if (IsPlaceholderCredential(p.Credential)) { placeholderFiltered++; continue; }
                if (CredentialRequiredProtocols.Contains(NormalizeProto(p.Protocol)) &&
                    string.IsNullOrEmpty(p.Credential)) { emptyCredFiltered++; continue; }
                if (!int.TryParse(p.Port, out int portNum) || portNum <= 0 || portNum > 65535) { badHostFiltered++; continue; }

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
            LogInfo($"After smart dedup: {uniqueProxies.Count} unique ({badHostFiltered} bad host/port, {placeholderFiltered} placeholder credential, {emptyCredFiltered} empty credential filtered)");
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
            int zeroYield = 0, formatGap = 0;
            foreach (var kv in sourceStats.OrderBy(k => k.Key))
            {
                if (kv.Value.Lines == 0)
                {
                    zeroYield++;
                    LogWarning($"  zero-yield (dead/empty/blocked): {kv.Key}");
                }
                else if (kv.Value.Parsed == 0)
                {
                    formatGap++;
                    LogWarning($"  FORMAT GAP ({kv.Value.Lines} lines, 0 parsed): {kv.Key}");
                }
            }
            LogInfo($"Source health: {sourceStats.Count} sources — {sourceStats.Count - zeroYield - formatGap} healthy, {zeroYield} zero-yield, {formatGap} format-gap.");
            GroupEnd();

            // Sort deterministically before remark numbering — without this, duplicate
            // suffixes (#1, #2, ...) would get reassigned to different physical servers on
            // every run even when the underlying node set hadn't changed at all. The
            // filters below preserve this order (Where() keeps list order).
            var alive = uniqueProxies
                .OrderBy(p => p.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(p => int.TryParse(p.Port, out var pn) ? pn : 0)
                .ThenBy(p => p.Protocol, StringComparer.OrdinalIgnoreCase)
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

            GroupStart("💀 Step 4/5 — Dead-node & alias filters");
            // Order is deliberate: DNS filter removes the dead first, then the resolved-IP
            // filter and alias collapse both run on the warm resolver cache (pure cache
            // hits, ~free), and the TCP filter runs LAST so it probes the smallest
            // possible set — alias-merged spelling variants never get probed twice.
            alive = await DropDnsDeadHostsAsync(alive);
            alive = await DropBadResolvedIpsAsync(alive);
            alive = await CollapseHostAliasesAsync(alive);
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

            GroupStart("💾 Step 5/5 — Rename + save output files");
            // Remark assignment runs AFTER the filters — a dropped node must not consume
            // an #N suffix, or every surviving duplicate's number would shift between runs.
            string Loc(string h) => locationCache.TryGetValue(h, out var l) ? l : "🌐 Unknown";
            string Cc(string h) => countryCache.TryGetValue(h, out var c) ? c : "XX";

            // A bare IPv6 literal next to " | " reads ambiguously (colons collide visually
            // with the separator) — bracket it for display, same as how IPv6 is normally
            // written next to a port. This only affects the remark text, not the link itself.
            string DisplayHost(string h) =>
                h.Contains(':') && IPAddress.TryParse(h, out var ip) &&
                ip.AddressFamily == AddressFamily.InterNetworkV6
                    ? $"[{h}]" : h;

            var finalProxies = new List<FinalProxy>();

            // Pass 1: count total occurrences of each base remark using frozen locations.
            var remarkTotal = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in alive)
            {
                string baseRemark = $"{Loc(p.Host)} | {DisplayHost(p.Host)}";
                remarkTotal.TryGetValue(baseRemark, out int cnt);
                remarkTotal[baseRemark] = cnt + 1;
            }

            // Pass 2: assign remarks. Unique nodes: no suffix. Nodes sharing a base
            // remark (same server, multiple inbounds) get disambiguated by PORT, then
            // port·proto — replacing the old bare "#N" counter. "Frankfurt #7" told the
            // user nothing; "Frankfurt :8443" says exactly which inbound it is.
            // Deterministic: alive is sorted host→port→proto, so suffix assignment is
            // stable across runs.
            var suffixUsed = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (var p in alive)
            {
                string proto = NormalizeProto(p.Protocol);
                string baseRemark = $"{Loc(p.Host)} | {DisplayHost(p.Host)}";
                remarkTotal.TryGetValue(baseRemark, out int total);

                string remark;
                if (total <= 1)
                {
                    remark = baseRemark;
                }
                else
                {
                    if (!suffixUsed.TryGetValue(baseRemark, out var used))
                        suffixUsed[baseRemark] = used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                    string suffix = $" :{p.Port}";
                    if (used.Contains(suffix)) suffix = $" :{p.Port}·{proto}";
                    if (used.Contains(suffix)) suffix = $" :{p.Port}·{proto}·#{used.Count + 1}";
                    used.Add(suffix);
                    remark = baseRemark + suffix;
                }

                string cleanLink = BuildCleanLink(p, remark);
                string cc = Cc(p.Host);
                string continent = GetContinent(cc);

                // v6.14 composite score — the /top ranking. Only signals whose vantage
                // bias is known: Iran-side trust (delegated), clean-vantage liveness
                // (this hour), consistency streaks, ecosystem persistence, proximity.
                // No single signal can carry a node to the top — convergence across
                // vantage classes is what the score rewards.
                int score = 0;
                if (p.IranTested) score += 30;                      // Iran-vantage validation (delegated)
                if (p.TlsVerified) score += 20;                     // clean-vantage liveness, this hour
                if (p.XrayVerified) score += 35;                    // Increased weight: full proxy roundtrip
                if (p.EdgeVerified) score += 20;                    // Increased weight: second-vantage TLS (CF edge)
                score += Math.Min(p.VerifiedStreak, 5) * 2;         // up to +10 — verified N runs in a row
                if (p.XrayStreak >= 2) score += Math.Min(p.XrayStreak, 5) * 3;  // up to +15 — roundtrip-verified N runs in a row (>=2 gate: the first run already paid via XrayVerified)
                score += Math.Min(p.Streak, 20);                    // up to +20 — survived N hourly runs
                score += (9 - ProximityTier(cc)) * 3;               // up to +27 — empirical region weight (Europe-first, v6.18)
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

            // Sort deterministically by Host -> Protocol.
            finalProxies = finalProxies
                .OrderBy(p => p.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(p => p.Proto, StringComparer.OrdinalIgnoreCase)
                .ToList();

            await SaveAllCategories(finalProxies);
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

        // NXDOMAIN-only dropping: timeouts no longer count (see DnsVerdict). The DNS
        // breaker is higher than TCP's because NXDOMAIN is authoritative and a high
        // dead-domain rate is EXPECTED in this domain — the breaker now guards only
        // against pathological garbage, not signal failure.
        private const double MaxDnsDropFraction = 0.50;

        private async Task<List<ParsedProxy>> DropDnsDeadHostsAsync(List<ParsedProxy> proxies)
        {
            var hosts = proxies.Select(p => p.Host)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Where(h => !IPAddress.TryParse(h, out _))
                .ToList();
            if (hosts.Count == 0) return proxies;

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
                LogWarning($"DNS filter: {deadSet.Count}/{hosts.Count} NXDOMAINs — over {MaxDnsDropFraction:P0} circuit breaker, keeping all.");
                return proxies;
            }

            int before = proxies.Count;
            var result = proxies.Where(p => !deadSet.Contains(p.Host)).ToList();
            LogWarning($"DNS-dead: dropped {deadSet.Count} NXDOMAIN hosts ({before - result.Count} nodes).");
            return result;
        }

        // ====================== RESOLVED-IP FILTER ======================
        // IsBadHost's FireHOL/reserved-IP checks only ran for IP-LITERAL hosts — a
        // hostname that RESOLVES into a private range or a FireHOL bogon slipped
        // through untouched. This closes that gap: every surviving hostname's
        // resolved IP (already cached from the GeoIP stage) goes through the same
        // two checks. Affirmative by definition — an endpoint inside 10/8 or a
        // hijacked range can never be a public proxy, whatever it's called.
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
                    var ip = await Resolver.ResolveAsync(host);   // cache hit from GeoIP stage
                    if (ip == null) return;                       // unresolvable = DNS filter's territory
                    if (IsPrivateOrReservedIp(ip) || IsFireholBlacklisted(ip))
                        bad.Add(host);
                });

            if (bad.IsEmpty) return proxies;

            var badSet = bad.ToHashSet(StringComparer.OrdinalIgnoreCase);
            if (badSet.Count > hosts.Count * MaxDnsDropFraction)   // same breaker discipline as DNS
            {
                LogWarning($"Resolved-IP filter: {badSet.Count}/{hosts.Count} flagged — over {MaxDnsDropFraction:P0} breaker, keeping all.");
                return proxies;
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
        //   - different SNI/path/REALITY keys (fronting & transport variants)
        private async Task<List<ParsedProxy>> CollapseHostAliasesAsync(List<ParsedProxy> proxies)
        {
            var index = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var kept = new List<ParsedProxy>();
            int collapsed = 0;

            foreach (var p in proxies)   // input is deterministically sorted
            {
                string canonical;
                if (IPAddress.TryParse(p.Host, out var literal))
                    canonical = literal.ToString();
                else
                {
                    var ip = await Resolver.ResolveAsync(p.Host);   // cache hit — GeoIP resolved these
                    canonical = ip?.ToString() ?? "unresolved|" + p.Host.Trim().ToLowerInvariant();
                }

                string key = p.EndpointKey(canonical);
                if (index.TryGetValue(key, out var pos))
                {
                    collapsed++;
                    // Upgrade: if the kept form is a bare IP and this one is a hostname,
                    // swap it in — the hostname spelling is strictly better for clients.
                    if (IPAddress.TryParse(kept[pos].Host, out _) && !IPAddress.TryParse(p.Host, out _))
                        kept[pos] = p;
                }
                else
                {
                    index[key] = kept.Count;
                    kept.Add(p);
                }
            }

            if (collapsed > 0)
                LogInfo($"Alias collapse: {collapsed} spelling-variants merged (same endpoint, IP/hostname forms).");
            return kept;
        }

        private async Task<List<ParsedProxy>> DropTcpRefusedAsync(List<ParsedProxy> proxies)
        {
            // RST on connect = the server's own TCP stack saying nothing listens on that
            // port. This is the exact opposite of the removed v6-style check: there, a
            // timeout meant "dead"; here a timeout means "unknown, keep". UDP-based
            // protocols skip entirely — RST semantics don't apply to them (v6.4 lesson).
            // Connects go to the pre-resolved IP from the resolver cache, so the 3s
            // budget is purely the handshake — the v6.7 regression (DNS resolution
            // eating the connect timeout) structurally cannot recur here.
            var candidates = proxies
                .Where(p => !UdpProtocols.Contains(p.Protocol) && int.TryParse(p.Port, out _))
                .ToList();
            if (candidates.Count == 0) return proxies;

            // v6.12: probe ENDPOINTS (resolved IP + port), not nodes. An RST is a
            // property of the endpoint, not the credential — but the dedup key
            // deliberately keeps cred/SNI/path variants apart, so one host:port with
            // 3 nodes was probed 3 times, and CF-fronted hostnames collapse onto shared
            // IPs on top of that. Sequential warm-cache lookups (~free), probe each
            // endpoint once, refuse ⇒ drop every node mapped to it. Breaker still
            // counts NODES (dropped / candidates), unchanged semantics.
            var endpointSet = new Dictionary<(string Ip, int Port), byte>();
            var nodeEndpoints = new List<(ParsedProxy Node, string Ip, int Port)>(candidates.Count);
            foreach (var p in candidates)
            {
                var ip = await Resolver.ResolveAsync(p.Host);   // cache hit from GeoIP stage
                if (ip == null) continue;                       // unresolvable — DNS filter's territory
                int port = int.Parse(p.Port);
                endpointSet.TryAdd((ip.ToString(), port), 0);
                nodeEndpoints.Add((p, ip.ToString(), port));
            }
            if (endpointSet.Count == 0) return proxies;

            var deadEndpoints = new ConcurrentBag<(string Ip, int Port)>();
            await Parallel.ForEachAsync(endpointSet.Keys, new ParallelOptions { MaxDegreeOfParallelism = 500 },
                async (ep, ct) =>
                {
                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeoutCts.CancelAfter(TimeSpan.FromSeconds(3));   // without this a
                                                                      // blackholed SYN hangs
                                                                      // ~2min on OS defaults
                    try
                    {
                        using var tcp = new TcpClient();
                        await tcp.ConnectAsync(IPAddress.Parse(ep.Ip), ep.Port, timeoutCts.Token);
                        // connected — endpoint stays (we deliberately don't send anything)
                    }
                    catch (SocketException e) when (e.SocketErrorCode == SocketError.ConnectionRefused)
                    {
                        deadEndpoints.Add(ep);        // affirmative death only
                    }
                    catch (OperationCanceledException) { /* 3s timeout — inconclusive, keep */ }
                    catch { /* unreachable / no-v6-route / anything else — keep */ }
                });

            if (deadEndpoints.IsEmpty) return proxies;

            var deadSet = deadEndpoints.ToHashSet();
            int droppedNodes = nodeEndpoints.Count(ne => deadSet.Contains((ne.Ip, ne.Port)));
            if (droppedNodes > candidates.Count * MaxDropFraction)
            {
                LogWarning($"TCP filter: {deadSet.Count} refused endpoints ({droppedNodes}/{candidates.Count} nodes) — over {MaxDropFraction:P0} circuit breaker, keeping all.");
                return proxies;
            }

            var deadNodeKeys = nodeEndpoints
                .Where(ne => deadSet.Contains((ne.Ip, ne.Port)))
                .Select(ne => ne.Node.DeduplicationKey)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var result = proxies.Where(p => !deadNodeKeys.Contains(p.DeduplicationKey)).ToList();
            LogWarning($"TCP-refused: dropped {proxies.Count - result.Count} nodes across {deadSet.Count} refused endpoints (RST received, port closed).");
            return result;
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
            var candidates = proxies
                .Where(p => IsXrayCandidate(p) && int.TryParse(p.Port, out _)
                    && IsPreferredRegion(countryCache.TryGetValue(p.Host, out var pcc) ? pcc : "XX"))
                .OrderBy(p => countryCache.TryGetValue(p.Host, out var cc) ? ProximityTier(cc) : 9)
                .ThenByDescending(p => p.IranTested)
                .ThenByDescending(p => p.TlsVerified)
                .Take(XrayTopN)
                .ToList();
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

                // 90s: the pool is ~5000 inbounds (preferred regions alone fill it) —
                // startup runs past the old 15s window. Last run xray was healthy but
                // still binding when the window expired; the kill then zeroed verified.txt.
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
                    IPAddress? ip = IPAddress.TryParse(p.Host, out var literal)
                        ? literal
                        : await Resolver.ResolveAsync(p.Host);
                    if (ip != null && IsCloudflareIp(ip)) { cfSkipped++; return; }
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
                .Where(p => p.TlsVerified && int.TryParse(p.Port, out _) && IsTlsCandidate(p)
                    && IsPreferredRegion(countryCache.TryGetValue(p.Host, out var ecc) ? ecc : "XX"))   // v6.20: +20 is only spendable in gated files
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
                .Where(p => !p.TlsVerified && int.TryParse(p.Port, out _) && IsTlsCandidate(p)
                    && IsPreferredRegion(countryCache.TryGetValue(p.Host, out var ecc) ? ecc : "XX"))
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
                var ip = await Resolver.ResolveAsync(p.Host);   // warm cache
                if (ip == null) continue;
                // CF-fronted hosts: a TLS handshake with a Cloudflare edge SUCCEEDS even
                // when the proxy backend behind it is dead — the handshake terminates at
                // the edge and never reaches the origin. That's junk evidence, and it was
                // flooding top.txt with +20 "verified" CF nodes that never work. These
                // nodes must prove life via the Xray roundtrip instead.
                if (CfCidrs.Length > 0 && IsCloudflareIp(ip)) { cfSkippedTls++; continue; }
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
        private static string BuildVmessLink(string host, string port, string uuid, string net,
            string tls, string sni, string path, string aid, string remark)
        {
            var obj = new Dictionary<string, object?>
            {
                ["v"] = "2", ["ps"] = remark, ["add"] = host, ["port"] = port, ["id"] = uuid,
                ["aid"] = string.IsNullOrEmpty(aid) ? "0" : aid,
                ["net"] = string.IsNullOrEmpty(net) ? "tcp" : net,
                ["type"] = "none",
                ["host"] = sni ?? "",
                ["path"] = path ?? "",
                ["tls"] = tls == "tls" ? "tls" : ""
            };
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
			
        // ====================== SOURCE DECODING ======================
        private static List<string> DecodeAndExtractLines(string text, string url)
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
                    if (t.Contains("://") && !t.StartsWith("#")) results.Add(CleanExtracted(t));
                }
                return results;
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
                        int port = ob.TryGetProperty("server_port", out var portEl) && portEl.ValueKind == JsonValueKind.Number
                            ? portEl.GetInt32() : 0;
                        if (string.IsNullOrEmpty(server) || port <= 0) continue;

                        string uuid = ob.TryGetProperty("uuid", out var u) ? u.GetString() ?? "" : "";
                        string password = ob.TryGetProperty("password", out var pw) ? pw.GetString() ?? "" : "";
                        string name = ob.TryGetProperty("tag", out var tag) ? tag.GetString() ?? "" : "";

                        string sni = "";
                        bool tls = false;
                        string realityPbk = "", realitySid = "";
                        if (ob.TryGetProperty("tls", out var tlsEl) && tlsEl.ValueKind == JsonValueKind.Object)
                        {
                            if (tlsEl.TryGetProperty("enabled", out var en) && en.ValueKind == JsonValueKind.True) tls = true;
                            if (tlsEl.TryGetProperty("server_name", out var sn)) sni = sn.GetString() ?? "";
                            // sing-box nests REALITY under tls.reality — without this a
                            // REALITY outbound was rebuilt as security=tls with no
                            // pbk/sid: a link that can never connect.
                            if (tlsEl.TryGetProperty("reality", out var re) && re.ValueKind == JsonValueKind.Object)
                            {
                                realityPbk = re.TryGetProperty("public_key", out var pk) ? pk.GetString() ?? "" : "";
                                realitySid = re.TryGetProperty("short_id", out var si) ? si.GetString() ?? "" : "";
                            }
                        }
                        string flow = ob.TryGetProperty("flow", out var fl) ? fl.GetString() ?? "" : "";

                        string transport = "tcp", path = "";
                        if (ob.TryGetProperty("transport", out var tEl) && tEl.ValueKind == JsonValueKind.Object)
                        {
                            if (tEl.TryGetProperty("type", out var ttEl)) transport = ttEl.GetString() ?? "tcp";
                            if (tEl.TryGetProperty("path", out var pEl)) path = pEl.GetString() ?? "";
                        }

                        string remark = Uri.EscapeDataString(name);
                        string? link = type switch
                        {
                            // vmess now goes through BuildVmessLink — it used to emit
                            // "vmess://uuid@host:port?..." which is not a real vmess link
                            // (those are base64 JSON) and ParseProxyLine silently dropped
                            // every one of them.
                            "vmess" when !string.IsNullOrEmpty(uuid) =>
                                BuildVmessLink(server, port.ToString(), uuid, transport,
                                    tls ? "tls" : "", sni, path, "0", name),
                            "vless" when !string.IsNullOrEmpty(uuid) =>
                                $"vless://{uuid}@{server}:{port}?security={(realityPbk.Length > 0 ? "reality" : tls ? "tls" : "none")}&type={transport}&sni={Uri.EscapeDataString(sni)}&path={Uri.EscapeDataString(path)}&flow={Uri.EscapeDataString(flow)}&pbk={Uri.EscapeDataString(realityPbk)}&sid={Uri.EscapeDataString(realitySid)}#{remark}",
                            "trojan" when !string.IsNullOrEmpty(password) =>
                                $"trojan://{password}@{server}:{port}?sni={Uri.EscapeDataString(sni)}&type={transport}#{remark}",
                            "hysteria2" when !string.IsNullOrEmpty(password) =>
                                $"hysteria2://{password}@{server}:{port}?sni={Uri.EscapeDataString(sni)}#{remark}",
                            "tuic" when !string.IsNullOrEmpty(uuid) =>
                                $"tuic://{uuid}:{password}@{server}:{port}?sni={Uri.EscapeDataString(sni)}#{remark}",
                            "shadowsocks" => BuildSsLinkFromJson(ob, server, port, remark),
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

        // SIP002 userinfo is STANDARD base64 — the old version URL-safe'd it (- and _
        // instead of + and /), which ParseShadowsocksLink then failed to decode for any
        // base64 containing + or / (i.e. almost all of them), silently dropping the node.
        private static string? BuildSsLinkFromJson(JsonElement ob, string server, int port, string remark)
        {
            string method = ob.TryGetProperty("method", out var m) ? m.GetString() ?? "" : "";
            string password = ob.TryGetProperty("password", out var p) ? p.GetString() ?? "" : "";
            if (string.IsNullOrEmpty(method) || string.IsNullOrEmpty(password)) return null;
            string userinfo = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{method}:{password}"));
            return $"ss://{userinfo}@{server}:{port}#{remark}";
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

                    var link = ClashFieldsToLink(fields);
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
        private static string? ClashFieldsToLinkV2(Dictionary<string, string> f)
        {
            if (!f.TryGetValue("type", out var type)) return null;
            if (!f.TryGetValue("server", out var server) || !f.TryGetValue("port", out var port)) return null;
            type = type.ToLowerInvariant();
            if (string.IsNullOrEmpty(server) || string.IsNullOrEmpty(port)) return null;

            string remark = Uri.EscapeDataString(f.GetValueOrDefault("name", ""));
            bool tls = f.GetValueOrDefault("tls", "").Equals("true", StringComparison.OrdinalIgnoreCase);
            string sni     = f.GetValueOrDefault("servername", f.GetValueOrDefault("sni", ""));
            string network = f.GetValueOrDefault("network", "tcp");
            string path    = f.GetValueOrDefault("ws-opts.path", f.GetValueOrDefault("h2-opts.path", ""));
            string hostHdr = f.GetValueOrDefault("ws-opts.headers.Host", "");
            string flow    = f.GetValueOrDefault("flow", "");
            string fp      = f.GetValueOrDefault("client-fingerprint", "");
            string pbk     = f.GetValueOrDefault("reality-opts.public-key", "");
            string sid     = f.GetValueOrDefault("reality-opts.short-id", "");
            string grpc    = f.GetValueOrDefault("grpc-opts.grpc-service-name", "");
            string alpn    = f.GetValueOrDefault("alpn", "");

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
                    return $"vless://{f["uuid"]}@{server}:{port}?{string.Join("&", q)}#{remark}";
                }
                case "trojan" when f.ContainsKey("password"):
                {
                    q.Add($"security={(pbk.Length > 0 ? "reality" : tls ? "tls" : "none")}");
                    Q("type", network); Q("sni", sni); Q("flow", flow); Q("fp", fp);
                    Q("pbk", pbk); Q("sid", sid); Q("serviceName", grpc);
                    return $"trojan://{f["password"]}@{server}:{port}?{string.Join("&", q)}#{remark}";
                }
                case "hysteria2" or "hy2" when f.ContainsKey("password"):
                {
                    Q("sni", sni); Q("obfs", f.GetValueOrDefault("obfs", ""));
                    Q("obfs-password", f.GetValueOrDefault("obfs-password", ""));
                    Q("alpn", alpn); Q("fp", fp);
                    return $"hysteria2://{f["password"]}@{server}:{port}?{string.Join("&", q)}#{remark}";
                }
                case "vmess" when f.ContainsKey("uuid"):
                    return BuildVmessLink(server, port, f["uuid"], network, tls ? "tls" : "",
                        string.IsNullOrEmpty(sni) ? hostHdr : sni, path,
                        f.GetValueOrDefault("alterId", f.GetValueOrDefault("aid", "0")),
                        f.GetValueOrDefault("name", ""));
                case "ss" or "shadowsocks" when f.ContainsKey("cipher") && f.ContainsKey("password"):
                {
                    // SIP002: standard base64 userinfo (NOT URL-safe — the parser
                    // couldn't decode URL-safe base64 for nearly all payloads).
                    string ui = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{f["cipher"]}:{f["password"]}"));
                    return $"ss://{ui}@{server}:{port}#{remark}";
                }
                default:
                    return null;
            }
        }

        private static string? ClashFieldsToLink(Dictionary<string, string> f)
        {
            if (!f.TryGetValue("type", out var type)) return null;
            type = type.ToLowerInvariant();
            if (!f.TryGetValue("server", out var server) || !f.TryGetValue("port", out var port)) return null;
            if (string.IsNullOrEmpty(server) || string.IsNullOrEmpty(port)) return null;

            string remark = Uri.EscapeDataString(f.GetValueOrDefault("name", ""));
            bool tls = f.GetValueOrDefault("tls", "false").Equals("true", StringComparison.OrdinalIgnoreCase);
            string sni = f.GetValueOrDefault("servername", f.GetValueOrDefault("sni", ""));
            string network = f.GetValueOrDefault("network", "tcp");

            return type switch
            {
                // vmess routes through BuildVmessLink — same bug as sing-box: the old
                // "vmess://uuid@host:port?..." form is not a valid vmess link and every
                // one of these nodes was silently dropped at parse time.
                "vmess" when f.ContainsKey("uuid") =>
                    BuildVmessLink(server, port, f["uuid"], network,
                        tls ? "tls" : "", sni, f.GetValueOrDefault("ws-path", ""),
                        f.GetValueOrDefault("alterId", f.GetValueOrDefault("aid", "0")),
                        f.GetValueOrDefault("name", "")),
                "vless" when f.ContainsKey("uuid") =>
                    $"vless://{f["uuid"]}@{server}:{port}?security={(tls ? "tls" : "none")}&type={network}&sni={Uri.EscapeDataString(sni)}#{remark}",
                "trojan" when f.ContainsKey("password") =>
                    $"trojan://{f["password"]}@{server}:{port}?sni={Uri.EscapeDataString(sni)}#{remark}",
                "hysteria2" or "hy2" when f.ContainsKey("password") =>
                    $"hysteria2://{f["password"]}@{server}:{port}?sni={Uri.EscapeDataString(sni)}#{remark}",
                // Standard base64 userinfo now — was URL-safe, which the parser couldn't
                // decode for nearly all real base64 payloads.
                "ss" or "shadowsocks" when f.ContainsKey("cipher") && f.ContainsKey("password") =>
                    BuildSsLinkFromClashFields(f["cipher"], f["password"], server, port, remark),
                _ => null
            };
        }

        private static string BuildSsLinkFromClashFields(string cipher, string password, string server, string port, string remark)
        {
            string userinfo = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{cipher}:{password}"));
            return $"ss://{userinfo}@{server}:{port}#{remark}";
        }

        // ====================== SAVE OUTPUTS ======================
        // everything.txt is always a single, full, uncapped file — never chunked.
        // Every other category's <name>.txt holds the first ChunkSize lines (this
        // filename never changes), overflow beyond that goes to <name>_part2.txt,
        // _part3.txt, ...
        private const int ChunkSize = 1000;

        private async Task SaveAllCategories(List<FinalProxy> proxies)
        {
            var sub = Path.Combine(Directory.GetCurrentDirectory(), "sub");

            // v6.13: wipe the ENTIRE sub tree (was: only the three category dirs) —
            // stale top-level files from past versions used to survive forever.
            // state/ lives OUTSIDE sub/ and is untouched.
            if (Directory.Exists(sub)) Directory.Delete(sub, recursive: true);
            Directory.CreateDirectory(sub);
            // v6.13.1: re-create the category dirs — the wipe patch above deleted the
            // old creation loop, and File.WriteAllLinesAsync never creates intermediate
            // directories, so the first protocols/vless.txt write crashed the run.
            foreach (var d in new[] { "protocols", "countries", "continents" })
                Directory.CreateDirectory(Path.Combine(sub, d));

            await File.WriteAllLinesAsync(Path.Combine(sub, "everything.txt"), proxies.Select(x => x.Link));
            LogSuccess($"Saved everything.txt ({proxies.Count})");

            // v6.13 quality tiers — single unsplit files, same policy as everything.txt.
            var stable = proxies.Where(x => x.IsStable).ToList();
            await File.WriteAllLinesAsync(Path.Combine(sub, "stable.txt"), stable.Select(x => x.Link));
            LogSuccess($"Saved stable.txt ({stable.Count}) — present ≥{StableMinRuns} consecutive runs");

            var tlsVerified = proxies.Where(x => x.TlsVerified).ToList();
            await File.WriteAllLinesAsync(Path.Combine(sub, "verified_tls.txt"), tlsVerified.Select(x => x.Link));
            LogSuccess($"Saved verified_tls.txt ({tlsVerified.Count}) — TLS handshake completed (clean-vantage, promotion only)");

            // v6.15: the strongest file in the repo — nodes that proxied a real HTTP
            // request end-to-end this run, through the actual protocol, via xray-core.
            var xrayVerified = proxies.Where(x => x.XrayVerified && IsPreferredRegion(x.CountryCode)).ToList();
            if (xrayVerified.Count > 0)
            {
                await File.WriteAllLinesAsync(Path.Combine(sub, "verified.txt"), xrayVerified.Select(x => x.Link));
                // keep a fallback copy for runs where the Xray stage itself fails
                Directory.CreateDirectory("state");
                await File.WriteAllLinesAsync(Path.Combine("state", "verified_last.txt"), xrayVerified.Select(x => x.Link));
            }
            else if (File.Exists(Path.Combine("state", "verified_last.txt")))
            {
                // Xray stage failed this run (e.g. startup freeze) — ship the last good
                // set rather than an empty file. Stale, but every node in it did complete
                // a real roundtrip at some point, and an empty subscription helps nobody.
                await File.WriteAllTextAsync(Path.Combine(sub, "verified.txt"),
                    await File.ReadAllTextAsync(Path.Combine("state", "verified_last.txt")));
                LogWarning("verified.txt: Xray verified 0 nodes this run — shipping the last successful set as fallback.");
            }
            LogSuccess($"Saved verified.txt ({xrayVerified.Count}) — full proxy roundtrip completed (this run)");

            // The Iran-optimization headline: explicitly Iran-tested sources, plus the
            // double-validated core (stable AND TLS-verified).
            var curated = proxies.Where(x => x.IranTested || (x.IsStable && x.TlsVerified)).ToList();
            await File.WriteAllLinesAsync(Path.Combine(sub, "curated.txt"), curated.Select(x => x.Link));
            LogSuccess($"Saved curated.txt ({curated.Count}) — Iran-tested source or stable+TLS-verified");

            // v6.14 /top — the precision file. Gate: at least one AFFIRMATIVE current
            // signal (TLS-verified this hour from a clean vantage, OR published by an
            // Iran-testing source). Then rank by composite score. Single unchunked
            // file of 1000 — small is the point.
            var top = proxies
                .Where(x => IsPreferredRegion(x.CountryCode))   // v6.19: Europe + IR + neighbors only
                .Where(x => x.TlsVerified || x.IranTested || x.XrayVerified || x.EdgeVerified)
                .OrderByDescending(x => x.Score)
                .ThenBy(x => x.Remark, StringComparer.OrdinalIgnoreCase)
                .Take(1000)
                .ToList();
            await File.WriteAllLinesAsync(Path.Combine(sub, "top.txt"), top.Select(x => x.Link));
            LogSuccess($"Saved top.txt ({top.Count}) — gate: TLS-verified or Iran-tested; " +
                       $"score range {top.LastOrDefault()?.Score ?? 0}–{top.FirstOrDefault()?.Score ?? 0}");

            // v6.13: IPv4/IPv6 by RESOLVED family — hostname nodes now classify too
            // (alias collapse swaps v6 literals for hostnames, which literal-only
            // classification undercounted). Warm cache ⇒ ~free.
            var ipv4Proxies = await FilterByFamilyAsync(proxies, AddressFamily.InterNetwork);
            var ipv6Proxies = await FilterByFamilyAsync(proxies, AddressFamily.InterNetworkV6);
            await File.WriteAllLinesAsync(Path.Combine(sub, "ipv4_only.txt"), ipv4Proxies.Select(x => x.Link));
            await File.WriteAllLinesAsync(Path.Combine(sub, "ipv6_only.txt"), ipv6Proxies.Select(x => x.Link));
            LogSuccess($"Saved ipv4_only.txt ({ipv4Proxies.Count}) / ipv6_only.txt ({ipv6Proxies.Count})");

            foreach (var g in proxies.GroupBy(x => x.Proto))
            {
                string key = g.Key.Trim().ToLowerInvariant();
                if (string.IsNullOrEmpty(key) || key == "unknown") continue;

                await WriteTxt(Path.Combine(sub, "protocols", key), g.ToList());
                LogSuccess($"  → protocols/{key} ({g.Count()})");
            }

            foreach (var g in proxies.GroupBy(x => x.CountryCode))
            {
                if (string.IsNullOrEmpty(g.Key) || g.Key == "XX" || g.Count() < 3) continue;
                string safe = Regex.Replace(g.Key, @"[^A-Z0-9]", "");
                if (string.IsNullOrEmpty(safe)) continue;
                await WriteTxt(Path.Combine(sub, "countries", safe), g.ToList());
                LogSuccess($"  → countries/{safe} ({g.Count()})");
            }

            foreach (var g in proxies.GroupBy(x => x.Continent))
            {
                if (g.Key == "Unknown" || g.Count() < 3) continue;
                await WriteTxt(Path.Combine(sub, "continents", g.Key), g.ToList());
                LogSuccess($"  → continents/{g.Key} ({g.Count()})");
            }

            // v6.16: WireGuard Clash YAML + .conf files
            // NekoBox's JSON parser has a bug with WireGuard outbounds, so we output
            // Clash YAML which NekoBox parses perfectly. The official WireGuard app
            // imports .conf files. We output BOTH so either client can use the data.
            var wgNodes = proxies.Where(x => x.Proto == "wireguard").ToList();
            if (wgNodes.Count > 0)
            {
                var wgDir = Path.Combine(sub, "wireguard");
                Directory.CreateDirectory(wgDir);

                var sb = new StringBuilder();
                sb.AppendLine("proxies:");
                int ok = 0;
                foreach (var node in wgNodes)
                {
                    var wgInfo = TryParseWireguardInfo(node.Link);
                    if (wgInfo == null) continue;
                    ok++;

                    // Individual .conf — WireGuard app imports this directly
                    string safe = Regex.Replace(node.Remark, @"[^\u0020-\u007E]", " ").Trim(); 
                    safe = Regex.Replace(safe, @"[\\/:\*\?""<>|]", "").Trim();
                    safe = Regex.Replace(safe, @"\s+", " ").TrimEnd('.').Trim();
                    if (safe.Length > 80) safe = safe[..80].Trim();
                    if (string.IsNullOrEmpty(safe)) safe = $"wg{ok:D3}";
                    await File.WriteAllTextAsync(Path.Combine(wgDir, $"{ok:D3} {safe}.conf"), BuildWireguardConf(wgInfo));

                    // Build Clash YAML format (quote strings to ensure IPv6/special chars don't break YAML)
                    string remark = node.Remark.Replace("\"", "\\\"");
                    sb.AppendLine($"  - name: \"{remark}\"");
                    sb.AppendLine($"    type: wireguard");
                    sb.AppendLine($"    server: \"{wgInfo.Host}\"");
                    sb.AppendLine($"    port: {wgInfo.Port}");
                    sb.AppendLine($"    ip: \"{wgInfo.Address}\"");
                    sb.AppendLine($"    public-key: \"{wgInfo.PublicKey}\"");
                    sb.AppendLine($"    private-key: \"{wgInfo.PrivateKey}\"");
                    sb.AppendLine($"    allowed-ips: \"{wgInfo.AllowedIPs}\"");
                    if (!string.IsNullOrEmpty(wgInfo.Dns)) sb.AppendLine($"    dns: \"{wgInfo.Dns}\"");
                    if (!string.IsNullOrEmpty(wgInfo.PresharedKey)) sb.AppendLine($"    preshared-key: \"{wgInfo.PresharedKey}\"");
                    sb.AppendLine($"    mtu: 1280");
                    if (wgInfo.Reserved.Length == 3)
                    {
                        sb.AppendLine($"    reserved: [{string.Join(",", wgInfo.Reserved.Select(r => r.Trim()))}]");
                    }
                    sb.AppendLine();
                }

                if (ok > 0)
                {
                    await File.WriteAllTextAsync(Path.Combine(sub, "protocols", "wireguard.txt"), sb.ToString());
                }
                else
                {
                    File.Delete(Path.Combine(sub, "protocols", "wireguard.txt"));   // 0 valid keys — don't ship raw unimportable links
                }

                LogSuccess($"Saved wireguard: {ok}/{wgNodes.Count} converted → " +
                           $"{ok} Clash YAML nodes (NekoBox) + {ok} .conf files (WireGuard app)");
            }
        }

        // v6.13: family by RESOLVED address — warm cache makes this ~free.
        private async Task<List<FinalProxy>> FilterByFamilyAsync(List<FinalProxy> proxies, AddressFamily family)
        {
            var result = new List<FinalProxy>();
            foreach (var x in proxies)
            {
                IPAddress? ip = IPAddress.TryParse(x.Host, out var literal)
                    ? literal
                    : await Resolver.ResolveAsync(x.Host);   // cache hit from GeoIP stage
                if (ip != null && ip.AddressFamily == family) result.Add(x);
            }
            return result;
        }

        // ====================== WIREGUARD CONF DECODER (v6.16) ======================
        // WireGuard has NO standard share-link format — the official app only
        // imports .conf files, and wireguard:// URIs are unrecognized by every
        // major client. This extracts the parameters from whatever the source published.
        private class WgInfo
        {
            public string? PrivateKey = null;
            public string? PublicKey = null;
            public string Address = "10.0.0.2/32";
            public string Dns = "1.1.1.1";
            public string AllowedIPs = "0.0.0.0/0, ::/0";
            public string? PresharedKey = null;
            public string Host = "";
            public int Port = 51820;
            public string[] Reserved = Array.Empty<string>();
        }

        private static WgInfo? TryParseWireguardInfo(string link)
        {
            try
            {
                string baseLink = link;
                int hash = baseLink.IndexOf('#');
                if (hash >= 0) baseLink = baseLink[..hash].Trim();
                if (!baseLink.Contains("://")) return null;

                string rest = baseLink[(baseLink.IndexOf("://") + 3)..];
                var info = new WgInfo();

                // Try 1: base64-encoded full .conf after the scheme
                try
                {
                    string b64 = rest.Replace('-', '+').Replace('_', '/');
                    int pad = b64.Length % 4; if (pad > 0) b64 += new string('=', 4 - pad);
                    string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
                    if (decoded.Contains("[Interface]") && decoded.Contains("[Peer]"))
                    {
                        string pk = Regex.Match(decoded, @"PrivateKey\s*=\s*(\S+)").Groups[1].Value;
                        if (!string.IsNullOrEmpty(pk)) info.PrivateKey = pk;
                        
                        string pubk = Regex.Match(decoded, @"PublicKey\s*=\s*(\S+)").Groups[1].Value;
                        if (!string.IsNullOrEmpty(pubk)) info.PublicKey = pubk;
                        
                        string addr = Regex.Match(decoded, @"Address\s*=\s*(\S+)").Groups[1].Value;
                        if (!string.IsNullOrEmpty(addr)) info.Address = addr;
                        
                        string dns = Regex.Match(decoded, @"DNS\s*=\s*(\S+)").Groups[1].Value;
                        if (!string.IsNullOrEmpty(dns)) info.Dns = dns;
                        
                        string allowed = Regex.Match(decoded, @"AllowedIPs\s*=\s*(.+)").Groups[1].Value.Trim();
                        if (!string.IsNullOrEmpty(allowed)) info.AllowedIPs = allowed;
                        
                        string psk = Regex.Match(decoded, @"PresharedKey\s*=\s*(\S+)").Groups[1].Value;
                        if (!string.IsNullOrEmpty(psk)) info.PresharedKey = psk;
                        
                        string endpoint = Regex.Match(decoded, @"Endpoint\s*=\s*(.+)").Groups[1].Value.Trim();
                        if (!string.IsNullOrEmpty(endpoint))
                        {
                            if (endpoint.StartsWith('['))
                            {
                                int close = endpoint.IndexOf(']');
                                info.Host = endpoint[1..close];
                                info.Port = int.Parse(endpoint[(close + 2)..]);
                            }
                            else
                            {
                                int colon = endpoint.LastIndexOf(':');
                                info.Host = endpoint[..colon];
                                info.Port = int.Parse(endpoint[(colon + 1)..]);
                            }
                        }
                    }
                }
                catch { }

                // Try 2: URI format — wg://privkey@host:port?pk=serverpub&ip=addr&dns=...
                if (string.IsNullOrEmpty(info.PrivateKey) || string.IsNullOrEmpty(info.PublicKey))
                {
                    var uri = new Uri(baseLink);
                    var q = ParseQuery(uri.Query);

                    info.PrivateKey = uri.UserInfo ?? "";
                    if (string.IsNullOrEmpty(info.PrivateKey))
                        info.PrivateKey = q.GetValueOrDefault("privatekey", q.GetValueOrDefault("private_key", ""));

                    info.Host = uri.Host;
                    info.Port = uri.Port > 0 ? uri.Port : 51820;
                    info.PublicKey = q.GetValueOrDefault("pk", q.GetValueOrDefault("publickey", q.GetValueOrDefault("server_publickey", "")));
                    info.Address = q.GetValueOrDefault("ip", q.GetValueOrDefault("address", q.GetValueOrDefault("allowed_ip", "10.0.0.2/32")));
                    info.Dns = q.GetValueOrDefault("dns", "1.1.1.1");
                    info.AllowedIPs = q.GetValueOrDefault("allowedips", q.GetValueOrDefault("allowed_ips", "0.0.0.0/0, ::/0"));
                    info.PresharedKey = q.GetValueOrDefault("psk", q.GetValueOrDefault("presharedkey", ""));
                    info.Reserved = q.GetValueOrDefault("reserved", "").Split(',', StringSplitOptions.RemoveEmptyEntries);
                }

                if (string.IsNullOrEmpty(info.PrivateKey) || string.IsNullOrEmpty(info.PublicKey) ||
                    string.IsNullOrEmpty(info.Host) || (!info.Host.Contains('.') && !info.Host.Contains(':')))
                    return null;

                // Sanitize and strictly validate keys. 
                // If a key is invalid (garbage data, wrong length), we drop the node.
                info.PrivateKey = SanitizeWgKey(info.PrivateKey);
                info.PublicKey = SanitizeWgKey(info.PublicKey);
                info.PresharedKey = SanitizeWgKey(info.PresharedKey); // Can be null if not present

                if (info.PrivateKey == null || info.PublicKey == null ||
                    string.IsNullOrEmpty(info.Host) || (!info.Host.Contains('.') && !info.Host.Contains(':')))
                    return null;

                return info;
            }
            catch { return null; }
        }

        // Bulletproof key sanitizer: removes spaces, normalizes URL-safe base64,
        // handles hex keys, and strictly enforces 32-byte base64 decoding.
        // Returns null if the key is fundamentally broken to prevent NekoBox crashes.
        private static string? SanitizeWgKey(string? key)
        {
            if (string.IsNullOrEmpty(key)) return null;
            try
            {
                // Remove ALL whitespace and newlines, normalize URL-safe base64
                string k = key.Trim().Replace(" ", "").Replace("\n", "").Replace("\r", "")
                              .Replace('-', '+').Replace('_', '/');

                // Add missing padding
                int pad = k.Length % 4;
                if (pad > 0) k += new string('=', 4 - pad);

                // Some sources provide a 64-character hex key instead of base64.
                if (k.Length == 64 && Regex.IsMatch(k, @"^[0-9a-fA-F]+$"))
                {
                    byte[] hexBytes = new byte[32];
                    for (int i = 0; i < 32; i++)
                        hexBytes[i] = Convert.ToByte(k.Substring(i * 2, 2), 16);
                    return Convert.ToBase64String(hexBytes);
                }

                // Strict validation: must decode to exactly 32 bytes
                byte[] bytes = Convert.FromBase64String(k);
                if (bytes.Length != 32) return null;
                
                return Convert.ToBase64String(bytes); // Return perfectly clean standard base64
            }
            catch
            {
                return null; // Not valid base64 at all
            }
        }

        private static string BuildWireguardConf(WgInfo info)
        {
            var sb = new StringBuilder();
            sb.AppendLine("[Interface]");
            sb.AppendLine($"PrivateKey = {info.PrivateKey}");
            sb.AppendLine($"Address = {info.Address}");
            if (!string.IsNullOrEmpty(info.Dns)) sb.AppendLine($"DNS = {info.Dns}");
            sb.AppendLine();
            sb.AppendLine("[Peer]");
            sb.AppendLine($"PublicKey = {info.PublicKey}");
            if (!string.IsNullOrEmpty(info.PresharedKey))
                sb.AppendLine($"PresharedKey = {info.PresharedKey}");
            sb.AppendLine($"Endpoint = {info.Host}:{info.Port}");
            sb.AppendLine($"AllowedIPs = {info.AllowedIPs}");
            sb.AppendLine("PersistentKeepalive = 25");
            return sb.ToString();
        }

        // ====================== WRITE TXT (chunked) ======================
        // First ChunkSize lines always go to <name>.txt — that filename never changes, so a
        // subscription link to it stays valid regardless of node count. Any overflow
        // beyond that goes to <name>_part2.txt, _part3.txt, ... (numbering starts at 2,
        // not 1, precisely so xx_part1.txt never exists and can't be confused with xx.txt).
        private static async Task WriteTxt(string pathNoExt, List<FinalProxy> proxies)
        {
            await File.WriteAllLinesAsync(pathNoExt + ".txt", proxies.Take(ChunkSize).Select(x => x.Link));

            if (proxies.Count <= ChunkSize) return;

            int partNum = 2;
            for (int i = ChunkSize; i < proxies.Count; i += ChunkSize)
            {
                var chunk = proxies.Skip(i).Take(ChunkSize).Select(x => x.Link);
                await File.WriteAllLinesAsync($"{pathNoExt}_part{partNum}.txt", chunk);
                partNum++;
            }
        }
		
        // ====================== PARSE ======================
        private static ParsedProxy? ParseProxyLine(string line)
        {
            line = line.Trim();
            if (line.Length < 10) return null;

            int hashIdx = line.IndexOf('#');
            string baseLink = hashIdx >= 0 ? line[..hashIdx].Trim() : line.Trim();
            if (string.IsNullOrEmpty(baseLink)) return null;

            if (baseLink.StartsWith("vmess://", StringComparison.OrdinalIgnoreCase))
            {
                // Standard vmess share link: base64(JSON). URL-safe base64 tolerated —
                // some sources publish it that way and plain FromBase64String rejects
                // '-'/'_', silently dropping every vmess node from those sources.
                try
                {
                    string b64 = baseLink["vmess://".Length..];
                    b64 = b64.Replace('-', '+').Replace('_', '/');
                    int pad = b64.Length % 4; if (pad > 0) b64 += new string('=', 4 - pad);
                    string json = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
                    using var doc = JsonDocument.Parse(json);
                    var r = doc.RootElement;

                    string host = r.TryGetProperty("add",  out var add)   ? (add.GetString()   ?? "") : "";
                    string port = r.TryGetProperty("port", out var portEl)
                        ? (portEl.ValueKind == JsonValueKind.Number ? portEl.GetInt32().ToString() : portEl.GetString() ?? "443")
                        : "443";
                    string uuid = r.TryGetProperty("id",   out var id)    ? (id.GetString()    ?? "") : "";
                    string net  = r.TryGetProperty("net",  out var netEl)  ? (netEl.GetString()  ?? "tcp") : "tcp";
                    if (string.IsNullOrEmpty(net)) net = "tcp";
                    string tls  = r.TryGetProperty("tls",  out var tlsEl)  ? (tlsEl.GetString()  ?? "") : "";
                    if (tls.Equals("none", StringComparison.OrdinalIgnoreCase)) tls = "";
                    string sni  = r.TryGetProperty("host", out var sniEl)  ? (sniEl.GetString()  ?? "") : "";
                    string path = r.TryGetProperty("path", out var pathEl) ? (pathEl.GetString() ?? "").TrimEnd('/') : "";
                    int aid     = r.TryGetProperty("aid",  out var aidEl)
                        ? (aidEl.ValueKind == JsonValueKind.Number ? aidEl.GetInt32() : 0) : 0;

                    if (string.IsNullOrEmpty(host) || host == "0.0.0.0") return null;

                    return new ParsedProxy
                    {
                        Protocol = "vmess", Host = host, Port = port,
                        Credential = uuid, Network = net, Security = tls,
                        Sni = sni, Path = path, Aid = aid, BaseLink = baseLink
                    };
                }
                catch { /* fall through to URI-form attempt below */ }

                // URI-form vmess ("vmess://uuid@host:port?security=tls&type=ws...") — not
                // the canonical base64-JSON shape, but some sources emit it and it used to
                // be an unconditional return null. Parse it like any other URI; the link
                // keeps its original form (BuildCleanLink appends #remark, which URI-form
                // vmess clients accept).
                try
                {
                    var uri = new Uri(baseLink);
                    var q = ParseQuery(uri.Query);
                    string net = q.GetValueOrDefault("type", "tcp");
                    if (string.IsNullOrEmpty(net)) net = "tcp";
                    string sec = q.GetValueOrDefault("security", "");
                    if (sec.Equals("none", StringComparison.OrdinalIgnoreCase)) sec = "";
                    string sni = q.GetValueOrDefault("sni", "") is var s && !string.IsNullOrEmpty(s)
                                  ? s : q.GetValueOrDefault("host", "");
                    return new ParsedProxy
                    {
                        Protocol = "vmess", Host = uri.Host,
                        Port = (uri.Port > 0 ? uri.Port : 443).ToString(),
                        Credential = uri.UserInfo ?? "",
                        Network = net, Security = sec,
                        Sni = sni, Path = q.GetValueOrDefault("path", "").TrimEnd('/'),
                        Aid = int.TryParse(q.GetValueOrDefault("aid", "0"), out var a) ? a : 0,
                        BaseLink = baseLink
                    };
                }
                catch { return null; }
            }

            if (baseLink.StartsWith("ss://", StringComparison.OrdinalIgnoreCase))
                return ParseShadowsocksLink(baseLink);

            if (baseLink.StartsWith("ssr://", StringComparison.OrdinalIgnoreCase))
                return ParseShadowsocksRLink(baseLink);

            try
            {
                var uri = new Uri(baseLink);
                string scheme = uri.Scheme.ToLowerInvariant();
                if (!ValidProtocols.Contains(scheme)) return null;

                // Uri.Host returns IPv6 literals WITHOUT brackets — no manual stripping
                // needed on this path (the ss parser splits host:port by hand and does).
                string h = uri.Host;
                // Per-scheme default port when the link omits one — "socks5://host" means
                // 1080, not 443. Uri.Port is -1 when the link carries no port.
                int p = uri.Port > 0 ? uri.Port
                    : scheme switch { "socks" or "socks5" or "socks4" => 1080,
                                      "brook" => 9999, "snell" => 61825, _ => 443 };
                if (string.IsNullOrEmpty(h) || h == "0.0.0.0") return null;

                var q = ParseQuery(uri.Query);
                string sec  = q.GetValueOrDefault("security", "");
                if (sec.Equals("none", StringComparison.OrdinalIgnoreCase)) sec = ""; // "security=none" and no security param at all mean the same thing
                string net  = q.GetValueOrDefault("type", "tcp");
                if (string.IsNullOrEmpty(net)) net = "tcp"; // GetValueOrDefault only falls back when the key is ABSENT — an explicit "type=" (present, empty) slipped through otherwise
                string sni  = q.GetValueOrDefault("sni", "") is var s && !string.IsNullOrEmpty(s)
                              ? s : q.GetValueOrDefault("host", "");
                string path = q.GetValueOrDefault("path", "").TrimEnd('/'); // trailing-slash-only difference shouldn't produce a different dedup key
                string pbk  = q.GetValueOrDefault("pbk", "");
                string sid  = q.GetValueOrDefault("sid", "");

                // v6.12: flow and obfs-password are part of a node's connection identity
                // — links differing only by them are DIFFERENT nodes (and one variant is
                // usually broken). They were previously unparsed, so both produced the
                // same dedup key and one was silently discarded.
                string flow = q.GetValueOrDefault("flow", "");
                string obfsPwd = scheme is "hysteria" or "hysteria2" or "hy2"
                    ? q.GetValueOrDefault("obfs-password", "") : "";

                // Hysteria v1 puts its auth token in a query param ("auth"), not userinfo —
                // unlike Hysteria2/TUIC/etc. which use the normal "user@host" position.
                // Without this, Credential was always empty for v1 links, so two different
                // v1 servers sharing a host:port would incorrectly look like duplicates.
                string cred = uri.UserInfo ?? "";
                if (string.IsNullOrEmpty(cred) && scheme == "hysteria")
                    cred = q.GetValueOrDefault("auth", "");

                return new ParsedProxy
                {
                    Protocol   = scheme,
                    Host       = h,
                    Port       = p.ToString(),
                    Credential = cred,
                    Network    = net,
                    Security   = sec,
                    Sni        = sni,
                    Path       = path,
                    Pbk        = pbk,
                    Sid        = sid,
                    Flow       = flow,
                    ObfsPassword = obfsPwd,
                    BaseLink   = baseLink
                };
            }
            catch { return null; }
        }

        // SSR's share-link format is nothing like a normal URI — it's a single base64
        // blob of "host:port:protocol:method:obfs:base64(password)/?params" — so it needs
        // its own decoder rather than generic Uri parsing, which would just see one long
        // authority-less string and fail (or worse, parse something garbage out of it).
        private static ParsedProxy? ParseShadowsocksRLink(string baseLink)
        {
            try
            {
                string decoded = Base64UrlDecode(baseLink["ssr://".Length..]);

                int slashIdx = decoded.IndexOf('/');
                string main = slashIdx >= 0 ? decoded[..slashIdx] : decoded;
                string query = "";
                if (slashIdx >= 0)
                {
                    int qIdx = decoded.IndexOf('?', slashIdx);
                    if (qIdx >= 0) query = decoded[(qIdx + 1)..];
                }

                // host:port:protocol:method:obfs:base64(password)
                var parts = main.Split(':');
                if (parts.Length < 6) return null;

                string host = parts[0];
                string port = parts[1];
                string protocol = parts[2];
                string method = parts[3];
                string obfs = parts[4];
                string password = Base64UrlDecode(parts[5]);
                if (string.IsNullOrEmpty(host) || host == "0.0.0.0") return null;

                var q = ParseQuery(query);
                // obfsparam/protoparam are per-connection secrets too — different values
                // there mean a meaningfully different config, so fold them into Path for
                // dedup purposes even though they're not a literal path.
                string extra = q.GetValueOrDefault("obfsparam", "") + "|" + q.GetValueOrDefault("protoparam", "");

                return new ParsedProxy
                {
                    Protocol = "ssr", Host = host, Port = port,
                    Credential = $"{method}:{password}",
                    Network = protocol, Security = obfs,
                    Sni = "", Path = extra,
                    BaseLink = baseLink
                };
            }
            catch { return null; }
        }

        // SSR links use URL-safe base64 (- and _ instead of + and /), commonly without
        // padding. This genuinely IS the SSR convention — unlike ss/vmess, where
        // URL-safe is a tolerated variant, not the rule.
        private static string Base64UrlDecode(string s)
        {
            s = s.Replace('-', '+').Replace('_', '/');
            int pad = s.Length % 4; if (pad > 0) s += new string('=', 4 - pad);
            return Encoding.UTF8.GetString(Convert.FromBase64String(s));
        }

        // Handles both real-world ss:// forms:
        //   SIP002 mixed:  ss://BASE64(method:password)@host:port?params#remark
        //   Legacy:        ss://BASE64(method:password@host:port)#remark
        // v6.11 fixes: URL-safe base64 tolerated in the userinfo (was: any base64
        // containing + or / from a URL-safe source failed to decode and the node was
        // silently dropped); IPv6 bracket literals stripped from Host so those nodes
        // get GeoIP lookups and land in ipv6_only.txt (was: bracketed host matched
        // nothing downstream).
        private static ParsedProxy? ParseShadowsocksLink(string baseLink)
        {
            try
            {
                string rest = baseLink["ss://".Length..];
                int atIdx = rest.IndexOf('@');

                if (atIdx > 0)
                {
                    // SIP002 mixed form
                    string userPart = rest[..atIdx];
                    string hostPart = rest[(atIdx + 1)..];

                    string method = "", password = "";
                    try
                    {
                        string b64 = userPart.Replace('-', '+').Replace('_', '/');   // tolerate URL-safe
                        int pad = b64.Length % 4; if (pad > 0) b64 += new string('=', 4 - pad);
                        string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(b64));
                        int c = decoded.IndexOf(':');
                        if (c > 0) { method = decoded[..c]; password = decoded[(c + 1)..]; }
                    }
                    catch
                    {
                        // SIP002 also allows a cleartext "method:password" here
                        int c = userPart.IndexOf(':');
                        if (c > 0)
                        {
                            method = Uri.UnescapeDataString(userPart[..c]);
                            password = Uri.UnescapeDataString(userPart[(c + 1)..]);
                        }
                    }

                    if (string.IsNullOrEmpty(method)) return null;

                    int qIdx = hostPart.IndexOf('?');
                    string hostPort = qIdx >= 0 ? hostPart[..qIdx] : hostPart;
                    string query = qIdx >= 0 ? hostPart[(qIdx + 1)..] : "";

                    int colonIdx = hostPort.LastIndexOf(':');
                    if (colonIdx <= 0) return null;
                    string host = hostPort[..colonIdx];
                    string port = hostPort[(colonIdx + 1)..];
                    if (host.StartsWith('[') && host.EndsWith(']')) host = host[1..^1];   // [2001:db8::1] → bare literal
                    if (string.IsNullOrEmpty(host) || host == "0.0.0.0") return null;

                    var q = ParseQuery(query);
                    return new ParsedProxy
                    {
                        Protocol = "ss", Host = host, Port = port,
                        Credential = $"{method}:{password}",
                        Network = "tcp", Security = "",
                        Sni = q.GetValueOrDefault("host", ""), Path = "",
                        BaseLink = baseLink
                    };
                }

                // Fully-encoded legacy form — URL-safe tolerated here too
                string legacyB64 = rest.Replace('-', '+').Replace('_', '/');
                int legacyPad = legacyB64.Length % 4; if (legacyPad > 0) legacyB64 += new string('=', 4 - legacyPad);
                string legacyDecoded = Encoding.UTF8.GetString(Convert.FromBase64String(legacyB64));

                int atIdx2 = legacyDecoded.LastIndexOf('@');
                if (atIdx2 <= 0) return null;
                string userPart2 = legacyDecoded[..atIdx2];
                string hostPort2 = legacyDecoded[(atIdx2 + 1)..];

                int c2 = userPart2.IndexOf(':');
                if (c2 <= 0) return null;
                string method2 = userPart2[..c2];
                string password2 = userPart2[(c2 + 1)..];

                int colonIdx2 = hostPort2.LastIndexOf(':');
                if (colonIdx2 <= 0) return null;
                string host2 = hostPort2[..colonIdx2];
                string port2 = hostPort2[(colonIdx2 + 1)..];
                if (host2.StartsWith('[') && host2.EndsWith(']')) host2 = host2[1..^1];
                if (string.IsNullOrEmpty(host2) || host2 == "0.0.0.0") return null;

                return new ParsedProxy
                {
                    Protocol = "ss", Host = host2, Port = port2,
                    Credential = $"{method2}:{password2}",
                    Network = "tcp", Security = "", Sni = "", Path = "",
                    BaseLink = baseLink
                };
            }
            catch { return null; }
        }

        private static string NormalizeProto(string proto)
        {
            if (string.IsNullOrEmpty(proto)) return "unknown";
            proto = proto.ToLowerInvariant();
            if (proto == "hy2") return "hysteria2"; // alias only — do NOT merge plain "hysteria" (v1), a different incompatible protocol
            if (proto == "shadowsocks") return "ss";
            if (proto == "wg") return "wireguard";
            return proto;
        }

        private static Dictionary<string, string> ParseQuery(string query)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(query)) return result;
            foreach (var pair in query.TrimStart('?').Split('&'))
            {
                var kv = pair.Split('=', 2);
                if (kv.Length == 2)
                    result[Uri.UnescapeDataString(kv[0])] = Uri.UnescapeDataString(kv[1]);
            }
            return result;
        }
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
                return $"{NP(Protocol)}:{hostKey}:{portKey}:{CredKey(Protocol, Credential)}:{Network.ToLowerInvariant()}:{Security.ToLowerInvariant()}:{sniKey}:{Path.Trim().ToLowerInvariant()}:{Pbk.ToLowerInvariant()}:{Sid.ToLowerInvariant()}:{Flow.Trim().ToLowerInvariant()}:{ObfsPassword}";
            }
        }
		
        // Same identity as DeduplicationKey, but with the host component replaced by a
        // caller-supplied canonical form (the resolved IP) — used by alias collapse to
        // merge IP-literal vs hostname spellings of one endpoint.
        public string EndpointKey(string canonicalHost)
        {
            string portKey = int.TryParse(Port, out int pn) ? pn.ToString() : Port.Trim();
            string sniKey  = string.IsNullOrEmpty(Sni) ? canonicalHost : Sni.Trim().ToLowerInvariant();
            return $"{NP(Protocol)}:{canonicalHost.ToLowerInvariant()}:{portKey}:{CredKey(Protocol, Credential)}:{Network.ToLowerInvariant()}:{Security.ToLowerInvariant()}:{sniKey}:{Path.Trim().ToLowerInvariant()}:{Pbk.ToLowerInvariant()}:{Sid.ToLowerInvariant()}:{Flow.Trim().ToLowerInvariant()}:{ObfsPassword}";        }

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
