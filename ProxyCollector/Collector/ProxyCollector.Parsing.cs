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
using ProxyCollector.Configuration;
using ProxyCollector.Services;
using YamlDotNet.Serialization;

namespace ProxyCollector.Collector
{
    public partial class ProxyCollector
    {
        internal static ParsedProxy? ParseProxyLine(string line)
        {
            var parsed = ParseProxyLineCore(line);
            if (parsed is null ||
                !int.TryParse(parsed.Port, out int port) ||
                port is < 1 or > 65535)
                return null;

            string protocol = parsed.Protocol.ToLowerInvariant();
            if (protocol == "vless" && !IsValidVlessCredential(parsed.Credential))
                return null;
            if (protocol == "vmess" && !IsValidVmessCredential(parsed.Credential))
                return null;

            // Keep the original display metadata separately from the connection URI.
            // BaseLink intentionally excludes URI fragments for canonical parsing, but the
            // Cloudflare/WARP policy still needs the source label before output renaming.
            parsed.SourceRemark = ExtractSourceRemark(line, parsed);

            // Store a canonical numeric port for deduplication and probes. The published
            // URI remains the source form, but invalid source ports are never accepted.
            parsed.Port = port.ToString();
            return parsed;
        }

        private static string ExtractSourceRemark(string sourceLine, ParsedProxy parsed)
        {
            string safeSourceLine = sourceLine ?? "";
            int fragment = safeSourceLine.IndexOf('#');
            if (fragment >= 0 && fragment < safeSourceLine.Length - 1)
            {
                string raw = safeSourceLine[(fragment + 1)..].Trim();
                try { return Uri.UnescapeDataString(raw); }
                catch { return raw; }
            }

            string protocol = NormalizeProto(parsed.Protocol);
            if (protocol == "vmess")
            {
                var json = TryGetVmessJson(parsed.BaseLink);
                return GetVmessJsonString(json, "ps");
            }

            if (protocol == "ssr")
            {
                try
                {
                    string decoded = Base64UrlDecode(parsed.BaseLink["ssr://".Length..]);
                    int slash = decoded.IndexOf('/');
                    if (slash < 0) return "";
                    int queryStart = decoded.IndexOf('?', slash);
                    if (queryStart < 0 || queryStart == decoded.Length - 1) return "";
                    var query = ParseQuery(decoded[(queryStart + 1)..]);
                    string token = query.GetValueOrDefault("remarks_base64",
                        query.GetValueOrDefault("remarks", ""));
                    if (token.Length == 0) return "";

                    try
                    {
                        string label = Base64UrlDecode(token);
                        return label.Length > 0 &&
                               label.All(ch => !char.IsControl(ch) || ch is '\r' or '\n' or '\t')
                            ? label
                            : token;
                    }
                    catch { return token; }
                }
                catch { return ""; }
            }

            return "";
        }

        // Xray VLESS accepts a UUID or a custom ID shorter than 30 UTF-8 bytes.
        // Custom strings are mapped to UUIDv5 by Xray.
        internal static bool IsValidVlessCredential(string? credential)
            => !string.IsNullOrWhiteSpace(credential) &&
               (Guid.TryParseExact(credential, "D", out _) ||
                Encoding.UTF8.GetByteCount(credential) < 30);

        // Xray VMess accepts either a UUID or a custom ID shorter than 30 UTF-8 bytes.
        // Unlike VLESS, VMess custom IDs are valid and are mapped by Xray internally.
        internal static bool IsValidVmessCredential(string? credential)
            => !string.IsNullOrWhiteSpace(credential) &&
               (Guid.TryParseExact(credential, "D", out _) ||
                Encoding.UTF8.GetByteCount(credential) < 30);

        private static ParsedProxy? ParseProxyLineCore(string line)
        {
            line = line.Trim();
            if (line.Length < 10) return null;

            int hashIdx = line.IndexOf('#');
            string baseLink = hashIdx >= 0 ? line[..hashIdx].Trim() : line.Trim();
            if (string.IsNullOrEmpty(baseLink)) return null;
            // A literal whitespace inside the URI (for example before @ in userinfo)
            // is malformed. Encoded spaces (%20) remain valid; remarks after # were
            // already removed above.
            if (baseLink.Any(char.IsWhiteSpace)) return null;

            if (baseLink.StartsWith("mieru://", StringComparison.OrdinalIgnoreCase))
                return null; // standard mieru:// is a Base64 protobuf profile, not a host URI
            if (baseLink.StartsWith("mierus://", StringComparison.OrdinalIgnoreCase))
                return ParseMieruSimpleLink(baseLink);

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
                    // VMess "host" is commonly the WebSocket HTTP Host header, not
                    // TLS SNI. Keep the two settings separate; Xray falls back to the
                    // endpoint hostname when no explicit "sni" is present.
                    string sni = r.TryGetProperty("sni", out var sniEl)
                        ? (sniEl.GetString() ?? "") : "";
                    string path = r.TryGetProperty("path", out var pathEl) ? (pathEl.GetString() ?? "") : "";
                    int aid = 0;
                    if (r.TryGetProperty("aid", out var aidEl))
                    {
                        if (aidEl.ValueKind == JsonValueKind.Number) aid = aidEl.GetInt32();
                        else if (aidEl.ValueKind == JsonValueKind.String)
                            int.TryParse(aidEl.GetString(), out aid);
                    }

                    if (string.IsNullOrEmpty(host) || host == "0.0.0.0") return null;

                    return new ParsedProxy
                    {
                        Protocol = "vmess", Host = host, Port = port,
                        Credential = uuid, Network = net, Security = tls,
                        Sni = sni, Path = path, Aid = aid, BaseLink = baseLink,
                        ConnectionOptionsKey = BuildJsonIdentityKey(r, excludeNormalizedFields: true),
                        LegacyConnectionOptionsKey = BuildJsonIdentityKey(r)
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
                    // Do not silently turn an explicit port 0 into a default port.
                    if (uri.Port == 0) return null;
                    var q = ParseQuery(uri.Query);
                    string net = q.GetValueOrDefault("type", "tcp");
                    if (string.IsNullOrEmpty(net)) net = "tcp";
                    string sec = q.GetValueOrDefault("security", "");
                    if (sec.Equals("none", StringComparison.OrdinalIgnoreCase)) sec = "";
                    // URI-form VMess follows the same rule as other URI protocols:
                    // the transport Host header is not an implicit TLS SNI.
                    string host = NormalizeUriHost(uri.Host);
                    string sni = q.GetValueOrDefault("sni", "");
                    return new ParsedProxy
                    {
                        Protocol = "vmess", Host = host,
                        Port = (uri.Port > 0 ? uri.Port : 443).ToString(),
                        Credential = Uri.UnescapeDataString(uri.UserInfo ?? ""),
                        Network = net, Security = sec,
                        Sni = sni, Path = q.GetValueOrDefault("path", ""),
                        Aid = int.TryParse(q.GetValueOrDefault("aid", "0"), out var a) ? a : 0,
                        BaseLink = baseLink,
                        ConnectionOptionsKey = BuildProxyUriOptionsKey(uri.Query, host, net, sec, sni,
                            q.GetValueOrDefault("headerType", "none"),
                            "security", "type", "sni", "path", "aid"),
                        LegacyConnectionOptionsKey = BuildQueryIdentityKey(uri.Query)
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
                // Do not silently turn an explicit port 0 into a default port.
                if (uri.Port == 0) return null;
                string scheme = uri.Scheme.ToLowerInvariant();
                if (!ValidProtocols.Contains(scheme)) return null;

                // Uri.Host returns bracketed IPv6 literals on .NET. Normalize to a
                // bare IP here so DNS, GeoIP, reserved-range and Cloudflare checks agree
                // with the host spelling used by the Shadowsocks parser.
                string h = NormalizeUriHost(uri.Host);
                // Per-scheme default port when the link omits one — "socks5://host" means
                // 1080, not 443. Uri.Port is -1 when the link carries no port.
                int p = uri.Port > 0 ? uri.Port
                    : scheme switch { "socks" or "socks5" or "socks4" => 1080,
                                      "brook" => 9999, "snell" => 61825,
                                      "wireguard" or "wg" => 51820, _ => 443 };
                if (string.IsNullOrEmpty(h) || h == "0.0.0.0") return null;

                var q = ParseQuery(uri.Query);
                string sec  = q.GetValueOrDefault("security", "");
                if (sec.Equals("none", StringComparison.OrdinalIgnoreCase)) sec = ""; // "security=none" and no security param at all mean the same thing
                string net  = q.GetValueOrDefault("type", "tcp");
                if (string.IsNullOrEmpty(net)) net = "tcp"; // GetValueOrDefault only falls back when the key is ABSENT — an explicit "type=" (present, empty) slipped through otherwise
                // "host" is a transport HTTP Host/authority override, not an implicit TLS SNI.
                // The TLS layer falls back to the endpoint hostname when SNI is absent.
                string sni  = q.GetValueOrDefault("sni", "");
                string path = q.GetValueOrDefault("path", "");
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
                string cred = Uri.UnescapeDataString(uri.UserInfo ?? "");
                if (string.IsNullOrEmpty(cred) && scheme == "hysteria")
                    cred = q.GetValueOrDefault("auth", "");

                // A WireGuard link can contain more source-specific/unknown query options
                // than the exporter actually emits. Use the effective parsed tunnel as its
                // identity so variants that produce the same downloadable config collapse
                // in the master catalogue and every derived feed, not only in wireguard/.
                WgInfo? wireguardInfo = null;
                if (scheme is "wireguard" or "wg")
                {
                    wireguardInfo = TryParseWireguardInfo(baseLink);
                    if (wireguardInfo != null)
                    {
                        h = NormalizeUriHost(wireguardInfo.Host);
                        p = wireguardInfo.Port;
                        cred = wireguardInfo.PrivateKey ?? cred;
                        pbk = wireguardInfo.PublicKey ?? pbk;

                        // These generic URI fields describe TLS/stream transports and
                        // are not consumed by a WireGuard tunnel. Do not let stray
                        // source decorations keep identical exported tunnels apart.
                        net = "udp";
                        sec = "";
                        sni = "";
                        path = "";
                        sid = "";
                        flow = "";
                        obfsPwd = "";
                    }
                    else if (string.IsNullOrEmpty(cred))
                    {
                        cred = q.GetValueOrDefault("privatekey",
                            q.GetValueOrDefault("private_key", ""));
                    }
                }

                // For ordinary URI proxy schemes, DNS/MTU and other unrecognized
                // query options remain identity-significant unless explicitly normalized.
                // Valid WireGuard profiles instead use GetWireguardOutputIdentityKey above:
                // that key preserves every setting FastNodes exports and omits local DNS,
                // MTU, and source-only decorations the exporters do not consume.
                string[] identityExcludedOptions = new[]
                    {
                        "security", "type", "sni", "path", "pbk", "sid", "flow",
                        "obfs-password", "auth"
                    }
                    .Concat(scheme is "wireguard" or "wg"
                        ? new[] { "dns", "mtu" }
                        : Array.Empty<string>())
                    .ToArray();

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
                    BaseLink   = baseLink,
                    ConnectionOptionsKey = wireguardInfo != null
                        ? GetWireguardOutputIdentityKey(wireguardInfo, includeReserved: true)
                        : BuildProxyUriOptionsKey(uri.Query, h, net, sec, sni,
                            q.GetValueOrDefault("headerType", "none"),
                            identityExcludedOptions),
                    LegacyConnectionOptionsKey = BuildQueryIdentityKey(uri.Query)
                };
            }
            catch { return null; }
        }

        private static bool IsValidMieruPortBinding(string? value, out int firstPort)
        {
            firstPort = 0;
            string[] parts = (value ?? "").Trim().Split('-', StringSplitOptions.None);
            if (parts.Length is < 1 or > 2 ||
                !int.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out firstPort) ||
                firstPort is < 1 or > 65535)
                return false;
            return parts.Length == 1 ||
                (int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out int lastPort) &&
                 lastPort >= firstPort && lastPort <= 65535);
        }

        private static List<(string Key, string Value)> ParseQueryPairs(string query)
        {
            var pairs = new List<(string Key, string Value)>();
            if (string.IsNullOrEmpty(query)) return pairs;
            foreach (string raw in query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
            {
                int separator = raw.IndexOf('=');
                if (separator < 0) continue;
                pairs.Add((Uri.UnescapeDataString(raw[..separator]), Uri.UnescapeDataString(raw[(separator + 1)..])));
            }
            return pairs;
        }

        private static string BuildMieruSimpleLink(
            string server, string username, string password, string portBinding,
            string transport, IEnumerable<(string Key, string Value)> commonParameters, string remark)
        {
            var query = commonParameters
                .Where(item => !item.Key.Equals("port", StringComparison.OrdinalIgnoreCase) &&
                               !item.Key.Equals("protocol", StringComparison.OrdinalIgnoreCase))
                .Select(item => Uri.EscapeDataString(item.Key) + "=" + Uri.EscapeDataString(item.Value))
                .ToList();
            query.Add("port=" + Uri.EscapeDataString(portBinding));
            query.Add("protocol=" + Uri.EscapeDataString(transport.ToUpperInvariant()));
            string userInfo = Uri.EscapeDataString(username) + ":" + Uri.EscapeDataString(password);
            string label = string.IsNullOrEmpty(remark) ? "" : "#" + Uri.EscapeDataString(remark);
            return $"mierus://{userInfo}@{FormatUriHost(server)}?{string.Join("&", query)}{label}";
        }

        private static List<string> ExpandMieruSimpleLink(string link)
        {
            var results = new List<string>();
            try
            {
                var uri = new Uri(link);
                if (!uri.Scheme.Equals("mierus", StringComparison.OrdinalIgnoreCase)) return results;
                var pairs = ParseQueryPairs(uri.Query);
                var ports = pairs.Where(x => x.Key.Equals("port", StringComparison.OrdinalIgnoreCase)).ToArray();
                var protocols = pairs.Where(x => x.Key.Equals("protocol", StringComparison.OrdinalIgnoreCase)).ToArray();
                var profiles = pairs.Where(x => x.Key.Equals("profile", StringComparison.OrdinalIgnoreCase)).ToArray();
                if (profiles.Length != 1 || string.IsNullOrWhiteSpace(profiles[0].Value) ||
                    ports.Length == 0 || ports.Length != protocols.Length)
                    return results;
                foreach (string singleton in new[] { "mtu", "multiplexing", "handshake-mode", "traffic-pattern" })
                    if (pairs.Count(x => x.Key.Equals(singleton, StringComparison.OrdinalIgnoreCase)) > 1)
                        return results;

                string userInfo = Uri.UnescapeDataString(uri.GetComponents(UriComponents.UserInfo, UriFormat.UriEscaped));
                int separator = userInfo.IndexOf(':');
                if (separator <= 0 || separator == userInfo.Length - 1) return results;
                string username = userInfo[..separator], password = userInfo[(separator + 1)..];
                if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password)) return results;
                string remark = uri.Fragment.Length > 1 ? Uri.UnescapeDataString(uri.Fragment[1..]) : "";
                var common = pairs.Where(x =>
                    !x.Key.Equals("port", StringComparison.OrdinalIgnoreCase) &&
                    !x.Key.Equals("protocol", StringComparison.OrdinalIgnoreCase)).ToList();

                for (int i = 0; i < ports.Length; i++)
                {
                    string transport = protocols[i].Value.Trim().ToUpperInvariant();
                    if (!IsValidMieruPortBinding(ports[i].Value, out _) || transport is not ("TCP" or "UDP"))
                        return new List<string>();
                    results.Add(BuildMieruSimpleLink(uri.Host, username, password, ports[i].Value, transport, common, remark));
                }
            }
            catch { return new List<string>(); }
            return results;
        }

        private static bool TryReadMieruVarint(byte[] data, ref int offset, out ulong value)
        {
            value = 0;
            int shift = 0;
            while (offset < data.Length && shift < 64)
            {
                byte current = data[offset++];
                value |= (ulong)(current & 0x7F) << shift;
                if ((current & 0x80) == 0) return true;
                shift += 7;
            }
            return false;
        }

        private static List<(int Field, int Wire, ulong Number, byte[] Bytes)> ReadMieruProtoFields(byte[] data)
        {
            var fields = new List<(int, int, ulong, byte[])>();
            int offset = 0;
            while (offset < data.Length)
            {
                if (!TryReadMieruVarint(data, ref offset, out ulong tag) || tag == 0)
                    throw new FormatException("Invalid Mieru protobuf tag.");
                int field = (int)(tag >> 3), wire = (int)(tag & 7);
                if (field <= 0) throw new FormatException("Invalid Mieru protobuf field.");
                if (wire == 0)
                {
                    if (!TryReadMieruVarint(data, ref offset, out ulong number))
                        throw new FormatException("Truncated Mieru protobuf varint.");
                    fields.Add((field, wire, number, Array.Empty<byte>()));
                }
                else if (wire == 2)
                {
                    if (!TryReadMieruVarint(data, ref offset, out ulong length) ||
                        length > (ulong)(data.Length - offset) || length > 1_048_576)
                        throw new FormatException("Invalid Mieru protobuf length.");
                    int count = (int)length;
                    fields.Add((field, wire, 0, data.AsSpan(offset, count).ToArray()));
                    offset += count;
                }
                else if (wire == 1 || wire == 5)
                {
                    int count = wire == 1 ? 8 : 4;
                    if (data.Length - offset < count) throw new FormatException("Truncated Mieru protobuf fixed field.");
                    offset += count;
                }
                else throw new FormatException("Unsupported Mieru protobuf wire type.");
            }
            return fields;
        }

        private static string? MieruProtoString(List<(int Field, int Wire, ulong Number, byte[] Bytes)> fields, int field)
        {
            var item = fields.LastOrDefault(x => x.Field == field && x.Wire == 2);
            return item.Bytes is { Length: > 0 } ? Encoding.UTF8.GetString(item.Bytes) : null;
        }

        private static List<string> ExpandMieruProtobufShare(string link)
        {
            var results = new List<string>();
            try
            {
                const string prefix = "mieru://";
                if (!link.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)) return results;
                string encoded = link[prefix.Length..].Trim();
                int fragment = encoded.IndexOf('#');
                if (fragment >= 0) encoded = encoded[..fragment];
                encoded = encoded.Replace('-', '+').Replace('_', '/');
                int padding = encoded.Length % 4;
                if (padding == 1) return results;
                if (padding > 0) encoded += new string('=', 4 - padding);
                byte[] payload = Convert.FromBase64String(encoded);
                if (payload.Length is 0 or > 1_048_576) return results;

                var root = ReadMieruProtoFields(payload);
                foreach (var profileField in root.Where(x => x.Field == 1 && x.Wire == 2))
                {
                    var profile = ReadMieruProtoFields(profileField.Bytes);
                    string profileName = MieruProtoString(profile, 1) ?? "default";
                    var userField = profile.LastOrDefault(x => x.Field == 2 && x.Wire == 2);
                    if (userField.Bytes is null || userField.Bytes.Length == 0) continue;
                    var user = ReadMieruProtoFields(userField.Bytes);
                    string? username = MieruProtoString(user, 1);
                    string? password = MieruProtoString(user, 2);
                    if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password)) continue;

                    // Simple sharing links have no dialer field. A profile that
                    // requires a proxy dialer must not be silently converted into a
                    // direct connection with different routing semantics.
                    if (profile.Any(x => x.Field == 8 && x.Wire == 2))
                        continue;

                    foreach (var serverField in profile.Where(x => x.Field == 3 && x.Wire == 2))
                    {
                        var server = ReadMieruProtoFields(serverField.Bytes);
                        string? host = MieruProtoString(server, 2) ?? MieruProtoString(server, 1);
                        if (string.IsNullOrWhiteSpace(host)) continue;
                        // The official simple-share format supports the profile's
                        // MTU, multiplexing, handshake mode and traffic pattern. Preserve
                        // every supported option when expanding the binary protobuf link.
                        var common = new List<(string Key, string Value)> { ("profile", profileName) };
                        var mtu = profile.LastOrDefault(x => x.Field == 4 && x.Wire == 0);
                        if (mtu.Number is >= 1280 and <= 1400)
                            common.Add(("mtu", mtu.Number.ToString(CultureInfo.InvariantCulture)));

                        var multiplexingField = profile.LastOrDefault(x => x.Field == 5 && x.Wire == 2);
                        if (multiplexingField.Bytes is { Length: > 0 })
                        {
                            var multiplexing = ReadMieruProtoFields(multiplexingField.Bytes);
                            var level = multiplexing.LastOrDefault(x => x.Field == 1 && x.Wire == 0);
                            string? levelName = level.Number switch
                            {
                                1 => "MULTIPLEXING_OFF",
                                2 => "MULTIPLEXING_LOW",
                                3 => "MULTIPLEXING_MIDDLE",
                                4 => "MULTIPLEXING_HIGH",
                                _ => null
                            };
                            if (levelName is not null) common.Add(("multiplexing", levelName));
                        }

                        var handshake = profile.LastOrDefault(x => x.Field == 6 && x.Wire == 0);
                        string? handshakeName = handshake.Number switch
                        {
                            1 => "HANDSHAKE_STANDARD",
                            2 => "HANDSHAKE_NO_WAIT",
                            _ => null
                        };
                        if (handshakeName is not null) common.Add(("handshake-mode", handshakeName));

                        var trafficPattern = profile.LastOrDefault(x => x.Field == 7 && x.Wire == 2);
                        if (trafficPattern.Bytes is { Length: > 0 })
                            common.Add(("traffic-pattern", Convert.ToBase64String(trafficPattern.Bytes)));

                        foreach (var bindingField in server.Where(x => x.Field == 3 && x.Wire == 2))
                        {
                            var binding = ReadMieruProtoFields(bindingField.Bytes);
                            var portField = binding.LastOrDefault(x => x.Field == 1 && x.Wire == 0);
                            var protocolField = binding.LastOrDefault(x => x.Field == 2 && x.Wire == 0);
                            string? range = MieruProtoString(binding, 3);
                            string port = range ?? (portField.Number > 0 && portField.Number <= 65535
                                ? portField.Number.ToString(CultureInfo.InvariantCulture) : "");
                            string transport = protocolField.Number switch { 1 => "UDP", 2 => "TCP", _ => "" };
                            if (port.Length == 0 || transport.Length == 0 || !IsValidMieruPortBinding(port, out _))
                                continue;
                            results.Add(BuildMieruSimpleLink(host, username, password, port, transport, common, profileName));
                        }
                    }
                }
            }
            catch { return new List<string>(); }
            return results;
        }

        private static ParsedProxy? ParseMieruSimpleLink(string baseLink)
        {
            try
            {
                var uri = new Uri(baseLink);
                var pairs = ParseQueryPairs(uri.Query);
                var ports = pairs.Where(x => x.Key.Equals("port", StringComparison.OrdinalIgnoreCase)).ToArray();
                var protocols = pairs.Where(x => x.Key.Equals("protocol", StringComparison.OrdinalIgnoreCase)).ToArray();
                var profiles = pairs.Where(x => x.Key.Equals("profile", StringComparison.OrdinalIgnoreCase)).ToArray();
                if (ports.Length != 1 || protocols.Length != 1 || profiles.Length != 1 ||
                    string.IsNullOrWhiteSpace(profiles[0].Value) ||
                    !IsValidMieruPortBinding(ports[0].Value, out int firstPort) ||
                    !(protocols[0].Value.Equals("TCP", StringComparison.OrdinalIgnoreCase) ||
                      protocols[0].Value.Equals("UDP", StringComparison.OrdinalIgnoreCase)))
                    return null;

                string userInfo = Uri.UnescapeDataString(uri.GetComponents(UriComponents.UserInfo, UriFormat.UriEscaped));
                int separator = userInfo.IndexOf(':');
                if (separator <= 0 || separator == userInfo.Length - 1) return null;
                string username = userInfo[..separator], password = userInfo[(separator + 1)..];
                if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password)) return null;

                return new ParsedProxy
                {
                    Protocol = "mieru",
                    Host = NormalizeUriHost(uri.Host),
                    Port = firstPort.ToString(CultureInfo.InvariantCulture),
                    Credential = username + ":" + password,
                    Network = protocols[0].Value.ToLowerInvariant(),
                    BaseLink = baseLink,
                    ConnectionOptionsKey = BuildCanonicalQueryIdentityKey(uri.Query, "profile"),
                    LegacyConnectionOptionsKey = BuildQueryIdentityKey(uri.Query)
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

                // host:port:protocol:method:obfs:base64(password). IPv6 literals
                // must be bracketed in this colon-delimited format; split after the
                // closing bracket so the address's own colons aren't mistaken for fields.
                string host, port, protocol, method, obfs, encodedPassword;
                if (main.StartsWith("[", StringComparison.Ordinal))
                {
                    int closeBracket = main.IndexOf(']');
                    if (closeBracket <= 1 || closeBracket + 1 >= main.Length ||
                        main[closeBracket + 1] != ':')
                        return null;

                    host = main[1..closeBracket];
                    if (!IPAddress.TryParse(host, out var ipv6Host) ||
                        ipv6Host.AddressFamily != AddressFamily.InterNetworkV6)
                        return null;
                    host = ipv6Host.ToString();

                    var parts = main[(closeBracket + 2)..].Split(':');
                    if (parts.Length != 5) return null;
                    port = parts[0];
                    protocol = parts[1];
                    method = parts[2];
                    obfs = parts[3];
                    encodedPassword = parts[4];
                }
                else
                {
                    var parts = main.Split(':');
                    if (parts.Length != 6) return null;
                    host = parts[0];
                    port = parts[1];
                    protocol = parts[2];
                    method = parts[3];
                    obfs = parts[4];
                    encodedPassword = parts[5];
                }

                string password = Base64UrlDecode(encodedPassword);
                if (string.IsNullOrEmpty(host) || host == "0.0.0.0" ||
                    string.IsNullOrWhiteSpace(protocol) || string.IsNullOrWhiteSpace(method) ||
                    string.IsNullOrWhiteSpace(obfs) || string.IsNullOrEmpty(password) ||
                    !int.TryParse(port, out int portNumber) || portNumber is < 1 or > 65535)
                    return null;

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
                    BaseLink = baseLink,
                    ConnectionOptionsKey = BuildCanonicalQueryIdentityKey(query,
                        "remarks", "remarks_base64", "obfsparam", "protoparam"),
                    LegacyConnectionOptionsKey = BuildQueryIdentityKey(query, "remarks", "remarks_base64")
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

                    if (string.IsNullOrWhiteSpace(method) || string.IsNullOrEmpty(password)) return null;

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
                        BaseLink = baseLink,
                        ConnectionOptionsKey = BuildCanonicalQueryIdentityKey(query, "host"),
                        LegacyConnectionOptionsKey = BuildQueryIdentityKey(query)
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
                if (string.IsNullOrWhiteSpace(method2) || string.IsNullOrEmpty(password2)) return null;

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
                    BaseLink = baseLink, ConnectionOptionsKey = "", LegacyConnectionOptionsKey = ""
                };
            }
            catch { return null; }
        }

        // These options change only the local client interface or display metadata;
        // they do not identify a different remote proxy service. They are intentionally
        // omitted from current exact and compact identities, but are left in the original
        // share link so the selected representative keeps its source settings.
        private static readonly HashSet<string> NonIdentityQueryOptions = new(StringComparer.OrdinalIgnoreCase)
        {
            "dns", "mtu",
            "name", "tag", "remark", "remarks", "remarks_base64", "ps", "group",
            "country", "city", "region", "flag", "emoji", "display-name", "displayname"
        };

        private static string BuildQueryIdentityKey(string query, params string[] excludedKeys)
            // Preserve the pre-canonicalization behavior for the history migration key.
            => BuildQueryIdentityKeyCore(query, null, null, null, null, null,
                normalizeDefaults: false, decodeQueryForm: false, excludedKeys: excludedKeys);

        // Canonicalize URI options that are explicitly set to the protocol's default.
        // This is intentionally conservative: meaningful non-default values such as a
        // different WebSocket Host, HTTP obfuscation host, or allowInsecure=true remain
        // part of identity.
        private static string BuildProxyUriOptionsKey(
            string query, string endpointHost, string network, string security, string sni, string headerType,
            params string[] excludedKeys)
            => BuildQueryIdentityKeyCore(query, endpointHost, network, security, sni, headerType,
                normalizeDefaults: true, decodeQueryForm: true, excludedKeys: excludedKeys);

        private static string BuildCanonicalQueryIdentityKey(string query, params string[] excludedKeys)
            => BuildQueryIdentityKeyCore(query, null, null, null, null, null,
                normalizeDefaults: true, decodeQueryForm: true, excludedKeys: excludedKeys);

        private static string BuildQueryIdentityKeyCore(
            string query, string? endpointHost, string? network, string? security, string? sni,
            string? headerType, bool normalizeDefaults, bool decodeQueryForm, string[] excludedKeys)
        {
            if (string.IsNullOrEmpty(query)) return "";
            var excluded = new HashSet<string>(excludedKeys, StringComparer.OrdinalIgnoreCase);
            var queryParameters = query.TrimStart('?')
                .Split('&', StringSplitOptions.RemoveEmptyEntries)
                .Select(pair =>
                {
                    int equals = pair.IndexOf('=');
                    string rawKey = equals < 0 ? pair : pair[..equals];
                    string rawValue = equals < 0 ? "" : pair[(equals + 1)..];
                    return new
                    {
                        Key = UnescapeQueryComponent(rawKey, decodeQueryForm).ToLowerInvariant(),
                        Value = UnescapeQueryComponent(rawValue, decodeQueryForm)
                    };
                })
                .ToArray();
            bool tcpWithoutHttpHeader = normalizeDefaults &&
                string.Equals(network, "tcp", StringComparison.OrdinalIgnoreCase) &&
                (string.IsNullOrWhiteSpace(headerType) ||
                 string.Equals(headerType, "none", StringComparison.OrdinalIgnoreCase));
            bool normalizesDefaultHost = normalizeDefaults &&
                (string.Equals(network, "ws", StringComparison.OrdinalIgnoreCase) ||
                 string.Equals(network, "httpupgrade", StringComparison.OrdinalIgnoreCase) ||
                 tcpWithoutHttpHeader);
            string normalizedEndpoint = string.IsNullOrWhiteSpace(endpointHost)
                ? ""
                : ProxyCollector.NormalizeIdentityHost(endpointHost);
            string normalizedHostFallback = normalizedEndpoint;
            // HTTPUpgrade falls back to TLS serverName before the endpoint address;
            // WebSocket falls back directly to address. Keep that distinction.
            if (string.Equals(network, "httpupgrade", StringComparison.OrdinalIgnoreCase) &&
                string.Equals(security, "tls", StringComparison.OrdinalIgnoreCase) &&
                !string.IsNullOrWhiteSpace(sni))
                normalizedHostFallback = ProxyCollector.NormalizeIdentityHost(sni);
            // Do not discard an explicit host when a separate custom-header option
            // could also specify Host; Xray gives the explicit host precedence.
            bool hasCustomHeaders = normalizeDefaults && queryParameters.Any(item =>
                item.Key.Equals("header", StringComparison.OrdinalIgnoreCase) ||
                item.Key.Equals("headers", StringComparison.OrdinalIgnoreCase));
            // Preserve repeated parameters and their order within each key. ParseQuery's
            // dictionary is convenient for known fields, but keeps only the last duplicate
            // value; different plugins/transports may assign meaning to repeated options.
            // Sorting by key removes irrelevant ordering differences between separate names
            // while retaining the original order of repeated values for the same name.
            var canonical = queryParameters
                .Where(item => !excluded.Contains(item.Key))
                .Where(item =>
                {
                    // Keep the historical identity schema untouched for the one-run
                    // ranking-history migration, but remove known client-local and
                    // display-only options from every current identity.
                    if (normalizeDefaults && NonIdentityQueryOptions.Contains(item.Key))
                        return false;

                    // An omitted VLESS encryption option and encryption=none are the
                    // same protocol default. Non-default encryption values remain.
                    if (normalizeDefaults && item.Key == "encryption" &&
                        (string.IsNullOrWhiteSpace(item.Value) ||
                         item.Value.Equals("none", StringComparison.OrdinalIgnoreCase)))
                        return false;

                    // Xray's default for certificate validation is secure: explicit false
                    // and an omitted flag are the same client behavior.
                    if (normalizeDefaults && (item.Key is "allowinsecure" or "insecure") &&
                        (item.Value.Equals("0", StringComparison.OrdinalIgnoreCase) ||
                         item.Value.Equals("false", StringComparison.OrdinalIgnoreCase)))
                        return false;

                    // A raw TCP transport with headerType=none never consumes Host.
                    if (item.Key == "host" && tcpWithoutHttpHeader && !hasCustomHeaders)
                        return false;

                    // An explicit Host equal to the transport's effective fallback is
                    // redundant. HTTPUpgrade may fall back to TLS serverName; WebSocket
                    // falls back to address.
                    if (item.Key == "host" && normalizesDefaultHost && !tcpWithoutHttpHeader &&
                        !hasCustomHeaders && normalizedHostFallback.Length > 0 &&
                        string.Equals(
                            ProxyCollector.NormalizeIdentityHost(item.Value),
                            normalizedHostFallback,
                            StringComparison.Ordinal))
                        return false;

                    // TCP's header type defaults to "none".
                    if (item.Key == "headertype" && tcpWithoutHttpHeader &&
                        item.Value.Equals("none", StringComparison.OrdinalIgnoreCase))
                        return false;

                    return true;
                })
                .OrderBy(item => item.Key, StringComparer.Ordinal)
                .Select(item => new[] { item.Key, item.Value })
                .ToArray();
            return JsonSerializer.Serialize(canonical);
        }

        // Go net/url.QueryUnescape (used by Xray's URI query parsing) treats '+' as
        // a space. System.Uri.UnescapeDataString does not, so use this for actual query
        // parsing and canonical profile identity. Legacy history keys deliberately keep
        // the old decoding mode to preserve one-run migration compatibility.
        private static string UnescapeQueryComponent(string value, bool decodeQueryForm = true)
            => Uri.UnescapeDataString(decodeQueryForm
                ? value.Replace("+", " ", StringComparison.Ordinal)
                : value);

        private static string BuildJsonIdentityKey(JsonElement root, bool excludeNormalizedFields = false)
        {
            if (root.ValueKind != JsonValueKind.Object) return "";
            // VMess "ps" is display-only. Fields represented in ParsedProxy separately
            // are excluded from the option fingerprint; unknown/plugin fields are kept.
            string[] normalizedFields =
            {
                "v", "add", "port", "id", "aid", "net", "tls", "sni", "path"
            };
            string[] localAndDisplayFields =
            {
                "dns", "mtu", "name", "tag", "remark", "remarks", "group",
                "country", "city", "region", "flag", "emoji", "display-name", "displayname"
            };
            var canonical = root.EnumerateObject()
                .Where(property =>
                    !property.Name.Equals("ps", StringComparison.OrdinalIgnoreCase) &&
                    (!excludeNormalizedFields ||
                     (!normalizedFields.Contains(property.Name, StringComparer.OrdinalIgnoreCase) &&
                      !localAndDisplayFields.Contains(property.Name, StringComparer.OrdinalIgnoreCase) &&
                      !IsExplicitFalseJsonOption(property))))
                .OrderBy(property => property.Name, StringComparer.OrdinalIgnoreCase)
                .ThenBy(property => property.Name, StringComparer.Ordinal)
                .Select(property => new
                {
                    Name = property.Name.ToLowerInvariant(),
                    Value = property.Value.Clone()
                })
                .ToArray();
            return JsonSerializer.Serialize(canonical);
        }

        private static bool IsExplicitFalseJsonOption(JsonProperty property)
        {
            if (!property.Name.Equals("allowInsecure", StringComparison.OrdinalIgnoreCase) &&
                !property.Name.Equals("insecure", StringComparison.OrdinalIgnoreCase))
                return false;

            return property.Value.ValueKind == JsonValueKind.False ||
                (property.Value.ValueKind == JsonValueKind.String &&
                 property.Value.GetString() is { } text &&
                 (text.Equals("false", StringComparison.OrdinalIgnoreCase) || text == "0")) ||
                (property.Value.ValueKind == JsonValueKind.Number &&
                 property.Value.TryGetInt32(out int number) && number == 0);
        }

        private static string NormalizeUriHost(string host)
        {
            // Uri.Host can include brackets around IPv6 literals. ParsedProxy stores
            // the bare address consistently for resolver, GeoIP and family checks.
            return host.Length >= 2 && host[0] == '[' && host[^1] == ']'
                ? host[1..^1]
                : host;
        }

        internal static string NormalizeIdentityHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host)) return "";
            string value = host.Trim().Trim('[', ']');
            if (IPAddress.TryParse(value, out var address))
            {
                if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
                return address.ToString().ToLowerInvariant();
            }

            value = value.TrimEnd('.');
            if (value.Length == 0) return "";
            try { return new IdnMapping().GetAscii(value).ToLowerInvariant(); }
            catch { return value.ToLowerInvariant(); }
        }

        internal static string NormalizeProto(string proto)
        {
            if (string.IsNullOrEmpty(proto)) return "unknown";
            proto = proto.ToLowerInvariant();
            if (proto == "hy2") return "hysteria2"; // alias only — do NOT merge plain "hysteria" (v1), a different incompatible protocol
            if (proto == "shadowsocks") return "ss";
            if (proto == "wg") return "wireguard";
            if (proto == "mierus") return "mieru";
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
                    result[UnescapeQueryComponent(kv[0])] = UnescapeQueryComponent(kv[1]);
            }
            return result;
        }
    }
}
