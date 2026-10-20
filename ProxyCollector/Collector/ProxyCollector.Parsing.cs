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
    public partial class ProxyCollector
    {
        internal static ParsedProxy? ParseProxyLine(string line)
        {
            var parsed = ParseProxyLineCore(line);
            if (parsed is null ||
                !int.TryParse(parsed.Port, out int port) ||
                port is < 1 or > 65535)
                return null;

            // Store a canonical numeric port for deduplication and probes. The published
            // URI remains the source form, but invalid source ports are never accepted.
            parsed.Port = port.ToString();
            return parsed;
        }

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
                        Sni = sni, Path = path, Aid = aid, BaseLink = baseLink,
                        ConnectionOptionsKey = BuildJsonIdentityKey(r)
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
                    string sni = q.GetValueOrDefault("sni", "") is var s && !string.IsNullOrEmpty(s)
                                  ? s : q.GetValueOrDefault("host", "");
                    return new ParsedProxy
                    {
                        Protocol = "vmess", Host = NormalizeUriHost(uri.Host),
                        Port = (uri.Port > 0 ? uri.Port : 443).ToString(),
                        Credential = uri.UserInfo ?? "",
                        Network = net, Security = sec,
                        Sni = sni, Path = q.GetValueOrDefault("path", "").TrimEnd('/'),
                        Aid = int.TryParse(q.GetValueOrDefault("aid", "0"), out var a) ? a : 0,
                        BaseLink = baseLink, ConnectionOptionsKey = BuildQueryIdentityKey(q)
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
                    BaseLink   = baseLink,
                    ConnectionOptionsKey = BuildQueryIdentityKey(q)
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
                    BaseLink = baseLink,
                    ConnectionOptionsKey = BuildQueryIdentityKey(q, "remarks", "remarks_base64")
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
                        BaseLink = baseLink, ConnectionOptionsKey = BuildQueryIdentityKey(q)
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

        private static string BuildQueryIdentityKey(
            IReadOnlyDictionary<string, string> query,
            params string[] excludedKeys)
        {
            if (query.Count == 0) return "";
            var excluded = new HashSet<string>(excludedKeys, StringComparer.OrdinalIgnoreCase);
            // Serialize a sorted list of key/value pairs rather than concatenating with
            // delimiters, so encoded separators in values cannot create key collisions.
            var canonical = query
                .Where(item => !excluded.Contains(item.Key))
                .OrderBy(item => item.Key, StringComparer.OrdinalIgnoreCase)
                .ThenBy(item => item.Key, StringComparer.Ordinal)
                .Select(item => new[] { item.Key.ToLowerInvariant(), item.Value })
                .ToArray();
            return JsonSerializer.Serialize(canonical);
        }

        private static string BuildJsonIdentityKey(JsonElement root)
        {
            if (root.ValueKind != JsonValueKind.Object) return "";
            // VMess "ps" is its display remark, not a connection setting. Preserve every
            // other property—including fields this collector does not yet understand.
            var canonical = root.EnumerateObject()
                .Where(property => !property.Name.Equals("ps", StringComparison.OrdinalIgnoreCase))
                .OrderBy(property => property.Name, StringComparer.Ordinal)
                .Select(property => new
                {
                    Name = property.Name,
                    Value = property.Value.Clone()
                })
                .ToArray();
            return JsonSerializer.Serialize(canonical);
        }

        private static string NormalizeUriHost(string host)
        {
            return host.Length >= 2 && host[0] == '[' && host[^1] == ']'
                ? host[1..^1]
                : host;
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
}
