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
        private async Task SaveAllCategories(List<FinalProxy> proxies, string sourceReportCsv)
        {
            var root = Directory.GetCurrentDirectory();
            var finalSub = Path.Combine(root, "sub");
            var stagingSub = Path.Combine(root, "sub.staging");
            var backupSub = Path.Combine(root, "sub.previous");

            // Recover the last complete output tree if a prior process was interrupted
            // between directory renames. Otherwise remove only stale staging/backup
            // directories; never delete the currently published sub/ tree up front.
            if (!Directory.Exists(finalSub) && Directory.Exists(backupSub))
                Directory.Move(backupSub, finalSub);
            if (Directory.Exists(stagingSub)) Directory.Delete(stagingSub, recursive: true);
            if (Directory.Exists(backupSub)) Directory.Delete(backupSub, recursive: true);

            Directory.CreateDirectory(stagingSub);
            var sub = stagingSub;
            // v6.13.1: re-create the category dirs — the wipe patch above deleted the
            // old creation loop, and File.WriteAllLinesAsync never creates intermediate
            // directories, so the first protocols/vless.txt write crashed the run.
            foreach (var d in new[] { "protocols", "countries", "continents" })
                Directory.CreateDirectory(Path.Combine(sub, d));

            // Resolve family once per staged snapshot, then reuse the result for /top,
            // /verified ordering, and the dedicated IPv4/IPv6 feeds.
            var ipv4Proxies = await FilterByFamilyAsync(proxies, AddressFamily.InterNetwork);
            var ipv6Proxies = await FilterByFamilyAsync(proxies, AddressFamily.InterNetworkV6);
            var ipv6Links = new HashSet<string>(ipv6Proxies.Select(x => x.Link), StringComparer.Ordinal);

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
            // The runner can only establish success from its own vantage, but the
            // resulting evidence is still valid globally. Do not silently exclude
            // working nodes merely because their server is outside a preferred region.
            // Keep this file strictly roundtrip-verified; among those verified nodes,
            // put native-IPv6-capable endpoints first without promoting unverified nodes.
            var xrayVerified = proxies.Where(x => x.XrayVerified)
                .OrderByDescending(x => ipv6Links.Contains(x.Link))
                .ThenByDescending(x => x.Score)
                .ThenBy(x => x.Remark, StringComparer.OrdinalIgnoreCase)
                .ToList();
            string lastVerifiedPath = Path.Combine("state", "verified_last.txt");
            int previousVerifiedCount = File.Exists(lastVerifiedPath)
                ? (await File.ReadAllLinesAsync(lastVerifiedPath)).Count(line => !string.IsNullOrWhiteSpace(line))
                : 0;
            // Don't replace a useful last-good set with a suspiciously tiny partial run.
            // On first-ever success, any non-empty result is useful; after that, require
            // at least 25 nodes and 20% of the previous set before rotating the fallback.
            int replacementFloor = previousVerifiedCount == 0
                ? 1 : Math.Max(25, (int)Math.Ceiling(previousVerifiedCount * 0.20));
            // Commit the fallback snapshot only after the complete output tree is
            // published. A later category-generation failure must not advance state
            // beyond the last successfully published verified.txt.
            List<string>? nextVerifiedSnapshot = null;
            if (xrayVerified.Count >= replacementFloor)
            {
                var currentVerifiedLinks = xrayVerified.Select(x => x.Link).ToList();
                await File.WriteAllLinesAsync(Path.Combine(sub, "verified.txt"), currentVerifiedLinks);
                nextVerifiedSnapshot = currentVerifiedLinks;
                LogSuccess($"Saved verified.txt ({xrayVerified.Count}) — current-run full proxy roundtrip");
            }
            else if (File.Exists(lastVerifiedPath))
            {
                // The last-good snapshot predates this run and may contain entries that
                // no longer satisfy output safety policy. Reuse the existing safety filter
                // here; otherwise this helper is dead code and unsafe fallback entries can
                // make the entire publication fail the final Cloudflare/WARP audit.
                var previousLinks = await File.ReadAllLinesAsync(lastVerifiedPath);
                var safePreviousLinks = await FilterSafeLastGoodLinksAsync(previousLinks);
                if (safePreviousLinks.Count > 0)
                {
                    await File.WriteAllLinesAsync(Path.Combine(sub, "verified.txt"), safePreviousLinks);
                    // Sanitize the persistent fallback too, so removed entries do not
                    // reappear as unsafe candidates on every subsequent collection.
                    nextVerifiedSnapshot = safePreviousLinks;
                    int removed = previousLinks.Count(line => !string.IsNullOrWhiteSpace(line)) - safePreviousLinks.Count;
                    LogWarning($"verified.txt: only {xrayVerified.Count} current-run successes (replacement floor {replacementFloor}); preserving {safePreviousLinks.Count} safe last-good entries ({removed} filtered).");
                }
                else if (xrayVerified.Count > 0)
                {
                    // Do not publish an empty or entirely unsafe fallback snapshot when
                    // this run still has some positively verified nodes.
                    await File.WriteAllLinesAsync(Path.Combine(sub, "verified.txt"), xrayVerified.Select(x => x.Link));
                    nextVerifiedSnapshot = xrayVerified.Select(x => x.Link).ToList();
                    LogWarning($"verified.txt: last-good snapshot had no safe entries; using {xrayVerified.Count} current-run successes below replacement floor {replacementFloor}.");
                }
                else
                {
                    // Throw before the staged tree replaces sub/. The caller can retry
                    // without destroying the previously published complete output tree.
                    throw new InvalidOperationException(
                        "No current-run Xray-verified nodes and no safe entries in state/verified_last.txt; refusing to publish an unsafe verified.txt.");
                }
            }
            else
            {
                // No previous snapshot exists. Preserve any current successes; workflow
                // validation will still prevent an empty first publication.
                await File.WriteAllLinesAsync(Path.Combine(sub, "verified.txt"), xrayVerified.Select(x => x.Link));
                LogWarning($"verified.txt: first run has only {xrayVerified.Count} verified nodes.");
            }

            // Curated evidence tier: source-tested nodes plus the stable+TLS-verified core.
            // Source testing can include Iran-specific checks, but the output stays useful
            // internationally and does not assume the GitHub runner matches the user.
            var curated = proxies.Where(x => x.IranTested || (x.IsStable && x.TlsVerified)).ToList();
            await File.WriteAllLinesAsync(Path.Combine(sub, "curated.txt"), curated.Select(x => x.Link));
            LogSuccess($"Saved curated.txt ({curated.Count}) — Iran-tested source or stable+TLS-verified");

            // /top is a globally ranked precision file. Require at least one affirmative
            // signal, then rank by converging evidence; geography contributes only a
            // modest prior. Keep the single unchunked 1000-node contract.
            var topCandidates = proxies
                .Where(x => x.TlsVerified || x.IranTested || x.XrayVerified || x.EdgeVerified)
                .OrderByDescending(x => x.Score)
                .ThenByDescending(x => x.XrayVerified)
                .ThenByDescending(x => x.TlsVerified)
                .ThenBy(x => x.Remark, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var top = SelectTopWithIpv6Diversity(topCandidates, ipv6Links, maxCount: 1000, ipv6SharePercent: 20);
            await File.WriteAllLinesAsync(Path.Combine(sub, "top.txt"), top.Select(x => x.Link));
            int topIpv6Count = top.Count(x => ipv6Links.Contains(x.Link));
            LogSuccess($"Saved top.txt ({top.Count}) — global ranking with IPv6 diversity " +
                       $"({topIpv6Count} IPv6-capable); gate: TLS-verified or source-tested; " +
                       $"score range {top.LastOrDefault()?.Score ?? 0}–{top.FirstOrDefault()?.Score ?? 0}");

            // v6.13: IPv4/IPv6 by RESOLVED family — hostname nodes now classify too
            // (alias collapse swaps v6 literals for hostnames, which literal-only
            // classification undercounted). Warm cache ⇒ ~free.
            await File.WriteAllLinesAsync(Path.Combine(sub, "ipv4_only.txt"), ipv4Proxies.Select(x => x.Link));
            await File.WriteAllLinesAsync(Path.Combine(sub, "ipv6_only.txt"), ipv6Proxies.Select(x => x.Link));
            LogSuccess($"Saved ipv4_only.txt ({ipv4Proxies.Count}) / ipv6_only.txt ({ipv6Proxies.Count})");

            // A focused shortlist for IPv6-capable endpoints. Keep the same evidence
            // gate and score ordering as top.txt, but rank across the full IPv6-capable
            // candidate pool instead of only intersecting the global top 1,000.
            var topIpv6 = ipv6Proxies
                .Where(x => x.TlsVerified || x.IranTested || x.XrayVerified || x.EdgeVerified)
                .OrderByDescending(x => x.Score)
                .ThenByDescending(x => x.XrayVerified)
                .ThenByDescending(x => x.TlsVerified)
                .ThenBy(x => x.Remark, StringComparer.OrdinalIgnoreCase)
                .Take(1000)
                .ToList();
            await File.WriteAllLinesAsync(Path.Combine(sub, "top_ipv6.txt"), topIpv6.Select(x => x.Link));
            LogSuccess($"Saved top_ipv6.txt ({topIpv6.Count}) — IPv6-capable nodes with positive quality evidence");

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

            // Diagnostics are part of the same staged tree, so published subscriptions
            // and their source-health report always describe the same completed run.
            string diagnosticsDir = Path.Combine(sub, "diagnostics");
            Directory.CreateDirectory(diagnosticsDir);
            await File.WriteAllTextAsync(
                Path.Combine(diagnosticsDir, "source-health.csv"),
                sourceReportCsv, new UTF8Encoding(false));
            LogSuccess($"Saved source audit: sub/diagnostics/source-health.csv");

            // Publish only after every output has been generated. Keep the old tree as
            // a rollback copy until the staged tree is in place; if the second rename
            // fails, restore the previous tree before surfacing the error.
            bool movedOldTree = false;
            if (Directory.Exists(finalSub))
            {
                Directory.Move(finalSub, backupSub);
                movedOldTree = true;
            }

            try
            {
                Directory.Move(stagingSub, finalSub);
            }
            catch
            {
                if (movedOldTree && !Directory.Exists(finalSub) && Directory.Exists(backupSub))
                    Directory.Move(backupSub, finalSub);
                throw;
            }

            if (Directory.Exists(backupSub))
            {
                try { Directory.Delete(backupSub, recursive: true); }
                catch (Exception ex)
                {
                    // The workflow stages all repository changes for publication. Never
                    // leave an un-audited old output tree at the repo root and then return
                    // success; fail the run so it cannot be committed alongside sub/.
                    LogError($"Could not remove rollback directory; refusing to publish this run: {ex.Message}");
                    throw;
                }
            }

            LogSuccess($"Published complete output tree: {finalSub}");

            if (nextVerifiedSnapshot is not null)
            {
                Directory.CreateDirectory("state");
                await File.WriteAllLinesAsync(lastVerifiedPath, nextVerifiedSnapshot);
                LogSuccess($"Updated verified last-good snapshot ({nextVerifiedSnapshot.Count} entries) after publication.");
            }
        }

        // v6.13: family by RESOLVED address — warm cache makes this ~free.
        internal static bool HasAddressFamily(IEnumerable<IPAddress> addresses, AddressFamily family)
        {
            // IPv4-mapped IPv6 literals (for example ::ffff:65.109.219.162) are
            // IPv4 endpoints expressed in IPv6 syntax, not native IPv6 reachability.
            // Keep them in IPv4-capable outputs and exclude them from ipv6_only.txt.
            return addresses.Any(ip =>
            {
                bool isMappedV4 = ip.IsIPv4MappedToIPv6;
                if (family == AddressFamily.InterNetwork)
                    return ip.AddressFamily == AddressFamily.InterNetwork || isMappedV4;
                if (family == AddressFamily.InterNetworkV6)
                    return ip.AddressFamily == AddressFamily.InterNetworkV6 && !isMappedV4;
                return ip.AddressFamily == family;
            });
        }

        private async Task<List<string>> FilterSafeLastGoodLinksAsync(IReadOnlyList<string> links)
        {
            var safe = new string?[links.Count];
            await Parallel.ForEachAsync(Enumerable.Range(0, links.Count),
                new ParallelOptions { MaxDegreeOfParallelism = 50 },
                async (index, _) =>
                {
                    string link = links[index].Trim();
                    if (link.Length == 0) return;

                    var parsed = ParseProxyLine(link);
                    // Last-good snapshots may predate current host and credential policy.
                    // Reapply the same checks as live collection before publishing them.
                    if (parsed is null ||
                        IsCloudflareMetadata(parsed) ||
                        IsBadHost(parsed.Host) ||
                        IsPlaceholderCredential(parsed.Credential) ||
                        (CredentialRequiredProtocols.Contains(NormalizeProto(parsed.Protocol)) &&
                         string.IsNullOrEmpty(parsed.Credential)))
                        return;

                    // ParseProxyLine strips display remarks from BaseLink. Inspect the
                    // original fallback line too, matching the final-output audit policy.
                    string lower = link.ToLowerInvariant();
                    if (lower.Contains("cloudflare") ||
                        lower.Contains("workers.dev") ||
                        lower.Contains("pages.dev") ||
                        lower.Contains("trycloudflare.com") ||
                        lower.Contains("warp://") ||
                        (NormalizeProto(parsed.Protocol) == "wireguard" && lower.Contains("warp")))
                        return;

                    bool isUnsafeAddress = false;
                    if (IPAddress.TryParse(parsed.Host.Trim('[', ']'), out var literal))
                    {
                        isUnsafeAddress =
                            IsCloudflareIp(literal) ||
                            IsPrivateOrReservedIp(literal) ||
                            IsFireholBlacklisted(literal);
                    }
                    else
                    {
                        try
                        {
                            var addresses = await Resolver.ResolveAllAsync(parsed.Host);
                            // A hostname is unsafe if any current answer is unsafe. If DNS
                            // is inconclusive, retain the fail-open behavior so a resolver
                            // outage alone cannot wipe the last-good snapshot.
                            isUnsafeAddress = addresses.Any(address =>
                                IsCloudflareIp(address) ||
                                IsPrivateOrReservedIp(address) ||
                                IsFireholBlacklisted(address));
                        }
                        catch
                        {
                            // Preserve last-good entries during inconclusive DNS failures.
                        }
                    }

                    if (!isUnsafeAddress) safe[index] = link;
                });

            return safe.Where(link => !string.IsNullOrWhiteSpace(link))
                .Select(link => link!)
                .ToList();
        }

        internal static List<FinalProxy> SelectTopWithIpv6Diversity(
            IReadOnlyList<FinalProxy> rankedCandidates,
            ISet<string> ipv6Links,
            int maxCount = 1000,
            int ipv6SharePercent = 20)
        {
            if (maxCount <= 0 || rankedCandidates.Count == 0) return new List<FinalProxy>();
            if (ipv6SharePercent is < 0 or > 100)
                throw new ArgumentOutOfRangeException(nameof(ipv6SharePercent));

            int outputCount = Math.Min(maxCount, rankedCandidates.Count);
            int ipv6Target = (int)Math.Ceiling(outputCount * (ipv6SharePercent / 100.0));
            var selected = new List<FinalProxy>(outputCount);
            var selectedLinks = new HashSet<string>(StringComparer.Ordinal);

            void AddCandidates(IEnumerable<FinalProxy> candidates, int limit)
            {
                int added = 0;
                foreach (var candidate in candidates)
                {
                    if (selected.Count >= maxCount || added >= limit) break;
                    if (!selectedLinks.Add(candidate.Link)) continue;
                    selected.Add(candidate);
                    added++;
                }
            }

            // Preserve the global score ranking within each family: take the best
            // IPv6-capable nodes first, fill the remainder from the global pool,
            // then backfill any shortage without duplicates.
            AddCandidates(rankedCandidates.Where(x => ipv6Links.Contains(x.Link)), ipv6Target);
            AddCandidates(rankedCandidates.Where(x => !ipv6Links.Contains(x.Link)), maxCount - selected.Count);
            AddCandidates(rankedCandidates, maxCount - selected.Count);

            return selected
                .OrderByDescending(x => x.Score)
                .ThenByDescending(x => x.XrayVerified)
                .ThenByDescending(x => x.TlsVerified)
                .ThenBy(x => x.Remark, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        private async Task<List<FinalProxy>> FilterByFamilyAsync(List<FinalProxy> proxies, AddressFamily family)
        {
            var result = new List<FinalProxy>();
            foreach (var x in proxies)
            {
                var addresses = IPAddress.TryParse(x.Host, out var literal)
                    ? new[] { literal }
                    : await Resolver.ResolveAllAsync(x.Host); // cached full A/AAAA set from GeoIP stage
                if (HasAddressFamily(addresses, family)) result.Add(x);
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

    }
}
