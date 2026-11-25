using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
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
        internal static void PublishStagedDirectory(
            string finalDirectory, string stagingDirectory, string backupDirectory,
            Action<string, string>? moveDirectory = null)
        {
            Action<string, string> move = moveDirectory ?? Directory.Move;
            bool movedOldTree = false;
            if (Directory.Exists(finalDirectory))
            {
                move(finalDirectory, backupDirectory);
                movedOldTree = true;
            }

            try
            {
                move(stagingDirectory, finalDirectory);
            }
            catch
            {
                if (movedOldTree && !Directory.Exists(finalDirectory) && Directory.Exists(backupDirectory))
                    move(backupDirectory, finalDirectory);
                throw;
            }

            if (Directory.Exists(backupDirectory))
            {
                try { Directory.Delete(backupDirectory, recursive: true); }
                catch (Exception ex)
                {
                    // If backup cleanup fails, fail the run rather than commit an
                    // ambiguous mix of the new publication and an old rollback tree.
                    LogError($"Could not remove rollback directory: {ex.Message}");
                    throw;
                }
            }
        }

        private async Task SaveAllCategories(List<FinalProxy> proxies, string sourceReportCsv)
        {
            int receivedCount = proxies.Count;
            proxies = DeduplicateFinalProxies(proxies);
            if (proxies.Count != receivedCount)
                LogSuccess($"Output identity audit: collapsed {receivedCount - proxies.Count} repeated exact configuration(s); compact feeds will additionally collapse credential variants by connection profile.");

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

            // Resolve family once per staged snapshot. Compact category feeds use one
            // representative per connection profile, but the master list retains every
            // genuinely distinct credential/configuration.
            var ipv4Proxies = SelectBestEndpointProfiles(
                await FilterByFamilyAsync(proxies, AddressFamily.InterNetwork));
            var ipv6Proxies = SelectBestEndpointProfiles(
                await FilterByFamilyAsync(proxies, AddressFamily.InterNetworkV6));
            var ipv6Links = new HashSet<string>(ipv6Proxies.Select(x => x.Link), StringComparer.Ordinal);

            int everythingPartCount = await WriteSubscriptionPartsAsync(
                Path.Combine(sub, "everything"), proxies.Select(x => x.Link));
            LogSuccess($"Saved everything.txt ({proxies.Count})" +
                       (everythingPartCount > 1 ? $" across {everythingPartCount} parts (≤50 MiB each)" : ""));

            // Compact history/evidence feeds use one best representative per service
            // profile. The master everything.txt remains credential-complete.
            var stable = SelectBestEndpointProfiles(proxies.Where(x => x.IsStable));
            int stablePartCount = await WriteSubscriptionPartsAsync(
                Path.Combine(sub, "stable"), stable.Select(x => x.Link));
            LogSuccess($"Saved stable.txt ({stable.Count}) — present ≥{StableMinRuns} consecutive runs" +
                       (stablePartCount > 1 ? $"; split into {stablePartCount} parts" : ""));

            var tlsVerified = SelectBestEndpointProfiles(proxies.Where(x => x.TlsVerified));
            int tlsPartCount = await WriteSubscriptionPartsAsync(
                Path.Combine(sub, "verified_tls"), tlsVerified.Select(x => x.Link));
            LogSuccess($"Saved verified_tls.txt ({tlsVerified.Count}) — distinct endpoint profiles with a current TLS handshake" +
                       (tlsPartCount > 1 ? $"; split into {tlsPartCount} parts" : ""));

            // verified.txt is a strict current-run claim: every entry must have passed
            // the full Xray proxy round-trip (including the expected HTTP 204) in THIS
            // collection run. Never mix old successes into this feed.
            var xrayVerified = SelectCurrentVerifiedProfiles(proxies)
                .OrderByDescending(x => ipv6Links.Contains(x.Link))
                .ThenByDescending(x => x.XrayStreak)
                .ThenByDescending(x => x.Score)
                .ThenBy(x => x.Remark, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Link, StringComparer.Ordinal)
                .ToList();

            string lastVerifiedPath = Path.Combine("state", "verified_last.txt");
            int previousVerifiedCount = File.Exists(lastVerifiedPath)
                ? (await File.ReadAllLinesAsync(lastVerifiedPath)).Count(line => !string.IsNullOrWhiteSpace(line))
                : 0;
            int replacementFloor = previousVerifiedCount == 0
                ? 1 : Math.Max(25, (int)Math.Ceiling(previousVerifiedCount * 0.20));

            List<string> safeLastGood;
            if (xrayVerified.Count >= replacementFloor)
            {
                Directory.CreateDirectory("state");
                var currentLinks = xrayVerified.Select(x => x.Link).ToList();
                await File.WriteAllLinesAsync(lastVerifiedPath, currentLinks);
                safeLastGood = currentLinks;
                LogSuccess($"Rotated last-good Xray snapshot with {safeLastGood.Count} current-run verified endpoint profile(s).");
            }
            else if (File.Exists(lastVerifiedPath))
            {
                var lastGoodLines = await File.ReadAllLinesAsync(lastVerifiedPath);
                safeLastGood = await FilterSafeLastGoodLinksAsync(lastGoodLines);
                if (safeLastGood.Count == 0 && xrayVerified.Count > 0)
                    safeLastGood = xrayVerified.Select(x => x.Link).ToList();
                LogWarning($"Current Xray successes: {xrayVerified.Count} (snapshot replacement floor {replacementFloor}); sanitized last-good snapshot contains {safeLastGood.Count} profile(s).");
            }
            else
            {
                safeLastGood = xrayVerified.Select(x => x.Link).ToList();
                LogWarning($"No prior last-good Xray snapshot exists; retaining {safeLastGood.Count} current verified profile(s) as the initial fallback.");
            }

            // Keep the names semantically honest and consumers stable: verified.txt is
            // current-run only; verified_last_good.txt is explicitly historical fallback.
            await WriteSubscriptionPartsAsync(Path.Combine(sub, "verified"), xrayVerified.Select(x => x.Link));
            await WriteSubscriptionPartsAsync(Path.Combine(sub, "verified_last_good"), safeLastGood);
            LogSuccess($"Saved verified.txt ({xrayVerified.Count}) — current-run full Xray round-trip only.");
            LogSuccess($"Saved verified_last_good.txt ({safeLastGood.Count}) — sanitized historical snapshot, not a current verification claim.");

            // Curated evidence tier: source-tested nodes plus the stable+TLS-verified core.
            // Source testing can include Iran-specific checks, but the output stays useful
            // internationally and does not assume the GitHub runner matches the user.
            var curated = SelectBestEndpointProfiles(
                proxies.Where(x => x.IranTested || (x.IsStable && x.TlsVerified)));
            int curatedPartCount = await WriteSubscriptionPartsAsync(
                Path.Combine(sub, "curated"), curated.Select(x => x.Link));
            LogSuccess($"Saved curated.txt ({curated.Count}) — Iran-tested source or stable+TLS-verified" +
                       (curatedPartCount > 1 ? $"; split into {curatedPartCount} parts" : ""));

            // /top is a globally ranked precision file. Require at least one affirmative
            // signal, then rank by converging evidence; geography contributes only a
            // modest prior. Keep the single unchunked 1000-node contract.
            var topCandidates = RankTopCandidates(proxies);
            var top = SelectTopWithIpv6Diversity(topCandidates, ipv6Links, maxCount: 1000, ipv6SharePercent: 20);
            await WriteSubscriptionPartsAsync(Path.Combine(sub, "top"), top.Select(x => x.Link));
            int topIpv6Count = top.Count(x => ipv6Links.Contains(x.Link));
            string topLaneSummary = string.Join(", ", top
                .GroupBy(GetTopEvidenceLane)
                .OrderBy(g => g.Key)
                .Select(g => $"{GetTopEvidenceLaneName(g.First())}={g.Count()}"));
            int topNativeCount = top.Count(IsTopProbeLimitedProtocol);
            int topDistinctProfiles = top.Select(GetTopEndpointProfileKey)
                .Distinct(StringComparer.OrdinalIgnoreCase).Count();
            LogSuccess($"Saved top.txt ({top.Count}) — evidence-stratified ranking; " +
                       $"IPv6 {topIpv6Count}, native/QUIC probe-limited {topNativeCount}, " +
                       $"unique connection profiles {topDistinctProfiles}; lanes: {topLaneSummary}; " +
                       $"score range {top.LastOrDefault()?.Score ?? 0}–{top.FirstOrDefault()?.Score ?? 0}");
            if (top.Count < 1000)
                LogWarning($"top.txt contains {top.Count}/1000 entries: strict endpoint and diversity caps left no additional eligible profiles.");

            // v6.13: IPv4/IPv6 by RESOLVED family — hostname nodes now classify too
            // (alias collapse swaps v6 literals for hostnames, which literal-only
            // classification undercounted). Warm cache ⇒ ~free.
            int ipv4PartCount = await WriteSubscriptionPartsAsync(
                Path.Combine(sub, "ipv4_only"), ipv4Proxies.Select(x => x.Link));
            LogSuccess($"Saved ipv4_only.txt ({ipv4Proxies.Count})" +
                       (ipv4PartCount > 1 ? $"; split into {ipv4PartCount} parts" : ""));

            // A focused shortlist for IPv6-capable endpoints. Keep the same evidence
            // gate and score ordering as top.txt, but rank across the full IPv6-capable
            // candidate pool instead of only intersecting the global top 1,000.
            var topIpv6Candidates = RankTopCandidates(ipv6Proxies);
            var topIpv6 = SelectTopWithIpv6Diversity(
                topIpv6Candidates, ipv6Links, maxCount: 1000, ipv6SharePercent: 100);
            await WriteSubscriptionPartsAsync(Path.Combine(sub, "top_ipv6"), topIpv6.Select(x => x.Link));
            LogSuccess($"Saved top_ipv6.txt ({topIpv6.Count}) — independent IPv6 candidate pool, " +
                       $"unique profiles {topIpv6.Select(GetTopEndpointProfileKey).Distinct(StringComparer.OrdinalIgnoreCase).Count()}, " +
                       $"source/stability/QUIC lane retained where evidence is available.");

            // Publish the family feed after the shortlist is finalized, and include the
            // shortlist as a defensive invariant. This is normally a no-op because
            // topIpv6 is selected from ipv6Proxies, but prevents a stale/mismatched
            // family file from ever being emitted if candidate selection changes later.
            var ipv6OnlyLinks = ipv6Proxies.Select(x => x.Link)
                .Concat(topIpv6.Select(x => x.Link))
                .Distinct(StringComparer.Ordinal)
                .ToList();
            int ipv6PartCount = await WriteSubscriptionPartsAsync(
                Path.Combine(sub, "ipv6_only"), ipv6OnlyLinks);
            LogSuccess($"Saved ipv6_only.txt ({ipv6OnlyLinks.Count}) / top_ipv6.txt ({topIpv6.Count}) — shortlist membership guaranteed" +
                       (ipv6PartCount > 1 ? $"; split ipv6_only into {ipv6PartCount} parts" : ""));

            if (topIpv6.Any(x => !ipv6OnlyLinks.Contains(x.Link, StringComparer.Ordinal)))
                throw new InvalidOperationException("top_ipv6.txt contains a node missing from ipv6_only.txt");

            foreach (var g in GetRawProtocolGroups(proxies))
            {
                string key = g.Key.Trim().ToLowerInvariant();

                await WriteTxt(Path.Combine(sub, "protocols", key), SelectBestEndpointProfiles(g));
                LogSuccess($"  → protocols/{key} ({g.Count()})");
            }

            foreach (var g in proxies.GroupBy(x => x.CountryCode))
            {
                if (string.IsNullOrEmpty(g.Key) || g.Key == "XX" || g.Count() < 3) continue;
                string safe = Regex.Replace(g.Key, @"[^A-Z0-9]", "");
                if (string.IsNullOrEmpty(safe)) continue;
                await WriteTxt(Path.Combine(sub, "countries", safe), SelectBestEndpointProfiles(g));
                LogSuccess($"  → countries/{safe} ({g.Count()})");
            }

            foreach (var g in proxies.GroupBy(x => x.Continent))
            {
                if (g.Key == "Unknown" || g.Count() < 3) continue;
                await WriteTxt(Path.Combine(sub, "continents", g.Key), SelectBestEndpointProfiles(g));
                LogSuccess($"  → continents/{g.Key} ({g.Count()})");
            }

            // v6.16: WireGuard Clash YAML + .conf files
            // NekoBox's JSON parser has a bug with WireGuard outbounds, so we output
            // Clash YAML which NekoBox parses perfectly. The official WireGuard app
            // imports .conf files. We output BOTH so either client can use the data.
            var wgNodes = SelectBestEndpointProfiles(proxies.Where(x => x.Proto == "wireguard"));
            if (wgNodes.Count > 0)
            {
                var wgDir = Path.Combine(sub, "wireguard");
                Directory.CreateDirectory(wgDir);

                var clashProxies = new List<Dictionary<string, object?>>();
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

                    // Build the Clash node as data. YamlDotNet handles quoting and
                    // line breaks in every source-controlled scalar; string concatenation
                    // here would allow newline/quote injection into downloadable configs.
                    var clashNode = new Dictionary<string, object?>
                    {
                        ["name"] = node.Remark,
                        ["type"] = "wireguard",
                        ["server"] = wgInfo.Host,
                        ["port"] = wgInfo.Port,
                        ["ip"] = wgInfo.Address,
                        ["public-key"] = wgInfo.PublicKey,
                        ["private-key"] = wgInfo.PrivateKey,
                        ["allowed-ips"] = wgInfo.AllowedIPs,
                        ["mtu"] = 1280
                    };
                    if (!string.IsNullOrEmpty(wgInfo.Dns)) clashNode["dns"] = wgInfo.Dns;
                    if (!string.IsNullOrEmpty(wgInfo.PresharedKey)) clashNode["preshared-key"] = wgInfo.PresharedKey;
                    if (wgInfo.Reserved.Length == 3)
                        clashNode["reserved"] = wgInfo.Reserved.Select(r => (int)byte.Parse(r.Trim())).ToArray();
                    clashProxies.Add(clashNode);
                }

                string wireguardProtocolDirectory = Path.Combine(sub, "protocols");
                foreach (string stalePart in Directory.GetFiles(wireguardProtocolDirectory, "wireguard_part*.txt"))
                    File.Delete(stalePart);

                if (ok > 0)
                {
                    var yamlParts = SerializeWireguardClashYamlParts(clashProxies);
                    for (int partIndex = 0; partIndex < yamlParts.Count; partIndex++)
                    {
                        string fileName = partIndex == 0
                            ? "wireguard.txt"
                            : $"wireguard_part{partIndex + 1}.txt";
                        await File.WriteAllTextAsync(
                            Path.Combine(wireguardProtocolDirectory, fileName), yamlParts[partIndex]);
                    }
                }
                else
                {
                    File.Delete(Path.Combine(wireguardProtocolDirectory, "wireguard.txt"));
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
            var allNodesByEvidence = proxies
                .OrderByDescending(x => x.EvidenceTier)
                .ThenByDescending(x => x.Score)
                .ThenBy(x => x.Remark, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Link, StringComparer.Ordinal)
                .ToList();
            await WriteVerificationReportAsync(
                Path.Combine(diagnosticsDir, "verification-status.csv.gz"),
                allNodesByEvidence, top, topIpv6);
            await WriteRankingCalibrationAsync(
                Path.Combine(diagnosticsDir, "ranking-calibration.csv"),
                Path.Combine(diagnosticsDir, "ranking-calibration-summary.csv"),
                proxies);
            LogSuccess($"Saved source audit: sub/diagnostics/source-health.csv");

            // Publish the new tree atomically and restore the previous tree if the
            // stage-to-final move fails. Keep this transaction isolated for regression tests.
            PublishStagedDirectory(finalSub, stagingSub, backupSub);

            LogSuccess($"Published complete output tree: {finalSub}");
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
                    // A last-good snapshot can predate current live filtering. Reapply
                    // endpoint and credential policy before retaining any fallback link.
                    if (parsed is null ||
                        IsCloudflareMetadata(parsed) ||
                        IsBadHost(parsed.Host) ||
                        IsPlaceholderCredential(parsed.Protocol, parsed.Credential) ||
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
                        HasWarpRemark(link) ||
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
                            // Reject mixed DNS answers if any address is unsafe. Keep the
                            // existing fail-open behavior on resolver failure so a DNS
                            // outage alone does not erase the last-good snapshot.
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

            var filtered = DeduplicateFallbackLinks(
                safe.Where(link => !string.IsNullOrWhiteSpace(link)).Select(link => link!));

            // A last-good snapshot may still contain the old provider/hash-heavy remarks.
            // Rebuild fallback labels with the current naming format too, so verified.txt
            // does not revert to legacy names when a small run uses the safe snapshot.
            var occurrences = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var renamed = new List<string>(filtered.Count);
            foreach (string link in filtered)
            {
                var parsed = ParseProxyLine(link);
                if (parsed is null) continue;
                string baseName = BuildFallbackNodeName(GetLinkRemark(link), parsed.Host, parsed.Port);
                occurrences.TryGetValue(baseName, out int occurrence);
                occurrence++;
                occurrences[baseName] = occurrence;
                string remark = ApplyDuplicateNameSuffix(baseName, occurrence);
                renamed.Add(BuildCleanLink(parsed, remark));
            }
            return renamed;
        }

        internal static string GetLinkRemark(string link)
        {
            int hash = link.IndexOf('#');
            if (hash < 0 || hash == link.Length - 1) return string.Empty;
            string fragment = link[(hash + 1)..];
            try { return Uri.UnescapeDataString(fragment); }
            catch { return fragment; }
        }

        internal static string BuildFallbackNodeName(string oldRemark, string host, string port)
        {
            string remark = oldRemark ?? string.Empty;
            try { remark = Uri.UnescapeDataString(remark); }
            catch { /* keep the original remark if it has malformed escapes */ }

            // Already-renamed snapshots can be normalized without consulting GeoIP again.
            int dash = remark.IndexOf(" - ", StringComparison.Ordinal);
            int closeParen = dash >= 0 ? remark.LastIndexOf(')', dash) : -1;
            int openParen = closeParen > 0 ? remark.LastIndexOf('(', closeParen) : -1;
            int pipe = dash >= 0 ? remark.IndexOf(" | ", dash + 3, StringComparison.Ordinal) : -1;
            if (openParen >= 0 && closeParen > openParen && dash > closeParen && pipe > dash)
            {
                string code = remark[(openParen + 1)..closeParen].Trim().ToUpperInvariant();
                string city = remark[(dash + 3)..pipe].Trim();
                if (code == "XX")
                    return BuildClientNodeName("XX", $"🌐 {city}, XX", host, port);
                if (Flags.TryGetValue(code, out var knownFlag))
                    return BuildClientNodeName(code, $"{knownFlag} {city}, {code}", host, port);
            }

            // Normalize snapshots already using the new "flag Country - City | endpoint"
            // format before the legacy-label fallback below. The code-bearing format above
            // remains supported so existing verified snapshots migrate cleanly.
            if (dash >= 0 && pipe > dash)
            {
                string head = remark[..dash].Trim();
                string city = remark[(dash + 3)..pipe].Trim();
                if (head.Equals("🌐 Unknown", StringComparison.Ordinal))
                    return BuildClientNodeName("XX", $"🌐 {city}", host, port);

                foreach (var pair in Flags)
                {
                    string prefix = pair.Value + " ";
                    if (!head.StartsWith(prefix, StringComparison.Ordinal)) continue;
                    string canonical = BuildClientNodeName(pair.Key, $"{pair.Value} Unknown", "placeholder", "1");
                    int canonicalDash = canonical.IndexOf(" - ", StringComparison.Ordinal);
                    string expectedHead = canonicalDash >= 0 ? canonical[..canonicalDash] : "";
                    if (head.Equals(expectedHead, StringComparison.OrdinalIgnoreCase))
                        return BuildClientNodeName(pair.Key, $"{pair.Value} {city}", host, port);
                }
            }

            string countryCode = "XX";
            string flag = "🌐";
            string location = "Unknown";
            if (remark.StartsWith("🌐 ", StringComparison.Ordinal))
            {
                location = remark["🌐 ".Length..];
            }
            else
            {
                foreach (var pair in Flags)
                {
                    string prefix = pair.Value + " ";
                    if (!remark.StartsWith(prefix, StringComparison.Ordinal)) continue;
                    countryCode = pair.Key;
                    flag = pair.Value;
                    location = remark[prefix.Length..];
                    break;
                }
            }

            int providerAt = location.IndexOf(" · ", StringComparison.Ordinal);
            if (providerAt >= 0) location = location[..providerAt].Trim();
            if (location.Length == 0) location = "Unknown";
            return BuildClientNodeName(countryCode, $"{flag} {location}", host, port);
        }

        // Current evidence gets a guaranteed lead over historical reputation.
        internal static int CalculateRankingScore(ParsedProxy p, string countryCode)
        {
            int score = 0;
            if (p.XrayVerified) score += 100;                  // full proxy roundtrip, this run
            if (p.TlsVerified) score += 35;                    // TLS handshake, this run
            if (p.EdgeVerified) score += 20;                   // independent edge TLS check, this run
            if (p.IranTested) score += 15;                     // delegated upstream signal
            if (p.TlsVerified) score += Math.Min(p.VerifiedStreak, 3);
            if (p.XrayVerified) score += Math.Min(p.XrayStreak, 3) * 2;
            score += Math.Min(Math.Max(p.Streak, 0), 5);       // small presence bonus only
            score += Math.Max(0, 8 - ProximityTier(countryCode)) / 2; // at most +4
            if (p.SourceCount >= 2) score += Math.Min(p.SourceCount, 5);
            return score;
        }

        internal static int GetEvidenceTier(FinalProxy p) => p.EvidenceTier;

        internal static string GetEvidenceLevel(FinalProxy p) => p.EvidenceTier switch
        {
            3 => "full-proxy-roundtrip",
            2 => "partial-connectivity",
            1 => "source-tested-only",
            _ when p.IsStable && p.SourceCount >= 2 => "stable-and-multi-source",
            _ when p.IsStable => "stable-across-runs",
            _ when p.SourceCount >= 2 && p.Streak >= 2 => "multi-source-and-persistent",
            _ when p.SourceCount >= 2 => "multi-source-corroborated",
            _ => "no-positive-evidence"
        };

        internal static string GetTestStatus(bool tested, bool passed) =>
            passed ? "passed" : tested ? "failed" : "not-tested";

        internal static string GetVerificationStatus(FinalProxy p) => p.VerificationStatus;

        // The top feed has three explicit evidence lanes. Current full round trips
        // lead, partial TLS/edge checks remain competitive, and source-tested or
        // historically persistent nodes retain a reserved lane instead of being
        // starved by a large Xray pass pool.
        internal static int GetTopEvidenceLane(FinalProxy p) =>
            p.XrayVerified ? 0 :
            (p.TlsVerified || p.EdgeVerified) ? 1 : 2;

        internal static string GetTopEvidenceLaneName(FinalProxy p) =>
            GetTopEvidenceLane(p) switch
            {
                0 => "full-roundtrip",
                1 => "partial-connectivity",
                _ => "source-or-stability"
            };

        // These protocols use QUIC/UDP or a protocol-native tunnel and are outside
        // the current TCP/TLS and Xray probe coverage. They may enter the reserved
        // source/stability lane, but are never mislabeled as currently verified.
        internal static bool IsTopProbeLimitedProtocol(FinalProxy p)
        {
            string proto = (p.Proto ?? "").Trim().ToLowerInvariant();
            return proto is "hysteria" or "hysteria2" or "hy2" or "tuic" or
                "juicity" or "wireguard" or "wg" or "mieru";
        }

        internal static int CalculateTopSelectionScore(FinalProxy p)
        {
            int score = p.Score;
            if (p.IsStable) score += 20;
            score += Math.Min(Math.Max(p.Streak, 0), 5) * 2;
            score += Math.Min(Math.Max(p.SourceCount - 1, 0), 8) * 3;
            score += Math.Min(Math.Max(p.VerifiedStreak, 0), 3);
            score += Math.Min(Math.Max(p.XrayStreak, 0), 3) * 2;
            if (p.TlsTested && !p.TlsVerified) score -= 20;
            if (p.XrayTested && !p.XrayVerified) score -= 25;
            if (p.EdgeTested && !p.EdgeVerified) score -= 15;
            return score;
        }

        internal static List<FinalProxy> RankTopCandidates(IEnumerable<FinalProxy> proxies) =>
            proxies
                .Where(x => x.XrayVerified || x.TlsVerified || x.EdgeVerified || x.IranTested ||
                    x.IsStable || x.SourceCount >= 2)
                .OrderBy(GetTopEvidenceLane)
                .ThenByDescending(CalculateTopSelectionScore)
                .ThenByDescending(x => x.SourceCount)
                .ThenBy(x => x.Remark, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Link, StringComparer.Ordinal)
                .ToList();

        internal static string GetSourceDiversityGroup(string sourceUrl)
        {
            if (!Uri.TryCreate(sourceUrl, UriKind.Absolute, out var uri)) return "";
            var segments = uri.AbsolutePath.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
            string host = uri.Host.ToLowerInvariant();
            if ((host is "raw.githubusercontent.com" or "github.com") && segments.Length >= 2)
                return $"github:{segments[0].ToLowerInvariant()}/{segments[1].Split('@')[0].ToLowerInvariant()}";
            if (host == "cdn.jsdelivr.net" && segments.Length >= 3 &&
                segments[0].Equals("gh", StringComparison.OrdinalIgnoreCase))
                return $"github:{segments[1].ToLowerInvariant()}/{segments[2].Split('@')[0].ToLowerInvariant()}";
            if (host == "gitlab.com" && segments.Length >= 2)
                return $"gitlab:{segments[0].ToLowerInvariant()}/{segments[1].Split('@')[0].ToLowerInvariant()}";
            return $"host:{host}";
        }

        internal static string GetProviderDiversityGroup(string location)
        {
            int separator = location.IndexOf(" · ", StringComparison.Ordinal);
            if (separator < 0 || separator + 3 >= location.Length) return "";
            return Regex.Replace(location[(separator + 3)..].Trim().ToLowerInvariant(), @"\s+", " ");
        }

        internal static string GetHostnameDiversityGroup(string host)
        {
            string normalized = (host ?? "").Trim().Trim('[', ']').TrimEnd('.').ToLowerInvariant();
            if (normalized.Length == 0) return "";
            if (IPAddress.TryParse(normalized, out var ip)) return "ip:" + ip.ToString().ToLowerInvariant();

            string[] labels = normalized.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (labels.Length <= 2) return string.Join(".", labels);
            string suffix2 = labels[^2] + "." + labels[^1];
            var compoundSuffixes = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "co.uk", "org.uk", "gov.uk", "com.au", "net.au", "org.au",
                "co.jp", "co.in", "com.br", "com.cn", "com.tr", "com.sg", "com.hk",
                "com.tw", "com.mx", "co.za", "com.ar", "com.my", "com.vn"
            };
            return compoundSuffixes.Contains(suffix2)
                ? string.Join(".", labels[^3..])
                : suffix2;
        }

        private static int DiversityCap(
            IReadOnlyList<FinalProxy> ranked, Func<FinalProxy, string> groupSelector,
            int outputCount, int maximumSharePercent)
        {
            int groups = ranked.Select(groupSelector)
                .Where(g => !string.IsNullOrWhiteSpace(g))
                .Distinct(StringComparer.OrdinalIgnoreCase).Count();
            if (groups == 0) return outputCount;
            int shareCap = Math.Max(1, (int)Math.Ceiling(outputCount * maximumSharePercent / 100.0));
            int balancedCap = Math.Max(1, (int)Math.Ceiling(outputCount / (double)groups));
            return Math.Min(outputCount, Math.Max(shareCap, balancedCap));
        }

        // Endpoint profile identity excludes access credentials except for WireGuard,
        // where the private key defines a different local tunnel interface. Parsed
        // candidates carry this key from the single canonical identity implementation.
        internal static string GetFinalConnectionIdentityKey(FinalProxy p)
        {
            if (!string.IsNullOrWhiteSpace(p.ConnectionIdentityKey))
                return p.ConnectionIdentityKey;

            // Test fixtures and older serialized snapshots may not carry the parsed key.
            // Reconstruct exact configuration identity from the service profile plus its
            // credential (WireGuard already includes its private key in the profile).
            string credential = NormalizeTopProtocol(p.Proto) == "wireguard" ? "" : p.Credential ?? "";
            return JsonSerializer.Serialize(new[] { GetTopEndpointProfileKey(p), credential });
        }

        internal static List<FinalProxy> DeduplicateFinalProxies(IEnumerable<FinalProxy> proxies)
        {
            var groups = proxies
                .Where(p => !string.IsNullOrWhiteSpace(p.Link))
                .GroupBy(GetFinalConnectionIdentityKey, StringComparer.Ordinal)
                .ToList();

            var result = new List<FinalProxy>(groups.Count);
            foreach (var group in groups)
            {
                var items = group.ToList();
                var winner = items
                    .OrderByDescending(x => x.EvidenceTier)
                    .ThenByDescending(CalculateTopSelectionScore)
                    .ThenByDescending(x => x.SourceCount)
                    .ThenBy(x => x.Link, StringComparer.Ordinal)
                    .First();

                // Preserve all corroborated metadata when two representations collapse
                // to one exact connection configuration.
                winner.IranTested |= items.Any(x => x.IranTested);
                winner.IsStable |= items.Any(x => x.IsStable);
                winner.TlsTested |= items.Any(x => x.TlsTested);
                winner.TlsVerified |= items.Any(x => x.TlsVerified);
                winner.XrayTested |= items.Any(x => x.XrayTested);
                winner.XrayVerified |= items.Any(x => x.XrayVerified);
                winner.EdgeTested |= items.Any(x => x.EdgeTested);
                winner.EdgeVerified |= items.Any(x => x.EdgeVerified);
                winner.SourceCount = items.Max(x => x.SourceCount);
                winner.Streak = items.Max(x => x.Streak);
                winner.VerifiedStreak = items.Max(x => x.VerifiedStreak);
                winner.XrayStreak = items.Max(x => x.XrayStreak);
                winner.Score = items.Max(x => x.Score);
                result.Add(winner);
            }

            return result
                .OrderBy(x => x.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Proto, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Port, StringComparer.Ordinal)
                .ThenBy(x => x.Link, StringComparer.Ordinal)
                .ToList();
        }

        // Compact category feeds use one best representative per connection profile.
        // The master catalogue still retains distinct credentials as distinct configs.
        internal static List<FinalProxy> SelectCurrentVerifiedProfiles(IEnumerable<FinalProxy> candidates)
            => SelectBestEndpointProfiles(candidates.Where(x => x.XrayVerified))
                .OrderByDescending(x => x.XrayStreak)
                .ThenByDescending(x => x.Score)
                .ThenBy(x => x.Link, StringComparer.Ordinal)
                .ToList();

        internal static List<FinalProxy> SelectBestEndpointProfiles(IEnumerable<FinalProxy> candidates)
            => candidates
                .Where(x => !string.IsNullOrWhiteSpace(x.Link))
                .GroupBy(GetTopEndpointProfileKey, StringComparer.Ordinal)
                .Select(group => group
                    .OrderByDescending(x => x.XrayVerified)
                    .ThenByDescending(x => x.TlsVerified || x.EdgeVerified)
                    .ThenByDescending(x => x.IranTested)
                    .ThenByDescending(x => x.IsStable)
                    .ThenByDescending(x => x.XrayStreak)
                    .ThenByDescending(x => x.VerifiedStreak)
                    .ThenByDescending(CalculateTopSelectionScore)
                    .ThenByDescending(x => x.SourceCount)
                    .ThenBy(x => x.Link, StringComparer.Ordinal)
                    .First())
                .OrderBy(x => x.Host, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Proto, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Port, StringComparer.Ordinal)
                .ThenBy(x => x.Link, StringComparer.Ordinal)
                .ToList();

        internal static string GetTopEndpointProfileKey(FinalProxy p)
        {
            if (!string.IsNullOrWhiteSpace(p.SelectionProfileKey))
                return p.SelectionProfileKey;

            string host = NormalizeIdentityHost(p.Host);
            string port = (p.Port ?? "").Trim();
            if ((host.Length == 0 || port.Length == 0) &&
                Uri.TryCreate(p.Link, UriKind.Absolute, out var uri))
            {
                if (host.Length == 0) host = uri.Host.Trim('[', ']').TrimEnd('.').ToLowerInvariant();
                if (port.Length == 0 && !uri.IsDefaultPort) port = uri.Port.ToString(CultureInfo.InvariantCulture);
            }
            if (int.TryParse(port, NumberStyles.Integer, CultureInfo.InvariantCulture, out int portNumber))
                port = portNumber.ToString(CultureInfo.InvariantCulture);

            string protocol = NormalizeTopProtocol(p.Proto);
            string sni = string.IsNullOrWhiteSpace(p.Sni) ? host : NormalizeIdentityHost(p.Sni);
            string credential = protocol == "wireguard" ? p.Credential ?? "" : "";
            string network = string.IsNullOrWhiteSpace(p.Network) ? "tcp" : p.Network.Trim().ToLowerInvariant();
            string security = string.IsNullOrWhiteSpace(p.Security) ? "none" : p.Security.Trim().ToLowerInvariant();
            string path = (p.Path ?? "").Trim();
            string flow = (p.Flow ?? "").Trim().ToLowerInvariant();
            string realityKey = (p.Pbk ?? "").Trim();
            string realityId = (p.Sid ?? "").Trim().ToLowerInvariant();
            string obfuscation = (p.ObfsPassword ?? "").Trim();
            string alterId = p.Aid.ToString(CultureInfo.InvariantCulture);
            string options = (p.ConnectionOptionsKey ?? "").Trim();
            return JsonSerializer.Serialize(new[]
            {
                protocol, host, port, credential, sni, network, security, path,
                flow, realityKey, realityId, obfuscation, alterId, options
            });
        }

        private static string NormalizeTopProtocol(string protocol)
        {
            string value = (protocol ?? "").Trim().ToLowerInvariant();
            return value switch
            {
                "hy2" => "hysteria2",
                "wg" => "wireguard",
                "shadowsocks" => "ss",
                _ => value
            };
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

            // Collapse credential/remark variants before computing any quotas. Keep
            // the best-evidenced version of each actual connection profile.
            var ranked = rankedCandidates
                .Where(x => !string.IsNullOrWhiteSpace(x.Link))
                .GroupBy(GetTopEndpointProfileKey, StringComparer.OrdinalIgnoreCase)
                .Select(g => g
                    // When a service has both IPv4-only and IPv6-capable host spellings,
                    // choose its IPv6 candidate for the global IPv6 reservation too.
                    .OrderByDescending(x => ipv6Links.Contains(x.Link))
                    .ThenBy(GetTopEvidenceLane)
                    .ThenByDescending(CalculateTopSelectionScore)
                    .ThenBy(x => x.Link, StringComparer.Ordinal)
                    .First())
                .OrderBy(GetTopEvidenceLane)
                .ThenByDescending(CalculateTopSelectionScore)
                .ThenByDescending(x => x.SourceCount)
                .ThenBy(x => x.Remark, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Link, StringComparer.Ordinal)
                .ToList();

            int outputCount = Math.Min(maxCount, ranked.Count);
            if (outputCount == 0) return new List<FinalProxy>();

            // Hard caps are intentionally enforced in every selection pass. If the
            // eligible pool cannot supply 1,000 distinct and diverse profiles, publish
            // fewer rather than silently re-introducing duplicates to hit a number.
            int sourceCap = DiversityCap(ranked, x => x.SourceGroup, outputCount, 5);
            int providerCap = DiversityCap(ranked, x => x.ProviderGroup, outputCount, 8);
            int hostnameCap = DiversityCap(ranked, x => x.HostGroup, outputCount, 2);
            int transportCap = DiversityCap(ranked, x => x.TransportGroup, outputCount, 30);
            int protocolCap = DiversityCap(ranked, x => NormalizeTopProtocol(x.Proto), outputCount, 60);

            var selected = new List<FinalProxy>(outputCount);
            var selectedProfiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var sourceCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var providerCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var hostnameCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var transportCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var protocolCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            // Resolve IPv6 membership before local selection helpers capture it.
            // Profile-level membership survives credential/remark duplicate collapse.
            var ipv6Profiles = rankedCandidates
                .Where(x => ipv6Links.Contains(x.Link))
                .Select(GetTopEndpointProfileKey)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            bool IsIpv6Profile(FinalProxy candidate) =>
                ipv6Profiles.Contains(GetTopEndpointProfileKey(candidate));

            static bool WithinCap(Dictionary<string, int> counts, string group, int cap) =>
                string.IsNullOrWhiteSpace(group) || !counts.TryGetValue(group, out int count) || count < cap;

            bool TryAdd(FinalProxy candidate)
            {
                if (selected.Count >= outputCount) return false;
                string profile = GetTopEndpointProfileKey(candidate);
                if (selectedProfiles.Contains(profile)) return false;

                string protocol = NormalizeTopProtocol(candidate.Proto);
                if (!WithinCap(sourceCounts, candidate.SourceGroup, sourceCap) ||
                    !WithinCap(providerCounts, candidate.ProviderGroup, providerCap) ||
                    !WithinCap(hostnameCounts, candidate.HostGroup, hostnameCap) ||
                    !WithinCap(transportCounts, candidate.TransportGroup, transportCap) ||
                    !WithinCap(protocolCounts, protocol, protocolCap))
                    return false;

                selectedProfiles.Add(profile);
                selected.Add(candidate);

                static void Bump(Dictionary<string, int> counts, string group)
                {
                    if (string.IsNullOrWhiteSpace(group)) return;
                    counts.TryGetValue(group, out int current);
                    counts[group] = current + 1;
                }
                Bump(sourceCounts, candidate.SourceGroup);
                Bump(providerCounts, candidate.ProviderGroup);
                Bump(hostnameCounts, candidate.HostGroup);
                Bump(transportCounts, candidate.TransportGroup);
                Bump(protocolCounts, protocol);
                return true;
            }

            int AddCandidates(IEnumerable<FinalProxy> candidates, int limit, bool ipv6Only = false)
            {
                int added = 0;
                foreach (var candidate in candidates)
                {
                    if (selected.Count >= outputCount || added >= limit) break;
                    if (ipv6Only && !IsIpv6Profile(candidate)) continue;
                    if (TryAdd(candidate)) added++;
                }
                return added;
            }

            var lanes = new[]
            {
                ranked.Where(x => GetTopEvidenceLane(x) == 0).ToList(),
                ranked.Where(x => GetTopEvidenceLane(x) == 1).ToList(),
                ranked.Where(x => GetTopEvidenceLane(x) == 2).ToList()
            };

            // Target mix: 55% full-proxy round trips, 30% partial TLS/edge passes,
            // 15% source/stability/corroboration. Scarce lanes are backfilled below.
            int fullTarget = (int)Math.Round(outputCount * 0.55, MidpointRounding.AwayFromZero);
            int partialTarget = (int)Math.Round(outputCount * 0.30, MidpointRounding.AwayFromZero);
            int sourceTarget = outputCount - fullTarget - partialTarget;

            // Reserve up to 10% for modern UDP/QUIC/native-tunnel protocols. The current
            // Xray/TCP-TLS probes do not cover these protocols, so require positive
            // source/stability evidence and keep their verification status explicit.
            int nativeTarget = Math.Min(sourceTarget,
                (int)Math.Ceiling(outputCount * 0.10));
            AddCandidates(lanes[2].Where(IsTopProbeLimitedProtocol), nativeTarget,
                ipv6Only: ipv6SharePercent == 100);

            // IPv6 is a floor, not a reason to duplicate or bypass diversity limits.
            int availableIpv6 = ranked.Count(IsIpv6Profile);
            int ipv6Target = Math.Min(availableIpv6,
                (int)Math.Ceiling(outputCount * (ipv6SharePercent / 100.0)));

            // For the global list, satisfy the IPv6 floor before lane allocation.
            // For top_ipv6 (100%), do not pre-fill the whole list here: that would
            // bypass the evidence mix. Instead, each lane fills its own quota from
            // the IPv6-filtered candidate pool.
            if (ipv6SharePercent < 100 && ipv6Target > 0)
                AddCandidates(ranked.Where(IsIpv6Profile), ipv6Target);

            int[] laneTargets = { fullTarget, partialTarget, sourceTarget };
            for (int lane = 0; lane < lanes.Length && selected.Count < outputCount; lane++)
            {
                int alreadySelected = selected.Count(x => GetTopEvidenceLane(x) == lane);
                int remaining = Math.Max(0, laneTargets[lane] - alreadySelected);
                if (remaining > 0)
                    AddCandidates(lanes[lane], remaining, ipv6Only: ipv6SharePercent == 100);
            }

            // Reallocate any unused lane quota by evidence order, while preserving the
            // same hard endpoint/source/provider/domain/transport/protocol caps.
            if (selected.Count < outputCount)
                AddCandidates(ranked, outputCount - selected.Count,
                    ipv6Only: ipv6SharePercent == 100);

            return selected
                .OrderBy(GetTopEvidenceLane)
                .ThenByDescending(CalculateTopSelectionScore)
                .ThenByDescending(x => x.SourceCount)
                .ThenBy(x => x.Remark, StringComparer.OrdinalIgnoreCase)
                .ThenBy(x => x.Link, StringComparer.Ordinal)
                .ToList();
        }

        private static string EscapeRankingCsv(string? value) =>
            "\"" + (value ?? "").Replace("\"", "\"\"") + "\"";

        internal static async Task WriteVerificationReportAsync(
            string path, IReadOnlyList<FinalProxy> rankedCandidates,
            IReadOnlyList<FinalProxy> top, IReadOnlyList<FinalProxy> topIpv6)
        {
            var topLinks = top.Select(x => x.Link).ToHashSet(StringComparer.Ordinal);
            var topIpv6Links = topIpv6.Select(x => x.Link).ToHashSet(StringComparer.Ordinal);
            const string header = "diagnostic_rank,node_id,host,port,protocol,evidence_tier,evidence_level,selection_lane,top_selection_score,probe_limited_protocol,stable,verification_status,score,tls_status,xray_status,edge_status,source_tested,source_count,source_group,provider_group,hostname_group,transport_group,presence_streak,tls_success_streak,xray_success_streak,in_top_txt,in_top_ipv6_txt";

            // The report grows with every collected node. Stream it directly through
            // gzip instead of keeping a 70–100+ MiB StringBuilder and plain CSV blob
            // in memory or committing an oversized uncompressed file to the repo.
            await using (var file = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None))
            await using (var gzip = new GZipStream(file, CompressionLevel.Optimal))
            await using (var writer = new StreamWriter(gzip, new UTF8Encoding(false)))
            {
                await writer.WriteLineAsync(header);
                for (int i = 0; i < rankedCandidates.Count; i++)
                {
                    var p = rankedCandidates[i];
                    string line = string.Join(",", new[]
                    {
                        (i + 1).ToString(CultureInfo.InvariantCulture),
                        EscapeRankingCsv(p.NodeId), EscapeRankingCsv(p.Host), EscapeRankingCsv(p.Port),
                        EscapeRankingCsv(p.Proto), p.EvidenceTier.ToString(CultureInfo.InvariantCulture),
                        EscapeRankingCsv(GetEvidenceLevel(p)), EscapeRankingCsv(GetTopEvidenceLaneName(p)),
                        CalculateTopSelectionScore(p).ToString(CultureInfo.InvariantCulture),
                        IsTopProbeLimitedProtocol(p) ? "true" : "false",
                        p.IsStable ? "true" : "false",
                        EscapeRankingCsv(p.VerificationStatus),
                        p.Score.ToString(CultureInfo.InvariantCulture),
                        EscapeRankingCsv(GetTestStatus(p.TlsTested, p.TlsVerified)),
                        EscapeRankingCsv(GetTestStatus(p.XrayTested, p.XrayVerified)),
                        EscapeRankingCsv(GetTestStatus(p.EdgeTested, p.EdgeVerified)),
                        p.IranTested ? "true" : "false",
                        p.SourceCount.ToString(CultureInfo.InvariantCulture),
                        EscapeRankingCsv(p.SourceGroup), EscapeRankingCsv(p.ProviderGroup),
                        EscapeRankingCsv(p.HostGroup), EscapeRankingCsv(p.TransportGroup),
                        p.Streak.ToString(CultureInfo.InvariantCulture),
                        p.VerifiedStreak.ToString(CultureInfo.InvariantCulture),
                        p.XrayStreak.ToString(CultureInfo.InvariantCulture),
                        topLinks.Contains(p.Link) ? "true" : "false",
                        topIpv6Links.Contains(p.Link) ? "true" : "false"
                    });
                    await writer.WriteLineAsync(line);
                }
            }

            string summary = string.Join(", ", rankedCandidates.GroupBy(x => x.VerificationStatus)
                .OrderBy(g => g.Key, StringComparer.Ordinal)
                .Select(g => $"{g.Key}={g.Count()}"));
            LogInfo($"Ranking evidence report: {rankedCandidates.Count} ranked candidates ({summary}); details in sub/diagnostics/verification-status.csv.gz");
        }

        private static string GetScoreBand(int score) => score switch
        {
            < 20 => "0-19",
            < 40 => "20-39",
            < 60 => "40-59",
            < 80 => "60-79",
            < 100 => "80-99",
            _ => "100+"
        };

        private static RankingBaselineSnapshot LoadRankingBaseline()
        {
            try
            {
                string path = Path.Combine("state", "ranking-baseline.json");
                if (File.Exists(path))
                    return JsonSerializer.Deserialize<RankingBaselineSnapshot>(File.ReadAllText(path))
                        ?? new RankingBaselineSnapshot();
            }
            catch (Exception ex)
            {
                LogWarning($"Ranking calibration baseline unreadable; starting without prior scores: {ex.Message}");
            }
            return new RankingBaselineSnapshot();
        }

        private static async Task WriteRankingCalibrationAsync(
            string samplePath, string summaryPath, IReadOnlyList<FinalProxy> proxies)
        {
            var prior = LoadRankingBaseline();
            var priorById = prior.Nodes
                .Where(x => !string.IsNullOrWhiteSpace(x.NodeId))
                .GroupBy(x => x.NodeId, StringComparer.Ordinal)
                .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
            var samples = proxies
                .Where(x => x.XrayTested && !string.IsNullOrWhiteSpace(x.NodeId) && priorById.ContainsKey(x.NodeId))
                .Select(x => (Current: x, Previous: priorById[x.NodeId]))
                .OrderBy(x => x.Previous.Score)
                .ToList();

            var sampleCsv = new StringBuilder();
            sampleCsv.AppendLine("node_id,baseline_captured_at_utc,previous_score,previous_evidence_tier,previous_verification_status,previous_xray_result,current_xray_result");
            foreach (var s in samples)
                sampleCsv.AppendLine(string.Join(",", new[]
                {
                    EscapeRankingCsv(s.Current.NodeId), EscapeRankingCsv(prior.CapturedAtUtc),
                    s.Previous.Score.ToString(CultureInfo.InvariantCulture),
                    s.Previous.EvidenceTier.ToString(CultureInfo.InvariantCulture),
                    EscapeRankingCsv(s.Previous.VerificationStatus),
                    s.Previous.XrayVerified ? "passed" : "failed",
                    s.Current.XrayVerified ? "passed" : "failed"
                }));
            await File.WriteAllTextAsync(samplePath, sampleCsv.ToString(), new UTF8Encoding(false));

            var summaryCsv = new StringBuilder();
            summaryCsv.AppendLine("previous_score_band,retested_nodes,current_roundtrip_successes,current_roundtrip_failures,current_success_rate_percent,previous_roundtrip_successes,previous_successes_persisted,persistence_rate_percent");
            string[] bands = { "0-19", "20-39", "40-59", "60-79", "80-99", "100+" };
            foreach (string band in bands)
            {
                var group = samples.Where(s => GetScoreBand(s.Previous.Score) == band).ToList();
                int count = group.Count;
                int successes = group.Count(s => s.Current.XrayVerified);
                int priorSuccesses = group.Count(s => s.Previous.XrayVerified);
                int persisted = group.Count(s => s.Previous.XrayVerified && s.Current.XrayVerified);
                string rate = count == 0 ? "" : (successes * 100.0 / count).ToString("0.0", CultureInfo.InvariantCulture);
                string persistRate = priorSuccesses == 0 ? "" : (persisted * 100.0 / priorSuccesses).ToString("0.0", CultureInfo.InvariantCulture);
                summaryCsv.AppendLine(string.Join(",", new[]
                {
                    band, count.ToString(CultureInfo.InvariantCulture), successes.ToString(CultureInfo.InvariantCulture),
                    (count - successes).ToString(CultureInfo.InvariantCulture), rate,
                    priorSuccesses.ToString(CultureInfo.InvariantCulture), persisted.ToString(CultureInfo.InvariantCulture),
                    persistRate
                }));
            }
            await File.WriteAllTextAsync(summaryPath, summaryCsv.ToString(), new UTF8Encoding(false));

            if (samples.Count == 0)
                LogInfo($"Ranking calibration: no previously scored nodes were tested again this run (prior baseline {(string.IsNullOrEmpty(prior.CapturedAtUtc) ? "none" : prior.CapturedAtUtc)}); summary will fill as runs overlap.");
            else
            {
                string bandsSummary = string.Join("; ", bands.Select(band =>
                {
                    var group = samples.Where(s => GetScoreBand(s.Previous.Score) == band).ToList();
                    return group.Count == 0 ? $"{band}: n=0" :
                        $"{band}: {group.Count(s => s.Current.XrayVerified)}/{group.Count} succeeded";
                }));
                LogInfo($"Ranking calibration: {samples.Count} repeat-tested nodes; subsequent Xray success by previous score band: {bandsSummary}.");
            }

            var nextNodes = proxies
                .Where(x => x.XrayTested && !string.IsNullOrWhiteSpace(x.NodeId))
                .GroupBy(x => x.NodeId, StringComparer.Ordinal)
                .Select(g => g.First())
                .OrderByDescending(x => x.Score)
                .Select(x => new RankingBaselineEntry
                {
                    NodeId = x.NodeId, Score = x.Score, EvidenceTier = x.EvidenceTier,
                    VerificationStatus = x.VerificationStatus, XrayVerified = x.XrayVerified
                })
                .ToList();
            if (nextNodes.Count >= 50)
            {
                try
                {
                    Directory.CreateDirectory("state");
                    var snapshot = new RankingBaselineSnapshot
                    {
                        CapturedAtUtc = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture),
                        Nodes = nextNodes
                    };
                    File.WriteAllText(Path.Combine("state", "ranking-baseline.json"), JsonSerializer.Serialize(snapshot));
                    LogInfo($"Ranking calibration baseline refreshed with {nextNodes.Count} actual Xray attempts.");
                }
                catch (Exception ex)
                {
                    LogWarning($"Ranking calibration baseline could not be saved (non-fatal): {ex.Message}");
                }
            }
            else
                LogInfo($"Ranking calibration baseline kept unchanged: only {nextNodes.Count} actual Xray attempts (need 50 to refresh).");
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
        internal sealed class WgInfo
        {
            public string? PrivateKey = null;
            public string? PublicKey = null;
            public string Address = "10.0.0.2/32";
            public string Dns = "1.1.1.1";
            public string AllowedIPs = "0.0.0.0/0, ::/0";
            public string? PresharedKey = null;
            public string Host = "";
            public int Port = 51820;
            public int PersistentKeepalive = 25;
            public string[] Reserved = Array.Empty<string>();
        }

        internal static bool IsValidWireguardIpList(string value, bool requirePrefix)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Any(char.IsControl)) return false;
            var entries = value.Split(',', StringSplitOptions.TrimEntries);
            if (entries.Length == 0 || entries.Any(string.IsNullOrEmpty)) return false;

            foreach (var entry in entries)
            {
                int slash = entry.IndexOf('/');
                if (slash < 0)
                {
                    if (requirePrefix || !IPAddress.TryParse(entry, out _)) return false;
                    continue;
                }

                if (slash == 0 || slash != entry.LastIndexOf('/') ||
                    !IPAddress.TryParse(entry[..slash], out var address))
                    return false;

                string prefixText = entry[(slash + 1)..];
                if (prefixText.Length == 0 ||
                    prefixText.Any(ch => ch < '0' || ch > '9') ||
                    !int.TryParse(prefixText, out int prefix))
                    return false;

                int maxPrefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 :
                    address.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 0;
                if (prefix < 0 || prefix > maxPrefix) return false;
            }
            return true;
        }

        internal static bool IsValidWireguardDns(string value)
        {
            if (value.Any(char.IsControl)) return false;
            if (string.IsNullOrWhiteSpace(value)) return true;
            var entries = value.Split(',', StringSplitOptions.TrimEntries);
            return entries.Length > 0 &&
                entries.All(entry => !string.IsNullOrEmpty(entry) && IPAddress.TryParse(entry, out _));
        }

        internal static bool IsValidWireguardHost(string host)
        {
            if (string.IsNullOrWhiteSpace(host) || host.Any(char.IsControl) || host.Any(char.IsWhiteSpace))
                return false;

            string normalized = host.Trim().Trim('[', ']').TrimEnd('.');
            if (IPAddress.TryParse(normalized, out _)) return true;
            return normalized.Length <= 253 &&
                normalized.Contains('.') &&
                Uri.CheckHostName(normalized) == UriHostNameType.Dns;
        }

        internal static bool IsValidWireguardOutputFields(
            string host, int port, string address, string dns, string allowedIps,
            IEnumerable<string>? reserved = null)
        {
            if (port is < 1 or > 65535 ||
                !IsValidWireguardHost(host) ||
                !IsValidWireguardIpList(address, requirePrefix: false) ||
                !IsValidWireguardDns(dns) ||
                !IsValidWireguardIpList(allowedIps, requirePrefix: true))
                return false;

            var reservedValues = (reserved ?? Array.Empty<string>())
                .Select(value => value.Trim())
                .ToArray();
            return reservedValues.Length == 0 ||
                (reservedValues.Length == 3 && reservedValues.All(value => byte.TryParse(value, out _)));
        }

        internal static string SerializeWireguardClashYaml(
            IEnumerable<Dictionary<string, object?>> proxies)
        {
            var document = new Dictionary<string, object?>
            {
                ["proxies"] = proxies.ToList()
            };
            return new SerializerBuilder().Build().Serialize(document);
        }

        internal static List<string> SerializeWireguardClashYamlParts(
            IReadOnlyList<Dictionary<string, object?>> proxies,
            int maxNodesPerPart = 1000,
            int maxBytesPerPart = 50 * 1024 * 1024)
        {
            if (maxNodesPerPart < 1) throw new ArgumentOutOfRangeException(nameof(maxNodesPerPart));
            if (maxBytesPerPart < 1) throw new ArgumentOutOfRangeException(nameof(maxBytesPerPart));

            var parts = new List<string>();
            int offset = 0;
            while (offset < proxies.Count)
            {
                int count = Math.Min(maxNodesPerPart, proxies.Count - offset);
                string yaml;
                while (true)
                {
                    yaml = SerializeWireguardClashYaml(proxies.Skip(offset).Take(count));
                    if (Encoding.UTF8.GetByteCount(yaml) <= maxBytesPerPart)
                        break;

                    if (count == 1)
                        throw new InvalidOperationException(
                            "A single WireGuard YAML proxy entry exceeds the configured part-size limit.");
                    count = Math.Max(1, count / 2);
                }

                parts.Add(yaml);
                offset += count;
            }

            return parts;
        }

        internal static List<string> DeduplicateFallbackLinks(IEnumerable<string> links)
            => links
                .Where(link => !string.IsNullOrWhiteSpace(link))
                .Select(link => link.Trim())
                .GroupBy(link =>
                {
                    var parsed = ParseProxyLine(link);
                    return parsed?.SelectionProfileKey ?? "raw:" + link;
                }, StringComparer.Ordinal)
                .Select(group => group.OrderBy(link => link, StringComparer.Ordinal).First())
                .OrderBy(link => link, StringComparer.OrdinalIgnoreCase)
                .ThenBy(link => link, StringComparer.Ordinal)
                .ToList();

        internal static List<IGrouping<string, FinalProxy>> GetRawProtocolGroups(
            IEnumerable<FinalProxy> proxies)
            => proxies.GroupBy(proxy => proxy.Proto)
                .Where(group =>
                {
                    string key = group.Key?.Trim() ?? "";
                    return key.Length > 0 &&
                        !key.Equals("unknown", StringComparison.OrdinalIgnoreCase) &&
                        !key.Equals("wireguard", StringComparison.OrdinalIgnoreCase);
                })
                .ToList();

        internal static bool IsValidWireguardLink(string link)
            => TryParseWireguardInfo(link) is not null;

        internal static WgInfo? TryParseWireguardInfo(string link)
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
                    if (decoded.Contains("[Interface]", StringComparison.OrdinalIgnoreCase) &&
                        decoded.Contains("[Peer]", StringComparison.OrdinalIgnoreCase))
                    {
                        // One ParsedProxy represents one peer. Do not silently truncate a
                        // valid multi-peer profile into a different one-peer configuration.
                        int interfaceCount = Regex.Matches(decoded, @"(?im)^\s*\[Interface\]\s*$").Count;
                        int peerCount = Regex.Matches(decoded, @"(?im)^\s*\[Peer\]\s*$").Count;
                        if (interfaceCount != 1 || peerCount != 1) return null;

                        info.PrivateKey = GetWireguardDirective(decoded, "Interface", "PrivateKey");
                        info.PublicKey = GetWireguardDirective(decoded, "Peer", "PublicKey");
                        string address = GetWireguardDirective(decoded, "Interface", "Address");
                        if (!string.IsNullOrEmpty(address)) info.Address = address;
                        string dns = GetWireguardDirective(decoded, "Interface", "DNS");
                        if (!string.IsNullOrEmpty(dns)) info.Dns = dns;
                        string allowed = GetWireguardDirective(decoded, "Peer", "AllowedIPs");
                        if (!string.IsNullOrEmpty(allowed)) info.AllowedIPs = allowed;
                        string psk = GetWireguardDirective(decoded, "Peer", "PresharedKey");
                        if (!string.IsNullOrEmpty(psk)) info.PresharedKey = psk;

                        string endpoint = GetWireguardDirective(decoded, "Peer", "Endpoint");
                        if (!string.IsNullOrEmpty(endpoint))
                        {
                            if (endpoint.StartsWith('['))
                            {
                                int close = endpoint.IndexOf(']');
                                if (close <= 1 || close + 1 >= endpoint.Length || endpoint[close + 1] != ':')
                                    return null;
                                info.Host = endpoint[1..close];
                                if (!int.TryParse(endpoint[(close + 2)..], out info.Port)) return null;
                            }
                            else
                            {
                                int colon = endpoint.LastIndexOf(':');
                                if (colon <= 0 || !int.TryParse(endpoint[(colon + 1)..], out info.Port))
                                    return null;
                                info.Host = endpoint[..colon];
                            }
                        }

                        string keepalive = GetWireguardDirective(decoded, "Peer", "PersistentKeepalive");
                        if (!string.IsNullOrEmpty(keepalive) &&
                            (!int.TryParse(keepalive, out info.PersistentKeepalive) ||
                             info.PersistentKeepalive is < 0 or > 65535))
                            return null;
                    }
                }
                catch { }

                // Try 2: URI format — wg://privkey@host:port?pk=serverpub&ip=addr&dns=...
                if (string.IsNullOrEmpty(info.PrivateKey) || string.IsNullOrEmpty(info.PublicKey))
                {
                    var uri = new Uri(baseLink);
                    if (uri.Port == 0) return null;
                    var q = ParseQuery(uri.Query);

                    info.PrivateKey = Uri.UnescapeDataString(uri.UserInfo ?? "");
                    if (string.IsNullOrEmpty(info.PrivateKey))
                        info.PrivateKey = q.GetValueOrDefault("privatekey", q.GetValueOrDefault("private_key", ""));

                    info.Host = uri.Host;
                    info.Port = uri.Port > 0 ? uri.Port : 51820;
                    info.PublicKey = q.GetValueOrDefault("pk", q.GetValueOrDefault("publickey", q.GetValueOrDefault("server_publickey", "")));
                    info.Address = q.GetValueOrDefault("ip", q.GetValueOrDefault("address", q.GetValueOrDefault("allowed_ip", "10.0.0.2/32")));
                    info.Dns = q.GetValueOrDefault("dns", "1.1.1.1");
                    info.AllowedIPs = q.GetValueOrDefault("allowedips", q.GetValueOrDefault("allowed_ips", "0.0.0.0/0, ::/0"));
                    info.PresharedKey = q.GetValueOrDefault("psk", q.GetValueOrDefault("presharedkey", ""));
                    string keepalive = q.GetValueOrDefault("persistentkeepalive", q.GetValueOrDefault("keepalive", ""));
                    if (!string.IsNullOrEmpty(keepalive) &&
                        (!int.TryParse(keepalive, out info.PersistentKeepalive) ||
                         info.PersistentKeepalive is < 0 or > 65535))
                        return null;
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
                    info.PersistentKeepalive is < 0 or > 65535)
                    return null;

                info.Host = info.Host.Trim().Trim('[', ']');
                if (!IsValidWireguardOutputFields(
                        info.Host, info.Port, info.Address, info.Dns, info.AllowedIPs, info.Reserved))
                    return null;

                return info;
            }
            catch { return null; }
        }

        private static string GetWireguardDirective(string content, string sectionName, string directiveName)
        {
            string currentSection = "";
            foreach (string rawLine in content.Split(new[] { "\r\n", "\n", "\r" }, StringSplitOptions.None))
            {
                string line = rawLine.Trim();
                if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';'))
                    continue;

                if (line.StartsWith('[') && line.EndsWith(']'))
                {
                    currentSection = line[1..^1].Trim();
                    continue;
                }

                if (!currentSection.Equals(sectionName, StringComparison.OrdinalIgnoreCase))
                    continue;

                int separator = line.IndexOf('=');
                if (separator <= 0 ||
                    !line[..separator].Trim().Equals(directiveName, StringComparison.OrdinalIgnoreCase))
                    continue;

                string value = line[(separator + 1)..].Trim();
                int comment = value.IndexOf('#');
                if (comment >= 0) value = value[..comment].TrimEnd();
                return value;
            }

            return "";
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

        internal static string FormatWireguardEndpoint(string host, int port)
        {
            string normalizedHost = (host ?? "").Trim().Trim('[', ']');
            if (IPAddress.TryParse(normalizedHost, out var ip) &&
                ip.AddressFamily == AddressFamily.InterNetworkV6)
                return $"[{normalizedHost}]:{port}";
            return $"{normalizedHost}:{port}";
        }

        internal static string BuildWireguardConf(WgInfo info)
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
            sb.AppendLine($"Endpoint = {FormatWireguardEndpoint(info.Host, info.Port)}");
            sb.AppendLine($"AllowedIPs = {info.AllowedIPs}");
            sb.AppendLine($"PersistentKeepalive = {info.PersistentKeepalive}");
            return sb.ToString();
        }

        // ====================== WRITE TXT (chunked) ======================
        // First ChunkSize lines always go to <name>.txt — that filename never changes, so a
        // subscription link to it stays valid regardless of node count. Any overflow
        // beyond that goes to <name>_part2.txt, _part3.txt, ... (numbering starts at 2,
        // not 1, precisely so xx_part1.txt never exists and can't be confused with xx.txt).
        internal static async Task<int> WriteSubscriptionPartsAsync(
            string pathNoExt,
            IEnumerable<string> lines,
            long maxBytes = SubscriptionPartMaxBytes,
            int maxLinesPerPart = int.MaxValue)
        {
            if (string.IsNullOrWhiteSpace(pathNoExt))
                throw new ArgumentException("An output path is required.", nameof(pathNoExt));
            if (maxBytes <= 0)
                throw new ArgumentOutOfRangeException(nameof(maxBytes), "The part byte limit must be positive.");
            if (maxLinesPerPart <= 0)
                throw new ArgumentOutOfRangeException(nameof(maxLinesPerPart), "The part line limit must be positive.");

            Directory.CreateDirectory(Path.GetDirectoryName(pathNoExt) ?? ".");
            var currentPart = new List<string>();
            int partNumber = 1;
            int partCount = 0;
            long bytesInPart = 0;

            async Task FlushPartAsync()
            {
                string path = partNumber == 1
                    ? pathNoExt + ".txt"
                    : $"{pathNoExt}_part{partNumber}.txt";
                await File.WriteAllLinesAsync(path, currentPart, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
                partCount++;
                partNumber++;
                currentPart.Clear();
                bytesInPart = 0;
            }

            foreach (string line in lines)
            {
                if (line is null)
                    throw new InvalidDataException("A subscription entry cannot be null.");
                if (line.Contains('\r') || line.Contains('\n'))
                    throw new InvalidDataException("A subscription entry must occupy exactly one line.");

                long lineBytes = Encoding.UTF8.GetByteCount(line) + 1; // UTF-8 line plus LF.
                if (lineBytes > maxBytes)
                    throw new InvalidDataException(
                        $"A single subscription entry requires {lineBytes} bytes, exceeding the {maxBytes}-byte part limit.");

                if (currentPart.Count > 0 &&
                    (bytesInPart + lineBytes > maxBytes || currentPart.Count >= maxLinesPerPart))
                    await FlushPartAsync();

                currentPart.Add(line);
                bytesInPart += lineBytes;
            }

            // Keep the original filename as part one, including for an empty feed.
            if (currentPart.Count > 0 || partCount == 0)
                await FlushPartAsync();
            return partCount;
        }

        // Retain the existing 1,000-node category chunk behavior while applying
        // the same per-file byte ceiling as the other subscription feeds.
        private static async Task WriteTxt(string pathNoExt, List<FinalProxy> proxies)
        {
            await WriteSubscriptionPartsAsync(
                pathNoExt, proxies.Select(x => x.Link), maxLinesPerPart: ChunkSize);
        }

        // ====================== PARSE ======================

    }
}
