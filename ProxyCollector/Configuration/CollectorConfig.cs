using System;
using System.Collections.Generic;
using System.Linq;

namespace ProxyCollector.Configuration
{
    /// <summary>
    /// Reads the source list from the "Sources" environment variable (a multi-line
    /// string set by the GitHub Actions workflow). Lines starting with '#' are section
    /// headers/comments, not URLs — inside the workflow's block scalar they're part of
    /// the string, so filtering happens here rather than in the YAML.
    ///
    /// v6.11 additions:
    ///  - github.com/{user}/{repo}/raw/{branch}/{path} URLs are normalized to their
    ///    canonical raw.githubusercontent.com form. Both forms serve the identical file,
    ///    so when a source list contains both spellings they were being fetched twice —
    ///    pure wasted bandwidth and doubled parse work for zero extra nodes.
    ///  - Case-insensitive dedup after normalization.
    ///  - Startup accounting: how many raw lines, how many comments skipped, how many
    ///    duplicates collapsed, how many real sources remain.
    /// </summary>
    public sealed class CollectorConfig
    {
        private static readonly Lazy<CollectorConfig> _instance = new(() => new CollectorConfig());
        public static CollectorConfig Instance => _instance.Value;

        public string[] Sources { get; }

        private CollectorConfig()
        {
            var raw = Environment.GetEnvironmentVariable("Sources") ?? "";

            var lines = raw.Split('\n', '\r')
                .Select(l => l.Trim())
                .ToList();

            int commentLines = 0;
            int nonUrlLines = 0;
            var urls = new List<string>();

            foreach (var line in lines)
            {
                if (line.Length == 0) continue;

                if (line.StartsWith("#"))
                {
                    // section header ("# === Hysteria2 Priority ===") — not a source
                    commentLines++;
                    continue;
                }

                if (!line.StartsWith("http://", StringComparison.OrdinalIgnoreCase) &&
                    !line.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                {
                    // not a URL at all (stray text, YAML residue, whatever) — never
                    // hand this to HttpClient, it just burns two attempts + a 1.5s
                    // retry delay and logs a confusing failure
                    nonUrlLines++;
                    continue;
                }

                urls.Add(NormalizeUrl(line));
            }

            int beforeDedup = urls.Count;
            Sources = urls
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            Console.WriteLine(
                $"[INFO] Loaded {Sources.Length} sources " +
                $"({commentLines} comment lines, {nonUrlLines} non-URL lines, " +
                $"{beforeDedup - Sources.Length} duplicates collapsed).");
        }

        /// <summary>
        /// https://github.com/{user}/{repo}/raw/{branch}/{path}
        ///   → https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}
        ///
        /// Same bytes, one canonical spelling — makes duplicates that only differ by
        /// URL form collapse under Distinct().
        /// </summary>
        private static string NormalizeUrl(string url)
        {
            if (!url.StartsWith("https://github.com/", StringComparison.OrdinalIgnoreCase))
                return url;

            // everything between the host and "/raw/"
            int rawIdx = url.IndexOf("/raw/", StringComparison.OrdinalIgnoreCase);
            if (rawIdx < 0) return url;   // e.g. a github.com blob URL — leave untouched

            string ownerRepo = url["https://github.com/".Length..rawIdx];
            string rest = url[(rawIdx + "/raw/".Length)..];
            return $"https://raw.githubusercontent.com/{ownerRepo}/{rest}";
        }
    }
}
