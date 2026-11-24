using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ProxyCollector.Services;

/// <summary>
/// Runs concurrent source and nested-provider retrieval, applying bounded response
/// memory reservations and spooling extracted lines. The caller supplies format
/// decoders and source-policy callbacks, keeping collection policy out of transport.
/// </summary>
public sealed class SourceFetcher
{
    private readonly HttpClient _http;
    private readonly SourceFetchBudget _memoryBudget;
    private const int MaxConcurrentSources = 30;
    private const int MaxNestedProvidersPerSource = 8;
    private const int MaxNestedLinesPerSource = 20000;
    private const int MaxAttempts = 2;
    private const int MaxProviderResponseBytes = 16 * 1024 * 1024;

    public SourceFetcher(HttpClient http, SourceFetchBudget memoryBudget)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _memoryBudget = memoryBudget ?? throw new ArgumentNullException(nameof(memoryBudget));
    }

    public async Task<SourceFetchResult> FetchAsync(
        IReadOnlyList<string> sourceUrls,
        Func<string, int> getResponseLimit,
        Func<string, string, List<string>> decodeAndExtractLines,
        Func<string, List<string>> extractProviderUrls,
        Func<string, List<string>> getProviderFetchCandidates,
        Func<string, int> countRawLines,
        Action<string> logError,
        Action<string> logWarning,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(sourceUrls);
        ArgumentNullException.ThrowIfNull(getResponseLimit);
        ArgumentNullException.ThrowIfNull(decodeAndExtractLines);
        ArgumentNullException.ThrowIfNull(extractProviderUrls);
        ArgumentNullException.ThrowIfNull(getProviderFetchCandidates);
        ArgumentNullException.ThrowIfNull(countRawLines);
        ArgumentNullException.ThrowIfNull(logError);
        ArgumentNullException.ThrowIfNull(logWarning);

        var sourceIndices = sourceUrls
            .Select((url, index) => (Url: url, Index: index))
            .ToDictionary(item => item.Url, item => item.Index, StringComparer.Ordinal);
        var statistics = new ConcurrentDictionary<string, SourceFetchStatistics>(StringComparer.Ordinal);
        var spool = new SourceSpoolStore();

        try
        {
            await Parallel.ForEachAsync(
                sourceUrls,
                new ParallelOptions
                {
                    MaxDegreeOfParallelism = MaxConcurrentSources,
                    CancellationToken = cancellationToken
                },
                async (url, sourceCancellationToken) =>
                {
                    var stat = statistics.GetOrAdd(url, _ => new SourceFetchStatistics());
                    var fetchTimer = Stopwatch.StartNew();

                    try
                    {
                        for (int attempt = 1; attempt <= MaxAttempts; attempt++)
                        {
                            try
                            {
                                using var requestTimeout = CancellationTokenSource.CreateLinkedTokenSource(
                                    sourceCancellationToken);
                                requestTimeout.CancelAfter(TimeSpan.FromSeconds(25));

                                using var response = await _http.GetAsync(
                                    url,
                                    HttpCompletionOption.ResponseHeadersRead,
                                    requestTimeout.Token);
                                response.EnsureSuccessStatusCode();

                                int maxResponseBytes = getResponseLimit(url);
                                int reservationBytes = SourceFetchBudget.GetReservationBytes(
                                    response.Content.Headers.ContentLength,
                                    response.Content.Headers.ContentEncoding.Count > 0,
                                    maxResponseBytes);

                                int extractedLineCount;
                                string[] providerUrls;

                                // The response body is not read until its estimated working
                                // set has been reserved. Unknown or compressed bodies reserve
                                // the full decompressed ceiling.
                                using (await _memoryBudget.AcquireSourceAsync(
                                    reservationBytes, requestTimeout.Token))
                                {
                                    string text = await ReadContentLimitedAsync(
                                        response.Content, maxResponseBytes, requestTimeout.Token);

                                    Interlocked.Increment(ref stat.FetchSuccesses);
                                    Interlocked.Add(ref stat.RawBytes, Encoding.UTF8.GetByteCount(text));
                                    Interlocked.Add(ref stat.RawLines, countRawLines(text));

                                    List<string> lines = decodeAndExtractLines(text, url);
                                    extractedLineCount = lines.Count;
                                    providerUrls = extractedLineCount == 0 &&
                                        text.Contains("proxy-providers:", StringComparison.OrdinalIgnoreCase)
                                        ? extractProviderUrls(text).Take(MaxNestedProvidersPerSource).ToArray()
                                        : Array.Empty<string>();

                                    await spool.WriteSourceAsync(
                                        sourceIndices[url], lines, sourceCancellationToken);
                                }

                                // The top-level response and its decoded line list are now
                                // outside the working set. Fetch nested providers one at a time.
                                if (providerUrls.Length > 0)
                                {
                                    foreach (string providerUrl in providerUrls)
                                    {
                                        foreach (string fetchUrl in getProviderFetchCandidates(providerUrl))
                                        {
                                            bool yielded = false;
                                            for (int providerAttempt = 1; providerAttempt <= MaxAttempts; providerAttempt++)
                                            {
                                                try
                                                {
                                                    using var providerTimeout = CancellationTokenSource.CreateLinkedTokenSource(
                                                        sourceCancellationToken);
                                                    providerTimeout.CancelAfter(TimeSpan.FromSeconds(12));

                                                    using var providerResponse = await _http.GetAsync(
                                                        fetchUrl,
                                                        HttpCompletionOption.ResponseHeadersRead,
                                                        providerTimeout.Token);
                                                    providerResponse.EnsureSuccessStatusCode();

                                                    int providerReservationBytes = SourceFetchBudget.GetReservationBytes(
                                                        providerResponse.Content.Headers.ContentLength,
                                                        providerResponse.Content.Headers.ContentEncoding.Count > 0,
                                                        MaxProviderResponseBytes);

                                                    using (await _memoryBudget.AcquireProviderAsync(
                                                        providerReservationBytes, providerTimeout.Token))
                                                    {
                                                        string providerText = await ReadContentLimitedAsync(
                                                            providerResponse.Content,
                                                            MaxProviderResponseBytes,
                                                            providerTimeout.Token);
                                                        Interlocked.Increment(ref stat.ProviderSuccesses);

                                                        List<string> providerLines = decodeAndExtractLines(
                                                            providerText, fetchUrl);
                                                        if (providerLines.Count > 0)
                                                        {
                                                            await spool.AppendSourceAsync(
                                                                sourceIndices[url],
                                                                providerLines,
                                                                providerTimeout.Token);
                                                            extractedLineCount += providerLines.Count;
                                                            yielded = true;
                                                        }
                                                    }

                                                    break;
                                                }
                                                catch (OperationCanceledException) when (sourceCancellationToken.IsCancellationRequested)
                                                {
                                                    throw;
                                                }
                                                catch (Exception exception)
                                                {
                                                    if (providerAttempt == MaxAttempts)
                                                    {
                                                        Interlocked.Increment(ref stat.ProviderFailures);
                                                        logWarning(
                                                            $"  provider fetch failed (after retry) for {url} → {fetchUrl}: {exception.Message}");
                                                    }
                                                    else
                                                    {
                                                        await Task.Delay(700, sourceCancellationToken);
                                                    }
                                                }
                                            }

                                            // Prefer a direct underlying subscription only if it
                                            // produced proxy links; otherwise try the wrapper URL.
                                            if (yielded) break;
                                        }

                                        if (extractedLineCount >= MaxNestedLinesPerSource)
                                            break;
                                    }
                                }

                                Interlocked.Add(ref stat.Lines, extractedLineCount);
                                return;
                            }
                            catch (OperationCanceledException) when (sourceCancellationToken.IsCancellationRequested)
                            {
                                throw;
                            }
                            catch (Exception exception)
                            {
                                if (attempt == MaxAttempts)
                                {
                                    logError($"Failed {url}: {exception.Message}");
                                    return;
                                }

                                await Task.Delay(1500, sourceCancellationToken);
                            }
                        }
                    }
                    finally
                    {
                        Interlocked.Add(ref stat.FetchElapsedMs, fetchTimer.ElapsedMilliseconds);
                    }
                });

            return new SourceFetchResult(spool, statistics, sourceIndices);
        }
        catch
        {
            spool.Dispose();
            throw;
        }
    }

    public static async Task<string> ReadContentLimitedAsync(
        HttpContent content,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(content);
        if (maximumBytes <= 0) throw new ArgumentOutOfRangeException(nameof(maximumBytes));

        long? declaredLength = content.Headers.ContentLength;
        if (declaredLength.HasValue && declaredLength.Value > maximumBytes)
            throw new InvalidDataException(
                $"HTTP response declares {declaredLength.Value} bytes, above the {maximumBytes}-byte limit.");

        await using var stream = await content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];

        while (true)
        {
            int read = await stream.ReadAsync(chunk.AsMemory(0, chunk.Length), cancellationToken);
            if (read == 0) break;
            if (buffer.Length + read > maximumBytes)
                throw new InvalidDataException(
                    $"HTTP response exceeded the {maximumBytes}-byte limit while streaming.");
            await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken);
        }

        return Encoding.UTF8.GetString(buffer.GetBuffer(), 0, checked((int)buffer.Length));
    }
}

/// <summary>Mutable counters shared by the fetch stage and the sequential parser.</summary>
public sealed class SourceFetchStatistics
{
    public int FetchSuccesses;
    public int RawBytes;
    public int RawLines;
    public int Lines;
    public int Parsed;
    public int Unique;
    public int ProviderSuccesses;
    public int ProviderFailures;
    public long FetchElapsedMs;
    public long ParseElapsedMs;
}

/// <summary>Owns the source spool for one collection run and exposes per-feed diagnostics.</summary>
public sealed class SourceFetchResult : IDisposable
{
    public SourceSpoolStore Spool { get; }
    public ConcurrentDictionary<string, SourceFetchStatistics> Statistics { get; }
    public IReadOnlyDictionary<string, int> SourceIndices { get; }

    public long TotalExtractedLines
        => Statistics.Values.Sum(stat => (long)Volatile.Read(ref stat.Lines));

    internal SourceFetchResult(
        SourceSpoolStore spool,
        ConcurrentDictionary<string, SourceFetchStatistics> statistics,
        IReadOnlyDictionary<string, int> sourceIndices)
    {
        Spool = spool;
        Statistics = statistics;
        SourceIndices = sourceIndices;
    }

    public void Dispose() => Spool.Dispose();
}
