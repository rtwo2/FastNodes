using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
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
    internal const int MaxNestedLinesPerSource = 20000;
    private const int MaxAttempts = 3;
    private const int MaxProviderResponseBytes = 16 * 1024 * 1024;
    private static readonly TimeSpan MaximumRetryAfter = TimeSpan.FromSeconds(60);
    private static readonly ConcurrentDictionary<string, DateTimeOffset> HostBackoffUntil =
        new(StringComparer.OrdinalIgnoreCase);

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
                                await WaitForHostBackoffAsync(url, sourceCancellationToken);
                                using var requestTimeout = CancellationTokenSource.CreateLinkedTokenSource(
                                    sourceCancellationToken);
                                requestTimeout.CancelAfter(TimeSpan.FromSeconds(25));

                                using var response = await _http.GetAsync(
                                    url,
                                    HttpCompletionOption.ResponseHeadersRead,
                                    requestTimeout.Token);
                                if (!response.IsSuccessStatusCode)
                                {
                                    if (IsRetryableStatus(response.StatusCode))
                                    {
                                        TimeSpan retryDelay = GetRetryDelay(response, attempt);
                                        if (response.StatusCode == HttpStatusCode.TooManyRequests)
                                            RegisterHostBackoff(url, retryDelay);
                                        if (attempt == MaxAttempts)
                                        {
                                            logError($"Failed {url} after {MaxAttempts} attempts: HTTP {(int)response.StatusCode} {response.ReasonPhrase}");
                                            return;
                                        }
                                        if (response.StatusCode != HttpStatusCode.TooManyRequests)
                                            await Task.Delay(retryDelay, sourceCancellationToken);
                                        continue;
                                    }

                                    // Permanent 4xx failures (notably 404/410) are not retried.
                                    logError($"Failed {url}: HTTP {(int)response.StatusCode} {response.ReasonPhrase}");
                                    return;
                                }

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
                                    providerUrls = text.Contains("proxy-providers:", StringComparison.OrdinalIgnoreCase)
                                        ? extractProviderUrls(text).Take(MaxNestedProvidersPerSource).ToArray()
                                        : Array.Empty<string>();

                                    await spool.WriteSourceAsync(
                                        sourceIndices[url], lines, sourceCancellationToken);
                                }

                                // The top-level response and its decoded line list are now
                                // outside the working set. Fetch nested providers one at a time.
                                if (providerUrls.Length > 0)
                                {
                                    int nestedLineCount = 0;
                                    foreach (string providerUrl in providerUrls)
                                    {
                                        if (nestedLineCount >= MaxNestedLinesPerSource)
                                            break;

                                        foreach (string fetchUrl in getProviderFetchCandidates(providerUrl))
                                        {
                                            bool yielded = false;
                                            for (int providerAttempt = 1; providerAttempt <= MaxAttempts; providerAttempt++)
                                            {
                                                try
                                                {
                                                    await WaitForHostBackoffAsync(fetchUrl, sourceCancellationToken);
                                                    using var providerTimeout = CancellationTokenSource.CreateLinkedTokenSource(
                                                        sourceCancellationToken);
                                                    providerTimeout.CancelAfter(TimeSpan.FromSeconds(12));

                                                    using var providerResponse = await _http.GetAsync(
                                                        fetchUrl,
                                                        HttpCompletionOption.ResponseHeadersRead,
                                                        providerTimeout.Token);
                                                    if (!providerResponse.IsSuccessStatusCode)
                                                    {
                                                        if (IsRetryableStatus(providerResponse.StatusCode))
                                                        {
                                                            TimeSpan retryDelay = GetRetryDelay(providerResponse, providerAttempt);
                                                            if (providerResponse.StatusCode == HttpStatusCode.TooManyRequests)
                                                                RegisterHostBackoff(fetchUrl, retryDelay);
                                                            if (providerAttempt == MaxAttempts)
                                                            {
                                                                Interlocked.Increment(ref stat.ProviderFailures);
                                                                logWarning(
                                                                    $"  provider fetch failed after {MaxAttempts} attempts for {url} → {fetchUrl}: HTTP {(int)providerResponse.StatusCode} {providerResponse.ReasonPhrase}");
                                                                break;
                                                            }
                                                            if (providerResponse.StatusCode != HttpStatusCode.TooManyRequests)
                                                                await Task.Delay(retryDelay, sourceCancellationToken);
                                                            continue;
                                                        }

                                                        Interlocked.Increment(ref stat.ProviderFailures);
                                                        logWarning(
                                                            $"  provider fetch unavailable (HTTP {(int)providerResponse.StatusCode}; no retry) for {url} → {fetchUrl}: {providerResponse.ReasonPhrase}");
                                                        break;
                                                    }

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
                                                        int remainingLineCount = MaxNestedLinesPerSource - nestedLineCount;
                                                        if (providerLines.Count > remainingLineCount)
                                                            providerLines = providerLines.Take(remainingLineCount).ToList();

                                                        if (providerLines.Count > 0)
                                                        {
                                                            // Enforce the nested-line ceiling before the spool write. A single
                                                            // provider can return more than the remaining per-source allowance.
                                                            await spool.AppendSourceAsync(
                                                                sourceIndices[url],
                                                                providerLines,
                                                                providerTimeout.Token);
                                                            nestedLineCount += providerLines.Count;
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
                                                catch (Exception exception) when (!ShouldRetryFetchException(exception))
                                                {
                                                    Interlocked.Increment(ref stat.ProviderFailures);
                                                    logWarning(
                                                        $"  provider response rejected without retry for {url} → {fetchUrl}: {exception.Message}");
                                                    break;
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
                                                        await Task.Delay(GetTransientRetryDelay(providerAttempt), sourceCancellationToken);
                                                    }
                                                }
                                            }

                                            // Prefer a direct underlying subscription only if it
                                            // produced proxy links; otherwise try the wrapper URL.
                                            if (yielded) break;
                                        }

                                        if (nestedLineCount >= MaxNestedLinesPerSource)
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
                            catch (Exception exception) when (!ShouldRetryFetchException(exception))
                            {
                                logWarning($"Rejected source response for {url} without retry: {exception.Message}");
                                return;
                            }
                            catch (Exception exception)
                            {
                                if (attempt == MaxAttempts)
                                {
                                    logError($"Failed {url}: {exception.Message}");
                                    return;
                                }

                                await Task.Delay(GetTransientRetryDelay(attempt), sourceCancellationToken);
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

    // Payload-limit and invalid-data failures are deterministic for the same source;
    // retrying them downloads the same rejected body repeatedly. Network exceptions
    // remain retryable under the normal bounded attempt/backoff policy.
    internal static bool ShouldRetryFetchException(Exception exception)
    {
        ArgumentNullException.ThrowIfNull(exception);
        return exception is not InvalidDataException;
    }

    private static bool IsRetryableStatus(HttpStatusCode statusCode)
    {
        int code = (int)statusCode;
        return code is 408 or 429 || code >= 500;
    }

    internal static TimeSpan GetRetryDelay(HttpResponseMessage response, int attempt)
    {
        var retryAfter = response.Headers.RetryAfter;
        if (retryAfter?.Delta is TimeSpan delta)
            return ClampRetryDelay(delta);
        if (retryAfter?.Date is DateTimeOffset date)
            return ClampRetryDelay(date - DateTimeOffset.UtcNow);
        return GetTransientRetryDelay(attempt);
    }

    private static TimeSpan ClampRetryDelay(TimeSpan delay)
    {
        if (delay <= TimeSpan.Zero) return TimeSpan.Zero;
        return delay > MaximumRetryAfter ? MaximumRetryAfter : delay;
    }

    private static TimeSpan GetTransientRetryDelay(int attempt)
    {
        int exponent = Math.Clamp(attempt, 1, 5);
        double milliseconds = Math.Pow(2, exponent - 1) * 1000 +
                              Random.Shared.Next(100, 501);
        return TimeSpan.FromMilliseconds(Math.Min(milliseconds, MaximumRetryAfter.TotalMilliseconds));
    }

    private static string? GetHostKey(string url)
        => Uri.TryCreate(url, UriKind.Absolute, out var uri) ? uri.Host : null;

    private static void RegisterHostBackoff(string url, TimeSpan delay)
    {
        string? host = GetHostKey(url);
        if (host is null || delay <= TimeSpan.Zero) return;

        DateTimeOffset until = DateTimeOffset.UtcNow + ClampRetryDelay(delay);
        HostBackoffUntil.AddOrUpdate(
            host,
            until,
            (_, current) => current > until ? current : until);
    }

    private static async Task WaitForHostBackoffAsync(string url, CancellationToken cancellationToken)
    {
        string? host = GetHostKey(url);
        if (host is null) return;

        while (HostBackoffUntil.TryGetValue(host, out DateTimeOffset until))
        {
            TimeSpan delay = until - DateTimeOffset.UtcNow;
            if (delay <= TimeSpan.Zero)
            {
                HostBackoffUntil.TryRemove(host, out _);
                return;
            }
            await Task.Delay(delay, cancellationToken);
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
