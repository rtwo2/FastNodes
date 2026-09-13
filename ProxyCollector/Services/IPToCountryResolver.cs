using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;
using MaxMind.GeoIP2;
using ProxyCollector.Models;

namespace ProxyCollector.Services;

/// <summary>
/// DNS outcome, separating AFFIRMATIVE death from inconclusive failure.
/// The first v6.11 run tripped the circuit breaker at 47% "failures" because
/// timeouts (likely resolver throttling under 100-way parallel load) were being
/// counted as death alongside NXDOMAIN. Only NxDomain is affirmative.
/// </summary>
public enum DnsVerdict
{
    Resolved,        // got an address
    NxDomain,        // authoritative "no such host" — dead from everywhere
    Inconclusive     // timeout / transient / refused — KEEP the node
}

public sealed record DnsResult(IPAddress? Ip, DnsVerdict Verdict);

public sealed class IPToCountryResolver : IDisposable
{
    private readonly DatabaseReader? _countryReader;
    private readonly DatabaseReader? _cityReader;
    private readonly DatabaseReader? _asnReader;
    private readonly ConcurrentDictionary<string, CountryInfo> _countryCache = new();
    private readonly ConcurrentDictionary<string, CityInfo> _cityCache = new();
    private readonly ConcurrentDictionary<string, string> _orgCache = new();
    private readonly ConcurrentDictionary<string, Task<DnsResult>> _ipCache = new();
    private bool _disposed;

    public IPToCountryResolver()
    {
        var cityPath = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "GeoLite2-City.mmdb");
        if (File.Exists(cityPath))
        {
            try { _cityReader = new DatabaseReader(cityPath); Console.WriteLine($"[INFO] Loaded GeoLite2-City.mmdb"); }
            catch (Exception ex) { Console.WriteLine($"[WARN] City DB load failed: {ex.Message}"); }
        }

        var countryPath = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "GeoLite2-Country.mmdb");
        if (File.Exists(countryPath))
        {
            try { _countryReader = new DatabaseReader(countryPath); Console.WriteLine($"[INFO] Loaded GeoLite2-Country.mmdb"); }
            catch (Exception ex) { Console.WriteLine($"[WARN] Country DB load failed: {ex.Message}"); }
        }

        var asnPath = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "GeoLite2-ASN.mmdb");
        if (File.Exists(asnPath))
        {
            try { _asnReader = new DatabaseReader(asnPath); Console.WriteLine($"[INFO] Loaded GeoLite2-ASN.mmdb"); }
            catch (Exception ex) { Console.WriteLine($"[WARN] ASN DB load failed: {ex.Message}"); }
        }

        // A green run with no City/Country reader publishes every node as 🌐 Unknown and
        // silently drops every country/continent file — strictly worse than a red run.
        // The downloader already fails loud on missing files; this closes the remaining
        // gap (present-but-corrupt file) so a degraded run can never look successful.
        if (_countryReader is null || _cityReader is null)
            throw new InvalidOperationException(
                "Required GeoIP database(s) failed to load — refusing to publish an all-Unknown run.");
    }

    /// <summary>Cached resolution (shares the GeoIP stage's cache). Null = failed for any reason.</summary>
    public async Task<IPAddress?> ResolveAsync(string address)
        => (await ResolveIpAsync(address)).Ip;

    /// <summary>
    /// One live, UNCACHED attempt returning the VERDICT — the confirmation retry
    /// before dropping a host as DNS-dead. Only NxDomain authorizes a drop.
    /// Repairs the cache if the retry succeeds.
    /// </summary>
    public async Task<DnsVerdict> ResolveVerdictUncachedAsync(string address)
    {
        if (IPAddress.TryParse(address, out _)) return DnsVerdict.Resolved;
        var result = await ResolveUncachedInternalAsync(address);
        if (result.Verdict == DnsVerdict.Resolved)
            _ipCache[address.ToLowerInvariant()] = Task.FromResult(result);
        return result.Verdict;
    }

        public async Task<CityInfo> GetCityAsync(string address)
        {
            address = address.ToLowerInvariant();   // v6.13: case-insensitive cache keys
            if (_cityReader == null)
                return await GetCountryFallbackAsync(address);

        if (_cityCache.TryGetValue(address, out var cached))
            return cached;

        try
        {
            var ip = (await ResolveIpAsync(address)).Ip;
            if (ip == null)
            {
                var fb = await GetCountryFallbackAsync(address);
                _cityCache[address] = fb;
                return fb;
            }

            var response = _cityReader.City(ip);
            var cityInfo = new CityInfo
            {
                CountryCode = response.Country.IsoCode ?? "XX",
                CountryName = response.Country.Name ?? "Unknown",
                CityName = response.City.Name ?? ""
            };

            _cityCache[address] = cityInfo;
            _cityCache[ip.ToString()] = cityInfo;
            return cityInfo;
        }
        catch
        {
            var fb = await GetCountryFallbackAsync(address);
            _cityCache[address] = fb;
            return fb;
        }
    }

        public async Task<CountryInfo> GetCountryAsync(string address)
        {
            address = address.ToLowerInvariant();   // v6.13: case-insensitive cache keys
            if (_countryReader == null)
                return new CountryInfo { CountryCode = "XX", CountryName = "Unknown" };

        if (_countryCache.TryGetValue(address, out var cached))
            return cached;

        try
        {
            var ip = (await ResolveIpAsync(address)).Ip;
            if (ip == null)
            {
                var xx = new CountryInfo { CountryCode = "XX", CountryName = "Unknown" };
                _countryCache[address] = xx;
                return xx;
            }

            var response = _countryReader.Country(ip);
            var info = new CountryInfo
            {
                CountryCode = response.Country.IsoCode ?? "XX",
                CountryName = response.Country.Name ?? "Unknown"
            };

            _countryCache[address] = info;
            _countryCache[ip.ToString()] = info;
            return info;
        }
        catch
        {
            var xx = new CountryInfo { CountryCode = "XX", CountryName = "Unknown" };
            _countryCache[address] = xx;
            return xx;
        }
    }

        public async Task<string?> GetOrgAsync(string address)
        {
            address = address.ToLowerInvariant();   // v6.13: case-insensitive cache keys
            if (_asnReader == null) return null;

        if (_orgCache.TryGetValue(address, out var cached))
            return string.IsNullOrEmpty(cached) ? null : cached;

        try
        {
            var ip = (await ResolveIpAsync(address)).Ip;
            if (ip == null) { _orgCache[address] = ""; return null; }

            var response = _asnReader.Asn(ip);
            string org = response.AutonomousSystemOrganization ?? "";
            _orgCache[address] = org;
            _orgCache[ip.ToString()] = org;
            return string.IsNullOrEmpty(org) ? null : org;
        }
        catch
        {
            _orgCache[address] = "";
            return null;
        }
    }

    private async Task<CityInfo> GetCountryFallbackAsync(string address)
    {
        var country = await GetCountryAsync(address);
        return new CityInfo
        {
            CountryCode = country.CountryCode,
            CountryName = country.CountryName,
            CityName = ""
        };
    }

    private static readonly TimeSpan DnsTimeout = TimeSpan.FromSeconds(3);

    private Task<DnsResult> ResolveIpAsync(string address)
    {
            if (IPAddress.TryParse(address, out var ip))
            return Task.FromResult(new DnsResult(ip, DnsVerdict.Resolved));
        // v6.13: DNS names are case-insensitive — normalize the key so
        // "Server.com" and "server.com" share one entry and one query.
        address = address.ToLowerInvariant();
        return _ipCache.GetOrAdd(address, _ => ResolveUncachedInternalAsync(address));
    }

        private static async Task<DnsResult> ResolveUncachedInternalAsync(string address)
        {
            try
            {
                // v6.13: cancellation overload instead of Task.WhenAny — the old pattern
                // left the real query running as a zombie up to ~75s after every timeout
                // (needing the ContinueWith exception-observation hack). With thousands
                // of Inconclusive verdicts under 100-way parallelism that was a real
                // pile-up of wasted in-flight resolver calls.
                using var cts = new CancellationTokenSource(DnsTimeout);
                var addresses = await Dns.GetHostAddressesAsync(address, cts.Token);
                if (addresses.Length == 0) return new DnsResult(null, DnsVerdict.Inconclusive);

                var ip = addresses.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)
                     ?? addresses[0];
                return new DnsResult(ip, DnsVerdict.Resolved);
            }
            catch (SocketException e) when (e.SocketErrorCode is SocketError.HostNotFound or SocketError.NoData)
            {
                return new DnsResult(null, DnsVerdict.NxDomain);           // authoritative death
            }
            catch (OperationCanceledException)
            {
                return new DnsResult(null, DnsVerdict.Inconclusive);       // timeout — could be throttling
            }
            catch
            {
                return new DnsResult(null, DnsVerdict.Inconclusive);       // TryAgain / refused / transient
            }
        }

    public void Dispose()
    {
        if (!_disposed)
        {
            _cityReader?.Dispose();
            _countryReader?.Dispose();
            _asnReader?.Dispose();
            _disposed = true;
        }
    }
}
