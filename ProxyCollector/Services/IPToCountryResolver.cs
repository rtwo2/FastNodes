using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using MaxMind.GeoIP2;
using ProxyCollector.Models;

namespace ProxyCollector.Services;

public sealed class IPToCountryResolver : IDisposable
{
    private readonly DatabaseReader? _reader;
    private readonly ConcurrentDictionary<string, CountryInfo> _cache = new();
    private bool _disposed;

    public IPToCountryResolver()
    {
        var mmdbPath = Path.Combine(Directory.GetCurrentDirectory(), "ProxyCollector", "Country.mmdb");

        if (!File.Exists(mmdbPath))
        {
            Console.WriteLine($"[WARN] Country.mmdb not found at {mmdbPath} → all XX");
            _reader = null;
            return;
        }

        try
        {
            _reader = new DatabaseReader(mmdbPath);
            Console.WriteLine($"[INFO] Loaded GeoIP database: {mmdbPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[ERROR] Failed to load MMDB: {ex.Message} → all XX");
            _reader = null;
        }
    }

    public CountryInfo GetCountry(string address)
    {
        if (_reader == null)
            return new CountryInfo { CountryCode = "XX", CountryName = "Unknown" };

        // Quick cache check
        if (_cache.TryGetValue(address, out var cached))
            return cached;

        IPAddress? ip = null;

        // If address is already IP, skip DNS
        if (IPAddress.TryParse(address, out var parsedIp))
        {
            ip = parsedIp;
        }
        else
        {
            try
            {
                var addresses = Dns.GetHostAddresses(address);
                ip = addresses.Length > 0 ? addresses[0] : null;
            }
            catch
            {
                // DNS fail → XX
                var info = new CountryInfo { CountryCode = "XX", CountryName = "Unknown" };
                _cache[address] = info;
                return info;
            }
        }

        if (ip == null)
        {
            var info = new CountryInfo { CountryCode = "XX", CountryName = "Unknown" };
            _cache[address] = info;
            return info;
        }

        var ipStr = ip.ToString();
        if (_cache.TryGetValue(ipStr, out cached))
        {
            _cache[address] = cached;
            return cached;
        }

        try
        {
            var response = _reader.Country(ip);
            var code = response.Country.IsoCode ?? "XX";
            var name = response.Country.Name ?? "Unknown";
            var info = new CountryInfo { CountryCode = code, CountryName = name };
            _cache[ipStr] = info;
            _cache[address] = info;
            return info;
        }
        catch
        {
            var info = new CountryInfo { CountryCode = "XX", CountryName = "Unknown" };
            _cache[ipStr] = info;
            _cache[address] = info;
            return info;
        }
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _reader?.Dispose();
            _disposed = true;
        }
    }
}
