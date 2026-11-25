using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace ProxyCollector.Services;

/// <summary>Opens TCP connections with staggered IPv4/IPv6 fallback (Happy Eyeballs).</summary>
public static class HappyEyeballsConnector
{
    public static TimeSpan DefaultFallbackDelay { get; } = TimeSpan.FromMilliseconds(250);

    /// <summary>Interleave families, retaining resolver order within each family.</summary>
    public static IReadOnlyList<IPAddress> OrderAddresses(IEnumerable<IPAddress> addresses)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        var unique = addresses
            .Where(address => address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
            .Distinct()
            .ToArray();

        if (unique.Length < 2) return unique;

        var firstFamily = unique[0].AddressFamily;
        var preferred = new Queue<IPAddress>(unique.Where(address => address.AddressFamily == firstFamily));
        var alternate = new Queue<IPAddress>(unique.Where(address => address.AddressFamily != firstFamily));
        var ordered = new List<IPAddress>(unique.Length);

        while (preferred.Count > 0 || alternate.Count > 0)
        {
            if (preferred.Count > 0) ordered.Add(preferred.Dequeue());
            if (alternate.Count > 0) ordered.Add(alternate.Dequeue());
        }

        return ordered;
    }

    public static async Task<Socket> ConnectAsync(
        IEnumerable<IPAddress> addresses,
        int port,
        CancellationToken cancellationToken,
        TimeSpan? fallbackDelay = null)
    {
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        cancellationToken.ThrowIfCancellationRequested();

        var ordered = OrderAddresses(addresses);
        if (ordered.Count == 0)
            throw new SocketException((int)SocketError.HostNotFound);

        TimeSpan delay = fallbackDelay ?? DefaultFallbackDelay;
        if (delay < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(fallbackDelay));

        using var attemptsCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var pending = ordered
            .Select((address, index) => ConnectAfterDelayAsync(
                address, port, TimeSpan.FromTicks(delay.Ticks * index), attemptsCancellation.Token))
            .ToList();
        var errors = new List<Exception>();

        while (pending.Count > 0)
        {
            Task<Socket> completed = await Task.WhenAny(pending);
            pending.Remove(completed);

            try
            {
                Socket winner = await completed;
                attemptsCancellation.Cancel();
                await ObserveLosersAsync(pending);
                return winner;
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                attemptsCancellation.Cancel();
                await ObserveLosersAsync(pending);
                throw;
            }
            catch (Exception exception)
            {
                errors.Add(exception);
            }
        }

        cancellationToken.ThrowIfCancellationRequested();
        throw new AggregateException(
            $"Could not connect to any of {ordered.Count} IPv4/IPv6 addresses on port {port}.", errors);
    }

    private static async Task<Socket> ConnectAfterDelayAsync(
        IPAddress address,
        int port,
        TimeSpan delay,
        CancellationToken cancellationToken)
    {
        if (delay > TimeSpan.Zero)
            await Task.Delay(delay, cancellationToken);

        var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
        {
            NoDelay = true
        };

        try
        {
            await socket.ConnectAsync(new IPEndPoint(address, port), cancellationToken);
            return socket;
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    private static async Task ObserveLosersAsync(IEnumerable<Task<Socket>> attempts)
    {
        foreach (var attempt in attempts)
        {
            try { using var losingSocket = await attempt; }
            catch { /* Losing attempts fail or cancel after the winner connects. */ }
        }
    }
}
