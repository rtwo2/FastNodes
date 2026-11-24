using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ProxyCollector.Services;

/// <summary>
/// Performs the actual SOCKS5-to-HTTP generate_204 test through an existing Xray
/// inbound. Only the expected HTTP 204 response counts as a full round trip.
/// </summary>
public static class XrayConnectivityProbe
{
    public static async Task<bool> ProbeViaSocksAsync(int localPort, CancellationToken cancellationToken)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(8));
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(IPAddress.Loopback, localPort, timeout.Token);
            NetworkStream stream = tcp.GetStream();

            // SOCKS5 greeting: offer only no-authentication.
            await stream.WriteAsync(new byte[] { 5, 1, 0 }, timeout.Token);
            var greeting = new byte[2];
            await ReadExactlyAsync(stream, greeting, timeout.Token);
            if (greeting[0] != 5 || greeting[1] != 0) return false;

            // CONNECT www.gstatic.com:80 using the SOCKS domain-name address type.
            byte[] host = Encoding.ASCII.GetBytes("www.gstatic.com");
            var request = new byte[7 + host.Length];
            request[0] = 5; request[1] = 1; request[2] = 0; request[3] = 3;
            request[4] = (byte)host.Length;
            Array.Copy(host, 0, request, 5, host.Length);
            request[5 + host.Length] = 0;
            request[6 + host.Length] = 80;
            await stream.WriteAsync(request, timeout.Token);

            var responseHead = new byte[4];
            await ReadExactlyAsync(stream, responseHead, timeout.Token);
            if (responseHead[1] != 0) return false;

            int addressLength = responseHead[3] switch { 1 => 4, 4 => 16, 3 => 0, _ => -1 };
            if (addressLength < 0) return false;
            if (addressLength == 0)
            {
                var length = new byte[1];
                await ReadExactlyAsync(stream, length, timeout.Token);
                addressLength = length[0];
            }

            await ReadExactlyAsync(stream, new byte[addressLength + 2], timeout.Token);
            byte[] http = Encoding.ASCII.GetBytes(
                "GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nUser-Agent: FastNodes-probe\r\nConnection: close\r\n\r\n");
            await stream.WriteAsync(http, timeout.Token);

            string statusLine = await ReadHttpStatusLineAsync(stream, timeout.Token);
            return IsExpectedConnectivityStatusLine(statusLine);
        }
        catch
        {
            // No pass means no promotion; a failed probe never removes a node.
            return false;
        }
    }

    public static bool IsExpectedConnectivityStatusLine(string statusLine)
    {
        if (string.IsNullOrWhiteSpace(statusLine)) return false;
        string[] parts = statusLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        return parts.Length >= 2 &&
            parts[0].StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase) &&
            int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out int code) &&
            code == 204;
    }

    private static async Task<string> ReadHttpStatusLineAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        const int MaximumBytes = 1024;
        var bytes = new byte[MaximumBytes];
        var oneByte = new byte[1];
        int length = 0;

        while (length < bytes.Length)
        {
            int read = await stream.ReadAsync(oneByte.AsMemory(0, 1), cancellationToken);
            if (read == 0) throw new IOException("HTTP response closed before its status line completed.");
            if (oneByte[0] == (byte)'\n') break;
            if (oneByte[0] != (byte)'\r') bytes[length++] = oneByte[0];
        }

        if (length == bytes.Length)
            throw new InvalidDataException("HTTP status line exceeded the 1 KiB limit.");

        return Encoding.ASCII.GetString(bytes, 0, length);
    }

    private static async Task ReadExactlyAsync(NetworkStream stream, byte[] buffer, CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(offset, buffer.Length - offset), cancellationToken);
            if (read == 0) throw new IOException("SOCKS5 stream closed before the expected response was received.");
            offset += read;
        }
    }
}
