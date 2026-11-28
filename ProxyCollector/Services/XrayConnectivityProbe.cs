using System;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ProxyCollector.Services;

/// <summary>
/// Performs a SOCKS5-to-HTTPS generate_204 test through an existing Xray inbound.
/// The public production path validates the target's TLS certificate and hostname;
/// only the integration-test overload accepts a test certificate callback.
/// </summary>
public static class XrayConnectivityProbe
{
    private const string TargetHost = "www.gstatic.com";
    private const int TargetPort = 443;
    private const string RequestPath = "/generate_204";

    public static Task<bool> ProbeViaSocksAsync(int localPort, CancellationToken cancellationToken)
        => ProbeViaSocksCoreAsync(
            localPort, TargetHost, TargetPort, TargetHost, TargetHost, RequestPath,
            certificateValidation: null, cancellationToken: cancellationToken);

    // Used only by the loopback integration fixture so it can test the SOCKS→TLS→HTTP path
    // with a short-lived self-signed certificate.
    internal static Task<bool> ProbeViaSocksAsync(
        int localPort, string connectHost, int targetPort, string tlsServerName,
        string httpHostHeader, string requestPath,
        RemoteCertificateValidationCallback? certificateValidation,
        CancellationToken cancellationToken)
        => ProbeViaSocksCoreAsync(
            localPort, connectHost, targetPort, tlsServerName, httpHostHeader,
            requestPath, certificateValidation, cancellationToken);

    private static async Task<bool> ProbeViaSocksCoreAsync(
        int localPort, string connectHost, int targetPort, string tlsServerName,
        string httpHostHeader, string requestPath,
        RemoteCertificateValidationCallback? certificateValidation,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(connectHost);
        ArgumentException.ThrowIfNullOrWhiteSpace(tlsServerName);
        ArgumentException.ThrowIfNullOrWhiteSpace(httpHostHeader);
        if (targetPort is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(targetPort));
        if (string.IsNullOrEmpty(requestPath) || requestPath[0] != '/' ||
            requestPath.Contains('\r') || requestPath.Contains('\n') ||
            httpHostHeader.Contains('\r') || httpHostHeader.Contains('\n'))
            throw new ArgumentException("The HTTP path and Host header must be single-line request values.");

        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(TimeSpan.FromSeconds(8));
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(IPAddress.Loopback, localPort, timeout.Token);
            NetworkStream stream = tcp.GetStream();

            await stream.WriteAsync(new byte[] { 5, 1, 0 }, timeout.Token);
            var greeting = new byte[2];
            await ReadExactlyAsync(stream, greeting, timeout.Token);
            if (greeting[0] != 5 || greeting[1] != 0) return false;

            await stream.WriteAsync(BuildSocksConnectRequest(connectHost, targetPort), timeout.Token);
            var responseHead = new byte[4];
            await ReadExactlyAsync(stream, responseHead, timeout.Token);
            if (responseHead[0] != 5 || responseHead[1] != 0 || responseHead[2] != 0)
                return false;

            int addressLength = responseHead[3] switch { 1 => 4, 4 => 16, 3 => 0, _ => -1 };
            if (addressLength < 0) return false;
            if (addressLength == 0)
            {
                var length = new byte[1];
                await ReadExactlyAsync(stream, length, timeout.Token);
                addressLength = length[0];
            }
            await ReadExactlyAsync(stream, new byte[addressLength + 2], timeout.Token);

            // With no custom callback in production, SslStream performs normal
            // platform certificate-chain and hostname validation.
            using var ssl = new SslStream(
                stream, leaveInnerStreamOpen: true, userCertificateValidationCallback: certificateValidation);
            await ssl.AuthenticateAsClientAsync(
                new SslClientAuthenticationOptions { TargetHost = tlsServerName }, timeout.Token);

            byte[] http = Encoding.ASCII.GetBytes(
                $"GET {requestPath} HTTP/1.1\r\nHost: {httpHostHeader}\r\n" +
                "User-Agent: FastNodes-probe\r\nConnection: close\r\n\r\n");
            await ssl.WriteAsync(http, timeout.Token);
            string statusLine = await ReadHttpStatusLineAsync(ssl, timeout.Token);
            return IsExpectedConnectivityStatusLine(statusLine);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            // Probe-local timeouts, certificate failures and protocol errors mean no promotion.
            return false;
        }
    }

    private static byte[] BuildSocksConnectRequest(string host, int port)
    {
        byte[] addressBytes;
        byte[] request;
        if (IPAddress.TryParse(host, out var ip))
        {
            request = new byte[4 + ip.GetAddressBytes().Length + 2];
            request[3] = ip.AddressFamily == AddressFamily.InterNetwork ? (byte)1 : (byte)4;
            addressBytes = ip.GetAddressBytes();
            Array.Copy(addressBytes, 0, request, 4, addressBytes.Length);
        }
        else
        {
            addressBytes = Encoding.ASCII.GetBytes(host);
            if (addressBytes.Length is < 1 or > 255)
                throw new ArgumentException("SOCKS destination hostname must be 1–255 ASCII bytes.", nameof(host));
            request = new byte[4 + 1 + addressBytes.Length + 2];
            request[3] = 3;
            request[4] = (byte)addressBytes.Length;
            Array.Copy(addressBytes, 0, request, 5, addressBytes.Length);
        }

        request[0] = 5; request[1] = 1; request[2] = 0;
        int offset = request.Length - 2;
        request[offset] = (byte)(port >> 8);
        request[offset + 1] = (byte)(port & 0xff);
        return request;
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

    private static async Task<string> ReadHttpStatusLineAsync(Stream stream, CancellationToken cancellationToken)
    {
        const int MaximumBytes = 1024;
        var bytes = new byte[MaximumBytes];
        var oneByte = new byte[1];
        int length = 0;
        while (length < bytes.Length)
        {
            int read = await stream.ReadAsync(oneByte.AsMemory(0, 1), cancellationToken);
            if (read == 0) throw new IOException("HTTPS response closed before its status line completed.");
            if (oneByte[0] == (byte)'\n') break;
            if (oneByte[0] != (byte)'\r') bytes[length++] = oneByte[0];
        }
        if (length == bytes.Length)
            throw new InvalidDataException("HTTP status line exceeded the 1 KiB limit.");
        return Encoding.ASCII.GetString(bytes, 0, length);
    }

    private static async Task ReadExactlyAsync(Stream stream, byte[] buffer, CancellationToken cancellationToken)
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
