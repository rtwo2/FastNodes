using System.Diagnostics;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using ProxyCollector.Services;

internal static class Program
{
    private static async Task Main()
    {
        await TestDualStackFallbackAsync();
        await TestXrayProbeCallerCancellationAsync();
        await TestXrayLoopbackRoundtripAsync();
        await TestXrayRealityConfigValidationAsync();
        Console.WriteLine("Network/Xray integration tests passed.");
    }

    private static async Task TestDualStackFallbackAsync()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        Task<Socket> acceptTask = listener.AcceptSocketAsync(timeout.Token).AsTask();

        // The first candidate is IPv6, but this fixture listens only on IPv4.
        // The connector must tolerate that failed family and complete on IPv4.
        using var connected = await HappyEyeballsConnector.ConnectAsync(
            new[] { IPAddress.IPv6Loopback, IPAddress.Loopback },
            port,
            timeout.Token,
            TimeSpan.FromMilliseconds(80));
        using var accepted = await acceptTask;

        if (connected.AddressFamily != AddressFamily.InterNetwork)
            throw new InvalidOperationException($"Expected IPv4 fallback, connected over {connected.AddressFamily}.");

        Console.WriteLine("  dual-stack socket fallback: passed");
    }

    private static async Task TestXrayProbeCallerCancellationAsync()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        bool propagated = false;
        try
        {
            _ = await XrayConnectivityProbe.ProbeViaSocksAsync(port, cancellation.Token);
        }
        catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
        {
            propagated = true;
        }

        if (!propagated)
            throw new InvalidOperationException("Xray probe swallowed caller cancellation instead of propagating it.");

        Console.WriteLine("  Xray probe caller cancellation: passed");
    }

    private static async Task TestXrayLoopbackRoundtripAsync()
    {
        string? xrayPath = Environment.GetEnvironmentVariable("XRAY_BIN");
        if (string.IsNullOrWhiteSpace(xrayPath) || !File.Exists(xrayPath))
            throw new FileNotFoundException("XRAY_BIN must point to the pinned Xray binary for integration tests.", xrayPath);

        using var certificate = CreateTestCertificate();
        using var upstream = new TcpListener(IPAddress.Loopback, 0);
        upstream.Start();
        int upstreamPort = ((IPEndPoint)upstream.LocalEndpoint).Port;
        int socksPort = ReserveTcpPort();

        using var upstreamTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task upstreamTask = ServeGenerate204TlsAsync(upstream, certificate, upstreamTimeout.Token);
        string configPath = Path.Combine(Path.GetTempPath(),
            "fastnodes-xray-https-integration-" + Guid.NewGuid().ToString("N") + ".json");

        var config = new
        {
            log = new { loglevel = "error" },
            inbounds = new[]
            {
                new
                {
                    listen = "127.0.0.1",
                    port = socksPort,
                    protocol = "socks",
                    settings = new { auth = "noauth", udp = false },
                    tag = "integration-socks"
                }
            },
            outbounds = new[] { new { protocol = "freedom", tag = "direct" } }
        };

        await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(config));
        Process? process = null;
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = xrayPath,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            startInfo.ArgumentList.Add("run");
            startInfo.ArgumentList.Add("-c");
            startInfo.ArgumentList.Add(configPath);
            process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start Xray.");
            Task<string> stdout = process.StandardOutput.ReadToEndAsync();
            Task<string> stderr = process.StandardError.ReadToEndAsync();

            // Wait for Xray's SOCKS listener, then run the production HTTPS probe.
            // The test certificate callback is confined to this integration fixture.
            using (var readinessClient = await ConnectWithRetryAsync(process, socksPort, stdout, stderr)) { }
            using var probeTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(12));
            bool passed = await XrayConnectivityProbe.ProbeViaSocksAsync(
                socksPort, "127.0.0.1", upstreamPort, "localhost", "localhost",
                "/generate_204", (_, _, _, _) => true, probeTimeout.Token);
            if (!passed)
                throw new InvalidOperationException("Xray HTTPS loopback probe did not complete the expected HTTPS 204 exchange.");

            await upstreamTask.WaitAsync(TimeSpan.FromSeconds(5));
            Console.WriteLine("  real Xray process + SOCKS + TLS + HTTPS 204 loopback roundtrip: passed");
        }
        finally
        {
            try { upstreamTimeout.Cancel(); } catch { }
            try { await upstreamTask; } catch { }
            try
            {
                if (process is { HasExited: false })
                {
                    process.Kill(entireProcessTree: true);
                    await process.WaitForExitAsync();
                }
            }
            catch { }
            process?.Dispose();
            try { File.Delete(configPath); } catch { }
        }
    }

    private static async Task TestXrayRealityConfigValidationAsync()
    {
        string? xrayPath = Environment.GetEnvironmentVariable("XRAY_BIN");
        if (string.IsNullOrWhiteSpace(xrayPath) || !File.Exists(xrayPath))
            throw new FileNotFoundException("XRAY_BIN must point to the pinned Xray binary for integration tests.", xrayPath);

        string realityPassword = await GenerateRealityPasswordAsync(xrayPath);
        string configPath = Path.Combine(Path.GetTempPath(),
            "fastnodes-xray-reality-validation-" + Guid.NewGuid().ToString("N") + ".json");
        // This is deliberately a config-validation-only probe. It does not connect to
        // the example endpoint; Xray must accept the current REALITY schema and a real
        // X25519 public key generated by the same pinned executable.
        var config = new
        {
            log = new { loglevel = "error" },
            inbounds = new object[]
            {
                new
                {
                    listen = "127.0.0.1",
                    port = ReserveTcpPort(),
                    protocol = "socks",
                    settings = new { auth = "noauth", udp = false },
                    tag = "reality-validation-inbound"
                }
            },
            outbounds = new object[]
            {
                new
                {
                    tag = "reality-validation",
                    protocol = "vless",
                    settings = new
                    {
                        vnext = new[]
                        {
                            new
                            {
                                address = "reality.example.invalid",
                                port = 443,
                                users = new[]
                                {
                                    new
                                    {
                                        id = "123e4567-e89b-12d3-a456-426614174000",
                                        encryption = "none",
                                        flow = "xtls-rprx-vision"
                                    }
                                }
                            }
                        }
                    },
                    streamSettings = new
                    {
                        network = "tcp",
                        security = "reality",
                        realitySettings = new
                        {
                            serverName = "reality.example.invalid",
                            fingerprint = "chrome",
                            password = realityPassword,
                            shortId = "0123",
                            spiderX = "/"
                        }
                    }
                },
                new
                {
                    tag = "custom-vless-validation",
                    protocol = "vless",
                    settings = new
                    {
                        vnext = new[]
                        {
                            new
                            {
                                address = "custom-vless.example.invalid",
                                port = 443,
                                users = new[]
                                {
                                    new
                                    {
                                        // Xray allows short custom IDs below 30 UTF-8 bytes;
                                        // URI-reserved and non-ASCII characters must survive
                                        // percent-decoding in the collector before reaching Xray.
                                        id = "Telegram🇨🇳 @WangCai2",
                                        encryption = "none"
                                    }
                                }
                            }
                        }
                    },
                    streamSettings = new
                    {
                        network = "tcp",
                        security = "tls",
                        tlsSettings = new { serverName = "custom-vless.example.invalid" }
                    }
                },
                new { tag = "direct", protocol = "freedom" }
            }
        };

        await File.WriteAllTextAsync(configPath, JsonSerializer.Serialize(config));
        Process? process = null;
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = xrayPath,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };
            startInfo.ArgumentList.Add("run");
            startInfo.ArgumentList.Add("-test");
            startInfo.ArgumentList.Add("-c");
            startInfo.ArgumentList.Add(configPath);

            process = Process.Start(startInfo) ?? throw new InvalidOperationException("Could not start Xray config validation.");
            Task<string> stdout = process.StandardOutput.ReadToEndAsync();
            Task<string> stderr = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15));
            string output = await stdout;
            string error = await stderr;
            if (process.ExitCode != 0)
                throw new InvalidOperationException(
                    $"Pinned Xray rejected the REALITY outbound config (exit {process.ExitCode}). stdout: {output} stderr: {error}");

            Console.WriteLine("  pinned Xray REALITY config validation: passed");
        }
        finally
        {
            try
            {
                if (process is { HasExited: false })
                {
                    process.Kill(entireProcessTree: true);
                    await process.WaitForExitAsync();
                }
            }
            catch { }
            process?.Dispose();
            try { File.Delete(configPath); } catch { }
        }
    }

    private static async Task<string> GenerateRealityPasswordAsync(string xrayPath)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = xrayPath,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true
        };
        startInfo.ArgumentList.Add("x25519");

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start pinned Xray x25519 key generation.");
        Task<string> stdout = process.StandardOutput.ReadToEndAsync();
        Task<string> stderr = process.StandardError.ReadToEndAsync();
        await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
        string output = await stdout;
        string error = await stderr;
        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"Pinned Xray x25519 key generation failed (exit {process.ExitCode}). stdout: {output} stderr: {error}");

        foreach (string line in output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries))
        {
            int separator = line.IndexOf(':');
            if (separator > 0 &&
                line[..separator].Trim().StartsWith("Password", StringComparison.OrdinalIgnoreCase))
            {
                string password = line[(separator + 1)..].Trim();
                if (!string.IsNullOrWhiteSpace(password))
                    return password;
            }
        }

        throw new InvalidOperationException(
            $"Pinned Xray x25519 output did not include the generated REALITY Password field: {output}");
    }

    private static X509Certificate2 CreateTestCertificate()
    {
        using RSA rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=localhost", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        var subjectAlternativeNames = new SubjectAlternativeNameBuilder();
        subjectAlternativeNames.AddDnsName("localhost");
        request.CertificateExtensions.Add(subjectAlternativeNames.Build());
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-5), DateTimeOffset.UtcNow.AddHours(1));
    }

    private static async Task ServeGenerate204TlsAsync(
        TcpListener listener, X509Certificate2 certificate, CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        using var ssl = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
        await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
        {
            ServerCertificate = certificate,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
        }, cancellationToken);

        string headers = await ReadHeaderBlockAsync(ssl, cancellationToken);
        if (!headers.StartsWith("GET /generate_204 ", StringComparison.Ordinal) ||
            !headers.Contains("\r\nHost: localhost\r\n", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Xray did not forward the expected HTTPS generate_204 request.");

        byte[] response = Encoding.ASCII.GetBytes(
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await ssl.WriteAsync(response, cancellationToken);
    }

    private static async Task<TcpClient> ConnectWithRetryAsync(
        Process process, int port, Task<string> stdout, Task<string> stderr)
    {
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(15);
        Exception? lastError = null;

        while (DateTime.UtcNow < deadline)
        {
            if (process.HasExited)
            {
                await Task.WhenAll(stdout, stderr).WaitAsync(TimeSpan.FromSeconds(2));
                throw new InvalidOperationException(
                    $"Xray exited before opening its SOCKS inbound. stdout: {stdout.Result} stderr: {stderr.Result}");
            }

            var client = new TcpClient(AddressFamily.InterNetwork);
            try
            {
                await client.ConnectAsync(IPAddress.Loopback, port).WaitAsync(TimeSpan.FromMilliseconds(500));
                return client;
            }
            catch (Exception exception)
            {
                lastError = exception;
                client.Dispose();
                await Task.Delay(100);
            }
        }

        throw new TimeoutException($"Xray did not open its SOCKS inbound: {lastError?.Message}");
    }

    private static int ReserveTcpPort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    private static async Task<byte[]> ReadExactlyAsync(
        NetworkStream stream, int count, CancellationToken cancellationToken)
    {
        var result = new byte[count];
        int offset = 0;

        while (offset < count)
        {
            int read = await stream.ReadAsync(result.AsMemory(offset, count - offset), cancellationToken);
            if (read == 0) throw new EndOfStreamException("Socket closed before the expected response was received.");
            offset += read;
        }

        return result;
    }

    private static async Task<string> ReadLineAsync(NetworkStream stream, CancellationToken cancellationToken)
    {
        var bytes = new List<byte>();
        var buffer = new byte[1];

        while (bytes.Count < 1024)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(0, 1), cancellationToken);
            if (read == 0) throw new EndOfStreamException("Socket closed before an HTTP status line arrived.");
            bytes.Add(buffer[0]);

            if (bytes.Count >= 2 && bytes[^2] == (byte)'\r' && bytes[^1] == (byte)'\n')
                return Encoding.ASCII.GetString(bytes.ToArray()).TrimEnd('\r', '\n');
        }

        throw new InvalidDataException("HTTP status line exceeded 1 KiB.");
    }

    private static async Task<string> ReadHeaderBlockAsync(Stream stream, CancellationToken cancellationToken)
    {
        var bytes = new List<byte>();
        var buffer = new byte[1];

        while (bytes.Count < 8192)
        {
            int read = await stream.ReadAsync(buffer.AsMemory(0, 1), cancellationToken);
            if (read == 0) throw new EndOfStreamException("Socket closed before HTTP headers were complete.");
            bytes.Add(buffer[0]);

            int count = bytes.Count;
            if (count >= 4 && bytes[count - 4] == (byte)'\r' && bytes[count - 3] == (byte)'\n' &&
                bytes[count - 2] == (byte)'\r' && bytes[count - 1] == (byte)'\n')
                return Encoding.ASCII.GetString(bytes.ToArray());
        }

        throw new InvalidDataException("HTTP header block exceeded 8 KiB.");
    }
}
