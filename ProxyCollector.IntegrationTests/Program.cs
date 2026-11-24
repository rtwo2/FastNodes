using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
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

        using var upstream = new TcpListener(IPAddress.Loopback, 0);
        upstream.Start();
        int upstreamPort = ((IPEndPoint)upstream.LocalEndpoint).Port;
        int socksPort = ReserveTcpPort();

        using var upstreamTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        Task upstreamTask = ServeGenerate204Async(upstream, upstreamTimeout.Token);
        string configPath = Path.Combine(Path.GetTempPath(),
            "fastnodes-xray-integration-" + Guid.NewGuid().ToString("N") + ".json");

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

            using var socksClient = await ConnectWithRetryAsync(process, socksPort, stdout, stderr);
            using NetworkStream socks = socksClient.GetStream();
            using var socksTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(12));

            await socks.WriteAsync(new byte[] { 0x05, 0x01, 0x00 }, socksTimeout.Token);
            byte[] greeting = await ReadExactlyAsync(socks, 2, socksTimeout.Token);
            if (greeting[0] != 0x05 || greeting[1] != 0x00)
                throw new InvalidOperationException("Xray SOCKS inbound did not accept no-auth negotiation.");

            byte[] connectRequest =
            {
                0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1,
                (byte)(upstreamPort >> 8), (byte)(upstreamPort & 0xff)
            };
            await socks.WriteAsync(connectRequest, socksTimeout.Token);

            byte[] connectHead = await ReadExactlyAsync(socks, 4, socksTimeout.Token);
            if (connectHead[1] != 0x00)
                throw new InvalidOperationException($"Xray SOCKS CONNECT failed with reply code {connectHead[1]}.");

            int bindAddressLength = connectHead[3] switch
            {
                1 => 4,
                4 => 16,
                3 => (await ReadExactlyAsync(socks, 1, socksTimeout.Token))[0],
                _ => throw new InvalidOperationException($"Xray returned unknown SOCKS address type {connectHead[3]}.")
            };
            _ = await ReadExactlyAsync(socks, bindAddressLength + 2, socksTimeout.Token);

            byte[] request = Encoding.ASCII.GetBytes(
                "GET /generate_204 HTTP/1.1\r\nHost: integration.test\r\nConnection: close\r\n\r\n");
            await socks.WriteAsync(request, socksTimeout.Token);

            string statusLine = await ReadLineAsync(socks, socksTimeout.Token);
            if (!statusLine.StartsWith("HTTP/1.1 204", StringComparison.Ordinal))
                throw new InvalidOperationException($"Xray loopback roundtrip returned unexpected status: {statusLine}");

            await upstreamTask.WaitAsync(TimeSpan.FromSeconds(5));
            Console.WriteLine("  real Xray process + SOCKS + HTTP 204 loopback roundtrip: passed");
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

    private static async Task ServeGenerate204Async(TcpListener listener, CancellationToken cancellationToken)
    {
        using var client = await listener.AcceptTcpClientAsync(cancellationToken);
        using NetworkStream stream = client.GetStream();

        string headers = await ReadHeaderBlockAsync(stream, cancellationToken);
        if (!headers.StartsWith("GET /generate_204 ", StringComparison.Ordinal))
            throw new InvalidOperationException("Xray did not forward the expected generate_204 request.");

        byte[] response = Encoding.ASCII.GetBytes(
            "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        await stream.WriteAsync(response, cancellationToken);
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

    private static async Task<string> ReadHeaderBlockAsync(NetworkStream stream, CancellationToken cancellationToken)
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
