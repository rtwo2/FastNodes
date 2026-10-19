using System.Text;
using ProxyCollector.Collector;

static class Checks
{
    public static int Count { get; private set; }

    public static void That(bool condition, string message)
    {
        if (!condition)
            throw new InvalidOperationException("FAIL: " + message);
        Count++;
    }

    public static void Equal<T>(T expected, T actual, string message)
        => That(EqualityComparer<T>.Default.Equals(expected, actual),
            $"{message}; expected={expected}, actual={actual}");
}

var ipv6 = ProxyCollector.ParseProxyLine(
    "vless://123e4567-e89b-12d3-a456-426614174000@[2001:4860:4860::8888]:443?security=reality&type=tcp&sni=example.com&flow=xtls-rprx-vision&pbk=abc&sid=01#ipv6");
Checks.That(ipv6 is not null, "VLESS IPv6 link parses");
Checks.Equal("2001:4860:4860::8888", ipv6!.Host, "IPv6 host is normalized without brackets");
Checks.Equal("443", ipv6.Port, "VLESS port");
Checks.Equal("example.com", ipv6.Sni, "VLESS SNI");
Checks.Equal("xtls-rprx-vision", ipv6.Flow, "VLESS flow");

var vmessJson = """{"add":"vmess.example.com","port":"8443","id":"01234567-89ab-cdef-0123-456789abcdef","net":"ws","tls":"tls","host":"sni.example.com","path":"/ws","aid":"0"}""";
var vmessPayload = Convert.ToBase64String(Encoding.UTF8.GetBytes(vmessJson));
var vmess = ProxyCollector.ParseProxyLine("vmess://" + vmessPayload + "#vmess");
Checks.That(vmess is not null, "VMess base64 JSON link parses");
Checks.Equal("vmess.example.com", vmess!.Host, "VMess endpoint");
Checks.Equal("8443", vmess.Port, "VMess port");
Checks.Equal("ws", vmess.Network, "VMess transport");
Checks.Equal("sni.example.com", vmess.Sni, "VMess SNI");

var ssUser = Convert.ToBase64String(Encoding.UTF8.GetBytes("aes-128-gcm:CaseSensitive"));
var ss = ProxyCollector.ParseProxyLine($"ss://{ssUser}@[2001:4860:4860::8888]:8388#ss");
Checks.That(ss is not null, "Shadowsocks SIP002 IPv6 link parses");
Checks.Equal("2001:4860:4860::8888", ss!.Host, "Shadowsocks IPv6 host");
Checks.Equal("8388", ss.Port, "Shadowsocks port");
Checks.Equal("aes-128-gcm:CaseSensitive", ss.Credential, "Shadowsocks credentials");

var flowA = ProxyCollector.ParseProxyLine(
    "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=reality&flow=xtls-rprx-vision");
var flowB = ProxyCollector.ParseProxyLine(
    "vless://123e4567-e89b-12d3-a456-426614174000@example.com:443?security=reality");
Checks.That(flowA is not null && flowB is not null, "VLESS flow variants parse");
Checks.That(flowA!.DeduplicationKey != flowB!.DeduplicationKey,
    "Deduplication preserves materially different VLESS flow values");

var passwordA = ProxyCollector.ParseProxyLine("trojan://CaseSensitive@example.com:443?sni=example.com");
var passwordB = ProxyCollector.ParseProxyLine("trojan://casesensitive@example.com:443?sni=example.com");
Checks.That(passwordA is not null && passwordB is not null, "Trojan password variants parse");
Checks.That(passwordA!.DeduplicationKey != passwordB!.DeduplicationKey,
    "Deduplication preserves case-sensitive Trojan passwords");

Checks.That(ProxyCollector.ParseProxyLine("not a proxy URI") is null,
    "Malformed non-proxy input is rejected");

Console.WriteLine($"Parser regression tests passed ({Checks.Count} assertions).");
