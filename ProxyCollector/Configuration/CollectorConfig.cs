namespace ProxyCollector.Configuration;

public class CollectorConfig
{
    public static CollectorConfig Instance { get; } = new CollectorConfig();

    public string SingboxPath { get; }
    public string V2rayFormatResultPath { get; }
    public string SingboxFormatResultPath { get; }
    public int MaxThreadCount { get; }
    public int Timeout { get; }
    public int MaxDelay { get; }
    public string[] Sources { get; }

    private CollectorConfig()
    {
        SingboxPath = Environment.GetEnvironmentVariable("SingboxPath") ?? "sing-box";
        V2rayFormatResultPath = Environment.GetEnvironmentVariable("V2rayFormatResultPath") ?? "sub/proxies.txt";
        SingboxFormatResultPath = Environment.GetEnvironmentVariable("SingboxFormatResultPath") ?? "sub/singbox.json";
        MaxThreadCount = int.TryParse(Environment.GetEnvironmentVariable("MaxThreadCount"), out var mt) ? mt : 8;
        Timeout = int.TryParse(Environment.GetEnvironmentVariable("Timeout"), out var t) ? t : 20000;
        MaxDelay = int.TryParse(Environment.GetEnvironmentVariable("MaxDelay"), out var md) ? md : 5000;

        var src = Environment.GetEnvironmentVariable("Sources") ?? "";
        Sources = src.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                     .Where(s => Uri.IsWellFormedUriString(s, UriKind.Absolute))
                     .ToArray();

        if (Sources.Length == 0)
            Console.WriteLine("Warning: No valid sources found in env var 'Sources'");
    }
}
