using System;
using System.Threading.Tasks;
using ProxyCollector.Collector;   // ← this imports the namespace

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("Running full ProxyCollector mode");
        var collector = new ProxyCollector.Collector.ProxyCollector();   // ← correct full name
        await collector.StartAsync();
    }
}
