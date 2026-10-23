using System;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("Running full ProxyCollector mode");
        var collector = new ProxyCollector.Collector.ProxyCollector();
        await collector.StartAsync();
    }
}
