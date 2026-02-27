using System.Text.Json.Serialization;

namespace ProxyCollector.Models;

public class IpInfoResponse
{
    [JsonPropertyName("country")]
    public string? Country { get; set; }

    [JsonPropertyName("country_name")]
    public string? CountryName { get; set; }
}
