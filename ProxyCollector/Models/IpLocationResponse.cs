using System.Text.Json.Serialization;

namespace ProxyCollector.Models;

/// <summary>
/// Response model for IP geolocation API (e.g., https://api.iplocation.net or ipapi.co)
/// </summary>
public class IpLocationResponse
{
    [JsonPropertyName("ip")]
    public string Ip { get; set; } = string.Empty;

    [JsonPropertyName("ip_number")]
    public string IpNumber { get; set; } = string.Empty;

    [JsonPropertyName("ip_version")]
    public int IpVersion { get; set; }

    [JsonPropertyName("country_name")]
    public string CountryName { get; set; } = "Unknown";

    [JsonPropertyName("country_code2")]
    public string CountryCode { get; set; } = "XX";

    [JsonPropertyName("isp")]
    public string Isp { get; set; } = string.Empty;

    [JsonPropertyName("response_code")]
    public string? ResponseCode { get; set; }

    [JsonPropertyName("response_message")]
    public string? ResponseMessage { get; set; }
}
