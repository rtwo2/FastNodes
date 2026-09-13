namespace ProxyCollector.Models;

public class CityInfo
{
    public string CountryCode { get; set; } = "XX";
    public string CountryName { get; set; } = "Unknown";
    public string? CityName { get; set; }
    public string? City => CityName;
}
