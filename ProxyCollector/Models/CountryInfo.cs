namespace ProxyCollector.Models;

public class CountryInfo
{
    public string CountryCode { get; set; } = "XX";
    public string CountryName { get; set; } = "Unknown";

    private string? _countryFlag;
    public string CountryFlag
    {
        get
        {
            if (_countryFlag is null)
            {
                _countryFlag = IsoCountryCodeToFlagEmoji(CountryCode);
            }
            return _countryFlag;
        }
        set => _countryFlag = value;
    }

    private static string IsoCountryCodeToFlagEmoji(string? countryCode)
    {
        if (string.IsNullOrWhiteSpace(countryCode) || countryCode.Length != 2 || countryCode == "XX")
        {
            return "🌍"; // fallback globe for unknown
        }

        countryCode = countryCode.ToUpperInvariant();

        // Regional indicator symbols start at U+1F1E6 (A)
        const int offset = 0x1F1E6 - 'A';
        var flag = string.Create(2, countryCode, (span, code) =>
        {
            span[0] = (char)(offset + code[0]);
            span[1] = (char)(offset + code[1]);
        });

        return flag;
    }
}
