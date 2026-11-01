using System.Net.Http;

namespace Veyl.Shared;

public static class Web
{
    /// <summary>
    /// An HttpClient that names itself. GitHub refuses API requests without a User-Agent,
    /// and some feed hosts do too, so every client VEYL makes sends one.
    /// </summary>
    public static HttpClient Client(TimeSpan timeout)
    {
        var http = new HttpClient { Timeout = timeout };
        string version = typeof(Web).Assembly.GetName().Version?.ToString(3) ?? "0";
        http.DefaultRequestHeaders.UserAgent.ParseAdd($"VEYL/{version} (+https://github.com/Gurnski/VEYL)");
        return http;
    }
}
