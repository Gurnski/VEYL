using System.Text.Json;
using System.Text.Json.Serialization;

namespace Veyl.Shared;

public sealed class ChangelogEntry
{
    public string Version { get; set; } = "";
    public string Date { get; set; } = "";
    public List<string> Notes { get; set; } = [];
}

/// <summary>
/// manifest.json, written by build.ps1 next to the binaries. The launcher uses it
/// to check file integrity and, if <see cref="UpdateUrl"/> is set, to look for a
/// newer release (the remote URL must serve a manifest in the same format).
/// </summary>
public sealed class Manifest
{
    public const string FileName = "manifest.json";

    public string Product { get; set; } = "VEYL";
    public string Version { get; set; } = "0.0.0";
    public string Channel { get; set; } = "stable";
    public string BuildDate { get; set; } = "";
    public string UpdateUrl { get; set; } = "";
    public string DownloadUrl { get; set; } = "";

    /// <summary>
    /// SHA-256 and size of VEYL-Setup.exe at <see cref="DownloadUrl"/>. Only the release copy of the
    /// manifest (written by release.ps1) has these: the copy inside the installer can't hold its own hash.
    /// </summary>
    public string SetupSha256 { get; set; } = "";
    public long SetupSize { get; set; }

    public Dictionary<string, string> Files { get; set; } = [];
    public List<string> SignatureFeeds { get; set; } = [];
    public List<ChangelogEntry> Changelog { get; set; } = [];

    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public static Manifest? Load(string dir)
    {
        string path = Path.Combine(dir, FileName);
        if (!File.Exists(path)) return null;
        return JsonSerializer.Deserialize<Manifest>(File.ReadAllText(path), Json);
    }

    public static Manifest? Parse(string json) => JsonSerializer.Deserialize<Manifest>(json, Json);

    public static bool IsNewer(string candidate, string current) =>
        System.Version.TryParse(candidate, out var a) && System.Version.TryParse(current, out var b) && a > b;
}
