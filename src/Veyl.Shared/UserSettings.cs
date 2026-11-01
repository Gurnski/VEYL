using System.Text.Json;

namespace Veyl.Shared;

/// <summary>Per-user preferences, stored in the user's locked-down ProgramData folder.</summary>
public sealed class UserSettings
{
    public bool StartWithWindows { get; set; } = true;
    public bool StartMinimized { get; set; } = true;
    public bool CloseToTray { get; set; } = true;
    public bool Notifications { get; set; } = true;

    public bool RealtimeEnabled { get; set; } = true;
    public bool AutoQuarantine { get; set; } = true;
    public bool UseAmsi { get; set; } = true;
    public List<string> WatchedFolders { get; set; } = DefaultWatchedFolders();
    public DateTimeOffset? LastScan { get; set; }
    public int LastScanFiles { get; set; }
    public int LastScanThreats { get; set; }
    public DateTimeOffset? LastSignatureUpdate { get; set; }
    /// <summary>URLs or file paths of extra hash lists, on top of any in manifest.json.</summary>
    public List<string> SignatureFeeds { get; set; } = [];

    public int VaultAutoLockMinutes { get; set; } = 5;
    public int ClipboardClearSeconds { get; set; } = 20;
    public int GeneratorLength { get; set; } = 20;
    public bool GeneratorSymbols { get; set; } = true;

    public static List<string> DefaultWatchedFolders()
    {
        string home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        return
        [
            Path.Combine(home, "Downloads"),
            Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory),
            Environment.GetFolderPath(Environment.SpecialFolder.Startup),
            Path.GetTempPath().TrimEnd('\\'),
        ];
    }

    public static UserSettings Load()
    {
        try
        {
            if (File.Exists(VeylPaths.SettingsFile))
                return JsonSerializer.Deserialize<UserSettings>(File.ReadAllText(VeylPaths.SettingsFile), Manifest.Json) ?? new();
        }
        catch (JsonException) { /* fall back to defaults on a corrupt file */ }
        return new();
    }

    public void Save()
    {
        Directory.CreateDirectory(VeylPaths.UserDir);
        string tmp = VeylPaths.SettingsFile + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(this, Manifest.Json));
        File.Move(tmp, VeylPaths.SettingsFile, overwrite: true);
    }
}
